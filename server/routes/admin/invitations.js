const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../../models/User");
const Invitation = require("../../models/Invitation");
const { normalizeEmail } = require("../../lib/email");
const {
  applyEncryptedEmail,
  findUserByEmail,
  hashEmail,
  getPlainEmail,
} = require("../../lib/emailCrypto");
const {
  FREE_TRIAL_DAYS,
  trialExpiresFrom,
} = require("../../lib/subscription");
const { issueAuthTokens } = require("../../lib/tokens");
const { publicUser, isSuperAdmin, canAccessPanel } = require("../../lib/rbac");
const { logActivity } = require("../../lib/activityLog");
const { setAdminSessionCookie } = require("../../lib/adminSessionCookie");
const { validateBody } = require("../../middleware/validate");
const { adminInviteSchema, acceptInviteSchema } = require("../../validation/schemas");
const { adminAuthMiddleware } = require("../../middleware/adminAuth");
const SystemSettings = require("../../models/SystemSettings");

const router = express.Router();

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

router.post(
  "/",
  adminAuthMiddleware,
  validateBody(adminInviteSchema),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      const role = req.body.role || "subscriber";

      if (role === "reseller" && !isSuperAdmin(req.admin)) {
        return res.status(403).json({ error: "Only super admin can invite resellers", code: "ROLE_FORBIDDEN" });
      }
      if (
        role === "group_admin" &&
        !isSuperAdmin(req.admin) &&
        req.admin.role !== "reseller"
      ) {
        return res.status(403).json({
          error: "Only resellers can invite group admins",
          code: "ROLE_FORBIDDEN",
        });
      }

      if (role === "group_admin") {
        const gName = String(req.body.groupName || "").trim();
        if (gName.length < 2) {
          return res.status(400).json({
            error: "Group name is required when inviting a group admin",
            code: "GROUP_NAME_REQUIRED",
          });
        }
      }

      const existing = await findUserByEmail(User, email);
      if (existing?.claimed && !existing.deletedAt) {
        return res.status(409).json({ error: "User already registered", code: "USER_EXISTS" });
      }

      const token = Invitation.createToken();
      const invite = await Invitation.create({
        email,
        emailHash: hashEmail(email),
        invitedByUuid: req.admin.uuid,
        role,
        parentUuid: req.admin.uuid,
        sellerUuid:
          role === "reseller"
            ? null
            : req.admin.role === "reseller"
              ? req.admin.uuid
              : req.admin.sellerUuid || req.admin.uuid,
        groupAdminUuid:
          role === "group_admin"
            ? null
            : req.admin.role === "group_admin"
              ? req.admin.uuid
              : null,
        groupName:
          role === "group_admin" ? String(req.body.groupName || "").trim() : "",
        groupDescription:
          role === "group_admin"
            ? String(req.body.groupDescription || "").trim()
            : "",
        tokenHash: Invitation.hashToken(token),
        status: "pending",
        expiresAt: new Date(Date.now() + INVITE_TTL_MS),
      });

      await logActivity({
        actorUuid: req.admin.uuid,
        actorRole: req.admin.role,
        action: "admin.invite_create",
        targetType: "invitation",
        targetId: String(invite._id),
        meta: { email, role, trialDays: FREE_TRIAL_DAYS },
        ip: req.ip,
      });

      const appBase = (
        process.env.ADMIN_APP_URL ||
        process.env.APP_URL ||
        "http://localhost:5174"
      ).replace(/\/$/, "");

      return res.status(201).json({
        invitation: {
          id: invite._id,
          email: invite.email,
          role: invite.role,
          status: invite.status,
          expiresAt: invite.expiresAt,
          trialDays: FREE_TRIAL_DAYS,
        },
        inviteToken: token,
        inviteUrl: `${appBase}/accept-invite?token=${token}`,
      });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

router.get("/", adminAuthMiddleware, async (req, res) => {
  try {
    const filter = { invitedByUuid: req.admin.uuid };
    if (isSuperAdmin(req.admin)) {
      delete filter.invitedByUuid;
    } else if (req.admin.role === "reseller") {
      delete filter.invitedByUuid;
      filter.$or = [
        { invitedByUuid: req.admin.uuid },
        { sellerUuid: req.admin.uuid },
      ];
    }

    const invitations = await Invitation.find(filter)
      .sort({ createdAt: -1 })
      .limit(100);
    return res.json({
      trialDays: FREE_TRIAL_DAYS,
      invitations: invitations.map((i) => ({
        id: i._id,
        email: i.email,
        role: i.role,
        groupName: i.groupName || "",
        status: i.status,
        expiresAt: i.expiresAt,
        acceptedAt: i.acceptedAt,
        createdAt: i.createdAt,
      })),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/:id/revoke", adminAuthMiddleware, async (req, res) => {
  try {
    const invite = await Invitation.findById(req.params.id);
    if (!invite || invite.status !== "pending") {
      return res.status(404).json({ error: "Invitation not found" });
    }
    if (
      invite.invitedByUuid !== req.admin.uuid &&
      !isSuperAdmin(req.admin)
    ) {
      return res.status(403).json({ error: "Forbidden" });
    }
    invite.status = "revoked";
    await invite.save();
    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.invite_revoke",
      targetType: "invitation",
      targetId: String(invite._id),
      meta: { email: invite.email },
      ip: req.ip,
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/accept/:token", async (req, res) => {
  try {
    const invite = await Invitation.findOne({
      tokenHash: Invitation.hashToken(req.params.token),
    });
    if (!invite || invite.status !== "pending") {
      return res.status(404).json({ error: "Invitation not found", code: "INVITE_INVALID" });
    }
    if (invite.expiresAt.getTime() < Date.now()) {
      invite.status = "expired";
      await invite.save();
      return res.status(410).json({ error: "Invitation expired", code: "INVITE_EXPIRED" });
    }
    return res.json({
      email: invite.email,
      role: invite.role,
      trialDays: FREE_TRIAL_DAYS,
      expiresAt: invite.expiresAt,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/accept", validateBody(acceptInviteSchema), async (req, res) => {
  try {
    const invite = await Invitation.findOne({
      tokenHash: Invitation.hashToken(req.body.token),
    });
    if (!invite || invite.status !== "pending") {
      return res.status(404).json({ error: "Invitation not found", code: "INVITE_INVALID" });
    }
    if (invite.expiresAt.getTime() < Date.now()) {
      invite.status = "expired";
      await invite.save();
      return res.status(410).json({ error: "Invitation expired", code: "INVITE_EXPIRED" });
    }

    let user = await findUserByEmail(User, invite.email);
    if (user?.claimed && !user.deletedAt) {
      return res.status(409).json({ error: "Account already exists", code: "USER_EXISTS" });
    }

    const passwordHash = await bcrypt.hash(req.body.password, 12);
    if (!user) {
      user = new User({
        uuid: crypto.randomUUID(),
        claimed: true,
      });
      applyEncryptedEmail(user, invite.email);
    }

    user.claimed = true;
    user.deletedAt = null;
    user.blocked = false;
    user.passwordHash = passwordHash;
    user.termsAndConditions = true;
    user.name = req.body.name || user.name || "";
    user.role = invite.role;
    user.parentUuid = invite.parentUuid;
    user.sellerUuid =
      invite.role === "reseller" ? user.uuid : invite.sellerUuid;
    user.groupAdminUuid =
      invite.role === "group_admin" ? user.uuid : invite.groupAdminUuid;
    // Same as signup: 90-day (3 month) period on subscriptionExpiresAt
    user.subscriptionExpiresAt = trialExpiresFrom(new Date());
    user.onboardingComplete = true;
    await user.save();

    let createdGroup = null;
    if (invite.role === "group_admin" && String(invite.groupName || "").trim()) {
      const Group = require("../../models/Group");
      const existingGroup = await Group.findOne({ adminUuid: user.uuid });
      if (!existingGroup) {
        createdGroup = await Group.create({
          name: String(invite.groupName).trim(),
          description: String(invite.groupDescription || "").trim(),
          adminUuid: user.uuid,
          sellerUuid: invite.sellerUuid || null,
          createdByUuid: invite.invitedByUuid || user.uuid,
        });
        user.groupUuid = createdGroup.uuid;
        await user.save();
      } else {
        createdGroup = existingGroup;
        user.groupUuid = existingGroup.uuid;
        await user.save();
      }
    }

    invite.status = "accepted";
    invite.acceptedAt = new Date();
    invite.acceptedUserUuid = user.uuid;
    await invite.save();

    const settings = await SystemSettings.getOrCreate();
    const issued = await issueAuthTokens(user, {
      expiresInHours: Number(settings.tokenExpiryHours) || 8,
    });

    await logActivity({
      actorUuid: user.uuid,
      actorRole: user.role,
      action: "invite.accepted",
      targetType: "invitation",
      targetId: String(invite._id),
      ip: req.ip,
    });

    const userJson = publicUser(user, { getPlainEmail });
    if (canAccessPanel(user)) {
      setAdminSessionCookie(req, res, issued.token, issued.expiresAt);
    }

    return res.json({
      ok: true,
      expiresAt: issued.expiresAt,
      user: userJson,
      group: createdGroup
        ? {
            uuid: createdGroup.uuid,
            name: createdGroup.name,
            adminUuid: createdGroup.adminUuid,
          }
        : null,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
