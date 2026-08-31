const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../../models/User");
const Group = require("../../models/Group");
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
  calculateGroupExpiresAt,
  ensureGroupExpiresAt,
  syncGroupMembersExpiration,
} = require("../../lib/subscription");
const { issueAuthTokens } = require("../../lib/tokens");
const { publicUser, isSuperAdmin, canAccessPanel } = require("../../lib/rbac");
const { logActivity } = require("../../lib/activityLog");
const { setAdminSessionCookie } = require("../../lib/adminSessionCookie");
const { sendInviteEmail } = require("../../lib/mail");
const { validateBody } = require("../../middleware/validate");
const { adminInviteSchema, acceptInviteSchema } = require("../../validation/schemas");
const { adminAuthMiddleware } = require("../../middleware/adminAuth");
const SystemSettings = require("../../models/SystemSettings");

const router = express.Router();

const INVITE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

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

      let groupUuid = null;
      let groupName = role === "group_admin" ? String(req.body.groupName || "").trim() : "";
      if (req.admin.role === "group_admin") {
        const adminGroup = await Group.findOne({ adminUuid: req.admin.uuid }).lean();
        if (adminGroup) {
          groupUuid = adminGroup.uuid;
          if (!groupName) groupName = adminGroup.name;
        }
      }

      const existing = await findUserByEmail(User, email);
      if (existing && !existing.deletedAt && existing.claimed) {
        const inGroup = Boolean(
          existing.groupUuid ||
          existing.groupAdminUuid ||
          existing.role === "group_admin" ||
          existing.role === "reseller" ||
          existing.role === "super_admin"
        );
        if (inGroup) {
          return res.status(409).json({
            error: "This user already belongs to another group or organization.",
            code: "ALREADY_IN_GROUP",
          });
        }
        // Independent subscriber without a group can be invited into this group
      }

      const pendingInvite = await Invitation.findOne({
        emailHash: hashEmail(email),
        status: "pending",
        expiresAt: { $gt: new Date() },
      });
      if (pendingInvite) {
        return res.status(409).json({
          error: "A pending invite already exists for this email",
          code: "INVITE_PENDING",
        });
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
        groupUuid,
        groupName,
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

      const inviteUrl = `${appBase}/accept-invite?token=${token}`;

      await sendInviteEmail({
        to: email,
        inviteUrl,
        role,
        groupName,
        inviterEmail: getPlainEmail(req.admin),
      }).catch((err) => {
        console.error("Failed to send invite email:", err.message);
      });

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
        inviteUrl,
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
      return res.status(410).json({
        error: "Invitation expired. Invitation links are valid for 24 hours only.",
        code: "INVITE_EXPIRED",
      });
    }

    const user = await findUserByEmail(User, invite.email);
    const isExistingUser = Boolean(user && !user.deletedAt && user.claimed);

    return res.json({
      email: invite.email,
      role: invite.role,
      groupName: invite.groupName || "",
      trialDays: FREE_TRIAL_DAYS,
      expiresAt: invite.expiresAt,
      isExistingUser,
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
      return res.status(410).json({
        error: "Invitation expired. Invitation links are valid for 24 hours only.",
        code: "INVITE_EXPIRED",
      });
    }

    let user = await findUserByEmail(User, invite.email);
    const isExisting = Boolean(user && !user.deletedAt && user.claimed);

    if (isExisting) {
      // Check if user is already in another group
      if (user.groupUuid || user.groupAdminUuid || user.role === "group_admin" || user.role === "reseller") {
        return res.status(409).json({
          error: "Account already belongs to a group or organization.",
          code: "ALREADY_IN_GROUP",
        });
      }

      if (req.body.password && String(req.body.password).trim()) {
        user.passwordHash = await bcrypt.hash(req.body.password, 12);
      }
      if (req.body.name) {
        user.name = req.body.name;
      }
      user.role = invite.role;
      user.parentUuid = invite.parentUuid;
      user.sellerUuid =
        invite.role === "reseller" ? user.uuid : invite.sellerUuid;
      user.groupAdminUuid =
        invite.role === "group_admin" ? user.uuid : invite.groupAdminUuid;

      if (invite.groupUuid) {
        user.groupUuid = invite.groupUuid;
      } else if (invite.groupAdminUuid) {
        const adminGroup = await Group.findOne({ adminUuid: invite.groupAdminUuid }).lean();
        if (adminGroup) user.groupUuid = adminGroup.uuid;
      }

      user.onboardingComplete = true;
      user.termsAndConditions = true;
      await user.save();
    } else {
      if (!req.body.password || req.body.password.length < 12) {
        return res.status(400).json({
          error: "Password must be at least 12 characters",
          code: "INVALID_PASSWORD",
        });
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

      if (invite.groupUuid) {
        user.groupUuid = invite.groupUuid;
      } else if (invite.groupAdminUuid) {
        const adminGroup = await Group.findOne({ adminUuid: invite.groupAdminUuid }).lean();
        if (adminGroup) user.groupUuid = adminGroup.uuid;
      }

      // Same as signup: 90-day (3 month) period on subscriptionExpiresAt
      user.subscriptionExpiresAt = trialExpiresFrom(new Date());
      user.onboardingComplete = true;
      await user.save();
    }

    let createdGroup = null;
    if (invite.role === "group_admin" && String(invite.groupName || "").trim()) {
      const existingGroup = await Group.findOne({ adminUuid: user.uuid });
      if (!existingGroup) {
        const groupExpiresAt = await calculateGroupExpiresAt(new Date());
        createdGroup = await Group.create({
          name: String(invite.groupName).trim(),
          description: String(invite.groupDescription || "").trim(),
          adminUuid: user.uuid,
          sellerUuid: invite.sellerUuid || null,
          createdByUuid: invite.invitedByUuid || user.uuid,
          expiresAt: groupExpiresAt,
        });
        user.groupUuid = createdGroup.uuid;
        user.subscriptionExpiresAt = createdGroup.expiresAt;
        await user.save();
      } else {
        if (!existingGroup.expiresAt) {
          await ensureGroupExpiresAt(existingGroup, User);
        }
        createdGroup = existingGroup;
        user.groupUuid = existingGroup.uuid;
        user.subscriptionExpiresAt = existingGroup.expiresAt;
        await user.save();
      }
    } else if (user.groupUuid || user.groupAdminUuid) {
      const targetGroup = await Group.findOne({
        $or: [
          ...(user.groupUuid ? [{ uuid: user.groupUuid }] : []),
          ...(user.groupAdminUuid ? [{ adminUuid: user.groupAdminUuid }] : []),
        ],
      });
      if (targetGroup) {
        if (!targetGroup.expiresAt) {
          await ensureGroupExpiresAt(targetGroup, User);
        }
        user.subscriptionExpiresAt = targetGroup.expiresAt;
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
      isExistingUser: isExisting,
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
