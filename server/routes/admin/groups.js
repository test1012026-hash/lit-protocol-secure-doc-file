const express = require("express");
const Group = require("../../models/Group");
const User = require("../../models/User");
const Invitation = require("../../models/Invitation");
const { normalizeEmail } = require("../../lib/email");
const {
  getPlainEmail,
  findUserByEmail,
  hashEmail,
} = require("../../lib/emailCrypto");
const {
  isSuperAdmin,
  canManageUser,
  publicUser,
} = require("../../lib/rbac");
const { validateBody } = require("../../middleware/validate");
const {
  resellerCreateGroupSchema,
  updateGroupSchema,
} = require("../../validation/schemas");
const { logActivity } = require("../../lib/activityLog");

const router = express.Router();
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function publicGroup(group, adminUser = null) {
  if (!group) return null;
  return {
    uuid: group.uuid,
    name: group.name,
    description: group.description || "",
    adminUuid: group.adminUuid,
    sellerUuid: group.sellerUuid || null,
    createdByUuid: group.createdByUuid || null,
    adminEmail: adminUser ? getPlainEmail(adminUser) : null,
    adminName: adminUser?.name || "",
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
  };
}

function canActAsReseller(actor) {
  return isSuperAdmin(actor) || actor.role === "reseller";
}

function sellerUuidForActor(actor) {
  if (actor.role === "reseller") return actor.uuid;
  if (isSuperAdmin(actor)) return actor.uuid;
  return actor.sellerUuid || null;
}

async function assertCanManageGroup(actor, group) {
  if (!group) return false;
  if (isSuperAdmin(actor)) return true;
  if (actor.role === "reseller" && group.sellerUuid === actor.uuid) return true;
  if (actor.role === "group_admin" && group.adminUuid === actor.uuid) return true;
  return false;
}

/** List groups visible to the current actor. */
router.get("/", async (req, res) => {
  try {
    const actor = req.admin;
    let filter = {};

    if (isSuperAdmin(actor)) {
      filter = {};
    } else if (actor.role === "reseller") {
      filter = {
        $or: [
          { sellerUuid: actor.uuid },
          { createdByUuid: actor.uuid },
        ],
      };
    } else if (actor.role === "group_admin") {
      filter = { adminUuid: actor.uuid };
    } else {
      return res.json({ groups: [] });
    }

    const groups = await Group.find(filter).sort({ createdAt: -1 }).lean();
    const adminUuids = [...new Set(groups.map((g) => g.adminUuid))];
    const admins = await User.find({ uuid: { $in: adminUuids } }).lean();
    const byUuid = Object.fromEntries(admins.map((u) => [u.uuid, u]));

    return res.json({
      groups: groups.map((g) => publicGroup(g, byUuid[g.adminUuid] || null)),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Current user's group (if they are group_admin). */
router.get("/mine", async (req, res) => {
  try {
    const group = await Group.findOne({ adminUuid: req.admin.uuid }).lean();
    if (!group) {
      return res.json({ group: null });
    }
    return res.json({ group: publicGroup(group, req.admin) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * Reseller / super_admin: create a named group under a group admin.
 * - If adminEmail is an existing managed user → promote + create Group
 * - Otherwise → invite as group_admin with groupName (Group created on accept)
 */
router.post("/", validateBody(resellerCreateGroupSchema), async (req, res) => {
  try {
    const actor = req.admin;
    if (!canActAsReseller(actor)) {
      return res.status(403).json({
        error: "Only resellers can create groups",
        code: "ROLE_FORBIDDEN",
      });
    }

    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();
    const adminEmail = normalizeEmail(req.body.adminEmail);
    const sellerUuid = sellerUuidForActor(actor);

    const existingUser = await findUserByEmail(User, adminEmail);

    if (existingUser?.claimed && !existingUser.deletedAt) {
      if (!canManageUser(actor, existingUser) && !isSuperAdmin(actor)) {
        return res.status(403).json({
          error: "That user is outside your reseller scope",
          code: "OUT_OF_SCOPE",
        });
      }
      if (existingUser.role === "super_admin" || existingUser.role === "reseller") {
        return res.status(400).json({
          error: "Cannot assign this account as a group admin",
          code: "ROLE_FORBIDDEN",
        });
      }

      const alreadyOwns = await Group.findOne({ adminUuid: existingUser.uuid });
      if (alreadyOwns) {
        return res.status(409).json({
          error: "This user already administers a group",
          code: "GROUP_EXISTS",
          group: publicGroup(alreadyOwns, existingUser),
        });
      }

      existingUser.role = "group_admin";
      existingUser.parentUuid = actor.uuid;
      existingUser.sellerUuid = sellerUuid;
      existingUser.groupAdminUuid = existingUser.uuid;
      existingUser.onboardingComplete = true;
      await existingUser.save();

      const group = await Group.create({
        name,
        description,
        adminUuid: existingUser.uuid,
        sellerUuid,
        createdByUuid: actor.uuid,
      });
      existingUser.groupUuid = group.uuid;
      await existingUser.save();

      await logActivity({
        actorUuid: actor.uuid,
        actorRole: actor.role,
        action: "admin.group_create",
        targetType: "group",
        targetId: group.uuid,
        meta: { name, adminUuid: existingUser.uuid, mode: "promote" },
        ip: req.ip,
      });

      return res.status(201).json({
        mode: "created",
        group: publicGroup(group, existingUser),
        user: publicUser(existingUser, { getPlainEmail }),
      });
    }

    // Invite new group admin + attach group name for creation on accept
    const pendingInvite = await Invitation.findOne({
      emailHash: hashEmail(adminEmail),
      status: "pending",
    });
    if (pendingInvite) {
      return res.status(409).json({
        error: "A pending invite already exists for this email",
        code: "INVITE_PENDING",
      });
    }

    const token = Invitation.createToken();
    const invite = await Invitation.create({
      email: adminEmail,
      emailHash: hashEmail(adminEmail),
      invitedByUuid: actor.uuid,
      role: "group_admin",
      parentUuid: actor.uuid,
      sellerUuid,
      groupAdminUuid: null,
      groupName: name,
      groupDescription: description,
      tokenHash: Invitation.hashToken(token),
      status: "pending",
      expiresAt: new Date(Date.now() + INVITE_TTL_MS),
    });

    await logActivity({
      actorUuid: actor.uuid,
      actorRole: actor.role,
      action: "admin.group_create",
      targetType: "invitation",
      targetId: String(invite._id),
      meta: { name, adminEmail, mode: "invite" },
      ip: req.ip,
    });

    const appBase = (
      process.env.ADMIN_APP_URL ||
      process.env.APP_URL ||
      "http://localhost:5174"
    ).replace(/\/$/, "");

    return res.status(201).json({
      mode: "invited",
      invitation: {
        id: invite._id,
        email: invite.email,
        role: invite.role,
        groupName: invite.groupName,
        status: invite.status,
        expiresAt: invite.expiresAt,
      },
      inviteUrl: `${appBase}/accept-invite?token=${token}`,
      message:
        "Invite sent. When they accept, the group will be created and they become group admin.",
    });
  } catch (err) {
    return res.status(err.status || 500).json({
      error: err.message,
      code: err.code || undefined,
    });
  }
});

router.patch("/:uuid", validateBody(updateGroupSchema), async (req, res) => {
  try {
    const group = await Group.findOne({ uuid: req.params.uuid });
    if (!group || !(await assertCanManageGroup(req.admin, group))) {
      return res.status(404).json({ error: "Group not found", code: "GROUP_NOT_FOUND" });
    }
    if (req.body.name !== undefined) group.name = req.body.name;
    if (req.body.description !== undefined) {
      group.description = req.body.description;
    }
    await group.save();

    const adminUser = await User.findOne({ uuid: group.adminUuid }).lean();
    return res.json({ group: publicGroup(group, adminUser) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.delete("/:uuid", async (req, res) => {
  try {
    const group = await Group.findOne({ uuid: req.params.uuid });
    if (!group || !(await assertCanManageGroup(req.admin, group))) {
      return res.status(404).json({ error: "Group not found", code: "GROUP_NOT_FOUND" });
    }
    if (
      !isSuperAdmin(req.admin) &&
      req.admin.role !== "reseller"
    ) {
      return res.status(403).json({
        error: "Only resellers can delete groups",
        code: "ROLE_FORBIDDEN",
      });
    }

    const adminUuid = group.adminUuid;

    // Unlink references only — do NOT delete user accounts.
    await User.updateMany(
      { groupUuid: group.uuid },
      { $set: { groupUuid: null } },
    );

    // Subscribers that pointed at this group admin keep their accounts;
    // clear the group link so they are no longer under this deleted group.
    await User.updateMany(
      { groupAdminUuid: adminUuid, role: "subscriber" },
      { $set: { groupAdminUuid: null } },
    );

    const adminUser = await User.findOne({ uuid: adminUuid });
    if (adminUser) {
      if (adminUser.groupUuid === group.uuid) {
        adminUser.groupUuid = null;
      }
      // Demote group admin back to subscriber under the reseller (account kept).
      if (adminUser.role === "group_admin") {
        adminUser.role = "subscriber";
        adminUser.groupAdminUuid = null;
        if (group.sellerUuid) {
          adminUser.sellerUuid = group.sellerUuid;
          adminUser.parentUuid = group.sellerUuid;
        }
      }
      await adminUser.save();
    }

    await Group.deleteOne({ _id: group._id });

    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.group_delete",
      targetType: "group",
      targetId: group.uuid,
      meta: {
        name: group.name,
        adminUuid,
        usersDeleted: false,
        referencesCleared: true,
      },
      ip: req.ip,
    });

    return res.json({
      ok: true,
      usersDeleted: false,
      message:
        "Group removed. User accounts were kept; group links were cleared and the former group admin was demoted to subscriber.",
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
