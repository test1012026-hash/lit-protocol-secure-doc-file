const express = require("express");
const User = require("../../models/User");
const { getPlainEmail } = require("../../lib/emailCrypto");
const {
  canManageUser,
  scopeFilterForActor,
  publicUser,
  roleRank,
  isSuperAdmin,
} = require("../../lib/rbac");
const { logActivity } = require("../../lib/activityLog");
const { validateBody } = require("../../middleware/validate");
const {
  adminUpdateUserSchema,
  extendSubscriptionSchema,
} = require("../../validation/schemas");
const { extendSubscription, FREE_TRIAL_DAYS } = require("../../lib/subscription");

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const q = String(req.query.q || "").trim().toLowerCase();
    const role = req.query.role ? String(req.query.role) : null;
    const includeBlocked = req.query.includeBlocked === "true";
    const excludeSelf = req.query.excludeSelf === "true";
    // claimed=true|false filters; omit = all (claimed + unclaimed) so totals match analytics.
    const claimedParam = req.query.claimed;

    // Subscribers have no managed subtree for lists.
    if (req.admin.role === "subscriber" && (role === "subscriber" || role === "group_admin")) {
      return res.json({ page, limit, total: 0, totalPages: 0, users: [] });
    }

    const filter = scopeFilterForActor(req.admin);
    if (role) filter.role = role;
    if (!includeBlocked) filter.blocked = { $ne: true };
    if (claimedParam === "true") filter.claimed = true;
    if (claimedParam === "false") filter.claimed = { $ne: true };
    // Only drop self when listing the same role (e.g. group admin on Groups).
    if (excludeSelf && (!role || role === req.admin.role)) {
      filter.$and = [...(filter.$and || []), { uuid: { $ne: req.admin.uuid } }];
    }

    let users = await User.find(filter).sort({ createdAt: -1 });

    // Email is encrypted — filter by decrypted email in memory.
    if (q) {
      users = users.filter((u) => {
        const email = (getPlainEmail(u) || "").toLowerCase();
        const name = (u.name || "").toLowerCase();
        return email.includes(q) || name.includes(q);
      });
    }

    const total = users.length;
    const totalPages = Math.max(1, Math.ceil(total / limit) || 1);
    const safePage = Math.min(page, totalPages);
    const pageUsers = users.slice((safePage - 1) * limit, safePage * limit);
    return res.json({
      page: safePage,
      limit,
      total,
      totalPages: total === 0 ? 0 : totalPages,
      users: pageUsers.map((u) => publicUser(u, { getPlainEmail })),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/:uuid", async (req, res) => {
  try {
    const target = await User.findOne({ uuid: req.params.uuid });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }
    return res.json({ user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.patch("/:uuid", validateBody(adminUpdateUserSchema), async (req, res) => {
  try {
    const target = await User.findOne({ uuid: req.params.uuid, deletedAt: null });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }

    if (req.body.role) {
      // Only higher roles can change role; cannot promote to super_admin via API.
      if (roleRank(req.body.role) >= roleRank(req.admin.role) && !isSuperAdmin(req.admin)) {
        return res.status(403).json({ error: "Cannot assign that role", code: "ROLE_FORBIDDEN" });
      }
      if (isSuperAdmin(target)) {
        return res.status(403).json({ error: "Cannot change super admin role", code: "ROLE_FORBIDDEN" });
      }
      target.role = req.body.role;
      if (req.body.role === "reseller") {
        target.sellerUuid = target.uuid;
        target.groupAdminUuid = null;
      } else if (req.body.role === "group_admin") {
        target.sellerUuid = target.sellerUuid || req.admin.sellerUuid || req.admin.uuid;
        target.groupAdminUuid = target.uuid;
      }
    }

    for (const key of ["name", "phone", "country", "company"]) {
      if (req.body[key] !== undefined) target[key] = req.body[key];
    }
    if (req.body.subscriptionExpiresAt !== undefined) {
      if (!isSuperAdmin(req.admin) && req.admin.role !== "reseller") {
        return res.status(403).json({ error: "Cannot update subscription", code: "ROLE_FORBIDDEN" });
      }
      target.subscriptionExpiresAt = req.body.subscriptionExpiresAt
        ? new Date(req.body.subscriptionExpiresAt)
        : null;
    }

    const auditFields = [];
    if (req.body.role !== undefined) auditFields.push("role");
    if (req.body.subscriptionExpiresAt !== undefined) {
      auditFields.push("subscriptionExpiresAt");
    }

    await target.save();
    if (auditFields.length > 0) {
      await logActivity({
        actorUuid: req.admin.uuid,
        actorRole: req.admin.role,
        action: "admin.user_update",
        targetType: "user",
        targetId: target.uuid,
        meta: { fields: auditFields },
        ip: req.ip,
      });
    }
    return res.json({ user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Promote to admin role under actor's hierarchy. */
router.post("/:uuid/make-admin", async (req, res) => {
  try {
    const targetRole = req.body.role === "reseller" ? "reseller" : "group_admin";
    const target = await User.findOne({ uuid: req.params.uuid, deletedAt: null, claimed: true });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }
    if (isSuperAdmin(target)) {
      return res.status(400).json({ error: "Already super admin" });
    }

    if (targetRole === "reseller" && !isSuperAdmin(req.admin)) {
      return res.status(403).json({ error: "Only super admin can create resellers", code: "ROLE_FORBIDDEN" });
    }
    if (
      targetRole === "group_admin" &&
      !isSuperAdmin(req.admin) &&
      req.admin.role !== "reseller"
    ) {
      return res.status(403).json({ error: "Only resellers can create group admins", code: "ROLE_FORBIDDEN" });
    }

    target.role = targetRole;
    target.parentUuid = req.admin.uuid;
    if (targetRole === "reseller") {
      target.sellerUuid = target.uuid;
      target.groupAdminUuid = null;
    } else {
      target.sellerUuid =
        req.admin.role === "reseller" ? req.admin.uuid : req.admin.sellerUuid || req.admin.uuid;
      target.groupAdminUuid = target.uuid;
    }
    await target.save();

    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.make_admin",
      targetType: "user",
      targetId: target.uuid,
      meta: { role: targetRole },
      ip: req.ip,
    });

    return res.json({ user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Block: can receive + decrypt encrypted mail; cannot send/encrypt. */
router.post("/:uuid/block", async (req, res) => {
  try {
    const target = await User.findOne({ uuid: req.params.uuid, deletedAt: null });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }
    if (isSuperAdmin(target) || target.uuid === req.admin.uuid) {
      return res.status(400).json({ error: "Cannot block this account" });
    }
    target.blocked = true;
    await target.save();
    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.user_block",
      targetType: "user",
      targetId: target.uuid,
      ip: req.ip,
    });
    return res.json({ user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/:uuid/unblock", async (req, res) => {
  try {
    const target = await User.findOne({ uuid: req.params.uuid, deletedAt: null });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }
    target.blocked = false;
    await target.save();
    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.user_unblock",
      targetType: "user",
      targetId: target.uuid,
      ip: req.ip,
    });
    return res.json({ user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Soft delete — keep row; cannot login / encrypt / decrypt / receive. */
router.delete("/:uuid", async (req, res) => {
  try {
    const target = await User.findOne({ uuid: req.params.uuid, deletedAt: null });
    if (!target || !canManageUser(req.admin, target)) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }
    if (isSuperAdmin(target) || target.uuid === req.admin.uuid) {
      return res.status(400).json({ error: "Cannot delete this account" });
    }
    // Soft delete only — document stays in MongoDB.
    target.deletedAt = new Date();
    target.blocked = true;
    target.refreshTokenHash = null;
    target.accessTokenHash = null;
    await target.save();
    await User.updateOne(
      { _id: target._id },
      { $unset: { accessTokenCreatedAt: 1, accessTokenExpiresAt: 1 } },
    );
    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.user_soft_delete",
      targetType: "user",
      targetId: target.uuid,
      ip: req.ip,
    });
    return res.json({ ok: true, user: publicUser(target, { getPlainEmail }) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Extend subscription by FREE_TRIAL_DAYS (default 90) periods. */
router.post(
  "/:uuid/extend-subscription",
  validateBody(extendSubscriptionSchema),
  async (req, res) => {
    try {
      const target = await User.findOne({
        uuid: req.params.uuid,
        deletedAt: null,
        claimed: true,
      });
      if (!target || !canManageUser(req.admin, target)) {
        return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
      }

      const periods = req.body.periods || 1;
      extendSubscription(target, periods);
      await target.save();

      await logActivity({
        actorUuid: req.admin.uuid,
        actorRole: req.admin.role,
        action: "admin.subscription_extend",
        targetType: "user",
        targetId: target.uuid,
        meta: {
          periods,
          daysAdded: FREE_TRIAL_DAYS * periods,
          subscriptionExpiresAt: target.subscriptionExpiresAt,
        },
        ip: req.ip,
      });

      return res.json({ user: publicUser(target, { getPlainEmail }) });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
