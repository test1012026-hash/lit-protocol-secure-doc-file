const express = require("express");
const User = require("../../models/User");
const ActivityLog = require("../../models/ActivityLog");
const Invitation = require("../../models/Invitation");
const { scopeFilterForActor, isSuperAdmin } = require("../../lib/rbac");
const { isSubscriptionActive } = require("../../lib/subscription");
const { requireRoles } = require("../../middleware/adminAuth");

const router = express.Router();

router.get(
  "/summary",
  requireRoles("super_admin", "reseller", "group_admin"),
  async (req, res) => {
  try {
    const scope = scopeFilterForActor(req.admin);
    const superAdmin = isSuperAdmin(req.admin);
    // All accounts in scope (not soft-deleted) — includes unclaimed.
    const allScope = { ...scope };
    const claimedScope = { ...scope, claimed: true };

    const [
      totalUsers,
      claimedUsers,
      unclaimedUsers,
      blockedUsers,
      pendingInvites,
      recentActions,
      scopedUsers,
    ] = await Promise.all([
      User.countDocuments(allScope),
      User.countDocuments(claimedScope),
      User.countDocuments({ ...allScope, claimed: { $ne: true } }),
      User.countDocuments({ ...allScope, blocked: true }),
      Invitation.countDocuments({
        status: "pending",
        ...(superAdmin ? {} : { invitedByUuid: req.admin.uuid }),
      }),
      ActivityLog.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
        ...(superAdmin ? {} : { actorUuid: req.admin.uuid }),
      }),
      User.find(allScope).select("subscriptionExpiresAt claimed role").lean(),
    ]);

    const activeSubscriptions = scopedUsers.filter((u) =>
      isSubscriptionActive(u),
    ).length;
    const expiredSubscriptions = scopedUsers.filter(
      (u) => u.subscriptionExpiresAt && !isSubscriptionActive(u),
    ).length;

    const [byRole, byRoleClaimed] = await Promise.all([
      User.aggregate([
        { $match: allScope },
        { $group: { _id: "$role", count: { $sum: 1 } } },
      ]),
      User.aggregate([
        { $match: claimedScope },
        { $group: { _id: "$role", count: { $sum: 1 } } },
      ]),
    ]);
    const roleCounts = byRole.reduce((acc, row) => {
      acc[row._id || "unknown"] = row.count;
      return acc;
    }, {});
    const roleClaimedCounts = byRoleClaimed.reduce((acc, row) => {
      acc[row._id || "unknown"] = row.count;
      return acc;
    }, {});

    const subscribers = roleCounts.subscriber || 0;
    const groupAdmins = roleCounts.group_admin || 0;
    const resellers = roleCounts.reseller || 0;
    const superAdmins = roleCounts.super_admin || 0;
    const subscribersClaimed = roleClaimedCounts.subscriber || 0;
    const groupAdminsClaimed = roleClaimedCounts.group_admin || 0;
    const resellersClaimed = roleClaimedCounts.reseller || 0;

    return res.json({
      totals: {
        /** All non-deleted accounts in scope (claimed + unclaimed). */
        users: totalUsers,
        claimedUsers,
        unclaimedUsers,
        /** Role totals = claimed + unclaimed (matches list pages). */
        subscribers,
        subscribersClaimed,
        subscribersUnclaimed: Math.max(0, subscribers - subscribersClaimed),
        groupAdmins,
        groupAdminsClaimed,
        groupAdminsUnclaimed: Math.max(0, groupAdmins - groupAdminsClaimed),
        resellers,
        resellersClaimed,
        resellersUnclaimed: Math.max(0, resellers - resellersClaimed),
        superAdmins,
        /** Kept for older UI — sum of reseller + group_admin only (not super_admin). */
        admins: resellers + groupAdmins,
        blocked: blockedUsers,
        pendingInvites,
        actionsLast7Days: recentActions,
        activeSubscriptions,
        expiredSubscriptions,
      },
      byRole: roleCounts,
      byRoleClaimed: roleClaimedCounts,
      mySubscriptionExpiresAt: req.admin.subscriptionExpiresAt || null,
      mySubscriptionActive: isSubscriptionActive(req.admin),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
