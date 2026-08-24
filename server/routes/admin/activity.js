const express = require("express");
const ActivityLog = require("../../models/ActivityLog");
const Invitation = require("../../models/Invitation");
const { AUDIT_ACTIONS } = require("../../lib/activityLog");
const { scopeFilterForActor, isSuperAdmin } = require("../../lib/rbac");
const { getPlainEmail } = require("../../lib/emailCrypto");
const User = require("../../models/User");
const { requireRoles } = require("../../middleware/adminAuth");

const router = express.Router();

router.get(
  "/",
  requireRoles("super_admin", "reseller", "group_admin"),
  async (req, res) => {
    try {
      const page = Math.max(1, Number(req.query.page) || 1);
      const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
      const action = req.query.action ? String(req.query.action) : null;

      let filter = {
        // Hide basic noise (login, profile, etc.) even if old rows exist.
        action: { $in: AUDIT_ACTIONS },
      };

      if (isSuperAdmin(req.admin)) {
        // filter already set
      } else {
        const scoped = await User.find(scopeFilterForActor(req.admin))
          .select("uuid")
          .lean();
        const uuids = scoped.map((u) => u.uuid);
        filter = {
          action: { $in: AUDIT_ACTIONS },
          $or: [
            { actorUuid: { $in: uuids } },
            { targetId: { $in: uuids } },
          ],
        };
      }

      if (action) {
        if (!AUDIT_ACTIONS.includes(action)) {
          return res.json({
            logs: [],
            page,
            limit,
            total: 0,
            totalPages: 0,
            auditActions: AUDIT_ACTIONS,
          });
        }
        filter.action = action;
      }

      const total = await ActivityLog.countDocuments(filter);
      const totalPages = total > 0 ? Math.ceil(total / limit) : 0;
      const safePage = totalPages > 0 ? Math.min(page, totalPages) : 1;

      const logs = await ActivityLog.find(filter)
        .sort({ createdAt: -1 })
        .skip((safePage - 1) * limit)
        .limit(limit)
        .lean();

      const userUuids = new Set();
      const inviteIds = new Set();
      for (const log of logs) {
        if (log.actorUuid) userUuids.add(log.actorUuid);
        if (log.targetType === "user" && log.targetId) {
          userUuids.add(log.targetId);
        }
        if (log.targetType === "invitation" && log.targetId) {
          inviteIds.add(log.targetId);
        }
      }

      const [users, invites] = await Promise.all([
        userUuids.size
          ? User.find({ uuid: { $in: [...userUuids] } }).lean()
          : [],
        inviteIds.size
          ? Invitation.find({ _id: { $in: [...inviteIds] } }).lean()
          : [],
      ]);

      const emailByUuid = new Map();
      for (const u of users) {
        emailByUuid.set(u.uuid, getPlainEmail(u) || u.uuid);
      }

      const emailByInviteId = new Map();
      for (const inv of invites) {
        emailByInviteId.set(String(inv._id), inv.email || String(inv._id));
      }

      const enriched = logs.map((log) => {
        const actorEmail = log.actorUuid
          ? emailByUuid.get(log.actorUuid) || null
          : null;

        let targetEmail = null;
        if (log.targetType === "user" && log.targetId) {
          targetEmail = emailByUuid.get(log.targetId) || null;
        } else if (log.targetType === "invitation" && log.targetId) {
          targetEmail =
            emailByInviteId.get(String(log.targetId)) ||
            log.meta?.email ||
            null;
        } else if (log.targetType === "settings") {
          targetEmail = "system settings";
        }

        return {
          ...log,
          actorEmail,
          targetEmail,
        };
      });

      return res.json({
        logs: enriched,
        page: safePage,
        limit,
        total,
        totalPages,
        auditActions: AUDIT_ACTIONS,
      });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
