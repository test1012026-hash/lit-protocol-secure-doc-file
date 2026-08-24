const ActivityLog = require("../models/ActivityLog");

/**
 * Important audit actions only (no login / logout / profile noise).
 */
const AUDIT_ACTIONS = [
  "admin.user_update",
  "admin.make_admin",
  "admin.user_block",
  "admin.user_unblock",
  "admin.user_soft_delete",
  "admin.subscription_extend",
  "admin.invite_create",
  "admin.invite_revoke",
  "invite.accepted",
  "admin.settings_update",
  "admin.group_create",
  "admin.group_delete",
  "onboarding.subscriber",
  "onboarding.create_group",
];

/**
 * Fire-and-forget audit log for important user/system actions only.
 * Never throws to callers. Skips non-audit actions.
 */
async function logActivity({
  actorUuid = null,
  actorRole = null,
  action,
  targetType = null,
  targetId = null,
  meta = {},
  ip = null,
}) {
  if (!AUDIT_ACTIONS.includes(action)) return;
  try {
    await ActivityLog.create({
      actorUuid,
      actorRole,
      action,
      targetType,
      targetId,
      meta,
      ip,
    });
  } catch (err) {
    console.error("activity log failed:", err.message);
  }
}

module.exports = { logActivity, AUDIT_ACTIONS };
