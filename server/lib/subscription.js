/**
 * Subscription: 90-day (3 month) periods via subscriptionExpiresAt.
 * New users get FREE_TRIAL_DAYS from claim/creation (default 90).
 * After expiry, sending is blocked until an admin extends the period.
 */

const FREE_TRIAL_DAYS = Number(process.env.FREE_TRIAL_DAYS || 90);

function addDays(date, days) {
  const d = new Date(date);
  d.setUTCDate(d.getUTCDate() + days);
  return d;
}

function trialExpiresFrom(start = new Date()) {
  return addDays(start, FREE_TRIAL_DAYS);
}

function isSubscriptionActive(user) {
  if (!user?.subscriptionExpiresAt) return false;
  return new Date(user.subscriptionExpiresAt).getTime() > Date.now();
}

/**
 * Ensure claimed users have subscriptionExpiresAt.
 * Missing field: createdAt + FREE_TRIAL_DAYS (legacy backfill) or now + days.
 */
async function ensureUserSubscription(user) {
  if (!user || !user.claimed) return user;

  if (!user.subscriptionExpiresAt) {
    const start = user.createdAt ? new Date(user.createdAt) : new Date();
    user.subscriptionExpiresAt = trialExpiresFrom(start);
    await user.save();
  }
  return user;
}

function subscriptionPayload(user) {
  const expiresAt = user?.subscriptionExpiresAt
    ? new Date(user.subscriptionExpiresAt).toISOString()
    : null;
  const active = isSubscriptionActive(user);
  const msLeft = expiresAt ? new Date(expiresAt).getTime() - Date.now() : 0;
  const daysLeft = active
    ? Math.max(0, Math.ceil(msLeft / (24 * 60 * 60 * 1000)))
    : 0;

  return {
    subscriptionExpiresAt: expiresAt,
    subscriptionActive: active,
    subscriptionDaysLeft: daysLeft,
    subscriptionTrialDays: FREE_TRIAL_DAYS,
  };
}

function subscriptionBlockedError() {
  return {
    error: `Your ${FREE_TRIAL_DAYS}-day subscription period has ended. Renew to continue sending secure mail.`,
    code: "SUBSCRIPTION_EXPIRED",
  };
}

/**
 * Extend from max(now, current expiry) by another FREE_TRIAL_DAYS (default 90).
 * periods = how many 90-day blocks to add (default 1).
 */
function extendSubscription(user, periods = 1) {
  const n = Math.max(1, Math.min(12, Number(periods) || 1));
  const base =
    user.subscriptionExpiresAt &&
    new Date(user.subscriptionExpiresAt).getTime() > Date.now()
      ? new Date(user.subscriptionExpiresAt)
      : new Date();
  user.subscriptionExpiresAt = addDays(base, FREE_TRIAL_DAYS * n);
  return user;
}

module.exports = {
  FREE_TRIAL_DAYS,
  trialExpiresFrom,
  ensureUserSubscription,
  isSubscriptionActive,
  subscriptionPayload,
  subscriptionBlockedError,
  extendSubscription,
};
