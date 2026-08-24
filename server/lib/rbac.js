const User = require("../models/User");

const ROLE_RANK = {
  subscriber: 1,
  group_admin: 2,
  reseller: 3,
  super_admin: 4,
};

function roleRank(role) {
  return ROLE_RANK[role] || 0;
}

function isAdminRole(role) {
  return roleRank(role) >= roleRank("group_admin");
}

/** Any claimed account may use the web console (including subscribers). */
function canAccessPanel(userOrRole) {
  if (!userOrRole) return false;
  const role =
    typeof userOrRole === "string" ? userOrRole : userOrRole.role;
  return Boolean(ROLE_RANK[role]);
}

/** True when role is super_admin (accepts user doc or role string). */
function isSuperAdmin(userOrRole) {
  if (!userOrRole) return false;
  if (typeof userOrRole === "string") return userOrRole === "super_admin";
  return userOrRole.role === "super_admin";
}

/**
 * Can actor manage target based on hierarchy + role.
 * Super admin manages everyone. Reseller manages their subtree. Group admin manages their subscribers.
 */
function canManageUser(actor, target) {
  if (!actor || !target) return false;
  if (actor.deletedAt || target.deletedAt) return false;
  if (isSuperAdmin(actor)) return true;

  if (actor.role === "reseller") {
    if (target.uuid === actor.uuid) return true;
    return (
      target.sellerUuid === actor.uuid ||
      target.parentUuid === actor.uuid
    );
  }

  if (actor.role === "group_admin") {
    if (target.uuid === actor.uuid) return true;
    return (
      target.groupAdminUuid === actor.uuid ||
      target.parentUuid === actor.uuid
    );
  }

  return target.uuid === actor.uuid;
}

function scopeFilterForActor(actor) {
  if (isSuperAdmin(actor)) {
    return { deletedAt: null };
  }
  if (actor.role === "reseller") {
    return {
      deletedAt: null,
      $or: [
        { uuid: actor.uuid },
        { sellerUuid: actor.uuid },
        { parentUuid: actor.uuid },
      ],
    };
  }
  if (actor.role === "group_admin") {
    return {
      deletedAt: null,
      $or: [
        { uuid: actor.uuid },
        { groupAdminUuid: actor.uuid },
        { parentUuid: actor.uuid },
      ],
    };
  }
  return { uuid: actor.uuid, deletedAt: null };
}

function publicUser(user, { getPlainEmail }) {
  if (!user) return null;
  const expiresAt = user.subscriptionExpiresAt
    ? new Date(user.subscriptionExpiresAt)
    : null;
  const subscriptionActive = Boolean(
    expiresAt && expiresAt.getTime() > Date.now(),
  );
  return {
    uuid: user.uuid,
    email: getPlainEmail(user),
    name: user.name || "",
    phone: user.phone || "",
    country: user.country || "",
    company: user.company || "",
    role: user.role || "subscriber",
    parentUuid: user.parentUuid || null,
    sellerUuid: user.sellerUuid || null,
    groupAdminUuid: user.groupAdminUuid || null,
    groupUuid: user.groupUuid || null,
    onboardingComplete: Boolean(user.onboardingComplete),
    needsOnboarding:
      !user.onboardingComplete &&
      (user.role || "subscriber") === "subscriber" &&
      !user.parentUuid &&
      !user.groupAdminUuid &&
      !user.sellerUuid,
    blocked: Boolean(user.blocked),
    deletedAt: user.deletedAt || null,
    claimed: Boolean(user.claimed),
    subscriptionExpiresAt: expiresAt ? expiresAt.toISOString() : null,
    subscriptionActive,
    hasPassword: Boolean(user.passwordHash),
    hasPublicKey: Boolean(user.iron && user.thor),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

async function resolveRelatedUser(uuid, getPlainEmail) {
  if (!uuid) return null;
  const related = await User.findOne({ uuid, deletedAt: null }).lean();
  if (!related) return null;
  return {
    uuid: related.uuid,
    email: getPlainEmail(related),
    name: related.name || "",
    role: related.role || "subscriber",
  };
}

/** Attach reseller / group / parent summaries when those links exist. */
async function publicUserWithHierarchy(user, { getPlainEmail }) {
  const base = publicUser(user, { getPlainEmail });
  if (!base) return null;

  const [reseller, groupAdmin, parent] = await Promise.all([
    resolveRelatedUser(user.sellerUuid, getPlainEmail),
    resolveRelatedUser(user.groupAdminUuid, getPlainEmail),
    resolveRelatedUser(
      user.parentUuid &&
        user.parentUuid !== user.sellerUuid &&
        user.parentUuid !== user.groupAdminUuid
        ? user.parentUuid
        : null,
      getPlainEmail,
    ),
  ]);

  return {
    ...base,
    reseller: reseller || null,
    groupAdmin: groupAdmin || null,
    parent: parent || null,
  };
}

module.exports = {
  ROLE_RANK,
  roleRank,
  isAdminRole,
  canAccessPanel,
  isSuperAdmin,
  canManageUser,
  scopeFilterForActor,
  publicUser,
  publicUserWithHierarchy,
  User,
};
