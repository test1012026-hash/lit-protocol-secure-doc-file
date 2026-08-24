const User = require("../models/User");
const {
  verifySessionToken,
  sendRelogin,
  RELOGIN_STATUS,
} = require("../lib/tokens");
const { isSuperAdmin, canAccessPanel } = require("../lib/rbac");
const { readAdminToken } = require("../lib/adminSessionCookie");

/**
 * Requires panel session cookie (or Bearer) for any claimed console role.
 * Loads fresh user into req.admin.
 */
async function adminAuthMiddleware(req, res, next) {
  const token = readAdminToken(req);
  if (!token) {
    return res.status(401).json({
      error: "Missing token",
      code: "TOKEN_MISSING",
    });
  }

  let session;
  try {
    session = await verifySessionToken(token);
  } catch (err) {
    if (err.status === RELOGIN_STATUS || err.code === "TOKEN_EXPIRED" || err.code === "TOKEN_INVALID") {
      return sendRelogin(res, err.code || "RELOGIN_REQUIRED");
    }
    if (err.status === 403) {
      return res.status(403).json({ error: err.message, code: err.code });
    }
    return sendRelogin(res, "TOKEN_INVALID");
  }

  try {
    const user = session.user || (await User.findOne({ uuid: session.uuid }));
    if (!user || !user.claimed || user.deletedAt) {
      return sendRelogin(res, "ADMIN_NOT_FOUND");
    }
    if (user.blocked) {
      return res.status(403).json({
        error: "Account is blocked",
        code: "ACCOUNT_BLOCKED",
      });
    }
    if (!canAccessPanel(user)) {
      return res.status(403).json({
        error: "Panel access required",
        code: "PANEL_REQUIRED",
      });
    }

    req.user = session;
    req.admin = user;
    next();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

function requireRoles(...roles) {
  return (req, res, next) => {
    const admin = req.admin;
    if (!admin) {
      return res.status(401).json({ error: "Unauthorized", code: "UNAUTHORIZED" });
    }
    if (isSuperAdmin(admin)) return next();
    if (roles.includes(admin.role)) return next();
    return res.status(403).json({
      error: "Insufficient role",
      code: "ROLE_FORBIDDEN",
    });
  };
}

module.exports = {
  adminAuthMiddleware,
  requireRoles,
};
