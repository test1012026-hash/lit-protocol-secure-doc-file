const {
  verifySessionToken,
  sendRelogin,
  RELOGIN_STATUS,
} = require("../lib/tokens");

module.exports = async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({
      error: "Missing token",
      code: "TOKEN_MISSING",
    });
  }

  try {
    req.user = await verifySessionToken(token);
    next();
  } catch (err) {
    if (err.status === RELOGIN_STATUS || err.code === "TOKEN_EXPIRED" || err.code === "TOKEN_INVALID") {
      return sendRelogin(res, err.code || "RELOGIN_REQUIRED");
    }
    if (err.status === 403) {
      return res.status(403).json({ error: err.message, code: err.code });
    }
    return sendRelogin(res, "TOKEN_INVALID");
  }
};
