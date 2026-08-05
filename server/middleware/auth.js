const {
  verifyAccessToken,
} = require("../lib/tokens");

module.exports = function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({
      error: "Missing token",
      code: "TOKEN_MISSING",
    });
  }

  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Access token expired",
        code: "TOKEN_EXPIRED",
      });
    }
    return res.status(401).json({
      error: "Invalid or expired token",
      code: "TOKEN_INVALID",
    });
  }
};
