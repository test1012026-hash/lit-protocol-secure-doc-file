const ADMIN_COOKIE = "admin_session";

function isSecureRequest(req) {
  if (process.env.COOKIE_SECURE === "true") return true;
  if (process.env.COOKIE_SECURE === "false") return false;
  return Boolean(req.secure || req.headers["x-forwarded-proto"] === "https");
}

function adminCookieOptions(req, { maxAgeMs } = {}) {
  const opts = {
    httpOnly: true,
    secure: isSecureRequest(req),
    sameSite: "lax",
    path: "/",
  };
  if (maxAgeMs != null) opts.maxAge = maxAgeMs;
  return opts;
}

function setAdminSessionCookie(req, res, token, expiresAt) {
  const maxAgeMs = expiresAt
    ? Math.max(0, new Date(expiresAt).getTime() - Date.now())
    : 8 * 60 * 60 * 1000;
  res.cookie(ADMIN_COOKIE, token, adminCookieOptions(req, { maxAgeMs }));
}

function clearAdminSessionCookie(req, res) {
  res.clearCookie(ADMIN_COOKIE, adminCookieOptions(req));
}

/** Prefer httpOnly cookie; fall back to Authorization Bearer (scripts/tools). */
function readAdminToken(req) {
  const fromCookie = req.cookies?.[ADMIN_COOKIE];
  if (fromCookie) return fromCookie;
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) return header.slice(7);
  return null;
}

module.exports = {
  ADMIN_COOKIE,
  setAdminSessionCookie,
  clearAdminSessionCookie,
  readAdminToken,
  adminCookieOptions,
};
