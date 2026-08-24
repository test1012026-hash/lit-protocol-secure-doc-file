/**
 * User-facing OAuth (Outlook add-in / clients) — Google, Microsoft, Yahoo.
 * Reuses IdP client credentials from ADMIN_OAUTH_* (or USER_OAUTH_* overrides).
 * Callbacks are hub-style on APP_URL so Outlook (https://localhost:3000) does not need /api proxy.
 */
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const {
  PROVIDERS,
  configuredProviders,
  providerConfig,
  exchangeCode,
  fetchProfile,
  apiPublicBase,
} = require("./adminOAuth");

function jwtSecret() {
  return process.env.JWT_SECRET || "dev-secret-change-me";
}

function allowedReturnOrigins() {
  const raw = [
    process.env.OUTLOOK_OAUTH_RETURN_ORIGINS,
    process.env.USER_OAUTH_RETURN_ORIGINS,
    process.env.ADMIN_OAUTH_RETURN_ORIGINS,
    process.env.CORS_ORIGINS,
  ]
    .filter(Boolean)
    .join(",");
  const list = raw
    .split(",")
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);
  const defaults = [
    "https://localhost:3000",
    "http://localhost:5174",
    "https://localhost:5174",
  ];
  for (const d of defaults) {
    if (!list.includes(d)) list.push(d);
  }
  return [...new Set(list)];
}

function isAllowedReturnOrigin(origin) {
  if (!origin) return false;
  return allowedReturnOrigins().includes(
    String(origin).trim().replace(/\/$/, ""),
  );
}

/** Always hub callback on API host — register these URIs at each IdP. */
function callbackUri(provider) {
  return `${apiPublicBase()}/api/auth/oauth/${provider}/callback`;
}

function signState(payload) {
  return jwt.sign(payload, jwtSecret(), { expiresIn: "15m" });
}

function verifyState(token) {
  return jwt.verify(token, jwtSecret());
}

function buildAuthorizeUrl(
  provider,
  { returnOrigin, returnPath = "/oauth-dialog-callback.html", intent = "login", acceptTerms = false },
) {
  const cfg = providerConfig(provider);
  if (!cfg) {
    const err = new Error(`${provider} SSO is not configured`);
    err.status = 503;
    err.code = "OAUTH_NOT_CONFIGURED";
    throw err;
  }
  if (!isAllowedReturnOrigin(returnOrigin)) {
    const err = new Error("Return origin is not allowed for SSO");
    err.status = 400;
    err.code = "OAUTH_ORIGIN_FORBIDDEN";
    throw err;
  }

  const redirectUri = callbackUri(provider);
  const path = String(returnPath || "/oauth-dialog-callback.html");
  const state = signState({
    typ: "user_oauth",
    p: provider,
    o: String(returnOrigin).replace(/\/$/, ""),
    path: path.startsWith("/") ? path : `/${path}`,
    intent: intent === "signup" ? "signup" : "login",
    terms: Boolean(acceptTerms),
    n: crypto.randomBytes(16).toString("hex"),
  });

  const url = new URL(cfg.authUrl);
  url.searchParams.set("client_id", cfg.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", cfg.scopes.join(" "));
  url.searchParams.set("state", state);
  if (provider === "google") {
    url.searchParams.set("access_type", "online");
    url.searchParams.set("prompt", "select_account");
  }
  if (provider === "microsoft") {
    url.searchParams.set("response_mode", "query");
  }

  return { url: url.toString(), redirectUri, state };
}

/** One-time ticket → exchanged for user JWT in the Outlook dialog. */
function signUserOAuthTicket(userUuid) {
  return jwt.sign({ typ: "user_oauth_ticket", uuid: userUuid }, jwtSecret(), {
    expiresIn: "5m",
  });
}

function verifyUserOAuthTicket(token) {
  const payload = jwt.verify(token, jwtSecret());
  if (payload.typ !== "user_oauth_ticket" || !payload.uuid) {
    const err = new Error("Invalid OAuth ticket");
    err.status = 401;
    err.code = "OAUTH_TICKET_INVALID";
    throw err;
  }
  return payload;
}

module.exports = {
  PROVIDERS,
  configuredProviders,
  providerConfig,
  isAllowedReturnOrigin,
  allowedReturnOrigins,
  callbackUri,
  buildAuthorizeUrl,
  verifyState,
  exchangeCode,
  fetchProfile,
  signUserOAuthTicket,
  verifyUserOAuthTicket,
  apiPublicBase,
};
