const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const PROVIDERS = ["google", "microsoft", "yahoo"];

function jwtSecret() {
  return process.env.JWT_SECRET || "dev-secret-change-me";
}

function apiPublicBase() {
  return String(
    process.env.ADMIN_OAUTH_CALLBACK_BASE ||
      process.env.APP_URL ||
      "http://localhost:4000",
  ).replace(/\/$/, "");
}

/** Origins allowed to complete SSO and receive the session redirect. */
function allowedReturnOrigins() {
  const raw = [
    process.env.ADMIN_OAUTH_RETURN_ORIGINS,
    process.env.CORS_ORIGINS,
    process.env.ADMIN_APP_URL,
  ]
    .filter(Boolean)
    .join(",");
  const list = raw
    .split(",")
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);
  // Local admin panel default
  if (!list.includes("http://localhost:5174")) {
    list.push("http://localhost:5174");
  }
  return [...new Set(list)];
}

function isAllowedReturnOrigin(origin) {
  if (!origin) return false;
  const normalized = String(origin).trim().replace(/\/$/, "");
  return allowedReturnOrigins().includes(normalized);
}

function providerConfig(provider) {
  if (provider === "microsoft") {
    console.log("process.env.ADMIN_OAUTH_MICROSOFT_TENANT",process.env.ADMIN_OAUTH_MICROSOFT_TENANT);
    console.log("process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_ID",process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_ID);
    console.log("process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_SECRET",process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_SECRET);
    const clientId = process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_ID;
    const clientSecret = process.env.ADMIN_OAUTH_MICROSOFT_CLIENT_SECRET;
    const tenant = process.env.ADMIN_OAUTH_MICROSOFT_TENANT || "common";
    if (!clientId || !clientSecret) return null;
    return {
      provider: "microsoft",
      clientId,
      clientSecret,
      authUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
      tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      userInfoUrl: "https://graph.microsoft.com/v1.0/me",
      scopes: ["openid", "email", "profile", "User.Read"],
    };
  }

  if (provider === "google") {
    console.log("process.env.ADMIN_OAUTH_GOOGLE_CLIENT_ID",process.env.ADMIN_OAUTH_GOOGLE_CLIENT_ID);
    const clientId =
      process.env.ADMIN_OAUTH_GOOGLE_CLIENT_ID ||
      process.env.GOOGLE_GMAIL_CLIENT_ID ||
      process.env.GOOGLE_CLIENT_ID;
    const clientSecret =
      process.env.ADMIN_OAUTH_GOOGLE_CLIENT_SECRET ||
      process.env.GOOGLE_GMAIL_CLIENT_SECRET;
    if (!clientId || !clientSecret) return null;
    return {
      provider: "google",
      clientId,
      clientSecret,
      authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
      scopes: ["openid", "email", "profile"],
    };
  }



  if (provider === "yahoo") {
    const clientId = process.env.ADMIN_OAUTH_YAHOO_CLIENT_ID;
    const clientSecret = process.env.ADMIN_OAUTH_YAHOO_CLIENT_SECRET;
    if (!clientId || !clientSecret) return null;
    return {
      provider: "yahoo",
      clientId,
      clientSecret,
      authUrl: "https://api.login.yahoo.com/oauth2/request_auth",
      tokenUrl: "https://api.login.yahoo.com/oauth2/get_token",
      userInfoUrl: "https://api.login.yahoo.com/openid/v1/userinfo",
      scopes: ["openid", "email", "profile"],
    };
  }

  return null;
}

function configuredProviders() {
  return PROVIDERS.filter((p) => Boolean(providerConfig(p)));
}

/**
 * Callback URI registered at the IdP.
 * Strategy 1 (multi-domain, single key): each admin origin's /api/.../callback
 * so cookies stick to that domain (via Vite/nginx proxy).
 * Hub mode: single API callback URI.
 */
function callbackUri(provider, returnOrigin) {
  const mode = String(process.env.ADMIN_OAUTH_CALLBACK_MODE || "per_origin")
    .trim()
    .toLowerCase();
  if (mode === "hub") {
    return `${apiPublicBase()}/api/admin/auth/oauth/${provider}/callback`;
  }
  const origin = String(returnOrigin || "").replace(/\/$/, "");
  if (!origin) {
    return `${apiPublicBase()}/api/admin/auth/oauth/${provider}/callback`;
  }
  return `${origin}/api/admin/auth/oauth/${provider}/callback`;
}

function signState(payload) {
  return jwt.sign(payload, jwtSecret(), { expiresIn: "15m" });
}

function verifyState(token) {
  return jwt.verify(token, jwtSecret());
}

function buildAuthorizeUrl(
  provider,
  { returnOrigin, returnPath = "/", intent = "login", acceptTerms = false },
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

  const redirectUri = callbackUri(provider, returnOrigin);
  const state = signState({
    p: provider,
    o: returnOrigin.replace(/\/$/, ""),
    path: returnPath.startsWith("/") ? returnPath : "/",
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

async function exchangeCode(provider, code, redirectUri) {
  const cfg = providerConfig(provider);
  if (!cfg) throw new Error(`${provider} SSO is not configured`);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
  });

  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (provider === "yahoo") {
    const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString(
      "base64",
    );
    headers.Authorization = `Basic ${basic}`;
  }

  const res = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers,
    body,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(
      data.error_description || data.error || "Token exchange failed",
    );
    err.status = 401;
    err.code = "OAUTH_TOKEN_EXCHANGE";
    err.detail = data;
    throw err;
  }
  return data;
}

async function fetchProfile(provider, accessToken) {
  const cfg = providerConfig(provider);
  if (!cfg) throw new Error(`${provider} SSO is not configured`);

  const res = await fetch(cfg.userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(
      data.error?.message || data.error || "Failed to load SSO profile",
    );
    err.status = 401;
    err.code = "OAUTH_PROFILE";
    throw err;
  }

  if (provider === "microsoft") {
    const email =
      data.mail ||
      data.userPrincipalName ||
      (Array.isArray(data.otherMails) ? data.otherMails[0] : null);
    return {
      email: email ? String(email).toLowerCase() : null,
      name: data.displayName || "",
      subject: data.id || null,
    };
  }

  return {
    email: data.email ? String(data.email).toLowerCase() : null,
    name: data.name || data.given_name || "",
    subject: data.sub || data.id || null,
  };
}

/** Short-lived ticket when callback runs on API hub (cross-origin cookie). */
function signSsoTicket(userUuid) {
  return jwt.sign({ typ: "admin_sso", uuid: userUuid }, jwtSecret(), {
    expiresIn: "5m",
  });
}

function verifySsoTicket(token) {
  const payload = jwt.verify(token, jwtSecret());
  if (payload.typ !== "admin_sso" || !payload.uuid) {
    const err = new Error("Invalid SSO ticket");
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
  signSsoTicket,
  verifySsoTicket,
  apiPublicBase,
};
