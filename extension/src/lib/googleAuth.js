import {
  GOOGLE_CLIENT_ID,
  GOOGLE_GMAIL_CLIENT_ID,
  EXTENSION_ID,
  FIREFOX_EXTENSION_ID,
  GOOGLE_REDIRECT_URI,
} from "./config";
import { api } from "./api";
import { saveAuth } from "./authStorage";

const GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send";
const GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const CONTACTS_READONLY_SCOPE =
  "https://www.googleapis.com/auth/contacts.readonly";
const OTHER_CONTACTS_READONLY_SCOPE =
  "https://www.googleapis.com/auth/contacts.other.readonly";

/** Gmail send/read + People API contacts (emails for autocomplete). */
export const GMAIL_OAUTH_SCOPES = [
  GMAIL_SEND_SCOPE,
  GMAIL_READONLY_SCOPE,
  CONTACTS_READONLY_SCOPE,
  OTHER_CONTACTS_READONLY_SCOPE,
].join(" ");

/** One-time Google login: identity + all Gmail/Contacts scopes. */
export const GOOGLE_FULL_LOGIN_SCOPES = [
  "openid",
  "email",
  "profile",
  GMAIL_SEND_SCOPE,
  GMAIL_READONLY_SCOPE,
  CONTACTS_READONLY_SCOPE,
  OTHER_CONTACTS_READONLY_SCOPE,
].join(" ");

export function isFirefoxExtension() {
  const id = String(chrome.runtime?.id || "");
  return id.includes("@") || id === FIREFOX_EXTENSION_ID;
}

export function getGoogleRedirectUri() {
  try {
    if (typeof chrome?.identity?.getRedirectURL === "function") {
      const url = chrome.identity.getRedirectURL();
      if (url) return url.replace(/\/$/, "");
    }
  } catch {
    // fall through
  }
  if (isFirefoxExtension()) {
    return `https://${String(chrome.runtime.id).replace(
      /[^a-z0-9]/gi,
      "-",
    )}.extensions.allizom.org`;
  }
  return GOOGLE_REDIRECT_URI;
}

export function getGoogleOAuthSetup() {
  const runtimeId = chrome.runtime.id;
  const redirectUri = getGoogleRedirectUri();
  const allowedIds = new Set(
    [EXTENSION_ID, FIREFOX_EXTENSION_ID].filter(Boolean),
  );
  return {
    runtimeId,
    redirectUri,
    clientId: GOOGLE_CLIENT_ID,
    gmailClientId: GOOGLE_GMAIL_CLIENT_ID,
    idMatches: allowedIds.has(runtimeId),
    isFirefox: isFirefoxExtension(),
  };
}

function assertExtensionId() {
  const { runtimeId, idMatches, redirectUri } = getGoogleOAuthSetup();
  if (!idMatches) {
    throw new Error(
      `Extension ID mismatch. Loaded as ${runtimeId}, expected ${EXTENSION_ID} (Chrome) or ${FIREFOX_EXTENSION_ID} (Firefox). Rebuild with the matching build and reload.`,
    );
  }
  return redirectUri;
}

function launchWebAuthFlow(authUrl) {
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl, interactive: true },
      (redirectUrl) => {
        if (chrome.runtime.lastError || !redirectUrl) {
          reject(
            new Error(
              chrome.runtime.lastError?.message ||
                "Google authorization cancelled",
            ),
          );
          return;
        }
        resolve(redirectUrl);
      },
    );
  });
}

function getLoginClientId() {
  return isFirefoxExtension() ? GOOGLE_GMAIL_CLIENT_ID : GOOGLE_CLIENT_ID;
}

export async function googleSignIn() {
  const redirectUri = assertExtensionId();
  const clientId = getLoginClientId();
  const nonce = crypto.randomUUID();
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(clientId)}` +
    "&response_type=id_token" +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent("openid email profile")}` +
    `&nonce=${nonce}`;

  try {
    const redirectUrl = await launchWebAuthFlow(authUrl);
    const hash = redirectUrl.split("#")[1] || "";
    const params = new URLSearchParams(hash);
    const idToken = params.get("id_token");
    if (!idToken) {
      throw new Error(
        params.get("error_description") ||
          params.get("error") ||
          "No id_token returned",
      );
    }
    return idToken;
  } catch (err) {
    if (/redirect_uri_mismatch/i.test(err.message)) {
      throw new Error(
        `${err.message}. In Google Cloud Console (Web OAuth client), add authorized redirect URI: ${redirectUri}`,
      );
    }
    throw err;
  }
}

/**
 * Google signup/login with all app scopes in one consent
 * (identity + Gmail send/read + Contacts). Returns auth code for the server.
 *
 * `forceConsent` re-shows the consent screen; only needed when the server has
 * no refresh token stored, since Google issues one just on the first grant.
 */
export async function googleSignInWithFullAccess({ forceConsent = false } = {}) {
  const redirectUri = assertExtensionId();
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(GOOGLE_GMAIL_CLIENT_ID)}` +
    "&response_type=code" +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(GOOGLE_FULL_LOGIN_SCOPES)}` +
    "&access_type=offline" +
    `&prompt=${forceConsent ? "consent" : "select_account"}` +
    "&include_granted_scopes=true";

  try {
    const redirectUrl = await launchWebAuthFlow(authUrl);
    const query = redirectUrl.split("?")[1]?.split("#")[0] || "";
    const params = new URLSearchParams(query);
    const code = params.get("code");
    if (!code) {
      throw new Error(
        params.get("error_description") ||
          params.get("error") ||
          "No authorization code returned from Google",
      );
    }
    return { code, redirectUri };
  } catch (err) {
    if (/redirect_uri_mismatch/i.test(err.message)) {
      throw new Error(
        `${err.message}. In Google Cloud Console (Web OAuth client), add authorized redirect URI: ${redirectUri}`,
      );
    }
    throw err;
  }
}

export function scopeHasContacts(scopeStr) {
  const s = String(scopeStr || "");
  return (
    s.includes("contacts.readonly") ||
    s.includes("contacts.other.readonly") ||
    s.includes("/auth/contacts")
  );
}

export function scopeHasGmailReadonly(scopeStr) {
  const s = String(scopeStr || "");
  return s.includes("gmail.readonly") || s.includes("gmail.modify");
}

/** Read granted scopes for an access token. */
export async function getAccessTokenScopes(accessToken) {
  const res = await fetch(
    `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${encodeURIComponent(accessToken)}`,
  );
  if (!res.ok) return "";
  const data = await res.json().catch(() => ({}));
  return String(data.scope || "");
}

async function classifyPeopleProbe(accessToken) {
  const res = await fetch(
    "https://people.googleapis.com/v1/people/me/connections?personFields=emailAddresses&pageSize=1",
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  if (res.ok || res.status === 404) {
    return { ok: true };
  }

  const text = await res.text().catch(() => "");
  let body = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {};
  }
  const msg = String(body?.error?.message || text || `HTTP ${res.status}`);

  if (/has not been used|is disabled|API has not been|SERVICE_DISABLED/i.test(msg)) {
    return {
      ok: false,
      code: "PEOPLE_API_DISABLED",
      message:
        "People API is disabled for your Google Cloud project. Open Google Cloud Console → APIs & Services → Enable “People API”, then try again.",
    };
  }

  if (
    /insufficient|ACCESS_TOKEN_SCOPE|Request had insufficient authentication scopes/i.test(
      msg,
    ) ||
    res.status === 401 ||
    res.status === 403
  ) {
    return {
      ok: false,
      code: "CONTACTS_SCOPE_REQUIRED",
      message:
        "Google Contacts permission is missing. Click “Allow Google Contacts” and approve Contacts access.",
    };
  }

  return { ok: false, code: "PEOPLE_API_ERROR", message: msg };
}

/**
 * Connect Gmail + Contacts. Returns { accessToken, ... }.
 * forceReconsent re-shows the consent screen to add missing scopes.
 */
export async function ensureGmailConnected(
  jwtToken,
  auth,
  { forceReconsent = false } = {},
) {
  if (!forceReconsent) {
    const { data: status } = await api.gmailStatus(jwtToken);
    if (status.gmailConnected) {
      return {
        accessToken: null,
        gmailConnected: true,
        scope: status.scope || "",
        reused: true,
      };
    }
  }

  const redirectUri = assertExtensionId();
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(GOOGLE_GMAIL_CLIENT_ID)}` +
    "&response_type=code" +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(GMAIL_OAUTH_SCOPES)}` +
    "&access_type=offline" +
    "&prompt=consent" +
    "&include_granted_scopes=true";

  const redirectUrl = await launchWebAuthFlow(authUrl);
  const query = redirectUrl.split("?")[1]?.split("#")[0] || "";
  const params = new URLSearchParams(query);
  const code = params.get("code");
  if (!code) {
    throw new Error(
      params.get("error_description") ||
        params.get("error") ||
        "No authorization code returned for Gmail/Contacts",
    );
  }

  const { data } = await api.exchangeGmailCode({ code, redirectUri }, jwtToken);
  if (!data.accessToken) {
    throw new Error("Google did not return an access token after consent.");
  }
  if (auth) {
    const updated = {
      ...auth,
      gmailConnected: true,
    };
    delete updated.accessToken;
    delete updated.scope;
    await saveAuth(updated);
  }

  const scope =
    data.scope || (await getAccessTokenScopes(data.accessToken)) || "";

  return {
    accessToken: data.accessToken,
    gmailConnected: true,
    scope,
    hasContactsScope: scopeHasContacts(scope),
    reused: false,
  };
}

const SCOPE_CACHE_KEY = "googleGrantedScopes";

async function readCachedScope() {
  try {
    const store = chrome.storage.session || chrome.storage.local;
    const data = await store.get(SCOPE_CACHE_KEY);
    return String(data?.[SCOPE_CACHE_KEY] || "");
  } catch {
    return "";
  }
}

async function cacheScope(scope) {
  if (!scope) return;
  try {
    const store = chrome.storage.session || chrome.storage.local;
    await store.set({ [SCOPE_CACHE_KEY]: scope });
  } catch {
    // cache is best-effort
  }
}

/**
 * Scopes the user already approved. Prefers what the server recorded at consent
 * time so we don't re-check (or re-prompt) on every popup open.
 */
async function resolveGrantedScope(serverScope, accessToken) {
  if (serverScope) {
    await cacheScope(serverScope);
    return serverScope;
  }
  const cached = await readCachedScope();
  if (cached) return cached;
  if (!accessToken) return "";
  const scope = await getAccessTokenScopes(accessToken);
  await cacheScope(scope);
  return scope;
}

function scopeRequiredError(message, code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

/**
 * Access token that can call People API.
 * Only asks for consent when Contacts was never granted, and only when
 * `interactive` (e.g. the user clicked "Allow Google Contacts").
 */
export async function getPeopleAccessToken(
  jwtToken,
  auth,
  { interactive = true } = {},
) {
  let accessToken = null;
  let serverScope = "";

  try {
    const { data } = await api.gmailSendToken(jwtToken);
    accessToken = data.accessToken || null;
    serverScope = data.scope || "";
  } catch {
    accessToken = null;
  }

  if (accessToken) {
    const scope = await resolveGrantedScope(serverScope, accessToken);
    if (scopeHasContacts(scope)) return accessToken;
  }

  if (!interactive) {
    throw scopeRequiredError(
      "Google Contacts permission is missing. Click “Allow Google Contacts” and approve Contacts access.",
      "CONTACTS_SCOPE_REQUIRED",
    );
  }

  const connected = await ensureGmailConnected(jwtToken, auth, {
    forceReconsent: true,
  });
  accessToken = connected.accessToken;
  if (!accessToken) {
    const { data } = await api.gmailSendToken(jwtToken);
    accessToken = data.accessToken;
    serverScope = data.scope || "";
  }

  const scope =
    connected.scope || serverScope || (await getAccessTokenScopes(accessToken));
  await cacheScope(scope);
  if (!scopeHasContacts(scope)) {
    throw scopeRequiredError(
      "Contacts scope was not granted. On the Google consent screen, allow “See and download your contacts” (and Other contacts), then try again.",
      "CONTACTS_SCOPE_REQUIRED",
    );
  }

  const probe = await classifyPeopleProbe(accessToken);
  if (!probe.ok && probe.code === "PEOPLE_API_DISABLED") {
    throw scopeRequiredError(probe.message, probe.code);
  }

  return accessToken;
}

/**
 * Access token that can read Gmail (list/open messages).
 * Re-consents only when gmail.readonly was never granted.
 */
export async function getMailboxAccessToken(jwtToken, auth) {
  let accessToken = null;
  let serverScope = "";

  try {
    const { data } = await api.gmailMailboxToken(jwtToken);
    accessToken = data.accessToken || null;
    serverScope = data.scope || "";
  } catch {
    accessToken = null;
  }

  if (accessToken) {
    const scope = await resolveGrantedScope(serverScope, accessToken);
    if (scopeHasGmailReadonly(scope)) return accessToken;
  }

  const connected = await ensureGmailConnected(jwtToken, auth, {
    forceReconsent: true,
  });
  accessToken = connected.accessToken;
  if (!accessToken) {
    const { data } = await api.gmailMailboxToken(jwtToken);
    accessToken = data.accessToken;
    serverScope = data.scope || "";
  }

  const scope =
    connected.scope || serverScope || (await getAccessTokenScopes(accessToken));
  await cacheScope(scope);
  if (!scopeHasGmailReadonly(scope)) {
    throw scopeRequiredError(
      "Gmail read permission is missing. On the Google consent screen, allow “Read your email” / View your email messages, then try again.",
      "GMAIL_READONLY_REQUIRED",
    );
  }

  return accessToken;
}
