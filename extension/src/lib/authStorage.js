/**
 * Auth storage split:
 * - Profile (chrome.storage.local): non-sensitive account UI state
 * - Secrets (chrome.storage.session): JWTs / Google id token
 *   Session storage is cleared when the browser session ends and is not
 *   written to the durable local disk store like chrome.storage.local.
 *
 * Never persist Google OAuth accessToken or OAuth scope strings.
 */

const PROFILE_KEY = "authProfile";
const SECRETS_KEY = "authSecrets";
const LEGACY_AUTH_KEY = "auth";
const TAB_KEY = "activeTab";

const PROFILE_FIELDS = [
  "uuid",
  "email",
  "hasPassword",
  "hasPublicKey",
  "gmailConnected",
  "termsAndConditions",
  "loginMethod",
  "subscriptionActive",
  "subscriptionDaysLeft",
  "subscriptionExpiresAt",
  "subscriptionTrialDays",
];

const SECRET_FIELDS = ["token", "refreshToken", "googleIdToken"];

/** Fields that must never be persisted anywhere. */
const NEVER_STORE = new Set([
  "accessToken",
  "scope",
  "googleAccessToken",
  "gmailAccessToken",
]);

function pick(obj, keys) {
  const out = {};
  for (const key of keys) {
    if (obj?.[key] !== undefined) out[key] = obj[key];
  }
  return out;
}

function storageGet(area, keys) {
  return new Promise((resolve) => {
    const api = area === "session" ? chrome.storage.session : chrome.storage.local;
    if (!api?.get) {
      resolve({});
      return;
    }
    api.get(keys, (result) => resolve(result || {}));
  });
}

function storageSet(area, data) {
  return new Promise((resolve, reject) => {
    const api = area === "session" ? chrome.storage.session : chrome.storage.local;
    if (!api?.set) {
      resolve();
      return;
    }
    api.set(data, () => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve();
    });
  });
}

function storageRemove(area, keys) {
  return new Promise((resolve) => {
    const api = area === "session" ? chrome.storage.session : chrome.storage.local;
    if (!api?.remove) {
      resolve();
      return;
    }
    api.remove(keys, () => resolve());
  });
}

function mergeAuth(profile, secrets) {
  // Without session secrets, force re-login (profile alone is not enough).
  if (!secrets?.token && !secrets?.refreshToken) return null;
  return {
    ...(profile || {}),
    ...secrets,
  };
}

async function migrateLegacyAuthIfNeeded() {
  const local = await storageGet("local", [LEGACY_AUTH_KEY, PROFILE_KEY]);
  const legacy = local[LEGACY_AUTH_KEY];
  if (!legacy || local[PROFILE_KEY]) return;

  const profile = pick(legacy, PROFILE_FIELDS);
  const secrets = pick(legacy, SECRET_FIELDS);
  await storageSet("local", { [PROFILE_KEY]: profile });
  if (Object.keys(secrets).length) {
    await storageSet("session", { [SECRETS_KEY]: secrets });
  }
  await storageRemove("local", [LEGACY_AUTH_KEY]);
}

export async function getStoredAuth() {
  await migrateLegacyAuthIfNeeded();

  const [local, session] = await Promise.all([
    storageGet("local", [PROFILE_KEY, TAB_KEY]),
    storageGet("session", [SECRETS_KEY]),
  ]);

  return {
    auth: mergeAuth(local[PROFILE_KEY], session[SECRETS_KEY]),
    tab: local[TAB_KEY] === "receive" ? "receive" : "send",
  };
}

export async function saveAuth(auth) {
  if (!auth) {
    await clearAuth();
    return;
  }

  const cleaned = { ...auth };
  for (const key of NEVER_STORE) {
    delete cleaned[key];
  }

  const profile = pick(cleaned, PROFILE_FIELDS);
  const secrets = pick(cleaned, SECRET_FIELDS);

  // Preserve existing secrets when callers only update profile fields.
  const existingSession = await storageGet("session", [SECRETS_KEY]);
  const nextSecrets = {
    ...(existingSession[SECRETS_KEY] || {}),
    ...secrets,
  };
  for (const key of NEVER_STORE) {
    delete nextSecrets[key];
  }

  await Promise.all([
    storageSet("local", { [PROFILE_KEY]: profile }),
    storageSet("session", { [SECRETS_KEY]: nextSecrets }),
    storageRemove("local", [LEGACY_AUTH_KEY]),
  ]);
}

export async function clearAuth() {
  await Promise.all([
    storageRemove("local", [PROFILE_KEY, LEGACY_AUTH_KEY]),
    storageRemove("session", [SECRETS_KEY]),
  ]);
}

export function saveActiveTab(tab) {
  chrome.storage.local.set({ [TAB_KEY]: tab });
}

/**
 * Notify when either profile or secrets change. Callback receives merged auth.
 */
export function onAuthChanged(callback) {
  const notify = async () => {
    const { auth } = await getStoredAuth();
    callback(auth);
  };

  const listener = (changes, area) => {
    if (area === "local" && (changes[PROFILE_KEY] || changes[LEGACY_AUTH_KEY])) {
      notify();
      return;
    }
    if (area === "session" && changes[SECRETS_KEY]) {
      notify();
    }
  };

  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}
