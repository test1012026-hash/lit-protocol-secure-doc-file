import {
  GOOGLE_CLIENT_ID,
  GOOGLE_GMAIL_CLIENT_ID,
  EXTENSION_ID,
  GOOGLE_REDIRECT_URI,
} from "./config";
import { api } from "./api";
import { saveAuth } from "./authStorage";

const GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send";

export function getGoogleRedirectUri() {
  return GOOGLE_REDIRECT_URI;
}

export function getGoogleOAuthSetup() {
  const runtimeId = chrome.runtime.id;
  const redirectUri = getGoogleRedirectUri();
  return {
    runtimeId,
    redirectUri,
    clientId: GOOGLE_CLIENT_ID,
    gmailClientId: GOOGLE_GMAIL_CLIENT_ID,
    idMatches: runtimeId === EXTENSION_ID,
  };
}

function assertExtensionId() {
  const { runtimeId, idMatches } = getGoogleOAuthSetup();
  if (!idMatches) {
    throw new Error(
      `Extension ID mismatch. Loaded as ${runtimeId}, expected ${EXTENSION_ID}. Rebuild and reload the extension.`,
    );
  }
}

function launchWebAuthFlow(authUrl) {
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl, interactive: true },
      (redirectUrl) => {
        if (chrome.runtime.lastError || !redirectUrl) {
          reject(
            new Error(
              chrome.runtime.lastError?.message || "Google authorization cancelled",
            ),
          );
          return;
        }
        resolve(redirectUrl);
      },
    );
  });
}

/** Login + Lit identity — extension client, id_token in redirect hash. */
export async function googleSignIn() {
  assertExtensionId();
  const { redirectUri } = getGoogleOAuthSetup();
  const nonce = crypto.randomUUID();
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
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
        `${err.message}. In Google Cloud Console, open the Chrome extension OAuth client and ensure redirect URI: ${redirectUri}`,
      );
    }
    throw err;
  }
}

/**
 * Ask for Gmail once, store refresh token on server, then reuse silently.
 */
export async function ensureGmailConnected(jwtToken, auth) {
  const { data: status } = await api.gmailStatus(jwtToken);
  if (status.gmailConnected) {
    return true;
  }

  assertExtensionId();
  const { redirectUri } = getGoogleOAuthSetup();
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(GOOGLE_GMAIL_CLIENT_ID)}` +
    "&response_type=code" +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(GMAIL_SEND_SCOPE)}` +
    "&access_type=offline" +
    "&prompt=consent";

  const redirectUrl = await launchWebAuthFlow(authUrl);
  const query = redirectUrl.split("?")[1]?.split("#")[0] || "";
  const params = new URLSearchParams(query);
  const code = params.get("code");
  if (!code) {
    throw new Error(
      params.get("error_description") ||
        params.get("error") ||
        "No authorization code returned for Gmail",
    );
  }

  const { data } = await api.exchangeGmailCode({ code, redirectUri }, jwtToken);
  if (auth && data.gmailConnected) {
    const updated = { ...auth, gmailConnected: true };
    await saveAuth(updated);
  }
  return true;
}
