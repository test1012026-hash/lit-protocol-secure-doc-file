import { GOOGLE_CLIENT_ID, EXTENSION_ID, GOOGLE_REDIRECT_URI } from "./config";

export function getGoogleRedirectUri() {
  return GOOGLE_REDIRECT_URI;
}

export function getGoogleOAuthSetup() {
  const runtimeId = chrome.runtime.id;
  const redirectUri = getGoogleRedirectUri();
  return {
    runtimeId,
    redirectUri,
    idMatches: runtimeId === EXTENSION_ID,
  };
}

// Uses the implicit flow to get back a Google ID token (a JWT) directly,
// since that's what the Lit Action and backend both need to verify identity.
export function googleSignIn() {
  return new Promise((resolve, reject) => {
    const { runtimeId, redirectUri, idMatches } = getGoogleOAuthSetup();
    if (!idMatches) {
      return reject(
        new Error(
          `Extension ID mismatch. Loaded as ${runtimeId}, expected ${redirectUri.replace("https://", "").replace(".chromiumapp.org", "")}. Reload the extension from chrome://extensions after rebuilding.`,
        ),
      );
    }

    const nonce = crypto.randomUUID();
    const authUrl =
      "https://accounts.google.com/o/oauth2/v2/auth" +
      `?client_id=${GOOGLE_CLIENT_ID}` +
      "&response_type=id_token" +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent("openid email profile")}` +
      `&nonce=${nonce}`;

    chrome.identity.launchWebAuthFlow(
      { url: authUrl, interactive: true },
      (redirectUrl) => {
        if (chrome.runtime.lastError || !redirectUrl) {
          const err = chrome.runtime.lastError;
          const message = err?.message || "Google sign-in was cancelled";
          if (/redirect_uri_mismatch/i.test(message)) {
            return reject(
              new Error(
                `${message}. In Google Cloud Console, replace any old chromiumapp.org URI with: ${redirectUri}`,
              ),
            );
          }
          return reject(err || new Error(message));
        }
        const hash = redirectUrl.split("#")[1] || "";
        const params = new URLSearchParams(hash);
        const idToken = params.get("id_token");
        if (!idToken) return reject(new Error("No id_token returned"));
        resolve(idToken);
      },
    );
  });
}
