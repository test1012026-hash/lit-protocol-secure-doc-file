function env(key, fallback) {
  const value = import.meta.env[key];
  if (value !== undefined && value !== "") {
    return String(value).trim().replace(/^["']|["']$/g, "");
  }
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable: ${key}`);
}

export const API_BASE_URL = env("VITE_API_BASE_URL", "http://localhost:4000/api");
export const GOOGLE_CLIENT_ID = env("VITE_GOOGLE_CLIENT_ID");
export const GOOGLE_GMAIL_CLIENT_ID = env("VITE_GOOGLE_GMAIL_CLIENT_ID");
export const EXTENSION_ID = env("VITE_EXTENSION_ID");
export const FIREFOX_EXTENSION_ID = env(
  "VITE_FIREFOX_EXTENSION_ID",
  "securedocshare@local.dev",
);
export const GOOGLE_REDIRECT_URI = `https://${EXTENSION_ID}.chromiumapp.org`;
export const LIT_ACTION_ID = env("VITE_LIT_ACTION_ID");
