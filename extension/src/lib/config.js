function env(key, fallback) {
  const value = import.meta.env[key];
  if (value !== undefined && value !== "") return value;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable: ${key}`);
}

export const API_BASE_URL = env("VITE_API_BASE_URL", "http://localhost:4000/api");
export const GOOGLE_CLIENT_ID = env("VITE_GOOGLE_CLIENT_ID");
export const EXTENSION_ID = env("VITE_EXTENSION_ID");
export const GOOGLE_REDIRECT_URI = `https://${EXTENSION_ID}.chromiumapp.org`;
export const LIT_NETWORK = env("VITE_LIT_NETWORK", "datil-dev");
export const LIT_API_KEY = env("VITE_LIT_API_KEY");
export const LIT_PKP_ID = env("VITE_LIT_PKP_ID");
export const POLYGON_PRIVATE_KEY = env("VITE_POLYGON_PRIVATE_KEY");
export const POLYGON_PRIVATE_ADDRESS = env("VITE_POLYGON_PRIVATE_ADDRESS");
export const POLYGON_PRIVATE_CHAIN_CODE = env("VITE_POLYGON_PRIVATE_CHAIN_CODE");
export const POLYGON_PRIVATE_PUBLIC_KEY = env("VITE_POLYGON_PRIVATE_PUBLIC_KEY");
export const POLYGON_PRIVATE_EXTENDED_KEY = env("VITE_POLYGON_PRIVATE_EXTENDED_KEY");
export const POLYGON_API_KEY = env("VITE_POLYGON_API_KEY");
export const POLYGON_SENDER_PRIVATE_KEY = env("VITE_POLYGON_SENDER_PRIVATE_KEY");
