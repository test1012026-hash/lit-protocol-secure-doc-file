// Shared, dependency-free helpers used across the extension.

export function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function sanitizeHeaderValue(value) {
  return String(value || "")
    .replace(/[\r\n]+/g, " ")
    .trim();
}

/** True when a string appears to contain HTML markup. */
export function looksLikeHtml(text) {
  return /<\/?[a-z][\s\S]*>/i.test(String(text || ""));
}

export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(base64) {
  const cleaned = String(base64 || "").replace(/\s+/g, "");
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function getApiErrorMessage(err, fallback = "Something went wrong.") {
  return err?.response?.data?.error || err?.message || fallback;
}

export function getApiErrorCode(err) {
  return err?.response?.data?.code || err?.code || "";
}

export function toErrorStatus(err, fallback) {
  return `Error: ${getApiErrorMessage(err, fallback)}`;
}
