/**
 * Canonicalize emails so Gmail aliases map to one account/UUID.
 * - lowercase + trim
 * - googlemail.com → gmail.com
 * - gmail: ignore dots in local part, strip +tags
 */
function normalizeEmail(raw) {
  if (!raw || typeof raw !== "string") return "";

  const trimmed = raw.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return trimmed;

  let local = trimmed.slice(0, at);
  let domain = trimmed.slice(at + 1);

  if (domain === "googlemail.com") domain = "gmail.com";

  if (domain === "gmail.com") {
    const plus = local.indexOf("+");
    if (plus !== -1) local = local.slice(0, plus);
    local = local.replace(/\./g, "");
  }

  return `${local}@${domain}`;
}

module.exports = { normalizeEmail };
