/**
 * Per-mail SecureDocShare metadata: encrypted recipient email + UUID.
 * Appears as a separate section in every secure email; admins can paste
 * the token into the panel to resolve the user in the database.
 */
const {
  encryptEmail,
  decryptEmail,
  encryptUuid,
  decryptUuid,
  isEncryptedEmail,
  isEncryptedUuid,
} = require("./emailCrypto");
const { sha256Hex } = require("./secureCrypto");

const META_TOKEN_PREFIX = "sdmeta.v1.";

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Plain-mail Metadata HTML (full-width line + title + listed fields).
 * Never uses tables so Outlook/Gmail do not shrink the block.
 */
function formatMailMetadataHtml(meta) {
  const m = meta || {};
  const token = String(m.token || "").trim();
  const emailEnc = String(m.emailEnc || "").trim();
  const uuidEnc = String(m.uuidEnc || "").trim();
  const notice = String(m.mismatchNotice || "").trim();
  if (!token && !emailEnc && !uuidEnc) return "";

  return [
    '<div style="margin:16px 0 0 0;padding:12px 0 0 0;border-top:2px solid #0F766E;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5">',
    '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:700;color:#0F766E;margin:0 0 8px 0">Metadata</div>',
    notice
      ? `<div style="margin:0 0 8px 0;color:#B91C1C;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:700">${escapeHtml(notice)}</div>`
      : "",
    token
      ? `<div style="font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.5;margin:0 0 4px 0;word-break:break-all">${escapeHtml(token)}</div>`
      : "",
    emailEnc
      ? `<div style="font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.5;margin:0 0 4px 0;word-break:break-all">email: ${escapeHtml(emailEnc)}</div>`
      : "",
    uuidEnc
      ? `<div style="font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.5;margin:0;word-break:break-all">uuid: ${escapeHtml(uuidEnc)}</div>`
      : "",
    "</div>",
  ].join("");
}

/**
 * Build metadata for the mail recipient (locked-to user).
 * @returns {{ token, emailEnc, uuidEnc, messageUuidHash, textBlock, htmlBlock }}
 */
function buildMailMetadata({ email, uuid, messageUuidHash = null }) {
  const plainUuid = String(uuid || "").trim();
  const plainEmail = String(email || "").trim();
  const bindHash = plainUuid ? sha256Hex(plainUuid) : "";
  const incomingHash = String(messageUuidHash || "").trim().toLowerCase();
  const hashMismatch = Boolean(incomingHash && incomingHash !== bindHash);
  const mismatchNotice = hashMismatch
    ? `This mail is shown by this email ${plainEmail || "(unknown)"}`
    : "";

  const emailEnc = encryptEmail(plainEmail);
  const uuidEnc = encryptUuid(plainUuid);
  if (!emailEnc || !uuidEnc) {
    throw new Error("email and uuid are required for mail metadata");
  }
  const payload = JSON.stringify({
    e: emailEnc,
    u: uuidEnc,
    h: bindHash,
    v: 1,
    ...(hashMismatch
      ? { fallback: true, notice: mismatchNotice }
      : {}),
  });
  const token =
    META_TOKEN_PREFIX + Buffer.from(payload, "utf8").toString("base64url");

  const textBlock = [
    "",
    "",
    "Metadata",
    token,
    "email: " + emailEnc,
    "uuid: " + uuidEnc,
    hashMismatch ? "error: " + mismatchNotice : "",
    "",
  ]
    .filter((line, idx, arr) => !(line === "" && arr[idx - 1] === ""))
    .join("\n");

  // Plain mail style: full-width line, then Metadata title + listed fields (no table, no bind).
  const htmlBlock =
    "<br><br>" +
    formatMailMetadataHtml({
      token,
      emailEnc,
      uuidEnc,
      mismatchNotice: mismatchNotice || null,
    });

  return {
    token,
    emailEnc,
    uuidEnc,
    messageUuidHash: bindHash,
    hashMismatch,
    mismatchNotice: mismatchNotice || null,
    textBlock,
    htmlBlock,
  };
}

function extractMetaToken(raw) {
  const s = String(raw || "");
  const re = /sdmeta\.v1\.[A-Za-z0-9_-]+/;
  const m = re.exec(s);
  return m ? m[0] : "";
}

/**
 * Parse a pasted metadata token or full metadata section.
 * Returns encrypted fields + decrypted plain email/uuid when possible.
 */
function parseMailMetadata(raw) {
  const input = String(raw || "").trim();
  if (!input) {
    return { ok: false, error: "Metadata is empty" };
  }

  let emailEnc = null;
  let uuidEnc = null;
  let messageUuidHash = null;

  const token = extractMetaToken(input);
  if (token) {
    try {
      const b64 = token.slice(META_TOKEN_PREFIX.length);
      const json = Buffer.from(b64, "base64url").toString("utf8");
      const obj = JSON.parse(json);
      emailEnc = obj.e || null;
      uuidEnc = obj.u || null;
      messageUuidHash = obj.h || null;
    } catch (err) {
      return {
        ok: false,
        error: "Invalid sdmeta token: " + (err.message || String(err)),
      };
    }
  }

  if (!emailEnc) {
    const em = /(?:^|\n)\s*email:\s*(enc:v1:\S+)/i.exec(input);
    if (em) emailEnc = em[1].trim();
  }
  if (!uuidEnc) {
    const um = /(?:^|\n)\s*uuid:\s*(uid:v1:\S+)/i.exec(input);
    if (um) uuidEnc = um[1].trim();
  }
  if (!messageUuidHash) {
    const hm = /(?:^|\n)\s*bind:\s*([a-f0-9]{64})/i.exec(input);
    if (hm) messageUuidHash = hm[1].toLowerCase();
  }

  let mismatchNotice = null;
  const nm = /(?:^|\n)\s*error:\s*(This mail is shown by this email .+)/i.exec(
    input,
  );
  if (nm) mismatchNotice = nm[1].trim();
  if (!mismatchNotice) {
    const nm2 =
      /This mail is shown by this email\s+\S+/i.exec(input);
    if (nm2) mismatchNotice = nm2[0].trim();
  }

  // Allow pasting raw enc:v1 / uid:v1 lines only.
  if (!emailEnc && isEncryptedEmail(input)) emailEnc = input;
  if (!uuidEnc && isEncryptedUuid(input)) uuidEnc = input;

  if (!emailEnc && !uuidEnc) {
    return {
      ok: false,
      error:
        "No SecureDocShare metadata found. Paste the sdmeta.v1.… token or email:/uuid: lines.",
    };
  }

  let email = null;
  let uuid = null;
  const errors = [];
  if (emailEnc) {
    try {
      email = decryptEmail(emailEnc);
    } catch (err) {
      errors.push("email decrypt: " + (err.message || String(err)));
    }
  }
  if (uuidEnc) {
    try {
      uuid = decryptUuid(uuidEnc);
    } catch (err) {
      errors.push("uuid decrypt: " + (err.message || String(err)));
    }
  }

  return {
    ok: Boolean(email || uuid),
    token: token || null,
    emailEnc,
    uuidEnc,
    messageUuidHash,
    email,
    uuid,
    mismatchNotice,
    error: errors.length ? errors.join("; ") : null,
  };
}

module.exports = {
  META_TOKEN_PREFIX,
  buildMailMetadata,
  parseMailMetadata,
  extractMetaToken,
  formatMailMetadataHtml,
};
