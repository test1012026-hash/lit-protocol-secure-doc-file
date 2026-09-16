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
 * Build metadata for the mail recipient (locked-to user).
 * @returns {{ token, emailEnc, uuidEnc, messageUuidHash, textBlock, htmlBlock }}
 */
function buildMailMetadata({ email, uuid, messageUuidHash = null }) {
  const plainUuid = String(uuid || "").trim();
  const bindHash = plainUuid ? sha256Hex(plainUuid) : "";
  const incomingHash = String(messageUuidHash || "").trim().toLowerCase();
  const hashMismatch = Boolean(incomingHash && incomingHash !== bindHash);

  const emailEnc = encryptEmail(email);
  const uuidEnc = encryptUuid(plainUuid);
  if (!emailEnc || !uuidEnc) {
    throw new Error("email and uuid are required for mail metadata");
  }
  const payload = JSON.stringify({ e: emailEnc, u: uuidEnc, h: bindHash, v: 1 });
  const token =
    META_TOKEN_PREFIX + Buffer.from(payload, "utf8").toString("base64url");

  const textBlock = [
    "",
    "",
    "",
    token,
    "email: " + emailEnc,
    "uuid: " + uuidEnc,
    "bind: " + bindHash,
    hashMismatch ? "bindSource: message_uuid_fallback" : "",
    "",
  ].join("\n");

  // Visually separate from message body — titled "Metadata"
  const htmlBlock = `
<br><br>
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:20px 0 8px;border-collapse:collapse;clear:both">
  <tr>
    <td style="border:2px solid #0f766e;background:#f0fdfa;padding:0;font-family:Arial,Helvetica,sans-serif">
      <div style="background:#0f766e;color:#ffffff;font-size:13px;font-weight:700;letter-spacing:0.04em;padding:8px 12px">
        Metadata
      </div>
      <div style="padding:12px">
        <div style="word-break:break-all;font-family:Consolas,monospace;font-size:11px;color:#134e4a;background:#ffffff;border:1px solid #99f6e4;padding:10px">
          ${escapeHtml(token)}
        </div>
        <div style="margin-top:10px;word-break:break-all;font-family:Consolas,monospace;font-size:10px;color:#475569">
          <div><b>email:</b> ${escapeHtml(emailEnc)}</div>
          <div style="margin-top:4px"><b>uuid:</b> ${escapeHtml(uuidEnc)}</div>
          <div style="margin-top:4px"><b>bind:</b> ${escapeHtml(bindHash)}</div>
          ${
            hashMismatch
              ? '<div style="margin-top:4px"><b>bindSource:</b> message_uuid_fallback</div>'
              : ""
          }
        </div>
        <p style="margin:10px 0 0;font-size:11px;color:#64748b">
          Separate from the message body — support / admin identity only. Not required to decrypt.
        </p>
      </div>
    </td>
  </tr>
</table>
`.trim();

  return { token, emailEnc, uuidEnc, messageUuidHash: bindHash, textBlock, htmlBlock };
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
    error: errors.length ? errors.join("; ") : null,
  };
}

module.exports = {
  META_TOKEN_PREFIX,
  buildMailMetadata,
  parseMailMetadata,
  extractMetaToken,
};
