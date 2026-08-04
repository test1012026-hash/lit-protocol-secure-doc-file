import {
  DEMO_MODE,
  GOOGLE_CLIENT_ID,
  LIT_API_BASE,
  LIT_API_KEY,
  LIT_PKP_ID,
} from "./config";
import {
  hybridDecryptWithPrivateKey,
  hybridEncryptForPublicKey,
  loadPrivateKeyFromServer,
} from "./userKeys";

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const cleaned = String(base64 || "").replace(/\s+/g, "");
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export { bytesToBase64, base64ToBytes };

function stringToBase64(value) {
  return bytesToBase64(new TextEncoder().encode(value));
}

function writeUint32BE(view, offset, value) {
  view[offset] = (value >>> 24) & 0xff;
  view[offset + 1] = (value >>> 16) & 0xff;
  view[offset + 2] = (value >>> 8) & 0xff;
  view[offset + 3] = value & 0xff;
}

function readUint32BE(view, offset) {
  return (
    ((view[offset] << 24) |
      (view[offset + 1] << 16) |
      (view[offset + 2] << 8) |
      view[offset + 3]) >>>
    0
  );
}

/** Compact binary attachment (no nested base64) so ~25MB PDFs fit Gmail's 25MB cap. */
function encodeSdsbAttachment(payload, cipherBytes) {
  const meta = {
    version: 4,
    type: "secure-doc-share",
    kind: payload.kind,
    mode: payload.mode,
    keyScheme: payload.keyScheme || null,
    expectedEmail: payload.expectedEmail || null,
    recipientUuidHash: payload.recipientUuidHash,
    actionId: payload.actionId || null,
    filename: payload.filename,
    mimeType: payload.mimeType || "application/json",
    iv: payload.iv || null,
    wrappedKey: payload.wrappedKey || null,
  };
  const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
  const out = new Uint8Array(4 + 1 + 4 + metaBytes.length + 4 + cipherBytes.length);
  out[0] = 0x53; // S
  out[1] = 0x44; // D
  out[2] = 0x53; // S
  out[3] = 0x42; // B
  out[4] = 1; // format version
  writeUint32BE(out, 5, metaBytes.length);
  out.set(metaBytes, 9);
  const cipherOffset = 9 + metaBytes.length;
  writeUint32BE(out, cipherOffset, cipherBytes.length);
  out.set(cipherBytes, cipherOffset + 4);
  return out;
}

function parseSdsbAttachment(bytes) {
  if (
    bytes.length < 13 ||
    bytes[0] !== 0x53 ||
    bytes[1] !== 0x44 ||
    bytes[2] !== 0x53 ||
    bytes[3] !== 0x42
  ) {
    return null;
  }
  const formatVersion = bytes[4];
  if (formatVersion !== 1) {
    throw new Error("Unsupported SecureDocShare attachment format version.");
  }
  const metaLen = readUint32BE(bytes, 5);
  const metaStart = 9;
  const metaEnd = metaStart + metaLen;
  if (metaEnd + 4 > bytes.length) {
    throw new Error("Corrupt SecureDocShare attachment (metadata).");
  }
  let meta;
  try {
    meta = JSON.parse(new TextDecoder().decode(bytes.subarray(metaStart, metaEnd)));
  } catch {
    throw new Error("Corrupt SecureDocShare attachment metadata.");
  }
  const cipherLen = readUint32BE(bytes, metaEnd);
  const cipherStart = metaEnd + 4;
  const cipherEnd = cipherStart + cipherLen;
  if (cipherEnd > bytes.length) {
    throw new Error("Corrupt SecureDocShare attachment (ciphertext).");
  }
  const cipherBytes = bytes.subarray(cipherStart, cipherEnd);
  if (meta?.type !== "secure-doc-share" || !meta?.recipientUuidHash) {
    throw new Error("This is not a SecureDocShare encrypted package.");
  }
  return {
    ...meta,
    version: meta.version || 4,
    ciphertext: bytesToBase64(cipherBytes),
  };
}

/**
 * Parse uploaded attachment bytes (binary SDSB or legacy JSON).
 */
export function parseEncryptedPackageFromBytes(bytes) {
  const view =
    bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (!view.length) {
    throw new Error("Encrypted package is empty.");
  }

  const sdsb = parseSdsbAttachment(view);
  if (sdsb) return sdsb;

  // Legacy JSON / sds. text packages
  return parseEncryptedPackage(new TextDecoder().decode(view));
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function deriveKeyFromUuid(recipientUuid) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(recipientUuid),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("secure-doc-share-v1"),
      iterations: 120000,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptWithUuid(bytes, recipientUuid) {
  const key = await deriveKeyFromUuid(recipientUuid);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    bytes,
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    iv: bytesToBase64(iv),
  };
}

async function decryptWithUuid(ciphertext, iv, recipientUuid) {
  const key = await deriveKeyFromUuid(recipientUuid);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv) },
    key,
    base64ToBytes(ciphertext),
  );
  return new Uint8Array(plain);
}

async function callLitAction(code, jsParams) {
  const res = await fetch(`${LIT_API_BASE}/lit_action`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": LIT_API_KEY,
    },
    body: JSON.stringify({ code, js_params: jsParams }),
  });

  if (res.status === 402) {
    const errBody = await res.text().catch(() => "");
    throw new Error(
      `Lit account has insufficient credits (402). Add funds in the Chipotle Dashboard. Details: ${errBody}`,
    );
  }

  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`Lit Action HTTP ${res.status}: ${errBody}`);
  }

  const data = await res.json();
  if (data.has_error) {
    throw new Error(data.logs || "Lit Action execution failed");
  }

  if (typeof data.response === "string") {
    try {
      return JSON.parse(data.response);
    } catch {
      return data.response;
    }
  }
  return data.response;
}

/**
 * Fetch registered Lit Action IDs from Chipotle list_actions.
 */
export async function listLitActions() {
  if (!LIT_API_KEY) {
    throw new Error("VITE_LIT_API_KEY is required to list Lit actions.");
  }

  const fetchPage = async (pageNumber) => {
    const res = await fetch(
      `${LIT_API_BASE}/list_actions?page_number=${pageNumber}&page_size=10`,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          "X-Api-Key": LIT_API_KEY,
        },
      },
    );

    if (!res.ok) {
      const errBody = await res.text().catch(() => "");
      throw new Error(`list_actions HTTP ${res.status}: ${errBody}`);
    }

    const data = await res.json();
    return Array.isArray(data)
      ? data
      : Array.isArray(data?.actions)
        ? data.actions
        : [];
  };

  const first = (await fetchPage(0)).filter((a) => a?.id);
  if (first.length) return first;

  // Some dashboards use 1-based paging (as in the Chipotle curl example).
  return (await fetchPage(1)).filter((a) => a?.id);
}

/**
 * Get the Lit Action ID used for encrypt/decrypt binding.
 * Prefer a named action, otherwise the first registered action.
 */
export async function getLitActionId() {
  const actions = await listLitActions();
  if (!actions.length) {
    throw new Error(
      "No Lit actions found. Register an IPFS action in the Chipotle Dashboard first.",
    );
  }

  const named =
    actions.find((a) => /encrypt|secure|demo/i.test(String(a.name || ""))) ||
    actions[0];
  return named.id;
}

async function assertActionIdAllowed(actionId) {
  if (!actionId) {
    throw new Error("Encrypted package is missing Lit action id.");
  }

  try {
    const actions = await listLitActions();
    const ok = actions.some(
      (a) => String(a.id).toLowerCase() === String(actionId).toLowerCase(),
    );
    if (!ok) {
      throw new Error(
        "Lit action id is not registered on this account. Re-send the file or add the action in the Dashboard.",
      );
    }
  } catch (err) {
    // If Lit list_actions is unavailable, still allow RSA hybrid decrypt —
    // action id remains in the package for audit, keys unlock via UUID+actionId.
    if (/list_actions|LIT_API_KEY|HTTP|fetch|network/i.test(String(err.message || ""))) {
      console.warn("list_actions check skipped:", err.message);
      return;
    }
    throw err;
  }
}

/**
 * Encrypt message/file bytes for a recipient.
 * Demo mode: per-email AES key wrapped with recipient RSA public key (+ Lit action id).
 * Lit mode: UUID-AES then Lit PKP encrypt.
 */
export async function encryptForRecipient(
  messageBytes,
  recipientUuid,
  { publicKeySpki } = {},
) {
  if (!recipientUuid) {
    throw new Error("Recipient UUID is required for encryption");
  }

  const bytes =
    messageBytes instanceof Uint8Array
      ? messageBytes
      : new Uint8Array(messageBytes);

  const recipientUuidHash = await sha256Hex(recipientUuid);

  // Demo: public-key encrypt (new AES key every mail) + Lit action id binding.
  if (DEMO_MODE) {
    if (!publicKeySpki) {
      throw new Error(
        "Recipient has no public key. Re-send so keys can be created for them.",
      );
    }

    const actionId = await getLitActionId();
    const hybrid = await hybridEncryptForPublicKey(bytes, publicKeySpki);

    return {
      ciphertext: hybrid.ciphertext,
      iv: hybrid.iv,
      wrappedKey: hybrid.wrappedKey,
      recipientUuidHash,
      actionId,
      mode: "demo",
      keyScheme: "rsa-oaep+aes-gcm",
    };
  }

  // Lit mode: UUID-AES then Lit encrypt.
  const uuidEncrypted = await encryptWithUuid(bytes, recipientUuid);
  const litPayload = JSON.stringify({
    ciphertext: uuidEncrypted.ciphertext,
    iv: uuidEncrypted.iv,
  });

  const actionId = await getLitActionId();
  const code = `
    async function main({ pkpId, message }) {
      const ciphertext = await Lit.Actions.Encrypt({ pkpId, message });
      return { ciphertext };
    }
  `;

  const result = await callLitAction(code, {
    pkpId: LIT_PKP_ID,
    message: litPayload,
  });

  return {
    ciphertext: result.ciphertext,
    iv: null,
    wrappedKey: null,
    recipientUuidHash,
    actionId,
    mode: "lit",
  };
}

/**
 * Build plaintext bytes for one encrypted package.
 * Includes encrypted message text and/or PDF — at least one must be present.
 */
export async function buildContentPayloadBytes({ message, file }) {
  const raw = String(message || "").trim();
  const textOnly = raw
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  const payload = { version: 1 };

  if (textOnly) payload.message = raw;

  if (file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    payload.file = {
      filename: file.name,
      mimeType: file.type || "application/pdf",
      data: bytesToBase64(bytes),
    };
  }

  if (!payload.message && !payload.file) {
    throw new Error("Add a message or a PDF (or both).");
  }

  return new TextEncoder().encode(JSON.stringify(payload));
}

export function parseDecryptedContent(decryptedBytes, encryptedPackage = {}) {
  const mimeType = (encryptedPackage.mimeType || "").toLowerCase();
  const kind = encryptedPackage.kind;
  const filename = encryptedPackage.filename || "";

  // Unified JSON payload (message-only, file-only, or legacy bundle)
  if (
    kind === "bundle" ||
    kind === "message" ||
    kind === "file" ||
    mimeType === "application/json"
  ) {
    try {
      const obj = JSON.parse(new TextDecoder().decode(decryptedBytes));
      if (obj && (typeof obj.message === "string" || obj.file)) {
        return {
          message: typeof obj.message === "string" ? obj.message : null,
          file: obj.file
            ? {
                filename: obj.file.filename || "document.pdf",
                mimeType: obj.file.mimeType || "application/pdf",
                bytes: base64ToBytes(obj.file.data),
              }
            : null,
        };
      }
    } catch {
      // fall through to legacy handling
    }
  }

  // Legacy message package (raw text bytes)
  if (
    kind === "message" ||
    mimeType.startsWith("text/") ||
    filename.toLowerCase().endsWith(".txt")
  ) {
    return {
      message: new TextDecoder().decode(decryptedBytes),
      file: null,
    };
  }

  // Legacy PDF / file package
  return {
    message: null,
    file: {
      filename: filename || "document.pdf",
      mimeType: encryptedPackage.mimeType || "application/pdf",
      bytes: decryptedBytes,
    },
  };
}

export async function buildEncryptedPackage({
  ciphertext,
  iv,
  wrappedKey,
  recipientUuidHash,
  actionId,
  expectedEmail,
  filename,
  mimeType,
  mode,
  keyScheme,
  kind = "bundle",
}) {
  const safeFileName = filename || "secure-package.json";
  const encryptedName =
    safeFileName.replace(/\.[^./\\]+$/, "") || "secure-package";
  const payload = {
    version: 3,
    type: "secure-doc-share",
    kind,
    mode,
    keyScheme: keyScheme || null,
    expectedEmail,
    recipientUuidHash,
    actionId: actionId || null,
    filename: safeFileName,
    mimeType: mimeType || "application/json",
    ciphertext,
    iv,
    wrappedKey: wrappedKey || null,
  };

  const ext = kind === "file" ? "securepdf" : "securemsg";
  const result = {
    fileName: `${encryptedName}.${ext}`,
    text: JSON.stringify(payload, null, 2),
    base64: stringToBase64(JSON.stringify(payload)),
    cipherText: toCipherText(payload),
    attachmentBytes: null,
  };

  // File attachments: binary package (raw ciphertext) so 25MB PDFs fit Gmail's 25MB limit.
  // Message packages stay small JSON/base64.
  if (kind === "file" && ciphertext) {
    try {
      const cipherBytes = base64ToBytes(ciphertext);
      result.attachmentBytes = encodeSdsbAttachment(payload, cipherBytes);
      // Prefer binary for Gmail; keep base64 only as legacy fallback for tiny files.
      result.base64 = null;
    } catch {
      // Keep JSON base64 fallback if decode fails.
    }
  }

  return result;
}

/**
 * Pack package fields into one ciphertext string the user can copy/paste.
 */
export function toCipherText(pkg) {
  const raw = JSON.stringify({
    v: 3,
    mode: pkg.mode || "demo",
    kind: pkg.kind || "bundle",
    h: pkg.recipientUuidHash,
    a: pkg.actionId || null,
    ks: pkg.keyScheme || null,
    iv: pkg.iv || null,
    wk: pkg.wrappedKey || null,
    c: pkg.ciphertext,
  });
  return `sds.${stringToBase64(raw)}`;
}

function packageFromCipherPayload(o) {
  if (!o?.c || !o?.h) return null;
  const kind = o.kind || "bundle";
  return {
    version: o.v || 3,
    type: "secure-doc-share",
    kind,
    mode: o.mode || "demo",
    keyScheme: o.ks || o.keyScheme || null,
    recipientUuidHash: o.h,
    actionId: o.a || o.actionId || null,
    filename: kind === "file" ? "document.pdf" : "message.json",
    mimeType: "application/json",
    ciphertext: o.c,
    iv: o.iv || null,
    wrappedKey: o.wk || o.wrappedKey || null,
  };
}

export function parseEncryptedPackage(packageText) {
  let trimmed = String(packageText || "").trim();
  if (!trimmed) {
    throw new Error("Encrypted package is empty.");
  }

  // Email clients often insert spaces/newlines into long ciphertext.
  const compact = trimmed.replace(/\s+/g, "");
  if (compact.startsWith("sds.")) {
    trimmed = compact;
  }

  // Preferred: single ciphertext token (sds.<base64>)
  if (trimmed.startsWith("sds.")) {
    try {
      const raw = new TextDecoder().decode(base64ToBytes(trimmed.slice(4)));
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      if (parsed) return parsed;
    } catch {
      throw new Error(
        "Invalid ciphertext. Copy the full Message from the email (no missing characters).",
      );
    }
    throw new Error(
      "Invalid ciphertext. Copy the full Message from the email (no missing characters).",
    );
  }

  // Legacy SDS2|… token
  if (trimmed.startsWith("SDS2|")) {
    const parts = trimmed.split("|");
    if (parts.length < 6) {
      throw new Error("Invalid encrypted message token.");
    }
    const [, mode, kind, recipientUuidHash, ivPart, ...cipherParts] = parts;
    const ciphertext = cipherParts.join("|");
    const parsed = packageFromCipherPayload({
      mode,
      kind,
      h: recipientUuidHash,
      iv: !ivPart || ivPart === "-" ? null : ivPart,
      c: ciphertext,
    });
    if (parsed) return parsed;
    throw new Error("Invalid encrypted message token.");
  }

  // Full JSON package (from attachment file)
  if (trimmed.startsWith("{")) {
    let payload;
    try {
      payload = JSON.parse(trimmed);
    } catch {
      throw new Error("Invalid encrypted package JSON.");
    }
    if (payload?.type !== "secure-doc-share") {
      throw new Error("This is not a SecureDocShare encrypted package.");
    }
    if (!payload?.ciphertext) {
      throw new Error("Encrypted package is missing required fields.");
    }
    if (!payload?.recipientUuidHash) {
      throw new Error(
        "This encrypted package has no UUID lock. Ask the sender to re-send with the updated app.",
      );
    }
    return payload;
  }

  // Try bare base64 ciphertext blob (same payload as sds. without prefix)
  try {
    const raw = new TextDecoder().decode(base64ToBytes(trimmed));
    if (raw.startsWith("{")) {
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch {
    // ignore
  }

  throw new Error(
    "Paste the full ciphertext from the email Message (starts with sds.), or upload the attachment.",
  );
}

/**
 * Decrypt: demo uses MongoDB private key unlocked by uuid+Lit action id;
 * Lit mode uses Google + Lit + UUID-AES.
 */
export async function decryptForRecipient({
  encryptedPackage,
  recipientUuid,
  googleIdToken,
  authToken,
}) {
  if (!recipientUuid) {
    throw new Error("Your account UUID is missing. Log out and log in again.");
  }

  const uuidHash = await sha256Hex(recipientUuid);
  if (uuidHash !== encryptedPackage.recipientUuidHash) {
    throw new Error(
      "This file is locked to a different recipient UUID. You cannot decrypt it.",
    );
  }

  // Demo: unlock RSA private key from MongoDB, unwrap per-mail AES key.
  if (encryptedPackage.mode === "demo" || DEMO_MODE) {
    if (!encryptedPackage.iv) {
      throw new Error("Encrypted file is missing IV.");
    }

    if (encryptedPackage.actionId) {
      await assertActionIdAllowed(encryptedPackage.actionId);
    }

    if (encryptedPackage.wrappedKey) {
      if (!authToken) {
        throw new Error(
          "Auth token required to load your private key from the server.",
        );
      }
      try {
        const privateKey = await loadPrivateKeyFromServer(
          { uuid: recipientUuid, token: authToken },
          getLitActionId,
          encryptedPackage.actionId,
        );
        return await hybridDecryptWithPrivateKey(
          {
            ciphertext: encryptedPackage.ciphertext,
            iv: encryptedPackage.iv,
            wrappedKey: encryptedPackage.wrappedKey,
          },
          privateKey,
        );
      } catch (err) {
        const msg = String(err?.message || err);
        if (/OperationError|decrypt|unwrap|private key/i.test(msg)) {
          throw new Error(
            "Decrypt failed. Use the recipient account that owns this mail, ensure RSA keys exist (log out/in once), then re-send if keys were regenerated after this email.",
          );
        }
        throw err;
      }
    }

    // Legacy demo packages (UUID-only, no wrappedKey).
    return decryptWithUuid(
      encryptedPackage.ciphertext,
      encryptedPackage.iv,
      recipientUuid,
    );
  }

  if (encryptedPackage.actionId) {
    await assertActionIdAllowed(encryptedPackage.actionId);
  }

  const code = `
    async function main({ pkpId, ciphertext, googleIdToken, googleClientId }) {
      try {
        const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + googleIdToken);
        const payload = await res.json();

        const authorized = !!payload.email && payload.aud === googleClientId;

        if (!authorized) {
          return { authorized: false };
        }

        const plaintext = await Lit.Actions.Decrypt({ pkpId, ciphertext });
        return { authorized: true, plaintext };
      } catch (e) {
        return { authorized: false, error: String(e) };
      }
    }
  `;

  const result = await callLitAction(code, {
    pkpId: LIT_PKP_ID,
    ciphertext: encryptedPackage.ciphertext,
    googleIdToken,
    googleClientId: GOOGLE_CLIENT_ID,
  });

  if (!result?.authorized) {
    throw new Error(
      result?.error
        ? `Not authorized: ${result.error}`
        : "Not authorized to decrypt this file",
    );
  }

  const inner =
    typeof result.plaintext === "string"
      ? JSON.parse(result.plaintext)
      : result.plaintext;

  return decryptWithUuid(inner.ciphertext, inner.iv, recipientUuid);
}
