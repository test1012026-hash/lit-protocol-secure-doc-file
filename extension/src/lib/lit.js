import { base64ToBytes, bytesToBase64 } from "../utils/utils";
import {
  LIT_ACTION_ID
} from "./config";
import {
  hybridDecryptWithPrivateKey,
  hybridEncryptForPublicKey,
  loadPrivateKeyFromServer,
} from "./userKeys";

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
  out[0] = 0x53;
  out[1] = 0x44;
  out[2] = 0x53;
  out[3] = 0x42;
  out[4] = 1;
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

export function parseEncryptedPackageFromBytes(bytes) {
  const view =
    bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (!view.length) {
    throw new Error("Encrypted package is empty.");
  }

  const sdsb = parseSdsbAttachment(view);
  if (sdsb) return sdsb;

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

export async function getLitActionId() {
  if (!LIT_ACTION_ID) {
    throw new Error("VITE_LIT_ACTION_ID is required in the extension env.");
  }
  return LIT_ACTION_ID;
}

async function assertActionIdAllowed(actionId) {
  if (!actionId) {
    throw new Error("Encrypted package is missing Lit action id.");
  }
  if (!LIT_ACTION_ID) {
    throw new Error("VITE_LIT_ACTION_ID is required in the extension env.");
  }
  if (String(actionId).toLowerCase() !== String(LIT_ACTION_ID).toLowerCase()) {
    throw new Error(
      "Lit action id in this file does not match VITE_LIT_ACTION_ID. Re-send the file.",
    );
  }
}

export async function encryptForRecipient(
  messageBytes,
  recipientUuid,
  { iron } = {},
) {
  if (!recipientUuid) {
    throw new Error("Recipient UUID is required for encryption");
  }

  const bytes =
    messageBytes instanceof Uint8Array
      ? messageBytes
      : new Uint8Array(messageBytes);

  const recipientUuidHash = await sha256Hex(recipientUuid);

    if (!iron) {
      throw new Error(
        "Recipient has no public key. Re-send so keys can be created for them.",
      );
    }

    const actionId = await getLitActionId();
    const hybrid = await hybridEncryptForPublicKey(bytes, iron);

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

  if (kind === "file" && ciphertext) {
    try {
      const cipherBytes = base64ToBytes(ciphertext);
      result.attachmentBytes = encodeSdsbAttachment(payload, cipherBytes);
      result.base64 = null;
    } catch {
      // Keep JSON base64 fallback if decode fails.
    }
  }

  return result;
}

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

function tryParseSdsBase64(b64) {
  try {
    const raw = new TextDecoder().decode(base64ToBytes(b64));
    const obj = JSON.parse(raw);
    return packageFromCipherPayload(obj) ? true : false;
  } catch {
    return false;
  }
}

export function extractSdsCiphertext(text) {
  const raw = String(text || "");
  const match = /sds\./i.exec(raw);
  if (!match) return null;

  let i = match.index + 4;
  let b64 = "";
  while (i < raw.length) {
    const ch = raw[i];
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if (/[A-Za-z0-9+/_\-]/.test(ch)) {
      b64 += ch;
      i += 1;
      continue;
    }
    if (ch === "=") {
      b64 += "=";
      i += 1;
      while (i < raw.length && /\s/.test(raw[i])) i += 1;
      if (raw[i] === "=") b64 += "=";
      break;
    }
    break;
  }

  if (b64.length < 8) return null;

  if (!tryParseSdsBase64(b64)) {
    let candidate = b64;
    while (candidate.length >= 8 && !tryParseSdsBase64(candidate)) {
      candidate = candidate.slice(0, -1);
    }
    if (!tryParseSdsBase64(candidate)) return null;
    b64 = candidate;
  }

  return `sds.${b64}`;
}

export function parseEncryptedPackage(packageText) {
  let trimmed = String(packageText || "").trim();
  if (!trimmed) {
    throw new Error("Encrypted package is empty.");
  }

  const extracted = extractSdsCiphertext(trimmed);
  if (extracted) {
    trimmed = extracted;
  } else {
    const compact = trimmed.replace(/\s+/g, "");
    if (compact.startsWith("sds.")) {
      trimmed = compact;
    }
  }

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

  try {
    const raw = new TextDecoder().decode(base64ToBytes(trimmed));
    if (raw.startsWith("{")) {
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch(err) {
    console.error("Invalid encrypted package JSON.",err);
  }

  throw new Error(
    "Paste the full ciphertext from the email Message (starts with sds.), or upload the attachment.",
  );
}

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

    return decryptWithUuid(
      encryptedPackage.ciphertext,
      encryptedPackage.iv,
      recipientUuid,
    );

}
