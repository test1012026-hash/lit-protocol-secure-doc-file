/**
 * SecureDocShare encrypt / decrypt (server-side).
 * Compatible with packages previously created in the extension (RSA-OAEP + AES-GCM).
 *
 * Env: LIT_ACTION_ID (same value as VITE_LIT_ACTION_ID in the extension)
 */
const crypto = require("crypto");

const PBKDF2_ITERATIONS = 120000;
const AES_KEY_BITS = 256;
const AES_IV_LEN = 12;
const GCM_TAG_LEN = 16;
const RSA_MODULUS_BITS = 2048;

function getActionId() {
  const id = String(process.env.LIT_ACTION_ID || "").trim();
  if (!id) {
    throw new Error("LIT_ACTION_ID is required on the server for encrypt/decrypt.");
  }
  return id;
}

function bytesToBase64(buf) {
  return Buffer.from(buf).toString("base64");
}

function base64ToBytes(b64) {
  const cleaned = String(b64 || "").replace(/\s+/g, "");
  return Buffer.from(cleaned, "base64");
}

function stringToBase64(value) {
  return Buffer.from(String(value ?? ""), "utf8").toString("base64");
}

function stripHtmlToText(html) {
  return String(html || "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function buildKeyPassphrase(uuid, actionId) {
  const u = String(uuid || "").trim();
  const a = String(actionId || "").trim();
  if (!u || !a) {
    throw new Error("UUID and Lit action id are required for the key passphrase.");
  }
  return `${u}|${a}`;
}

function deriveWrapKey(passphrase, saltBytes) {
  return crypto.pbkdf2Sync(
    passphrase,
    saltBytes,
    PBKDF2_ITERATIONS,
    AES_KEY_BITS / 8,
    "sha256",
  );
}

/** AES-GCM encrypt → base64(ciphertext || tag), matching Web Crypto. */
function aesGcmEncrypt(keyBuf, plainBuf, ivBuf) {
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, ivBuf);
  const enc = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]);
}

/** AES-GCM decrypt from Web Crypto style ciphertext||tag. */
function aesGcmDecrypt(keyBuf, cipherWithTag, ivBuf) {
  if (cipherWithTag.length < GCM_TAG_LEN) {
    throw new Error("Ciphertext too short.");
  }
  const data = cipherWithTag.subarray(0, cipherWithTag.length - GCM_TAG_LEN);
  const tag = cipherWithTag.subarray(cipherWithTag.length - GCM_TAG_LEN);
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, ivBuf);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function generateUserKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: RSA_MODULUS_BITS,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return {
    iron: bytesToBase64(publicKey),
    pkcs8Base64: bytesToBase64(privateKey),
  };
}

function wrapPrivateKeyPkcs8(pkcs8Base64, uuid, actionId) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(AES_IV_LEN);
  const wrapKey = deriveWrapKey(buildKeyPassphrase(uuid, actionId), salt);
  const encrypted = aesGcmEncrypt(
    wrapKey,
    Buffer.from(String(pkcs8Base64), "utf8"),
    iv,
  );
  return {
    thor: bytesToBase64(encrypted),
    hulk: bytesToBase64(iv),
    venom: bytesToBase64(salt),
  };
}

function unwrapPrivateKey({ thor, hulk, venom, actionId, uuid }) {
  if (!thor || !hulk || !venom || !actionId) {
    throw new Error(
      "Encrypted private key is incomplete, or Lit action id is missing.",
    );
  }
  const salt = base64ToBytes(venom);
  const iv = base64ToBytes(hulk);
  const wrapKey = deriveWrapKey(buildKeyPassphrase(uuid, actionId), salt);
  let pkcs8Base64;
  try {
    const plain = aesGcmDecrypt(wrapKey, base64ToBytes(thor), iv);
    pkcs8Base64 = plain.toString("utf8");
  } catch {
    throw new Error(
      "Cannot unlock private key. Passphrase needs your UUID and LIT_ACTION_ID.",
    );
  }
  return crypto.createPrivateKey({
    key: base64ToBytes(pkcs8Base64),
    format: "der",
    type: "pkcs8",
  });
}

function hybridEncryptForPublicKey(plainBytes, publicKeySpkiBase64) {
  const publicKey = crypto.createPublicKey({
    key: base64ToBytes(publicKeySpkiBase64),
    format: "der",
    type: "spki",
  });

  const aesKey = crypto.randomBytes(AES_KEY_BITS / 8);
  const iv = crypto.randomBytes(AES_IV_LEN);
  const plain = Buffer.isBuffer(plainBytes)
    ? plainBytes
    : Buffer.from(plainBytes);
  const encrypted = aesGcmEncrypt(aesKey, plain, iv);

  const wrapped = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );

  return {
    // Keep raw bytes for SDSB packaging — avoid base64 round-trips on large PDFs.
    ciphertextBytes: encrypted,
    ciphertext: null,
    iv: bytesToBase64(iv),
    wrappedKey: bytesToBase64(wrapped),
  };
}

function hybridDecryptWithPrivateKey({ ciphertext, iv, wrappedKey }, privateKey) {
  if (!privateKey) {
    throw new Error("Private key is required to decrypt.");
  }
  if (!wrappedKey) {
    throw new Error("Package is missing the wrapped message key (wk).");
  }

  let rawAes;
  try {
    rawAes = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      base64ToBytes(wrappedKey),
    );
  } catch {
    throw new Error(
      "RSA unwrap failed. This mail was encrypted for a different public key.",
    );
  }

  try {
    return aesGcmDecrypt(
      rawAes,
      base64ToBytes(ciphertext),
      base64ToBytes(iv),
    );
  } catch {
    throw new Error(
      "AES decrypt failed. Ciphertext may be truncated — paste the full sds. token or upload the attachment.",
    );
  }
}

function writeUint32BE(buf, offset, value) {
  buf.writeUInt32BE(value >>> 0, offset);
}

function readUint32BE(buf, offset) {
  return buf.readUInt32BE(offset);
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
  const metaBytes = Buffer.from(JSON.stringify(meta), "utf8");
  const out = Buffer.alloc(4 + 1 + 4 + metaBytes.length + 4 + cipherBytes.length);
  out[0] = 0x53;
  out[1] = 0x44;
  out[2] = 0x53;
  out[3] = 0x42;
  out[4] = 1;
  writeUint32BE(out, 5, metaBytes.length);
  metaBytes.copy(out, 9);
  const cipherOffset = 9 + metaBytes.length;
  writeUint32BE(out, cipherOffset, cipherBytes.length);
  cipherBytes.copy(out, cipherOffset + 4);
  return out;
}

function parseSdsbAttachment(bytes) {
  const view = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (
    view.length < 13 ||
    view[0] !== 0x53 ||
    view[1] !== 0x44 ||
    view[2] !== 0x53 ||
    view[3] !== 0x42
  ) {
    return null;
  }
  if (view[4] !== 1) {
    throw new Error("Unsupported SecureDocShare attachment format version.");
  }
  const metaLen = readUint32BE(view, 5);
  const metaStart = 9;
  const metaEnd = metaStart + metaLen;
  if (metaEnd + 4 > view.length) {
    throw new Error("Corrupt SecureDocShare attachment (metadata).");
  }
  let meta;
  try {
    meta = JSON.parse(view.subarray(metaStart, metaEnd).toString("utf8"));
  } catch {
    throw new Error("Corrupt SecureDocShare attachment metadata.");
  }
  const cipherLen = readUint32BE(view, metaEnd);
  const cipherStart = metaEnd + 4;
  const cipherEnd = cipherStart + cipherLen;
  if (cipherEnd > view.length) {
    throw new Error("Corrupt SecureDocShare attachment (ciphertext).");
  }
  const cipherBytes = view.subarray(cipherStart, cipherEnd);
  if (meta?.type !== "secure-doc-share" || !meta?.recipientUuidHash) {
    throw new Error("This is not a SecureDocShare encrypted package.");
  }
  return {
    ...meta,
    version: meta.version || 4,
    ciphertext: bytesToBase64(cipherBytes),
  };
}

function toCipherText(pkg) {
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
    const raw = base64ToBytes(b64).toString("utf8");
    const obj = JSON.parse(raw);
    return Boolean(packageFromCipherPayload(obj));
  } catch {
    return false;
  }
}

function extractSdsCiphertext(text) {
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

function parseEncryptedPackage(packageText) {
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
      const raw = base64ToBytes(trimmed.slice(4)).toString("utf8");
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      console.log("parsed", parsed);
      if (parsed) return parsed;
    } catch(e) {
      console.error("Error parsing encrypted package:", e);
      throw new Error(
        "Invalid ciphertext. Copy the full Message from the email (no missing characters).",
      );
    }
    throw new Error(
      "Invalid ciphertext. Copy the full Message from the email (no missing characters).",
    );
  }

  if (trimmed.startsWith("{")) {
    let payload;
    try {
      payload = JSON.parse(trimmed);
      console.log("payload", payload);
    } catch {
      throw new Error("Invalid encrypted package JSON.");
    }
    if (payload?.type !== "secure-doc-share") {
      throw new Error("This is not a SecureDocShare encrypted package.");
    }
    if (!payload?.ciphertext || !payload?.recipientUuidHash) {
      throw new Error("Encrypted package is missing required fields.");
    }
    return payload;
  }

  try {
    const raw = base64ToBytes(trimmed).toString("utf8");
    if (raw.startsWith("{")) {
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch {
    // fall through
  }

  throw new Error(
    "Paste the full ciphertext from the email Message (starts with sds.), or upload the attachment.",
  );
}

function parseEncryptedPackageFromBytes(bytes) {
  const view = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  if (!view.length) {
    throw new Error("Encrypted package is empty.");
  }
  const sdsb = parseSdsbAttachment(view);
  if (sdsb) return sdsb;
  return parseEncryptedPackage(view.toString("utf8"));
}

function buildContentPayloadBytes({ message, fileBase64, fileName, mimeType }) {
  const raw = String(message || "").trim();
  const textOnly = stripHtmlToText(raw);
  const payload = { version: 1 };

  if (textOnly) payload.message = raw;

  if (fileBase64) {
    payload.file = {
      filename: fileName || "document.pdf",
      mimeType: mimeType || "application/pdf",
      data: String(fileBase64).replace(/\s+/g, ""),
    };
  }

  if (!payload.message && !payload.file) {
    throw new Error("Add a message or a PDF (or both).");
  }

  return Buffer.from(JSON.stringify(payload), "utf8");
}

function parseDecryptedContent(decryptedBytes, encryptedPackage = {}) {
  const mimeType = (encryptedPackage.mimeType || "").toLowerCase();
  const kind = encryptedPackage.kind;
  const filename = encryptedPackage.filename || "";
  const buf = Buffer.isBuffer(decryptedBytes)
    ? decryptedBytes
    : Buffer.from(decryptedBytes);

  // Raw PDF packages (new fast path) — never UTF-8 the whole buffer.
  if (
    mimeType === "application/pdf" ||
    filename.toLowerCase().endsWith(".pdf")
  ) {
    return {
      message: null,
      file: {
        filename: filename || "document.pdf",
        mimeType: mimeType || "application/pdf",
        dataBase64: bytesToBase64(buf),
      },
    };
  }

  if (
    kind === "bundle" ||
    kind === "message" ||
    mimeType === "application/json"
  ) {
    try {
      const obj = JSON.parse(buf.toString("utf8"));
      if (obj && (typeof obj.message === "string" || obj.file)) {
        return {
          message: typeof obj.message === "string" ? obj.message : null,
          file: obj.file
            ? {
                filename: obj.file.filename || "document.pdf",
                mimeType: obj.file.mimeType || "application/pdf",
                dataBase64: obj.file.data,
              }
            : null,
        };
      }
    } catch {
      // fall through
    }
  }

  // Legacy file packages stored JSON (kind=file, mime=application/json).
  if (kind === "file") {
    try {
      const obj = JSON.parse(buf.toString("utf8"));
      if (obj?.file?.data) {
        return {
          message: typeof obj.message === "string" ? obj.message : null,
          file: {
            filename: obj.file.filename || "document.pdf",
            mimeType: obj.file.mimeType || "application/pdf",
            dataBase64: obj.file.data,
          },
        };
      }
    } catch {
      // fall through to raw bytes
    }
  }

  if (
    kind === "message" ||
    mimeType.startsWith("text/") ||
    filename.toLowerCase().endsWith(".txt")
  ) {
    return { message: buf.toString("utf8"), file: null };
  }

  return {
    message: null,
    file: {
      filename: filename || "document.pdf",
      mimeType: encryptedPackage.mimeType || "application/pdf",
      dataBase64: bytesToBase64(buf),
    },
  };
}

function buildEncryptedPackage({
  ciphertext,
  ciphertextBytes,
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

  const cipherBytes =
    ciphertextBytes ||
    (ciphertext ? base64ToBytes(ciphertext) : null);

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
    iv,
    wrappedKey: wrappedKey || null,
  };

  const ext = kind === "file" ? "securepdf" : "securemsg";

  // File packages: only build SDSB binary. Skipping text/base64/cipherText
  // avoids multi-copy of multi‑MB ciphertext (was the 3–4 min bottleneck).
  if (kind === "file" && cipherBytes) {
    const attachmentBytes = encodeSdsbAttachment(payload, cipherBytes);
    return {
      fileName: `${encryptedName}.${ext}`,
      text: null,
      base64: null,
      cipherText: null,
      attachmentBase64: bytesToBase64(attachmentBytes),
    };
  }

  // Message packages are small — keep sds. token for the email body.
  const ciphertextB64 = ciphertext || bytesToBase64(cipherBytes);
  const fullPayload = { ...payload, ciphertext: ciphertextB64 };
  return {
    fileName: `${encryptedName}.${ext}`,
    text: null,
    base64: stringToBase64(JSON.stringify(fullPayload)),
    cipherText: toCipherText(fullPayload),
    attachmentBase64: null,
  };
}

function encryptForRecipient(messageBytes, recipientUuid, { iron } = {}) {
  if (!recipientUuid) {
    throw new Error("Recipient UUID is required for encryption");
  }
  if (!iron) {
    throw new Error(
      "Recipient has no public key. Keys must be provisioned first.",
    );
  }

  const bytes = Buffer.isBuffer(messageBytes)
    ? messageBytes
    : Buffer.from(messageBytes);
  const recipientUuidHash = sha256Hex(recipientUuid);
  const actionId = getActionId();
  const hybrid = hybridEncryptForPublicKey(bytes, iron);

  return {
    ciphertextBytes: hybrid.ciphertextBytes,
    ciphertext: hybrid.ciphertext,
    iv: hybrid.iv,
    wrappedKey: hybrid.wrappedKey,
    recipientUuidHash,
    actionId,
    mode: "demo",
    keyScheme: "rsa-oaep+aes-gcm",
  };
}

function assertActionIdAllowed(actionId) {
  if (!actionId) {
    throw new Error("Encrypted package is missing Lit action id.");
  }
  const expected = getActionId();
  if (String(actionId).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(
      "Lit action id in this file does not match LIT_ACTION_ID. Re-send the file.",
    );
  }
}

function unlockPrivateKeyFromBundle(user, packageActionId) {
  const liveActionId = getActionId();
  const candidates = [
    ...new Set([liveActionId, packageActionId].filter(Boolean)),
  ];
  let lastError;
  for (const actionId of candidates) {
    try {
      return unwrapPrivateKey({
        thor: user.thor,
        hulk: user.hulk,
        venom: user.venom,
        actionId,
        uuid: user.uuid,
      });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Cannot unlock private key.");
}

function decryptForRecipient({ encryptedPackage, recipientUuid, user }) {
  if (!recipientUuid) {
    throw new Error("Your account UUID is missing. Log out and log in again.");
  }

  const uuidHash = sha256Hex(recipientUuid);
  if (uuidHash !== encryptedPackage.recipientUuidHash) {
    throw new Error(
      "This file is locked to a different recipient UUID. You cannot decrypt it.",
    );
  }
  if (!encryptedPackage.iv) {
    throw new Error("Encrypted file is missing IV.");
  }
  if (encryptedPackage.actionId) {
    assertActionIdAllowed(encryptedPackage.actionId);
  }
  if (!encryptedPackage.wrappedKey) {
    throw new Error(
      "Package is missing wrapped key. Re-send with the updated app.",
    );
  }
  if (!user?.thor || !user?.hulk || !user?.venom) {
    throw new Error(
      "No complete RSA key pair on your account. Log out and log in again to generate keys.",
    );
  }

  try {
    const privateKey = unlockPrivateKeyFromBundle(
      user,
      encryptedPackage.actionId,
    );
    return hybridDecryptWithPrivateKey(
      {
        ciphertext: encryptedPackage.ciphertext,
        iv: encryptedPackage.iv,
        wrappedKey: encryptedPackage.wrappedKey,
      },
      privateKey,
    );
  } catch (err) {
    const msg = String(err?.message || err);
    if (/OperationError|decrypt|unwrap|private key|RSA/i.test(msg)) {
      throw new Error(
        "Decrypt failed. Use the recipient account that owns this mail, ensure RSA keys exist (log out/in once), then re-send if keys were regenerated after this email.",
      );
    }
    throw err;
  }
}

/**
 * Create RSA key bundle for a user if missing.
 * Returns { iron, created, alreadyExists }
 */
function createKeyBundleForUuid(uuid) {
  const actionId = getActionId();
  const pair = generateUserKeyPair();
  const wrapped = wrapPrivateKeyPkcs8(pair.pkcs8Base64, uuid, actionId);
  return {
    iron: pair.iron,
    thor: wrapped.thor,
    hulk: wrapped.hulk,
    venom: wrapped.venom,
  };
}

/**
 * High-level: build encrypted message + optional file packages for one recipient.
 */
function encryptMailPayload({
  recipientUuid,
  recipientEmail,
  iron,
  message,
  fileBase64,
  fileName,
  mimeType,
}) {
  const hasMessage = Boolean(stripHtmlToText(message));
  const hasFile = Boolean(fileBase64);

  if (!hasMessage && !hasFile) {
    throw new Error("Add a message or a PDF (or both).");
  }

  const t0 = Date.now();
  let messageCipherText = null;
  let fileCipherText = null;
  let encryptedPackage = null;
  let contentKind = "file";

  if (hasMessage) {
    const messageBytes = buildContentPayloadBytes({
      message,
      fileBase64: null,
    });
    const encryptedMessage = encryptForRecipient(messageBytes, recipientUuid, {
      iron,
    });
    // Message packages need base64 ciphertext for the sds. email token.
    encryptedMessage.ciphertext = bytesToBase64(encryptedMessage.ciphertextBytes);
    const messagePackage = buildEncryptedPackage({
      ...encryptedMessage,
      expectedEmail: recipientEmail,
      filename: "message.json",
      mimeType: "application/json",
      kind: "message",
    });
    messageCipherText = messagePackage.cipherText || null;
    if (!hasFile) {
      encryptedPackage = messagePackage;
      contentKind = "message";
    }
  }

  if (hasFile) {
    // Fast path: encrypt raw PDF bytes (not JSON-wrapped base64).
    // Old path inflated size ~33% and forced huge string copies.
    const rawPdf = base64ToBytes(String(fileBase64).replace(/\s+/g, ""));
    const encryptedFile = encryptForRecipient(rawPdf, recipientUuid, {
      iron,
    });
    const packageName =
      String(fileName || "document").replace(/\.[^./\\]+$/, "") || "document";
    encryptedPackage = buildEncryptedPackage({
      ...encryptedFile,
      expectedEmail: recipientEmail,
      filename: fileName || `${packageName}.pdf`,
      mimeType: mimeType || "application/pdf",
      kind: "file",
    });
    // File packages are SDSB binary (base64); never reuse the message sds. token.
    fileCipherText =
      encryptedPackage.attachmentBase64 || encryptedPackage.base64 || null;
    contentKind = hasMessage ? "bundle" : "file";
  }

  console.log(
    `[encryptMailPayload] ${contentKind} in ${Date.now() - t0}ms` +
      (hasFile
        ? ` (pdf≈${Math.round((fileBase64.length * 0.75) / 1024 / 1024)}MB)`
        : ""),
  );

  return {
    messageCipherText,
    fileCipherText,
    contentKind,
    encryptedPackage,
  };
}

module.exports = {
  getActionId,
  sha256Hex,
  createKeyBundleForUuid,
  encryptMailPayload,
  encryptForRecipient,
  decryptForRecipient,
  parseEncryptedPackage,
  parseEncryptedPackageFromBytes,
  parseDecryptedContent,
  buildEncryptedPackage,
  extractSdsCiphertext,
  toCipherText,
  stripHtmlToText,
};
