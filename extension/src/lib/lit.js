import {
  DEMO_MODE,
  GOOGLE_CLIENT_ID,
  LIT_API_BASE,
  LIT_API_KEY,
  LIT_PKP_ID,
} from "./config";

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export { bytesToBase64, base64ToBytes };

function stringToBase64(value) {
  return bytesToBase64(new TextEncoder().encode(value));
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
 * Encrypt PDF bytes with a key derived from the recipient UUID.
 * Without that UUID, the file cannot be decrypted (ChatGPT/others cannot open it).
 */
export async function encryptForRecipient(messageBytes, recipientUuid) {
  if (!recipientUuid) {
    throw new Error("Recipient UUID is required for encryption");
  }

  const bytes =
    messageBytes instanceof Uint8Array
      ? messageBytes
      : new Uint8Array(messageBytes);

  const uuidEncrypted = await encryptWithUuid(bytes, recipientUuid);

  // Demo mode: UUID-AES only (still real crypto — not plain base64).
  if (DEMO_MODE) {
    return {
      ciphertext: uuidEncrypted.ciphertext,
      iv: uuidEncrypted.iv,
      recipientUuidHash: await sha256Hex(recipientUuid),
      mode: "demo",
    };
  }

  // Lit mode: encrypt UUID-AES payload further with Lit, then gate decrypt with Google email.
  const litPayload = JSON.stringify({
    ciphertext: uuidEncrypted.ciphertext,
    iv: uuidEncrypted.iv,
  });

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
    recipientUuidHash: await sha256Hex(recipientUuid),
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
  recipientUuidHash,
  expectedEmail,
  filename,
  mimeType,
  mode,
  kind = "bundle",
}) {
  const safeFileName = filename || "secure-package.json";
  const encryptedName =
    safeFileName.replace(/\.[^./\\]+$/, "") || "secure-package";
  const payload = {
    version: 2,
    type: "secure-doc-share",
    kind,
    mode,
    // Delivery metadata only — decrypt is gated by recipientUuidHash, not email.
    expectedEmail,
    recipientUuidHash,
    filename: safeFileName,
    mimeType: mimeType || "application/json",
    ciphertext,
    iv,
  };

  const ext = kind === "file" ? "securepdf" : "securemsg";
  return {
    fileName: `${encryptedName}.${ext}`,
    text: JSON.stringify(payload, null, 2),
    base64: stringToBase64(JSON.stringify(payload)),
    // Opaque string for email Message body / Receive → Paste ciphertext.
    cipherText: toCipherText(payload),
  };
}

/**
 * Pack package fields into one ciphertext string the user can copy/paste.
 * Looks like normal ciphertext — not pretty JSON.
 */
export function toCipherText(pkg) {
  const raw = JSON.stringify({
    v: 2,
    mode: pkg.mode || "demo",
    kind: pkg.kind || "bundle",
    h: pkg.recipientUuidHash,
    iv: pkg.iv || null,
    c: pkg.ciphertext,
  });
  return `sds.${stringToBase64(raw)}`;
}

function packageFromCipherPayload(o) {
  if (!o?.c || !o?.h) return null;
  const kind = o.kind || "bundle";
  return {
    version: 2,
    type: "secure-doc-share",
    kind,
    mode: o.mode || "demo",
    recipientUuidHash: o.h,
    filename: kind === "file" ? "document.pdf" : "message.json",
    // Message/file payloads are JSON wrappers; only legacy raw PDFs used application/pdf.
    mimeType: "application/json",
    ciphertext: o.c,
    iv: o.iv || null,
  };
}

export function parseEncryptedPackage(packageText) {
  const trimmed = String(packageText || "").trim();
  if (!trimmed) {
    throw new Error("Encrypted package is empty.");
  }

  // Preferred: single ciphertext token (sds.<base64>)
  if (trimmed.startsWith("sds.")) {
    try {
      const raw = new TextDecoder().decode(base64ToBytes(trimmed.slice(4)));
      const parsed = packageFromCipherPayload(JSON.parse(raw));
      if (parsed) return parsed;
    } catch {
      throw new Error("Invalid ciphertext. Copy the full Message from the email.");
    }
    throw new Error("Invalid ciphertext. Copy the full Message from the email.");
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
 * Decrypt only if the logged-in user's UUID matches the package hash.
 * Email in the package is delivery metadata only — aliases must not block decrypt.
 */
export async function decryptForRecipient({
  encryptedPackage,
  recipientUuid,
  googleIdToken,
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

  // Demo / UUID layer
  if (encryptedPackage.mode === "demo" || DEMO_MODE) {
    if (!encryptedPackage.iv) {
      throw new Error("Encrypted file is missing IV.");
    }
    return decryptWithUuid(
      encryptedPackage.ciphertext,
      encryptedPackage.iv,
      recipientUuid,
    );
  }

  // Lit mode: require a valid Google session, then Lit decrypt + UUID-AES.
  // Do not compare emails — UUID is the recipient lock (alias-safe).
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
