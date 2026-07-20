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

export async function buildEncryptedPackage({
  ciphertext,
  iv,
  recipientUuidHash,
  expectedEmail,
  filename,
  mimeType,
  mode,
}) {
  const safeFileName = filename || "document.pdf";
  const encryptedName = safeFileName.replace(/\.[^./\\]+$/, "") || "document";
  const payload = {
    version: 2,
    type: "secure-doc-share",
    mode,
    expectedEmail,
    recipientUuidHash,
    filename: safeFileName,
    mimeType: mimeType || "application/pdf",
    ciphertext,
    iv,
  };

  return {
    fileName: `${encryptedName}.securepdf`,
    text: JSON.stringify(payload, null, 2),
    base64: stringToBase64(JSON.stringify(payload)),
  };
}

export function parseEncryptedPackage(packageText) {
  const payload = JSON.parse(packageText);
  if (payload?.type !== "secure-doc-share") {
    throw new Error("This file is not a SecureDocShare encrypted file.");
  }
  if (!payload?.ciphertext || !payload?.expectedEmail) {
    throw new Error("Encrypted file is missing required fields.");
  }
  if (!payload?.recipientUuidHash) {
    throw new Error(
      "This encrypted file has no UUID lock. Ask the sender to re-send with the updated app.",
    );
  }
  return payload;
}

/**
 * Decrypt only if logged-in user's UUID matches the hash locked in the package.
 */
export async function decryptForRecipient({
  encryptedPackage,
  recipientUuid,
  expectedEmail,
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

  if (
    encryptedPackage.expectedEmail.toLowerCase() !==
    expectedEmail.toLowerCase()
  ) {
    throw new Error("This encrypted file was sent to a different email address.");
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

  // Lit mode: Google gate + Lit decrypt, then UUID-AES decrypt
  const code = `
    async function main({ pkpId, ciphertext, googleIdToken, expectedEmail, googleClientId }) {
      try {
        const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + googleIdToken);
        const payload = await res.json();

        const authorized = !!payload.email &&
          payload.email.toLowerCase() === expectedEmail.toLowerCase() &&
          payload.aud === googleClientId;

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
    expectedEmail: encryptedPackage.expectedEmail,
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
