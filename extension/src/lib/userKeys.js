import { base64ToBytes } from "../utils/utils";
import { api } from "./api";

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** Passphrase = account UUID + VITE_LIT_ACTION_ID. */
export function buildKeyPassphrase(uuid, actionId) {
  const u = String(uuid || "").trim();
  const a = String(actionId || "").trim();
  if (!u || !a) {
    throw new Error(
      "UUID and Lit action id are required for the key passphrase.",
    );
  }
  return `${u}|${a}`;
}

async function deriveWrapKey(passphrase, saltBytes) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 120000,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function generateUserKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function exportPublicKeySpkiBase64(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToBase64(new Uint8Array(spki));
}

export async function importPublicKeySpkiBase64(spkiBase64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBytes(spkiBase64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

async function exportPrivateKeyPkcs8Base64(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return bytesToBase64(new Uint8Array(pkcs8));
}

async function importPrivateKeyPkcs8Base64(pkcs8Base64) {
  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBytes(pkcs8Base64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"],
  );
}

export async function wrapPrivateKeyPkcs8(pkcs8Base64, uuid, actionId) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapKey = await deriveWrapKey(buildKeyPassphrase(uuid, actionId), salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrapKey,
    new TextEncoder().encode(pkcs8Base64),
  );
  return {
    thor: bytesToBase64(new Uint8Array(encrypted)),
    hulk: bytesToBase64(iv),
    venom: bytesToBase64(salt),
  };
}

export async function unwrapPrivateKey({
  thor,
  hulk,
  venom,
  actionId,
  uuid,
}) {
  if (!thor || !hulk || !venom || !actionId) {
    throw new Error("Encrypted private key is incomplete, or Lit action id is missing.");
  }
  const salt = base64ToBytes(venom);
  const iv = base64ToBytes(hulk);
  const wrapKey = await deriveWrapKey(
    buildKeyPassphrase(uuid, actionId),
    salt,
  );
  let pkcs8Base64;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      wrapKey,
      base64ToBytes(thor),
    );
    pkcs8Base64 = new TextDecoder().decode(plain);
  } catch {
    throw new Error(
      "Cannot unlock private key. Passphrase needs your UUID and VITE_LIT_ACTION_ID.",
    );
  }
  return importPrivateKeyPkcs8Base64(pkcs8Base64);
}

function hasCompleteKeyBundle(data) {
  return Boolean(
    data?.iron &&
      data?.thor &&
      data?.hulk &&
      data?.venom,
  );
}

export async function provisionRecipientKeyPair({
  recipientEmail,
  recipientUuid,
  token,
  getLitActionId,
}) {
  if (!recipientEmail || !recipientUuid || !token) {
    throw new Error("Recipient email, UUID, and auth token are required.");
  }
  if (typeof getLitActionId !== "function") {
    throw new Error("getLitActionId is required.");
  }

  const actionId = await getLitActionId();
  const pair = await generateUserKeyPair();
  const iron = await exportPublicKeySpkiBase64(pair.publicKey);
  const pkcs8 = await exportPrivateKeyPkcs8Base64(pair.privateKey);
  const wrapped = await wrapPrivateKeyPkcs8(pkcs8, recipientUuid, actionId);

  const { data } = await api.provisionRecipientKeys(
    {
      recipientEmail,
      recipientUuid,
      iron,
      thor: wrapped.thor,
      hulk: wrapped.hulk,
      venom: wrapped.venom,
    },
    token,
  );

  return {
    iron: data.iron || iron,
    created: !data.alreadyProvisioned,
  };
}

/**
 * Create RSA keys if missing. Private key wrapped with uuid + VITE_LIT_ACTION_ID.
 * Never regenerates or overwrites an existing public/private key pair.
 */
const ensureKeyInflight = new Map();

export async function ensureUserKeyPair(auth, getLitActionId) {
  if (!auth?.uuid || !auth?.token) {
    throw new Error("Login required to set up encryption keys.");
  }
  if (typeof getLitActionId !== "function") {
    throw new Error("getLitActionId is required.");
  }

  // Already known on this session — do not touch server keys.
  if (auth.hasPublicKey) {
    return { iron: null, created: false, skipped: true };
  }

  const inflightKey = String(auth.uuid);
  if (ensureKeyInflight.has(inflightKey)) {
    return ensureKeyInflight.get(inflightKey);
  }

  const work = (async () => {
    const { data: existing } = await api.getMyKeys(auth.token);
    if (hasCompleteKeyBundle(existing)) {
      return {
        iron: existing.iron,
        created: false,
      };
    }

    const actionId = await getLitActionId();
    const pair = await generateUserKeyPair();
    const iron = await exportPublicKeySpkiBase64(pair.publicKey);
    const pkcs8 = await exportPrivateKeyPkcs8Base64(pair.privateKey);
    const wrapped = await wrapPrivateKeyPkcs8(pkcs8, auth.uuid, actionId);

    const { data: registered } = await api.registerKeys(
      {
        iron,
        thor: wrapped.thor,
        hulk: wrapped.hulk,
        venom: wrapped.venom,
      },
      auth.token,
    );

    // Server may have rejected overwrite if another request won the race.
    if (registered?.alreadyExists) {
      const { data: again } = await api.getMyKeys(auth.token);
      return {
        iron: again.iron || iron,
        created: false,
      };
    }

    return { iron, created: true };
  })();

  ensureKeyInflight.set(inflightKey, work);
  try {
    return await work;
  } finally {
    ensureKeyInflight.delete(inflightKey);
  }
}

/**
 * Unlock private key from MongoDB using uuid + VITE_LIT_ACTION_ID.
 */
export async function loadPrivateKeyFromServer(auth, getLitActionId, packageActionId) {
  if (!auth?.uuid || !auth?.token) {
    throw new Error("Login required to decrypt.");
  }
  if (typeof getLitActionId !== "function") {
    throw new Error("getLitActionId is required.");
  }

  const { data } = await api.getMyKeys(auth.token);
  if (!hasCompleteKeyBundle(data)) {
    throw new Error(
      "No complete RSA key pair on your account. Log out and log in again to generate keys, then ask the sender to re-send.",
    );
  }

  // Env action id; also try package action id as fallback.
  const liveActionId = await getLitActionId();
  const candidates = [...new Set([liveActionId, packageActionId].filter(Boolean))];

  let lastError;
  for (const actionId of candidates) {
    try {
      return await unwrapPrivateKey({
        thor: data.thor,
        hulk: data.hulk,
        venom: data.venom,
        actionId,
        uuid: auth.uuid,
      });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Cannot unlock private key.");
}

export async function hybridEncryptForPublicKey(plainBytes, publicKeySpkiBase64) {
  const publicKey = await importPublicKeySpkiBase64(publicKeySpkiBase64);
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes),
  );
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawAes,
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    iv: bytesToBase64(iv),
    wrappedKey: bytesToBase64(new Uint8Array(wrapped)),
  };
}

export async function hybridDecryptWithPrivateKey(
  { ciphertext, iv, wrappedKey },
  privateKey,
) {
  if (!privateKey) {
    throw new Error("Private key is required to decrypt.");
  }
  if (!wrappedKey) {
    throw new Error("Package is missing the wrapped message key (wk).");
  }

  let rawAes;
  try {
    rawAes = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64ToBytes(wrappedKey),
    );
  } catch {
    throw new Error(
      "RSA unwrap failed. This mail was encrypted for a different public key. Log in as the recipient and ask the sender to re-send after your keys were created.",
    );
  }

  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAes,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(iv) },
      aesKey,
      base64ToBytes(ciphertext),
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error(
      "AES decrypt failed. Ciphertext may be truncated — paste the full sds. token or upload the attachment.",
    );
  }
}
