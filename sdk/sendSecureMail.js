const DEFAULT_API_BASE = "https://server-nine-rosy.vercel.app/api";

function normalizeBaseUrl(url) {
  return String(url || DEFAULT_API_BASE).replace(/\/$/, "");
}

async function parseJsonResponse(res) {
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text || res.statusText || "Invalid JSON response" };
  }
  return data;
}

function failure(status, data = {}, fallbackError = "Request failed") {
  return {
    ok: false,
    status,
    error: data.error || data.message || fallbackError,
    code: data.code || null,
    data,
  };
}

function success(status, data = {}) {
  return {
    ok: true,
    status,
    error: null,
    code: null,
    data,
    ...data,
  };
}

async function apiRequest(baseUrl, path, { method = "GET", token, body } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await parseJsonResponse(res);
  return { res, data };
}

/**
 * Login and return access token (and user payload).
 */
async function loginSecureDoc({
  apiBaseUrl = DEFAULT_API_BASE,
  email,
  password,
} = {}) {
  const baseUrl = normalizeBaseUrl(apiBaseUrl);
  if (!email || !password) {
    return failure(400, {
      error: "email and password are required when token is not provided",
      code: "AUTH_REQUIRED",
    });
  }

  const { res, data } = await apiRequest(baseUrl, "/auth/login", {
    method: "POST",
    body: { email, password },
  });

  if (!res.ok || !data?.token) {
    return failure(
      res.status || 401,
      data || {},
      "Login failed — user may not exist or password is wrong",
    );
  }

  return success(res.status, {
    token: data.token,
    refreshToken: data.refreshToken || null,
    uuid: data.uuid,
    email: data.email,
    hasPublicKey: Boolean(data.hasPublicKey),
    subscriptionActive: Boolean(data.subscriptionActive),
    subscriptionExpiresAt: data.subscriptionExpiresAt || null,
  });
}

/**
 * Public — no login / no JWT.
 * Check whether an email has an account and a valid subscription.
 *
 * @example
 * const { checkSubscription } = require("./sendSecureMail");
 * const result = await checkSubscription({ email: "admin@gmail.com" });
 * // result.ok && result.subscriptionActive
 */
async function checkSubscription({
  apiBaseUrl = DEFAULT_API_BASE,
  email,
} = {}) {
  const baseUrl = normalizeBaseUrl(apiBaseUrl);
  if (!email) {
    return failure(400, {
      error: "Email is required",
      code: "EMAIL_REQUIRED",
    });
  }

  const qs = `?email=${encodeURIComponent(String(email).trim().toLowerCase())}`;
  const { res, data } = await apiRequest(
    baseUrl,
    `/public/subscription-check${qs}`,
  );

  if (res.status === 404 || data?.exists === false) {
    return failure(404, {
      error: data?.error || "No account found for this email",
      code: data?.code || "USER_NOT_FOUND",
      exists: false,
      subscriptionActive: false,
    });
  }

  if (!res.ok || data?.ok === false) {
    return failure(
      res.status || 500,
      data || {},
      data?.error || "Failed to check subscription",
    );
  }

  if (!data?.subscriptionActive) {
    return failure(403, {
      error:
        data?.code === "SUBSCRIBER_NOT_CLAIMED"
          ? "Account exists but has not been claimed yet"
          : "Subscription is expired or inactive",
      code: data?.code || "SUBSCRIPTION_EXPIRED",
      exists: true,
      claimed: Boolean(data.claimed),
      subscriptionActive: false,
      subscriptionExpiresAt: data?.subscriptionExpiresAt || null,
      subscriptionDaysLeft: data?.subscriptionDaysLeft ?? 0,
    });
  }

  return success(200, {
    exists: true,
    claimed: Boolean(data.claimed),
    subscriptionActive: true,
    subscriptionExpiresAt: data.subscriptionExpiresAt || null,
    subscriptionDaysLeft: data.subscriptionDaysLeft ?? null,
    code: data.code || "SUBSCRIPTION_ACTIVE",
  });
}




/**
 * Public — no login / no JWT.
 * Creates the recipient if missing, provisions RSA keys, encrypts
 * message and/or file so only that recipient can decrypt.
 *
 * Returns separate ciphertexts:
 *   messageCipherText — encrypted message (sds. token), or null
 *   fileCipherText    — encrypted file (SDSB base64), or null
 *
 * @example
 * const { encryptOnly } = require("./sendSecureMail");
 * const result = await encryptOnly({
 *   to: "receiver@gmail.com",
 *   message: "Hello",
 *   fileBase64: "...",
 *   fileName: "doc.pdf",
 * });
 * // result.messageCipherText, result.fileCipherText
 */
async function encryptOnly(options = {}) {
  const {
    apiBaseUrl = DEFAULT_API_BASE,
    to,
    receiverEmail,
    subject = "",
    message = "",
    fileBase64,
    fileContent,
    fileName,
    mimeType,
  } = options;

  const baseUrl = normalizeBaseUrl(apiBaseUrl);
  const recipient = to || receiverEmail;

  if (!recipient) {
    return failure(400, {
      error: "Recipient email (to) is required",
      code: "RECIPIENT_REQUIRED",
    });
  }

  const filePayload = fileBase64 || fileContent || null;
  const hasMessage = String(message || "").trim().length > 0;
  const hasFile = Boolean(filePayload);
  if (!hasMessage && !hasFile) {
    return failure(400, {
      error: "Add a message or a file (or both)",
      code: "CONTENT_REQUIRED",
    });
  }

  const { res, data } = await apiRequest(baseUrl, "/public/encrypt", {
    method: "POST",
    body: {
      to: recipient,
      subject,
      message: message || "",
      ...(filePayload
        ? {
            fileBase64: filePayload,
            fileName: fileName || "document.pdf",
            mimeType: mimeType || "application/pdf",
          }
        : {}),
    },
  });

  if (!res.ok || data?.ok === false) {
    return failure(
      res.status || 500,
      data || {},
      data?.error || "Encrypt failed",
    );
  }

  return success(res.status, {
    encrypted: true,
    recipientUuid: data.recipientUuid || null,
    recipientEmail: data.recipientEmail || null,
    recipientCreated: Boolean(data.recipientCreated),
    recipientClaimed: Boolean(data.recipientClaimed),
    keysCreated: Boolean(data.keysCreated),
    subscriptionActive: Boolean(data.subscriptionActive),
    subject: data.subject,
    contentKind: data.contentKind || null,
    messageCipherText: data.messageCipherText || null,
    fileCipherText: data.fileCipherText || null,
    attachment: data.attachment || null,
  });
}

/**
 * Public — no login / no JWT.
 * Decrypt message and/or file ciphertext for a recipient email
 * (uses the same RSA keys stored for that email).
 *
 * @example
 * const { decryptOnly } = require("./sendSecureMail");
 * const result = await decryptOnly({
 *   email: "receiver@gmail.com",
 *   messageCipherText: "sds....",
 *   fileCipherText: "<SDSB base64>",
 * });
 * // result.message, result.file
 */
async function decryptOnly(options = {}) {
  const {
    apiBaseUrl = DEFAULT_API_BASE,
    email,
    to,
    receiverEmail,
    messageCipherText,
    fileCipherText,
    packageText,
    packageBase64,
    encryptedMessage,
    encryptedFile,
    encryptedPdf,
  } = options;

  const baseUrl = normalizeBaseUrl(apiBaseUrl);
  const recipient = email || to || receiverEmail;

  if (!recipient) {
    return failure(400, {
      error: "Recipient email is required",
      code: "EMAIL_REQUIRED",
    });
  }

  const msgCipher =
    messageCipherText || packageText || encryptedMessage || null;
  const fileCipher =
    fileCipherText ||
    packageBase64 ||
    encryptedFile ||
    encryptedPdf ||
    null;

  if (!msgCipher && !fileCipher) {
    return failure(400, {
      error: "Provide messageCipherText and/or fileCipherText",
      code: "CIPHERTEXT_REQUIRED",
    });
  }

  const { res, data } = await apiRequest(baseUrl, "/public/decrypt", {
    method: "POST",
    body: {
      email: recipient,
      ...(msgCipher ? { messageCipherText: msgCipher } : {}),
      ...(fileCipher ? { fileCipherText: fileCipher } : {}),
    },
  });

  if (!res.ok || data?.ok === false) {
    return failure(
      res.status || 500,
      data || {},
      data?.error || "Decrypt failed",
    );
  }

  return success(res.status, {
    decrypted: true,
    recipientUuid: data.recipientUuid || null,
    recipientEmail: data.recipientEmail || null,
    recipientClaimed: Boolean(data.recipientClaimed),
    messageDecrypted: Boolean(data.messageDecrypted),
    fileDecrypted: Boolean(data.fileDecrypted),
    message: data.message || null,
    file: data.file || null,
    kind: data.kind || null,
    filename: data.filename || null,
  });
}

module.exports = {
  DEFAULT_API_BASE,
  encryptOnly,
  decryptOnly,
  loginSecureDoc,
  checkSubscription,
};

// ESM-friendly default when bundled / re-exported
module.exports.default = encryptOnly;
