/**
 * Portable SecureDocShare helper for other repos.
 *
 * Copy this file into any Node 18+ / browser project that has `fetch`.
 *
 * Flow:
 *  1. Resolve auth (token, or email+password login)
 *  2. Confirm sender exists + subscription is active
 *  3. Call /api/files/secure-send → creates recipient if needed,
 *     encrypts message (+ optional PDF), sends encrypted Gmail
 *
 * @example
 * const { sendSecureMail } = require("./sendSecureMail");
 * const result = await sendSecureMail({
 *   email: "admin@gmail.com",
 *   password: "Test@123",
 *   to: "friend@example.com",
 *   subject: "Secure docs",
 *   message: "Please open in SecureDocShare",
 *   fileBase64: optionalPdfBase64, // omit if no PDF
 *   fileName: "invoice.pdf",
 * });
 * if (!result.ok) console.error(result.status, result.error, result.code);
 */

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
 * Check whether the authenticated sender exists and subscription is active.
 * Expired subscription → ok:false with status 403.
 */
async function checkSenderSubscription({
  apiBaseUrl = DEFAULT_API_BASE,
  token,
} = {}) {
  const baseUrl = normalizeBaseUrl(apiBaseUrl);
  if (!token) {
    return failure(401, {
      error: "Auth token is required",
      code: "AUTH_REQUIRED",
    });
  }

  const { res, data } = await apiRequest(baseUrl, "/auth/subscription", {
    token,
  });

  if (res.status === 404) {
    return failure(404, {
      error: data?.error || "User not found",
      code: "USER_NOT_FOUND",
    });
  }

  if (!res.ok) {
    return failure(res.status, data || {}, "Failed to load subscription");
  }

  if (!data?.subscriptionActive) {
    return failure(403, {
      error:
        data?.error ||
        "Your free trial has ended. Subscribe to continue sending secure mail.",
      code: data?.code || "SUBSCRIPTION_EXPIRED",
      subscriptionExpiresAt: data?.subscriptionExpiresAt || null,
      subscriptionActive: false,
    });
  }

  return success(200, {
    subscriptionActive: true,
    subscriptionExpiresAt: data.subscriptionExpiresAt || null,
    subscriptionDaysLeft: data.subscriptionDaysLeft ?? null,
  });
}

/**
 * Common entry point for other repos.
 *
 * @param {object} options
 * @param {string} [options.apiBaseUrl] default production API
 * @param {string} [options.token] JWT access token (skip login if set)
 * @param {string} [options.email] login email when token omitted
 * @param {string} [options.password] login password when token omitted
 * @param {string} options.to recipient email
 * @param {string} [options.subject]
 * @param {string} [options.message] plaintext message (encrypted server-side)
 * @param {string} [options.fileBase64] optional PDF as base64 (no data: prefix)
 * @param {string} [options.fileName] e.g. document.pdf
 * @param {string} [options.mimeType] default application/pdf
 * @param {boolean} [options.skipSubscriptionCheck] rely only on secure-send checks
 * @returns {Promise<{ok:boolean,status:number,error?:string,code?:string,emailSent?:boolean,...}>}
 */
async function sendSecureMail(options = {}) {
  const {
    apiBaseUrl = DEFAULT_API_BASE,
    token: inputToken,
    email,
    password,
    to,
    subject = "",
    message = "",
    fileBase64,
    fileName,
    mimeType,
    skipSubscriptionCheck = false,
  } = options;

  const baseUrl = normalizeBaseUrl(apiBaseUrl);

  if (!to) {
    return failure(400, {
      error: "Recipient email (to) is required",
      code: "RECIPIENT_REQUIRED",
    });
  }

  const hasMessage = String(message || "").trim().length > 0;
  const hasFile = Boolean(fileBase64);
  if (!hasMessage && !hasFile) {
    return failure(400, {
      error: "Add a message or a PDF (or both)",
      code: "CONTENT_REQUIRED",
    });
  }

  let token = inputToken || null;
  let loginData = null;

  if (!token) {
    const loggedIn = await loginSecureDoc({ apiBaseUrl: baseUrl, email, password });
    if (!loggedIn.ok) return loggedIn;
    token = loggedIn.token;
    loginData = loggedIn;

    if (loginData.subscriptionActive === false) {
      return failure(403, {
        error:
          "Your free trial has ended. Subscribe to continue sending secure mail.",
        code: "SUBSCRIPTION_EXPIRED",
        subscriptionExpiresAt: loginData.subscriptionExpiresAt,
      });
    }
  }

  if (!skipSubscriptionCheck) {
    const sub = await checkSenderSubscription({ apiBaseUrl: baseUrl, token });
    if (!sub.ok) return sub;
  }

  const { res, data } = await apiRequest(baseUrl, "/files/secure-send", {
    method: "POST",
    token,
    body: {
      recipientEmail: to,
      subject,
      message: message || "",
      ...(fileBase64
        ? {
            fileBase64,
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
      data?.error || "Secure send failed",
    );
  }

  return success(res.status, {
    token,
    emailSent: Boolean(data.emailSent),
    recipientUuid: data.recipientUuid,
    recipientEmail: data.recipientEmail,
    recipientCreated: Boolean(data.recipientCreated),
    keysCreated: Boolean(data.keysCreated),
    recipientClaimed: Boolean(data.recipientClaimed),
    contentKind: data.contentKind,
    subject: data.subject,
    from: data.from,
    appUrl: data.appUrl,
  });
}

module.exports = {
  DEFAULT_API_BASE,
  sendSecureMail,
  loginSecureDoc,
  checkSenderSubscription,
};

// ESM-friendly default when bundled / re-exported
module.exports.default = sendSecureMail;
