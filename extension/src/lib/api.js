import axios from "axios";
import { API_BASE_URL } from "./config";
import { clearAuth, getStoredAuth, saveAuth } from "./authStorage";

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60_000,
});

/** Large PDF encrypt/decrypt needs a longer timeout (upload + AES + download). */
const largeFileClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 180_000,
});

function authHeader(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

let refreshPromise = null;

async function persistRefreshedAuth(data) {
  const { auth } = await getStoredAuth();
  const next = {
    ...(auth || {}),
    token: data.token,
    refreshToken: data.refreshToken,
  };
  for (const key of [
    "uuid",
    "email",
    "hasPassword",
    "hasPublicKey",
    "gmailConnected",
    "termsAndConditions",
    "subscriptionActive",
    "subscriptionDaysLeft",
    "subscriptionExpiresAt",
    "subscriptionTrialDays",
  ]) {
    if (data[key] !== undefined) next[key] = data[key];
  }
  await saveAuth(next);
  return next;
}

export async function refreshSession() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const { auth } = await getStoredAuth();
    const refreshToken = auth?.refreshToken;
    if (!refreshToken) {
      await clearAuth();
      const err = new Error("Session expired. Please log in again.");
      err.code = "REFRESH_MISSING";
      throw err;
    }

    try {
      const { data } = await axios.post(
        `${API_BASE_URL}/auth/refresh`,
        { refreshToken },
        { timeout: 60_000 },
      );
      return await persistRefreshedAuth(data);
    } catch (err) {
      await clearAuth();
      const apiErr = new Error(
        err.response?.data?.error || "Session expired. Please log in again.",
      );
      apiErr.code = err.response?.data?.code || "REFRESH_FAILED";
      throw apiErr;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

function shouldAttemptRefresh(error) {
  const status = error.response?.status;
  const code = error.response?.data?.code;
  if (status !== 401) return false;
  if (error.config?.skipAuthRefresh) return false;
  if (error.config?._retry) return false;
  return (
    code === "TOKEN_EXPIRED" ||
    code === "TOKEN_INVALID" ||
    code === "TOKEN_MISSING" ||
    /expired|invalid token|missing token/i.test(
      String(error.response?.data?.error || ""),
    )
  );
}

async function refreshAndRetry(error, axiosClient) {
  const original = error.config;
  if (!original || !shouldAttemptRefresh(error)) {
    throw error;
  }
  const nextAuth = await refreshSession();
  original._retry = true;
  original.headers = original.headers || {};
  original.headers.Authorization = `Bearer ${nextAuth.token}`;
  return axiosClient.request(original);
}

client.interceptors.response.use(
  (response) => response,
  (error) => refreshAndRetry(error, client),
);

largeFileClient.interceptors.response.use(
  (response) => response,
  (error) => refreshAndRetry(error, largeFileClient),
);

export const api = {
  signup: (email, password, acceptTerms) =>
    client.post("/auth/signup", { email, password, acceptTerms }),
  login: (email, password) => client.post("/auth/login", { email, password }),
  loginGoogle: (idToken) => client.post("/auth/login/google", { idToken }),
  loginGoogleFull: (payload) => client.post("/auth/login/google", payload),
  refresh: (refreshToken) =>
    client.post(
      "/auth/refresh",
      { refreshToken },
      { skipAuthRefresh: true },
    ),
  logout: (token) =>
    client.post("/auth/logout", {}, { ...authHeader(token), skipAuthRefresh: true }),
  exchangeGmailCode: (payload, token) =>
    client.post("/auth/gmail/access-token", payload, authHeader(token)),
  requestPasswordReset: (email) =>
    client.post("/auth/password-reset/request", { email }),
  gmailStatus: (token) => client.get("/auth/gmail/status", authHeader(token)),
  getSubscription: (token) =>
    client.get("/auth/subscription", authHeader(token)),
  gmailSendToken: (token) =>
    client.post("/auth/gmail/send-token", {}, authHeader(token)),
  gmailMailboxToken: (token) =>
    client.post("/auth/gmail/mailbox-token", {}, authHeader(token)),
  ensureRecipient: (recipientEmail, token) =>
    client.post(
      "/files/ensure-recipient",
      { recipientEmail },
      authHeader(token),
    ),
  provisionRecipientKeys: (payload, token) =>
    client.post("/files/provision-recipient-keys", payload, authHeader(token)),
  encryptFile: (payload, token) =>
    largeFileClient.post("/files/encrypt", payload, {
      ...authHeader(token),
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }),
  decryptFile: (payload, token) =>
    largeFileClient.post("/files/decrypt", payload, {
      ...authHeader(token),
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }),
  sendFile: (payload, token) =>
    client.post("/files/send", payload, authHeader(token)),
  registerKeys: (payload, token) =>
    client.post("/auth/keys", payload, authHeader(token)),
  ensureKeys: (token) =>
    client.post("/auth/keys/ensure", {}, authHeader(token)),
  getMyKeys: (token) => client.get("/auth/keys/me", authHeader(token)),
};
