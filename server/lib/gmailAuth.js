const crypto = require("crypto");
const { google } = require("googleapis");
const User = require("../models/User");

const GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send";
const USERINFO_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email";
const USERINFO_PROFILE_SCOPE =
  "https://www.googleapis.com/auth/userinfo.profile";
const STATE_TTL_MS = 15 * 60 * 1000;

function trimEnv(name) {
  const value = process.env[name];
  return value ? String(value).trim() : "";
}

function getOAuthConfig() {
  const clientId =
    trimEnv("GOOGLE_GMAIL_CLIENT_ID") || trimEnv("GOOGLE_CLIENT_ID");
  const clientSecret = trimEnv("GOOGLE_GMAIL_CLIENT_SECRET");
  const redirectUri =
    trimEnv("GOOGLE_GMAIL_REDIRECT_URI") ||
    `${(trimEnv("APP_URL") || "http://localhost:4000").replace(/\/$/, "")}/api/auth/gmail/callback`;

  if (!clientId || !clientSecret) {
    throw new Error(
      "GOOGLE_GMAIL_CLIENT_ID and GOOGLE_GMAIL_CLIENT_SECRET must be set",
    );
  }

  return { clientId, clientSecret, redirectUri };
}

function getOAuthClient() {
  const { clientId, clientSecret, redirectUri } = getOAuthConfig();
  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

async function createConnectState(uuid) {
  const token = crypto.randomBytes(24).toString("hex");
  await User.updateOne(
    { uuid },
    {
      gmailConnectState: token,
      gmailConnectStateExpires: new Date(Date.now() + STATE_TTL_MS),
    },
  );
  return token;
}

async function consumeConnectState(token) {
  const user = await User.findOne({ gmailConnectState: token });
  if (!user) return null;

  const expired =
    !user.gmailConnectStateExpires ||
    user.gmailConnectStateExpires.getTime() < Date.now();

  user.gmailConnectState = null;
  user.gmailConnectStateExpires = null;
  await user.save();

  if (expired) return null;
  return user.uuid;
}

function getGmailAuthUrl(state) {
  const { redirectUri, clientId } = getOAuthConfig();
  const client = getOAuthClient();
  const url = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: [GMAIL_SEND_SCOPE, USERINFO_EMAIL_SCOPE, USERINFO_PROFILE_SCOPE],
    state,
    redirect_uri: redirectUri,
  });

  if (!url.startsWith("https://accounts.google.com/")) {
    throw new Error("Generated OAuth URL is invalid");
  }

  return { url, redirectUri, clientId };
}

async function exchangeCodeForTokens(code, redirectUri) {
  const { clientId, clientSecret } = getOAuthConfig();
  const uri = redirectUri || getOAuthConfig().redirectUri;
  const client = new google.auth.OAuth2(clientId, clientSecret, uri);
  const { tokens } = await client.getToken({ code, redirect_uri: uri });
  return tokens;
}

function getGoogleOAuthAudience() {
  return trimEnv("GOOGLE_GMAIL_CLIENT_ID") || trimEnv("GOOGLE_CLIENT_ID");
}

async function verifyGoogleIdToken(idToken) {
  const { OAuth2Client } = require("google-auth-library");
  const audience = getGoogleOAuthAudience();
  const client = new OAuth2Client(audience);
  const ticket = await client.verifyIdToken({ idToken, audience });
  return ticket.getPayload();
}

function gmailClientForRefreshToken(refreshToken) {
  if (!refreshToken) {
    throw new Error("Gmail refresh token is missing");
  }
  const client = getOAuthClient();
  client.setCredentials({ refresh_token: refreshToken });
  return google.gmail({ version: "v1", auth: client });
}

/** Mint a short-lived Gmail access token from the stored refresh token. */
async function getGmailAccessTokenFromRefresh(refreshToken) {
  if (!refreshToken) {
    throw new Error("Gmail refresh token is missing");
  }
  const client = getOAuthClient();
  client.setCredentials({ refresh_token: refreshToken });
  const tokenResponse = await client.getAccessToken();
  const accessToken =
    typeof tokenResponse === "string"
      ? tokenResponse
      : tokenResponse?.token || null;
  if (!accessToken) {
    throw new Error("Could not refresh Gmail access token");
  }
  return accessToken;
}

module.exports = {
  getOAuthClient,
  getGmailAuthUrl,
  exchangeCodeForTokens,
  gmailClientForRefreshToken,
  getGmailAccessTokenFromRefresh,
  createConnectState,
  consumeConnectState,
  getGoogleOAuthAudience,
  verifyGoogleIdToken,
};
