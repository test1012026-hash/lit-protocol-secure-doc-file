const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

/** Default session lifetime (hours). */
const DEFAULT_TOKEN_HOURS = 8;

const RELOGIN_MESSAGE = "Token invalid. Please re-login.";
const RELOGIN_CODE = "RELOGIN_REQUIRED";
/** Non-standard HTTP status: Login Time-out / session expired. */
const RELOGIN_STATUS = 440;

function accessSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
  }
  return process.env.JWT_SECRET;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function parseExpiresInToHours(expiresIn, fallback = DEFAULT_TOKEN_HOURS) {
  if (expiresIn == null) return fallback;
  if (typeof expiresIn === "number" && Number.isFinite(expiresIn)) {
    return Math.max(0.25, expiresIn);
  }
  const raw = String(expiresIn).trim();
  const match = /^(\d+(?:\.\d+)?)(h|m|s)?$/i.exec(raw);
  if (!match) return fallback;
  const value = Number(match[1]);
  const unit = (match[2] || "h").toLowerCase();
  if (unit === "h") return Math.max(0.25, value);
  if (unit === "m") return Math.max(0.25, value / 60);
  if (unit === "s") return Math.max(0.25, value / 3600);
  return fallback;
}

function makeReloginError(code = RELOGIN_CODE) {
  const err = new Error(RELOGIN_MESSAGE);
  err.name = "SessionError";
  err.code = code;
  err.status = RELOGIN_STATUS;
  return err;
}

/**
 * Decode a verified JWT payload into createdAt / expiresAt Dates.
 * Prefer custom claims; fall back to standard iat / exp.
 */
function timesFromPayload(payload) {
  const createdAt = payload.createdAt
    ? new Date(payload.createdAt)
    : payload.iat
      ? new Date(payload.iat * 1000)
      : null;
  const expiresAt = payload.expiresAt
    ? new Date(payload.expiresAt)
    : payload.exp
      ? new Date(payload.exp * 1000)
      : null;
  return { createdAt, expiresAt };
}

/**
 * Create JWT with createdAt + expiresAt in the payload.
 * Stores only accessTokenHash in DB (times live in the token).
 */
async function createSessionToken(user, options = {}) {
  const { getPlainEmail } = require("./emailCrypto");
  const hours = parseExpiresInToHours(
    options.expiresInHours ?? options.expiresIn,
    DEFAULT_TOKEN_HOURS,
  );
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + hours * 60 * 60 * 1000);
  const iat = Math.floor(createdAt.getTime() / 1000);
  const exp = Math.floor(expiresAt.getTime() / 1000);

  const token = jwt.sign(
    {
      uuid: user.uuid,
      email: getPlainEmail(user),
      role: user.role || "subscriber",
      type: "access",
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      iat,
      exp,
    },
    accessSecret(),
    { algorithm: "HS256", noTimestamp: true },
  );

  user.accessTokenHash = hashToken(token);
  user.refreshTokenHash = null;
  await user.save();
  await User.updateOne(
    { _id: user._id },
    { $unset: { accessTokenCreatedAt: 1, accessTokenExpiresAt: 1 } },
  );

  return {
    token,
    createdAt,
    expiresAt,
    expiresInHours: hours,
  };
}

/**
 * Verify JWT (signature + exp), then confirm hash matches DB session.
 * Returns session payload including createdAt / expiresAt from the token.
 */
async function verifySessionToken(rawToken) {
  if (!rawToken) {
    const err = new Error("Missing token");
    err.name = "SessionError";
    err.code = "TOKEN_MISSING";
    err.status = 401;
    throw err;
  }

  let payload;
  try {
    payload = jwt.verify(rawToken, accessSecret(), {
      algorithms: ["HS256"],
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      throw makeReloginError("TOKEN_EXPIRED");
    }
    throw makeReloginError("TOKEN_INVALID");
  }

  if (payload.type && payload.type !== "access") {
    throw makeReloginError("TOKEN_INVALID");
  }

  const { createdAt, expiresAt } = timesFromPayload(payload);
  if (expiresAt && expiresAt.getTime() <= Date.now()) {
    throw makeReloginError("TOKEN_EXPIRED");
  }

  const tokenHash = hashToken(rawToken);
  const user = await User.findOne({
    uuid: payload.uuid,
    accessTokenHash: tokenHash,
  });

  if (!user || !user.claimed) {
    throw makeReloginError("TOKEN_INVALID");
  }

  if (user.deletedAt) {
    const err = new Error("This account was removed and cannot sign in.");
    err.name = "SessionError";
    err.code = "ACCOUNT_DELETED";
    err.status = 403;
    throw err;
  }

  return {
    uuid: user.uuid,
    role: user.role || payload.role || "subscriber",
    email: payload.email,
    type: "access",
    createdAt,
    expiresAt,
    user,
  };
}

/** Decode JWT without verifying (debug / display only). Prefer verifySessionToken. */
function decodeToken(rawToken) {
  const payload = jwt.decode(rawToken);
  if (!payload || typeof payload !== "object") return null;
  const { createdAt, expiresAt } = timesFromPayload(payload);
  return {
    uuid: payload.uuid || null,
    role: payload.role || null,
    email: payload.email || null,
    createdAt,
    expiresAt,
    payload,
  };
}

async function clearSessionToken(userOrUuid) {
  const filter =
    typeof userOrUuid === "string"
      ? { uuid: userOrUuid }
      : { _id: userOrUuid._id };
  await User.updateOne(filter, {
    $unset: {
      accessTokenHash: 1,
      accessTokenCreatedAt: 1,
      accessTokenExpiresAt: 1,
      refreshTokenHash: 1,
    },
  });
}

async function issueAuthTokens(user, options = {}) {
  const session = await createSessionToken(user, options);
  return {
    token: session.token,
    refreshToken: session.token,
    expiresAt: session.expiresAt,
    createdAt: session.createdAt,
    expiresInHours: session.expiresInHours,
  };
}

async function verifyAccessToken(token) {
  return verifySessionToken(token);
}

function sendRelogin(res, code = RELOGIN_CODE) {
  return res.status(RELOGIN_STATUS).json({
    error: RELOGIN_MESSAGE,
    code,
  });
}

module.exports = {
  DEFAULT_TOKEN_HOURS,
  RELOGIN_MESSAGE,
  RELOGIN_CODE,
  RELOGIN_STATUS,
  hashToken,
  parseExpiresInToHours,
  timesFromPayload,
  decodeToken,
  createSessionToken,
  verifySessionToken,
  verifyAccessToken,
  clearSessionToken,
  issueAuthTokens,
  sendRelogin,
  makeReloginError,
};
