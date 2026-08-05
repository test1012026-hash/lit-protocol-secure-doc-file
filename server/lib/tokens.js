const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || "15m";
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES || "30d";

function accessSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
  }
  return process.env.JWT_SECRET;
}

function refreshSecret() {
  return process.env.JWT_REFRESH_SECRET || `${accessSecret()}:refresh`;
}

function issueAccessToken(user) {
  return jwt.sign(
    {
      uuid: user.uuid,
      email: user.email,
      type: "access",
    },
    accessSecret(),
    { expiresIn: ACCESS_EXPIRES },
  );
}

function issueRefreshToken(user) {
  return jwt.sign(
    {
      uuid: user.uuid,
      email: user.email,
      type: "refresh",
      jti: crypto.randomUUID(),
    },
    refreshSecret(),
    { expiresIn: REFRESH_EXPIRES },
  );
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function verifyAccessToken(token) {
  const payload = jwt.verify(token, accessSecret());
  // Accept legacy tokens (no type) and new access tokens.
  if (payload.type && payload.type !== "access") {
    const err = new Error("Invalid token type");
    err.name = "JsonWebTokenError";
    throw err;
  }
  return payload;
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, refreshSecret());
  if (payload.type !== "refresh") {
    const err = new Error("Invalid refresh token");
    err.name = "JsonWebTokenError";
    throw err;
  }
  return payload;
}

function issueAuthTokens(user) {
  const token = issueAccessToken(user);
  const refreshToken = issueRefreshToken(user);
  return {
    token,
    refreshToken,
    refreshTokenHash: hashToken(refreshToken),
  };
}

module.exports = {
  ACCESS_EXPIRES,
  REFRESH_EXPIRES,
  issueAccessToken,
  issueRefreshToken,
  issueAuthTokens,
  hashToken,
  verifyAccessToken,
  verifyRefreshToken,
};
