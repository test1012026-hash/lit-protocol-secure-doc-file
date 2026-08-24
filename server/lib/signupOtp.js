const crypto = require("crypto");
const User = require("../models/User");
const { normalizeEmail } = require("./email");
const { findUserByEmail, applyEncryptedEmail } = require("./emailCrypto");
const { sendSignupOtpEmail } = require("./mail");

const OTP_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

function generateOtp() {
  return String(crypto.randomInt(0, 10000)).padStart(4, "0");
}

function clearSignupOtp(user) {
  user.signupOtpHash = null;
  user.signupOtpAttempts = 0;
  user.signupOtpExpiresAt = null;
}

async function assertEmailAvailableForSignup(email) {
  const normalized = normalizeEmail(email);
  const user = await findUserByEmail(User, normalized);
  if (user?.deletedAt) {
    const err = new Error(
      "This account was removed. Contact your administrator to restore access.",
    );
    err.status = 403;
    err.code = "ACCOUNT_DELETED";
    throw err;
  }
  if (user?.claimed) {
    const err = new Error(
      "An account with this email already exists. Log in instead.",
    );
    err.status = 409;
    err.code = "ACCOUNT_EXISTS";
    throw err;
  }
  return { email: normalized, user };
}

async function issueSignupOtp(rawEmail) {
  const { email, user: existing } = await assertEmailAvailableForSignup(
    rawEmail,
  );
  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  let user = existing;
  if (!user) {
    user = new User({
      claimed: false,
      onboardingComplete: false,
    });
    applyEncryptedEmail(user, email);
  }

  user.signupOtpHash = hashOtp(otp);
  user.signupOtpAttempts = 0;
  user.signupOtpExpiresAt = expiresAt;
  await user.save();

  await sendSignupOtpEmail(email, otp);

  const out = {
    ok: true,
    email,
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    expiresAt: expiresAt.toISOString(),
    message:
      "A 4-digit verification code was sent to your email. It is valid for 10 minutes. Requesting a new code invalidates the previous one.",
  };
  if (
    process.env.NODE_ENV !== "production" &&
    (!process.env.GOOGLE_REFRESH_TOKEN || !process.env.GMAIL_SENDER)
  ) {
    out.devOtp = otp;
  }
  return out;
}

async function consumeSignupOtp(rawEmail, rawOtp) {
  const email = normalizeEmail(rawEmail);
  const otp = String(rawOtp || "").trim();
  if (!/^\d{4}$/.test(otp)) {
    const err = new Error("Enter the 4-digit code from your email");
    err.status = 400;
    err.code = "OTP_INVALID";
    throw err;
  }

  const user = await findUserByEmail(User, email);
  if (!user?.signupOtpHash || !user.signupOtpExpiresAt) {
    const err = new Error(
      "No verification code found. Request a new code and try again.",
    );
    err.status = 400;
    err.code = "OTP_NOT_FOUND";
    throw err;
  }

  if (user.signupOtpExpiresAt < new Date()) {
    clearSignupOtp(user);
    await user.save();
    const err = new Error(
      "This code has expired. Request a new code and try again.",
    );
    err.status = 400;
    err.code = "OTP_EXPIRED";
    throw err;
  }

  if (user.signupOtpAttempts >= MAX_ATTEMPTS) {
    clearSignupOtp(user);
    await user.save();
    const err = new Error(
      "Too many incorrect attempts. Request a new code and try again.",
    );
    err.status = 429;
    err.code = "OTP_LOCKED";
    throw err;
  }

  if (user.signupOtpHash !== hashOtp(otp)) {
    user.signupOtpAttempts += 1;
    await user.save();
    const left = MAX_ATTEMPTS - user.signupOtpAttempts;
    const err = new Error(
      left > 0
        ? `Incorrect code. ${left} attempt${left === 1 ? "" : "s"} left.`
        : "Too many incorrect attempts. Request a new code.",
    );
    err.status = 400;
    err.code = "OTP_MISMATCH";
    throw err;
  }

  clearSignupOtp(user);
  await user.save();
  return email;
}

module.exports = {
  issueSignupOtp,
  consumeSignupOtp,
  assertEmailAvailableForSignup,
  clearSignupOtp,
  OTP_TTL_MS,
};
