const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const { sendResetEmail } = require("../lib/mail");

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;

function appUrl() {
  return (
    process.env.APP_URL || `http://localhost:${process.env.PORT || 4000}`
  ).replace(/\/$/, "");
}

function issueToken(user) {
  return jwt.sign(
    { uuid: user.uuid, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" },
  );
}

function userPayload(user) {
  return {
    token: issueToken(user),
    uuid: user.uuid,
    email: user.email,
    hasPassword: Boolean(user.passwordHash),
  };
}

function normalizeEmail(email) {
  return email?.toLowerCase().trim();
}

function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashResetToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

router.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    let user = await User.findOne({ email: email.toLowerCase() });
    if (user?.claimed)
      return res
        .status(409)
        .json({ error: "An account with this email already exists" });

    const passwordHash = await bcrypt.hash(password, 12);
    if (user) {
      user.passwordHash = passwordHash;
      user.claimed = true;
    } else {
      user = new User({
        email: email.toLowerCase(),
        passwordHash,
        claimed: true,
      });
    }
    await user.save();

    res.json(userPayload(user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({
      email: email?.toLowerCase(),
      claimed: true,
    });
    if (!user || !user.passwordHash)
      return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    res.json(userPayload(user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/login/google", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "Missing idToken" });

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, googleId: payload.sub, claimed: true });
    } else {
      user.googleId = payload.sub;
      user.claimed = true;
    }
    await user.save();

    res.json(userPayload(user));
  } catch (err) {
    res
      .status(401)
      .json({ error: "Google verification failed: " + err.message });
  }
});

router.post("/password-reset/request", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!email) return res.status(400).json({ error: "Email is required" });

    const user = await User.findOne({ email, claimed: true });
    if (!user)
      return res.status(404).json({ error: "No account found for this email" });

    const token = generateResetToken();
    const tokenHash = hashResetToken(token);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await PasswordReset.findOneAndUpdate(
      { email },
      { email, tokenHash, expiresAt },
      { upsert: true, new: true },
    );

    const resetLink = `${appUrl()}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
    await sendResetEmail(email, resetLink);
    res.json({
      ok: true,
      message: "A password reset link has been sent to your email",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/password-reset/complete", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { token, password } = req.body;
    if (!email || !token || !password) {
      return res
        .status(400)
        .json({ error: "Email, token, and password are required" });
    }
    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });
    }

    const record = await PasswordReset.findOne({ email });
    if (!record || record.tokenHash !== hashResetToken(token)) {
      return res
        .status(400)
        .json({ error: "Invalid or expired reset link. Request a new one." });
    }
    if (record.expiresAt < new Date()) {
      await PasswordReset.deleteOne({ email });
      return res
        .status(400)
        .json({ error: "Reset link expired. Request a new one." });
    }

    const user = await User.findOne({ email, claimed: true });
    if (!user)
      return res.status(404).json({ error: "No account found for this email" });

    user.passwordHash = await bcrypt.hash(password, 12);
    await user.save();
    await PasswordReset.deleteOne({ email });

    res.json(userPayload(user));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
