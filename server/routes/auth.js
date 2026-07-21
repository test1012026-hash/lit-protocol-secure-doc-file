const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const { sendResetEmail } = require("../lib/mail");
const { normalizeEmail } = require("../lib/email");
const { validateBody, validateQuery } = require("../middleware/validate");
const {
  signupSchema,
  loginSchema,
  googleLoginSchema,
  passwordResetRequestSchema,
  passwordResetCompleteSchema,
  passwordResetVerifySchema,
} = require("../validation/schemas");

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

function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashResetToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

router.post("/signup", validateBody(signupSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;

    let user = await User.findOne({ email });
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
        email,
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

router.post("/login", validateBody(loginSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;
    const user = await User.findOne({
      email,
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

router.post(
  "/login/google",
  validateBody(googleLoginSchema),
  async (req, res) => {
    try {
      const { idToken } = req.body;

      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      const email = normalizeEmail(payload.email);

      let user = await User.findOne({ email });
      if (!user) {
        const raw = String(payload.email || "")
          .trim()
          .toLowerCase();
        if (raw && raw !== email) {
          user = await User.findOne({ email: raw });
          if (user) user.email = email;
        }
      }
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
  },
);

router.post(
  "/password-reset/request",
  validateBody(passwordResetRequestSchema),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);

      const user = await User.findOne({ email, claimed: true });
      if (!user)
        return res
          .status(404)
          .json({ error: "No account found for this email" });

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
  },
);

router.get(
  "/password-reset/verify",
  validateQuery(passwordResetVerifySchema),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.query.email);
      const { token } = req.query;
      const record = await PasswordReset.findOne({ email });

      if (!record || record.tokenHash !== hashResetToken(token)) {
        return res.status(400).json({
          valid: false,
          expired: false,
          error: "This reset link is invalid. Please request a new one.",
        });
      }

      if (record.expiresAt < new Date()) {
        await PasswordReset.deleteOne({ email });
        return res.status(400).json({
          valid: false,
          expired: true,
          error:
            "This reset link has expired (links are valid for 30 minutes). Please request a new one.",
        });
      }

      const msLeft = record.expiresAt.getTime() - Date.now();
      res.json({
        valid: true,
        expired: false,
        email,
        expiresInSeconds: Math.max(0, Math.floor(msLeft / 1000)),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

router.post(
  "/password-reset/complete",
  validateBody(passwordResetCompleteSchema),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      const { token, password } = req.body;

      const record = await PasswordReset.findOne({ email });
      if (!record || record.tokenHash !== hashResetToken(token)) {
        return res.status(400).json({
          error: "This reset link is invalid. Please request a new one.",
        });
      }
      if (record.expiresAt < new Date()) {
        await PasswordReset.deleteOne({ email });
        return res.status(400).json({
          error:
            "This reset link has expired (links are valid for 30 minutes). Please request a new one.",
        });
      }

      const user = await User.findOne({ email, claimed: true });
      if (!user)
        return res
          .status(404)
          .json({ error: "No account found for this email" });

      user.passwordHash = await bcrypt.hash(password, 12);
      await user.save();
      await PasswordReset.deleteOne({ email });

      res.json(userPayload(user));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  },
);

module.exports = router;
