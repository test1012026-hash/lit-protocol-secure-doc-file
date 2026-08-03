const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const { sendResetEmail } = require("../lib/mail");
const { normalizeEmail } = require("../lib/email");
const {
  getGmailAuthUrl,
  exchangeCodeForTokens,
  getOAuthClient,
  createConnectState,
  consumeConnectState,
  getGoogleOAuthAudience,
  verifyGoogleIdToken,
} = require("../lib/gmailAuth");
const authMiddleware = require("../middleware/auth");
const { validateBody, validateQuery } = require("../middleware/validate");
const {
  signupSchema,
  loginSchema,
  googleLoginSchema,
  passwordResetRequestSchema,
  passwordResetCompleteSchema,
  passwordResetVerifySchema,
  gmailAccessTokenSchema,
  registerPublicKeySchema,
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
    gmailConnected: Boolean(user.gmailRefreshToken),
    hasPublicKey: Boolean(user.publicKeySpki && user.privateKeyEnc),
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

async function upsertGoogleUser(payload, gmailRefreshToken) {
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
  if (gmailRefreshToken) {
    user.gmailRefreshToken = gmailRefreshToken;
  }
  await user.save();
  return user;
}

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
      const user = await upsertGoogleUser(payload);

      res.json({
        ...userPayload(user),
        googleIdToken: idToken,
      });
    } catch (err) {
      const msg = err.message || String(err);
      res.status(401).json({ error: "Google verification failed: " + msg });
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

router.post(
  "/keys",
  authMiddleware,
  validateBody(registerPublicKeySchema),
  async (req, res) => {
    try {
      const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!user) return res.status(404).json({ error: "User not found" });

      const {
        publicKeySpki,
        privateKeyEnc,
        privateKeyIv,
        privateKeySalt,
      } = req.body;

      user.publicKeySpki = String(publicKeySpki).trim();
      user.privateKeyEnc = String(privateKeyEnc).trim();
      user.privateKeyIv = String(privateKeyIv).trim();
      user.privateKeySalt = String(privateKeySalt).trim();
      await user.save();
      // Drop legacy keyActionId if it still exists in older documents.
      await User.updateOne(
        { _id: user._id },
        { $unset: { keyActionId: 1 } },
      );

      res.json({
        ok: true,
        hasPublicKey: true,
        uuid: user.uuid,
        email: user.email,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

router.get("/keys/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid });
    if (!user) return res.status(404).json({ error: "User not found" });

    const hasKeys = Boolean(
      user.publicKeySpki &&
        user.privateKeyEnc &&
        user.privateKeyIv &&
        user.privateKeySalt,
    );

    res.json({
      hasPublicKey: hasKeys,
      publicKeySpki: user.publicKeySpki || null,
      privateKeyEnc: user.privateKeyEnc || null,
      privateKeyIv: user.privateKeyIv || null,
      privateKeySalt: user.privateKeySalt || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/google/refresh", authMiddleware, async (req, res) => {
  try {
    const { code, redirectUri } = req.body;
    if (!code) {
      return res.status(400).json({ error: "Google authorization code is required" });
    }

    const tokens = await exchangeCodeForTokens(code, redirectUri);
    if (!tokens.id_token) {
      return res.status(401).json({ error: "Google did not return an id_token" });
    }

    const payload = await verifyGoogleIdToken(tokens.id_token);
    const user = await User.findOne({ uuid: req.user.uuid });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (normalizeEmail(payload.email) !== normalizeEmail(user.email)) {
      return res.status(403).json({
        error: "Google account does not match your logged-in email.",
      });
    }

    if (tokens.refresh_token) {
      user.gmailRefreshToken = tokens.refresh_token;
      await user.save();
    }

    res.json({
      googleIdToken: tokens.id_token,
      gmailConnected: Boolean(user.gmailRefreshToken),
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

router.post(
  "/gmail/access-token",
  authMiddleware,
  validateBody(gmailAccessTokenSchema),
  async (req, res) => {
    try {
      const { code, redirectUri } = req.body;
      const tokens = await exchangeCodeForTokens(code, redirectUri);
      if (!tokens.access_token) {
        return res
          .status(401)
          .json({ error: "Google did not return an access token" });
      }

      const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (tokens.refresh_token) {
        user.gmailRefreshToken = tokens.refresh_token;
        await user.save();
      } else if (!user.gmailRefreshToken) {
        return res.status(401).json({
          error:
            "Gmail permission was not saved. Approve all requested access and try again.",
          code: "GMAIL_CONSENT_REQUIRED",
        });
      }

      res.json({
        accessToken: tokens.access_token,
        gmailConnected: Boolean(user.gmailRefreshToken),
      });
    } catch (err) {
      const msg = err.message || String(err);
      res.status(401).json({ error: msg });
    }
  },
);

router.get("/gmail/status", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ gmailConnected: Boolean(user.gmailRefreshToken) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/gmail/connect", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });

    const state = await createConnectState(user.uuid);
    const { url, redirectUri, clientId } = getGmailAuthUrl(state);
    res.json({ url, redirectUri, clientId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/gmail/callback", async (req, res) => {
  const fail = (message) =>
    res.status(400).send(
      `<html><body style="font-family:system-ui;padding:24px"><h2>Gmail connect failed</h2><p>${message}</p></body></html>`,
    );

  try {
    const { code, state, error, error_description: errorDescription } =
      req.query;
    if (error) {
      return fail(`${error}${errorDescription ? `: ${errorDescription}` : ""}`);
    }
    if (!code || !state) return fail("Missing code or state.");

    const uuid = await consumeConnectState(String(state));
    if (!uuid) {
      return fail("Connect link expired. Try Connect Gmail again.");
    }

    const tokens = await exchangeCodeForTokens(String(code));
    if (!tokens.refresh_token) {
      return fail(
        "No refresh token returned. Revoke app access at myaccount.google.com/permissions and try again.",
      );
    }

    const oauth2Client = getOAuthClient();
    oauth2Client.setCredentials(tokens);
    const { google } = require("googleapis");
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const googleEmail = (await oauth2.userinfo.get()).data.email;

    const user = await User.findOne({ uuid });
    if (!user) return fail("User not found.");

    if (
      googleEmail &&
      normalizeEmail(googleEmail) !== normalizeEmail(user.email)
    ) {
      return fail(
        `Google account (${googleEmail}) must match your login (${user.email}).`,
      );
    }

    user.gmailRefreshToken = tokens.refresh_token;
    if (googleEmail) user.email = normalizeEmail(googleEmail);
    await user.save();

    res.send(
      `<html><body style="font-family:system-ui;padding:24px"><h2>Gmail connected</h2><p>Sends will appear From: <b>${user.email}</b></p></body></html>`,
    );
  } catch (err) {
    console.error("Gmail callback error:", err);
    fail(err.message || "Unexpected error");
  }
});

module.exports = router;
