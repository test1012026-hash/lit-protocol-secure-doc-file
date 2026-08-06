const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const { sendResetEmail } = require("../lib/mail");
const { normalizeEmail } = require("../lib/email");
const {
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
  hashEmail,
  encryptEmail,
} = require("../lib/emailCrypto");
const {
  // getGmailAuthUrl,
  exchangeCodeForTokens,
  getOAuthClient,
  // createConnectState,
  consumeConnectState,
  // getGoogleOAuthAudience,
  // verifyGoogleIdToken,
  getGmailAccessTokenFromRefresh,
} = require("../lib/gmailAuth");
const {
  ensureUserSubscription,
  isSubscriptionActive,
  subscriptionPayload,
  subscriptionBlockedError,
  trialExpiresFrom,
} = require("../lib/subscription");
const {
  issueAuthTokens,
  hashToken,
  verifyRefreshToken,
} = require("../lib/tokens");
const authMiddleware = require("../middleware/auth");
const { validateBody, validateQuery } = require("../middleware/validate");
const {
  signupSchema,
  loginSchema,
  googleLoginSchema,
  passwordResetRequestSchema,
  passwordResetCompleteSchema,
  passwordResetVerifySchema,
  refreshTokenSchema,
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

async function attachAuthTokens(user) {
  const issued = issueAuthTokens(user);
  user.refreshTokenHash = issued.refreshTokenHash;
  await user.save();
  return {
    token: issued.token,
    refreshToken: issued.refreshToken,
  };
}

/** Union of previously granted scopes and newly returned ones. */
function mergeGrantedScopes(existing, incoming) {
  const set = new Set(
    `${existing || ""} ${incoming || ""}`.split(/\s+/).filter(Boolean),
  );
  return Array.from(set).join(" ");
}

function userPayload(user, tokens) {
  return {
    token: tokens.token,
    refreshToken: tokens.refreshToken,
    uuid: user.uuid,
    email: getPlainEmail(user),
    hasPassword: Boolean(user.passwordHash),
    gmailConnected: Boolean(user.gmailRefreshToken),
    hasPublicKey: Boolean(user.iron && user.thor),
    termsAndConditions: Boolean(user.termsAndConditions),
    ...subscriptionPayload(user),
  };
}

async function finalizeClaimedUser(user) {
  if (!user.subscriptionExpiresAt) {
    user.subscriptionExpiresAt = trialExpiresFrom(new Date());
  }
  await user.save();
  await ensureUserSubscription(user);
  return user;
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

    let user = await findUserByEmail(User, email);
    if (user?.claimed)
      return res
        .status(409)
        .json({ error: "An account with this email already exists" });

    const passwordHash = await bcrypt.hash(password, 12);
    if (user) {
      applyEncryptedEmail(user, email);
      user.passwordHash = passwordHash;
      user.claimed = true;
      user.termsAndConditions = true;
    } else {
      user = new User({
        passwordHash,
        claimed: true,
        termsAndConditions: true,
      });
      applyEncryptedEmail(user, email);
    }
    await finalizeClaimedUser(user);

    const tokens = await attachAuthTokens(user);
    res.json(userPayload(user, tokens));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/login", validateBody(loginSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;
    const user = await findUserByEmail(User, email, { claimed: true });
    if (!user || !user.passwordHash)
      return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    await ensureUserSubscription(user);
    const tokens = await attachAuthTokens(user);
    res.json(userPayload(user, tokens));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function upsertGoogleUser(
  payload,
  gmailRefreshToken,
  { acceptTerms = false, intent = "login", gmailScopes = "" } = {},
) {
  const email = normalizeEmail(payload.email);

  let user = await findUserByEmail(User, email);
  if (!user) {
    const raw = String(payload.email || "")
      .trim()
      .toLowerCase();
    if (raw && raw !== email) {
      user = await findUserByEmail(User, raw);
    }
  }

  const isNewClaim = !user || !user.claimed;

  // Google Log in: existing claimed accounts only — never auto-create.
  if (intent !== "signup" && isNewClaim) {
    const err = new Error(
      "You are not able to log in. Please sign up first.",
    );
    err.status = 404;
    err.code = "ACCOUNT_NOT_FOUND";
    throw err;
  }

  if (isNewClaim && !acceptTerms) {
    const err = new Error(
      "You must accept the Terms & Conditions to create an account",
    );
    err.status = 400;
    err.code = "TERMS_REQUIRED";
    throw err;
  }

  if (!user) {
    user = new User({
      googleId: payload.sub,
      claimed: true,
      termsAndConditions: Boolean(acceptTerms),
    });
    applyEncryptedEmail(user, email);
  } else {
    applyEncryptedEmail(user, email);
    user.googleId = payload.sub;
    user.claimed = true;
    if (acceptTerms) user.termsAndConditions = true;
  }
  if (gmailRefreshToken) {
    user.gmailRefreshToken = gmailRefreshToken;
  }
  if (gmailScopes) {
    user.gmailScopes = mergeGrantedScopes(user.gmailScopes, gmailScopes);
  }
  await finalizeClaimedUser(user);
  return user;
}

router.post(
  "/login/google",
  validateBody(googleLoginSchema),
  async (req, res) => {
    try {
      let idToken = req.body.idToken || null;
      let gmailRefreshToken = null;
      let accessToken = null;
      let scope = "";

      // Full Google login (code): identity + Gmail/Contacts/mailbox in one consent.
      if (req.body.code) {
        const tokens = await exchangeCodeForTokens(
          req.body.code,
          req.body.redirectUri,
        );
        idToken = tokens.id_token || null;
        gmailRefreshToken = tokens.refresh_token || null;
        accessToken = tokens.access_token || null;
        scope = tokens.scope || "";

        if (!idToken) {
          return res.status(401).json({
            error:
              "Google did not return an id_token. Approve Sign-in + Gmail/Contacts access and try again.",
          });
        }
      }

      const audiences = [
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_GMAIL_CLIENT_ID,
      ].filter(Boolean);

      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: audiences.length === 1 ? audiences[0] : audiences,
      });
      const payload = ticket.getPayload();
      const user = await upsertGoogleUser(payload, gmailRefreshToken, {
        acceptTerms: Boolean(req.body.acceptTerms),
        intent: req.body.intent === "signup" ? "signup" : "login",
        gmailScopes: scope,
      });

      // Google only returns a refresh token on first grant; ask for consent
      // again only when we have none stored for this user.
      if (req.body.code && !user.gmailRefreshToken) {
        return res.status(401).json({
          error:
            "Google did not return offline access. Approve all requested permissions.",
          code: "GMAIL_CONSENT_REQUIRED",
        });
      }

      const tokens = await attachAuthTokens(user);
      res.json({
        ...userPayload(user, tokens),
        googleIdToken: idToken,
        accessToken,
        scope: user.gmailScopes || scope,
      });
    } catch (err) {
      const msg = err.message || String(err);
      const status =
        err.status ||
        (err.code === "TERMS_REQUIRED"
          ? 400
          : err.code === "ACCOUNT_NOT_FOUND"
            ? 404
            : 401);
      res.status(status).json({
        error:
          err.code === "TERMS_REQUIRED" ||
          err.code === "ACCOUNT_NOT_FOUND" ||
          err.status === 400 ||
          err.status === 404
            ? msg
            : "Google verification failed: " + msg,
        code: err.code || undefined,
      });
    }
  },
);

router.post(
  "/password-reset/request",
  validateBody(passwordResetRequestSchema),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);

      const user = await findUserByEmail(User, email, { claimed: true });
      if (!user)
        return res
          .status(404)
          .json({ error: "No account found for this email" });

      const token = generateResetToken();
      const tokenHash = hashResetToken(token);
      const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);
      const emailHash = hashEmail(email);

      await PasswordReset.findOneAndUpdate(
        { emailHash },
        {
          email: encryptEmail(email),
          emailHash,
          tokenHash,
          expiresAt,
        },
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
      const emailHash = hashEmail(email);
      let record = await PasswordReset.findOne({ emailHash });
      if (!record) {
        // Legacy plaintext rows
        record = await PasswordReset.findOne({ email });
      }

      if (!record || record.tokenHash !== hashResetToken(token)) {
        return res.status(400).json({
          valid: false,
          expired: false,
          error: "This reset link is invalid. Please request a new one.",
        });
      }

      if (record.expiresAt < new Date()) {
        await PasswordReset.deleteOne({ _id: record._id });
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

      const emailHash = hashEmail(email);
      let record = await PasswordReset.findOne({ emailHash });
      if (!record) {
        record = await PasswordReset.findOne({ email });
      }
      if (!record || record.tokenHash !== hashResetToken(token)) {
        return res.status(400).json({
          error: "This reset link is invalid. Please request a new one.",
        });
      }
      if (record.expiresAt < new Date()) {
        await PasswordReset.deleteOne({ _id: record._id });
        return res.status(400).json({
          error:
            "This reset link has expired (links are valid for 30 minutes). Please request a new one.",
        });
      }

      const user = await findUserByEmail(User, email, { claimed: true });
      if (!user)
        return res
          .status(404)
          .json({ error: "No account found for this email" });

      user.passwordHash = await bcrypt.hash(password, 12);
      await user.save();
      await PasswordReset.deleteOne({ _id: record._id });

      await ensureUserSubscription(user);
      const tokens = await attachAuthTokens(user);
      res.json(userPayload(user, tokens));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  },
);

/** Exchange a valid refresh token for a new access + refresh pair. */
router.post("/refresh", validateBody(refreshTokenSchema), async (req, res) => {
  try {
    const { refreshToken } = req.body;
    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          error: "Refresh token expired. Please log in again.",
          code: "REFRESH_EXPIRED",
        });
      }
      return res.status(401).json({
        error: "Invalid refresh token. Please log in again.",
        code: "REFRESH_INVALID",
      });
    }

    const user = await User.findOne({ uuid: payload.uuid, claimed: true });
    if (!user) {
      return res.status(401).json({
        error: "Account not found. Please log in again.",
        code: "REFRESH_INVALID",
      });
    }

    const incomingHash = hashToken(refreshToken);
    if (!user.refreshTokenHash || user.refreshTokenHash !== incomingHash) {
      return res.status(401).json({
        error: "Refresh token revoked. Please log in again.",
        code: "REFRESH_REVOKED",
      });
    }

    await ensureUserSubscription(user);
    const tokens = await attachAuthTokens(user);
    res.json(userPayload(user, tokens));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/logout", authMiddleware, async (req, res) => {
  try {
    await User.updateOne(
      { uuid: req.user.uuid },
      { $unset: { refreshTokenHash: 1 } },
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post(
  "/keys",
  authMiddleware,
  validateBody(registerPublicKeySchema),
  async (req, res) => {
    try {
      const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!user) return res.status(404).json({ error: "User not found" });

      if (
        user.iron &&
        user.thor &&
        user.hulk &&
        user.venom
      ) {
        return res.json({
          ok: true,
          hasPublicKey: true,
          alreadyExists: true,
          uuid: user.uuid,
          email: getPlainEmail(user),
        });
      }

      const {
        iron,
        thor,
        hulk,
        venom,
      } = req.body;

      user.iron = String(iron).trim();
      user.thor = String(thor).trim();
      user.hulk = String(hulk).trim();
      user.venom = String(venom).trim();
      await user.save();
      // Drop legacy keyActionId if it still exists in older documents.
      await User.updateOne(
        { _id: user._id },
        { $unset: { keyActionId: 1 } },
      );

      res.json({
        ok: true,
        hasPublicKey: true,
        alreadyExists: false,
        uuid: user.uuid,
        email: getPlainEmail(user),
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
      user.iron &&
        user.thor &&
        user.hulk &&
        user.venom,
    );

    res.json({
      hasPublicKey: hasKeys,
      iron: user.iron || null,
      thor: user.thor || null,
      hulk: user.hulk || null,
      venom: user.venom || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// router.post("/google/refresh", authMiddleware, async (req, res) => {
//   try {
//     const { code, redirectUri } = req.body;
//     if (!code) {
//       return res.status(400).json({ error: "Google authorization code is required" });
//     }

//     const tokens = await exchangeCodeForTokens(code, redirectUri);
//     if (!tokens.id_token) {
//       return res.status(401).json({ error: "Google did not return an id_token" });
//     }

//     const payload = await verifyGoogleIdToken(tokens.id_token);
//     const user = await User.findOne({ uuid: req.user.uuid });
//     if (!user) return res.status(404).json({ error: "User not found" });

//     if (normalizeEmail(payload.email) !== getPlainEmail(user)) {
//       return res.status(403).json({
//         error: "Google account does not match your logged-in email.",
//       });
//     }

//     if (tokens.refresh_token) {
//       user.gmailRefreshToken = tokens.refresh_token;
//     }
//     user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
//     await user.save();

//     res.json({
//       googleIdToken: tokens.id_token,
//       gmailConnected: Boolean(user.gmailRefreshToken),
//       scope: user.gmailScopes,
//     });
//   } catch (err) {
//     res.status(401).json({ error: err.message });
//   }
// });

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
      } else if (!user.gmailRefreshToken) {
        return res.status(401).json({
          error:
            "Gmail permission was not saved. Approve all requested access and try again.",
          code: "GMAIL_CONSENT_REQUIRED",
        });
      }
      user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
      await user.save();

      res.json({
        accessToken: tokens.access_token,
        gmailConnected: Boolean(user.gmailRefreshToken),
        scope: user.gmailScopes,
      });
    } catch (err) {
      const msg = err.message || String(err);
      res.status(401).json({ error: msg });
    }
  },
);

// router.post("/gmail/disconnect", authMiddleware, async (req, res) => {
//   try {
//     await User.updateOne(
//       { uuid: req.user.uuid },
//       { $unset: { gmailRefreshToken: 1 }, $set: { gmailScopes: "" } },
//     );
//     res.json({ gmailConnected: false });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

router.get("/gmail/status", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      gmailConnected: Boolean(user.gmailRefreshToken),
      scope: user.gmailScopes || "",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/subscription", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    await ensureUserSubscription(user);
    res.json(subscriptionPayload(user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** Short-lived access token so the extension can send large attachments via Gmail (bypasses Vercel 4.5MB body limit). */
router.post("/gmail/send-token", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    await ensureUserSubscription(user);
    if (!isSubscriptionActive(user)) {
      return res.status(403).json(subscriptionBlockedError());
    }
    if (!user.gmailRefreshToken) {
      return res.status(403).json({
        error: "Allow Gmail access once to send from your address.",
        code: "GMAIL_NOT_CONNECTED",
      });
    }

    try {
      const accessToken = await getGmailAccessTokenFromRefresh(
        user.gmailRefreshToken,
      );
      res.json({
        accessToken,
        from: getPlainEmail(user),
        scope: user.gmailScopes || "",
        appUrl: (process.env.APP_URL || "").replace(/\/$/, ""),
      });
    } catch (tokenErr) {
      const msg = tokenErr.message || String(tokenErr);
      if (/invalid_grant|token has been expired|revoked/i.test(msg)) {
        await User.updateOne(
          { uuid: req.user.uuid },
          { $unset: { gmailRefreshToken: 1 } },
        );
        return res.status(403).json({
          error: "Gmail access expired. Allow Gmail again to continue sending.",
          code: "GMAIL_NOT_CONNECTED",
        });
      }
      throw tokenErr;
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** Access token for reading mailbox (Receive). No subscription required. */
router.post("/gmail/mailbox-token", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.gmailRefreshToken) {
      return res.status(403).json({
        error: "Allow Gmail access once to read your mailbox.",
        code: "GMAIL_NOT_CONNECTED",
      });
    }

    try {
      const accessToken = await getGmailAccessTokenFromRefresh(
        user.gmailRefreshToken,
      );
      res.json({
        accessToken,
        email: getPlainEmail(user),
        scope: user.gmailScopes || "",
      });
    } catch (tokenErr) {
      const msg = tokenErr.message || String(tokenErr);
      if (/invalid_grant|token has been expired|revoked/i.test(msg)) {
        await User.updateOne(
          { uuid: req.user.uuid },
          { $unset: { gmailRefreshToken: 1 } },
        );
        return res.status(403).json({
          error: "Gmail access expired. Allow Gmail again to read your mailbox.",
          code: "GMAIL_NOT_CONNECTED",
        });
      }
      throw tokenErr;
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// router.get("/gmail/connect", authMiddleware, async (req, res) => {
//   try {
//     const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
//     if (!user) return res.status(404).json({ error: "User not found" });

//     const state = await createConnectState(user.uuid);
//     const { url, redirectUri, clientId } = getGmailAuthUrl(state);
//     res.json({ url, redirectUri, clientId });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

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
      normalizeEmail(googleEmail) !== getPlainEmail(user)
    ) {
      return fail(
        `Google account (${googleEmail}) must match your login (${getPlainEmail(user)}).`,
      );
    }

    user.gmailRefreshToken = tokens.refresh_token;
    user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
    if (googleEmail) applyEncryptedEmail(user, googleEmail);
    await user.save();

    res.send(
      `<html><body style="font-family:system-ui;padding:24px"><h2>Gmail connected</h2><p>Sends will appear From: <b>${getPlainEmail(user)}</b></p></body></html>`,
    );
  } catch (err) {
    console.error("Gmail callback error:", err);
    fail(err.message || "Unexpected error");
  }
});

module.exports = router;
