const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const { sendResetEmail } = require("../lib/mail");
const {
  issueSignupOtp,
  consumeSignupOtp,
} = require("../lib/signupOtp");
const { normalizeEmail } = require("../lib/email");
const {
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
  findUserByMicrosoftId,
  linkMicrosoftIdentity,
} = require("../lib/emailCrypto");
const {
  getGmailAuthUrl,
  getOAuthConfig,
  exchangeCodeForTokens,
  getOAuthClient,
  createConnectState,
  consumeConnectState,
  getGmailAccessTokenFromRefresh,
  signWorkspaceGoogleState,
  verifyWorkspaceGoogleState,
  signWorkspaceConnectTicket,
  verifyWorkspaceConnectTicket,
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
  verifySessionToken,
  clearSessionToken,
  sendRelogin,
  RELOGIN_STATUS,
  DEFAULT_TOKEN_HOURS,
} = require("../lib/tokens");
const authMiddleware = require("../middleware/auth");
const { validateBody, validateQuery } = require("../middleware/validate");
const {
  signupSchema,
  signupSendOtpSchema,
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

async function attachAuthTokens(user, options = {}) {
  const issued = await issueAuthTokens(user, {
    expiresInHours: options.expiresInHours || DEFAULT_TOKEN_HOURS,
  });
  return {
    token: issued.token,
    refreshToken: issued.refreshToken,
    expiresAt: issued.expiresAt,
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
    refreshToken: tokens.refreshToken || tokens.token,
    createdAt: tokens.createdAt
      ? new Date(tokens.createdAt).toISOString()
      : null,
    expiresAt: tokens.expiresAt
      ? new Date(tokens.expiresAt).toISOString()
      : null,
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

router.post(
  "/signup/send-otp",
  validateBody(signupSendOtpSchema),
  async (req, res) => {
    try {
      const result = await issueSignupOtp(req.body.email);
      res.json(result);
    } catch (err) {
      const status = err.status || 500;
      res.status(status).json({
        error: err.message,
        code: err.code || undefined,
      });
    }
  },
);

router.post("/signup", validateBody(signupSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password, otp } = req.body;

    await consumeSignupOtp(email, otp);

    let user = await findUserByEmail(User, email);
    if (user?.deletedAt) {
      return res.status(403).json({
        error:
          "This account was removed. Contact your administrator to restore access.",
        code: "ACCOUNT_DELETED",
      });
    }
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
      user.onboardingComplete = false;
    } else {
      user = new User({
        passwordHash,
        claimed: true,
        termsAndConditions: true,
        onboardingComplete: false,
      });
      applyEncryptedEmail(user, email);
    }
    await finalizeClaimedUser(user);

    const tokens = await attachAuthTokens(user);
    res.json(userPayload(user, tokens));
  } catch (err) {
    const status = err.status || 500;
    res.status(status).json({
      error: err.message,
      code: err.code || undefined,
    });
  }
});

router.post("/login", validateBody(loginSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;
    const user = await findUserByEmail(User, email, { claimed: true });
    if (!user || !user.passwordHash)
      return res.status(401).json({ error: "Invalid credentials" });

    if (user.deletedAt) {
      return res.status(403).json({
        error: "This account was removed and cannot sign in.",
        code: "ACCOUNT_DELETED",
      });
    }

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

  if (user?.deletedAt) {
    const err = new Error(
      "This account was removed and cannot sign in. Contact your administrator.",
    );
    err.status = 403;
    err.code = "ACCOUNT_DELETED";
    throw err;
  }

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
      let gmailRefreshToken = req.body.gmailRefreshToken || null;
      let accessToken = null;
      let scope = String(req.body.gmailScopes || "");

      // Full Google login (code): identity + Gmail/Contacts/mailbox in one consent.
      if (req.body.code) {
        const tokens = await exchangeCodeForTokens(
          req.body.code,
          req.body.redirectUri,
        );
        idToken = tokens.id_token || null;
        gmailRefreshToken = tokens.refresh_token || gmailRefreshToken || null;
        accessToken = tokens.access_token || null;
        scope = tokens.scope || scope;

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
      if (!payload?.email_verified && payload?.email_verified !== undefined) {
        // Google may omit email_verified on some tokens; only reject explicit false.
      }
      if (payload && payload.email_verified === false) {
        return res.status(401).json({
          error: "Google email is not verified.",
          code: "EMAIL_NOT_VERIFIED",
        });
      }
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

function clearPasswordReset(user) {
  user.passwordResetTokenHash = null;
  user.passwordResetExpiresAt = null;
}

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
      user.passwordResetTokenHash = hashResetToken(token);
      user.passwordResetExpiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);
      await user.save();

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
      const user = await findUserByEmail(User, email, { claimed: true });

      if (
        !user?.passwordResetTokenHash ||
        user.passwordResetTokenHash !== hashResetToken(token)
      ) {
        return res.status(400).json({
          valid: false,
          expired: false,
          error: "This reset link is invalid. Please request a new one.",
        });
      }

      if (
        !user.passwordResetExpiresAt ||
        user.passwordResetExpiresAt < new Date()
      ) {
        clearPasswordReset(user);
        await user.save();
        return res.status(400).json({
          valid: false,
          expired: true,
          error:
            "This reset link has expired (links are valid for 30 minutes). Please request a new one.",
        });
      }

      const msLeft = user.passwordResetExpiresAt.getTime() - Date.now();
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

      const user = await findUserByEmail(User, email, { claimed: true });
      if (
        !user?.passwordResetTokenHash ||
        user.passwordResetTokenHash !== hashResetToken(token)
      ) {
        return res.status(400).json({
          error: "This reset link is invalid. Please request a new one.",
        });
      }
      if (
        !user.passwordResetExpiresAt ||
        user.passwordResetExpiresAt < new Date()
      ) {
        clearPasswordReset(user);
        await user.save();
        return res.status(400).json({
          error:
            "This reset link has expired (links are valid for 30 minutes). Please request a new one.",
        });
      }

      user.passwordHash = await bcrypt.hash(password, 12);
      clearPasswordReset(user);
      await user.save();

      await ensureUserSubscription(user);
      const tokens = await attachAuthTokens(user);
      res.json(userPayload(user, tokens));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  },
);

/**
 * Session tokens are DB-backed and last ~8h.
 * Refresh no longer extends JWT — if the session is still valid, return it;
 * otherwise require re-login (440).
 */
router.post("/refresh", validateBody(refreshTokenSchema), async (req, res) => {
  try {
    const { refreshToken } = req.body;
    let session;
    try {
      session = await verifySessionToken(refreshToken);
    } catch (err) {
      if (err.status === RELOGIN_STATUS || err.code === "TOKEN_EXPIRED" || err.code === "TOKEN_INVALID") {
        return sendRelogin(res, err.code || "RELOGIN_REQUIRED");
      }
      if (err.status === 403) {
        return res.status(403).json({ error: err.message, code: err.code });
      }
      return sendRelogin(res, "TOKEN_INVALID");
    }

    await ensureUserSubscription(session.user);
    return res.json(
      userPayload(session.user, {
        token: refreshToken,
        refreshToken,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
      }),
    );
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/logout", authMiddleware, async (req, res) => {
  try {
    await clearSessionToken(req.user.uuid);
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

/** Create RSA keys on the server if the logged-in user has none. */
router.post("/keys/ensure", authMiddleware, async (req, res) => {
  try {
    const { createKeyBundleForUuid } = require("../lib/secureCrypto");
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.iron && user.thor && user.hulk && user.venom) {
      return res.json({
        ok: true,
        hasPublicKey: true,
        created: false,
        iron: user.iron,
      });
    }

    const bundle = createKeyBundleForUuid(user.uuid);
    user.iron = bundle.iron;
    user.thor = bundle.thor;
    user.hulk = bundle.hulk;
    user.venom = bundle.venom;
    await user.save();
    await User.updateOne({ _id: user._id }, { $unset: { keyActionId: 1 } });

    res.json({
      ok: true,
      hasPublicKey: true,
      created: true,
      iron: user.iron,
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
    res.json({
      ...subscriptionPayload(user),
      email: getPlainEmail(user),
      uuid: user.uuid,
    });
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

router.get("/gmail/connect", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Same /auth/google/callback as Workspace login/signup.
    const ticket = signWorkspaceConnectTicket(user.uuid);
    const goUrl = `${appUrl()}/auth/google/start?mode=connect&ticket=${encodeURIComponent(ticket)}`;
    res.json({ goUrl, url: goUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** Legacy alias → unified Google start (connect). */
router.get("/gmail/go", async (req, res) => {
  const state = String(req.query.state || "").trim();
  if (!state) {
    return res
      .status(400)
      .send("Missing connect state. Return to Gmail and try Encrypt & send again.");
  }
  try {
    const user = await User.findOne({ gmailConnectState: state });
    if (
      !user ||
      !user.gmailConnectStateExpires ||
      user.gmailConnectStateExpires.getTime() < Date.now()
    ) {
      return res
        .status(400)
        .send(
          "Connect link expired. Return to Gmail, tap Encrypt & send, and allow Gmail again.",
        );
    }
    const ticket = signWorkspaceConnectTicket(user.uuid);
    return res.redirect(
      `${appUrl()}/auth/google/start?mode=connect&ticket=${encodeURIComponent(ticket)}`,
    );
  } catch (err) {
    return res.status(500).send(err.message || "Could not start Google sign-in.");
  }
});

const userOAuth = require("../lib/userOAuth");

/** Allow Workspace Apps Script + configured Outlook/admin return origins. */
function isWorkspaceGoogleReturnOrigin_(origin) {
  if (userOAuth.isAllowedReturnOrigin(origin)) return true;
  try {
    const host = new URL(String(origin || "")).hostname.toLowerCase();
    return (
      host === "script.google.com" ||
      host.endsWith(".googleusercontent.com") ||
      host === "localhost" ||
      host === "127.0.0.1"
    );
  } catch (_) {
    return false;
  }
}

function googleOAuthFailPage(res, title, message) {
  return res.status(400).send(
    `<!DOCTYPE html><html><body style="font-family:system-ui;padding:24px;background:#0f1c24;color:#eef6f8">
<h2 style="color:#ff6b7a">${title}</h2>
<p>${message}</p>
<p>Close this window and return to the SecureDocShare Workspace app.</p>
</body></html>`,
  );
}

/**
 * Unified Google callback for Workspace:
 * - login / signup (creates session ticket + stores Gmail refresh token)
 * - connect (Gmail scopes only for an existing logged-in user)
 * Same redirect URI: /auth/google/callback
 */
async function handleGoogleOAuthCallback(req, res) {
  try {
    const { code, state, error, error_description: errorDescription } =
      req.query;
    if (error) {
      return googleOAuthFailPage(
        res,
        "Google sign-in failed",
        `${error}${errorDescription ? `: ${errorDescription}` : ""}`,
      );
    }
    if (!code || !state) {
      return googleOAuthFailPage(
        res,
        "Google sign-in failed",
        "Missing code or state.",
      );
    }

    let wsState = null;
    try {
      wsState = verifyWorkspaceGoogleState(String(state));
    } catch (_) {
      wsState = null;
    }

    // Legacy hex connect-state (older Encrypt & send links).
    if (!wsState) {
      return handleLegacyGmailConnectCallback(req, res, String(code), String(state));
    }

    const tokens = await exchangeCodeForTokens(String(code));
    const oauth2Client = getOAuthClient();
    oauth2Client.setCredentials(tokens);
    const { google } = require("googleapis");
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const info = (await oauth2.userinfo.get()).data;
    const googleEmail = info.email;
    if (!googleEmail) {
      return googleOAuthFailPage(
        res,
        "Google sign-in failed",
        "Google did not return an email address.",
      );
    }

    const mode = wsState.mode === "connect" ? "connect" : "auth";
    const intent = wsState.intent === "signup" ? "signup" : "login";
    const acceptTerms = Boolean(wsState.terms);

    if (mode === "connect") {
      if (!wsState.uuid) {
        return googleOAuthFailPage(
          res,
          "Gmail connect failed",
          "Missing user on connect state.",
        );
      }
      if (!tokens.refresh_token) {
        return googleOAuthFailPage(
          res,
          "Gmail connect failed",
          "No refresh token returned. Revoke SecureDocShare at myaccount.google.com/permissions and try again.",
        );
      }
      const user = await User.findOne({ uuid: wsState.uuid, claimed: true });
      if (!user) {
        return googleOAuthFailPage(res, "Gmail connect failed", "User not found.");
      }
      if (normalizeEmail(googleEmail) !== getPlainEmail(user)) {
        return googleOAuthFailPage(
          res,
          "Gmail connect failed",
          `Google account (${googleEmail}) must match your login (${getPlainEmail(user)}).`,
        );
      }
      user.gmailRefreshToken = tokens.refresh_token;
      user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
      await user.save();
      return res.send(
        `<!DOCTYPE html><html><body style="font-family:system-ui;padding:24px;background:#0f1c24;color:#eef6f8">
<h2 style="color:#2bb3a0">Gmail connected</h2>
<p>Sends will appear From: <b>${getPlainEmail(user)}</b></p>
<p>Close this window and tap Encrypt & send again.</p>
<script>setTimeout(function(){try{window.close();}catch(e){}},900);</script>
</body></html>`,
      );
    }

    // Login / signup for Workspace Marketplace app.
    let user;
    try {
      user = await upsertUserFromOAuth(
        {
          email: googleEmail,
          name: info.name || "",
          subject: info.id || info.sub || "",
        },
        {
          intent,
          acceptTerms,
          provider: "google",
          gmailRefreshToken: tokens.refresh_token || null,
          gmailScopes: tokens.scope || "",
        },
      );
    } catch (err) {
      return googleOAuthFailPage(
        res,
        intent === "signup" ? "Sign up failed" : "Login failed",
        err.message || "Could not complete Google sign-in.",
      );
    }

    // If Google did not return a new refresh token, keep any existing grant.
    if (tokens.refresh_token) {
      user.gmailRefreshToken = tokens.refresh_token;
      user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
      await user.save();
    }

    const ticket = userOAuth.signUserOAuthTicket(user.uuid);
    const returnOrigin = String(wsState.o || appUrl()).replace(/\/$/, "");
    const returnPath = String(wsState.path || "/api/auth/oauth/popup-done");
    // Workspace web app runs on script.google.com; Outlook origins stay on the allow-list.
    if (!isWorkspaceGoogleReturnOrigin_(returnOrigin)) {
      const dest = new URL("/api/auth/oauth/popup-done", `${appUrl()}/`);
      dest.searchParams.set("oauth_ticket", ticket);
      return res.redirect(dest.toString());
    }
    const dest = new URL(
      returnPath.startsWith("/") ? returnPath : `/${returnPath}`,
      `${returnOrigin}/`,
    );
    dest.searchParams.set("oauth_ticket", ticket);
    return res.redirect(dest.toString());
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    return googleOAuthFailPage(
      res,
      "Google sign-in failed",
      err.message || "Unexpected error",
    );
  }
}

async function handleLegacyGmailConnectCallback(req, res, code, state) {
  const uuid = await consumeConnectState(state);
  if (!uuid) {
    return googleOAuthFailPage(
      res,
      "Gmail connect failed",
      "Connect link expired. Try Encrypt & send again.",
    );
  }
  const tokens = await exchangeCodeForTokens(code);
  if (!tokens.refresh_token) {
    return googleOAuthFailPage(
      res,
      "Gmail connect failed",
      "No refresh token returned. Revoke app access at myaccount.google.com/permissions and try again.",
    );
  }
  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials(tokens);
  const { google } = require("googleapis");
  const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
  const googleEmail = (await oauth2.userinfo.get()).data.email;
  const user = await User.findOne({ uuid });
  if (!user) {
    return googleOAuthFailPage(res, "Gmail connect failed", "User not found.");
  }
  if (googleEmail && normalizeEmail(googleEmail) !== getPlainEmail(user)) {
    return googleOAuthFailPage(
      res,
      "Gmail connect failed",
      `Google account (${googleEmail}) must match your login (${getPlainEmail(user)}).`,
    );
  }
  user.gmailRefreshToken = tokens.refresh_token;
  user.gmailScopes = mergeGrantedScopes(user.gmailScopes, tokens.scope);
  if (googleEmail) applyEncryptedEmail(user, googleEmail);
  await user.save();
  return res.send(
    `<!DOCTYPE html><html><body style="font-family:system-ui;padding:24px;background:#0f1c24;color:#eef6f8">
<h2 style="color:#2bb3a0">Gmail connected</h2>
<p>Sends will appear From: <b>${getPlainEmail(user)}</b></p>
<p>Close this window and tap Encrypt & send again.</p>
<script>setTimeout(function(){try{window.close();}catch(e){}},900);</script>
</body></html>`,
  );
}

/** Start Workspace Google OAuth (login / signup / connect) → same callback. */
async function handleGoogleOAuthStart(req, res) {
  try {
    const mode =
      String(req.query.mode || "").toLowerCase() === "connect"
        ? "connect"
        : "auth";
    const intent = req.query.intent === "signup" ? "signup" : "login";
    const acceptTerms =
      req.query.acceptTerms === "1" ||
      req.query.acceptTerms === "true" ||
      req.query.acceptTerms === true;

    if (mode === "auth" && intent === "signup" && !acceptTerms) {
      return googleOAuthFailPage(
        res,
        "Sign up failed",
        "You must accept the Terms & Conditions.",
      );
    }

    let returnOrigin = String(
      req.query.returnOrigin || appUrl(),
    ).replace(/\/$/, "");
    let returnPath = String(
      req.query.returnPath || "/api/auth/oauth/popup-done",
    );
    if (!returnPath.startsWith("/")) returnPath = `/${returnPath}`;

    const statePayload = {
      mode,
      intent,
      terms: Boolean(acceptTerms),
      o: returnOrigin,
      path: returnPath,
    };

    if (mode === "connect") {
      const ticket = String(req.query.ticket || "").trim();
      const payload = verifyWorkspaceConnectTicket(ticket);
      statePayload.uuid = payload.uuid;
      statePayload.mode = "connect";
    }

    const state = signWorkspaceGoogleState(statePayload);
    const { url } = getGmailAuthUrl(state);
    return res.redirect(url);
  } catch (err) {
    console.error("Google OAuth start error:", err);
    return googleOAuthFailPage(
      res,
      "Google sign-in failed",
      err.message || "Could not start Google sign-in.",
    );
  }
}

router.get("/gmail/callback", handleGoogleOAuthCallback);

async function upsertUserFromOAuth(
  profile,
  {
    intent = "login",
    acceptTerms = false,
    provider = "google",
    gmailRefreshToken = null,
    gmailScopes = "",
  } = {},
) {
  const email = normalizeEmail(profile.email);
  const microsoftId =
    provider === "microsoft" && profile.subject
      ? String(profile.subject)
      : null;

  // Prefer stable provider ids so Hotmail/Outlook/Live aliases map to one RSA user.
  let user = microsoftId
    ? await findUserByMicrosoftId(User, microsoftId)
    : null;
  if (!user && provider === "google" && profile.subject) {
    user = await User.findOne({
      googleId: String(profile.subject),
      deletedAt: null,
    });
  }
  if (!user) {
    user = await findUserByEmail(User, email);
  }

  const isNewClaim = !user || !user.claimed;

  if (user?.deletedAt) {
    const err = new Error(
      "This account was removed and cannot sign in. Contact your administrator.",
    );
    err.status = 403;
    err.code = "ACCOUNT_DELETED";
    throw err;
  }

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

  if (intent === "signup" && user?.claimed) {
    const sameMicrosoft =
      Boolean(microsoftId) &&
      String(user.microsoftId || "") === String(microsoftId);
    const sameGoogle =
      provider === "google" &&
      profile.subject &&
      String(user.googleId || "") === String(profile.subject);
    if (!sameMicrosoft && !sameGoogle) {
      const err = new Error(
        "An account with this email already exists. Log in instead.",
      );
      err.status = 409;
      err.code = "ACCOUNT_EXISTS";
      throw err;
    }
  }

  if (!user) {
    user = new User({
      claimed: true,
      termsAndConditions: Boolean(acceptTerms),
      name: profile.name ? String(profile.name).slice(0, 200) : "",
      onboardingComplete: intent === "signup" ? false : true,
    });
    applyEncryptedEmail(user, email);
  } else {
    // Existing Microsoft account (any alias): keep RSA keys; don't overwrite
    // primary email if already set — aliases are tracked separately.
    if (!user.claimed) {
      applyEncryptedEmail(user, email);
    } else if (!getPlainEmail(user) && email) {
      applyEncryptedEmail(user, email);
    }
    user.claimed = true;
    if (acceptTerms) user.termsAndConditions = true;
    if (intent === "signup" && !user.onboardingComplete) {
      user.onboardingComplete = false;
    }
    if (profile.name && !user.name) {
      user.name = String(profile.name).slice(0, 200);
    }
  }

  if (provider === "google" && profile.subject) {
    user.googleId = String(profile.subject);
  }
  if (microsoftId) {
    linkMicrosoftIdentity(user, {
      microsoftId,
      emails: profile.emails || [],
      primaryEmail: email,
    });
  }

  if (provider === "google") {
    if (gmailRefreshToken) {
      user.gmailRefreshToken = gmailRefreshToken;
    }
    if (gmailScopes) {
      user.gmailScopes = mergeGrantedScopes(user.gmailScopes, gmailScopes);
    }
  }

  await finalizeClaimedUser(user);

  if (microsoftId) {
    console.log("[upsertUserFromOAuth] saved User.microsoftId", {
      uuid: user.uuid,
      microsoftId: user.microsoftId,
      primaryEmail: getPlainEmail(user),
      aliasHashes: Array.isArray(user.microsoftAliasHashes)
        ? user.microsoftAliasHashes.length
        : 0,
    });
  }

  return user;
}

function redirectUserOAuthError(returnOrigin, returnPath, message) {
  const path = returnPath || "/oauth-dialog-callback.html";
  const url = new URL(path, `${returnOrigin}/`);
  url.searchParams.set("oauth_error", message || "SSO failed");
  return url.toString();
}

router.get("/oauth/providers", (req, res) => {
  return res.json({
    providers: userOAuth.configuredProviders(),
  });
});

router.get("/oauth/:provider/start", (req, res) => {
  try {
    const provider = String(req.params.provider || "").toLowerCase();
    console.log("[outlook oauth] START", {
      provider,
      returnOrigin: req.query.returnOrigin,
      intent: req.query.intent,
      host: req.get("host"),
    });
    if (!userOAuth.PROVIDERS.includes(provider)) {
      return res.status(404).json({ error: "Unknown SSO provider" });
    }
    const returnOrigin = String(
      req.query.returnOrigin || req.get("origin") || "",
    ).replace(/\/$/, "");
    const returnPath = String(
      req.query.returnPath || "/oauth-dialog-callback.html",
    );
    const intent = req.query.intent === "signup" ? "signup" : "login";
    const acceptTerms =
      req.query.acceptTerms === "1" ||
      req.query.acceptTerms === "true" ||
      req.query.acceptTerms === true;

    if (intent === "signup" && !acceptTerms) {
      return res.redirect(
        redirectUserOAuthError(
          returnOrigin,
          returnPath,
          "You must accept the Terms & Conditions",
        ),
      );
    }

    const { url, redirectUri } = userOAuth.buildAuthorizeUrl(provider, {
      returnOrigin,
      returnPath,
      intent,
      acceptTerms,
    });
    console.log("[outlook oauth] START redirect_uri", redirectUri);
    return res.redirect(url);
  } catch (err) {
    const status = err.status || 500;
    const origin = String(req.query.returnOrigin || "").replace(/\/$/, "");
    const returnPath = String(
      req.query.returnPath || "/oauth-dialog-callback.html",
    );
    if (origin && req.accepts("html")) {
      return res.redirect(
        redirectUserOAuthError(origin, returnPath, err.message),
      );
    }
    return res.status(status).json({
      error: err.message,
      code: err.code || "OAUTH_START_FAILED",
    });
  }
});

router.get("/oauth/:provider/callback", async (req, res) => {
  let returnOrigin = String(
    process.env.ADDIN_HTTPS_ORIGIN || "https://localhost:3000",
  ).replace(/\/$/, "");
  let returnPath = "/oauth-dialog-callback.html";
  try {
    const provider = String(req.params.provider || "").toLowerCase();
    console.log("[outlook oauth] CALLBACK hit", {
      provider,
      hasCode: Boolean(req.query.code),
      hasError: Boolean(req.query.error),
      host: req.get("host"),
    });
    if (!userOAuth.PROVIDERS.includes(provider)) {
      return res.status(404).send("Unknown SSO provider");
    }

    if (req.query.error) {
      try {
        if (req.query.state) {
          const peek = userOAuth.verifyState(String(req.query.state));
          if (peek?.o) returnOrigin = peek.o;
          if (peek?.path) returnPath = peek.path;
        }
      } catch {
        /* ignore */
      }
      return res.redirect(
        redirectUserOAuthError(
          returnOrigin,
          returnPath,
          String(req.query.error_description || req.query.error),
        ),
      );
    }

    const code = String(req.query.code || "");
    const stateToken = String(req.query.state || "");
    if (!code || !stateToken) {
      return res.redirect(
        redirectUserOAuthError(returnOrigin, returnPath, "Missing OAuth code"),
      );
    }

    const state = userOAuth.verifyState(stateToken);
    if (state.typ !== "user_oauth" || state.p !== provider) {
      return res.redirect(
        redirectUserOAuthError(returnOrigin, returnPath, "Invalid OAuth state"),
      );
    }
    returnOrigin = state.o;
    returnPath = state.path || "/oauth-dialog-callback.html";
    const intent = state.intent === "signup" ? "signup" : "login";
    const acceptTerms = Boolean(state.terms);

    const redirectUri = state.ru || userOAuth.callbackUri(provider);
    const tokens = await userOAuth.exchangeCode(provider, code, redirectUri);
    if (!tokens.access_token) {
      return res.redirect(
        redirectUserOAuthError(
          returnOrigin,
          returnPath,
          "No access token from provider",
        ),
      );
    }

    // TEMP: copy into Postman Bearer token for Graph /me. Remove after debugging.
    if (provider === "microsoft") {
      console.log("[Outlook Microsoft SSO] access_token:\n" + tokens.access_token);
      console.log("[Outlook Microsoft SSO] token meta", {
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        redirectUri,
      });
    }

    const profile = await userOAuth.fetchProfile(
      provider,
      tokens.access_token,
    );
    if (!profile.email) {
      return res.redirect(
        redirectUserOAuthError(
          returnOrigin,
          returnPath,
          "Provider did not return an email address",
        ),
      );
    }

    const user = await upsertUserFromOAuth(profile, {
      intent,
      acceptTerms,
      provider,
      gmailRefreshToken:
        provider === "google" ? tokens.refresh_token || null : null,
      gmailScopes: provider === "google" ? tokens.scope || "" : "",
    });

    const ticket = userOAuth.signUserOAuthTicket(user.uuid);
    const dest = new URL(returnPath, `${returnOrigin}/`);
    dest.searchParams.set("oauth_ticket", ticket);
    return res.redirect(dest.toString());
  } catch (err) {
    console.error("user oauth callback:", err.message);
    return res.redirect(
      redirectUserOAuthError(
        returnOrigin,
        returnPath,
        err.message || "SSO failed",
      ),
    );
  }
});

router.post("/oauth/complete", async (req, res) => {
  try {
    const ticket = String(req.body?.ticket || req.body?.oauth_ticket || "");
    if (!ticket) {
      return res.status(400).json({
        error: "Missing OAuth ticket",
        code: "OAUTH_TICKET_REQUIRED",
      });
    }
    const payload = userOAuth.verifyUserOAuthTicket(ticket);
    const user = await User.findOne({ uuid: payload.uuid });
    if (!user || user.deletedAt || !user.claimed) {
      return res.status(401).json({
        error: "Invalid or expired OAuth session",
        code: "OAUTH_TICKET_INVALID",
      });
    }
    const tokens = await attachAuthTokens(user);
    return res.json(userPayload(user, tokens));
  } catch (err) {
    const status = err.status || 401;
    return res.status(status).json({
      error: err.message || "OAuth complete failed",
      code: err.code || "OAUTH_COMPLETE_FAILED",
    });
  }
});

module.exports = router;
module.exports.handleGoogleOAuthCallback = handleGoogleOAuthCallback;
module.exports.handleGoogleOAuthStart = handleGoogleOAuthStart;
// Back-compat alias
module.exports.handleGmailOAuthCallback = handleGoogleOAuthCallback;
