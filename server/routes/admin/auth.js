const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../../models/User");
const SystemSettings = require("../../models/SystemSettings");
const { normalizeEmail } = require("../../lib/email");
const {
  findUserByEmail,
  getPlainEmail,
  applyEncryptedEmail,
  findUserByMicrosoftId,
  linkMicrosoftIdentity,
} = require("../../lib/emailCrypto");
const {
  issueAuthTokens,
  clearSessionToken,
  DEFAULT_TOKEN_HOURS,
} = require("../../lib/tokens");
const {
  calculateGroupExpiresAt,
} = require("../../lib/subscription");
const {
  canAccessPanel,
  publicUserWithHierarchy,
} = require("../../lib/rbac");
const {
  setAdminSessionCookie,
  clearAdminSessionCookie,
} = require("../../lib/adminSessionCookie");
const {
  PROVIDERS,
  configuredProviders,
  buildAuthorizeUrl,
  verifyState,
  exchangeCode,
  fetchProfile,
  callbackUri,
  usesHubCallback,
  verifySsoTicket,
  issueSsoHandoff,
  consumeSsoHandoff,
} = require("../../lib/adminOAuth");
const {
  ensureUserSubscription,
  trialExpiresFrom,
} = require("../../lib/subscription");
const { validateBody } = require("../../middleware/validate");
const {
  adminLoginSchema,
  signupSchema,
  signupSendOtpSchema,
  profileUpdateSchema,
  profilePasswordSchema,
  createGroupOnboardingSchema,
  chooseSubscriberOnboardingSchema,
} = require("../../validation/schemas");
const { adminAuthMiddleware } = require("../../middleware/adminAuth");
const {
  issueSignupOtp,
  consumeSignupOtp,
} = require("../../lib/signupOtp");
const Group = require("../../models/Group");
const { logActivity } = require("../../lib/activityLog");

const router = express.Router();

async function sessionHours() {
  const settings = await SystemSettings.getOrCreate();
  return Number(settings.tokenExpiryHours) || DEFAULT_TOKEN_HOURS;
}

async function issuePanelSession(res, req, user) {
  const settings = await SystemSettings.getOrCreate();
  const hours = await sessionHours();
  const issued = await issueAuthTokens(user, { expiresInHours: hours });
  setAdminSessionCookie(req, res, issued.token, issued.expiresAt);
  return {
    ok: true,
    expiresAt: issued.expiresAt,
    user: await publicUserWithHierarchy(user, { getPlainEmail }),
    settings: {
      tokenExpiryHours: settings.tokenExpiryHours,
      checkInIntervalHours: settings.checkInIntervalHours,
    },
    session: {
      createdAt: issued.createdAt,
      expiresAt: issued.expiresAt,
    },
  };
}

async function resolvePanelUserByEmail(email) {
  const user = await findUserByEmail(User, normalizeEmail(email));
  if (!user?.claimed || user.deletedAt) {
    const err = new Error(
      "No account for this email. Sign up first or ask an admin to invite you.",
    );
    err.status = 404;
    err.code = "ACCOUNT_NOT_FOUND";
    throw err;
  }
  if (!canAccessPanel(user)) {
    const err = new Error("Panel access required");
    err.status = 403;
    err.code = "PANEL_REQUIRED";
    throw err;
  }
  if (user.blocked) {
    const err = new Error("Account is blocked");
    err.status = 403;
    err.code = "ACCOUNT_BLOCKED";
    throw err;
  }
  return user;
}

/** Login or create (signup) panel user from SSO profile. */
async function resolveOrCreatePanelUserFromSso(profile, { intent, acceptTerms, provider }) {
  const email = normalizeEmail(profile.email);
  const microsoftId =
    provider === "microsoft" && profile.subject
      ? String(profile.subject)
      : null;

  // Microsoft: resolve by stable Graph oid first (aliases share the same id).
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
      "No account for this email. Sign up first or ask an admin to invite you.",
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

  // Same Microsoft account signing up again under a different alias → allow (login).
  if (intent === "signup" && user?.claimed) {
    const sameMicrosoft =
      Boolean(microsoftId) &&
      String(user.microsoftId || "") === String(microsoftId);
    if (!sameMicrosoft) {
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
      name: profile.name || "",
      role: "subscriber",
      subscriptionExpiresAt: trialExpiresFrom(new Date()),
      onboardingComplete: intent === "signup" ? false : true,
    });
    applyEncryptedEmail(user, email);
  } else if (!user.claimed) {
    applyEncryptedEmail(user, email);
    user.claimed = true;
    user.termsAndConditions = Boolean(acceptTerms);
    if (profile.name && !user.name) user.name = profile.name;
    if (!user.subscriptionExpiresAt) {
      user.subscriptionExpiresAt = trialExpiresFrom(new Date());
    }
    if (intent === "signup") user.onboardingComplete = false;
  } else {
    if (profile.name && !user.name) user.name = profile.name;
  }

  if (provider === "google" && profile.subject) {
    user.googleId = profile.subject;
  }
  if (microsoftId) {
    linkMicrosoftIdentity(user, {
      microsoftId,
      emails: profile.emails || [],
      primaryEmail: email,
    });
  }

  await user.save();
  await ensureUserSubscription(user);

  if (microsoftId) {
    console.log("[admin SSO] saved User.microsoftId", {
      uuid: user.uuid,
      microsoftId: user.microsoftId,
      primaryEmail: getPlainEmail(user),
      aliasHashes: Array.isArray(user.microsoftAliasHashes)
        ? user.microsoftAliasHashes.length
        : 0,
    });
  }

  if (!canAccessPanel(user)) {
    const err = new Error("Panel access required");
    err.status = 403;
    err.code = "PANEL_REQUIRED";
    throw err;
  }
  if (user.blocked) {
    const err = new Error("Account is blocked");
    err.status = 403;
    err.code = "ACCOUNT_BLOCKED";
    throw err;
  }
  return user;
}

function redirectAuthError(returnOrigin, message, { intent } = {}) {
  const path = intent === "signup" ? "/signup" : "/login";
  const url = new URL(path, `${returnOrigin}/`);
  url.searchParams.set("sso_error", message || "SSO failed");
  return url.toString();
}

router.get("/oauth/providers", (req, res) => {
  return res.json({
    providers: configuredProviders(),
    callbackMode: process.env.ADMIN_OAUTH_CALLBACK_MODE || "per_origin",
  });
});

router.get("/oauth/:provider/start", (req, res) => {
  try {
    const provider = String(req.params.provider || "").toLowerCase();
    console.log("[admin oauth] START", {
      provider,
      returnOrigin: req.query.returnOrigin,
      intent: req.query.intent,
      host: req.get("host"),
    });
    if (!PROVIDERS.includes(provider)) {
      return res.status(404).json({ error: "Unknown SSO provider" });
    }
    const returnOrigin = String(
      req.query.returnOrigin || req.get("origin") || "",
    ).replace(/\/$/, "");
    const returnPath = String(req.query.returnPath || "/");
    const intent = req.query.intent === "signup" ? "signup" : "login";
    const acceptTerms =
      req.query.acceptTerms === "1" ||
      req.query.acceptTerms === "true" ||
      req.query.acceptTerms === true;
    if (intent === "signup" && !acceptTerms) {
      return res.redirect(
        redirectAuthError(returnOrigin, "You must accept the Terms & Conditions", {
          intent: "signup",
        }),
      );
    }
    const { url, redirectUri } = buildAuthorizeUrl(provider, {
      returnOrigin,
      returnPath,
      intent,
      acceptTerms,
    });
    console.log("[admin oauth] START redirect_uri", redirectUri);
    return res.redirect(url);
  } catch (err) {
    const status = err.status || 500;
    const origin = String(req.query.returnOrigin || "").replace(/\/$/, "");
    const intent = req.query.intent === "signup" ? "signup" : "login";
    if (origin && req.accepts("html")) {
      return res.redirect(redirectAuthError(origin, err.message, { intent }));
    }
    return res.status(status).json({
      error: err.message,
      code: err.code || "OAUTH_START_FAILED",
    });
  }
});

router.get("/oauth/:provider/callback", async (req, res) => {
  let returnOrigin = String(
    process.env.ADMIN_APP_URL || "http://localhost:5174",
  ).replace(/\/$/, "");
  let returnPath = "/";
  let intent = "login";
  try {
    const provider = String(req.params.provider || "").toLowerCase();
    console.log("[admin oauth] CALLBACK hit", {
      provider,
      hasCode: Boolean(req.query.code),
      hasError: Boolean(req.query.error),
      host: req.get("host"),
    });
    if (!PROVIDERS.includes(provider)) {
      return res.status(404).send("Unknown SSO provider");
    }

    if (req.query.error) {
      try {
        if (req.query.state) {
          const peek = verifyState(String(req.query.state));
          if (peek?.o) returnOrigin = peek.o;
          if (peek?.intent) intent = peek.intent;
        }
      } catch {
        /* ignore */
      }
      return res.redirect(
        redirectAuthError(
          returnOrigin,
          String(req.query.error_description || req.query.error),
          { intent },
        ),
      );
    }

    const code = String(req.query.code || "");
    const stateToken = String(req.query.state || "");
    if (!code || !stateToken) {
      return res.redirect(
        redirectAuthError(returnOrigin, "Missing OAuth code", { intent }),
      );
    }

    const state = verifyState(stateToken);
    if (state.p !== provider) {
      return res.redirect(
        redirectAuthError(returnOrigin, "Invalid OAuth state", { intent }),
      );
    }
    returnOrigin = state.o;
    returnPath = state.path || "/";
    intent = state.intent === "signup" ? "signup" : "login";
    const acceptTerms = Boolean(state.terms);

    // Must match the redirect_uri from the authorize request exactly.
    const redirectUri =
      state.ru || callbackUri(provider, returnOrigin);
    const tokens = await exchangeCode(provider, code, redirectUri);
    if (!tokens.access_token) {
      return res.redirect(
        redirectAuthError(returnOrigin, "No access token from provider", {
          intent,
        }),
      );
    }

    // TEMP: copy this into Postman Bearer token for Graph /me testing.
    // Remove after debugging — do not leave tokens in production logs.
    if (provider === "microsoft") {
      console.log("[Microsoft SSO] access_token:\n" + tokens.access_token);
      console.log("[Microsoft SSO] token meta", {
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        redirectUri,
      });
    }

    const profile = await fetchProfile(provider, tokens.access_token);
    if (!profile.email) {
      return res.redirect(
        redirectAuthError(
          returnOrigin,
          "Provider did not return an email address",
          { intent },
        ),
      );
    }

    const user = await resolveOrCreatePanelUserFromSso(profile, {
      intent,
      acceptTerms,
      provider,
    });

    if (state.hub || usesHubCallback(provider, returnOrigin)) {
      const ticket = await issueSsoHandoff(user);
      const url = new URL(
        intent === "signup" ? "/signup" : "/login",
        `${returnOrigin}/`,
      );
      url.searchParams.set("sso_ticket", ticket);
      if (returnPath && returnPath !== "/") {
        url.searchParams.set("next", returnPath);
      }
      return res.redirect(url.toString());
    }

    await issuePanelSession(res, req, user);
    const destPath =
      returnPath && returnPath !== "/"
        ? returnPath
        : user.role === "subscriber"
          ? "/profile"
          : "/";
    const dest = new URL(destPath, `${returnOrigin}/`);
    dest.searchParams.set("sso", "ok");
    return res.redirect(dest.toString());
  } catch (err) {
    console.error("admin oauth callback:", err.message);
    return res.redirect(
      redirectAuthError(returnOrigin, err.message || "SSO failed", { intent }),
    );
  }
});

router.post(
  "/signup/send-otp",
  validateBody(signupSendOtpSchema),
  async (req, res) => {
    try {
      const result = await issueSignupOtp(req.body.email);
      return res.json(result);
    } catch (err) {
      return res.status(err.status || 500).json({
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
    if (user?.claimed) {
      return res.status(409).json({
        error: "An account with this email already exists. Log in instead.",
        code: "ACCOUNT_EXISTS",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    if (user) {
      applyEncryptedEmail(user, email);
      user.passwordHash = passwordHash;
      user.claimed = true;
      user.termsAndConditions = true;
      user.role = user.role || "subscriber";
      user.onboardingComplete = false;
      if (!user.subscriptionExpiresAt) {
        user.subscriptionExpiresAt = trialExpiresFrom(new Date());
      }
    } else {
      user = new User({
        passwordHash,
        claimed: true,
        termsAndConditions: true,
        role: "subscriber",
        onboardingComplete: false,
        subscriptionExpiresAt: trialExpiresFrom(new Date()),
      });
      applyEncryptedEmail(user, email);
    }
    await user.save();
    await ensureUserSubscription(user);

    if (!canAccessPanel(user)) {
      return res.status(403).json({
        error: "Panel access required",
        code: "PANEL_REQUIRED",
      });
    }

    const data = await issuePanelSession(res, req, user);
    return res.status(201).json(data);
  } catch (err) {
    return res.status(err.status || 500).json({
      error: err.message,
      code: err.code || undefined,
    });
  }
});

router.post("/oauth/complete", async (req, res) => {
  try {
    const ticket = String(req.body.ticket || "");
    if (!ticket) {
      return res.status(400).json({ error: "Missing SSO ticket" });
    }

    // Prefer DB handoff (Yahoo hub → local). Falls back to legacy JWT ticket.
    let user = await consumeSsoHandoff(ticket);
    if (!user) {
      const payload = verifySsoTicket(ticket);
      user = await User.findOne({ uuid: payload.uuid, deletedAt: null });
    }

    if (!user?.claimed) {
      return res.status(404).json({
        error: "Account not found",
        code: "ACCOUNT_NOT_FOUND",
      });
    }
    if (!canAccessPanel(user)) {
      return res.status(403).json({
        error: "Panel access required",
        code: "PANEL_REQUIRED",
      });
    }
    if (user.blocked) {
      return res.status(403).json({
        error: "Account is blocked",
        code: "ACCOUNT_BLOCKED",
      });
    }
    const data = await issuePanelSession(res, req, user);
    return res.json(data);
  } catch (err) {
    const status =
      err.status || (err.name === "JsonWebTokenError" ? 401 : 500);
    return res.status(status).json({
      error: err.message || "SSO complete failed",
      code: err.code || "OAUTH_COMPLETE_FAILED",
    });
  }
});

router.post("/login", validateBody(adminLoginSchema), async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const user = await findUserByEmail(User, email);
    if (!user?.claimed || !user.passwordHash || user.deletedAt) {
      return res
        .status(401)
        .json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
    }
    if (!canAccessPanel(user)) {
      return res
        .status(403)
        .json({ error: "Panel access required", code: "PANEL_REQUIRED" });
    }
    if (user.blocked) {
      return res
        .status(403)
        .json({ error: "Account is blocked", code: "ACCOUNT_BLOCKED" });
    }

    const ok = await bcrypt.compare(req.body.password, user.passwordHash);
    if (!ok) {
      return res
        .status(401)
        .json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
    }

    const data = await issuePanelSession(res, req, user);
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/logout", adminAuthMiddleware, async (req, res) => {
  try {
    await clearSessionToken(req.admin.uuid);
    clearAdminSessionCookie(req, res);
    return res.json({ ok: true });
  } catch (err) {
    clearAdminSessionCookie(req, res);
    return res.status(500).json({ error: err.message });
  }
});

/** Soft logout when session already invalid — still clears cookie. */
router.post("/logout-local", async (req, res) => {
  clearAdminSessionCookie(req, res);
  return res.json({ ok: true });
});

router.get("/me", adminAuthMiddleware, async (req, res) => {
  try {
    const settings = await SystemSettings.getOrCreate();
    return res.json({
      user: await publicUserWithHierarchy(req.admin, { getPlainEmail }),
      settings: {
        tokenExpiryHours: settings.tokenExpiryHours,
        checkInIntervalHours: settings.checkInIntervalHours,
        keyRotationRemindDays: settings.keyRotationRemindDays,
      },
      session: {
        createdAt: req.user.createdAt || null,
        expiresAt: req.user.expiresAt || null,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

function assertNeedsOnboarding(user) {
  if (!user?.claimed || user.deletedAt) {
    const err = new Error("Account not available");
    err.status = 403;
    err.code = "ACCOUNT_UNAVAILABLE";
    throw err;
  }
  if (user.onboardingComplete) {
    const err = new Error("Onboarding already completed");
    err.status = 409;
    err.code = "ONBOARDING_DONE";
    throw err;
  }
  if (user.role !== "subscriber") {
    const err = new Error("Only new subscriber accounts can choose a path");
    err.status = 400;
    err.code = "ONBOARDING_ROLE";
    throw err;
  }
  if (user.parentUuid || user.groupAdminUuid || user.sellerUuid) {
    const err = new Error("This account is already linked to an organization");
    err.status = 400;
    err.code = "ONBOARDING_LINKED";
    throw err;
  }
}

/** Stay as an individual subscriber (no group). */
router.post(
  "/onboarding/subscriber",
  adminAuthMiddleware,
  validateBody(chooseSubscriberOnboardingSchema),
  async (req, res) => {
    try {
      const user = await User.findOne({ uuid: req.admin.uuid, deletedAt: null });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      assertNeedsOnboarding(user);
      user.role = "subscriber";
      user.onboardingComplete = true;
      await user.save();

      await logActivity({
        actorUuid: user.uuid,
        actorRole: user.role,
        action: "onboarding.subscriber",
        targetType: "user",
        targetId: user.uuid,
        ip: req.ip,
      }).catch(() => {});

      return res.json({
        user: await publicUserWithHierarchy(user, { getPlainEmail }),
      });
    } catch (err) {
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || undefined,
      });
    }
  },
);

/**
 * Create a named group — creator becomes group_admin.
 * Stores group in Group collection and links User.groupUuid.
 */
router.post(
  "/onboarding/create-group",
  adminAuthMiddleware,
  validateBody(createGroupOnboardingSchema),
  async (req, res) => {
    try {
      const user = await User.findOne({ uuid: req.admin.uuid, deletedAt: null });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      assertNeedsOnboarding(user);

      const existing = await Group.findOne({ adminUuid: user.uuid });
      if (existing) {
        return res.status(409).json({
          error: "You already own a group",
          code: "GROUP_EXISTS",
        });
      }

      const expiresAt = await calculateGroupExpiresAt(new Date());
      const group = new Group({
        name: req.body.name,
        description: req.body.description || "",
        adminUuid: user.uuid,
        createdByUuid: user.uuid,
        sellerUuid: null,
        expiresAt,
      });
      await group.save();

      user.role = "group_admin";
      user.groupAdminUuid = user.uuid;
      user.groupUuid = group.uuid;
      user.parentUuid = user.parentUuid || null;
      user.sellerUuid = user.sellerUuid || null;
      user.subscriptionExpiresAt = group.expiresAt;
      user.onboardingComplete = true;
      await user.save();

      await logActivity({
        actorUuid: user.uuid,
        actorRole: user.role,
        action: "onboarding.create_group",
        targetType: "group",
        targetId: group.uuid,
        meta: { name: group.name },
        ip: req.ip,
      }).catch(() => {});

      return res.status(201).json({
        user: await publicUserWithHierarchy(user, { getPlainEmail }),
        group: {
          uuid: group.uuid,
          name: group.name,
          description: group.description || "",
          adminUuid: group.adminUuid,
          createdAt: group.createdAt,
        },
      });
    } catch (err) {
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || undefined,
      });
    }
  },
);

router.patch(
  "/me",
  adminAuthMiddleware,
  validateBody(profileUpdateSchema),
  async (req, res) => {
    try {
      const user = req.admin;
      const fields = ["name", "phone", "country", "company"];
      for (const key of fields) {
        if (req.body[key] !== undefined) user[key] = req.body[key];
      }
      await user.save();
      return res.json({
        user: await publicUserWithHierarchy(user, { getPlainEmail }),
      });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

router.post(
  "/me/password",
  adminAuthMiddleware,
  validateBody(profilePasswordSchema),
  async (req, res) => {
    try {
      const user = req.admin;
      const hasPassword = Boolean(user.passwordHash);

      if (hasPassword) {
        if (!req.body.currentPassword) {
          return res.status(400).json({
            error: "Current password is required",
            code: "CURRENT_PASSWORD_REQUIRED",
          });
        }
        const ok = await bcrypt.compare(
          req.body.currentPassword,
          user.passwordHash,
        );
        if (!ok) {
          return res.status(400).json({
            error: "Current password is incorrect",
            code: "INVALID_CURRENT_PASSWORD",
          });
        }
      }

      user.passwordHash = await bcrypt.hash(req.body.password, 12);
      await user.save();

      return res.json({
        ok: true,
        hasPassword: true,
        message: hasPassword ? "Password updated" : "Password set",
        user: await publicUserWithHierarchy(user, { getPlainEmail }),
      });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
