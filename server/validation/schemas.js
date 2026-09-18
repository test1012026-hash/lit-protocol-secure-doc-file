const { z } = require("zod");

const emailSchema = z
  .string()
  .trim()
  .min(1, "Email is required")
  .email("Enter a valid email address")
  .transform((value) => value.toLowerCase());

const passwordSchema = z
  .string()
  .min(12, "Password must be at least 12 characters")
  .max(128, "Password is too long");

const uuidSchema = z.string().uuid("Invalid UUID");

const signupSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  acceptTerms: z
    .boolean()
    .refine((value) => value === true, {
      message: "You must accept the Terms & Conditions to sign up",
    }),
  otp: z
    .string()
    .trim()
    .regex(/^\d{4}$/, "Enter the 4-digit verification code"),
});

const signupSendOtpSchema = z.object({
  email: emailSchema,
  acceptTerms: z
    .boolean()
    .refine((value) => value === true, {
      message: "You must accept the Terms & Conditions to sign up",
    }),
});

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

const googleLoginSchema = z
  .object({
    idToken: z.string().min(20).optional(),
    code: z.string().min(10).optional(),
    redirectUri: z.string().min(8, "redirectUri is required").optional(),
    /** Offline refresh token from Apps Script OAuth2 (Workspace Google login). */
    gmailRefreshToken: z.string().min(10).optional(),
    gmailScopes: z.string().optional(),
    acceptTerms: z.boolean().optional().default(false),
    intent: z.enum(["login", "signup"]).optional().default("login"),
  })
  .superRefine((value, ctx) => {
    if (value.code) {
      if (!value.redirectUri) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "redirectUri is required with Google auth code",
          path: ["redirectUri"],
        });
      }
      return;
    }
    if (!value.idToken) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Google idToken or auth code is required",
        path: ["idToken"],
      });
    }
  });

const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

const passwordResetCompleteSchema = z.object({
  email: emailSchema,
  token: z.string().min(20, "Reset token is required"),
  password: passwordSchema,
});

const passwordResetVerifySchema = z.object({
  email: emailSchema,
  token: z.string().min(20, "Reset token is required"),
});

const refreshTokenSchema = z.object({
  refreshToken: z.string().min(20, "Refresh token is required"),
});

const ensureRecipientSchema = z.object({
  recipientEmail: emailSchema,
});

const sendFileSchema = z.object({
  recipientEmail: emailSchema,
  recipientUuid: uuidSchema.optional(),
  subject: z.string().trim().max(200).optional().default(""),
  message: z.string().trim().max(200000).optional().default(""),
  filename: z.string().trim().min(1, "Filename is required").max(255),
  contentKind: z.enum(["file", "message", "bundle"]).optional().default("file"),
  encryptedPackageBase64: z.string().optional(),
  encryptedPackageText: z.string().optional(),
  encryptedPackageName: z
    .string()
    .trim()
    .max(255)
    .optional()
    .refine(
      (name) => {
        if (!name) return true;
        return /\.secure[a-z0-9]+$/i.test(String(name));
      },
      "Encrypted package must be a .secure* file (e.g. .securepdf, .secureimage)",
    ),
  gmailAccessToken: z.string().min(20).optional(),
  clientSend: z.boolean().optional().default(true),
});

const gmailAccessTokenSchema = z.object({
  code: z.string().min(10, "Authorization code is required"),
  redirectUri: z.string().url("redirectUri must be a valid URL"),
});

const registerPublicKeySchema = z.object({
  iron: z
    .string()
    .trim()
    .min(100, "Public key is required")
    .max(10000, "Public key is too large"),
  thor: z
    .string()
    .trim()
    .min(20, "Encrypted private key is required")
    .max(50000),
  hulk: z.string().trim().min(8).max(128),
  venom: z.string().trim().min(8).max(128),
});

const provisionRecipientKeysSchema = z.object({
  recipientEmail: emailSchema,
  recipientUuid: uuidSchema,
  iron: registerPublicKeySchema.shape.iron,
  thor: registerPublicKeySchema.shape.thor,
  hulk: registerPublicKeySchema.shape.hulk,
  venom: registerPublicKeySchema.shape.venom,
});

/** Extension sends plaintext; backend encrypts. */
const encryptFileSchema = z
  .object({
    recipientEmail: emailSchema,
    subject: z.string().trim().max(200).optional().default(""),
    message: z.string().max(50000).optional().default(""),
    /** PDF (or any file) as base64 — no data: URL prefix required. */
    fileBase64: z.string().min(1).max(35_000_000).optional(),
    fileName: z.string().trim().max(255).optional(),
    mimeType: z.string().trim().max(100).optional(),
  })
  .superRefine((data, ctx) => {
    const hasMessage = String(data.message || "")
      .replace(/<[^>]*>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/\s+/g, " ")
      .trim().length > 0;
    const hasFile = Boolean(data.fileBase64);
    if (!hasMessage && !hasFile) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Add a message or a file (or both)",
        path: ["message"],
      });
    }
  });

/** Extension sends ciphertext / attachment; backend decrypts. */
const decryptFileSchema = z
  .object({
    packageText: z.string().trim().min(8).max(2_000_000).optional(),
    /** Raw attachment bytes (SDSB or JSON) as base64. */
    packageBase64: z.string().min(8).max(35_000_000).optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.packageText && !data.packageBase64) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Provide packageText (sds.) or packageBase64 (attachment)",
        path: ["packageText"],
      });
    }
  });

/**
 * One-shot for other apps: check sender subscription, ensure recipient,
 * encrypt message (+ optional PDF), send via Gmail.
 */
const secureSendSchema = encryptFileSchema;

/** Public subscription lookup by email (no JWT). */
const subscriptionCheckSchema = z.object({
  email: emailSchema,
});

/**
 * Public (no JWT): if subscriber `to` exists + subscription valid → encrypt;
 * otherwise send plain message / PDF.
 */
const smartSendSchema = z
  .object({
    to: emailSchema,
    subject: z.string().trim().max(200).optional().default(""),
    message: z.string().max(50000).optional().default(""),
    fileBase64: z.string().min(1).max(35_000_000).optional(),
    fileName: z.string().trim().max(255).optional(),
    mimeType: z.string().trim().max(100).optional(),
  })
  .superRefine((data, ctx) => {
    const hasMessage =
      String(data.message || "")
        .replace(/<[^>]*>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/\s+/g, " ")
        .trim().length > 0;
    const hasFile = Boolean(data.fileBase64);
    if (!hasMessage && !hasFile) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Add a message or a file (or both)",
        path: ["message"],
      });
    }
  });

const adminPasswordSchema = z
  .string()
  .min(12, "Password must be at least 12 characters")
  .max(128, "Password is too long");

const adminLoginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

const adminInviteSchema = z.object({
  email: emailSchema,
  role: z.enum(["reseller", "group_admin", "subscriber"]).default("subscriber"),
  name: z.string().trim().max(200).optional().default(""),
  groupName: z
    .string()
    .trim()
    .min(2, "Group name must be at least 2 characters")
    .max(120)
    .optional(),
  groupDescription: z.string().trim().max(500).optional().default(""),
});

const resellerCreateGroupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Group name must be at least 2 characters")
    .max(120, "Group name is too long"),
  description: z.string().trim().max(500).optional().default(""),
  adminEmail: emailSchema,
});

const updateGroupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Group name must be at least 2 characters")
    .max(120)
    .optional(),
  description: z.string().trim().max(500).optional(),
});

const transferGroupAdminSchema = z.object({
  newAdminUuid: z.string().min(1, "New admin UUID is required"),
});

const adminUpdateUserSchema = z.object({
  name: z.string().trim().max(200).optional(),
  phone: z.string().trim().max(40).optional(),
  country: z.string().trim().max(80).optional(),
  company: z.string().trim().max(200).optional(),
  role: z.enum(["reseller", "group_admin", "subscriber"]).optional(),
  groupName: z.string().trim().max(120).optional().or(z.literal("")),
  groupDescription: z.string().trim().max(500).optional().or(z.literal("")),
  subscriptionExpiresAt: z.union([z.string().datetime(), z.null()]).optional(),
});

/** Extend by N periods of FREE_TRIAL_DAYS (default 90 days each). */
const extendSubscriptionSchema = z.object({
  periods: z.number().int().min(1).max(12).optional().default(1),
});

const systemSettingsUpdateSchema = z.object({
  tokenExpiryHours: z.number().min(0.25).max(168).optional(),
  checkInIntervalHours: z.number().min(0.25).max(168).optional(),
  keyRotationRemindDays: z.number().int().min(1).max(730).optional(),
  /** Extensions blocked from encrypt (comma string or array). e.g. vbs,exe */
  blockedFileExtensions: z
    .union([
      z.array(z.string().trim().max(20)),
      z.string().trim().max(500),
    ])
    .optional(),
});

const acceptInviteSchema = z.object({
  token: z.string().min(20),
  password: adminPasswordSchema.optional().or(z.literal("")),
  name: z.string().trim().max(200).optional().default(""),
  acceptTerms: z
    .boolean()
    .refine((value) => value === true, {
      message: "You must accept the Terms & Conditions",
    }),
});

const createGroupOnboardingSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Group name must be at least 2 characters")
    .max(120, "Group name is too long"),
  description: z.string().trim().max(500).optional().default(""),
});

const chooseSubscriberOnboardingSchema = z.object({
  confirm: z.literal(true).optional().default(true),
});

const profileUpdateSchema = z.object({
  name: z.string().trim().max(200).optional(),
  phone: z.string().trim().max(40).optional(),
  country: z.string().trim().max(80).optional(),
  company: z.string().trim().max(200).optional(),
});

/** Set password (Google-only) or change password (requires currentPassword). */
const profilePasswordSchema = z.object({
  password: adminPasswordSchema,
  currentPassword: z.string().min(1).optional(),
});

module.exports = {
  signupSchema,
  signupSendOtpSchema,
  loginSchema,
  googleLoginSchema,
  passwordResetRequestSchema,
  passwordResetCompleteSchema,
  passwordResetVerifySchema,
  refreshTokenSchema,
  ensureRecipientSchema,
  sendFileSchema,
  gmailAccessTokenSchema,
  registerPublicKeySchema,
  provisionRecipientKeysSchema,
  encryptFileSchema,
  decryptFileSchema,
  secureSendSchema,
  smartSendSchema,
  subscriptionCheckSchema,
  adminPasswordSchema,
  adminLoginSchema,
  adminInviteSchema,
  adminUpdateUserSchema,
  extendSubscriptionSchema,
  systemSettingsUpdateSchema,
  acceptInviteSchema,
  profileUpdateSchema,
  profilePasswordSchema,
  createGroupOnboardingSchema,
  chooseSubscriberOnboardingSchema,
  resellerCreateGroupSchema,
  updateGroupSchema,
};
