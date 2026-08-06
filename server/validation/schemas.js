const { z } = require("zod");

const emailSchema = z
  .string()
  .trim()
  .min(1, "Email is required")
  .email("Enter a valid email address")
  .transform((value) => value.toLowerCase());

const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
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
        const lower = name.toLowerCase();
        return lower.endsWith(".securepdf") || lower.endsWith(".securemsg");
      },
      "Encrypted package must be a .securepdf or .securemsg file",
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

module.exports = {
  signupSchema,
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
};
