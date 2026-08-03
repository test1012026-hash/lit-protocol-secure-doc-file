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
});

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

const googleLoginSchema = z.object({
  idToken: z.string().min(20, "Google idToken is required"),
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

const ensureRecipientSchema = z.object({
  recipientEmail: emailSchema,
});

const sendFileSchema = z.object({
  recipientEmail: emailSchema,
  recipientUuid: uuidSchema.optional(),
  subject: z.string().trim().max(200).optional().default(""),
  // Ciphertext (sds.…); larger than plain text because of encryption overhead.
  message: z.string().trim().max(200000).optional().default(""),
  filename: z.string().trim().min(1, "Filename is required").max(255),
  contentKind: z.enum(["file", "message", "bundle"]).optional().default("file"),
  encryptedPackageBase64: z
    .string()
    .min(1, "Encrypted package is required"),
  encryptedPackageText: z.string().optional(),
  encryptedPackageName: z
    .string()
    .trim()
    .min(1, "Encrypted package name is required")
    .max(255)
    .refine(
      (name) => {
        const lower = name.toLowerCase();
        return lower.endsWith(".securepdf") || lower.endsWith(".securemsg");
      },
      "Encrypted package must be a .securepdf or .securemsg file",
    ),
  gmailAccessToken: z.string().min(20).optional(),
});

const gmailAccessTokenSchema = z.object({
  code: z.string().min(10, "Authorization code is required"),
  redirectUri: z.string().url("redirectUri must be a valid URL"),
});

module.exports = {
  signupSchema,
  loginSchema,
  googleLoginSchema,
  passwordResetRequestSchema,
  passwordResetCompleteSchema,
  passwordResetVerifySchema,
  ensureRecipientSchema,
  sendFileSchema,
  gmailAccessTokenSchema,
};
