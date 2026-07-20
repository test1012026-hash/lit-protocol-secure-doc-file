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
  message: z.string().trim().max(5000).optional().default(""),
  filename: z.string().trim().min(1, "Filename is required").max(255),
  encryptedPackageBase64: z
    .string()
    .min(1, "Encrypted package is required")
    .regex(/^[A-Za-z0-9+/=]+$/, "Encrypted package must be valid base64"),
  encryptedPackageName: z
    .string()
    .trim()
    .min(1, "Encrypted package name is required")
    .max(255)
    .refine(
      (name) => name.toLowerCase().endsWith(".securepdf"),
      "Encrypted package must be a .securepdf file",
    ),
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
};
