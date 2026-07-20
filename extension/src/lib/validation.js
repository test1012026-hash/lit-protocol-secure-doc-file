import { z } from "zod";

export const emailSchema = z
  .string()
  .trim()
  .min(1, "Email is required")
  .email("Enter a valid email address")
  .transform((value) => value.toLowerCase());

export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password is too long");

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

export const signupSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

export const sendFileFormSchema = z.object({
  recipientEmail: emailSchema,
  subject: z.string().trim().max(200).optional().default(""),
  message: z.string().trim().max(5000).optional().default(""),
  file: z
    .custom((value) => value instanceof File, {
      message: "Choose a PDF file to send",
    })
    .refine(
      (file) =>
        file.type === "application/pdf" ||
        file.name.toLowerCase().endsWith(".pdf"),
      "Only PDF files are allowed",
    )
    .refine((file) => file.size > 0, "Selected file is empty")
    .refine(
      (file) => file.size <= 20 * 1024 * 1024,
      "PDF must be 20MB or smaller",
    ),
});

export const receiveFileFormSchema = z.object({
  encryptedFile: z
    .custom((value) => value instanceof File, {
      message: "Choose the encrypted .securepdf file",
    })
    .refine(
      (file) =>
        file.name.toLowerCase().endsWith(".securepdf") ||
        file.type === "application/json",
      "Upload a .securepdf file",
    )
    .refine((file) => file.size > 0, "Selected file is empty"),
});

export function formatZodError(error) {
  return error.issues.map((issue) => issue.message).join(". ");
}

export function parseOrThrow(schema, data) {
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new Error(formatZodError(parsed.error));
  }
  return parsed.data;
}
