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

/** Treat Quill empty HTML (<p><br></p>, etc.) as blank. */
export function isEmptyRichText(html) {
  const raw = String(html || "").trim();
  if (!raw) return true;
  const text = raw
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length === 0;
}

export const sendFileFormSchema = z
  .object({
    recipientEmails: z
      .array(emailSchema)
      .min(1, "Add at least one recipient email")
      .max(20, "You can send to at most 20 recipients at once"),
    subject: z.string().trim().max(200).optional().default(""),
    message: z.string().max(50000).optional().default(""),
    file: z.any().optional().nullable(),
  })
  .superRefine((data, ctx) => {
    const hasMessage = !isEmptyRichText(data.message);
    const file = data.file;
    const hasFile = file instanceof File;

    if (!hasMessage && !hasFile) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Add a message or a PDF (or both)",
        path: ["message"],
      });
      return;
    }

    if (!hasFile) return;

    if (
      file.type !== "application/pdf" &&
      !file.name.toLowerCase().endsWith(".pdf")
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Only PDF files are allowed",
        path: ["file"],
      });
    }
    if (file.size <= 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Selected file is empty",
        path: ["file"],
      });
    }
    if (file.size > 25 * 1024 * 1024) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "PDF must be 25MB or smaller (Gmail limit)",
        path: ["file"],
      });
    }
  });

export const receiveFileFormSchema = z.object({
  encryptedFile: z
    .custom((value) => value instanceof File, {
      message: "Choose the encrypted .securepdf file",
    })
    .refine(
      (file) =>
        file.name.toLowerCase().endsWith(".securepdf") ||
        file.name.toLowerCase().endsWith(".securemsg") ||
        file.type === "application/json" ||
        file.type === "application/octet-stream" ||
        file.type === "text/plain",
      "Upload a .securepdf or .securemsg file",
    )
    .refine((file) => file.size > 0, "Selected file is empty")
    .refine(
      (file) => file.size <= 25 * 1024 * 1024,
      "Encrypted file must be 25MB or smaller",
    ),
});

export const receivePasteFormSchema = z.object({
  packageText: z
    .string()
    .trim()
    .min(20, "Paste the ciphertext from the email Message"),
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
