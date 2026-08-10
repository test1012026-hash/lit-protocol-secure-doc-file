import { buildEmailBodies, createMimeRfc822Blob } from "./email";
import { base64ToBytes } from "../utils/utils";

/**
 * Prefer binary MIME (no base64 CTE). Base64 CTE inflates size ~33% and
 * makes Gmail uploadType=media much slower for large PDFs.
 */
function resolveAttachmentBytes(attachmentBytes, attachmentBase64) {
  if (attachmentBytes && attachmentBytes.byteLength) {
    return attachmentBytes instanceof Uint8Array
      ? attachmentBytes
      : new Uint8Array(attachmentBytes);
  }
  if (attachmentBase64) {
    return base64ToBytes(attachmentBase64);
  }
  return null;
}

export async function sendEncryptedEmailViaGmail({
  accessToken,
  from,
  to,
  subject,
  message = "",
  attachmentName,
  attachmentBase64,
  attachmentBytes,
  appUrl,
  onProgress,
}) {
  if (!accessToken) throw new Error("Gmail access token is required.");
  if (!from || !to) throw new Error("Sender and recipient are required.");

  const bytes = resolveAttachmentBytes(attachmentBytes, attachmentBase64);
  const hasAttachment = Boolean(bytes?.byteLength);
  const { text, html } = buildEmailBodies({
    senderEmail: from,
    message,
    hasAttachment,
    appUrl,
  });

  const mimeBlob = createMimeRfc822Blob({
    from,
    to,
    subject: subject || "Secure document",
    text,
    html,
    attachmentName,
    // Always use binary path when we have bytes — never re-base64 the MIME body.
    attachmentBytes: bytes,
    attachmentBase64: null,
  });

  const sizeMb = (mimeBlob.size / (1024 * 1024)).toFixed(1);
  if (typeof onProgress === "function") {
    onProgress(`Uploading to Gmail (${sizeMb} MB)…`);
  }

  // Gmail's documented limit is ~25MB for the total encoded message.
  if (mimeBlob.size > 24.5 * 1024 * 1024) {
    throw new Error(
      `Message is ${sizeMb} MB after encryption (Gmail limit ~25 MB). Use a smaller PDF.`,
    );
  }

  // uploadType=media supports large messages (JSON { raw } is capped ~5MB).
  const res = await fetch(
    "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=media",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "message/rfc822",
      },
      body: mimeBlob,
    },
  );

  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    if (
      res.status === 413 ||
      /too large|PayloadTooLarge|Message too large|Media too large/i.test(
        errBody,
      )
    ) {
      throw new Error(
        "Attachment exceeds Gmail's 25MB limit. Use a PDF of 25MB or smaller.",
      );
    }
    if (res.status === 401 || res.status === 403) {
      const err = new Error(
        "Gmail access expired. Allow Gmail again to continue sending.",
      );
      err.code = "GMAIL_NOT_CONNECTED";
      throw err;
    }
    throw new Error(
      `Gmail send failed (${res.status}): ${errBody || res.statusText}`,
    );
  }

  return true;
}
