import { buildEmailBodies, createMimeRfc822Blob } from "./email";

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
}) {
  if (!accessToken) throw new Error("Gmail access token is required.");
  if (!from || !to) throw new Error("Sender and recipient are required.");

  const hasAttachment = Boolean(
    (attachmentBytes && attachmentBytes.byteLength) || attachmentBase64,
  );
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
    attachmentBase64,
    attachmentBytes,
  });

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
