/**
 * Send encrypted mail directly from the extension via Gmail API.
 * File attachments use binary MIME (no base64 expansion) so PDFs up to 25MB
 * match Gmail's 25MB attachment limit.
 */

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function sanitizeHeaderValue(value) {
  return String(value || "")
    .replace(/[\r\n]+/g, " ")
    .trim();
}

/**
 * Build an RFC822 MIME message as a Blob.
 * Prefer attachmentBytes with Content-Transfer-Encoding: binary (no +33% bloat).
 */
function createMimeRfc822Blob({
  from,
  to,
  subject,
  text,
  html,
  attachmentName,
  attachmentBase64,
  attachmentBytes,
}) {
  const boundary = "SecureDocShareBoundary";
  const parts = [
    `From: ${sanitizeHeaderValue(from)}`,
    `To: ${sanitizeHeaderValue(to)}`,
    `Subject: ${sanitizeHeaderValue(subject)}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    'Content-Type: multipart/alternative; boundary="altBoundary"',
    "",
    "--altBoundary",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    text,
    "",
    "--altBoundary",
    "Content-Type: text/html; charset=UTF-8",
    "",
    html,
    "",
    "--altBoundary--",
  ];

  const blobs = [parts.join("\r\n")];
  const safeName = sanitizeHeaderValue(
    attachmentName || "secure-package.securepdf",
  );

  if (attachmentBytes && attachmentBytes.byteLength) {
    const bytes =
      attachmentBytes instanceof Uint8Array
        ? attachmentBytes
        : new Uint8Array(attachmentBytes);
    blobs.push(
      [
        "",
        `--${boundary}`,
        `Content-Type: application/octet-stream; name="${safeName}"`,
        "Content-Transfer-Encoding: binary",
        `Content-Disposition: attachment; filename="${safeName}"`,
        "",
        "",
      ].join("\r\n"),
    );
    // Raw binary body (no base64) — required to fit Gmail's 25MB limit.
    blobs.push(bytes);
    blobs.push(`\r\n--${boundary}--\r\n`);
  } else if (attachmentBase64) {
    const chunked = String(attachmentBase64).replace(/.{1,76}/g, "$&\r\n");
    blobs.push(
      [
        "",
        `--${boundary}`,
        `Content-Type: application/octet-stream; name="${safeName}"`,
        "Content-Transfer-Encoding: base64",
        `Content-Disposition: attachment; filename="${safeName}"`,
        "",
        chunked.trimEnd(),
        "",
        `--${boundary}--`,
        "",
      ].join("\r\n"),
    );
  } else {
    blobs.push(`\r\n--${boundary}--\r\n`);
  }

  return new Blob(blobs, { type: "message/rfc822" });
}

function buildEmailBodies({ senderEmail, message, hasAttachment, appUrl }) {
  const displayMessage = String(message || "").trim();
  const openUrl = appUrl
    ? `${String(appUrl).replace(/\/$/, "")}/open-extension`
    : null;

  const openButton = openUrl
    ? `<p><a href="${openUrl}" style="display:inline-block;padding:12px 24px;background:#2bb3a0;color:#ffffff;font-weight:700;text-decoration:none;border-radius:8px;font-size:14px">Open SecureDocShare</a></p>`
    : "<p>Click the SecureDocShare icon in Chrome to open the extension.</p>";

  const text = [
    `${senderEmail} sent you a secure file.`,
    "",
    displayMessage ? `Message:\n${displayMessage}` : "",
    "",
    displayMessage
      ? "Open SecureDocShare → Receive → Paste ciphertext → paste the Message above → Decrypt."
      : "",
    hasAttachment
      ? "To open the file: Open SecureDocShare → Receive → Upload file → Decrypt."
      : "",
    openUrl ? `\nOpen extension: ${openUrl}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const html = `
<div style="font-size:16px">${escapeHtml(senderEmail)} sent you a secure email - This email will be decrypted by <b>Receipient Authorization Verification</b></div>
${
  displayMessage
    ? `<p><b>Message (ciphertext):</b><br><span style="word-break:break-all;font-family:monospace;font-size:12px;color:green">${escapeHtml(
        displayMessage,
      )}</span></p>
        <p>Copy and paste the Message ciphertext above to decrypt the message</p>`
    : ""
}
${hasAttachment ? "<p>The encrypted file is attached separately.</p>" : ""}
<ol>
<li>Open SecureDocShare</li>
<li>Login with Google</li>
<li>Go to Receive</li>
${
  displayMessage
    ? "<li>Copy the Message ciphertext above to decrypt the message</li>"
    : ""
}
${hasAttachment ? "<li>Upload the attachment to decrypt the file</li>" : ""}
<li>Decrypt and open</li>
</ol>
${openButton}
<p style="color:gray">Log in with the recipient account to decrypt.</p>
<p style="color:gray">Only the recipient account can decrypt this file.</p>
`;

  return { text, html };
}

/**
 * Send via Gmail upload API. Binary attachments allow up to Gmail's 25MB limit.
 */
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
