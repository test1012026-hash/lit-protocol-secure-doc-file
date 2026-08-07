import { escapeHtml, sanitizeHeaderValue } from "../utils/utils";

export function normalizeEmail(raw) {
  if (!raw || typeof raw !== "string") return "";

  const trimmed = raw.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return trimmed;

  let local = trimmed.slice(0, at);
  let domain = trimmed.slice(at + 1);

  if (domain === "googlemail.com") domain = "gmail.com";

  if (domain === "gmail.com") {
    const plus = local.indexOf("+");
    if (plus !== -1) local = local.slice(0, plus);
    local = local.replace(/\./g, "");
  }

  return `${local}@${domain}`;
}

 export function createMimeRfc822Blob({
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

export function buildEmailBodies({ senderEmail, message, hasAttachment, appUrl }) {
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