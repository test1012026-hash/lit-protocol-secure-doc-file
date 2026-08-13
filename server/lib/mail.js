require("dotenv").config();
const { google } = require("googleapis");

function createMimeMessage({
  from,
  to,
  subject,
  text,
  html,
  attachmentName,
  attachmentBase64,
}) {
  const boundary = "SecureDocShareBoundary";

  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
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

  if (attachmentBase64) {
    lines.push(
      "",
      `--${boundary}`,
      `Content-Type: application/octet-stream; name="${attachmentName}"`,
      "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment; filename="${attachmentName}"`,
      "",
      attachmentBase64,
    );
  }

  lines.push("", `--${boundary}--`);

  return Buffer.from(lines.join("\r\n"))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sendEmail({
  to,
  from,
  subject,
  text,
  html,
  attachmentName,
  attachmentBase64,
  accessToken,
  refreshToken,
}) {
  const oauth2 = new google.auth.OAuth2();
  if (accessToken) {
    oauth2.setCredentials({ access_token: accessToken });
  } else if (refreshToken) {
    const { gmailClientForRefreshToken } = require("./gmailAuth");
    const gmail = gmailClientForRefreshToken(refreshToken);
    const raw = createMimeMessage({
      from,
      to,
      subject,
      text,
      html,
      attachmentName,
      attachmentBase64,
    });
    await gmail.users.messages.send({ userId: "me", requestBody: { raw } });
    return;
  } else {
    throw new Error("Gmail access token is required");
  }

  const gmail = google.gmail({ version: "v1", auth: oauth2 });
  const raw = createMimeMessage({
    from,
    to,
    subject,
    text,
    html,
    attachmentName,
    attachmentBase64,
  });
  await gmail.users.messages.send({ userId: "me", requestBody: { raw } });
}

async function sendResetEmail(email, resetLink) {
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  const from = process.env.GMAIL_SENDER;
  if (!refreshToken || !from) {
    console.log("Password reset link (Gmail not configured):", resetLink);
    return;
  }

  const subject = "Set your SecureDocShare password";
  const text = `Click the link below to set a new password.\n\n${resetLink}\n\nThis link expires in 30 minutes.`;
  const html = `<h2>SecureDocShare</h2><p><a href="${resetLink}">Set Password</a></p>`;

  try {
    await sendEmail({ to: email, from, subject, text, html, refreshToken });
  } catch (err) {
    console.error("Failed to send reset email:", err.message);
    console.log("Password reset link:", resetLink);
  }
}

async function sendEncryptedFileEmail({
  to,
  senderEmail,
  subject,
  message,
  contentKind = "file",
  attachmentName,
  attachmentBase64,
  encryptedPackageText = "",
  gmailAccessToken,
  senderRefreshToken,
}) {
  if (!gmailAccessToken && !senderRefreshToken) {
    throw new Error("Gmail access token is required to send as your address.");
  }

  const appUrl = (process.env.APP_URL || "").replace(/\/$/, "");
  const openUrl = appUrl ? `${appUrl}/open-extension` : null;

  // Only the sender's message ciphertext goes in the email Message field.
  // File packages stay on the attachment — do not convert the attachment into Message.
  const displayMessage = String(message || "").trim();
  const hasAttachment = Boolean(attachmentBase64);

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
<div style="font-size:16px">${senderEmail} sent you a secure email - This email will be decrypted by <b>Receipient Authorization Verification</b></div>
${
  displayMessage
    ? `<p><b>Message (ciphertext):</b><br><span style="word-break:break-all;font-family:monospace;font-size:12px;color:green">${String(
        displayMessage,
      )
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")}</span></p>
        
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
<p style="color:gray">
  Log in with the recipient account to decrypt.
</p>
<p style="color:gray">${
   "Only the recipient account can decrypt this file."
  }</p>
`;

  await sendEmail({
    to,
    from: senderEmail,
    subject,
    text,
    html,
    attachmentName,
    attachmentBase64,
    accessToken: senderRefreshToken ? undefined : gmailAccessToken,
    refreshToken: senderRefreshToken,
  });

  console.log("Encrypted email sent from", senderEmail);
  return true;
}

/** Plain (unencrypted) message + optional PDF via system Gmail. */
async function sendPlainFileEmail({
  to,
  subject,
  message = "",
  fileBase64,
  fileName,
  mimeType = "application/pdf",
}) {
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  const from = process.env.GMAIL_SENDER;
  if (!refreshToken || !from) {
    throw new Error(
      "System Gmail is not configured (GOOGLE_REFRESH_TOKEN / GMAIL_SENDER)",
    );
  }

  const bodyText = String(message || "").trim() || "(no message)";
  const safeHtml = bodyText
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\n/g, "<br>");
  const hasFile = Boolean(fileBase64);
  const attachmentName = hasFile ? fileName || "document.pdf" : undefined;
  const contentType = hasFile
    ? mimeType || "application/pdf"
    : "application/octet-stream";

  // Temporarily support proper PDF content-type for plain attachments.
  const boundary = "SecureDocShareBoundary";
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    'Content-Type: multipart/alternative; boundary="altBoundary"',
    "",
    "--altBoundary",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    bodyText,
    "",
    "--altBoundary",
    "Content-Type: text/html; charset=UTF-8",
    "",
    `<div>${safeHtml}</div>`,
    "",
    "--altBoundary--",
  ];

  if (hasFile) {
    lines.push(
      "",
      `--${boundary}`,
      `Content-Type: ${contentType}; name="${attachmentName}"`,
      "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment; filename="${attachmentName}"`,
      "",
      String(fileBase64).replace(/\s+/g, ""),
    );
  }
  lines.push("", `--${boundary}--`);

  const raw = Buffer.from(lines.join("\r\n"))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const { gmailClientForRefreshToken } = require("./gmailAuth");
  const gmail = gmailClientForRefreshToken(refreshToken);
  await gmail.users.messages.send({ userId: "me", requestBody: { raw } });
  console.log("Plain email sent from", from, "to", to);
  return true;
}

module.exports = {
  sendResetEmail,
  sendEncryptedFileEmail,
  sendPlainFileEmail,
};
