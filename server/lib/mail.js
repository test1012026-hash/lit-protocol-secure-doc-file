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

async function sendSystemEmail({ to, subject, text, html }) {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    try {
      const nodemailer = require("nodemailer");
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === "true",
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        subject,
        text,
        html,
      });
      console.log(`System email (${subject}) sent via SMTP to:`, to);
      return true;
    } catch (smtpErr) {
      console.warn("SMTP send failed, trying Gmail OAuth fallback:", smtpErr.message);
    }
  }

  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  const from = process.env.GMAIL_SENDER || process.env.SMTP_FROM || process.env.SMTP_USER;
  if (refreshToken && from) {
    try {
      await sendEmail({ to, from, subject, text, html, refreshToken });
      console.log(`System email (${subject}) sent via Gmail OAuth to:`, to);
      return true;
    } catch (gmailErr) {
      console.error("Gmail OAuth send failed:", gmailErr.message);
    }
  }

  console.log(`System email (${subject}) to ${to} could not be delivered (check SMTP/Gmail config).`);
  return false;
}

async function sendResetEmail(email, resetLink) {
  const subject = "Set your SecureDocShare password";
  const text = `Click the link below to set a new password.\n\n${resetLink}\n\nThis link expires in 30 minutes.`;
  const html = `<h2>SecureDocShare</h2><p><a href="${resetLink}">Set Password</a></p><p>Or copy this link: ${resetLink}</p>`;

  await sendSystemEmail({ to: email, subject, text, html });
}

async function sendSignupOtpEmail(email, otp) {
  const code = String(otp || "").trim();
  const subject = "Your SecureDocShare verification code";
  const text = `Your SecureDocShare signup code is: ${code}\n\nThis code is valid for 10 minutes from when it was requested. If you request a new code, this one stops working.\n\nIf you did not request it, you can ignore this email.`;
  const html = `
    <h2>SecureDocShare</h2>
    <p>Your signup verification code is:</p>
    <p style="font-size:28px;letter-spacing:6px;font-weight:700">${code}</p>
    <p>This code is valid for <b>10 minutes</b> from when it was requested. Requesting a new code invalidates the previous one.</p>
  `;

  await sendSystemEmail({ to: email, subject, text, html });
}

async function sendInviteEmail({
  to,
  inviteUrl,
  role = "subscriber",
  groupName = "",
  inviterEmail = "",
}) {
  const formattedRole = role.replace(/_/g, " ");
  const subject = groupName
    ? `You're invited to join group "${groupName}" on SecureDocShare`
    : `You're invited to join SecureDocShare as ${formattedRole}`;

  const text = [
    `You have been invited to join SecureDocShare${groupName ? ` in group "${groupName}"` : ""}.`,
    "",
    `Role: ${formattedRole}`,
    inviterEmail ? `Invited by: ${inviterEmail}` : "",
    "",
    `Accept your invitation here:\n${inviteUrl}`,
    "",
    "Note: This invitation link is valid for 24 hours only. After 24 hours, the link will become inactive.",
  ]
    .filter(Boolean)
    .join("\n");

  const html = `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1e293b;border:1px solid #e2e8f0;border-radius:12px;background:#ffffff">
      <h2 style="color:#0f172a;margin-top:0">SecureDocShare Invitation</h2>
      <p style="font-size:15px;line-height:1.5">You have been invited to join SecureDocShare${groupName ? ` as part of group <strong>${groupName}</strong>` : ""}.</p>
      <table style="margin:16px 0;font-size:14px;border-collapse:collapse;width:100%">
        <tr>
          <td style="padding:6px 0;color:#64748b;width:110px">Role:</td>
          <td style="padding:6px 0;font-weight:600;color:#0f172a;text-transform:capitalize">${formattedRole}</td>
        </tr>
        ${groupName ? `<tr><td style="padding:6px 0;color:#64748b">Group:</td><td style="padding:6px 0;font-weight:600;color:#0f172a">${groupName}</td></tr>` : ""}
        ${inviterEmail ? `<tr><td style="padding:6px 0;color:#64748b">Invited by:</td><td style="padding:6px 0;color:#0f172a">${inviterEmail}</td></tr>` : ""}
      </table>
      <div style="margin:24px 0">
        <a href="${inviteUrl}" style="background-color:#0d9488;color:#ffffff;padding:12px 28px;text-decoration:none;font-weight:600;border-radius:8px;display:inline-block;font-size:15px">
          Accept Invitation
        </a>
      </div>
      <div style="background:#f8fafc;padding:12px 16px;border-radius:8px;border:1px solid #e2e8f0;margin-top:20px">
        <p style="color:#475569;font-size:13px;margin:0">
          <strong>Important:</strong> This invitation link is valid for <strong>24 hours</strong> only. After 24 hours, the link will expire and become inactive.
        </p>
      </div>
      <p style="color:#94a3b8;font-size:12px;margin-top:20px;word-break:break-all">If the button above does not work, copy and paste this URL into your browser:<br>${inviteUrl}</p>
    </div>
  `;

  return sendSystemEmail({ to, subject, text, html });
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
  sendSignupOtpEmail,
  sendInviteEmail,
  sendSystemEmail,
  sendEncryptedFileEmail,
  sendPlainFileEmail,
};
