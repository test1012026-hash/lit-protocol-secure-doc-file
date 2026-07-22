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
  attachmentName,
  attachmentBase64,
  demoMode,
  gmailAccessToken,
  senderRefreshToken,
}) {
  if (!gmailAccessToken && !senderRefreshToken) {
    throw new Error("Gmail access token is required to send as your address.");
  }

  const appUrl = (process.env.APP_URL || "").replace(/\/$/, "");
  const openUrl = appUrl ? `${appUrl}/open-extension` : null;

  const text = [
    `${senderEmail} sent you a secure file.`,
    "",
    message || "",
    "",
    "Open SecureDocShare → Receive → upload the attachment.",
    openUrl ? `\nOpen extension: ${openUrl}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const openButton = openUrl
    ? `<p><a href="${openUrl}" style="display:inline-block;padding:12px 24px;background:#2bb3a0;color:#ffffff;font-weight:700;text-decoration:none;border-radius:8px;font-size:14px">Open SecureDocShare</a></p>`
    : "<p>Click the SecureDocShare icon in Chrome to open the extension.</p>";

  const html = `
<h2>${senderEmail} sent you a secure file</h2>
${message ? `<p><b>Message:</b><br>${message}</p>` : ""}
<p>The encrypted file is attached.</p>
<ol>
<li>Open SecureDocShare</li>
<li>Login with Google</li>
<li>Go to Receive</li>
<li>Upload the attached file</li>
</ol>
${openButton}
<p style="color:gray">
  Log in with the same Google account this email was sent to, then upload the attached <code>.securepdf</code> on the Receive tab.
</p>
<p style="color:gray">${
    demoMode ? "Demo mode enabled." : "Only this email can decrypt this file."
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

module.exports = {
  sendResetEmail,
  sendEncryptedFileEmail,
};
