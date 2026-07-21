require("dotenv").config();
const { google } = require("googleapis");

// ===============================
// Google OAuth2 Configuration
// ===============================
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_GMAIL_CLIENT_ID || process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_GMAIL_CLIENT_SECRET,
  process.env.GOOGLE_GMAIL_REDIRECT_URI ||
    "http://localhost:4000/auth/google/callback",
);

oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
});

const gmail = google.gmail({
  version: "v1",
  auth: oauth2Client,
});

// ===============================
// Create MIME Email
// ===============================
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
      attachmentBase64
    );
  }

  lines.push("", `--${boundary}--`);

  return Buffer.from(lines.join("\r\n"))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ===============================
// Generic Send Email
// ===============================
async function sendEmail({
  to,
  subject,
  text,
  html,
  attachmentName,
  attachmentBase64,
}) {
  const raw = createMimeMessage({
    from: process.env.GMAIL_SENDER,
    to,
    subject,
    text,
    html,
    attachmentName,
    attachmentBase64,
  });

  await gmail.users.messages.send({
    userId: "me",
    requestBody: {
      raw,
    },
  });
}

// ===============================
// Reset Password Email
// ===============================
async function sendResetEmail(email, resetLink) {
  const subject = "Set your SecureDocShare password";

  const text = `
Click the link below to set a new password.

${resetLink}

This link expires in 30 minutes.
`;

  const html = `
<h2>SecureDocShare</h2>

<p>Click below to set your password.</p>

<p>
<a href="${resetLink}"
style="
padding:12px 20px;
background:#3366cc;
color:white;
text-decoration:none;
border-radius:4px;">
Set Password
</a>
</p>

<p>
Or open:
<br>
${resetLink}
</p>

<p style="color:#777">
This link expires in 30 minutes.
</p>
`;

  try {
    await sendEmail({
      to: email,
      subject,
      text,
      html,
    });

    console.log("Reset email sent.");
  } catch (err) {
    console.error(err);
  }
}

// ===============================
// Encrypted File Email
// ===============================
async function sendEncryptedFileEmail({
  to,
  senderEmail,
  subject,
  message,
  attachmentName,
  attachmentBase64,
  demoMode,
}) {
  const text = `
${senderEmail} sent you a secure file.

${message || ""}

Steps:

1. Open SecureDocShare Extension

2. Login

3. Go to Receive

4. Upload attached file

${
  demoMode
    ? "Demo mode enabled."
    : "Only this email can decrypt the file."
}
`;

  const html = `
<h2>${senderEmail} sent you a secure file</h2>

${
  message
    ? `<p><b>Message:</b><br>${message}</p>`
    : ""
}

<p>The encrypted file is attached.</p>

<ol>
<li>Open SecureDocShare Extension</li>
<li>Login with Google</li>
<li>Go to Receive</li>
<li>Upload attached file</li>
</ol>

<p style="color:gray">
${
  demoMode
    ? "Demo mode enabled."
    : "Only this email can decrypt this file."
}
</p>
`;

  try {
    await sendEmail({
      to,
      subject,
      text,
      html,
      attachmentName,
      attachmentBase64,
    });

    console.log("Encrypted email sent.");
    return true;
  } catch (err) {
    console.error("Failed to send email:", err);
    return false;
  }
}

module.exports = {
  sendResetEmail,
  sendEncryptedFileEmail,
};