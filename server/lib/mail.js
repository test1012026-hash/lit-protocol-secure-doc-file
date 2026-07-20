const nodemailer = require("nodemailer");

let transporter;

function getTransporter() {
  if (transporter) return transporter;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;

  const port = Number(SMTP_PORT || 587);
  // Port 465 = implicit TLS (secure: true). Port 587 = STARTTLS (secure: false).
  const secure =
    process.env.SMTP_SECURE === "true"
      ? true
      : process.env.SMTP_SECURE === "false"
        ? false
        : port === 465;

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS.replace(/\s+/g, ""),
    },
    family: 4, // IPv4
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });

  return transporter;
}

async function sendResetEmail(email, resetLink) {
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = "Set your SecureDocShare password";
  const text = [
    "Click the link below to set a new password for your SecureDocShare account:",
    "",
    resetLink,
    "",
    "This link expires in 30 minutes.",
    "If you did not request this, you can ignore this email.",
  ].join("\n");
  const html = [
    "<p>Click the button below to set a new password for your SecureDocShare account:</p>",
    `<p><a href="${resetLink}" style="display:inline-block;padding:10px 18px;background:#3366cc;color:#fff;text-decoration:none;border-radius:4px">Set new password</a></p>`,
    `<p>Or paste this link into your browser:<br><a href="${resetLink}">${resetLink}</a></p>`,
    '<p style="color:#666;font-size:12px">This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>',
  ].join("");

  const transport = getTransporter();
  if (!transport) {
    console.log(
      `[mail] SMTP not configured. Password reset link for ${email}: ${resetLink}`,
    );
    return;
  }

  await transport.sendMail({ from, to: email, subject, text, html });
}

async function sendEncryptedFileEmail({
  to,
  senderEmail,
  subject,
  message,
  attachmentName,
  attachmentBase64,
  demoMode,
}) {
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const mailSubject = `${subject}`;
  const text = [
    `${senderEmail} sent you a secure file.`,
    "",
    message ? `Message: ${message}` : "",
    message ? "" : null,
    "The encrypted file is attached to this email.",
    "",
    "To open it:",
    "1. Open the SecureDocShare Chrome extension",
    "2. Sign in with this Google account",
    "3. Go to the Receive tab",
    "4. Upload the attached encrypted file",
    "",
    demoMode
      ? "Demo mode is enabled, so the extension will simulate decryption after checking your account."
      : "Only this email address can decrypt the attachment.",
    "Only this email address can access the file.",
  ]
    .filter((line) => line !== null)
    .join("\n");

  const html = [
    `<p><strong>${senderEmail}</strong> sent you a secure file: `,
    message ? `<p><b>Message:</b> <br/>${message}</p>` : "",
    "<p>The encrypted file is attached to this email.</p>",
    "<p><strong>To open it:</strong></p>",
    "<ol>",
    "<li>Open the SecureDocShare Chrome extension</li>",
    "<li>Sign in with this Google account</li>",
    "<li>Go to the <strong>Receive</strong> tab</li>",
    "<li>Upload the attached encrypted file</li>",
    "</ol>",
    `<p style='color:#666;font-size:12px'>${
      demoMode
        ? "Demo mode is enabled, so the extension will simulate decryption after checking your account."
        : "Only this email address can decrypt the attachment."
    }</p>`,
  ].join("");

  const transport = getTransporter();
  console.log("transport -->",transport);
  if (!transport) {
    console.log(`[mail] SMTP not configured. Secure file email for ${to}:`);
    console.log(`  From: ${senderEmail}, Subject: ${subject}`);
    console.log(`  Attachment: ${attachmentName}`);
    return false;
  }

  try {
    await transport.sendMail({
      from,
      to,
      subject: mailSubject,
      text,
      html,
      attachments: [
        {
          filename: attachmentName,
          content: Buffer.from(attachmentBase64, "base64"),
          contentType: "application/octet-stream",
        },
      ],
    });
    return true;
  } catch (err) {
    console.error("[mail] Failed to send encrypted file email:", err.message);
    return false;
  }
}

module.exports = { sendResetEmail, sendEncryptedFileEmail };
