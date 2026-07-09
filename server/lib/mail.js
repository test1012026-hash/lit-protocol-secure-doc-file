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

module.exports = { sendResetEmail };
