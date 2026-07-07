const nodemailer = require('nodemailer');

let transporter;

function getTransporter() {
  if (transporter) return transporter;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;

  const port = Number(SMTP_PORT || 587);
  // Port 465 = implicit TLS (secure: true). Port 587 = STARTTLS (secure: false).
  const secure = process.env.SMTP_SECURE === 'true' ? true
    : process.env.SMTP_SECURE === 'false' ? false
    : port === 465;

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS.replace(/\s+/g, '')
    }
  });

  return transporter;
}

async function sendOtpEmail(email, otp) {
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const subject = 'SecureDocShare password reset code';
  const text = [
    'Use this one-time code to reset your SecureDocShare password:',
    '',
    otp,
    '',
    'This code expires in 10 minutes.',
    'If you did not request this, you can ignore this email.'
  ].join('\n');

  const transport = getTransporter();
  if (!transport) {
    console.log(`[mail] SMTP not configured. OTP for ${email}: ${otp}`);
    return;
  }

  await transport.sendMail({ from, to: email, subject, text });
}

module.exports = { sendOtpEmail };
