/**
 * Test: encrypt a small PDF + send mail with Workspace button + .securepdf attachment.
 * Usage: node scripts/send-workspace-pdf-test.js
 */
require("dotenv").config();
const nodemailer = require("nodemailer");

const TO = "patelashik2226@gmail.com";
const WEB_APP =
  "https://script.google.com/macros/s/AKfycby7Mdpb1YtesfMR8UG2EI1L2MphutOr0uz7vGLCkIgE/exec";
const API =
  String(process.env.APP_URL || "https://server-nine-rosy.vercel.app").replace(
    /\/$/,
    "",
  ) + "/api";

/** Minimal valid 1-page PDF */
function tinyPdfBase64() {
  const pdf = `%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj
4 0 obj<< /Length 68 >>stream
BT /F1 18 Tf 40 80 Td (SecureDocShare PDF test) Tj ET
endstream
endobj
5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000384 00000 n 
trailer<< /Size 6 /Root 1 0 R >>
startxref
461
%%EOF
`;
  return Buffer.from(pdf, "utf8").toString("base64");
}

async function main() {
  const encRes = await fetch(API + "/public/encrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      to: TO,
      subject: "SecureDocShare test — PDF attachment",
      message:
        "Hello Ashik — encrypted PDF test. Open Workspace app, then decrypt message and/or upload the .securepdf attachment.",
      fileBase64: tinyPdfBase64(),
      fileName: "securedoc-test.pdf",
      mimeType: "application/pdf",
    }),
  });
  const enc = await encRes.json();
  if (!encRes.ok) {
    console.error("encrypt failed", encRes.status, enc);
    process.exit(1);
  }

  const cipher = enc.messageCipherText || "";
  const att =
    enc.attachment &&
    (enc.attachment.attachmentBase64 || enc.attachment.base64);
  const attName =
    (enc.attachment && enc.attachment.fileName) || "securedoc-test.securepdf";

  if (!att) {
    console.error("encrypt returned no attachment", {
      contentKind: enc.contentKind,
      hasFileCipher: Boolean(enc.fileCipherText),
    });
    process.exit(1);
  }

  console.log("encrypted ok", {
    recipientUuid: enc.recipientUuid,
    recipientEmail: enc.recipientEmail,
    attachmentName: attName,
    hasMessageCipher: Boolean(cipher),
  });

  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.error("SMTP not configured in server/.env");
    process.exit(2);
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const subject = "SecureDocShare test — PDF + Workspace button";
  const text = [
    "You received a SecureDocShare encrypted PDF test.",
    "",
    "Open Workspace app: " + WEB_APP,
    "",
    cipher ? "Message (ciphertext):\n" + cipher : "",
    "",
    "Encrypted file is attached as " + attName,
    "Open SecureDocShare, sign in as " + TO + ", decrypt message and/or upload the attachment.",
  ]
    .filter(Boolean)
    .join("\n");

  const html =
    '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#323130;line-height:1.5">' +
    "<p><b>SecureDocShare</b> encrypted PDF test</p>" +
    "<p>An encrypted <code>.securepdf</code> is attached. Click the button to open the Workspace app.</p>" +
    '<p style="margin:20px 0">' +
    '<a href="' +
    WEB_APP +
    '" style="display:inline-block;padding:12px 24px;background:#0f766e;color:#ffffff;font-weight:700;text-decoration:none;border-radius:8px;font-size:14px">' +
    "Open SecureDocShare Workspace" +
    "</a></p>" +
    (cipher
      ? "<p><b>Message (ciphertext):</b></p>" +
        '<div style="word-break:break-all;font-family:Consolas,monospace;font-size:11px;color:green;white-space:pre-wrap">' +
        cipher +
        "</div>"
      : "") +
    "<p>The encrypted PDF package is attached as <b>" +
    attName +
    "</b>.</p>" +
    '<p style="color:gray;font-size:12px">Log in as ' +
    TO +
    " to decrypt.</p></div>";

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: TO,
    subject,
    text,
    html,
    attachments: [
      {
        filename: attName,
        content: Buffer.from(String(att).replace(/\s+/g, ""), "base64"),
        contentType: "application/octet-stream",
      },
    ],
  });

  console.log("SENT to", TO, "with attachment", attName);
  console.log("Web app button URL:", WEB_APP);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
