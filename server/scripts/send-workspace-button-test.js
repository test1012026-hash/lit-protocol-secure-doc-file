/**
 * One-off test: encrypt + email with Workspace web-app button.
 * Usage: node scripts/send-workspace-button-test.js
 */
require("dotenv").config();
const { sendSystemEmail } = require("../lib/mail");

const TO = "patelashik2226@gmail.com";
const WEB_APP =
  "https://script.google.com/macros/s/AKfycby7Mdpb1YtesfMR8UG2EI1L2MphutOr0uz7vGLCkIgE/exec";
const API =
  String(process.env.APP_URL || "https://server-nine-rosy.vercel.app").replace(
    /\/$/,
    "",
  ) + "/api";

async function main() {
  const encRes = await fetch(API + "/public/encrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      to: TO,
      subject: "SecureDocShare test — open Workspace app",
      message:
        "Hello Ashik — this is a SecureDocShare Workspace button test. Open the app to decrypt.",
    }),
  });
  const enc = await encRes.json();
  if (!encRes.ok || !enc.messageCipherText) {
    console.error("encrypt failed", encRes.status, enc);
    process.exit(1);
  }
  console.log("encrypted ok", {
    recipientUuid: enc.recipientUuid,
    recipientEmail: enc.recipientEmail,
  });

  const cipher = enc.messageCipherText;
  const subject = "SecureDocShare test — Open Workspace app";
  const text = [
    "You received a SecureDocShare test message.",
    "",
    "Open Workspace app: " + WEB_APP,
    "",
    "Message (ciphertext):",
    cipher,
    "",
    "Open SecureDocShare Workspace, sign in as " + TO + ", paste the ciphertext, then Decrypt.",
  ].join("\n");

  const html =
    '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#323130;line-height:1.5">' +
    "<p><b>SecureDocShare</b> test mail</p>" +
    "<p>Click the button below to open the Workspace web app, then paste the ciphertext and decrypt.</p>" +
    '<p style="margin:20px 0">' +
    '<a href="' +
    WEB_APP +
    '" style="display:inline-block;padding:12px 24px;background:#0f766e;color:#ffffff;font-weight:700;text-decoration:none;border-radius:8px;font-size:14px">' +
    "Open SecureDocShare Workspace" +
    "</a></p>" +
    '<p style="font-size:12px;color:#605e5c">If the button does not work, open:<br>' +
    '<a href="' +
    WEB_APP +
    '">' +
    WEB_APP +
    "</a></p>" +
    "<p><b>Message (ciphertext):</b></p>" +
    '<div style="word-break:break-all;font-family:Consolas,monospace;font-size:11px;color:green;white-space:pre-wrap">' +
    cipher +
    "</div>" +
    '<p style="color:gray;font-size:12px">Log in as ' +
    TO +
    " to decrypt.</p></div>";

  const ok = await sendSystemEmail({ to: TO, subject, text, html });
  if (!ok) {
    console.error("send failed");
    process.exit(2);
  }
  console.log("SENT to", TO);
  console.log("Web app button URL:", WEB_APP);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
