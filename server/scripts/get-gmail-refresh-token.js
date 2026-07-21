/**
 * One-time helper: open a browser, authorize Gmail send, print refresh token.
 *
 * Prerequisites in server/.env:
 *   GOOGLE_GMAIL_CLIENT_ID=...
 *   GOOGLE_GMAIL_CLIENT_SECRET=...
 *   GOOGLE_GMAIL_REDIRECT_URI=http://localhost:4000/auth/google/callback
 *
 * Usage:
 *   node scripts/get-gmail-refresh-token.js
 */
require("dotenv").config();
const http = require("http");
const { google } = require("googleapis");

const clientId = process.env.GOOGLE_GMAIL_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
const clientSecret = process.env.GOOGLE_GMAIL_CLIENT_SECRET;
const redirectUri =
  process.env.GOOGLE_GMAIL_REDIRECT_URI ||
  "http://localhost:4000/auth/google/callback";

if (!clientId || !clientSecret) {
  console.error(
    "Set GOOGLE_GMAIL_CLIENT_ID and GOOGLE_GMAIL_CLIENT_SECRET in server/.env",
  );
  process.exit(1);
}

const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);
const scopes = ["https://www.googleapis.com/auth/gmail.send"];

const authUrl = oauth2Client.generateAuthUrl({
  access_type: "offline",
  prompt: "consent",
  scope: scopes,
});

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, redirectUri);
    const code = url.searchParams.get("code");
    if (!code) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Missing code");
      return;
    }

    const { tokens } = await oauth2Client.getToken(code);
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(
      "<h2>Success</h2><p>You can close this tab and return to the terminal.</p>",
    );

    console.log("\nAdd this to server/.env:\n");
    console.log(`GOOGLE_REFRESH_TOKEN=${tokens.refresh_token || ""}`);
    if (!tokens.refresh_token) {
      console.log(
        "\nNo refresh_token returned. Revoke app access at https://myaccount.google.com/permissions then run again with prompt=consent.",
      );
    }
    console.log("");
  } catch (err) {
    console.error(err.message);
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end(err.message);
  } finally {
    server.close();
    process.exit(0);
  }
});

const listenPort = Number(new URL(redirectUri).port || 4000);
server.listen(listenPort, () => {
  console.log("Open this URL in your browser and authorize Gmail send:\n");
  console.log(authUrl);
  console.log(`\nWaiting on ${redirectUri} ...`);
});
