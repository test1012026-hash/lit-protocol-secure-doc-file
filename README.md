# SecureDocShare

Chrome extension (React) + Node/Express + MongoDB backend for sending a document
that only the intended recipient can decrypt, using Lit Protocol for the
encryption/access-control layer.

This is a working scaffold, not a finished product — read "Before you run it"
below, since a few values only you can provide (database URL, Google OAuth
client, Lit network).

## Folder structure

```
secure-doc-share/
├── server/       Node/Express + MongoDB API
└── extension/    React popup, built with Vite + CRXJS for Manifest V3
```

## 1. Backend setup

```bash
cd server
npm install
cp .env.example .env
```

Edit `.env`:
- `MONGODB_URI` — a local `mongodb://localhost:27017/secure-doc-share` or an Atlas connection string.
- `JWT_SECRET` — any long random string.
- `GOOGLE_CLIENT_ID` — from the Google Cloud project you set up in step 3.

Run it:
```bash
npm run dev     # or: npm start
```
It listens on `http://localhost:4000` by default. Check `http://localhost:4000/api/health`.

## 2. Extension setup

```bash
cd extension
npm install
```

Edit `src/lib/config.js`:
```js
export const API_BASE_URL = 'http://localhost:4000/api'; // your backend
export const GOOGLE_CLIENT_ID = '...your client id...';   // same as server .env
export const LIT_NETWORK = 'datil';                        // check current Lit docs for the active network name
```

Build it:
```bash
npm run build
```
This produces a `dist/` folder.

Load it in Chrome:
1. Go to `chrome://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked** and select the `extension/dist` folder

## 3. Google OAuth client (needed for "Continue with Google")

1. In the Google Cloud Console, create an OAuth 2.0 Client ID of type **Chrome extension** (or **Web application** if the extension type isn't available in your project) — https://console.cloud.google.com/apis/credentials
2. After loading the unpacked extension once, get its redirect URL by running this in the extension's service worker console: `chrome.identity.getRedirectURL()`. Add that exact URL as an authorized redirect URI on the OAuth client.
3. Put the client ID in both `server/.env` (`GOOGLE_CLIENT_ID`) and `extension/src/lib/config.js` (`GOOGLE_CLIENT_ID`) — they must match.

## 4. Lit Protocol

`extension/src/lib/lit.js` contains:
- `encryptForRecipient()` — encrypts the file client-side.
- `decryptFile()` — asks the Lit network to run a **Lit Action** that checks the caller's Google ID token against the intended recipient's email before releasing the decryption key.

Lit's SDK has changed its exact method signatures across versions, so **before running this for real**, check the current docs and adjust `encrypt()` / `decrypt()` / `getLitActionSessionSigs()` calls to match the installed `@lit-protocol/lit-node-client` version:
- https://developer.litprotocol.com/lit-actions/examples
- https://developer.litprotocol.com

## How the pieces fit together

1. Sender signs up or logs in (email/password or Google) → backend returns a JWT plus their UUID.
2. Sender picks a recipient email + file. The extension encrypts the file with Lit, embedding a Lit Action that will later check "is the caller `recipient@email.com`?"
3. Extension calls `POST /api/files/send`. The backend finds the recipient's user record, or creates an unclaimed one with a fresh UUID if they've never signed up.
4. Recipient opens the extension, signs in (creating/claiming their account), and sees the file in **Inbox**.
5. On **Decrypt**, the extension gets the recipient's Google ID token and asks Lit to run the access-control Lit Action. Lit only returns decryption key shares if the token's email matches.
6. Decrypted bytes are turned into a `Blob` and saved via `chrome.downloads.download()`.

## Security notes

- Access control is enforced by the Lit network running your Lit Action — not by your own server — so a compromised backend can't leak file contents on its own.
- The Lit Action verifies the Google ID token against `https://oauth2.googleapis.com/tokeninfo` and checks both the email and the `aud` (your OAuth client ID) claims. Don't remove the `aud` check — without it, a token from a different app could be replayed.
- Passwords are hashed with bcrypt; never log or store plaintext passwords.
- Treat `JWT_SECRET` like any other credential — keep it out of version control (already covered by `.gitignore`).
