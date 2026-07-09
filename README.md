# SecureDocShare

Chrome extension (React) + Node/Express + MongoDB backend for sending a document that only the intended recipient can decrypt, using Lit Protocol for encryption and access control.

## Prerequisites

Before you start, make sure you have:

- **Node.js 18+** and npm
- **MongoDB** — local install or a [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) cluster
- **Google Chrome**
- **Google Cloud OAuth client** — for “Continue with Google” sign-in
- **Lit Protocol account** — API key and PKP ID from the [Lit developer dashboard](https://developer.litprotocol.com)

## Project structure

```
lit-protocol-secure-doc-file/
├── server/       Node/Express + MongoDB API
└── extension/    React popup, built with Vite + CRXJS (Manifest V3)
```

---

## Step 1 — Start MongoDB

If you use a local database, start MongoDB before the backend.

Example connection string (used in the next step):

```
mongodb://localhost:27017/secure-doc-share
```

---

## Step 2 — Configure and run the backend

```bash
cd server
npm install
```

Copy the example env file and edit it:

```bash
cp .env.example .env        # macOS / Linux
copy .env.example .env      # Windows CMD
```

Edit `server/.env`:

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | API port (default `4000`) |
| `APP_URL` | Yes | Public URL of this server (e.g. `http://localhost:4000`) |
| `MONGODB_URI` | Yes | MongoDB connection string |
| `JWT_SECRET` | Yes | Long random string for signing JWTs |
| `GOOGLE_CLIENT_ID` | Yes | Google OAuth client ID (must match the extension) |
| `SMTP_*` | No | Email settings for password-reset links; if omitted, reset links print in the server console |

Start the API:

```bash
npm run dev
```

Verify it is running:

```bash
curl http://localhost:4000/api/health
```

Expected response: `{"ok":true}`

---

## Step 3 — Configure the extension

```bash
cd extension
npm install
```

Copy the example env file:

```bash
cp .env.example .env        # macOS / Linux
copy .env.example .env      # Windows CMD
```

Edit `extension/.env`. All extension config lives here — **do not hardcode secrets in source files**.

| Variable | Required | Description |
|---|---|---|
| `VITE_API_BASE_URL` | Yes | Backend API URL (default `http://localhost:4000/api`) |
| `VITE_GOOGLE_CLIENT_ID` | Yes | Same value as `GOOGLE_CLIENT_ID` in `server/.env` |
| `VITE_EXTENSION_ID` | Yes | Chrome extension ID (see Step 4) |
| `VITE_LIT_NETWORK` | No | Lit network name (default `datil-dev`) |
| `VITE_LIT_API_KEY` | Yes | Lit API key |
| `VITE_LIT_PKP_ID` | Yes | Lit PKP ID used for encrypt/decrypt |
| `VITE_POLYGON_API_KEY` | Yes* | Alchemy (or other) RPC key for Polygon Amoy |
| `VITE_POLYGON_PRIVATE_*` | Yes* | Polygon wallet credentials used by wallet helpers |

\* Required if you use the Polygon wallet features in the extension.

Also update `extension/manifest.json` so the OAuth client ID matches your env:

```json
"oauth2": {
  "client_id": "<same-as-VITE_GOOGLE_CLIENT_ID>",
  ...
}
```

> **Important:** Restart `npm run dev` after changing `.env`. Vite reads env vars at startup.

---

## Step 4 — Google OAuth (Chrome extension)

Google sign-in requires a matching OAuth client, extension ID, and redirect URI.

1. Open [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials).
2. Create an OAuth 2.0 Client ID:
   - Type: **Chrome extension**, or **Web application** if Chrome extension is unavailable.
3. Build or run the extension once (Step 5), then load it in Chrome.
4. On `chrome://extensions`, copy the **Extension ID**.
5. Set that ID in `extension/.env` as `VITE_EXTENSION_ID`.
6. Add these **Authorized redirect URIs** to the OAuth client (replace `<EXTENSION_ID>`):

   ```
   https://<EXTENSION_ID>.chromiumapp.org
   https://<EXTENSION_ID>.chromiumapp.org/
   ```

   You can also confirm the redirect URL from the extension service worker console:

   ```js
   chrome.identity.getRedirectURL()
   ```

### Optional: pin a stable extension ID

To keep the same extension ID across reloads (recommended for OAuth setup):

```bash
node scripts/setup-extension-key.mjs
```

This writes a public key into `manifest.json` and prints the pinned extension ID. Put that ID in `VITE_EXTENSION_ID` and register the redirect URIs above in Google Cloud.

---

## Step 5 — Lit Protocol

The extension calls Lit Actions over HTTP from `extension/src/lib/lit.js`:

- `encryptForRecipient()` — encrypts file content client-side via a Lit Action
- `decryptFile()` — runs a Lit Action that verifies the recipient’s Google ID token before decrypting

You need:

1. A **Lit API key** (`VITE_LIT_API_KEY`) from the Lit dashboard
2. A **PKP ID** (`VITE_LIT_PKP_ID`) tied to your Lit account
3. **Sufficient Lit credits** — a `402 Payment Required` response means the account needs funding

Docs: https://developer.litprotocol.com

---

## Step 6 — Run the extension

### Development (hot reload)

In a **second terminal** (keep the backend running in the first):

```bash
cd extension
npm run dev
```

Vite prints:

```
CRXJS: Load dist as unpacked extension
```

Load the extension in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/dist` folder (not the repo root)

Leave `npm run dev` running while you develop. Reload the extension in Chrome when prompted or after manifest changes.

### Production build

```bash
cd extension
npm run build
```

Then load `extension/dist` the same way in Chrome.

---

## Step 7 — Smoke test

1. **Backend** — `http://localhost:4000/api/health` returns `{"ok":true}`.
2. **Extension popup** — click the SecureDocShare icon; the login screen loads without console errors.
3. **Sign up** — create an account with email/password, or use **Continue with Google**.
4. **Send** — log in as sender, pick a recipient email and file, send.
5. **Inbox** — log in as recipient, open **Inbox**, decrypt the file.

Password reset (optional): request a reset link; without SMTP configured, the link appears in the server terminal.

---

## How the pieces fit together

1. Sender signs up or logs in (email/password or Google) → backend returns a JWT and user UUID.
2. Sender picks a recipient email and file. The extension encrypts the file with Lit, embedding a Lit Action that checks whether the caller is the intended recipient.
3. Extension calls `POST /api/files/send`. The backend finds or creates the recipient user record.
4. Recipient opens the extension, signs in, and sees the file in **Inbox**.
5. On **Decrypt**, the extension passes the recipient’s Google ID token to Lit. Lit only returns decryption key shares if the token email matches.
6. Decrypted bytes are saved via `chrome.downloads.download()`.

---

## Environment files (summary)

| File | Purpose |
|---|---|
| `server/.env` | Backend secrets and config |
| `server/.env.example` | Template for backend env |
| `extension/.env` | Extension secrets and config (Vite `VITE_*` vars) |
| `extension/.env.example` | Template for extension env |

Neither `.env` file should be committed — they are listed in `.gitignore`.

---

## Security notes

- Access control is enforced by Lit running your Lit Action — not by your server alone — so a compromised backend cannot decrypt file contents on its own.
- The Lit Action verifies the Google ID token via `https://oauth2.googleapis.com/tokeninfo` and checks both the email and `aud` (your OAuth client ID). Do not remove the `aud` check.
- Passwords are hashed with bcrypt; never log or store plaintext passwords.
- Treat `JWT_SECRET`, Lit API keys, and wallet private keys as credentials. Keep them in `.env` only.
