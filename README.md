# SecureDocShare

Chrome extension + Node/Express + MongoDB app for sending encrypted documents. Only the intended recipient can decrypt them, using **Lit Protocol v3 (Chipotle)** and Google identity checks.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Node.js 18+** and npm | [nodejs.org](https://nodejs.org) |
| **MongoDB** | Local install or [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) |
| **Google Chrome** | Required to load the extension |
| **Google Cloud OAuth client** | For “Continue with Google” |
| **Lit v3 account** | API key + PKP ID from the [Lit Dashboard](https://dashboard.dev.litprotocol.com) |
| **Alchemy Solana API key** (optional) | Improves Solana RPC; public devnet works without it |

---

## Project structure

```
lit-protocol-secure-doc-file/
├── server/          Express API + MongoDB
│   ├── .env.example
│   └── index.js
└── extension/       Chrome extension (React + Vite + CRXJS)
    ├── .env.example
    ├── manifest.json
    ├── dist/        ← load this folder in Chrome
    └── src/
```

---

## Quick start (checklist)

1. Start MongoDB  
2. Configure and run the **server**  
3. Configure and build the **extension**  
4. Load `extension/dist` in Chrome  
5. Finish Google OAuth with the extension ID  
6. Sign up → Send a file → Decrypt in Inbox  

---

## 1. Start MongoDB

Local example URI:

```
mongodb://localhost:27017/secure-doc-share
```

If you use Atlas, copy the connection string from the Atlas UI.

---

## 2. Server setup and run

Open a terminal:

```bash
cd server
npm install
```

Create your env file:

```bash
# macOS / Linux
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Edit `server/.env`:

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Default `4000` |
| `APP_URL` | Yes | Public URL of this server, e.g. `http://localhost:4000` |
| `MONGODB_URI` | Yes | MongoDB connection string |
| `JWT_SECRET` | Yes | Long random string for JWTs |
| `GOOGLE_CLIENT_ID` | Yes | Same Google OAuth client ID used by the extension |
| `SMTP_*` | No | Password-reset emails; if omitted, reset links print in the server console |

Start the API:

```bash
npm run dev
```

You should see:

```
MongoDB connected
Server running on port 4000
```

Check health:

```bash
curl http://localhost:4000/api/health
```

Expected:

```json
{"ok":true}
```

Keep this terminal running.

---

## 3. Extension setup

Open a **second** terminal:

```bash
cd extension
npm install
```

Create your env file:

```bash
# macOS / Linux
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Edit `extension/.env`:

| Variable | Required | Description |
|---|---|---|
| `VITE_API_BASE_URL` | Yes | Backend API URL (default `http://localhost:4000/api`) |
| `VITE_GOOGLE_CLIENT_ID` | Yes | Same as `GOOGLE_CLIENT_ID` in `server/.env` |
| `VITE_EXTENSION_ID` | Yes | Chrome extension ID (set after first load — see below) |
| `VITE_LIT_API_BASE` | No | Default `https://api.chipotle.litprotocol.com/core/v1` |
| `VITE_LIT_API_KEY` | Yes | Lit v3 API key |
| `VITE_LIT_PKP_ID` | Yes | Lit PKP ID used for encrypt/decrypt |
| `VITE_SOLANA_ALCHEMY_API_KEY` | No | Alchemy Solana key (recommended) |
| `VITE_SOLANA_NETWORK` | No | `devnet` or `mainnet-beta` (default `devnet`) |
| `VITE_SOLANA_PUBLIC_KEY` | No | Optional Solana test wallet pubkey |
| `VITE_SOLANA_SECRET_KEY` | No | Optional Solana test wallet secret (base58) |

Also set the same Google client ID in `extension/manifest.json`:

```json
"oauth2": {
  "client_id": "<same-as-VITE_GOOGLE_CLIENT_ID>",
  "scopes": ["openid", "email", "profile"]
}
```

> Vite only reads `.env` at startup. Restart `npm run dev` / rebuild after env changes.

---

## 4. Build the extension

### Development (hot reload)

```bash
cd extension
npm run dev
```

Vite builds into `extension/dist` and watches for changes.

### Production build

```bash
cd extension
npm run build
```

---

## 5. Install in Chrome

1. Open Chrome and go to:

   ```
   chrome://extensions
   ```

2. Turn on **Developer mode** (top-right toggle).

3. Click **Load unpacked**.

4. Select this folder (not the repo root):

   ```
   lit-protocol-secure-doc-file/extension/dist
   ```

5. Confirm **SecureDocShare** appears in the list and is enabled.

6. Pin it (puzzle icon → pin) so you can open the popup easily.

7. Copy the **Extension ID** shown under the extension name (e.g. `gljjkimecepnndocjchjabdmiogdapeb`).

8. Put that ID in `extension/.env`:

   ```env
   VITE_EXTENSION_ID=your-extension-id-here
   ```

9. Restart the extension build (`Ctrl+C`, then `npm run dev` or `npm run build`), then click **Reload** on the extension card in `chrome://extensions`.

### Pin a stable extension ID (recommended)

So the ID does not change between machines/reloads:

```bash
cd extension
node scripts/setup-extension-key.mjs
```

This writes a `key` into `manifest.json` and prints the pinned ID. Use that value for `VITE_EXTENSION_ID` and Google OAuth redirect URIs.

---

## 6. Google OAuth setup

1. Open [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** (Chrome extension type if available, otherwise Web application).
3. Add authorized redirect URIs (replace `<EXTENSION_ID>` with your real ID):

   ```
   https://<EXTENSION_ID>.chromiumapp.org
   https://<EXTENSION_ID>.chromiumapp.org/
   ```

4. Use the same client ID in:
   - `server/.env` → `GOOGLE_CLIENT_ID`
   - `extension/.env` → `VITE_GOOGLE_CLIENT_ID`
   - `extension/manifest.json` → `oauth2.client_id`

To confirm the redirect URI from the extension service worker console:

```js
chrome.identity.getRedirectURL()
```

---

## 7. Lit Protocol v3 (Chipotle)

Datil and Naga networks are retired. This app uses Lit v3 Chipotle over HTTP.

1. Sign up at the [Lit Dashboard](https://dashboard.dev.litprotocol.com).
2. Create an API key and a PKP.
3. Set in `extension/.env`:

   ```env
   VITE_LIT_API_KEY=your-api-key
   VITE_LIT_PKP_ID=your-pkp-id
   ```

4. Ensure the account has credits (a `402` error means funding is needed).

**Flow:**

- **Encrypt** — extension calls Chipotle; file bytes are encrypted with the PKP  
- **Decrypt** — Lit Action verifies the recipient’s Google ID token email, then decrypts  

Docs: [developer.litprotocol.com](https://developer.litprotocol.com)

---

## 8. Smoke test

With server and extension both running:

1. Open the SecureDocShare popup.  
2. Sign up with email/password, or use **Continue with Google**.  
3. On **Send**, enter a recipient email, pick a file, click **Encrypt and send**.  
4. Sign in as the recipient (or another account with that email).  
5. Open **Inbox** → **Decrypt** → the file should download.

Password reset (optional): request a reset; without SMTP, the link is printed in the server terminal.

---

## How it works

1. User logs in → server returns a JWT and user UUID.  
2. Sender picks recipient email + file → extension encrypts via Lit Chipotle.  
3. Extension posts ciphertext to `POST /api/files/send`.  
4. Recipient signs in and sees the file in Inbox.  
5. On decrypt, extension sends the Google ID token into a Lit Action that checks email + `aud`, then decrypts.  
6. Decrypted bytes are saved with `chrome.downloads.download()`.

---

## Environment files

| File | Purpose |
|---|---|
| `server/.env` | Backend secrets |
| `server/.env.example` | Backend template |
| `extension/.env` | Extension Vite `VITE_*` config |
| `extension/.env.example` | Extension template |

Do not commit `.env` files (they are gitignored).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Extension fails to load / empty content script | Rebuild (`npm run build`) and reload; load `extension/dist`, not the repo root |
| `Extension ID mismatch` | Set `VITE_EXTENSION_ID` to the ID on `chrome://extensions`, rebuild, reload |
| Google `redirect_uri_mismatch` | Add `https://<EXTENSION_ID>.chromiumapp.org` in Google Cloud Console |
| Backend not reachable | Confirm `npm run dev` in `server/` and `VITE_API_BASE_URL=http://localhost:4000/api` |
| Lit `402 Payment Required` | Add credits in the Lit Dashboard |
| Decrypt fails for old files | Re-send the file; older ciphertext formats may not match the current Lit Action |
| Popup shows “Loading…” forever | Check the service worker / popup console for missing env vars |

---

## Security notes

- Lit enforces decrypt gating inside the Lit Action; a compromised backend alone cannot decrypt ciphertext.  
- The Lit Action verifies Google tokens via `oauth2.googleapis.com/tokeninfo` and checks email + `aud`.  
- Passwords are hashed with bcrypt.  
- Keep `JWT_SECRET`, Lit API keys, and wallet secrets only in `.env`.
