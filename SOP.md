# Standard Operating Procedure (SOP)
## SecureDocShare Chrome Extension
**Stack:** React (extension) + Node/Express + MongoDB (backend) + Lit Protocol (encryption)
**Target timeline:** 3–4 working days
**Owner:** ______________________
**Reviewer / approver:** ______________________

---

## 1. Purpose

This SOP defines the process, features, and checkpoints for building, testing, and shipping the SecureDocShare Chrome extension — a tool that lets a sender encrypt a document so only a named recipient can decrypt it.

## 2. Scope

Covers backend setup, extension build, third-party integrations (Google OAuth, Lit Protocol, MongoDB), QA, and handoff. Does not cover long-term production hosting or scaling.

## 3. Prerequisites (before work starts)

| Item | Owner | Status |
|---|---|---|
| Node.js 18+ and npm installed | Dev | ☐ |
| MongoDB instance available (local or Atlas) | Dev | ☐ |
| Google Cloud project created, OAuth consent screen configured | Dev | ☐ |
| Lit Protocol account / network access confirmed, current SDK docs reviewed | Dev | ☐ |
| Project zip extracted, repo initialized | Dev | ☐ |

## 4. Roles

- **Backend developer** — server, database, auth routes
- **Extension developer** — React popup, Lit integration, Chrome APIs
- **QA / reviewer** — testing, security check, sign-off

---

## 5. Project timeline

| Day | Phase | Deliverable |
|---|---|---|
| Day 1 | Backend & core services | API running, database connected, all routes responding |
| Day 2 | Extension build | Popup UI complete, wired to backend and Lit Protocol |
| Day 3 | Integration | Full send → receive → decrypt cycle working end to end |
| Day 4 | QA, security review, packaging | Signed-off, distributable build |

*If the team is experienced with this stack, Days 1–3 can compress; Day 4 should still be kept as a dedicated QA/security buffer.*

---

## 6. Full feature list

### 6.1 Authentication
| Feature | Description |
|---|---|
| Email/password signup | New user registers with email + password; account created with a unique UUID |
| Email/password login | Returning user authenticates; backend issues a JWT session token |
| Google sign-in | User authenticates via Google OAuth (Chrome `identity` API); backend verifies the ID token and issues a JWT |
| Session persistence | Logged-in state stored in `chrome.storage.local`; survives popup close/reopen |
| Logout | Clears local session, returns user to login screen |

### 6.2 User identity & UUID management
| Feature | Description |
|---|---|
| UUID generation on signup | Every user gets a unique UUID at account creation, used as their identity anchor for encryption |
| Auto-create unclaimed recipients | If a file is sent to an email with no existing account, a shell user record + UUID is created automatically |
| Recipient claiming | When that email later signs up, the existing UUID is retained (not regenerated) so any files already sent to them stay valid |

### 6.3 Encryption (sender side)
| Feature | Description |
|---|---|
| Client-side encryption | File is encrypted in the browser before it ever leaves the sender's machine, using Lit Protocol |
| Recipient-gated access control | Encryption is paired with a custom Lit Action that restricts decryption to the intended recipient only |
| File selection | Sender picks any local file via a standard file input |
| Recipient input | Sender enters the recipient's email address to target the encryption |
| Send action | Encrypted payload + metadata (subject, recipient, hash) sent to the backend in one action |

### 6.4 File transfer & storage (backend)
| Feature | Description |
|---|---|
| Encrypted file storage | Backend stores ciphertext, hash, and the associated Lit Action logic in MongoDB — never plaintext |
| Sender/recipient linkage | Each file record tracks sender UUID, sender email, and recipient email |
| Inbox listing | Recipient can list all files sent to their account (ciphertext excluded from the list view for efficiency) |
| Access enforcement | Backend rejects any request for a file from an account that isn't the intended recipient |
| Download status tracking | Backend marks a file as downloaded once the recipient successfully retrieves it |

### 6.5 Decryption (receiver side)
| Feature | Description |
|---|---|
| Identity re-verification | Receiver re-confirms their Google identity at decryption time (fresh ID token) |
| Lit Action verification | Lit network independently checks the token's email and audience claim before releasing decryption key shares |
| Local decryption | Decryption happens entirely client-side; the backend never sees plaintext or decryption keys |
| Download to disk | Decrypted file is saved to the recipient's system via the Chrome downloads API |
| Rejection of wrong recipient | If a different account attempts to decrypt, the Lit Action denies the request |

### 6.6 Extension shell
| Feature | Description |
|---|---|
| Popup UI | Single-page React app inside the browser action popup |
| Send / Inbox tabs | Two-tab navigation for sending files vs. viewing/decrypting received files |
| Status messaging | Inline status text during encrypt/send/decrypt steps (e.g. "Encrypting...", "Sending...", "Decrypted.") |
| Manifest V3 compliant | Uses a background service worker, `identity`, `storage`, and `downloads` permissions only |

---

## 7. QA checklist

- ☐ Signup with new email/password succeeds
- ☐ Login with correct credentials succeeds; wrong password is rejected
- ☐ Google sign-in succeeds and reuses the same account on repeat login
- ☐ Sending to a brand-new (never-registered) email creates an unclaimed recipient record
- ☐ That unclaimed recipient, once they sign up with the same email, sees the pending file in their inbox
- ☐ Inbox list loads without exposing ciphertext in the list view
- ☐ Decrypt + download produces a file identical to the original (checksum match)
- ☐ Logout clears local session and returns to Login screen
- ☐ Extension reload/update doesn't break an existing logged-in session unexpectedly

## 8. Security review checklist

- ☐ `JWT_SECRET` is a long random value, not committed to version control
- ☐ Passwords stored only as bcrypt hashes, never logged
- ☐ Lit Action checks both the recipient's email **and** the `aud` claim on the Google ID token
- ☐ Recipient authorization is enforced by the Lit network, not solely by backend logic
- ☐ `.env` files excluded from any repo or shared zip
- ☐ HTTPS confirmed for any non-localhost deployment of the backend
- ☐ Dependency versions checked for known CVEs (`npm audit`)

## 9. Rollback / troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Google sign-in fails silently | Redirect URI not registered exactly | Re-check `chrome.identity.getRedirectURL()` output vs Google Console |
| Decrypt always rejected | Lit Action `aud`/email mismatch, or client ID mismatch between server/.env and extension config | Confirm both configs use the identical client ID |
| Recipient never sees file | Email case mismatch | Confirm all emails are lowercased consistently |
| Backend won't start | MongoDB not reachable | Check `MONGODB_URI`, confirm `mongod` running or Atlas IP allowlist includes dev machine |

## 10. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Backend developer | | | |
| Extension developer | | | |
| QA / reviewer | | | |
| Approver | | | |
