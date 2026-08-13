/**
 * Public routes — no authMiddleware, no JWT, no validate middleware.
 * Mounted at /api/public
 */
const express = require("express");
const crypto = require("crypto");
const User = require("../models/User");
const { normalizeEmail } = require("../lib/email");
const {
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
} = require("../lib/emailCrypto");
const {
  ensureUserSubscription,
  subscriptionPayload,
  isSubscriptionActive,
} = require("../lib/subscription");
const {
  createKeyBundleForUuid,
  encryptMailPayload,
  decryptForRecipient,
  parseEncryptedPackage,
  parseEncryptedPackageFromBytes,
  parseDecryptedContent,
} = require("../lib/secureCrypto");

const router = express.Router();

function hasCompleteRecipientKeys(user) {
  return Boolean(user?.iron && user?.thor && user?.hulk && user?.venom);
}

async function ensureRecipientByEmail(rawEmail) {
  const email = normalizeEmail(rawEmail);
  let recipient = await findUserByEmail(User, rawEmail);
  if (recipient) return { recipient, created: false };

  try {
    const user = new User({
      claimed: false,
      uuid: crypto.randomUUID(),
    });
    applyEncryptedEmail(user, email);
    await user.save();
    return { recipient: user, created: true };
  } catch (err) {
    if (err.code === 11000) {
      recipient = await findUserByEmail(User, email);
      if (recipient) return { recipient, created: false };
    }
    throw err;
  }
}

/** Create RSA keys on the server if the user has none. */
async function ensureKeysOnUser(user) {
  if (hasCompleteRecipientKeys(user)) {
    return { iron: user.iron, created: false };
  }
  const bundle = createKeyBundleForUuid(user.uuid);
  user.iron = bundle.iron;
  user.thor = bundle.thor;
  user.hulk = bundle.hulk;
  user.venom = bundle.venom;
  await user.save();
  await User.updateOne({ _id: user._id }, { $unset: { keyActionId: 1 } });
  return { iron: user.iron, created: true };
}

function stripMessage(message) {
  return String(message || "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * GET /api/public/subscription-check?email=user@example.com
 * Open for all — returns whether the email has a valid subscription.
 */
router.get("/subscription-check", async (req, res) => {
  try {
    const email = normalizeEmail(req.query.email);
    if (!email || !email.includes("@")) {
      return res.status(400).json({
        ok: false,
        exists: false,
        subscriptionActive: false,
        code: "EMAIL_REQUIRED",
        error: "Valid email query param is required",
      });
    }

    const user = await findUserByEmail(User, email);
    if (!user) {
      return res.status(404).json({
        ok: false,
        exists: false,
        subscriptionActive: false,
        code: "USER_NOT_FOUND",
        error: "No account found for this email",
      });
    }

    if (user.claimed) {
      await ensureUserSubscription(user);
    }

    const payload = subscriptionPayload(user);
    const active =
      Boolean(user.claimed) && Boolean(payload.subscriptionActive);

    return res.json({
      ok: true,
      exists: true,
      claimed: Boolean(user.claimed),
      subscriptionActive: active,
      subscriptionExpiresAt: payload.subscriptionExpiresAt,
      subscriptionDaysLeft: active ? payload.subscriptionDaysLeft : 0,
      subscriptionTrialDays: payload.subscriptionTrialDays,
      code: active
        ? "SUBSCRIPTION_ACTIVE"
        : user.claimed
          ? "SUBSCRIPTION_EXPIRED"
          : "SUBSCRIBER_NOT_CLAIMED",
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message,
      code: "SUBSCRIPTION_CHECK_FAILED",
    });
  }
});

/**
 * POST /api/public/encrypt
 * Open for all — no JWT / no auth.
 *
 * Creates the recipient if missing, provisions RSA keys from their UUID,
 * encrypts message and/or file so only that recipient can decrypt.
 *
 * Body:
 *   { to, message?, fileBase64?, fileName?, mimeType?, subject? }
 *
 * Response:
 *   messageCipherText  — encrypted message (sds. token), or null
 *   fileCipherText     — encrypted file (SDSB base64), or null
 *   (always separate variables — never the same value)
 */
router.post("/encrypt", async (req, res) => {
  try {
    const body = req.body || {};
    const to = normalizeEmail(body.to || body.receiverEmail || body.email);
    const message = body.message || "";
    const fileBase64 = body.fileBase64 || body.fileContent || null;
    const fileName = body.fileName || "document.pdf";
    const mimeType = body.mimeType || "application/pdf";
    const subject = body.subject || "";

    if (!to || !to.includes("@")) {
      return res.status(400).json({
        ok: false,
        code: "RECIPIENT_REQUIRED",
        error: "Receiver email (to) is required",
      });
    }

    const hasMessage = stripMessage(message).length > 0;
    const hasFile = Boolean(fileBase64);
    if (!hasMessage && !hasFile) {
      return res.status(400).json({
        ok: false,
        code: "CONTENT_REQUIRED",
        error: "Add a message or a file (base64), or both",
      });
    }

    if (hasFile && String(fileBase64).length > 35_000_000) {
      return res.status(413).json({
        ok: false,
        code: "PAYLOAD_TOO_LARGE",
        error: "File is too large for the encrypt API. Use a file under ~25 MB.",
      });
    }

    const { recipient, created: recipientCreated } =
      await ensureRecipientByEmail(to);
    const { iron, created: keysCreated } = await ensureKeysOnUser(recipient);

    const subjectText =
      subject ||
      (hasFile ? fileName || "document.pdf" : "Secure message");

    const {
      messageCipherText,
      fileCipherText,
      contentKind,
      encryptedPackage,
    } = encryptMailPayload({
      recipientUuid: recipient.uuid,
      recipientEmail: to,
      iron,
      message: hasMessage ? message : "",
      fileBase64: hasFile ? fileBase64 : null,
      fileName,
      mimeType,
    });

    return res.json({
      ok: true,
      encrypted: true,
      recipientUuid: recipient.uuid,
      recipientEmail: getPlainEmail(recipient) || to,
      recipientCreated,
      recipientClaimed: Boolean(recipient.claimed),
      keysCreated,
      subscriptionActive: isSubscriptionActive(recipient),
      subject: subjectText,
      contentKind,
      // Separate ciphertexts — manage independently on the client.
      messageCipherText: messageCipherText || null,
      fileCipherText: fileCipherText || null,
      attachment: encryptedPackage
        ? {
            fileName: encryptedPackage.fileName,
            base64: encryptedPackage.base64 || null,
            attachmentBase64: encryptedPackage.attachmentBase64 || null,
          }
        : null,
      iron,
    });
  } catch (err) {
    console.error("[public/encrypt]", err);
    res.status(500).json({
      ok: false,
      error: err.message,
      code: "ENCRYPT_FAILED",
    });
  }
});

/**
 * Decrypt one ciphertext blob with the recipient's stored RSA keys.
 * messageCipherText → sds. token / JSON text
 * fileCipherText    → SDSB attachment base64 (or JSON package base64)
 */
function decryptOnePackage({ user, packageText, packageBase64 }) {
  let encryptedPackage;
  if (packageBase64) {
    const bytes = Buffer.from(
      String(packageBase64).replace(/\s+/g, ""),
      "base64",
    );
    encryptedPackage = parseEncryptedPackageFromBytes(bytes);
  } else {
    encryptedPackage = parseEncryptedPackage(packageText);
  }

  const decrypted = decryptForRecipient({
    encryptedPackage,
    recipientUuid: user.uuid,
    user,
  });
  const content = parseDecryptedContent(decrypted, encryptedPackage);
  return { encryptedPackage, content };
}

/**
 * POST /api/public/decrypt
 * Open for all — no JWT / no auth.
 *
 * Looks up the recipient by email, unlocks their RSA private key,
 * and decrypts message and/or file ciphertext (same crypto as /files/decrypt).
 *
 * Body (send any combination):
 *   {
 *     email | to | receiverEmail,
 *     messageCipherText?,   // sds. token from /public/encrypt
 *     fileCipherText?,      // SDSB base64 from /public/encrypt
 *     packageText?,         // alias for messageCipherText
 *     packageBase64?        // alias for fileCipherText
 *   }
 *
 * Response:
 *   message          — decrypted plain message, or null
 *   file             — { filename, mimeType, dataBase64 } or null
 *   messageDecrypted / fileDecrypted — booleans
 */
router.post("/decrypt", async (req, res) => {
  try {
    const body = req.body || {};
    const email = normalizeEmail(
      body.email || body.to || body.receiverEmail || body.recipientEmail,
    );
    const messageCipherText =
      body.messageCipherText || body.packageText || body.encryptedMessage || null;
    const fileCipherText =
      body.fileCipherText ||
      body.packageBase64 ||
      body.encryptedFile ||
      body.encryptedPdf ||
      null;

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        ok: false,
        code: "EMAIL_REQUIRED",
        error: "Recipient email is required",
      });
    }

    const hasMessage = Boolean(
      messageCipherText && String(messageCipherText).trim().length >= 8,
    );
    const hasFile = Boolean(
      fileCipherText && String(fileCipherText).replace(/\s+/g, "").length >= 8,
    );
    if (!hasMessage && !hasFile) {
      return res.status(400).json({
        ok: false,
        code: "CIPHERTEXT_REQUIRED",
        error:
          "Provide messageCipherText (sds.) and/or fileCipherText (encrypted PDF base64)",
      });
    }

    if (hasFile && String(fileCipherText).length > 35_000_000) {
      return res.status(413).json({
        ok: false,
        code: "PAYLOAD_TOO_LARGE",
        error: "Encrypted file is too large for the decrypt API.",
      });
    }

    const user = await findUserByEmail(User, email);
    if (!user) {
      return res.status(404).json({
        ok: false,
        code: "USER_NOT_FOUND",
        error: "No account found for this email",
      });
    }

    if (!hasCompleteRecipientKeys(user)) {
      return res.status(400).json({
        ok: false,
        code: "KEYS_MISSING",
        error:
          "No complete RSA key pair on this account. Encrypt something to this email first (or claim the account).",
      });
    }

    let message = null;
    let file = null;
    let messageKind = null;
    let fileKind = null;
    let messageFilename = null;
    let fileFilename = null;

    if (hasMessage) {
      const { encryptedPackage, content } = decryptOnePackage({
        user,
        packageText: String(messageCipherText).trim(),
      });
      message = content.message;
      // Rare: message package that also embeds a file (legacy JSON bundle).
      if (content.file && !file) file = content.file;
      messageKind = encryptedPackage.kind || null;
      messageFilename = encryptedPackage.filename || null;
    }

    if (hasFile) {
      const { encryptedPackage, content } = decryptOnePackage({
        user,
        packageBase64: String(fileCipherText),
      });
      if (content.file) file = content.file;
      // Rare: text-only package passed as fileCipherText.
      if (content.message && !message) message = content.message;
      fileKind = encryptedPackage.kind || null;
      fileFilename = encryptedPackage.filename || null;
    }

    return res.json({
      ok: true,
      decrypted: true,
      recipientUuid: user.uuid,
      recipientEmail: getPlainEmail(user) || email,
      recipientClaimed: Boolean(user.claimed),
      messageDecrypted: hasMessage,
      fileDecrypted: hasFile,
      message: message || null,
      file: file || null,
      kind: fileKind || messageKind || null,
      filename: (file && file.filename) || fileFilename || messageFilename || null,
    });
  } catch (err) {
    console.error("[public/decrypt]", err);
    const msg = String(err.message || err);
    const status = /locked to a different|cannot decrypt|missing|Invalid|not a SecureDocShare|Corrupt|KEYS/i.test(
      msg,
    )
      ? 400
      : 500;
    res.status(status).json({
      ok: false,
      error: msg,
      code: "DECRYPT_FAILED",
    });
  }
});

module.exports = router;
