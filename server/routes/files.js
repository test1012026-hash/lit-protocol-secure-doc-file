const express = require("express");
const crypto = require("crypto");
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");
const { validateBody } = require("../middleware/validate");
const {
  ensureRecipientSchema,
  sendFileSchema,
  provisionRecipientKeysSchema,
  encryptFileSchema,
  decryptFileSchema,
  secureSendSchema,
} = require("../validation/schemas");
const { sendEncryptedFileEmail } = require("../lib/mail");
const { normalizeEmail } = require("../lib/email");
const {
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
} = require("../lib/emailCrypto");
const {
  ensureUserSubscription,
  isSubscriptionActive,
  subscriptionBlockedError,
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

async function ensureRecipientByEmail(rawEmail) {
  const email = normalizeEmail(rawEmail);
  let recipient = await findUserByEmail(User, rawEmail);
  if (recipient) return recipient;

  try {
    const user = new User({
      claimed: false,
      uuid: crypto.randomUUID(),
    });
    applyEncryptedEmail(user, email);
    await user.save();
    return user;
  } catch (err) {
    if (err.code === 11000) {
      recipient = await findUserByEmail(User, email);
      if (recipient) return recipient;
    }
    throw err;
  }
}

function hasCompleteRecipientKeys(user) {
  return Boolean(user?.iron && user?.thor && user?.hulk && user?.venom);
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

router.post(
  "/ensure-recipient",
  authMiddleware,
  validateBody(ensureRecipientSchema),
  async (req, res) => {
    try {
      const { recipientEmail } = req.body;
      const recipient = await ensureRecipientByEmail(recipientEmail);
      res.json({
        recipientUuid: recipient.uuid,
        recipientEmail: getPlainEmail(recipient),
        recipientClaimed: recipient.claimed,
        iron: recipient.iron || null,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

/** Store RSA keys for a new recipient so mail can be sent before they log in. */
router.post(
  "/provision-recipient-keys",
  authMiddleware,
  validateBody(provisionRecipientKeysSchema),
  async (req, res) => {
    try {
      const {
        recipientEmail,
        recipientUuid,
        iron,
        thor,
        hulk,
        venom,
      } = req.body;

      const recipient = await ensureRecipientByEmail(recipientEmail);
      if (recipient.uuid !== recipientUuid) {
        return res.status(400).json({
          error:
            "Recipient UUID mismatch. Re-fetch recipient and provision again.",
        });
      }

      if (hasCompleteRecipientKeys(recipient)) {
        return res.json({
          ok: true,
          alreadyProvisioned: true,
          iron: recipient.iron,
          recipientUuid: recipient.uuid,
        });
      }

      recipient.iron = String(iron).trim();
      recipient.thor = String(thor).trim();
      recipient.hulk = String(hulk).trim();
      recipient.venom = String(venom).trim();
      await recipient.save();
      await User.updateOne(
        { _id: recipient._id },
        { $unset: { keyActionId: 1 } },
      );

      res.json({
        ok: true,
        alreadyProvisioned: false,
        iron: recipient.iron,
        recipientUuid: recipient.uuid,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

/**
 * Encrypt plaintext message + optional PDF for a recipient.
 * Body: { recipientEmail, subject?, message?, fileBase64?, fileName?, mimeType? }
 * Returns ciphertext + attachment for the extension to send via Gmail.
 */
router.post(
  "/encrypt",
  authMiddleware,
  validateBody(encryptFileSchema),
  async (req, res) => {
    try {
      const {
        recipientEmail,
        subject,
        message,
        fileBase64,
        fileName,
        mimeType,
      } = req.body;

      const sender = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!sender) {
        return res.status(401).json({ error: "Sender account not found" });
      }
      await ensureUserSubscription(sender);
      if (!isSubscriptionActive(sender)) {
        return res.status(403).json(subscriptionBlockedError());
      }

      await ensureKeysOnUser(sender);

      const recipient = await ensureRecipientByEmail(recipientEmail);
      const { iron } = await ensureKeysOnUser(recipient);

      const { messageCipherText, contentKind, encryptedPackage } =
        encryptMailPayload({
          recipientUuid: recipient.uuid,
          recipientEmail: normalizeEmail(recipientEmail),
          iron,
          message: message || "",
          fileBase64: fileBase64 || null,
          fileName: fileName || "document.pdf",
          mimeType: mimeType || "application/pdf",
        });

      const hasFile = Boolean(fileBase64);
      const subjectText =
        subject || (hasFile ? fileName || "document.pdf" : "Secure message");

      res.json({
        recipientUuid: recipient.uuid,
        recipientEmail: getPlainEmail(recipient),
        recipientClaimed: recipient.claimed,
        subject: subjectText,
        contentKind,
        messageCipherText,
        filename: hasFile ? fileName || "document.pdf" : "message.txt",
        attachment: encryptedPackage
          ? {
              fileName: encryptedPackage.fileName,
              // Only one of these is set — never both (was doubling response size).
              base64: encryptedPackage.base64 || null,
              attachmentBase64: encryptedPackage.attachmentBase64 || null,
            }
          : null,
      });
    } catch (err) {
      console.error("[encrypt]", err);
      res.status(500).json({ error: err.message });
    }
  },
);

/**
 * Decrypt an encrypted package for the logged-in user.
 * Body: { packageText? } or { packageBase64? }
 */
router.post(
  "/decrypt",
  authMiddleware,
  validateBody(decryptFileSchema),
  async (req, res) => {
    try {
      const { packageText, packageBase64 } = req.body;
      const user = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!user) {
        return res.status(401).json({ error: "Account not found" });
      }
      if (!hasCompleteRecipientKeys(user)) {
        return res.status(400).json({
          error:
            "No complete RSA key pair on your account. Log out and log in again to generate keys.",
          code: "KEYS_MISSING",
        });
      }

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

      res.json({
        message: content.message,
        file: content.file,
        kind: encryptedPackage.kind || null,
        filename: encryptedPackage.filename || null,
      });
    } catch (err) {
      console.error("[decrypt]", err);
      const status = /locked to a different|cannot decrypt|missing/i.test(
        String(err.message || ""),
      )
        ? 400
        : 500;
      res.status(status).json({ error: err.message });
    }
  },
);

/**
 * One-shot API for other repos:
 * 1) Verify sender exists
 * 2) If subscription expired → 403 + message
 * 3) Create recipient if missing (+ RSA keys)
 * 4) Encrypt message + optional PDF, send encrypted Gmail
 *
 * Body: { recipientEmail, subject?, message?, fileBase64?, fileName?, mimeType? }
 */
router.post(
  "/secure-send",
  authMiddleware,
  validateBody(secureSendSchema),
  async (req, res) => {
    try {
      const {
        recipientEmail,
        subject,
        message,
        fileBase64,
        fileName,
        mimeType,
      } = req.body;

      const sender = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!sender) {
        return res.status(404).json({
          ok: false,
          code: "USER_NOT_FOUND",
          error: "Sender account not found",
        });
      }

      await ensureUserSubscription(sender);
      if (!isSubscriptionActive(sender)) {
        return res.status(403).json({
          ok: false,
          ...subscriptionBlockedError(),
        });
      }

      if (!sender.gmailRefreshToken) {
        return res.status(403).json({
          ok: false,
          error: "Allow Gmail access once to send from your address.",
          code: "GMAIL_NOT_CONNECTED",
        });
      }

      await ensureKeysOnUser(sender);

      const recipientExisted = Boolean(
        await findUserByEmail(User, recipientEmail),
      );
      const recipient = await ensureRecipientByEmail(recipientEmail);
      const { iron, created: keysCreated } = await ensureKeysOnUser(recipient);

      const { messageCipherText, contentKind, encryptedPackage } =
        encryptMailPayload({
          recipientUuid: recipient.uuid,
          recipientEmail: normalizeEmail(recipientEmail),
          iron,
          message: message || "",
          fileBase64: fileBase64 || null,
          fileName: fileName || "document.pdf",
          mimeType: mimeType || "application/pdf",
        });

      const hasFile = Boolean(fileBase64);
      const subjectText =
        subject || (hasFile ? fileName || "document.pdf" : "Secure message");
      const senderEmail = getPlainEmail(sender);
      const appUrl = (process.env.APP_URL || "").replace(/\/$/, "");

      const attachmentBase64 =
        encryptedPackage?.attachmentBase64 ||
        encryptedPackage?.base64 ||
        null;

      let emailSent = false;
      try {
        emailSent = await sendEncryptedFileEmail({
          to: recipientEmail,
          senderEmail,
          subject: subjectText,
          message: messageCipherText || "",
          contentKind,
          attachmentName: encryptedPackage?.fileName || null,
          attachmentBase64,
          encryptedPackageText: messageCipherText || "",
          senderRefreshToken: sender.gmailRefreshToken,
        });
      } catch (mailErr) {
        const msg = mailErr.message || "Gmail send failed";
        if (/invalid_grant|token has been expired|revoked/i.test(msg)) {
          await User.updateOne(
            { uuid: req.user.uuid },
            { $unset: { gmailRefreshToken: 1 } },
          );
          return res.status(403).json({
            ok: false,
            error:
              "Gmail access expired. Allow Gmail again to continue sending.",
            code: "GMAIL_NOT_CONNECTED",
          });
        }
        return res.status(502).json({
          ok: false,
          error: msg,
          code: "GMAIL_SEND_FAILED",
        });
      }

      res.json({
        ok: true,
        emailSent,
        recipientUuid: recipient.uuid,
        recipientEmail: getPlainEmail(recipient),
        recipientCreated: !recipientExisted,
        keysCreated,
        recipientClaimed: recipient.claimed,
        contentKind,
        subject: subjectText,
        from: senderEmail,
        appUrl,
      });
    } catch (err) {
      console.error("[secure-send]", err);
      res.status(500).json({
        ok: false,
        error: err.message,
        code: "SECURE_SEND_FAILED",
      });
    }
  },
);

router.post(
  "/send",
  authMiddleware,
  validateBody(sendFileSchema),
  async (req, res) => {
    try {
      const {
        recipientEmail,
        subject,
        message,
        filename,
        contentKind,
        encryptedPackageBase64,
        encryptedPackageName,
        encryptedPackageText,
        recipientUuid,
        gmailAccessToken,
        clientSend,
      } = req.body;
      const recipient = await ensureRecipientByEmail(recipientEmail);
      if (recipientUuid && recipient.uuid !== recipientUuid) {
        return res.status(400).json({
          error:
            "Recipient UUID mismatch. Re-fetch recipient and encrypt again.",
        });
      }
      const sender = await User.findOne({ uuid: req.user.uuid, claimed: true });
      if (!sender) {
        return res.status(401).json({ error: "Sender account not found" });
      }
      await ensureUserSubscription(sender);
      if (!isSubscriptionActive(sender)) {
        return res.status(403).json(subscriptionBlockedError());
      }
      if (!sender.gmailRefreshToken && !gmailAccessToken && !clientSend) {
        return res.status(403).json({
          error: "Allow Gmail access once to send from your address.",
          code: "GMAIL_NOT_CONNECTED",
        });
      }

      const normalizedSubject = subject || filename || "Untitled document";
      const appUrl = (process.env.APP_URL || "").replace(/\/$/, "");
      const senderEmail = getPlainEmail(sender);

      // Default path: extension sends the email (avoids Vercel 4.5MB body limit).
      if (clientSend !== false || !encryptedPackageBase64) {
        if (!sender.gmailRefreshToken) {
          return res.status(403).json({
            error: "Allow Gmail access once to send from your address.",
            code: "GMAIL_NOT_CONNECTED",
          });
        }
        return res.json({
          recipientUuid: recipient.uuid,
          recipientClaimed: recipient.claimed,
          emailSent: false,
          clientSendRequired: true,
          from: senderEmail,
          subject: normalizedSubject,
          appUrl,
        });
      }

      let emailSent = false;
      try {
        emailSent = await sendEncryptedFileEmail({
          to: recipientEmail,
          senderEmail,
          subject: normalizedSubject,
          message: message || "",
          contentKind: contentKind || "file",
          attachmentName: encryptedPackageName,
          attachmentBase64: encryptedPackageBase64,
          encryptedPackageText: encryptedPackageText || "",
          gmailAccessToken,
          senderRefreshToken: sender.gmailRefreshToken,
        });
      } catch (mailErr) {
        const msg = mailErr.message || "Gmail send failed";
        if (/invalid_grant|token has been expired|revoked/i.test(msg)) {
          await User.updateOne(
            { uuid: req.user.uuid },
            { $unset: { gmailRefreshToken: 1 } },
          );
          return res.status(403).json({
            error:
              "Gmail access expired. Allow Gmail again to continue sending.",
            code: "GMAIL_NOT_CONNECTED",
          });
        }
        return res.status(502).json({
          error: msg,
          code: "GMAIL_SEND_FAILED",
        });
      }

      res.json({
        recipientUuid: recipient.uuid,
        recipientClaimed: recipient.claimed,
        emailSent,
        from: senderEmail,
        appUrl,
      });
    } catch (err) {
      console.log("err -->", err);
      res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
