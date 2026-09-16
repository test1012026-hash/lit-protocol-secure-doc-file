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
  smartSendSchema,
} = require("../validation/schemas");
const { sendEncryptedFileEmail, sendPlainFileEmail } = require("../lib/mail");
const { normalizeEmail } = require("../lib/email");
const {
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
  resolveEncryptRecipient,
} = require("../lib/emailCrypto");
const { buildMailMetadata } = require("../lib/mailMetadata");
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
const { assertCanReceiveEncryptedMail } = require("../lib/recipientAccess");
const {
  assertCanEncryptOrSend,
  assertCanDecrypt,
} = require("../lib/accountAccess");
const { assertEncryptFileAllowed } = require("../lib/filePolicy");

const router = express.Router();

async function ensureRecipientByEmail(rawEmail) {
  const { recipient } = await resolveEncryptRecipient(User, rawEmail);
  return recipient;
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
        blocked: Boolean(recipient.blocked),
        deleted: Boolean(recipient.deletedAt),
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
      assertCanEncryptOrSend(sender);
      await ensureUserSubscription(sender);
      if (!isSubscriptionActive(sender)) {
        return res.status(403).json(subscriptionBlockedError());
      }

      await ensureKeysOnUser(sender);

      const recipient = await ensureRecipientByEmail(recipientEmail);
      assertCanReceiveEncryptedMail(recipient);
      const { iron } = await ensureKeysOnUser(recipient);

      const hasFile = Boolean(fileBase64);
      const resolvedFileName = hasFile
        ? fileName || "document.bin"
        : null;
      if (hasFile) {
        const fileCheck = await assertEncryptFileAllowed(resolvedFileName);
        if (!fileCheck.ok) {
          return res.status(400).json({
            error: fileCheck.error,
            code: fileCheck.code || "FILE_EXTENSION_BLOCKED",
            extension: fileCheck.extension || null,
            blockedFileExtensions: fileCheck.blockedExtensions || [],
          });
        }
      }

      const {
        messageCipherText,
        fileCipherText,
        contentKind,
        encryptedPackage,
      } = encryptMailPayload({
        recipientUuid: recipient.uuid,
        recipientEmail: normalizeEmail(recipientEmail),
        iron,
        message: message || "",
        fileBase64: fileBase64 || null,
        fileName: resolvedFileName || "document.bin",
        mimeType: mimeType || "application/octet-stream",
      });

      const subjectText =
        subject || (hasFile ? resolvedFileName || "Secure file" : "Secure message");

      let mailMetadata = null;
      try {
        mailMetadata = buildMailMetadata({
          email: getPlainEmail(recipient) || normalizeEmail(recipientEmail),
          uuid: recipient.uuid,
          messageUuidHash: encryptedPackage?.recipientUuidHash || null,
        });
      } catch (metaErr) {
        console.warn("[encrypt] mail metadata skipped", metaErr.message || metaErr);
      }

      res.json({
        recipientUuid: recipient.uuid,
        recipientEmail: getPlainEmail(recipient),
        recipientClaimed: recipient.claimed,
        subject: subjectText,
        contentKind,
        messageCipherText: messageCipherText || null,
        fileCipherText: fileCipherText || null,
        filename: hasFile ? resolvedFileName || "document.bin" : "message.txt",
        mailMetadata: mailMetadata
          ? {
              token: mailMetadata.token,
              textBlock: mailMetadata.textBlock,
              htmlBlock: mailMetadata.htmlBlock,
              emailEnc: mailMetadata.emailEnc,
              uuidEnc: mailMetadata.uuidEnc,
              messageUuidHash: mailMetadata.messageUuidHash,
              hashMismatch: Boolean(mailMetadata.hashMismatch),
              mismatchNotice: mailMetadata.mismatchNotice || null,
            }
          : null,
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
      res.status(err.status || 500).json({ error: err.message, code: err.code });
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
      assertCanDecrypt(user);
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
      const status =
        err.status ||
        (/locked to a different|cannot decrypt|missing/i.test(
          String(err.message || ""),
        )
          ? 400
          : 500);
      res.status(status).json({ error: err.message, code: err.code });
    }
  },
);

/**
 * Public API (no login / no JWT) — encrypt only, nothing is sent.
 * Prefer POST /api/public/encrypt (same behavior, no validate middleware).
 *
 * Creates recipient if missing, provisions RSA keys, encrypts message/file.
 * Body : { to, message?, fileBase64?, fileName?, mimeType?, subject? }
 */
router.post("/encrypt-only", validateBody(smartSendSchema), async (req, res) => {
  try {
    const { to, subject, message, fileBase64, fileName, mimeType } = req.body;

    const recipient = await ensureRecipientByEmail(to);
    assertCanReceiveEncryptedMail(recipient);
    const hasFile = Boolean(fileBase64);
    const resolvedFileName = hasFile ? fileName || "document.bin" : null;
    if (hasFile) {
      const fileCheck = await assertEncryptFileAllowed(resolvedFileName);
      if (!fileCheck.ok) {
        return res.status(400).json({
          ok: false,
          code: fileCheck.code || "FILE_EXTENSION_BLOCKED",
          error: fileCheck.error,
          extension: fileCheck.extension || null,
          blockedFileExtensions: fileCheck.blockedExtensions || [],
        });
      }
    }
    const subjectText =
      subject ||
      (hasFile ? resolvedFileName || "Secure file" : "Secure message");

    const { iron } = await ensureKeysOnUser(recipient);
    const {
      messageCipherText,
      fileCipherText,
      contentKind,
      encryptedPackage,
    } = encryptMailPayload({
      recipientUuid: recipient.uuid,
      recipientEmail: normalizeEmail(to),
      iron,
      message: message || "",
      fileBase64: fileBase64 || null,
      fileName: resolvedFileName || "document.bin",
      mimeType: mimeType || "application/octet-stream",
    });

    return res.json({
      ok: true,
      encrypted: true,
      recipientUuid: recipient.uuid,
      recipientClaimed: recipient.claimed,
      subscriptionActive: isSubscriptionActive(recipient),
      subscriptionExpiresAt: recipient.subscriptionExpiresAt
        ? new Date(recipient.subscriptionExpiresAt).toISOString()
        : null,
      subject: subjectText,
      contentKind,
      messageCipherText: messageCipherText || null,
      fileCipherText: fileCipherText || null,
      attachment: encryptedPackage
        ? {
            fileName: encryptedPackage.fileName,
            base64: encryptedPackage.base64 || null,
            attachmentBase64: encryptedPackage.attachmentBase64 || null,
          }
        : null,
    });
  } catch (err) {
    console.error("[encrypt-only]", err);
    res.status(500).json({ ok: false, error: err.message, code: "ENCRYPT_FAILED" });
  }
});

/**
 * Public API (no login / no JWT).
 * 1) Look up subscriber by `to`
 * 2) If exists + subscription active → encrypt + send encrypted mail
 * 3) Otherwise → send the same content as plain (not encrypted)
 *
 * Body: { to, subject?, message?, fileBase64?, fileName?, mimeType? }
 * Sends from system Gmail (GOOGLE_REFRESH_TOKEN / GMAIL_SENDER).
 */
router.post("/smart-send", validateBody(smartSendSchema), async (req, res) => {
  try {
    const { to, subject, message, fileBase64, fileName, mimeType } = req.body;

    const systemRefresh = process.env.GOOGLE_REFRESH_TOKEN;
    const systemFrom = process.env.GMAIL_SENDER;
    if (!systemRefresh || !systemFrom) {
      return res.status(503).json({
        ok: false,
        code: "MAILER_NOT_CONFIGURED",
        error: "System Gmail is not configured on the server",
      });
    }

    const hasFile = Boolean(fileBase64);
    const resolvedFileName = hasFile ? fileName || "document.bin" : null;
    const subjectText =
      subject || (hasFile ? resolvedFileName || "document.bin" : "Message");

    if (hasFile) {
      const fileCheck = await assertEncryptFileAllowed(resolvedFileName);
      if (!fileCheck.ok) {
        return res.status(400).json({
          ok: false,
          code: fileCheck.code || "FILE_EXTENSION_BLOCKED",
          error: fileCheck.error,
          extension: fileCheck.extension || null,
          blockedFileExtensions: fileCheck.blockedExtensions || [],
        });
      }
    }

    const subscriber = await findUserByEmail(User, to);
    let shouldEncrypt = false;
    let subscriptionExpiresAt = null;

    if (subscriber) {
      if (subscriber.claimed) {
        await ensureUserSubscription(subscriber);
      }
      subscriptionExpiresAt = subscriber.subscriptionExpiresAt
        ? new Date(subscriber.subscriptionExpiresAt).toISOString()
        : null;
      shouldEncrypt =
        Boolean(subscriber.claimed) && isSubscriptionActive(subscriber);
    }

    if (!shouldEncrypt) {
      try {
        await sendPlainFileEmail({
          to,
          subject: subjectText,
          message: message || "",
          fileBase64: fileBase64 || null,
          fileName: resolvedFileName || "document.bin",
          mimeType: mimeType || "application/octet-stream",
        });
      } catch (mailErr) {
        return res.status(502).json({
          ok: false,
          encrypted: false,
          subscriberExists: Boolean(subscriber),
          subscriptionActive: false,
          subscriptionExpiresAt,
          error: mailErr.message || "Gmail send failed",
          code: "GMAIL_SEND_FAILED",
        });
      }

      return res.json({
        ok: true,
        emailSent: true,
        encrypted: false,
        reason: !subscriber
          ? "SUBSCRIBER_NOT_FOUND"
          : !subscriber.claimed
            ? "SUBSCRIBER_NOT_CLAIMED"
            : "SUBSCRIPTION_INACTIVE",
        subscriberExists: Boolean(subscriber),
        subscriptionActive: false,
        subscriptionExpiresAt,
        subject: subjectText,
        from: systemFrom,
        to,
      });
    }

    const { iron } = await ensureKeysOnUser(subscriber);
    const { messageCipherText, contentKind, encryptedPackage } =
      encryptMailPayload({
        recipientUuid: subscriber.uuid,
        recipientEmail: normalizeEmail(to),
        iron,
        message: message || "",
        fileBase64: fileBase64 || null,
        fileName: resolvedFileName || "document.bin",
        mimeType: mimeType || "application/octet-stream",
      });

    const attachmentBase64 =
      encryptedPackage?.attachmentBase64 || encryptedPackage?.base64 || null;

    try {
      await sendEncryptedFileEmail({
        to,
        senderEmail: systemFrom,
        subject: subjectText,
        message: messageCipherText || "",
        contentKind,
        attachmentName: encryptedPackage?.fileName || null,
        attachmentBase64,
        encryptedPackageText: messageCipherText || "",
        senderRefreshToken: systemRefresh,
        mailMetadata: buildMailMetadata({
          email: getPlainEmail(subscriber) || normalizeEmail(to),
          uuid: subscriber.uuid,
          messageUuidHash: encryptedPackage?.recipientUuidHash || null,
        }),
      });
    } catch (mailErr) {
      return res.status(502).json({
        ok: false,
        encrypted: true,
        subscriberExists: true,
        subscriptionActive: true,
        subscriptionExpiresAt,
        error: mailErr.message || "Gmail send failed",
        code: "GMAIL_SEND_FAILED",
      });
    }

    return res.json({
      ok: true,
      emailSent: true,
      encrypted: true,
      reason: "SUBSCRIPTION_ACTIVE",
      subscriberExists: true,
      subscriptionActive: true,
      subscriptionExpiresAt,
      recipientUuid: subscriber.uuid,
      contentKind,
      subject: subjectText,
      from: systemFrom,
      to,
    });
  } catch (err) {
    console.error("[smart-send]", err);
    res.status(500).json({
      ok: false,
      error: err.message,
      code: "SMART_SEND_FAILED",
    });
  }
});

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
      assertCanEncryptOrSend(sender);

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
      assertCanReceiveEncryptedMail(recipient);
      const { iron, created: keysCreated } = await ensureKeysOnUser(recipient);

      const hasFile = Boolean(fileBase64);
      const resolvedFileName = hasFile ? fileName || "document.bin" : null;
      if (hasFile) {
        const fileCheck = await assertEncryptFileAllowed(resolvedFileName);
        if (!fileCheck.ok) {
          return res.status(400).json({
            ok: false,
            code: fileCheck.code || "FILE_EXTENSION_BLOCKED",
            error: fileCheck.error,
            extension: fileCheck.extension || null,
            blockedFileExtensions: fileCheck.blockedExtensions || [],
          });
        }
      }

      const { messageCipherText, contentKind, encryptedPackage } =
        encryptMailPayload({
          recipientUuid: recipient.uuid,
          recipientEmail: normalizeEmail(recipientEmail),
          iron,
          message: message || "",
          fileBase64: fileBase64 || null,
          fileName: resolvedFileName || "document.bin",
          mimeType: mimeType || "application/octet-stream",
        });

      const subjectText =
        subject || (hasFile ? resolvedFileName || "Secure file" : "Secure message");
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
          mailMetadata: buildMailMetadata({
            email: getPlainEmail(recipient) || normalizeEmail(recipientEmail),
            uuid: recipient.uuid,
            messageUuidHash: encryptedPackage?.recipientUuidHash || null,
          }),
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
      res.status(err.status || 500).json({
        ok: false,
        error: err.message,
        code: err.code || "SECURE_SEND_FAILED",
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
      assertCanReceiveEncryptedMail(recipient);
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
      assertCanEncryptOrSend(sender);
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
      let mailMetadata = null;
      try {
        mailMetadata = buildMailMetadata({
          email: getPlainEmail(recipient) || normalizeEmail(recipientEmail),
          uuid: recipient.uuid,
          messageUuidHash: encryptedPackage?.recipientUuidHash || null,
        });
      } catch (metaErr) {
        console.warn("[send] mail metadata skipped", metaErr.message || metaErr);
      }

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
          mailMetadata: mailMetadata
            ? {
                token: mailMetadata.token,
                textBlock: mailMetadata.textBlock,
                htmlBlock: mailMetadata.htmlBlock,
                emailEnc: mailMetadata.emailEnc,
                uuidEnc: mailMetadata.uuidEnc,
                messageUuidHash: mailMetadata.messageUuidHash,
                hashMismatch: Boolean(mailMetadata.hashMismatch),
                mismatchNotice: mailMetadata.mismatchNotice || null,
              }
            : null,
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
          mailMetadata,
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
      res.status(err.status || 500).json({ error: err.message, code: err.code });
    }
  },
);

module.exports = router;
