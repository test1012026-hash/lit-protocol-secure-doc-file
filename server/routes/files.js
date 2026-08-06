const express = require("express");
const crypto = require("crypto");
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");
const { validateBody } = require("../middleware/validate");
const {
  ensureRecipientSchema,
  sendFileSchema,
  provisionRecipientKeysSchema,
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
  return Boolean(
    user?.iron &&
      user?.thor &&
      user?.hulk &&
      user?.venom,
  );
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
            error: "Gmail access expired. Allow Gmail again to continue sending.",
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
