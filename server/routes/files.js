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

const router = express.Router();
const DEMO_MODE = process.env.DEMO_MODE === "true";

async function findUserByEmail(rawEmail) {
  const canonical = normalizeEmail(rawEmail);
  const raw = String(rawEmail || "")
    .trim()
    .toLowerCase();

  let user =
    (await User.findOne({ email: canonical, claimed: true })) ||
    (await User.findOne({ email: canonical }));

  if (!user && raw && raw !== canonical) {
    user =
      (await User.findOne({ email: raw, claimed: true })) ||
      (await User.findOne({ email: raw }));

    if (user) {
      const existingCanonical = await User.findOne({ email: canonical });
      if (
        existingCanonical &&
        String(existingCanonical._id) !== String(user._id)
      ) {
        return existingCanonical.claimed || !user.claimed
          ? existingCanonical
          : user;
      }
      user.email = canonical;
      try {
        await user.save();
      } catch (err) {
        if (err.code === 11000) {
          return (
            (await User.findOne({ email: canonical, claimed: true })) ||
            (await User.findOne({ email: canonical })) ||
            user
          );
        }
        throw err;
      }
    }
  }

  return user;
}

async function ensureRecipientByEmail(rawEmail) {
  const email = normalizeEmail(rawEmail);
  let recipient = await findUserByEmail(rawEmail);
  if (recipient) return recipient;

  try {
    return await User.create({
      email,
      claimed: false,
      uuid: crypto.randomUUID(),
    });
  } catch (err) {
    if (err.code === 11000) {
      recipient = await findUserByEmail(email);
      if (recipient) return recipient;
    }
    throw err;
  }
}

function hasCompleteRecipientKeys(user) {
  return Boolean(
    user?.publicKeySpki &&
      user?.privateKeyEnc &&
      user?.privateKeyIv &&
      user?.privateKeySalt,
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
        recipientEmail: recipient.email,
        recipientClaimed: recipient.claimed,
        publicKeySpki: recipient.publicKeySpki || null,
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
        publicKeySpki,
        privateKeyEnc,
        privateKeyIv,
        privateKeySalt,
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
          publicKeySpki: recipient.publicKeySpki,
          recipientUuid: recipient.uuid,
        });
      }

      recipient.publicKeySpki = String(publicKeySpki).trim();
      recipient.privateKeyEnc = String(privateKeyEnc).trim();
      recipient.privateKeyIv = String(privateKeyIv).trim();
      recipient.privateKeySalt = String(privateKeySalt).trim();
      await recipient.save();
      await User.updateOne(
        { _id: recipient._id },
        { $unset: { keyActionId: 1 } },
      );

      res.json({
        ok: true,
        alreadyProvisioned: false,
        publicKeySpki: recipient.publicKeySpki,
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
      if (!sender.gmailRefreshToken && !gmailAccessToken) {
        return res.status(403).json({
          error: "Allow Gmail access once to send from your address.",
          code: "GMAIL_NOT_CONNECTED",
        });
      }

      const normalizedSubject = subject || filename || "Untitled document";
      let emailSent = false;
      try {
        emailSent = await sendEncryptedFileEmail({
          to: recipientEmail,
          senderEmail: sender.email,
          subject: normalizedSubject,
          message: message || "",
          contentKind: contentKind || "file",
          attachmentName: encryptedPackageName,
          attachmentBase64: encryptedPackageBase64,
          encryptedPackageText: encryptedPackageText || "",
          demoMode: DEMO_MODE,
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
        from: sender.email,
      });
    } catch (err) {
      console.log("err -->", err);
      res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
