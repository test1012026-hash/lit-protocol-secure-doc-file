const express = require("express");
const crypto = require("crypto");
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");
const { validateBody } = require("../middleware/validate");
const {
  ensureRecipientSchema,
  sendFileSchema,
} = require("../validation/schemas");
const { sendEncryptedFileEmail } = require("../lib/mail");

const router = express.Router();
const DEMO_MODE = process.env.DEMO_MODE === "true";

async function ensureRecipientByEmail(email) {
  let recipient = await User.findOne({ email });
  if (recipient) return recipient;

  try {
    return await User.create({
      email,
      claimed: false,
      uuid: crypto.randomUUID(),
    });
  } catch (err) {
    if (err.code === 11000) {
      recipient = await User.findOne({ email });
      if (recipient) return recipient;
    }
    throw err;
  }
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
        encryptedPackageBase64,
        encryptedPackageName,
        recipientUuid,
      } = req.body;

      const recipient = await ensureRecipientByEmail(recipientEmail);

      if (recipientUuid && recipient.uuid !== recipientUuid) {
        return res.status(400).json({
          error:
            "Recipient UUID mismatch. Re-fetch recipient and encrypt again.",
        });
      }

      const normalizedSubject = subject || filename || "Untitled document";
      const emailSent = await sendEncryptedFileEmail({
        to: recipientEmail,
        senderEmail: req.user.email,
        subject: normalizedSubject,
        message: message || "",
        attachmentName: encryptedPackageName,
        attachmentBase64: encryptedPackageBase64,
        demoMode: DEMO_MODE,
      });

      res.json({
        recipientUuid: recipient.uuid,
        recipientClaimed: recipient.claimed,
        emailSent,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
