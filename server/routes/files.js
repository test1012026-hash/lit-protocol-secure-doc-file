const express = require("express");
const crypto = require("crypto");
const User = require("../models/User");
const SharedFile = require("../models/SharedFile");
const authMiddleware = require("../middleware/auth");

const router = express.Router();

router.post("/send", authMiddleware, async (req, res) => {
  try {
    const {
      recipientEmail,
      ciphertext,
      dataToEncryptHash,
      litActionCode,
      subject,
      message,
      filename,
    } = req.body;
    if (
      !recipientEmail ||
      !ciphertext ||
      !dataToEncryptHash ||
      !litActionCode
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const email = recipientEmail.toLowerCase();

    // Find the recipient, or create an unclaimed shell record with a UUID
    // ready for when they eventually sign up.
    let recipient = await User.findOne({ email });
    if (!recipient) {
      recipient = new User({
        email,
        claimed: false,
        uuid: crypto.randomUUID(),
      });
      await recipient.save();
    }

    const file = await SharedFile.create({
      senderUuid: req.user.uuid,
      senderEmail: req.user.email,
      recipientEmail: email,
      subject: subject?.trim() || filename?.trim() || "Untitled document",
      message: message?.trim() || "",
      filename: filename?.trim() || subject?.trim() || "Untitled document",
      ciphertext,
      dataToEncryptHash,
      litActionCode,
      expectedEmail: email,
    });

    res.json({
      fileId: file._id,
      recipientUuid: recipient.uuid,
      recipientClaimed: recipient.claimed,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/inbox", authMiddleware, async (req, res) => {
  const files = await SharedFile.find({ recipientEmail: req.user.email })
    .select("-ciphertext")
    .sort({ createdAt: -1 });
  res.json(files);
});

router.get("/receive/:id", authMiddleware, async (req, res) => {
  const file = await SharedFile.findById(req.params.id);
  if (!file) return res.status(404).json({ error: "File not found" });
  if (file.recipientEmail !== req.user.email) {
    return res.status(403).json({ error: "This file was not sent to you" });
  }

  file.downloaded = true;
  await file.save();
  res.json(file);
});

module.exports = router;
