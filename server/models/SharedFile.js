const mongoose = require('mongoose');

const sharedFileSchema = new mongoose.Schema({
  senderUuid: { type: String, required: true },
  senderEmail: { type: String, required: true, lowercase: true },
  recipientEmail: { type: String, required: true, lowercase: true },
  subject: { type: String, required: true },
  message: { type: String, default: '' },
  filename: { type: String, default: '' },
  ciphertext: { type: String, required: true },
  dataToEncryptHash: { type: String, required: true },
  litActionCode: { type: String, required: true },
  expectedEmail: { type: String, required: true, lowercase: true },
  downloaded: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SharedFile', sharedFileSchema);
