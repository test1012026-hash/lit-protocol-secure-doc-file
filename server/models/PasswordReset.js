const mongoose = require("mongoose");

const passwordResetSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
  },
  emailHash: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  tokenHash: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("PasswordReset", passwordResetSchema);
