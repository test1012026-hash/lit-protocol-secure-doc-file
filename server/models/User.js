const mongoose = require("mongoose");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  // AES-GCM ciphertext (enc:v1:...). Never store plaintext email.
  email: {
    type: String,
    required: true,
    trim: true,
  },
  // HMAC of normalized email — unique lookup key.
  emailHash: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  uuid: {
    type: String,
    required: true,
    unique: true,
    default: () => crypto.randomUUID(),
  },
  passwordHash: { type: String, default: null },
  googleId: { type: String, default: null },
  gmailRefreshToken: { type: String, default: null },
  gmailScopes: { type: String, default: "" },
  gmailConnectState: { type: String, default: null },
  gmailConnectStateExpires: { type: Date, default: null },
  claimed: { type: Boolean, default: false },
  termsAndConditions: { type: Boolean, default: false },
  refreshTokenHash: { type: String, default: null },
  subscriptionExpiresAt: { type: Date, default: null },
  iron: { type: String, default: null }, //publicKeySpki
  thor: { type: String, default: null }, //privateKeyEnc
  hulk: { type: String, default: null }, //privateKeyIv
  venom: { type: String, default: null }, //privateKeySalt

  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
