const mongoose = require("mongoose");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
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
  gmailConnectState: { type: String, default: null },
  gmailConnectStateExpires: { type: Date, default: null },
  claimed: { type: Boolean, default: false },
  subscriptionExpiresAt: { type: Date, default: null },

  // RSA-OAEP public key (SPKI base64) — used by senders to encrypt every mail.
  publicKeySpki: { type: String, default: null },
  // Private key PKCS8, AES-GCM encrypted with passphrase = uuid + live Lit action id.
  privateKeyEnc: { type: String, default: null },
  privateKeyIv: { type: String, default: null },
  privateKeySalt: { type: String, default: null },

  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
