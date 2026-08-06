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
  // Space-separated Google scopes already granted, so we never re-prompt for them.
  gmailScopes: { type: String, default: "" },
  gmailConnectState: { type: String, default: null },
  gmailConnectStateExpires: { type: Date, default: null },
  claimed: { type: Boolean, default: false },
  termsAndConditions: { type: Boolean, default: false },
  // Hashed app refresh JWT — used to mint new access tokens.
  refreshTokenHash: { type: String, default: null },
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
