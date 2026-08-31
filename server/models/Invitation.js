const mongoose = require("mongoose");
const crypto = require("crypto");

const invitationSchema = new mongoose.Schema({
  email: { type: String, required: true, trim: true, lowercase: true },
  emailHash: { type: String, required: true, index: true },
  invitedByUuid: { type: String, required: true, index: true },
  role: {
    type: String,
    enum: ["reseller", "group_admin", "subscriber"],
    default: "subscriber",
  },
  parentUuid: { type: String, default: null },
  sellerUuid: { type: String, default: null },
  groupAdminUuid: { type: String, default: null },
  groupUuid: { type: String, default: null },
  /** Optional group name when inviting a group_admin (created on accept). */
  groupName: { type: String, default: "", trim: true, maxlength: 120 },
  groupDescription: { type: String, default: "", trim: true, maxlength: 500 },
  tokenHash: { type: String, required: true, unique: true },
  status: {
    type: String,
    enum: ["pending", "accepted", "revoked", "expired"],
    default: "pending",
    index: true,
  },
  expiresAt: { type: Date, required: true },
  acceptedAt: { type: Date, default: null },
  acceptedUserUuid: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

invitationSchema.statics.hashToken = function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
};

invitationSchema.statics.createToken = function createToken() {
  return crypto.randomBytes(32).toString("hex");
};

module.exports = mongoose.model("Invitation", invitationSchema);
