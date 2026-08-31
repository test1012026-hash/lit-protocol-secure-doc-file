const mongoose = require("mongoose");
const crypto = require("crypto");

/**
 * Named organization group.
 * - adminUuid: group_admin who runs the group
 * - sellerUuid: reseller that owns/created the group (nullable for self-serve signup groups)
 */
const groupSchema = new mongoose.Schema({
  uuid: {
    type: String,
    required: true,
    unique: true,
    default: () => crypto.randomUUID(),
    index: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 120,
  },
  /** User.uuid of the group admin. */
  adminUuid: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  /** Reseller that owns this group (when created by a reseller). */
  sellerUuid: {
    type: String,
    default: null,
    index: true,
  },
  /** Who created the group record (reseller, super_admin, or the group admin). */
  createdByUuid: {
    type: String,
    default: null,
    index: true,
  },
  description: {
    type: String,
    default: "",
    trim: true,
    maxlength: 500,
  },
  /** Group subscription / expiration date derived from system settings (keyRotationRemindDays). */
  expiresAt: {
    type: Date,
    default: null,
    index: true,
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

groupSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model("Group", groupSchema);
