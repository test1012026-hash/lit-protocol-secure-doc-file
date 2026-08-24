const mongoose = require("mongoose");
const crypto = require("crypto");

const ROLES = ["super_admin", "reseller", "group_admin", "subscriber"];

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
  name: { type: String, default: "", trim: true, maxlength: 200 },
  phone: { type: String, default: "", trim: true, maxlength: 40 },
  country: { type: String, default: "", trim: true, maxlength: 80 },
  company: { type: String, default: "", trim: true, maxlength: 200 },

  passwordHash: { type: String, default: null },
  /** Signup email OTP (SHA-256). Cleared after successful verify / claim. */
  signupOtpHash: { type: String, default: null },
  signupOtpAttempts: { type: Number, default: 0 },
  signupOtpExpiresAt: { type: Date, default: null },
  /** Password reset token (SHA-256). Cleared after use or expiry. */
  passwordResetTokenHash: { type: String, default: null },
  passwordResetExpiresAt: { type: Date, default: null },
  googleId: { type: String, default: null },
  gmailRefreshToken: { type: String, default: null },
  gmailScopes: { type: String, default: "" },
  gmailConnectState: { type: String, default: null },
  gmailConnectStateExpires: { type: Date, default: null },
  claimed: { type: Boolean, default: false },
  termsAndConditions: { type: Boolean, default: false },
  /** Legacy — cleared on new logins. */
  refreshTokenHash: { type: String, default: null },
  /** SHA-256 of current JWT (session binding). createdAt/expiresAt live in the JWT. */
  accessTokenHash: { type: String, default: null, index: true },
  subscriptionExpiresAt: { type: Date, default: null },
  iron: { type: String, default: null }, // publicKeySpki
  thor: { type: String, default: null }, // privateKeyEnc
  hulk: { type: String, default: null }, // privateKeyIv
  venom: { type: String, default: null }, // privateKeySalt

  /** RBAC: super_admin | reseller | group_admin | subscriber */
  role: {
    type: String,
    enum: ROLES,
    default: "subscriber",
    index: true,
  },
  /** Immediate parent in the hierarchy (reseller → group → subscriber). */
  parentUuid: { type: String, default: null, index: true },
  /** Top-level reseller for this subtree. */
  sellerUuid: { type: String, default: null, index: true },
  /** Group admin for subscribers. */
  groupAdminUuid: { type: String, default: null, index: true },
  /** Link to Group.uuid when this user created / belongs to a named group. */
  groupUuid: { type: String, default: null, index: true },
  /**
   * Self-signup users must choose Create group vs Subscriber once.
   * Default true so existing accounts are not forced through onboarding.
   * New public signups set this to false until they choose a path.
   */
  onboardingComplete: { type: Boolean, default: true, index: true },

  /** Blocked: can receive + decrypt encrypted mail; cannot send/encrypt. */
  blocked: { type: Boolean, default: false, index: true },
  /** Soft delete — account removed from active use but retained. */
  deletedAt: { type: Date, default: null, index: true },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

userSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

userSchema.statics.ROLES = ROLES;

module.exports = mongoose.model("User", userSchema);
