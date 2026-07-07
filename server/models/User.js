const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  uuid: { type: String, required: true, unique: true, default: () => crypto.randomUUID() },
  passwordHash: { type: String, default: null },
  googleId: { type: String, default: null },
  // false = a shell record created because someone sent this address a file
  // before the owner ever signed up. The UUID stays the same once claimed.
  claimed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
