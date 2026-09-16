const mongoose = require("mongoose");

const SETTINGS_KEY = "platform";

const systemSettingsSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    default: SETTINGS_KEY,
  },
  /** Access / check-in token lifetime in hours (default 8). */
  tokenExpiryHours: { type: Number, default: 8, min: 0.25, max: 168 },
  checkInIntervalHours: { type: Number, default: 8, min: 0.25, max: 168 },
  keyRotationRemindDays: { type: Number, default: 90, min: 1, max: 730 },
  /**
   * File extensions that must not be encrypted / sent via SecureDoc
   * (e.g. ["vbs","exe","bat"]). Stored without leading dots.
   */
  blockedFileExtensions: { type: [String], default: [] },
  updatedAt: { type: Date, default: Date.now },
  updatedByUuid: { type: String, default: null },
});

systemSettingsSchema.statics.SETTINGS_KEY = SETTINGS_KEY;

systemSettingsSchema.statics.getOrCreate = async function getOrCreate() {
  let doc = await this.findOne({ key: SETTINGS_KEY });
  if (!doc) {
    doc = await this.create({ key: SETTINGS_KEY });
  }
  return doc;
};

module.exports = mongoose.model("SystemSettings", systemSettingsSchema);
