const express = require("express");
const SystemSettings = require("../../models/SystemSettings");
const { logActivity } = require("../../lib/activityLog");
const { validateBody } = require("../../middleware/validate");
const { systemSettingsUpdateSchema } = require("../../validation/schemas");
const { requireRoles } = require("../../middleware/adminAuth");
const { normalizeExtensionList } = require("../../lib/filePolicy");

const router = express.Router();

function settingsPayload(settings) {
  return {
    tokenExpiryHours: settings.tokenExpiryHours,
    checkInIntervalHours: settings.checkInIntervalHours,
    keyRotationRemindDays: settings.keyRotationRemindDays,
    blockedFileExtensions: normalizeExtensionList(
      settings.blockedFileExtensions || [],
    ),
    updatedAt: settings.updatedAt,
    updatedByUuid: settings.updatedByUuid,
  };
}

router.get("/", async (req, res) => {
  try {
    const settings = await SystemSettings.getOrCreate();
    return res.json({ settings: settingsPayload(settings) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/** Only super admin may update platform settings. */
router.patch(
  "/",
  requireRoles("super_admin"),
  validateBody(systemSettingsUpdateSchema),
  async (req, res) => {
    try {
      const settings = await SystemSettings.getOrCreate();
      for (const key of [
        "tokenExpiryHours",
        "checkInIntervalHours",
        "keyRotationRemindDays",
      ]) {
        if (req.body[key] !== undefined) settings[key] = req.body[key];
      }
      if (req.body.blockedFileExtensions !== undefined) {
        settings.blockedFileExtensions = normalizeExtensionList(
          req.body.blockedFileExtensions,
        );
      }
      settings.updatedAt = new Date();
      settings.updatedByUuid = req.admin.uuid;
      await settings.save();

      await logActivity({
        actorUuid: req.admin.uuid,
        actorRole: req.admin.role,
        action: "admin.settings_update",
        targetType: "settings",
        targetId: "platform",
        meta: {
          ...req.body,
          blockedFileExtensions: settings.blockedFileExtensions,
        },
        ip: req.ip,
      });

      return res.json({ settings: settingsPayload(settings) });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
