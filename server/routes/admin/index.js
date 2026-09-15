const express = require("express");
const authRoutes = require("./auth");
const usersRoutes = require("./users");
const invitationsRoutes = require("./invitations");
const settingsRoutes = require("./settings");
const activityRoutes = require("./activity");
const analyticsRoutes = require("./analytics");
const groupsRoutes = require("./groups");
const cipherInspectRoutes = require("./cipherInspect");
const { adminAuthMiddleware } = require("../../middleware/adminAuth");

const router = express.Router();

router.use("/auth", authRoutes);
router.use("/invitations", invitationsRoutes);

router.use(adminAuthMiddleware);
router.use("/users", usersRoutes);
router.use("/groups", groupsRoutes);
router.use("/settings", settingsRoutes);
router.use("/activity", activityRoutes);
router.use("/analytics", analyticsRoutes);
router.use("/cipher", cipherInspectRoutes);

module.exports = router;
