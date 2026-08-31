const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });
const mongoose = require("mongoose");
const Group = require("../models/Group");
const User = require("../models/User");
const SystemSettings = require("../models/SystemSettings");
const { getGroupTrialDays, addDays } = require("../lib/subscription");

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("MONGODB_URI is required");
    process.exit(1);
  }

  await mongoose.connect(uri);
  console.log("Connected to MongoDB.");

  const trialDays = await getGroupTrialDays();
  console.log(`Using trial days from SystemSettings: ${trialDays} days`);

  const groups = await Group.find({});
  console.log(`Found ${groups.length} groups.`);

  let updatedGroupsCount = 0;
  let updatedUsersCount = 0;

  for (const group of groups) {
    let groupExpiresAt = group.expiresAt;
    if (!groupExpiresAt) {
      const createdAt = group.createdAt ? new Date(group.createdAt) : new Date();
      groupExpiresAt = addDays(createdAt, trialDays);
      group.expiresAt = groupExpiresAt;
      await group.save();
      updatedGroupsCount++;
      console.log(`Updated group "${group.name}" (${group.uuid}) expiresAt to ${groupExpiresAt.toISOString()}`);
    }

    // Sync all connected users (group admin + members)
    const result = await User.updateMany(
      {
        deletedAt: null,
        $or: [
          { groupUuid: group.uuid },
          { groupAdminUuid: group.adminUuid },
          { uuid: group.adminUuid },
        ],
      },
      {
        $set: { subscriptionExpiresAt: groupExpiresAt },
      }
    );

    console.log(`Synced ${result.modifiedCount} users for group "${group.name}" to expiresAt: ${groupExpiresAt.toISOString()}`);
    updatedUsersCount += result.modifiedCount;
  }

  console.log(`\nDone! Updated ${updatedGroupsCount} groups and synced ${updatedUsersCount} users.`);
  await mongoose.disconnect();
}

main().catch((err) => {
  console.error("Error syncing group expiration:", err);
  process.exit(1);
});
