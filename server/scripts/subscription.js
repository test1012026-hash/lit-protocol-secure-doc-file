/**
 * One-time: set subscriptionExpiresAt for claimed users missing it,
 * and remove obsolete subscriptionStatus field from all users.
 *
 * Run: node scripts/backfill-subscription.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const User = require("../models/User");
const { FREE_TRIAL_DAYS, trialExpiresFrom } = require("../lib/subscription");

async function main() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is required");
  }

  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connected. FREE_TRIAL_DAYS =", FREE_TRIAL_DAYS);

  const missing = await User.find();

  let updated = 0;
  for (const user of missing) {
    const start = user.createdAt ? new Date(user.createdAt) : new Date();
    user.subscriptionExpiresAt = trialExpiresFrom(start);
    await user.save();
    updated += 1;
    console.log(
      `Set expires for ${user.email}: ${user.subscriptionExpiresAt.toISOString()}`,
    );
  }

  const unsetResult = await User.updateMany(
    {},
    { $unset: { subscriptionStatus: "" } },
  );

  console.log(
    `Backfilled subscriptionExpiresAt on ${updated} claimed user(s).`,
  );
  console.log(
    `Removed subscriptionStatus from ${unsetResult.modifiedCount} document(s).`,
  );
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect().catch(() => {});
  });
