/**
 * Fix E11000 on users.microsoftId_1 when many docs have microsoftId: null.
 * Unsets null/empty microsoftId and replaces the unique index with a partial one.
 *
 *   node scripts/fix-microsoft-id-index.js
 */
require("dotenv").config();
const mongoose = require("mongoose");

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required");

  await mongoose.connect(uri);
  const col = mongoose.connection.collection("users");

  const unsetResult = await col.updateMany(
    {
      $or: [
        { microsoftId: null },
        { microsoftId: "" },
      ],
    },
    { $unset: { microsoftId: "" } },
  );
  console.log("Unset null/empty microsoftId:", unsetResult.modifiedCount);

  const indexes = await col.indexes();
  for (const idx of indexes) {
    if (idx.name === "microsoftId_1" || idx.name === "microsoftId_1_partial") {
      try {
        await col.dropIndex(idx.name);
        console.log("Dropped index:", idx.name);
      } catch (err) {
        console.warn("Drop index failed:", idx.name, err.message);
      }
    }
  }

  await col.createIndex(
    { microsoftId: 1 },
    {
      unique: true,
      name: "microsoftId_1_partial",
      partialFilterExpression: {
        microsoftId: { $type: "string", $gt: "" },
      },
    },
  );
  console.log("Created partial unique index microsoftId_1_partial");

  await mongoose.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
