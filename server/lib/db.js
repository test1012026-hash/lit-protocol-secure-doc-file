const User = require("../models/User");

const STALE_USER_INDEXES = ["userName_1", "username_1"];

async function syncUserIndexes() {
  const collection = User.collection;
  const existing = await collection.indexes();

  for (const indexName of STALE_USER_INDEXES) {
    const stale = existing.some((index) => index.name === indexName);
    if (!stale) continue;

    await collection.dropIndex(indexName);
    console.log(`Dropped stale MongoDB index: ${indexName}`);
  }

  await User.syncIndexes();
}

module.exports = { syncUserIndexes };
