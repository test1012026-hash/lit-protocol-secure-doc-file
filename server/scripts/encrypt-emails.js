require("dotenv").config();
const mongoose = require("mongoose");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const {
  applyEncryptedEmail,
  isEncryptedEmail,
  getPlainEmail,
  hashEmail,
  encryptEmail,
} = require("../lib/emailCrypto");

async function main() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is required");
  }

  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connected. Encrypting emails…");

  let usersUpdated = 0;
  const users = await User.find({});
  for (const user of users) {
    if (!user.email) continue;
    if (isEncryptedEmail(user.email) && user.emailHash) continue;
    const plain = getPlainEmail(user);
    if (!plain) continue;
    applyEncryptedEmail(user, plain);
    await user.save();
    usersUpdated += 1;
    console.log(`User ${user.uuid} → encrypted`);
  }

  let resetsUpdated = 0;
  const resets = await PasswordReset.find({});
  for (const row of resets) {
    if (!row.email) continue;
    if (isEncryptedEmail(row.email) && row.emailHash) continue;
    const plain = getPlainEmail(row);
    if (!plain) continue;
    row.email = encryptEmail(plain);
    row.emailHash = hashEmail(plain);
    await row.save();
    resetsUpdated += 1;
  }

  console.log(
    `Done. Users encrypted: ${usersUpdated}. Password resets encrypted: ${resetsUpdated}.`,
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
