const crypto = require("crypto");
const { normalizeEmail } = require("./email");

const ENC_PREFIX = "enc:v1:";

/** Personal Microsoft mailbox domains that often share one account / oid. */
const MS_CONSUMER_DOMAINS = [
  "hotmail.com",
  "outlook.com",
  "live.com",
  "msn.com",
];

function emailKeyMaterial() {
  const raw =
    process.env.EMAIL_ENCRYPTION_KEY ||
    process.env.JWT_SECRET ||
    "";
  if (!raw) {
    throw new Error(
      "EMAIL_ENCRYPTION_KEY (or JWT_SECRET) is required to encrypt emails at rest",
    );
  }
  return crypto.createHash("sha256").update(String(raw)).digest();
}

/** Deterministic HMAC for lookups — never store plaintext for queries. */
function hashEmail(raw) {
  const email = normalizeEmail(raw);
  if (!email) return "";
  return crypto
    .createHmac("sha256", emailKeyMaterial())
    .update(`email|${email}`)
    .digest("hex");
}

function isEncryptedEmail(value) {
  return String(value || "").startsWith(ENC_PREFIX);
}

/** AES-256-GCM ciphertext stored in DB (random IV per write). */
function encryptEmail(raw) {
  const email = normalizeEmail(raw);
  if (!email) return "";
  const key = emailKeyMaterial();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([
    cipher.update(email, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return (
    ENC_PREFIX +
    Buffer.concat([iv, tag, enc]).toString("base64url")
  );
}

/** Decrypt stored value; plaintext legacy rows pass through. */
function decryptEmail(stored) {
  const value = String(stored || "");
  if (!value) return "";
  if (!isEncryptedEmail(value)) return normalizeEmail(value);

  const buf = Buffer.from(value.slice(ENC_PREFIX.length), "base64url");
  if (buf.length < 12 + 16) {
    throw new Error("Corrupt encrypted email");
  }
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    emailKeyMaterial(),
    iv,
  );
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([
    decipher.update(data),
    decipher.final(),
  ]).toString("utf8");
  return normalizeEmail(plain);
}

/** Set encrypted email + lookup hash on a mongoose doc / plain object. */
function applyEncryptedEmail(doc, raw) {
  const email = normalizeEmail(raw);
  if (!email) {
    throw new Error("Email is required");
  }
  doc.email = encryptEmail(email);
  doc.emailHash = hashEmail(email);
  return email;
}

function getPlainEmail(doc) {
  if (!doc) return "";
  return decryptEmail(doc.email);
}

function splitEmail(raw) {
  const email = normalizeEmail(raw);
  if (!email || !email.includes("@")) return null;
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!local || !domain) return null;
  return { local, domain, email };
}

/**
 * If email is on a Microsoft consumer domain, return same local-part on
 * hotmail/outlook/live/msn so Graph-missing aliases still resolve.
 */
function expandMicrosoftConsumerAliases(rawEmail) {
  const parts = splitEmail(rawEmail);
  if (!parts) return [];
  if (!MS_CONSUMER_DOMAINS.includes(parts.domain)) return [parts.email];
  return MS_CONSUMER_DOMAINS.map((d) => `${parts.local}@${d}`);
}

/**
 * Find a Microsoft-linked user that owns a sibling consumer alias
 * (e.g. encrypt to x@outlook.com → find x@hotmail.com with microsoftId).
 */
async function findUserByMicrosoftConsumerSibling(
  UserModel,
  rawEmail,
  extraQuery = {},
) {
  const parts = splitEmail(rawEmail);
  if (!parts || !MS_CONSUMER_DOMAINS.includes(parts.domain)) return null;

  const siblingHashes = expandMicrosoftConsumerAliases(parts.email)
    .filter((e) => e !== parts.email)
    .map((e) => hashEmail(e));

  if (!siblingHashes.length) return null;

  const user = await UserModel.findOne({
    microsoftId: { $ne: null, $exists: true },
    $or: [
      { emailHash: { $in: siblingHashes } },
      { microsoftAliasHashes: { $in: siblingHashes } },
    ],
    ...extraQuery,
  });

  if (user) {
    console.log("[findUserByMicrosoftConsumerSibling]", {
      lookup: parts.email,
      uuid: user.uuid,
      microsoftId: user.microsoftId,
      primaryEmail: getPlainEmail(user) || null,
    });
  }
  return user;
}

/**
 * Find user by email. Migrates legacy plaintext rows to encrypted on read.
 * @param {import('mongoose').Model} UserModel
 */
async function findUserByEmail(UserModel, rawEmail, extraQuery = {}) {
  const email = normalizeEmail(rawEmail);
  if (!email) return null;

  const hash = hashEmail(email);
  let user = await UserModel.findOne({ emailHash: hash, ...extraQuery });
  let match = user ? "emailHash" : null;

  // Same Microsoft account may receive mail on hotmail/outlook/live aliases.
  if (!user) {
    user = await UserModel.findOne({
      microsoftAliasHashes: hash,
      ...extraQuery,
    });
    if (user) match = "microsoftAliasHashes";
  }

  // Graph /me often only returns one consumer address; still match siblings.
  if (!user) {
    user = await findUserByMicrosoftConsumerSibling(
      UserModel,
      email,
      extraQuery,
    );
    if (user) match = "microsoftConsumerSibling";
  }

  if (!user) {
    // Legacy plaintext (or missing hash) — match old unique email field.
    user = await UserModel.findOne({ email, ...extraQuery });
    if (!user) {
      const raw = String(rawEmail || "").trim().toLowerCase();
      if (raw && raw !== email) {
        user = await UserModel.findOne({ email: raw, ...extraQuery });
      }
    }
    if (user) match = match || "legacyEmail";
    if (user && !isEncryptedEmail(user.email)) {
      applyEncryptedEmail(user, email);
      try {
        await user.save();
      } catch (err) {
        if (err.code !== 11000) throw err;
        const raced = await UserModel.findOne({
          emailHash: hash,
          ...extraQuery,
        });
        if (raced) return raced;
      }
    } else if (user && !user.emailHash) {
      user.emailHash = hashEmail(getPlainEmail(user));
      try {
        await user.save();
      } catch {
        // ignore race
      }
    }
  }

  if (user) {
    console.log("[findUserByEmail]", {
      lookup: email,
      match,
      uuid: user.uuid,
      microsoftId: user.microsoftId || null,
      primaryEmail: (() => {
        try {
          return getPlainEmail(user);
        } catch {
          return null;
        }
      })(),
    });
  } else {
    console.log("[findUserByEmail] NOT FOUND", { lookup: email });
  }

  return user;
}

/** Find by Graph /me.id (oid). Also migrates legacy googleId = "microsoft:<id>". */
async function findUserByMicrosoftId(UserModel, microsoftId, extraQuery = {}) {
  const id = String(microsoftId || "").trim();
  if (!id) return null;

  let user = await UserModel.findOne({ microsoftId: id, ...extraQuery });
  if (user) return user;

  user = await UserModel.findOne({
    googleId: `microsoft:${id}`,
    ...extraQuery,
  });
  if (user) {
    user.microsoftId = id;
    if (String(user.googleId || "").startsWith("microsoft:")) {
      user.googleId = null;
    }
    try {
      await user.save();
    } catch (err) {
      if (err.code === 11000) {
        return UserModel.findOne({ microsoftId: id, ...extraQuery });
      }
      throw err;
    }
  }
  return user;
}

/**
 * Record Microsoft oid + every known alias hash so encrypt-to-alias finds this user.
 * Also expands hotmail/outlook/live/msn siblings for the same local-part.
 */
function linkMicrosoftIdentity(user, { microsoftId, emails = [], primaryEmail } = {}) {
  if (!user) return user;
  const id = microsoftId ? String(microsoftId).trim() : "";
  if (id) user.microsoftId = id;

  const list = Array.isArray(user.microsoftAliasHashes)
    ? [...user.microsoftAliasHashes]
    : [];
  const add = (raw) => {
    const e = normalizeEmail(raw);
    if (!e || e.includes("#ext#")) return;
    const h = hashEmail(e);
    if (h && !list.includes(h)) list.push(h);
    // Register consumer siblings (Graph often omits outlook.com when mail is hotmail).
    for (const sibling of expandMicrosoftConsumerAliases(e)) {
      const sh = hashEmail(sibling);
      if (sh && !list.includes(sh)) list.push(sh);
    }
  };
  for (const e of emails) add(e);
  if (primaryEmail) add(primaryEmail);
  user.microsoftAliasHashes = list;
  return user;
}

/**
 * Prefer Microsoft-linked account over an unclaimed stub for the same To: address.
 */
async function preferMicrosoftLinkedRecipient(UserModel, email, candidate) {
  if (candidate?.microsoftId) return candidate;

  const sibling = await findUserByMicrosoftConsumerSibling(UserModel, email);
  if (!sibling) return candidate;

  // Attach this To: address as an alias on the Microsoft account.
  linkMicrosoftIdentity(sibling, {
    microsoftId: sibling.microsoftId,
    primaryEmail: email,
  });
  try {
    await sibling.save();
  } catch {
    /* ignore */
  }

  // Drop unclaimed stub created earlier for the alias (no microsoftId).
  if (
    candidate &&
    !candidate.microsoftId &&
    !candidate.claimed &&
    String(candidate._id) !== String(sibling._id)
  ) {
    try {
      await UserModel.deleteOne({ _id: candidate._id, claimed: false });
      console.log("[preferMicrosoftLinkedRecipient] removed unclaimed stub", {
        stubUuid: candidate.uuid,
        keptUuid: sibling.uuid,
        to: email,
      });
    } catch {
      /* ignore */
    }
  }

  return sibling;
}

/**
 * Encrypt/send recipient resolution:
 * - Prefer existing user by email OR microsoftAliasHashes OR MS consumer sibling
 * - If that user has microsoftId → reuse SAME RSA keys (do not create a new user)
 * - Only create an unclaimed stub when no match exists
 */
async function resolveEncryptRecipient(UserModel, rawEmail) {
  const email = normalizeEmail(rawEmail);
  if (!email) {
    const err = new Error("Receiver email (to) is required");
    err.status = 400;
    err.code = "RECIPIENT_REQUIRED";
    throw err;
  }

  let recipient = await findUserByEmail(UserModel, email);
  recipient = await preferMicrosoftLinkedRecipient(
    UserModel,
    email,
    recipient,
  );

  if (recipient) {
    // Same Microsoft account (any alias) → keep this user + RSA keys.
    if (recipient.microsoftId) {
      const before = Array.isArray(recipient.microsoftAliasHashes)
        ? recipient.microsoftAliasHashes.length
        : 0;
      linkMicrosoftIdentity(recipient, {
        microsoftId: recipient.microsoftId,
        primaryEmail: email,
      });
      const after = recipient.microsoftAliasHashes.length;
      if (after !== before) {
        try {
          await recipient.save();
        } catch {
          /* ignore race */
        }
      }
      console.log("[resolveEncryptRecipient] reuse Microsoft account keys", {
        to: email,
        uuid: recipient.uuid,
        microsoftId: recipient.microsoftId,
        hasKeys: Boolean(recipient.iron && recipient.thor),
        primaryEmail: getPlainEmail(recipient) || null,
      });
    } else {
      console.log(
        "[resolveEncryptRecipient] reuse email user (no microsoftId yet)",
        {
          to: email,
          uuid: recipient.uuid,
          hasKeys: Boolean(recipient.iron && recipient.thor),
        },
      );
    }
    return {
      recipient,
      created: false,
      reusedMicrosoftKeys: Boolean(recipient.microsoftId),
    };
  }

  // Last chance before create: sibling with microsoftId
  const sibling = await findUserByMicrosoftConsumerSibling(UserModel, email);
  if (sibling) {
    linkMicrosoftIdentity(sibling, {
      microsoftId: sibling.microsoftId,
      primaryEmail: email,
    });
    try {
      await sibling.save();
    } catch {
      /* ignore */
    }
    console.log("[resolveEncryptRecipient] reuse Microsoft sibling keys", {
      to: email,
      uuid: sibling.uuid,
      microsoftId: sibling.microsoftId,
      primaryEmail: getPlainEmail(sibling) || null,
    });
    return {
      recipient: sibling,
      created: false,
      reusedMicrosoftKeys: true,
    };
  }

  try {
    recipient = new UserModel({
      claimed: false,
      uuid: crypto.randomUUID(),
    });
    applyEncryptedEmail(recipient, email);
    await recipient.save();
    console.log("[resolveEncryptRecipient] created new unclaimed recipient", {
      to: email,
      uuid: recipient.uuid,
    });
    return { recipient, created: true, reusedMicrosoftKeys: false };
  } catch (err) {
    if (err.code === 11000) {
      recipient = await findUserByEmail(UserModel, email);
      recipient = await preferMicrosoftLinkedRecipient(
        UserModel,
        email,
        recipient,
      );
      if (recipient) {
        return {
          recipient,
          created: false,
          reusedMicrosoftKeys: Boolean(recipient.microsoftId),
        };
      }
    }
    throw err;
  }
}

module.exports = {
  hashEmail,
  encryptEmail,
  decryptEmail,
  isEncryptedEmail,
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
  findUserByMicrosoftId,
  linkMicrosoftIdentity,
  resolveEncryptRecipient,
  expandMicrosoftConsumerAliases,
  MS_CONSUMER_DOMAINS,
};
