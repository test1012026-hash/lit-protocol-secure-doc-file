const crypto = require("crypto");
const { normalizeEmail } = require("./email");

const ENC_PREFIX = "enc:v1:";

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

/**
 * Find user by email. Migrates legacy plaintext rows to encrypted on read.
 * @param {import('mongoose').Model} UserModel
 */
async function findUserByEmail(UserModel, rawEmail, extraQuery = {}) {
  const email = normalizeEmail(rawEmail);
  if (!email) return null;

  const hash = hashEmail(email);
  let user = await UserModel.findOne({ emailHash: hash, ...extraQuery });

  if (!user) {
    // Legacy plaintext (or missing hash) — match old unique email field.
    user = await UserModel.findOne({ email, ...extraQuery });
    if (!user) {
      const raw = String(rawEmail || "").trim().toLowerCase();
      if (raw && raw !== email) {
        user = await UserModel.findOne({ email: raw, ...extraQuery });
      }
    }
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

  return user;
}

module.exports = {
  hashEmail,
  encryptEmail,
  decryptEmail,
  isEncryptedEmail,
  applyEncryptedEmail,
  getPlainEmail,
  findUserByEmail,
};
