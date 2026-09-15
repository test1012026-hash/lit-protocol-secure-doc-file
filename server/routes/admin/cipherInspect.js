const express = require("express");
const User = require("../../models/User");
const { requireRoles } = require("../../middleware/adminAuth");
const { logActivity } = require("../../lib/activityLog");
const { getPlainEmail } = require("../../lib/emailCrypto");
const {
  sha256Hex,
  parseEncryptedPackage,
  parseEncryptedPackageFromBytes,
  decryptForRecipient,
  parseDecryptedContent,
} = require("../../lib/secureCrypto");

const router = express.Router();

/**
 * Find user whose sha256(uuid) matches package.recipientUuidHash.
 * Stops at first match (uuid is unique).
 */
async function findUserByUuidHash(hash) {
  const target = String(hash || "")
    .trim()
    .toLowerCase();
  if (!target || target.length < 32) return null;

  const cursor = User.find({ deletedAt: null })
    .select(
      "uuid email claimed role blocked microsoftId iron thor hulk venom subscriptionExpiresAt createdAt",
    )
    .lean()
    .cursor();

  for await (const user of cursor) {
    if (!user?.uuid) continue;
    if (sha256Hex(user.uuid) === target) {
      return user;
    }
  }
  return null;
}

function previewBase64(value, max = 48) {
  const s = String(value || "");
  if (!s) return null;
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
}

function packageSummary(pkg) {
  const ciphertext = pkg.ciphertext || null;
  const wrappedKey = pkg.wrappedKey || null;
  const iv = pkg.iv || null;
  return {
    version: pkg.version || null,
    type: pkg.type || "secure-doc-share",
    kind: pkg.kind || null,
    mode: pkg.mode || null,
    keyScheme: pkg.keyScheme || null,
    recipientUuidHash: pkg.recipientUuidHash || null,
    actionId: pkg.actionId || null,
    filename: pkg.filename || null,
    mimeType: pkg.mimeType || null,
    expectedEmail: pkg.expectedEmail || null,
    hasIv: Boolean(iv),
    hasWrappedKey: Boolean(wrappedKey),
    hasCiphertext: Boolean(ciphertext),
    iv: iv || null,
    ivLength: iv ? String(iv).length : 0,
    wrappedKeyLength: wrappedKey ? String(wrappedKey).length : 0,
    ciphertextLength: ciphertext ? String(ciphertext).length : 0,
    wrappedKeyPreview: previewBase64(wrappedKey),
    ciphertextPreview: previewBase64(ciphertext),
  };
}

function recipientSummary(user) {
  if (!user) {
    return {
      found: false,
      uuid: null,
      email: null,
    };
  }
  return {
    found: true,
    uuid: user.uuid,
    email: getPlainEmail(user) || null,
    claimed: Boolean(user.claimed),
    role: user.role || null,
    blocked: Boolean(user.blocked),
    microsoftId: user.microsoftId || null,
    hasPublicKey: Boolean(user.iron),
    hasPrivateKeyBundle: Boolean(user.thor && user.hulk && user.venom),
    subscriptionExpiresAt: user.subscriptionExpiresAt || null,
    createdAt: user.createdAt || null,
  };
}

/**
 * POST /api/admin/cipher/inspect
 * Super-admin only. Paste sds. ciphertext or upload packageBase64 (.securepdf).
 * Returns package fields + resolved recipient UUID (via hash match).
 * Optional decryptAttempt for support (does not expose private keys).
 */
router.post("/inspect", requireRoles("super_admin"), async (req, res) => {
  try {
    const body = req.body || {};
    const packageText =
      body.packageText ||
      body.ciphertext ||
      body.messageCipherText ||
      body.text ||
      null;
    const packageBase64 =
      body.packageBase64 ||
      body.fileCipherText ||
      body.fileBase64 ||
      null;
    const decryptAttempt = body.decryptAttempt === true;

    if (!packageText && !packageBase64) {
      return res.status(400).json({
        ok: false,
        error:
          "Provide packageText (sds.…) and/or packageBase64 (encrypted PDF / package).",
        code: "INPUT_REQUIRED",
      });
    }

    let encryptedPackage;
    let source = "text";
    try {
      if (packageBase64) {
        const bytes = Buffer.from(
          String(packageBase64).replace(/\s+/g, ""),
          "base64",
        );
        encryptedPackage = parseEncryptedPackageFromBytes(bytes);
        source = "base64";
      } else {
        encryptedPackage = parseEncryptedPackage(String(packageText));
        source = "text";
      }
    } catch (err) {
      return res.status(400).json({
        ok: false,
        error: err.message || "Could not parse package",
        code: err.code || "PARSE_FAILED",
      });
    }

    const hash = encryptedPackage.recipientUuidHash || null;
    const matchedUser = hash ? await findUserByUuidHash(hash) : null;
    const recipient = recipientSummary(matchedUser);

    let decrypt = {
      attempted: false,
      ok: false,
      message: null,
      file: null,
      error: null,
    };

    if (decryptAttempt && matchedUser) {
      decrypt.attempted = true;
      try {
        const plain = decryptForRecipient({
          encryptedPackage,
          recipientUuid: matchedUser.uuid,
          user: matchedUser,
        });
        const content = parseDecryptedContent(plain, encryptedPackage);
        decrypt.ok = true;
        decrypt.message = content.message || null;
        if (content.file) {
          decrypt.file = {
            filename: content.file.filename || content.file.name || null,
            mimeType: content.file.mimeType || content.file.contentType || null,
            // Keep payload small in UI — return size only, not full bytes.
            hasData: Boolean(
              content.file.dataBase64 ||
                content.file.base64 ||
                content.file.data,
            ),
            dataBase64Length: String(
              content.file.dataBase64 ||
                content.file.base64 ||
                content.file.data ||
                "",
            ).length,
          };
        }
      } catch (err) {
        decrypt.ok = false;
        decrypt.error = err.message || String(err);
      }
    } else if (decryptAttempt && !matchedUser) {
      decrypt.attempted = true;
      decrypt.error =
        "Cannot decrypt: no user matched recipientUuidHash in the database.";
    }

    await logActivity({
      actorUuid: req.admin.uuid,
      actorRole: req.admin.role,
      action: "admin.cipher_inspect",
      targetType: "cipher",
      targetUuid: recipient.uuid || null,
      meta: {
        source,
        kind: encryptedPackage.kind || null,
        hashPrefix: hash ? String(hash).slice(0, 12) : null,
        recipientFound: recipient.found,
        decryptAttempted: decrypt.attempted,
        decryptOk: decrypt.ok,
      },
    }).catch(() => {});

    return res.json({
      ok: true,
      source,
      package: packageSummary(encryptedPackage),
      recipient,
      // Explicit UUID for convenience in admin UI
      uuid: recipient.uuid || null,
      uuidResolved: recipient.found,
      decrypt,
      note: recipient.found
        ? "UUID resolved by matching sha256(user.uuid) to package.h"
        : "UUID not found in DB — hash cannot be reversed; only matched against stored users.",
    });
  } catch (err) {
    console.error("[admin/cipher/inspect]", err);
    return res.status(500).json({
      ok: false,
      error: err.message || "Inspect failed",
      code: "INSPECT_FAILED",
    });
  }
});

module.exports = router;
