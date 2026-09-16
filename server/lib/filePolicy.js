/**
 * Platform file policy: which extensions may be encrypted / attached.
 * Admin settings store blockedFileExtensions (e.g. ["vbs","exe"]).
 */
const SystemSettings = require("../models/SystemSettings");

function normalizeExtension(value) {
  let ext = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^\.+/, "");
  // Strip path fragments / query junk
  ext = ext.split(/[\\/]/)[0].split("?")[0].trim();
  if (!ext) return "";
  // Allow only simple extension tokens
  if (!/^[a-z0-9]{1,20}$/.test(ext)) return "";
  return ext;
}

function normalizeExtensionList(list) {
  const out = [];
  const seen = new Set();
  const raw = Array.isArray(list) ? list : String(list || "").split(/[,\s;]+/);
  for (const item of raw) {
    const ext = normalizeExtension(item);
    if (!ext || seen.has(ext)) continue;
    seen.add(ext);
    out.push(ext);
  }
  return out;
}

function extensionFromFileName(fileName) {
  const name = String(fileName || "").trim();
  if (!name) return "";
  const base = name.split(/[\\/]/).pop() || "";
  const dot = base.lastIndexOf(".");
  if (dot <= 0 || dot === base.length - 1) return "";
  return normalizeExtension(base.slice(dot + 1));
}

async function getBlockedFileExtensions() {
  const settings = await SystemSettings.getOrCreate();
  return normalizeExtensionList(settings.blockedFileExtensions || []);
}

/**
 * @returns {{ ok: true, extension } | { ok: false, error, code, extension, blockedExtensions }}
 */
function assertFileExtensionAllowed(fileName, blockedExtensions) {
  const blocked = normalizeExtensionList(blockedExtensions);
  const extension = extensionFromFileName(fileName);
  if (!extension) {
    return { ok: true, extension: "" };
  }
  if (blocked.includes(extension)) {
    return {
      ok: false,
      code: "FILE_EXTENSION_BLOCKED",
      error: `Files with .${extension} extension are blocked by admin and cannot be encrypted.`,
      extension,
      blockedExtensions: blocked,
    };
  }
  return { ok: true, extension };
}

async function assertEncryptFileAllowed(fileName) {
  if (!fileName) return { ok: true, extension: "", blockedExtensions: [] };
  const blocked = await getBlockedFileExtensions();
  const check = assertFileExtensionAllowed(fileName, blocked);
  return { ...check, blockedExtensions: blocked };
}

module.exports = {
  normalizeExtension,
  normalizeExtensionList,
  extensionFromFileName,
  getBlockedFileExtensions,
  assertFileExtensionAllowed,
  assertEncryptFileAllowed,
};
