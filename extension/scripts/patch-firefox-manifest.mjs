/**
 * Patch extension/dist/manifest.json for Firefox temporary install.
 * Firefox often has background.service_worker disabled → needs background.scripts.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distManifest = path.join(__dirname, "..", "dist", "manifest.json");

if (!fs.existsSync(distManifest)) {
  console.error("dist/manifest.json not found. Run npm run build first.");
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(distManifest, "utf8"));
const sw =
  manifest.background?.service_worker ||
  manifest.background?.scripts?.[0];

if (!sw) {
  console.error("No background script found in dist/manifest.json");
  process.exit(1);
}

// Firefox event page (service workers often disabled for add-ons)
manifest.background = {
  scripts: [sw],
  type: "module",
};

// Chrome-only fields that can break or confuse Firefox
delete manifest.key;
delete manifest.oauth2;
delete manifest.externally_connectable;

manifest.browser_specific_settings = {
  gecko: {
    id: "securedocshare@local.dev",
    strict_min_version: "121.0",
  },
};

fs.writeFileSync(distManifest, JSON.stringify(manifest, null, 2) + "\n");
console.log("Firefox manifest ready:", distManifest);
console.log('background.scripts =', manifest.background.scripts);
