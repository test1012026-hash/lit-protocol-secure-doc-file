import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

function extensionIdFromPublicKeyDer(der) {
  const hash = crypto.createHash('sha256').update(der).digest();
  let id = '';
  for (let i = 0; i < 16; i++) {
    id += String.fromCharCode(97 + (hash[i] >> 4));
    id += String.fromCharCode(97 + (hash[i] & 0xf));
  }
  return id;
}

function extensionIdFromPath(filepath) {
  let p = filepath;
  if (p.length >= 2 && p[0] >= 'a' && p[0] <= 'z' && p[1] === ':') {
    p = p[0].toUpperCase() + p.slice(1);
  }
  const hash = crypto.createHash('sha256').update(Buffer.from(p, 'utf16le')).digest();
  let id = '';
  for (let i = 0; i < 16; i++) {
    id += String.fromCharCode(97 + (hash[i] >> 4));
    id += String.fromCharCode(97 + (hash[i] & 0xf));
  }
  return id;
}

const distPath = path.join(root, 'dist');
console.log('Path-based ID (without manifest key):', extensionIdFromPath(distPath));

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const pubB64 = publicKey.toString('base64');
const id = extensionIdFromPublicKeyDer(publicKey);

fs.writeFileSync(path.join(root, 'extension-key.pem'), privateKey);

const manifestPath = path.join(root, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.key = pubB64;
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

console.log('Pinned extension ID:', id);
console.log('Add BOTH of these to Google Cloud authorized redirect URIs:');
console.log(`  https://${id}.chromiumapp.org`);
console.log(`  https://${id}.chromiumapp.org/`);
