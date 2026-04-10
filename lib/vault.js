/**
 * Vault — encrypts/decrypts sensitive values using envelope format.
 *
 * Current suite: ML-KEM-1024 + P-384 ECDH hybrid / XChaCha20-Poly1305 / SHAKE256
 * Keys are stored in data/vault.key (auto-generated on first run).
 * Encrypted values are prefixed with "vault:" so they can be detected.
 *
 * Key file format:
 *   v1 (legacy): { publicKey, privateKey }                    — ML-KEM-768 only
 *   v2 (current): { publicKey, privateKey, ecPublicKey, ecPrivateKey } — hybrid
 *
 * The vault auto-detects key format and encrypts with the best available.
 * Decryption works with any format via envelope versioning in lib/crypto.js.
 */
var fs = require("fs");
var path = require("path");
var { generateEncryptionKeyPair, encrypt, decrypt } = require("./crypto");
var { VAULT_PREFIX } = require("./constants");

var dataDir = path.join(__dirname, "..", "data");
var keyPath = path.join(dataDir, "vault.key");
var keys = null;

function loadKeys() {
  if (keys) return keys;

  if (fs.existsSync(keyPath)) {
    try {
      var loaded = JSON.parse(fs.readFileSync(keyPath, "utf8"));
      // Detect legacy v1 key (ML-KEM-768 only, no EC keys)
      if (!loaded.ecPublicKey) {
        console.log("  Vault: legacy ML-KEM key detected — upgrading to hybrid ML-KEM-1024 + P-384");
        var upgraded = generateEncryptionKeyPair();
        // Keep old ML-KEM key for decrypting existing data
        upgraded._legacyPrivateKey = loaded.privateKey;
        upgraded._legacyPublicKey = loaded.publicKey;
        // Write upgraded key file (preserves old keys inline)
        var toWrite = {
          publicKey: upgraded.publicKey,
          privateKey: upgraded.privateKey,
          ecPublicKey: upgraded.ecPublicKey,
          ecPrivateKey: upgraded.ecPrivateKey,
          _legacyPrivateKey: loaded.privateKey,
          _legacyPublicKey: loaded.publicKey,
        };
        fs.writeFileSync(keyPath, JSON.stringify(toWrite, null, 2), { mode: 0o600 });
        keys = toWrite;
        return keys;
      }
      keys = loaded;
      return keys;
    } catch (e) {
      console.error("FATAL: Vault key file corrupted or unreadable at " + keyPath + " — " + e.message);
      console.error("All sealed data (emails, files, sessions) requires the original key.");
      console.error("Restore data/vault.key from backup, then restart.");
      process.exit(1);
    }
  }

  // First run only — generate hybrid keypair
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  keys = generateEncryptionKeyPair();
  fs.writeFileSync(keyPath, JSON.stringify(keys, null, 2), { mode: 0o600 });
  console.log("  Vault keypair generated at data/vault.key (ML-KEM-1024 + P-384 hybrid)");
  process.nextTick(function () {
    try { var audit = require("./audit"); audit.log(audit.ACTIONS.VAULT_KEY_GENERATED, { performedBy: "system", details: "New ML-KEM-1024 + P-384 hybrid keypair created" }); } catch (_e) {}
  });
  return keys;
}

/**
 * Encrypt a sensitive value. Returns "vault:base64..."
 */
function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  var k = loadKeys();
  return VAULT_PREFIX + encrypt(String(plaintext), k);
}

/**
 * Decrypt a vault value. Returns plaintext.
 * Tries current keys first, falls back to legacy keys for old data.
 */
function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  var k = loadKeys();
  var payload = String(value).substring(VAULT_PREFIX.length);
  try {
    return decrypt(payload, k);
  } catch (_e) {
    // If current keys fail (e.g., data was encrypted with old ML-KEM-768 key),
    // try legacy key if available
    if (k._legacyPrivateKey) {
      return decrypt(payload, k._legacyPrivateKey);
    }
    throw _e;
  }
}

module.exports = { seal: seal, unseal: unseal };
