/**
 * Vault — encrypts/decrypts sensitive values using envelope format.
 *
 * Suite: ML-KEM-1024 + P-384 ECDH hybrid / XChaCha20-Poly1305 / SHAKE256
 * Keys are stored in data/vault.key (auto-generated on first run).
 * Encrypted values are prefixed with "vault:" so they can be detected.
 *
 * No backwards compatibility — only ML-KEM-1024 + P-384 hybrid keys accepted.
 * Legacy ML-KEM-768 keys must be migrated before upgrading.
 */
var fs = require("fs");
var { generateEncryptionKeyPair, encrypt, decrypt } = require("./crypto");
var C = require("./constants");
var VAULT_PREFIX = C.VAULT_PREFIX;

var keyPath = C.PATHS.VAULT_KEY;
var keys = null;

function loadKeys() {
  if (keys) return keys;

  if (fs.existsSync(keyPath)) {
    try {
      var loaded = JSON.parse(fs.readFileSync(keyPath, "utf8"));
      // Require hybrid key format (ML-KEM-1024 + P-384)
      if (!loaded.ecPublicKey || !loaded.ecPrivateKey) {
        console.error("FATAL: Vault key file is a legacy ML-KEM-768 format.");
        console.error("This version requires ML-KEM-1024 + P-384 hybrid keys.");
        console.error("Run the migration tool to upgrade your vault keys, then restart.");
        process.exit(1);
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
  if (!fs.existsSync(C.DATA_DIR)) fs.mkdirSync(C.DATA_DIR, { recursive: true });
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
 */
function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  var k = loadKeys();
  var payload = String(value).substring(VAULT_PREFIX.length);
  return decrypt(payload, k);
}

module.exports = { seal: seal, unseal: unseal };
