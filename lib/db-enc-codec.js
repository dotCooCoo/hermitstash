/**
 * db.enc envelope codec — side-effect-free.
 *
 * The encrypted database file (hermitstash.db.enc) is XChaCha20-Poly1305 AEAD
 * with its tag bound to the data directory via b.db._dbEncAad(dir). b.vaultRotate
 * rotate re-encrypts it AAD-bound (and blamejs's own db.js writes it the same way),
 * so a rotated db.enc is unreadable by a plain decrypt — without the AAD-first read
 * the server was unbootable after any vault-key rotation.
 *
 * This module holds the read/write codec with NO module-init side effects, so the
 * rotation E2E test (which builds fixture data dirs) can import the exact production
 * decrypt path without pulling in lib/db.js's heavy init (which opens the real DB).
 */
var b = require("./vendor/blamejs");

// Decrypt a db.enc envelope: try the dataDir-bound AAD first, then fall back to an
// un-bound decrypt for an existing pre-AAD file or a portable backup restored
// across installs without the dataDir binding.
function decryptDbEnc(packed, key, dir) {
  var aad = b.db._dbEncAad(dir);
  try { return b.crypto.decryptPacked(packed, key, aad); }
  catch (_e) { return b.crypto.decryptPacked(packed, key); }
}

// Encrypt the live db.enc AAD-bound to the data directory (swap-protection;
// matches what b.vaultRotate.rotate writes). Backups are encrypted WITHOUT this
// AAD so they stay portable across installs — see db.js snapshotEncryptedDb.
function encryptDbEnc(plain, key, dir) {
  return b.crypto.encryptPacked(plain, key, b.db._dbEncAad(dir));
}

module.exports = { decryptDbEnc: decryptDbEnc, encryptDbEnc: encryptDbEnc };
