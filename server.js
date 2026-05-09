/**
 * HermitStash — bootstrap wrapper.
 *
 * This tiny entry point exists so the vault can be initialized asynchronously
 * BEFORE any module that transitively calls vault.seal/unseal at require-time
 * (notably lib/db.js, which reads db.key.enc via vault.unseal when its module
 * initializer runs).
 *
 * In plaintext mode (VAULT_PASSPHRASE_MODE unset or =disabled), vault.init()
 * resolves via a synchronous file read — the await is essentially free.
 * In wrapped mode (VAULT_PASSPHRASE_MODE=required), vault.init() awaits the
 * passphrase unwrap (Argon2id is async) before allowing server-main to load.
 *
 * All real server logic lives in server-main.js. Any command-line tooling
 * that needs the server's modules should follow the same pattern: await
 * vault.init() first, then require the code that depends on it.
 */
"use strict";

// Node version guard — fail fast with a clear message on <24.8.
// HermitStash needs Node 24.8+ for OpenSSL 3.5 PQC bindings (ML-KEM-1024,
// SLH-DSA-SHAKE-256f, ML-DSA-87) and Node 24.4+ for the vendored
// blamejs framework (which also uses crypto.argon2 and other 24.x
// additions). The 24.8 floor covers both. Operators bypassing
// deploy/install.sh + Dockerfile (e.g. running directly under a
// system Node) get this error instead of cryptic blamejs / OpenSSL
// failures deep in the require chain.
(function checkNodeVersion() {
  var parts = process.versions.node.split(".").map(Number);
  var major = parts[0], minor = parts[1];
  if (major < 24 || (major === 24 && minor < 8)) {
    console.error(
      "FATAL: HermitStash requires Node.js 24.8 or newer (found v" + process.versions.node + ").\n" +
      "  HermitStash uses OpenSSL 3.5 post-quantum bindings (ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87)\n" +
      "  that landed in Node 24.x. The vendored blamejs framework requires 24.4+; HermitStash's own\n" +
      "  PQC + crypto.argon2 usage requires 24.8+. Upgrade Node and re-run.\n" +
      "  Install: https://nodejs.org/  |  Linux/systemd: deploy/install.sh"
    );
    process.exit(1);
  }
})();

(async function boot() {
  var vault;
  try {
    vault = require("./lib/vault");
  } catch (e) {
    console.error("FATAL: cannot load lib/vault: " + (e && e.message));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
  try {
    await vault.init();
  } catch (e) {
    // vault.init() itself calls process.exit(1) on fatal errors and prints a
    // detailed message. A throw reaching here means an unexpected exception
    // bubbled out — fail loudly.
    console.error("FATAL: unexpected error during vault init: " + (e && e.message));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
  // Vault is now either loaded (plaintext) or unsealed (wrapped). The module
  // cache for lib/vault holds the plaintext keys, so every downstream
  // vault.seal/unseal from here on is synchronous and safe.

  // Boot-time auto-migrate (Phase 2): if the on-disk envelope is still
  // 0xE1, convert it to 0xE2 before any subsequent module calls
  // vault.unseal (which post-Phase-2 refuses 0xE1). Idempotent — the
  // module's isAlreadyMigrated() probe short-circuits when data is
  // already 0xE2. Logs progress with [envelope-migrate] lines so an
  // operator watching `docker logs` sees the conversion happen on
  // first boot after the v1.9.17 → v1.9.18 upgrade. Subsequent boots
  // are a no-op.
  try {
    var migrate = require("./lib/legacy-envelope-migrate");
    if (!migrate.isAlreadyMigrated()) {
      console.log("[envelope-migrate] detected 0xE1 sealed data — converting to 0xE2 before server start...");
      var keys = JSON.parse(vault.getKeysJson());
      var result = migrate.run({
        keys: keys,
        log:  { info: function (m) { console.log("[envelope-migrate] " + m); }, warn: console.warn, error: console.error },
      });
      console.log("[envelope-migrate] complete — " + result.filesMigrated + " sealed files + " + result.rowsMigrated + " DB rows migrated to 0xE2");
    }
  } catch (e) {
    console.error("FATAL: envelope migration failed: " + (e && e.message));
    if (e && e.stack) console.error(e.stack);
    console.error("Restore data/ from a pre-upgrade backup, then either re-run the upgrade or run scripts/envelope-migrate-0xE1-to-0xE2.js manually.");
    process.exit(1);
  }

  require("./server-main");
})();
