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
