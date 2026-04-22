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
  require("./server-main");
})();
