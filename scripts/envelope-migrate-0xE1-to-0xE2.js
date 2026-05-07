#!/usr/bin/env node
/**
 * envelope-migrate-0xE1-to-0xE2 — operator-run CLI for the
 * one-shot 0xE1 → 0xE2 envelope migration.
 *
 * Thin wrapper around lib/legacy-envelope-migrate.js. The actual
 * migration logic lives in that module so the boot-time auto-migrate
 * shim (Phase 2) can share it.
 *
 * What gets migrated:
 *   - data/ca.key.sealed, data/tls/privkey.pem.sealed,
 *     data/api-encrypt-keypair.sealed (sealed PEM/key files)
 *   - data/db.key.enc (vault-sealed DB-file symmetric key)
 *   - Every sealed DB column (vault:-prefixed strings in any column)
 *
 * Usage:
 *   node scripts/envelope-migrate-0xE1-to-0xE2.js          # dry-run (default)
 *   node scripts/envelope-migrate-0xE1-to-0xE2.js --apply  # actually migrate
 *
 * Crash safety: marker file at data/envelope-migration.marker.
 * Re-running on already-migrated data is a no-op (the module's
 * isAlreadyMigrated() probe checks the on-disk envelope magic byte
 * directly without touching lib/db, so the v1.9.x auto-regenerate
 * fallback can never trip).
 */
"use strict";

var args = process.argv.slice(2);
var DRY_RUN = !args.includes("--apply");
var VERBOSE = args.includes("--verbose") || args.includes("-v");

console.log("=== HermitStash envelope migration 0xE1 → 0xE2 (" + (DRY_RUN ? "DRY-RUN" : "APPLY") + ") ===\n");

(async function main() {
  var hermitstashVault = require("../lib/vault");
  await hermitstashVault.init();

  var migrate = require("../lib/legacy-envelope-migrate");
  var keys = JSON.parse(hermitstashVault.getKeysJson());

  var result = migrate.run({
    keys:    keys,
    dryRun:  DRY_RUN,
    verbose: VERBOSE,
    log:     console,
  });

  console.log("\n=== Summary ===");
  console.log("Mode:           " + (DRY_RUN ? "DRY-RUN" : "APPLY"));
  if (result.alreadyMigrated) {
    console.log("Status:         already migrated (envelope magic 0xE2 detected on db.key.enc)");
    console.log("Sealed files:   0");
    console.log("DB rows:        0");
    process.exit(0);
  }
  console.log("Sealed files:   " + result.filesMigrated + (DRY_RUN ? " WOULD migrate" : " migrated"));
  console.log("DB rows:        " + result.rowsMigrated + (DRY_RUN ? " WOULD migrate" : " migrated"));
  if (DRY_RUN) {
    console.log("\nRe-run with --apply to perform the migration.");
    console.log("The server must be stopped during --apply.");
  } else {
    console.log("\nMigration complete. You may now upgrade HermitStash to v1.9.18+ when ready.");
  }
  process.exit(0);
})().catch(function (err) {
  console.error("\n[fatal] " + (err && err.message ? err.message : String(err)));
  if (err && err.stack) console.error(err.stack);
  process.exit(1);
});
