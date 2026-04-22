#!/usr/bin/env node
/**
 * ca-key-seal.js — vault-seal data/ca.key (v1.9.4).
 *
 * Migrates a plaintext mTLS CA private key into the vault-sealed format
 * (data/ca.key.sealed). After success, set CA_KEY_SEALED=required in the
 * server environment so plaintext is refused on subsequent boots.
 *
 * Usage:
 *   docker exec hermitstash node scripts/ca-key-seal.js
 *
 * Run online OR offline — the CA key is only read during cert issuance/
 * revocation, so sealing it while the server is running is safe (the
 * existing in-memory CA usage continues; new cert ops after this script
 * runs will pick up the sealed file via the dispatch).
 *
 * To revert: scripts/ca-key-unseal.js
 *
 * ⚠ Loss of the vault key = loss of the CA. The CA becomes downstream of
 *   the vault key after sealing. If the vault is unrecoverable, every
 *   existing client cert becomes invalid and users must re-enroll.
 */
"use strict";

var fs = require("fs");
var C = require("../lib/constants");
var pemSeal = require("../lib/pem-seal");
var vault = require("../lib/vault");

var CA_KEY_PATH = C.PATHS.CA_KEY;
var CA_KEY_SEALED_PATH = C.PATHS.CA_KEY_SEALED;

function parseArgs(argv) {
  var opts = { keepPlaintext: false, allowRoot: false, help: false };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--keep-plaintext") opts.keepPlaintext = true;
    else if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else { console.error("Unknown argument: " + a); process.exit(2); }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "ca-key-seal.js — vault-seal the mTLS CA private key (data/ca.key)",
    "",
    "Options:",
    "  --keep-plaintext  Don't delete data/ca.key after sealing (rollback window)",
    "  --allow-root      Permit running as UID 0",
    "  -h, --help        This help",
    "",
    "After success:",
    "  1. Set CA_KEY_SEALED=required in the server environment",
    "  2. Restart the server (or just leave it running — the next cert op",
    "     loads the sealed file via the dispatch)",
    "  3. Confirm with: ls data/ca.key.sealed (and absence of data/ca.key)",
    "",
    "To revert: node scripts/ca-key-unseal.js",
    "",
    "⚠ Loss of the vault key = loss of the CA. Sealing makes ca.key downstream",
    "  of vault.key. If the vault is unrecoverable, every existing client cert",
    "  becomes invalid; users must re-enroll via the enrollment-code flow.",
    "",
  ].join("\n"));
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed.");
    process.exit(1);
  }

  if (!fs.existsSync(CA_KEY_PATH)) {
    console.error("ERROR: " + CA_KEY_PATH + " does not exist — nothing to seal.");
    console.error("  This tool migrates an existing plaintext CA key to the sealed format.");
    process.exit(1);
  }
  if (fs.existsSync(CA_KEY_SEALED_PATH)) {
    console.error("ERROR: " + CA_KEY_SEALED_PATH + " already exists — refusing to overwrite.");
    process.exit(1);
  }
  if (fs.existsSync(CA_KEY_SEALED_PATH + ".tmp") || fs.existsSync(CA_KEY_SEALED_PATH + ".migration-pending")) {
    console.error("ERROR: stale .tmp or .migration-pending exists for the sealed file.");
    console.error("  A previous attempt crashed mid-operation. Delete the stale files manually,");
    console.error("  then re-run.");
    process.exit(1);
  }

  // Vault must be initialized so vault.seal() works
  try {
    await vault.init();
  } catch (e) {
    console.error("FATAL: vault.init() failed: " + e.message);
    process.exit(1);
  }

  console.log("[ca-key-seal] Sealing " + CA_KEY_PATH + " → " + CA_KEY_SEALED_PATH);
  try {
    var result = pemSeal.sealPemFile(CA_KEY_PATH, CA_KEY_SEALED_PATH, { keepPlaintext: opts.keepPlaintext });
    console.log("[ca-key-seal] Done. Sealed file written; plaintext " +
      (result.plaintextDeleted ? "deleted" : "RETAINED (--keep-plaintext)"));
  } catch (e) {
    console.error("FATAL: " + e.message);
    process.exit(1);
  }

  console.log("");
  console.log("======================================================================");
  console.log("  ✓ CA key sealing complete.");
  console.log("");
  console.log("  Next steps:");
  console.log("    1. Set CA_KEY_SEALED=required in the server environment.");
  console.log("    2. Restart the server (or leave running — the dispatch picks");
  console.log("       up the sealed file on the next cert operation).");
  console.log("");
  console.log("  To revert: node scripts/ca-key-unseal.js");
  console.log("======================================================================");
})().catch(function (e) {
  console.error("FATAL: " + (e && e.message || String(e)));
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
