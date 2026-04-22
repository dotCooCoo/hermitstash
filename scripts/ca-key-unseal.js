#!/usr/bin/env node
/**
 * ca-key-unseal.js — reverse direction of ca-key-seal.js (v1.9.4).
 *
 * Unwraps data/ca.key.sealed back to data/ca.key (plaintext PEM).
 *
 * Used for:
 *   - Reverting a sealing decision
 *   - Pre-downgrade to v1.9.3 or earlier (which doesn't understand the
 *     .sealed format)
 *   - Troubleshooting CA-key-load failures
 *
 * Usage:
 *   docker exec hermitstash node scripts/ca-key-unseal.js
 *
 * After success, unset CA_KEY_SEALED (or set =disabled) before the next
 * cert operation. Otherwise dispatch refuses with "config mismatch".
 */
"use strict";

var fs = require("fs");
var C = require("../lib/constants");
var pemSeal = require("../lib/pem-seal");
var vault = require("../lib/vault");

var CA_KEY_PATH = C.PATHS.CA_KEY;
var CA_KEY_SEALED_PATH = C.PATHS.CA_KEY_SEALED;

function parseArgs(argv) {
  var opts = { allowRoot: false, help: false };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else { console.error("Unknown argument: " + a); process.exit(2); }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "ca-key-unseal.js — unwrap data/ca.key.sealed back to plaintext data/ca.key",
    "",
    "Options:",
    "  --allow-root  Permit running as UID 0",
    "  -h, --help    This help",
    "",
    "After success:",
    "  1. Unset CA_KEY_SEALED (or set =disabled)",
    "  2. Restart the server",
    "",
    "If you intend to downgrade to v1.9.3 or earlier, run this BEFORE the",
    "downgrade — older versions don't understand .sealed files.",
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

  if (!fs.existsSync(CA_KEY_SEALED_PATH)) {
    console.error("ERROR: " + CA_KEY_SEALED_PATH + " does not exist — nothing to unseal.");
    process.exit(1);
  }
  if (fs.existsSync(CA_KEY_PATH)) {
    console.error("ERROR: " + CA_KEY_PATH + " already exists — refusing to overwrite.");
    console.error("  Delete or rename it first if you really want to unseal over it.");
    process.exit(1);
  }
  if (fs.existsSync(CA_KEY_PATH + ".tmp") || fs.existsSync(CA_KEY_PATH + ".unseal-pending")) {
    console.error("ERROR: stale .tmp or .unseal-pending exists for the plaintext file.");
    process.exit(1);
  }

  try {
    await vault.init();
  } catch (e) {
    console.error("FATAL: vault.init() failed: " + e.message);
    process.exit(1);
  }

  console.log("[ca-key-unseal] Unsealing " + CA_KEY_SEALED_PATH + " → " + CA_KEY_PATH);
  try {
    pemSeal.unsealPemFile(CA_KEY_SEALED_PATH, CA_KEY_PATH);
    console.log("[ca-key-unseal] Done. Plaintext written; sealed file removed.");
  } catch (e) {
    console.error("FATAL: " + e.message);
    process.exit(1);
  }

  console.log("");
  console.log("======================================================================");
  console.log("  ✓ CA key unsealing complete.");
  console.log("");
  console.log("  Next steps:");
  console.log("    1. Unset CA_KEY_SEALED (or set =disabled).");
  console.log("    2. Restart the server.");
  console.log("======================================================================");
})().catch(function (e) {
  console.error("FATAL: " + (e && e.message || String(e)));
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
