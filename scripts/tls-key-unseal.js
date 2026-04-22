#!/usr/bin/env node
/**
 * tls-key-unseal.js — reverse direction of tls-key-seal.js (v1.9.4).
 *
 * Unwraps data/tls/privkey.pem.sealed back to data/tls/privkey.pem.
 *
 * Usage:
 *   docker exec hermitstash node scripts/tls-key-unseal.js
 *
 * After success, unset TLS_KEY_SEALED (or set =disabled) before the next
 * boot. Otherwise dispatch refuses with "config mismatch".
 */
"use strict";

var fs = require("fs");
var path = require("path");
var C = require("../lib/constants");
var pemSeal = require("../lib/pem-seal");
var vault = require("../lib/vault");

var TLS_KEY = process.env.TLS_KEY || path.join(C.PATHS.TLS_DIR, "privkey.pem");
var TLS_KEY_SEALED = TLS_KEY + ".sealed";

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
    "tls-key-unseal.js — unwrap data/tls/privkey.pem.sealed back to plaintext",
    "",
    "Options:",
    "  --allow-root  Permit running as UID 0",
    "  -h, --help    This help",
    "",
    "After success:",
    "  1. Unset TLS_KEY_SEALED (or set =disabled)",
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

  if (!fs.existsSync(TLS_KEY_SEALED)) {
    console.error("ERROR: " + TLS_KEY_SEALED + " does not exist — nothing to unseal.");
    process.exit(1);
  }
  if (fs.existsSync(TLS_KEY)) {
    console.error("ERROR: " + TLS_KEY + " already exists — refusing to overwrite.");
    process.exit(1);
  }
  if (fs.existsSync(TLS_KEY + ".tmp") || fs.existsSync(TLS_KEY + ".unseal-pending")) {
    console.error("ERROR: stale .tmp or .unseal-pending exists for the plaintext file.");
    process.exit(1);
  }

  try {
    await vault.init();
  } catch (e) {
    console.error("FATAL: vault.init() failed: " + e.message);
    process.exit(1);
  }

  console.log("[tls-key-unseal] Unsealing " + TLS_KEY_SEALED + " → " + TLS_KEY);
  try {
    pemSeal.unsealPemFile(TLS_KEY_SEALED, TLS_KEY);
    console.log("[tls-key-unseal] Done. Plaintext written; sealed file removed.");
  } catch (e) {
    console.error("FATAL: " + e.message);
    process.exit(1);
  }

  console.log("");
  console.log("======================================================================");
  console.log("  ✓ TLS key unsealing complete.");
  console.log("");
  console.log("  Next steps:");
  console.log("    1. Unset TLS_KEY_SEALED (or set =disabled).");
  console.log("    2. Restart the server.");
  console.log("======================================================================");
})().catch(function (e) {
  console.error("FATAL: " + (e && e.message || String(e)));
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
