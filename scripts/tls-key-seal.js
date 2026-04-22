#!/usr/bin/env node
/**
 * tls-key-seal.js — vault-seal data/tls/privkey.pem (v1.9.4).
 *
 * Migrates a plaintext TLS server private key into the vault-sealed format
 * (data/tls/privkey.pem.sealed). After success, set TLS_KEY_SEALED=required
 * in the server environment so plaintext is refused on subsequent boots.
 *
 * Usage:
 *   docker exec hermitstash node scripts/tls-key-seal.js
 *   docker exec hermitstash node scripts/tls-key-seal.js --reload
 *
 * --reload sends SIGHUP to the running server so the new sealed key is
 * picked up immediately via setSecureContext (no restart). Useful from
 * ACME renewal hooks. Without --reload, the running server keeps using
 * the in-memory copy until restart or the next watcher tick.
 *
 * To revert: scripts/tls-key-unseal.js
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
  var opts = { keepPlaintext: false, allowRoot: false, reload: false, help: false };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--keep-plaintext") opts.keepPlaintext = true;
    else if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--reload") opts.reload = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else { console.error("Unknown argument: " + a); process.exit(2); }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "tls-key-seal.js — vault-seal the TLS server private key (data/tls/privkey.pem)",
    "",
    "Options:",
    "  --keep-plaintext  Don't delete the plaintext after sealing",
    "  --reload          Send SIGHUP to the running server after sealing so",
    "                    the new sealed key is picked up immediately",
    "  --allow-root      Permit running as UID 0",
    "  -h, --help        This help",
    "",
    "Environment:",
    "  TLS_KEY           Override the path (default: data/tls/privkey.pem)",
    "",
    "After success:",
    "  1. Set TLS_KEY_SEALED=required in the server environment",
    "  2. If you didn't use --reload, restart the server (or wait up to 1",
    "     minute for the watcher to pick up the change)",
    "",
    "ACME / Let's Encrypt note:",
    "  When TLS_KEY_SEALED=required is active, the running server's cert",
    "  watcher auto-seals plaintext renewals as they appear. You don't need",
    "  to call this tool from your renewal hook — it'll happen on the next",
    "  poll within ~1 minute. Use --reload after this tool only when you",
    "  want immediate effect.",
    "",
    "To revert: node scripts/tls-key-unseal.js",
    "",
  ].join("\n"));
}

function findServerPid() {
  // PID file convention: data/hermitstash.pid (best effort — server may
  // not write one in all deployments, in which case --reload is a no-op
  // with a warning).
  var pidPath = path.join(C.DATA_DIR, "hermitstash.pid");
  if (!fs.existsSync(pidPath)) return null;
  try { return parseInt(fs.readFileSync(pidPath, "utf8").trim(), 10) || null; } catch { return null; }
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed.");
    process.exit(1);
  }

  if (!fs.existsSync(TLS_KEY)) {
    console.error("ERROR: " + TLS_KEY + " does not exist — nothing to seal.");
    process.exit(1);
  }
  if (fs.existsSync(TLS_KEY_SEALED)) {
    console.error("ERROR: " + TLS_KEY_SEALED + " already exists — refusing to overwrite.");
    process.exit(1);
  }
  if (fs.existsSync(TLS_KEY_SEALED + ".tmp") || fs.existsSync(TLS_KEY_SEALED + ".migration-pending")) {
    console.error("ERROR: stale .tmp or .migration-pending exists for the sealed file.");
    process.exit(1);
  }

  try {
    await vault.init();
  } catch (e) {
    console.error("FATAL: vault.init() failed: " + e.message);
    process.exit(1);
  }

  console.log("[tls-key-seal] Sealing " + TLS_KEY + " → " + TLS_KEY_SEALED);
  try {
    var result = pemSeal.sealPemFile(TLS_KEY, TLS_KEY_SEALED, { keepPlaintext: opts.keepPlaintext });
    console.log("[tls-key-seal] Done. Sealed file written; plaintext " +
      (result.plaintextDeleted ? "deleted" : "RETAINED"));
  } catch (e) {
    console.error("FATAL: " + e.message);
    process.exit(1);
  }

  if (opts.reload) {
    var pid = findServerPid();
    if (!pid) {
      console.warn("[tls-key-seal] --reload requested but no PID file at data/hermitstash.pid");
      console.warn("                Restart the server manually, or wait for the next watcher tick.");
    } else {
      try {
        process.kill(pid, "SIGHUP");
        console.log("[tls-key-seal] Sent SIGHUP to PID " + pid + " — server will reload TLS context");
      } catch (e) {
        console.error("[tls-key-seal] Failed to signal PID " + pid + ": " + e.message);
      }
    }
  }

  console.log("");
  console.log("======================================================================");
  console.log("  ✓ TLS key sealing complete.");
  console.log("");
  console.log("  Next steps:");
  console.log("    1. Set TLS_KEY_SEALED=required in the server environment.");
  console.log("    2. " + (opts.reload ? "(SIGHUP already sent — context reloaded)" :
        "Restart the server, or wait up to 1 minute for the watcher."));
  console.log("");
  console.log("  ACME / Let's Encrypt: with TLS_KEY_SEALED=required active,");
  console.log("  future renewals auto-seal on watch — no hook changes needed.");
  console.log("======================================================================");
})().catch(function (e) {
  console.error("FATAL: " + (e && e.message || String(e)));
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
