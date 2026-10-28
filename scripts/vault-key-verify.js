#!/usr/bin/env node
/**
 * vault-key-verify.js — read-only verifier for the live vault key (v1.9.3).
 *
 * Samples sealed columns across every FIELD_SCHEMA table and confirms they
 * decrypt with the currently-configured vault key. Does not mutate anything;
 * safe to run against a running server (it opens its own handle on an
 * owner-only temp copy of the decrypted DB, written to HERMITSTASH_TMPDIR,
 * /dev/shm or the OS temp directory).
 *
 * Primary use cases:
 *   - After running scripts/vault-key-rotate.js, gain confidence that the
 *     rotated data is decryptable without having to restart the server
 *   - Periodic health check for disk corruption
 *   - Pre-upgrade sanity check
 *
 * Exit code:
 *   0  all sampled rows decrypted cleanly
 *   1  one or more failures (details printed)
 *   2  CLI argument error or environment problem
 */
"use strict";

var fs = require("fs");
var { DatabaseSync } = require("node:sqlite");

var C = require("../lib/constants");
var b = require("../lib/vendor/blamejs");
var safeLog = require("../lib/safe-log");
var passphraseSource = require("../lib/passphrase-source");
var fieldCrypto = require("../lib/field-crypto");
var liveDb = require("./lib/live-db");

// Populate b.cryptoField with HS's FIELD_SCHEMA before any
// b.vaultRotate call — its schema walker reads from b.cryptoField.
fieldCrypto.registerWithBlamejs();

var DATA_DIR = C.DATA_DIR;
var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;

function parseArgs(argv) {
  var opts = { help: false };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else {
      console.error("Unknown argument: " + a);
      process.exit(2);
    }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "vault-key-verify.js — verify every sealed DB column decrypts with the current vault key",
    "",
    "Usage:",
    "  node scripts/vault-key-verify.js",
    "",
    "Passphrase sources (wrapped mode only, same conventions as the server):",
    "  VAULT_PASSPHRASE              — direct env",
    "  VAULT_PASSPHRASE_FILE         — read from a file",
    "  stdin (if TTY)                — interactive prompt",
    "",
    "Exit codes:",
    "  0   all sampled rows decrypt cleanly",
    "  1   one or more sampled rows failed to decrypt",
    "  2   CLI / environment error",
    "",
    "Safe to run against a running server. The tool opens its own handle on",
    "a temporary owner-only copy of the decrypted DB in HERMITSTASH_TMPDIR,",
    "/dev/shm or the OS temp directory, and deletes it afterwards; the live",
    "hermitstash.db.enc is never modified.",
    "Run it with the same HERMITSTASH_DATA_DIR the server uses: the database",
    "file is bound to that path.",
    "",
  ].join("\n"));
}

function detectMode() {
  if (fs.existsSync(SEALED_PATH)) return "wrapped";
  if (fs.existsSync(PLAINTEXT_PATH)) return "plaintext";
  console.error("ERROR: no vault.key or vault.key.sealed in " + DATA_DIR + ".");
  console.error("  Nothing to verify.");
  process.exit(2);
}

async function loadKeys(mode) {
  if (mode === "plaintext") {
    // Guard the parse: a SyntaxError of the plaintext keypair echoes private-key
    // bytes, which the top-level catch would write via e.message/e.stack (CWE-532).
    try { return b.safeJson.parse(fs.readFileSync(PLAINTEXT_PATH, "utf8"), { maxBytes: b.constants.BYTES.mib(1) }); }
    catch (_e) { console.error("FATAL: vault.key is not valid JSON (parser detail suppressed to avoid logging key material). Restore from backup."); process.exit(1); }
  }
  var sealedBytes = fs.readFileSync(SEALED_PATH);
  var pw;
  try {
    pw = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
  } catch (e) {
    console.error("ERROR: " + safeLog.scrub(e.message));
    process.exit(2);
  }
  var plainBuf;
  try {
    plainBuf = await b.vaultWrap.unwrap(sealedBytes, pw);
  } catch (e) {
    if (e && e.code === "vault-wrap/passphrase-rejected") {
      console.error("ERROR: passphrase rejected: " + safeLog.scrub(e.message));
    } else {
      console.error("ERROR: vault.key.sealed could not be unwrapped: " + safeLog.scrub(e.message));
      console.error("  The passphrase was not checked.");
    }
    process.exit(1);
  }
  try { return b.safeJson.parse(plainBuf.toString("utf8"), { maxBytes: b.constants.BYTES.mib(1) }); }
  catch (_e) { console.error("FATAL: unsealed vault key is not valid JSON (parser detail suppressed to avoid logging key material). The sealed file may be corrupt."); process.exit(1); }
}

function decryptDbToTemp(keys) {
  if (!liveDb.present(DATA_DIR)) {
    console.log("[verify] no encrypted DB present — nothing to sample");
    process.exit(0);
  }
  var dbKey;
  try {
    dbKey = liveDb.unsealDbKey(DATA_DIR, keys);
  } catch (e) {
    console.error("ERROR: " + safeLog.scrub(e.message));
    if (e && e.code === "live-db/db-key-unsealable") {
      console.error("  The vault key does not match this db.key.enc, or db.key.enc is damaged.");
    }
    process.exit(1);
  }
  var plainBytes;
  try {
    plainBytes = liveDb.decrypt(DATA_DIR, dbKey);
  } catch (e) {
    console.error("ERROR: " + safeLog.scrub(e.message));
    console.error("  Run this tool with the same HERMITSTASH_DATA_DIR the server uses.");
    process.exit(1);
  }
  return liveDb.writeTempDb(plainBytes, "verify");
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  var mode = detectMode();
  console.log("[verify] Detected mode: " + mode);
  var keys = await loadKeys(mode);
  console.log("[verify] Vault keypair loaded successfully");

  var tmpPath = decryptDbToTemp(keys);
  var db = new DatabaseSync(tmpPath);
  var result;
  try {
    result = b.vaultRotate.verify({ keys: keys, db: db });
  } finally {
    db.close();
    liveDb.removeTempDb(tmpPath);
  }

  // Print per-table verification summary
  console.log("");
  console.log("Verification results by table:");
  for (var i = 0; i < result.passed.length; i++) {
    var p = result.passed[i];
    console.log("  " + p.table + ": " + p.verified + "/" + p.sampled + " sampled rows verified");
  }

  if (result.failures.length > 0) {
    console.log("");
    console.error("FAILURES (" + result.failures.length + "):");
    var max = Math.min(result.failures.length, 10);
    for (var f = 0; f < max; f++) {
      var fail = result.failures[f];
      console.error("  " + fail.table + "." + fail.column + " _id=" + fail._id + " → " + safeLog.scrub(fail.error));
    }
    if (result.failures.length > max) {
      console.error("  ... and " + (result.failures.length - max) + " more failure(s)");
    }
    process.exit(1);
  }

  console.log("");
  console.log("✓ All sampled sealed columns decrypt cleanly with the current vault key.");
})().catch(function (e) {
  // Backstop for unexpected errors. This tool reads sealed key material, so never
  // dump a raw stack (CWE-532); scrub any credential-shaped substring from the
  // message and surface only the non-secret error code.
  console.error("FATAL: " + safeLog.scrub(e && e.message || String(e)) + " (code: " + safeLog.code(e) + ")");
  process.exit(1);
});
