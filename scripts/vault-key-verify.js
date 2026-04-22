#!/usr/bin/env node
/**
 * vault-key-verify.js — read-only verifier for the live vault key (v1.9.3).
 *
 * Samples sealed columns across every FIELD_SCHEMA table and confirms they
 * decrypt with the currently-configured vault key. Does not mutate anything;
 * safe to run against a running server (it opens its own read-only handle on
 * a temp copy of the decrypted DB).
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
var path = require("path");
var { DatabaseSync } = require("node:sqlite");

var C = require("../lib/constants");
var cryptoLib = require("../lib/crypto");
var passphraseSource = require("../lib/passphrase-source");
var vaultWrap = require("../lib/vault-wrap");
var vaultRotate = require("../lib/vault-rotate");

var DATA_DIR = C.DATA_DIR;
var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var DB_ENC_PATH = C.PATHS.DB_ENC;
var DB_KEY_ENC_PATH = C.PATHS.DB_KEY_ENC;
var VAULT_PREFIX = C.VAULT_PREFIX;

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
    "Safe to run against a running server. The tool opens its own read-only",
    "handle on a temp copy of the decrypted DB; the live hermitstash.db.enc",
    "is never modified.",
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
    return JSON.parse(fs.readFileSync(PLAINTEXT_PATH, "utf8"));
  }
  var sealedBytes = fs.readFileSync(SEALED_PATH);
  var pw;
  try {
    pw = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
  } catch (e) {
    console.error("ERROR: " + e.message);
    process.exit(2);
  }
  var plainBuf;
  try {
    plainBuf = await vaultWrap.unwrap(sealedBytes, pw);
  } catch (e) {
    console.error("ERROR: passphrase rejected — " + e.message);
    process.exit(1);
  }
  return JSON.parse(plainBuf.toString("utf8"));
}

function decryptDbToTemp(keys) {
  if (!fs.existsSync(DB_ENC_PATH) || !fs.existsSync(DB_KEY_ENC_PATH)) {
    console.log("[verify] no encrypted DB present — nothing to sample");
    process.exit(0);
  }
  var sealedDbKey = fs.readFileSync(DB_KEY_ENC_PATH, "utf8").trim();
  if (sealedDbKey.indexOf(VAULT_PREFIX) !== 0) {
    console.error("ERROR: db.key.enc is not vault-sealed");
    process.exit(1);
  }
  var dbKey;
  try {
    dbKey = Buffer.from(
      cryptoLib.decrypt(sealedDbKey.substring(VAULT_PREFIX.length), keys),
      "base64"
    );
  } catch (e) {
    console.error("ERROR: db.key.enc cannot be unsealed with the current vault — " + e.message);
    console.error("  The DB file encryption key is not readable by this vault keypair.");
    console.error("  Either the vault key is wrong, or db.key.enc is corrupted.");
    process.exit(1);
  }
  var packed = fs.readFileSync(DB_ENC_PATH);
  var plainBytes;
  try {
    plainBytes = cryptoLib.decryptPacked(packed, dbKey);
  } catch (e) {
    console.error("ERROR: hermitstash.db.enc cannot be decrypted with the unsealed dbKey — " + e.message);
    process.exit(1);
  }
  var tmpPath = path.join(path.dirname(DATA_DIR), ".verify-" + Date.now() + ".db");
  fs.writeFileSync(tmpPath, plainBytes);
  return tmpPath;
}

function cleanupTemp(tmpPath) {
  try { fs.unlinkSync(tmpPath); } catch { /* best-effort */ }
  try { fs.unlinkSync(tmpPath + "-wal"); } catch { /* best-effort */ }
  try { fs.unlinkSync(tmpPath + "-shm"); } catch { /* best-effort */ }
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
    result = vaultRotate.verifyRotation(keys, db, {});
  } finally {
    db.close();
    cleanupTemp(tmpPath);
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
      console.error("  " + fail.table + "." + fail.column + " _id=" + fail._id + " → " + fail.error);
    }
    if (result.failures.length > max) {
      console.error("  ... and " + (result.failures.length - max) + " more failure(s)");
    }
    process.exit(1);
  }

  console.log("");
  console.log("✓ All sampled sealed columns decrypt cleanly with the current vault key.");
})().catch(function (e) {
  console.error("FATAL: " + (e && e.message || String(e)));
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
