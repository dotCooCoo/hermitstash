#!/usr/bin/env node
/**
 * vault-passphrase-remove.js — reverse of vault-passphrase-setup.js.
 *
 * Unwraps data/vault.key.sealed back to a plaintext data/vault.key.
 * Required before downgrading to v1.8.x, which doesn't understand the
 * wrapped format.
 *
 * Run offline (stop the server first).
 *
 * Usage:
 *   node scripts/vault-passphrase-remove.js
 *
 * Uses the same passphrase source as the server / setup tool:
 *   VAULT_PASSPHRASE_FILE, VAULT_PASSPHRASE, or interactive stdin.
 *
 * On success: data/vault.key is written, data/vault.key.sealed is deleted.
 * The operator is instructed to unset VAULT_PASSPHRASE_MODE before restart.
 *
 * Crash safety: writes proceed through a .tmp file + unseal-pending marker +
 * atomic rename. Boot recovery in lib/vault.js handles crashes mid-operation.
 */
"use strict";

var fs = require("fs");
var http = require("http");

var C = require("../lib/constants");
var vaultWrap = require("../lib/vault-wrap");
var passphraseSource = require("../lib/passphrase-source");
var { sha3Hash } = require("../lib/crypto");

var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var PLAINTEXT_TMP_PATH = PLAINTEXT_PATH + ".tmp";
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var MARKER_PATH = C.PATHS.VAULT_KEY_UNSEAL_PENDING;
var MARKER_TMP_PATH = MARKER_PATH + ".tmp";

function parseArgs(argv) {
  var opts = {
    forceWithServerRunning: false,
    allowRoot: false,
    help: false,
  };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--force-with-server-running") opts.forceWithServerRunning = true;
    else if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else {
      console.error("Unknown argument: " + a);
      process.exit(2);
    }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "vault-passphrase-remove.js — unwrap vault.key.sealed back to plaintext vault.key",
    "",
    "Options:",
    "  --force-with-server-running   Skip the running-server check (dangerous)",
    "  --allow-root                  Run as UID 0 (discouraged)",
    "  -h, --help                    This help",
    "",
    "Passphrase sources (auto-detected):",
    "  VAULT_PASSPHRASE_FILE, VAULT_PASSPHRASE, or interactive stdin",
    "",
    "After success:",
    "  1. Unset VAULT_PASSPHRASE_MODE (or set to `disabled`) in the server env",
    "  2. Restart the server — it will use the plaintext vault.key",
    "",
  ].join("\n"));
}

function preflight(opts) {
  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed.");
    process.exit(1);
  }
  if (!fs.existsSync(SEALED_PATH)) {
    console.error("ERROR: " + SEALED_PATH + " does not exist — nothing to unwrap.");
    process.exit(1);
  }
  if (fs.existsSync(PLAINTEXT_PATH)) {
    console.error("ERROR: " + PLAINTEXT_PATH + " already exists. Refusing to overwrite.");
    console.error("  Delete it manually if you're sure you want to proceed.");
    process.exit(1);
  }
  if (fs.existsSync(PLAINTEXT_TMP_PATH)) {
    console.error("ERROR: stale " + PLAINTEXT_TMP_PATH + " exists. Delete it first.");
    process.exit(1);
  }
  if (fs.existsSync(MARKER_PATH)) {
    console.error("ERROR: unseal marker " + MARKER_PATH + " exists.");
    console.error("  A previous run crashed. Start the server briefly to run recovery, then retry.");
    process.exit(1);
  }

  if (!opts.forceWithServerRunning) {
    return new Promise(function (resolve) {
      var port = Number(process.env.PORT || 3000);
      var req = http.get({ host: "127.0.0.1", port: port, path: "/health", timeout: 1500 }, function (res) {
        res.resume();
        console.error("ERROR: a HermitStash server appears to be running on port " + port + ".");
        console.error("  Stop it first. Or pass --force-with-server-running.");
        process.exit(1);
      });
      req.on("error", function () { resolve(); });
      req.on("timeout", function () { req.destroy(); resolve(); });
    });
  }
  return Promise.resolve();
}

async function acquirePassphrase() {
  var kind = passphraseSource.sourceKind();
  if (kind === "file" || kind === "env") {
    console.log("[remove] Passphrase source: " + kind);
    return await passphraseSource.getPassphrase();
  }
  if (kind !== "stdin") {
    throw new Error("No usable passphrase source");
  }
  if (!process.stdin.isTTY) {
    console.error("ERROR: interactive stdin source requires a TTY.");
    process.exit(1);
  }
  console.log("");
  console.log("Unsealing vault.key.sealed — you'll need the current passphrase.");
  return await passphraseSource.fromStdin("Current vault passphrase: ");
}

async function execute(passphrase) {
  console.log("[remove] Reading " + SEALED_PATH + "...");
  var sealedBytes = fs.readFileSync(SEALED_PATH);

  console.log("[remove] Unwrapping (this may take ~1 second)...");
  var plaintextBytes;
  try {
    plaintextBytes = await vaultWrap.unwrap(sealedBytes, passphrase);
  } catch (e) {
    console.error("ERROR: " + e.message);
    console.error("  The sealed file is unchanged. Verify you used the correct passphrase.");
    process.exit(1);
  }

  // Step 1: write plaintext.tmp + fsync
  fs.writeFileSync(PLAINTEXT_TMP_PATH, plaintextBytes, { mode: 0o600 });
  fsyncPath(PLAINTEXT_TMP_PATH);
  fsyncDataDir();

  // Step 2: round-trip sanity — re-read tmp, verify bytes match
  var verifyBytes = fs.readFileSync(PLAINTEXT_TMP_PATH);
  if (Buffer.compare(verifyBytes, plaintextBytes) !== 0) {
    fs.unlinkSync(PLAINTEXT_TMP_PATH);
    console.error("ERROR: plaintext.tmp re-read differs from in-memory bytes.");
    console.error("  Filesystem may be faulty. vault.key.sealed is UNCHANGED.");
    process.exit(1);
  }

  // Step 3: write unseal-pending marker
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    // For the unseal path, the marker's sealedSha3 refers to the PLAINTEXT
    // target. The recoverFromMarker() call in vault.js is generic over
    // target/other; it hashes whatever targetFilePath points at.
    sealedSha3: sha3Hash(plaintextBytes),
  };
  fs.writeFileSync(MARKER_TMP_PATH, JSON.stringify(marker), { mode: 0o600 });
  fsyncPath(MARKER_TMP_PATH);
  fs.renameSync(MARKER_TMP_PATH, MARKER_PATH);
  fsyncDataDir();

  // Step 4: atomic rename plaintext into place
  fs.renameSync(PLAINTEXT_TMP_PATH, PLAINTEXT_PATH);
  fsyncDataDir();

  // Step 5: delete sealed file
  fs.unlinkSync(SEALED_PATH);
  fsyncDataDir();

  // Step 6: delete marker
  fs.unlinkSync(MARKER_PATH);
  fsyncDataDir();
}

function fsyncPath(p) {
  try {
    var fd = fs.openSync(p, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort */ }
}

function fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort */ }
}

function printSuccess() {
  console.log("");
  console.log("======================================================================");
  console.log("  ✓ Unsealing complete.");
  console.log("");
  console.log("    " + SEALED_PATH + " — deleted");
  console.log("    " + PLAINTEXT_PATH + " — active (plaintext, filesystem-protected)");
  console.log("");
  console.log("  Remember to unset VAULT_PASSPHRASE_MODE (or set to `disabled`)");
  console.log("  before restarting the server — otherwise boot will abort because");
  console.log("  plaintext + required is a config mismatch.");
  console.log("======================================================================");
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  try {
    await preflight(opts);
    var passphrase = await acquirePassphrase();
    await execute(passphrase);
    printSuccess();
  } catch (e) {
    console.error("FATAL: " + (e && e.message || String(e)));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
})();
