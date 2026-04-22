#!/usr/bin/env node
/**
 * vault-passphrase-setup.js — migrate data/vault.key to the passphrase-wrapped
 * vault.key.sealed format.
 *
 * Run offline (stop the server first).
 *
 * Usage:
 *   node scripts/vault-passphrase-setup.js               # interactive or env/file-sourced
 *   node scripts/vault-passphrase-setup.js --keep-plaintext
 *       Do NOT delete the plaintext backup after successful wrap. Leaves
 *       data/vault.key in place. The boot state machine will then refuse to
 *       start until the operator manually deletes one of the two files —
 *       this flag is a manual rollback window for cautious operators.
 *   node scripts/vault-passphrase-setup.js --force-with-server-running
 *       Skip the "is the server already running?" check. Only use if you're
 *       sure you know what you're doing.
 *   node scripts/vault-passphrase-setup.js --allow-root
 *       Run even if invoked as UID 0.
 *
 * Passphrase sources (priority order, same as server):
 *   VAULT_PASSPHRASE_FILE=/path/to/secret     (Docker secrets idiom — preferred)
 *   VAULT_PASSPHRASE=<passphrase>             (env var)
 *   (interactive stdin prompt if no env source)
 *
 * On success: data/vault.key.sealed is written, data/vault.key is deleted
 * (unless --keep-plaintext), and the operator is instructed to set
 * VAULT_PASSPHRASE_MODE=required in the server's environment.
 *
 * Crash safety: writes proceed through a .tmp file + migration marker +
 * atomic rename. A crash at any step is recoverable via the marker logic
 * in lib/vault.js.
 */
"use strict";

var fs = require("fs");
var path = require("path");
var os = require("os");
var http = require("http");

var C = require("../lib/constants");
var vaultWrap = require("../lib/vault-wrap");
var passphraseSource = require("../lib/passphrase-source");
var { sha3Hash } = require("../lib/crypto");

var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var MARKER_PATH = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var MARKER_TMP_PATH = MARKER_PATH + ".tmp";

// ---- CLI argument parsing ----
function parseArgs(argv) {
  var opts = {
    keepPlaintext: false,
    forceWithServerRunning: false,
    allowRoot: false,
    help: false,
  };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--keep-plaintext") opts.keepPlaintext = true;
    else if (a === "--force-with-server-running") opts.forceWithServerRunning = true;
    else if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else {
      console.error("Unknown argument: " + a);
      console.error("Run with --help for usage.");
      process.exit(2);
    }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "vault-passphrase-setup.js — migrate vault.key to wrapped format",
    "",
    "Options:",
    "  --keep-plaintext              Keep plaintext vault.key as backup (manual rollback)",
    "  --force-with-server-running   Skip the running-server check (dangerous)",
    "  --allow-root                  Run as UID 0 (discouraged)",
    "  -h, --help                    This help",
    "",
    "Passphrase sources (auto-detected, priority order):",
    "  VAULT_PASSPHRASE_FILE=/path/to/secret  (Docker secrets idiom, recommended)",
    "  VAULT_PASSPHRASE=<passphrase>          (env var)",
    "  (interactive stdin prompt if neither env source is set)",
    "",
    "After success:",
    "  1. Set VAULT_PASSPHRASE_MODE=required in your server environment",
    "  2. Ensure the same passphrase source is configured",
    "  3. Restart the server — it should unseal on boot",
    "",
  ].join("\n"));
}

// ---- Pre-flight checks ----
function preflight(opts) {
  // Root check
  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed anyway.");
    process.exit(1);
  }

  // Data dir must exist
  if (!fs.existsSync(C.DATA_DIR)) {
    console.error("ERROR: data directory does not exist: " + C.DATA_DIR);
    console.error("  Start the server once in plaintext mode to create it, or mkdir it manually.");
    process.exit(1);
  }

  // Plaintext vault.key must exist (source material)
  if (!fs.existsSync(PLAINTEXT_PATH)) {
    console.error("ERROR: " + PLAINTEXT_PATH + " does not exist — nothing to migrate.");
    console.error("  This tool migrates an existing plaintext vault key to the wrapped format.");
    console.error("  For a first-run wrapped install, set VAULT_PASSPHRASE_MODE=required and");
    console.error("  start the server directly; it will prompt for a passphrase and generate");
    console.error("  a wrapped key.");
    process.exit(1);
  }

  // Refuse if sealed already exists (ambiguous state)
  if (fs.existsSync(SEALED_PATH)) {
    console.error("ERROR: " + SEALED_PATH + " already exists.");
    console.error("  The vault appears to be already wrapped. Refusing to overwrite.");
    console.error("  If you want to re-wrap: use vault-passphrase-remove.js first, then re-run setup.");
    process.exit(1);
  }

  // Refuse if .tmp or marker files are present (previous crash — resolve first)
  if (fs.existsSync(SEALED_TMP_PATH)) {
    console.error("ERROR: stale " + SEALED_TMP_PATH + " exists.");
    console.error("  A previous setup crashed. Start the server briefly (or delete this file");
    console.error("  manually) — its boot cleanup will remove the orphan.");
    process.exit(1);
  }
  if (fs.existsSync(MARKER_PATH)) {
    console.error("ERROR: migration marker " + MARKER_PATH + " exists.");
    console.error("  A previous setup crashed. Start the server briefly to run recovery,");
    console.error("  then re-run setup.");
    process.exit(1);
  }

  // Best-effort: check if server is responding on localhost:3000
  if (!opts.forceWithServerRunning) {
    return new Promise(function (resolve) {
      var port = Number(process.env.PORT || 3000);
      var req = http.get({ host: "127.0.0.1", port: port, path: "/health", timeout: 1500 }, function (res) {
        res.resume();
        console.error("ERROR: a HermitStash server appears to be running on port " + port + ".");
        console.error("  Stop it first, then re-run. Or pass --force-with-server-running.");
        process.exit(1);
      });
      req.on("error", function () { resolve(); });
      req.on("timeout", function () { req.destroy(); resolve(); });
    });
  }
  return Promise.resolve();
}

// ---- Passphrase acquisition + confirmation ----
async function acquirePassphrase() {
  var kind = passphraseSource.sourceKind();
  if (kind === "file" || kind === "env") {
    // Non-interactive source: caller has pre-staged the passphrase.
    // Use it directly; no confirmation prompt — the source itself is the
    // commitment (operator has placed it in the right env or file).
    console.log("[setup] Passphrase source: " + kind);
    var pw = await passphraseSource.getPassphrase();
    // Warn but don't refuse if passphrase is short
    if (pw.length < 12) {
      console.warn("[setup] WARNING: passphrase is shorter than 12 bytes. Consider a longer one.");
    }
    return pw;
  }

  if (kind !== "stdin") {
    throw new Error("No usable passphrase source (" + kind + ")");
  }
  if (!process.stdin.isTTY) {
    console.error("ERROR: interactive stdin source requires a TTY (run with `docker run -it`).");
    process.exit(1);
  }
  // Interactive path — require typed confirmation of safe storage
  console.log("");
  console.log("======================================================================");
  console.log("  Vault passphrase — LOSS = LOSS OF ALL ENCRYPTED DATA");
  console.log("");
  console.log("  HermitStash has NO recovery mechanism. If you lose this passphrase,");
  console.log("  every file, every audit entry, every setting is unrecoverable.");
  console.log("");
  console.log("  Store it in a password manager or equivalent safe location BEFORE");
  console.log("  proceeding.");
  console.log("======================================================================");
  console.log("");

  var pw1 = await passphraseSource.fromStdin("Enter new passphrase: ");
  if (pw1.length < 12) {
    console.warn("[setup] Note: passphrase is shorter than 12 bytes. Continuing anyway.");
  }
  var pw2 = await passphraseSource.fromStdin("Confirm passphrase:   ");
  if (Buffer.compare(pw1, pw2) !== 0) {
    console.error("ERROR: passphrases do not match. Aborting.");
    process.exit(1);
  }

  // Require typed YES to confirm safe storage
  console.log("");
  console.log("Have you stored this passphrase in a password manager or equivalent");
  console.log("safe location? This operation will DELETE the plaintext data/vault.key");
  console.log("after the wrapped file is verified" + (process.argv.includes("--keep-plaintext") ? " (SKIPPED because --keep-plaintext is set)" : "") + ".");
  var yes = await readLine("Type YES (all caps) to confirm: ");
  if (yes !== "YES") {
    console.error("ERROR: confirmation declined. No changes made.");
    process.exit(1);
  }

  return pw1;
}

function readLine(prompt) {
  return new Promise(function (resolve) {
    var readline = require("readline");
    var rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, function (answer) { rl.close(); resolve(answer); });
  });
}

// ---- The 9-step atomic migration ----
async function execute(passphrase, opts) {
  console.log("[setup] Reading plaintext vault.key...");
  var plaintextBytes = fs.readFileSync(PLAINTEXT_PATH);

  console.log("[setup] Wrapping with Argon2id (this may take ~1 second)...");
  var sealedBytes = await vaultWrap.wrap(plaintextBytes, passphrase);
  console.log("[setup] Wrapped " + plaintextBytes.length + " bytes → " + sealedBytes.length + " bytes.");

  // Step 4: write .tmp + fsync
  fs.writeFileSync(SEALED_TMP_PATH, sealedBytes, { mode: 0o600 });
  fsyncPath(SEALED_TMP_PATH);
  fsyncDataDir();

  // Step 5: in-process round-trip verify
  console.log("[setup] Verifying round-trip (re-reading, re-unwrapping)...");
  var verifyBytes = fs.readFileSync(SEALED_TMP_PATH);
  var unwrapped;
  try {
    unwrapped = await vaultWrap.unwrap(verifyBytes, passphrase);
  } catch (e) {
    fs.unlinkSync(SEALED_TMP_PATH);
    console.error("ERROR: round-trip verification failed — " + e.message);
    console.error("  vault.key is UNCHANGED. Nothing was committed.");
    process.exit(1);
  }
  if (Buffer.compare(unwrapped, plaintextBytes) !== 0) {
    fs.unlinkSync(SEALED_TMP_PATH);
    console.error("ERROR: round-trip produced different bytes than the original.");
    console.error("  This should be impossible — please report this as a bug.");
    console.error("  vault.key is UNCHANGED. Nothing was committed.");
    process.exit(1);
  }
  console.log("[setup] Round-trip verified.");

  // Step 6: write migration marker with sealed-file hash
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    sealedSha3: sha3Hash(sealedBytes),
    keepPlaintext: !!opts.keepPlaintext,
  };
  fs.writeFileSync(MARKER_TMP_PATH, JSON.stringify(marker), { mode: 0o600 });
  fsyncPath(MARKER_TMP_PATH);
  fs.renameSync(MARKER_TMP_PATH, MARKER_PATH);
  fsyncDataDir();

  // Step 7: atomic rename sealed file into place
  fs.renameSync(SEALED_TMP_PATH, SEALED_PATH);
  fsyncDataDir();

  // Step 8: delete plaintext (unless --keep-plaintext)
  if (!opts.keepPlaintext) {
    fs.unlinkSync(PLAINTEXT_PATH);
    fsyncDataDir();
    console.log("[setup] Plaintext vault.key deleted.");
  } else {
    console.log("[setup] --keep-plaintext: vault.key preserved as rollback backup.");
    console.log("[setup] NOTE: server will REFUSE to boot while both files exist. Either");
    console.log("[setup]       delete data/vault.key manually once confident, or run");
    console.log("[setup]       scripts/vault-passphrase-remove.js to revert.");
  }

  // Step 9: delete migration marker
  fs.unlinkSync(MARKER_PATH);
  fsyncDataDir();
}

function fsyncPath(p) {
  try {
    var fd = fs.openSync(p, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort: Windows rejects fsync on some fd modes */ }
}

function fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* dir fsync not portable; best-effort */ }
}

// ---- Final operator output ----
function printSuccess(opts) {
  console.log("");
  console.log("======================================================================");
  console.log("  ✓ Migration complete.");
  console.log("");
  console.log("    " + SEALED_PATH + " — active (wrapped with passphrase)");
  if (opts.keepPlaintext) {
    console.log("    " + PLAINTEXT_PATH + " — preserved (manual rollback backup)");
  } else {
    console.log("    " + PLAINTEXT_PATH + " — deleted");
  }
  console.log("");
  console.log("  To activate passphrase-protected boot:");
  console.log("    1. Set VAULT_PASSPHRASE_MODE=required in the server's environment.");
  console.log("    2. Ensure the passphrase source is configured the same way used here:");
  console.log("         VAULT_PASSPHRASE=<passphrase>              (env var)");
  console.log("         VAULT_PASSPHRASE_FILE=/path/to/secret      (Docker secrets)");
  console.log("         (interactive prompt requires -it Docker flag)");
  console.log("    3. Restart the server. Expected startup line:");
  console.log("         [vault] Unsealing vault.key.sealed...");
  console.log("         [vault] Unsealed successfully.");
  console.log("");
  console.log("  If something goes wrong, revert with:");
  console.log("    node scripts/vault-passphrase-remove.js");
  console.log("    (then unset VAULT_PASSPHRASE_MODE before restarting)");
  console.log("======================================================================");
}

// ---- Main ----
(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  try {
    await preflight(opts);
    var passphrase = await acquirePassphrase();
    await execute(passphrase, opts);
    printSuccess(opts);
  } catch (e) {
    console.error("FATAL: " + (e && e.message || String(e)));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
})();
