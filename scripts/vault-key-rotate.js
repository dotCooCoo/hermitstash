#!/usr/bin/env node
/**
 * vault-key-rotate.js — full vault keypair rotation (v1.9.3).
 *
 * Generates a brand new ML-KEM-1024 + P-384 hybrid vault keypair and
 * re-encrypts every vault-sealed value in the data directory:
 *   - every sealed column in every DB table
 *   - every per-file XChaCha20 key stored in the `files.encryptionKey`
 *     column (re-sealed as part of the DB row walk)
 *   - data/db.key.enc (wraps the SQLite file encryption key)
 *   - data/vault.key or data/vault.key.sealed (the keypair itself)
 *
 * File blobs in the upload directory are NOT re-encrypted — their
 * per-file keys are already ephemeral and isolated; re-sealing the
 * column entries is sufficient.
 *
 * Run OFFLINE (stop the server first). The tool refuses to run while a
 * server is responding on the configured port. Operates on a side-by-
 * side staging copy of the data directory and atomically swaps it in
 * only after verification, so any failure leaves the original data
 * directory byte-exact.
 *
 * Usage:
 *   # interactive (recommended)
 *   docker exec -it hermitstash node scripts/vault-key-rotate.js
 *
 *   # scripted (wrapped mode)
 *   VAULT_PASSPHRASE_OLD='<current>' VAULT_PASSPHRASE_NEW='<new>' \
 *     node scripts/vault-key-rotate.js
 *
 *   # dry run — exercise everything except the final swap
 *   node scripts/vault-key-rotate.js --dry-run
 *
 * After success:
 *   1. data.old.<ISO timestamp>/ is retained (delete at your discretion
 *      after verifying the rotation via vault-key-verify.js + normal
 *      traffic; recommended retention: 7 days)
 *   2. If the passphrase changed, update VAULT_PASSPHRASE /
 *      VAULT_PASSPHRASE_FILE in the server environment to the new value
 *   3. Restart the server. Expected log line:
 *        [vault] Unsealed successfully.    (wrapped mode)
 *      OR no special output                (plaintext mode)
 */
"use strict";

var fs = require("fs");
var path = require("path");
var http = require("http");
var { DatabaseSync } = require("node:sqlite");

var C = require("../lib/constants");
var cryptoLib = require("../lib/crypto");
var passphraseSource = require("../lib/passphrase-source");
var vaultWrap = require("../lib/vault-wrap");
var vaultRotate = require("../lib/vault-rotate");

var DATA_DIR = C.DATA_DIR;
var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var ROTATING_DIR = C.PATHS.DATA_ROTATING_DIR;
var ROTATION_PENDING = C.PATHS.DATA_ROTATION_PENDING;
var DATA_OLD_PREFIX = C.PATHS.DATA_OLD_PREFIX;
var VAULT_PREFIX = C.VAULT_PREFIX;

function parseArgs(argv) {
  var opts = {
    dryRun: false,
    keepOldKey: true, // decisions locked: retain data.old by default
    forceWithServerRunning: false,
    allowRoot: false,
    help: false,
  };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--force-with-server-running") opts.forceWithServerRunning = true;
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
    "vault-key-rotate.js — generate a new vault keypair and re-encrypt every sealed value",
    "",
    "Options:",
    "  --dry-run                     Run all steps except the final swap.",
    "                                  data.rotating/ is cleaned up at end;",
    "                                  data/ is never touched.",
    "  --force-with-server-running   Skip the live-server check (data-corruption",
    "                                  prone — diagnostic use only).",
    "  --allow-root                  Permit running as UID 0.",
    "  -h, --help                    This help.",
    "",
    "Passphrase sources (wrapped mode only):",
    "  Interactive:    no env vars set → three stdin prompts (current,",
    "                                     new, confirm).",
    "  Env (scripted): VAULT_PASSPHRASE_OLD + VAULT_PASSPHRASE_NEW",
    "  Files:          VAULT_PASSPHRASE_OLD_FILE + VAULT_PASSPHRASE_NEW_FILE",
    "",
    "The new passphrase can be the same as the current one — you may want to",
    "rotate the keypair without rotating the passphrase.",
    "",
    "This tool refuses plaintext↔wrapped mode transitions. Run the appropriate",
    "setup/remove tool separately if you need to change modes.",
    "",
    "After success:",
    "  data.old.<ISO timestamp>/ is retained by default. Delete it with `rm -rf`",
    "  once you've verified the rotated state via:",
    "    node scripts/vault-key-verify.js",
    "",
    "Performance expectations (single CPU core):",
    "  ~500 sealed column-values rotated per second",
    "  100k rows with ~5 sealed cols each (500k values) ≈ 15 minutes",
    "  1M rows ≈ ~90 minutes",
    "  Bottleneck is per-value ML-KEM-1024 + ECDH P-384 hybrid crypto;",
    "  SQL overhead is negligible. CPU-bound, not I/O-bound.",
    "",
    "⚠  Loss of the new passphrase = loss of all encrypted data.",
    "   Store it in a password manager BEFORE running with --dry-run=false.",
    "",
  ].join("\n"));
}

// ---- Pre-flight ----

function preflightSync(opts) {
  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed.");
    process.exit(1);
  }

  if (!fs.existsSync(PLAINTEXT_PATH) && !fs.existsSync(SEALED_PATH)) {
    console.error("ERROR: no vault.key or vault.key.sealed in " + DATA_DIR + ".");
    console.error("  Nothing to rotate. Has HermitStash ever been started in this directory?");
    process.exit(1);
  }
  if (fs.existsSync(PLAINTEXT_PATH) && fs.existsSync(SEALED_PATH)) {
    console.error("ERROR: both vault.key and vault.key.sealed exist in " + DATA_DIR + ".");
    console.error("  This is an invariant violation. Resolve manually before rotating.");
    process.exit(1);
  }
  if (fs.existsSync(ROTATING_DIR)) {
    console.error("ERROR: stale " + ROTATING_DIR + " exists.");
    console.error("  A previous rotation attempt didn't complete. Start the server briefly");
    console.error("  so its boot-time recovery cleans it up, then re-run rotation.");
    process.exit(1);
  }
  if (fs.existsSync(ROTATION_PENDING)) {
    console.error("ERROR: stale rotation-pending marker exists at " + ROTATION_PENDING + ".");
    console.error("  Start the server briefly to run boot recovery, then re-run rotation.");
    process.exit(1);
  }

  // Cross-filesystem check: DATA_DIR and its sibling rotating dir must be on
  // the same filesystem for atomic rename to work.
  var dataParent = path.dirname(DATA_DIR);
  try {
    var parentStat = fs.statSync(dataParent);
    var dataStat = fs.statSync(DATA_DIR);
    if (parentStat.dev !== dataStat.dev) {
      console.error("ERROR: " + DATA_DIR + " is on a different filesystem from its parent (" + dataParent + ").");
      console.error("  Cross-filesystem rename is not atomic; rotation's core invariant cannot be met.");
      console.error("  Move the data directory to a simple path on a single filesystem, or remove the bind mount.");
      process.exit(1);
    }
  } catch (e) {
    console.error("ERROR: could not stat " + DATA_DIR + " or its parent: " + e.message);
    process.exit(1);
  }

  // Inform about any existing data.old.* dirs (decisions: warn but permit)
  var parentEntries;
  try { parentEntries = fs.readdirSync(dataParent); } catch { parentEntries = []; }
  var oldPrefixBase = path.basename(DATA_OLD_PREFIX);
  var oldDirs = parentEntries.filter(function (e) { return e.indexOf(oldPrefixBase) === 0; });
  if (oldDirs.length > 0) {
    console.log("[rotate] Note: " + oldDirs.length + " existing data.old.* director" +
      (oldDirs.length === 1 ? "y" : "ies") + " present:");
    for (var i = 0; i < oldDirs.length; i++) {
      var fullDir = path.join(dataParent, oldDirs[i]);
      var ageDays = 0;
      try {
        var stat = fs.statSync(fullDir);
        ageDays = Math.floor((Date.now() - stat.mtimeMs) / (24 * 60 * 60 * 1000));
      } catch { /* stat failure doesn't block rotation */ }
      console.log("         " + oldDirs[i] + " (mtime age: " + ageDays + " days)");
    }
    console.log("         These are backups from previous rotations; delete at your discretion.");
  }
}

function preflightHealthCheck(opts) {
  if (opts.forceWithServerRunning) return Promise.resolve();
  return new Promise(function (resolve) {
    var port = Number(process.env.PORT || 3000);
    var req = http.get({ host: "127.0.0.1", port: port, path: "/health", timeout: 1500 }, function (res) {
      res.resume();
      console.error("ERROR: a HermitStash server appears to be running on port " + port + ".");
      console.error("  Stop it first, or pass --force-with-server-running.");
      console.error("  CAUTION: rotating with a running server corrupts the DB in unpredictable ways.");
      process.exit(1);
    });
    req.on("error", function () { resolve(); });
    req.on("timeout", function () { req.destroy(); resolve(); });
  });
}

// ---- Mode detection and passphrase acquisition ----

function detectMode() {
  if (fs.existsSync(SEALED_PATH)) return "wrapped";
  if (fs.existsSync(PLAINTEXT_PATH)) return "plaintext";
  // Can't happen — preflightSync already errored on neither
  throw new Error("internal: no vault key file found after pre-flight");
}

function readLine(prompt) {
  return new Promise(function (resolve) {
    var readline = require("readline");
    var rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, function (answer) { rl.close(); resolve(answer); });
  });
}

async function acquirePassphrasesWrapped() {
  var oldFromEnv = process.env.VAULT_PASSPHRASE_OLD;
  var newFromEnv = process.env.VAULT_PASSPHRASE_NEW;
  var oldFileEnv = process.env.VAULT_PASSPHRASE_OLD_FILE;
  var newFileEnv = process.env.VAULT_PASSPHRASE_NEW_FILE;

  var anyEnv = !!(oldFromEnv || newFromEnv || oldFileEnv || newFileEnv);
  if (anyEnv) {
    if ((oldFromEnv || oldFileEnv) && (newFromEnv || newFileEnv)) {
      var oldPw = oldFileEnv ? await passphraseSource.fromFile(oldFileEnv) : Buffer.from(oldFromEnv, "utf8");
      var newPw = newFileEnv ? await passphraseSource.fromFile(newFileEnv) : Buffer.from(newFromEnv, "utf8");
      if (oldFromEnv) delete process.env.VAULT_PASSPHRASE_OLD;
      if (newFromEnv) delete process.env.VAULT_PASSPHRASE_NEW;
      return { oldPw: oldPw, newPw: newPw };
    }
    console.error("ERROR: partial env passphrase config. Need BOTH:");
    console.error("  VAULT_PASSPHRASE_OLD[_FILE] and VAULT_PASSPHRASE_NEW[_FILE]");
    process.exit(1);
  }

  if (!process.stdin.isTTY) {
    console.error("ERROR: no passphrase env vars set, and stdin is not a TTY.");
    console.error("  Either run with -it for interactive prompts, or set");
    console.error("  VAULT_PASSPHRASE_OLD and VAULT_PASSPHRASE_NEW in the environment.");
    process.exit(1);
  }

  console.log("");
  console.log("======================================================================");
  console.log("  Full vault key rotation — INTERACTIVE");
  console.log("");
  console.log("  Generates a brand new ML-KEM-1024 + P-384 hybrid vault keypair and");
  console.log("  re-encrypts every sealed value in the data directory.");
  console.log("");
  console.log("  The new passphrase CAN be the same as the current one. You're");
  console.log("  rotating the KEYPAIR, not just the passphrase.");
  console.log("");
  console.log("  Store the NEW passphrase in a password manager BEFORE proceeding.");
  console.log("  Loss of the passphrase = loss of all encrypted data.");
  console.log("======================================================================");
  console.log("");

  var curPw = await passphraseSource.fromStdin("Current vault passphrase: ");
  var newPw1 = await passphraseSource.fromStdin("New vault passphrase:     ");
  var newPw2 = await passphraseSource.fromStdin("Confirm new passphrase:   ");
  if (Buffer.compare(newPw1, newPw2) !== 0) {
    console.error("ERROR: new passphrase confirmation does not match. Aborting.");
    process.exit(1);
  }
  if (newPw1.length < 12) {
    console.warn("[rotate] NOTE: new passphrase is shorter than 12 bytes. Continuing anyway.");
  }

  var yes = await readLine("Type YES (all caps) to confirm you've stored the new passphrase safely: ");
  if (yes !== "YES") {
    console.error("ERROR: confirmation declined. No changes made.");
    process.exit(1);
  }
  return { oldPw: curPw, newPw: newPw1 };
}

async function confirmPlaintextRotation() {
  if (!process.stdin.isTTY) return; // env-driven, no confirmation needed
  console.log("");
  console.log("======================================================================");
  console.log("  Full vault key rotation — plaintext mode");
  console.log("");
  console.log("  Generates a new vault keypair and re-encrypts every sealed value.");
  console.log("  No passphrase involved. The new key will be written to vault.key");
  console.log("  (plaintext) exactly like the current one.");
  console.log("======================================================================");
  console.log("");
  var yes = await readLine("Type YES (all caps) to proceed: ");
  if (yes !== "YES") {
    console.error("ERROR: confirmation declined. No changes made.");
    process.exit(1);
  }
}

// ---- Key loading ----

async function loadOldKeys(mode, oldPw) {
  if (mode === "plaintext") {
    var plainJson = fs.readFileSync(PLAINTEXT_PATH, "utf8");
    return JSON.parse(plainJson);
  }
  var sealedBytes = fs.readFileSync(SEALED_PATH);
  var plainBuf;
  try {
    plainBuf = await vaultWrap.unwrap(sealedBytes, oldPw);
  } catch (e) {
    console.error("ERROR: current passphrase rejected — " + e.message);
    console.error("  The sealed vault.key is unchanged. No rotation was attempted.");
    process.exit(1);
  }
  return JSON.parse(plainBuf.toString("utf8"));
}

// ---- Schema drift pre-flight ----

function runSchemaDriftCheck(oldKeys) {
  // Open the live DB read-only to run validateSchemaMatch. We need to
  // decrypt hermitstash.db.enc first — mirror lib/db.js's approach.
  var dbKeyEnc = path.join(DATA_DIR, "db.key.enc");
  var dbEnc = path.join(DATA_DIR, "hermitstash.db.enc");
  if (!fs.existsSync(dbKeyEnc) || !fs.existsSync(dbEnc)) {
    console.log("[rotate] No encrypted DB present — skipping schema-drift check.");
    return;
  }
  var sealedDbKey = fs.readFileSync(dbKeyEnc, "utf8").trim();
  var dbKey = Buffer.from(
    cryptoLib.decrypt(sealedDbKey.substring(VAULT_PREFIX.length), oldKeys),
    "base64"
  );
  var packed = fs.readFileSync(dbEnc);
  var plain = cryptoLib.decryptPacked(packed, dbKey);
  var tmpPath = path.join(path.dirname(DATA_DIR), ".schema-check-" + Date.now() + ".db");
  fs.writeFileSync(tmpPath, plain);
  var db = new DatabaseSync(tmpPath);
  var result;
  try {
    result = vaultRotate.validateSchemaMatch(db);
  } finally {
    db.close();
    try { fs.unlinkSync(tmpPath); } catch { /* best-effort */ }
    try { fs.unlinkSync(tmpPath + "-wal"); } catch { /* best-effort */ }
    try { fs.unlinkSync(tmpPath + "-shm"); } catch { /* best-effort */ }
  }
  if (result.errors.length > 0 || result.warnings.length > 0) {
    console.log(vaultRotate.formatValidationResult(result));
  } else {
    console.log("[rotate] schema match: OK");
  }
  if (result.errors.length > 0) {
    console.error("[rotate] Refusing to proceed with schema drift errors present.");
    process.exit(1);
  }
}

// ---- Atomic swap ----

function computeStagingHash() {
  var names = fs.readdirSync(ROTATING_DIR).slice().sort();
  return cryptoLib.sha3Hash(names.join("\n"));
}

function writeRotationMarker() {
  var marker = {
    format: 1,
    startedAt: new Date().toISOString(),
    stagingHash: computeStagingHash(),
    hashAlg: "sha3-512",
  };
  var tmp = ROTATION_PENDING + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(marker, null, 2), { mode: 0o600 });
  try {
    var fd = fs.openSync(tmp, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch { /* best-effort */ }
  fs.renameSync(tmp, ROTATION_PENDING);
  fsyncParentOfDataDir();
}

function fsyncParentOfDataDir() {
  try {
    var parent = path.dirname(DATA_DIR);
    var fd = fs.openSync(parent, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch { /* best-effort */ }
}

function performSwap() {
  var isoTs = new Date().toISOString().replace(/[:.]/g, "-");
  var dataOldDir = DATA_OLD_PREFIX + isoTs;
  console.log("[rotate] Swapping: " + DATA_DIR + " → " + dataOldDir);
  fs.renameSync(DATA_DIR, dataOldDir);
  fsyncParentOfDataDir();
  console.log("[rotate] Swapping: " + ROTATING_DIR + " → " + DATA_DIR);
  fs.renameSync(ROTATING_DIR, DATA_DIR);
  fsyncParentOfDataDir();
  return dataOldDir;
}

function clearMarker() {
  try {
    fs.unlinkSync(ROTATION_PENDING);
    fsyncParentOfDataDir();
  } catch (e) {
    console.error("[rotate] WARNING: could not delete rotation marker (boot will auto-clear): " + e.message);
  }
}

// ---- Main ----

function progressLine(ev) {
  if (ev.phase === "rotate_rows" && ev.rowsProcessed !== undefined && ev.rowsTotal > 0) {
    // Only log occasionally — every 10% or on completion
    var pct = Math.floor((ev.rowsProcessed / ev.rowsTotal) * 100);
    if (pct >= 100 || pct % 10 === 0) {
      process.stdout.write("\r[rotate] " + ev.table + "." + ev.column + ": " + ev.rowsProcessed + "/" + ev.rowsTotal + " (" + pct + "%)     ");
      if (pct >= 100) process.stdout.write("\n");
    }
  } else if (ev.phase === "done") {
    console.log("[rotate] Rotation phase complete: " + ev.tablesProcessed + " tables, " + ev.totalRowsProcessed + " rows, " + ev.durationMs + "ms");
  } else if (ev.phase === "verify") {
    console.log("[rotate] Running round-trip verification...");
  } else if (ev.phase === "reseal_files") {
    console.log("[rotate] Re-sealing db.key.enc with new vault keypair...");
  } else if (ev.phase === "decrypt_db") {
    console.log("[rotate] Decrypting DB file with old vault keypair...");
  } else if (ev.phase === "reencrypt_db") {
    console.log("[rotate] Re-encrypting DB file...");
  }
}

function printSuccess(dataOldDir, result) {
  console.log("");
  console.log("======================================================================");
  console.log("  ✓ Rotation complete.");
  console.log("");
  console.log("    tables rotated:  " + result.tablesProcessed);
  console.log("    rows rotated:    " + result.totalRowsProcessed);
  console.log("    duration:        " + result.durationMs + " ms");
  if (result.warnings.length > 0) {
    console.log("    warnings:        " + result.warnings.length + " (see above)");
  }
  console.log("");
  console.log("    backup retained at: " + dataOldDir);
  console.log("");
  console.log("  To activate the new vault keypair:");
  console.log("    1. If the passphrase changed, update VAULT_PASSPHRASE /");
  console.log("       VAULT_PASSPHRASE_FILE to the new value.");
  console.log("    2. Restart the server.");
  console.log("    3. Verify access with: node scripts/vault-key-verify.js");
  console.log("");
  console.log("  Once confident (recommended: 7 days of normal traffic):");
  console.log("    rm -rf \"" + dataOldDir + "\"");
  console.log("");
  console.log("  The OLD vault keypair is no longer usable to read live data.");
  console.log("======================================================================");
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  try {
    preflightSync(opts);
    await preflightHealthCheck(opts);

    var mode = detectMode();
    console.log("[rotate] Detected mode: " + mode);

    var pws = mode === "wrapped" ? await acquirePassphrasesWrapped() : null;
    var oldKeys = await loadOldKeys(mode, pws && pws.oldPw);

    if (mode === "plaintext") await confirmPlaintextRotation();

    runSchemaDriftCheck(oldKeys);

    console.log("[rotate] Generating new vault keypair...");
    var newKeys = cryptoLib.generateEncryptionKeyPair();

    console.log("[rotate] Building rotated copy at " + ROTATING_DIR);
    var result = await vaultRotate.rotateDataDirectory({
      oldKeys: oldKeys,
      newKeys: newKeys,
      dataDir: DATA_DIR,
      stagingDir: ROTATING_DIR,
      mode: mode,
      newPassphrase: pws && pws.newPw,
      progressCallback: progressLine,
    });

    if (result.warnings.length > 0) {
      console.log("[rotate] warnings (" + result.warnings.length + "):");
      for (var w = 0; w < result.warnings.length; w++) {
        console.log("  - " + result.warnings[w]);
      }
    }

    if (opts.dryRun) {
      console.log("[rotate] --dry-run: not performing swap. Cleaning up " + ROTATING_DIR);
      fs.rmSync(ROTATING_DIR, { recursive: true, force: true });
      console.log("[rotate] Dry run complete. Original " + DATA_DIR + " untouched.");
      return;
    }

    console.log("[rotate] Writing rotation-pending marker");
    writeRotationMarker();

    var dataOldDir = performSwap();
    clearMarker();
    printSuccess(dataOldDir, result);
  } catch (e) {
    console.error("FATAL: " + (e && e.message || String(e)));
    if (e && e.stack) console.error(e.stack);
    // Attempt cleanup if staging exists
    if (fs.existsSync(ROTATING_DIR)) {
      console.error("[rotate] Cleaning up partial " + ROTATING_DIR);
      try { fs.rmSync(ROTATING_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
    process.exit(1);
  }
})();
