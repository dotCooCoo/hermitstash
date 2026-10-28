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
 * Run OFFLINE (stop the server first). The tool refuses to run while the
 * server's lease in the data directory is fresh or a server answers on the
 * configured ports. It builds the rotated copy in DATA_DIR/.rotation-staging,
 * verifies it, and then moves the entries of DATA_DIR into
 * DATA_DIR/.rotation-old-<timestamp> and the staged entries into DATA_DIR
 * (lib/rotation-swap.js). DATA_DIR itself is not renamed, so it may be a
 * mount point. A failure before the swap leaves DATA_DIR byte-exact; a
 * failure during the swap moves every entry back.
 *
 * The encrypted database is bound to the DATA_DIR path, so run the tool with
 * the same HERMITSTASH_DATA_DIR as the server.
 *
 * Usage:
 *   # Docker: stop the server, then run the tool in a one-off container as
 *   # the stack's PUID:PGID (99:100 by default)
 *   docker compose stop hermitstash
 *   docker compose run --rm --no-deps --entrypoint node --user 99:100 \
 *     hermitstash scripts/vault-key-rotate.js
 *   docker compose up -d hermitstash
 *
 *   # scripted (wrapped mode)
 *   VAULT_PASSPHRASE_OLD='<current>' VAULT_PASSPHRASE_NEW='<new>' \
 *     node scripts/vault-key-rotate.js
 *
 *   # dry run — exercise everything except the final swap
 *   node scripts/vault-key-rotate.js --dry-run
 *
 * After success:
 *   1. DATA_DIR/.rotation-old-<ISO timestamp>/ holds the pre-rotation files
 *      (delete it after verifying the rotation via vault-key-verify.js and
 *      normal traffic; recommended retention: 7 days)
 *   2. If the passphrase changed, update VAULT_PASSPHRASE /
 *      VAULT_PASSPHRASE_FILE in the server environment to the new value
 *   3. Restart the server. Expected log line:
 *        [vault] Unsealed successfully.    (wrapped mode)
 *      OR no special output                (plaintext mode)
 */
"use strict";

var fs = require("fs");
var path = require("path");
var { DatabaseSync } = require("node:sqlite");

var C = require("../lib/constants");
var b = require("../lib/vendor/blamejs");
var safeLog = require("../lib/safe-log");
var cryptoLib = require("../lib/crypto");
var passphraseSource = require("../lib/passphrase-source");
var fieldCrypto = require("../lib/field-crypto");
var rotationInventory = require("../lib/rotation-inventory");
var rotationSwap = require("../lib/rotation-swap");
var serverLease = require("../lib/server-lease");
var serverLiveness = require("./lib/server-liveness");
var liveDb = require("./lib/live-db");

// Populate b.cryptoField with HS's FIELD_SCHEMA before any
// b.vaultRotate call — its schema walker reads from b.cryptoField.
fieldCrypto.registerWithBlamejs();

var DATA_DIR = C.DATA_DIR;
var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var STAGING_DIR = C.PATHS.ROTATION_STAGING_DIR;
var SWAP_MARKER = C.PATHS.ROTATION_MARKER;
var LEGACY_ROTATING_DIR = C.PATHS.DATA_ROTATING_DIR;
var LEGACY_ROTATION_PENDING = C.PATHS.DATA_ROTATION_PENDING;

function parseArgs(argv) {
  var opts = {
    dryRun: false,
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
    "                                  The staged copy is deleted at the end;",
    "                                  nothing else in the data directory changes.",
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
    "Run the tool with the same HERMITSTASH_DATA_DIR as the server. The",
    "encrypted database is bound to that path.",
    "",
    "After success:",
    "  <data dir>/.rotation-old-<ISO timestamp>/ holds the pre-rotation files.",
    "  Delete it with `rm -rf` once you've verified the rotated state via:",
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
  if (fs.existsSync(SWAP_MARKER)) {
    console.error("ERROR: " + SWAP_MARKER + " exists: a previous rotation stopped during its swap.");
    console.error("  Start the server once so boot recovery finishes or undoes that swap, then re-run rotation.");
    process.exit(1);
  }
  if (fs.existsSync(STAGING_DIR)) {
    console.error("ERROR: stale " + STAGING_DIR + " exists: a previous rotation did not finish building its copy.");
    console.error("  Start the server once so boot recovery deletes it, then re-run rotation.");
    process.exit(1);
  }
  if (fs.existsSync(LEGACY_ROTATING_DIR) || fs.existsSync(LEGACY_ROTATION_PENDING)) {
    console.error("ERROR: " + LEGACY_ROTATING_DIR + " or " + LEGACY_ROTATION_PENDING + " exists,");
    console.error("  left by an earlier version of this tool. Start the server once so boot recovery");
    console.error("  resolves it, then re-run rotation.");
    process.exit(1);
  }

  // Every top-level entry moves with a rename inside DATA_DIR, which fails for
  // an entry on another filesystem (a separately mounted subdirectory).
  var dataDev;
  try { dataDev = fs.statSync(DATA_DIR).dev; }
  catch (e) {
    console.error("ERROR: could not stat " + DATA_DIR + ": " + e.message);
    process.exit(1);
  }
  var otherFs = rotationSwap.listLive(DATA_DIR).filter(function (name) {
    return fs.lstatSync(path.join(DATA_DIR, name)).dev !== dataDev;
  });
  if (otherFs.length > 0) {
    console.error("ERROR: these entries of " + DATA_DIR + " are on a different filesystem from it: " + otherFs.join(", "));
    console.error("  The swap moves each entry with a rename, which cannot cross filesystems.");
    console.error("  Mount the data directory as one volume, without separately mounted subdirectories.");
    process.exit(1);
  }

  // Inform about the copies earlier rotations retained (warn but permit)
  var oldDirs = rotationSwap.listOldDirs(DATA_DIR);
  if (oldDirs.length > 0) {
    console.log("[rotate] Note: " + oldDirs.length + " pre-rotation director" +
      (oldDirs.length === 1 ? "y" : "ies") + " from earlier rotations present in " + DATA_DIR + ":");
    for (var i = 0; i < oldDirs.length; i++) {
      var ageDays = 0;
      try {
        ageDays = Math.floor((Date.now() - fs.statSync(path.join(DATA_DIR, oldDirs[i])).mtimeMs) / C.TIME.days(1));
      } catch { /* stat failure doesn't block rotation */ }
      console.log("         " + oldDirs[i] + " (mtime age: " + ageDays + " days)");
    }
    console.log("         They hold the vault keys those rotations replaced; delete them once you no longer need them.");
  }
}

function preflightHealthCheck(opts) {
  return serverLiveness.claimDataDir(opts, "vault-key-rotate.js", [
    "  CAUTION: rotating with a running server corrupts the DB in unpredictable ways.",
  ]);
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
    // Guard the parse: a SyntaxError of the plaintext keypair echoes private-key
    // bytes, which the top-level catch would write via e.message/e.stack (CWE-532).
    try { return b.safeJson.parse(plainJson, { maxBytes: b.constants.BYTES.mib(1) }); }
    catch (_e) { console.error("FATAL: vault.key is not valid JSON (parser detail suppressed to avoid logging key material). Restore from backup."); process.exit(1); }
  }
  var sealedBytes = fs.readFileSync(SEALED_PATH);
  var plainBuf;
  try {
    plainBuf = await b.vaultWrap.unwrap(sealedBytes, oldPw);
  } catch (e) {
    if (e && e.code === "vault-wrap/passphrase-rejected") {
      console.error("ERROR: current passphrase rejected: " + safeLog.scrub(e.message));
    } else {
      console.error("ERROR: vault.key.sealed could not be unwrapped: " + safeLog.scrub(e.message));
      console.error("  The passphrase was not checked.");
    }
    console.error("  The sealed vault.key is unchanged. No rotation was attempted.");
    process.exit(1);
  }
  try { return b.safeJson.parse(plainBuf.toString("utf8"), { maxBytes: b.constants.BYTES.mib(1) }); }
  catch (_e) { console.error("FATAL: unsealed vault key is not valid JSON (parser detail suppressed to avoid logging key material). The sealed file may be corrupt."); process.exit(1); }
}

// ---- Schema drift pre-flight ----

function runSchemaDriftCheck(oldKeys) {
  // Decrypt the live DB the way lib/db.js does at boot (scripts/lib/live-db.js)
  // and run validateSchemaMatch on an owner-only temporary copy outside DATA_DIR.
  if (!liveDb.present(DATA_DIR)) {
    console.log("[rotate] No encrypted DB present — skipping schema-drift check.");
    return null;
  }
  var dbKey = liveDb.unsealDbKey(DATA_DIR, oldKeys);
  var tmpPath = liveDb.writeTempDb(liveDb.decrypt(DATA_DIR, dbKey), "schema-check");
  var db = new DatabaseSync(tmpPath);
  var result;
  try {
    result = b.vaultRotate.validateSchemaMatch(db, {
      infraColumns: C.ROTATION_INFRA_COLUMNS,
      tables:       Object.keys(fieldCrypto.FIELD_SCHEMA),
    });
  } finally {
    db.close();
    liveDb.removeTempDb(tmpPath);
  }
  if (result.errors.length > 0 || result.warnings.length > 0) {
    console.log(b.vaultRotate.formatValidationResult(result));
  } else {
    console.log("[rotate] schema match: OK");
  }
  if (result.errors.length > 0) {
    console.error("[rotate] Refusing to proceed with schema drift errors present.");
    process.exit(1);
  }
  // AAD-bound sealed values (vault.aad:) are re-sealed old-root → new-root by
  // b.vaultRotate (blamejs >= 0.14.12), which also verifies that each cell
  // opens under the new root and no longer opens under the old — so there is
  // no AAD scan or gate here.
  return dbKey;
}

// ---- Swap ----

// This tool has held the lease since the preflight. Another process may still
// have written over it, or a server may be listening locally.
async function assertStillOffline(opts) {
  if (opts.forceWithServerRunning) return;
  var lease = serverLease.read();
  var reason = null;
  if (!lease || !serverLease.isMine(lease)) {
    reason = lease ? serverLease.describe(lease) + " replaced this tool's lease on the data directory"
      : "this tool's lease on the data directory was deleted";
  } else if (await serverLiveness.isServerRunning()) {
    reason = "a HermitStash server answers on port " + serverLiveness.gatePort() + " or " + serverLiveness.internalTlsPort();
  }
  if (!reason) return;
  fs.rmSync(STAGING_DIR, { recursive: true, force: true });
  console.error("ERROR: " + reason + " while the rotated copy was being built.");
  console.error("  The rotated copy has been deleted and " + DATA_DIR + " is unchanged. Stop the other process and re-run.");
  process.exit(1);
}

// The staged copy holds every top-level entry the rotation was asked to write
// or carry. A staging directory that was emptied and recreated while
// b.vaultRotate.rotate ran is missing the entries it copied first.
function assertStagedComplete(rotatePaths, carried) {
  var expected = Object.create(null);
  function top(rel) { return String(rel).split(/[\\/]/)[0]; }
  carried.verbatimFiles.concat(carried.verbatimDirs).concat(carried.symlinks).forEach(function (e) {
    expected[top(e.relativePath)] = true;
  });
  [rotatePaths.encryptedDb, rotatePaths.dbKeySealed, rotatePaths.vaultKeyPlain, rotatePaths.vaultKeySealed]
    .concat(rotatePaths.additionalSealed.map(function (e) { return e.relativePath; }))
    .forEach(function (rel) { if (fs.existsSync(path.join(DATA_DIR, rel))) expected[top(rel)] = true; });
  // lstat, so a carried symbolic link counts whether or not its target resolves
  var missing = Object.keys(expected).filter(function (n) {
    try { fs.lstatSync(path.join(STAGING_DIR, n)); return false; } catch (_e) { return true; }
  });
  if (missing.length === 0) return;
  fs.rmSync(STAGING_DIR, { recursive: true, force: true });
  console.error("ERROR: the rotated copy is missing " + missing.join(", ") + ".");
  console.error("  The rotated copy has been deleted and " + DATA_DIR + " is unchanged. Re-run the rotation.");
  process.exit(1);
}

// Read the swapped-in database the way the server will at its next boot.
function verifySwapped(newKeys, dbKey) {
  if (!dbKey) return;
  var swappedKey = liveDb.unsealDbKey(DATA_DIR, newKeys);
  if (Buffer.compare(swappedKey, dbKey) !== 0) {
    throw new Error("db.key.enc in " + DATA_DIR + " does not hold the database key");
  }
  liveDb.decrypt(DATA_DIR, swappedKey);
}

function performSwap(newKeys, dbKey) {
  var marker = rotationSwap.planSwap(DATA_DIR, new Date().toISOString());
  var oldDir = path.join(DATA_DIR, marker.oldDir);
  console.log("[rotate] Writing swap marker " + SWAP_MARKER);
  rotationSwap.writeMarker(DATA_DIR, marker);
  try {
    console.log("[rotate] Moving " + marker.live.length + " entries into " + oldDir +
      " and " + marker.staged.length + " rotated entries into " + DATA_DIR);
    rotationSwap.rollForward(DATA_DIR, marker);
    verifySwapped(newKeys, dbKey);
  } catch (e) {
    console.error("[rotate] Swap failed: " + safeLog.scrub(e && e.message || String(e)));
    marker.direction = "backward";
    try { rotationSwap.writeMarker(DATA_DIR, marker); }
    catch (eMark) {
      console.error("FATAL: could not record the move back in " + SWAP_MARKER + ": " + safeLog.scrub(eMark.message));
      console.error("  The marker still records the forward swap. Starting the server finishes it, and the");
      console.error("  pre-rotation entries stay in " + oldDir + ".");
      process.exit(1);
    }
    try {
      console.error("[rotate] Moving the original entries back from " + oldDir);
      rotationSwap.rollBack(DATA_DIR, marker);
      rotationSwap.clearMarker(DATA_DIR);
    } catch (eBack) {
      console.error("FATAL: could not move the original entries back: " + safeLog.scrub(eBack.message));
      console.error("  " + SWAP_MARKER + " records the move back. Starting the server finishes it from " + oldDir + ".");
      process.exit(1);
    }
    console.error("[rotate] " + DATA_DIR + " is back in its pre-rotation state. The rotation did not take effect.");
    process.exit(1);
  }
  rotationSwap.clearMarker(DATA_DIR);
  return oldDir;
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
  console.log("    pre-rotation files retained at: " + dataOldDir);
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

    var dbKey = runSchemaDriftCheck(oldKeys);

    console.log("[rotate] Generating new vault keypair...");
    var newKeys = cryptoLib.generateEncryptionKeyPair();

    var rotatePaths = {
      encryptedDb:      "hermitstash.db.enc",
      dbKeySealed:      "db.key.enc",
      vaultKeyPlain:    "vault.key",
      vaultKeySealed:   "vault.key.sealed",
      additionalSealed: C.ROTATION_SEALED_FILES.filter(function (e) { return e.relativePath !== "db.key.enc"; }),
    };
    // Everything the rotation does not rewrite is carried into the rotated copy
    // unchanged: CA state, the audit signing key, logos, audit archives, markers.
    var carried = rotationInventory.carriedEntries(DATA_DIR, rotatePaths);
    rotatePaths.verbatimFiles = carried.verbatimFiles;
    rotatePaths.verbatimDirs = carried.verbatimDirs;
    console.log("[rotate] Carrying " + carried.verbatimFiles.length + " file(s), " +
      carried.verbatimDirs.length + " director(ies) and " + carried.symlinks.length +
      " symbolic link(s) into the rotated copy unchanged");

    console.log("[rotate] Building rotated copy at " + STAGING_DIR);
    var result = await b.vaultRotate.rotate({
      oldKeys: oldKeys,
      newKeys: newKeys,
      dataDir: DATA_DIR,
      stagingDir: STAGING_DIR,
      mode: mode,
      newPassphrase: pws && pws.newPw,
      progressCallback: progressLine,
      // HermitStash uses none of blamejs's agent / archive AAD features
      // (agent idempotency / orchestrator / tenant / snapshot, archive-wrap
      // tenant blobs). Those modules' AAD_ROTATION descriptors live entirely
      // in the vendored framework; no HS table or store carries that state.
      // Acknowledge so the rotation isn't refused for stores that don't exist
      // in this deployment.
      externalAadResealed: true,
      paths: rotatePaths,
    });
    rotationInventory.recreateSymlinks(STAGING_DIR, carried.symlinks);

    if (result.warnings.length > 0) {
      console.log("[rotate] warnings (" + result.warnings.length + "):");
      for (var w = 0; w < result.warnings.length; w++) {
        console.log("  - " + result.warnings[w]);
      }
    }

    if (opts.dryRun) {
      console.log("[rotate] --dry-run: not performing swap. Cleaning up " + STAGING_DIR);
      fs.rmSync(STAGING_DIR, { recursive: true, force: true });
      console.log("[rotate] Dry run complete. Original " + DATA_DIR + " untouched.");
      return;
    }

    assertStagedComplete(rotatePaths, carried);
    await assertStillOffline(opts);
    var dataOldDir = performSwap(newKeys, dbKey);
    printSuccess(dataOldDir, result);
  } catch (e) {
    // Do NOT log e.stack here: the old/new vault keypairs and the decrypted DB key
    // are live in this function's scope during rotation, and a thrown crypto error
    // can carry a window of those bytes in its stack/detail (CWE-532). e.message is
    // sanitized; surface only it plus the error code/name for diagnosis.
    console.error("FATAL: " + safeLog.scrub(e && e.message || String(e)));
    if (e && (e.code || e.name)) console.error("  (" + (e.code || e.name) + ")");
    // Before the swap marker exists, the staged copy is the only thing written.
    if (!fs.existsSync(SWAP_MARKER) && fs.existsSync(STAGING_DIR)) {
      console.error("[rotate] Cleaning up partial " + STAGING_DIR);
      try { fs.rmSync(STAGING_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
    process.exit(1);
  }
})();
