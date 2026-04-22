/**
 * Vault — encrypts/decrypts sensitive values using envelope format.
 *
 * Suite: ML-KEM-1024 + P-384 ECDH hybrid / XChaCha20-Poly1305 / SHAKE256
 * Keys are stored in data/vault.key (plaintext JSON) OR data/vault.key.sealed
 * (passphrase-wrapped) depending on VAULT_PASSPHRASE_MODE. Encrypted values
 * are prefixed with "vault:" so they can be detected.
 *
 * No backwards compatibility — only ML-KEM-1024 + P-384 hybrid keys accepted.
 * Legacy ML-KEM-768 keys must be migrated before upgrading.
 *
 * Two APIs:
 *   init()    — async, called ONCE at server bootstrap, populates the key cache.
 *               In plaintext mode it resolves via a sync file read.
 *               In wrapped mode it awaits the passphrase unwrap.
 *   seal() / unseal() — sync, access the populated cache. Must be called AFTER init().
 *
 * Why two APIs: seal/unseal are called from hundreds of call sites, many at
 * module-require time (e.g. lib/db.js). Making them async would require an
 * invasive refactor. Instead, the server's async bootstrap awaits init()
 * once, then everything else runs synchronously against the cached keys.
 */
var fs = require("fs");
var { generateEncryptionKeyPair, encrypt, decrypt, sha3Hash } = require("./crypto");
var C = require("./constants");
var VAULT_PREFIX = C.VAULT_PREFIX;

var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var MIGRATION_PENDING_PATH = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var UNSEAL_PENDING_PATH = C.PATHS.VAULT_KEY_UNSEAL_PENDING;
var DATA_DIR_PATH = C.DATA_DIR;
var DATA_ROTATING_PATH = C.PATHS.DATA_ROTATING_DIR;
var ROTATION_PENDING_PATH = C.PATHS.DATA_ROTATION_PENDING;

// Module-local cache populated by init() or a plaintext loadKeys() fallback.
var keys = null;
var initialized = false;
// Passphrase held in memory for operations that need it post-init (backup's
// re-wrap on restore, passphrase rotation via admin API). Already present in
// JS heap during unwrap; retaining the reference here doesn't change the
// threat model meaningfully (a process-memory-dump attacker wins regardless).
// The passphrase IS still stripped from process.env after read so it's not
// visible in env-dump surfaces. Null in plaintext mode.
var currentPassphrase = null;

function log(msg) { console.log("[vault] " + msg); }
function logErr(msg) { console.error("[vault] " + msg); }

// ---- Pre-dispatch cleanup helpers ----

function cleanOrphanTmp() {
  if (fs.existsSync(SEALED_TMP_PATH)) {
    try {
      fs.unlinkSync(SEALED_TMP_PATH);
      log("Cleaned orphan vault.key.sealed.tmp from a previous crash");
    } catch (e) {
      logErr("Failed to clean orphan vault.key.sealed.tmp: " + e.message);
    }
  }
}

// Recover from a crashed setup/remove tool mid-execution.
// Marker files bind a specific sealed-file hash so tampering between crash
// and restart is detected.
function recoverFromMarker(markerPath, targetFilePath, otherFilePath) {
  // targetFilePath is the file the migration was producing (e.g. vault.key.sealed for setup)
  // otherFilePath is the file that should be deleted to finalize (e.g. vault.key for setup)
  var marker;
  try {
    marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
  } catch (e) {
    logErr("FATAL: migration marker at " + markerPath + " is unreadable: " + e.message);
    logErr("Manually resolve: delete the marker and the partial file, then retry.");
    process.exit(1);
  }
  if (!marker || marker.format !== 1 || !marker.sealedSha3) {
    logErr("FATAL: unknown migration marker format at " + markerPath + ".");
    logErr("Upgrade HermitStash or manually resolve.");
    process.exit(1);
  }

  var targetExists = fs.existsSync(targetFilePath);
  var otherExists = fs.existsSync(otherFilePath);

  if (!targetExists) {
    // Crash before the target file's atomic rename completed. The partial
    // .tmp will be cleaned by cleanOrphanTmp(). Just drop the marker.
    fs.unlinkSync(markerPath);
    log("Recovery: marker without target file — discarded marker, continuing with existing state");
    return;
  }

  // Target exists — verify its hash matches what the marker expected
  var actualSha3 = sha3Hash(fs.readFileSync(targetFilePath));
  if (actualSha3 !== marker.sealedSha3) {
    logErr("FATAL: " + targetFilePath + " hash does not match migration marker.");
    logErr("  Expected: " + marker.sealedSha3);
    logErr("  Actual:   " + actualSha3);
    logErr("Possible tampering between crash and restart. Investigate manually before continuing.");
    process.exit(1);
  }

  if (otherExists) {
    // Crash between atomic rename (step 7 in setup) and unlink-other (step 8).
    // Finish the migration by unlinking the "other" file.
    try {
      fs.unlinkSync(otherFilePath);
      log("Recovery: completed migration by unlinking " + otherFilePath);
      fsyncDataDir();
    } catch (e) {
      logErr("FATAL: failed to unlink " + otherFilePath + " during recovery: " + e.message);
      process.exit(1);
    }
  }

  fs.unlinkSync(markerPath);
  fsyncDataDir();
  log("Recovery: migration marker cleared — boot can proceed");
}

function fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* fsync on directory isn't supported on all platforms; best effort */ }
}

// ---- v1.9.3 rotation-marker recovery ----
//
// The CLI-driven full vault key rotation (scripts/vault-key-rotate.js)
// builds a rotated copy of DATA_DIR at DATA_DIR.rotating, writes a
// DATA_DIR.rotation-pending JSON marker, then atomic-renames
//   DATA_DIR          → DATA_DIR.old.<ISO timestamp>
//   DATA_DIR.rotating → DATA_DIR
// and finally unlinks the marker. If the tool crashes mid-sequence,
// the next server boot observes the marker and dispatches per spec §6.1:
//
//   Marker | rotating/ | data/ | Action
//   -------|-----------|-------|------------------------------------------
//     Y    |    Y      |   Y   | Crash before any rename — discard both
//          |           |       | (operator re-runs)
//     Y    |    Y      |   N   | Crash between renames — finish the swap
//          |           |       | (rotating → data, delete marker)
//     Y    |    N      |   Y   | Crash after swap, before marker delete —
//          |           |       | just delete marker
//     Y    |    N      |   N   | FATAL — data missing entirely; restore
//          |           |       | from backup
//     N    |    Y      |   Y   | FATAL — invariant violation; inspect
//          |           |       | manually before boot
//
// The marker's `stagingHash` is a cheap top-level-filename fingerprint
// (sha3_512 of sorted filenames) — enough to detect tampering that
// ADDED or REMOVED files between crash and restart without the cost of
// hashing gigabyte-scale DB contents.
function _hashDirListing(dirPath) {
  var names = fs.readdirSync(dirPath).slice().sort();
  return sha3Hash(names.join("\n"));
}

function _readRotationMarker() {
  var raw;
  try {
    raw = fs.readFileSync(ROTATION_PENDING_PATH, "utf8");
  } catch (e) {
    logErr("FATAL: rotation-pending marker at " + ROTATION_PENDING_PATH + " is unreadable: " + e.message);
    logErr("Manually resolve: inspect " + DATA_ROTATING_PATH + " and " + DATA_DIR_PATH + ", then retry.");
    process.exit(1);
  }
  var marker;
  try { marker = JSON.parse(raw); } catch (e) {
    logErr("FATAL: rotation-pending marker JSON is malformed: " + e.message);
    process.exit(1);
  }
  if (!marker || marker.format !== 1 || !marker.stagingHash) {
    logErr("FATAL: unknown rotation marker format at " + ROTATION_PENDING_PATH + ".");
    process.exit(1);
  }
  return marker;
}

function recoverFromRotationMarker() {
  var hasMarker = fs.existsSync(ROTATION_PENDING_PATH);
  var hasRotating = fs.existsSync(DATA_ROTATING_PATH);
  var hasData = fs.existsSync(DATA_DIR_PATH);

  // No marker + both present = invariant violation. The CLI always writes
  // the marker before any rename, so both existing without a marker means
  // someone manually interfered.
  if (!hasMarker && hasRotating && hasData) {
    logErr("FATAL: Both " + DATA_DIR_PATH + " and " + DATA_ROTATING_PATH + " exist, but no rotation marker.");
    logErr("This indicates manual interference or an older tool writing unmarked state.");
    logErr("Inspect both directories, decide which is canonical, rename the other out of the way, then restart.");
    process.exit(1);
  }

  if (!hasMarker) return; // nothing to recover

  var marker = _readRotationMarker();

  if (!hasRotating && !hasData) {
    logErr("FATAL: rotation marker exists but both " + DATA_DIR_PATH + " and " + DATA_ROTATING_PATH + " are missing.");
    logErr("The data directory has been lost. Restore from a backup, then restart.");
    process.exit(1);
  }

  if (hasRotating && hasData) {
    // Crash before any rename — the swap never started. Discard staging
    // and the marker; the original data directory is intact.
    log("Rotation-recovery: crash before swap detected — discarding " + DATA_ROTATING_PATH + " and marker");
    try {
      fs.rmSync(DATA_ROTATING_PATH, { recursive: true, force: true });
    } catch (e) {
      logErr("FATAL: could not remove stale " + DATA_ROTATING_PATH + ": " + e.message);
      logErr("Manually delete it, then restart.");
      process.exit(1);
    }
    fs.unlinkSync(ROTATION_PENDING_PATH);
    fsyncDataDir();
    return;
  }

  if (hasRotating && !hasData) {
    // Crash between the two renames. The original data/ has been moved to
    // data.old.<ts>/ and rotating/ is the intended new data/ but hasn't been
    // renamed yet. Verify the staging hash matches the marker to detect
    // tampering between crash and restart, then complete the swap.
    var actualHash = _hashDirListing(DATA_ROTATING_PATH);
    if (actualHash !== marker.stagingHash) {
      logErr("FATAL: " + DATA_ROTATING_PATH + " filename fingerprint does not match rotation marker.");
      logErr("  Expected: " + marker.stagingHash);
      logErr("  Actual:   " + actualHash);
      logErr("Possible tampering between crash and restart. Investigate manually — do NOT blindly rename.");
      process.exit(1);
    }
    log("Rotation-recovery: completing swap (" + DATA_ROTATING_PATH + " → " + DATA_DIR_PATH + ")");
    fs.renameSync(DATA_ROTATING_PATH, DATA_DIR_PATH);
    fs.unlinkSync(ROTATION_PENDING_PATH);
    fsyncDataDir();
    return;
  }

  // hasData && !hasRotating — crash after the swap, before the marker unlink.
  // Verify the hash matches what we just promoted, then clean up.
  if (!hasRotating && hasData) {
    var postHash = _hashDirListing(DATA_DIR_PATH);
    if (postHash !== marker.stagingHash) {
      logErr("FATAL: " + DATA_DIR_PATH + " filename fingerprint does not match rotation marker.");
      logErr("  Expected (from staging): " + marker.stagingHash);
      logErr("  Actual (current data):   " + postHash);
      logErr("This suggests the swap completed but the data directory has been modified since.");
      logErr("Inspect manually — a partial swap with subsequent writes is ambiguous.");
      process.exit(1);
    }
    log("Rotation-recovery: swap completed, clearing marker");
    fs.unlinkSync(ROTATION_PENDING_PATH);
    fsyncDataDir();
  }
}

// ---- State dispatch ----

async function init() {
  if (initialized) return;

  // v1.9.3: recover from an interrupted full vault key rotation BEFORE
  // ensuring DATA_DIR exists — if a crash happened mid-swap, DATA_DIR may
  // not exist yet (it's being promoted from the staging dir). Must run
  // before any other filesystem operation that assumes DATA_DIR.
  recoverFromRotationMarker();

  // Ensure data dir exists (first-run case)
  if (!fs.existsSync(C.DATA_DIR)) fs.mkdirSync(C.DATA_DIR, { recursive: true });

  // Pre-dispatch cleanup + marker recovery
  cleanOrphanTmp();
  if (fs.existsSync(MIGRATION_PENDING_PATH)) {
    // Setup-tool marker: target = sealed, other = plaintext
    recoverFromMarker(MIGRATION_PENDING_PATH, SEALED_PATH, PLAINTEXT_PATH);
  }
  if (fs.existsSync(UNSEAL_PENDING_PATH)) {
    // Remove-tool marker: target = plaintext, other = sealed
    // Note: for the remove path we hash the PLAINTEXT target file
    recoverFromMarker(UNSEAL_PENDING_PATH, PLAINTEXT_PATH, SEALED_PATH);
  }

  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  var hasPlaintext = fs.existsSync(PLAINTEXT_PATH);
  var hasSealed = fs.existsSync(SEALED_PATH);

  // Invariant violation: both files exist after recovery → refuse to guess
  if (hasPlaintext && hasSealed) {
    logErr("FATAL: Both data/vault.key and data/vault.key.sealed exist.");
    logErr("This indicates an incomplete migration or manual interference.");
    logErr("Resolve by deleting the file you do NOT want to keep, then restart.");
    process.exit(1);
  }

  // Config mismatches
  if (hasPlaintext && mode === "required") {
    logErr("FATAL: data/vault.key is plaintext but VAULT_PASSPHRASE_MODE=required.");
    logErr("Run `node scripts/vault-passphrase-setup.js` to migrate, or unset VAULT_PASSPHRASE_MODE.");
    process.exit(1);
  }
  if (hasSealed && mode === "disabled") {
    logErr("FATAL: data/vault.key.sealed exists but VAULT_PASSPHRASE_MODE is disabled.");
    logErr("Set VAULT_PASSPHRASE_MODE=required, or run `node scripts/vault-passphrase-remove.js` to unseal.");
    process.exit(1);
  }

  // Normal paths
  if (hasSealed && mode === "required") {
    await initWrapped();
  } else if (!hasPlaintext && !hasSealed && mode === "required") {
    await initFirstRunWrapped();
  } else {
    // Plaintext paths (existing behavior)
    initPlaintext();
  }

  initialized = true;
}

function initPlaintext() {
  if (fs.existsSync(PLAINTEXT_PATH)) {
    try {
      var loaded = JSON.parse(fs.readFileSync(PLAINTEXT_PATH, "utf8"));
      if (!loaded.ecPublicKey || !loaded.ecPrivateKey) {
        logErr("FATAL: Vault key file is a legacy ML-KEM-768 format.");
        logErr("This version requires ML-KEM-1024 + P-384 hybrid keys.");
        logErr("Run the migration tool to upgrade your vault keys, then restart.");
        process.exit(1);
      }
      keys = loaded;
      return;
    } catch (e) {
      logErr("FATAL: Vault key file corrupted or unreadable at " + PLAINTEXT_PATH + " — " + e.message);
      logErr("All sealed data (emails, files, sessions) requires the original key.");
      logErr("Restore data/vault.key from backup, then restart.");
      process.exit(1);
    }
  }

  // First run, plaintext mode — generate hybrid keypair
  keys = generateEncryptionKeyPair();
  fs.writeFileSync(PLAINTEXT_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
  log("Vault keypair generated at " + PLAINTEXT_PATH + " (ML-KEM-1024 + P-384 hybrid)");
  process.nextTick(function () {
    try {
      var audit = require("./audit");
      audit.log(audit.ACTIONS.VAULT_KEY_GENERATED, {
        performedBy: "system",
        details: "New ML-KEM-1024 + P-384 hybrid keypair created (plaintext)",
      });
    } catch (_e) { /* audit best-effort — key file already written + console-logged */ }
  });
}

async function initWrapped() {
  var passphraseSource = require("./passphrase-source");
  var vaultWrap = require("./vault-wrap");

  log("Unsealing vault.key.sealed...");
  var sealedBytes;
  try {
    sealedBytes = fs.readFileSync(SEALED_PATH);
  } catch (e) {
    logErr("FATAL: cannot read " + SEALED_PATH + ": " + e.message);
    process.exit(1);
  }

  var passphrase;
  try {
    passphrase = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
  } catch (e) {
    logErr("FATAL: " + e.message);
    process.exit(1);
  }

  var plaintextJson;
  try {
    var plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase);
    plaintextJson = plaintextBuf.toString("utf8");
  } catch (e) {
    logErr("FATAL: passphrase rejected or sealed file corrupted (" + e.message + ")");
    process.exit(1);
  }
  // Retain passphrase for operations that need it post-init (restore re-wrap,
  // rotation via admin API). See currentPassphrase comment at top of file.
  currentPassphrase = passphrase;

  try {
    keys = JSON.parse(plaintextJson);
  } catch (e) {
    logErr("FATAL: unwrapped vault key is not valid JSON: " + e.message);
    process.exit(1);
  }
  if (!keys || !keys.ecPublicKey || !keys.ecPrivateKey || !keys.publicKey || !keys.privateKey) {
    logErr("FATAL: unwrapped vault key is missing required fields.");
    logErr("This version requires ML-KEM-1024 + P-384 hybrid keys.");
    process.exit(1);
  }

  log("Unsealed successfully.");
}

async function initFirstRunWrapped() {
  var passphraseSource = require("./passphrase-source");
  var vaultWrap = require("./vault-wrap");

  log("First run with VAULT_PASSPHRASE_MODE=required — generating wrapped keypair...");

  var passphrase;
  try {
    passphrase = await passphraseSource.getPassphrase({
      prompt: "Choose a vault passphrase (loss = data loss, store it safely): ",
    });
  } catch (e) {
    logErr("FATAL: " + e.message);
    process.exit(1);
  }
  // Retain for post-init operations (see comment at top of file)
  currentPassphrase = passphrase;

  keys = generateEncryptionKeyPair();
  var plaintextJson = JSON.stringify(keys, null, 2);
  var sealed;
  try {
    sealed = await vaultWrap.wrap(plaintextJson, passphrase);
  } catch (e) {
    logErr("FATAL: failed to wrap new vault key: " + e.message);
    process.exit(1);
  }

  // Write sealed file atomically via .tmp + rename (no marker needed — this
  // is first-run with no prior plaintext to coordinate with).
  // fsync is best-effort: POSIX-portable sync semantics matter on Linux,
  // but Windows rejects fsync on read-mode fds and NTFS treats write+close
  // as durable anyway.
  fs.writeFileSync(SEALED_TMP_PATH, sealed, { mode: 0o600 });
  try {
    var fd = fs.openSync(SEALED_TMP_PATH, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* platform doesn't permit fsync here; writeFileSync is already durable enough */ }
  fs.renameSync(SEALED_TMP_PATH, SEALED_PATH);
  fsyncDataDir();

  log("Generated and sealed new vault keypair (ML-KEM-1024 + P-384 hybrid).");
  process.nextTick(function () {
    try {
      var audit = require("./audit");
      audit.log(audit.ACTIONS.VAULT_KEY_GENERATED, {
        performedBy: "system",
        details: "First-run wrapped key generation",
      });
    } catch (_e) { /* audit best-effort */ }
  });
}

// ---- Sync API — operates against the populated cache ----

function loadKeys() {
  if (keys) return keys;

  // Not yet initialized. In plaintext mode, do the sync load now (for
  // compatibility with callers that forget to call init() — though init
  // SHOULD be called at server bootstrap). In wrapped mode, throw — we
  // can't derive an Argon2 key synchronously.
  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  if (mode === "required") {
    throw new Error(
      "vault in passphrase mode but init() not called — await vault.init() " +
      "during async bootstrap before any seal/unseal usage"
    );
  }

  // Plaintext fallback — essentially the pre-v1.9 behavior
  initPlaintext();
  initialized = true;
  return keys;
}

function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  var k = loadKeys();
  return VAULT_PREFIX + encrypt(String(plaintext), k);
}

function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  var k = loadKeys();
  var payload = String(value).substring(VAULT_PREFIX.length);
  return decrypt(payload, k);
}

// Return the in-memory vault keypair as a JSON string. Used by backup/restore
// workers so they don't have to re-read vault.key from disk — critical for
// wrapped mode where the plaintext file doesn't exist on disk, only the
// in-memory copy produced by init(). Throws if called before init().
function getKeysJson() {
  if (!keys) {
    throw new Error("vault not initialized — call vault.init() before requesting keys");
  }
  return JSON.stringify(keys, null, 2);
}

// Return the current passphrase buffer (wrapped mode only). Used by backup
// runRestore to re-wrap the extracted plaintext vault key with the current
// server's passphrase. Null in plaintext mode.
function getCurrentPassphrase() {
  return currentPassphrase;
}

module.exports = {
  init: init,
  seal: seal,
  unseal: unseal,
  getKeysJson: getKeysJson,
  getCurrentPassphrase: getCurrentPassphrase,
  // Testing helpers — not part of the public contract
  _resetForTest: function () { keys = null; initialized = false; currentPassphrase = null; },
  _getKeysForTest: function () { return keys; },
};
