/**
 * HermitStash vault layer.
 *
 * Thin orchestration around b.vault.{init, seal, unseal, ...}. Adds:
 *   - HS-specific crash-recovery markers for the operator-facing
 *     setup / remove / rotate CLI tools (vault-passphrase-setup.js,
 *     vault-passphrase-remove.js, vault-key-rotate.js). blamejs's
 *     vault has no opinion on those tools, so HS owns the markers.
 *   - VAULT_PASSPHRASE_MODE env mapping ("disabled"/"required" →
 *     b.vault's "plaintext"/"wrapped").
 *   - Legacy 0xE1 envelope fallback on unseal — covers the boot
 *     window where lib/db.js reads db.key.enc before the auto-
 *     migrate script (lib/legacy-envelope-migrate) has rewritten
 *     it as 0xE2. Once every operator deployment has run the
 *     migration this branch is dead code; delete it then.
 *
 * Two APIs are still exposed because seal/unseal are sync at hundreds
 * of HS call sites — including module-require time (lib/db.js). The
 * server's async bootstrap awaits init() once, then everything else
 * runs synchronously against b.vault's cache.
 */
"use strict";

var fs = require("fs");
var b = require("./vendor/blamejs");
var hermitstashCrypto = require("./crypto");
var C = require("./constants");

var VAULT_PREFIX = C.VAULT_PREFIX;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var MIGRATION_PENDING_PATH = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var UNSEAL_PENDING_PATH = C.PATHS.VAULT_KEY_UNSEAL_PENDING;
var DATA_DIR_PATH = C.DATA_DIR;
var DATA_ROTATING_PATH = C.PATHS.DATA_ROTATING_DIR;
var ROTATION_PENDING_PATH = C.PATHS.DATA_ROTATION_PENDING;
var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;

function log(msg) { console.log("[vault] " + msg); }
function logErr(msg) { console.error("[vault] " + msg); }

function fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* fsync on directory isn't supported on all platforms; best effort */ }
}

// ---- HS marker recovery (setup / remove tool crash safety) ----

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

function recoverFromMarker(markerPath, targetFilePath, otherFilePath) {
  var marker;
  try { marker = JSON.parse(fs.readFileSync(markerPath, "utf8")); }
  catch (e) {
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
    fs.unlinkSync(markerPath);
    log("Recovery: marker without target file — discarded marker, continuing with existing state");
    return;
  }
  var actualSha3 = b.crypto.sha3Hash(fs.readFileSync(targetFilePath));
  if (actualSha3 !== marker.sealedSha3) {
    logErr("FATAL: " + targetFilePath + " hash does not match migration marker.");
    logErr("  Expected: " + marker.sealedSha3);
    logErr("  Actual:   " + actualSha3);
    logErr("Possible tampering between crash and restart. Investigate manually before continuing.");
    process.exit(1);
  }
  if (otherExists) {
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

// ---- HS rotation marker recovery (vault-key-rotate.js crash safety) ----

function _hashDirListing(dirPath) {
  var names = fs.readdirSync(dirPath).slice().sort();
  return b.crypto.sha3Hash(names.join("\n"));
}

function _readRotationMarker() {
  var raw;
  try { raw = fs.readFileSync(ROTATION_PENDING_PATH, "utf8"); }
  catch (e) {
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

  if (!hasMarker && hasRotating && hasData) {
    logErr("FATAL: Both " + DATA_DIR_PATH + " and " + DATA_ROTATING_PATH + " exist, but no rotation marker.");
    logErr("This indicates manual interference or an older tool writing unmarked state.");
    logErr("Inspect both directories, decide which is canonical, rename the other out of the way, then restart.");
    process.exit(1);
  }
  if (!hasMarker) return;

  var marker = _readRotationMarker();

  if (!hasRotating && !hasData) {
    logErr("FATAL: rotation marker exists but both " + DATA_DIR_PATH + " and " + DATA_ROTATING_PATH + " are missing.");
    logErr("The data directory has been lost. Restore from a backup, then restart.");
    process.exit(1);
  }
  if (hasRotating && hasData) {
    log("Rotation-recovery: crash before swap detected — discarding " + DATA_ROTATING_PATH + " and marker");
    try { fs.rmSync(DATA_ROTATING_PATH, { recursive: true, force: true }); }
    catch (e) {
      logErr("FATAL: could not remove stale " + DATA_ROTATING_PATH + ": " + e.message);
      logErr("Manually delete it, then restart.");
      process.exit(1);
    }
    fs.unlinkSync(ROTATION_PENDING_PATH);
    fsyncDataDir();
    return;
  }
  if (hasRotating && !hasData) {
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

// ---- Mode-vs-state guards (HS keeps its own framing of the failure modes) ----

function _refuseModeMismatch() {
  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  var hasPlaintext = fs.existsSync(PLAINTEXT_PATH);
  var hasSealed = fs.existsSync(SEALED_PATH);
  if (hasPlaintext && hasSealed) {
    logErr("FATAL: Both data/vault.key and data/vault.key.sealed exist.");
    logErr("This indicates an incomplete migration or manual interference.");
    logErr("Resolve by deleting the file you do NOT want to keep, then restart.");
    process.exit(1);
  }
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
}

// ---- Module-local key cache ----
// Keep HS's own cache so seal/unseal stay sync at hundreds of HS call
// sites — including module-require time (lib/db.js reads db.key.enc on
// load). b.vault.seal/unseal would throw "vault/not-initialized" before
// the async bootstrap awaits init(); HS's contract is "lazy-load
// plaintext mode if init() hasn't run yet, throw for wrapped".

var keys = null;
var initialized = false;
var currentPassphrase = null;

function loadKeysSync() {
  if (keys) return keys;
  // Wrapped mode requires async init for the Argon2 unwrap. Refuse here.
  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  if (mode === "required") {
    throw new Error(
      "vault in passphrase mode but init() not called — await vault.init() " +
      "during async bootstrap before any seal/unseal usage"
    );
  }
  // Plaintext fallback — sync read of vault.key. Generates a new keypair
  // on first run if absent.
  if (fs.existsSync(PLAINTEXT_PATH)) {
    var loaded;
    try { loaded = JSON.parse(fs.readFileSync(PLAINTEXT_PATH, "utf8")); }
    catch (e) {
      logErr("FATAL: Vault key file corrupted or unreadable at " + PLAINTEXT_PATH + " — " + e.message);
      process.exit(1);
    }
    if (!loaded.ecPublicKey || !loaded.ecPrivateKey || !loaded.publicKey || !loaded.privateKey) {
      logErr("FATAL: Vault key file is missing required ML-KEM-1024 + P-384 fields.");
      logErr("Run the migration tool to upgrade your vault keys, then restart.");
      process.exit(1);
    }
    keys = loaded;
  } else {
    keys = b.crypto.generateEncryptionKeyPair();
    fs.writeFileSync(PLAINTEXT_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
    log("Vault keypair generated at " + PLAINTEXT_PATH + " (ML-KEM-1024 + P-384 hybrid)");
  }
  initialized = true;
  return keys;
}

// ---- init() — runs HS recovery, then loads / wraps keys ----

async function init() {
  if (initialized) return;

  // v1.9.3: rotation recovery must run BEFORE any filesystem operation
  // that assumes DATA_DIR exists.
  recoverFromRotationMarker();

  if (!fs.existsSync(C.DATA_DIR)) fs.mkdirSync(C.DATA_DIR, { recursive: true });

  cleanOrphanTmp();
  if (fs.existsSync(MIGRATION_PENDING_PATH)) {
    recoverFromMarker(MIGRATION_PENDING_PATH, SEALED_PATH, PLAINTEXT_PATH);
  }
  if (fs.existsSync(UNSEAL_PENDING_PATH)) {
    recoverFromMarker(UNSEAL_PENDING_PATH, PLAINTEXT_PATH, SEALED_PATH);
  }

  _refuseModeMismatch();

  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();

  if (mode === "required") {
    var passphraseSource = require("./passphrase-source");
    var hasSealed = fs.existsSync(SEALED_PATH);
    if (hasSealed) {
      log("Unsealing vault.key.sealed...");
      var sealedBytes = fs.readFileSync(SEALED_PATH);
      var passphrase = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
      var plaintextBuf;
      try { plaintextBuf = await b.vaultWrap.unwrap(sealedBytes, passphrase); }
      catch (e) {
        logErr("FATAL: passphrase rejected or sealed file corrupted (" + e.message + ")");
        process.exit(1);
      }
      keys = JSON.parse(plaintextBuf.toString("utf8"));
      currentPassphrase = passphrase;
      log("Unsealed successfully.");
    } else {
      log("First run with VAULT_PASSPHRASE_MODE=required — generating wrapped keypair...");
      var newPp = await passphraseSource.getPassphrase({ prompt: "Choose a vault passphrase (loss = data loss, store it safely): " });
      keys = b.crypto.generateEncryptionKeyPair();
      var sealed = await b.vaultWrap.wrap(JSON.stringify(keys, null, 2), newPp);
      fs.writeFileSync(SEALED_TMP_PATH, sealed, { mode: 0o600 });
      try {
        var fd = fs.openSync(SEALED_TMP_PATH, "r+");
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      } catch (_e) { /* fsync best-effort across platforms */ }
      fs.renameSync(SEALED_TMP_PATH, SEALED_PATH);
      fsyncDataDir();
      currentPassphrase = newPp;
      log("Generated and sealed new vault keypair (ML-KEM-1024 + P-384 hybrid).");
    }
  } else {
    // Plaintext mode — sync read suffices.
    loadKeysSync();
  }

  initialized = true;
}

// ---- seal — produces 0xE2 envelope via b.crypto.encrypt ----

function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  var k = keys || loadKeysSync();
  return VAULT_PREFIX + b.crypto.encrypt(String(plaintext), k);
}

// ---- unseal — dispatches on envelope magic ----
// b.crypto.decrypt explicitly rejects 0xE1 envelopes (see lib/vendor/
// blamejs/lib/crypto.js:756). lib/legacy-envelope-migrate runs at boot
// to convert all 0xE1 → 0xE2, but lib/db.js loads db.key.enc BEFORE
// the migration runs — so this wrapper still needs the legacy path
// during the migration window. After every operator has cleared their
// backlog, delete the 0xE1 branch.

function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  var k = keys || loadKeysSync();
  var payload = String(value).substring(VAULT_PREFIX.length);
  var first = Buffer.from(payload.substring(0, 4), "base64")[0];
  if (first === 0xE1) return hermitstashCrypto.decrypt(payload, k);
  return b.crypto.decrypt(payload, k);
}

function getKeysJson() {
  if (!keys) throw new Error("vault not initialized — call vault.init() before requesting keys");
  return JSON.stringify(keys, null, 2);
}

function getCurrentPassphrase() { return currentPassphrase; }

module.exports = {
  init: init,
  seal: seal,
  unseal: unseal,
  getKeysJson: getKeysJson,
  getCurrentPassphrase: getCurrentPassphrase,
  _resetForTest: function () { keys = null; initialized = false; currentPassphrase = null; },
  _getKeysForTest: function () { return keys; },
};
