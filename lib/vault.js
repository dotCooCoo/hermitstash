/**
 * The vault layer: orchestration around the framework's own, adding the
 * crash-recovery markers for the operator CLIs that set up, remove and rotate
 * a passphrase, the VAULT_PASSPHRASE_MODE mapping, and a fallback for the
 * older envelope format.
 *
 * That fallback covers one window: lib/db.js reads db.key.enc before the boot
 * migration has converted it. Delete the branch once no deployment can still
 * be holding an unconverted file.
 *
 * seal and unseal stay synchronous because hundreds of call sites are, module
 * require time included. The bootstrap awaits init() once and everything after
 * it runs against the cache.
 */
// codebase-patterns:allow-file raw-process-env — vault is the boot-time mirror layer for legacy VAULT_PASSPHRASE_* → BLAMEJS_VAULT_PASSPHRASE_* env vars; precedes safeEnv schema initialization.
// codebase-patterns:allow-file process-exit — vault is the boot-fatal layer; every exit point refuses to serve traffic on unrecoverable state (corrupt key, mode/state mismatch, missing data dir).
// codebase-patterns:allow-file console-direct — vault runs before logger is initialized (logger depends on env/safeEnv/vault chain); direct stdout/stderr emission is the only sink available at this stage.
// codebase-patterns:allow-file inline-require — passphrase-source loads lazily after env-mirroring runs; importing at top would break the BLAMEJS_VAULT_PASSPHRASE_* mirror order.
"use strict";

var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var bCrypto = require("./crypto");
var C = require("./constants");
var safeLog = require("./safe-log");

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
// logErr routes every message through the credential redactor (CWE-532 barrier):
// a structural crypto/fs error that ever interpolates a credential-shaped substring
// (bearer token, URL userinfo, key=secret) is scrubbed before it reaches stderr. Raw
// key-byte leaks cannot be pattern-matched and are handled at their source instead —
// the key-parse/unwrap catches log only a generic message + non-secret code.
function logErr(msg) { console.error("[vault] " + b.redact.redactText(String(msg))); }

function fsyncDataDir() { b.atomicFile.fsyncDir(C.DATA_DIR); }

// TOCTOU/symlink-safe read of a recovery marker / target file we manage
// ourselves (boot recovery + vault-key load) — shared with pem-seal.js +
// vault-passphrase-ops.js via lib/safe-read.
var _safeReadRecovery = require("./secret-read").safeReadSecretFile;

// ---- HS marker recovery (setup / remove tool crash safety) ----

function cleanOrphanTmp() {
  if (nodeFs.existsSync(SEALED_TMP_PATH)) {
    try {
      nodeFs.unlinkSync(SEALED_TMP_PATH);
      log("Cleaned orphan vault.key.sealed.tmp from a previous crash");
    } catch (e) {
      logErr("Failed to clean orphan vault.key.sealed.tmp: " + e.message);
    }
  }
}

function recoverFromMarker(markerPath, targetFilePath, otherFilePath) {
  var marker;
  try { marker = b.safeJson.parse(_safeReadRecovery(markerPath, { encoding: "utf8" }), { maxBytes: b.constants.BYTES.mib(1) }); }
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

  var targetExists = nodeFs.existsSync(targetFilePath);
  var otherExists = nodeFs.existsSync(otherFilePath);

  if (!targetExists) {
    nodeFs.unlinkSync(markerPath);
    log("Recovery: marker without target file — discarded marker, continuing with existing state");
    return;
  }
  var actualSha3 = b.crypto.sha3Hash(_safeReadRecovery(targetFilePath));
  if (actualSha3 !== marker.sealedSha3) {
    logErr("FATAL: " + targetFilePath + " hash does not match migration marker.");
    logErr("  Expected: " + marker.sealedSha3);
    logErr("  Actual:   " + actualSha3);
    logErr("Possible tampering between crash and restart. Investigate manually before continuing.");
    process.exit(1);
  }
  if (otherExists) {
    try {
      nodeFs.unlinkSync(otherFilePath);
      log("Recovery: completed migration by unlinking " + otherFilePath);
      fsyncDataDir();
    } catch (e) {
      logErr("FATAL: failed to unlink " + otherFilePath + " during recovery: " + e.message);
      process.exit(1);
    }
  }
  nodeFs.unlinkSync(markerPath);
  fsyncDataDir();
  log("Recovery: migration marker cleared — boot can proceed");
}

// ---- HS rotation marker recovery (vault-key-rotate.js crash safety) ----

function _hashDirListing(dirPath) {
  var names = nodeFs.readdirSync(dirPath).slice().sort();
  return b.crypto.sha3Hash(names.join("\n"));
}

function _readRotationMarker() {
  var raw;
  try { raw = _safeReadRecovery(ROTATION_PENDING_PATH, { encoding: "utf8" }); }
  catch (e) {
    logErr("FATAL: rotation-pending marker at " + ROTATION_PENDING_PATH + " is unreadable: " + e.message);
    logErr("Manually resolve: inspect " + DATA_ROTATING_PATH + " and " + DATA_DIR_PATH + ", then retry.");
    process.exit(1);
  }
  var marker;
  try { marker = b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) }); } catch (e) {
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
  var hasMarker = nodeFs.existsSync(ROTATION_PENDING_PATH);
  var hasRotating = nodeFs.existsSync(DATA_ROTATING_PATH);
  var hasData = nodeFs.existsSync(DATA_DIR_PATH);

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
    try { nodeFs.rmSync(DATA_ROTATING_PATH, { recursive: true, force: true }); }
    catch (e) {
      logErr("FATAL: could not remove stale " + DATA_ROTATING_PATH + ": " + e.message);
      logErr("Manually delete it, then restart.");
      process.exit(1);
    }
    nodeFs.unlinkSync(ROTATION_PENDING_PATH);
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
    // Atomic dir rename with Windows-transient-lock retry (CWE-367-safe commit).
    b.atomicFile.renameWithRetry(DATA_ROTATING_PATH, DATA_DIR_PATH);
    nodeFs.unlinkSync(ROTATION_PENDING_PATH);
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
    nodeFs.unlinkSync(ROTATION_PENDING_PATH);
    fsyncDataDir();
  }
}

// ---- Mode-vs-state guards (HS keeps its own framing of the failure modes) ----

function _refuseModeMismatch() {
  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  var hasPlaintext = nodeFs.existsSync(PLAINTEXT_PATH);
  var hasSealed = nodeFs.existsSync(SEALED_PATH);
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
  if (nodeFs.existsSync(PLAINTEXT_PATH)) {
    var loaded;
    try { loaded = b.safeJson.parse(_safeReadRecovery(PLAINTEXT_PATH, { encoding: "utf8" }), { maxBytes: b.constants.BYTES.mib(1) }); }
    catch (e) {
      // Never interpolate e.message/e.stack here. A JSON.parse SyntaxError of a
      // corrupted vault.key echoes a window of the file's bytes, and that file is
      // dominated by the ML-KEM-1024 + P-384 PRIVATE keys — logging the parser
      // detail would leak key material to stderr (CWE-532). fs error codes are
      // safe to surface; the SyntaxError text is not.
      logErr("FATAL: Vault key file at " + PLAINTEXT_PATH + " is corrupted or not valid JSON (parser detail suppressed to avoid logging key material). Restore data/vault.key from backup, then restart.");
      if (e && e.code) logErr("  fs error code: " + e.code);
      process.exit(1);
    }
    if (!loaded.ecPublicKey || !loaded.ecPrivateKey || !loaded.publicKey || !loaded.privateKey) {
      logErr("FATAL: Vault key file is missing required ML-KEM-1024 + P-384 fields.");
      logErr("Run the migration tool to upgrade your vault keys, then restart.");
      process.exit(1);
    }
    keys = loaded;
  } else {
    // Minting a keypair is only ever right on a true first run. An existing
    // db.key.enc or database file was sealed with a keypair that is now
    // missing — a lost or mismatched vault.key, not a fresh install — and a new
    // keypair here would let the unseal fail and overwrite the only sealed copy
    // of the real database key. Refuse, so the operator can restore the match.
    if (nodeFs.existsSync(C.PATHS.DB_KEY_ENC) || nodeFs.existsSync(C.PATHS.DB_ENC)) {
      logErr("FATAL: data/vault.key is missing but an encrypted database already exists.");
      logErr("This signals a lost or mismatched vault key — NOT a fresh install.");
      logErr("Restore the matching data/vault.key from backup, then restart. Refusing to mint a new keypair (it would strand the existing database).");
      process.exit(1);
    }
    keys = b.crypto.generateEncryptionKeyPair();
    b.atomicFile.writeSync(PLAINTEXT_PATH, JSON.stringify(keys, null, 2), { fileMode: 0o600 });
    log("Vault keypair generated at " + PLAINTEXT_PATH + " (ML-KEM-1024 + P-384 hybrid)");
  }
  initialized = true;
  return keys;
}

// ---- init() — runs HS recovery, then loads / wraps keys ----

async function init() {
  if (initialized) {
    // The synchronous first-seal path marks the vault initialized without ever
    // calling the framework's init, which leaves its per-deployment salt
    // unavailable and breaks session creation. So init is always awaited at
    // least once; it short-circuits on its own, so this is idempotent.
    var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
    try {
      await b.vault.init({ dataDir: C.DATA_DIR, mode: mode === "required" ? "wrapped" : "plaintext" });
    } catch (e) {
      // b.vault.init re-reads and re-parses the same on-disk keypair through the
      // framework's JSON parser, whose error text can embed raw key bytes (CWE-532).
      // Suppress the parser/framework detail; log only the non-secret code + exit.
      logErr("FATAL: framework vault init failed (code: " + safeLog.code(e) + "). Error text suppressed to avoid logging key material.");
      process.exit(1);
    }
    return;
  }

  // v1.9.3: rotation recovery must run BEFORE any filesystem operation
  // that assumes DATA_DIR exists.
  recoverFromRotationMarker();

  if (!nodeFs.existsSync(C.DATA_DIR)) nodeFs.mkdirSync(C.DATA_DIR, { recursive: true });

  cleanOrphanTmp();
  if (nodeFs.existsSync(MIGRATION_PENDING_PATH)) {
    recoverFromMarker(MIGRATION_PENDING_PATH, SEALED_PATH, PLAINTEXT_PATH);
  }
  if (nodeFs.existsSync(UNSEAL_PENDING_PATH)) {
    recoverFromMarker(UNSEAL_PENDING_PATH, PLAINTEXT_PATH, SEALED_PATH);
  }

  _refuseModeMismatch();

  var mode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();

  // Must happen before the wrapped-mode flow reads the passphrase: both
  // readers strip the variable after reading it, so whichever runs first
  // destroys the source, and the copy has to exist under the framework's name
  // by then or its init sees nothing.
  if (mode === "required") {
    if (process.env.VAULT_PASSPHRASE_FILE && !process.env.BLAMEJS_VAULT_PASSPHRASE_FILE) {
      process.env.BLAMEJS_VAULT_PASSPHRASE_FILE = process.env.VAULT_PASSPHRASE_FILE;
    }
    if (process.env.VAULT_PASSPHRASE && !process.env.BLAMEJS_VAULT_PASSPHRASE) {
      process.env.BLAMEJS_VAULT_PASSPHRASE = process.env.VAULT_PASSPHRASE;
    }
    if (process.env.VAULT_PASSPHRASE_SOURCE && !process.env.BLAMEJS_VAULT_PASSPHRASE_SOURCE) {
      process.env.BLAMEJS_VAULT_PASSPHRASE_SOURCE = process.env.VAULT_PASSPHRASE_SOURCE;
    }
  }

  if (mode === "required") {
    var passphraseSource = require("./passphrase-source");
    var hasSealed = nodeFs.existsSync(SEALED_PATH);
    if (hasSealed) {
      log("Unsealing vault.key.sealed...");
      var sealedBytes = _safeReadRecovery(SEALED_PATH);
      var passphrase = await passphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
      var plaintextBuf;
      try { plaintextBuf = await b.vaultWrap.unwrap(sealedBytes, passphrase); }
      catch (e) {
        logErr("FATAL: passphrase rejected or sealed file corrupted (" + e.message + ")");
        process.exit(1);
      }
      // Wrap the parse: plaintextBuf is the freshly Argon2id-unwrapped keypair
      // (ML-KEM-1024 + P-384 private keys). An uncaught SyntaxError here would
      // propagate out of init() to callers that log e.message/e.stack and echo
      // decrypted key bytes (CWE-532). Suppress the parser detail; the sealed
      // file is corrupt if this fails.
      try { keys = b.safeJson.parse(plaintextBuf.toString("utf8"), { maxBytes: b.constants.BYTES.mib(1) }); }
      catch (_e) {
        logErr("FATAL: unsealed vault key did not decode to valid JSON (parser detail suppressed to avoid logging key material). The sealed file may be corrupted; restore from backup.");
        process.exit(1);
      }
      currentPassphrase = passphrase;
      log("Unsealed successfully.");
    } else {
      log("First run with VAULT_PASSPHRASE_MODE=required — generating wrapped keypair...");
      var newPp = await passphraseSource.getPassphrase({ prompt: "Choose a vault passphrase (loss = data loss, store it safely): " });
      keys = b.crypto.generateEncryptionKeyPair();
      var sealed = await b.vaultWrap.wrap(JSON.stringify(keys, null, 2), newPp);
      // Atomic write (temp + fsync + rename-with-retry + parent-dir fsync) — a
      // torn write here would lose the only copy of the sealed vault key. The
      // boot-recovery cleanup of a stray SEALED_TMP_PATH (init) still handles a
      // legacy half-write from a pre-upgrade crash.
      b.atomicFile.writeSync(SEALED_PATH, sealed, { fileMode: 0o600 });
      currentPassphrase = newPp;
      log("Generated and sealed new vault keypair (ML-KEM-1024 + P-384 hybrid).");
    }
  } else {
    // Plaintext mode — sync read suffices.
    loadKeysSync();
  }

  // So the framework primitives that seal directly share this keypair. Both
  // read the same file, so initialising after the load here picks up the same
  // bytes; the passphrase was mirrored earlier in this function for it to find.
  try {
    await b.vault.init({ dataDir: C.DATA_DIR, mode: mode === "required" ? "wrapped" : "plaintext" });
  } catch (e) {
    // Same posture as the initialized-early-return path above: b.vault.init
    // re-parses the decrypted keypair via the framework parser, whose error can
    // carry raw key bytes (CWE-532). Log only the non-secret code and exit.
    logErr("FATAL: framework vault init failed (code: " + safeLog.code(e) + "). Error text suppressed to avoid logging key material.");
    process.exit(1);
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

// Dispatches on the envelope's magic byte. The framework refuses the older
// format outright, and the boot migration converts every file that carries it —
// but lib/db.js reads db.key.enc before that runs, so the legacy path survives
// for exactly that one file, and can go once no deployment still holds one.

function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  var k = keys || loadKeysSync();
  var payload = String(value).substring(VAULT_PREFIX.length);
  var first = Buffer.from(payload.substring(0, 4), "base64")[0];
  if (first === 0xE1) return bCrypto.decrypt(payload, k);
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
