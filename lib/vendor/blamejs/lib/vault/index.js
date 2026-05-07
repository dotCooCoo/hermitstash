"use strict";
/**
 * Vault — sealed keystore for the framework's encryption keys.
 *
 * Holds the ML-KEM-1024 + P-384 hybrid keypair used by every other framework
 * subsystem that calls vault.seal() / vault.unseal() (db field encryption,
 * session storage, audit log signing, etc.). Keys never leave the process
 * after init() in any decrypted form except via the vault.seal/unseal API.
 *
 * Modes (default is 'wrapped' — highest-security; 'plaintext' is opt-out
 * with explicit boot warning per the framework's modernity stance):
 *
 *   wrapped    — vault.key.sealed file, passphrase-derived AEAD wrap (lib/vault-wrap.js).
 *                Argon2id → SHAKE256 → XChaCha20-Poly1305. Default.
 *   plaintext  — vault.key file (JSON, mode 0o600). For development only.
 *                Emits console.warn at boot. Opt-out only.
 *
 * Two-API contract (sync seal/unseal, async init):
 *
 *   await vault.init({ dataDir, mode? })   ← call once at app bootstrap
 *   vault.seal(value)                      ← sync, post-init
 *   vault.unseal(value)                    ← sync, post-init
 *
 * Why two APIs: seal/unseal have hundreds of call sites across a typical app,
 * many at module-require time. Making them async would require an invasive
 * refactor of every consumer. Instead, the bootstrap awaits init() once, then
 * everything runs synchronously against the in-process key cache.
 *
 * Sealed-value format: "vault:" prefix + base64 envelope from lib/crypto.js.
 * Old envelopes always remain readable (envelope versioning); new writes use
 * the active KEM/CIPHER/KDF.
 */
var fs = require("fs");
var path = require("path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var { generateEncryptionKeyPair, encrypt, decrypt } = require("../crypto");
var { boot } = require("../log");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var observability = require("../observability");
var vaultPassphraseSource = require("./passphrase-source");
var vaultWrap = require("./wrap");
var { defineClass } = require("../framework-error");

// VaultError — thrown by init() for fatal boot-time conditions
// (corrupt sealed file, schema mismatch, mode/state conflicts). The
// CLI / app entry point catches it and exits; lib code never calls
// process.exit() unilaterally.
var VaultError = defineClass("VaultError", { alwaysPermanent: true });

var VAULT_PREFIX = C.VAULT_PREFIX;

// Module-local cache populated by init().
var keys = null;
var initialized = false;
// Passphrase retained post-init (best-effort) for vault rotation +
// backup re-wrap. Already in JS heap during unwrap; retaining doesn't
// change the threat model meaningfully.
var currentPassphrase = null;
// Resolved paths (set by init based on dataDir option)
var paths = null;
var currentMode = null;

var log = boot("vault");

function resolvePaths(dataDir) {
  return {
    dataDir:           dataDir,
    plaintext:         path.join(dataDir, "vault.key"),
    sealed:            path.join(dataDir, "vault.key.sealed"),
    derivedHashSalt:   path.join(dataDir, "vault.derived-hash-salt"),
  };
}

// derivedHashSalt — per-deployment salt for crypto-field
// derivedHashes (D-H1). Pre-v0.8.42 the deterministic
// sha3(namespace + plaintext) shape allowed cross-deployment
// rainbow + cross-table correlation; binding a 32-byte
// per-deployment salt closes that class without breaking
// indexed-lookup determinism inside one deployment. The salt
// persists across vault rotations (different file from vault.key)
// so existing derivedHash columns survive a passphrase change.
function _readOrCreateDerivedHashSalt() {
  if (!paths) {
    throw new VaultError("vault/not-initialized",
      "vault.derivedHashSalt() requires init()");
  }
  if (fs.existsSync(paths.derivedHashSalt)) {
    var raw = atomicFile.readSync(paths.derivedHashSalt);
    if (raw.length !== 32) {                                                       // allow:raw-byte-literal — 32-byte (256-bit) salt
      throw new VaultError("vault/derived-hash-salt-corrupted",
        "vault.derived-hash-salt must be exactly 32 bytes; got " + raw.length);
    }
    return raw;
  }
  var nodeCrypto = require("node:crypto");
  var salt = nodeCrypto.randomBytes(32);                                           // allow:raw-byte-literal — 32-byte salt
  atomicFile.writeSync(paths.derivedHashSalt, salt, { fileMode: 0o600 });
  log("generated per-deployment derivedHash salt at " + paths.derivedHashSalt);
  return salt;
}

var _cachedDerivedHashSalt = null;
function getDerivedHashSalt() {
  if (_cachedDerivedHashSalt === null) {
    _cachedDerivedHashSalt = _readOrCreateDerivedHashSalt();
  }
  return _cachedDerivedHashSalt;
}

// ---- Init dispatch ----

async function init(opts) {
  if (initialized) return;
  opts = opts || {};

  if (!opts.dataDir) {
    throw new VaultError("vault/bad-init", "vault.init({ dataDir }) is required");
  }

  var mode = (opts.mode || "wrapped").toLowerCase();
  if (mode !== "wrapped" && mode !== "plaintext") {
    throw new VaultError("vault/bad-mode",
      "vault.init: mode must be 'wrapped' or 'plaintext', got: " + opts.mode);
  }
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  if (!fs.existsSync(paths.dataDir)) {
    fs.mkdirSync(paths.dataDir, { recursive: true });
  }

  // Sweep tmp files left behind by a previously-crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = fs.existsSync(paths.plaintext);
  var hasSealed    = fs.existsSync(paths.sealed);

  // Refuse to guess when both files coexist
  if (hasPlaintext && hasSealed) {
    throw new VaultError("vault/both-files-exist",
      "both vault.key and vault.key.sealed exist in " + paths.dataDir +
      " — delete the one you do NOT want to keep, then restart");
  }

  // Mode-vs-state mismatches
  if (hasSealed && mode === "plaintext") {
    throw new VaultError("vault/mode-mismatch",
      "vault.key.sealed exists but vault.init({ mode: 'plaintext' }) was requested — " +
      "either run with mode: 'wrapped', or remove the sealed file (after migration)");
  }
  if (hasPlaintext && mode === "wrapped") {
    throw new VaultError("vault/mode-mismatch",
      "vault.key (plaintext) exists but vault.init({ mode: 'wrapped' }) was requested — " +
      "either run with mode: 'plaintext', or migrate the key to a wrapped form");
  }

  if (mode === "wrapped") {
    if (hasSealed) await initWrapped();
    else await initFirstRunWrapped();
  } else {
    // mode === "plaintext"
    log.warn("WARNING: running in PLAINTEXT mode — vault.key is unprotected on disk.");
    log.warn("         Use mode: 'wrapped' (default) for any deployment that holds real data.");
    log.warn("         See https://github.com/blamejs/blamejs#vault-modes for details.");
    initPlaintext();
  }

  initialized = true;
}

function initPlaintext() {
  if (fs.existsSync(paths.plaintext)) {
    var loaded;
    try {
      loaded = safeJson.parse(atomicFile.readSync(paths.plaintext), {
        schema: {
          type: "object",
          required: ["publicKey", "privateKey", "ecPublicKey", "ecPrivateKey"],
          properties: {
            publicKey:    { type: "string" },
            privateKey:   { type: "string" },
            ecPublicKey:  { type: "string" },
            ecPrivateKey: { type: "string" },
          },
        },
      });
    } catch (e) {
      throw new VaultError("vault/key-corrupt",
        "vault.key corrupted, unreadable, or schema-invalid at " + paths.plaintext +
        " — " + e.message +
        " — all sealed data requires the original key; restore from backup, then restart");
    }
    keys = loaded;
    return;
  }
  // First run, plaintext mode
  keys = generateEncryptionKeyPair();
  atomicFile.writeSync(paths.plaintext, JSON.stringify(keys, null, 2), { fileMode: 0o600 });
  log("plaintext vault keypair generated at " + paths.plaintext);
}

async function initWrapped() {
  log("unsealing vault.key.sealed...");
  var sealedBytes;
  try {
    sealedBytes = atomicFile.readSync(paths.sealed);
  } catch (e) {
    throw new VaultError("vault/sealed-unreadable",
      "cannot read " + paths.sealed + ": " + e.message);
  }

  var passphrase;
  try {
    passphrase = await vaultPassphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
  } catch (e) {
    throw new VaultError("vault/passphrase-error", e.message);
  }

  var plaintextJson;
  var plaintextBuf;
  try {
    plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase);
    plaintextJson = plaintextBuf.toString("utf8");
  } catch (e) {
    throw new VaultError("vault/unwrap-failed",
      "passphrase rejected or sealed file corrupted (" + e.message + ")");
  } finally {
    // The Buffer holding the unwrapped key JSON is no longer needed once
    // toString has copied the bytes into plaintextJson. The string itself
    // is referenced by the JSON parser below; can't be zeroed (V8 strings
    // are GC-managed). secureZero on the Buffer at least removes one
    // copy of the secret from the heap.
    if (plaintextBuf) safeBuffer.secureZero(plaintextBuf);
  }
  currentPassphrase = passphrase;

  try {
    keys = safeJson.parse(plaintextJson, {
      schema: {
        type: "object",
        required: ["publicKey", "privateKey", "ecPublicKey", "ecPrivateKey"],
        properties: {
          publicKey:    { type: "string" },
          privateKey:   { type: "string" },
          ecPublicKey:  { type: "string" },
          ecPrivateKey: { type: "string" },
        },
      },
    });
  } catch (e) {
    throw new VaultError("vault/unwrapped-invalid",
      "unwrapped vault key invalid: " + e.message);
  }
  log("unsealed successfully.");
}

async function initFirstRunWrapped() {
  log("first run with mode: 'wrapped' — generating wrapped keypair...");

  var passphrase;
  try {
    passphrase = await vaultPassphraseSource.getPassphrase({
      prompt: "Choose a vault passphrase (loss = data loss, store it safely): ",
    });
  } catch (e) {
    throw new VaultError("vault/passphrase-error", e.message);
  }
  currentPassphrase = passphrase;

  keys = generateEncryptionKeyPair();
  var plaintextJson = JSON.stringify(keys, null, 2);
  var sealed;
  try {
    sealed = await vaultWrap.wrap(plaintextJson, passphrase);
  } catch (e) {
    throw new VaultError("vault/wrap-failed",
      "failed to wrap new vault key: " + e.message);
  }

  // Atomic write via the framework's atomic-file primitive (temp + fsync +
  // rename + dir fsync — same flow this code used to inline manually).
  atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });

  log("generated and sealed new vault keypair (ML-KEM-1024 + P-384 hybrid)");
}

// ---- Sync API — operates against the populated cache ----

function _requireInit() {
  if (!initialized) {
    throw new VaultError("vault/not-initialized",
      "vault.init() must be awaited before vault.seal/unseal/getKeysJson");
  }
}

function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  _requireInit();
  return observability.tap("vault.seal", null, function () {
    return VAULT_PREFIX + encrypt(String(plaintext), keys);
  });
}

function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  _requireInit();
  return observability.tap("vault.unseal", null, function () {
    var payload = String(value).substring(VAULT_PREFIX.length);
    return decrypt(payload, keys);
  });
}

function getKeysJson() {
  _requireInit();
  return JSON.stringify(keys, null, 2);
}

function getCurrentPassphrase() {
  return currentPassphrase;
}

function getMode() {
  return currentMode;
}

var vaultAad = require("../vault-aad");

var sealPemFileModule = require("./seal-pem-file");

// _zeroizeAndReplace — best-effort secureZero of prior in-memory keys
// before a swap. V8 strings can't be reliably overwritten (string
// interning + GC managed), so the pre-swap pass converts each PEM
// string to a Buffer, secureZeros the Buffer, and rebinds the
// property to "ZEROED" before the new keys land. The string copy
// inside V8 may still linger until GC; this just removes the
// largest-window heap copy (the ones held by `keys`).
function _zeroizeAndReplace(replacement) {
  if (!keys) { keys = replacement; return; }
  Object.keys(keys).forEach(function (k) {
    var v = keys[k];
    if (typeof v === "string" && v.length > 0) {
      try {
        var buf = Buffer.from(v, "utf8");
        safeBuffer.secureZero(buf);
      } catch (_e) { /* best-effort */ }
      keys[k] = "ZEROED";
    }
  });
  keys = replacement;
}

module.exports = {
  init:                  init,
  seal:                  seal,
  unseal:                unseal,
  getDerivedHashSalt:    getDerivedHashSalt,
  _zeroizeAndReplace:    _zeroizeAndReplace,
  aad:                   vaultAad,
  getKeysJson:           getKeysJson,
  getCurrentPassphrase:  getCurrentPassphrase,
  getMode:               getMode,
  VaultError:            VaultError,
  sealPemFile:           sealPemFileModule.sealPemFile,
  SealPemFileError:      sealPemFileModule.SealPemFileError,
  // Testing helpers — not part of the public contract
  _resetForTest:         function () {
    if (currentPassphrase) safeBuffer.secureZero(currentPassphrase);
    keys = null; initialized = false; currentPassphrase = null; paths = null; currentMode = null;
  },
  _getKeysForTest:       function () { return keys; },
  _getPathsForTest:      function () { return paths; },
};
