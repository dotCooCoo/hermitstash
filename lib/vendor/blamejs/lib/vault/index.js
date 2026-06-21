"use strict";
/**
 * @module b.vault
 * @featured true
 * @nav    Crypto
 * @title  Vault
 *
 * @intro
 *   Sealed keystore that anchors every other framework subsystem holding
 *   secrets at rest: db field encryption, encrypted session storage,
 *   audit-log signing keys, OAuth refresh tokens, anything that flows
 *   through `b.vault.seal` / `b.vault.unseal`. The vault is the single
 *   trust root for the framework — rotate it and everything sealed under
 *   the old keys re-seals as part of the same operation.
 *
 *   Keys held: an ML-KEM-1024 + ECDH P-384 hybrid keypair plus a
 *   per-deployment derivedHash salt. After `init()` the keypair never
 *   leaves the process in any decrypted form except via the seal /
 *   unseal API.
 *
 *   Modes (`wrapped` is the default; `plaintext` is opt-out with an
 *   explicit boot warning per the framework's modernity stance):
 *
 *   - `wrapped`   — `vault.key.sealed` file, passphrase-derived AEAD
 *                   wrap (Argon2id → SHAKE256 → XChaCha20-Poly1305).
 *                   The plaintext keypair never lands on disk.
 *   - `plaintext` — `vault.key` JSON at mode `0o600`. Development only.
 *                   Emits a `console.warn` at every boot.
 *
 *   Two-API contract: bootstrap awaits `init()` once, and every other
 *   consumer (often at module-require time across hundreds of call
 *   sites) runs synchronously against the in-process key cache.
 *
 *   ```js
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "wrapped" });
 *   var sealed = b.vault.seal("4111-1111-1111-1111");
 *   sealed.startsWith("vault:");      // → true
 *   b.vault.unseal(sealed);           // → "4111-1111-1111-1111"
 *   ```
 *
 *   Rotating the KEK (passphrase change, sealed-blob refresh,
 *   hardware-token swap) is a separate primitive — `b.vaultRotate.rotate`
 *   walks every sealed column under the old keypair and re-seals it
 *   under the new one with batched commits and a round-trip verify.
 *   The vault module owns the in-process cache; the rotator owns the
 *   on-disk data sweep.
 *
 *   ```js
 *   // Wrapped-mode bootstrap (first run): the vault generates an
 *   // ML-KEM-1024 + P-384 keypair, wraps it under the operator's
 *   // passphrase, and writes vault.key.sealed atomically.
 *   process.env.BLAMEJS_VAULT_PASSPHRASE = "S0meStrongPassphr@se!";
 *   await b.vault.init({ dataDir: "/var/lib/blamejs" });
 *   b.vault.getMode();                // → "wrapped"
 *   ```
 *
 *   Sealed-value format: `"vault:"` prefix + base64 envelope produced
 *   by `b.crypto.encrypt`. Old envelopes always remain readable
 *   (envelope versioning); new writes use whichever KEM / CIPHER / KDF
 *   the active framework version pins as default.
 *
 * @card
 *   Sealed keystore that anchors every other framework subsystem holding secrets at rest: db field encryption, encrypted session storage, audit-log signing keys, OAuth refresh tokens, anything that flows through `b.vault.seal` / `b.vault.unseal`.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var { generateEncryptionKeyPair, encrypt, decrypt } = require("../crypto");
var { boot } = require("../log");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var observability = require("../observability");
var frameworkFiles = require("../framework-files");
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
    plaintext:         nodePath.join(dataDir, frameworkFiles.fileName("vaultKey")),
    sealed:            nodePath.join(dataDir, frameworkFiles.fileName("vaultKey") + ".sealed"),
    derivedHashSalt:   nodePath.join(dataDir, "vault.derived-hash-salt"),
    derivedHashMacKey: nodePath.join(dataDir, "vault.derived-hash-mac.sealed"),
  };
}

// derivedHashSalt — per-deployment salt for crypto-field
// derivedHashes. Pre-v0.8.42 the deterministic
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
  if (nodeFs.existsSync(paths.derivedHashSalt)) {
    var raw = atomicFile.readSync(paths.derivedHashSalt);
    if (raw.length !== 32) {                                                       // 32-byte (256-bit) salt
      throw new VaultError("vault/derived-hash-salt-corrupted",
        "vault.derived-hash-salt must be exactly 32 bytes; got " + raw.length);
    }
    return raw;
  }
  var nodeCrypto = require("node:crypto");
  var salt = nodeCrypto.randomBytes(32);                                           // 32-byte salt
  atomicFile.writeSync(paths.derivedHashSalt, salt, { fileMode: 0o600 });
  log("generated per-deployment derivedHash salt at " + paths.derivedHashSalt);
  return salt;
}

var _cachedDerivedHashSalt = null;
/**
 * @primitive b.vault.getDerivedHashSalt
 * @signature b.vault.getDerivedHashSalt()
 * @since     0.8.42
 * @related   b.vault.init, b.vault.seal
 *
 * Returns the 32-byte per-deployment salt used by crypto-field's
 * derivedHash columns. The salt is generated once on first init,
 * persisted at `vault.derived-hash-salt` (mode `0o600`) inside
 * `dataDir`, and read back on subsequent boots. It survives vault
 * KEK rotations — different file from `vault.key.sealed` — so
 * indexed-lookup determinism for derivedHash columns holds across a
 * passphrase change.
 *
 * Why per-deployment: pre-v0.8.42 the deterministic
 * `sha3(namespace + plaintext)` shape allowed cross-deployment
 * rainbow tables and cross-table correlation between deployments
 * sharing a namespace. Binding a 32-byte salt closes that class
 * without losing the determinism inside a single deployment that
 * makes the index lookup possible.
 *
 * Throws `VaultError("vault/not-initialized")` if `init()` has not
 * been awaited yet. Throws `vault/derived-hash-salt-corrupted` if
 * the on-disk file exists but is not exactly 32 bytes.
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   var salt = b.vault.getDerivedHashSalt();
 *   salt.length;          // → 32
 *   Buffer.isBuffer(salt); // → true
 *
 *   // Same value on every call within a process — cached.
 *   b.vault.getDerivedHashSalt() === salt;  // → true
 */
function getDerivedHashSalt() {
  if (_cachedDerivedHashSalt === null) {
    _cachedDerivedHashSalt = _readOrCreateDerivedHashSalt();
  }
  return _cachedDerivedHashSalt;
}

// derivedHashMacKey — per-deployment SECRET key for crypto-field's
// keyed (hmac-shake256) derived-hash mode. Unlike the salt, this is
// SEALED at rest (vault.derived-hash-mac.sealed), so an attacker with
// disk access alone cannot recompute the keyed digest and correlate
// low-entropy plaintexts. Like the salt, it is keypair-bound and
// survives a passphrase-only rotation; an ENVELOPE rotation re-seals it
// because it is registered in rotate's additionalSealed sweep.
function _readOrCreateDerivedHashMacKey() {
  if (!paths) {
    throw new VaultError("vault/not-initialized",
      "vault.getDerivedHashMacKey() requires init()");
  }
  if (nodeFs.existsSync(paths.derivedHashMacKey)) {
    var sealed = atomicFile.readSync(paths.derivedHashMacKey, { encoding: "utf8" }).trim();
    var b64 = unseal(sealed);
    var key = Buffer.from(b64, "base64");
    if (key.length !== 32) {                                                        // 32-byte (256-bit) MAC key
      throw new VaultError("vault/derived-hash-mac-key-corrupted",
        "vault.derived-hash-mac key must unseal to exactly 32 bytes; got " + key.length);
    }
    return key;
  }
  var nodeCrypto = require("node:crypto");
  var raw = nodeCrypto.randomBytes(32);                                            // 32-byte MAC key
  atomicFile.writeSync(paths.derivedHashMacKey, seal(raw.toString("base64")), { fileMode: 0o600 });
  log("generated per-deployment derivedHash MAC key at " + paths.derivedHashMacKey);
  return raw;
}

var _cachedDerivedHashMacKey = null;
/**
 * @primitive b.vault.getDerivedHashMacKey
 * @signature b.vault.getDerivedHashMacKey()
 * @since     0.14.7
 * @related   b.vault.getDerivedHashSalt, b.cryptoField.registerTable
 *
 * Returns the 32-byte per-deployment SECRET key that backs crypto-
 * field's keyed (`hmac-shake256`) derived-hash mode. Generated once on
 * first use, SEALED at rest (`vault.derived-hash-mac.sealed`, mode
 * `0o600`) so disk access alone does not expose it, and re-sealed by an
 * envelope vault rotation. Distinct from `getDerivedHashSalt`, which is
 * a non-secret salt stored in plaintext.
 *
 * Throws `VaultError("vault/not-initialized")` before `init()`, or
 * `vault/derived-hash-mac-key-corrupted` if the sealed file does not
 * unseal to exactly 32 bytes.
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   var k = b.vault.getDerivedHashMacKey();
 *   k.length;           // → 32
 *   Buffer.isBuffer(k); // → true
 */
function getDerivedHashMacKey() {
  if (_cachedDerivedHashMacKey === null) {
    _cachedDerivedHashMacKey = _readOrCreateDerivedHashMacKey();
  }
  return _cachedDerivedHashMacKey;
}

// ---- Init dispatch ----

/**
 * @primitive b.vault.init
 * @signature b.vault.init(opts)
 * @since     0.1.0
 * @related   b.vault.seal, b.vault.unseal, b.vault.getMode, b.vaultRotate.rotate
 *
 * Bootstraps the vault. Call once at application startup before any
 * code path that reads sealed values from the database, opens the
 * encrypted session store, or signs audit-log entries. Subsequent
 * calls after a successful init are no-ops, so guard-rail wrappers
 * that re-call `init()` from worker entry points are safe.
 *
 * Mode dispatch:
 *
 * - `wrapped` (default) — if `vault.key.sealed` exists, prompts for the
 *   passphrase via `b.vaultPassphraseSource` and unwraps. If neither
 *   sealed nor plaintext file is present, generates a fresh keypair
 *   and wraps it under a freshly-prompted passphrase.
 * - `plaintext` — reads `vault.key` if present, generates a fresh
 *   keypair and writes it at mode `0o600` otherwise. Logs a `WARNING`
 *   line at every boot.
 *
 * Refuses to guess when both `vault.key` and `vault.key.sealed` exist
 * in `dataDir`, or when the requested mode mismatches the on-disk
 * shape (sealed file present but `mode: "plaintext"` requested, or
 * vice versa). Throws a `VaultError` in either case so the bootstrap
 * exits cleanly instead of silently picking one.
 *
 * @opts
 *   {
 *     dataDir: string,    // required — directory holding vault.key /
 *                         //            vault.key.sealed / derived-hash-salt
 *     mode:    string,    // "wrapped" (default) | "plaintext"
 *   }
 *
 * @example
 *   // Wrapped-mode bootstrap with passphrase from the env var
 *   // b.vaultPassphraseSource consults by default.
 *   process.env.BLAMEJS_VAULT_PASSPHRASE = "S0meStrongPassphr@se!";
 *   await b.vault.init({
 *     dataDir: "/var/lib/blamejs",
 *     mode:    "wrapped",
 *   });
 *   b.vault.getMode();   // → "wrapped"
 *
 *   // Re-calling init() after a successful boot is a no-op.
 *   await b.vault.init({ dataDir: "/var/lib/blamejs" });
 *   b.vault.getMode();   // → "wrapped"
 */
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

  if (!nodeFs.existsSync(paths.dataDir)) {
    nodeFs.mkdirSync(paths.dataDir, { recursive: true });
  }

  // Sweep tmp files left behind by a previously-crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = nodeFs.existsSync(paths.plaintext);
  var hasSealed    = nodeFs.existsSync(paths.sealed);

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
  if (nodeFs.existsSync(paths.plaintext)) {
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

/**
 * @primitive b.vault.seal
 * @signature b.vault.seal(plaintext)
 * @since     0.1.0
 * @related   b.vault.unseal, b.vaultRotate.rotate
 *
 * Synchronously encrypts `plaintext` under the in-process keypair and
 * returns a `"vault:"`-prefixed string suitable for storage in any
 * column declared sealed in the field-crypto schema. Called from
 * hundreds of call sites across a typical application — keep it sync.
 *
 * Idempotent on already-sealed input: a value that already starts
 * with the vault prefix is returned unchanged so seal-on-write paths
 * survive code that re-seals the same row twice. Empty / falsy input
 * passes through verbatim — there's nothing to encrypt and the
 * caller likely meant `null` to land in the column.
 *
 * Throws `VaultError("vault/not-initialized")` if `init()` has not
 * been awaited yet — the seal/unseal API is sync, but the keypair
 * cache it consults is populated by the async init.
 *
 * Sealed values from this primitive decrypt regardless of which
 * row / column / table they came from. Use `b.vault.aad.seal` for
 * AEAD-bound seals when copy-paste between rows is part of the
 * threat model.
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   var sealed = b.vault.seal("4111-1111-1111-1111");
 *   sealed.indexOf("vault:");        // → 0
 *
 *   // Idempotent: re-sealing returns the input unchanged.
 *   b.vault.seal(sealed) === sealed; // → true
 *
 *   // Falsy input is passed through verbatim.
 *   b.vault.seal("") === "";         // → true
 */
function seal(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(VAULT_PREFIX)) return plaintext;
  _requireInit();
  return observability.tap("vault.seal", null, function () {
    return VAULT_PREFIX + encrypt(String(plaintext), keys);
  });
}

/**
 * @primitive b.vault.unseal
 * @signature b.vault.unseal(value)
 * @since     0.1.0
 * @related   b.vault.seal
 *
 * Synchronously decrypts a `"vault:"`-prefixed string produced by
 * `b.vault.seal` and returns the plaintext. Idempotent on
 * non-sealed input: a value that does not start with the vault
 * prefix is returned unchanged so read paths that select a column
 * before knowing whether it's sealed don't have to branch.
 *
 * The envelope inside the prefix is versioned — values sealed under
 * older KEM / KDF / cipher choices remain readable across framework
 * upgrades. New seals always use the active algorithm set, so a
 * full read-write cycle migrates a row forward.
 *
 * Throws `VaultError("vault/not-initialized")` if `init()` has not
 * been awaited yet. Throws on AEAD-tag failure (corrupted ciphertext,
 * wrong keypair) — operators rotating keys validate the rotation
 * via `b.vaultRotate.verify` rather than catching here.
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   var sealed = b.vault.seal("hello");
 *   b.vault.unseal(sealed);          // → "hello"
 *
 *   // Non-sealed input passes through unchanged.
 *   b.vault.unseal("plain-string");  // → "plain-string"
 *   b.vault.unseal(null);            // → null
 */
function unseal(value) {
  if (!value || !String(value).startsWith(VAULT_PREFIX)) return value;
  _requireInit();
  return observability.tap("vault.unseal", null, function () {
    var payload = String(value).substring(VAULT_PREFIX.length);
    return decrypt(payload, keys);
  });
}

/**
 * @primitive b.vault.getKeysJson
 * @signature b.vault.getKeysJson()
 * @since     0.6.0
 * @related   b.vault.init, b.vaultRotate.rotate
 *
 * Returns the in-process keypair as a pretty-printed JSON string —
 * the same shape that lives on disk for `mode: "plaintext"` and
 * inside the wrapped envelope for `mode: "wrapped"`. Used by the
 * rotation pipeline to feed `oldKeys` into a fresh
 * `b.vaultRotate.rotate({ oldKeys, newKeys, ... })` call without
 * round-tripping through disk.
 *
 * The returned JSON has four properties: `publicKey`, `privateKey`
 * (ML-KEM-1024), `ecPublicKey`, `ecPrivateKey` (P-384). Operators
 * routing this through structured logging or telemetry must redact
 * — these are the production keys, not metadata.
 *
 * Throws `VaultError("vault/not-initialized")` if `init()` has not
 * been awaited yet.
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   var json = b.vault.getKeysJson();
 *   var keys = JSON.parse(json);
 *   Object.keys(keys).sort().join(",");
 *   // → "ecPrivateKey,ecPublicKey,privateKey,publicKey"
 */
function getKeysJson() {
  _requireInit();
  return JSON.stringify(keys, null, 2);
}

/**
 * @primitive b.vault.getCurrentPassphrase
 * @signature b.vault.getCurrentPassphrase()
 * @since     0.6.0
 * @related   b.vault.init, b.vaultPassphraseOps.changePassphrase, b.vaultRotate.rotate
 *
 * Returns the Buffer holding the passphrase the vault was unsealed
 * with on this boot, or `null` for `mode: "plaintext"` and for
 * any future scenario where the vault was bootstrapped without
 * one. Used by passphrase-rotation flows that re-wrap the keypair
 * under a fresh passphrase without prompting the operator twice.
 *
 * The Buffer is already in the JS heap during unwrap; retaining it
 * does not change the threat model meaningfully and is what makes
 * `b.vaultPassphraseOps.changePassphrase` ergonomic. Operators
 * concerned about heap residency rotate the passphrase and let the
 * old Buffer get zeroed and replaced.
 *
 * @example
 *   process.env.BLAMEJS_VAULT_PASSPHRASE = "S0meStrongPassphr@se!";
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "wrapped" });
 *   var pass = b.vault.getCurrentPassphrase();
 *   Buffer.isBuffer(pass);                     // → true
 *   pass.toString("utf8");                     // → "S0meStrongPassphr@se!"
 *
 *   // Plaintext mode never holds a passphrase.
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   b.vault.getCurrentPassphrase();            // → null
 */
function getCurrentPassphrase() {
  return currentPassphrase;
}

/**
 * @primitive b.vault.getMode
 * @signature b.vault.getMode()
 * @since     0.6.0
 * @related   b.vault.init
 *
 * Returns the active vault mode: `"wrapped"`, `"plaintext"`, or
 * `null` before `init()` has been awaited. Useful from health-check
 * endpoints that surface a deployment-posture badge ("plaintext mode
 * — DEV ONLY") or refuse to start the public listener until the
 * vault is in `wrapped` mode in production.
 *
 * @example
 *   b.vault.getMode();                           // → null  (pre-init)
 *
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "wrapped" });
 *   b.vault.getMode();                           // → "wrapped"
 *
 *   if (process.env.NODE_ENV === "production" && b.vault.getMode() !== "wrapped") {
 *     throw new Error("refusing to start: vault must be in wrapped mode");
 *   }
 */
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
  // The default sealed-storage Store: a { seal, unseal } pair backed by the
  // in-process vault key. b.cert.create (and other sealed-disk consumers)
  // resolve `opts.vault || getDefaultStore()`; documented in their @opts.
  getDefaultStore:       function () { return { seal: seal, unseal: unseal }; },
  Store:                 { seal: seal, unseal: unseal },
  getDerivedHashSalt:    getDerivedHashSalt,
  getDerivedHashMacKey:  getDerivedHashMacKey,
  _zeroizeAndReplace:    _zeroizeAndReplace,
  aad:                   vaultAad,
  getKeysJson:           getKeysJson,
  getCurrentPassphrase:  getCurrentPassphrase,
  getMode:               getMode,
  isInitialized:         function () { return initialized; },
  VaultError:            VaultError,
  sealPemFile:           sealPemFileModule.sealPemFile,
  SealPemFileError:      sealPemFileModule.SealPemFileError,
  // Testing helpers — not part of the public contract
  _resetForTest:         function () {
    if (currentPassphrase) safeBuffer.secureZero(currentPassphrase);
    keys = null; initialized = false; currentPassphrase = null; paths = null; currentMode = null;
    _cachedDerivedHashSalt = null; _cachedDerivedHashMacKey = null;
  },
  _getKeysForTest:       function () { return keys; },
  _getPathsForTest:      function () { return paths; },
};
