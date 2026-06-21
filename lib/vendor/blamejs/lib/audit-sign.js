"use strict";
/**
 * @module b.auditSign
 * @nav    Crypto
 * @title  Audit Signing
 *
 * @intro
 *   SLH-DSA-SHAKE-256f post-quantum signature for audit-chain
 *   checkpoints. Wrapped vs plaintext on-disk modes, key derivation
 *   from an operator passphrase, periodic checkpoint sign / verify,
 *   multiple-key support so a key rotation doesn't strand history.
 *
 *   Algorithm: SLH-DSA-SHAKE-256f (FIPS 205) by default. ML-DSA-87
 *   (FIPS 204 Category 5) and ML-DSA-65 (FIPS 204 Category 3, ~192-bit
 *   symmetric security, smaller signatures + faster verify than 87)
 *   ship as opt-in alternatives for throughput-sensitive deployments.
 *   SLH-DSA-SHAKE-256f is hash-only — its security depends solely on
 *   the underlying hash function, with no lattice / module-hardness
 *   assumptions — and matches the framework's SHAKE256 KDF + SHA3-512
 *   hash family. Audit checkpoints are long-lived integrity
 *   attestations (must verify for the data retention period — years
 *   for HIPAA / SOX), so the conservative-PQC posture carries more
 *   weight here than the smaller ML-DSA signatures (~5 KB at 87,
 *   ~3.3 KB at 65) and faster sign (~0.6 ms vs 76 ms).
 *
 *   The algorithm is recorded in the on-disk key file's `algorithm`
 *   field. The framework refuses to load a key file that lacks it.
 *   Operators upgrading the algorithm rotate their audit-signing key
 *   via `b.auditSign.rotateSigningKey({ algorithm })`.
 *
 *   Design:
 *     - Different keypair from the vault encryption keys. Compromise
 *       of the vault DOES NOT let an attacker forge audit checkpoints.
 *     - Stored at <dataDir>/audit-sign.key.sealed (default 'wrapped'
 *       mode) or <dataDir>/audit-sign.key (opt-out 'plaintext' mode
 *       with warning).
 *     - Wrapped under its OWN passphrase, sourced via:
 *         BLAMEJS_AUDIT_SIGNING_PASSPHRASE         (env)
 *         BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE    (file)
 *         BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE  (auto|env|file|stdin)
 *       Intentionally distinct from BLAMEJS_VAULT_PASSPHRASE so
 *       operator-error reuse of the same passphrase is explicit.
 *     - First-run generates the keypair automatically.
 *
 *   Threat model:
 *     - Vault key compromised + DB write access: attacker can read
 *       sealed values + rewrite audit_log rows + recompute per-row
 *       chain hashes. They CANNOT forge new audit_checkpoint rows —
 *       each checkpoint requires the audit-signing private key.
 *     - Audit signing key compromised: attacker can forge new
 *       checkpoints but cannot read sealed values. Existing
 *       checkpoints still anchor history that pre-dated the compromise
 *       (operator should rotate signing key on detection).
 *     - Both compromised: framework cannot defend against this — the
 *       operator's physical / administrative controls (HIPAA §164.310,
 *       GDPR Art. 32(1)(d)) cover this case.
 *
 * @card
 *   SLH-DSA-SHAKE-256f post-quantum signature for audit-chain checkpoints.
 */
var nodeFs = require("node:fs");
var numericBounds = require("./numeric-bounds");
var nodePath = require("node:path");
var nodeCrypto = require("node:crypto");
var atomicFile = require("./atomic-file");
var { sha3Hash } = require("./crypto");
var frameworkFiles = require("./framework-files");
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var vaultPassphraseSource = require("./vault/passphrase-source");
var vaultWrap = require("./vault/wrap");

// AuditSignError is thrown by init() for fatal boot-time conditions
// (conflicting on-disk key files, passphrase rejected, schema invalid).
// The caller — CLI or app boot — catches and translates to an exit code;
// lib/ never calls process.exit unilaterally.
var AuditSignError = defineClass("AuditSignError", { alwaysPermanent: true });
var _err = AuditSignError.factory;

// Default for newly-generated keys. Operators can override at init
// via opts.algorithm — e.g. `auditSigning: { algorithm: "ml-dsa-87" }`
// for throughput-sensitive deployments. Every key file MUST carry the
// `algorithm` field on disk — the framework refuses to load a key file
// that lacks it. The legacy implicit-default-to-ml-dsa-87 fallback was
// removed as part of the pre-v1 compat-shim sweep.
var DEFAULT_SIGNING_ALG = "slh-dsa-shake-256f";
// ml-dsa-65 (FIPS 204 Category 3, ~192-bit symmetric security) is opt-
// in alongside ml-dsa-87 — same code path (both auto-detected by
// node:crypto from the PEM), smaller signatures (~3.3 KB vs ~5 KB at
// 87 / ~29.5 KB at SLH-DSA-SHAKE-256f), faster verify. Operators with
// throughput-sensitive checkpoint streams or audit-feed shippers
// elect ml-dsa-65 explicitly via opts.algorithm.
var SUPPORTED_SIGNING_ALGS = Object.freeze(["slh-dsa-shake-256f", "ml-dsa-87", "ml-dsa-65"]);

var SIGNING_KEY_SCHEMA = {
  type: "object",
  required: ["publicKey", "privateKey"],
  properties: {
    publicKey:  { type: "string" },
    privateKey: { type: "string" },
    algorithm:  { type: "string" },     // load-time-required — _initPlaintext + _initWrapped both throw KEY_FILE_MISSING_ALG / UNWRAPPED_MISSING_ALG when the field is absent (legacy implicit-default-to-ml-dsa-87 was removed in the pre-v1 compat-shim sweep). Schema's `required` keeps publicKey + privateKey only so the runtime checks fire with the precise error codes operators have wired alerting on.
  },
};

var ENV_VARS = {
  value:  "BLAMEJS_AUDIT_SIGNING_PASSPHRASE",
  file:   "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE",
  source: "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE",
};

var keys = null;            // { publicKey: PEM, privateKey: PEM, fingerprint }
var initialized = false;
var currentMode = null;
var paths = null;

var log = boot("audit-sign");

function resolvePaths(dataDir) {
  return {
    dataDir:    dataDir,
    plaintext:  nodePath.join(dataDir, frameworkFiles.fileName("auditSignKey")),
    sealed:     nodePath.join(dataDir, frameworkFiles.fileName("auditSignKey") + ".sealed"),
    // Unsealed registry of rotated-out PUBLIC keys (public keys are not
    // secret). It lets verify-time code (b.audit.verifyCheckpoints) resolve
    // the public key for a checkpoint signed under a now-rotated key WITHOUT
    // the old passphrase, so a rotation does not strand historical checkpoints.
    publicHistory: nodePath.join(dataDir, "audit-sign.pubkeys.json"),
  };
}

// Append a rotated-out public key to the unsealed public-key history. Public
// keys carry no secret, so storing them in the clear is safe and is what
// makes passphrase-free historical verification possible. De-duplicated by
// fingerprint; best-effort (a write failure must not abort the rotation, the
// sealed private-key history is the durable archive of record).
function _appendPublicHistory(entry) {
  if (!paths || !paths.publicHistory) return;
  var list = [];
  try {
    if (nodeFs.existsSync(paths.publicHistory)) {
      var parsed = safeJson.parse(atomicFile.readSync(paths.publicHistory));
      if (Array.isArray(parsed)) list = parsed;
    }
  } catch (_e) { list = []; }   // corrupt registry — rebuild from this entry
  for (var i = 0; i < list.length; i += 1) {
    if (list[i] && list[i].fingerprint === entry.fingerprint) return;   // already recorded
  }
  list.push(entry);
  try {
    atomicFile.writeSync(paths.publicHistory, JSON.stringify(list, null, 2), { fileMode: 0o600 });
  } catch (_e) { /* best-effort */ }
}

/**
 * @primitive b.auditSign.getPublicKeyByFingerprint
 * @signature b.auditSign.getPublicKeyByFingerprint(fingerprint)
 * @since     0.14.29
 * @status    stable
 * @related   b.auditSign.getPublicKey, b.auditSign.verify, b.auditSign.rotateSigningKey
 *
 * Resolve the audit-signing public key (SPKI PEM) for a fingerprint: the
 * live key, or a rotated-out key recorded in the unsealed public-key history
 * that `rotateSigningKey` maintains. Returns `null` when no key matches. Only
 * public material is consulted, so no passphrase is needed - this is what
 * lets `b.audit.verifyCheckpoints` verify a checkpoint signed under a
 * now-rotated key without stranding history.
 *
 * @example
 *   var pem = b.auditSign.getPublicKeyByFingerprint(checkpoint.publicKeyFingerprint);
 *   // -> "-----BEGIN PUBLIC KEY-----\n..." (or null if the key is unknown)
 */
function getPublicKeyByFingerprint(fp) {
  _requireInit();
  if (fp === keys.fingerprint) return keys.publicKey;
  if (!paths || !paths.publicHistory || !nodeFs.existsSync(paths.publicHistory)) return null;
  var list;
  try { list = safeJson.parse(atomicFile.readSync(paths.publicHistory)); }
  catch (_e) { return null; }
  if (!Array.isArray(list)) return null;
  for (var i = 0; i < list.length; i += 1) {
    if (list[i] && list[i].fingerprint === fp && typeof list[i].publicKey === "string") {
      return list[i].publicKey;
    }
  }
  return null;
}

function _computeFingerprint(publicKeyPem) {
  return sha3Hash(publicKeyPem);
}

// ---- Store-independent chain anchor (the checkpoint protocol lifted off the
// framework audit_log / audit_checkpoints store so a consumer can anchor THEIR
// OWN hash chain) ----

// Domain-separation magic for a consumer anchor's signed bytes. DISTINCT from
// the framework audit-checkpoint format on purpose: a checkpoint signature can
// never be replayed as an anchor (or vice versa), and the framework
// audit_checkpoints wire format stays byte-stable (b.audit.checkpoint is
// untouched). Changing this invalidates every prior anchor.
var ANCHOR_FORMAT = "blamejs-chain-anchor-v1";

// Build the canonical signed bytes for one anchor. Fixed multi-line layout (no
// JSON serializer quirks). prevTipHash IS part of the signed payload, so the
// link between consecutive anchors is tamper-evident — an attacker cannot
// rewrite the linkage without breaking the signature. `format` lets a consumer
// domain-separate their own anchors from any other anchored chain.
function anchorPayload(counter, tipHash, prevTipHash, createdAt, format) {
  return Buffer.from(
    (format || ANCHOR_FORMAT) + "\n" +
    String(counter) + "\n" +
    tipHash + "\n" +
    (prevTipHash || "") + "\n" +
    String(createdAt),
    "utf8"
  );
}

// ---- Passphrase sourcing (delegates to lib/passphrase-source.js with
// audit-signing-specific env var names) ----

function _getPassphrase(promptText) {
  return vaultPassphraseSource.getPassphrase({
    envVars: ENV_VARS,
    prompt:  promptText || "Audit-signing passphrase: ",
  });
}

// ---- Init ----

// Algorithm chosen for newly-generated keypairs. Set once per init()
// call and read by _initPlaintext / _initFirstRunWrapped. Existing key
// files take their algorithm from the file itself, ignoring this.
var pendingNewKeyAlg = null;

/**
 * @primitive  b.auditSign.init
 * @signature  b.auditSign.init(opts)
 * @since      0.1.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.sign, b.auditSign.verify, b.auditSign.rotateSigningKey
 *
 * Boot the audit-signing keypair. Called once during `b.db.init()`;
 * later calls are no-ops. First run generates a fresh PQC keypair and
 * either seals it under an operator passphrase ('wrapped' mode,
 * default) or writes it plaintext at 0600 ('plaintext' mode, opt-out
 * with stderr warning). Subsequent boots load the existing key file
 * and refuse if both wrapped + plaintext copies exist on disk
 * (KEY_FILE_CONFLICT) or the on-disk mode disagrees with `opts.mode`
 * (MODE_MISMATCH).
 *
 * @opts
 *   dataDir:   string,                                          // required — directory holding the key file
 *   mode:      "wrapped" | "plaintext",                         // default "wrapped"
 *   algorithm: "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65" // default "slh-dsa-shake-256f"; only consulted when generating a fresh key
 *
 * @example
 *   await b.auditSign.init({
 *     dataDir:   "/var/lib/blamejs/data",
 *     mode:      "wrapped",
 *     algorithm: "slh-dsa-shake-256f",
 *   });
 *   b.auditSign.getMode();        // → "wrapped"
 *   b.auditSign.getAlgorithm();   // → "slh-dsa-shake-256f"
 */
async function init(opts) {
  if (initialized) return;
  if (!opts || !opts.dataDir) {
    throw new AuditSignError("audit-sign/bad-init",
      "auditSign.init({ dataDir }) is required");
  }

  var mode = (opts.mode || "wrapped").toLowerCase();
  if (mode !== "wrapped" && mode !== "plaintext") {
    throw new AuditSignError("audit-sign/bad-mode",
      "auditSign.init: mode must be 'wrapped' or 'plaintext'");
  }
  // Algorithm-on-generate. Validated against the supported list so
  // typos surface here, not as an opaque "key generation failed"
  // deeper in nodeCrypto.
  var alg = (opts.algorithm || DEFAULT_SIGNING_ALG).toLowerCase();
  if (SUPPORTED_SIGNING_ALGS.indexOf(alg) === -1) {
    throw new AuditSignError("audit-sign/bad-algorithm",
      "auditSign.init: algorithm must be one of " +
      SUPPORTED_SIGNING_ALGS.join(", ") + " (got: " + alg + ")");
  }
  pendingNewKeyAlg = alg;
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  if (!nodeFs.existsSync(paths.dataDir)) nodeFs.mkdirSync(paths.dataDir, { recursive: true });
  // Sweep tmp files from any prior crashed write
  atomicFile.cleanOrphans(paths.sealed);
  atomicFile.cleanOrphans(paths.plaintext);

  var hasPlaintext = nodeFs.existsSync(paths.plaintext);
  var hasSealed    = nodeFs.existsSync(paths.sealed);
  if (hasPlaintext && hasSealed) {
    throw _err("KEY_FILE_CONFLICT",
      "both audit-sign.key and audit-sign.key.sealed exist; resolve manually");
  }
  if (hasSealed && mode === "plaintext") {
    throw _err("MODE_MISMATCH",
      "audit-sign.key.sealed exists but mode='plaintext' requested");
  }
  if (hasPlaintext && mode === "wrapped") {
    throw _err("MODE_MISMATCH",
      "audit-sign.key (plaintext) exists but mode='wrapped' requested");
  }

  if (mode === "wrapped") {
    if (hasSealed) await _initWrapped();
    else await _initFirstRunWrapped();
  } else {
    log.warn("WARNING: PLAINTEXT mode — audit-sign.key is unprotected on disk.");
    log.warn("         Use mode: 'wrapped' (default) for any deployment that holds real data.");
    _initPlaintext();
  }

  initialized = true;
}

function _initPlaintext() {
  if (nodeFs.existsSync(paths.plaintext)) {
    var loaded;
    try { loaded = safeJson.parse(atomicFile.readSync(paths.plaintext), { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) {
      throw _err("KEY_FILE_CORRUPT",
        "audit-sign.key corrupted or schema-invalid at " + paths.plaintext + " - " + e.message);
    }
    if (typeof loaded.algorithm !== "string" || loaded.algorithm.length === 0) {
      throw _err("KEY_FILE_MISSING_ALG",
        "audit-sign.key at " + paths.plaintext + " is missing the required " +
        "`algorithm` field. Regenerate the keypair (deletes the file and " +
        "boots fresh) or hand-edit to add `\"algorithm\": \"slh-dsa-shake-256f\"`.");
    }
    keys = {
      publicKey:  loaded.publicKey,
      privateKey: loaded.privateKey,
      algorithm:  loaded.algorithm,
      fingerprint: _computeFingerprint(loaded.publicKey),
    };
    return;
  }
  // First run, plaintext — generate with the operator-selected (or default) alg
  var alg = pendingNewKeyAlg || DEFAULT_SIGNING_ALG;
  var pair = nodeCrypto.generateKeyPairSync(alg, {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = {
    publicKey:  pair.publicKey,
    privateKey: pair.privateKey,
    algorithm:  alg,
    fingerprint: _computeFingerprint(pair.publicKey),
  };
  atomicFile.writeSync(
    paths.plaintext,
    JSON.stringify({ algorithm: alg, publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2),
    { fileMode: 0o600 }
  );
  log("plaintext audit-signing keypair generated at " + paths.plaintext + " (alg=" + alg + ")");
}

async function _initWrapped() {
  log("unsealing audit-sign.key.sealed...");
  var sealedBytes = atomicFile.readSync(paths.sealed);
  var passphrase = await _getPassphrase("Audit-signing passphrase: ");
  var plaintextBuf;
  try {
    try { plaintextBuf = await vaultWrap.unwrap(sealedBytes, passphrase); }
    catch (e) {
      throw _err("PASSPHRASE_REJECTED",
        "audit-signing passphrase rejected (" + e.message + ")");
    }
    var loaded;
    try { loaded = safeJson.parse(plaintextBuf, { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) {
      throw _err("UNWRAPPED_INVALID",
        "unwrapped audit-sign.key invalid: " + e.message);
    }
    if (typeof loaded.algorithm !== "string" || loaded.algorithm.length === 0) {
      throw _err("UNWRAPPED_MISSING_ALG",
        "unwrapped audit-sign.key is missing the required `algorithm` field.");
    }
    keys = {
      publicKey:  loaded.publicKey,
      privateKey: loaded.privateKey,
      algorithm:  loaded.algorithm,
      fingerprint: _computeFingerprint(loaded.publicKey),
    };
    log("audit-signing keypair unsealed (alg=" + loaded.algorithm + ").");
  } finally {
    // The audit-signing passphrase is single-use at boot — no re-wrap path
    // keeps it alive (unlike vault.currentPassphrase). Zero on the way out.
    safeBuffer.secureZero(passphrase);
    if (plaintextBuf) safeBuffer.secureZero(plaintextBuf);
  }
}

async function _initFirstRunWrapped() {
  var alg = pendingNewKeyAlg || DEFAULT_SIGNING_ALG;
  log("first-run wrapped — generating audit-signing keypair (alg=" + alg + ")...");
  var passphrase = await _getPassphrase("Choose an audit-signing passphrase: ");
  try {
    var pair = nodeCrypto.generateKeyPairSync(alg, {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    keys = {
      publicKey:  pair.publicKey,
      privateKey: pair.privateKey,
      algorithm:  alg,
      fingerprint: _computeFingerprint(pair.publicKey),
    };

    var sealed = await vaultWrap.wrap(
      JSON.stringify({ algorithm: alg, publicKey: keys.publicKey, privateKey: keys.privateKey }, null, 2),
      passphrase
    );
    atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });
    log("generated and sealed audit-signing keypair (alg=" + alg + ")");
  } finally {
    safeBuffer.secureZero(passphrase);
  }
}

// ---- Public API ----

function _requireInit() {
  if (!initialized) {
    throw new AuditSignError("audit-sign/not-initialized",
      "auditSign.init() must be awaited before sign/verify");
  }
}

/**
 * @primitive  b.auditSign.sign
 * @signature  b.auditSign.sign(payload)
 * @since      0.1.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.verify, b.audit.checkpoint
 *
 * Sign a payload (Buffer or string) with the in-memory PQC private
 * key. Returns the raw signature bytes as a Buffer. Throws if `init()`
 * has not been awaited. Used by `b.audit.checkpoint()` to anchor the
 * chain tip; operators normally don't call it directly.
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *
 *   // Sign a chain checkpoint payload (the audit module passes the
 *   // chain tip's row hash + monotonic counter as canonical bytes).
 *   var tip = { rowHash: "9f4e2c3a", counter: 1042 };
 *   var payload = Buffer.from(JSON.stringify(tip), "utf8");
 *   var signature = b.auditSign.sign(payload);
 *   // → <Buffer ...> roughly 29.5 KB for SLH-DSA-SHAKE-256f
 */
function sign(payload) {
  _requireInit();
  var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  return nodeCrypto.sign(null, buf, keys.privateKey);
}

/**
 * @primitive  b.auditSign.verify
 * @signature  b.auditSign.verify(payload, signature, publicKeyPem)
 * @since      0.1.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.sign, b.audit.verifyCheckpoints
 *
 * Verify a signature against the supplied (or current) public key.
 * Returns `true` when the signature is valid, `false` otherwise; never
 * throws on a forgery — callers branch on the boolean. The third
 * argument lets verification use a HISTORICAL key (read from
 * `audit-sign.key.sealed.history-*`) so a checkpoint signed years
 * earlier still verifies after rotation.
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *
 *   // Re-walk every checkpoint to confirm chain integrity.
 *   var tip = { rowHash: "9f4e2c3a", counter: 1042 };
 *   var payload = Buffer.from(JSON.stringify(tip), "utf8");
 *   var signature = b.auditSign.sign(payload);
 *
 *   var ok = b.auditSign.verify(payload, signature);
 *   // → true
 *
 *   // A historical checkpoint signed under an old key:
 *   var oldPubPem = "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----";
 *   b.auditSign.verify(payload, signature, oldPubPem);
 *   // → true (when payload + signature were produced under that key)
 */
function verify(payload, signature, publicKeyPem) {
  _requireInit();
  var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  var sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
  var pub = publicKeyPem || keys.publicKey;
  return nodeCrypto.verify(null, buf, pub, sigBuf);
}

/**
 * @primitive b.auditSign.getPublicKey
 * @signature b.auditSign.getPublicKey()
 * @since     0.1.0
 * @status    stable
 * @related   b.auditSign.getPublicKeyFingerprint, b.auditSign.verify
 *
 * Return the in-memory public key as a SPKI PEM string. Operators
 * publish this so external auditors can verify checkpoint signatures
 * without holding any private material.
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *   var pem = b.auditSign.getPublicKey();
 *   // → "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----\n"
 */
function getPublicKey() { _requireInit(); return keys.publicKey; }

/**
 * @primitive b.auditSign.getPublicKeyFingerprint
 * @signature b.auditSign.getPublicKeyFingerprint()
 * @since     0.1.0
 * @status    stable
 * @related   b.auditSign.getPublicKey, b.auditSign.rotateSigningKey
 *
 * Return the SHA3-512 fingerprint of the public key as a lowercase
 * hex string. Stable across boots for the same keypair; a different
 * fingerprint after `rotateSigningKey()` is the signal that the
 * rotation actually changed material.
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *   var fp = b.auditSign.getPublicKeyFingerprint();
 *   // → "9f4e2c3a..." (128 hex chars, SHA3-512)
 */
function getPublicKeyFingerprint() { _requireInit(); return keys.fingerprint; }

/**
 * @primitive b.auditSign.getMode
 * @signature b.auditSign.getMode()
 * @since     0.1.0
 * @status    stable
 * @related   b.auditSign.init
 *
 * Return the on-disk storage mode chosen at `init()` — `"wrapped"`
 * (passphrase-sealed, default) or `"plaintext"` (0600 file, opt-out).
 * Returns `null` before `init()` runs.
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *   b.auditSign.getMode();
 *   // → "wrapped"
 */
function getMode() { return currentMode; }

/**
 * @primitive b.auditSign.getAlgorithm
 * @signature b.auditSign.getAlgorithm()
 * @since     0.7.0
 * @status    stable
 * @related   b.auditSign.init, b.auditSign.rotateSigningKey
 *
 * Return the algorithm of the currently-loaded keypair —
 * `"slh-dsa-shake-256f"`, `"ml-dsa-87"`, or `"ml-dsa-65"`. Read from
 * the on-disk key file, not from the operator's `init()` opts (the
 * file's algorithm wins so a key generated under one alg keeps
 * verifying under that alg even when a later boot passes a different
 * default).
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *   b.auditSign.getAlgorithm();
 *   // → "slh-dsa-shake-256f"
 */
function getAlgorithm() { _requireInit(); return keys.algorithm; }

// Re-sign every payload in the operator-supplied iterable using the
// CURRENT in-memory key. Returns { reSigned: number, skipped: number,
// errors: number } so the caller (audit module's checkpoint store)
// can log a summary. Each iteration is wrapped in try/catch — a
// payload that fails to verify under the OLD key is skipped (already
// tampered or never signed under the historical key) rather than
// aborting the whole walk.
//
// The iterable yields { payload, signature, oldPublicKeyPem } so the
// caller's storage layer doesn't need to reach into audit-sign's
// internal key-history. The caller persists the new signature in
// place — this primitive returns the new bytes without touching
// storage.
/**
 * @primitive  b.auditSign.reSignAll
 * @signature  b.auditSign.reSignAll(iter, opts)
 * @since      0.7.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.rotateSigningKey, b.auditSign.sign
 *
 * Re-sign every payload in `iter` under the CURRENT in-memory key.
 * Each iteration yields `{ id, payload, signature, oldPublicKeyPem }`
 * — payloads whose old signature fails to verify under
 * `oldPublicKeyPem` are skipped (already tampered or never signed
 * under that key) rather than aborting the whole walk. Returns
 * `{ reSigned, skipped, errors }`. The caller (typically the audit
 * module's checkpoint store) persists the new bytes; this primitive
 * does not touch storage.
 *
 * @opts
 *   onProgress: function (entry),   // called with { id, newSignature } per re-sign; errors in the hook are drop-silent
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *
 *   async function* allCheckpoints() {
 *     yield {
 *       id:               1,
 *       payload:          Buffer.from("{\"counter\":1}", "utf8"),
 *       signature:        Buffer.from("00", "hex"),
 *       oldPublicKeyPem:  b.auditSign.getPublicKey(),
 *     };
 *   }
 *
 *   var summary = await b.auditSign.reSignAll(allCheckpoints(), {
 *     onProgress: function (entry) {
 *       // persist entry.newSignature against entry.id atomically
 *     },
 *   });
 *   // → { reSigned: 1, skipped: 0, errors: 0 }
 */
async function reSignAll(iter, opts) {
  _requireInit();
  opts = opts || {};
  var summary = { reSigned: 0, skipped: 0, errors: 0 };
  var onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
  for await (var entry of iter) {
    try {
      if (!entry || !entry.payload || !entry.signature) {
        summary.skipped += 1;
        continue;
      }
      var oldPub = entry.oldPublicKeyPem || keys.publicKey;
      if (!verify(entry.payload, entry.signature, oldPub)) {
        summary.skipped += 1;
        continue;
      }
      var newSig = sign(entry.payload);
      summary.reSigned += 1;
      if (onProgress) {
        try { onProgress({ id: entry.id, newSignature: newSig }); }
        catch (_e) { /* operator hook, drop-silent */ }
      }
    } catch (_e) {
      summary.errors += 1;
    }
  }
  return summary;
}

// Rotate the in-memory + on-disk keypair. Generates a fresh keypair
// (or accepts operator-supplied keypair via opts.privateKeyPem +
// publicKeyPem for the BYO-key case), writes the OLD sealed file
// to a timestamped history path so historical checkpoints can still
// be verified, then re-seals with the new keypair.
//
// rotation does NOT walk and re-sign existing audit checkpoints —
// the audit module orchestrates that via reSignAll() above so the
// per-row storage transactions stay in one place. Operators rotating
// the audit key in production typically:
//   1. Read existing audit checkpoints
//   2. Call rotateSigningKey() — gets new keys live
//   3. Walk checkpoints through reSignAll()
//   4. Write back the new signatures atomically
/**
 * @primitive  b.auditSign.rotateSigningKey
 * @signature  b.auditSign.rotateSigningKey(opts)
 * @since      0.7.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.reSignAll, b.auditSign.init
 *
 * Generate (or accept) a fresh keypair, copy the existing sealed /
 * plaintext key file to a timestamped `*.history-<iso>-<fp>` path, and
 * persist the new key to disk through the same wrap path as boot. The
 * in-memory swap happens last so a write failure leaves the framework
 * with the OLD key still in memory + on disk. Refuses (`ROTATE_NOOP`)
 * when the new keypair has the same fingerprint as the current one.
 * Operators rotating the audit-signing key in production typically:
 * read existing checkpoints, call `rotateSigningKey()`, walk the
 * checkpoints through `reSignAll()`, then write the new signatures
 * back atomically. Returns metadata about the rotation including the
 * `historyPath` so external tools can verify pre-rotation checkpoints
 * later.
 *
 * @opts
 *   privateKeyPem: string,                                     // BYO keypair (pair with publicKeyPem); when omitted the framework generates fresh material
 *   publicKeyPem:  string,
 *   algorithm:     "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65"  // defaults to the current keypair's algorithm
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *
 *   // Annual rotation — same algorithm, framework-generated material:
 *   var result = await b.auditSign.rotateSigningKey();
 *   // → {
 *   //     previousFingerprint: "9f4e...",
 *   //     newFingerprint:      "3a7c...",
 *   //     algorithm:           "slh-dsa-shake-256f",
 *   //     rotatedAt:           "2026-05-09T12:00:00.000Z",
 *   //     historyPath:         "/var/lib/blamejs/data/audit-sign.key.sealed.history-2026-05-09T12-00-00-000Z-9f4e2c3aabbccdd0",
 *   //     ...
 *   //   }
 *
 *   // Algorithm upgrade — same call, with explicit `algorithm`:
 *   await b.auditSign.rotateSigningKey({ algorithm: "ml-dsa-65" });
 */
async function rotateSigningKey(rotOpts) {
  _requireInit();
  rotOpts = rotOpts || {};
  var prevFingerprint = keys.fingerprint;
  var prevPublicKey = keys.publicKey;
  var prevAlgorithm = keys.algorithm;

  // Operator may supply the new keypair (BYO; useful for a hardware-
  // backed signer) or let the framework generate. The algorithm
  // defaults to the current keypair's algorithm; operators upgrading
  // the algorithm pass the new alg explicitly.
  var newAlg;
  var newPair;
  if (typeof rotOpts.privateKeyPem === "string" && typeof rotOpts.publicKeyPem === "string") {
    newAlg  = rotOpts.algorithm || prevAlgorithm;
    newPair = { publicKey: rotOpts.publicKeyPem, privateKey: rotOpts.privateKeyPem };
  } else {
    newAlg = rotOpts.algorithm || prevAlgorithm;
    newPair = nodeCrypto.generateKeyPairSync(newAlg, {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  }
  if (SUPPORTED_SIGNING_ALGS.indexOf(newAlg) === -1) {
    throw _err("ROTATE_BAD_ALG",
      "audit-sign.rotateSigningKey: algorithm '" + newAlg + "' is not in SUPPORTED_SIGNING_ALGS");
  }

  var newFingerprint = _computeFingerprint(newPair.publicKey);
  if (newFingerprint === prevFingerprint) {
    throw _err("ROTATE_NOOP",
      "audit-sign.rotateSigningKey: new keypair has identical fingerprint to the current — refusing to write a no-op rotation");
  }

  // Move the existing sealed/plaintext file to a timestamped history
  // path so historical checkpoints can still be verified by readers
  // that load the old key. We keep the history forever — the file is
  // small (a few KB) and signed audit checkpoints can be decades old.
  var iso = new Date().toISOString().replace(/[:.]/g, "-");
  if (currentMode === "wrapped" && paths && paths.sealed) {
    var historyPath = paths.sealed + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       /* fingerprint hex truncation count */;
    try { await atomicFile.copy(paths.sealed, historyPath); }
    catch (_e) { /* history copy is best-effort; the in-memory rotation still proceeds */ }
  } else if (currentMode === "plaintext" && paths && paths.plaintext) {
    var historyPathP = paths.plaintext + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       /* fingerprint hex truncation count */;
    try { await atomicFile.copy(paths.plaintext, historyPathP); }
    catch (_e) { /* history copy is best-effort */ }
  }

  // Record the rotated-out PUBLIC key (unsealed) so b.audit.verifyCheckpoints
  // can verify a checkpoint signed under it after rotation without the old
  // passphrase. Without this the public key only lives inside the sealed
  // history archive and verification of pre-rotation checkpoints is stranded.
  _appendPublicHistory({
    fingerprint: prevFingerprint,
    publicKey:   prevPublicKey,
    algorithm:   prevAlgorithm,
    rotatedAt:   new Date().toISOString(),
  });

  // Persist the new keypair through the same path as boot — sealed
  // mode re-wraps with the operator's passphrase; plaintext mode
  // writes JSON. We don't accept a passphrase override here; the
  // existing in-process passphrase derivation runs again.
  if (currentMode === "wrapped") {
    var passphrase = await _getPassphrase("Audit-signing passphrase (rotate): ");
    try {
      var sealed = await vaultWrap.wrap(
        JSON.stringify({ algorithm: newAlg, publicKey: newPair.publicKey, privateKey: newPair.privateKey }, null, 2),
        passphrase
      );
      atomicFile.writeSync(paths.sealed, sealed, { fileMode: 0o600 });
    } finally { safeBuffer.secureZero(passphrase); }
  } else if (currentMode === "plaintext") {
    atomicFile.writeSync(
      paths.plaintext,
      JSON.stringify({ algorithm: newAlg, publicKey: newPair.publicKey, privateKey: newPair.privateKey }, null, 2),
      { fileMode: 0o600 }
    );
  }

  // Atomic in-memory swap last (so a write failure above doesn't
  // leave a half-rotated state where memory has the new key but the
  // disk has the old one).
  keys = {
    publicKey:  newPair.publicKey,
    privateKey: newPair.privateKey,
    algorithm:  newAlg,
    fingerprint: newFingerprint,
  };
  log("audit-signing keypair rotated (alg=" + newAlg + ", fp=" + newFingerprint.slice(0, 16) + "...)");                       /* fingerprint hex truncation count */

  return {
    previousFingerprint: prevFingerprint,
    previousPublicKey:   prevPublicKey,
    newFingerprint:      newFingerprint,
    newPublicKey:        newPair.publicKey,
    algorithm:           newAlg,
    rotatedAt:           new Date().toISOString(),
    historyPath:         (currentMode === "wrapped" && paths && paths.sealed)
                          ? paths.sealed + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       /* fingerprint hex truncation count */
                          : (currentMode === "plaintext" && paths && paths.plaintext)
                            ? paths.plaintext + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       /* fingerprint hex truncation count */
                            : null,
  };
}

// Defensive coercion of an operator-supplied tip into the canonical fields.
// Config-time tier: throws a typed AuditSignError on a malformed tip so the
// consumer catches the bug at the call site, not as an opaque "signature
// failed" later. prevTipHash is OPTIONAL (absent for the genesis anchor).
function _normalizeTip(tip, fnLabel) {
  if (!tip || typeof tip !== "object") {
    throw _err("ANCHOR_BAD_TIP",
      "auditSign." + fnLabel + ": tip must be an object { counter, tipHash }");
  }
  var counter = tip.counter;
  if (!numericBounds.isNonNegativeFiniteInt(counter)) {
    throw _err("ANCHOR_BAD_COUNTER",
      "auditSign." + fnLabel + ": tip.counter must be a non-negative integer (got: " + counter + ")");
  }
  if (typeof tip.tipHash !== "string" || tip.tipHash.length === 0) {
    throw _err("ANCHOR_BAD_TIPHASH",
      "auditSign." + fnLabel + ": tip.tipHash must be a non-empty string");
  }
  if (tip.prevTipHash != null && typeof tip.prevTipHash !== "string") {
    throw _err("ANCHOR_BAD_PREV",
      "auditSign." + fnLabel + ": tip.prevTipHash, when present, must be a string");
  }
  return {
    counter:     counter,
    tipHash:     tip.tipHash,
    prevTipHash: tip.prevTipHash != null ? tip.prevTipHash : null,
  };
}

/**
 * @primitive  b.auditSign.anchor
 * @signature  b.auditSign.anchor(tip, opts?)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.verifyAnchor, b.auditSign.verifyAnchorChain, b.audit.checkpoint
 *
 * Sign a hash-chain tip with the in-memory PQC key, returning a
 * self-describing anchor object the consumer persists in THEIR OWN store. This
 * is the `b.audit.checkpoint()` protocol lifted off the framework `audit_log` /
 * `audit_checkpoints` tables: a consumer running their own append-only chain
 * anchors its tip the same tamper-evident way, with no framework table, no
 * `clusterStorage`, and no leader requirement. A full-chain rewrite that
 * recomputes every row hash still cannot forge the signature without the
 * audit-signing private key, so a later `verifyAnchorChain` detects it.
 *
 * `tip.prevTipHash` (optional) is bound into the signed bytes, so truncation /
 * reorder of a stored anchor sequence is caught by the signature, not just a
 * plaintext compare. `opts.format` domain-separates a consumer's anchors
 * (default `"blamejs-chain-anchor-v1"`).
 *
 * Verification resolves the public key from the recorded fingerprint via the
 * key-history file under the `init({ dataDir })` directory, so it is bound to
 * that key store (not fully store-free) — keep the history with the anchors.
 *
 * Throws `AuditSignError` (`ANCHOR_BAD_TIP` / `ANCHOR_BAD_COUNTER` /
 * `ANCHOR_BAD_TIPHASH` / `ANCHOR_BAD_PREV`) on a malformed tip;
 * `audit-sign/not-initialized` when `init()` has not been awaited.
 *
 * @opts
 *   format:    string,   // default "blamejs-chain-anchor-v1" — domain-separation magic in the signed payload
 *   createdAt: number,   // default Date.now() — the anchor timestamp (also signed)
 *
 * @example
 *   await b.auditSign.init({ dataDir: "/var/lib/blamejs/data" });
 *   var a = b.auditSign.anchor({ counter: 42, tipHash: "9f4e", prevTipHash: "1b7d" },
 *                              { format: "my-app-ledger-v1" });
 *   // → { format, counter, tipHash, prevTipHash, createdAt, algorithm,
 *   //     publicKeyFingerprint, signature }
 */
function anchor(tip, opts) {
  _requireInit();
  opts = opts || {};
  var t = _normalizeTip(tip, "anchor");
  var format = (typeof opts.format === "string" && opts.format.length > 0) ? opts.format : ANCHOR_FORMAT;
  var createdAt = (typeof opts.createdAt === "number" && isFinite(opts.createdAt)) ? opts.createdAt : Date.now();
  var payload = anchorPayload(t.counter, t.tipHash, t.prevTipHash, createdAt, format);
  var sigBuf = sign(payload);
  return {
    format:               format,
    counter:              t.counter,
    tipHash:              t.tipHash,
    prevTipHash:          t.prevTipHash,
    createdAt:            createdAt,
    algorithm:            keys.algorithm,
    publicKeyFingerprint: keys.fingerprint,
    signature:            sigBuf.toString("hex"),
  };
}

// Resolve + verify ONE anchor's signature. Returns { ok, reason? }. Never
// throws on a forgery / unknown key (defensive-reader tier) — the caller
// branches on ok.
function _verifyOneAnchor(a) {
  if (!a || typeof a !== "object") return { ok: false, reason: "anchor is not an object" };
  if (typeof a.tipHash !== "string" || typeof a.signature !== "string" ||
      typeof a.publicKeyFingerprint !== "string") {
    return { ok: false, reason: "anchor missing tipHash / signature / publicKeyFingerprint" };
  }
  if (typeof a.counter !== "number" || !isFinite(a.counter)) {
    return { ok: false, reason: "anchor counter is not a finite number" };
  }
  var pub = getPublicKeyByFingerprint(a.publicKeyFingerprint);
  if (!pub) {
    return { ok: false, reason: "no audit-signing key on record for this anchor's fingerprint" };
  }
  var format = (typeof a.format === "string" && a.format.length > 0) ? a.format : ANCHOR_FORMAT;
  // prevTipHash is part of the signed payload — rebuild it the same way anchor()
  // did (absent / null → "") so the bytes are byte-identical on a clean anchor.
  var prevTipHash = (a.prevTipHash != null && typeof a.prevTipHash === "string") ? a.prevTipHash : "";
  var payload = anchorPayload(Number(a.counter), a.tipHash, prevTipHash, Number(a.createdAt), format);
  // Buffer.from(hex) silently truncates on non-hex / odd-length; reject when
  // the parsed bytes don't round-trip to the original lowercased hex.
  var sigBuf = Buffer.from(a.signature, "hex");
  if (sigBuf.toString("hex") !== String(a.signature).toLowerCase()) {
    return { ok: false, reason: "anchor signature is not valid hex" };
  }
  if (!verify(payload, sigBuf, pub)) {
    return { ok: false, reason: "post-quantum signature failed" };
  }
  return { ok: true };
}

/**
 * @primitive  b.auditSign.verifyAnchor
 * @signature  b.auditSign.verifyAnchor(anchor)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.anchor, b.auditSign.verifyAnchorChain
 *
 * Verify a single anchor produced by `b.auditSign.anchor`. Resolves the public
 * key by the anchor's recorded fingerprint (live key or a rotated-out key from
 * the unsealed history), rebuilds the canonical payload, and checks the
 * post-quantum signature. Returns `{ ok: true }` when valid, or
 * `{ ok: false, reason }` for a forgery, an unknown signing key, malformed hex,
 * or a missing field. Never throws on adversarial content.
 *
 * @example
 *   var a = b.auditSign.anchor({ counter: 1, tipHash: "ab12" });
 *   b.auditSign.verifyAnchor(a);   // → { ok: true }
 */
function verifyAnchor(a) {
  _requireInit();
  return _verifyOneAnchor(a);
}

/**
 * @primitive  b.auditSign.verifyAnchorChain
 * @signature  b.auditSign.verifyAnchorChain(anchors, opts?)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related    b.auditSign.anchor, b.auditSign.verifyAnchor, b.audit.verifyCheckpoints
 *
 * Walk an ordered array of anchors (oldest first) and verify each one's
 * signature AND that the sequence is internally consistent: counters strictly
 * increase, and each anchor's `prevTipHash` equals the previous anchor's
 * `tipHash`. This catches the two attacks a single-anchor check cannot — a
 * stored-anchor truncation / reorder (link break) and a full-chain rewrite
 * (signature break). Returns `{ ok: true, anchorsVerified }`, or
 * `{ ok: false, anchorsVerified, breakAt, reason }` at the first break.
 *
 * `requireLinkage` (default true) makes a non-genesis anchor that omits
 * `prevTipHash` a break, so an attacker can't drop the link to bypass the
 * check. Pass `requireLinkage: false` for unlinked anchors.
 *
 * @opts
 *   requireLinkage: boolean,   // default true — every non-genesis anchor must carry a matching prevTipHash
 *
 * @example
 *   var a1 = b.auditSign.anchor({ counter: 1, tipHash: "h1" });
 *   var a2 = b.auditSign.anchor({ counter: 2, tipHash: "h2", prevTipHash: "h1" });
 *   b.auditSign.verifyAnchorChain([a1, a2]);   // → { ok: true, anchorsVerified: 2 }
 */
function verifyAnchorChain(anchors, opts) {
  _requireInit();
  opts = opts || {};
  var requireLinkage = opts.requireLinkage !== false;
  if (!Array.isArray(anchors)) {
    return { ok: false, anchorsVerified: 0, breakAt: 0, reason: "anchors must be an array" };
  }
  if (anchors.length === 0) return { ok: true, anchorsVerified: 0 };

  var prev = null;
  for (var i = 0; i < anchors.length; i += 1) {
    var a = anchors[i];
    var sigResult = _verifyOneAnchor(a);
    if (!sigResult.ok) {
      return { ok: false, anchorsVerified: i, breakAt: i, reason: sigResult.reason };
    }
    if (prev === null) {
      // Genesis: a prevTipHash on the FIRST anchor means a predecessor was
      // dropped — fail closed.
      if (a.prevTipHash != null) {
        return {
          ok: false, anchorsVerified: i, breakAt: i,
          reason: "non-genesis anchor missing predecessor (prevTipHash set on first anchor)",
        };
      }
    } else {
      if (!(Number(a.counter) > Number(prev.counter))) {
        return {
          ok: false, anchorsVerified: i, breakAt: i,
          reason: "anchor counter not strictly increasing",
        };
      }
      if (requireLinkage) {
        if (a.prevTipHash == null) {
          return {
            ok: false, anchorsVerified: i, breakAt: i,
            reason: "non-genesis anchor missing prevTipHash linkage",
          };
        }
        if (a.prevTipHash !== prev.tipHash) {
          return {
            ok: false, anchorsVerified: i, breakAt: i,
            reason: "anchor prevTipHash does not match the previous tipHash (truncation / reorder)",
          };
        }
      }
    }
    prev = a;
  }
  return { ok: true, anchorsVerified: anchors.length };
}

function _resetForTest() {
  keys = null;
  initialized = false;
  currentMode = null;
  paths = null;
  pendingNewKeyAlg = null;
}

module.exports = {
  init:                     init,
  sign:                     sign,
  verify:                   verify,
  anchor:                   anchor,
  verifyAnchor:             verifyAnchor,
  verifyAnchorChain:        verifyAnchorChain,
  rotateSigningKey:         rotateSigningKey,
  reSignAll:                reSignAll,
  getPublicKey:             getPublicKey,
  getPublicKeyFingerprint:  getPublicKeyFingerprint,
  getPublicKeyByFingerprint: getPublicKeyByFingerprint,
  getMode:                  getMode,
  getAlgorithm:             getAlgorithm,
  DEFAULT_SIGNING_ALG:      DEFAULT_SIGNING_ALG,
  SUPPORTED_SIGNING_ALGS:   SUPPORTED_SIGNING_ALGS,
  ENV_PASSPHRASE:           ENV_VARS.value,
  ENV_PASSPHRASE_FILE:      ENV_VARS.file,
  ENV_PASSPHRASE_SRC:       ENV_VARS.source,
  _resetForTest:            _resetForTest,
};
