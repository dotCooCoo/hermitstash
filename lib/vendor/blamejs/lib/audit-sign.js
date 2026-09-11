// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var vaultPassphraseSource = require("./vault/passphrase-source");
var vaultWrap = require("./vault/wrap");

var AuditSignError = defineClass("AuditSignError", { alwaysPermanent: true });
var _err = AuditSignError.factory;

var DEFAULT_SIGNING_ALG = "slh-dsa-shake-256f";
var SUPPORTED_SIGNING_ALGS = Object.freeze(["slh-dsa-shake-256f", "ml-dsa-87", "ml-dsa-65"]);

var SIGNING_KEY_SCHEMA = {
  type: "object",
  required: ["publicKey", "privateKey"],
  properties: {
    publicKey:  { type: "string" },
    privateKey: { type: "string" },
    algorithm:  { type: "string" },
  },
};

var ENV_VARS = {
  value:  "BLAMEJS_AUDIT_SIGNING_PASSPHRASE",
  file:   "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE",
  source: "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE",
};

var keys = null;
var initialized = false;
var currentMode = null;
var paths = null;

var log = boot("audit-sign");

function resolvePaths(dataDir) {
  return {
    dataDir:    dataDir,
    plaintext:  nodePath.join(dataDir, frameworkFiles.fileName("auditSignKey")),
    sealed:     nodePath.join(dataDir, frameworkFiles.fileName("auditSignKey") + ".sealed"),
    publicHistory: nodePath.join(dataDir, "audit-sign.pubkeys.json"),
  };
}

function _appendPublicHistory(entry) {
  if (!paths || !paths.publicHistory) return;
  var list = [];
  try {
    if (nodeFs.existsSync(paths.publicHistory)) {
      var parsed = safeJson.parse(atomicFile.readSync(paths.publicHistory));
      if (Array.isArray(parsed)) list = parsed;
    }
  } catch (_e) { list = []; }
  for (var i = 0; i < list.length; i += 1) {
    if (list[i] && list[i].fingerprint === entry.fingerprint) return;
  }
  list.push(entry);
  try {
    atomicFile.writeSync(paths.publicHistory, JSON.stringify(list, null, 2), { fileMode: 0o600 });
  } catch (_e) { /* best-effort */ }
}

/**
 * @primitive b.auditSign.publicKeyFromHistory
 * @signature b.auditSign.publicKeyFromHistory(dataDir, fingerprint)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditSign.getPublicKeyByFingerprint, b.auditChain.verifyPurgeAnchor
 *
 * Resolve a public key by fingerprint from a data directory's unsealed
 * public-key history WITHOUT initializing signing. Returns the SPKI PEM, or
 * `null` when the directory records no such key.
 *
 * `getPublicKeyByFingerprint` answers the same question for a process that has
 * signing loaded. This one exists for a process that does not and should not:
 * a deployment running `auditSigning: false` still has to verify signatures
 * that were written while signing was on — a purge anchor especially, since it
 * decides which rows are allowed to be missing. Bootstrapping a keypair just
 * to read a public key would write to a volume the operator opened without
 * signing, which is the opposite of what they asked for.
 *
 * Public keys carry no secret, so no passphrase is involved. A key that was
 * never rotated is not in the history file, so this can return `null` for a
 * key that exists; the caller decides what an unresolvable fingerprint means.
 *
 * @example
 *   var pem = b.auditSign.publicKeyFromHistory("/var/lib/blamejs/data", fp);
 *   // -> "-----BEGIN PUBLIC KEY-----\n..." (or null)
 */
function _historyKeyMatching(list, fp) {
  if (!Array.isArray(list)) return null;
  for (var i = 0; i < list.length; i += 1) {
    var entry = list[i];
    if (!entry || entry.fingerprint !== fp || typeof entry.publicKey !== "string") continue;
    var actual;
    try { actual = _computeFingerprint(entry.publicKey); }
    catch (_e) { continue; }
    if (actual !== fp) continue;
    return entry.publicKey;
  }
  return null;
}

function publicKeyFromHistory(dataDir, fp) {
  if (typeof dataDir !== "string" || dataDir.length === 0) return null;
  if (typeof fp !== "string" || fp.length === 0) return null;
  var historyPath = resolvePaths(dataDir).publicHistory;
  if (!nodeFs.existsSync(historyPath)) return null;
  var list;
  try { list = safeJson.parse(atomicFile.readSync(historyPath)); }
  catch (_e) { return null; }
  return _historyKeyMatching(list, fp);
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
  return _historyKeyMatching(list, fp);
}

/**
 * @primitive b.auditSign.publicKeyLicensingDeletion
 * @signature b.auditSign.publicKeyLicensingDeletion(fingerprint)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditSign.getPublicKeyByFingerprint, b.auditChain.verifyPurgeAnchor
 *
 * Resolve the audit-signing public key for a fingerprint, for the one question
 * where a rotated-out key is NOT good enough: whether a purge boundary may
 * license missing rows. Returns the live key when the fingerprint is its own,
 * and `null` otherwise — the rotated-key history is deliberately not consulted.
 *
 * The history file is unsealed, because a verifier holding no passphrase has
 * to be able to resolve a key that signed a checkpoint before a rotation.
 * Making an entry hash to its own label stops one key being filed under
 * another's name, but it cannot make the file AUTHORITATIVE: generating a
 * keypair and filing a self-consistent entry for it does not require a secret. An
 * attacker who can write the audit store can write that file too, so anything
 * it authorizes is worth exactly as much as their own say-so.
 *
 * A checkpoint attests that a tip existed; a forged one adds a claim. A purge
 * anchor licenses rows to be ABSENT, so a forged one erases. Only the live key
 * — which lives sealed, behind a passphrase this process had to be given —
 * carries that weight.
 *
 * @example
 *   var pem = b.auditSign.publicKeyLicensingDeletion(anchor.publicKeyFingerprint);
 *   // -> the live key's PEM, or null when the anchor names any other key
 */
/**
 * @primitive b.auditSign.canonicalPublicKeyPem
 * @signature b.auditSign.canonicalPublicKeyPem(publicKeyPem)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditSign.fingerprintOf, b.auditSign.rotateSigningKey
 *
 * Re-export a PEM public key through the parsed key, giving one spelling for
 * one key. Throws `TypeError` when the input is not a readable PEM.
 *
 * A fingerprint is the hash of the PEM TEXT, so the spelling is the identity:
 * the same key saved with CRLF line endings hashes differently from the same
 * key saved with LF, and two readers that disagree about which to hash
 * disagree about which key signed something. Anywhere a key is ingested or
 * pinned, put it through here first.
 *
 * @example
 *   var pem = b.auditSign.canonicalPublicKeyPem(fs.readFileSync(p, "utf8"));
 *   var fp  = b.auditSign.fingerprintOf(pem);
 */
function canonicalPublicKeyPem(publicKeyPem) {
  try {
    return nodeCrypto.createPublicKey(publicKeyPem)
      .export({ type: "spki", format: "pem" }).toString();
  } catch (e) {
    throw new TypeError("canonicalPublicKeyPem: not a readable PEM public key: " +
      ((e && e.message) || String(e)));
  }
}

/**
 * @primitive b.auditSign.pinnedKeyResolver
 * @signature b.auditSign.pinnedKeyResolver(publicKeyPem)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditSign.canonicalPublicKeyPem, b.auditChain.verifyChain
 *
 * Build a `resolvePublicKey(fingerprint)` function for ONE operator-supplied
 * key: it answers with that key for either fingerprint the key can legitimately
 * carry, and `null` for anything else. Throws `TypeError` when the PEM is not
 * readable.
 *
 * One key can answer to two fingerprints because a fingerprint hashes the PEM
 * TEXT. A key handed to `rotateSigningKey` before that call canonicalized what
 * it ingested was fingerprinted exactly as written, CRLF and all, and the
 * anchors signed under it carry that hash — so hashing only a re-export
 * reports those volumes as signed by a key nobody knows. Hashing only the
 * file's bytes refuses the same key for how it was saved. Both derive from a
 * PEM that parsed into the key in hand, so carrying the pair resolves either
 * spelling without widening what counts as a valid key, and the spelling that
 * matched is what comes back — the text the fingerprint was taken over.
 *
 * @example
 *   var resolve = b.auditSign.pinnedKeyResolver(fs.readFileSync(p, "utf8"));
 *   var vc = await b.auditChain.verifyChain(q, "audit_log", { resolvePublicKey: resolve });
 */
function pinnedKeyResolver(publicKeyPem) {
  var canonical = canonicalPublicKeyPem(publicKeyPem);
  var byFingerprint = Object.create(null);
  byFingerprint[_computeFingerprint(publicKeyPem)] = publicKeyPem;
  byFingerprint[_computeFingerprint(canonical)] = canonical;
  return function (fp) {
    var key = String(fp);
    return Object.prototype.hasOwnProperty.call(byFingerprint, key)
      ? byFingerprint[key] : null;
  };
}

function publicKeyLicensingDeletion(fp) {
  _requireInit();
  return fp === keys.fingerprint ? keys.publicKey : null;
}

function _computeFingerprint(publicKeyPem) {
  return sha3Hash(publicKeyPem);
}

var ANCHOR_FORMAT = "blamejs-chain-anchor-v1";

var ANCHOR_FIELD_DELIMITER = "\n";
function _containsAnchorDelimiter(s) {
  return typeof s === "string" && s.indexOf(ANCHOR_FIELD_DELIMITER) !== -1;
}

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

function _getPassphrase(promptText) {
  return vaultPassphraseSource.getPassphrase({
    envVars: ENV_VARS,
    prompt:  promptText || "Audit-signing passphrase: ",
  });
}

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
 *   algorithm: "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65", // default "slh-dsa-shake-256f"; only consulted when generating a fresh key
 *   readOnly:  boolean                                          // default false — load an existing key but never create the directory, sweep orphaned temp files, or generate a keypair. A volume with no key leaves signing uninitialized rather than acquiring one.
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
  var alg = (opts.algorithm || DEFAULT_SIGNING_ALG).toLowerCase();
  if (SUPPORTED_SIGNING_ALGS.indexOf(alg) === -1) {
    throw new AuditSignError("audit-sign/bad-algorithm",
      "auditSign.init: algorithm must be one of " +
      SUPPORTED_SIGNING_ALGS.join(", ") + " (got: " + alg + ")");
  }
  pendingNewKeyAlg = alg;
  currentMode = mode;
  paths = resolvePaths(opts.dataDir);

  var readOnly = opts.readOnly === true;

  if (!readOnly) {
    if (!nodeFs.existsSync(paths.dataDir)) nodeFs.mkdirSync(paths.dataDir, { recursive: true });
    atomicFile.cleanOrphans(paths.sealed);
    atomicFile.cleanOrphans(paths.plaintext);
  }

  var hasPlaintext = nodeFs.existsSync(paths.plaintext);
  var hasSealed    = nodeFs.existsSync(paths.sealed);

  if (readOnly && !hasPlaintext && !hasSealed) return;
  if (hasPlaintext && hasSealed) {
    throw _err("audit-sign/key-file-conflict",
      "both audit-sign.key and audit-sign.key.sealed exist; resolve manually");
  }
  if (hasSealed && mode === "plaintext") {
    throw _err("audit-sign/mode-mismatch",
      "audit-sign.key.sealed exists but mode='plaintext' requested");
  }
  if (hasPlaintext && mode === "wrapped") {
    throw _err("audit-sign/mode-mismatch",
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
      throw _err("audit-sign/key-file-corrupt",
        "audit-sign.key corrupted or schema-invalid at " + paths.plaintext + " - " + e.message);
    }
    if (typeof loaded.algorithm !== "string" || loaded.algorithm.length === 0) {
      throw _err("audit-sign/key-file-missing-alg",
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
      throw _err("audit-sign/passphrase-rejected",
        "audit-signing passphrase rejected (" + e.message + ")");
    }
    var loaded;
    try { loaded = safeJson.parse(plaintextBuf, { schema: SIGNING_KEY_SCHEMA }); }
    catch (e) {
      throw _err("audit-sign/unwrapped-invalid",
        "unwrapped audit-sign.key invalid: " + e.message);
    }
    if (typeof loaded.algorithm !== "string" || loaded.algorithm.length === 0) {
      throw _err("audit-sign/unwrapped-missing-alg",
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
 *   // → <Buffer ...> 49,856 bytes under SLH-DSA-SHAKE-256f, the default
 *   //   (FIPS 205 Table 2). The `256s` variant is 29,792; ML-DSA-87 is
 *   //   4,627 and ML-DSA-65 3,309, which is what a deployment sizing
 *   //   checkpoint storage trades verify speed for.
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
  if (!publicKeyPem) _requireInit();
  var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), "utf8");
  var sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
  var pub = publicKeyPem || keys.publicKey;
  try {
    return nodeCrypto.verify(null, buf, pub, sigBuf);
  } catch (_e) {
    return false;
  }
}

/**
 * @primitive b.auditSign.fingerprintOf
 * @signature b.auditSign.fingerprintOf(publicKeyPem)
 * @since     0.15.21
 * @status    stable
 * @related   b.auditSign.getPublicKeyFingerprint, b.auditSign.verify
 *
 * Compute the SHA3-512 fingerprint (lowercase hex) of a SPKI-PEM public key —
 * the same derivation `getPublicKeyFingerprint()` returns for the active key,
 * but for any supplied key and WITHOUT requiring `init()`. A verifier pins a
 * trusted fingerprint and checks it against `fingerprintOf(block.publicKey)`
 * before trusting a detached signature block, so an attacker can't substitute
 * their own key while claiming the trusted fingerprint.
 *
 * @example
 *   var fp = b.auditSign.fingerprintOf(block.publicKey);
 *   if (fp !== trustedFingerprint) throw new Error("untrusted signing key");
 */
function fingerprintOf(publicKeyPem) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new AuditSignError("audit-sign/bad-public-key",
      "fingerprintOf: publicKeyPem must be a non-empty PEM string");
  }
  return _computeFingerprint(publicKeyPem);
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
      // Drop-silent, and a rejection is a failure like any other: a re-signing
      safeAsync.safeInvoke(onProgress, { id: entry.id, newSignature: newSig });
    } catch (_e) {
      summary.errors += 1;
    }
  }
  return summary;
}

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
 * with the OLD key still in memory + on disk. Refuses (`audit-sign/rotate-noop`)
 * when the new keypair has the same fingerprint as the current one.
 * Operators rotating the audit-signing key in production typically:
 * read existing checkpoints, call `rotateSigningKey()`, walk the
 * checkpoints through `reSignAll()`, then write the new signatures
 * back atomically. Returns metadata about the rotation including the
 * `historyPath` so external tools can verify pre-rotation checkpoints
 * later.
 *
 * A volume that has ever purged needs one more step: call
 * `b.auditTools.signExistingPurgeAnchor()` after rotating. A checkpoint
 * signed by the outgoing key still verifies from the public-key history,
 * but a purge anchor does not — the history is unsealed, so it can say
 * which key signed something and cannot say which key was ALLOWED to
 * license deleted rows. Until the anchor is re-signed under the new key
 * the chain refuses to verify, with a message naming that call.
 *
 * @opts
 *   privateKeyPem: string,                                     // BYO keypair (pair with publicKeyPem); when omitted the framework generates fresh material
 *   publicKeyPem:  string,
 *   algorithm:     "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65"  // defaults to the current keypair's algorithm
 *
 * @example
 *   // requires: a signing passphrase source (BLAMEJS_AUDIT_SIGNING_PASSPHRASE,
 *   //           BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE, or a TTY on stdin)
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

  var newAlg = rotOpts.algorithm || prevAlgorithm;
  if (SUPPORTED_SIGNING_ALGS.indexOf(newAlg) === -1) {
    throw _err("audit-sign/rotate-bad-alg",
      "audit-sign.rotateSigningKey: algorithm '" + newAlg + "' is not in SUPPORTED_SIGNING_ALGS");
  }
  var newPair;
  if (typeof rotOpts.privateKeyPem === "string" && typeof rotOpts.publicKeyPem === "string") {
    var canonicalPublicPem;
    try {
      canonicalPublicPem = canonicalPublicKeyPem(rotOpts.publicKeyPem);
    } catch (e) {
      throw _err("audit-sign/rotate-bad-key",
        "audit-sign.rotateSigningKey: publicKeyPem is not a readable PEM public key: " +
        ((e && e.message) || String(e)));
    }
    newPair = { publicKey: canonicalPublicPem, privateKey: rotOpts.privateKeyPem };
  } else {
    newPair = nodeCrypto.generateKeyPairSync(newAlg, {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  }

  var newFingerprint = _computeFingerprint(newPair.publicKey);
  if (newFingerprint === prevFingerprint) {
    throw _err("audit-sign/rotate-noop",
      "audit-sign.rotateSigningKey: new keypair has identical fingerprint to the current — refusing to write a no-op rotation");
  }

  var iso = new Date().toISOString().replace(/[:.]/g, "-");
  if (currentMode === "wrapped" && paths && paths.sealed) {
    var historyPath = paths.sealed + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       ;
    try { await atomicFile.copy(paths.sealed, historyPath); }
    catch (_e) { /* history copy is best-effort; the in-memory rotation still proceeds */ }
  } else if (currentMode === "plaintext" && paths && paths.plaintext) {
    var historyPathP = paths.plaintext + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       ;
    try { await atomicFile.copy(paths.plaintext, historyPathP); }
    catch (_e) { /* history copy is best-effort */ }
  }

  _appendPublicHistory({
    fingerprint: prevFingerprint,
    publicKey:   prevPublicKey,
    algorithm:   prevAlgorithm,
    rotatedAt:   new Date().toISOString(),
  });

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

  keys = {
    publicKey:  newPair.publicKey,
    privateKey: newPair.privateKey,
    algorithm:  newAlg,
    fingerprint: newFingerprint,
  };
  log("audit-signing keypair rotated (alg=" + newAlg + ", fp=" + newFingerprint.slice(0, 16) + "...)");                       

  return {
    previousFingerprint: prevFingerprint,
    previousPublicKey:   prevPublicKey,
    newFingerprint:      newFingerprint,
    newPublicKey:        newPair.publicKey,
    algorithm:           newAlg,
    rotatedAt:           new Date().toISOString(),
    historyPath:         (currentMode === "wrapped" && paths && paths.sealed)
                          ? paths.sealed + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       
                          : (currentMode === "plaintext" && paths && paths.plaintext)
                            ? paths.plaintext + ".history-" + iso + "-" + prevFingerprint.slice(0, 16)                                       
                            : null,
  };
}

function _normalizeTip(tip, fnLabel) {
  if (!tip || typeof tip !== "object") {
    throw _err("audit-sign/anchor-bad-tip",
      "auditSign." + fnLabel + ": tip must be an object { counter, tipHash }");
  }
  var counter = tip.counter;
  if (!numericBounds.isNonNegativeSafeInt(counter)) {
    throw _err("audit-sign/anchor-bad-counter",
      "auditSign." + fnLabel + ": tip.counter must be a non-negative integer below 2^53 (got: " + counter + ")");
  }
  if (typeof tip.tipHash !== "string" || tip.tipHash.length === 0) {
    throw _err("audit-sign/anchor-bad-tiphash",
      "auditSign." + fnLabel + ": tip.tipHash must be a non-empty string");
  }
  if (_containsAnchorDelimiter(tip.tipHash)) {
    throw _err("audit-sign/anchor-bad-tiphash",
      "auditSign." + fnLabel + ": tip.tipHash must not contain a newline (the anchor " +
      "record delimiter — it would make the signed bytes ambiguous)");
  }
  if (tip.prevTipHash != null && typeof tip.prevTipHash !== "string") {
    throw _err("audit-sign/anchor-bad-prev",
      "auditSign." + fnLabel + ": tip.prevTipHash, when present, must be a string");
  }
  if (_containsAnchorDelimiter(tip.prevTipHash)) {
    throw _err("audit-sign/anchor-bad-prev",
      "auditSign." + fnLabel + ": tip.prevTipHash must not contain a newline (the anchor " +
      "record delimiter — it would make the signed bytes ambiguous)");
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
 * Throws `AuditSignError` (`audit-sign/anchor-bad-tip` / `audit-sign/anchor-bad-counter` /
 * `audit-sign/anchor-bad-tiphash` / `audit-sign/anchor-bad-prev` / `audit-sign/anchor-bad-format`) on a malformed
 * tip — including any `format` / `tipHash` / `prevTipHash` that carries a
 * newline, which would make the signed bytes ambiguous;
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
  if (_containsAnchorDelimiter(opts.format)) {
    throw _err("audit-sign/anchor-bad-format",
      "auditSign.anchor: opts.format must not contain a newline (the anchor " +
      "record delimiter — it would make the signed bytes ambiguous)");
  }
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

function _verifyOneAnchor(a) {
  if (!a || typeof a !== "object") return { ok: false, reason: "anchor is not an object" };
  if (typeof a.tipHash !== "string" || typeof a.signature !== "string" ||
      typeof a.publicKeyFingerprint !== "string") {
    return { ok: false, reason: "anchor missing tipHash / signature / publicKeyFingerprint" };
  }
  if (!numericBounds.isNonNegativeSafeInt(a.counter)) {
    return { ok: false, reason: "anchor counter is not a non-negative whole number below 2^53" };
  }
  if (_containsAnchorDelimiter(a.tipHash) ||
      _containsAnchorDelimiter(a.format) ||
      _containsAnchorDelimiter(a.prevTipHash)) {
    return { ok: false, reason: "anchor field contains the record delimiter (ambiguous canonicalization)" };
  }
  var pub = getPublicKeyByFingerprint(a.publicKeyFingerprint);
  if (!pub) {
    return { ok: false, reason: "no audit-signing key on record for this anchor's fingerprint" };
  }
  var format = (typeof a.format === "string" && a.format.length > 0) ? a.format : ANCHOR_FORMAT;
  var prevTipHash = (a.prevTipHash != null && typeof a.prevTipHash === "string") ? a.prevTipHash : "";
  var payload = anchorPayload(Number(a.counter), a.tipHash, prevTipHash, Number(a.createdAt), format);
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
  publicKeyLicensingDeletion: publicKeyLicensingDeletion,
  canonicalPublicKeyPem: canonicalPublicKeyPem,
  pinnedKeyResolver: pinnedKeyResolver,
  publicKeyFromHistory:      publicKeyFromHistory,
  fingerprintOf:            fingerprintOf,
  getMode:                  getMode,
  getAlgorithm:             getAlgorithm,
  DEFAULT_SIGNING_ALG:      DEFAULT_SIGNING_ALG,
  SUPPORTED_SIGNING_ALGS:   SUPPORTED_SIGNING_ALGS,
  ENV_PASSPHRASE:           ENV_VARS.value,
  ENV_PASSPHRASE_FILE:      ENV_VARS.file,
  ENV_PASSPHRASE_SRC:       ENV_VARS.source,
  _resetForTest:            _resetForTest,
};
