// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mtlsCa
 * @nav    Crypto
 * @title  mTLS CA
 *
 * @intro
 *   Mutual TLS Certificate Authority — internal CA cert issuance,
 *   mTLS gate setup, fingerprint pinning.
 *
 *   The framework owns storage, sealed-loading dispatch, generation
 *   tagging, and atomic commit. Cert issuance (CA generation, client
 *   cert signing, PKCS#12 packaging) delegates to a pluggable engine
 *   so the operator chooses the X.509 toolchain. The default pure-JS
 *   engine lives in `lib/mtls-engine-default.js` (backed by the vendored
 *   zero-dep @blamejs/pki toolkit); operators with custom requirements
 *   pass their own via `opts.engine`.
 *
 *   Files relative to `dataDir`: `ca.crt` (PEM cert, plaintext),
 *   `ca.key` (PEM key, plaintext — refused under `caKeySealedMode:
 *   "required"`), `ca.key.sealed` (vault.seal of the PEM bytes — the
 *   default at-rest shape), `revocations.json` (revocation registry),
 *   `ca.crl` (signed CRL derived from the registry).
 *
 *   `caKeySealedMode` defaults to "required" — sealed file required,
 *   plaintext refused. There is no "auto" mode, because deciding
 *   for the operator means writing plaintext on a fresh install,
 *   which is the inverse of the framework's security-defaults-on posture for
 *   at-rest key material. The "disabled" mode is a dev-only opt-out
 *   (operator must justify with audited reason).
 *
 *   Generation tagging: every CA cert issued by the framework embeds
 *   an `OU=CAv{N}` RDN in its subject DN. `parseGeneration` reads that
 *   back so an upgrade flow can detect legacy CAs and prompt
 *   regeneration without breaking active mTLS clients.
 *
 *   Engine contract:
 *     async generateCa({ generation }) -> { caCertPem, caKeyPem }
 *     async signClientCert({ cn, validityDays, caCertPem, caKeyPem })
 *       -> { cert, key, ca, issuedAt, expiresAt }
 *     async packageP12({ cn, password, validityDays, caCertPem, caKeyPem })
 *       -> { p12, certPem, issuedAt, expiresAt }
 *
 *   The engine returns the cert PEM but does NOT compute a
 *   fingerprint — the framework hashes the certificate's DER via
 *   `b.crypto.hashCertFingerprint(certPem)` (the same value the
 *   require-mtls gate pins) so the SHA3-512 posture stays
 *   consistent across the stack. Operators who need the X.509-
 *   conventional SHA-256 fingerprint (browser cert-details panels,
 *   openssl interop) compute it separately from the cert PEM.
 *
 * @card
 *   Mutual TLS Certificate Authority — internal CA cert issuance, mTLS gate setup, fingerprint pinning.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeCrypto = require("node:crypto");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
// Lazy — the SHA3-512 fingerprint surfaced from issuance must match the one
// the require-mtls gate pins (b.crypto.hashCertFingerprint of the cert DER).
var bCrypto = lazyRequire(function () { return require("./crypto"); });
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// The default engine carries a vendored X.509 toolkit (@blamejs/pki).
// Lazy-require it so operators wiring a custom engine never pay the cost.
// The lazyRequire wrapper keeps the require at top-of-file declaration
// shape — no indented inline calls.
var mtlsEngineDefault = lazyRequire(function () { return require("./mtls-engine-default"); });

var caLog = boot("mtls-ca");

class MtlsCaError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsCaError";
    this.permanent = true;
    this.isMtlsCaError = true;
  }
}

var DEFAULT_PATHS = {
  caKey:        "ca.key",
  caKeySealed:  "ca.key.sealed",
  caCert:       "ca.crt",
  revocations:  "revocations.json",
  crl:          "ca.crl",
  caCertPrev:   "ca.prev.crt",
  issuance:     "issuance.json",
  revokedGeneration: "revoked-generation",
  algorithm:    "ca.algorithm",
};

var VALID_SEAL_MODES = { required: 1, disabled: 1 };

function _absoluteOrUnderDataDir(dataDir, p) {
  return nodePath.isAbsolute(p) ? p : nodePath.join(dataDir, p);
}

function _resolvePaths(dataDir, paths) {
  var p = Object.assign({}, DEFAULT_PATHS, paths || {});
  return {
    caKey:        _absoluteOrUnderDataDir(dataDir, p.caKey),
    caKeySealed:  _absoluteOrUnderDataDir(dataDir, p.caKeySealed),
    caCert:       _absoluteOrUnderDataDir(dataDir, p.caCert),
    revocations:  _absoluteOrUnderDataDir(dataDir, p.revocations),
    crl:          _absoluteOrUnderDataDir(dataDir, p.crl),
    caCertPrev:   _absoluteOrUnderDataDir(dataDir, p.caCertPrev),
    issuance:     _absoluteOrUnderDataDir(dataDir, p.issuance),
    revokedGeneration: _absoluteOrUnderDataDir(dataDir, p.revokedGeneration),
    algorithm:    _absoluteOrUnderDataDir(dataDir, p.algorithm),
  };
}

function _isDnSpace(cc) {
  if (cc === 0x20 || (cc >= 0x09 && cc <= 0x0D)) return true;
  if (cc < 0x00A0) return false;
  return codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES);
}

function _dnGeneration(subj) {
  var n = subj.length;
  var start = 0;
  for (var i = 0; i <= n; i += 1) {
    if (i < n) {
      var ch = subj.charAt(i);
      var separates = ch === "\r" || ch === "\n" ||
                      ((ch === "," || ch === "+") && subj.charAt(i - 1) !== "\\");
      if (!separates) continue;
    }
    var j = start;
    while (j < i && _isDnSpace(subj.charCodeAt(j))) j += 1;
    if (subj.startsWith("OU=CAv", j)) {
      var d = j + 6;
      var digits = d;
      while (digits < i && subj.charCodeAt(digits) >= 0x30 &&
             subj.charCodeAt(digits) <= 0x39) digits += 1;
      if (digits > d) return parseInt(subj.slice(d, digits), 10);
    }
    start = i + 1;
  }
  return null;
}

/**
 * @primitive b.mtlsCa.parseGeneration
 * @signature b.mtlsCa.parseGeneration(certPem)
 * @since     0.7.68
 * @related   b.mtlsCa.create
 *
 * Read the `OU=CAv{N}` generation tag from a PEM CA certificate's
 * subject DN. Returns the integer `N`, defaulting to `1` for untagged
 * legacy CAs (so the first regen lifts a legacy CA to generation 2
 * without misidentifying it as fresh) or `0` when the cert is
 * unreadable. Operators wire this into upgrade flows that detect
 * pre-rotation CAs whose key parameters are below the current bar.
 *
 * @example
 *   var pem = "-----BEGIN CERTIFICATE-----\n(invalid)\n-----END CERTIFICATE-----\n";
 *   b.mtlsCa.parseGeneration(pem);
 *   // → 0
 *
 *   b.mtlsCa.parseGeneration(null);
 *   // → 0
 */
function parseGeneration(certPem) {
  if (typeof certPem !== "string" && !Buffer.isBuffer(certPem)) return 0;
  try {
    var cert = new nodeCrypto.X509Certificate(certPem);
    /* c8 ignore next -- defensive: a successfully-parsed X.509 certificate always exposes a subject DN */
    var subj = cert.subject || "";
    var gen = _dnGeneration(subj);
    return gen === null ? 1 : gen;
  } catch (_e) {
    return 0;
  }
}

function _validManifestB64Field(v) {
  if (v === null || v === undefined) return true;
  if (typeof v !== "string" || v.length === 0) return false;
  var buf = Buffer.from(v, "base64");
  return buf.length > 0 && buf.toString("base64") === v;
}

/**
 * @primitive b.mtlsCa.create
 * @signature b.mtlsCa.create(opts)
 * @since     0.7.68
 * @related   b.mtlsCa.parseGeneration, b.crypto.sha3Hash
 *
 * Build an mTLS CA handle bound to `opts.dataDir`. The handle owns
 * sealed-loading of the CA private key, generation tagging on issued
 * certs, atomic commit of newly generated material, and a pluggable
 * engine for the X.509 work itself. Returns an object with
 * `initCA()`, `generateClientCert({ cn, validityDays })`,
 * `generateClientP12({ cn, password, validityDays })`, plus
 * revocation helpers.
 *
 * Throws `MtlsCaError` at config-time on bad opts (missing dataDir,
 * sealed-mode mismatch, missing vault when seal required).
 *
 * @opts
 *   dataDir:          string,                                  // required — base for cert / key / revocation files
 *   paths:            { caKey, caKeySealed, caCert, revocations, crl },  // override defaults
 *   vault:            object,                                  // b.vault — required when caKeySealedMode = "required"
 *   caKeySealedMode:  string,                                  // "required" (default) | "disabled"
 *   generation:       number,                                  // current CA generation for OU=CAv{N}
 *   engine:           object,                                  // pluggable X.509 engine; default lib/mtls-engine-default
 *   algorithm:        string,                                  // pin CA + leaf key algorithm; default ML-DSA-87. Pass "ECDSA-P384-SHA384" for a classical CA when a peer predates OpenSSL 3.5
 *   issuanceStore:    object,                                  // bring-your-own { list(), add(entry) } for the issuance ledger revokeGeneration reads; default is a JSON file under dataDir
 *   revocationStore:  object,                                  // bring-your-own { list(), add(entry) } for the revocation registry; default is a JSON file under dataDir. For a CLUSTERED deployment (shared store, per-host dataDir) also expose { readGenerationWatermark(), bumpGenerationWatermark(n) } so the issuance-supersede watermark is shared across hosts
 *
 * The handle also supports a non-breaking CA algorithm migration: status()
 * reports the stored CA's algorithm / keyType; rotate({ generation, algorithm })
 * generates and atomically commits a new CA (returning { caCertPem,
 * previousCaCertPem }) without the algorithm-mismatch initCA raises;
 * commit({ retainPrevious:true }) + loadTrustBundle() + dropRetained() keep the
 * superseded CA trusted during a re-enrollment grace window; canVerifyInTls(algorithm?)
 * runs a loopback mTLS self-test proving node:tls verifies a given algorithm on
 * this runtime (pass the prospective algorithm to pre-flight a migration before
 * rotating to it); revokeGeneration(n) revokes every cert the issuance ledger
 * recorded under a CA generation below n; and importIssuance(entries) backfills
 * leaf identities the ledger lacks (a pre-upgrade dataDir or out-of-band certs)
 * so revokeGeneration can sweep them.
 *
 * @example
 *   var fs   = require("fs");
 *   var os   = require("os");
 *   var path = require("path");
 *   var dir  = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-"));
 *   var ca   = b.mtlsCa.create({
 *     dataDir:         dir,
 *     caKeySealedMode: "disabled",
 *     generation:      1,
 *   });
 *   typeof ca.initCA;
 *   // → "function"
 */
var CLASSICAL_CA_CURVE = "secp384r1";
var SHA3_512_HEX_LEN = 128;
var STORE_READ_CAP = C.BYTES.mib(16);

function _expectedKeyTypeForPin(label) {
  var l = String(label).toLowerCase();
  if (l.indexOf("ecdsa") !== -1) return "ec";
  var m = l.match(/ml-dsa-(\d+)/);
  return m ? ("ml-dsa-" + m[1]) : null;
}

function _labelForKeyType(type) {
  /* c8 ignore next -- the "" fallback is defensive: callers pass a non-empty asymmetricKeyType */
  var t = String(type || "").toLowerCase();
  if (t === "ec") return "ECDSA-P384-SHA384";
  if (/^ml-dsa-\d+$/.test(t)) return t.toUpperCase();
  /* c8 ignore next -- the unrecognized-type fallback is reached only via _certAlgorithm's unmapped-type branch (an RSA/other custom-engine CA key, itself c8-ignored as a non-framework configuration); _labelForCaKeyType only ever passes ec/ml-dsa default-engine CA keys */
  return undefined;
}

function _labelForCaKeyType(caKeyPem) {
  var type;
  /* c8 ignore next -- the "" fallback is defensive: a parsed KeyObject always reports a non-empty asymmetricKeyType, so it is never reached */
  try { type = String(nodeCrypto.createPrivateKey(caKeyPem).asymmetricKeyType || "").toLowerCase(); }
  catch (_e) { return undefined; }
  return _labelForKeyType(type);
}

function _certAlgorithm(certPem) {
  try {
    var cert = new nodeCrypto.X509Certificate(certPem);
    var pub = cert.publicKey;
    /* c8 ignore next -- the "" fallback is defensive: a parsed public key always reports a non-empty asymmetricKeyType */
    var type = String(pub.asymmetricKeyType || "").toLowerCase();
    if (type === "ec") {
      /* c8 ignore next 2 -- the :null fallback is defensive: a parsed EC key always reports a namedCurve */
      var curve = pub.asymmetricKeyDetails && pub.asymmetricKeyDetails.namedCurve
        ? String(pub.asymmetricKeyDetails.namedCurve).toLowerCase() : null;
      /* c8 ignore next -- the "" fallback is defensive: a parsed cert always reports a signatureAlgorithm */
      var sigAlg = String(cert.signatureAlgorithm || "").toLowerCase();
      var isP384Sha384 = curve === CLASSICAL_CA_CURVE && /sha-?384/.test(sigAlg);
      return { keyType: type, algorithm: isP384Sha384 ? "ECDSA-P384-SHA384" : null };
    }
    /* c8 ignore next -- the ||null fallbacks are defensive: `type` is non-empty here, and an unmapped type (e.g. a custom RSA CA) is not a framework configuration */
    return { keyType: type || null, algorithm: _labelForKeyType(type) || null };
  } catch (_e) {
    return { keyType: null, algorithm: null };
  }
}

function _writeStoreCapped(path, serialized, writeOpts, fullCode, label) {
  if (Buffer.byteLength(serialized, "utf8") > STORE_READ_CAP) {
    throw new MtlsCaError(fullCode,
      "the default " + label + " (" + path + ") would exceed its " + STORE_READ_CAP + "-byte read cap; the framework's " +
      "own read of a larger file fails closed, disabling future issuance/revocation until the file is repaired — provide " +
      "a bring-your-own store that can grow past this cap for a deployment this large");
  }
  atomicFile.writeSync(path, serialized, writeOpts);
}

function _sameCert(pemA, pemB) {
  try {
    return new nodeCrypto.X509Certificate(pemA).raw.equals(new nodeCrypto.X509Certificate(pemB).raw);
  } catch (_e) {
    return Buffer.from(pemA).equals(Buffer.from(pemB));
  }
}

function _caPairConsistent(certPem, keyPem) {
  try {
    var certSpki = new nodeCrypto.X509Certificate(certPem).publicKey.export({ type: "spki", format: "der" });
    var keySpki = nodeCrypto.createPublicKey(keyPem).export({ type: "spki", format: "der" });
    return Buffer.from(certSpki).equals(Buffer.from(keySpki));
  } catch (_e) {
    return true;
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "paths", "vault",
    "caKeySealedMode", "generation", "engine", "revocationStore", "issuanceStore", "algorithm",
  ], "b.mtlsCa");
  validateOpts.requireNonEmptyString(opts.dataDir, "mtlsCa.create: opts.dataDir", MtlsCaError, "mtls-ca/no-datadir");
  if (!nodeFs.existsSync(opts.dataDir)) {
    nodeFs.mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  }
  var paths = _resolvePaths(opts.dataDir, opts.paths);
  [paths.caKey, paths.caKeySealed, paths.caCert, paths.caCertPrev,
   paths.revocations, paths.crl, paths.issuance, paths.revokedGeneration].forEach(function (p) {
    var dir = nodePath.dirname(p);
    if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  });
  var vault = opts.vault || null;
  var caKeySealedMode = (opts.caKeySealedMode || "required").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(VALID_SEAL_MODES, caKeySealedMode)) {
    throw new MtlsCaError("mtls-ca/bad-mode",
      "caKeySealedMode must be 'required' or 'disabled' " +
      "(legacy 'auto' was removed — it defaulted to plaintext-on-disk)");
  }
  var generation = typeof opts.generation === "number" && opts.generation >= 1
    ? Math.floor(opts.generation) : 1;
  var usesDefaultEngine = !opts.engine;
  var engine = opts.engine || mtlsEngineDefault();

  var caAlgorithm = opts.algorithm;
  if (caAlgorithm !== undefined && (typeof caAlgorithm !== "string" || caAlgorithm.length === 0)) {
    throw new MtlsCaError("mtls-ca/bad-algorithm",
      "opts.algorithm must be a non-empty string label " +
      "(e.g. \"ECDSA-P384-SHA384\") when set");
  }

  function _requireVault(reason) {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw new MtlsCaError("mtls-ca/no-vault",
        reason + " requires opts.vault (with seal/unseal). Pass b.vault " +
        "or use caKeySealedMode='disabled' to keep the CA key on disk in plaintext.");
    }
  }

  function keyExists() {
    return nodeFs.existsSync(paths.caKey) || nodeFs.existsSync(paths.caKeySealed);
  }
  function exists() {
    return keyExists() && nodeFs.existsSync(paths.caCert);
  }

  function status() {
    if (!exists()) {
      return {
        exists:     false,
        generation: 0,
        isLegacy:   false,
        current:    generation,
        algorithm:  null,
        keyType:    null,
      };
    }
    var pem = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) });
    var gen = parseGeneration(pem);
    var alg = _certAlgorithm(pem);
    var _statusAlgorithm;
    if (usesDefaultEngine) {
      _statusAlgorithm = alg.algorithm;
    } else {
      var _persistedStatusLabel = _currentCustomLabel();
      _statusAlgorithm = (_persistedStatusLabel !== undefined) ? _persistedStatusLabel : null;
    }
    return {
      exists:     true,
      generation: gen,
      isLegacy:   gen >= 1 && gen < generation,
      current:    generation,
      algorithm:  _statusAlgorithm,
      keyType:    alg.keyType,
    };
  }

  function loadKey() {
    var hasPlain  = nodeFs.existsSync(paths.caKey);
    var hasSealed = nodeFs.existsSync(paths.caKeySealed);
    if (!hasPlain && !hasSealed) {
      throw new MtlsCaError("mtls-ca/missing-key",
        "no CA key on disk at " + paths.caKey + " or " + paths.caKeySealed);
    }
    if (caKeySealedMode === "required") {
      if (!hasSealed) {
        throw new MtlsCaError("mtls-ca/sealed-required",
          "CA_KEY_SEALED='required' but " + paths.caKeySealed + " does not exist");
      }
      _requireVault("sealed CA key load");
      var sealedBytes = atomicFile.fdSafeReadSync(paths.caKeySealed, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
      var pem = vault.unseal(sealedBytes);
      if (!pem) {
        throw new MtlsCaError("mtls-ca/unseal-failed",
          "vault.unseal of " + paths.caKeySealed + " returned empty — vault key mismatch?");
      }
      return Buffer.from(pem, "utf8");
    }
    if (!hasPlain) {
      throw new MtlsCaError("mtls-ca/plain-required",
        "caKeySealedMode='disabled' but " + paths.caKey + " does not exist");
    }
    return atomicFile.fdSafeReadSync(paths.caKey, { maxBytes: C.BYTES.kib(64) });
  }

  function loadCert() {
    if (!nodeFs.existsSync(paths.caCert)) {
      throw new MtlsCaError("mtls-ca/missing-cert",
        "no CA cert on disk at " + paths.caCert);
    }
    return atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) });
  }

  function _commitLocked(opts2) {
    /* c8 ignore next 4 -- defense in depth: the public commit() validates these synchronously before the lock, and rotate()/_freshCreateSerialized pass engine output already validated as { caKeyPem, caCertPem } strings, so _commitLocked never sees bad args */
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    if (opts2.retainPrevious !== undefined && typeof opts2.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-retain-previous",
        "commit opts.retainPrevious must be a boolean when provided (got " +
        JSON.stringify(opts2.retainPrevious) + ") — a non-boolean like the string \"false\" is truthy and " +
        "would retain the outgoing root instead of hard-cutting it");
    }
    var currentCaCert = (opts2.retainPrevious && nodeFs.existsSync(paths.caCert))
      ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) })
      : null;
    var outgoingCaCert = (currentCaCert !== null && !_sameCert(currentCaCert.toString("utf8"), opts2.caCertPem))
      ? currentCaCert
      : null;
    var priorPrevExisted = nodeFs.existsSync(paths.caCertPrev);
    var priorPrev = null;
    if (priorPrevExisted) {
      try { priorPrev = atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorPrev = null; }
    }
    if (outgoingCaCert !== null && priorPrevExisted) {
      throw new MtlsCaError("mtls-ca/retained-root-exists",
        "a retained root from a prior rotation is still present at " + paths.caCertPrev + " — a second " +
        "retained rotation would drop it and reject clients still enrolled under it. End the existing grace " +
        "window with dropRetained(), or rotate({ retainPrevious: false }) to hard-cut, before rotating again");
    }
    if (priorPrevExisted && typeof opts2.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/retention-intent-required",
        "a retained root from a prior rotation is present at " + paths.caCertPrev + " — a commit that omits " +
        "retainPrevious would replace the active CA while leaving that root, dropping trust for the just-" +
        "superseded generation. Pass retainPrevious explicitly (false to hard-cut), or dropRetained() first");
    }
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    var commitTok = bCrypto().generateToken(C.BYTES.bytes(8));
    var keyTmp = keyDest + ".tmp-" + commitTok;
    var certTmp = paths.caCert + ".tmp-" + commitTok;
    var priorKeyExisted = nodeFs.existsSync(keyDest);
    var priorKey = null;
    if (priorKeyExisted) {
      try { priorKey = atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorKey = null; }
    }
    var priorCert = null;
    if (nodeFs.existsSync(paths.caCert)) {
      try { priorCert = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorCert = null; }
    }
    var _priorPersistedLabel = !usesDefaultEngine ? _readPersistedAlgorithm() : undefined;
    if (priorKeyExisted && priorKey === null) {
      throw new MtlsCaError("mtls-ca/prior-key-unreadable",
        "the existing CA key at " + keyDest + " could not be read to capture a rollback copy — refusing to " +
        "overwrite it (a failed publish would otherwise strand the CA); resolve the read fault and retry");
    }
    if (nodeFs.existsSync(paths.caCert) && priorCert === null) {
      throw new MtlsCaError("mtls-ca/prior-cert-unreadable",
        "the existing CA certificate at " + paths.caCert + " could not be read to capture the rollback " +
        "journal's prior-cert marker — refusing to rotate (a partial journal could mis-reconcile the " +
        "retained root after a crash); resolve the read fault and retry");
    }
    if (priorPrevExisted && priorPrev === null) {
      throw new MtlsCaError("mtls-ca/prior-retained-root-unreadable",
        "the existing retained root at " + paths.caCertPrev + " could not be read to capture a rollback " +
        "copy — refusing to rotate (a failed rotation could otherwise permanently lose it, stranding clients " +
        "in the existing grace window); resolve the read fault and retry");
    }
    if (nodeFs.existsSync(paths.caCert) && !priorKeyExisted) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "the stored CA certificate at " + paths.caCert + " has no matching private key at " + keyDest +
        " (a corrupt or half-published CA state) — refusing to commit over it, which would leave an " +
        "unrecoverable new-key/old-cert pair with no rollback journal; restore the key or remove " + paths.caCert +
        " to re-initialize");
    }
    var keyJournal = keyDest + ".rollback";
    var keyJournalWritten = false;
    var crlRollback = _crlRollbackPath();
    var crlExisted = nodeFs.existsSync(paths.crl);
    var caCertChanged = priorCert === null || !_sameCert(priorCert.toString("utf8"), opts2.caCertPem);
    var movingCrlAside = crlExisted && caCertChanged;

    function _writeExclusive(path, data, mode) {
      var fd = nodeFs.openSync(path, "wx", mode);
      try {
        var buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        var w = 0;
        while (w < buf.length) {
          w += nodeFs.writeSync(fd, buf, w, buf.length - w, null);
        }
        /* c8 ignore next -- best-effort: fsync on a freshly-opened, still-valid fd does not throw here */
        try { nodeFs.fsyncSync(fd); } catch (_fe) { /* fsync best-effort */ }
      } finally {
        /* c8 ignore next -- best-effort: closeSync on the just-written fd does not throw here */
        try { nodeFs.closeSync(fd); } catch (_ce) { /* close best-effort */ }
      }
    }
    try {
      var newKeyOnDisk = Buffer.from(sealed
        ? (_requireVault("sealed CA key commit"), vault.seal(opts2.caKeyPem))
        : opts2.caKeyPem);
      _writeExclusive(keyTmp, newKeyOnDisk, 0o600);
      _writeExclusive(certTmp, opts2.caCertPem, 0o644);
      var _customCommitLabel = !usesDefaultEngine
        ? ((typeof opts2.algorithm === "string" && opts2.algorithm.length > 0) ? opts2.algorithm
          : ((typeof caAlgorithm === "string" && caAlgorithm.length > 0) ? caAlgorithm : null))
        : null;
      if (priorKeyExisted && priorKey !== null) {
        /* c8 ignore next -- the "leave" arm is dead: the prior-retained-root-unreadable check above throws when priorPrevExisted && priorPrev===null, so priorPrev!==null here */
        var prevAction = !priorPrevExisted ? "delete" : (priorPrev !== null ? "restore" : "leave");
        var retainAfterCert = (opts2.retainPrevious === false)
          ? null
          : (outgoingCaCert !== null ? outgoingCaCert : priorPrev);
        atomicFile.writeSync(keyJournal, JSON.stringify({
          key:         priorKey.toString("base64"),
          newKey:      newKeyOnDisk.toString("base64"),
          cert:        priorCert !== null ? priorCert.toString("base64") : null,
          newCert:     Buffer.from(opts2.caCertPem).toString("base64"),
          retainAfter: retainAfterCert !== null,
          retainAfterCert: retainAfterCert !== null ? retainAfterCert.toString("base64") : null,
          crlMovedAside: movingCrlAside,
          prevAction:  prevAction,
          prevData:    prevAction === "restore" ? priorPrev.toString("base64") : null,
          customAlgorithm: _customCommitLabel,
          priorCustomAlgorithm: (_priorPersistedLabel !== undefined ? _priorPersistedLabel : null),
        }), { fileMode: 0o600 });
        keyJournalWritten = true;
      }
      if (!keyJournalWritten && _customCommitLabel !== null) _persistAlgorithm(_customCommitLabel);
      atomicFile.renameWithRetry(keyTmp, keyDest);
      atomicFile.fsyncDir(nodePath.dirname(keyDest));
      if (outgoingCaCert !== null) {
        atomicFile.writeSync(paths.caCertPrev, outgoingCaCert, { fileMode: 0o644 });
      } else if (opts2.retainPrevious === false && nodeFs.existsSync(paths.caCertPrev)) {
        nodeFs.unlinkSync(paths.caCertPrev);
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      if (movingCrlAside) {
        if (nodeFs.existsSync(crlRollback)) {
          try { nodeFs.unlinkSync(crlRollback); }
          /* c8 ignore next -- best-effort: if this unlink fails the renameWithRetry below fails the commit closed, so it is not swallowed silently */
          catch (_orphanErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: crlRollback, error: _orphanErr.message }); }
        }
        atomicFile.renameWithRetry(paths.crl, crlRollback);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
      atomicFile.renameWithRetry(certTmp, paths.caCert);
      atomicFile.fsyncDir(nodePath.dirname(paths.caCert));
      if (movingCrlAside && nodeFs.existsSync(crlRollback)) {
        try {
          nodeFs.unlinkSync(crlRollback);
          atomicFile.fsyncDir(nodePath.dirname(crlRollback));
          caLog.info("invalidated stale CRL on CA change (regenerate with generateCrl)", { path: paths.crl });
        }
        /* c8 ignore next -- best-effort: unlink of the CRL we just moved aside does not throw here */
        catch (_ce) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: crlRollback, error: _ce.message }); }
      }
      var _labelPersistDeferred = false;
      if (keyJournalWritten && _customCommitLabel !== null) {
        try {
          _persistAlgorithm(_customCommitLabel);
        } catch (_le) {
          if (!caCertChanged) throw _le;
          _labelPersistDeferred = true;
          caLog.debug("cleanup-failed", { op: "persist-algorithm", path: paths.algorithm, error: _le.message });
        }
      }
      if (keyJournalWritten && !_labelPersistDeferred) {
        try {
          nodeFs.unlinkSync(keyJournal);
          atomicFile.fsyncDir(nodePath.dirname(keyJournal));
        }
        catch (_je) {
          if (!caCertChanged) throw _je;
          caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyJournal, error: _je.message });
        }
      }
    } catch (e) {
      /* c8 ignore next -- defensive existence guard: the tmp file may or may not exist depending where the commit threw; both arms are best-effort cleanup */
      try { if (nodeFs.existsSync(keyTmp))  nodeFs.unlinkSync(keyTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyTmp, error: cleanupErr.message }); }
      /* c8 ignore next -- defensive existence guard: the tmp file may or may not exist depending where the commit threw; both arms are best-effort cleanup */
      try { if (nodeFs.existsSync(certTmp)) nodeFs.unlinkSync(certTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: certTmp, error: cleanupErr.message }); }
      var keyRolledBack = false;
      try {
        if (priorKeyExisted && priorKey !== null) {
          atomicFile.writeSync(keyDest, priorKey, { fileMode: 0o600 });
        }
        keyRolledBack = true;
      /* c8 ignore next 4 -- best-effort double-fault path: the key-restore writeSync does not throw in tests */
      } catch (keyRbErr) {
        caLog.error("ca-key-rollback-failed",
          { path: keyDest, error: (keyRbErr && keyRbErr.message) || String(keyRbErr) });
      }
      var prevRolledBack = false;
      try {
        if (priorPrevExisted && priorPrev !== null) {
          atomicFile.writeSync(paths.caCertPrev, priorPrev, { fileMode: 0o644 });
        } else if (!priorPrevExisted && nodeFs.existsSync(paths.caCertPrev)) {
          nodeFs.unlinkSync(paths.caCertPrev);
          atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
        }
        prevRolledBack = true;
      /* c8 ignore next 4 -- best-effort double-fault path: the retained-root restore/unlink does not throw in tests */
      } catch (rbErr) {
        caLog.error("retained-root-rollback-failed",
          { path: paths.caCertPrev, error: (rbErr && rbErr.message) || String(rbErr) });
      }
      var crlRolledBack = false;
      try {
        if (movingCrlAside && nodeFs.existsSync(crlRollback) && !nodeFs.existsSync(paths.crl)) {
          atomicFile.renameWithRetry(crlRollback, paths.crl);
          atomicFile.fsyncDir(nodePath.dirname(paths.crl));
        }
        crlRolledBack = true;
      /* c8 ignore next 4 -- best-effort double-fault path: the CRL restore rename does not throw in tests */
      } catch (crlRbErr) {
        caLog.error("crl-rollback-failed",
          { path: paths.crl, error: (crlRbErr && crlRbErr.message) || String(crlRbErr) });
      }
      var labelRolledBack = false;
      try {
        if (!usesDefaultEngine && _customCommitLabel !== null) {
          if (_priorPersistedLabel !== undefined) {
            _persistAlgorithm(_priorPersistedLabel);
          } else if (nodeFs.existsSync(paths.algorithm)) {
            nodeFs.unlinkSync(paths.algorithm);
            atomicFile.fsyncDir(nodePath.dirname(paths.algorithm));
          }
        }
        labelRolledBack = true;
      /* c8 ignore next 4 -- best-effort double-fault path: the label restore writeSync/unlink does not throw in tests */
      } catch (lblRbErr) {
        caLog.error("ca-label-rollback-failed",
          { path: paths.algorithm, error: (lblRbErr && lblRbErr.message) || String(lblRbErr) });
      }
      if (keyJournalWritten && keyRolledBack && prevRolledBack && crlRolledBack && labelRolledBack) {
        try { nodeFs.unlinkSync(keyJournal); }
        /* c8 ignore next -- best-effort: unlink of the journal we just wrote does not throw here */
        catch (_je) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyJournal, error: _je.message }); }
      }
      throw new MtlsCaError("mtls-ca/commit-failed",
        "atomic CA commit failed: " + ((e && e.message) || String(e)));
    }
    return {
      keyPath:  keyDest,
      certPath: paths.caCert,
      sealed:   sealed,
    };
  }

  async function _assertCommittedCaUsable(caCertPem, caKeyPem) {
    /* c8 ignore start -- defensive: a certificate node reports as .ca=true carries a basicConstraints pathLen, which RFC 5280 sec. 4.2.1.9 requires be paired with keyUsage keyCertSign, so a conforming CA that reaches this point always signs leaves; this arm guards a non-conforming externally-built CA (pathLen without keyCertSign) and is not reachable with toolkit-built fixtures (the toolkit refuses to emit pathLen without keyCertSign) */
    try {
      await engine.signClientCert({ cn: "commit-usability-preflight", caCertPem: caCertPem, caKeyPem: caKeyPem });
    } catch (e) {
      throw new MtlsCaError("mtls-ca/ca-cannot-issue",
        "commit: the bundled engine cannot issue a leaf under the committed CA (its key usage likely omits " +
        "keyCertSign, or the material is otherwise unusable): " + ((e && e.message) || String(e)) +
        " — refusing to publish a CA that cannot sign certificates");
    }
    /* c8 ignore stop */
    var _now = Date.now();
    try {
      await engine.generateCrl({ caCertPem: caCertPem, caKeyPem: caKeyPem, revocations: [],
        thisUpdate: new Date(_now), nextUpdate: new Date(_now + C.TIME.days(1)) });
    } catch (e) {
      throw new MtlsCaError("mtls-ca/ca-cannot-sign-crl",
        "commit: the bundled engine cannot sign a CRL under the committed CA (its key usage likely omits cRLSign): " +
        /* c8 ignore next -- String(e) fallback unreachable: a thrown engine Error always has a .message */
        ((e && e.message) || String(e)) + " — refusing to publish a CA that would disable the revocation-export path");
    }
  }

  function commit(opts2) {
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    if (opts2.algorithm !== undefined && (typeof opts2.algorithm !== "string" || opts2.algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "commit: opts.algorithm must be a non-empty string label when set (the new effective algorithm for a " +
        "pinned custom-engine handle migrating to a different-algorithm CA)");
    }
    if (usesDefaultEngine) {
      var _commitCert = null, _commitKey = null;
      try { _commitCert = new nodeCrypto.X509Certificate(opts2.caCertPem); } catch (_ce) { _commitCert = null; }
      try { _commitKey = nodeCrypto.createPrivateKey(opts2.caKeyPem); } catch (_ke) { _commitKey = null; }
      if (_commitCert === null || _commitKey === null) {
        throw new MtlsCaError("mtls-ca/bad-commit",
          "commit: the bundled CA engine requires a parseable X.509 certificate and private key, but the supplied " +
          "caCertPem/caKeyPem did not parse — refusing to publish unusable material that would fail every subsequent " +
          "issuance; supply valid PEM (a custom engine may commit opaque material)");
      }
      if (_commitCert.ca !== true) {
        throw new MtlsCaError("mtls-ca/not-a-ca-certificate",
          "commit: the bundled CA engine requires a CA certificate (basicConstraints cA:true), but the supplied " +
          "caCertPem is not a CA (e.g. a leaf / end-entity certificate) — publishing it would succeed, but the next " +
          "generateClientCert() would fail because a non-CA issuer cannot sign leaves; supply the CA certificate.");
      }
      var _nowMs = Date.now();
      if (_commitCert.validFromDate.getTime() > _nowMs || _commitCert.validToDate.getTime() < _nowMs) {
        throw new MtlsCaError("mtls-ca/ca-outside-validity",
          "commit: the supplied CA certificate is outside its validity window (validFrom " + _commitCert.validFrom +
          " .. validTo " + _commitCert.validTo + ") — publishing it would succeed, but every issued leaf would chain to " +
          "an expired or not-yet-valid CA that a TLS peer rejects (CERT_HAS_EXPIRED); supply a currently-valid CA.");
      }
      var _committedLabel = _certAlgorithm(opts2.caCertPem).algorithm;
      var _supportedLabels = engine.algorithmEnvelope().cert.priority.map(function (p) { return p.label; });
      if (_committedLabel === null || _supportedLabels.indexOf(_committedLabel) === -1) {
        throw new MtlsCaError("mtls-ca/unsupported-ca-algorithm",
          "commit: the bundled CA engine does not support the supplied CA's algorithm" +
          (_committedLabel ? " (" + _committedLabel + ")" : " (an EC curve/digest the engine does not issue, e.g. P-256)") +
          " — supported: " + _supportedLabels.join(", ") + ". Publishing it would succeed, but the next initCA() would " +
          "throw mtls-ca/algorithm-mismatch and leave issuance unavailable; commit a CA in a supported algorithm (a " +
          "custom engine may commit its own).");
      }
      opts2 = Object.assign({}, opts2, { caKeyPem: _commitKey.export({ type: "pkcs8", format: "pem" }) });
    }
    if (!_caPairConsistent(opts2.caCertPem, opts2.caKeyPem)) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "commit: the supplied caCertPem and caKeyPem are not a matching pair (the certificate's public key does " +
        "not correspond to the private key) — refusing to publish a mismatched CA the next initCA() would reject; " +
        "supply a certificate and key from the same CA");
    }
    return atomicFile.lock(paths.caCert, async function () {
      _reconcileCommitJournalLocked();
      if (usesDefaultEngine) { await _assertCommittedCaUsable(opts2.caCertPem, opts2.caKeyPem); }
      var result = _commitLocked(opts2);
      if (usesDefaultEngine && caAlgorithm !== undefined) {
        var committedAlg = _certAlgorithm(opts2.caCertPem).algorithm;
        if (committedAlg !== null && committedAlg !== undefined) caAlgorithm = committedAlg;
      } else if (!usesDefaultEngine && opts2.algorithm !== undefined) {
        caAlgorithm = opts2.algorithm;
      }
      return result;
    });
  }

  function _reconcileCommitJournalLocked() {
    var keyDest = (caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey;
    var keyJournal = keyDest + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return;
    var manifest;
    try {
      manifest = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
    } catch (_je) {
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " exists but could not be parsed (" +
        /* c8 ignore next -- String(_je) fallback unreachable: a thrown parse Error always has a .message */
        ((_je && _je.message) || String(_je)) + ") — refusing to mutate the CA while an unresolved rotation " +
        "journal is present; restore or remove it, then retry");
    }
    if (!manifest || typeof manifest.key !== "string") {
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " is present but is not a valid rollback manifest " +
        "(missing the prior-key field) — refusing to mutate the CA while an unresolved rotation journal is " +
        "present; restore or remove it, then retry");
    }
    if (![manifest.key, manifest.newKey, manifest.cert, manifest.newCert, manifest.prevData, manifest.retainAfterCert]
          .every(_validManifestB64Field)) {
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " has an empty or malformed base64 field — refusing to " +
        "recover the CA from a corrupt manifest (an empty key would overwrite and destroy the live CA); " +
        "restore or remove it, then retry");
    }
    var curCertBuf = nodeFs.existsSync(paths.caCert)
      ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }) : null;
    var priorCertBuf = (typeof manifest.cert === "string") ? Buffer.from(manifest.cert, "base64") : null;
    var newCertBuf = (typeof manifest.newCert === "string") ? Buffer.from(manifest.newCert, "base64") : null;
    var completed;
    if (priorCertBuf !== null) {
      var certRepublished = curCertBuf !== null && !Buffer.from(curCertBuf).equals(priorCertBuf);
      var certKeyUnchanged = !certRepublished && manifest.key === manifest.newKey;
      var hardCutRemovalDone = certKeyUnchanged && manifest.retainAfter === false &&
        manifest.prevAction === "restore" && !nodeFs.existsSync(paths.caCertPrev);
      completed = certRepublished || hardCutRemovalDone;
    } else {
      completed = curCertBuf !== null && newCertBuf !== null && Buffer.from(curCertBuf).equals(newCertBuf);
    }
    var wantKeyBuf, wantPrevBuf;
    if (completed) {
      wantKeyBuf  = (typeof manifest.newKey === "string") ? Buffer.from(manifest.newKey, "base64") : null;
      wantPrevBuf = manifest.retainAfter
        ? (typeof manifest.retainAfterCert === "string" ? Buffer.from(manifest.retainAfterCert, "base64") : priorCertBuf)
        : null;
      if (typeof manifest.customAlgorithm === "string" && manifest.customAlgorithm.length > 0) {
        _persistAlgorithm(manifest.customAlgorithm);
      }
    } else {
      wantKeyBuf  = Buffer.from(manifest.key, "base64");
      wantPrevBuf = (manifest.prevAction === "restore" && typeof manifest.prevData === "string")
        ? Buffer.from(manifest.prevData, "base64")
        : (manifest.prevAction === "delete" ? null : undefined);
      if (typeof manifest.priorCustomAlgorithm === "string" && manifest.priorCustomAlgorithm.length > 0) {
        _persistAlgorithm(manifest.priorCustomAlgorithm);
      } else if (manifest.priorCustomAlgorithm === null && typeof manifest.customAlgorithm === "string" &&
                 manifest.customAlgorithm.length > 0 && nodeFs.existsSync(paths.algorithm)) {
        nodeFs.unlinkSync(paths.algorithm);
        atomicFile.fsyncDir(nodePath.dirname(paths.algorithm));
      }
    }
    if (wantKeyBuf !== null) {
      var curKeyRaw = nodeFs.existsSync(keyDest)
        ? atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }) : null;
      if (curKeyRaw === null || !Buffer.from(curKeyRaw).equals(wantKeyBuf)) {
        atomicFile.writeSync(keyDest, wantKeyBuf, { fileMode: 0o600 });
      }
    }
    if (wantPrevBuf !== undefined) {
      var curPrev = nodeFs.existsSync(paths.caCertPrev)
        ? atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }) : null;
      if (wantPrevBuf === null) {
        if (curPrev !== null) { nodeFs.unlinkSync(paths.caCertPrev); atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev)); }
      } else if (curPrev === null || !Buffer.from(curPrev).equals(wantPrevBuf)) {
        atomicFile.writeSync(paths.caCertPrev, wantPrevBuf, { fileMode: 0o644 });
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
    }
    var crlRollback = _crlRollbackPath();
    if (manifest.crlMovedAside) {
      if (completed) {
        if (nodeFs.existsSync(crlRollback)) {
          nodeFs.unlinkSync(crlRollback);
          atomicFile.fsyncDir(nodePath.dirname(crlRollback));
        }
        if (nodeFs.existsSync(paths.crl)) {
          nodeFs.unlinkSync(paths.crl);
          atomicFile.fsyncDir(nodePath.dirname(paths.crl));
        }
      } else if (nodeFs.existsSync(crlRollback) && !nodeFs.existsSync(paths.crl)) {
        atomicFile.renameWithRetry(crlRollback, paths.crl);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
    }
    nodeFs.unlinkSync(keyJournal);
    atomicFile.fsyncDir(nodePath.dirname(keyJournal));
    caLog.warn("recovered-interrupted-rotation",
      { path: keyDest, detail: (completed ? "finished" : "rolled back") +
        " an interrupted rotation from the rollback journal (byte-exact)" });
  }

  function _commitJournalPath() {
    return ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
  }

  function _crlRollbackPath() {
    return paths.crl + ".rollback";
  }

  function _assertPinMatchesStoredCa(certPem, keyPem) {
    if (caAlgorithm === undefined) return;
    var expectedType = _expectedKeyTypeForPin(caAlgorithm);
    var actualType   = null;
    var actualCurve  = null;
    try {
      var caKeyObj = nodeCrypto.createPrivateKey(keyPem);
      /* c8 ignore next -- the "" fallback is defensive: a parsed KeyObject always reports a non-empty asymmetricKeyType, so it is never reached */
      actualType  = String(caKeyObj.asymmetricKeyType || "").toLowerCase();
      actualCurve = caKeyObj.asymmetricKeyDetails && caKeyObj.asymmetricKeyDetails.namedCurve
        ? String(caKeyObj.asymmetricKeyDetails.namedCurve).toLowerCase() : null;
    } catch (_e) { actualType = null; }
    if (expectedType !== null && actualType && actualType !== expectedType) {
      throw new MtlsCaError("mtls-ca/algorithm-mismatch",
        "the CA at this dataDir was generated under " + actualType + ", but algorithm " +
        JSON.stringify(caAlgorithm) + " (" + expectedType + ") was requested. A leaf issued " +
        "under the pin would be signed by the mismatched CA and fail chain verification at a " +
        "peer. Rotate to a new CA (a fresh dataDir, or a higher generation) to change algorithms.");
    }
    if (actualType === "ec" && /ecdsa-p384/i.test(String(caAlgorithm)) && actualCurve !== CLASSICAL_CA_CURVE) {
      throw new MtlsCaError("mtls-ca/algorithm-mismatch",
        "the CA at this dataDir uses EC curve " + actualCurve + ", but algorithm " +
        JSON.stringify(caAlgorithm) + " requires P-384 (" + CLASSICAL_CA_CURVE + "). Rotate to a new " +
        "CA (a fresh dataDir, or a higher generation) to change the curve.");
    }
  }

  function _persistAlgorithm(label) {
    atomicFile.writeSync(paths.algorithm, String(label), { fileMode: 0o600 });
  }
  function _readPersistedAlgorithm() {
    if (!nodeFs.existsSync(paths.algorithm)) return undefined;
    var s = "";
    try {
      s = atomicFile.fdSafeReadSync(paths.algorithm, { maxBytes: C.BYTES.kib(4) }).toString("utf8");
    } catch (_e) {
      if (_e && _e.code === "ENOENT") return undefined;
      throw _e;
    }
    return s.length > 0 ? s : undefined;
  }

  function _pendingCompletedJournalLabel() {
    /* c8 ignore next -- the sealed-mode key path is the same derivation reconcile()/_commitLocked() use; the read-only label consultation is exercised in the default (disabled) mode */
    var keyJournal = ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return undefined;
    var manifest;
    try {
      manifest = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
    /* c8 ignore next -- defensive: a corrupt/truncated journal is treated as "no pending label"; reconcile validates and quarantines it, so the read-only status path just falls back to the file */
    } catch (_je) { return undefined; }
    /* c8 ignore start -- defensive: a journal RETAINED by a deferred label persist always carries a
       customAlgorithm (retention is driven by it) AND a prior cert string (the deferral is only ever on a
       CA-changing commit over an existing cert), and paths.caCert is present (a journal exists only after
       a commit published a cert) — this guards a malformed/legacy/key-only-cold-start journal */
    if (!manifest || typeof manifest.customAlgorithm !== "string" || manifest.customAlgorithm.length === 0 ||
        typeof manifest.cert !== "string" || !nodeFs.existsSync(paths.caCert)) {
      return undefined;
    }
    /* c8 ignore stop */
    var liveCert = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }).toString("utf8");
    var priorCert = Buffer.from(manifest.cert, "base64").toString("utf8");
    return !_sameCert(liveCert, priorCert) ? manifest.customAlgorithm : undefined;
  }

  function _currentCustomLabel() {
    var pending = _pendingCompletedJournalLabel();
    return (pending !== undefined) ? pending : _readPersistedAlgorithm();
  }

  function _verifiedCASnapshot(certPem, keyPem) {
    if (!_caPairConsistent(certPem, keyPem)) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "the stored CA certificate and private key did not become a matching pair after re-reading " +
        "(a rotation may still be publishing, or the store is corrupt) — retry issuance");
    }
    _assertPinMatchesStoredCa(certPem, keyPem);
    return { caCertPem: certPem, caKeyPem: keyPem, algorithm: caAlgorithm };
  }

  async function _adoptExistingCASnapshot() {
    var existingCertPem = loadCert().toString("utf8");
    var existingKeyPem  = loadKey().toString("utf8");
    var pairTries = 0;
    while (!_caPairConsistent(existingCertPem, existingKeyPem) && pairTries < 8) {
      pairTries += 1;
      await safeAsync.sleep(10);
      existingCertPem = loadCert().toString("utf8");
      existingKeyPem  = loadKey().toString("utf8");
    }
    if (!_caPairConsistent(existingCertPem, existingKeyPem) ||
        nodeFs.existsSync(_commitJournalPath()) || !usesDefaultEngine) {
      var _snap;
      await atomicFile.lock(paths.caCert, function () {
        _reconcileCommitJournalLocked();
        existingCertPem = loadCert().toString("utf8");
        existingKeyPem  = loadKey().toString("utf8");
        if (!usesDefaultEngine) {
          var _persisted = _readPersistedAlgorithm();
          if (_persisted !== undefined) caAlgorithm = _persisted;
        }
        _snap = _verifiedCASnapshot(existingCertPem, existingKeyPem);
      });
      return _snap;
    }
    return _verifiedCASnapshot(existingCertPem, existingKeyPem);
  }

  var _initChain = Promise.resolve();
  async function _freshCreateSerialized() {
    if (exists()) {
      return _adoptExistingCASnapshot();
    }
    var caGenArgs = { generation: generation };
    if (caAlgorithm !== undefined) caGenArgs.algorithm = caAlgorithm;
    var fresh = await engine.generateCa(caGenArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    return atomicFile.lock(paths.caCert, function () {
      if (exists()) {
        _reconcileCommitJournalLocked();
        var adoptedCert = loadCert().toString("utf8");
        var adoptedKey  = loadKey().toString("utf8");
        if (!usesDefaultEngine) {
          var _adoptedLabel = _readPersistedAlgorithm();
          if (_adoptedLabel !== undefined) caAlgorithm = _adoptedLabel;
        }
        return _verifiedCASnapshot(adoptedCert, adoptedKey);
      }
      _commitLocked(fresh);
      return Object.assign({}, fresh, { algorithm: caAlgorithm });
    });
  }

  async function initCA() {
    if (exists()) {
      return _adoptExistingCASnapshot();
    }
    var next = _initChain.then(function () { return _freshCreateSerialized(); });
    _initChain = next.then(function () {}, function () {});
    return next;
  }

  function _certIdentity(certPem) {
    var serialNumber = null;
    try {
      serialNumber = _normalizeSerial(new nodeCrypto.X509Certificate(certPem).serialNumber);
    } catch (_e) {
      serialNumber = null;
    }
    var fingerprint;
    try {
      fingerprint = bCrypto().hashCertFingerprint(certPem).hex;
    } catch (_fpErr) {
      fingerprint = bCrypto().sha3Hash(certPem);
    }
    return {
      serialNumber: serialNumber,
      fingerprint:  fingerprint,
    };
  }

  function _leafEngineArgs(ca, opts2) {
    var leafAlg = usesDefaultEngine ? _labelForCaKeyType(ca.caKeyPem) : ca.algorithm;
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    if (leafAlg !== undefined) {
      if (opts2.algorithm !== undefined && opts2.algorithm !== leafAlg) {
        throw new MtlsCaError("mtls-ca/algorithm-conflict",
          "generateClientCert/generateClientP12: opts.algorithm " + JSON.stringify(opts2.algorithm) +
          " conflicts with the CA's algorithm " + JSON.stringify(leafAlg) +
          " (the leaf must match the CA; rotate to a fresh CA to change algorithms)");
      }
      args.algorithm = leafAlg;
    }
    return args;
  }

  async function generateClientCert(opts2) {
    opts2 = opts2 || {};
    var ca = await initCA();
    var args = _leafEngineArgs(ca, opts2);
    var result = await engine.signClientCert(args);
    if (!result || typeof result.cert !== "string" || typeof result.key !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.signClientCert must return { cert, key, ca?, issuedAt?, expiresAt? }");
    }
    var id = _certIdentity(result.cert);
    await _recordIssuance(ca.caCertPem, id);
    return Object.assign({}, result, { serialNumber: id.serialNumber, fingerprint: id.fingerprint });
  }

  async function generateClientP12(opts2) {
    opts2 = opts2 || {};
    if (!opts2.password || typeof opts2.password !== "string") {
      throw new MtlsCaError("mtls-ca/no-password",
        "generateClientP12 requires opts.password (the PKCS#12 encryption password)");
    }
    var ca = await initCA();
    var args = _leafEngineArgs(ca, opts2);
    var result = await engine.packageP12(args);
    if (!result || !Buffer.isBuffer(result.p12)) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return { p12: Buffer, certPem, issuedAt, expiresAt }");
    }
    if (typeof result.certPem !== "string" || result.certPem.length === 0) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return a non-empty certPem so the archive is recorded in the issuance " +
        "ledger — an unrecorded P12 could not be revoked by revokeGeneration()");
    }
    var id12 = _certIdentity(result.certPem);
    await _recordIssuance(ca.caCertPem, id12);
    return Object.assign({}, result, { serialNumber: id12.serialNumber, fingerprint: id12.fingerprint });
  }

  function _defaultFileStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.revocations)) return [];
      try {
        var json = safeJson.parse(atomicFile.fdSafeReadSync(paths.revocations, { maxBytes: STORE_READ_CAP, encoding: "utf8" }),
          { maxBytes: STORE_READ_CAP });
        return (json && Array.isArray(json.revocations)) ? json.revocations : [];
      } catch (e) {
        /* c8 ignore next 2 -- defensive: safeJson.parse throws an Error with a message, so the String(e) fallback is unreachable */
        throw new MtlsCaError("mtls-ca/revocation-corrupt",
          "could not parse " + paths.revocations + ": " + ((e && e.message) || String(e)));
      }
    }
    return {
      list: _list,
      add:  function (entry) {
        var entries = _list();
        entries.push(entry);
        _writeStoreCapped(paths.revocations,
          JSON.stringify({ revocations: entries }, null, 2) + "\n", { mode: 0o600 },
          "mtls-ca/revocation-registry-full", "revocation registry");
      },
      version: function () {
        try { var st = nodeFs.statSync(paths.revocations); return st.size + ":" + st.mtimeMs; }
        catch (_e) { return "0:0"; }
      },
    };
  }
  var usesDefaultRevocationStore = !opts.revocationStore;
  var revocationStore = opts.revocationStore || _defaultFileStore();
  validateOpts.requireMethods(revocationStore, ["list", "add"],
    "opts.revocationStore", MtlsCaError, "mtls-ca/bad-revocation-store");
  if ((typeof revocationStore.readGenerationWatermark === "function") !==
      (typeof revocationStore.bumpGenerationWatermark === "function")) {
    throw new MtlsCaError("mtls-ca/bad-revocation-store",
      "a revocationStore providing one of readGenerationWatermark() / bumpGenerationWatermark() must " +
      "provide BOTH — a split watermark would let a revoked generation still issue on another host");
  }

  function _readRevokedWatermark() {
    if (typeof revocationStore.readGenerationWatermark === "function") {
      var v = revocationStore.readGenerationWatermark();
      if (typeof v === "number" && isFinite(v) && v >= 0) return v;
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "revocationStore.readGenerationWatermark() returned a non-numeric value — refusing issuance rather " +
        "than treating a revoked generation as unrevoked");
    }
    if (!nodeFs.existsSync(paths.revokedGeneration)) return 0;
    var raw;
    try {
      raw = atomicFile.fdSafeReadSync(paths.revokedGeneration, { maxBytes: 64, encoding: "utf8" });
    } catch (e) {
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "the revoked-generation watermark (" + paths.revokedGeneration + ") exists but is unreadable (" +
        /* c8 ignore next -- String(e) fallback unreachable: a thrown fs Error always has a .message */
        ((e && e.message) || String(e)) + ") — refusing issuance rather than treating it as unrevoked");
    }
    var trimmed = String(raw).trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "the revoked-generation watermark (" + paths.revokedGeneration + ") is malformed — refusing issuance");
    }
    var n = parseInt(trimmed, 10);
    return n;
  }
  function _bumpRevokedWatermark(n) {
    if (typeof revocationStore.bumpGenerationWatermark === "function") {
      return Promise.resolve(revocationStore.bumpGenerationWatermark(n));
    }
    return atomicFile.lock(paths.revokedGeneration, function () {
      if (n > _readRevokedWatermark()) {
        atomicFile.writeSync(paths.revokedGeneration, String(n) + "\n", { mode: 0o600 });
      }
    });
  }

  var _revIndex = null;
  var _revSerialOnly = null;
  var _revIndexVersion = null;
  function _revIndexFor() {
    var hasVersion = typeof revocationStore.version === "function";
    var storeVersion = hasVersion ? revocationStore.version() : null;
    if (_revIndex === null || !hasVersion || storeVersion !== _revIndexVersion) {
      _revIndex = new Set();
      _revSerialOnly = new Set();
      revocationStore.list().forEach(function (r) {
        if (r && r.serialNumber) _revIndex.add(r.serialNumber);
        if (r && r.fingerprint) _revIndex.add(r.fingerprint);
        if (r && r.serialNumber && r.fingerprint == null) _revSerialOnly.add(r.serialNumber);
      });
      _revIndexVersion = storeVersion;
    }
    return _revIndex;
  }
  function _revSerialOnlyFor() { _revIndexFor(); return _revSerialOnly; }

  function _defaultIssuanceStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.issuance)) return [];
      var json;
      try {
        json = safeJson.parse(atomicFile.fdSafeReadSync(paths.issuance, { maxBytes: STORE_READ_CAP, encoding: "utf8" }),
          { maxBytes: STORE_READ_CAP });
      } catch (e) {
        /* c8 ignore next 2 -- defensive: safeJson.parse throws an Error with a message, so the String(e) fallback is unreachable */
        throw new MtlsCaError("mtls-ca/issuance-corrupt",
          "could not parse " + paths.issuance + ": " + ((e && e.message) || String(e)));
      }
      if (!json || !Array.isArray(json.issued)) {
        throw new MtlsCaError("mtls-ca/issuance-corrupt",
          paths.issuance + " is present but has no `issued` array (ledger schema corruption) — " +
          "refusing to treat a corrupt issuance ledger as empty");
      }
      return json.issued;
    }
    return {
      list: _list,
      add:  function (entry) {
        var entries = _list();
        entries.push(entry);
        _writeStoreCapped(paths.issuance,
          JSON.stringify({ issued: entries }, null, 2) + "\n", { mode: 0o600 },
          "mtls-ca/issuance-ledger-full", "issuance ledger");
      },
      version: function () {
        try { var st = nodeFs.statSync(paths.issuance); return st.size + ":" + st.mtimeMs; }
        catch (_e) { return "0:0"; }
      },
    };
  }
  var usesDefaultIssuanceStore = !opts.issuanceStore;
  var issuanceStore = opts.issuanceStore || _defaultIssuanceStore();
  validateOpts.requireMethods(issuanceStore, ["list", "add"],
    "opts.issuanceStore", MtlsCaError, "mtls-ca/bad-issuance-store");
  if (typeof revocationStore.readGenerationWatermark === "function" && usesDefaultIssuanceStore) {
    throw new MtlsCaError("mtls-ca/bad-issuance-store",
      "a clustered revocationStore (readGenerationWatermark/bumpGenerationWatermark) requires a shared " +
      "issuanceStore as well — the default per-host ledger would let revokeGeneration() miss certificates " +
      "issued on another host, leaving them accepted by the shared revocation gate");
  }

  async function _recordIssuance(caCertPem, id) {
    var parsedGen = parseGeneration(caCertPem);
    var gen = parsedGen >= 1 ? parsedGen : null;
    var entry = {
      serialNumber: id.serialNumber,
      fingerprint:  id.fingerprint,
      generation:   gen,
      caFingerprint: _certIdentity(caCertPem).fingerprint,
      issuedAt:     Date.now(),
    };
    try {
      if (usesDefaultIssuanceStore) {
        await atomicFile.lock(paths.issuance, function () { issuanceStore.add(entry); });
      } else {
        issuanceStore.add(entry);
      }
    } catch (e) {
      throw new MtlsCaError("mtls-ca/issuance-ledger-write-failed",
        "certificate " + id.serialNumber + " was signed but could not be recorded in the issuance " +
        /* c8 ignore next -- String(e) fallback unreachable: a thrown store Error always has a .message */
        "ledger (" + paths.issuance + "): " + ((e && e.message) || String(e)) +
        " — refusing to return an untracked credential revokeGeneration() could not later revoke");
    }
    if (typeof gen === "number" && gen < _readRevokedWatermark()) {
      /* c8 ignore next -- the ||null fallbacks are defensive API normalization: _certIdentity always yields a fingerprint, and a serial is present for every leaf a parseable-CA engine issues */
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "certificate for CA generation " + gen + " was issued while revokeGeneration() revoked that " +
        "generation (a concurrent rotation) — the certificate has been revoked; re-issue under the current generation");
    }
    var _issuingRoots = await loadTrustBundle();
    if (!_issuingRoots.some(function (root) { return _sameCert(root, caCertPem); })) {
      /* c8 ignore next -- the ||null fallbacks are defensive API normalization: _certIdentity always yields a fingerprint, and a serial is present for every leaf a parseable-CA engine issues */
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "the CA root this certificate was signed under was removed (a concurrent hard-cut rotation or " +
        "dropRetained()) before issuance completed — the certificate has been revoked; re-issue under the current CA");
    }
  }

  function _normalizeFingerprint(fp) {
    if (!fp || typeof fp !== "string") {
      throw new MtlsCaError("mtls-ca/bad-fingerprint", "fingerprint must be a non-empty string");
    }
    var stripped = fp.replace(/^0x/i, "").replace(/[:\-\s]/g, "");
    if (!safeBuffer.isHex(stripped)) {
      throw new MtlsCaError("mtls-ca/bad-fingerprint",
        "fingerprint contains non-hex characters: " + JSON.stringify(fp));
    }
    return stripped.toLowerCase();
  }

  function _normalizeGateFingerprint(fp) {
    var norm = _normalizeFingerprint(fp);
    if (norm.length !== SHA3_512_HEX_LEN) {
      throw new MtlsCaError("mtls-ca/bad-fingerprint",
        "fingerprint must be the framework's SHA3-512 leaf fingerprint (" + SHA3_512_HEX_LEN + " hex characters — the " +
        "value the require-mtls gate pins), got " + norm.length + ": a SHA-256 (64-hex) or truncated fingerprint would " +
        "be stored but never match the gate, leaving the certificate admitted");
    }
    return norm;
  }

  function _normalizeSerial(s) {
    if (!s || typeof s !== "string") {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number must be a non-empty string");
    }
    var stripped = s.replace(/^0x/i, "").replace(/[:\-\s]/g, "");
    if (!safeBuffer.isHex(stripped)) {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number contains non-hex characters " +
        "(allowed shapes: hex with optional 0x prefix, ':', '-', or whitespace " +
        "as separators): " + JSON.stringify(s));
    }
    return stripped.toLowerCase();
  }

  var CRL_REASON_BY_NAME = {
    "unspecified":          0,
    "keyCompromise":        1,
    "key-compromise":       1,
    "caCompromise":         2,
    "ca-compromise":        2,
    "affiliationChanged":   3,
    "superseded":           4,
    "cessationOfOperation": 5,
    "cessation-of-operation": 5,
    "certificateHold":      6,
    "privilegeWithdrawn":   9,
    "aACompromise":         10,
  };

  function _revokeCore(serial, fingerprint, reasonName, reasonCode) {
    var existing = revocationStore.list().find(function (r) {
      var serialMatch = serial && r.serialNumber === serial;
      var fingerprintMatch = fingerprint && r.fingerprint === fingerprint;
      if (!serialMatch && !fingerprintMatch) return false;
      var coversSerial = !serial || r.serialNumber === serial;
      var coversFingerprint = fingerprint ? (r.fingerprint === fingerprint) : (r.fingerprint == null);
      return coversSerial && coversFingerprint;
    });
    if (existing) {
      return existing;
    }
    var entry = {
      serialNumber: serial,
      fingerprint:  fingerprint,
      reason:       reasonName,
      reasonCode:   reasonCode,
      revokedAt:    Date.now(),
    };
    revocationStore.add(entry);
    return entry;
  }

  function revoke(idOrOpts, opts3) {
    var spec = (idOrOpts && typeof idOrOpts === "object") ? idOrOpts : null;
    opts3 = opts3 || {};
    var serialIn      = spec ? spec.serial      : idOrOpts;
    var fingerprintIn = spec ? spec.fingerprint : opts3.fingerprint;
    var reasonName    = (spec ? spec.reason : opts3.reason) || "unspecified";

    var serial = (serialIn !== undefined && serialIn !== null) ? _normalizeSerial(serialIn) : null;
    var fingerprint = (fingerprintIn !== undefined && fingerprintIn !== null)
      ? _normalizeGateFingerprint(fingerprintIn) : null;
    if (!serial && !fingerprint) {
      throw new MtlsCaError("mtls-ca/no-revocation-key",
        "revoke requires a serial number or a fingerprint " +
        "(revoke(serial, opts) or revoke({ serial, fingerprint }))");
    }
    if (reasonName === "removeFromCRL") {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revoke: 'removeFromCRL' (RFC 5280 code 8) is a delta-CRL un-revocation " +
        "directive, not a revocation reason — this CA issues full CRLs only, and a " +
        "persisted code-8 entry would make every generateCrl() fail");
    }
    var reasonCode = CRL_REASON_BY_NAME[reasonName];
    if (reasonCode === undefined) {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revoke: unknown reason '" + reasonName + "' (valid: " +
        Object.keys(CRL_REASON_BY_NAME).join(", ") + ")");
    }
    if (usesDefaultRevocationStore) {
      return atomicFile.lock(paths.revocations, function () {
        return _revokeCore(serial, fingerprint, reasonName, reasonCode);
      });
    }
    return Promise.resolve(_revokeCore(serial, fingerprint, reasonName, reasonCode));
  }

  function isRevoked(serialOrFingerprint) {
    if (!serialOrFingerprint || typeof serialOrFingerprint !== "string") {
      throw new MtlsCaError("mtls-ca/bad-revocation-key",
        "isRevoked requires a serial number or a fingerprint (hex string)");
    }
    var norm = _normalizeFingerprint(serialOrFingerprint);
    return _revIndexFor().has(norm);
  }

  function isSerialRevoked(serial) {
    if (!serial || typeof serial !== "string") {
      throw new MtlsCaError("mtls-ca/bad-revocation-key",
        "isSerialRevoked requires a serial number (hex string)");
    }
    return _revSerialOnlyFor().has(_normalizeFingerprint(serial));
  }

  function getRevocations() {
    return revocationStore.list().slice();
  }

  async function generateCrl(opts3) {
    opts3 = opts3 || {};
    if (typeof engine.generateCrl !== "function") {
      throw new MtlsCaError("mtls-ca/engine-no-crl",
        "configured engine does not implement generateCrl(); use the " +
        "framework's bundled CA engine, which supports it");
    }
    if (opts3.persist !== undefined && typeof opts3.persist !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-persist",
        "generateCrl: opts.persist must be a boolean when set (got " + JSON.stringify(opts3.persist) +
        ") — a non-boolean like the string \"false\" is not the literal false and would still persist the CRL");
    }
    var ca = await initCA();
    var allRevocations, revSnapshotVersion;
    var _snapshotRevocations = function () {
      allRevocations = revocationStore.list();
      revSnapshotVersion = (typeof revocationStore.version === "function") ? revocationStore.version() : null;
    };
    if (usesDefaultRevocationStore) { await atomicFile.lock(paths.revocations, _snapshotRevocations); }
    else { _snapshotRevocations(); }
    var _issuanceEntries, issuanceSnapshotVersion;
    var _snapshotIssuance = function () {
      _issuanceEntries = issuanceStore.list();
      issuanceSnapshotVersion = (typeof issuanceStore.version === "function") ? issuanceStore.version() : null;
    };
    if (usesDefaultIssuanceStore) { await atomicFile.lock(paths.issuance, _snapshotIssuance); }
    else { _snapshotIssuance(); }
    var currentCaId = _certIdentity(ca.caCertPem).fingerprint;
    var _caIdByFingerprint = new Map();
    var _caIdsBySerial = new Map();
    _issuanceEntries.forEach(function (e) {
      if (!e || e.caFingerprint == null) return;
      if (e.fingerprint != null) _caIdByFingerprint.set(e.fingerprint, e.caFingerprint);
      if (e.serialNumber != null) {
        if (!_caIdsBySerial.has(e.serialNumber)) _caIdsBySerial.set(e.serialNumber, new Set());
        _caIdsBySerial.get(e.serialNumber).add(e.caFingerprint);
      }
    });
    var _entryCaIdentity = function (r) {
      if (r.fingerprint != null && _caIdByFingerprint.has(r.fingerprint)) return _caIdByFingerprint.get(r.fingerprint);
      var ids = _caIdsBySerial.get(r.serialNumber);
      if (ids && ids.size === 1) return ids.values().next().value;
      return null;
    };
    var seenSerials = new Set();
    var revocations = allRevocations.filter(function (r) {
      if (!(r && r.serialNumber != null)) return false;
      if (currentCaId != null) {
        var ei = _entryCaIdentity(r);
        if (ei != null && ei !== currentCaId) return false;
      }
      if (seenSerials.has(r.serialNumber)) return false;
      seenSerials.add(r.serialNumber);
      return true;
    });
    var _scopedCrlSerials = function (revList, issList) {
      var byFp = new Map(), bySerial = new Map();
      issList.forEach(function (e) {
        if (!e || e.caFingerprint == null) return;
        if (e.fingerprint != null) byFp.set(e.fingerprint, e.caFingerprint);
        if (e.serialNumber != null) {
          if (!bySerial.has(e.serialNumber)) bySerial.set(e.serialNumber, new Set());
          bySerial.get(e.serialNumber).add(e.caFingerprint);
        }
      });
      var resolve = function (r) {
        if (r.fingerprint != null && byFp.has(r.fingerprint)) return byFp.get(r.fingerprint);
        var ids = bySerial.get(r.serialNumber);
        if (ids && ids.size === 1) return ids.values().next().value;
        return null;
      };
      var seen = {}, out = [];
      revList.forEach(function (r) {
        if (!(r && r.serialNumber != null)) return;
        if (currentCaId != null) { var ei = resolve(r); if (ei != null && ei !== currentCaId) return; }
        if (seen[r.serialNumber]) return;
        seen[r.serialNumber] = 1; out.push(r.serialNumber);
      });
      return out.sort().join(",");
    };
    var signedCrlSerials = revocations.map(function (r) { return r.serialNumber; }).slice().sort().join(",");
    var fingerprintOnlyOmitted = allRevocations.filter(function (r) {
      return r && r.serialNumber == null;
    }).length;
    var nowMs = Date.now();
    var thisUpdate = opts3.thisUpdate || new Date(nowMs);
    var nextUpdate = opts3.nextUpdate ||
                     new Date(nowMs + C.TIME.days(7));
    var crlPem = await engine.generateCrl({
      caCertPem:   ca.caCertPem,
      caKeyPem:    ca.caKeyPem,
      revocations: revocations,
      thisUpdate:  thisUpdate,
      nextUpdate:  nextUpdate,
    });
    if (typeof crlPem !== "string" || crlPem.length === 0) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCrl must return a non-empty PEM string");
    }
    var persisted = false;
    if (opts3.persist !== false) {
      await atomicFile.lock(paths.caCert, function () {
        if (!(nodeFs.existsSync(paths.caCert) &&
              _sameCert(atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }).toString("utf8"), ca.caCertPem))) {
          return;
        }
        var _writeCrl = function () {
          atomicFile.writeSync(paths.crl, crlPem, { fileMode: 0o644 });
          persisted = true;
        };
        var _persistIfScopeUnchanged = function () {
          var revFresh = usesDefaultRevocationStore ? revocationStore.list() : allRevocations;
          var issFresh = usesDefaultIssuanceStore ? issuanceStore.list() : _issuanceEntries;
          var revUnchanged = !usesDefaultRevocationStore || revocationStore.version() === revSnapshotVersion;
          var issUnchanged = !usesDefaultIssuanceStore || issuanceStore.version() === issuanceSnapshotVersion;
          if ((revUnchanged && issUnchanged) ||
              _scopedCrlSerials(revFresh, issFresh) === signedCrlSerials) { _writeCrl(); }
        };
        var _underIssuanceLock = function () {
          if (usesDefaultIssuanceStore) {
            return atomicFile.lock(paths.issuance, _persistIfScopeUnchanged);
          }
          return _persistIfScopeUnchanged();
        };
        if (usesDefaultRevocationStore) {
          return atomicFile.lock(paths.revocations, _underIssuanceLock);
        }
        return _underIssuanceLock();
      });
    }
    return { crlPem: crlPem, thisUpdate: thisUpdate, nextUpdate: nextUpdate,
             entryCount: revocations.length,
             fingerprintOnlyOmitted: fingerprintOnlyOmitted,
             persisted: persisted,
             path: paths.crl };
  }

  var _rotateChain = Promise.resolve();
  function rotate(rotateOpts) {
    var next = _rotateChain.then(function () { return _rotateImpl(rotateOpts); },
                                 function () { return _rotateImpl(rotateOpts); });
    _rotateChain = next.then(function () {}, function () {});
    return next;
  }

  async function _rotateImpl(rotateOpts) {
    rotateOpts = rotateOpts || {};
    if (rotateOpts.algorithm !== undefined &&
        (typeof rotateOpts.algorithm !== "string" || rotateOpts.algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "rotate: algorithm must be a non-empty string label when set (e.g. \"ECDSA-P384-SHA384\")");
    }
    if (rotateOpts.retainPrevious !== undefined && typeof rotateOpts.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-retain-previous",
        "rotate: retainPrevious must be a boolean when set (got " + JSON.stringify(rotateOpts.retainPrevious) +
        ") — a non-boolean like the string \"false\" is not the literal false and would retain the outgoing root");
    }
    var st = status();
    var previousCaCertPem = st.exists ? loadCert().toString("utf8") : null;
    var curGen = st.exists ? st.generation : 0;
    var previousPersistedLabel = !usesDefaultEngine ? _readPersistedAlgorithm() : undefined;
    if (st.exists && curGen === 0) {
      throw new MtlsCaError("mtls-ca/generation-undeterminable",
        "the stored CA's generation cannot be determined — its certificate did not parse to a generation on " +
        "this runtime, so rotation cannot compute or validate a strictly-increasing generation. Causes: a " +
        "custom-engine certificate node:crypto cannot classify; the bundled certificate on a runtime that " +
        "cannot parse its algorithm (e.g. an ML-DSA CA on a Node/OpenSSL build without ML-DSA support); or a " +
        "corrupt/truncated ca.crt. Restore a valid ca.crt from backup, run on a runtime that parses the " +
        "certificate's algorithm, or (custom engine) use one whose certificate encodes a parseable generation " +
        "(OU=CAv<n>); a fresh dataDir resets generations only for a genuinely new CA.");
    }
    if (rotateOpts.generation !== undefined && rotateOpts.generation !== null &&
        (typeof rotateOpts.generation !== "number" || !Number.isInteger(rotateOpts.generation))) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation must be a positive integer, got " + JSON.stringify(rotateOpts.generation));
    }
    var newGen = (rotateOpts.generation !== undefined && rotateOpts.generation !== null)
      ? rotateOpts.generation : curGen + 1;
    /* c8 ignore next 4 -- defensive: newGen is a validated integer >= 1 (rotateOpts.generation validated above, else curGen+1), so this never throws */
    if (typeof newGen !== "number" || !isFinite(newGen) || newGen < 1) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation must be a positive integer, got " + JSON.stringify(rotateOpts.generation));
    }
    if (st.exists && newGen <= curGen) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "rotate: generation " + newGen + " must be greater than the current CA generation " +
        curGen + " — a rotation moves forward (use a fresh dataDir to reset generations)");
    }
    var genArgs = { generation: newGen };
    var pin = rotateOpts.algorithm !== undefined ? rotateOpts.algorithm : caAlgorithm;
    if (rotateOpts.algorithm === undefined && !usesDefaultEngine) {
      var _persistedPin = _readPersistedAlgorithm();
      if (_persistedPin !== undefined) pin = _persistedPin;
    }
    if (pin === undefined && usesDefaultEngine && previousCaCertPem !== null) {
      /* c8 ignore next -- the ||undefined fallback is unreachable: a default-engine CA cert always classifies to a non-null algorithm (ML-DSA / ECDSA-P384) */
      pin = _certAlgorithm(previousCaCertPem).algorithm || undefined;
    }
    if (pin !== undefined) genArgs.algorithm = pin;
    var fresh = await engine.generateCa(genArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    var retain = rotateOpts.retainPrevious !== false && previousCaCertPem !== null;
    await atomicFile.lock(paths.caCert, function () {
      _reconcileCommitJournalLocked();
      var nowSt = status();
      var nowGen = nowSt.exists ? nowSt.generation : 0;
      var nowCert = nowSt.exists ? loadCert().toString("utf8") : null;
      var nowCertChanged = (nowCert === null || previousCaCertPem === null)
        ? nowCert !== previousCaCertPem
        : !_sameCert(nowCert, previousCaCertPem);
      var nowLabelChanged = !usesDefaultEngine && _readPersistedAlgorithm() !== previousPersistedLabel;
      if (nowGen !== curGen || nowCertChanged || nowLabelChanged) {
        throw new MtlsCaError("mtls-ca/rotation-conflict",
          "the CA changed (generation " + curGen + " -> " + nowGen + ", a same-generation replacement, or a " +
          "concurrent algorithm-label migration) during rotation — a concurrent rotate/commit on another handle " +
          "or process. Retry against the current CA");
      }
      _commitLocked({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: retain,
        algorithm: (rotateOpts.algorithm !== undefined ? rotateOpts.algorithm : pin) });
      if (rotateOpts.algorithm !== undefined) {
        caAlgorithm = rotateOpts.algorithm;
      } else if (!usesDefaultEngine && pin !== undefined) {
        caAlgorithm = pin;
      }
    });
    caLog.info("rotated CA", { generation: newGen, retainedPrevious: retain });
    return {
      caCertPem:         fresh.caCertPem,
      previousCaCertPem: previousCaCertPem,
      generation:        newGen,
      algorithm:         usesDefaultEngine
        ? _certAlgorithm(fresh.caCertPem).algorithm
        : (pin !== undefined ? pin : null),
    };
  }

  function _readCurrentCert() {
    return nodeFs.existsSync(paths.caCert) ? loadCert().toString("utf8") : null;
  }
  function _readRetainedRoot() {
    if (!nodeFs.existsSync(paths.caCertPrev)) return null;
    try {
      return atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }).toString("utf8");
    } catch (e) {
      /* c8 ignore next 2 -- concurrent-removal race path: the retained-root read rarely throws in tests (ENOENT -> null; any other error re-throws) */
      if (!e || e.code !== "ENOENT") throw e;
      return null;
    }
  }
  function _journalRetainedRoot() {
    var keyJournal = ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return null;
    try {
      var m = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
      if (m && m.prevAction === "restore" && m.retainAfter !== false &&
          _validManifestB64Field(m.prevData) && typeof m.prevData === "string" &&
          _validManifestB64Field(m.cert) && typeof m.cert === "string") {
        var priorCertBuf = Buffer.from(m.cert, "base64");
        var curBuf = nodeFs.existsSync(paths.caCert)
          ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }) : null;
        if (curBuf !== null && Buffer.from(curBuf).equals(priorCertBuf)) {
          return Buffer.from(m.prevData, "base64").toString("utf8");
        }
      }
    } catch (_e) { /* unreadable journal — the locked reconcile handles it */ }
    return null;
  }
  function _trustRoots() {
    var cur = null;
    var bundle = null;
    for (var attempt = 0; attempt < 8 && bundle === null; attempt += 1) {
      cur = _readCurrentCert();
      var prev = _readRetainedRoot();
      if (cur === _readCurrentCert() && prev === _readRetainedRoot()) {
        bundle = [];
        if (cur) bundle.push(cur);
        if (prev && prev !== cur) bundle.push(prev);
      }
    }
    /* c8 ignore next -- retry-exhausted fallback: the 8-attempt stable-snapshot loop sets bundle on the first pass (a rotation completes in microseconds), so bundle===null is unreachable */
    if (bundle === null) bundle = cur ? [cur] : [];
    var journalRoot = _journalRetainedRoot();
    if (journalRoot && bundle.indexOf(journalRoot) === -1) bundle.push(journalRoot);
    return bundle;
  }
  function loadTrustBundle() {
    return atomicFile.lock(paths.caCert, function () { return _trustRoots(); });
  }

  function dropRetained() {
    return atomicFile.lock(paths.caCert, function () {
      _reconcileCommitJournalLocked();
      var had = nodeFs.existsSync(paths.caCertPrev);
      if (had) {
        nodeFs.unlinkSync(paths.caCertPrev);
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      return { dropped: had };
    });
  }

  function importIssuance(entries) {
    if (!Array.isArray(entries)) {
      throw new MtlsCaError("mtls-ca/bad-import",
        "importIssuance requires an array of { fingerprint, generation, serialNumber? } entries");
    }
    var normalized = entries.map(function (e) {
      if (!e || typeof e !== "object") {
        throw new MtlsCaError("mtls-ca/bad-import", "each importIssuance entry must be an object");
      }
      if (typeof e.generation !== "number" || !Number.isInteger(e.generation) || e.generation < 1) {
        throw new MtlsCaError("mtls-ca/bad-import", "importIssuance entry.generation must be a positive integer");
      }
      var fp = (e.fingerprint !== undefined && e.fingerprint !== null) ? _normalizeGateFingerprint(e.fingerprint) : null;
      var serial = (e.serialNumber !== undefined && e.serialNumber !== null) ? _normalizeSerial(e.serialNumber) : null;
      if (!fp) {
        throw new MtlsCaError("mtls-ca/bad-import",
          "importIssuance entry requires a fingerprint (the globally-unique SHA3-512 identity the require-mtls gate " +
          "pins) — a serial number is unique only per issuer, so a serial-only entry would be generation-revoked into a " +
          "fingerprint-null revocation that false-revokes an unrelated current certificate reusing the serial; supply the " +
          "certificate's fingerprint (serialNumber may accompany it for the CRL)");
      }
      if (e.caCert !== undefined && e.caCert !== null && typeof e.caCert !== "string") {
        throw new MtlsCaError("mtls-ca/bad-import", "importIssuance entry.caCert must be a PEM string (the issuing CA certificate) when set");
      }
      var caFp = (e.caCert !== undefined && e.caCert !== null) ? _certIdentity(e.caCert).fingerprint : null;
      return { serialNumber: serial, fingerprint: fp, generation: e.generation, caFingerprint: caFp, issuedAt: e.issuedAt || Date.now() };
    });
    var add = function () { normalized.forEach(function (n) { issuanceStore.add(n); }); };
    var run = usesDefaultIssuanceStore ? atomicFile.lock(paths.issuance, add) : Promise.resolve(add());
    return run.then(function () {
      var wm = _readRevokedWatermark();
      var superseded = normalized.filter(function (n) { return n.generation < wm; });
      return Promise.all(superseded.map(function (n) {
        return revoke({ serial: n.serialNumber || null, fingerprint: n.fingerprint, reason: "superseded" });
      })).then(function () { return { imported: normalized.length, revoked: superseded.length }; });
    });
  }

  function revokeGeneration(n, opts3) {
    if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) {
      throw new MtlsCaError("mtls-ca/bad-generation",
        "revokeGeneration: n must be a positive integer (revokes every cert issued under a CA generation < n)");
    }
    opts3 = opts3 || {};
    var reason = opts3.reason || "superseded";
    var reasonCode = CRL_REASON_BY_NAME[reason];
    if (reasonCode === undefined) {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revokeGeneration: unknown reason '" + reason + "' (valid: " +
        Object.keys(CRL_REASON_BY_NAME).join(", ") + ")");
    }
    var sweep = function () {
      var before = revocationStore.list().length;
      issuanceStore.list().forEach(function (e) {
        if (e && typeof e.generation === "number" && e.generation < n && (e.serialNumber || e.fingerprint)) {
          _revokeCore(e.serialNumber || null, e.fingerprint || null, reason, reasonCode);
        }
      });
      return { revoked: revocationStore.list().length - before };
    };
    return _bumpRevokedWatermark(n).then(function () {
      return usesDefaultRevocationStore ? atomicFile.lock(paths.revocations, sweep) : Promise.resolve(sweep());
    });
  }

  async function canVerifyInTls(algorithm) {
    if (typeof engine.canVerifyInTls !== "function") {
      throw new MtlsCaError("mtls-ca/no-tls-probe",
        "the configured engine does not implement canVerifyInTls(label)");
    }
    if (algorithm !== undefined && (typeof algorithm !== "string" || algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "canVerifyInTls(algorithm) requires a non-empty string algorithm label when provided " +
        "(e.g. \"ML-DSA-87\"); omit the argument to probe the stored CA");
    }
    var st = status();
    var _effectiveCustomLabel = caAlgorithm;
    if (!usesDefaultEngine) {
      var _persistedLabel = _currentCustomLabel();
      if (_persistedLabel !== undefined) _effectiveCustomLabel = _persistedLabel;
    }
    var label = (typeof algorithm === "string" && algorithm.length > 0)
      ? algorithm
      : (usesDefaultEngine ? (st.algorithm || caAlgorithm) : (_effectiveCustomLabel || st.algorithm));
    if ((typeof label !== "string" || label.length === 0) && st.exists) {
      throw new MtlsCaError("mtls-ca/algorithm-undeterminable",
        "canVerifyInTls() cannot derive the stored CA's algorithm (a custom-engine CA this runtime does " +
        "not classify, with no create-time pin) — pass the algorithm explicitly, e.g. canVerifyInTls(\"ML-DSA-87\")");
    }
    return engine.canVerifyInTls(label);
  }

  return {
    exists:               exists,
    keyExists:            keyExists,
    status:               status,
    loadKey:              loadKey,
    loadCert:             loadCert,
    loadTrustBundle:      loadTrustBundle,
    commit:               commit,
    initCA:               initCA,
    rotate:               rotate,
    dropRetained:         dropRetained,
    canVerifyInTls:       canVerifyInTls,
    revokeGeneration:     revokeGeneration,
    importIssuance:       importIssuance,
    generateClientCert:   generateClientCert,
    generateClientP12:    generateClientP12,
    revoke:               revoke,
    isRevoked:            isRevoked,
    isSerialRevoked:      isSerialRevoked,
    getRevocations:       getRevocations,
    generateCrl:          generateCrl,
    paths:                paths,
    generation:           generation,
    caKeySealedMode:      caKeySealedMode,
  };
}

module.exports = {
  create:           create,
  parseGeneration:  parseGeneration,
  MtlsCaError:      MtlsCaError,
  DEFAULT_PATHS:    DEFAULT_PATHS,
};
