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
 *   engine lives in `lib/mtls-engine-default.js` (backed by the
 *   vendored @peculiar/x509 + pkijs bundle); operators with custom
 *   requirements pass their own via `opts.engine`.
 *
 *   Files relative to `dataDir`: `ca.crt` (PEM cert, plaintext),
 *   `ca.key` (PEM key, plaintext — refused under `caKeySealedMode:
 *   "required"`), `ca.key.sealed` (vault.seal of the PEM bytes — the
 *   default at-rest shape), `revocations.json` (revocation registry),
 *   `ca.crl` (signed CRL derived from the registry).
 *
 *   `caKeySealedMode` defaults to "required" — sealed file required,
 *   plaintext refused. The legacy "auto" fallback was removed; it
 *   defaulted to writing plaintext on a fresh install, which is the
 *   inverse of the framework's security-defaults-on posture for
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
 *   fingerprint — the framework hashes the cert via
 *   `b.crypto.sha3Hash(certPem)` so the SHA3-512 posture stays
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
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// The default engine carries a 600+ KB vendored bundle (peculiar/x509 +
// pkijs + reflect-metadata). Lazy-require it so operators wiring a
// custom engine never pay the cost. The lazyRequire wrapper keeps the
// require at top-of-file declaration shape — no indented inline calls.
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
  // Revocation registry — JSON file under dataDir tracking revoked
  // serial numbers. Operators export this as a CRL via
  // ca.generateCrl() (engine.generateCrl signs the list with the CA
  // key). Persisted as JSON rather than a stored CRL because the
  // signed CRL is a derivative artifact — the registry survives CA
  // rotation, the CRL doesn't.
  revocations:  "revocations.json",
  crl:          "ca.crl",
};

var VALID_SEAL_MODES = { required: 1, disabled: 1 };

// Resolve relative path entries under `dataDir`; pass absolute paths
// through unchanged. The pre-v0.8.58 shape always joined under
// dataDir, which silently overrode an operator-supplied absolute
// path (e.g. `MTLS_CA_KEY=/etc/ssl/ca.key` → `<dataDir>/etc/ssl/ca.key`).
// Standard Node `nodePath.join` semantics already preserve absolute
// arguments — the always-join was an oversight, not by design.
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
  };
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
    var subj = cert.subject || "";
    var m = /OU=CAv(\d+)/.exec(subj);
    return m ? parseInt(m[1], 10) : 1;
  } catch (_e) {
    return 0;
  }
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
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "paths", "vault",
    "caKeySealedMode", "generation", "engine",
  ], "b.mtlsCa");
  validateOpts.requireNonEmptyString(opts.dataDir, "mtlsCa.create: opts.dataDir", MtlsCaError, "mtls-ca/no-datadir");
  // Auto-create the dataDir with restrictive perms (CA keys live here).
  // Matches the behaviour of other framework primitives that own a
  // dataDir — log-stream-local, backup, restore-bundle. Without this
  // the first initCA() / generateClientCert() call fails with ENOENT
  // on `ca.key.tmp` because the atomic-file write expects the parent
  // dir to exist.
  if (!nodeFs.existsSync(opts.dataDir)) {
    nodeFs.mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  }
  var paths = _resolvePaths(opts.dataDir, opts.paths);
  var vault = opts.vault || null;
  var caKeySealedMode = (opts.caKeySealedMode || "required").toLowerCase();
  if (!VALID_SEAL_MODES[caKeySealedMode]) {
    throw new MtlsCaError("mtls-ca/bad-mode",
      "caKeySealedMode must be 'required' or 'disabled' " +
      "(legacy 'auto' was removed — it defaulted to plaintext-on-disk)");
  }
  var generation = typeof opts.generation === "number" && opts.generation >= 1
    ? Math.floor(opts.generation) : 1;
  // The default engine is lazy-loaded at top-of-file; resolve it only
  // when no custom engine was passed.
  var engine = opts.engine || mtlsEngineDefault();

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
      };
    }
    var pem = nodeFs.readFileSync(paths.caCert);
    var gen = parseGeneration(pem);
    return {
      exists:     true,
      generation: gen,
      isLegacy:   gen < generation,
      current:    generation,
    };
  }

  // Load the CA key in whichever form is on disk, applying the
  // caKeySealedMode dispatch. Returns Buffer of PEM bytes, or throws
  // with a precise reason when the mode rejects the on-disk form.
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
      var sealedBytes = nodeFs.readFileSync(paths.caKeySealed, "utf8").trim();
      var pem = vault.unseal(sealedBytes);
      if (!pem) {
        throw new MtlsCaError("mtls-ca/unseal-failed",
          "vault.unseal of " + paths.caKeySealed + " returned empty — vault key mismatch?");
      }
      return Buffer.from(pem, "utf8");
    }
    // disabled: plaintext only.
    if (!hasPlain) {
      throw new MtlsCaError("mtls-ca/plain-required",
        "caKeySealedMode='disabled' but " + paths.caKey + " does not exist");
    }
    return nodeFs.readFileSync(paths.caKey);
  }

  function loadCert() {
    if (!nodeFs.existsSync(paths.caCert)) {
      throw new MtlsCaError("mtls-ca/missing-cert",
        "no CA cert on disk at " + paths.caCert);
    }
    return nodeFs.readFileSync(paths.caCert);
  }

  // Atomic commit: write .tmp + atomic rename for both key and cert.
  // Honors caKeySealedMode — when 'required' (the default), the key is
  // vault-sealed before the on-disk write so plaintext PEM never touches
  // the filesystem; when 'disabled', it goes to disk as PEM with the
  // operator's audited reason on record.
  function commit(opts2) {
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    var keyTmp = keyDest + ".tmp";
    var certTmp = paths.caCert + ".tmp";

    // CodeQL js/insecure-temporary-file defense — exclusive-create ("wx")
    // refuses to write through a pre-existing path (symlink or regular
    // file). keyTmp / certTmp live under the operator-supplied dataDir
    // (owner-only 0o700 framework dir established by atomicFile.ensureDir
    // upstream), but exclusive-create hardens against a residual tmp file
    // from a crashed prior commit or an attacker who pre-creates the
    // path as a symlink. EEXIST surfaces as the commit-failed error.
    function _writeExclusive(path, data, mode) {
      var fd = nodeFs.openSync(path, "wx", mode);
      try {
        var buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        var w = 0;
        while (w < buf.length) {
          w += nodeFs.writeSync(fd, buf, w, buf.length - w, null);
        }
        try { nodeFs.fsyncSync(fd); } catch (_fe) { /* fsync best-effort */ }
      } finally {
        try { nodeFs.closeSync(fd); } catch (_ce) { /* close best-effort */ }
      }
    }
    try {
      if (sealed) {
        _requireVault("sealed CA key commit");
        _writeExclusive(keyTmp, vault.seal(opts2.caKeyPem), 0o600);
      } else {
        _writeExclusive(keyTmp, opts2.caKeyPem, 0o600);
      }
      _writeExclusive(certTmp, opts2.caCertPem, 0o644);
      nodeFs.renameSync(keyTmp, keyDest);
      nodeFs.renameSync(certTmp, paths.caCert);
    } catch (e) {
      // Best-effort cleanup of half-written tmp files; the original
      // commit error is what we re-raise. Log cleanup failures at debug
      // so a genuinely-broken filesystem state surfaces in operator logs
      // rather than getting silently swallowed.
      try { if (nodeFs.existsSync(keyTmp))  nodeFs.unlinkSync(keyTmp); }
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyTmp, error: cleanupErr.message }); }
      try { if (nodeFs.existsSync(certTmp)) nodeFs.unlinkSync(certTmp); }
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: certTmp, error: cleanupErr.message }); }
      throw new MtlsCaError("mtls-ca/commit-failed",
        "atomic CA commit failed: " + ((e && e.message) || String(e)));
    }
    return {
      keyPath:  keyDest,
      certPath: paths.caCert,
      sealed:   sealed,
    };
  }

  async function initCA() {
    if (exists()) {
      return { caCertPem: loadCert().toString("utf8"), caKeyPem: loadKey().toString("utf8") };
    }
    var fresh = await engine.generateCa({ generation: generation });
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    commit(fresh);
    return fresh;
  }

  async function generateClientCert(opts2) {
    opts2 = opts2 || {};
    var ca = await initCA();
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    var result = await engine.signClientCert(args);
    if (!result || typeof result.cert !== "string" || typeof result.key !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.signClientCert must return { cert, key, ca?, issuedAt?, expiresAt? }");
    }
    return result;
  }

  async function generateClientP12(opts2) {
    opts2 = opts2 || {};
    if (!opts2.password || typeof opts2.password !== "string") {
      throw new MtlsCaError("mtls-ca/no-password",
        "generateClientP12 requires opts.password (the PKCS#12 encryption password)");
    }
    var ca = await initCA();
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    var result = await engine.packageP12(args);
    if (!result || !Buffer.isBuffer(result.p12)) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return { p12: Buffer, certPem, issuedAt, expiresAt }");
    }
    return result;
  }

  // ---- Revocation registry + CRL ----

  function _loadRevocations() {
    if (!nodeFs.existsSync(paths.revocations)) return { revocations: [] };
    try {
      // safeJson.parse caps depth + size + protects against
      // proto-pollution; the revocation file is under the operator's
      // dataDir but a tampered or truncated file shouldn't be able to
      // corrupt the rotator process.
      var json = safeJson.parse(nodeFs.readFileSync(paths.revocations, "utf8"),
        { maxBytes: C.BYTES.mib(16) });
      if (!json || !Array.isArray(json.revocations)) return { revocations: [] };
      return json;
    } catch (e) {
      throw new MtlsCaError("mtls-ca/revocation-corrupt",
        "could not parse " + paths.revocations + ": " +
        ((e && e.message) || String(e)));
    }
  }

  function _saveRevocations(state) {
    atomicFile.writeSync(paths.revocations,
      JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  }

  function _normalizeSerial(s) {
    if (!s || typeof s !== "string") {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number must be a non-empty string");
    }
    // Strip the optional leading `0x` and any common separators
    // (`:` or `-` or whitespace). What remains MUST be hex — otherwise
    // we silently accept gibberish like "xyz-not-hex" (which previously
    // normalised to a single "e" because the strip-non-hex regex left
    // exactly one valid char). Operators pasting an openssl-printed
    // serial use any of: "0xABC123", "AB:C1:23", "AB-C1-23", "abc 123";
    // a typo or non-serial string fails fast instead of registering a
    // phantom revocation row.
    var stripped = s.replace(/^0x/i, "").replace(/[:\-\s]/g, "");
    if (!safeBuffer.isHex(stripped)) {
      throw new MtlsCaError("mtls-ca/bad-serial",
        "serial number contains non-hex characters " +
        "(allowed shapes: hex with optional 0x prefix, ':', '-', or whitespace " +
        "as separators): " + JSON.stringify(s));
    }
    return stripped.toLowerCase();
  }

  // Map operator-friendly reason codes to RFC 5280 numeric codes used
  // by X.509 CRLs. Default "unspecified" (0) when omitted. removeFromCRL
  // uses hex 0x08 to express RFC 5280's reason code 8 — the literal is a
  // protocol identifier, not a byte quantity.
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
    "removeFromCRL":        0x08,
    "privilegeWithdrawn":   9,
    "aACompromise":         10,
  };

  function revoke(serialNumber, opts3) {
    var serial = _normalizeSerial(serialNumber);
    opts3 = opts3 || {};
    var reasonName = opts3.reason || "unspecified";
    var reasonCode = CRL_REASON_BY_NAME[reasonName];
    if (reasonCode === undefined) {
      throw new MtlsCaError("mtls-ca/bad-reason",
        "revoke: unknown reason '" + reasonName + "' (valid: " +
        Object.keys(CRL_REASON_BY_NAME).join(", ") + ")");
    }
    var state = _loadRevocations();
    var existing = state.revocations.find(function (r) {
      return r.serialNumber === serial;
    });
    if (existing) {
      // Idempotent — repeated revoke() of the same serial doesn't
      // shift the revokedAt timestamp.
      return existing;
    }
    var entry = {
      serialNumber: serial,
      reason:       reasonName,
      reasonCode:   reasonCode,
      revokedAt:    Date.now(),
    };
    state.revocations.push(entry);
    _saveRevocations(state);
    return entry;
  }

  function isRevoked(serialNumber) {
    var serial = _normalizeSerial(serialNumber);
    var state = _loadRevocations();
    return state.revocations.some(function (r) {
      return r.serialNumber === serial;
    });
  }

  function getRevocations() {
    return _loadRevocations().revocations.slice();
  }

  // Generate a signed X.509 CRL covering every entry in the registry.
  // RFC 5280 — issuer = CA subject, signed by the CA private key.
  // Operators publish the resulting PEM at a CRL distribution point
  // referenced from issued certs (cert extension support is on the
  // engine roadmap; for now operators set up the URL externally).
  async function generateCrl(opts3) {
    opts3 = opts3 || {};
    if (typeof engine.generateCrl !== "function") {
      throw new MtlsCaError("mtls-ca/engine-no-crl",
        "configured engine does not implement generateCrl(); use the " +
        "framework's bundled CA engine, which supports it");
    }
    var ca = await initCA();
    var revocations = _loadRevocations().revocations;
    var nowMs = Date.now();
    var thisUpdate = opts3.thisUpdate || new Date(nowMs);
    var nextUpdate = opts3.nextUpdate ||
                     new Date(nowMs + C.TIME.days(7));   // 7d default
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
    if (opts3.persist !== false) {
      atomicFile.writeSync(paths.crl, crlPem, { mode: 0o644 });
    }
    return { crlPem: crlPem, thisUpdate: thisUpdate, nextUpdate: nextUpdate,
             entryCount: revocations.length, path: paths.crl };
  }

  return {
    exists:               exists,
    keyExists:            keyExists,
    status:               status,
    loadKey:              loadKey,
    loadCert:             loadCert,
    commit:               commit,
    initCA:               initCA,
    generateClientCert:   generateClientCert,
    generateClientP12:    generateClientP12,
    revoke:               revoke,
    isRevoked:            isRevoked,
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
