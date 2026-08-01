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
  // Revocation registry — JSON file under dataDir tracking revoked
  // serial numbers. Operators export this as a CRL via
  // ca.generateCrl() (engine.generateCrl signs the list with the CA
  // key). Persisted as JSON rather than a stored CRL because the
  // signed CRL is a derivative artifact — the registry survives CA
  // rotation, the CRL doesn't.
  revocations:  "revocations.json",
  crl:          "ca.crl",
  // Superseded-CA snapshot for a re-enrollment grace window. `commit({
  // retainPrevious: true })` copies the outgoing ca.crt here before the new
  // one lands; `loadTrustBundle()` returns [current, ...retained] so live
  // clients holding a cert from the old CA still verify while they re-enroll;
  // `dropRetained()` ends the window.
  caCertPrev:   "ca.prev.crt",
  // Issuance ledger — append-only JSON index of every leaf this CA has signed
  // ({ serialNumber, fingerprint, generation, issuedAt }). `revokeGeneration(n)`
  // reads it to revoke every cert issued under a CA generation < n.
  issuance:     "issuance.json",
  // Revoked-generation watermark — the highest n passed to revokeGeneration().
  // A leaf whose signing straddled a rotate()+revokeGeneration() is recorded in
  // the ledger AFTER the sweep read it, so at record time issuance compares its
  // generation against this watermark and revokes itself if the generation has
  // already been swept — closing the issuance-vs-generation-revocation race.
  revokedGeneration: "revoked-generation",
  // Effective CUSTOM-engine algorithm label — durable shared metadata so a SECOND handle over the
  // same dataDir issues under the CURRENT label after another handle's commit/rotate({ algorithm }).
  // A custom label is not derivable from the stored cert (only the bundled engine's is), so without
  // this a stale-pinned sibling handle would pass its old label to the new issuer and be rejected.
  algorithm:    "ca.algorithm",
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
    caCertPrev:   _absoluteOrUnderDataDir(dataDir, p.caCertPrev),
    issuance:     _absoluteOrUnderDataDir(dataDir, p.issuance),
    revokedGeneration: _absoluteOrUnderDataDir(dataDir, p.revokedGeneration),
    algorithm:    _absoluteOrUnderDataDir(dataDir, p.algorithm),
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
    /* c8 ignore next -- defensive: a successfully-parsed X.509 certificate always exposes a subject DN */
    var subj = cert.subject || "";
    // Anchor the OU=CAv{N} match to an RDN BOUNDARY (subject start, a newline RDN separator, or an
    // unescaped comma / " + " attribute separator node emits between RDNs / inside a MULTI-VALUED
    // RDN, e.g. "CN=x + OU=CAv7") so a CN or other attribute VALUE that literally contains the
    // substring "OU=CAv<k>" is not misread as the generation, and the FIRST real OU RDN is taken.
    // The comma AND plus boundaries use a `(?<!\\)` lookbehind so an ESCAPED "\," / "\+" — a literal
    // comma / plus inside a value ("CN=foo\,OU=CAv9", "CN=foo\+OU=CAv9") — is NOT treated as a
    // separator; \r/\n are structural line separators node never escapes. An embedded "OU=CAv" inside
    // a value never sits at a boundary (it follows "<Type>=").
    var m = /(?:^|[\r\n]|(?<!\\)[,+])\s*OU=CAv(\d+)/.exec(subj);
    return m ? parseInt(m[1], 10) : 1;
  } catch (_e) {
    return 0;
  }
}

// A rollback-manifest byte field, when PRESENT, must be a non-empty string of CANONICAL
// base64 decoding to a non-empty buffer. An empty ("") or malformed value would decode to
// an empty / garbage buffer that, written over the live CA key on the interrupted path,
// permanently destroys the CA. Absent (null / undefined) is allowed — the recovery code
// handles a missing field. Canonical round-trip (re-encode equals the input) rejects
// whitespace / non-canonical padding a lenient Buffer.from would otherwise accept.
function _validManifestB64Field(v) {
  if (v === null || v === undefined) return true;
  if (typeof v !== "string" || v.length === 0) return false;
  // Buffer.from(<string>, "base64") never throws (invalid chars are dropped), so no
  // try/catch is needed — an empty/garbage decode is caught by the length + round-trip.
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
// Map an algorithm-pin label to the node KeyObject.asymmetricKeyType a stored CA
// key of that algorithm reports, so a pin can be checked against an on-disk CA.
// Returns null for a label this file can't map (a custom engine's own naming) —
// the check is then skipped and the engine owns the semantics.
// The OpenSSL curve name node reports for the framework's sole classical pin
// (ECDSA-P384-SHA384). A stored EC CA must report this curve to satisfy that pin.
var CLASSICAL_CA_CURVE = "secp384r1";
// The require-mtls gate pins a leaf's SHA3-512 (FIPS 202) fingerprint: 64 bytes -> 128 hex
// characters. A fingerprint STORED for that gate (revoke({fingerprint}) / importIssuance) must be
// exactly this length, else a shorter but valid-hex value (a SHA-256 64-hex fingerprint, a truncated
// paste) is accepted yet the gate's 128-hex compare never matches — a silent fail-open.
var SHA3_512_HEX_LEN = 128;
// Both default file stores (issuance ledger + revocation registry) are READ with this maxBytes cap
// (fdSafeReadSync throws "too-large" over it). A write that pushes a file past the cap would succeed
// but then fail every later read, bricking future issuance/revocation — so add() must size-check the
// serialized output against this SAME value before writing (see _writeStoreCapped).
var STORE_READ_CAP = C.BYTES.mib(16);

function _expectedKeyTypeForPin(label) {
  var l = String(label).toLowerCase();
  if (l.indexOf("ecdsa") !== -1) return "ec";
  var m = l.match(/ml-dsa-(\d+)/);
  return m ? ("ml-dsa-" + m[1]) : null;
}

// Map a node asymmetricKeyType (from a key OR a cert public key) to the
// framework algorithm label. "ec" -> ECDSA-P384-SHA384 (the sole classical
// pin), "ml-dsa-N" -> ML-DSA-N. undefined for a type this file doesn't map
// (a custom engine's own naming) — the engine then owns the semantics.
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

// Derive { keyType, algorithm } from a CA CERT's public key — the shape
// status() exposes. Uses only the public key (no vault / private-key load),
// so it works regardless of caKeySealedMode. keyType is the raw node
// asymmetricKeyType ("ec" / "ml-dsa-87" / ...); algorithm is the mapped label
// (null for a type this file doesn't recognize, e.g. a custom engine's).
function _certAlgorithm(certPem) {
  try {
    var cert = new nodeCrypto.X509Certificate(certPem);
    var pub = cert.publicKey;
    /* c8 ignore next -- the "" fallback is defensive: a parsed public key always reports a non-empty asymmetricKeyType */
    var type = String(pub.asymmetricKeyType || "").toLowerCase();
    if (type === "ec") {
      // The framework's sole classical label (ECDSA-P384-SHA384) is P-384 /
      // secp384r1 signed with SHA-384. A custom engine may issue a P-256 / P-521
      // EC CA, or a P-384 CA signed with SHA-256 — node still reports "ec", so
      // require BOTH the curve AND the SHA-384 signature before labeling;
      // otherwise return null (a wrong label misreports status() and feeds a bad
      // label to a custom engine's canVerifyInTls()).
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

// Atomically write a default-store file, but REFUSE an over-cap write first. Both default file
// stores (issuance ledger + revocation registry) are read with STORE_READ_CAP as fdSafeReadSync's
// maxBytes; a write that pushes the file past that cap succeeds yet then fails every later read
// (too-large), silently disabling future issuance/revocation. Size-checking the serialized output
// here — against the SAME cap the read uses — turns that into an explicit refusal BEFORE the store
// mutates and (via _recordIssuance) before the signed credential is returned.
function _writeStoreCapped(path, serialized, writeOpts, fullCode, label) {
  if (Buffer.byteLength(serialized, "utf8") > STORE_READ_CAP) {
    throw new MtlsCaError(fullCode,
      "the default " + label + " (" + path + ") would exceed its " + STORE_READ_CAP + "-byte read cap; the framework's " +
      "own read of a larger file fails closed, disabling future issuance/revocation until the file is repaired — provide " +
      "a bring-your-own store that can grow past this cap for a deployment this large");
  }
  atomicFile.writeSync(path, serialized, writeOpts);
}

// Do two cert PEMs represent the SAME X.509 certificate? Compares parsed DER IDENTITY, so
// harmless PEM differences (CRLF vs LF line endings, line wrapping, a stripped trailing
// newline) between the stored cert and a recommitted one do not read as a new issuer — which
// would spuriously open the retained-root grace window and invalidate a still-valid CRL. Falls
// back to a raw-byte comparison only when a cert cannot be parsed (an opaque custom-engine
// cert), where the bytes are the only identity signal available.
function _sameCert(pemA, pemB) {
  try {
    return new nodeCrypto.X509Certificate(pemA).raw.equals(new nodeCrypto.X509Certificate(pemB).raw);
  } catch (_e) {
    return Buffer.from(pemA).equals(Buffer.from(pemB));
  }
}

// Does this CA cert's public key correspond to this CA private key? A rotation
// renames the key and cert as two separate steps, so an issuer reading the pair
// mid-rotation can combine the old cert with the new key. initCA re-reads until
// this holds. Returns true for a cert/key node can't parse (a custom engine owns
// its own pairing; the two-file rename race is specific to the default store).
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
  // Ensure the parent directory of every managed path exists. atomicFile.lock()
  // opens `<path>.lock` directly and does NOT create the parent, so a nested
  // operator path (e.g. paths.revocations = "state/revocations.json") would make
  // the first locked revoke()/issuance/rotation fail ENOENT before the store's
  // own writeSync (which used to create it). Create the parents up front.
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
  // The default engine is lazy-loaded at top-of-file; resolve it only
  // when no custom engine was passed. Whether the bundled engine is in use
  // gates the CA-following algorithm inference below: _labelForCaKeyType maps a
  // key to the BUNDLED engine's label set, which is meaningless (or wrong) for a
  // custom engine's own labels / key curves. A falsy engine (null / undefined)
  // selects the bundled engine, so the flag must match the `opts.engine || ...`
  // fallback exactly — an explicit engine: null is the bundled engine, not custom.
  var usesDefaultEngine = !opts.engine;
  var engine = opts.engine || mtlsEngineDefault();

  // Optional algorithm pin. When set, it is threaded into BOTH CA generation
  // (initCA) and every leaf/PKCS#12 issuance so the whole chain shares one
  // algorithm — the operator opt-in for a classical (ECDSA-P384-SHA384) CA when
  // a peer predates the OpenSSL 3.5 that verifies the ML-DSA-87 default. The
  // label set is the engine's to validate (a custom engine may define its own),
  // so this is a config-time type guard only; an unknown label surfaces from the
  // engine at issuance.
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
    // keyType is read from the stored cert's PUBLIC key, so a consumer deciding whether to migrate a
    // classical CA no longer has to re-parse loadCert() with node:crypto to learn ECDSA-vs-ML-DSA.
    var alg = _certAlgorithm(pem);
    // The default engine's labels ARE the cert-derived ones, so report _certAlgorithm's inference. A
    // CUSTOM engine may use its own label ("CUSTOM-P384") for a key type _certAlgorithm would misreport
    // as the bundled "ECDSA-P384-SHA384" (or cannot classify at all → null), so report the durable
    // PERSISTED label instead — the same source issuance/rotation/probing use — falling back to null
    // (undeterminable) when unpinned rather than a misleading bundled guess. keyType stays cert-derived.
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
      // gen === 0 means the generation is UNDETERMINABLE (an opaque cert node:crypto
      // cannot parse), NOT "older than current". Reporting isLegacy:true there would
      // mislabel a current opaque-engine CA as legacy — an isLegacy-keyed upgrade flow
      // would then rotate() it and hit mtls-ca/generation-undeterminable, contradicting
      // status(). Only a DETERMINED generation below the create-time one is legacy.
      isLegacy:   gen >= 1 && gen < generation,
      current:    generation,
      algorithm:  _statusAlgorithm,
      keyType:    alg.keyType,
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
      // Cap + fd-bound CA-private-key read. NO refuseSymlink: caKeySealed may be
      // an operator-absolute path on a k8s/KMS secret volume that symlinks it.
      var sealedBytes = atomicFile.fdSafeReadSync(paths.caKeySealed, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
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
    // Cap + fd-bound plaintext CA-private-key read (disabled mode = dev opt-out).
    // NO refuseSymlink (operator-absolute path may symlink).
    return atomicFile.fdSafeReadSync(paths.caKey, { maxBytes: C.BYTES.kib(64) });
  }

  function loadCert() {
    if (!nodeFs.existsSync(paths.caCert)) {
      throw new MtlsCaError("mtls-ca/missing-cert",
        "no CA cert on disk at " + paths.caCert);
    }
    return atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) });
  }

  // Atomic commit: write .tmp + atomic rename for both key and cert.
  // Honors caKeySealedMode — when 'required' (the default), the key is
  // vault-sealed before the on-disk write so plaintext PEM never touches
  // the filesystem; when 'disabled', it goes to disk as PEM with the
  // operator's audited reason on record.
  // The commit body. MUST run under atomicFile.lock(paths.caCert): the journal
  // write, key/cert renames, retained-root update, and journal delete are a single
  // critical section — two unlocked commits over one dataDir would race the staged
  // temp files and each other's renames, clobbering the CA. rotate() already holds
  // the lock; the public commit() below acquires it.
  function _commitLocked(opts2) {
    /* c8 ignore next 4 -- defense in depth: the public commit() validates these synchronously before the lock, and rotate()/_freshCreateSerialized pass engine output already validated as { caKeyPem, caCertPem } strings, so _commitLocked never sees bad args */
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    // retainPrevious drives a truthiness check below (outgoingCaCert). A non-boolean
    // (e.g. the string "false" from config) is TRUTHY, so it would retain the outgoing
    // root when the operator intended a hard cut. Reject a supplied non-boolean rather
    // than silently misinterpreting it (rotate() validates its own raw value too).
    if (opts2.retainPrevious !== undefined && typeof opts2.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-retain-previous",
        "commit opts.retainPrevious must be a boolean when provided (got " +
        JSON.stringify(opts2.retainPrevious) + ") — a non-boolean like the string \"false\" is truthy and " +
        "would retain the outgoing root instead of hard-cutting it");
    }
    // Grace-window retention: capture the OUTGOING cert now (before the new one
    // overwrites it), but do NOT touch the retained-root file until the commit
    // below SUCCEEDS. If sealing / tmp-write / rename fails, the active CA is
    // unchanged, so the retained root must stay intact — otherwise a client still
    // using it is stranded by a rotation that never landed.
    var currentCaCert = (opts2.retainPrevious && nodeFs.existsSync(paths.caCert))
      ? atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) })
      : null;
    // Retain ONLY when the committed cert actually SUPERSEDES the current issuer. An
    // idempotent recommit of the same cert supersedes nothing, so retaining it would open
    // the single retained-root window (rejecting the NEXT real retained rotation with
    // mtls-ca/retained-root-exists until the operator calls dropRetained()) for no benefit —
    // loadTrustBundle() dedups the duplicate, but the ca.prev.crt FILE still opens the window.
    var outgoingCaCert = (currentCaCert !== null && !_sameCert(currentCaCert.toString("utf8"), opts2.caCertPem))
      ? currentCaCert
      : null;
    // Capture the PRIOR retained root so a rollback can restore it if the final
    // cert rename fails after we overwrote/removed ca.prev.crt — a failed rotation
    // must not strand clients still enrolled under the previously-retained CA.
    var priorPrevExisted = nodeFs.existsSync(paths.caCertPrev);
    var priorPrev = null;
    if (priorPrevExisted) {
      try { priorPrev = atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorPrev = null; }
    }
    // Single retained grace window at a time — enforced HERE so EVERY retention
    // entry point is covered (rotate() AND the public commit(), which calls
    // _commitLocked directly). ca.prev.crt holds one prior root; a second retained
    // commit would overwrite it and strand clients still enrolled under the first
    // retained generation. End the existing window explicitly (dropRetained(), or a
    // retainPrevious:false commit that hard-cuts) before retaining again.
    if (outgoingCaCert !== null && priorPrevExisted) {
      throw new MtlsCaError("mtls-ca/retained-root-exists",
        "a retained root from a prior rotation is still present at " + paths.caCertPrev + " — a second " +
        "retained rotation would drop it and reject clients still enrolled under it. End the existing grace " +
        "window with dropRetained(), or rotate({ retainPrevious: false }) to hard-cut, before rotating again");
    }
    // A commit while a grace window is open MUST state its retention intent. With
    // retainPrevious OMITTED, outgoingCaCert is null (so the single-window guard above
    // does not fire) AND the hard-cut branch below (retainPrevious === false) does not
    // fire either — so the outgoing retained root is left untouched while the active
    // cert is replaced, silently dropping trust for the just-superseded generation (its
    // cert becomes neither the new current nor the retained root). Refuse an ambiguous
    // commit: rotate()/first-init always pass a boolean, so this binds only the public
    // commit() legacy form. End the window (dropRetained() / rotate({ retainPrevious:
    // false })), or pass retainPrevious explicitly.
    if (priorPrevExisted && typeof opts2.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/retention-intent-required",
        "a retained root from a prior rotation is present at " + paths.caCertPrev + " — a commit that omits " +
        "retainPrevious would replace the active CA while leaving that root, dropping trust for the just-" +
        "superseded generation. Pass retainPrevious explicitly (false to hard-cut), or dropRetained() first");
    }
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    // Random-token temp names (not fixed ".tmp"): an O_EXCL create through a fixed
    // name would EEXIST against a crash residue OR a concurrent writer's staged
    // file — a spurious commit-failed, or a cross-process clobber. A per-commit
    // token makes both impossible (matches atomicFile.writeSync's tmp scheme).
    var commitTok = bCrypto().generateToken(C.BYTES.bytes(8));
    var keyTmp = keyDest + ".tmp-" + commitTok;
    var certTmp = paths.caCert + ".tmp-" + commitTok;
    // Capture the PRIOR key bytes so a failed cert publish can restore them too —
    // the key rename runs before the cert rename, so without this a rotation that
    // fails at the cert step would leave the new key beside the OLD cert (a
    // permanently mismatched, unusable pair). Raw on-disk bytes (sealed or plain).
    var priorKeyExisted = nodeFs.existsSync(keyDest);
    var priorKey = null;
    if (priorKeyExisted) {
      try { priorKey = atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorKey = null; }
    }
    // The current cert BEFORE this rotation republishes it. Recorded in the journal
    // so recovery (and loadTrustBundle) can tell an INTERRUPTED rotation — the live
    // cert still equals this prior one, so the cert was never republished and the
    // journal's saved retained root must be trusted / restored — from a COMPLETED
    // one — the live cert differs, so the journal is spent and its old retained
    // root must NOT be re-trusted (which would defeat a hard cutoff).
    var priorCert = null;
    if (nodeFs.existsSync(paths.caCert)) {
      try { priorCert = atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { priorCert = null; }
    }
    // Capture the prior CUSTOM label so a REJECTED re-label restores it (the outer catch and an
    // interrupted reconcile both roll it back — else a same-cert re-stamp whose label write succeeded
    // but whose commit then failed would leave the new label active despite reporting failure).
    // _readPersistedAlgorithm() fails closed on a real read error, aborting before any mutation.
    var _priorPersistedLabel = !usesDefaultEngine ? _readPersistedAlgorithm() : undefined;
    // Abort if ANY existing prior artifact could not be captured for the journal.
    // The rollback journal must hold a complete snapshot of the pre-rotation state:
    //   - the KEY, or a failed publish strands the CA on a new-key/old-cert pair;
    //   - the CERT, or the interrupted-vs-completed comparison (live cert == prior
    //     cert) cannot run, so reconcile could delete a newly-established grace root
    //     or restore a hard-cut one;
    //   - the RETAINED ROOT, or a failed hard-cut rotation cannot restore it.
    // A transient read fault on any of these must not silently produce a partial
    // journal that later mis-reconciles — refuse to mutate the CA and let the
    // operator resolve the fault and retry.
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
    // A CERT-ONLY store (ca.crt present but NO key at the current mode's destination) is corrupt
    // or half-published. Committing over it journals no prior key (the journal write below is
    // gated on priorKeyExisted), so if the new key rename lands and the cert rename then fails
    // (or the process exits between them), the catch has no prior key to restore AND leaves the
    // new key in place — an old-cert/new-key pair with no journal that every later initCA() then
    // rejects as ca-pair-inconsistent. Refuse before mutating; the operator restores the key (or
    // removes ca.crt for a clean re-init). A key-only cold start (key present, cert absent) is
    // the LEGITIMATE inverse and is handled via the journal's newCert discriminator.
    if (nodeFs.existsSync(paths.caCert) && !priorKeyExisted) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "the stored CA certificate at " + paths.caCert + " has no matching private key at " + keyDest +
        " (a corrupt or half-published CA state) — refusing to commit over it, which would leave an " +
        "unrecoverable new-key/old-cert pair with no rollback journal; restore the key or remove " + paths.caCert +
        " to re-initialize");
    }
    // Crash-recovery rollback journal. The CA key, current cert, and retained root
    // (ca.prev.crt) are separate files, so the renames/writes below cannot be one
    // atomic swap: if the process dies mid-publish, the in-memory catch rollback
    // never runs and BOTH the prior key (already overwritten) and the prior
    // retained root (already replaced or removed) are otherwise unrecoverable —
    // stranding the CA (mtls-ca/ca-pair-inconsistent) AND dropping trust for
    // clients still enrolled under the formerly-retained generation. Persist both
    // prior artifacts durably (fsync'd) BEFORE mutating them; the journal's
    // presence is the "rotation in progress" marker _reconcileCommitJournalLocked()
    // rolls back from, and a clean commit removes it once the new state is durably
    // consistent. Manifest: key = base64 prior key bytes; prevAction/prevData
    // capture the prior ca.prev.crt (restore its bytes, delete a prev this rotation
    // created, or leave an unreadable prior untouched — mirroring the catch).
    var keyJournal = keyDest + ".rollback";
    var keyJournalWritten = false;
    // The stale CRL is invalidated by moving it ASIDE to a fixed rollback name BEFORE
    // the cert publish, then deleting it once the new cert lands (see the CRL block
    // below). Capturing crlExisted + crlRollback here (function scope) lets the catch
    // restore it: the CA it rolled back to is still active, so its CRL is still valid
    // and must keep being served. reconcile() drives the same fixed name.
    var crlRollback = _crlRollbackPath();
    var crlExisted = nodeFs.existsSync(paths.crl);
    // Only invalidate the CRL when the committed cert actually CHANGES the issuer: an
    // idempotent recommit of the same certificate leaves the CRL's issuer unchanged, so
    // the valid CRL must keep being served rather than being moved aside and deleted.
    var caCertChanged = priorCert === null || !_sameCert(priorCert.toString("utf8"), opts2.caCertPem);
    var movingCrlAside = crlExisted && caCertChanged;

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
        /* c8 ignore next -- best-effort: fsync on a freshly-opened, still-valid fd does not throw here */
        try { nodeFs.fsyncSync(fd); } catch (_fe) { /* fsync best-effort */ }
      } finally {
        /* c8 ignore next -- best-effort: closeSync on the just-written fd does not throw here */
        try { nodeFs.closeSync(fd); } catch (_ce) { /* close best-effort */ }
      }
    }
    try {
      // The NEW key in its on-disk form (sealed or plain) — written to the temp AND
      // recorded in the journal so recovery can complete a rotation whose key rename
      // was lost (a Windows/FUSE fsyncDir no-op) as byte-exactly as it can roll one
      // back, without depending on node being able to parse the key.
      var newKeyOnDisk = Buffer.from(sealed
        ? (_requireVault("sealed CA key commit"), vault.seal(opts2.caKeyPem))
        : opts2.caKeyPem);
      _writeExclusive(keyTmp, newKeyOnDisk, 0o600);
      _writeExclusive(certTmp, opts2.caCertPem, 0o644);
      // Persist a COMPLETE snapshot of the pre-rotation state AND the intended
      // post-rotation state before mutating anything, so recovery can drive the CA
      // to whichever state the rotation reached — byte-exact, engine-agnostic:
      //   key/cert       — the prior key + prior cert (the interrupted discriminator);
      //   newKey         — the new key, to finish a completed rotation whose key
      //                    rename didn't stick;
      //   retainAfter    — whether a COMPLETED rotation should retain the outgoing
      //                    root (= the prior cert) or hard-cut it;
      //   newCert        — the intended NEW cert, the completed-vs-interrupted
      //                    discriminator when there is NO prior cert (a key-only cold
      //                    start: ca.key present, ca.crt absent). Without it, reconcile
      //                    could not classify a completed key-only init (manifest.cert
      //                    is null) and would restore the orphaned prior key beside the
      //                    newly published cert, leaving the CA an unusable pair;
      //   prevAction/prevData — how to roll the retained root BACK on an interrupted
      //                    rotation ("restore" prior bytes / "delete" a prev this
      //                    rotation created / "leave" an unreadable prior).
      //   customAlgorithm — the CUSTOM-engine effective label this commit publishes; the
      //                    ca.algorithm write is done under this journal so a crash leaves it
      //                    recoverable (a custom label is not cert-derivable).
      // The CUSTOM-engine effective label to publish alongside the CA (the default engine derives its
      // label from the cert, so it is never persisted). Prefer an explicit override — a
      // commit/rotate({ algorithm }) or the preserved persisted label a bare custom rotate resolves —
      // and otherwise fall back to the handle's own effective pin (caAlgorithm), so a pinned handle
      // that bootstraps or migrates the CA via commit() WITHOUT redundantly repeating the label still
      // publishes ca.algorithm (else a sibling adopts the CA under its own stale pin / engine default).
      var _customCommitLabel = !usesDefaultEngine
        ? ((typeof opts2.algorithm === "string" && opts2.algorithm.length > 0) ? opts2.algorithm
          : ((typeof caAlgorithm === "string" && caAlgorithm.length > 0) ? caAlgorithm : null))
        : null;
      if (priorKeyExisted && priorKey !== null) {
        /* c8 ignore next -- the "leave" arm is dead: the prior-retained-root-unreadable check above throws when priorPrevExisted && priorPrev===null, so priorPrev!==null here */
        var prevAction = !priorPrevExisted ? "delete" : (priorPrev !== null ? "restore" : "leave");
        // The retained root a COMPLETED commit should leave in ca.prev.crt. Normally the outgoing
        // (prior) cert when retaining, or removed on a hard cut — BUT an idempotent recommit that only
        // REFORMATS the current cert (outgoingCaCert===null, same identity) with a grace window ALREADY
        // open must PRESERVE the existing retained root (priorPrev), not delete it or replace it with
        // the same-identity prior cert. Record the ACTUAL bytes: reconcile reads the byte-different
        // reformatted live cert as COMPLETED and, without this, would derive retainAfter:false from
        // outgoingCaCert===null and DELETE ca.prev.crt, stranding clients enrolled under it.
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
          crlMovedAside: movingCrlAside,   // did THIS commit move a CRL aside (so reconcile may restore it)?
          prevAction:  prevAction,
          prevData:    prevAction === "restore" ? priorPrev.toString("base64") : null,
          // The CUSTOM-engine effective label this commit publishes, so the ca.algorithm write below is
          // crash-ATOMIC with the CA: a power loss between the CA publish and the label write leaves this
          // journal, and a COMPLETED-commit reconcile restores the label from here — else ca.algorithm
          // stays stale (the old label) against the new CA and every sibling issues under the wrong one.
          customAlgorithm: _customCommitLabel,
          // The label BEFORE this commit — an INTERRUPTED-commit reconcile restores it (mirrors the outer
          // catch), so a re-label whose write landed but whose commit then rolled back is fully undone.
          priorCustomAlgorithm: (_priorPersistedLabel !== undefined ? _priorPersistedLabel : null),
        }), { fileMode: 0o600 });
        keyJournalWritten = true;
      }
      // No journal was written (an INITIAL commit with no prior key, or an unreadable prior key), so
      // nothing can reconcile the custom label from disk after a crash. Persist it BEFORE publishing
      // the key/cert, so a failed label write aborts here — before any CA lands — rather than leaving
      // a labelless CA a sibling would issue under its own stale pin. A commit WITH a journal persists
      // the label at the commit point below and rolls it forward from the journal on failure instead.
      if (!keyJournalWritten && _customCommitLabel !== null) _persistAlgorithm(_customCommitLabel);
      atomicFile.renameWithRetry(keyTmp, keyDest);
      // Make the KEY rename durable BEFORE publishing the cert. renameSync alone is
      // not crash-durable and keyDest/caCert can have distinct operator-configured
      // parents, so without this a power loss could persist the LATER cert rename
      // while losing the key rename — leaving an old-key/new-cert pair the journal
      // (which holds only the OLD key) cannot repair. Ordering the durability this
      // way means at every crash point the on-disk pair is either consistent or
      // recoverable from the OLD-key journal. fsyncDir is best-effort (Windows
      // rejects directory fsync), matching atomicFile's own durability contract.
      atomicFile.fsyncDir(nodePath.dirname(keyDest));
      // Publish the retained root BEFORE the new current cert, so a concurrent
      // loadTrustBundle() that observes the new ca.crt already sees the outgoing
      // root in ca.prev.crt — closing the window where only the new root would be
      // trusted. Both the retain write AND the retain:false removal are REQUIRED
      // parts of the commit: a failure throws to the outer catch, which rolls the
      // whole rotation back. Retaining but omitting the outgoing root breaks the
      // no-outage migration (clients under the superseded CA are rejected); failing
      // to remove the old root under retainPrevious:false silently keeps trusting a
      // root the operator asked to hard-cut, admitting certs chained to it. Never
      // publish a new CA whose trust bundle contradicts the requested retention.
      if (outgoingCaCert !== null) {
        // writeSync fsyncs its own file + directory, so the retain write is durable.
        atomicFile.writeSync(paths.caCertPrev, outgoingCaCert, { fileMode: 0o644 });
      } else if (opts2.retainPrevious === false && nodeFs.existsSync(paths.caCertPrev)) {
        nodeFs.unlinkSync(paths.caCertPrev);
        // Make the removal durable: ca.prev.crt may live in a different parent than
        // ca.crt (whose fsync below would not cover it), so without this a power
        // loss could resurrect the stale root after the rotation reported success,
        // leaving loadTrustBundle() trusting a root the operator hard-cut.
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      // Invalidate a persisted CRL as a REQUIRED part of the commit, but tie its fate
      // ATOMICALLY to the cert publication: this commit republishes the CA cert, so a
      // CRL persisted under the OLD cert becomes signed by a superseded issuer, yet if
      // the publish fails (or a crash intervenes) the OLD CA stays active and its CRL
      // is STILL VALID and must keep being served. So MOVE the CRL aside to a fixed
      // rollback name here (before the cert rename, the point of no return) rather than
      // deleting it: a failure to move it (e.g. paths.crl in a separately-configured
      // read-only directory) throws to the outer catch, which rolls the whole commit
      // back — the rename is a required precondition. Only AFTER the new cert lands is
      // the moved-aside CRL truly stale (its issuer is superseded), so it is deleted
      // then. A rollback (catch) or an interrupted-rotation reconcile renames it back;
      // a completed-rotation reconcile deletes it. fsyncDir is best-effort (it swallows
      // platform errors); only the rename can fail the commit.
      if (movingCrlAside) {
        // Clear an ORPHAN crl.rollback first: a prior CA-changing commit's best-effort delete of
        // its moved-aside CRL may have failed, leaving one behind. On Windows renameSync cannot
        // replace an existing destination, so without this the move-aside below would exhaust
        // renameWithRetry and abort every later rotation until the orphan is removed by hand. A
        // LEGITIMATE crl.rollback was already restored/deleted by the reconcile the caller ran
        // before this commit, so any survivor here is inert (a superseded-issuer CRL).
        if (nodeFs.existsSync(crlRollback)) {
          try { nodeFs.unlinkSync(crlRollback); }
          /* c8 ignore next -- best-effort: if this unlink fails the renameWithRetry below fails the commit closed, so it is not swallowed silently */
          catch (_orphanErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: crlRollback, error: _orphanErr.message }); }
        }
        atomicFile.renameWithRetry(paths.crl, crlRollback);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
      atomicFile.renameWithRetry(certTmp, paths.caCert);   // publish the new current LAST
      // Make the cert rename durable too (see the key-rename fsync note) before
      // removing the recovery journal below — else a power loss could persist the
      // journal deletion while losing the cert rename.
      atomicFile.fsyncDir(nodePath.dirname(paths.caCert));
      // The new cert is published — the moved-aside CRL is now signed by a superseded
      // issuer, so delete it for good (best-effort: a leftover is an unserved orphan at
      // the .rollback name, and a completed-rotation reconcile deletes it on next open).
      // A consumer regenerates the CRL under the new CA via generateCrl().
      if (movingCrlAside && nodeFs.existsSync(crlRollback)) {
        try {
          nodeFs.unlinkSync(crlRollback);
          atomicFile.fsyncDir(nodePath.dirname(crlRollback));
          caLog.info("invalidated stale CRL on CA change (regenerate with generateCrl)", { path: paths.crl });
        }
        /* c8 ignore next -- best-effort: unlink of the CRL we just moved aside does not throw here */
        catch (_ce) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: crlRollback, error: _ce.message }); }
      }
      // Persist the CUSTOM-engine label alongside the now-durable CA, BEFORE deleting the journal
      // (the commit point): a power loss between the CA publish and here leaves the journal, and a
      // completed-commit reconcile restores ca.algorithm from manifest.customAlgorithm — so the label
      // can never be left stale (old) against the new CA. Only the JOURNALED path lands here; a
      // journal-less commit already persisted the label before publishing (above). Default-engine
      // labels are cert-derived.
      var _labelPersistDeferred = false;
      if (keyJournalWritten && _customCommitLabel !== null) {
        try {
          _persistAlgorithm(_customCommitLabel);
        } catch (_le) {
          // The new key/cert/prev/CRL are already durably published and consistent here; only the
          // ca.algorithm label file failed to write. For a CA-CHANGING commit the outer catch CANNOT
          // un-publish the new cert (line 922's rollback restores the prior key + retained root only,
          // leaving an old-key/new-cert pair, then deletes the journal that would heal it) — so DON'T
          // abort: leave the journal and roll forward. The next reconcile reads live cert != journal.cert
          // (COMPLETED) and restores the label from manifest.customAlgorithm. A SAME-cert re-stamp CAN
          // roll back to a fully consistent prior state, so fail closed there (as the journal-delete
          // path does) rather than report success with an unpersisted label.
          if (!caCertChanged) throw _le;
          _labelPersistDeferred = true;
          caLog.debug("cleanup-failed", { op: "persist-algorithm", path: paths.algorithm, error: _le.message });
        }
      }
      // The new key/cert pair is durably published and consistent on disk — the rollback journal has
      // served its purpose; remove it (the commit point). Skip the delete when the label write failed
      // above so the surviving journal reconciles the label forward on the next boot.
      if (keyJournalWritten && !_labelPersistDeferred) {
        try {
          nodeFs.unlinkSync(keyJournal);
          atomicFile.fsyncDir(nodePath.dirname(keyJournal));   // make the deletion durable
        }
        catch (_je) {
          // A CERT-CHANGING commit self-heals a surviving journal: the next reconcile sees
          // live cert != journal.cert (COMPLETED) and rolls forward, deleting it. But a
          // SAME-CERT commit (caCertChanged false — e.g. a retainPrevious:false hard-cut of
          // the grace window) CANNOT: reconcile reads live cert == journal.cert as INTERRUPTED
          // and restores ca.prev.crt, AND the lock-free _journalRetainedRoot() re-adds it —
          // resurrecting the very retained root the operator cut, while commit() reported
          // success. So propagate the unlink failure there (fail closed, as reconcile's own
          // journal delete does), so a cutoff cannot succeed with an authoritative journal
          // still present. For a cert-changing commit the leftover self-heals, so keep the
          // deletion best-effort (a spurious rollback of a published cert would be worse).
          if (!caCertChanged) throw _je;
          caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyJournal, error: _je.message });
        }
      }
    } catch (e) {
      // Best-effort cleanup of half-written tmp files; the original
      // commit error is what we re-raise. Log cleanup failures at debug
      // so a genuinely-broken filesystem state surfaces in operator logs
      // rather than getting silently swallowed.
      /* c8 ignore next -- defensive existence guard: the tmp file may or may not exist depending where the commit threw; both arms are best-effort cleanup */
      try { if (nodeFs.existsSync(keyTmp))  nodeFs.unlinkSync(keyTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: keyTmp, error: cleanupErr.message }); }
      /* c8 ignore next -- defensive existence guard: the tmp file may or may not exist depending where the commit threw; both arms are best-effort cleanup */
      try { if (nodeFs.existsSync(certTmp)) nodeFs.unlinkSync(certTmp); }
      /* c8 ignore next -- best-effort cleanup: unlink of a tmp file we just created does not throw here */
      catch (cleanupErr) { caLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: certTmp, error: cleanupErr.message }); }
      // The rotation FAILED (the new cert was not published). Roll back the two
      // artifacts the key rename + retained-root update already replaced, so the
      // previously-active CA survives intact: restore the prior KEY (else the new
      // key sits beside the old cert — a mismatched, unusable pair), and restore
      // the prior retained root (or remove a prev created for this failed attempt).
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
          // Remove the retained root THIS failed rotation created, and fsync its
          // parent so the removal is durable: else a power loss could preserve the
          // root creation while preserving the journal deletion, leaving a phantom
          // ca.prev.crt that _commitLocked() reads as an existing grace window and
          // rejects every later retained rotation (mtls-ca/retained-root-exists).
          nodeFs.unlinkSync(paths.caCertPrev);
          atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
        }
        prevRolledBack = true;
      /* c8 ignore next 4 -- best-effort double-fault path: the retained-root restore/unlink does not throw in tests */
      } catch (rbErr) {
        caLog.error("retained-root-rollback-failed",
          { path: paths.caCertPrev, error: (rbErr && rbErr.message) || String(rbErr) });
      }
      // Restore the CRL THIS commit moved aside: the CA it rolled back to is still
      // active, so its CRL is still valid and must keep being served. Gate on crlExisted
      // (whether THIS commit moved a CRL aside) — a crl.rollback present when crlExisted
      // is false is an ORPHAN from a prior commit whose best-effort delete failed, signed
      // by an earlier issuer; restoring it would publish a stale-issuer CRL under the
      // still-active CA. A no-op when the move never ran or the CRL is already restored.
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
      // Roll back a partially-applied CUSTOM re-label: this commit may have already written the new
      // ca.algorithm (a same-cert re-stamp whose label write succeeded but whose journal delete then
      // threw), so the rejected commit must not leave the new label active. Restore the prior label, or
      // remove ca.algorithm if there was none. Default engines never persist a label, so nothing to do.
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
      // The in-memory rollback restored the live key, the retained root, the CRL, AND the label,
      // so the journal is spent — remove it. If ANY restore FAILED, keep the journal so
      // the next _reconcileCommitJournalLocked() completes the rollback: it holds the
      // prior key, the retained root (prevData), AND the prior label (priorCustomAlgorithm), and the
      // fixed-name crl.rollback lets reconcile finish the CRL restore too. Deleting it on a partial
      // rollback would permanently lose whichever the in-memory restore could not write (e.g. a hard-
      // cut rotation whose key rollback succeeds but whose retained-root restore fails).
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

  // Functionally verify a bundled-engine commit's material can perform BOTH engine operations —
  // sign a leaf AND sign a CRL — before publishing. node's X509Certificate exposes no KeyUsage
  // extension and the toolkit has no cert parser, so a CA cert missing keyCertSign or cRLSign passes
  // every static check yet the next generateClientCert()/generateCrl() fails (x509/bad-input /
  // crl/bad-input), disabling issuance or the revocation-export path after a "successful" commit. The
  // engine ops only sign and return PEM (no storage I/O), so this is a safe pre-publication probe.
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

  // Public commit — the LOCKED commit primitive (the migration docs direct
  // operators here, so it must be safe against a concurrent rotate/init over the
  // same dataDir). It acquires the rotation lock so its key/cert renames and
  // rollback-journal writes cannot interleave with another commit/rotation and
  // leave a mixed pair or a lost journal. rotate() and first-time creation call
  // _commitLocked directly (they already hold the lock; atomicFile.lock is
  // non-reentrant). Returns a PROMISE — await it.
  function commit(opts2) {
    // Validate the argument shape SYNCHRONOUSLY (a config-time typo), before taking
    // the lock, so a caller sees a synchronous TypeError-style throw for bad input;
    // the durable work (and its runtime aborts) happens under the lock.
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    // A supplied algorithm is the NEW effective label for a pinned CUSTOM-engine handle
    // migrating to a different-algorithm CA (the bundled label can't be inferred from a
    // custom cert). Validate its shape synchronously, matching rotate({ algorithm }).
    if (opts2.algorithm !== undefined && (typeof opts2.algorithm !== "string" || opts2.algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "commit: opts.algorithm must be a non-empty string label when set (the new effective algorithm for a " +
        "pinned custom-engine handle migrating to a different-algorithm CA)");
    }
    // The BUNDLED engine always emits parseable X.509 material, so require the same from a commit
    // to it — else a typo / garbage string ("garbage-cert") would slip past _caPairConsistent
    // (which returns "consistent" whenever parsing throws, the opaque-custom fallback) and publish
    // unusable material that bricks every later issuance. This parse requirement is DEFAULT-engine
    // only; a custom engine may legitimately commit opaque cert/key material.
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
      // The bundled engine signs leaves WITH the committed CA, so the material must be a CA
      // CERTIFICATE (basicConstraints cA:true). A leaf / end-entity cert parses, classifies as a
      // supported algorithm, and pairs with its key, yet a non-CA issuer cannot sign — the next
      // generateClientCert() would fail x509/bad-input, commit() reporting success while bricking
      // issuance. Require X509Certificate.ca before publishing (custom engines own their issuance).
      if (_commitCert.ca !== true) {
        throw new MtlsCaError("mtls-ca/not-a-ca-certificate",
          "commit: the bundled CA engine requires a CA certificate (basicConstraints cA:true), but the supplied " +
          "caCertPem is not a CA (e.g. a leaf / end-entity certificate) — publishing it would succeed, but the next " +
          "generateClientCert() would fail because a non-CA issuer cannot sign leaves; supply the CA certificate.");
      }
      // A CA outside its validity window (expired or not-yet-valid) parses, is a CA, classifies,
      // pairs, and even signs a leaf — but every issued leaf chains to it, and a TLS peer rejects an
      // expired/not-yet-valid chain (CERT_HAS_EXPIRED), so a successful commit would make every new
      // credential unusable. Reject it before mutating storage.
      var _nowMs = Date.now();
      if (_commitCert.validFromDate.getTime() > _nowMs || _commitCert.validToDate.getTime() < _nowMs) {
        throw new MtlsCaError("mtls-ca/ca-outside-validity",
          "commit: the supplied CA certificate is outside its validity window (validFrom " + _commitCert.validFrom +
          " .. validTo " + _commitCert.validTo + ") — publishing it would succeed, but every issued leaf would chain to " +
          "an expired or not-yet-valid CA that a TLS peer rejects (CERT_HAS_EXPIRED); supply a currently-valid CA.");
      }
      // A parseable, MATCHING pair can still be an algorithm the bundled engine cannot drive (a
      // P-256 / P-521 EC CA, a P-384 cert on a non-SHA-384 digest, an ML-DSA parameter set outside
      // the engine's set). _caPairConsistent checks only pairing, so such a CA would publish, then
      // the next initCA() adopting it throws mtls-ca/algorithm-mismatch (the ECDSA-P384 pin requires
      // P-384) and every later issuance fails — commit() reporting success while bricking the CA.
      // Require the committed CA to classify as one of the bundled engine's SUPPORTED algorithms
      // before mutating storage; the set is read from engine.algorithmEnvelope() so it tracks the
      // engine rather than a drifting hardcoded list. (Custom engines skip this — they own issuance.)
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
      // Normalize the committed key to the engine-decodable PKCS#8 form. createPrivateKey() also
      // parses the common OpenSSL SEC1 EC encoding (BEGIN EC PRIVATE KEY), which pairs and classifies,
      // but the bundled toolkit decodes only PKCS#8 — storing SEC1 verbatim would fail the next
      // generateClientCert()/generateCrl() (x509/bad-input). Idempotent for a PKCS#8 input.
      opts2 = Object.assign({}, opts2, { caKeyPem: _commitKey.export({ type: "pkcs8", format: "pem" }) });
    }
    // A PARSEABLE cert/key pair from DIFFERENT CA material (a caller supplying, say, a cert and a
    // key from two generations) would publish successfully but leave the next initCA() failing
    // ca-pair-inconsistent — an unusable CA that cannot issue certs or CRLs despite commit()
    // reporting success. Reject a mismatched pair up front (synchronously, before the lock).
    // A custom engine's opaque cert/key node cannot parse returns "consistent" here, so its own
    // pairing is preserved — the framework can only verify what it can parse.
    if (!_caPairConsistent(opts2.caCertPem, opts2.caKeyPem)) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "commit: the supplied caCertPem and caKeyPem are not a matching pair (the certificate's public key does " +
        "not correspond to the private key) — refusing to publish a mismatched CA the next initCA() would reject; " +
        "supply a certificate and key from the same CA");
    }
    return atomicFile.lock(paths.caCert, async function () {
      // Reconcile a leftover journal FIRST (as rotate() does): a crash that left a
      // new-key/old-cert state plus a journal would otherwise be overwritten by this
      // commit, which would record the ORPHANED new key as its prior key and, on a
      // failed publish, roll back to that orphan and delete the journal — losing the
      // actual matching old key. Safe here: the lock excludes any live commit.
      _reconcileCommitJournalLocked();
      // Functionally verify the bundled-engine material is fully usable (sign a leaf + a CRL) before
      // mutating storage — the KeyUsage extension is not statically readable, so a CA missing
      // keyCertSign/cRLSign would otherwise publish and disable issuance/revocation on the next call.
      if (usesDefaultEngine) { await _assertCommittedCaUsable(opts2.caCertPem, opts2.caKeyPem); }
      var result = _commitLocked(opts2);
      // Refresh the handle's effective algorithm pin to the committed CA's algorithm
      // (as rotate() does on rotate({ algorithm })). Without this, a handle created with
      // an algorithm pin that migrates to a different-algorithm CA via this documented
      // public commit() path keeps the stale pin, so the next initCA() (via
      // generateClientCert/P12) compares it against the new stored CA and throws
      // mtls-ca/algorithm-mismatch — unusable right after a successful commit. Only for
      // the DEFAULT engine: _certAlgorithm() yields BUNDLED labels, so refreshing a
      // CUSTOM engine's pin would REPLACE its own label (e.g. "CUSTOM-P384") with the
      // bundled one and the next issuance would pass a label the engine rejects — a
      // custom engine's pin is preserved (its parseable-key validation in initCA is
      // skipped for an unrecognized label anyway, so no spurious mismatch arises). Only
      // when pinned AND the committed algorithm is determinable (an unpinned handle
      // follows the stored CA already; an opaque cert yields null and leaves the pin).
      if (usesDefaultEngine && caAlgorithm !== undefined) {
        var committedAlg = _certAlgorithm(opts2.caCertPem).algorithm;
        if (committedAlg !== null && committedAlg !== undefined) caAlgorithm = committedAlg;
      } else if (!usesDefaultEngine && opts2.algorithm !== undefined) {
        // A CUSTOM engine's label can't be inferred from the committed cert, so a handle
        // migrating to a different-algorithm CA supplies the NEW effective label explicitly
        // (as rotate({ algorithm }) does). Apply it regardless of the handle's PRIOR pin state:
        // an UNPINNED custom handle (caAlgorithm === undefined) that commits an explicit label
        // must have it recorded too, else the next initCA() snapshot has no algorithm,
        // _leafEngineArgs omits it, and the engine selects its old default or rejects issuance
        // despite the successful commit. (A pinned handle likewise migrates off its stale pin.)
        caAlgorithm = opts2.algorithm;
        // The ca.algorithm FILE was already written crash-atomically inside _commitLocked (under the
        // rollback journal) from opts2.algorithm, so no separate persist here.
      }
      return result;
    });
  }

  // Reconcile a rotation that crashed mid-publish. commit() writes a durable copy
  // of the prior CA key (keyDest + ".rollback") before overwriting the live key,
  // and removes it only once the new key/cert pair is durably consistent. So a
  // lingering journal means a rotation died between the key rename and the cert
  // rename: the on-disk key is the NEW key but the cert is still the OLD one (an
  // unusable, otherwise-unrecoverable pair). Roll the live key back to the prior
  // copy so the previously-active CA (still able to issue leaves and CRLs during
  // the grace window) survives; if the pair is already consistent (the crash
  // landed after the cert rename, or the key was never overwritten), the journal
  // is simply spent and dropped.
  //
  // MUST hold the rotation lock (atomicFile.lock(paths.caCert)) across this call.
  // commit() runs UNDER that lock, so holding it here guarantees no rotation is
  // mid-publish — an inconsistent pair with a journal is then definitively a
  // CRASHED rotation, not the transient NEW-key/OLD-cert window a live commit
  // briefly shows. Reconciling lock-free would let a concurrent issuance clobber
  // an in-flight rotation's new key. Idempotent under the lock.
  function _reconcileCommitJournalLocked() {
    var keyDest = (caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey;
    var keyJournal = keyDest + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return;
    var manifest;
    try {
      manifest = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
    } catch (_je) {
      // A rollback journal exists but cannot be read/parsed — the "rotation in
      // progress / crashed" marker, so we CANNOT tell whether the live key/cert pair
      // is mid-rotation. Continuing would let the caller (commit/rotate) overwrite the
      // ONLY durable copy of the prior key while snapshotting a possibly-orphaned live
      // key; a later failed publish could then restore the orphan and permanently lose
      // the matching key (and an opaque custom engine would issue from the mixed pair
      // node cannot verify). Fail closed: refuse to mutate until the fault is resolved.
      // Reconcile is idempotent, so the operator restores/removes the journal and
      // retries. A read-only trust read (_journalRetainedRoot) still tolerates it.
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " exists but could not be parsed (" +
        /* c8 ignore next -- String(_je) fallback unreachable: a thrown parse Error always has a .message */
        ((_je && _je.message) || String(_je)) + ") — refusing to mutate the CA while an unresolved rotation " +
        "journal is present; restore or remove it, then retry");
    }
    if (!manifest || typeof manifest.key !== "string") {
      // Present, valid JSON, but not a rollback manifest (missing the prior-key field):
      // a truncated / externally-rewritten journal. Same hazard as an unparseable one —
      // fail closed rather than overwrite an unresolved rotation marker.
      throw new MtlsCaError("mtls-ca/rollback-journal-corrupt",
        "the CA rollback journal at " + keyJournal + " is present but is not a valid rollback manifest " +
        "(missing the prior-key field) — refusing to mutate the CA while an unresolved rotation journal is " +
        "present; restore or remove it, then retry");
    }
    // Every PRESENT byte field must be non-empty CANONICAL base64. A typeof-only guard
    // would accept an empty ("") or malformed key/newKey/cert/newCert/prevData that
    // decodes to an empty or garbage buffer and, written over the live CA key on the
    // interrupted path, permanently destroys the CA. Which field a given recovery path
    // USES is only known after the completed/interrupted branch below, so validate them
    // all up front and fail closed on any malformed one.
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
    // The rotation is COMPLETED (roll-forward) iff it republished the cert — the live
    // cert differs (BYTE-exact; a custom engine may emit non-UTF-8 cert bytes) from
    // the journal's recorded prior cert. Otherwise it is INTERRUPTED (roll-back): the
    // cert was never republished (a crash before the cert rename, or a partial catch
    // rollback). Both drive the CA to an authoritative on-disk state recorded in the
    // journal, byte-exact and engine-agnostic — no _caPairConsistent heuristic, which
    // is blind to custom-engine keys node cannot parse and would skip the key restore.
    var newCertBuf = (typeof manifest.newCert === "string") ? Buffer.from(manifest.newCert, "base64") : null;
    var completed;
    if (priorCertBuf !== null) {
      var certRepublished = curCertBuf !== null && !Buffer.from(curCertBuf).equals(priorCertBuf);
      // A commit that changed NEITHER the cert NOR the key bytes (a hard cut that only removed
      // ca.prev.crt, re-committing the byte-IDENTICAL current CA) can't be classified by the cert
      // alone — the live cert equals the journal's prior cert. It only matters for a HARD CUT
      // (retainAfter:false): a COMPLETED one removed ca.prev.crt, an INTERRUPTED one must restore it.
      // Tie-break on the prev state — an intended-removed prev already ABSENT means the removal
      // completed, so do not resurrect the root the operator hard-cut. Gate on the key being unchanged
      // too so a different-key interrupted rotation (whose live cert also equals its prior cert) is
      // untouched and still rolls back to its prior key.
      var certKeyUnchanged = !certRepublished && manifest.key === manifest.newKey;
      // Only when the hard cut was REMOVING an existing retained root (prevAction "restore"): a "delete"/
      // "leave" journal never had a readable prev, so an absent ca.prev.crt there is the normal state of
      // an INTERRUPTED rotation (crash before the cert publish), not evidence a removal completed.
      var hardCutRemovalDone = certKeyUnchanged && manifest.retainAfter === false &&
        manifest.prevAction === "restore" && !nodeFs.existsSync(paths.caCertPrev);
      completed = certRepublished || hardCutRemovalDone;
    } else {
      // No PRIOR cert (a key-only cold start: the retry's _commitLocked captured an
      // orphaned prior key with no cert). The "cert changed from prior" discriminator
      // cannot run, so classify by the intended NEW cert: completed iff the live cert IS
      // the one this commit meant to publish. Without this a completed key-only init
      // would be misread as interrupted and restore the orphaned key beside the new cert.
      completed = curCertBuf !== null && newCertBuf !== null && Buffer.from(curCertBuf).equals(newCertBuf);
    }
    var wantKeyBuf, wantPrevBuf;   // wantPrevBuf: Buffer=write it, null=remove prev, undefined=leave untouched
    if (completed) {
      // Finish the rotation: the new key, and the retained root it intended (the
      // outgoing/prior cert if it retained, else removed). Closes a completed
      // rotation whose key rename or prev unlink didn't durably stick.
      wantKeyBuf  = (typeof manifest.newKey === "string") ? Buffer.from(manifest.newKey, "base64") : null;
      // Roll forward to the ACTUAL intended retained root recorded at commit (retainAfterCert), not
      // the prior cert: an idempotent reformatted recommit keeps the EXISTING ca.prev.crt (priorPrev),
      // which differs from the prior cert. Fall back to priorCertBuf for a journal predating the field.
      wantPrevBuf = manifest.retainAfter
        ? (typeof manifest.retainAfterCert === "string" ? Buffer.from(manifest.retainAfterCert, "base64") : priorCertBuf)
        : null;
      // Restore the CUSTOM-engine label the completed commit published, so a crash between the CA
      // publish and the ca.algorithm write cannot leave the label stale against the new CA. Idempotent
      // (a no-op when it already matches). Only on COMPLETED — an interrupted commit rolled the CA back
      // to the prior cert, whose label the un-overwritten ca.algorithm still correctly holds.
      if (typeof manifest.customAlgorithm === "string" && manifest.customAlgorithm.length > 0) {
        _persistAlgorithm(manifest.customAlgorithm);
      }
    } else {
      // Roll back to the prior key, and the prior retained root per prevAction
      // ("restore" bytes / "delete" a prev this rotation created / "leave" untouched).
      wantKeyBuf  = Buffer.from(manifest.key, "base64");
      wantPrevBuf = (manifest.prevAction === "restore" && typeof manifest.prevData === "string")
        ? Buffer.from(manifest.prevData, "base64")
        : (manifest.prevAction === "delete" ? null : undefined);
      // Undo a partially-applied re-label: the interrupted commit may have already written the new
      // ca.algorithm, so restore the prior label the journal captured (mirrors the outer catch's
      // in-memory rollback for a crash BETWEEN the catch's restore and the journal delete). A null
      // priorCustomAlgorithm means there was NO prior label (an unpinned CA re-labeled), so REMOVE the
      // rejected label — matching the catch's unlink arm — rather than leaving it active.
      if (typeof manifest.priorCustomAlgorithm === "string" && manifest.priorCustomAlgorithm.length > 0) {
        _persistAlgorithm(manifest.priorCustomAlgorithm);
      } else if (manifest.priorCustomAlgorithm === null && typeof manifest.customAlgorithm === "string" &&
                 manifest.customAlgorithm.length > 0 && nodeFs.existsSync(paths.algorithm)) {
        nodeFs.unlinkSync(paths.algorithm);
        atomicFile.fsyncDir(nodePath.dirname(paths.algorithm));
      }
    }
    // Drive the live key to the authoritative bytes (idempotent — a no-op when it
    // already matches). Byte comparison so it works for a custom engine too.
    if (wantKeyBuf !== null) {
      var curKeyRaw = nodeFs.existsSync(keyDest)
        ? atomicFile.fdSafeReadSync(keyDest, { maxBytes: C.BYTES.mib(1) }) : null;
      if (curKeyRaw === null || !Buffer.from(curKeyRaw).equals(wantKeyBuf)) {
        atomicFile.writeSync(keyDest, wantKeyBuf, { fileMode: 0o600 });
      }
    }
    // Drive the retained root to the authoritative state (write bytes / remove /
    // leave). Repairs a resurrected hard-cut root or a lost retained-root write.
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
    // Drive the moved-aside CRL to its authoritative state (BEFORE the journal delete,
    // so a failure keeps the journal for a retry — matching the key/prev drives). Only
    // when THIS journaled commit moved a CRL aside (manifest.crlMovedAside): a
    // crl.rollback present otherwise is an ORPHAN from a prior commit whose best-effort
    // delete failed, so restoring it would publish a stale-issuer CRL and deleting it
    // would touch a file this journal has no claim on — leave it (it is inert at the
    // .rollback name and a later move-aside overwrites it). When it IS ours: if this
    // rotation COMPLETED (the cert republished), that CRL is signed by the superseded
    // issuer — delete it; if it was INTERRUPTED (rolled back), the CA it reverts to is
    // still active, so its CRL is still valid — rename it back to the documented path.
    var crlRollback = _crlRollbackPath();
    if (manifest.crlMovedAside) {
      if (completed) {
        // A completed rotation superseded the CRL's issuer. Remove the moved-aside copy
        // if the move stuck, AND any live paths.crl a LOST move-aside (a best-effort
        // fsyncDir that did not persist the rename, while the later cert rename did) left
        // as the stale OLD-issuer CRL under the new CA — else it stays published until the
        // operator regenerates. Safe: a journal is still present, so no generateCrl() has
        // written a fresh CRL since the crash (it would have reconciled first).
        if (nodeFs.existsSync(crlRollback)) {
          nodeFs.unlinkSync(crlRollback);
          atomicFile.fsyncDir(nodePath.dirname(crlRollback));
        }
        if (nodeFs.existsSync(paths.crl)) {
          nodeFs.unlinkSync(paths.crl);
          atomicFile.fsyncDir(nodePath.dirname(paths.crl));
        }
      } else if (nodeFs.existsSync(crlRollback) && !nodeFs.existsSync(paths.crl)) {
        // Interrupted: the CA reverts to the one whose CRL is still valid — restore it.
        atomicFile.renameWithRetry(crlRollback, paths.crl);
        atomicFile.fsyncDir(nodePath.dirname(paths.crl));
      }
    }
    // Delete the journal durably, and PROPAGATE a failure — this is NOT best-effort.
    // A surviving journal would let _journalRetainedRoot()/loadTrustBundle() keep
    // treating it as authoritative and re-trust its saved root, undoing a completed
    // cutoff. Throwing here fails the caller closed (dropRetained/initCA/rotate),
    // so a cutoff never "completes" while its interrupted journal is still live; the
    // operator resolves the fault (e.g. a read-only journal dir) and retries — the
    // restore above is idempotent, so re-running reconcile is safe. The fsync (best-
    // effort per platform) makes the deletion durable across a power loss.
    nodeFs.unlinkSync(keyJournal);
    atomicFile.fsyncDir(nodePath.dirname(keyJournal));
    caLog.warn("recovered-interrupted-rotation",
      { path: keyDest, detail: (completed ? "finished" : "rolled back") +
        " an interrupted rotation from the rollback journal (byte-exact)" });
  }

  function _commitJournalPath() {
    return ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
  }

  // Fixed name a CA-changing commit moves the stale CRL aside to before publishing the
  // new cert. A fixed (untokenized) name is safe because reconcile runs first on every
  // mutating open, so no stale crl.rollback survives into a later rotation; presence +
  // the completed/interrupted discriminator drive whether reconcile deletes it (stale)
  // or renames it back (still valid), so it needs no journal field.
  function _crlRollbackPath() {
    return paths.crl + ".rollback";
  }

  // Refuse to RETURN a stored CA that disagrees with the handle's algorithm pin: the
  // CA's own signature over every leaf is what a peer verifies, so issuing an ECDSA
  // leaf pinned for a legacy peer under a stored ML-DSA CA still yields an ML-DSA chain
  // that peer cannot verify. Shared by initCA()'s existing-CA path AND the fresh-init
  // adoption branch (a concurrent process may have created the CA under a different
  // recognized algorithm while this handle awaited generateCa) so every path that
  // adopts a stored CA enforces the pin identically. A custom engine may store a key
  // node cannot parse — the check is skipped then (the engine owns leaf issuance).
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
    // Every ECDSA label maps to the generic "ec" type, so the type check alone would
    // accept a P-256/P-521 stored CA under the ECDSA-P384 pin — leaving the operator
    // believing they hold P-384 posture. The framework's sole classical pin is
    // ECDSA-P384-SHA384 (secp384r1), so enforce the curve for it; a custom-engine label
    // (unrecognized here) owns its own curve.
    if (actualType === "ec" && /ecdsa-p384/i.test(String(caAlgorithm)) && actualCurve !== CLASSICAL_CA_CURVE) {
      throw new MtlsCaError("mtls-ca/algorithm-mismatch",
        "the CA at this dataDir uses EC curve " + actualCurve + ", but algorithm " +
        JSON.stringify(caAlgorithm) + " requires P-384 (" + CLASSICAL_CA_CURVE + "). Rotate to a new " +
        "CA (a fresh dataDir, or a higher generation) to change the curve.");
    }
  }

  // Durably record the effective CUSTOM-engine algorithm label as shared metadata, so a SECOND handle
  // over the same dataDir picks up the CURRENT label after this handle's commit/rotate({ algorithm }).
  // Called under the rotation lock, alongside the CA publish. Default-engine labels are cert-derivable,
  // so they are never persisted or read here.
  function _persistAlgorithm(label) {
    atomicFile.writeSync(paths.algorithm, String(label), { fileMode: 0o600 });
  }
  // Read the persisted custom label a prior commit/rotate recorded (undefined when absent). fdSafeRead
  // caps the read; a missing/unreadable file just means no cross-handle label was recorded.
  function _readPersistedAlgorithm() {
    if (!nodeFs.existsSync(paths.algorithm)) return undefined;
    var s = "";
    try {
      s = atomicFile.fdSafeReadSync(paths.algorithm, { maxBytes: C.BYTES.kib(4) }).toString("utf8");
    } catch (_e) {
      // Only a genuine absent-file race — the label unlinked between the existsSync check and the open
      // — is "no label". Any OTHER read failure (permissions, an unreadable/temporarily-unmounted
      // algorithm path, an over-cap read) must NOT masquerade as missing: a stale create-time pin or a
      // bundled label a later probe infers would then be used against the CA. Fail closed so adoption,
      // rotation, and probing abort rather than silently downgrade the durable cross-handle label.
      if (_e && _e.code === "ENOENT") return undefined;
      throw _e;
    }
    return s.length > 0 ? s : undefined;
  }

  // The NEW label of a COMPLETED-commit journal whose ca.algorithm write was deferred (a CA-changing
  // commit whose label write failed but whose CA published — _labelPersistDeferred) or crash-stranded:
  // the live cert equals the journal's newCert, so the journal's customAlgorithm is the CA's actual
  // label even though the on-disk ca.algorithm file is still the old one. Read-only — reconcile applies
  // it durably; this reports what reconcile WOULD apply so the status/probe paths never read the stale
  // file. undefined when there is no such pending completed label.
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
    // COMPLETED as reconcile classifies it: the live cert is NOT the journal's PRIOR cert, so the
    // commit's new CA — and its customAlgorithm — is the published one, and a deferred label persist
    // (_labelPersistDeferred, only ever on a CA-changing commit) is what left the file stale. A same-cert
    // REJECTED re-stamp (live cert == the journal's prior cert) is INTERRUPTED — its rollback-restored
    // file label is authoritative, NOT this journal's rejected label — so report nothing.
    var priorCert = Buffer.from(manifest.cert, "base64").toString("utf8");
    return !_sameCert(liveCert, priorCert) ? manifest.customAlgorithm : undefined;
  }

  // The custom engine's CURRENT effective label for the read-only status/probe paths (which do not
  // reconcile): a pending completed-commit journal's newer label, else the persisted file.
  function _currentCustomLabel() {
    var pending = _pendingCompletedJournalLabel();
    return (pending !== undefined) ? pending : _readPersistedAlgorithm();
  }

  // Verify a read CA pair and return it as a snapshot: refuse a persistent mismatch, validate
  // the pin, and capture the pin WITH the pair (so _leafEngineArgs binds the leaf to the pin as
  // of this read). Shared by every adoption tail (initCA's existing-CA path AND
  // _freshCreateSerialized's under-lock adopt) so none can skip the pairing / pin check.
  function _verifiedCASnapshot(certPem, keyPem) {
    if (!_caPairConsistent(certPem, keyPem)) {
      throw new MtlsCaError("mtls-ca/ca-pair-inconsistent",
        "the stored CA certificate and private key did not become a matching pair after re-reading " +
        "(a rotation may still be publishing, or the store is corrupt) — retry issuance");
    }
    _assertPinMatchesStoredCa(certPem, keyPem);
    return { caCertPem: certPem, caKeyPem: keyPem, algorithm: caAlgorithm };
  }

  // Read the STORED CA as a CONSISTENT snapshot: re-read past a transient in-flight rotation
  // (old-cert paired with new-key while another handle renames the two in sequence), reconcile
  // a leftover journal UNDER the rotation lock, refuse a persistent mismatch, validate the pin,
  // and capture the pin WITH the snapshot. Shared by initCA()'s existing-CA path AND
  // _freshCreateSerialized()'s cold-start adopt — the latter used to read unlocked with no
  // consistency check and could hand a mismatched pair to a custom engine.
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
    // A persistent mismatch (survived the re-read window), a leftover journal (a crash
    // between the cert rename and the journal delete), or a CUSTOM engine (whose cert/key
    // _caPairConsistent cannot verify, so only the lock proves the pair corresponds) needs
    // the rotation lock: reconcile, re-read the pair, AND build the verified snapshot inside
    // the SAME locked section. _verifiedCASnapshot samples the mutable caAlgorithm pin, so
    // building it after releasing the lock would let a concurrent same-handle rotate/commit
    // ({ algorithm: B }) publish B in the gap — pairing this A key/cert with label B, which a
    // custom signer rejects or mints an incompatible leaf under. (_freshCreateSerialized's
    // under-lock adopt tail builds its snapshot inside the lock for the same reason.)
    if (!_caPairConsistent(existingCertPem, existingKeyPem) ||
        nodeFs.existsSync(_commitJournalPath()) || !usesDefaultEngine) {
      var _snap;
      await atomicFile.lock(paths.caCert, function () {
        _reconcileCommitJournalLocked();
        existingCertPem = loadCert().toString("utf8");
        existingKeyPem  = loadKey().toString("utf8");
        // For a CUSTOM engine, adopt the CURRENT effective label another handle may have persisted via
        // commit/rotate({ algorithm }): a custom label is not cert-derivable, so this handle's stale
        // create-time pin would otherwise be passed to the new issuer and rejected. Read it UNDER the
        // lock, atomically with the cert/key, so the snapshot's label matches the stored CA.
        if (!usesDefaultEngine) {
          var _persisted = _readPersistedAlgorithm();
          if (_persisted !== undefined) caAlgorithm = _persisted;
        }
        _snap = _verifiedCASnapshot(existingCertPem, existingKeyPem);
      });
      return _snap;
    }
    // No lock was needed (a default-engine, already-consistent pair with no journal): the
    // snapshot's captured algorithm is unused by default-engine issuance (_leafEngineArgs derives
    // the leaf label from the CA key, not the pin), so sampling caAlgorithm unlocked here is safe.
    return _verifiedCASnapshot(existingCertPem, existingKeyPem);
  }

  var _initChain = Promise.resolve();
  // Serialized first-time creation (see initCA's fresh path). Re-checks exists() at
  // the start (a prior chained init may have created it, avoiding a wasted keygen)
  // and again UNDER the rotation lock (a separate process may have created it while
  // we awaited generateCa) — adopting the committed CA instead of clobbering it.
  async function _freshCreateSerialized() {
    // A prior chained init (or a separate process) may have created the CA before this
    // keygen runs. Adopt it through the SAME consistent-snapshot path as initCA (re-read
    // past an in-flight rotation, reconcile under the lock) — reading it unlocked here could
    // return an old-cert/new-key pair mid-rotation and hand a mismatched pair to a custom
    // engine.
    if (exists()) {
      return _adoptExistingCASnapshot();
    }
    // Build the args conditionally so an `algorithm` key is present ONLY when the
    // operator pinned one — a strict custom engine that validates its generateCa
    // option shape would reject an own `algorithm: undefined` key on an unpinned
    // first-time init (matching the conditional custom leaf-engine handling).
    var caGenArgs = { generation: generation };
    if (caAlgorithm !== undefined) caGenArgs.algorithm = caAlgorithm;
    var fresh = await engine.generateCa(caGenArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    return atomicFile.lock(paths.caCert, function () {
      if (exists()) {
        // A separate process committed a CA under the shared dataDir while we awaited
        // generateCa. Adopt it rather than clobber it — but RECONCILE a leftover journal
        // first and verify the pair (that process may have crashed mid-rotation, leaving an
        // old-cert/new-key pair; an unpinned default-engine handle's _assertPinMatchesStoredCa
        // does no pairing check, so signing the mismatched snapshot would return a leaf that
        // does not chain to the stored root). Same discipline as initCA's existing-CA path.
        _reconcileCommitJournalLocked();
        var adoptedCert = loadCert().toString("utf8");
        var adoptedKey  = loadKey().toString("utf8");
        // A concurrent create won the CA: for a custom engine, adopt its PERSISTED label (as
        // _adoptExistingCASnapshot does) rather than this handle's own create-time pin — else a
        // cold-start sibling with a different pin issues under the wrong label against the winner's CA.
        if (!usesDefaultEngine) {
          var _adoptedLabel = _readPersistedAlgorithm();
          if (_adoptedLabel !== undefined) caAlgorithm = _adoptedLabel;
        }
        return _verifiedCASnapshot(adoptedCert, adoptedKey);
      }
      // _commitLocked persists the create-time custom label (its _customCommitLabel falls back to this
      // handle's caAlgorithm) BEFORE publishing the CA: a fresh create writes no rollback journal, so
      // the label goes down first, and an unwritable algorithm path throws before the cert lands —
      // leaving no CA installed rather than a labelless CA a sibling would issue under its own stale
      // pin. Since the cert is published last, any handle that sees the CA also sees its label.
      _commitLocked(fresh);
      // Carry the create-time pin as the snapshot's algorithm (as the existing-CA and adopt
      // paths do) so an issuance that triggered this creation binds its leaf to the pin the
      // CA was made under, not a later rotate()-refreshed caAlgorithm.
      return Object.assign({}, fresh, { algorithm: caAlgorithm });
    });
  }

  async function initCA() {
    // A stored CA is adopted as a consistent snapshot (re-read past an in-flight rotation,
    // reconcile under the lock, refuse a persistent mismatch, validate + capture the pin).
    if (exists()) {
      return _adoptExistingCASnapshot();
    }
    // First-time creation. Serialize it (like rotation) so two concurrent cold-start
    // callers — the normal generateClientCert()-before-a-CA-exists path, same handle
    // or two processes over one dataDir — cannot each generate a CA and clobber one
    // another (the loser's just-issued leaf would chain to a CA that no longer
    // exists). _initChain serializes same-handle creation; the lock + double-check
    // handles cross-process.
    var next = _initChain.then(function () { return _freshCreateSerialized(); });
    _initChain = next.then(function () {}, function () {});
    return next;
  }

  // Recover the issued certificate's identity from its PEM so issuance and
  // any later revocation/indexing share identifiers without a round-trip back
  // through an X.509 parser. serialNumber is normalized to the same hex form
  // revoke() stores; fingerprint is the SHA3-512 the require-mtls gate pins.
  function _certIdentity(certPem) {
    // serialNumber comes from an X.509 parse, which is best-effort: a custom
    // engine (or a test double) may return a cert in a shape this Node build
    // cannot parse as X.509. The fingerprint is a hash of the returned bytes,
    // so it is always available and is what the require-mtls gate pins —
    // revoke()/isRevoked() by fingerprint keep working even when the serial
    // can't be recovered. Never let optional identity enrichment crash issuance.
    var serialNumber = null;
    try {
      serialNumber = _normalizeSerial(new nodeCrypto.X509Certificate(certPem).serialNumber);
    } catch (_e) {
      serialNumber = null;
    }
    // Hash the certificate's DER — exactly what the require-mtls gate pins
    // (b.crypto.hashCertFingerprint decodes the PEM envelope first). Hashing the
    // PEM TEXT instead (b.crypto.sha3Hash(certPem)) yields a value that never
    // matches the gate, so revoke()/revokeGeneration() by it could not be
    // enforced by a revocationSource-wired gate. A custom engine may return a
    // cert with no decodable PEM/DER envelope — that cert can't reach a standard
    // TLS gate either, so fall back to a stable hash of the returned bytes:
    // issuance always surfaces a revocable id and never crashes.
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

  // Build the engine call args for a leaf/PKCS#12 issuance. The leaf follows the
  // CA's algorithm: the pin when set (initCA already verified it matches the
  // stored CA), otherwise — for the BUNDLED engine only — the stored CA's own
  // algorithm, so an unpinned upgrade over an existing classical CA keeps issuing
  // classical leaves instead of the engine's ML-DSA process default. A custom
  // engine gets no inferred algorithm (its label set / key curve is its own to
  // resolve; the bundled ECDSA-P384-SHA384 label would break it). An explicit
  // opts2.algorithm always wins.
  function _leafEngineArgs(ca, opts2) {
    // Derive the leaf algorithm from the SNAPSHOTTED CA, never from the mutable caAlgorithm
    // pin. A concurrent commit()/rotate() can refresh the pin between an issuance's initCA()
    // snapshot and this call (the pin is a closure variable both mutate); reading the pin
    // would then mint a leaf under the NEW algorithm but signed by the OLD snapshotted issuer
    // (e.g. an ML-DSA leaf under a retained ECDSA CA that the grace window's legacy peers
    // cannot authenticate). The snapshot is immutable, so binding the leaf to it guarantees
    // the algorithm matches the CA the leaf is actually signed under.
    //
    // For the DEFAULT engine the stored CA's own key type maps to the bundled label set (and
    // equals a valid pin, which initCA already validated against the stored CA — so this is a
    // no-op in the non-racing case). A CUSTOM engine resolves its OWN algorithm from its own
    // key: its pin passes through unchanged (injecting a bundled ECDSA-P384-SHA384 label would
    // break a P-256/P-521 or custom-labeled engine that validates its option shape). The custom
    // pin comes from the SNAPSHOT (ca.algorithm, captured by initCA atomically with the CA) —
    // NOT the mutable caAlgorithm closure, which a concurrent rotate({ algorithm }) can refresh
    // to a different label before this line runs, handing the engine a new label with the old
    // snapshotted CA (mint an incompatible leaf / reject issuance).
    var leafAlg = usesDefaultEngine ? _labelForCaKeyType(ca.caKeyPem) : ca.algorithm;
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    if (leafAlg !== undefined) {
      // The resolved CA algorithm (a pin verified against the stored CA, or the
      // bundled engine's stored-CA inference) is AUTHORITATIVE and wins over a
      // per-issuance opts.algorithm: silently honoring a conflicting one would let
      // a classical ECDSA CA issue an ML-DSA leaf its legacy peers can't
      // authenticate (and mis-select the P12 MAC tier). Refuse a conflict outright
      // rather than issue a leaf that doesn't match the CA the operator pinned.
      if (opts2.algorithm !== undefined && opts2.algorithm !== leafAlg) {
        throw new MtlsCaError("mtls-ca/algorithm-conflict",
          "generateClientCert/generateClientP12: opts.algorithm " + JSON.stringify(opts2.algorithm) +
          " conflicts with the CA's algorithm " + JSON.stringify(leafAlg) +
          " (the leaf must match the CA; rotate to a fresh CA to change algorithms)");
      }
      args.algorithm = leafAlg;
    }
    // When leafAlg is undefined (a custom engine), opts2.algorithm passes through
    // for the engine to resolve; caCertPem/caKeyPem are forced last so opts2 can't
    // shadow them.
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
    // Surface the issued serial + fingerprint so the caller can track/revoke
    // the cert by the same identifiers without re-parsing the PEM.
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
    // Leaf (and its P12 MAC tier) follows the CA's algorithm via the shared
    // arg-builder — the pin when set, else the bundled engine's stored-CA
    // inference, never a custom engine's inferred label or the process default.
    var args = _leafEngineArgs(ca, opts2);
    var result = await engine.packageP12(args);
    if (!result || !Buffer.isBuffer(result.p12)) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return { p12: Buffer, certPem, issuedAt, expiresAt }");
    }
    // certPem is required engine output: it is the identity _recordIssuance writes to
    // the ledger. It must be a non-empty string, but it need NOT be node-parseable — a
    // custom engine may package a valid certificate this runtime cannot parse (e.g. a
    // newer post-quantum algorithm), exactly as generateClientCert() accepts. _certIdentity
    // still derives a stable fingerprint from the bytes, and parsing here could not prove
    // certPem is the certificate INSIDE the encrypted p12 anyway — that pairing is the
    // packageP12 engine's contract (the bundled engine builds both from one signing
    // operation so they always agree; the framework cannot re-verify an arbitrary
    // engine's encrypted, engine-defined bag). Requiring parseability only broke the
    // opaque-engine case without establishing the pairing guarantee.
    if (typeof result.certPem !== "string" || result.certPem.length === 0) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return a non-empty certPem so the archive is recorded in the issuance " +
        "ledger — an unrecorded P12 could not be revoked by revokeGeneration()");
    }
    var id12 = _certIdentity(result.certPem);
    await _recordIssuance(ca.caCertPem, id12);
    return Object.assign({}, result, { serialNumber: id12.serialNumber, fingerprint: id12.fingerprint });
  }

  // ---- Revocation registry + CRL ----

  // Revocation entries are read + written through a store so the registry can
  // live somewhere other than the default plaintext revocations.json — e.g. an
  // operator-supplied encrypted / clustered store (the bring-your-own-store
  // precedent b.queue's config.db set). Contract (sync):
  //   list()     -> array of revocation entries
  //   add(entry) -> append one entry (the caller has already deduped)
  function _defaultFileStore() {
    function _list() {
      if (!nodeFs.existsSync(paths.revocations)) return [];
      try {
        // safeJson.parse caps depth + size + protects against
        // proto-pollution; a tampered or truncated file shouldn't be able to
        // corrupt the rotator process.
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
      // Cheap change signal for isRevoked()'s index — the append-only file's byte
      // length grows on every add (mtime disambiguates a same-size rewrite), so a
      // revocation written by ANOTHER handle / process over this file bumps it and
      // the index rebuilds on the next lookup. O(1) statSync, not an O(n) parse.
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
  // The clustered-watermark methods are all-or-nothing: providing only one would
  // SPLIT the watermark (one operation shared, the other on the local file), so a
  // revoked generation could still issue on another host — a fail-open. Refuse it.
  if ((typeof revocationStore.readGenerationWatermark === "function") !==
      (typeof revocationStore.bumpGenerationWatermark === "function")) {
    throw new MtlsCaError("mtls-ca/bad-revocation-store",
      "a revocationStore providing one of readGenerationWatermark() / bumpGenerationWatermark() must " +
      "provide BOTH — a split watermark would let a revoked generation still issue on another host");
  }

  // Revoked-generation watermark — the highest n passed to revokeGeneration(),
  // read by issuance to catch a leaf whose signing straddled a generation
  // revocation (see _recordIssuance). Stored in the LOCAL dataDir file by default,
  // which coordinates same-host processes. A CLUSTERED custom store (shared across
  // hosts, per-host dataDir) must instead expose { readGenerationWatermark(),
  // bumpGenerationWatermark(n) } so the watermark lives in the shared store; when
  // present those win. bumpGenerationWatermark(n) must be a monotonic max and own
  // its own atomicity.
  function _readRevokedWatermark() {
    if (typeof revocationStore.readGenerationWatermark === "function") {
      var v = revocationStore.readGenerationWatermark();
      // Fail CLOSED: a store that can't return a valid watermark must not let a
      // revoked generation slip through as 0. Only a genuine "never set" (0/absent)
      // is a valid zero.
      if (typeof v === "number" && isFinite(v) && v >= 0) return v;
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "revocationStore.readGenerationWatermark() returned a non-numeric value — refusing issuance rather " +
        "than treating a revoked generation as unrevoked");
    }
    // ONLY an absent file is a real zero. A present-but-unreadable/malformed file
    // must ABORT issuance — reporting 0 would let a below-n generation issued
    // during the sweep pass the _recordIssuance() check (the race this closes).
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
    // Require the WHOLE trimmed content to be digits — parseInt would accept
    // "1junk"/"1.5" and take a lower prefix, letting a below-watermark generation
    // slip through. Any non-integer content fails closed.
    var trimmed = String(raw).trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new MtlsCaError("mtls-ca/watermark-unreadable",
        "the revoked-generation watermark (" + paths.revokedGeneration + ") is malformed — refusing issuance");
    }
    var n = parseInt(trimmed, 10);
    return n;
  }
  // Returns a PROMISE: the shared-store bump owns its atomicity; the local-file
  // bump takes a cross-process lock on the watermark file for its read-modify-write.
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

  // In-memory revocation index — a Set of every revoked serial + fingerprint —
  // so isRevoked() (called PER REQUEST by a revocationSource-wired require-mtls
  // gate) is O(1) with no filesystem read/JSON-parse on the event-loop hot path.
  // Built lazily from the store on first use, then kept in sync by revoke().
  // Reflects revocations made through THIS handle; the default file store is
  // single-process, so a store mutated out-of-band is not re-read here.
  var _revIndex = null;
  var _revSerialOnly = null;
  var _revIndexVersion = null;
  // Return a fresh-enough Set of revoked serials + fingerprints. When the store
  // exposes version(), the index is rebuilt only when that signal changes — so a
  // revocation written by another handle / process is picked up (cache coherence)
  // while an unchanged store costs one version() call + a Set lookup, not an O(n)
  // reparse. A store with no version() signal owns its own coherence, so it is
  // read fresh each call rather than risk serving a stale cached view.
  function _revIndexFor() {
    var hasVersion = typeof revocationStore.version === "function";
    var storeVersion = hasVersion ? revocationStore.version() : null;
    if (_revIndex === null || !hasVersion || storeVersion !== _revIndexVersion) {
      _revIndex = new Set();
      _revSerialOnly = new Set();
      revocationStore.list().forEach(function (r) {
        if (r && r.serialNumber) _revIndex.add(r.serialNumber);
        if (r && r.fingerprint) _revIndex.add(r.fingerprint);
        // A serial is unique only PER ISSUER, so it is a SOUND revocation key on its own only
        // when the entry carries nothing else (a bare revoke(serial)). A serial+fingerprint
        // entry (revoke({serial,fingerprint}) / revokeGeneration's fingerprint backfill) is
        // scoped to its SPECIFIC cert by the fingerprint; keying it by serial too would
        // false-deny a different generation's cert reusing that serial in the live multi-root
        // gate (a custom engine that restarts its serial counter on rotation). Index the
        // serial-only entries separately so isSerialRevoked() consults only those.
        if (r && r.serialNumber && r.fingerprint == null) _revSerialOnly.add(r.serialNumber);
      });
      _revIndexVersion = storeVersion;
    }
    return _revIndex;
  }
  // The serial-only revocation index (see _revIndexFor) — built alongside _revIndex so it is
  // coherent with the same version() signal.
  function _revSerialOnlyFor() { _revIndexFor(); return _revSerialOnly; }

  // Issuance ledger — same bring-your-own-store contract as revocationStore
  // ({ list(), add(entry) }). Every generateClientCert/generateClientP12
  // appends { serialNumber, fingerprint, generation, issuedAt } so
  // revokeGeneration(n) can find the certs a superseded CA generation signed.
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
      // A PRESENT ledger MUST carry an `issued` array. Missing / non-array `issued`
      // (an accidental `{}`, a truncated or externally-rewritten file) is
      // corruption, not an empty ledger — silently treating it as [] would let the
      // next add() overwrite the file with only its own entry, dropping every prior
      // certificate from the SOLE index revokeGeneration() consults, so those certs
      // would survive a later generation revocation. Fail closed, as malformed JSON
      // does; the operator must restore or remove the file.
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
      // Cheap change signal, mirroring the revocation store's version(): every
      // _recordIssuance / importIssuance appends, growing the file (mtime
      // disambiguates a same-size rewrite), so generateCrl()'s issuer-scoping
      // snapshot can detect a backfill that lands while the engine signs and
      // skip publishing the now-stale CRL. O(1) statSync, not an O(n) parse.
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
  // Clustered operation (a shared revocationStore with the watermark methods, but
  // per-host dataDirs) REQUIRES a shared issuanceStore too. revokeGeneration()
  // sweeps the issuance ledger to find the certs a superseded generation signed;
  // with the DEFAULT local-file ledger each host records only its own issuances,
  // so a cert fully issued on host B before host A calls revokeGeneration() is
  // absent from A's sweep and stays accepted by the shared live gate — a fail-open
  // the shared watermark can't close (it only supersedes FUTURE appends). Refuse
  // the split at construction rather than silently under-revoking in a cluster.
  if (typeof revocationStore.readGenerationWatermark === "function" && usesDefaultIssuanceStore) {
    throw new MtlsCaError("mtls-ca/bad-issuance-store",
      "a clustered revocationStore (readGenerationWatermark/bumpGenerationWatermark) requires a shared " +
      "issuanceStore as well — the default per-host ledger would let revokeGeneration() miss certificates " +
      "issued on another host, leaving them accepted by the shared revocation gate");
  }

  // Record an issued leaf in the ledger. Fail-closed: the ledger is the SOLE
  // index revokeGeneration() consults, so a cert absent from it can never be
  // revoked by generation and would stay accepted by fingerprint-based
  // enforcement. A write failure (disk full, the 16 MiB cap crossed, a custom
  // store throwing) therefore FAILS issuance rather than returning an untracked
  // credential — the caller must resolve the persistence fault and re-issue.
  async function _recordIssuance(caCertPem, id) {
    // parseGeneration() returns 0 when node:crypto cannot parse the CA cert (a custom
    // engine's opaque / post-quantum cert). 0 is NOT a real generation (they are >= 1),
    // so record it as UNDETERMINABLE (null), never 0: recording 0 would make
    // revokeGeneration(1) sweep these CURRENT-generation leaves (0 < 1) and, via the
    // bumped watermark, self-revoke every future issuance under the CA. A null-generation
    // entry is skipped by revokeGeneration()'s numeric sweep (it stays revocable by
    // serial/fingerprint); a custom engine that wants generation-based revocation must
    // embed a node-parseable generation (OU=CAv<n>) in its cert.
    var parsedGen = parseGeneration(caCertPem);
    var gen = parsedGen >= 1 ? parsedGen : null;
    var entry = {
      serialNumber: id.serialNumber,
      fingerprint:  id.fingerprint,
      generation:   gen,
      // The IDENTITY of the CA cert that signed this leaf (DER-based fingerprint, reformat-stable;
      // a PEM-hash fallback for an opaque custom cert). generateCrl() scopes its entries by this,
      // NOT by generation — commit() can replace a CA with a DIFFERENT cert at the SAME generation,
      // so generation equality is not issuer equality; a serial reused under the new issuer would
      // otherwise be false-revoked by the old cert's entry.
      caFingerprint: _certIdentity(caCertPem).fingerprint,
      issuedAt:     Date.now(),
    };
    try {
      if (usesDefaultIssuanceStore) {
        // Serialize the ledger's read-modify-write across processes: two issuers
        // over the same dataDir must not both read the ledger, append locally,
        // and clobber each other's entry (a lost entry is invisible to
        // revokeGeneration(), so the cert would survive a generation revocation).
        // A custom store owns its own concurrency, so it is written directly.
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
    // Issuance-vs-generation-revocation race: this leaf's signing may have
    // straddled a rotate()+revokeGeneration(gen'>gen), whose sweep read the
    // ledger BEFORE the append above. revokeGeneration bumps the watermark before
    // sweeping, so having recorded FIRST then reading it here guarantees the leaf
    // is caught by one side or the other. Applies to ALL stores — the watermark is
    // a separate file, so a custom store (list()/add() only) is covered too. If
    // this generation is already revoked, revoke the leaf and refuse it. An
    // undeterminable (null) generation is never below the watermark — an opaque
    // custom cert can't be classified as superseded, so it is not self-revoked here.
    if (typeof gen === "number" && gen < _readRevokedWatermark()) {
      /* c8 ignore next -- the ||null fallbacks are defensive API normalization: _certIdentity always yields a fingerprint, and a serial is present for every leaf a parseable-CA engine issues */
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "certificate for CA generation " + gen + " was issued while revokeGeneration() revoked that " +
        "generation (a concurrent rotation) — the certificate has been revoked; re-issue under the current generation");
    }
    // Issuance-vs-root-removal race: a hard-cut rotate({ retainPrevious:false }) or a
    // dropRetained() can remove the root this leaf was signed under while its signing
    // was in flight, leaving a leaf that chains to a root no longer in loadTrustBundle().
    // Having recorded the leaf FIRST, then checking membership here, a leaf whose
    // issuing root was dropped mid-flight is caught and revoked instead of returned
    // un-verifiable — covering both the hard cut and dropRetained without a watermark
    // bump that races the removal or wrongly supersedes on a failed rotation. (A root
    // removed AFTER this check is the operator's intended cut of that generation,
    // which cuts this leaf along with its cohort; a RETAINED rotation keeps the old
    // root in the bundle, so its straddling leaf still chains and is NOT revoked.)
    // Membership by cert IDENTITY (not exact PEM text): an idempotent commit() that
    // republished this same root with harmless PEM differences (CRLF, wrapping, a stripped
    // trailing newline) leaves the same root in the bundle under different bytes — a string
    // indexOf would miss it and falsely revoke a leaf that still chains.
    var _issuingRoots = await loadTrustBundle();
    if (!_issuingRoots.some(function (root) { return _sameCert(root, caCertPem); })) {
      /* c8 ignore next -- the ||null fallbacks are defensive API normalization: _certIdentity always yields a fingerprint, and a serial is present for every leaf a parseable-CA engine issues */
      await revoke({ serial: id.serialNumber || null, fingerprint: id.fingerprint || null, reason: "superseded" });
      throw new MtlsCaError("mtls-ca/issuance-superseded",
        "the CA root this certificate was signed under was removed (a concurrent hard-cut rotation or " +
        "dropRetained()) before issuance completed — the certificate has been revoked; re-issue under the current CA");
    }
  }

  // A fingerprint is the SHA3-512 hex the require-mtls gate pins. Normalize it
  // like a serial (strip 0x / separators / whitespace, lowercase, hex-validate)
  // so a consumer can revoke by the same value the gate compares against.
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

  // Normalize a fingerprint that will be STORED for the require-mtls gate to compare against
  // (revoke({ fingerprint }) / importIssuance). Beyond _normalizeFingerprint's hex validation,
  // require the framework's SHA3-512 length: a SHA-256 (64-hex) or truncated value is valid hex, so
  // it would be accepted and "revoke" successfully, yet the gate pins the peer's 128-hex SHA3-512
  // fingerprint — the compare never matches and the certificate stays admitted (a silent fail-open).
  // Reject the wrong length at the write. isRevoked()/isSerialRevoked() keep the bare normalizer:
  // they also accept a SERIAL (shorter), matched against either key an entry carries.
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

  // Map operator-friendly reason codes to RFC 5280 numeric codes used by X.509
  // CRLs. Default "unspecified" (0) when omitted. removeFromCRL (code 8) is
  // deliberately absent: it is a DELTA-CRL directive to UN-revoke a cert from the
  // base CRL, not a revocation reason, and is invalid in a full CRL (all this CA
  // issues) — the toolkit refuses it at sign time, so a persisted code-8 entry
  // would poison every later generateCrl(). revoke() rejects it explicitly below.
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

  // Unlocked registry read/dedupe/add. Callers hold the revocation lock (default
  // store) or own their own concurrency (custom store) before invoking this.
  function _revokeCore(serial, fingerprint, reasonName, reasonCode) {
    var existing = revocationStore.list().find(function (r) {
      var serialMatch = serial && r.serialNumber === serial;
      var fingerprintMatch = fingerprint && r.fingerprint === fingerprint;
      if (!serialMatch && !fingerprintMatch) return false;
      // A TRUE duplicate already carries every identifier this call supplies AND is no MORE
      // specific in a way that matters to enforcement. A serial-only entry matched by a
      // revoke({ serial, fingerprint }) call (revokeGeneration's shape) is NOT a duplicate —
      // its fingerprint is missing, so the require-mtls gate (fingerprint-keyed) would still
      // admit the cert; fall through and record the fingerprint-bearing entry. Conversely, a
      // SERIAL-ONLY revoke(serial) must only dedup against an existing SERIAL-ONLY entry: a
      // pre-existing serial+FINGERPRINT entry (e.g. an OLD generation's cert with a since-reused
      // serial) is a DIFFERENT cert, and treating it as a duplicate would drop the serial-only
      // entry so isSerialRevoked() stays false and the gate admits the current cert.
      var coversSerial = !serial || r.serialNumber === serial;
      var coversFingerprint = fingerprint ? (r.fingerprint === fingerprint) : (r.fingerprint == null);
      return coversSerial && coversFingerprint;
    });
    if (existing) {
      // Idempotent — repeated revoke() of the same serial/fingerprint doesn't
      // shift the revokedAt timestamp.
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

  // revoke() validates its input SYNCHRONOUSLY (entry-point tier: a bad serial /
  // fingerprint / reason throws before any work) but returns a PROMISE for the
  // result, because the default store's read/dedupe/add runs under a cross-process
  // lock. Await the returned promise for the recorded entry.
  function revoke(idOrOpts, opts3) {
    // Accept either revoke(serialString, { reason, fingerprint }) — the
    // backward-compatible serial-keyed form — or revoke({ serial?,
    // fingerprint?, reason? }). The require-mtls gate denies by fingerprint,
    // so a fingerprint-indexed consumer can revoke by the same value it pins
    // on; serial-keyed behavior stays the default. At least one key required.
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
      // Serialize the registry read/dedupe/add across processes (same rationale
      // as the issuance ledger) so a concurrent revoke() / revokeGeneration() in
      // another process cannot read the same file, append locally, and clobber
      // this entry — a lost revocation would let the live gate admit the cert.
      return atomicFile.lock(paths.revocations, function () {
        return _revokeCore(serial, fingerprint, reasonName, reasonCode);
      });
    }
    return Promise.resolve(_revokeCore(serial, fingerprint, reasonName, reasonCode));
  }

  function isRevoked(serialOrFingerprint) {
    // Accept a serial number OR a SHA3-512 fingerprint — both are hex, so one
    // normalized form is matched against either key each entry carries.
    if (!serialOrFingerprint || typeof serialOrFingerprint !== "string") {
      throw new MtlsCaError("mtls-ca/bad-revocation-key",
        "isRevoked requires a serial number or a fingerprint (hex string)");
    }
    var norm = _normalizeFingerprint(serialOrFingerprint);
    return _revIndexFor().has(norm);
  }

  // Is this serial revoked by a SERIAL-ONLY entry (a bare revoke(serial), fingerprint:null)?
  // Used by the require-mtls live gate for a serial fallback: a serial+fingerprint revocation
  // is already matched by its fingerprint there, and a serial is unique only per issuer, so
  // matching it globally would false-deny a different generation's cert reusing the serial.
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
    // persist gates a `!== false` truthiness check below (default: persist). A supplied
    // non-boolean (e.g. the string "false" from config) is not the literal false and
    // would persist when the operator meant return-only. Reject it, matching commit()/
    // rotate()'s retainPrevious validation (config-time input throws on a typo).
    if (opts3.persist !== undefined && typeof opts3.persist !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-persist",
        "generateCrl: opts.persist must be a boolean when set (got " + JSON.stringify(opts3.persist) +
        ") — a non-boolean like the string \"false\" is not the literal false and would still persist the CRL");
    }
    var ca = await initCA();
    // Snapshot the revocation registry together with the default store's version() so the
    // persist below can detect a revoke()/revokeGeneration() that COMPLETES while we await
    // engine.generateCrl(): publishing a CRL signed over the older snapshot would drop a
    // revocation that already returned success, leaving CRL-based clients accepting the
    // revoked certificate until the next regeneration. For a custom store the framework does
    // not own the write lock, so there is no version signal to compare (operator's concern).
    var allRevocations, revSnapshotVersion;
    var _snapshotRevocations = function () {
      allRevocations = revocationStore.list();
      revSnapshotVersion = (typeof revocationStore.version === "function") ? revocationStore.version() : null;
    };
    if (usesDefaultRevocationStore) { await atomicFile.lock(paths.revocations, _snapshotRevocations); }
    else { _snapshotRevocations(); }
    // A standard X.509 CRL (RFC 5280 §5.1) is keyed by certificate serial
    // number. revoke({ fingerprint }) — a first-class revocation mode, and the
    // value the require-mtls gate pins on — stores no serial (serialNumber is
    // null). Such an entry cannot be represented in a CRL, so project it out
    // here rather than handing a null serial to the CRL encoder: the encoder
    // throws on it, which would break CRL generation for the ENTIRE registry,
    // dropping the serial-keyed certs that CAN be published from every fresh
    // CRL (a fail-open for those certs' published revocation). Fingerprint-only
    // revocations stay enforced through isRevoked()/the mTLS gate, which is
    // fingerprint-aware; the count that could not be represented is surfaced.
    // Dedup by serial: one certificate can carry two registry entries (a
    // serial-only revocation plus a later serial+fingerprint one added when
    // revokeGeneration backfills the fingerprint), but a CRL must list each
    // serial once.
    // Scope the CRL to the CURRENT ISSUER IDENTITY. A CRL is signed by ONE CA, and X.509 serials
    // are unique only per issuer, so a revocation whose cert was issued by a DIFFERENT CA must NOT
    // be published here — under a custom engine that reuses a serial, that CA's revoked serial
    // would false-revoke the unrelated current certificate reusing it. Scope by the ISSUING CA's
    // identity (the ledger's caFingerprint), NOT by generation: commit() can replace a CA with a
    // different cert at the SAME generation, so generation equality is not issuer equality.
    // Resolve each entry's issuer from the ledger — by leaf FINGERPRINT (unique) preferentially,
    // else by serial when it maps to a single issuer. An entry whose issuer cannot be determined
    // (an out-of-band serial, or an undeterminable current identity) stays in, best-effort.
    // Snapshot the issuance ledger (the issuer-scoping source) together with its version(), the
    // same way the revocation registry is snapshotted above: an importIssuance() that backfills a
    // revoked serial's issuer can COMPLETE while we await engine.generateCrl(), and the persist
    // below re-checks this version so a CRL built from the older ledger view — which would still
    // list an old-issuer serial a serial-reusing custom engine reassigned to a current cert — is
    // not published. For a custom store the framework owns no lock, so there is no version signal
    // (operator's concern), matching the revocation-store handling.
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
        if (ei != null && ei !== currentCaId) return false;   // issued by a different CA — not this CRL
      }
      if (seenSerials.has(r.serialNumber)) return false;
      seenSerials.add(r.serialNumber);
      return true;
    });
    // The CRL's content IS its issuer-scoped, deduped SERIAL set. Compute a stable signature of it
    // (and a re-computer from arbitrary fresh store views) so the persist below can re-check the CRL's
    // ACTUAL content — not each store's coarse version() — and skip a re-sign only when the content
    // genuinely changed. A normal generateClientCert() appends an unrelated fresh serial to the ledger
    // (and a fingerprint-only revoke() adds no serial), advancing a version() but leaving this set
    // unchanged; only a new serial revocation OR an importIssuance issuer-backfill of a revoked serial
    // alters it. _scopedCrlSerials mirrors the filter above (issuer maps + issuer-scope + dedup).
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
    // Count ONLY entries that genuinely lack a serial (fingerprint-only, thus
    // unrepresentable in an X.509 CRL). Deriving this from allRevocations.length
    // - revocations.length would wrongly fold in the serial DUPLICATES the dedup
    // above dropped, over-reporting the CRL as incomplete when those serials are
    // in fact published.
    var fingerprintOnlyOmitted = allRevocations.filter(function (r) {
      return r && r.serialNumber == null;
    }).length;
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
    var persisted = false;
    if (opts3.persist !== false) {
      // The CA may have ROTATED while we awaited engine.generateCrl() — the signed
      // CRL is then for the SUPERSEDED CA, and persisting it would recreate the
      // stale-issuer artifact a rotation just invalidated. Under the rotation lock
      // (so no rotation is in flight), re-check that the CA we signed under is still
      // current; persist only then. If it rotated, skip — the caller regenerates
      // under the new CA (persisted=false signals it).
      await atomicFile.lock(paths.caCert, function () {
        // Compare by cert IDENTITY, not exact PEM text: an idempotent commit() that republished
        // the SAME cert with harmless PEM reformatting during signing must not read as a rotation
        // and skip the persist.
        if (!(nodeFs.existsSync(paths.caCert) &&
              _sameCert(atomicFile.fdSafeReadSync(paths.caCert, { maxBytes: C.BYTES.mib(1) }).toString("utf8"), ca.caCertPem))) {
          return;   // CA rotated during signing — this CRL is for the superseded issuer
        }
        var _writeCrl = function () {
          atomicFile.writeSync(paths.crl, crlPem, { fileMode: 0o644 });
          persisted = true;
        };
        // The just-signed CRL depends on BOTH the revocation snapshot AND the issuance-ledger
        // snapshot that resolved issuer-scoping (which serials are in/out). A revoke()/
        // revokeGeneration() OR an importIssuance() issuer-backfill may have COMPLETED while we
        // signed, making the CRL stale. Recompute the scoped serial set from BOTH fresh lists in ONE
        // coherent view with BOTH leaf locks held, so the check and the paths.crl write are atomic
        // with every store write. Checking each store against the OTHER's stale snapshot misses a
        // scope change only the combined fresh view reveals: a revoke by a NEW fingerprint plus an
        // importIssuance mapping that fingerprint to the current issuer each look scope-neutral alone,
        // but together move a serial into the CRL. Global lock order is caCert < revocations <
        // issuance — each is only ever a leaf lock elsewhere (revokeGeneration reads the ledger
        // unlocked; _recordIssuance releases the issuance lock before taking caCert), so this nesting
        // has no inverse and cannot deadlock. The version fast-path stays: if neither default store
        // advanced, nothing changed. If the scope moved, skip — persisted=false tells the caller to
        // regenerate.
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

  // ---- Algorithm migration (issue #532) ----

  // Serialize rotations on this handle. Two concurrent rotate() calls must not
  // both read the same current generation, both mint the next one, and clobber
  // each other's CA + retained root (the second commit would overwrite the first
  // and snapshot a short-lived intermediate as ca.prev.crt, dropping the original
  // root from loadTrustBundle()). Each call waits for the prior to settle, THEN
  // re-reads state inside _rotateImpl, so generations advance monotonically.
  var _rotateChain = Promise.resolve();
  function rotate(rotateOpts) {
    var next = _rotateChain.then(function () { return _rotateImpl(rotateOpts); },
                                 function () { return _rotateImpl(rotateOpts); });
    // Keep the chain alive past a rejection so one failed rotation doesn't wedge
    // every later one; the caller still awaits `next` for the real outcome.
    _rotateChain = next.then(function () {}, function () {});
    return next;
  }

  async function _rotateImpl(rotateOpts) {
    rotateOpts = rotateOpts || {};
    // A defined algorithm must be a non-empty label (matching create({ algorithm })).
    // An empty string would be treated as a pin here yet as "no pin" by the engine
    // (selecting the process default) and as "omitted" by canVerifyInTls(), letting
    // a pre-flight pass for the stored algorithm while rotation activates the default.
    if (rotateOpts.algorithm !== undefined &&
        (typeof rotateOpts.algorithm !== "string" || rotateOpts.algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "rotate: algorithm must be a non-empty string label when set (e.g. \"ECDSA-P384-SHA384\")");
    }
    // retainPrevious is coerced by `!== false` below, so a non-boolean (e.g. the string
    // "false" from config) would enable retention for every value except the literal
    // false — keeping a superseded CA trusted when the operator intended a hard cut.
    // Reject a supplied non-boolean (matching the public commit() validation).
    if (rotateOpts.retainPrevious !== undefined && typeof rotateOpts.retainPrevious !== "boolean") {
      throw new MtlsCaError("mtls-ca/bad-retain-previous",
        "rotate: retainPrevious must be a boolean when set (got " + JSON.stringify(rotateOpts.retainPrevious) +
        ") — a non-boolean like the string \"false\" is not the literal false and would retain the outgoing root");
    }
    var st = status();
    var previousCaCertPem = st.exists ? loadCert().toString("utf8") : null;
    var curGen = st.exists ? st.generation : 0;
    // Snapshot the persisted CUSTOM label too: a concurrent commit({ algorithm }) can re-label the
    // byte-identical current cert/key without changing the generation or cert identity, which the
    // cert+generation compare-and-swap below would miss — letting this rotation overwrite the newer
    // effective-label migration instead of conflicting. A default engine derives its label from the
    // cert, so a cert-unchanged commit cannot move it; only custom labels need the extra guard.
    var previousPersistedLabel = !usesDefaultEngine ? _readPersistedAlgorithm() : undefined;
    // A stored CA whose generation is UNDETERMINABLE (status().generation === 0, since
    // real generations are >= 1) cannot be rotated: a default rotation would mint
    // generation 1 even when the active CA was already 1 or higher, and an explicit
    // lower/equal generation would be accepted below (curGen 0) — either mis-assigns the
    // revocation cohort and violates the documented strictly-increasing invariant. The
    // certificate failed to parse to a generation on this runtime; that has several
    // causes (see the message), so the diagnostic names them all rather than assuming a
    // custom engine.
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
    // Validate the ORIGINAL value before any normalization: Math.floor would
    // silently accept 1.9 / 2.9 as generation 1 / 2, committing the CA under a
    // different generation than requested and mis-assigning its revocation cohort.
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
    // The pin threads into generateCa exactly as create({ algorithm }) / initCA
    // do; a per-call rotate({ algorithm }) overrides the create-time pin so an
    // operator can flip a stored classical CA to the ML-DSA default (or back)
    // WITHOUT the mtls-ca/algorithm-mismatch initCA raises — rotation is the
    // sanctioned path to change a CA's algorithm.
    var genArgs = { generation: newGen };
    var pin = rotateOpts.algorithm !== undefined ? rotateOpts.algorithm : caAlgorithm;
    // An UNPINNED rotation on a CUSTOM engine must PRESERVE the stored CA's PERSISTED label (the
    // authoritative current label) over this handle's possibly-stale create-time pin — else a bare
    // rotate({ generation }) on a stale-pinned sibling silently reverts a completed migration and
    // diverges ca.algorithm from the stored CA. Mirrors the default engine's cert-derived
    // preservation below (a custom label is not cert-derivable, so read the shared metadata).
    if (rotateOpts.algorithm === undefined && !usesDefaultEngine) {
      var _persistedPin = _readPersistedAlgorithm();
      if (_persistedPin !== undefined) pin = _persistedPin;
    }
    if (pin === undefined && usesDefaultEngine && previousCaCertPem !== null) {
      // An UNPINNED rotation (no rotate({algorithm}) and no create-time pin) over an
      // existing CA must PRESERVE the stored algorithm, not silently adopt the engine
      // default (ML-DSA-87). Otherwise a bare rotate({generation}) to advance a cohort
      // would flip a classical ECDSA CA to ML-DSA and reject legacy peers — mirroring
      // the stored-CA inference _leafEngineArgs does for unpinned leaf issuance.
      // Changing algorithm stays explicit via rotate({algorithm}).
      /* c8 ignore next -- the ||undefined fallback is unreachable: a default-engine CA cert always classifies to a non-null algorithm (ML-DSA / ECDSA-P384) */
      pin = _certAlgorithm(previousCaCertPem).algorithm || undefined;
    }
    if (pin !== undefined) genArgs.algorithm = pin;
    var fresh = await engine.generateCa(genArgs);
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    // retainPrevious defaults ON for a rotation (the grace window is the point);
    // pass retainPrevious:false to overwrite without retaining the old CA.
    var retain = rotateOpts.retainPrevious !== false && previousCaCertPem !== null;
    // Cross-process compare-and-swap. _rotateChain serializes rotations on THIS
    // handle, but a separate handle over the same dataDir (or another process)
    // owns a different chain and could have committed a new generation while we
    // awaited generateCa. Hold the dataDir rotation lock, re-read the on-disk
    // generation UNDER it, and refuse if it moved — so the revalidation and the
    // commit are atomic and the loser cannot overwrite the winner's CA or
    // snapshot its transient intermediate as ca.prev.crt (dropping the root
    // clients still trust). The caller retries against the current generation.
    await atomicFile.lock(paths.caCert, function () {
      // Heal a prior rotation that crashed mid-publish BEFORE re-reading the
      // generation — otherwise this rotation would snapshot a new-key/old-cert
      // state and journal the orphaned new key, permanently losing the
      // recoverable prior. Safe here: the lock excludes any live commit.
      _reconcileCommitJournalLocked();
      var nowSt = status();
      var nowGen = nowSt.exists ? nowSt.generation : 0;
      // Compare cert IDENTITY, not only the generation number: a public commit()
      // could have replaced the CA with a DIFFERENT cert at the SAME generation
      // while we awaited generateCa(), which a gen-only check would miss — letting
      // this older rotation overwrite that later commit. Refuse if the current cert
      // is not the one we snapshotted before generating. Compare by DER identity (via
      // _sameCert) so a concurrent idempotent commit() that merely REFORMATTED the same
      // cert (CRLF, wrapping, a stripped trailing newline) does not spuriously abort an
      // expensive rotation; the null checks stay (either side is null before a first CA).
      var nowCert = nowSt.exists ? loadCert().toString("utf8") : null;
      var nowCertChanged = (nowCert === null || previousCaCertPem === null)
        ? nowCert !== previousCaCertPem
        : !_sameCert(nowCert, previousCaCertPem);
      // A concurrent commit may have re-labelled a byte-identical CA (custom engine): the cert and
      // generation are unchanged, but the effective label moved, so proceeding would overwrite that
      // migration. Compare the persisted label snapshot too.
      var nowLabelChanged = !usesDefaultEngine && _readPersistedAlgorithm() !== previousPersistedLabel;
      if (nowGen !== curGen || nowCertChanged || nowLabelChanged) {
        throw new MtlsCaError("mtls-ca/rotation-conflict",
          "the CA changed (generation " + curGen + " -> " + nowGen + ", a same-generation replacement, or a " +
          "concurrent algorithm-label migration) during rotation — a concurrent rotate/commit on another handle " +
          "or process. Retry against the current CA");
      }
      // The single-retained-window invariant (refuse a second retained rotation
      // while a root is still retained) is enforced inside _commitLocked, so every
      // retention entry point — rotate() and the public commit() — is covered.
      _commitLocked({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: retain,
        // The effective CUSTOM label the new CA is minted under (explicit, else the preserved persisted
        // label) — _commitLocked persists it crash-atomically under the rollback journal.
        algorithm: (rotateOpts.algorithm !== undefined ? rotateOpts.algorithm : pin) });
      // Persist the effective algorithm on the handle WITHIN the same locked section as
      // its commit. Without this pin update, a handle created with an algorithm pin that
      // then rotate({ algorithm })s to a different one keeps the stale closed-over pin,
      // so the next initCA() (via generateClientCert / generateClientP12) compares it
      // against the new stored CA and throws mtls-ca/algorithm-mismatch. It MUST run
      // under the lock: a public commit() that acquires the lock the instant this
      // rotation releases it could publish a different CA and set the pin to match,
      // only for an unlocked assignment here to overwrite the pin afterwards — leaving
      // the stored CA and the pin disagreeing (the same mismatch on the next issuance).
      // Update the handle's in-memory pin. The ca.algorithm FILE was already written crash-atomically
      // inside _commitLocked (under the rollback journal) from the effective label passed below, so no
      // separate persist here — a crash cannot leave the file and the CA disagreeing.
      if (rotateOpts.algorithm !== undefined) {
        caAlgorithm = rotateOpts.algorithm;
      } else if (!usesDefaultEngine && pin !== undefined) {
        // An UNPINNED custom rotate minted the new CA under `pin` (the preserved persisted label).
        caAlgorithm = pin;
      }
    });
    // A hard cut (retainPrevious:false) removes the old root, so a leaf whose signing
    // straddled this rotation would chain to a root now gone from the trust bundle.
    // That is handled where the removal races the issuance — _recordIssuance re-checks
    // trust-bundle membership of its issuing root after recording (covering both this
    // hard cut and dropRetained), rather than a post-commit watermark bump that would
    // both race the removal and wrongly supersede a generation on a FAILED rotation.
    // A persisted CRL signed by the superseded CA is invalidated inside _commitLocked
    // (under the lock, covering rotate() and the public commit() alike) — regenerate
    // it under the new CA with generateCrl().
    caLog.info("rotated CA", { generation: newGen, retainedPrevious: retain });
    return {
      caCertPem:         fresh.caCertPem,
      previousCaCertPem: previousCaCertPem,
      generation:        newGen,
      // The documented migration algorithm callers persist. For the BUNDLED engine the fresh
      // cert is authoritative (the engine chose the key type), so infer from it. A CUSTOM
      // engine's own label is NOT inferable — _certAlgorithm() only understands bundled labels
      // and would misreport a custom P-384 CA as ECDSA-P384-SHA384 (or null for other custom
      // certs), recording the wrong migration algorithm — so report the effective label: the
      // pin carried into this rotation (rotate({algorithm}) else the create-time pin), null when
      // a custom label is genuinely unknown.
      algorithm:         usesDefaultEngine
        ? _certAlgorithm(fresh.caCertPem).algorithm
        : (pin !== undefined ? pin : null),
    };
  }

  function _readCurrentCert() {
    return nodeFs.existsSync(paths.caCert) ? loadCert().toString("utf8") : null;
  }
  function _readRetainedRoot() {
    // Read the retained root without a lock, tolerating a concurrent removal: a
    // dropRetained() / rotate({ retainPrevious:false }) in another process can
    // unlink ca.prev.crt between this existsSync and the read, so an ENOENT here
    // just means the grace window ended.
    if (!nodeFs.existsSync(paths.caCertPrev)) return null;
    try {
      return atomicFile.fdSafeReadSync(paths.caCertPrev, { maxBytes: C.BYTES.mib(1) }).toString("utf8");
    } catch (e) {
      /* c8 ignore next 2 -- concurrent-removal race path: the retained-root read rarely throws in tests (ENOENT -> null; any other error re-throws) */
      if (!e || e.code !== "ENOENT") throw e;
      return null;
    }
  }
  // The retained root a crashed rotation saved ONLY in its rollback journal (no
  // initCA()/rotate() has reconciled it back to ca.prev.crt yet). Returned so a
  // restart that calls only loadTrustBundle() still trusts clients enrolled under
  // the formerly-retained generation. Best-effort: an unreadable journal is left
  // for the locked reconcile to handle.
  function _journalRetainedRoot() {
    var keyJournal = ((caKeySealedMode === "required") ? paths.caKeySealed : paths.caKey) + ".rollback";
    if (!nodeFs.existsSync(keyJournal)) return null;
    try {
      var m = safeJson.parse(atomicFile.fdSafeReadSync(keyJournal, { maxBytes: C.BYTES.mib(2), encoding: "utf8" }),
        { maxBytes: C.BYTES.mib(2) });
      // Validate the base64 byte fields canonically (matching the locked reconcile): a
      // malformed prevData would otherwise leniently decode to a garbage NON-empty string
      // that this read path returns into loadTrustBundle() BEFORE any reconcile runs, so
      // an operator feeding that bundle to node:tls `ca:` gets a SecureContext failure (a
      // DoS of the mTLS gate). A malformed field means the journal is corrupt — leave it
      // for the locked reconcile (which fails closed) rather than trusting garbage.
      if (m && m.prevAction === "restore" && m.retainAfter !== false &&
          _validManifestB64Field(m.prevData) && typeof m.prevData === "string" &&
          _validManifestB64Field(m.cert) && typeof m.cert === "string") {
        // Only trust the journal's retained root when it represents an INTERRUPTED
        // RETENTION rotation: the live cert still equals the prior cert the journal recorded,
        // so the rotation never republished and the old root is still the operative
        // one. A SPENT journal (rotation COMPLETED — but its delete failed) has a different
        // live cert. A HARD CUT (retainAfter:false) is excluded even when byte-identical: a
        // COMPLETED byte-identical hard cut has the SAME live cert as the interrupted one, so the
        // cert compare can't distinguish them — re-trusting here would resurrect the very root the
        // operator hard-cut (the reconcile path's hardCutRemovalDone tie-break handles this; this
        // lock-free read must fail closed the same way). An INTERRUPTED hard cut loses nothing:
        // ca.prev.crt is still present and _trustRoots() reads it directly.
        // Byte comparison (a custom engine may emit non-UTF-8 cert bytes).
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
  // Lock-free trust-root snapshot. The double-read makes the snapshot internally
  // consistent; the PUBLIC loadTrustBundle() wraps this in the rotation lock so a
  // completed dropRetained()/rotation cannot precede delivery of a stale bundle.
  // _recordIssuance's root-drop check uses the LOCKED loadTrustBundle(), not this,
  // so a hard-cut/dropRetained that completes is seen and the leaf self-revokes.
  function _trustRoots() {
    // A retained rotation publishes ca.prev.crt = old THEN ca.crt = new as two
    // steps, so a naive read can interleave: read the OLD current, then read the
    // just-written ca.prev.crt (also old), returning [old, old] and OMITTING the
    // new active root — a TLS context reloaded from that rejects newly-enrolled
    // clients until another reload. Read a STABLE snapshot: re-read the current
    // cert after the retained one and retry if it changed mid-read (a rotation
    // published between the reads). Bounded — a rotation completes in microseconds;
    // sustained churn still returns the last current snapshot rather than looping.
    var cur = null;
    var bundle = null;
    for (var attempt = 0; attempt < 8 && bundle === null; attempt += 1) {
      cur = _readCurrentCert();
      var prev = _readRetainedRoot();
      // Accept only a snapshot where BOTH the current cert AND the retained root
      // are unchanged across the read. Re-checking only `cur` would let a
      // dropRetained() that unlinks ca.prev.crt between the prev read and here slip
      // through — returning a root the operator just cut. Re-reading prev too means
      // that removal is seen as prev-changed and retried (next pass reads prev=null).
      if (cur === _readCurrentCert() && prev === _readRetainedRoot()) {
        bundle = [];
        if (cur) bundle.push(cur);
        if (prev && prev !== cur) bundle.push(prev);    // dedup — never return [old, old]
      }
    }
    /* c8 ignore next -- retry-exhausted fallback: the 8-attempt stable-snapshot loop sets bundle on the first pass (a rotation completes in microseconds), so bundle===null is unreachable */
    if (bundle === null) bundle = cur ? [cur] : [];
    // Include a retained root held ONLY in an unreconciled rollback journal (a
    // crash left it there before any initCA()/rotate() reconciled) so a restart
    // that loads trust without first reconciling does not drop that cohort.
    var journalRoot = _journalRetainedRoot();
    if (journalRoot && bundle.indexOf(journalRoot) === -1) bundle.push(journalRoot);
    return bundle;
  }
  // Public trust bundle. Returns a PROMISE: it takes the rotation lock so the read
  // is serialized with dropRetained()/rotation — a cutoff that has COMPLETED (held
  // then released the lock) cannot be preceded by delivery of a bundle that still
  // trusts the cut root, closing the residual window a lock-free read leaves after
  // its last comparison. Under the lock no rotation/removal is in flight, so the
  // snapshot is both consistent and current. Await it.
  function loadTrustBundle() {
    return atomicFile.lock(paths.caCert, function () { return _trustRoots(); });
  }

  // Ends the retained-root grace window. Returns a PROMISE: it takes the rotation
  // lock (paths.caCert) so it cannot unlink ca.prev.crt in the middle of a
  // concurrent retained rotation (which writes prev, then renames the new cert) —
  // that interleaving would leave the rotation with no retained root, stranding
  // clients on the outgoing CA. Await it.
  function dropRetained() {
    return atomicFile.lock(paths.caCert, function () {
      // Reconcile an interrupted rotation FIRST. A crashed hard-cut rotation can
      // remove ca.prev.crt yet leave a journal whose recorded root loadTrustBundle()
      // still trusts (its prior cert matches the live cert). Without reconciling,
      // dropRetained() would see no live retained file, remove nothing, and the
      // journal would keep serving the "dropped" root — so the window never ends.
      // Under this lock, reconcile restores that root (or drops a spent journal);
      // the removal below then actually ends the grace window.
      _reconcileCommitJournalLocked();
      var had = nodeFs.existsSync(paths.caCertPrev);
      if (had) {
        nodeFs.unlinkSync(paths.caCertPrev);
        // Durable removal — see the commit-path note; ca.prev.crt's parent may
        // differ from ca.crt's, so a power loss must not resurrect the dropped root.
        atomicFile.fsyncDir(nodePath.dirname(paths.caCertPrev));
      }
      return { dropped: had };
    });
  }

  // Backfill leaf identities the issuance ledger does not have — certificates
  // issued by a PRE-#532 release (whose runs never recorded issuance) or issued
  // out of band. revokeGeneration(n) can only sweep what the ledger records, so an
  // upgraded dataDir's older cohort must be imported first: each entry is
  // { fingerprint, generation, serialNumber?, caCert? }. `generation` is the ISSUING
  // CA's generation (the OU=CAvN tag lives on the CA cert's subject, NOT the leaf), so
  // derive it from the ISSUER cert — parseGeneration(<issuing CA cert>), or the
  // known cohort number — never parseGeneration(<leaf>), which would fall back to 1
  // and mislabel a gen-2+ leaf (revokeGeneration could then revoke a current cert).
  // `caCert` (the issuing CA certificate PEM, optional) records the same issuer identity
  // normal issuance stores so generateCrl() can issuer-scope the entry. Returns
  // { imported }. SYNC-throws on bad input.
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
      // A fingerprint is MANDATORY: importIssuance exists so revokeGeneration() can sweep the entry,
      // and a serial is unique only per issuer. A serial-only entry would be swept into a
      // fingerprint-null revocation that isSerialRevoked() matches GLOBALLY, false-revoking a current
      // certificate that reuses the serial under a rotated / serial-reusing custom CA (recording
      // caCert does not help — the live serial lookup does not consult it). The gate pins the
      // globally-unique SHA3-512 fingerprint, so require it; serialNumber stays optional (recorded
      // for the CRL alongside the fingerprint).
      if (!fp) {
        throw new MtlsCaError("mtls-ca/bad-import",
          "importIssuance entry requires a fingerprint (the globally-unique SHA3-512 identity the require-mtls gate " +
          "pins) — a serial number is unique only per issuer, so a serial-only entry would be generation-revoked into a " +
          "fingerprint-null revocation that false-revokes an unrelated current certificate reusing the serial; supply the " +
          "certificate's fingerprint (serialNumber may accompany it for the CRL)");
      }
      // Record the ISSUING CA's identity (as normal issuance does via caFingerprint) so
      // generateCrl() can issuer-scope this backfilled entry: without it, an imported old-CA
      // revocation whose serial a current CA reuses is left in the current CRL, false-revoking the
      // unrelated current cert. Accept the issuing CA cert PEM (caCert) and derive the same
      // DER-based identity; absent it the entry stays issuer-unknown (best-effort included).
      if (e.caCert !== undefined && e.caCert !== null && typeof e.caCert !== "string") {
        throw new MtlsCaError("mtls-ca/bad-import", "importIssuance entry.caCert must be a PEM string (the issuing CA certificate) when set");
      }
      var caFp = (e.caCert !== undefined && e.caCert !== null) ? _certIdentity(e.caCert).fingerprint : null;
      return { serialNumber: serial, fingerprint: fp, generation: e.generation, caFingerprint: caFp, issuedAt: e.issuedAt || Date.now() };
    });
    var add = function () { normalized.forEach(function (n) { issuanceStore.add(n); }); };
    var run = usesDefaultIssuanceStore ? atomicFile.lock(paths.issuance, add) : Promise.resolve(add());
    return run.then(function () {
      // Read the watermark AFTER the append (matching _recordIssuance's ordering,
      // fail-closed on a malformed value): a concurrent revokeGeneration that
      // bumps the watermark and finishes its sweep before our append lands would,
      // with a pre-read stale value, be missed by BOTH the sweep and this check —
      // reading here guarantees one side catches the entry. An imported leaf whose
      // generation is already revoked is revoked here.
      var wm = _readRevokedWatermark();
      var superseded = normalized.filter(function (n) { return n.generation < wm; });
      return Promise.all(superseded.map(function (n) {
        // n.fingerprint is always present — importIssuance requires it — so no ||null fallback here.
        return revoke({ serial: n.serialNumber || null, fingerprint: n.fingerprint, reason: "superseded" });
      })).then(function () { return { imported: normalized.length, revoked: superseded.length }; });
    });
  }

  // Revoke every cert the issuance ledger recorded under a CA generation < n.
  // (Pre-#532 / out-of-band certs are unindexed until importIssuance() backfills
  // them — see above.) Enforcement is fingerprint-keyed through the revocation
  // registry —
  // isRevoked() and a require-mtls gate wired with `revocationSource: caHandle`
  // deny these certs regardless of which CA generation issued them. A standard
  // X.509 CRL cannot: generateCrl() signs with the CURRENT CA, which a peer will
  // not accept as revoking a cert issued by a superseded generation. For a CRL-
  // consuming deployment, publish generateCrl() for a generation while it is
  // still current (before rotate() supersedes its signing key); the registry
  // path above needs no such ordering.
  // Like revoke(): SYNC-throws on bad input, returns a PROMISE for { revoked }.
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
      // Uses _revokeCore directly — for the default store we already hold the
      // revocation lock here, so calling revoke() would re-enter it.
      var before = revocationStore.list().length;
      issuanceStore.list().forEach(function (e) {
        if (e && typeof e.generation === "number" && e.generation < n && (e.serialNumber || e.fingerprint)) {
          _revokeCore(e.serialNumber || null, e.fingerprint || null, reason, reasonCode);
        }
      });
      return { revoked: revocationStore.list().length - before };
    };
    // Bump the watermark (atomic for ALL stores — a shared custom store's
    // bumpGenerationWatermark, else a locked local-file RMW) BEFORE sweeping, so
    // an in-flight issuance that records after the sweep-read still self-revokes
    // (see _recordIssuance).
    return _bumpRevokedWatermark(n).then(function () {
      return usesDefaultRevocationStore ? atomicFile.lock(paths.revocations, sweep) : Promise.resolve(sweep());
    });
  }

  // CA-handle convenience over the engine probe: can node:tls VERIFY a chain
  // under a given algorithm on this runtime? Pass the PROSPECTIVE algorithm to
  // pre-flight a migration — canVerifyInTls("ML-DSA-87") before
  // rotate({ algorithm: "ML-DSA-87" }) probes the TARGET, not the current CA, so
  // an ECDSA-stored handle does not falsely pass when the runtime cannot verify
  // the ML-DSA chain it is about to activate. With no argument it probes the
  // stored CA's algorithm (or the create-time pin / engine default when none is
  // stored yet). Delegates to engine.canVerifyInTls(label).
  async function canVerifyInTls(algorithm) {
    if (typeof engine.canVerifyInTls !== "function") {
      throw new MtlsCaError("mtls-ca/no-tls-probe",
        "the configured engine does not implement canVerifyInTls(label)");
    }
    // Validate a SUPPLIED argument before any fallback (same as create()/rotate()): an
    // empty string or non-string explicit target must be REFUSED, not silently treated
    // as "omitted" and answered against the stored/default algorithm — that would let a
    // migration pre-flight return true without ever testing the requested target. Only
    // an OMITTED argument (undefined) falls back to the stored CA / create-time pin.
    if (algorithm !== undefined && (typeof algorithm !== "string" || algorithm.length === 0)) {
      throw new MtlsCaError("mtls-ca/bad-algorithm",
        "canVerifyInTls(algorithm) requires a non-empty string algorithm label when provided " +
        "(e.g. \"ML-DSA-87\"); omit the argument to probe the stored CA");
    }
    var st = status();
    // For a CUSTOM engine, prefer the durable stored label over status()'s inferred label:
    // status() infers a BUNDLED label (e.g. ML-DSA-87) from the cert's key type, but a custom
    // engine may use its own label for that key type, which only its stored metadata carries —
    // passing the bundled label could make the engine reject or misinterpret the probe. The
    // stored label lives in ca.algorithm (the durable shared file), which a SIBLING handle's
    // migration updates, so read it here rather than trusting this handle's possibly-stale
    // caAlgorithm closure — as the issuance, cold-start adopt, and rotate paths do. The default
    // engine's inferred label matches its own label set, so status() wins there.
    var _effectiveCustomLabel = caAlgorithm;
    if (!usesDefaultEngine) {
      var _persistedLabel = _currentCustomLabel();
      if (_persistedLabel !== undefined) _effectiveCustomLabel = _persistedLabel;
    }
    var label = (typeof algorithm === "string" && algorithm.length > 0)
      ? algorithm
      : (usesDefaultEngine ? (st.algorithm || caAlgorithm) : (_effectiveCustomLabel || st.algorithm));
    // Refuse an undeterminable label ONLY when a CA is STORED whose algorithm this
    // runtime cannot classify (status().algorithm === null — e.g. a P-256 custom
    // engine — with no create-time pin): passing undefined to the engine would then
    // let one that reads an omitted label as "current default" probe a DIFFERENT
    // algorithm than the stored CA, reporting on the wrong chain. With NO CA stored
    // yet, an omitted label is unambiguous — the engine resolves its default, which
    // is exactly the intended pre-flight probe on a fresh deployment — so pass it
    // through rather than forcing the operator to name a label they may not know.
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
    // isRevoked already matches a serial OR fingerprint; this alias signals to a
    // require-mtls gate that this source supports serial-number lookups (so it may
    // check the peer cert's serial), without changing isRevoked's contract.
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
