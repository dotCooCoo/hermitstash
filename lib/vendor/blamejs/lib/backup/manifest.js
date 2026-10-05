// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var { FrameworkError } = require("../framework-error");

// audit-sign is loaded lazily — manifest.js is consumed by both the
// backup writer (which has audit-sign initialized) and read-only
// inspectors (CLI / verifier) where audit-sign may not be wired.
var auditSign = lazyRequire(function () { return require("../audit-sign"); });

class BackupManifestError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "BackupManifestError";
    this.permanent = true;
    this.isBackupManifestError = true;
  }
}

var FORMAT_VERSION = 1;
var FRAMEWORK_NAME = "blamejs";
var KEY_SCHEME_BUNDLE = "argon2id-hkdf-sha3-512-path-digest";
var BUNDLE_SALT_HEX_LENGTH = 64;
var MAX_MANIFEST_BYTES = C.BYTES.mib(64);
var VALID_KINDS = { "raw": 1, "vault-sealed": 1, "plaintext": 1 };
var SHA3_512_HEX_LENGTH = 128;
function _isHex(s, evenLength) {
  if (!safeBuffer.isHex(s)) return false;
  if (evenLength && s.length % 2 !== 0) return false;
  return true;
}
function _isBase64(s) {
  return typeof s === "string" && s.length > 0 && safeBuffer.isBase64(s);
}
function _isIso8601(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  var d = new Date(s);
  return !isNaN(d.getTime()) && d.toISOString() === s;
}

function _validateFileEntry(f, idx, errors) {
  if (!f || typeof f !== "object") {
    errors.push("files[" + idx + "]: must be an object");
    return;
  }
  if (typeof f.relativePath !== "string" || f.relativePath.length === 0) {
    errors.push("files[" + idx + "].relativePath: required non-empty string");
  } else if (f.relativePath.indexOf("..") !== -1 || /^[/\\]/.test(f.relativePath) || f.relativePath.indexOf(":") !== -1) {
    errors.push("files[" + idx + "].relativePath: must be a relative path without '..', a leading separator, or a colon (drive letter / NTFS data-stream marker)");
  }
  if (typeof f.encryptedPath !== "string" || f.encryptedPath.length === 0) {
    errors.push("files[" + idx + "].encryptedPath: required non-empty string");
  } else if (f.encryptedPath.indexOf("..") !== -1 || /^[/\\]/.test(f.encryptedPath) || f.encryptedPath.indexOf(":") !== -1) {
    errors.push("files[" + idx + "].encryptedPath: must be a relative path without '..', a leading separator, or a colon (drive letter / NTFS data-stream marker)");
  }
  if (typeof f.size !== "number" || !Number.isInteger(f.size) || f.size < 0) {
    errors.push("files[" + idx + "].size: required non-negative integer");
  }
  if (typeof f.encryptedSize !== "number" || !Number.isInteger(f.encryptedSize) || f.encryptedSize < 0) {
    errors.push("files[" + idx + "].encryptedSize: required non-negative integer");
  }
  if (!_isHex(f.checksum, true) || f.checksum.length !== SHA3_512_HEX_LENGTH) {
    errors.push("files[" + idx + "].checksum: required 128-char hex string (sha3-512)");
  }
  if (!_isHex(f.salt, true)) {
    errors.push("files[" + idx + "].salt: required hex string");
  }
  if (typeof f.kind !== "string" || !Object.prototype.hasOwnProperty.call(VALID_KINDS, f.kind)) {
    errors.push("files[" + idx + "].kind: must be one of raw, vault-sealed, plaintext");
  }
}

function validate(manifest) {
  var errors = [];
  if (!manifest || typeof manifest !== "object") {
    return { ok: false, errors: ["manifest must be an object"] };
  }
  if (manifest.version !== FORMAT_VERSION) {
    errors.push("version: required " + FORMAT_VERSION + ", got " + manifest.version);
  }
  if (manifest.framework !== FRAMEWORK_NAME) {
    errors.push("framework: required '" + FRAMEWORK_NAME + "', got " + JSON.stringify(manifest.framework));
  }
  if (typeof manifest.frameworkVersion !== "string" || manifest.frameworkVersion.length === 0) {
    errors.push("frameworkVersion: required non-empty string");
  }
  if (!_isIso8601(manifest.createdAt)) {
    errors.push("createdAt: required ISO-8601 timestamp string");
  }
  if (!_isHex(manifest.vaultKeySalt, true)) {
    errors.push("vaultKeySalt: required hex string");
  }
  if (!_isBase64(manifest.vaultKeyEnc)) {
    errors.push("vaultKeyEnc: required base64 string");
  }
  if (!Array.isArray(manifest.files)) {
    errors.push("files: required array");
  } else if (manifest.files.length === 0) {
    errors.push("files: required non-empty array");
  } else {
    var seenRel = Object.create(null);
    var seenEnc = Object.create(null);
    for (var i = 0; i < manifest.files.length; i++) {
      _validateFileEntry(manifest.files[i], i, errors);
      var f = manifest.files[i];
      if (f && typeof f.relativePath === "string") {
        if (seenRel[f.relativePath]) {
          errors.push("files[" + i + "].relativePath: duplicate '" + f.relativePath + "'");
        }
        seenRel[f.relativePath] = true;
      }
      if (f && typeof f.encryptedPath === "string") {
        if (seenEnc[f.encryptedPath]) {
          errors.push("files[" + i + "].encryptedPath: duplicate '" + f.encryptedPath + "'");
        }
        seenEnc[f.encryptedPath] = true;
      }
    }
  }
  if (manifest.keyScheme !== undefined && manifest.keyScheme !== KEY_SCHEME_BUNDLE) {
    errors.push("keyScheme: must be '" + KEY_SCHEME_BUNDLE + "' when present, got " + JSON.stringify(manifest.keyScheme));
  }
  if (manifest.keyScheme === KEY_SCHEME_BUNDLE) {
    if (!_isHex(manifest.bundleSalt, true) || manifest.bundleSalt.length !== BUNDLE_SALT_HEX_LENGTH) {
      errors.push("bundleSalt: required " + BUNDLE_SALT_HEX_LENGTH + "-character hex string with keyScheme");
    }
  } else if (manifest.bundleSalt !== undefined) {
    errors.push("bundleSalt: only valid with keyScheme '" + KEY_SCHEME_BUNDLE + "'");
  }
  if (manifest.metadata !== undefined &&
      (manifest.metadata === null || typeof manifest.metadata !== "object" || Array.isArray(manifest.metadata))) {
    errors.push("metadata: must be a plain object when present");
  }
  if (manifest.signature !== undefined) {
    if (manifest.signature === null || typeof manifest.signature !== "object" ||
        Array.isArray(manifest.signature)) {
      errors.push("signature: must be a plain object when present");
    } else {
      if (typeof manifest.signature.algorithm !== "string" || manifest.signature.algorithm.length === 0) {
        errors.push("signature.algorithm: required non-empty string");
      }
      if (typeof manifest.signature.publicKey !== "string" || manifest.signature.publicKey.length === 0) {
        errors.push("signature.publicKey: required non-empty string");
      }
      if (typeof manifest.signature.fingerprint !== "string" || manifest.signature.fingerprint.length === 0) {
        errors.push("signature.fingerprint: required non-empty string");
      }
      if (!_isBase64(manifest.signature.value)) {
        errors.push("signature.value: required base64 string");
      }
      if (!_isIso8601(manifest.signature.signedAt)) {
        errors.push("signature.signedAt: required ISO-8601 timestamp string");
      }
    }
  }
  return { ok: errors.length === 0, errors: errors };
}

function create(opts) {
  opts = opts || {};
  var manifest = {
    version:          FORMAT_VERSION,
    framework:        FRAMEWORK_NAME,
    frameworkVersion: typeof opts.frameworkVersion === "string" && opts.frameworkVersion.length > 0
      ? opts.frameworkVersion
      : (C.version || "0.0.0"),
    createdAt:        opts.createdAt || new Date().toISOString(),
    vaultKeySalt:     opts.vaultKeySalt,
    vaultKeyEnc:      opts.vaultKeyEnc,
    files:            Array.isArray(opts.files) ? opts.files.slice() : [],
  };
  if (opts.metadata && typeof opts.metadata === "object" && !Array.isArray(opts.metadata)) {
    manifest.metadata = Object.assign({}, opts.metadata);
  }
  if (opts.aadBound === true) manifest.aadBound = true;
  if (opts.keyScheme !== undefined) manifest.keyScheme = opts.keyScheme;
  if (opts.bundleSalt !== undefined) manifest.bundleSalt = opts.bundleSalt;
  var v = validate(manifest);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "create: " + v.errors.join("; "));
  }
  return manifest;
}

function _canonical(manifest, includeSignature) {
  var canonical = {
    version:          manifest.version,
    framework:        manifest.framework,
    frameworkVersion: manifest.frameworkVersion,
    createdAt:        manifest.createdAt,
    vaultKeySalt:     manifest.vaultKeySalt,
    vaultKeyEnc:      manifest.vaultKeyEnc,
    files:            manifest.files.map(function (f) {
      return {
        relativePath:  f.relativePath,
        encryptedPath: f.encryptedPath,
        size:          f.size,
        encryptedSize: f.encryptedSize,
        checksum:      f.checksum,
        salt:          f.salt,
        kind:          f.kind,
      };
    }),
  };
  if (manifest.metadata) canonical.metadata = manifest.metadata;
  if (manifest.aadBound === true) canonical.aadBound = true;
  if (manifest.keyScheme !== undefined) canonical.keyScheme = manifest.keyScheme;
  if (manifest.bundleSalt !== undefined) canonical.bundleSalt = manifest.bundleSalt;
  if (includeSignature && manifest.signature) {
    canonical.signature = {
      algorithm:   manifest.signature.algorithm,
      publicKey:   manifest.signature.publicKey,
      fingerprint: manifest.signature.fingerprint,
      value:       manifest.signature.value,
      signedAt:    manifest.signature.signedAt,
    };
  }
  return canonical;
}

function signingPayload(manifest) {
  return JSON.stringify(_canonical(manifest, false), null, 2) + "\n";
}

function serialize(manifest) {
  var v = validate(manifest);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "serialize: " + v.errors.join("; "));
  }
  var text = JSON.stringify(_canonical(manifest, true), null, 2) + "\n";
  var byteLength = Buffer.byteLength(text, "utf8");
  if (byteLength > MAX_MANIFEST_BYTES) {
    throw new BackupManifestError("backup-manifest/too-large",
      "serialize: the manifest for " + manifest.files.length + " files is " + byteLength +
      " bytes, above the " + MAX_MANIFEST_BYTES + "-byte limit every manifest reader applies; " +
      "split the include list across more than one backup");
  }
  return text;
}

function readFile(manifestPath, opts) {
  opts = opts || {};
  return parse(atomicFile.fdSafeReadSync(manifestPath, {
    maxBytes: MAX_MANIFEST_BYTES, encoding: "utf8", errorFor: opts.errorFor,
  }));
}

/**
 * @primitive b.backupManifest.readBuffer
 * @signature b.backupManifest.readBuffer(bytes, opts?)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupManifest.verifyBytes
 *
 * Read a manifest a caller already holds as bytes, under the same size limit
 * `b.backupManifest.readFile` applies to one on disk. A storage backend whose
 * manifest arrives from an object store has no path to hand to `readFile`,
 * and calling `parse` on bytes it measured itself would put a second copy of
 * the limit in the caller.
 *
 * Throws `backup-manifest/bad-input` when `bytes` is not a Buffer, and
 * `backup-manifest/too-large` when the bytes exceed the limit
 * `b.backupManifest.serialize` enforces on the writer. Parsing then throws
 * `backup-manifest/bad-json` when the bytes are not valid JSON, and
 * `backup-manifest/invalid` when they parse but do not match the v1 schema.
 *
 * @opts
 *   errorFor: function,  // build the caller's own error class
 *
 * @example
 *   var manifest = b.backupManifest.readBuffer(bytes);
 *   manifest.files.length;                            // → 3
 */
function readBuffer(bytes, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(bytes)) {
    throw new BackupManifestError("backup-manifest/bad-input",
      "readBuffer: bytes must be a Buffer");
  }
  if (bytes.length > MAX_MANIFEST_BYTES) {
    if (typeof opts.errorFor === "function") {
      throw opts.errorFor("too-large", { size: bytes.length, max: MAX_MANIFEST_BYTES });
    }
    throw new BackupManifestError("backup-manifest/too-large",
      "readBuffer: manifest is " + bytes.length + " bytes, above the " +
      MAX_MANIFEST_BYTES + "-byte limit");
  }
  return parse(bytes.toString("utf8"));
}

function _signPayload(payload, who) {
  var signer = auditSign();
  if (!signer || typeof signer.sign !== "function") {
    throw new BackupManifestError("backup-manifest/no-signer",
      who + ": audit-sign module is not available; call b.auditSign.init() first");
  }
  var signatureBytes;
  try { signatureBytes = signer.sign(payload); }
  catch (e) {
    throw new BackupManifestError("backup-manifest/sign-failed",
      who + ": audit-sign.sign threw: " + ((e && e.message) || String(e)));
  }
  return {
    algorithm:   signer.getAlgorithm(),
    publicKey:   signer.getPublicKey(),
    fingerprint: signer.getPublicKeyFingerprint(),
    value:       signatureBytes.toString("base64"),
    signedAt:    new Date().toISOString(),
  };
}

function _verifyPayloadAgainstBlock(payload, sig, opts) {
  opts = opts || {};
  if (!sig || typeof sig !== "object") {
    return { ok: false, reason: "signature block must be an object" };
  }
  if (typeof sig.algorithm !== "string" || sig.algorithm.length === 0) {
    return { ok: false, reason: "signature.algorithm is required" };
  }
  if (typeof sig.publicKey !== "string" || sig.publicKey.length === 0) {
    return { ok: false, reason: "signature.publicKey is required" };
  }
  if (typeof sig.value !== "string" || sig.value.length === 0) {
    return { ok: false, reason: "signature.value is required" };
  }
  var signer = auditSign();
  if (signer.SUPPORTED_SIGNING_ALGS.indexOf(sig.algorithm) === -1) {
    return { ok: false, reason: "signature.algorithm '" + sig.algorithm + "' is not an audit-sign algorithm (" +
      signer.SUPPORTED_SIGNING_ALGS.join(", ") + ")" };
  }
  var keyObject;
  try { keyObject = nodeCrypto.createPublicKey(sig.publicKey); }
  catch (_e) {
    return { ok: false, reason: "signature.publicKey is not a readable public key" };
  }
  if (keyObject.asymmetricKeyType !== sig.algorithm) {
    return { ok: false, reason: "signature.publicKey is a " + keyObject.asymmetricKeyType +
      " key, not the " + sig.algorithm + " key signature.algorithm names" };
  }
  if (typeof signer.fingerprintOf !== "function") {
    return { ok: false, reason: "a signature is trusted by the fingerprint of its key, which requires audit-sign.fingerprintOf (unavailable)" };
  }
  var derivedFingerprint;
  try { derivedFingerprint = signer.fingerprintOf(sig.publicKey); }
  catch (e) {
    return { ok: false, reason: "could not derive fingerprint from publicKey: " + ((e && e.message) || String(e)) };
  }
  if (typeof opts.expectedFingerprint === "string" && opts.expectedFingerprint.length > 0) {
    if (derivedFingerprint !== opts.expectedFingerprint) {
      return {
        ok: false,
        reason: "publicKey fingerprint=" + derivedFingerprint +
                " does not match expectedFingerprint=" + opts.expectedFingerprint,
        fingerprint: derivedFingerprint,
      };
    }
  } else {
    var trustedKey;
    try { trustedKey = signer.getPublicKeyByFingerprint(derivedFingerprint); }
    catch (_e) {
      return { ok: false, reason: "no trusted signing key: pass opts.expectedFingerprint, or initialize " +
        "b.auditSign so its active and rotated keys are trusted", fingerprint: derivedFingerprint };
    }
    if (trustedKey === null) {
      return { ok: false, reason: "publicKey fingerprint=" + derivedFingerprint +
        " is not the active or a rotated audit-sign key", fingerprint: derivedFingerprint };
    }
  }
  if (!safeBuffer.isCanonicalBase64(sig.value)) {
    return { ok: false, reason: "signature.value is not valid base64" };
  }
  var sigBuf = Buffer.from(sig.value, "base64");
  var ok;
  try {
    ok = nodeCrypto.verify(null, Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8"), keyObject, sigBuf);
  } catch (e) {
    return {
      ok:          false,
      reason:      "verify threw: " + ((e && e.message) || String(e)),
      fingerprint: derivedFingerprint,
    };
  }
  if (!ok) {
    return {
      ok:          false,
      reason:      "signature did not verify under provided publicKey",
      fingerprint: derivedFingerprint,
    };
  }
  return { ok: true, fingerprint: derivedFingerprint };
}

/**
 * @primitive b.backupManifest.sign
 * @signature b.backupManifest.sign(manifest)
 * @since     0.6.0
 * @status    stable
 * @related   b.backupManifest.verifySignature, b.backupManifest.signBytes, b.auditSign.sign
 *
 * Sign a v1 backup manifest in place with the audit-sign keypair, attaching a
 * detached `signature` block over the manifest's canonical bytes (the
 * serialization WITHOUT the signature field, so appending it doesn't change
 * the signed payload). Validates the manifest against the v1 schema first;
 * throws `backup-manifest/invalid` on a malformed manifest,
 * `backup-manifest/no-signer` when `b.auditSign.init()` hasn't run, and
 * `backup-manifest/sign-failed` when the signer rejects the payload. For a
 * schema-agnostic alternative see `signBytes`.
 *
 * @example
 *   b.backupManifest.sign(manifest);
 *   manifest.signature.fingerprint;   // the signing key's fingerprint
 */
function sign(manifest) {
  var v = validate(manifest);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "sign: " + v.errors.join("; "));
  }
  manifest.signature = _signPayload(signingPayload(manifest), "sign");
  return manifest;
}

/**
 * @primitive b.backupManifest.signBytes
 * @signature b.backupManifest.signBytes(canonicalBytes)
 * @since     0.15.21
 * @status    stable
 * @related   b.backupManifest.verifyBytes, b.backupManifest.sign, b.auditSign.sign
 *
 * Sign caller-supplied canonical bytes with the framework's audit-sign keypair,
 * returning a detached signature block — the schema-agnostic counterpart of
 * `sign()`. Where `sign()` is bound to the v1 manifest schema (it `validate()`s
 * the whole `{ version, framework, files[] }` shape before signing), this signs
 * any bytes a consumer canonicalizes itself, so a bespoke backup-header /
 * manifest format reuses the same post-quantum signing keypair + fingerprint
 * pinning without adopting the framework schema.
 *
 * `canonicalBytes` is a Buffer (signed verbatim) or a string (signed as UTF-8);
 * any other type throws `backup-manifest/bad-input`.
 * Returns `{ algorithm, publicKey, fingerprint, value, signedAt }`. Requires
 * `b.auditSign.init()` (throws `backup-manifest/no-signer` otherwise), and
 * throws `backup-manifest/sign-failed` when the signer rejects the payload.
 *
 * @example
 *   var sig = b.backupManifest.signBytes(myCanonicalHeaderBuffer);
 *   // store sig alongside the header; later:
 *   var v = b.backupManifest.verifyBytes(myCanonicalHeaderBuffer, sig,
 *     { expectedFingerprint: b.auditSign.getPublicKeyFingerprint() });
 *   // v.ok === true
 */
function signBytes(canonicalBytes) {
  if (typeof canonicalBytes !== "string" && !Buffer.isBuffer(canonicalBytes)) {
    throw new BackupManifestError("backup-manifest/bad-input",
      "signBytes: canonicalBytes must be a string or Buffer");
  }
  return _signPayload(canonicalBytes, "signBytes");
}

/**
 * @primitive b.backupManifest.verifySignature
 * @signature b.backupManifest.verifySignature(manifest, opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.backupManifest.sign, b.backupManifest.verifyBytes
 *
 * Verify a signed v1 backup manifest's detached `signature` block over its
 * canonical bytes. Returns `{ ok, reason?, fingerprint? }` and does not throw,
 * so a caller decides whether a missing or mismatched signature is fatal.
 *
 * The signature is trusted only under a known key. With
 * `opts.expectedFingerprint`, the fingerprint computed from
 * `signature.publicKey` must equal it. Without a pin, that key must be the
 * active or a rotated `b.auditSign` key, and a process that has not run
 * `b.auditSign.init()` gets `ok: false`. `signature.algorithm` must be one of
 * `b.auditSign.SUPPORTED_SIGNING_ALGS` and must name the type of
 * `signature.publicKey`. The `fingerprint` in the result is the one computed
 * from the key, never the block's own `fingerprint` field. For a
 * schema-agnostic alternative see `verifyBytes`.
 *
 * @opts
 *   expectedFingerprint: string,   // trust only the key with this fingerprint
 *
 * @example
 *   var v = b.backupManifest.verifySignature(manifest,
 *     { expectedFingerprint: b.auditSign.getPublicKeyFingerprint() });
 *   if (!v.ok) throw new Error("untrusted backup: " + v.reason);
 */
function verifySignature(manifest, opts) {
  if (!manifest || typeof manifest !== "object") {
    return { ok: false, reason: "manifest must be an object" };
  }
  if (!manifest.signature || typeof manifest.signature !== "object") {
    return { ok: false, reason: "manifest has no signature block" };
  }
  return _verifyPayloadAgainstBlock(signingPayload(manifest), manifest.signature, opts);
}

/**
 * @primitive b.backupManifest.verifyBytes
 * @signature b.backupManifest.verifyBytes(canonicalBytes, signatureBlock, opts?)
 * @since     0.15.21
 * @status    stable
 * @related   b.backupManifest.signBytes, b.backupManifest.verifySignature
 *
 * Verify caller-supplied canonical bytes against a detached signature block
 * produced by `signBytes()` — the schema-agnostic counterpart of
 * `verifySignature()`. Returns `{ ok, reason?, fingerprint? }`, and applies the
 * same key trust as `verifySignature()`: the key must match
 * `opts.expectedFingerprint`, or be the active or a rotated `b.auditSign` key.
 * A verifier process that does not hold the signing key passes
 * `expectedFingerprint`; without it and without `b.auditSign.init()`, the
 * result is `ok: false`.
 *
 * @opts
 *   expectedFingerprint: string,   // trust only the key with this fingerprint
 *
 * @example
 *   var v = b.backupManifest.verifyBytes(headerBytes, sigBlock,
 *     { expectedFingerprint: trustedFingerprint });
 *   if (!v.ok) throw new Error("untrusted header: " + v.reason);
 */
function verifyBytes(canonicalBytes, signatureBlock, opts) {
  if (typeof canonicalBytes !== "string" && !Buffer.isBuffer(canonicalBytes)) {
    return { ok: false, reason: "verifyBytes: canonicalBytes must be a string or Buffer" };
  }
  return _verifyPayloadAgainstBlock(canonicalBytes, signatureBlock, opts);
}

function parse(jsonStr) {
  if (typeof jsonStr !== "string" && !Buffer.isBuffer(jsonStr)) {
    throw new BackupManifestError("backup-manifest/bad-input",
      "parse: argument must be a string or Buffer");
  }
  var s = Buffer.isBuffer(jsonStr) ? jsonStr.toString("utf8") : jsonStr;
  var obj = safeJson.parseTyped(s, {
    maxBytes:   MAX_MANIFEST_BYTES,
    errorClass: BackupManifestError,
    code:       "backup-manifest/bad-json",
    label:      "parse: not valid JSON",
  });
  var v = validate(obj);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "parse: " + v.errors.join("; "));
  }
  return obj;
}

module.exports = {
  create:               create,
  validate:             validate,
  serialize:            serialize,
  parse:                parse,
  readFile:             readFile,
  readBuffer:           readBuffer,
  sign:                 sign,
  signBytes:            signBytes,
  signingPayload:       signingPayload,
  verifySignature:      verifySignature,
  verifyBytes:          verifyBytes,
  FORMAT_VERSION:       FORMAT_VERSION,
  FRAMEWORK_NAME:       FRAMEWORK_NAME,
  KEY_SCHEME_BUNDLE:    KEY_SCHEME_BUNDLE,
  MAX_MANIFEST_BYTES:   MAX_MANIFEST_BYTES,
  VALID_KINDS:          VALID_KINDS,
  BackupManifestError:  BackupManifestError,
};
