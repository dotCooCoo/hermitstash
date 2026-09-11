// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  return JSON.stringify(_canonical(manifest, true), null, 2) + "\n";
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
  var derivedFingerprint = null;
  try {
    var signerForFp = auditSign();
    if (signerForFp && typeof signerForFp.fingerprintOf === "function") {
      derivedFingerprint = signerForFp.fingerprintOf(sig.publicKey);
    }
  } catch (fpErr) {
    return { ok: false, reason: "could not derive fingerprint from publicKey: " +
      ((fpErr && fpErr.message) || String(fpErr)) };
  }
  if (typeof opts.expectedFingerprint === "string" && opts.expectedFingerprint.length > 0) {
    if (derivedFingerprint === null) {
      return { ok: false, reason: "fingerprint pinning requires audit-sign.fingerprintOf (unavailable)" };
    }
    if (derivedFingerprint !== opts.expectedFingerprint) {
      return {
        ok: false,
        reason: "publicKey fingerprint=" + derivedFingerprint +
                " does not match expectedFingerprint=" + opts.expectedFingerprint,
        fingerprint: derivedFingerprint,
      };
    }
  }
  var sigBuf;
  try { sigBuf = Buffer.from(sig.value, "base64"); }
  catch (_e) {
    return { ok: false, reason: "signature.value is not valid base64" };
  }
  var ok;
  try {
    var signer = auditSign();
    if (signer && typeof signer.verify === "function") {
      ok = signer.verify(payload, sigBuf, sig.publicKey);
    } else {
      ok = require("node:crypto").verify(null,
        Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8"), sig.publicKey, sigBuf);
    }
  } catch (e) {
    return {
      ok:          false,
      reason:      "verify threw: " + ((e && e.message) || String(e)),
      fingerprint: sig.fingerprint,
    };
  }
  if (!ok) {
    return {
      ok:          false,
      reason:      "signature did not verify under provided publicKey",
      fingerprint: derivedFingerprint || sig.fingerprint,
    };
  }
  return { ok: true, fingerprint: derivedFingerprint || sig.fingerprint };
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
 * throws `backup-manifest/invalid` on a malformed manifest and
 * `backup-manifest/no-signer` when `b.auditSign.init()` hasn't run. For a
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
 * `canonicalBytes` is a Buffer (signed verbatim) or a string (signed as UTF-8).
 * Returns `{ algorithm, publicKey, fingerprint, value, signedAt }`. Requires
 * `b.auditSign.init()` (throws `backup-manifest/no-signer` otherwise).
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
 * canonical bytes. Returns `{ ok, reason?, fingerprint? }` — never throws — so
 * a caller decides whether a missing / mismatched signature is fatal. Pass
 * `opts.expectedFingerprint` to pin the active audit-sign key and refuse a
 * manifest signed under a different (rotated) key. For a schema-agnostic
 * alternative see `verifyBytes`.
 *
 * @opts
 *   expectedFingerprint: string,   // refuse a manifest whose fingerprint differs
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
 * `verifySignature()`. Returns `{ ok, reason?, fingerprint? }`. Pass
 * `opts.expectedFingerprint` to pin the active audit-sign key and refuse a
 * block signed under a different (rotated / historical) key. Falls back to
 * `node:crypto.verify` when audit-sign isn't initialized, so a downstream
 * verifier process can check a signature without holding the signing key.
 *
 * @opts
 *   expectedFingerprint: string,   // refuse a block whose fingerprint differs
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
  var obj;
  try { obj = safeJson.parse(s, { maxBytes: C.BYTES.mib(16) }); }
  catch (e) {
    throw new BackupManifestError("backup-manifest/bad-json",
      "parse: not valid JSON: " + ((e && e.message) || String(e)));
  }
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
  sign:                 sign,
  signBytes:            signBytes,
  signingPayload:       signingPayload,
  verifySignature:      verifySignature,
  verifyBytes:          verifyBytes,
  FORMAT_VERSION:       FORMAT_VERSION,
  FRAMEWORK_NAME:       FRAMEWORK_NAME,
  VALID_KINDS:          VALID_KINDS,
  BackupManifestError:  BackupManifestError,
};
