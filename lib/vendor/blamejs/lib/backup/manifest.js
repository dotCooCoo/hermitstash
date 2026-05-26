"use strict";
/**
 * backup-manifest — schema + validation for backup bundle manifests.
 *
 * Every backup bundle the framework produces carries a manifest.json
 * at its root. The manifest is the single source of truth for: which
 * files are in the bundle, their plaintext size + checksum, the per-
 * file salt used by backup-crypto, and the wrapped vault key needed
 * to interpret vault-sealed file contents post-restore.
 *
 * The encrypted file BYTES are stored separately under the bundle's
 * files/ directory (one file per entry) — the manifest references
 * them by relativePath. This keeps the manifest small enough to
 * inspect / log without carrying gigabytes of base64 inline, and lets
 * a restorer stream-decrypt files one at a time without loading the
 * whole bundle into memory.
 *
 * Manifest format (v1):
 *
 *   {
 *     version:           1,
 *     createdAt:         "<ISO 8601 string>",
 *     framework:         "blamejs",
 *     frameworkVersion:  "0.1.84",
 *     vaultKeySalt:      "<hex>",         // salt used to wrap vault.key
 *     vaultKeyEnc:       "<base64>",      // wrapped vault.key bytes
 *     files: [
 *       {
 *         relativePath:    "db.enc",         // operator-facing path under dataDir
 *         encryptedPath:   "files/db.enc.bin", // path within the bundle
 *         size:            12345,           // plaintext size in bytes
 *         checksum:        "<sha3-512 hex>",  // checksum of the PLAINTEXT
 *         encryptedSize:   12369,           // size of the encrypted blob (bytes)
 *         salt:            "<hex>",         // per-file Argon2 salt
 *         kind:            "raw"            // "raw" | "vault-sealed" | "plaintext"
 *       },
 *       ...
 *     ],
 *     metadata: { ... operator-supplied free-form ... }
 *   }
 *
 * The `kind` field hints at how the post-restore framework should
 * interpret the file:
 *   - raw            on-disk binary that the framework reads as-is
 *                    (db.enc, db.key.enc, etc.)
 *   - vault-sealed   the file's contents are vault-prefix wrapped
 *                    (legacy-style sealed PEMs); restore writes them
 *                    back as-is and the framework unseals at use
 *   - plaintext      operator content not under vault discipline
 *                    (config snapshots, README, etc.)
 *
 * The kind is informational — the bundler does NOT re-seal or unseal
 * based on it; backup-crypto encrypts every file's bytes the same
 * way regardless of kind. Operators / dashboards can use kind for
 * post-restore validation.
 *
 *   var bm = b.backupManifest;
 *
 *   var manifest = bm.create({
 *     vaultKeySalt: "...",
 *     vaultKeyEnc:  "<base64>",
 *     files: [...],
 *     metadata: { reason: "scheduled-daily" },
 *   });
 *   var json = bm.serialize(manifest);    // canonical JSON for storage
 *
 *   var loaded = bm.parse(json);          // validates on parse, throws on error
 *   var v = bm.validate(loaded);          // → { ok, errors } without throwing
 */

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
// SHA3-512 produces 64 raw bytes — each byte serializes as 2 hex chars
// in the manifest, so the hex string is 128 chars long.
var SHA3_512_HEX_LENGTH = 128;
var HEX_RE = safeBuffer.HEX_RE;
var BASE64_RE = safeBuffer.BASE64_RE;

function _isHex(s, evenLength) {
  if (typeof s !== "string" || s.length === 0) return false;
  if (!HEX_RE.test(s)) return false;
  if (evenLength && s.length % 2 !== 0) return false;
  return true;
}
function _isBase64(s) {
  return typeof s === "string" && s.length > 0 && BASE64_RE.test(s);
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
  } else if (f.relativePath.indexOf("..") !== -1 || /^[/\\]/.test(f.relativePath)) {
    // No traversal — when restored, relativePath joins under dataDir
    errors.push("files[" + idx + "].relativePath: must be a relative path without '..' or leading separator");
  }
  if (typeof f.encryptedPath !== "string" || f.encryptedPath.length === 0) {
    errors.push("files[" + idx + "].encryptedPath: required non-empty string");
  } else if (f.encryptedPath.indexOf("..") !== -1 || /^[/\\]/.test(f.encryptedPath)) {
    errors.push("files[" + idx + "].encryptedPath: must be a relative path without '..' or leading separator");
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
  if (typeof f.kind !== "string" || !VALID_KINDS[f.kind]) {
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
  } else {
    // Detect duplicate relativePath / encryptedPath — would corrupt restore
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
  // Optional signature block. When present, every sub-field is
  // required — partial signatures are a smell (operators saw an
  // unsigned bundle and tried to hand-edit a signature in).
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
  var v = validate(manifest);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "create: " + v.errors.join("; "));
  }
  return manifest;
}

function _canonical(manifest, includeSignature) {
  // Stable key ordering so the same manifest object always serializes
  // to the same bytes (operators can hash the manifest as part of
  // bundle-integrity logging without surprises across runs).
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
  // Signature block lives alongside the rest of the manifest fields
  // and is itself stable-ordered. Sign-time canonicalization (the
  // bytes the audit-sign keypair signs) excludes the signature field
  // so the signature can be appended without altering the signed
  // payload.
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

// The canonical payload the audit-sign keypair signs over — the
// manifest serialized without its `signature` field. Exposed so
// verifiers can recompute the exact bytes that produced the signature.
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

// Sign the manifest in-place via the audit-sign keypair (ML-DSA-87
// or SLH-DSA-SHAKE-256f — whichever audit-sign was initialized with).
// The signature covers the manifest's canonical bytes WITHOUT the
// signature field; appending it does not change the signed payload.
function sign(manifest) {
  var v = validate(manifest);
  if (!v.ok) {
    throw new BackupManifestError("backup-manifest/invalid",
      "sign: " + v.errors.join("; "));
  }
  var signer = auditSign();
  if (!signer || typeof signer.sign !== "function") {
    throw new BackupManifestError("backup-manifest/no-signer",
      "sign: audit-sign module is not available; call b.auditSign.init() first");
  }
  var payload = signingPayload(manifest);
  var signatureBytes;
  try { signatureBytes = signer.sign(payload); }
  catch (e) {
    throw new BackupManifestError("backup-manifest/sign-failed",
      "sign: audit-sign.sign threw: " + ((e && e.message) || String(e)));
  }
  manifest.signature = {
    algorithm:   signer.getAlgorithm(),
    publicKey:   signer.getPublicKey(),
    fingerprint: signer.getPublicKeyFingerprint(),
    value:       signatureBytes.toString("base64"),
    signedAt:    new Date().toISOString(),
  };
  return manifest;
}

// Verify a previously-signed manifest. Returns { ok, reason?,
// fingerprint? }. Caller policy decides whether a missing or
// fingerprint-mismatched signature is fatal — verifyManifestSignature
// in lib/backup/index.js wraps this with operator-facing semantics.
function verifySignature(manifest, opts) {
  opts = opts || {};
  if (!manifest || typeof manifest !== "object") {
    return { ok: false, reason: "manifest must be an object" };
  }
  if (!manifest.signature || typeof manifest.signature !== "object") {
    return { ok: false, reason: "manifest has no signature block" };
  }
  var sig = manifest.signature;
  if (typeof sig.algorithm !== "string" || sig.algorithm.length === 0) {
    return { ok: false, reason: "signature.algorithm is required" };
  }
  if (typeof sig.publicKey !== "string" || sig.publicKey.length === 0) {
    return { ok: false, reason: "signature.publicKey is required" };
  }
  if (typeof sig.value !== "string" || sig.value.length === 0) {
    return { ok: false, reason: "signature.value is required" };
  }
  // Caller may pin the expected fingerprint — operators tracking key
  // rotation pass the active audit-sign fingerprint and refuse any
  // bundle signed under a different historical key.
  if (typeof opts.expectedFingerprint === "string" &&
      opts.expectedFingerprint.length > 0 &&
      sig.fingerprint !== opts.expectedFingerprint) {
    return {
      ok: false,
      reason: "signature.fingerprint=" + sig.fingerprint +
              " does not match expectedFingerprint=" + opts.expectedFingerprint,
      fingerprint: sig.fingerprint,
    };
  }
  var payload = signingPayload(manifest);
  var sigBuf;
  try { sigBuf = Buffer.from(sig.value, "base64"); }
  catch (_e) {
    return { ok: false, reason: "signature.value is not valid base64" };
  }
  // Use audit-sign.verify when available (handles algorithm dispatch
  // identically to the signer); fall back to nodeCrypto.verify for
  // verifier processes that don't init audit-sign.
  var ok;
  try {
    var signer = auditSign();
    if (signer && typeof signer.verify === "function") {
      ok = signer.verify(payload, sigBuf, sig.publicKey);
    } else {
      ok = require("node:crypto").verify(null,
        Buffer.from(payload, "utf8"), sig.publicKey, sigBuf);
    }
  } catch (e) {
    return {
      ok:           false,
      reason:       "verify threw: " + ((e && e.message) || String(e)),
      fingerprint:  sig.fingerprint,
    };
  }
  if (!ok) {
    return {
      ok:          false,
      reason:      "signature did not verify under provided publicKey",
      fingerprint: sig.fingerprint,
    };
  }
  return { ok: true, fingerprint: sig.fingerprint };
}

function parse(jsonStr) {
  if (typeof jsonStr !== "string" && !Buffer.isBuffer(jsonStr)) {
    throw new BackupManifestError("backup-manifest/bad-input",
      "parse: argument must be a string or Buffer");
  }
  var s = Buffer.isBuffer(jsonStr) ? jsonStr.toString("utf8") : jsonStr;
  var obj;
  // Backup manifests are file-bounded operator-supplied input. 16 MiB
  // is generous; real manifests are kilobytes.
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
  signingPayload:       signingPayload,
  verifySignature:      verifySignature,
  FORMAT_VERSION:       FORMAT_VERSION,
  FRAMEWORK_NAME:       FRAMEWORK_NAME,
  VALID_KINDS:          VALID_KINDS,
  BackupManifestError:  BackupManifestError,
};
