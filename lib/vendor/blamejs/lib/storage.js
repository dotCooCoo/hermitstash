"use strict";
/**
 * Storage abstraction — multi-backend, classification-routed, residency-
 * enforced file storage with per-file vault-sealed encryption.
 *
 * Two configuration shapes (both supported, internally normalized to
 * the multi-backend form):
 *
 *   1. Single-backend (legacy shape — preserved):
 *        storage.init({ backend: 'local', uploadDir: './data/uploads' })
 *
 *   2. Multi-backend:
 *        storage.init({
 *          backends: {
 *            'eu-private': { protocol: 'http-put', baseUrl: '...',
 *                            classifications: ['personal'], residencyTag: 'EU' },
 *            'us-ops':     { protocol: 'local', rootDir: '/data/ops',
 *                            classifications: ['operational', 'public'],
 *                            residencyTag: 'US' },
 *          },
 *          defaultClassification: 'personal',
 *          refuseUnclassified:    true,
 *        });
 *
 * Classification routing (per-call):
 *   storage.saveFile(buf, 'invoice.pdf', { classification: 'personal' })
 *     → routes to a backend whose `classifications` includes 'personal'.
 *   storage.saveFile(buf, 'logo.png', { backend: 'us-ops' })
 *     → explicit backend; framework still validates the backend serves
 *        the classification.
 *
 * Residency enforcement (boot-time):
 *   - If db.getDataResidency() declares a region, every backend serving the
 *     'personal' classification must have residencyTag === region (or be
 *     listed in dataResidency.allowedStorageRegions).
 *   - Refuses to boot otherwise — catches operator misconfiguration where
 *     a US-region backend was configured for personal data in an EU app.
 *
 * Audit hooks:
 *   - Every saveFile records a 'system.storage.write' event with metadata
 *     { backend, classification, residencyTag, sizeBytes }.
 *   - getFile records 'system.storage.read'.
 *   - delete records 'system.storage.delete'.
 *
 * Public API (sync entry, async ops since backends may be remote):
 *   storage.init(opts)                                            (sync)
 *   storage.saveFile(buffer, key, opts?)        async →  { storedPath, encryptionKey, backend, classification }
 *   storage.getFileBuffer(storedPath, sealedKey, opts?) async → Buffer
 *   storage.getFileStream(storedPath, sealedKey, opts?) async → Readable
 *   storage.saveRaw(buffer, key, opts?)         async → { storedPath, backend }
 *   storage.getRawBuffer(storedPath, opts?)     async → Buffer
 *   storage.deleteFile(storedPath, opts?)       async → boolean
 *   storage.exists(storedPath, opts?)           async → boolean
 *   storage.presignedUploadUrl(key, opts?)              → { url, method, headers, expiresAt }
 *   storage.presignedDownloadUrl(key, opts?)            → { url, method, headers, expiresAt }
 *   storage.presignedUploadPolicy(key, opts)            → { url, method, fields, expiresAt, maxBytes, enforcement }
 *   storage.listBackends()                              → [{ name, protocol, classifications, residencyTag }]
 *   storage.getBackend(name)                            → backend instance (or null)
 */
var C = require("./constants");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var objectStore = require("./object-store");
var lazyRequire = require("./lazy-require");
var { StorageError } = require("./framework-error");

var vault = lazyRequire(function () { return require("./vault"); });
var audit = lazyRequire(function () { return require("./audit"); });
var db    = lazyRequire(function () { return require("./db"); });

var initialized = false;
var backends = {};                    // name → backend instance from object-store
var defaultClassification = null;
var refuseUnclassified = false;

var _err = StorageError.factory;

// ---- Init ----

function init(opts) {
  if (initialized) return;
  if (!opts) throw _err("INVALID_CONFIG", "storage.init() requires options", true);

  // Normalize single-backend config into multi-backend form
  var normalized = _normalizeConfig(opts);

  defaultClassification = normalized.defaultClassification;
  refuseUnclassified    = !!normalized.refuseUnclassified;

  backends = {};
  for (var name in normalized.backends) {
    var cfg = Object.assign({}, normalized.backends[name], { name: name });
    backends[name] = objectStore.buildBackend(cfg);
  }

  // Boot-time residency validation
  _validateResidency();

  initialized = true;
}

function _normalizeConfig(opts) {
  if (opts.backends) {
    return {
      backends:              opts.backends,
      defaultClassification: opts.defaultClassification || null,
      refuseUnclassified:    !!opts.refuseUnclassified,
    };
  }
  // Single-backend syntax: { backend, uploadDir, ... }
  if (opts.backend) {
    if (opts.backend === "s3") {
      throw _err("INVALID_CONFIG",
        "storage backend 's3' is now spelled 'sigv4' (covers AWS S3, R2, B2, " +
        "MinIO, Wasabi, Tigris, DO Spaces, IDrive e2, Storj, Linode). " +
        "Use { backend: 'sigv4', endpoint, region, bucket, accessKeyId, secretAccessKey }.",
        true);
    }
    if (opts.backend === "local") {
      return {
        backends: {
          "default": {
            protocol:        "local",
            rootDir:         opts.uploadDir,
            classifications: ["*"],
            residencyTag:    "unrestricted",
          },
        },
        defaultClassification: null,
        refuseUnclassified:    false,
      };
    }
    if (opts.backend === "http-put" || opts.backend === "sigv4" || opts.backend === "gcs" || opts.backend === "azure-blob") {
      // Forward as-is; user provided a single-backend spec for a remote protocol
      return {
        backends: { "default": Object.assign({}, opts, { name: undefined }) },
        defaultClassification: null,
        refuseUnclassified:    false,
      };
    }
    throw _err("INVALID_CONFIG",
      "storage.init: unknown backend '" + opts.backend + "'", true);
  }
  throw _err("INVALID_CONFIG",
    "storage.init: must provide either { backend } or { backends }", true);
}

function _validateResidency() {
  var residency;
  try { residency = db().getDataResidency(); } catch (_e) { residency = null; }
  if (!residency || !residency.region) return;

  var allowed = [residency.region].concat(residency.allowedStorageRegions || []);

  for (var name in backends) {
    var b = backends[name];
    var serves = b.classifications.indexOf("*") !== -1 || b.classifications.indexOf("personal") !== -1;
    if (!serves) continue;
    if (allowed.indexOf(b.residencyTag) === -1) {
      throw _err(
        "RESIDENCY_VIOLATION",
        "backend '" + name + "' serves 'personal' data with residencyTag '" + b.residencyTag +
        "' but app's dataResidency.region is '" + residency.region + "' (allowed: " + allowed.join(", ") + ")",
        true
      );
    }
  }

  // If defaultClassification is 'personal', confirm at least one backend serves it
  if (defaultClassification === "personal") {
    var found = false;
    for (var n in backends) {
      if (backends[n].servesClassification("personal")) { found = true; break; }
    }
    if (!found) {
      throw _err("NO_PERSONAL_BACKEND",
        "defaultClassification='personal' but no backend declares 'personal' in classifications", true);
    }
  }
}

// ---- Backend selection ----

function _pickBackend(opts) {
  opts = opts || {};
  if (opts.backend) {
    var b = backends[opts.backend];
    if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + opts.backend + "'", true);
    if (opts.classification && !b.servesClassification(opts.classification)) {
      throw _err("CLASSIFICATION_MISMATCH",
        "backend '" + opts.backend + "' does not serve classification '" + opts.classification + "'", true);
    }
    return { backend: b, classification: opts.classification || null };
  }

  // refuseUnclassified forces every call to declare classification explicitly,
  // even when defaultClassification is configured. The default is for
  // convenience; refuseUnclassified is for explicit boundary enforcement.
  if (refuseUnclassified && !opts.classification) {
    throw _err("UNCLASSIFIED",
      "saveFile requires { classification } (or set { backend } explicitly); " +
      "framework is configured with refuseUnclassified: true", true);
  }
  var classification = opts.classification || defaultClassification;
  if (!classification) {
    // No classification + no refusal → pick any backend
    for (var n in backends) return { backend: backends[n], classification: null };
    throw _err("NO_BACKENDS", "no backends configured", true);
  }

  for (var name in backends) {
    if (backends[name].servesClassification(classification)) {
      return { backend: backends[name], classification: classification };
    }
  }
  throw _err("NO_BACKEND_FOR_CLASSIFICATION",
    "no backend serves classification '" + classification + "'", true);
}

// ---- File encryption helpers ----

function _encryptBuffer(buffer) {
  var key = generateBytes(C.BYTES.bytes(32));
  var packed = encryptPacked(buffer, key);
  var sealedKey = vault().seal(key.toString("base64"));
  return { data: packed, encryptionKey: sealedKey };
}

function _decryptBuffer(packed, sealedKey) {
  if (!sealedKey) {
    throw _err("KEY_REQUIRED", "encryptionKey is required (no legacy plaintext support)", true);
  }
  var key = Buffer.from(vault().unseal(sealedKey), "base64");
  return decryptPacked(packed, key);
}

// ---- Audit emission ----

function _emit(action, info) {
  // safeEmit handles default-fill + try/catch. Audit must never block
  // storage operations — if it fails the missing entry shows up at the
  // next chain verify.
  audit().safeEmit({ action: action, ...(info || {}) });
}

// ---- Public API ----

async function saveFile(buffer, key, opts) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) throw _err("INVALID_BODY", "saveFile body must be a Buffer", true);
  opts = opts || {};
  var picked = _pickBackend(opts);
  var enc = _encryptBuffer(buffer);
  var result = await picked.backend.put(key, enc.data, opts);
  _emit("system.storage.write", {
    metadata: {
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      sizeBytes:      result.size != null ? result.size : enc.data.length,
    },
  });
  return {
    storedPath:    key,
    encryptionKey: enc.encryptionKey,
    backend:       picked.backend.name,
    classification: picked.classification,
  };
}

async function getFileBuffer(key, sealedKey, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  var packed = await picked.backend.get(key);
  var decrypted = _decryptBuffer(packed, sealedKey);
  _emit("system.storage.read", {
    metadata: {
      backend: picked.backend.name,
      key:     key,
      sizeBytes: decrypted.length,
    },
  });
  return decrypted;
}

async function getFileStream(key, sealedKey, opts) {
  // Buffer-then-stream: per-file XChaCha20 encryption needs the whole
  // ciphertext to verify the AEAD tag before any plaintext can be released
  // to the consumer. Chunked-encryption with per-chunk AEAD would let us
  // stream end-to-end, but at the cost of finer-grained tampering windows.
  var buf = await getFileBuffer(key, sealedKey, opts);
  return require("stream").Readable.from(buf);
}

async function saveRaw(buffer, key, opts) {
  _requireInit();
  if (!Buffer.isBuffer(buffer)) throw _err("INVALID_BODY", "saveRaw body must be a Buffer", true);
  opts = opts || {};
  var picked = _pickBackend(opts);
  var result = await picked.backend.put(key, buffer, opts);
  _emit("system.storage.write", {
    metadata: {
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      sizeBytes:      result.size != null ? result.size : buffer.length,
      raw:            true,
    },
  });
  return { storedPath: key, backend: picked.backend.name };
}

async function getRawBuffer(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  return picked.backend.get(key);
}

async function deleteFile(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  var result = await picked.backend.delete(key);
  _emit("system.storage.delete", {
    metadata: {
      backend: picked.backend.name,
      key:     key,
      existed: result,
    },
  });
  return result;
}

async function exists(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  try {
    await picked.backend.head(key);
    return true;
  } catch (e) {
    if (e && e.code === "NOT_FOUND") return false;
    throw e;
  }
}

function listBackends() {
  _requireInit();
  var out = [];
  for (var name in backends) {
    out.push({
      name:            name,
      protocol:        backends[name].protocol,
      classifications: backends[name].classifications.slice(),
      residencyTag:    backends[name].residencyTag,
      breakerState:    backends[name].breaker.getState(),
    });
  }
  return out;
}

function _presign(direction, key, opts) {
  _requireInit();
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "presigned" + direction + "Url: key is required", true);
  }
  opts = opts || {};
  var picked = _pickBackend(opts);
  var fnName = "presigned" + direction + "Url";
  if (typeof picked.backend[fnName] !== "function") {
    throw _err("PRESIGN_NOT_SUPPORTED",
      "backend '" + picked.backend.name + "' (protocol '" + picked.backend.protocol +
      "') does not support presigned " + direction.toLowerCase() + " URLs", true);
  }
  var result = picked.backend[fnName](Object.assign({}, opts, { key: key }));
  _emit("system.storage.presign", {
    metadata: {
      direction:      direction.toLowerCase(),
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      expiresAt:      result.expiresAt,
    },
  });
  return result;
}

function presignedUploadUrl(key, opts)   { return _presign("Upload", key, opts); }
function presignedDownloadUrl(key, opts) { return _presign("Download", key, opts); }

// presignedUploadPolicy — issues a POST-form policy (or vendor-equivalent
// PUT) that the client uses to upload directly to the object store with
// server-side body-size enforcement. Distinct from presignedUploadUrl
// because that signs only the URL; this signs a full policy document
// that includes a content-length-range condition.
//
// Vendor enforcement:
//   sigv4    — content-length-range condition; S3 rejects bodies outside
//   gcs      — content-length-range condition; GCS rejects bodies outside
//   azure    — SAS doesn't natively cap body size; returns SAS PUT URL
//              with enforcement: "client-only" — operator must HEAD the
//              blob post-upload and reject if oversize
//   local    — NOT_SUPPORTED (use saveFile directly)
//   http-put — NOT_SUPPORTED (no signing convention)
function presignedUploadPolicy(key, opts) {
  _requireInit();
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "presignedUploadPolicy: key is required", true);
  }
  opts = opts || {};
  var picked = _pickBackend(opts);
  if (typeof picked.backend.presignedUploadPolicy !== "function") {
    throw _err("PRESIGN_NOT_SUPPORTED",
      "backend '" + picked.backend.name + "' (protocol '" + picked.backend.protocol +
      "') does not support presigned upload policies", true);
  }
  var result = picked.backend.presignedUploadPolicy(Object.assign({}, opts, { key: key }));
  _emit("system.storage.presign", {
    metadata: {
      direction:      "upload-policy",
      backend:        picked.backend.name,
      classification: picked.classification,
      residencyTag:   picked.backend.residencyTag,
      key:            key,
      expiresAt:      result.expiresAt,
      maxBytes:       result.maxBytes,
      enforcement:    result.enforcement,
    },
  });
  return result;
}

function getBackend(name) {
  _requireInit();
  return backends[name] || null;
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "storage.init() must be called before any file operation", true);
}

function _resetForTest() {
  initialized = false;
  backends = {};
  defaultClassification = null;
  refuseUnclassified = false;
  vault.reset();
  audit.reset();
  db.reset();
}

module.exports = {
  init:           init,
  saveFile:       saveFile,
  getFileBuffer:  getFileBuffer,
  getFileStream:  getFileStream,
  saveRaw:        saveRaw,
  getRawBuffer:   getRawBuffer,
  deleteFile:     deleteFile,
  exists:         exists,
  presignedUploadUrl:    presignedUploadUrl,
  presignedDownloadUrl:  presignedDownloadUrl,
  presignedUploadPolicy: presignedUploadPolicy,
  listBackends:   listBackends,
  getBackend:     getBackend,
  _resetForTest:  _resetForTest,
};
