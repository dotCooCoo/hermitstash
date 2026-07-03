// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.storage
 * @featured true
 * @nav    Data
 * @title  Storage
 *
 * @intro
 *   Filesystem-and-cloud-backed object storage with sealed per-file
 *   encryption keys, classification routing, and residency enforcement.
 *
 *   `b.storage` sits one layer above `b.objectStore`: the lower
 *   primitive abstracts the byte-level adapter (local FS, sigv4-style
 *   S3-compatible, GCS, Azure Blob, generic HTTP-PUT); this module
 *   adds the framework-shaped policy on top — multi-backend
 *   registration, per-call classification → backend dispatch,
 *   boot-time residency validation against `b.db.getDataResidency()`,
 *   per-file XChaCha20-Poly1305 encryption with the data key sealed
 *   into the framework's vault, and audit-chain emission for every
 *   read / write / delete / presign.
 *
 *   Configuration accepts either the legacy single-backend shape
 *   (`{ backend, uploadDir }`) or the multi-backend shape
 *   (`{ backends: { name: cfg, ... }, defaultClassification,
 *   refuseUnclassified }`). Both normalize internally to the
 *   multi-backend form. `refuseUnclassified: true` forces every call
 *   to declare its `classification` explicitly, which is the right
 *   posture for apps mixing personal / operational / public data
 *   across different residency zones.
 *
 *   Encrypted save/get is the default surface (`saveFile` /
 *   `getFileBuffer` / `getFileStream`); `saveRaw` / `getRawBuffer`
 *   skip the per-file encryption envelope for content that is
 *   already-public or already-encrypted (e.g. signed image assets,
 *   pre-encrypted backup bundles).
 *
 * @card
 *   Filesystem-and-cloud-backed object storage with sealed per-file encryption keys, classification routing, and residency enforcement.
 */
var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var objectStore = require("./object-store");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");
var canonicalJson = require("./canonical-json");
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

/**
 * @primitive b.storage.init
 * @signature b.storage.init(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.saveFile, b.storage.listBackends, b.objectStore.buildBackend
 *
 * Register one or more storage backends and lock the framework into
 * the configured policy. Idempotent — a second call after the first
 * succeeds is a no-op (operators rebuild via `_resetForTest` only).
 * Validates classification → residency mapping at boot so a
 * misconfigured deployment (US backend serving EU personal data)
 * fails fast instead of leaking on first write.
 *
 * @opts
 *   backend:                "local" | "sigv4" | "gcs" | "azure-blob" | "http-put",  // single-backend shorthand
 *   uploadDir:              string,             // local backend root (single-backend shorthand)
 *   backends:               object,             // multi-backend map: name -> backend cfg
 *   defaultClassification:  string,             // applied when a call omits { classification }
 *   refuseUnclassified:     boolean,            // refuse calls without explicit classification
 *
 * @example
 *   // Single-backend, local FS — typical small-app shape.
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *
 * @example
 *   // Multi-backend with classification routing + residency tags.
 *   b.storage.init({
 *     backends: {
 *       "eu-private": {
 *         protocol:        "local",
 *         rootDir:         "/srv/eu/private",
 *         classifications: ["personal"],
 *         residencyTag:    "EU",
 *       },
 *       "us-ops": {
 *         protocol:        "local",
 *         rootDir:         "/srv/us/ops",
 *         classifications: ["operational", "public"],
 *         residencyTag:    "US",
 *       },
 *     },
 *     defaultClassification: "operational",
 *     refuseUnclassified:    true,
 *   });
 */
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

/**
 * @primitive b.storage.saveFile
 * @signature b.storage.saveFile(buffer, key, opts)
 * @since     0.1.0
 * @status    stable
 * @compliance gdpr, hipaa, pci-dss, soc2
 * @related   b.storage.getFileBuffer, b.storage.deleteFile, b.storage.saveRaw
 *
 * Encrypt `buffer` under a fresh XChaCha20-Poly1305 data key, seal
 * the data key into the framework vault, and write the ciphertext to
 * the backend selected by `opts.classification` (or `opts.backend`
 * for explicit pinning). Returns the storage path plus the sealed
 * key the caller MUST persist alongside the row that references the
 * blob — without it, the bytes are unrecoverable. Emits a
 * `system.storage.write` audit event with `{ backend, classification,
 * residencyTag, sizeBytes }`.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name (still validates classification serve)
 *
 * @example
 *   var buf = Buffer.from("invoice pdf bytes");
 *   var saved = await b.storage.saveFile(buf, "invoices/2026/001.pdf", {
 *     classification: "personal",
 *   });
 *   // → { storedPath: "invoices/2026/001.pdf",
 *   //     encryptionKey: "v1:...",   // sealed; persist with the row
 *   //     backend: "eu-private",
 *   //     classification: "personal" }
 */
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

/**
 * @primitive b.storage.getFileBuffer
 * @signature b.storage.getFileBuffer(key, sealedKey, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.saveFile, b.storage.getFileStream
 *
 * Fetch the ciphertext at `key` from the routed backend, unseal the
 * per-file data key via the framework vault, and return the
 * decrypted plaintext as a Buffer. The AEAD tag is verified before
 * any plaintext is released — a tampered ciphertext throws
 * `crypto/decrypt-failed`, never returns partial bytes. Emits
 * `system.storage.read` with `{ backend, key, sizeBytes }`.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *
 * @example
 *   // Round-trip a small text payload through saveFile/getFileBuffer.
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var saved = await b.storage.saveFile(Buffer.from("hello"), "greet.txt");
 *   var roundTrip = await b.storage.getFileBuffer("greet.txt", saved.encryptionKey);
 *   roundTrip.toString("utf8");   // → "hello"
 */
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

/**
 * @primitive b.storage.getFileStream
 * @signature b.storage.getFileStream(key, sealedKey, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.getFileBuffer, b.storage.saveFile
 *
 * Buffer-then-stream variant of `getFileBuffer` — returns a
 * `stream.Readable` once the AEAD tag has verified the entire
 * ciphertext. Per-file XChaCha20-Poly1305 needs the whole frame
 * before it can release the first byte; chunked AEAD with
 * per-chunk tags would let us stream end-to-end at the cost of
 * finer-grained tampering windows, so the framework defaults to
 * the safe variant.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var saved = await b.storage.saveFile(Buffer.from("stream-me"), "blob.bin");
 *   var stream = await b.storage.getFileStream("blob.bin", saved.encryptionKey);
 *   var chunks = [];
 *   for await (var chunk of stream) chunks.push(chunk);
 *   Buffer.concat(chunks).toString("utf8");   // → "stream-me"
 */
async function getFileStream(key, sealedKey, opts) {
  // Buffer-then-stream: per-file XChaCha20 encryption needs the whole
  // ciphertext to verify the AEAD tag before any plaintext can be released
  // to the consumer. Chunked-encryption with per-chunk AEAD would let us
  // stream end-to-end, but at the cost of finer-grained tampering windows.
  var buf = await getFileBuffer(key, sealedKey, opts);
  return require("node:stream").Readable.from(buf);
}

/**
 * @primitive b.storage.saveRaw
 * @signature b.storage.saveRaw(buffer, key, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.saveFile, b.storage.getRawBuffer
 *
 * Write `buffer` to the routed backend as-is, skipping the per-file
 * encryption envelope. Use for content that is already public
 * (signed CDN assets, image thumbnails) or already encrypted
 * (pre-sealed backup bundles); use `saveFile` for everything else.
 * Audit metadata records `raw: true` so storage reads in the audit
 * chain can be distinguished from encrypted reads.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var saved = await b.storage.saveRaw(Buffer.from("public-bytes"), "logo.png");
 *   // → { storedPath: "logo.png", backend: "default", versionId: null }
 */
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
  // versionId is non-null only on a versioning-enabled (S3 Object-Lock)
  // backend; capture it to target the exact version for later erasure.
  return { storedPath: key, backend: picked.backend.name, versionId: result.versionId || null };
}

/**
 * @primitive b.storage.getRawBuffer
 * @signature b.storage.getRawBuffer(key, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.saveRaw, b.storage.getFileBuffer
 *
 * Fetch the raw bytes at `key` from the routed backend. No
 * decryption layer is applied — the caller receives whatever was
 * stored, byte-for-byte. Pair with `saveRaw`; for encrypted blobs
 * use `getFileBuffer` instead so the AEAD tag is verified.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   await b.storage.saveRaw(Buffer.from("raw-payload"), "asset.bin");
 *   var bytes = await b.storage.getRawBuffer("asset.bin");
 *   bytes.toString("utf8");   // → "raw-payload"
 */
async function getRawBuffer(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  return picked.backend.get(key);
}

/**
 * @primitive b.storage.deleteFile
 * @signature b.storage.deleteFile(key, opts)
 * @since     0.1.0
 * @status    stable
 * @compliance gdpr
 * @related   b.storage.saveFile, b.storage.exists
 *
 * Remove `key` from the routed backend. Returns `true` when the
 * object existed and was removed, `false` when it was already
 * absent. Emits `system.storage.delete` with `{ backend, key,
 * existed, versionId }` so the audit chain records GDPR right-to-erasure
 * flows. The sealed encryption key the caller persisted alongside
 * the row should be discarded by the caller after a successful
 * delete — without the bytes, the key has no recovery value.
 *
 * On a versioning-enabled (S3 Object-Lock) backend an unversioned
 * delete only writes a delete-marker — the data version survives. To
 * erase a specific version pass `versionId` (from `saveRaw`'s return or
 * `listVersions`); a version under an active retention is refused (the
 * call throws), and `bypassGovernanceRetention` lifts a GOVERNANCE-mode
 * retention for callers with the permission (COMPLIANCE stays immutable).
 * `versionId` is S3/sigv4-only and is refused on other backends.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *   versionId:       string,    // erase a specific object version (S3 Object-Lock)
 *   bypassGovernanceRetention: boolean, // lift GOVERNANCE retention (not COMPLIANCE)
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   await b.storage.saveRaw(Buffer.from("doomed"), "tmp/x.bin");
 *   var existed = await b.storage.deleteFile("tmp/x.bin");
 *   // → true
 *   var second = await b.storage.deleteFile("tmp/x.bin");
 *   // → false
 */
async function deleteFile(key, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  var result = await picked.backend.delete(key, {
    versionId:                 opts.versionId,
    bypassGovernanceRetention: opts.bypassGovernanceRetention,
  });
  _emit("system.storage.delete", {
    metadata: {
      backend:   picked.backend.name,
      key:       key,
      existed:   result,
      versionId: opts.versionId || null,
    },
  });
  return result;
}

/**
 * @primitive b.storage.exists
 * @signature b.storage.exists(key, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.deleteFile, b.storage.getFileBuffer
 *
 * HEAD-style existence check — returns `true` when the routed
 * backend reports the key present, `false` on `NOT_FOUND`. Other
 * backend errors propagate so transient outages aren't swallowed
 * as "doesn't exist." Cheaper than a full GET when the caller only
 * needs to gate a downstream operation on presence.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   await b.storage.saveRaw(Buffer.from("here"), "probe.bin");
 *   var present = await b.storage.exists("probe.bin");
 *   // → true
 *   var missing = await b.storage.exists("nope.bin");
 *   // → false
 */
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

/**
 * @primitive b.storage.listVersions
 * @signature b.storage.listVersions(prefix, opts?)
 * @since     0.15.10
 * @status    stable
 * @compliance gdpr, sox-404, soc2
 * @related   b.storage.deleteFile, b.storage.saveRaw, b.worm.create
 *
 * Enumerate every object VERSION and delete-marker under `prefix` on a
 * versioning-enabled (S3 Object-Lock) backend. Plain reads only see the
 * current version; right-to-erasure / crypto-shred on an Object-Lock
 * bucket must target prior versions by `versionId`, which only this call
 * surfaces. Each item is `{ key, versionId, isLatest, deleteMarker, size,
 * lastModified, etag }`; `deleteMarker: true` rows are tombstones with no
 * data. Pair with `deleteFile(key, { versionId })` to erase a version.
 *
 * Versioning is an S3/sigv4 feature — a backend without a version surface
 * (filesystem, and the current Azure/GCS adapters) throws
 * `VERSIONS_UNSUPPORTED` rather than silently returning the current view,
 * so an erasure workflow can never mistake a single-version backend for a
 * fully-enumerated one.
 *
 * @opts
 *   classification:   string,   // route to a backend serving this classification
 *   backend:          string,   // explicit backend by name
 *   maxResults:       number,   // page size
 *   keyMarker:        string,   // pagination cursor (from a prior page)
 *   versionIdMarker:  string,   // pagination cursor (from a prior page)
 *
 * @example
 *   var page = await b.storage.listVersions("filings/2026/");
 *   for (var v of page.items) {
 *     if (!v.isLatest) await b.storage.deleteFile(v.key, { versionId: v.versionId });
 *   }
 */
async function listVersions(prefix, opts) {
  _requireInit();
  opts = opts || {};
  var picked = _pickBackend(opts);
  if (typeof picked.backend.listVersions !== "function") {
    throw _err("VERSIONS_UNSUPPORTED",
      "listVersions: backend '" + picked.backend.name + "' has no version surface " +
      "(S3/sigv4 only). A filesystem / single-version backend cannot enumerate versions.", true);
  }
  return picked.backend.listVersions(prefix, opts);
}

/**
 * @primitive b.storage.listBackends
 * @signature b.storage.listBackends()
 * @since     0.1.0
 * @status    stable
 * @related   b.storage.getBackend, b.storage.init
 *
 * Snapshot every registered backend with `{ name, protocol,
 * classifications, residencyTag, breakerState }`. The
 * `breakerState` is the live circuit-breaker state from the
 * underlying `b.objectStore` adapter — handy for ops dashboards
 * surfacing a degraded backend before it cascades.
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var info = b.storage.listBackends();
 *   info[0].name;       // → "default"
 *   info[0].protocol;   // → "local"
 */
function listBackends() {
  _requireInit();
  var out = [];
  for (var name in backends) {
    var entry = {
      name:            name,
      protocol:        backends[name].protocol,
      classifications: backends[name].classifications.slice(),
      residencyTag:    backends[name].residencyTag,
      breakerState:    backends[name].breaker.getState(),
    };
    // Surface the resolved local rootDir so downstream operators
    // building path-traversal guards or scratch-dir layouts read the
    // live path (with config-reload propagation) directly from the
    // backend rather than re-deriving from operator-supplied opts.
    // Remote protocols (sigv4 / gcs / azure-blob / http-put) don't
    // have a rootDir; the field stays absent for those.
    if (backends[name].protocol === "local" && backends[name].raw && typeof backends[name].raw.rootDir === "string") {
      entry.rootDir = backends[name].raw.rootDir;
    }
    out.push(entry);
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

/**
 * @primitive b.storage.presignedUploadUrl
 * @signature b.storage.presignedUploadUrl(key, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.storage.presignedDownloadUrl, b.storage.presignedUploadPolicy
 *
 * Issue a short-lived signed URL the client uses to PUT bytes
 * directly to the object store, bypassing the framework process
 * for the upload bytes. Backend-dependent: sigv4 / gcs / azure-blob
 * support it natively; local / http-put backends throw
 * `PRESIGN_NOT_SUPPORTED`. Emits `system.storage.presign` with
 * `direction: "upload"`.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *   expiresInSec:    number,    // URL lifetime; backend-defaulted when omitted
 *   contentType:     string,    // pin the upload Content-Type into the signature
 *
 * @example
 *   b.storage.init({
 *     backends: {
 *       "us-ops": {
 *         protocol:        "sigv4",
 *         endpoint:        "https://s3.us-east-1.amazonaws.com",
 *         region:          "us-east-1",
 *         bucket:          "uploads",
 *         accessKeyId:     "AKIAEXAMPLE",
 *         secretAccessKey: "secret",
 *         classifications: ["operational"],
 *         residencyTag:    "US",
 *       },
 *     },
 *   });
 *   var presigned = b.storage.presignedUploadUrl("incoming/x.bin", {
 *     backend:      "us-ops",
 *     expiresInSec: 300,
 *   });
 *   presigned.method;   // → "PUT"
 */
function presignedUploadUrl(key, opts)   { return _presign("Upload", key, opts); }

/**
 * @primitive b.storage.presignedDownloadUrl
 * @signature b.storage.presignedDownloadUrl(key, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.storage.presignedUploadUrl, b.storage.getFileBuffer
 *
 * Issue a short-lived signed URL the client uses to GET bytes
 * directly from the object store. Same backend-support matrix as
 * the upload variant. Use this only with `saveRaw` content —
 * encrypted blobs (`saveFile`) need the per-file sealed key, which
 * the framework does not expose to the client.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *   expiresInSec:    number,    // URL lifetime; backend-defaulted when omitted
 *   responseHeaders: {          // S3 response-header overrides (sigv4 backend)
 *     contentDisposition: string,  // e.g. 'attachment; filename="invoice.pdf"'
 *     contentType:        string,
 *     contentLanguage:    string,
 *     contentEncoding:    string,
 *     cacheControl:       string,
 *     expires:            string,
 *   },
 *
 * @example
 *   b.storage.init({
 *     backends: {
 *       "us-ops": {
 *         protocol:        "sigv4",
 *         endpoint:        "https://s3.us-east-1.amazonaws.com",
 *         region:          "us-east-1",
 *         bucket:          "uploads",
 *         accessKeyId:     "AKIAEXAMPLE",
 *         secretAccessKey: "secret",
 *         classifications: ["public"],
 *         residencyTag:    "US",
 *       },
 *     },
 *   });
 *   var presigned = b.storage.presignedDownloadUrl("public/logo.png", {
 *     backend:      "us-ops",
 *     expiresInSec: 60,
 *     responseHeaders: {
 *       contentDisposition: 'attachment; filename="logo.png"',
 *     },
 *   });
 *   presigned.method;   // → "GET"
 */
function presignedDownloadUrl(key, opts) { return _presign("Download", key, opts); }

/**
 * @primitive b.storage.presignedUploadPolicy
 * @signature b.storage.presignedUploadPolicy(key, opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.storage.presignedUploadUrl, b.fileUpload
 *
 * Issue a signed POST-form policy (sigv4 / gcs) or vendor-equivalent
 * PUT (azure-blob) that the client uploads against, with the body-
 * size cap baked into the signature so an oversize upload is
 * rejected by the object store, not by the framework process. Use
 * this — not `presignedUploadUrl` — when the upload size matters
 * and you can't trust the client. `result.enforcement` indicates
 * whether the cap is server-side (`"server"`) or client-only
 * (`"client-only"` — Azure SAS, where the operator must HEAD the
 * blob post-upload to reject oversize). `local` and `http-put`
 * backends throw `PRESIGN_NOT_SUPPORTED`.
 *
 * @opts
 *   classification:  string,    // route to a backend serving this classification
 *   backend:         string,    // explicit backend by name
 *   maxBytes:        number,    // body-size cap (required for size enforcement)
 *   expiresInSec:    number,    // policy lifetime; backend-defaulted when omitted
 *   contentType:     string,    // pin the upload Content-Type into the policy
 *
 * @example
 *   b.storage.init({
 *     backends: {
 *       "us-ops": {
 *         protocol:        "sigv4",
 *         endpoint:        "https://s3.us-east-1.amazonaws.com",
 *         region:          "us-east-1",
 *         bucket:          "uploads",
 *         accessKeyId:     "AKIAEXAMPLE",
 *         secretAccessKey: "secret",
 *         classifications: ["operational"],
 *         residencyTag:    "US",
 *       },
 *     },
 *   });
 *   var policy = b.storage.presignedUploadPolicy("user/avatar.png", {
 *     backend:      "us-ops",
 *     maxBytes:     5 * 1024 * 1024,   // 5 MiB cap, server-enforced
 *     expiresInSec: 300,
 *     contentType:  "image/png",
 *   });
 *   policy.enforcement;   // → "server"
 */
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

/**
 * @primitive b.storage.getBackend
 * @signature b.storage.getBackend(name)
 * @since     0.6.0
 * @status    stable
 * @related   b.storage.listBackends, b.storage.init
 *
 * Return the named backend instance from the underlying
 * `b.objectStore` adapter, or `null` when no backend with that
 * name is registered. Most operator code routes through the
 * dispatching primitives (`saveFile` / `getFileBuffer` / ...);
 * `getBackend` is the escape hatch for adapter-specific operations
 * (lifecycle policy ops, vendor-specific HEAD probes) the
 * framework does not abstract.
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var backend = b.storage.getBackend("default");
 *   backend.protocol;   // → "local"
 *   var missing = b.storage.getBackend("does-not-exist");
 *   // → null
 */
function getBackend(name) {
  _requireInit();
  return backends[name] || null;
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "storage.init() must be called before any file operation", true);
}

// ---- chunk-scratch -------------------------------------------------
//
// Resumable-chunked-upload primitive. Operators handling large file
// uploads (multipart form / tus / S3-multipart-style flow) need to
// persist incoming chunks during the upload window, then concatenate
// them in order when the upload completes. Without a framework
// primitive every consumer ended up reinventing the per-assembly
// directory layout + ordered gap-checked assembly + GC of partial
// assemblies that never completed.
//
// chunkScratch owns:
//   - per-assembly directory layout (sealed in the operator's
//     storage backend just like saveFile)
//   - chunk persistence + retrieval with the framework envelope
//   - assembly metadata tracking createdAt/totalChunks/chunkHashes
//   - ordered, gap-checked concat returning the assembled bytes for
//     the caller to persist (the primitive does not write a final file)
//   - GC of stale partial assemblies (operator opts in via gc())
//
// Backend is the same `b.storage` backend the operator already
// configured — chunkScratch routes through it. No new backend
// concept. The chunk keys are namespaced under
// `<rootKeyPrefix>/<assemblyId>/<chunkIndex>` so the operator can
// see them via the backend's existing list/inspect surface.
//
// assemblyId is operator-supplied (typically a UUID tied to the
// upload session). Shape is validated to refuse path-traversal,
// slash/backslash, NUL/C0/DEL, oversize. The chunkScratch primitive
// is identity-agnostic — it doesn't know which user owns which
// assembly; that gate is the operator's surrounding handler.

var ASSEMBLY_ID_MAX_LEN  = 128;
var CHUNK_INDEX_MAX      = 100000;                                                                  // chunk-index cap (not bytes, not seconds)
var CHUNK_BYTES_DEFAULT  = C.BYTES.mib(16);
var STALE_DEFAULT_MS     = C.TIME.hours(24);

function _stripTrailingSlashes(s) {
  // Linear-time alternative to `.replace(/\/+$/, "")` — CodeQL flags the
  // regex form as polynomial-ReDoS-vulnerable on inputs with many
  // trailing slashes (theoretical here since rootKeyPrefix is operator-
  // supplied at create-time, not request-bound, but using the explicit
  // loop avoids the regex-engine backtracking surface entirely).
  var end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x2F /* / */) end -= 1;
  return end === s.length ? s : s.slice(0, end);
}

function _validateAssemblyId(id) {
  if (typeof id !== "string" || id.length === 0) {
    throw _err("INVALID_ARGUMENT", "chunkScratch: assemblyId must be a non-empty string", true);
  }
  if (id.length > ASSEMBLY_ID_MAX_LEN) {
    throw _err("INVALID_ARGUMENT",
      "chunkScratch: assemblyId exceeds " + ASSEMBLY_ID_MAX_LEN + "-char cap", true);
  }
  for (var i = 0; i < id.length; i += 1) {
    var c = id.charCodeAt(i);
    // Refuse: C0 (0x00-0x1F), DEL (0x7F), slash, backslash, dot-prefix
    if (codepointClass.isForbiddenControlChar(c, { forbidTab: true }) || c === 0x2F || c === 0x5C) {
      throw _err("INVALID_ARGUMENT",
        "chunkScratch: assemblyId carries forbidden character at byte " + i, true);
    }
  }
  // Refuse path-traversal shapes — operator-supplied ID should be a
  // UUID-shape or opaque session token, not a path.
  if (id.indexOf("..") !== -1 || id.charAt(0) === ".") {
    throw _err("INVALID_ARGUMENT",
      "chunkScratch: assemblyId carries path-traversal shape", true);
  }
}

function _validateChunkIndex(idx) {
  if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0) {
    throw _err("INVALID_ARGUMENT",
      "chunkScratch: chunkIndex must be a non-negative integer", true);
  }
  if (idx >= CHUNK_INDEX_MAX) {
    throw _err("INVALID_ARGUMENT",
      "chunkScratch: chunkIndex exceeds cap " + CHUNK_INDEX_MAX, true);
  }
}

/**
 * @primitive b.storage.chunkScratch
 * @signature b.storage.chunkScratch(opts?)
 * @since     0.9.44
 * @status    stable
 * @related   b.storage.saveFile, b.storage.getFileBuffer
 *
 * Resumable-chunked-upload primitive. Persists incoming upload chunks
 * during the upload window, then concatenates them in order on
 * completion and returns the assembled bytes for the caller to persist
 * (the primitive does not itself write a final file). Owns per-assembly
 * directory layout, envelope-encrypted chunk persistence, ordered
 * gap-checked assembly, and GC of partial assemblies.
 *
 * Composes existing primitives: each chunk routes through
 * `b.storage.saveFile` (same XChaCha20-Poly1305 envelope as the
 * non-chunked surface), assembly reads through `getFileBuffer`,
 * deletion through `deleteFile`. No new crypto.
 *
 * Prior art / wire-protocol references:
 *   - tus.io v1.0.0 protocol (Termination + Creation + Concatenation
 *     extensions) — operator-facing HTTP shape that ships chunks
 *     against a server-side assembly. This primitive is the
 *     server-side persistence the tus protocol's upload handler
 *     consumes.
 *   - RFC 9110 §14.4 Content-Range — the wire-protocol header that
 *     PUT/PATCH-based resumable uploads use to declare each chunk's
 *     byte-range within the assembly.
 *   - draft-ietf-httpbis-resumable-upload-08 — IETF working-draft
 *     resumable-upload protocol; this primitive's surface mirrors
 *     its server-side state requirements.
 *   - AWS S3 Multipart Upload — the cloud-vendor analogue;
 *     `saveChunk` / `assemble` are the framework's local equivalents
 *     of UploadPart / CompleteMultipartUpload.
 *
 * Threat-model coverage:
 *   - Path-traversal in upload paths (CVE-2018-1000656 class) —
 *     `assemblyId` is validated to refuse `..`, `/`, `\`, NUL / C0
 *     controls, DEL, dot-prefix, and oversize. A hostile client
 *     can't escape the rootKeyPrefix namespace.
 *   - Chunk-out-of-order replay / TOCTOU between saveChunk and
 *     assemble — `assemble` verifies monotonic 0..N-1 indices and
 *     refuses on gaps; a chunk inserted out-of-order can't be
 *     surfaced as a valid assembly.
 *   - Storage exhaustion from abandoned uploads — `gc({ olderThanMs })`
 *     prunes stale assemblies; operator wires it on a schedule.
 *   - AEAD context-binding — each chunk's encryption envelope is
 *     keyed independently; an attacker who guesses one chunk's key
 *     can't decrypt other chunks in the same assembly (the
 *     XChaCha20-Poly1305 keys are framework-vault-derived per-call).
 *
 * assemblyId shape is validated to refuse path-traversal, control
 * chars, and oversize at every entry point.
 *
 * @opts
 *   rootKeyPrefix: string,   // default "chunk-scratch" — namespace under the backend
 *   backend:       string,   // explicit backend by name (default: framework default)
 *   maxChunkBytes: number,   // default 16 MiB — per-chunk cap
 *   staleAfterMs:  number,   // default 24h — assemblies idle longer get GC'd
 *
 * @example
 *   b.storage.init({ backend: "local", uploadDir: "./data/uploads" });
 *   var cs = b.storage.chunkScratch({ rootKeyPrefix: "uploads/scratch" });
 *
 *   // During upload — each PUT lands one chunk. saveChunk returns the
 *   // chunk's sealed encryptionKey; collect them in order for assemble.
 *   var keys = [];
 *   keys[0] = (await cs.saveChunk({ assemblyId: "upload-abc", chunkIndex: 0, data: chunk0 })).encryptionKey;
 *   keys[1] = (await cs.saveChunk({ assemblyId: "upload-abc", chunkIndex: 1, data: chunk1 })).encryptionKey;
 *   keys[2] = (await cs.saveChunk({ assemblyId: "upload-abc", chunkIndex: 2, data: chunk2 })).encryptionKey;
 *
 *   // On completion — concat the chunks (in order) into the assembled
 *   // buffer, then clean up. chunkEncryptionKeys is one key per chunk.
 *   var assembled = await cs.assemble({ assemblyId: "upload-abc", expectedTotal: 3, chunkEncryptionKeys: keys });
 *   await cs.removeAssembly("upload-abc");
 *
 *   // Periodic GC of partial uploads abandoned mid-stream
 *   var removed = await cs.gc({ olderThanMs: 86400000 });
 */
function chunkScratch(opts) {
  _requireInit();
  opts = opts || {};
  var rootKeyPrefix = typeof opts.rootKeyPrefix === "string" && opts.rootKeyPrefix.length > 0
    ? _stripTrailingSlashes(opts.rootKeyPrefix)
    : "chunk-scratch";
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.maxChunkBytes, "chunkScratch.maxChunkBytes", StorageError, "INVALID_ARGUMENT");
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.staleAfterMs, "chunkScratch.staleAfterMs", StorageError, "INVALID_ARGUMENT");
  var maxChunkBytes = opts.maxChunkBytes !== undefined ? opts.maxChunkBytes : CHUNK_BYTES_DEFAULT;
  var staleAfterMs  = opts.staleAfterMs  !== undefined ? opts.staleAfterMs  : STALE_DEFAULT_MS;
  var backendOverride = opts.backend;

  function _chunkKey(assemblyId, chunkIndex) {
    return rootKeyPrefix + "/" + assemblyId + "/" + String(chunkIndex).padStart(8, "0") + ".chunk";   // 8-digit zero-pad covers CHUNK_INDEX_MAX
  }
  function _pickOpts() {
    return backendOverride ? { backend: backendOverride } : {};
  }

  async function saveChunk(args) {
    if (!args || typeof args !== "object") {
      throw _err("INVALID_ARGUMENT", "chunkScratch.saveChunk: args must be an object", true);
    }
    _validateAssemblyId(args.assemblyId);
    _validateChunkIndex(args.chunkIndex);
    if (!Buffer.isBuffer(args.data)) {
      throw _err("INVALID_ARGUMENT", "chunkScratch.saveChunk: data must be a Buffer", true);
    }
    if (safeBuffer.byteLengthOf(args.data) > maxChunkBytes) {
      throw _err("INVALID_ARGUMENT",
        "chunkScratch.saveChunk: chunk exceeds maxChunkBytes (" + args.data.length + " > " + maxChunkBytes + ")", true);
    }
    var saved = await saveFile(args.data, _chunkKey(args.assemblyId, args.chunkIndex), _pickOpts());
    _emit("system.storage.chunk_scratch.chunk_saved", {
      metadata: {
        assemblyId: args.assemblyId,
        chunkIndex: args.chunkIndex,
        sizeBytes:  args.data.length,
        backend:    saved.backend,
      },
    });
    return { encryptionKey: saved.encryptionKey, sizeBytes: args.data.length };
  }

  async function getChunk(args) {
    if (!args || typeof args !== "object") {
      throw _err("INVALID_ARGUMENT", "chunkScratch.getChunk: args must be an object", true);
    }
    _validateAssemblyId(args.assemblyId);
    _validateChunkIndex(args.chunkIndex);
    if (typeof args.encryptionKey !== "string" || args.encryptionKey.length === 0) {
      throw _err("INVALID_ARGUMENT", "chunkScratch.getChunk: encryptionKey required", true);
    }
    return getFileBuffer(_chunkKey(args.assemblyId, args.chunkIndex),
      args.encryptionKey, _pickOpts());
  }

  async function chunkExists(args) {
    _validateAssemblyId(args.assemblyId);
    _validateChunkIndex(args.chunkIndex);
    return exists(_chunkKey(args.assemblyId, args.chunkIndex), _pickOpts());
  }

  async function listChunks(assemblyId) {
    _validateAssemblyId(assemblyId);
    var picked = _pickBackend(_pickOpts());
    if (typeof picked.backend.list !== "function") {
      throw _err("UNSUPPORTED",
        "chunkScratch.listChunks: backend '" + picked.backend.name + "' does not implement list()", true);
    }
    var prefix = rootKeyPrefix + "/" + assemblyId + "/";
    var listRes = await picked.backend.list(prefix);
    var items = listRes && Array.isArray(listRes.items) ? listRes.items
              : Array.isArray(listRes) ? listRes : [];
    var indices = [];
    for (var i = 0; i < items.length; i += 1) {
      // Backends return either { key, size, lastModified } objects
      // (local + S3 + GCS) or bare key strings. Normalize.
      var item = items[i];
      var rawKey = typeof item === "string" ? item : item && item.key;
      if (typeof rawKey !== "string") continue;
      // The local backend's `list(prefix)` returns keys relative to
      // the prefix; cloud backends return absolute keys. Normalize
      // by stripping the prefix when present.
      var base = rawKey.indexOf(prefix) === 0 ? rawKey.slice(prefix.length) : rawKey;
      if (base === ".meta" || base.indexOf("/") !== -1) continue;
      if (!/^[0-9]{1,8}\.chunk$/.test(base)) continue;
      indices.push(parseInt(base.slice(0, -6), 10));
    }
    indices.sort(function (a, b) { return a - b; });
    return indices;
  }

  async function countChunks(assemblyId) {
    var indices = await listChunks(assemblyId);
    return indices.length;
  }

  async function removeChunk(args) {
    _validateAssemblyId(args.assemblyId);
    _validateChunkIndex(args.chunkIndex);
    return deleteFile(_chunkKey(args.assemblyId, args.chunkIndex), _pickOpts());
  }

  async function assemble(args) {
    if (!args || typeof args !== "object") {
      throw _err("INVALID_ARGUMENT", "chunkScratch.assemble: args must be an object", true);
    }
    _validateAssemblyId(args.assemblyId);
    if (!Array.isArray(args.chunkEncryptionKeys) || args.chunkEncryptionKeys.length === 0) {
      throw _err("INVALID_ARGUMENT",
        "chunkScratch.assemble: chunkEncryptionKeys must be a non-empty array (one per chunk in order)", true);
    }
    var indices = await listChunks(args.assemblyId);
    if (typeof args.expectedTotal === "number" && indices.length !== args.expectedTotal) {
      throw _err("INCOMPLETE_ASSEMBLY",
        "chunkScratch.assemble: have " + indices.length + " chunks; expected " + args.expectedTotal, true);
    }
    if (indices.length !== args.chunkEncryptionKeys.length) {
      throw _err("INVALID_ARGUMENT",
        "chunkScratch.assemble: chunkEncryptionKeys.length (" + args.chunkEncryptionKeys.length +
        ") must match chunk count (" + indices.length + ")", true);
    }
    // Verify monotonic 0..N-1 indices — no gaps.
    for (var i = 0; i < indices.length; i += 1) {
      if (indices[i] !== i) {
        throw _err("INCOMPLETE_ASSEMBLY",
          "chunkScratch.assemble: chunk gap at index " + i + " (found " + indices[i] + ")", true);
      }
    }
    // Concatenate in order. Each chunk decrypts via its own envelope
    // key; the operator persisted the per-chunk key when saveChunk
    // returned it.
    var parts = [];
    var totalBytes = 0;
    for (var c = 0; c < indices.length; c += 1) {
      var buf = await getChunk({
        assemblyId:    args.assemblyId,
        chunkIndex:    c,
        encryptionKey: args.chunkEncryptionKeys[c],
      });
      parts.push(buf);
      totalBytes += buf.length;
    }
    _emit("system.storage.chunk_scratch.assembled", {
      metadata: {
        assemblyId: args.assemblyId,
        chunkCount: indices.length,
        sizeBytes:  totalBytes,
      },
    });
    return Buffer.concat(parts, totalBytes);
  }

  async function removeAssembly(assemblyId) {
    _validateAssemblyId(assemblyId);
    var indices = await listChunks(assemblyId);
    var removed = 0;
    for (var i = 0; i < indices.length; i += 1) {
      try { await removeChunk({ assemblyId: assemblyId, chunkIndex: indices[i] }); removed += 1; }
      catch (_e) { /* best-effort */ }
    }
    _emit("system.storage.chunk_scratch.removed", {
      metadata: { assemblyId: assemblyId, chunksRemoved: removed },
    });
    return { chunksRemoved: removed };
  }

  async function listAssemblies() {
    var picked = _pickBackend(_pickOpts());
    if (typeof picked.backend.list !== "function") {
      throw _err("UNSUPPORTED",
        "chunkScratch.listAssemblies: backend '" + picked.backend.name + "' does not implement list()", true);
    }
    var listRes = await picked.backend.list(rootKeyPrefix + "/");
    var items = listRes && Array.isArray(listRes.items) ? listRes.items
              : Array.isArray(listRes) ? listRes : [];
    var ids = {};
    var prefixWithSlash = rootKeyPrefix + "/";
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      var rawKey = typeof item === "string" ? item : item && item.key;
      if (typeof rawKey !== "string") continue;
      var rel = rawKey.indexOf(prefixWithSlash) === 0
        ? rawKey.slice(prefixWithSlash.length) : rawKey;
      var slash = rel.indexOf("/");
      if (slash === -1) continue;
      ids[rel.slice(0, slash)] = true;
    }
    return canonicalJson.sortKeys(ids);
  }

  async function listStaleAssemblies(args) {
    args = args || {};
    var olderThan = (typeof args.olderThanMs === "number" && args.olderThanMs > 0)
      ? args.olderThanMs : staleAfterMs;
    var cutoff = Date.now() - olderThan;
    var picked = _pickBackend(_pickOpts());
    if (typeof picked.backend.list !== "function") {
      throw _err("UNSUPPORTED",
        "chunkScratch.listStaleAssemblies: backend does not implement list()", true);
    }
    var assemblies = await listAssemblies();
    var stale = [];
    for (var i = 0; i < assemblies.length; i += 1) {
      var assemblyId = assemblies[i];
      // Use the earliest chunk's mtime as the assembly's createdAt
      // proxy. Backends that surface mtime via list() inspect items;
      // others fall through to a stat probe on the first chunk.
      var indices = await listChunks(assemblyId);
      if (indices.length === 0) { stale.push(assemblyId); continue; }
      var firstKey = _chunkKey(assemblyId, indices[0]);
      var stat = null;
      if (typeof picked.backend.stat === "function") {
        try { stat = await picked.backend.stat(firstKey); } catch (_e) { stat = null; }
      }
      var mtime = stat && (stat.mtimeMs || (stat.mtime && stat.mtime.getTime && stat.mtime.getTime()));
      if (typeof mtime === "number" && mtime < cutoff) {
        stale.push(assemblyId);
      }
    }
    return stale;
  }

  async function gc(args) {
    args = args || {};
    var stale = await listStaleAssemblies({ olderThanMs: args.olderThanMs });
    var removed = [];
    for (var i = 0; i < stale.length; i += 1) {
      try {
        var r = await removeAssembly(stale[i]);
        removed.push({ assemblyId: stale[i], chunksRemoved: r.chunksRemoved });
      } catch (_e) { /* best-effort GC */ }
    }
    _emit("system.storage.chunk_scratch.gc", {
      metadata: { staleCount: stale.length, removedCount: removed.length },
    });
    return { removed: removed };
  }

  return {
    saveChunk:           saveChunk,
    getChunk:            getChunk,
    chunkExists:         chunkExists,
    listChunks:          listChunks,
    countChunks:         countChunks,
    removeChunk:         removeChunk,
    assemble:            assemble,
    removeAssembly:      removeAssembly,
    listAssemblies:      listAssemblies,
    listStaleAssemblies: listStaleAssemblies,
    gc:                  gc,
  };
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
  listVersions:   listVersions,
  presignedUploadUrl:    presignedUploadUrl,
  presignedDownloadUrl:  presignedDownloadUrl,
  presignedUploadPolicy: presignedUploadPolicy,
  listBackends:   listBackends,
  getBackend:     getBackend,
  chunkScratch:   chunkScratch,
  _resetForTest:  _resetForTest,
};
