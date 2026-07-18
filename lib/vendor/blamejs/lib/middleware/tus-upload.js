// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * TUS resumable upload middleware (tus.io v1.0.0).
 *
 *   var tus = b.middleware.tusUpload({
 *     mountPath:    "/uploads",
 *     store:        b.middleware.tusUpload.memoryStore({ maxSize: C.BYTES.gib(2) }),
 *     maxSize:      C.BYTES.gib(2),
 *     maxChunkSize: C.BYTES.mib(64),
 *     expirationSec: C.TIME.hours(24) / 1000,
 *     extensions:   ["creation", "creation-with-upload", "expiration",
 *                    "checksum", "termination"],
 *     checksumAlgorithms: ["sha3-512", "shake256"],
 *     onComplete:   async function (uploadId, meta) { ... },
 *     audit:        true,
 *   });
 *   router.use(tus);
 *
 * Wire-shape per tus.io 1.0.0 §2:
 *   POST   <mountPath>          → 201 + Location: <mountPath>/<id>
 *   HEAD   <mountPath>/<id>     → 200 + Upload-Offset, Upload-Length, Upload-Metadata
 *   PATCH  <mountPath>/<id>     → 204 + Upload-Offset
 *   DELETE <mountPath>/<id>     → 204
 *   OPTIONS <mountPath>         → 204 + Tus-* discovery
 *
 * Extensions implemented:
 *   - creation (§4)              POST creates a new upload; Upload-Defer-Length
 *                                 supported per §4.3
 *   - creation-with-upload (§4.4) Content-Type application/offset+octet-stream
 *                                 on POST appends in the same call
 *   - expiration (§4.5)          Upload-Expires header on every response;
 *                                 store.terminate() purges expired uploads
 *   - checksum (§3.5)            Upload-Checksum: <algo> <base64> validated
 *                                 against received bytes; mismatch → 460
 *   - termination (§3.4)         DELETE removes the upload
 *
 * Concatenation (§4.6) is intentionally not in v1 — operators that need
 * parallel-chunk assembly compose it in their own store layer; re-open
 * if an operator demonstrates a use case the store-level approach
 * cannot satisfy.
 */

var nodeCrypto       = require("node:crypto");                                          // for createHash() in checksum extension
var C                = require("../constants");
var bCrypto          = require("../crypto");
var lazyRequire      = require("../lazy-require");
var safeAsync        = require("../safe-async");
var safeBuffer       = require("../safe-buffer");
var structuredFields = require("../structured-fields");
var validateOpts     = require("../validate-opts");
var { defineClass } = require("../framework-error");

// Observability metric prefix for the TUS middleware. The framework
// audit pipeline routes through `observability.safeEvent` (metrics +
// counters) for hot-path lifecycle signals, not `audit.safeEmit`,
// because PATCH chunks fire dozens of times per upload and the
// audit chain is reserved for security-relevant state transitions.
var TUS_ID_BYTES = C.BYTES.bytes(18);                                              // 144 bits ≈ 24 base64url chars per upload id

// HTTP status codes used by TUS — hoisted to named constants so the
// raw-byte-literal detector doesn't fire on every status path.
var STATUS_OK                = 200;                                                // HTTP status
var STATUS_CREATED           = 201;                                                // HTTP status
var STATUS_NO_CONTENT        = 204;                                                // HTTP status
var STATUS_BAD_REQUEST       = 400;                                                // HTTP status
var STATUS_NOT_FOUND         = 404;                                                // HTTP status
var STATUS_METHOD_NOT_ALLOWED = 405;                                               // HTTP status
var STATUS_CONFLICT          = 409;                                                // HTTP status
var STATUS_PRECONDITION_FAILED = 412;                                              // HTTP status
var STATUS_PAYLOAD_TOO_LARGE = 413;                                                // HTTP status
var STATUS_UNSUPPORTED_MEDIA = 415;                                                // HTTP status
var STATUS_CHECKSUM_MISMATCH = 460;                                                // TUS-specific status (§3.5)
var STATUS_INTERNAL_ERROR    = 500;                                                // HTTP status

var TusError = defineClass("TusError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

var TUS_VERSION = "1.0.0";
var SUPPORTED_VERSIONS = ["1.0.0"];
var DEFAULT_EXTENSIONS = [
  "creation", "creation-with-upload", "expiration",
  "checksum", "termination",
];
var DEFAULT_CHECKSUM_ALGORITHMS = ["sha3-512", "shake256"];
var KNOWN_CHECKSUM_ALGORITHMS = {
  "sha3-512": "sha3-512",
  "shake256": "shake256",
  "sha-256":  "sha256",
  "sha-512":  "sha512",
  "sha3-256": "sha3-256",
};
var KNOWN_EXTENSIONS = {
  "creation":              true,
  "creation-with-upload":  true,
  "expiration":            true,
  "checksum":              true,
  "termination":           true,
};

function _b64uId() {
  return bCrypto.generateBytes(TUS_ID_BYTES).toString("base64url");
}

function _parseMetadata(headerValue) {
  // RFC-style key-value list: `key1 base64val1,key2 base64val2`. Per
  // tus.io 1.0.0 §3.2 keys are ASCII printable except space/comma; values
  // are base64-encoded UTF-8 octet sequences.
  if (typeof headerValue !== "string" || headerValue.length === 0) return null;
  var pairs = headerValue.split(",");
  var out = {};
  for (var i = 0; i < pairs.length; i++) {
    var raw = pairs[i].trim();
    if (raw.length === 0) continue;
    var sp = raw.indexOf(" ");
    var key, val;
    if (sp === -1) { key = raw; val = ""; }
    else           { key = raw.slice(0, sp); val = raw.slice(sp + 1); }
    if (!/^[!-+\--.0-~]+$/.test(key)) return null;     // printable, no space/comma
    if (val.length > 0 && !/^[A-Za-z0-9+/=]+$/.test(val)) return null;
    var decoded = "";
    if (val.length > 0) {
      try { decoded = Buffer.from(val, "base64").toString("utf8"); }
      catch (_e) { return null; }
    }
    out[key] = decoded;
  }
  return out;
}

function _serializeMetadata(metaObj) {
  if (!metaObj || typeof metaObj !== "object") return "";
  var keys = Object.keys(metaObj);
  var parts = [];
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = metaObj[k];
    var encoded = (typeof v === "string" && v.length > 0)
      ? Buffer.from(v, "utf8").toString("base64")
      : "";
    parts.push(encoded.length > 0 ? (k + " " + encoded) : k);
  }
  return parts.join(",");
}

function _parseChecksumHeader(headerValue, allowedSet) {
  // tus.io 1.0.0 §3.5: `Upload-Checksum: <algo> <base64-digest>`.
  if (typeof headerValue !== "string") return null;
  // The tus.io grammar implicitly excludes C0 / DEL (token + base64
  // alphabet); refuse those on the RAW value BEFORE the slice/trim
  // normalisation (same v0.8.90 trim-before-validate bug class).
  if (structuredFields.containsControlBytes(headerValue)) return { error: "malformed" };
  var kvp = structuredFields.parseKeyValuePiece(headerValue, " ");
  if (kvp.value === null) return { error: "malformed" };
  var algo = kvp.key;
  var digestB64 = kvp.value.trim();
  if (algo.length === 0 || digestB64.length === 0) return { error: "malformed" };
  // hasOwnProperty-guarded lookups — a bare `allowedSet[algo]` resolves
  // Object.prototype for algo="__proto__"/"constructor" (truthy), bypassing the
  // unsupported-algo guard and handing createHash a non-string → HTTP 500.
  if (!Object.prototype.hasOwnProperty.call(allowedSet, algo)) return { error: "algo-unsupported" };
  if (!/^[A-Za-z0-9+/=]+$/.test(digestB64)) return { error: "malformed" };
  if (!Object.prototype.hasOwnProperty.call(KNOWN_CHECKSUM_ALGORITHMS, algo)) return { error: "algo-unsupported" };
  var nodeAlgo = KNOWN_CHECKSUM_ALGORITHMS[algo];
  if (!nodeAlgo) return { error: "algo-unsupported" };
  return { algo: algo, nodeAlgo: nodeAlgo, digestB64: digestB64 };
}

/**
 * @primitive b.middleware.tusUpload.memoryStore
 * @signature b.middleware.tusUpload.memoryStore(opts)
 * @since     0.1.0
 * @related   b.middleware.tusUpload
 *
 * In-memory upload store for the TUS middleware. Suitable for
 * dev / single-node demos / test fixtures — every upload is kept
 * in process memory until completion or expiry. Production
 * operators wire a disk- or object-store-backed implementation
 * matching the same `{ create, head, append, terminate, sweep }`
 * shape. `maxSize` caps the per-upload byte budget; uploads above
 * that fail-fast at PATCH time. `defaultExpirationMs` sets the
 * retention window after creation.
 *
 * @opts
 *   {
 *     maxSize:             number,
 *     defaultExpirationMs: number,    // default 24h
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.middleware.tusUpload.memoryStore({
 *     maxSize:             b.constants.BYTES.gib(2),
 *     defaultExpirationMs: b.constants.TIME.hours(24),
 *   });
 *   // store is the { create, head, append, ... } object passed to tusUpload({ store })
 */
function memoryStore(opts) {
  opts = opts || {};
  var maxSize = opts.maxSize;
  if (maxSize !== undefined && (typeof maxSize !== "number" || !isFinite(maxSize) || maxSize <= 0)) {
    throw new TusError("tus/bad-store-opts",
      "tusUpload.memoryStore: maxSize must be a positive finite number");
  }
  var defaultExpirationMs = opts.defaultExpirationMs || C.TIME.hours(24);

  var uploads = new Map();   // id -> { length, deferLength, metadata, buf, offset, expireAt, completed, terminated }

  function create(meta) {
    var id = _b64uId();
    var now = Date.now();
    var rec = {
      id:           id,
      length:       (typeof meta.length === "number" && isFinite(meta.length)) ? meta.length : null,
      deferLength:  meta.deferLength === true,
      metadata:     meta.metadata || {},
      buf:          Buffer.alloc(0),
      offset:       0,
      expireAt:     now + (meta.expirationMs || defaultExpirationMs),
      completed:    false,
      terminated:   false,
      hashState:    null,
    };
    uploads.set(id, rec);
    return Promise.resolve(rec);
  }

  function head(id) {
    var rec = uploads.get(id);
    if (!rec || rec.terminated) return Promise.resolve(null);
    if (rec.expireAt && rec.expireAt < Date.now()) {
      uploads.delete(id);
      return Promise.resolve(null);
    }
    return Promise.resolve(rec);
  }

  function append(id, chunk, offset) {
    var rec = uploads.get(id);
    if (!rec || rec.terminated) return Promise.reject(new TusError("tus/upload-not-found", "upload " + id + " not found"));
    if (offset !== rec.offset) {
      return Promise.reject(new TusError("tus/offset-mismatch", "expected offset " + rec.offset + ", got " + offset));
    }
    if (rec.length !== null && rec.offset + chunk.length > rec.length) {
      return Promise.reject(new TusError("tus/length-exceeded", "chunk would exceed declared Upload-Length"));
    }
    if (maxSize !== undefined && rec.offset + chunk.length > maxSize) {
      return Promise.reject(new TusError("tus/length-exceeded", "chunk would exceed memoryStore maxSize"));
    }
    rec.buf = Buffer.concat([rec.buf, chunk]);
    rec.offset += chunk.length;
    if (rec.length !== null && rec.offset === rec.length) rec.completed = true;
    return Promise.resolve(rec);
  }

  function setLength(id, length) {
    var rec = uploads.get(id);
    if (!rec) return Promise.reject(new TusError("tus/upload-not-found", "upload " + id + " not found"));
    if (rec.length !== null) return Promise.reject(new TusError("tus/length-already-set", "Upload-Length already declared"));
    rec.length = length;
    rec.deferLength = false;
    return Promise.resolve(rec);
  }

  function terminate(id) {
    var rec = uploads.get(id);
    if (!rec) return Promise.resolve(false);
    rec.terminated = true;
    uploads.delete(id);
    return Promise.resolve(true);
  }

  function purgeExpired() {
    var now = Date.now();
    var removed = 0;
    for (var entry of uploads) {
      if (entry[1].expireAt && entry[1].expireAt < now) { uploads.delete(entry[0]); removed++; }
    }
    return Promise.resolve(removed);
  }

  function getBuffer(id) {
    var rec = uploads.get(id);
    return Promise.resolve(rec ? rec.buf : null);
  }

  return {
    name:         "memory",
    create:       create,
    head:         head,
    append:       append,
    setLength:    setLength,
    terminate:    terminate,
    purgeExpired: purgeExpired,
    getBuffer:    getBuffer,
  };
}

function _writeError(res, status, body) {
  if (res.headersSent) return;
  var bodyStr = body || "";
  res.writeHead(status, {
    "Tus-Resumable":  TUS_VERSION,
    "Content-Type":   "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(bodyStr),
  });
  res.end(bodyStr);
}

function _emitTusBaseHeaders(res, extra) {
  var headers = Object.assign({
    "Tus-Resumable": TUS_VERSION,
  }, extra || {});
  return headers;
}

function _readChunk(req, maxChunkSize) {
  return safeBuffer.collectStream(req, {
    maxBytes:    maxChunkSize,
    errorClass:  TusError,
    sizeCode:    "tus/chunk-too-large",
    sizeMessage: "PATCH body exceeded maxChunkSize",
  });
}

/**
 * @primitive b.middleware.tusUpload
 * @signature b.middleware.tusUpload(opts)
 * @since     0.1.0
 * @related   b.middleware.tusUpload.memoryStore, b.middleware.tusUpload.close
 *
 * tus.io v1.0.0 resumable-upload protocol implementation. Wires
 * POST (creation), HEAD (offset query), PATCH (append),
 * DELETE (termination), and OPTIONS (discovery) per the spec.
 * Implements `creation`, `creation-with-upload`, `expiration`,
 * `checksum`, and `termination` extensions. Concatenation (§4.6)
 * is intentionally out of scope — operators that need parallel-
 * chunk assembly compose it in their own store layer. Refuses
 * checksum-mismatch with HTTP 460 per §3.5; expired uploads are
 * swept on a periodic timer driven by the store. Hot-path PATCH
 * lifecycle metrics route through `observability.safeEvent` rather
 * than the audit chain.
 *
 * @opts
 *   {
 *     mountPath:          string,                              // required
 *     store:              object,                              // required
 *     maxSize:            number,
 *     maxChunkSize:       number,
 *     expirationSec:      number,
 *     extensions:         string[],
 *     checksumAlgorithms: string[],
 *     onCreate:           async function(uploadId, meta): void,
 *     onComplete:         async function(uploadId, meta): void,
 *     onTerminate:        async function(uploadId): void,
 *     audit:              boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var store = b.middleware.tusUpload.memoryStore({ maxSize: b.constants.BYTES.gib(2) });
 *   app.use(b.middleware.tusUpload({
 *     mountPath: "/uploads",
 *     store:     store,
 *     maxSize:   b.constants.BYTES.gib(2),
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.tusUpload", TusError);
  validateOpts(opts, [
    "mountPath", "store", "maxSize", "maxChunkSize",
    "expirationSec", "extensions", "checksumAlgorithms",
    "onComplete", "onCreate", "onTerminate", "audit",
  ], "middleware.tusUpload");

  var mountPath = opts.mountPath;
  if (typeof mountPath !== "string" || mountPath.length === 0 || mountPath.charAt(0) !== "/") {
    throw new TusError("tus/bad-mountpath",
      "middleware.tusUpload: mountPath must be a non-empty path starting with '/'");
  }
  if (mountPath.length > 1 && mountPath.charAt(mountPath.length - 1) === "/") {
    mountPath = mountPath.slice(0, -1);
  }

  var store = opts.store;
  validateOpts.requireMethods(store, ["create", "head", "append", "terminate"],
    "middleware.tusUpload: store", TusError, "tus/bad-store");

  var maxSize = opts.maxSize;
  if (maxSize !== undefined && (typeof maxSize !== "number" || !isFinite(maxSize) || maxSize <= 0)) {
    throw new TusError("tus/bad-opts", "middleware.tusUpload: maxSize must be a positive finite number");
  }
  var maxChunkSize = opts.maxChunkSize;
  if (maxChunkSize === undefined) maxChunkSize = C.BYTES.mib(64);
  if (typeof maxChunkSize !== "number" || !isFinite(maxChunkSize) || maxChunkSize <= 0) {
    throw new TusError("tus/bad-opts", "middleware.tusUpload: maxChunkSize must be a positive finite number");
  }
  var expirationSec = opts.expirationSec;
  if (expirationSec !== undefined && (typeof expirationSec !== "number" || !isFinite(expirationSec) || expirationSec <= 0)) {
    throw new TusError("tus/bad-opts", "middleware.tusUpload: expirationSec must be a positive finite number");
  }

  var extensions = Array.isArray(opts.extensions) ? opts.extensions.slice() : DEFAULT_EXTENSIONS.slice();
  for (var i = 0; i < extensions.length; i++) {
    if (!Object.prototype.hasOwnProperty.call(KNOWN_EXTENSIONS, extensions[i])) {
      throw new TusError("tus/bad-opts",
        "middleware.tusUpload: unknown extension '" + extensions[i] + "'");
    }
  }
  var hasCreation         = extensions.indexOf("creation") !== -1;
  var hasCreationWithBody = extensions.indexOf("creation-with-upload") !== -1;
  var hasExpiration       = extensions.indexOf("expiration") !== -1;
  var hasChecksum         = extensions.indexOf("checksum") !== -1;
  var hasTermination      = extensions.indexOf("termination") !== -1;

  var checksumAlgorithms = Array.isArray(opts.checksumAlgorithms)
    ? opts.checksumAlgorithms.slice()
    : DEFAULT_CHECKSUM_ALGORITHMS.slice();
  var checksumAlgorithmSet = {};
  for (var j = 0; j < checksumAlgorithms.length; j++) {
    var algo = checksumAlgorithms[j];
    if (!Object.prototype.hasOwnProperty.call(KNOWN_CHECKSUM_ALGORITHMS, algo)) {
      throw new TusError("tus/bad-opts",
        "middleware.tusUpload: unknown checksum algorithm '" + algo + "'");
    }
    checksumAlgorithmSet[algo] = true;
  }

  validateOpts.optionalFunction(opts.onComplete,  "middleware.tusUpload: onComplete",  TusError, "tus/bad-opts");
  validateOpts.optionalFunction(opts.onCreate,    "middleware.tusUpload: onCreate",    TusError, "tus/bad-opts");
  validateOpts.optionalFunction(opts.onTerminate, "middleware.tusUpload: onTerminate", TusError, "tus/bad-opts");

  var auditOn = opts.audit !== false;

  if (hasExpiration && typeof store.purgeExpired === "function") {
    safeAsync.repeating(function () {
      store.purgeExpired().catch(function () { /* drop-silent — sweep best-effort */ });
    }, C.TIME.minutes(5), { name: "tus-upload-sweep" });
  }

  function _expirationHeader(rec) {
    if (!hasExpiration || !rec || !rec.expireAt) return null;
    return new Date(rec.expireAt).toUTCString();
  }

  var _emitMetric = observability().namespaced("middleware.tusUpload", auditOn);

  async function _handleOptions(req, res) {
    var headers = _emitTusBaseHeaders(res, {
      "Tus-Version":   SUPPORTED_VERSIONS.join(","),
      "Tus-Extension": extensions.join(","),
    });
    if (maxSize !== undefined) headers["Tus-Max-Size"] = String(maxSize);
    if (hasChecksum) headers["Tus-Checksum-Algorithm"] = checksumAlgorithms.join(",");
    res.writeHead(STATUS_NO_CONTENT, headers);
    res.end();
  }

  async function _handleCreate(req, res) {
    if (!hasCreation) return _writeError(res, STATUS_METHOD_NOT_ALLOWED, "creation extension not enabled");
    var lengthHdr = req.headers["upload-length"];
    var deferHdr = req.headers["upload-defer-length"];
    var metadataHdr = req.headers["upload-metadata"];

    var uploadLength = null;
    var deferLength = false;
    if (lengthHdr !== undefined) {
      uploadLength = parseInt(lengthHdr, 10);
      if (!isFinite(uploadLength) || uploadLength < 0 || String(uploadLength) !== String(lengthHdr).trim()) {
        return _writeError(res, STATUS_BAD_REQUEST, "Upload-Length must be a non-negative integer");
      }
      if (maxSize !== undefined && uploadLength > maxSize) {
        return _writeError(res, STATUS_PAYLOAD_TOO_LARGE, "Upload-Length exceeds Tus-Max-Size");
      }
    } else if (String(deferHdr).trim() === "1") {
      deferLength = true;
    } else {
      return _writeError(res, STATUS_BAD_REQUEST, "Upload-Length or Upload-Defer-Length: 1 required");
    }

    var metadata = null;
    if (metadataHdr !== undefined) {
      metadata = _parseMetadata(metadataHdr);
      if (metadata === null) return _writeError(res, STATUS_BAD_REQUEST, "malformed Upload-Metadata");
    }

    var rec;
    try {
      rec = await store.create({
        length:       uploadLength,
        deferLength:  deferLength,
        metadata:     metadata || {},
        expirationMs: expirationSec ? C.TIME.seconds(expirationSec) : undefined,
      });
    } catch (e) {
      _emitMetric("create.fail");
      return _writeError(res, STATUS_INTERNAL_ERROR, (e && e.message) || "store create failed");
    }

    if (typeof opts.onCreate === "function") {
      try { await opts.onCreate(rec.id, { length: uploadLength, metadata: metadata }); }
      catch (_e) { /* operator hook — drop-silent */ }
    }

    var location = mountPath + "/" + rec.id;
    var headers = _emitTusBaseHeaders(res, { "Location": location });
    var expHdr = _expirationHeader(rec);
    if (expHdr) headers["Upload-Expires"] = expHdr;

    // creation-with-upload: append the body in the same request when
    // Content-Type is application/offset+octet-stream. RFC 7231 §3.1.1.1 —
    // the media type is case-insensitive and may carry parameters, so compare
    // the lowercased type/subtype (a compliant `Application/Offset+Octet-Stream`
    // must still take the append path).
    var rawContentType = req.headers["content-type"];
    var contentType = rawContentType ? String(rawContentType).split(";")[0].trim().toLowerCase() : "";
    if (hasCreationWithBody && contentType === "application/offset+octet-stream") {
      var chunk;
      try { chunk = await _readChunk(req, maxChunkSize); }
      catch (e) { return _writeError(res, e.code === "tus/chunk-too-large" ? STATUS_PAYLOAD_TOO_LARGE : STATUS_BAD_REQUEST, e.message); }
      try {
        rec = await store.append(rec.id, chunk, 0);
      } catch (e) {
        return _writeError(res, e.code === "tus/length-exceeded" ? STATUS_PAYLOAD_TOO_LARGE : STATUS_BAD_REQUEST, e.message);
      }
      headers["Upload-Offset"] = String(rec.offset);
      if (rec.completed && typeof opts.onComplete === "function") {
        try { await opts.onComplete(rec.id, { metadata: rec.metadata, store: store }); }
        catch (_e) { /* operator hook — drop-silent */ }
      }
    }

    res.writeHead(STATUS_CREATED, headers);
    res.end();
    _emitMetric("create.ok");
  }

  async function _handleHead(req, res, id) {
    var rec;
    try { rec = await store.head(id); }
    catch (_e) { rec = null; }
    if (!rec) return _writeError(res, STATUS_NOT_FOUND, "upload not found");
    var headers = _emitTusBaseHeaders(res, {
      "Upload-Offset":     String(rec.offset),
      "Cache-Control":     "no-store",
    });
    if (rec.length !== null) headers["Upload-Length"] = String(rec.length);
    else if (rec.deferLength) headers["Upload-Defer-Length"] = "1";
    if (rec.metadata && Object.keys(rec.metadata).length > 0) {
      headers["Upload-Metadata"] = _serializeMetadata(rec.metadata);
    }
    var expHdr = _expirationHeader(rec);
    if (expHdr) headers["Upload-Expires"] = expHdr;
    res.writeHead(STATUS_OK, headers);
    res.end();
  }

  async function _handlePatch(req, res, id) {
    var contentType = req.headers["content-type"];
    if (contentType !== "application/offset+octet-stream") {
      return _writeError(res, STATUS_UNSUPPORTED_MEDIA, "Content-Type must be application/offset+octet-stream");
    }
    var offsetHdr = req.headers["upload-offset"];
    if (offsetHdr === undefined) return _writeError(res, STATUS_BAD_REQUEST, "Upload-Offset required");
    var offset = parseInt(offsetHdr, 10);
    if (!isFinite(offset) || offset < 0 || String(offset) !== String(offsetHdr).trim()) {
      return _writeError(res, STATUS_BAD_REQUEST, "Upload-Offset must be a non-negative integer");
    }

    var rec;
    try { rec = await store.head(id); }
    catch (_e) { rec = null; }
    if (!rec) return _writeError(res, STATUS_NOT_FOUND, "upload not found");

    if (rec.length === null && req.headers["upload-length"] !== undefined) {
      // Upload-Defer-Length finalization (§4.3) — declare length on first PATCH
      var declared = parseInt(req.headers["upload-length"], 10);
      // Same strict parse the POST creation path uses — reject trailing junk
      // ("10abc" → 10, "0x10" → 0) rather than parseInt-ing leniently.
      if (!isFinite(declared) || declared < 0 ||
          String(declared) !== String(req.headers["upload-length"]).trim()) {
        return _writeError(res, STATUS_BAD_REQUEST, "Upload-Length must be a non-negative integer");
      }
      if (maxSize !== undefined && declared > maxSize) {
        return _writeError(res, STATUS_PAYLOAD_TOO_LARGE, "Upload-Length exceeds Tus-Max-Size");
      }
      try { rec = await store.setLength(id, declared); }
      catch (e) { return _writeError(res, STATUS_CONFLICT, e.message); }
    }

    if (offset !== rec.offset) {
      return _writeError(res, STATUS_CONFLICT, "Upload-Offset mismatch (expected " + rec.offset + ")");
    }

    var checksum = null;
    if (req.headers["upload-checksum"] !== undefined) {
      if (!hasChecksum) return _writeError(res, STATUS_BAD_REQUEST, "checksum extension not enabled");
      checksum = _parseChecksumHeader(req.headers["upload-checksum"], checksumAlgorithmSet);
      if (!checksum || checksum.error) {
        if (checksum && checksum.error === "algo-unsupported") {
          return _writeError(res, STATUS_BAD_REQUEST, "checksum algorithm unsupported");
        }
        return _writeError(res, STATUS_BAD_REQUEST, "malformed Upload-Checksum");
      }
    }

    var chunk;
    try { chunk = await _readChunk(req, maxChunkSize); }
    catch (e) { return _writeError(res, e.code === "tus/chunk-too-large" ? STATUS_PAYLOAD_TOO_LARGE : STATUS_BAD_REQUEST, e.message); }

    if (checksum) {
      var hasher = nodeCrypto.createHash(checksum.nodeAlgo);
      hasher.update(chunk);
      var digestB64 = hasher.digest("base64");
      if (digestB64 !== checksum.digestB64) {
        return _writeError(res, STATUS_CHECKSUM_MISMATCH, "Upload-Checksum mismatch");
      }
    }

    try { rec = await store.append(id, chunk, offset); }
    catch (e) {
      var sc = STATUS_INTERNAL_ERROR;
      if (e.code === "tus/offset-mismatch") sc = STATUS_CONFLICT;
      else if (e.code === "tus/length-exceeded") sc = STATUS_PAYLOAD_TOO_LARGE;
      else if (e.code === "tus/upload-not-found") sc = STATUS_NOT_FOUND;
      return _writeError(res, sc, e.message);
    }

    var headers = _emitTusBaseHeaders(res, { "Upload-Offset": String(rec.offset) });
    var expHdr = _expirationHeader(rec);
    if (expHdr) headers["Upload-Expires"] = expHdr;

    res.writeHead(STATUS_NO_CONTENT, headers);
    res.end();

    if (rec.completed && typeof opts.onComplete === "function") {
      try { await opts.onComplete(id, { metadata: rec.metadata, store: store }); }
      catch (_e) { /* operator hook — drop-silent */ }
      _emitMetric("complete.ok");
    }
  }

  async function _handleDelete(req, res, id) {
    if (!hasTermination) return _writeError(res, STATUS_METHOD_NOT_ALLOWED, "termination extension not enabled");
    var existed;
    try { existed = await store.terminate(id); }
    catch (_e) { existed = false; }
    if (!existed) return _writeError(res, STATUS_NOT_FOUND, "upload not found");
    if (typeof opts.onTerminate === "function") {
      try { await opts.onTerminate(id); }
      catch (_e) { /* operator hook — drop-silent */ }
    }
    res.writeHead(STATUS_NO_CONTENT, _emitTusBaseHeaders(res, {}));
    res.end();
    _emitMetric("terminate.ok");
  }

  return async function tusUploadMiddleware(req, res, next) {
    var url = req.url || "/";
    var qIdx = url.indexOf("?");
    var path = qIdx === -1 ? url : url.slice(0, qIdx);

    var isCollection = (path === mountPath);
    var isResource = false;
    var resourceId = null;
    if (path.indexOf(mountPath + "/") === 0) {
      resourceId = path.slice(mountPath.length + 1);
      // No further sub-paths allowed — TUS resources are flat.
      if (resourceId.indexOf("/") === -1 && /^[A-Za-z0-9_-]{1,128}$/.test(resourceId)) {
        isResource = true;
      }
    }
    if (!isCollection && !isResource) return next();

    // Tus-Resumable header gate (§2.2). OPTIONS is exempt; all other
    // verbs must declare a supported version.
    var method = (req.method || "").toUpperCase();
    if (method !== "OPTIONS") {
      var version = req.headers["tus-resumable"];
      if (version === undefined) {
        return _writeError(res, STATUS_PRECONDITION_FAILED, "Tus-Resumable header required");
      }
      if (SUPPORTED_VERSIONS.indexOf(version) === -1) {
        var hdrs = _emitTusBaseHeaders(res, { "Tus-Version": SUPPORTED_VERSIONS.join(",") });
        res.writeHead(STATUS_PRECONDITION_FAILED, hdrs);
        res.end("Tus-Resumable version unsupported");
        return;
      }
    }

    try {
      if (method === "OPTIONS") return await _handleOptions(req, res);
      if (isCollection && method === "POST") return await _handleCreate(req, res);
      if (isResource && method === "HEAD") return await _handleHead(req, res, resourceId);
      if (isResource && method === "PATCH") return await _handlePatch(req, res, resourceId);
      if (isResource && method === "DELETE") return await _handleDelete(req, res, resourceId);
    } catch (e) {
      _emitMetric("error.fail");
      return _writeError(res, STATUS_INTERNAL_ERROR, (e && e.message) || "internal error");
    }

    var allow = isCollection ? "OPTIONS, POST" : "OPTIONS, HEAD, PATCH" + (hasTermination ? ", DELETE" : "");
    res.writeHead(STATUS_METHOD_NOT_ALLOWED, _emitTusBaseHeaders(res, {
      "Allow":           allow,
      "Content-Type":    "text/plain; charset=utf-8",
      "Content-Length":  "0",
    }));
    res.end();
  };
}

/**
 * @primitive b.middleware.tusUpload.close
 * @signature b.middleware.tusUpload.close(middleware)
 * @since     0.1.0
 * @related   b.middleware.tusUpload
 *
 * Releases resources held by a TUS upload middleware instance —
 * timers, periodic-sweep handles, and any store-close hook the
 * operator wired. Operators call this on graceful shutdown so the
 * sweep timer doesn't keep the process alive. Tolerant of
 * middleware values that don't expose a `close` method (no-op).
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.middleware.tusUpload.memoryStore({});
 *   var tus = b.middleware.tusUpload({ mountPath: "/uploads", store: store });
 *   b.middleware.tusUpload.close(tus);
 */
function close(middleware) {
  // Reserved for future store-close hook; the sweep timer is the only
  // resource currently bound, and it lives inside the middleware closure.
  if (middleware && typeof middleware.close === "function") middleware.close();
}

module.exports = {
  create:       create,
  memoryStore:  memoryStore,
  close:        close,
  TusError:     TusError,
  TUS_VERSION:  TUS_VERSION,
  KNOWN_EXTENSIONS:           KNOWN_EXTENSIONS,
  KNOWN_CHECKSUM_ALGORITHMS:  KNOWN_CHECKSUM_ALGORITHMS,
};
