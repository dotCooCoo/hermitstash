// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.fileUpload
 * @nav    HTTP
 * @title  File Upload
 *
 * @intro
 *   Streaming multipart upload with content-safety guards wired on
 *   by default. Init / acceptChunk / finalize lifecycle: operator
 *   calls `init` to allocate per-upload staging, streams chunks via
 *   `acceptChunk` (each carrying its own SHA3-512 hex), then calls
 *   `finalize` with a manifest so the framework can verify per-chunk
 *   + total hash, sniff magic bytes against an `allowedFileTypes`
 *   allowlist, and hand off to the operator's `onFinalize` (buffer
 *   for small uploads, Readable stream above `maxStreamReassemblyBytes`).
 *
 *   Default-on safety: `b.guardAll.byExtension({ profile: "strict" })`
 *   for content gating and `b.guardFilename.gate({ profile: "strict" })`
 *   for filename gating. Operators opt out via `contentSafety: null`
 *   / `filenameSafety: null` (audited at create time so a security
 *   review can find the disabled-on-deploy rows). The byte-level
 *   content gate inspects the reassembled buffer, so it runs on uploads
 *   up to `maxStreamReassemblyBytes` (default 64 MiB); a larger upload
 *   is handed to `onFinalize` as a stream and the byte-content gate is
 *   skipped (MIME-sniff + filename gates still run). Every skip path —
 *   the upload streamed past the reassembly cap, no gate is registered
 *   for the file's extension, or `contentSafety: null` disabled scanning
 *   — emits a `fileUpload.content_safety_skipped` audit whose `reason`
 *   names the cause, so a security review of the audit log can tell which
 *   uploads reached storage without a content scan and why. To guarantee
 *   content-gating of a type, cap `maxFileBytes` at or below
 *   `maxStreamReassemblyBytes`. Per-chunk hooks
 *   (`onChunk`) are the integration point for virus scanners and
 *   schema-shape checks; rejecting from the hook surfaces as a
 *   permanent `FileUploadError`.
 *
 *   Quotas: `maxFileBytes`, `maxChunkBytes`, `maxStagingBytes`,
 *   `maxActiveUploadsPerActor`, `maxChunks`, `incompleteTtlMs`,
 *   `maxIdleMs`. `purgeIncomplete()` reclaims TTL'd / idle staging
 *   directories — operators wire it to `b.scheduler` for a cron-shaped
 *   sweep. Permission scopes (`fileUpload.init` / `accept` / `finalize`
 *   / `status` / `list` / `cancel`) are checked through `b.permissions`
 *   when wired.
 *
 * @card
 *   Streaming multipart upload with content-safety guards wired on by default.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeStream = require("node:stream");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var bCrypto = require("./crypto");
var gateContract = require("./gate-contract");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var requestHelpers = require("./request-helpers");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { FileUploadError } = require("./framework-error");

// guard-* family is wired on by default; lazy-loaded to avoid eager
// import cycles (guards consume framework primitives that may not be
// resolved at file-upload load-time).
var guardAll      = lazyRequire(function () { return require("./guard-all"); });
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });

var _err = FileUploadError.factory;

var DEFAULTS = Object.freeze({
  maxFileBytes:               C.BYTES.gib(2),
  maxChunkBytes:              C.BYTES.mib(8),
  maxStreamReassemblyBytes:   C.BYTES.mib(64),
  maxStagingBytes:            C.BYTES.gib(50),
  maxActiveUploadsPerActor:   0x10,
  maxChunks:                  0x4000,
  incompleteTtlMs:            C.TIME.hours(24),
  maxIdleMs:                  C.TIME.minutes(30),
  allowedFileTypes:           Object.freeze([]),
});

var SHA3_512_HEX_LENGTH = C.BYTES.bytes(128);
var SIDECAR_MAX_BYTES = C.BYTES.kib(256);
var METADATA_MAX_BYTES = C.BYTES.kib(64);

var UPLOAD_ID_RE = /^[A-Za-z0-9._-]+$/;
var UPLOAD_ID_MAX_LENGTH = C.BYTES.bytes(128);

function _validateUploadId(id) {
  if (typeof id !== "string" ||
      id.length === 0 ||
      id.length > UPLOAD_ID_MAX_LENGTH ||
      id === "." || id === ".." ||
      !UPLOAD_ID_RE.test(id)) {
    var ID_PREVIEW_CHARS = C.BYTES.bytes(64);
    throw _err("file-upload/bad-upload-id",
      "fileUpload: uploadId must be 1-128 chars matching " + UPLOAD_ID_RE +
      " (path-traversal-hostile inputs refused before any filesystem op), got " +
      JSON.stringify(typeof id === "string" ? id.slice(0, ID_PREVIEW_CHARS) : id));
  }
  return id;
}

function _validateCreateOpts(opts) {
  validateOpts.shape(opts, {
    stagingDir: function (v, label) {
      validateOpts.requireNonEmptyString(v, label, FileUploadError);
      if (!nodePath.isAbsolute(v)) {
        throw _err("file-upload/bad-opt", "fileUpload.create: stagingDir must be an absolute path, got " +
          JSON.stringify(v));
      }
    },
    onFinalize: "optional-function",
    onChunk:    "optional-function",
    maxFileBytes:             "optional-positive-finite-int",
    maxChunkBytes:            "optional-positive-finite-int",
    maxStreamReassemblyBytes: "optional-positive-finite-int",
    maxStagingBytes:          "optional-positive-finite-int",
    maxActiveUploadsPerActor: "optional-positive-finite-int",
    maxChunks:                "optional-positive-finite-int",
    incompleteTtlMs:          "optional-non-negative-finite-int",
    maxIdleMs:                "optional-non-negative-finite-int",
    audit:         function (v) { validateOpts.auditShape(v, "fileUpload.create", FileUploadError); },
    observability: function (v) { validateOpts.observabilityShape(v, "fileUpload.create", FileUploadError); },
    clock:         "optional-function",
    allowedFileTypes: function (v, label) {
      validateOpts.optionalNonEmptyStringArray(v, label, FileUploadError, "file-upload/bad-opt");
      if (Array.isArray(v) && v.length > 0 &&
          (!opts.fileType || typeof opts.fileType.detect !== "function")) {
        throw _err("file-upload/bad-opt",
          "fileUpload.create: allowedFileTypes is set but fileType primitive is not wired " +
          "(pass fileType: b.fileType so the framework can sniff magic bytes at finalize)");
      }
    },
    permissions: function (v, label) {
      validateOpts.optionalObjectWithMethod(v, "check", label, FileUploadError, "file-upload/bad-opt",
        "must be a b.permissions instance (check fn)");
    },
    allowCrossActor: function (v, label) {
      validateOpts.optionalBoolean(v, label, FileUploadError, "file-upload/bad-opt");
    },
    contentSafety: function (v, label) {
      if (v === undefined || v === null) return;
      validateOpts.optionalPlainObject(v, label, FileUploadError, "file-upload/bad-opt",
        "must be a plain { ext: gate } object, null to opt out, or " +
        "undefined for the default-on b.guardAll wiring");
      var safetyKeys = Object.keys(v);
      for (var sk = 0; sk < safetyKeys.length; sk++) {
        var ext = safetyKeys[sk];
        var g = v[ext];
        if (!g || typeof g.check !== "function") {
          throw _err("file-upload/bad-opt",
            "fileUpload.create: contentSafety[" + JSON.stringify(ext) +
            "] must be a gate (b.guardCsv.gate / b.guardHtml.gate / etc.)");
        }
      }
    },
    filenameSafety: function (v, label) {
      if (v === undefined || v === null) return;
      validateOpts.optionalObjectWithMethod(v, "check", label, FileUploadError, "file-upload/bad-opt",
        "must be a gate (b.guardFilename.gate(...)), null to opt out, or " +
        "undefined for the default-on wiring");
    },
    fileType: function (v, label) {
      if (v === undefined || v === null) return;
      validateOpts.optionalObjectWithMethod(v, "detect", label, FileUploadError, "file-upload/bad-opt",
        "must be a b.fileType instance (detect fn)");
    },
    contentSafetyDisabledReason:  "optional-string",
    filenameSafetyDisabledReason: "optional-string",
  }, "fileUpload.create", FileUploadError, "file-upload/bad-opt", { exhaustive: true });
}

/**
 * @primitive b.fileUpload.create
 * @signature b.fileUpload.create(opts)
 * @since     0.7.2
 * @related   b.fileType.detect, b.fileType.assertOneOf
 *
 * Builds an upload manager bound to `opts.stagingDir`. The returned
 * object exposes `init`, `acceptChunk`, `finalize`, `status`, `list`,
 * `cancelUpload`, `purgeIncomplete`, and `close`. Uploads are written
 * chunk-per-file under a per-upload directory (mode 0o700); finalize
 * walks the manifest in order, verifies per-chunk + total SHA3-512,
 * runs the magic-byte allowlist (when `allowedFileTypes` is set), and
 * hands the assembled buffer (or a stream above `maxStreamReassemblyBytes`)
 * to the operator's `onFinalize`.
 *
 * Per-chunk and per-upload audits flow through the wired `audit` and
 * `observability` instances. Quota refusals, hash mismatches, MIME-claim
 * disagreement, filename-safety refusal, and content-safety refusal all
 * throw `FileUploadError` with `permanent: true` — no retry succeeds.
 *
 * @opts
 *   stagingDir:                string,                 // absolute path; created mode 0o700 if missing
 *   maxFileBytes:              number,                 // default 2 GiB
 *   maxChunkBytes:             number,                 // default 8 MiB
 *   maxStreamReassemblyBytes:  number,                 // above this finalize streams; default 64 MiB
 *   maxStagingBytes:           number,                 // default 50 GiB
 *   maxActiveUploadsPerActor:  number,                 // default 16
 *   maxChunks:                 number,                 // default 16384
 *   incompleteTtlMs:           number,                 // since createdAt; default 24h
 *   maxIdleMs:                 number,                 // since lastChunkAt; default 30m
 *   allowedFileTypes:          string[],               // MIME allowlist; "image/*" wildcard supported
 *   audit:                     b.audit,
 *   observability:             b.observability,
 *   permissions:               b.permissions,          // optional; gates init/accept/finalize/status/list/cancel
 *   allowCrossActor:           boolean,                // default false; admin escape hatch — bypasses per-upload ownership when the caller holds the "fileUpload.admin" scope
 *   fileType:                  b.fileType,             // required when allowedFileTypes is non-empty
 *   contentSafety:             Object | null,          // ext→gate map; null = audited opt-out; undefined = b.guardAll.byExtension({ profile: "strict" })
 *   filenameSafety:            Object | null,          // gate; null = audited opt-out; undefined = b.guardFilename.gate({ profile: "strict" })
 *   onChunk:                   async function (info),  // optional per-chunk hook
 *   onFinalize:                async function (info),  // operator decides final storage
 *   clock:                     function () → number,    // test-fixture clock; default Date.now
 *
 * @example
 *   var uploads = b.fileUpload.create({
 *     stagingDir:        "/var/lib/myapp/uploads",
 *     maxFileBytes:      C.BYTES.gib(2),
 *     allowedFileTypes:  ["image/png", "image/jpeg", "application/pdf"],
 *     fileType:          b.fileType,
 *     audit:             b.audit,
 *     observability:     b.observability,
 *     onFinalize:        async function (info) {
 *       // → info.body / info.stream → operator's storage layer
 *       return { ok: true, sha3: info.sha3, size: info.size };
 *     },
 *   });
 *
 *   await uploads.init({ uploadId: "u-1", actor: { id: "ada" }, metadata: { filename: "photo.png" } });
 *   // → { uploadId: "u-1", createdAt: 1762560000000, expiresAt: 1762646400000 }
 */
function create(opts) {
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var stagingDir              = opts.stagingDir;
  var onFinalize              = opts.onFinalize || null;
  var onChunk                 = opts.onChunk || null;
  var fileType                = opts.fileType || null;
  var permissions             = opts.permissions || null;
  var allowCrossActor         = opts.allowCrossActor === true;
  var contentSafety;
  if (opts.contentSafety === undefined) {
    contentSafety = guardAll().byExtension({
      profile:       "strict",
      audit:         opts.audit,
      observability: opts.observability,
    });
  } else if (opts.contentSafety === null) {
    if (opts.audit && typeof opts.audit.safeEmit === "function") {
      try {
        opts.audit.safeEmit({
          action:   "fileUpload.contentSafety.disabled",
          actor:    {},
          outcome:  "success",
          metadata: {
            reason: opts.contentSafetyDisabledReason || "operator-explicit-opt-out",
          },
        });
      } catch (_e) { /* audit best-effort */ }
    }
    contentSafety = null;
  } else {
    contentSafety = opts.contentSafety;
  }
  var filenameSafety;
  if (opts.filenameSafety === undefined) {
    filenameSafety = guardFilename().gate({
      profile:       "strict",
      audit:         opts.audit,
      observability: opts.observability,
    });
  } else if (opts.filenameSafety === null) {
    if (opts.audit && typeof opts.audit.safeEmit === "function") {
      try {
        opts.audit.safeEmit({
          action:   "fileUpload.filenameSafety.disabled",
          actor:    {},
          outcome:  "success",
          metadata: {
            reason: opts.filenameSafetyDisabledReason || "operator-explicit-opt-out",
          },
        });
      } catch (_e) { /* audit best-effort */ }
    }
    filenameSafety = null;
  } else {
    filenameSafety = opts.filenameSafety;
  }
  var maxFileBytes            = cfg.maxFileBytes;
  var maxChunkBytes           = cfg.maxChunkBytes;
  var maxStreamReassemblyBytes = cfg.maxStreamReassemblyBytes;
  var maxStagingBytes         = cfg.maxStagingBytes;
  var maxActiveUploadsPerActor = cfg.maxActiveUploadsPerActor;
  var maxChunks               = cfg.maxChunks;
  var incompleteTtlMs         = cfg.incompleteTtlMs;
  var maxIdleMs               = cfg.maxIdleMs;
  var allowedFileTypes        = cfg.allowedFileTypes;
  var audit                   = opts.audit || null;
  var clock                   = opts.clock || function () { return Date.now(); };

  var _emitAudit = validateOpts.makeAuditEmitter(audit);
  function _emitObs(name, value, labels) {
    if (opts.observability) opts.observability.safeEvent(name, value, labels || {});
  }

  // (drop-silent — by design) so a throwing sink never breaks the upload.
  function _emitContentSafetySkipped(uploadId, actor, reason, ext, size) {
    _emitObs("fileUpload.content_safety_skipped", 1, { reason: reason, ext: ext || "" });
    _emitAudit("fileUpload.content_safety_skipped", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      reason:   reason,
      metadata: { uploadId: uploadId, ext: ext || null, size: size, reason: reason },
    });
  }

  atomicFile.ensureDir(stagingDir, 0o700);

  function _uploadDir(uploadId) { return nodePath.join(stagingDir, uploadId); }
  function _chunkPath(uploadId, index) { return nodePath.join(_uploadDir(uploadId), String(index)); }
  function _receivedPath(uploadId) { return nodePath.join(_uploadDir(uploadId), "_received.json"); }
  function _metaPath(uploadId) { return nodePath.join(_uploadDir(uploadId), "_meta.json"); }

  function _checkPermission(action, actor) {
    if (!permissions) return;
    var allowed;
    try { allowed = permissions.check(actor, "fileUpload." + action); }
    catch (_e) { allowed = false; }
    if (!allowed) {
      _emitObs("fileUpload.permission_denied", 1, { action: action });
      throw _err("file-upload/permission-denied",
        "fileUpload." + action + ": actor lacks permission scope 'fileUpload." + action + "'");
    }
  }

  function _checkOwnership(action, actor, meta) {
    if (!meta) return;
    var callerKey = _actorKey(actor);
    if (meta.actorId === callerKey) return;
    if (allowCrossActor) {
      var adminOk = !permissions;
      if (permissions) {
        try { adminOk = permissions.check(actor, "fileUpload.admin"); }
        catch (_e) { adminOk = false; }
      }
      if (adminOk) return;
      _emitObs("fileUpload.permission_denied", 1, { action: "admin" });
      _emitAudit("fileUpload." + action, {
        actor:    requestHelpers.extractActorContext(actor),
        resource: { kind: "fileUpload", id: meta.uploadId },
        outcome:  "denied",
        reason:   "cross-actor-admin-scope-required",
        metadata: { uploadId: meta.uploadId, owner: meta.actorId,
                    caller: callerKey, action: action },
      });
      throw _err("file-upload/permission-denied",
        "fileUpload." + action + ": cross-actor access requires scope 'fileUpload.admin'");
    }
    _emitObs("fileUpload.ownership_violation", 1, { action: action });
    _emitAudit("fileUpload." + action, {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: meta.uploadId },
      outcome:  "denied",
      reason:   "ownership-violation",
      metadata: { uploadId: meta.uploadId, owner: meta.actorId,
                  caller: callerKey, action: action },
    });
    throw _err("file-upload/ownership-violation",
      "fileUpload." + action + ": actor does not own upload '" + meta.uploadId +
      "' (ownership enforced; set allowCrossActor + 'fileUpload.admin' scope for admin tooling)");
  }

  function _readReceivedIndices(uploadId) {
    var p = _receivedPath(uploadId);
    if (!nodeFs.existsSync(p)) return [];
    try {
      var raw = atomicFile.readSync(p, { maxBytes: SIDECAR_MAX_BYTES });
      var parsed = safeJson.parse(raw.toString("utf8"));
      return Array.isArray(parsed) ? parsed : [];
    } catch (_e) { return []; }
  }
  function _writeReceivedIndices(uploadId, indices) {
    atomicFile.writeSync(_receivedPath(uploadId), JSON.stringify(indices), { mode: 0o600 });
  }

  function _readMeta(uploadId) {
    var p = _metaPath(uploadId);
    if (!nodeFs.existsSync(p)) return null;
    try {
      var raw = atomicFile.readSync(p, { maxBytes: SIDECAR_MAX_BYTES });
      return safeJson.parse(raw.toString("utf8"));
    } catch (_e) { return null; }
  }
  function _writeMeta(uploadId, meta) {
    atomicFile.writeSync(_metaPath(uploadId), JSON.stringify(meta), { mode: 0o600 });
  }

  function _actorKey(actor) {
    return (actor && (actor.id || actor.userId)) || "_anonymous";
  }

  function _enumerateUploads() {
    if (!nodeFs.existsSync(stagingDir)) return [];
    var entries;
    try { entries = atomicFile.listDir(stagingDir, { includeStat: true }); }
    catch (_e) { return []; }
    var uploads = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e.isDirectory) continue;
      var meta = _readMeta(e.name);
      uploads.push({
        uploadId:    e.name,
        meta:        meta,
        mtimeMs:     e.mtimeMs,
      });
    }
    return uploads;
  }

  function _stagingTotalBytes() {
    var uploads = _enumerateUploads();
    var total = 0;
    for (var i = 0; i < uploads.length; i++) {
      total += (uploads[i].meta && uploads[i].meta.totalBytesAccepted) || 0;
    }
    return total;
  }

  function _activeUploadsForActor(actorId) {
    var uploads = _enumerateUploads();
    var count = 0;
    for (var i = 0; i < uploads.length; i++) {
      if (uploads[i].meta && uploads[i].meta.actorId === actorId) count += 1;
    }
    return count;
  }

  async function init(callerOpts) {
    validateOpts.requireObject(callerOpts, "fileUpload.init", FileUploadError);
    var uploadId = _validateUploadId(callerOpts.uploadId);
    var actor    = callerOpts.actor || null;
    var metadata = callerOpts.metadata !== undefined ? callerOpts.metadata : {};

    _checkPermission("init", actor);

    if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) {
      throw _err("file-upload/bad-metadata",
        "fileUpload.init: metadata must be a plain object (operator app-bag)");
    }
    var metadataJson = JSON.stringify(metadata);
    if (Buffer.byteLength(metadataJson, "utf8") > METADATA_MAX_BYTES) {
      throw _err("file-upload/metadata-too-large",
        "fileUpload.init: metadata exceeds " + METADATA_MAX_BYTES + " bytes");
    }

    if (nodeFs.existsSync(_uploadDir(uploadId))) {
      throw _err("file-upload/upload-exists",
        "fileUpload.init: upload '" + uploadId + "' already exists; cancel or finalize first");
    }

    var actorId = _actorKey(actor);
    if (_activeUploadsForActor(actorId) >= maxActiveUploadsPerActor) {
      _emitObs("fileUpload.actor_quota_exceeded", 1);
      throw _err("file-upload/actor-quota-exceeded",
        "fileUpload.init: actor '" + actorId + "' has " + maxActiveUploadsPerActor +
        " active uploads (cap maxActiveUploadsPerActor)");
    }
    if (_stagingTotalBytes() >= maxStagingBytes) {
      _emitObs("fileUpload.staging_quota_exceeded", 1);
      throw _err("file-upload/staging-quota-exceeded",
        "fileUpload.init: total staging exceeds " + maxStagingBytes + " bytes (maxStagingBytes)");
    }

    atomicFile.ensureDir(_uploadDir(uploadId), 0o700);
    var now = clock();
    var meta = {
      uploadId:             uploadId,
      actorId:              actorId,
      metadata:             metadata,
      createdAt:            now,
      lastChunkAt:          now,
      totalBytesAccepted:   0,
    };
    _writeMeta(uploadId, meta);
    _writeReceivedIndices(uploadId, []);

    _emitObs("fileUpload.init", 1);
    _emitAudit("fileUpload.init", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      metadata: { metadata: metadata },
    });

    return {
      uploadId:  uploadId,
      createdAt: now,
      expiresAt: now + incompleteTtlMs,
    };
  }

  async function acceptChunk(callerOpts) {
    validateOpts.requireObject(callerOpts, "fileUpload.acceptChunk", FileUploadError);
    var uploadId = _validateUploadId(callerOpts.uploadId);
    var index    = callerOpts.index;
    var body     = callerOpts.body;
    var sha3Hex  = callerOpts.sha3;
    var actor    = callerOpts.actor;

    _checkPermission("accept", actor);

    var meta = _readMeta(uploadId);
    if (!meta) {
      throw _err("file-upload/unknown-upload",
        "fileUpload.acceptChunk: no init() seen for '" + uploadId + "'; call init() first");
    }
    _checkOwnership("accept", actor, meta);
    if (clock() - meta.lastChunkAt > maxIdleMs) {
      throw _err("file-upload/upload-idle-expired",
        "fileUpload.acceptChunk: upload '" + uploadId + "' exceeded maxIdleMs (" + maxIdleMs +
        " ms since last chunk or init)");
    }

    if (!Number.isInteger(index) || index < 0 || index >= maxChunks) {
      throw _err("file-upload/bad-index",
        "fileUpload.acceptChunk: index must be a non-negative integer < " + maxChunks +
        ", got " + numericBounds.shape(index));
    }
    if (!Buffer.isBuffer(body)) {
      throw _err("file-upload/bad-body",
        "fileUpload.acceptChunk: body must be a Buffer, got " + typeof body);
    }
    if (body.length === 0) {
      throw _err("file-upload/empty-chunk",
        "fileUpload.acceptChunk: body is empty (0 bytes)");
    }
    if (safeBuffer.byteLengthOf(body) > maxChunkBytes) {
      _emitObs("fileUpload.chunk_too_large", 1);
      throw _err("file-upload/chunk-too-large",
        "fileUpload.acceptChunk: chunk body is " + body.length +
        " bytes, exceeds maxChunkBytes (" + maxChunkBytes + ")");
    }
    if (!safeBuffer.isHex(sha3Hex) || sha3Hex.length !== SHA3_512_HEX_LENGTH) {
      throw _err("file-upload/bad-chunk-hash",
        "fileUpload.acceptChunk: sha3 must be a SHA3-512 hex string (" +
        SHA3_512_HEX_LENGTH + " chars); got " +
        (typeof sha3Hex === "string" ? sha3Hex.length + " chars" : typeof sha3Hex));
    }

    var actualHex = bCrypto.sha3Hash(body);
    if (!bCrypto.timingSafeEqual(actualHex, sha3Hex)) {
      _emitObs("fileUpload.chunk_hash_mismatch", 1);
      _emitAudit("fileUpload.chunk_received", {
        actor:    requestHelpers.extractActorContext(actor),
        resource: { kind: "fileUpload", id: uploadId },
        outcome:  "failure",
        reason:   "chunk-hash-mismatch",
        metadata: { index: index, size: body.length },
      });
      throw _err("file-upload/chunk-hash-mismatch",
        "fileUpload.acceptChunk: chunk SHA3-512 mismatch — supplied does not equal computed");
    }

    if (onChunk) {
      try {
        await onChunk({
          uploadId: uploadId,
          index:    index,
          body:     body,
          sha3:     actualHex,
          actor:    actor,
          metadata: meta.metadata,
        });
      } catch (e) {
        _emitObs("fileUpload.onchunk_rejected", 1);
        _emitAudit("fileUpload.chunk_received", {
          actor:    requestHelpers.extractActorContext(actor),
          resource: { kind: "fileUpload", id: uploadId },
          outcome:  "failure",
          reason:   "onchunk-rejected",
          metadata: { index: index, size: body.length,
                      error: (e && e.message) || String(e) },
        });
        throw e;
      }
    }

    var p = _chunkPath(uploadId, index);
    if (nodeFs.existsSync(p)) {
      var existing = atomicFile.readSync(p, { maxBytes: maxChunkBytes });
      if (bCrypto.timingSafeEqual(bCrypto.sha3Hash(existing), sha3Hex)) {
        return {
          received:           _readReceivedIndices(uploadId).length,
          totalBytesAccepted: meta.totalBytesAccepted,
          status:             "in-progress",
          duplicate:          true,
        };
      }
      throw _err("file-upload/chunk-reuse-mismatch",
        "fileUpload.acceptChunk: chunk " + index +
        " already received with a different body (caller-side bug; refusing overwrite)");
    }

    atomicFile.writeSync(p, body, { mode: 0o600 });
    var receivedIndices = _readReceivedIndices(uploadId);
    if (receivedIndices.indexOf(index) === -1) {
      receivedIndices.push(index);
      _writeReceivedIndices(uploadId, receivedIndices);
    }

    meta.lastChunkAt = clock();
    meta.totalBytesAccepted = (meta.totalBytesAccepted || 0) + body.length;
    if (meta.totalBytesAccepted > maxFileBytes) {
      try { nodeFs.rmSync(_uploadDir(uploadId), { recursive: true, force: true }); }
      catch (_e) { /* purgeIncomplete will reclaim */ }
      _emitObs("fileUpload.file_too_large", 1);
      throw _err("file-upload/file-too-large",
        "fileUpload.acceptChunk: cumulative upload exceeded maxFileBytes (" + maxFileBytes +
        "); upload reclaimed");
    }
    _writeMeta(uploadId, meta);

    _emitObs("fileUpload.chunks_received", 1);
    _emitObs("fileUpload.bytes_received", body.length);
    _emitAudit("fileUpload.chunk_received", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      metadata: { index: index, size: body.length },
    });

    return {
      received:           receivedIndices.length,
      totalBytesAccepted: meta.totalBytesAccepted,
      status:             "in-progress",
    };
  }

  function _validateManifest(manifest) {
    validateOpts.requireObject(manifest, "fileUpload.finalize: manifest", FileUploadError);
    if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
      throw _err("file-upload/bad-manifest",
        "fileUpload.finalize: manifest.chunks must be a non-empty array");
    }
    if (manifest.chunks.length > maxChunks) {
      throw _err("file-upload/too-many-chunks",
        "fileUpload.finalize: manifest declares " + manifest.chunks.length +
        " chunks, exceeds maxChunks (" + maxChunks + ")");
    }
    if (!Number.isInteger(manifest.totalBytes) || manifest.totalBytes <= 0) {
      throw _err("file-upload/bad-manifest",
        "fileUpload.finalize: manifest.totalBytes must be a positive integer");
    }
    if (manifest.totalBytes > maxFileBytes) {
      throw _err("file-upload/file-too-large",
        "fileUpload.finalize: manifest.totalBytes (" + manifest.totalBytes +
        ") exceeds maxFileBytes (" + maxFileBytes + ")");
    }
    if (!safeBuffer.isHex(manifest.sha3) || manifest.sha3.length !== SHA3_512_HEX_LENGTH) {
      throw _err("file-upload/bad-manifest",
        "fileUpload.finalize: manifest.sha3 must be a SHA3-512 hex string (" +
        SHA3_512_HEX_LENGTH + " chars)");
    }
  }

  function _verifyChunksOnDisk(uploadId, manifest) {
    var sortedChunks = manifest.chunks.slice().sort(function (a, b) {
      return a.index - b.index;
    });
    var paths = [];
    var hasher = require("node:crypto").createHash("sha3-512");
    var totalBytes = 0;

    for (var i = 0; i < sortedChunks.length; i++) {
      var ck = sortedChunks[i];
      if (!Number.isInteger(ck.index) || ck.index !== i) {
        throw _err("file-upload/manifest-index-gap",
          "fileUpload.finalize: chunk " + i + " in manifest has index " + ck.index +
          " (expected " + i + " — chunk indices must be 0..N-1 contiguous)");
      }
      if (!safeBuffer.isHex(ck.sha3) || ck.sha3.length !== SHA3_512_HEX_LENGTH) {
        throw _err("file-upload/bad-manifest",
          "fileUpload.finalize: chunk " + i + ".sha3 must be a SHA3-512 hex string (" +
          SHA3_512_HEX_LENGTH + " chars)");
      }
      var chunkPath = _chunkPath(uploadId, ck.index);
      if (!nodeFs.existsSync(chunkPath)) {
        throw _err("file-upload/missing-chunk",
          "fileUpload.finalize: chunk " + ck.index + " missing from staging");
      }
      var chunkBody = atomicFile.readSync(chunkPath, { maxBytes: maxChunkBytes });
      var actualChunkHex = bCrypto.sha3Hash(chunkBody);
      if (!bCrypto.timingSafeEqual(actualChunkHex, ck.sha3)) {
        throw _err("file-upload/chunk-hash-mismatch",
          "fileUpload.finalize: chunk " + ck.index +
          " on-disk SHA3-512 doesn't match manifest");
      }
      paths.push(chunkPath);
      totalBytes += chunkBody.length;
      if (totalBytes > maxFileBytes) {
        throw _err("file-upload/file-too-large",
          "fileUpload.finalize: reassembly exceeds maxFileBytes mid-walk");
      }
      hasher.update(chunkBody);
    }
    if (totalBytes !== manifest.totalBytes) {
      throw _err("file-upload/manifest-size-mismatch",
        "fileUpload.finalize: reassembled " + totalBytes +
        " bytes, manifest declares " + manifest.totalBytes);
    }
    var totalHashHex = hasher.digest("hex");
    if (!bCrypto.timingSafeEqual(totalHashHex, manifest.sha3)) {
      throw _err("file-upload/manifest-hash-mismatch",
        "fileUpload.finalize: reassembled SHA3-512 doesn't match manifest.sha3");
    }
    return { paths: paths, totalBytes: totalBytes, totalHashHex: totalHashHex };
  }

  function _checkAllowedFileType(firstChunkBody, claimedMime) {
    if (!allowedFileTypes || allowedFileTypes.length === 0) return;
    if (!fileType) return;
    var detected = fileType.detect(firstChunkBody);
    var detectedMime = detected && detected.mime;
    if (!detectedMime) {
      throw _err("file-upload/mime-not-detected",
        "fileUpload.finalize: could not classify magic bytes against allowedFileTypes");
    }
    var ok = false;
    for (var i = 0; i < allowedFileTypes.length; i++) {
      var allowed = allowedFileTypes[i];
      if (allowed === detectedMime) { ok = true; break; }
      if (allowed.endsWith("/*")) {
        var prefix = allowed.slice(0, -1);
        if (detectedMime.indexOf(prefix) === 0) { ok = true; break; }
      }
    }
    if (!ok) {
      throw _err("file-upload/mime-not-allowed",
        "fileUpload.finalize: detected MIME '" + detectedMime +
        "' not in allowedFileTypes (" + allowedFileTypes.join(", ") + ")");
    }
    if (claimedMime && typeof claimedMime === "string" && claimedMime.indexOf("/") !== -1) {
      var claimedNormalized = claimedMime.split(";")[0].trim().toLowerCase();
      if (claimedNormalized && claimedNormalized !== detectedMime) {
        var claimedFamily = claimedNormalized.split("/")[0];
        var detectedFamily = detectedMime.split("/")[0];
        if (claimedFamily !== detectedFamily) {
          throw _err("file-upload/mime-claim-mismatch",
            "fileUpload.finalize: claimed Content-Type '" + claimedNormalized +
            "' disagrees with detected magic-byte MIME '" + detectedMime +
            "'. Refusing to proceed with mis-typed file.");
        }
      }
    }
  }

  function _streamFromChunkPaths(paths ) {
    async function* generate() {
      for (var i = 0; i < paths.length; i += 1) {
        var fh = nodeFs.createReadStream(paths[i]);
        for await (var chunk of fh) {
          yield chunk;
        }
      }
    }
    return nodeStream.Readable.from(generate(), { objectMode: false });
  }

  async function finalize(callerOpts) {
    validateOpts.requireObject(callerOpts, "fileUpload.finalize", FileUploadError);
    var uploadId = _validateUploadId(callerOpts.uploadId);
    var manifest = callerOpts.manifest;
    var actor    = callerOpts.actor;

    _checkPermission("finalize", actor);

    var meta = _readMeta(uploadId);
    if (!meta) {
      throw _err("file-upload/unknown-upload",
        "fileUpload.finalize: no init() seen for '" + uploadId + "'");
    }
    _checkOwnership("finalize", actor, meta);

    _validateManifest(manifest);

    var verified = _verifyChunksOnDisk(uploadId, manifest);

    var useStream = verified.totalBytes > maxStreamReassemblyBytes;
    var bodyBuffer = null;
    var bodyStream = null;
    var firstChunk = null;

    if (useStream) {
      firstChunk = atomicFile.readSync(verified.paths[0], { maxBytes: maxChunkBytes });
      bodyStream = _streamFromChunkPaths(verified.paths, verified.totalBytes);
    } else {
      var pieces = [];
      for (var i = 0; i < verified.paths.length; i++) {
        pieces.push(atomicFile.readSync(verified.paths[i], { maxBytes: maxChunkBytes }));
      }
      bodyBuffer = Buffer.concat(pieces, verified.totalBytes);
      firstChunk = pieces[0];
    }

    var claimedMime = (meta && meta.metadata && meta.metadata.contentType) || null;
    try { _checkAllowedFileType(firstChunk, claimedMime); }
    catch (e) {
      _emitObs("fileUpload.mime_rejected", 1);
      _emitAudit("fileUpload.finalize", {
        actor:    requestHelpers.extractActorContext(actor),
        resource: { kind: "fileUpload", id: uploadId },
        outcome:  "failure",
        reason:   "mime-not-allowed",
        metadata: { size: verified.totalBytes,
                    error: (e && e.message) || String(e) },
      });
      throw e;
    }

    var filename = (meta.metadata && meta.metadata.filename) || uploadId;
    if (filenameSafety && typeof filenameSafety.check === "function") {
      var fnDecision;
      try {
        fnDecision = await filenameSafety.check({
          filename:  filename,
          actor:     actor,
          direction: "inbound",
          metadata:  meta.metadata,
        });
      } catch (fnErr) {
        _emitObs("fileUpload.filename_safety_threw", 1);
        _emitAudit("fileUpload.finalize_failure", {
          actor:    requestHelpers.extractActorContext(actor),
          outcome:  "failure", reason: "filename-safety-threw",
          metadata: { uploadId: uploadId, error: fnErr && fnErr.message },
        });
        throw _err("file-upload/filename-safety-threw",
          "fileUpload.finalize: filenameSafety gate threw: " + (fnErr && fnErr.message));
      }
      if (!fnDecision.ok || fnDecision.action === "refuse") {
        _emitObs("fileUpload.filename_safety_refused", 1);
        _emitAudit("fileUpload.finalize_failure", {
          actor:    requestHelpers.extractActorContext(actor),
          outcome:  "failure", reason: "filename-safety-refused",
          metadata: {
            uploadId: uploadId, filename: filename,
            issues: gateContract.summarizeIssues(fnDecision.issues),
          },
        });
        throw _err("file-upload/filename-safety-refused",
          "fileUpload.finalize: filenameSafety refused " + JSON.stringify(filename) +
          ": " + gateContract.summarizeIssues(fnDecision.issues));
      }
      var cleanedName = fnDecision.sanitized || fnDecision.sanitizedFilename;
      if (fnDecision.action === "sanitize" && cleanedName) {
        cleanedName = String(cleanedName);
        meta.metadata = Object.assign({}, meta.metadata || {},
          { filename: cleanedName });
        filename = cleanedName;
      }
    }
    if (contentSafety) {
      var safetyExt = nodePath.extname(filename).toLowerCase();
      var gateExts = [safetyExt];
      var sniffBytes = bodyBuffer || firstChunk;
      if (fileType && sniffBytes) {
        var sniffed = fileType.detect(sniffBytes);
        if (sniffed && sniffed.extension) {
          var sniffedExt = "." + String(sniffed.extension).toLowerCase();
          if (sniffedExt !== safetyExt && gateExts.indexOf(sniffedExt) === -1) {
            gateExts.push(sniffedExt);
          }
        }
      }
      var contentSanitized = false;
      var _runContentSafetyGate = async function (gate, gateExt) {
        var safetyDecision;
        try {
          safetyDecision = await gate.check({
            bytes:    bodyBuffer,
            filename: filename,
            actor:    actor,
            direction: "inbound",
            metadata: meta.metadata,
          });
        } catch (gateErr) {
          _emitObs("fileUpload.content_safety_threw", 1);
          _emitAudit("fileUpload.finalize_failure", {
            actor:    requestHelpers.extractActorContext(actor),
            outcome:  "failure", reason: "content-safety-threw",
            metadata: { uploadId: uploadId, error: gateErr && gateErr.message },
          });
          throw _err("file-upload/content-safety-threw",
            "fileUpload.finalize: contentSafety gate threw: " + (gateErr && gateErr.message));
        }
        if (!safetyDecision.ok || safetyDecision.action === "refuse") {
          _emitObs("fileUpload.content_safety_refused", 1, { ext: gateExt });
          _emitAudit("fileUpload.finalize_failure", {
            actor:    requestHelpers.extractActorContext(actor),
            outcome:  "failure", reason: "content-safety-refused",
            metadata: {
              uploadId: uploadId, ext: gateExt,
              issues: gateContract.summarizeIssues(safetyDecision.issues),
            },
          });
          throw _err("file-upload/content-safety-refused",
            "fileUpload.finalize: contentSafety gate refused upload (" +
            (safetyDecision.issues || []).map(function (i) { return i.kind; }).join(", ") + ")");
        }
        if (safetyDecision.action === "sanitize" && safetyDecision.sanitized) {
          bodyBuffer = safetyDecision.sanitized;
          bodyStream = null;
          contentSanitized = true;
        }
      };
      var ranAnyGate = false;
      var hasGateButNoBody = false;
      for (var ge = 0; ge < gateExts.length; ge += 1) {
        var gateForExt = contentSafety[gateExts[ge]];
        if (gateForExt && typeof gateForExt.check === "function") {
          if (bodyBuffer) {
            await _runContentSafetyGate(gateForExt, gateExts[ge]);
            ranAnyGate = true;
          } else {
            hasGateButNoBody = true;
          }
        }
      }
      if (!ranAnyGate && hasGateButNoBody) {
        _emitContentSafetySkipped(uploadId, actor, "streamed-over-reassembly-cap",
                                  safetyExt, verified.totalBytes);
      } else if (!ranAnyGate) {
        _emitContentSafetySkipped(uploadId, actor, "no-gate-for-extension",
                                  safetyExt, verified.totalBytes);
      }
    } else {
      _emitContentSafetySkipped(uploadId, actor, "content-safety-disabled",
                                nodePath.extname(filename).toLowerCase(),
                                verified.totalBytes);
    }

    var deliveredSha3 = verified.totalHashHex;
    var deliveredSize = verified.totalBytes;
    if (contentSanitized && bodyBuffer) {
      deliveredSha3 = require("node:crypto").createHash("sha3-512").update(bodyBuffer).digest("hex");
      deliveredSize = bodyBuffer.length;
    }

    var rv;
    try {
      if (onFinalize) {
        rv = await onFinalize({
          uploadId: uploadId,
          body:     bodyBuffer,
          stream:   bodyStream,
          sha3:     deliveredSha3,
          size:     deliveredSize,
          actor:    actor,
          metadata: meta.metadata,
        });
      } else {
        rv = { ok: true, sha3: deliveredSha3, size: deliveredSize };
      }
    } catch (e) {
      _emitObs("fileUpload.finalize_failure", 1);
      _emitAudit("fileUpload.finalize", {
        actor:    requestHelpers.extractActorContext(actor),
        resource: { kind: "fileUpload", id: uploadId },
        outcome:  "failure",
        reason:   "onfinalize-threw",
        metadata: { size: deliveredSize, sha3: deliveredSha3,
                    error: (e && e.message) || String(e) },
      });
      throw e;
    }

    try { nodeFs.rmSync(_uploadDir(uploadId), { recursive: true, force: true }); }
    catch (_e) { /* best-effort */ }

    _emitObs("fileUpload.finalize_success", 1);
    _emitObs("fileUpload.finalize_bytes", deliveredSize);
    _emitAudit("fileUpload.finalize", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      metadata: { size: deliveredSize, sha3: deliveredSha3,
                  mode: useStream ? "stream" : "buffer" },
    });

    return rv;
  }

  function status(uploadId, callerOpts) {
    callerOpts = callerOpts || {};
    _validateUploadId(uploadId);
    _checkPermission("status", callerOpts.actor);
    var meta = _readMeta(uploadId);
    if (!meta) return null;
    _checkOwnership("status", callerOpts.actor, meta);
    var indices = _readReceivedIndices(uploadId).slice().sort(function (a, b) { return a - b; });
    return {
      uploadId:           uploadId,
      received:           indices,
      totalBytesAccepted: meta.totalBytesAccepted || 0,
      createdAt:          meta.createdAt,
      lastChunkAt:        meta.lastChunkAt,
      metadata:           meta.metadata || {},
      expiresAt:          meta.createdAt + incompleteTtlMs,
    };
  }

  function list(callerOpts) {
    callerOpts = callerOpts || {};
    _checkPermission("list", callerOpts.actor);
    var actorFilter = callerOpts.actor && (callerOpts.actor.id || callerOpts.actor.userId);
    var sinceMs     = (typeof callerOpts.since === "number") ? callerOpts.since : 0;
    var uploads     = _enumerateUploads();
    var out = [];
    for (var i = 0; i < uploads.length; i++) {
      var u = uploads[i];
      if (!u.meta) continue;
      if (sinceMs && u.meta.createdAt < sinceMs) continue;
      if (actorFilter && callerOpts.scopeToActor !== false && u.meta.actorId !== actorFilter) continue;
      out.push({
        uploadId:           u.meta.uploadId,
        actorId:            u.meta.actorId,
        metadata:           u.meta.metadata || {},
        createdAt:          u.meta.createdAt,
        lastChunkAt:        u.meta.lastChunkAt,
        totalBytesAccepted: u.meta.totalBytesAccepted || 0,
      });
    }
    return out;
  }

  async function cancelUpload(uploadId, callerOpts) {
    callerOpts = callerOpts || {};
    _validateUploadId(uploadId);
    _checkPermission("cancel", callerOpts.actor);
    var meta = _readMeta(uploadId);
    if (!meta) return { ok: false, uploadId: uploadId, reason: "not-found" };
    _checkOwnership("cancel", callerOpts.actor, meta);
    try { nodeFs.rmSync(_uploadDir(uploadId), { recursive: true, force: true }); }
    catch (_e) { /* best-effort */ }
    _emitObs("fileUpload.cancelled", 1);
    _emitAudit("fileUpload.cancelled", {
      actor:    requestHelpers.extractActorContext(callerOpts.actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      metadata: { totalBytesAccepted: meta.totalBytesAccepted || 0 },
    });
    return { ok: true, uploadId: uploadId };
  }

  function purgeIncomplete() {
    if (!nodeFs.existsSync(stagingDir)) return { purged: 0, ids: [] };
    var now = clock();
    var entries;
    try { entries = atomicFile.listDir(stagingDir, { includeStat: true }); }
    catch (_e) { return { purged: 0, ids: [] }; }
    var purged = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e.isDirectory) continue;
      var meta = _readMeta(e.name);
      var purgeReason = null;
      if (meta) {
        if (now - meta.createdAt > incompleteTtlMs) purgeReason = "ttl-exceeded";
        else if (now - meta.lastChunkAt > maxIdleMs) purgeReason = "idle-exceeded";
      } else {
        if (now - e.mtimeMs > incompleteTtlMs) purgeReason = "orphan";
      }
      if (!purgeReason) continue;
      try {
        nodeFs.rmSync(e.fullPath, { recursive: true, force: true });
        purged.push({ id: e.name, reason: purgeReason });
      } catch (_e2) { /* best-effort; will retry */ }
    }
    if (purged.length > 0) {
      _emitObs("fileUpload.purged_incomplete", purged.length);
      _emitAudit("fileUpload.purged", {
        actor:    { kind: "framework" },
        resource: { kind: "fileUpload", id: stagingDir },
        outcome:  "success",
        metadata: { purgedIds: purged.map(function (p) { return p.id; }),
                    count: purged.length },
      });
    }
    return {
      purged: purged.length,
      ids:    purged.map(function (p) { return p.id; }),
      reasons: purged,
    };
  }

  function close() {
    // Lifecycle parity. No timers / connections to release.
  }

  return {
    init:             init,
    acceptChunk:      acceptChunk,
    finalize:         finalize,
    status:           status,
    list:             list,
    cancelUpload:     cancelUpload,
    purgeIncomplete:  purgeIncomplete,
    close:            close,
  };
}

module.exports = {
  create:           create,
  FileUploadError:  FileUploadError,
  DEFAULTS:         DEFAULTS,
  UPLOAD_ID_RE:     UPLOAD_ID_RE,
};
