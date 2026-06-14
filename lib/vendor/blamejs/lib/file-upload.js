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
/**
 * b.fileUpload — chunked file upload primitive.
 *
 *   var uploads = b.fileUpload.create({
 *     stagingDir:                 "/var/lib/myapp/uploads",
 *     maxFileBytes:               C.BYTES.gib(2),
 *     maxChunkBytes:              C.BYTES.mib(8),
 *     maxStreamReassemblyBytes:   C.BYTES.mib(64),  // > this → stream onFinalize
 *     maxStagingBytes:            C.BYTES.gib(50),
 *     maxActiveUploadsPerActor:   5,
 *     maxChunks:                  16384,
 *     incompleteTtlMs:            C.TIME.hours(24),
 *     maxIdleMs:                  C.TIME.minutes(30),
 *     allowedFileTypes:           ["image/jpeg", "image/png", "application/pdf"],
 *     audit:                      b.audit,
 *     observability:              b.observability,
 *     permissions:                b.permissions,                // optional
 *     fileType:                   b.fileType,                    // optional — needed for allowedFileTypes
 *     onChunk:        async function (info) { ... },             // optional per-chunk hook
 *     onFinalize:     async function (info) { ... },             // operator decides final storage
 *   });
 *
 *   // Lifecycle:
 *   var initRv = await uploads.init({ uploadId, metadata, actor });
 *   await uploads.acceptChunk({ uploadId, index, body, sha3, actor });
 *   var rv = await uploads.finalize({ uploadId, manifest, actor });
 *
 *   // Operator dashboards:
 *   var st = uploads.status(uploadId, { actor });            // { received, totalBytesAccepted, createdAt, ... }
 *   var active = uploads.list({ actor });                    // active uploads for this actor
 *   await uploads.cancelUpload(uploadId, { actor });         // operator-cancel
 *
 *   // Periodic cleanup (wire to b.scheduler):
 *   await uploads.purgeIncomplete();   // → { purged, ids }
 *
 * Surface (returned by create):
 *
 *   init(opts)            → { uploadId, expiresAt, ... }
 *                           Allocates staging dir, stores metadata + actor +
 *                           createdAt. Required before acceptChunk. Permission-
 *                           checked: action "fileUpload.init".
 *
 *   acceptChunk(opts)     → { received, totalBytesAccepted, status }
 *                           Validates body length + per-chunk SHA3-512.
 *                           Per-chunk hook (onChunk) runs before write.
 *                           Permission-checked: action "fileUpload.accept".
 *                           Idempotent on re-PUT of same (uploadId, index)
 *                           with matching body.
 *
 *   finalize(opts)        → result of onFinalize (or framework default)
 *                           Walks chunks in manifest order, verifies per-chunk
 *                           + total SHA3-512, sniffs MIME (when fileType
 *                           wired) and gates against allowedFileTypes, hands
 *                           assembled buffer (or readable stream when size >
 *                           maxStreamReassemblyBytes) to onFinalize. Removes
 *                           staging dir on success. Permission-checked:
 *                           action "fileUpload.finalize".
 *
 *   status(uploadId, opts) → { received, totalBytesAccepted, createdAt,
 *                              lastChunkAt, metadata, expiresAt } | null
 *                           Permission-checked: action "fileUpload.status".
 *                           Returns null if upload not found.
 *
 *   list(opts)            → [{ uploadId, metadata, createdAt, lastChunkAt,
 *                              totalBytesAccepted, actor }]
 *                           Operator dashboards. Permission-checked: action
 *                           "fileUpload.list". Filter by actor + since.
 *
 *   cancelUpload(id,opts) → { ok, uploadId }
 *                           Force-removes staging. Permission-checked:
 *                           action "fileUpload.cancel".
 *
 *   purgeIncomplete()     → { purged: N, ids: [string] }
 *                           Reclaims staging dirs that exceeded
 *                           incompleteTtlMs (since createdAt) OR maxIdleMs
 *                           (since lastChunkAt). Operator wires to
 *                           b.scheduler or triggers on-demand.
 *
 *   close()               → void
 *                           Lifecycle parity with other framework primitives.
 *
 * Design posture:
 *
 *   - **init() before any chunk**: explicit lifecycle. Init records
 *     createdAt + actor + metadata + signing key in a per-upload sidecar
 *     so subsequent acceptChunk / finalize / status calls can authenticate
 *     and audit consistently.
 *
 *   - **Framework owns chunk lifecycle**, not final storage. Operator
 *     decides via `onFinalize` what to do with the assembled buffer
 *     OR streamed chunks. Framework doesn't dictate the storage layer.
 *
 *   - **SHA3-512** is the hash. PQC-first; SHA-256 is not offered.
 *     Per-chunk hash + total hash both verified.
 *
 *   - **Stream reassembly above maxStreamReassemblyBytes**: in-memory
 *     Buffer.concat of a 2 GiB upload would OOM the process. When the
 *     upload exceeds the threshold, finalize calls onFinalize with a
 *     readable stream reading the chunk files in order; the body
 *     parameter is null. Operator pipes to disk / S3 / etc.
 *
 *   - **MIME / file-type gate**: when allowedFileTypes is set and the
 *     fileType primitive is wired, finalize sniffs the assembled bytes
 *     (or first chunk for streamed uploads) and rejects if the magic
 *     bytes don't classify into one of the allowed types. Defense
 *     against `.exe disguised as .jpg` and similar mismatches.
 *
 *   - **Per-actor + total staging quotas**: maxActiveUploadsPerActor
 *     prevents one actor from holding open dozens of uploads;
 *     maxStagingBytes prevents the staging dir from filling the disk
 *     across all actors. Both checked at init() time before any
 *     filesystem allocation.
 *
 *   - **Permissions integration**: when `permissions` opt is wired,
 *     every operator-facing call checks the action via
 *     `permissions.check(actor, "fileUpload.<op>")` before acting.
 *     Action names: init / accept / finalize / status / list / cancel.
 *
 *   - **Tombstone cleanup**: purgeIncomplete() walks staging entries
 *     and reclaims those exceeding incompleteTtlMs (since createdAt)
 *     OR maxIdleMs (since lastChunkAt — for in-flight uploads
 *     abandoned mid-stream). Audit emission on every purge.
 *
 *   - **Validation errors are permanent**: chunk-hash mismatch,
 *     oversized chunk, oversized total file, manifest verification
 *     failure, MIME-type rejection, quota exhaustion all throw
 *     `FileUploadError` with `permanent: true` — no retry will
 *     succeed.
 *
 * Security defaults:
 *
 *   - Per-chunk SHA3-512 mandatory.
 *   - Upload ID format: 1-128 chars from [A-Za-z0-9._-]; hostile
 *     values (`..`, `/`, `\`, `\0`, glob chars) refused.
 *   - Staging dir mode 0o700.
 *   - allowedFileTypes default empty (no whitelist; operator opts in).
 *     When set without fileType primitive wired, finalize throws at
 *     create() — fail-fast on misconfig.
 *
 * What this primitive intentionally does NOT do:
 *
 *   - Resumable uploads via Range header — operator builds on top by
 *     reading status()'s `received` indices and resuming at index N+1
 *     client-side.
 *   - Direct browser → S3 presigned-PUT bypass — operators with that
 *     requirement use b.objectStore.presignedUploadUrl directly.
 *   - Background virus scanning — onChunk hook is the integration
 *     point. Operator wires their scanner of choice.
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
  // Empty array = no MIME allowlist gate (any type accepted).
  allowedFileTypes:           Object.freeze([]),
});

// SHA3-512 produces 64 bytes; named here so the chunk + manifest
// hash-shape checks read intentionally instead of as a raw 128.
var SHA3_512_HEX_LENGTH = C.BYTES.bytes(128);
// Cap on the bytes the per-upload sidecar files can grow to.
var SIDECAR_MAX_BYTES = C.BYTES.kib(256);
// Metadata cap — operators stash filename / mimeType / app-bag here.
// 64 KiB is generous for normal use and refuses payloads that look
// like the operator is trying to use the upload sidecar as a row store.
var METADATA_MAX_BYTES = C.BYTES.kib(64);

var UPLOAD_ID_RE = /^[A-Za-z0-9._-]+$/;
var UPLOAD_ID_MAX_LENGTH = C.BYTES.bytes(128);

function _validateUploadId(id) {
  if (typeof id !== "string" ||
      id.length === 0 ||
      id.length > UPLOAD_ID_MAX_LENGTH ||
      !UPLOAD_ID_RE.test(id)) {
    var ID_PREVIEW_CHARS = C.BYTES.bytes(64);
    throw _err("BAD_UPLOAD_ID",
      "fileUpload: uploadId must be 1-128 chars matching " + UPLOAD_ID_RE +
      " (path-traversal-hostile inputs refused before any filesystem op), got " +
      JSON.stringify(typeof id === "string" ? id.slice(0, ID_PREVIEW_CHARS) : id));
  }
  return id;
}

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "fileUpload.create", FileUploadError);
  validateOpts.requireNonEmptyString(opts.stagingDir, "fileUpload.create: stagingDir", FileUploadError);
  if (!nodePath.isAbsolute(opts.stagingDir)) {
    throw _err("BAD_OPT", "fileUpload.create: stagingDir must be an absolute path, got " +
      JSON.stringify(opts.stagingDir));
  }
  validateOpts.optionalFunction(opts.onFinalize, "fileUpload.create: onFinalize", FileUploadError);
  validateOpts.optionalFunction(opts.onChunk, "fileUpload.create: onChunk", FileUploadError);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxFileBytes", "maxChunkBytes", "maxStreamReassemblyBytes",
     "maxStagingBytes", "maxActiveUploadsPerActor"],
    "fileUpload.create", FileUploadError, "BAD_OPT");
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.incompleteTtlMs,
    "fileUpload.create: incompleteTtlMs", FileUploadError, "BAD_OPT");
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.maxIdleMs,
    "fileUpload.create: maxIdleMs", FileUploadError, "BAD_OPT");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxChunks,
    "fileUpload.create: maxChunks", FileUploadError, "BAD_OPT");
  validateOpts.auditShape(opts.audit, "fileUpload.create", FileUploadError);
  validateOpts.observabilityShape(opts.observability, "fileUpload.create", FileUploadError);
  validateOpts.optionalFunction(opts.clock, "fileUpload.create: clock", FileUploadError);
  // allowedFileTypes — operator's MIME allowlist. Empty / undefined
  // disables the gate. Setting it without wiring a fileType primitive
  // is a misconfig — the gate would have nothing to enforce against.
  validateOpts.optionalNonEmptyStringArray(opts.allowedFileTypes,
    "fileUpload.create: allowedFileTypes", FileUploadError, "BAD_OPT");
  if (Array.isArray(opts.allowedFileTypes) && opts.allowedFileTypes.length > 0 &&
      (!opts.fileType || typeof opts.fileType.detect !== "function")) {
    throw _err("BAD_OPT",
      "fileUpload.create: allowedFileTypes is set but fileType primitive is not wired " +
      "(pass fileType: b.fileType so the framework can sniff magic bytes at finalize)");
  }
  // permissions — when set, must expose check(actor, scope) → boolean.
  validateOpts.optionalObjectWithMethod(opts.permissions, "check",
    "fileUpload.create: permissions", FileUploadError, "BAD_OPT",
    "must be a b.permissions instance (check fn)");
  // contentSafety — extension-keyed gate map for per-extension content
  // validation. Default behaviour: when undefined, the framework wires
  // b.guardAll.byExtension({ profile: "strict" }) automatically so every
  // shipped guard is ON by default. Explicit opt-out: contentSafety:
  // null (audited at create() time so a security review can reconstruct
  // which deploys disabled the default-on protection).
  // Example: contentSafety: { ".csv": b.guardCsv.gate({ profile: "strict" }) }
  if (opts.contentSafety !== undefined && opts.contentSafety !== null) {
    validateOpts.optionalPlainObject(opts.contentSafety,
      "fileUpload.create: contentSafety", FileUploadError, "BAD_OPT",
      "must be a plain { ext: gate } object, null to opt out, or " +
      "undefined for the default-on b.guardAll wiring");
    var safetyKeys = Object.keys(opts.contentSafety);
    for (var sk = 0; sk < safetyKeys.length; sk++) {
      var ext = safetyKeys[sk];
      var g = opts.contentSafety[ext];
      if (!g || typeof g.check !== "function") {
        throw _err("BAD_OPT",
          "fileUpload.create: contentSafety[" + JSON.stringify(ext) +
          "] must be a gate (b.guardCsv.gate / b.guardHtml.gate / etc.)");
      }
    }
  }
  // filenameSafety — single gate for filename validation. Default: on.
  // Operator opts out with filenameSafety: null (audited).
  if (opts.filenameSafety !== undefined && opts.filenameSafety !== null) {
    validateOpts.optionalObjectWithMethod(opts.filenameSafety, "check",
      "fileUpload.create: filenameSafety", FileUploadError, "BAD_OPT",
      "must be a gate (b.guardFilename.gate(...)), null to opt out, or " +
      "undefined for the default-on wiring");
  }
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
  // ---- Default-on safety wiring ----
  // contentSafety: undefined → wire b.guardAll.byExtension({ profile: "strict" })
  // contentSafety: null      → explicit opt-out, audit row emitted
  // contentSafety: { ... }   → use operator-supplied map
  var contentSafety;
  if (opts.contentSafety === undefined) {
    // Strict profile is the security-correct default — every shipped
    // guard's full threat catalog refused, including dangerous tags
    // (script / style / iframe), event handlers, dangerous URL
    // schemes, formula injection, DOCTYPE / SVGZ / animation-href
    // hijack. Operators who need a broader content vocabulary opt up
    // explicitly via contentSafety: b.guardAll.byExtension({
    // profile: "balanced" | "permissive" }).
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
  // filenameSafety: undefined → b.guardFilename.gate({ profile: "strict" })
  // filenameSafety: null      → explicit opt-out, audit row emitted
  // filenameSafety: gate      → use operator-supplied gate
  var filenameSafety;
  if (opts.filenameSafety === undefined) {
    // Strict filename profile: ASCII-only, single-dot, 64-byte leaf
    // cap, refuses every shell-exec extension (.exe / .bat / .vbs /
    // .ps1 / .lnk / .scr / .dll / .so / .dmg / .msi / etc.). Operators
    // accepting Unicode filenames or executable-extension artifacts
    // opt up explicitly via filenameSafety: b.guardFilename.gate({
    // profile: "balanced" | "permissive" }).
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

  // Emit an audit row whenever the byte-level content-safety scan is
  // SKIPPED for a finalized upload — so a security review of the audit
  // log can tell that bytes reached storage without passing the
  // content gate, and WHY. Without this, every skip path (operator
  // opt-out, no gate registered for the file's extension, or the upload
  // streamed past maxStreamReassemblyBytes) was silent: the audit log
  // showed a clean `fileUpload.finalize` success indistinguishable from
  // a scanned upload. `reason` names the skip cause so operators can
  // alert / lower maxStreamReassemblyBytes / register the missing gate.
  // Observability-only: `_emitAudit` wraps audit.safeEmit in try/catch
  // (drop-silent — by design) so a throwing sink never breaks the upload.
  function _emitContentSafetySkipped(uploadId, actor, reason, ext, size) {
    _emitObs("fileUpload.content_safety_skipped", 1, { reason: reason, ext: ext || "" });
    // outcome "success" — the upload itself finalized; the audit records
    // that the byte-level scan did NOT run, with `reason` naming why
    // (the only outcomes the audit chain accepts are success / failure /
    // denied, so the skip-cause lives in `reason` + `metadata`).
    _emitAudit("fileUpload.content_safety_skipped", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      reason:   reason,
      metadata: { uploadId: uploadId, ext: ext || null, size: size, reason: reason },
    });
  }

  // Staging dir mode 0o700 — only the framework process reads its own
  // staging files.
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
      throw _err("PERMISSION_DENIED",
        "fileUpload." + action + ": actor lacks permission scope 'fileUpload." + action + "'");
    }
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
    // Actor identity for quota grouping. id field if present; otherwise
    // anonymous bucket. Operators with un-id'd actors share quota.
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

  // ---- init ----

  async function init(callerOpts) {
    validateOpts.requireObject(callerOpts, "fileUpload.init", FileUploadError);
    var uploadId = _validateUploadId(callerOpts.uploadId);
    var actor    = callerOpts.actor || null;
    var metadata = callerOpts.metadata !== undefined ? callerOpts.metadata : {};

    _checkPermission("init", actor);

    if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) {
      throw _err("BAD_METADATA",
        "fileUpload.init: metadata must be a plain object (operator app-bag)");
    }
    var metadataJson = JSON.stringify(metadata);
    if (Buffer.byteLength(metadataJson, "utf8") > METADATA_MAX_BYTES) {
      throw _err("METADATA_TOO_LARGE",
        "fileUpload.init: metadata exceeds " + METADATA_MAX_BYTES + " bytes");
    }

    // Refuse re-init of an existing upload (caller-side bug).
    if (nodeFs.existsSync(_uploadDir(uploadId))) {
      throw _err("UPLOAD_EXISTS",
        "fileUpload.init: upload '" + uploadId + "' already exists; cancel or finalize first");
    }

    var actorId = _actorKey(actor);
    if (_activeUploadsForActor(actorId) >= maxActiveUploadsPerActor) {
      _emitObs("fileUpload.actor_quota_exceeded", 1);
      throw _err("ACTOR_QUOTA_EXCEEDED",
        "fileUpload.init: actor '" + actorId + "' has " + maxActiveUploadsPerActor +
        " active uploads (cap maxActiveUploadsPerActor)");
    }
    if (_stagingTotalBytes() >= maxStagingBytes) {
      _emitObs("fileUpload.staging_quota_exceeded", 1);
      throw _err("STAGING_QUOTA_EXCEEDED",
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

  // ---- acceptChunk ----

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
      throw _err("UNKNOWN_UPLOAD",
        "fileUpload.acceptChunk: no init() seen for '" + uploadId + "'; call init() first");
    }
    if (clock() - meta.lastChunkAt > maxIdleMs) {
      // Idle-timed-out — too much time since init or last chunk.
      throw _err("UPLOAD_IDLE_EXPIRED",
        "fileUpload.acceptChunk: upload '" + uploadId + "' exceeded maxIdleMs (" + maxIdleMs +
        " ms since last chunk or init)");
    }

    if (!Number.isInteger(index) || index < 0 || index >= maxChunks) {
      throw _err("BAD_INDEX",
        "fileUpload.acceptChunk: index must be a non-negative integer < " + maxChunks +
        ", got " + numericBounds.shape(index));
    }
    if (!Buffer.isBuffer(body)) {
      throw _err("BAD_BODY",
        "fileUpload.acceptChunk: body must be a Buffer, got " + typeof body);
    }
    if (body.length === 0) {
      throw _err("EMPTY_CHUNK",
        "fileUpload.acceptChunk: body is empty (0 bytes)");
    }
    if (body.length > maxChunkBytes) {
      _emitObs("fileUpload.chunk_too_large", 1);
      throw _err("CHUNK_TOO_LARGE",
        "fileUpload.acceptChunk: chunk body is " + body.length +
        " bytes, exceeds maxChunkBytes (" + maxChunkBytes + ")");
    }
    if (!safeBuffer.isHex(sha3Hex) || sha3Hex.length !== SHA3_512_HEX_LENGTH) {
      throw _err("BAD_CHUNK_HASH",
        "fileUpload.acceptChunk: sha3 must be a SHA3-512 hex string (" +
        SHA3_512_HEX_LENGTH + " chars); got " +
        (typeof sha3Hex === "string" ? sha3Hex.length + " chars" : typeof sha3Hex));
    }

    // Verify chunk hash matches the supplied header.
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
      throw _err("CHUNK_HASH_MISMATCH",
        "fileUpload.acceptChunk: chunk SHA3-512 mismatch — supplied does not equal computed");
    }

    // Per-chunk operator hook (e.g. virus scan, schema check). May
    // throw to refuse the chunk.
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

    // Idempotent re-PUT: if this index is already received with a
    // matching body, no-op. Different body = caller bug.
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
      throw _err("CHUNK_REUSE_MISMATCH",
        "fileUpload.acceptChunk: chunk " + index +
        " already received with a different body (caller-side bug; refusing overwrite)");
    }

    atomicFile.writeSync(p, body, { mode: 0o600 });
    var receivedIndices = _readReceivedIndices(uploadId);
    if (receivedIndices.indexOf(index) === -1) {
      receivedIndices.push(index);
      _writeReceivedIndices(uploadId, receivedIndices);
    }

    // Update meta.
    meta.lastChunkAt = clock();
    meta.totalBytesAccepted = (meta.totalBytesAccepted || 0) + body.length;
    if (meta.totalBytesAccepted > maxFileBytes) {
      // Reclaim staging — the upload exceeded the cap mid-nodeStream.
      try { nodeFs.rmSync(_uploadDir(uploadId), { recursive: true, force: true }); }
      catch (_e) { /* purgeIncomplete will reclaim */ }
      _emitObs("fileUpload.file_too_large", 1);
      throw _err("FILE_TOO_LARGE",
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

  // ---- finalize ----

  function _validateManifest(manifest) {
    validateOpts.requireObject(manifest, "fileUpload.finalize: manifest", FileUploadError);
    if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
      throw _err("BAD_MANIFEST",
        "fileUpload.finalize: manifest.chunks must be a non-empty array");
    }
    if (manifest.chunks.length > maxChunks) {
      throw _err("TOO_MANY_CHUNKS",
        "fileUpload.finalize: manifest declares " + manifest.chunks.length +
        " chunks, exceeds maxChunks (" + maxChunks + ")");
    }
    if (!Number.isInteger(manifest.totalBytes) || manifest.totalBytes <= 0) {
      throw _err("BAD_MANIFEST",
        "fileUpload.finalize: manifest.totalBytes must be a positive integer");
    }
    if (manifest.totalBytes > maxFileBytes) {
      throw _err("FILE_TOO_LARGE",
        "fileUpload.finalize: manifest.totalBytes (" + manifest.totalBytes +
        ") exceeds maxFileBytes (" + maxFileBytes + ")");
    }
    if (!safeBuffer.isHex(manifest.sha3) || manifest.sha3.length !== SHA3_512_HEX_LENGTH) {
      throw _err("BAD_MANIFEST",
        "fileUpload.finalize: manifest.sha3 must be a SHA3-512 hex string (" +
        SHA3_512_HEX_LENGTH + " chars)");
    }
  }

  function _verifyChunksOnDisk(uploadId, manifest) {
    // Returns sorted chunk paths + verifies per-chunk + total hash.
    // For small uploads we walk + concat; for large we just walk and
    // verify, returning paths so the streaming path can read on
    // demand.
    var sortedChunks = manifest.chunks.slice().sort(function (a, b) {
      return a.index - b.index;
    });
    var paths = [];
    var hasher = require("node:crypto").createHash("sha3-512");
    var totalBytes = 0;

    for (var i = 0; i < sortedChunks.length; i++) {
      var ck = sortedChunks[i];
      if (!Number.isInteger(ck.index) || ck.index !== i) {
        throw _err("MANIFEST_INDEX_GAP",
          "fileUpload.finalize: chunk " + i + " in manifest has index " + ck.index +
          " (expected " + i + " — chunk indices must be 0..N-1 contiguous)");
      }
      if (!safeBuffer.isHex(ck.sha3) || ck.sha3.length !== SHA3_512_HEX_LENGTH) {
        throw _err("BAD_MANIFEST",
          "fileUpload.finalize: chunk " + i + ".sha3 must be a SHA3-512 hex string (" +
          SHA3_512_HEX_LENGTH + " chars)");
      }
      var chunkPath = _chunkPath(uploadId, ck.index);
      if (!nodeFs.existsSync(chunkPath)) {
        throw _err("MISSING_CHUNK",
          "fileUpload.finalize: chunk " + ck.index + " missing from staging");
      }
      var chunkBody = atomicFile.readSync(chunkPath, { maxBytes: maxChunkBytes });
      var actualChunkHex = bCrypto.sha3Hash(chunkBody);
      if (!bCrypto.timingSafeEqual(actualChunkHex, ck.sha3)) {
        throw _err("CHUNK_HASH_MISMATCH",
          "fileUpload.finalize: chunk " + ck.index +
          " on-disk SHA3-512 doesn't match manifest");
      }
      paths.push(chunkPath);
      totalBytes += chunkBody.length;
      if (totalBytes > maxFileBytes) {
        throw _err("FILE_TOO_LARGE",
          "fileUpload.finalize: reassembly exceeds maxFileBytes mid-walk");
      }
      hasher.update(chunkBody);
    }
    if (totalBytes !== manifest.totalBytes) {
      throw _err("MANIFEST_SIZE_MISMATCH",
        "fileUpload.finalize: reassembled " + totalBytes +
        " bytes, manifest declares " + manifest.totalBytes);
    }
    var totalHashHex = hasher.digest("hex");
    if (!bCrypto.timingSafeEqual(totalHashHex, manifest.sha3)) {
      throw _err("MANIFEST_HASH_MISMATCH",
        "fileUpload.finalize: reassembled SHA3-512 doesn't match manifest.sha3");
    }
    return { paths: paths, totalBytes: totalBytes, totalHashHex: totalHashHex };
  }

  function _checkAllowedFileType(firstChunkBody, claimedMime) {
    if (!allowedFileTypes || allowedFileTypes.length === 0) return;
    if (!fileType) return;   // create() guards this; defensive
    var detected = fileType.detect(firstChunkBody);
    var detectedMime = detected && detected.mime;
    if (!detectedMime) {
      throw _err("MIME_NOT_DETECTED",
        "fileUpload.finalize: could not classify magic bytes against allowedFileTypes");
    }
    var ok = false;
    for (var i = 0; i < allowedFileTypes.length; i++) {
      var allowed = allowedFileTypes[i];
      if (allowed === detectedMime) { ok = true; break; }
      // Wildcard support: "image/*" matches "image/png".
      if (allowed.endsWith("/*")) {
        var prefix = allowed.slice(0, -1);  // "image/"
        if (detectedMime.indexOf(prefix) === 0) { ok = true; break; }
      }
    }
    if (!ok) {
      throw _err("MIME_NOT_ALLOWED",
        "fileUpload.finalize: detected MIME '" + detectedMime +
        "' not in allowedFileTypes (" + allowedFileTypes.join(", ") + ")");
    }
    // Cross-check claimed MIME (Content-Type header) against detected
    // magic bytes. When both exist and disagree, refuse — downstream
    // renderers / storage layers that trust metadata.contentType
    // (CDN cache routing, MIME-sniff fallbacks, attachment-disposition
    // decisions) will mis-handle the file. The strict-MIME check is
    // load-bearing for image-pipelines that pass to image processors:
    // a "image/png" claim with PDF magic bytes lands in image-rendering
    // code-paths that will exec PDF parsers with surprising semantics.
    if (claimedMime && typeof claimedMime === "string" && claimedMime.indexOf("/") !== -1) {
      var claimedNormalized = claimedMime.split(";")[0].trim().toLowerCase();
      if (claimedNormalized && claimedNormalized !== detectedMime) {
        // Wildcard / family acceptance: "image/jpeg" claim + "image/jpg"
        // detect (synonyms) is OK; "image/png" claim + "image/jpeg"
        // detect is NOT.
        var claimedFamily = claimedNormalized.split("/")[0];
        var detectedFamily = detectedMime.split("/")[0];
        if (claimedFamily !== detectedFamily) {
          throw _err("MIME_CLAIM_MISMATCH",
            "fileUpload.finalize: claimed Content-Type '" + claimedNormalized +
            "' disagrees with detected magic-byte MIME '" + detectedMime +
            "'. Refusing to proceed with mis-typed file.");
        }
      }
    }
  }

  function _streamFromChunkPaths(paths /* totalBytes */) {
    // Sequential ReadableStream over chunk files. Operator's
    // onFinalize reads through to wherever they're piping.
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
      throw _err("UNKNOWN_UPLOAD",
        "fileUpload.finalize: no init() seen for '" + uploadId + "'");
    }

    _validateManifest(manifest);

    var verified = _verifyChunksOnDisk(uploadId, manifest);

    // Decide buffer-vs-stream based on size.
    var useStream = verified.totalBytes > maxStreamReassemblyBytes;
    var bodyBuffer = null;
    var bodyStream = null;
    var firstChunk = null;

    if (useStream) {
      // Read just the first chunk for the MIME sniff; the operator
      // gets the stream for the actual data.
      firstChunk = atomicFile.readSync(verified.paths[0], { maxBytes: maxChunkBytes });
      bodyStream = _streamFromChunkPaths(verified.paths, verified.totalBytes);
    } else {
      // Small enough to assemble in memory. Buffer.concat.
      var pieces = [];
      for (var i = 0; i < verified.paths.length; i++) {
        pieces.push(atomicFile.readSync(verified.paths[i], { maxBytes: maxChunkBytes }));
      }
      bodyBuffer = Buffer.concat(pieces, verified.totalBytes);
      firstChunk = pieces[0];
    }

    // MIME allowlist gate (if configured). Pass the operator-supplied
    // contentType from upload metadata so the cross-check can refuse
    // claimed-vs-detected mismatches.
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

    // Content-safety gate — operator-supplied per-extension gate
    // (b.guardCsv.gate / b.guardHtml.gate / etc.). Routes the assembled
    // body through the gate's check() before handing to onFinalize. The
    // decision is honored:
    //   - serve     → continue with the original buffer
    //   - sanitize  → continue with decision.sanitized (operator's
    //                  onFinalize sees the cleaned bytes)
    //   - refuse    → throw FileUploadError; operator route surfaces the
    //                  rejection to the client
    // filenameSafety — single gate that validates the filename string
    // (path traversal / null-byte / Windows reserved names / NTFS ADS /
    // RTLO bidi / overlong UTF-8 / shell-exec / double-extension).
    // Runs BEFORE contentSafety because a refused filename obviates
    // the need to validate the body.
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
        throw _err("FILENAME_SAFETY_THREW",
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
        throw _err("FILENAME_SAFETY_REFUSED",
          "fileUpload.finalize: filenameSafety refused " + JSON.stringify(filename) +
          ": " + gateContract.summarizeIssues(fnDecision.issues));
      }
      // sanitize: replace metadata.filename with the sanitized form so
      // downstream code sees the cleaned name.
      if (fnDecision.action === "sanitize" && fnDecision.sanitizedFilename) {
        meta.metadata = Object.assign({}, meta.metadata || {},
          { filename: fnDecision.sanitizedFilename });
        filename = fnDecision.sanitizedFilename;
      }
    }
    if (contentSafety) {
      var safetyExt = nodePath.extname(filename).toLowerCase();
      var safetyGate = contentSafety[safetyExt];
      if (safetyGate && typeof safetyGate.check === "function" && bodyBuffer) {
        var safetyDecision;
        try {
          safetyDecision = await safetyGate.check({
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
          throw _err("CONTENT_SAFETY_THREW",
            "fileUpload.finalize: contentSafety gate threw: " + (gateErr && gateErr.message));
        }
        if (!safetyDecision.ok || safetyDecision.action === "refuse") {
          _emitObs("fileUpload.content_safety_refused", 1, { ext: safetyExt });
          _emitAudit("fileUpload.finalize_failure", {
            actor:    requestHelpers.extractActorContext(actor),
            outcome:  "failure", reason: "content-safety-refused",
            metadata: {
              uploadId: uploadId, ext: safetyExt,
              issues: gateContract.summarizeIssues(safetyDecision.issues),
            },
          });
          throw _err("CONTENT_SAFETY_REFUSED",
            "fileUpload.finalize: contentSafety gate refused upload (" +
            (safetyDecision.issues || []).map(function (i) { return i.kind; }).join(", ") + ")");
        }
        if (safetyDecision.action === "sanitize" && safetyDecision.sanitized) {
          // Replace the body buffer with the sanitized variant.
          bodyBuffer = safetyDecision.sanitized;
          // Clear the streaming alias if present — sanitized fits in memory.
          bodyStream = null;
        }
      } else if (safetyGate && typeof safetyGate.check === "function" && !bodyBuffer) {
        // A content-safety gate is configured for this extension, but the
        // upload streamed past maxStreamReassemblyBytes and was never
        // reassembled into a buffer the byte-level gate can inspect. The
        // MIME-sniff and filename gates still ran; the per-extension
        // content gate did NOT. Audit the skip (with the streamed reason)
        // so operators can alert, lower maxStreamReassemblyBytes, or cap
        // maxFileBytes to force content-gating of this type.
        _emitContentSafetySkipped(uploadId, actor, "streamed-over-reassembly-cap",
                                  safetyExt, verified.totalBytes);
      } else {
        // contentSafety is wired but no gate is registered for this file's
        // extension — the byte-level scan does not run. Audit the skip so
        // a review can tell the upload bypassed content scanning (and
        // register a gate for the extension if it should be scanned).
        _emitContentSafetySkipped(uploadId, actor, "no-gate-for-extension",
                                  safetyExt, verified.totalBytes);
      }
    } else {
      // Content-safety scanning is disabled for this upload manager
      // (contentSafety: null opt-out at create()). The create-time audit
      // recorded the disable; this per-upload audit makes the bypass
      // visible at the point bytes reached storage.
      _emitContentSafetySkipped(uploadId, actor, "content-safety-disabled",
                                nodePath.extname(filename).toLowerCase(),
                                verified.totalBytes);
    }

    // Hand to operator's onFinalize.
    var rv;
    try {
      if (onFinalize) {
        rv = await onFinalize({
          uploadId: uploadId,
          body:     bodyBuffer,
          stream:   bodyStream,
          sha3:     verified.totalHashHex,
          size:     verified.totalBytes,
          actor:    actor,
          metadata: meta.metadata,
        });
      } else {
        rv = { ok: true, sha3: verified.totalHashHex, size: verified.totalBytes };
      }
    } catch (e) {
      _emitObs("fileUpload.finalize_failure", 1);
      _emitAudit("fileUpload.finalize", {
        actor:    requestHelpers.extractActorContext(actor),
        resource: { kind: "fileUpload", id: uploadId },
        outcome:  "failure",
        reason:   "onfinalize-threw",
        metadata: { size: verified.totalBytes, sha3: verified.totalHashHex,
                    error: (e && e.message) || String(e) },
      });
      throw e;
    }

    // Cleanup staging on success.
    try { nodeFs.rmSync(_uploadDir(uploadId), { recursive: true, force: true }); }
    catch (_e) { /* best-effort */ }

    _emitObs("fileUpload.finalize_success", 1);
    _emitObs("fileUpload.finalize_bytes", verified.totalBytes);
    _emitAudit("fileUpload.finalize", {
      actor:    requestHelpers.extractActorContext(actor),
      resource: { kind: "fileUpload", id: uploadId },
      outcome:  "success",
      metadata: { size: verified.totalBytes, sha3: verified.totalHashHex,
                  mode: useStream ? "stream" : "buffer" },
    });

    return rv;
  }

  // ---- status / list / cancel ----

  function status(uploadId, callerOpts) {
    callerOpts = callerOpts || {};
    _validateUploadId(uploadId);
    _checkPermission("status", callerOpts.actor);
    var meta = _readMeta(uploadId);
    if (!meta) return null;
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

  // ---- purgeIncomplete ----

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
        // No meta sidecar → orphaned dir from a prior version or
        // failed init. Reclaim by mtime.
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
