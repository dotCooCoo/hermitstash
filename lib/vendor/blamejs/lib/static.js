// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeFs = require("node:fs");
var fsp = require("node:fs/promises");
var nodeCrypto = require("node:crypto");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var gateContract = require("./gate-contract");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safePath = require("./safe-path");
var validateOpts = require("./validate-opts");
var { StaticServeError } = require("./framework-error");

// observability is lazy-required because it pulls in the metrics tap +
// safeEvent path, and during framework boot static.js may load before
// observability is ready.
var observability = lazyRequire(function () { return require("./observability"); });

// guard-* family is wired on by default; lazy-loaded to avoid eager
// import cycles. Operators opt out via contentSafety: null (audited).
var guardAll = lazyRequire(function () { return require("./guard-all"); });
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var guardRegex = lazyRequire(function () { return require("./guard-regex"); });

var _err = StaticServeError.factory;

var HTTP = requestHelpers.HTTP_STATUS;

var DEFAULT_HASHED_PATTERN = /\.[a-fA-F0-9]{8,}\./;
var DEFAULT_INDEX_FILE     = "index.html";
var DEFAULT_MAX_AGE_SEC    = C.TIME.hours(1) / C.TIME.seconds(1);
var IMMUTABLE_MAX_AGE_SEC  = C.TIME.days(365) / C.TIME.seconds(1);
var DEFAULT_BANDWIDTH_WINDOW_MS = C.TIME.minutes(1);
var DEFAULT_MAX_IDLE_MS    = C.TIME.minutes(2);
var ETAG_HEX_PREFIX = C.BYTES.bytes(32);

var DEFAULT_CONTENT_TYPES = {
  ".html":  "text/html; charset=utf-8",
  ".htm":   "text/html; charset=utf-8",
  ".css":   "text/css; charset=utf-8",
  ".js":    "application/javascript; charset=utf-8",
  ".mjs":   "application/javascript; charset=utf-8",
  ".json":  "application/json; charset=utf-8",
  ".map":   "application/json; charset=utf-8",
  ".txt":   "text/plain; charset=utf-8",
  ".md":    "text/markdown; charset=utf-8",
  ".xml":   "application/xml; charset=utf-8",
  ".svg":   "image/svg+xml",
  ".png":   "image/png",
  ".jpg":   "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":   "image/gif",
  ".webp":  "image/webp",
  ".avif":  "image/avif",
  ".ico":   "image/x-icon",
  ".woff":  "font/woff",
  ".woff2": "font/woff2",
  ".ttf":   "font/ttf",
  ".otf":   "font/otf",
  ".pdf":   "application/pdf",
  ".wasm":  "application/wasm",
  ".webmanifest": "application/manifest+json",
};

var DEFAULTS = Object.freeze({
  defaultMaxAge:                    DEFAULT_MAX_AGE_SEC,
  acceptRanges:                     true,
  maxRangeBytes:                    C.BYTES.mib(64),
  allowedFileTypes:                 Object.freeze([]),
  maxBytesPerActorPerWindowMs:      0,
  maxBytesAllActorsPerWindowMs:     0,
  bandwidthWindowMs:                DEFAULT_BANDWIDTH_WINDOW_MS,
  maxConcurrentDownloadsPerActor:   0,
  maxIdleMs:                        DEFAULT_MAX_IDLE_MS,
  auditSuccess:                     true,
  auditFailures:                    true,
  mountType:                        "curated",
  forceAttachmentForNonText:        false,
  safeRenderSvg:                    true,
  safeRenderPdf:                    false,
});

function _assertInsideRoot(root, candidate) {
  if (typeof root !== "string" || root.length === 0) return null;
  if (typeof candidate !== "string" || candidate.length === 0) return null;
  if (candidate.indexOf("\0") !== -1) return null;
  var rootResolved = nodePath.resolve(root);
  var requested = nodePath.isAbsolute(candidate)
    ? nodePath.relative(rootResolved, candidate)
    : candidate;
  var rel = nodePath.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");
  if (rel.indexOf("\0") !== -1) return null;
  if (rel === ".." ||
      rel.indexOf(".." + nodePath.sep) !== -1 ||
      rel.indexOf(".." + (nodePath.sep === "/" ? "\\" : "/")) !== -1 ||
      nodePath.isAbsolute(rel)) return null;
  return safePath.confineToBase(rootResolved, rel);
}

var _metaCache = new Map();

async function _readMeta(root, candidate) {
  var absPath = _assertInsideRoot(root, candidate);
  if (!absPath) return null;

  var stat;
  try { stat = await fsp.stat(absPath); }
  catch (_e) { return null; }
  if (!stat.isFile()) return null;

  var cached = _metaCache.get(absPath);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached;
  }

  var sri = nodeCrypto.createHash("sha384");
  var sha3 = nodeCrypto.createHash("sha3-512");
  try {
    await new Promise(function (resolve, reject) {
      var s;
      try { s = nodeFs.createReadStream(absPath, { fd: atomicFile.openNoFollowSync(absPath) }); }
      catch (e) { reject(e); return; }
      s.on("data", function (chunk) { sri.update(chunk); sha3.update(chunk); });
      s.on("end", resolve);
      s.on("error", reject);
    });
  } catch (_hashErr) {
    return null;
  }
  var sriDigest = sri.digest("base64");
  var sha3Hex = sha3.digest("hex");

  var entry = {
    mtimeMs:    stat.mtimeMs,
    size:       stat.size,
    etag:       '"' + sha3Hex.slice(0, ETAG_HEX_PREFIX) + '"',
    integrity:  "sha384-" + sriDigest,
    lastModified: new Date(stat.mtimeMs).toUTCString(),
    sha3Hex:    sha3Hex,
    absPath:    absPath,
  };
  _metaCache.set(absPath, entry);
  return entry;
}

function _integrityHeadersForBytes(buf) {
  var sha3Hex = nodeCrypto.createHash("sha3-512").update(buf).digest("hex");
  var sriDigest = nodeCrypto.createHash("sha384").update(buf).digest("base64");
  return {
    etag:      '"' + sha3Hex.slice(0, ETAG_HEX_PREFIX) + '"',
    integrity: "sha384-" + sriDigest,
  };
}

function _resolveSafe(root, requestedPath) {
  if (typeof requestedPath !== "string" || requestedPath.length === 0) return null;
  if (requestedPath.indexOf("\0") !== -1) return null;
  var resolved = _assertInsideRoot(root, nodePath.resolve(root, "." + requestedPath));
  if (!resolved) return null;
  var rootResolved = nodePath.resolve(root);

  try {
    var real = nodeFs.realpathSync(resolved);
    var rootReal = nodeFs.realpathSync(rootResolved);
    if (real !== rootReal && !real.startsWith(rootReal + nodePath.sep)) return null;
  } catch (_e) {
    // Path doesn't exist (or is denied) — fall through with the lexical
    // resolution so the caller's stat() returns the natural ENOENT and
    // 404s. realpath failures from non-existence are NOT a smuggling
    // signal; the lexical bound check above already rejected escapes.
  }

  var fname = nodePath.basename(resolved);
  var rv = guardFilename().validate(fname, {
    profile:             "balanced",
    shellExecExtPolicy:  "allow",
  });
  if (!rv.ok) return null;

  return resolved;
}

function _contentTypeFor(filePath, table) {
  var ext = nodePath.extname(filePath).toLowerCase();
  return (table && table[ext]) || DEFAULT_CONTENT_TYPES[ext] || "application/octet-stream";
}

var RISKY_INLINE_MIMES = {
  "text/html":              true,
  "text/xml":               true,
  "application/xml":        true,
  "application/xhtml+xml":  true,
  "image/svg+xml":          true,
  "application/javascript": true,
  "text/javascript":        true,
  "application/x-javascript": true,
};

function _isRiskyInlineMime(contentType) {
  if (typeof contentType !== "string" || contentType.length === 0) return false;
  var semi = contentType.indexOf(";");
  var bare = (semi === -1 ? contentType : contentType.slice(0, semi)).trim().toLowerCase();
  return RISKY_INLINE_MIMES[bare] === true;
}

var SAFE_RENDER_RASTER_MIMES = {
  "image/png":   true,
  "image/jpeg":  true,
  "image/webp":  true,
  "image/gif":   true,
};

function _bareMime(contentType) {
  if (typeof contentType !== "string" || contentType.length === 0) return "";
  var semi = contentType.indexOf(";");
  return (semi === -1 ? contentType : contentType.slice(0, semi)).trim().toLowerCase();
}

function _shouldForceAttachment(contentType, ext, contentSafetyMap, allowSvgRender, allowPdfRender) {
  var bare = _bareMime(contentType);
  if (bare.length === 0) return true;
  if (bare === "text/html" || bare === "text/xml" ||
      bare === "text/javascript" || bare === "application/xhtml+xml") {
    return true;
  }
  if (bare.indexOf("text/") === 0) return false;
  if (Object.prototype.hasOwnProperty.call(SAFE_RENDER_RASTER_MIMES, bare)) return false;
  if (bare === "image/svg+xml") {
    if (!allowSvgRender) return true;
    if (!contentSafetyMap || typeof contentSafetyMap !== "object") return true;
    var svgGate = contentSafetyMap[".svg"];
    if (!svgGate || typeof svgGate.check !== "function") return true;
    return false;
  }
  if (bare === "application/pdf") {
    return !allowPdfRender;
  }
  if (ext === ".html" || ext === ".htm" || ext === ".xhtml" ||
      ext === ".js" || ext === ".mjs" || ext === ".svg" ||
      ext === ".xml" || ext === ".pdf") {
    if (ext === ".svg" && allowSvgRender) {
      if (contentSafetyMap && contentSafetyMap[".svg"] &&
          typeof contentSafetyMap[".svg"].check === "function") return false;
    }
    if (ext === ".pdf" && allowPdfRender) return false;
    return true;
  }
  return true;
}

function _attachmentDisposition(filePath) {
  var name = nodePath.basename(filePath);
  if (/[\r\n\0]/.test(name)) name = "download";
  var asciiName = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  var encName = encodeURIComponent(name);
  return 'attachment; filename="' + asciiName + '"; filename*=UTF-8\'\'' + encName;
}

function _parseRangeHeader(header, size) {
  if (typeof header !== "string" || header.length === 0) return null;
  if (header.indexOf("bytes=") !== 0) return { malformed: true };
  var spec = header.slice(6).trim();
  if (spec.length === 0) return { malformed: true };
  if (spec.indexOf(",") !== -1) return { multi: true };
  var dash = spec.indexOf("-");
  if (dash === -1) return { malformed: true };
  var startStr = spec.slice(0, dash);
  var endStr = spec.slice(dash + 1);
  var start, end;
  if (startStr === "") {
    var suffix = parseInt(endStr, 10);
    if (!isFinite(suffix) || suffix <= 0) return { malformed: true };
    if (suffix > size) suffix = size;
    start = size - suffix;
    end = size - 1;
  } else {
    start = parseInt(startStr, 10);
    if (!isFinite(start) || start < 0) return { malformed: true };
    if (endStr === "") {
      end = size - 1;
    } else {
      end = parseInt(endStr, 10);
      if (!isFinite(end) || end < start) return { malformed: true };
      if (end > size - 1) end = size - 1;
    }
  }
  if (start >= size) return { unsatisfiable: true };
  return { start: start, end: end, length: end - start + 1 };
}

function _validateCreateOpts(opts) {
  validateOpts.shape(opts, {
    root: "required-string",
    mountPath: function (value, _label, errorClass, code) {
      if (typeof value === "string" && value.length === 0) return;
      if (value !== undefined && value !== null && typeof value !== "string") {
        throw errorClass.factory(code, "staticServe.create: mountPath must be a string");
      }
    },
    hashedPathPattern: function (value, _label, errorClass, code) {
      if (value !== undefined && value !== null && !(value instanceof RegExp)) {
        throw errorClass.factory(code, "staticServe.create: hashedPathPattern must be a RegExp");
      }
      if (value instanceof RegExp) {
        guardRegex().assertSafe(value, "staticServe: hashedPathPattern", StaticServeError, "static/unsafe-pattern");
      }
    },
    indexFile: "optional-string",
    defaultMaxAge: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    contentTypes: "optional-plain-object",
    contentSafety: function (value, _label, errorClass, code) {
      if (value === undefined || value === null) return;
      validateOpts.optionalPlainObject(value,
        "staticServe.create: contentSafety", errorClass, code,
        "must be a plain { ext: gate } object, null to opt out, or " +
        "undefined for the default-on b.guardAll wiring");
      var safetyKeys = Object.keys(value);
      for (var sk = 0; sk < safetyKeys.length; sk++) {
        var ext = safetyKeys[sk];
        var g = value[ext];
        if (!g || typeof g.check !== "function") {
          throw errorClass.factory(code,
            "staticServe.create: contentSafety[" + JSON.stringify(ext) +
            "] must be a gate (b.guardCsv.gate / b.guardHtml.gate / etc.)");
        }
      }
    },
    permissions: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "check", label, errorClass, code,
        "must be a b.permissions instance (check fn)");
    },
    cache: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "get", label, errorClass, code,
        "must be a b.cache instance (used for cluster-shared bandwidth + concurrency tracking)");
    },
    fileType: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "detect", label, errorClass, code,
        "must be a b.fileType instance (magic-byte MIME detection)");
    },
    retention: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "isServable", label, errorClass, code,
        "must expose isServable(absPath, ctx) → boolean (compliance retention check)");
    },
    revokeStore: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "isRevoked", label, errorClass, code,
        "must expose isRevoked(key) and revoke(key) for force-revoke support");
    },
    allowedFileTypes: "optional-string-array",
    audit: function (value, _label, errorClass, _code) {
      validateOpts.auditShape(value, "staticServe.create", errorClass);
    },
    observability: function (value, _label, errorClass, _code) {
      validateOpts.observabilityShape(value, "staticServe.create", errorClass);
    },
    onServe: "optional-function",
    onError: "optional-function",
    acceptRanges: "optional-boolean",
    auditSuccess: "optional-boolean",
    auditFailures: "optional-boolean",
    safeAttachmentForRiskyMimes: "optional-boolean",
    forceAttachmentForNonText: "optional-boolean",
    safeRenderSvg: "optional-boolean",
    safeRenderPdf: "optional-boolean",
    maxBytesPerActorPerWindowMs: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxBytesAllActorsPerWindowMs: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    bandwidthWindowMs: function (value, label, errorClass, code) {
      numericBounds.requirePositiveFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxConcurrentDownloadsPerActor: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxIdleMs: function (value, label, errorClass, code) {
      numericBounds.requirePositiveFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxRangeBytes: function (value, label, errorClass, code) {
      if (value === undefined || value === null || value === Infinity) return;
      numericBounds.requirePositiveFiniteInt(value, label, errorClass, code);
    },
  }, "staticServe.create", StaticServeError, "static/bad-opt", {
    allow: ["contentSafetyDisabledReason", "mountType"],
  });

  if (!nodeFs.existsSync(opts.root)) {
    throw _err("static/bad-opt", "staticServe.create: root does not exist: " + opts.root);
  }
  if (Array.isArray(opts.allowedFileTypes) && opts.allowedFileTypes.length > 0 &&
      (!opts.fileType || typeof opts.fileType.detect !== "function")) {
    throw _err("static/bad-opt",
      "staticServe.create: allowedFileTypes is set but fileType primitive is not wired " +
      "(pass fileType: b.fileType so the framework can sniff magic bytes before serving)");
  }
  if (opts.mountType !== undefined &&
      opts.mountType !== "curated" && opts.mountType !== "user-content") {
    throw _err("static/bad-opt",
      "staticServe.create: mountType must be 'curated' (default) or " +
      "'user-content'; got " + JSON.stringify(opts.mountType));
  }
  if (opts.maxBytesPerActorPerWindowMs > 0 ||
      opts.maxBytesAllActorsPerWindowMs > 0 ||
      opts.maxConcurrentDownloadsPerActor > 0) {
    if (!opts.cache) {
      throw _err("static/bad-opt",
        "staticServe.create: bandwidth / concurrency quotas require opts.cache " +
        "(pass cache: b.cache.create({ backend: 'cluster' }) so multi-replica deploys honor caps globally)");
    }
    if (typeof opts.cache.update !== "function") {
      throw _err("static/bad-opt",
        "staticServe.create: the quota cache must support atomic update() — a plain " +
        "get/set cache loses concurrent bandwidth/concurrency charges; use b.cache.create(...)");
    }
  }
}

async function _checkBandwidthQuota(cache, actorKey, perActorCap, globalCap, windowMs, requestedBytes) {
  if (!cache || (perActorCap === 0 && globalCap === 0)) return { ok: true };
  var now = Date.now();
  var windowStart = now - windowMs;
  if (perActorCap > 0 && actorKey) {
    var aKey = "static:bw:actor:" + actorKey;
    var aUsed = (await cache.get(aKey)) || 0;
    if (aUsed + requestedBytes > perActorCap) {
      return { ok: false, retryAfter: Math.ceil(windowMs / C.TIME.seconds(1)), scope: "actor", used: aUsed, cap: perActorCap };
    }
  }
  if (globalCap > 0) {
    var gKey = "static:bw:global";
    var gUsed = (await cache.get(gKey)) || 0;
    if (gUsed + requestedBytes > globalCap) {
      return { ok: false, retryAfter: Math.ceil(windowMs / C.TIME.seconds(1)), scope: "global", used: gUsed, cap: globalCap };
    }
  }
  return { ok: true, windowStart: windowStart, now: now };
}

var STATIC_COUNTER_MAX_RETRIES = 6;
async function _atomicCounter(cache, key, mutate, ttlMs) {
  for (var attempt = 0; ; attempt++) {
    try {
      await cache.update(key, function (current) {
        var c = (typeof current === "number" && isFinite(current)) ? current : 0;
        return { value: mutate(c) };
      }, { ttlMs: ttlMs });
      return;
    } catch (e) {
      if (e && e.code === "cache/update-contention" && attempt < STATIC_COUNTER_MAX_RETRIES) continue;
      throw e;
    }
  }
}

async function _consumeBandwidth(cache, actorKey, perActorCap, globalCap, windowMs, bytes) {
  if (!cache) return;
  if (perActorCap > 0 && actorKey) {
    await _atomicCounter(cache, "static:bw:actor:" + actorKey, function (c) { return c + bytes; }, windowMs);
  }
  if (globalCap > 0) {
    await _atomicCounter(cache, "static:bw:global", function (c) { return c + bytes; }, windowMs);
  }
}

async function _checkConcurrencyCap(cache, actorKey, cap) {
  if (!cache || cap === 0 || !actorKey) return { ok: true };
  var key = "static:conc:" + actorKey;
  var current = (await cache.get(key)) || 0;
  if (current >= cap) return { ok: false, current: current, cap: cap };
  return { ok: true, current: current };
}

async function _incConcurrency(cache, actorKey) {
  if (!cache || !actorKey) return;
  await _atomicCounter(cache, "static:conc:" + actorKey, function (c) { return c + 1; }, C.TIME.minutes(10));
}

async function _decConcurrency(cache, actorKey) {
  if (!cache || !actorKey) return;
  await _atomicCounter(cache, "static:conc:" + actorKey, function (c) { return c > 0 ? c - 1 : 0; }, C.TIME.minutes(10));
}

function _actorKeyFromContext(ctx) {
  if (!ctx) return null;
  if (ctx.userId) return "id:" + ctx.userId;
  if (ctx.ip)     return "ip:" + ctx.ip;
  return null;
}

function _writeError(res, status, code, message, headers) {
  var hdrs = Object.assign({ "Content-Type": "text/plain; charset=utf-8" }, headers || {});
  hdrs["Content-Length"] = Buffer.byteLength(message, "utf8");
  try {
    res.writeHead(status, hdrs);
    res.end(message);
  } catch (_e) {
    // response already torn down — best effort
  }
  void code;
}

async function integrity(absPath) {
  if (typeof absPath !== "string" || absPath.length === 0) {
    throw _err("static/bad-opt", "staticServe.integrity: absPath must be a non-empty string");
  }
  var resolved = nodePath.resolve(absPath);
  var meta = await _readMeta(resolved, resolved);
  if (!meta) throw _err("static/not-found", "staticServe.integrity: file not found: " + absPath);
  return meta.integrity;
}

function create(opts) {
  opts = opts || {};
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var root            = nodePath.resolve(opts.root);
  var mountPath       = opts.mountPath || "";
  var hashedPattern   = opts.hashedPathPattern || DEFAULT_HASHED_PATTERN;
  var indexFile       = opts.indexFile === null ? null : (opts.indexFile || DEFAULT_INDEX_FILE);
  var defaultMaxAge   = cfg.defaultMaxAge;
  var contentTypes    = opts.contentTypes || null;
  var permissions     = opts.permissions || null;
  var cache           = opts.cache || null;
  var fileType        = opts.fileType || null;
  var retention       = opts.retention || null;
  var revokeStore     = opts.revokeStore || null;
  var allowedFileTypes = Array.isArray(opts.allowedFileTypes) ? opts.allowedFileTypes.slice() : [];
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
          action:   "staticServe.contentSafety.disabled",
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
  var onServe         = opts.onServe || null;
  var onError         = opts.onError || null;
  var audit           = opts.audit || null;
  var auditSuccess    = cfg.auditSuccess;
  var auditFailures   = cfg.auditFailures;
  var acceptRanges    = cfg.acceptRanges;
  var safeAttachment  = !!opts.safeAttachmentForRiskyMimes;
  var mountType       = opts.mountType || "curated";
  var forceAttachmentForNonText = opts.forceAttachmentForNonText !== undefined
    ? !!opts.forceAttachmentForNonText
    : (mountType === "user-content");
  var allowSvgRender  = cfg.safeRenderSvg !== false;
  var allowPdfRender  = !!cfg.safeRenderPdf;
  var perActorCap     = cfg.maxBytesPerActorPerWindowMs;
  var globalCap       = cfg.maxBytesAllActorsPerWindowMs;
  var bandwidthWindowMs = cfg.bandwidthWindowMs;
  var concurrencyCap  = cfg.maxConcurrentDownloadsPerActor;
  var maxIdleMs       = cfg.maxIdleMs;

  var emitAudit = validateOpts.makeAuditEmitter(audit);

  var localRevoked = new Set();

  function _emitObs(name, value, labels) {
    observability().safeEvent(name, value, labels || {});
  }

  var stats = {
    requestsServed:    0,
    bytesServed:       0,
    etagHits:          0,
    rangeRequests:     0,
    permissionDenied:  0,
    quotaRejected:     0,
    failures:          0,
  };

  function _cacheControlFor(urlPath) {
    if (hashedPattern.test(urlPath)) {
      return "public, max-age=" + IMMUTABLE_MAX_AGE_SEC + ", immutable";
    }
    return "public, max-age=" + defaultMaxAge;
  }

  async function _isRevoked(key) {
    if (revokeStore) {
      try { return !!(await revokeStore.isRevoked(key)); }
      catch (_e) { return false; }
    }
    return localRevoked.has(key);
  }

  async function _checkRetention(absPath, ctx) {
    if (!retention) return true;
    try { return !!(await retention.isServable(absPath, ctx)); }
    catch (_e) { return false; }
  }

  async function _checkPermission(req) {
    if (!permissions) return { ok: true };
    try {
      var ok = await permissions.check(req, "static.serve");
      return { ok: !!ok };
    } catch (_e) {
      return { ok: false, error: _e };
    }
  }

  async function _checkMimeAllowlist(absPath, meta) {
    if (allowedFileTypes.length === 0 || !fileType) return { ok: true };
    var confined = _assertInsideRoot(root, absPath);
    if (!confined) return { ok: false, reason: "read-failed" };
    var sample;
    try {
      var sniffFd = atomicFile.openNoFollowSync(confined);
      try {
        var sniffBuf = Buffer.alloc(C.BYTES.kib(64));
        var sniffN = nodeFs.readSync(sniffFd, sniffBuf, 0, sniffBuf.length, 0);
        sample = sniffBuf.slice(0, sniffN);
      } finally { nodeFs.closeSync(sniffFd); }
    } catch (_e) { return { ok: false, reason: "read-failed" }; }
    var detected = fileType.detect(sample) || {};
    if (!detected.mime) return { ok: false, reason: "indeterminate" };
    if (allowedFileTypes.indexOf(detected.mime) === -1) {
      return { ok: false, reason: "not-allowed", detected: detected.mime };
    }
    void meta;
    return { ok: true, detected: detected.mime };
  }

  async function middleware(req, res, next) {
    if (req.method !== "GET" && req.method !== "HEAD") return next();

    var urlPath = (req.url || "").split("?")[0];
    if (mountPath && urlPath.indexOf(mountPath) === 0) {
      urlPath = urlPath.slice(mountPath.length) || "/";
    }
    var decoded;
    try { decoded = decodeURIComponent(urlPath); }
    catch (_e) { return next(); }

    var absPath = _resolveSafe(root, decoded);
    if (!absPath) return next();

    var actorCtx = requestHelpers.extractActorContext(req);
    var actorKey = _actorKeyFromContext(actorCtx);

    function writeErr(r, status, code, message, headers) {
      _writeError(r, status, code, message, headers);
      safeAsync.safeInvoke(onError, {
        req: req, res: r, urlPath: urlPath, absPath: absPath,
        status: status, code: code, actor: actorCtx,
      });
    }

    var perm = await _checkPermission(req);
    if (!perm.ok) {
      stats.permissionDenied += 1;
      _emitObs("staticServe.permission_denied", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "permission_denied", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.FORBIDDEN, "permission_denied",
        "Forbidden");
    }

    var statTarget = _assertInsideRoot(root, absPath);
    if (!statTarget) return next();
    var stat;
    try { stat = await fsp.stat(statTarget); }
    catch (_e) { return next(); }
    if (stat.isDirectory()) {
      if (!indexFile) return next();
      absPath = _assertInsideRoot(root, nodePath.join(absPath, indexFile));
      if (!absPath) return next();
    }

    if (await _isRevoked(absPath)) {
      stats.failures += 1;
      _emitObs("staticServe.revoked", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "revoked", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.NOT_FOUND, "not_found", "Not Found");
    }

    if (!(await _checkRetention(absPath, actorCtx))) {
      stats.failures += 1;
      _emitObs("staticServe.retention_blocked", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "retention_blocked", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.UNAVAILABLE_FOR_LEGAL_REASONS,
        "retention_blocked", "Unavailable For Legal Reasons");
    }

    var meta = await _readMeta(root, absPath);
    if (!meta) return next();

    if (allowedFileTypes.length > 0) {
      var mimeCheck = await _checkMimeAllowlist(absPath, meta);
      if (!mimeCheck.ok) {
        stats.failures += 1;
        _emitObs("staticServe.mime_rejected", 1, { route: urlPath, reason: mimeCheck.reason });
        if (auditFailures) {
          emitAudit("staticServe.serve.failure", Object.assign({
            outcome: "failure", reason: "mime_rejected", resource: urlPath,
            detectedMime: mimeCheck.detected || null,
          }, actorCtx));
        }
        return writeErr(res, HTTP.UNSUPPORTED_MEDIA_TYPE,
          "mime_rejected", "Unsupported Media Type");
      }
    }

    var gateBytesOverride = null;
    if (contentSafety) {
      var ext = nodePath.extname(absPath).toLowerCase();
      var safetyGate = contentSafety[ext];
      if (safetyGate && typeof safetyGate.check === "function") {
        var gateConfined = _assertInsideRoot(root, absPath);
        if (!gateConfined) return next();
        var gateBuf;
        var gateHandle = null;
        var gateOpenFlags = nodeFs.constants.O_RDONLY |
          (nodeFs.constants.O_NOFOLLOW || 0);
        try {
          gateHandle = await fsp.open(gateConfined, gateOpenFlags, 0o600);
          var gateStat = await gateHandle.stat();
          if (gateStat.size > C.BYTES.mib(16)) {
            stats.failures += 1;
            _emitObs("staticServe.content_safety_refused", 1, { route: urlPath });
            try { await gateHandle.close(); } catch (_ce) { /* close best-effort */ }
            if (auditFailures) {
              emitAudit("staticServe.serve.failure", Object.assign({
                outcome: "failure", reason: "content_safety_too_large",
                resource: urlPath, ext: ext, sizeBytes: gateStat.size,
              }, actorCtx));
            }
            return writeErr(res, HTTP.UNSUPPORTED_MEDIA_TYPE,
              "content_safety_refused", "Unsupported Media Type");
          }
          gateBuf = Buffer.alloc(gateStat.size);
          var gateRead = 0;
          while (gateRead < gateStat.size) {
            var gateN = await gateHandle.read(gateBuf, gateRead, gateStat.size - gateRead, null);
            if (gateN.bytesRead === 0) break;
            gateRead += gateN.bytesRead;
          }
          if (gateRead < gateStat.size) gateBuf = gateBuf.slice(0, gateRead);
        }
        catch (_e) {
          stats.failures += 1;
          if (gateHandle) { try { await gateHandle.close(); } catch (_ce) { /* close best-effort */ } }
          return writeErr(res, HTTP.INTERNAL_SERVER_ERROR,
            "read_failed", "Internal Server Error");
        }
        try { await gateHandle.close(); } catch (_ce) { /* close best-effort */ }
        var gateDecision;
        try {
          gateDecision = await safetyGate.check({
            bytes:       gateBuf,
            contentType: _contentTypeFor(absPath, contentTypes),
            filename:    nodePath.basename(absPath),
            actor:       actorCtx,
            route:       urlPath,
            direction:   "outbound",
            req:         req,
          });
        } catch (gateErr) {
          stats.failures += 1;
          _emitObs("staticServe.content_safety_threw", 1, { route: urlPath });
          if (auditFailures) {
            emitAudit("staticServe.serve.failure", Object.assign({
              outcome: "failure", reason: "content_safety_threw", resource: urlPath,
              error: gateErr && gateErr.message,
            }, actorCtx));
          }
          return writeErr(res, HTTP.INTERNAL_SERVER_ERROR,
            "content_safety_threw", "Internal Server Error");
        }
        if (!gateDecision.ok || gateDecision.action === "refuse") {
          stats.failures += 1;
          _emitObs("staticServe.content_safety_refused", 1, { route: urlPath });
          if (auditFailures) {
            emitAudit("staticServe.serve.failure", Object.assign({
              outcome: "failure", reason: "content_safety_refused",
              resource: urlPath, ext: ext,
              issues: gateContract.summarizeIssues(gateDecision.issues),
            }, actorCtx));
          }
          return writeErr(res, HTTP.UNSUPPORTED_MEDIA_TYPE,
            "content_safety_refused", "Unsupported Media Type");
        }
        if (gateDecision.action === "sanitize" && gateDecision.sanitized) {
          gateBytesOverride = gateDecision.sanitized;
        }
      }
    }

    var cacheControl = _cacheControlFor(urlPath);

    var served = gateBytesOverride
      ? _integrityHeadersForBytes(gateBytesOverride)
      : { etag: meta.etag, integrity: meta.integrity };

    var headersIn = req.headers || {};

    var ifNone = headersIn["if-none-match"];
    if (ifNone && ifNone === served.etag) {
      stats.etagHits += 1;
      _emitObs("staticServe.etag_hits", 1, { route: urlPath });
      res.writeHead(HTTP.NOT_MODIFIED, {
        "ETag":          served.etag,
        "Cache-Control": cacheControl,
        "Last-Modified": meta.lastModified,
      });
      return res.end();
    }

    var ifMatch = headersIn["if-match"];
    if (ifMatch && ifMatch !== "*" && ifMatch !== served.etag) {
      stats.failures += 1;
      _emitObs("staticServe.precondition_failed", 1, { route: urlPath, header: "if-match" });
      return writeErr(res, HTTP.PRECONDITION_FAILED || 412,
        "precondition_failed", "Precondition Failed");
    }

    var ifModSince = !ifNone && headersIn["if-modified-since"];
    if (ifModSince) {
      var ims = Date.parse(ifModSince);
      if (isFinite(ims) && Math.floor(meta.mtimeMs / C.TIME.seconds(1)) <= Math.floor(ims / C.TIME.seconds(1))) {
        stats.etagHits += 1;
        _emitObs("staticServe.if_modified_since_hits", 1, { route: urlPath });
        res.writeHead(HTTP.NOT_MODIFIED, {
          "ETag":          served.etag,
          "Cache-Control": cacheControl,
          "Last-Modified": meta.lastModified,
        });
        return res.end();
      }
    }

    var ifUnmodSince = !ifMatch && headersIn["if-unmodified-since"];
    if (ifUnmodSince) {
      var ius = Date.parse(ifUnmodSince);
      if (isFinite(ius) && Math.floor(meta.mtimeMs / C.TIME.seconds(1)) > Math.floor(ius / C.TIME.seconds(1))) {
        stats.failures += 1;
        _emitObs("staticServe.precondition_failed", 1, { route: urlPath, header: "if-unmodified-since" });
        return writeErr(res, HTTP.PRECONDITION_FAILED,
          "precondition_failed", "Precondition Failed");
      }
    }

    var range = null;
    if (acceptRanges) {
      var raw = headersIn["range"];
      if (raw) {
        range = _parseRangeHeader(raw, meta.size);
        if (range && (range.malformed || range.multi)) {
          stats.failures += 1;
          _emitObs("staticServe.range_invalid", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_not_satisfiable",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range && range.unsatisfiable) {
          stats.failures += 1;
          _emitObs("staticServe.range_invalid", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_not_satisfiable",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range && cfg.maxRangeBytes !== Infinity && range.length > cfg.maxRangeBytes) {
          stats.failures += 1;
          _emitObs("staticServe.range_too_large", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_too_large",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range) {
          stats.rangeRequests += 1;
          _emitObs("staticServe.range_requests", 1, { route: urlPath });
        }
      }
    }

    var sendBytes = range ? range.length : meta.size;

    var concCheck = await _checkConcurrencyCap(cache, actorKey, concurrencyCap);
    if (!concCheck.ok) {
      stats.quotaRejected += 1;
      _emitObs("staticServe.concurrency_rejected", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "concurrency_cap", resource: urlPath,
          current: concCheck.current, cap: concCheck.cap,
        }, actorCtx));
      }
      return writeErr(res, HTTP.TOO_MANY_REQUESTS,
        "concurrency_cap", "Too Many Requests",
        { "Retry-After": "5" });
    }

    var bwCheck = await _checkBandwidthQuota(cache, actorKey, perActorCap, globalCap, bandwidthWindowMs, sendBytes);
    if (!bwCheck.ok) {
      stats.quotaRejected += 1;
      _emitObs("staticServe.bandwidth_rejected", 1, { route: urlPath, scope: bwCheck.scope });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "bandwidth_quota", resource: urlPath,
          scope: bwCheck.scope, used: bwCheck.used, cap: bwCheck.cap,
        }, actorCtx));
      }
      return writeErr(res, HTTP.TOO_MANY_REQUESTS,
        "bandwidth_quota", "Too Many Requests",
        { "Retry-After": String(bwCheck.retryAfter) });
    }

    var status = range ? 206 : HTTP.OK;
    var headers = {
      "Content-Type":   _contentTypeFor(absPath, contentTypes),
      "Content-Length": sendBytes,
      "ETag":           served.etag,
      "Cache-Control":  cacheControl,
      "Last-Modified":  meta.lastModified,
      "X-Integrity":    served.integrity,
    };
    if (safeAttachment && _isRiskyInlineMime(headers["Content-Type"])) {
      headers["Content-Disposition"] = _attachmentDisposition(absPath);
    }
    if (forceAttachmentForNonText) {
      var dispoExt = nodePath.extname(absPath).toLowerCase();
      if (_shouldForceAttachment(headers["Content-Type"], dispoExt, contentSafety,
                                 allowSvgRender, allowPdfRender)) {
        headers["Content-Disposition"] = _attachmentDisposition(absPath);
        headers["X-Content-Type-Options"] = "nosniff";
      }
    }
    if (acceptRanges) headers["Accept-Ranges"] = "bytes";
    if (range) headers["Content-Range"] = "bytes " + range.start + "-" + range.end + "/" + meta.size;

    if (onServe) {
      try {
        await onServe({
          req: req, res: res, absPath: absPath, urlPath: urlPath,
          size: meta.size, sendBytes: sendBytes, range: range,
          headers: headers, actor: actorCtx,
        });
      } catch (e) {
        stats.failures += 1;
        _emitObs("staticServe.onServe_threw", 1, { route: urlPath });
        if (auditFailures) {
          emitAudit("staticServe.serve.failure", Object.assign({
            outcome: "failure", reason: "onServe_threw", resource: urlPath,
            error: e && e.message,
          }, actorCtx));
        }
        return writeErr(res, HTTP.INTERNAL_SERVER_ERROR, "onServe_threw",
          "Internal Server Error");
      }
    }

    if (req.method === "HEAD") {
      var headSize = gateBytesOverride ? gateBytesOverride.length : meta.size;
      if (gateBytesOverride) {
        headers = Object.assign({}, headers, { "Content-Length": headSize });
        delete headers["Content-Range"];
        status = HTTP.OK;
      }
      res.writeHead(status, headers);
      res.end();
      stats.requestsServed += 1;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "HEAD" });
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "HEAD",
          size: headSize, contentType: headers["Content-Type"],
        }, actorCtx));
      }
      return;
    }

    if (gateBytesOverride) {
      var overrideHeaders = Object.assign({}, headers, {
        "Content-Length": gateBytesOverride.length,
      });
      delete overrideHeaders["Content-Range"];
      res.writeHead(HTTP.OK, overrideHeaders);
      res.end(gateBytesOverride);
      stats.requestsServed += 1;
      stats.bytesServed += gateBytesOverride.length;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "GET", sanitized: true });
      _emitObs("staticServe.bytes_served", gateBytesOverride.length, { route: urlPath, sanitized: true });
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "GET",
          size: gateBytesOverride.length, contentType: overrideHeaders["Content-Type"],
          sanitized: true,
        }, actorCtx));
      }
      return;
    }

    var streamTarget = _assertInsideRoot(root, absPath);
    if (!streamTarget) {
      stats.failures += 1;
      return writeErr(res, HTTP.NOT_FOUND, "not_found", "Not Found");
    }

    res.writeHead(status, headers);

    await _incConcurrency(cache, actorKey);
    var slotReleased = false;
    function releaseSlot() {
      if (slotReleased) return;
      slotReleased = true;
      _decConcurrency(cache, actorKey).catch(function () {});
    }

    var streamOpts = range ? { start: range.start, end: range.end } : {};
    var fileStream;
    try {
      fileStream = nodeFs.createReadStream(streamTarget,
        Object.assign({ fd: atomicFile.openNoFollowSync(streamTarget) }, streamOpts));
    } catch (_openErr) {
      releaseSlot();
      try { res.destroy(); } catch (_d) { /* already torn down */ }
      return;
    }

    var idleTimer = null;
    function resetIdleTimer() {
      if (idleTimer) clearTimeout(idleTimer); // allow:handrolled-debounce-stream-idle — file-stream idle deadline
      idleTimer = setTimeout(function () {
        try { fileStream.destroy(_err("static/idle-timeout", "client idle for " + maxIdleMs + "ms")); }
        catch (_) { /* stream already torn down */ }
        try { res.destroy(); } catch (_) { /* response already torn down */ }
      }, maxIdleMs);
    }
    resetIdleTimer();

    function onClientClose() {
      try { fileStream.destroy(); } catch (_) { /* allow:silent-catch-stream-teardown — stream already torn down */ }
      releaseSlot();
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
    }
    req.on("aborted", onClientClose);
    res.on("close", onClientClose);

    var bytesSent = 0;
    fileStream.on("data", function (chunk) {
      bytesSent += chunk.length;
      resetIdleTimer();
    });

    fileStream.on("error", function (e) {
      stats.failures += 1;
      _emitObs("staticServe.stream_error", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "stream_error", resource: urlPath,
          error: e && e.message,
        }, actorCtx));
      }
      try { res.destroy(e); } catch (_) { /* allow:silent-catch-stream-teardown — response already torn down */ }
      releaseSlot();
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
    });

    fileStream.on("end", function () {
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      stats.requestsServed += 1;
      stats.bytesServed += bytesSent;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "GET" });
      _emitObs("staticServe.bytes_served", bytesSent, { route: urlPath });
      _consumeBandwidth(cache, actorKey, perActorCap, globalCap, bandwidthWindowMs, bytesSent)
        .catch(function () {});
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "GET",
          size: bytesSent, contentType: headers["Content-Type"],
          range: range ? { start: range.start, end: range.end } : null,
        }, actorCtx));
      }
      releaseSlot();
    });

    fileStream.pipe(res);
  }

  async function fn(req, res, next) { return middleware(req, res, next); }
  fn.middleware = middleware;
  fn.revoke = async function (key) {
    if (revokeStore && typeof revokeStore.revoke === "function") {
      await revokeStore.revoke(key);
      return { ok: true, key: key };
    }
    localRevoked.add(key);
    return { ok: true, key: key };
  };
  fn.unrevoke = async function (key) {
    if (revokeStore && typeof revokeStore.unrevoke === "function") {
      await revokeStore.unrevoke(key);
      return { ok: true, key: key };
    }
    localRevoked.delete(key);
    return { ok: true, key: key };
  };
  fn.stats = function () {
    return Object.assign({}, stats);
  };
  fn.invalidateMeta = function (key) {
    _metaCache.delete(key);
    return { ok: true, key: key };
  };
  return fn;
}

function _resetCacheForTest() { _metaCache.clear(); }

module.exports = {
  create:                 create,
  integrity:              integrity,
  DEFAULT_MAX_AGE_SEC:    DEFAULT_MAX_AGE_SEC,
  IMMUTABLE_MAX_AGE_SEC:  IMMUTABLE_MAX_AGE_SEC,
  DEFAULT_HASHED_PATTERN: DEFAULT_HASHED_PATTERN,
  _resetCacheForTest:     _resetCacheForTest,
  _parseRangeHeader:      _parseRangeHeader,
};
