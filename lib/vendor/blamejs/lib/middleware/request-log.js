// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * request-log — HTTP access-log middleware. Captures method, path,
 * status, duration, response bytes, requestId, actor IP, user-agent
 * and emits one structured log entry per request via b.log.
 *
 *   router.use(b.middleware.requestLog({
 *     logger:        b.log.boot("http"),     // any b.log instance
 *     skipPaths:     ["/healthz", /^\/static/],
 *     trustProxy:    true,                   // honors X-Forwarded-For
 *     levelFn:       function (status) {     // default: 5xx=error, 4xx=warn, else info
 *       return status >= 500 ? "error" : status >= 400 ? "warn" : "info";
 *     },
 *     fields:        ["method", "path", "status", "durationMs",
 *                     "actorIp", "userAgent", "requestId", "bytes"],
 *   }));
 *
 * The middleware adopts `b.requestHelpers.captureResponseStatus` to
 * read the final status reliably (handlers that call `res.writeHead`
 * vs `res.statusCode = ...` vs `res.status(...).send(...)` all work).
 *
 * trustProxy gates X-Forwarded-For consumption — same boundary as the
 * rest of the framework. Default false; operators behind a sanitizing
 * reverse proxy opt in.
 *
 * Emits at log-level keyed off response status by default. Operators
 * who want one-level-fits-all pass a static string for `level` (e.g.
 * "debug" to keep access logs out of production stdout) or a function
 * for fully custom logic (e.g. "warn" only on slow-path requests).
 */
var C = require("../constants");
var guardRegex = require("../guard-regex");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");

var DEFAULT_FIELDS = [
  "method", "path", "status", "durationMs", "bytes",
  "actorIp", "userAgent", "requestId",
];

function _defaultLevel(status) {
  if (status >= 500) return "error";
  if (status >= 400) return "warn";
  return "info";
}

/**
 * @primitive b.middleware.requestLog
 * @signature b.middleware.requestLog(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.requestId, b.middleware.traceLogCorrelation
 *
 * HTTP access-log middleware. Constructed via
 * `b.middleware.requestLog(opts)`; the resulting middleware has the
 * `(req, res, next)` shape shown above. Emits one structured log entry per
 * request via the operator-supplied `b.log` instance, capturing
 * method / path / status / durationMs / bytes / actorIp / userAgent
 * / requestId. Reads the final status via
 * `b.requestHelpers.captureResponseStatus` so handlers using any
 * shape (`writeHead` / `statusCode =` / fluent `status(...).send`)
 * report correctly. `levelFn(status)` defaults to 5xx=error,
 * 4xx=warn, else info; pass a string `level` or custom function for
 * different policies. `trustProxy` gates `X-Forwarded-For`
 * consumption.
 *
 * @opts
 *   {
 *     logger:     object,                       // required b.log instance
 *     skipPaths:  Array<string|RegExp>,
 *     trustProxy: boolean|number,
 *     level:      string,
 *     levelFn:    function(status): string,
 *     fields:     string[],
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.requestLog({
 *     logger:    b.log.boot("http"),
 *     skipPaths: ["/healthz"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "logger", "skipPaths", "trustProxy", "level", "levelFn", "fields",
  ], "middleware.requestLog");
  var logger = opts.logger;
  if (!logger || typeof logger.info !== "function") {
    throw new Error("middleware.requestLog: opts.logger must be a b.log instance " +
      "(call b.log.boot(...) or b.log.create({...}))");
  }
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  for (var i = 0; i < skipPaths.length; i++) {
    if (typeof skipPaths[i] !== "string" && !(skipPaths[i] instanceof RegExp)) {
      throw new Error("middleware.requestLog: skipPaths[" + i + "] must be a string prefix or RegExp");
    }
    if (skipPaths[i] instanceof RegExp) {
      guardRegex.assertSafe(skipPaths[i], "middleware.requestLog: skipPaths[" + i + "]");
    }
  }
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var levelFn;
  if (typeof opts.levelFn === "function") {
    levelFn = opts.levelFn;
  } else if (typeof opts.level === "string") {
    var fixedLevel = opts.level;
    levelFn = function () { return fixedLevel; };
  } else {
    levelFn = _defaultLevel;
  }
  var fields = Array.isArray(opts.fields) && opts.fields.length > 0
    ? opts.fields.slice()
    : DEFAULT_FIELDS;

  function _shouldSkip(req) {
    var path = req.pathname || (req.url || "").split("?")[0];
    for (var i = 0; i < skipPaths.length; i++) {
      var entry = skipPaths[i];
      if (typeof entry === "string") { if (path.indexOf(entry) === 0) return true; }
      else if (entry.test(path)) return true;
    }
    return false;
  }

  return function requestLog(req, res, next) {
    if (_shouldSkip(req)) return next();
    var startedAt = process.hrtime ? process.hrtime() : null;
    var startedMs = Date.now();
    var bytes = 0;
    var statusFromWriteHead = null;
    var emitted = false;

    // Tally bytes off res.write / res.end and read the final status
    // when end fires. Inlined here (rather than composing
    // captureResponseStatus + a separate byte-counter) so the log
    // entry sees the fully-populated bytes counter — wrap order
    // matters: bytes must be incremented BEFORE the log emit.
    var origWrite     = res.write;
    var origEnd       = res.end;
    var origWriteHead = res.writeHead;
    res.writeHead = function (s) {
      statusFromWriteHead = s;
      return origWriteHead.apply(res, arguments);
    };
    res.write = function (chunk, enc, cb) {
      if (chunk != null) {
        var len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), enc || "utf8");
        bytes += len;
      }
      return origWrite.call(res, chunk, enc, cb);
    };
    res.end = function (chunk, enc, cb) {
      if (chunk != null) {
        var len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), enc || "utf8");
        bytes += len;
      }
      _emit();
      return origEnd.call(res, chunk, enc, cb);
    };

    function _emit() {
      if (emitted) return;
      emitted = true;
      var statusCode = statusFromWriteHead != null
        ? statusFromWriteHead
        : (typeof res.statusCode === "number" ? res.statusCode : requestHelpers.HTTP_STATUS.OK);
      var durationMs;
      if (startedAt && process.hrtime) {
        var d = process.hrtime(startedAt);
        durationMs = C.TIME.seconds(d[0]) + (d[1] / 1e6);
      } else {
        durationMs = Date.now() - startedMs;
      }
      var entry = {};
      var actor = requestHelpers.extractActorContext(req, {
        ip: requestHelpers.clientIp(req, { trustProxy: trustProxy }),
      });
      var src = {
        method:     req.method,
        path:       req.pathname || (req.url || "").split("?")[0],
        status:     statusCode,
        durationMs: Math.round(durationMs * 100) / 100,
        bytes:      bytes,
        actorIp:    actor.ip,
        userAgent:  actor.userAgent,
        requestId:  actor.requestId,
        sessionId:  actor.sessionId,
        userId:     actor.userId,
        route:      actor.route,
      };
      for (var fi = 0; fi < fields.length; fi++) {
        var f = fields[fi];
        if (Object.prototype.hasOwnProperty.call(src, f)) entry[f] = src[f];
      }
      var level = levelFn(statusCode, req, res);
      var fn = typeof logger[level] === "function" ? logger[level] : logger.info;
      try { fn.call(logger, "http", entry); } catch (_e) { /* never let log-emit failure crash the response */ }
    }

    return next();
  };
}

module.exports = {
  create: create,
};
