// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("../codepoint-class");
var lazyRequire = require("../lazy-require");
var safeBuffer = require("../safe-buffer");

var observability = lazyRequire(function () { return require("../observability"); });
void observability;

var _isToken = safeBuffer.isHttpToken;

var DEPRECATED_TRUST_HEADERS = Object.freeze([
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-real-ip",
]);

function _emitAudit(audit, action, outcome, metadata) {
  if (!audit || typeof audit.safeEmit !== "function") return;
  try {
    audit.safeEmit({
      action:   action,
      actor:    metadata.actor || { kind: "framework", id: "middleware/headers" },
      outcome:  outcome,
      metadata: metadata,
    });
  } catch (_e) { /* drop-silent — observability sink */ }
}

function _detectIssues(headers, opts) {
  var issues = [];
  if (!headers || typeof headers !== "object") return issues;

  var names = Object.keys(headers);

  if (names.length > opts.maxHeaderCount) {
    issues.push({
      kind: "header-count-cap", severity: "high",
      snippet: "request has " + names.length + " headers, exceeds " +
               "maxHeaderCount " + opts.maxHeaderCount,
    });
  }

  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    var value = headers[name];

    if (!_isToken(name)) {
      issues.push({
        kind: "header-name-shape", severity: "high",
        snippet: "header name `" + name + "` is not a valid RFC 9110 " +
                 "§5.1 token",
      });
    }

    var valueArr = Array.isArray(value) ? value : [value];
    for (var vi = 0; vi < valueArr.length; vi += 1) {
      var v = valueArr[vi];
      if (typeof v !== "string") continue;
      if (Buffer.byteLength(v, "utf8") > opts.maxValueBytes) {
        issues.push({
          kind: "header-value-cap", severity: "high", header: name,
          snippet: "header `" + name + "` value " + v.length +
                   " bytes exceeds maxValueBytes " + opts.maxValueBytes,
        });
        continue;
      }
      if (codepointClass.firstLineInjectionCharOffset(v) !== -1) {
        issues.push({
          kind: "header-value-control-byte", severity: "high", header: name,
          snippet: "header `" + name + "` value contains CR / LF / NUL " +
                   "— header-injection defense in depth",
        });
      }
    }
  }

  var clRaw = headers["content-length"];
  var teRaw = headers["transfer-encoding"];
  if (clRaw !== undefined && teRaw !== undefined) {
    issues.push({
      kind: "smuggling-cl-te", severity: "high",
      snippet: "both Content-Length and Transfer-Encoding present " +
               "(RFC 9112 §6.1 — CL.TE / TE.CL request-smuggling vector)",
    });
  }
  if (Array.isArray(clRaw) && clRaw.length > 1) {
    issues.push({
      kind: "smuggling-cl-multi", severity: "high",
      snippet: "multiple Content-Length values — proxy-desync " +
               "request-smuggling vector",
    });
  }
  if (Array.isArray(teRaw) && teRaw.length > 1) {
    issues.push({
      kind: "smuggling-te-multi", severity: "high",
      snippet: "multiple Transfer-Encoding values — proxy-desync " +
               "request-smuggling vector",
    });
  }

  if (!opts.trustProxy) {
    for (var di = 0; di < DEPRECATED_TRUST_HEADERS.length; di += 1) {
      var h = DEPRECATED_TRUST_HEADERS[di];
      if (headers[h] !== undefined) {
        issues.push({
          kind: "deprecated-trust-header", severity: "warn", header: h,
          snippet: "request carries `" + h + "` but trustProxy is " +
                   "false — adopt RFC 7239 `Forwarded` or set " +
                   "trustProxy explicitly",
        });
      }
    }
  }

  return issues;
}

/**
 * @primitive b.middleware.headers
 * @signature b.middleware.headers(opts)
 * @since     0.1.0
 * @related   b.middleware.cookies, b.middleware.bodyParser
 *
 * Inbound HTTP header threat detection. Validates header names
 * against the RFC 9110 §5.1 token grammar and surfaces CRLF
 * injection, RFC 9112 §6.1 CL+TE request-smuggling shapes, multiple
 * `Content-Length` / `Transfer-Encoding` values, oversize header
 * count / value, and deprecated `X-Forwarded-*` patterns when the
 * operator hasn't opted into `trustProxy`. In `mode: "enforce"`
 * (default) high-severity issues refuse with HTTP 400 + `Connection:
 * close`; `audit-only` and `log-only` pass through but still emit
 * audits.
 *
 * @opts
 *   {
 *     mode:           "enforce"|"audit-only"|"log-only",  // default "enforce"
 *     refuseOnHigh:   boolean,    // default true (enforce only)
 *     maxHeaderCount: number,     // default 100
 *     maxValueBytes:  number,     // default 8 KiB
 *     trustProxy:     boolean,
 *     audit:          object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.headers({
 *     mode:           "enforce",
 *     maxHeaderCount: 100,
 *     maxValueBytes:  b.constants.BYTES.kib(8),
 *   }));
 */
function create(opts) {
  opts = opts || {};
  var mode = opts.mode || "enforce";
  var refuseOnHigh = opts.refuseOnHigh !== false && mode === "enforce";
  var audit = opts.audit || null;
  var resolved = {
    maxHeaderCount: opts.maxHeaderCount || 100,
    maxValueBytes:  opts.maxValueBytes  || 8 * 1024,                             // allow:raw-byte-literal — header value cap (8 KiB)
    trustProxy:     !!opts.trustProxy,
  };

  return function headersMiddleware(req, res, next) {
    var headers = req && req.headers ? req.headers : {};
    var issues = _detectIssues(headers, resolved);
    if (issues.length === 0) return next();

    var hasHigh = false;
    for (var i = 0; i < issues.length; i += 1) {
      var iss = issues[i];
      if (iss.severity === "high") hasHigh = true;
      _emitAudit(audit, "middleware.headers.threat-detected",
        iss.severity === "high" ? "blocked" : "audit", {
          kind:    iss.kind,
          header:  iss.header || null,
          snippet: iss.snippet,
          mode:    mode,
        });
    }

    if (hasHigh && refuseOnHigh) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({
        error:  "header-threat-detected",
        issues: issues.filter(function (i) { return i.severity === "high"; })
                      .map(function (i) {
                        return { kind: i.kind, header: i.header || null };
                      }),
      }));
      return;
    }
    return next();
  };
}

module.exports = { create: create };
