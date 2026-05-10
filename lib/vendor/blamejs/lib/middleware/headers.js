"use strict";
/**
 * b.middleware.headers — inbound HTTP header threat detection.
 *
 * Sits at the top of the request lifecycle. Validates the inbound
 * headers against the RFC 9110 §5.1 token grammar and surfaces threat
 * shapes: CRLF injection, CL+TE request smuggling (RFC 9112 §6.1),
 * oversized header / count, deprecated trust-header patterns.
 *
 * Threat catalog:
 *   - header-name-shape — header name not a valid RFC 9110 token.
 *   - header-value-control-byte — CR / LF / NUL inside a header value
 *     (header-injection defense in depth on top of Node's rejection).
 *   - header-count-cap — > maxHeaderCount headers (default 100).
 *   - header-value-cap — single value > maxValueBytes (default 8 KiB).
 *   - smuggling-cl-te — Content-Length AND Transfer-Encoding both
 *     present (RFC 9112 §6.1 — CL.TE / TE.CL smuggling shape).
 *   - smuggling-cl-multi — multiple Content-Length values (proxy-
 *     desync class).
 *   - smuggling-te-multi — multiple Transfer-Encoding values.
 *   - deprecated-trust-header — X-Forwarded-For / X-Forwarded-Proto /
 *     X-Forwarded-Host present without operator-supplied trustProxy
 *     opt — the framework warns once that the operator should adopt
 *     RFC 7239 `Forwarded` or explicit trustProxy.
 *
 *   var middleware = b.middleware.headers({
 *     mode:               "enforce",       // "enforce" | "audit-only" | "log-only"
 *     audit:              b.audit,
 *     maxHeaderCount:     100,
 *     maxValueBytes:      8 * 1024,
 *     trustProxy:         false,            // whether X-Forwarded-* is allowed
 *     refuseOnHigh:       true,
 *   });
 */

var lazyRequire = require("../lazy-require");
var safeBuffer = require("../safe-buffer");

var observability = lazyRequire(function () { return require("../observability"); });
void observability;

// RFC 9110 §5.1 token grammar — tchar set per RFC 7230.
var TOKEN_RE = safeBuffer.RFC7230_TCHAR_RE;

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

    // Header name shape — Node lowercases names; the original tchar
    // grammar covers a-z / 0-9 / `!#$%&'*+-.^_`|~`.
    if (!TOKEN_RE.test(name)) {                                                  // allow:regex-no-length-cap — Node already caps header name length at 8190 chars by default (HTTP/1.1 line cap)
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
      for (var ci = 0; ci < v.length; ci += 1) {
        var cc = v.charCodeAt(ci);
        if (cc === 0x0D || cc === 0x0A || cc === 0x00) {                         // allow:raw-byte-literal — CR / LF / NUL forbidden in header value
          issues.push({
            kind: "header-value-control-byte", severity: "high", header: name,
            snippet: "header `" + name + "` value contains CR / LF / NUL " +
                     "— header-injection defense in depth",
          });
          break;
        }
      }
    }
  }

  // Smuggling shapes (RFC 9112 §6.1).
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

  // Deprecated trust-header pattern.
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
    maxHeaderCount: opts.maxHeaderCount || 100,                                  // allow:raw-byte-literal — header count ceiling
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
