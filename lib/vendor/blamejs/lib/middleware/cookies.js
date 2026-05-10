"use strict";
/**
 * b.middleware.cookies — inbound cookie-header threat detection.
 *
 * Sits in the request lifecycle and runs `b.cookies.parseSafe` against
 * the inbound `Cookie` header. Threat detection always-on; the gate
 * either refuses, audits, or logs the detected anomalies based on the
 * operator's `mode`.
 *
 * Threats surfaced (see lib/cookies.js parseSafe):
 *   - header-cap        — Cookie header exceeds maxHeaderBytes
 *   - header-control-byte — CR / LF / NUL injected through proxy
 *   - pair-malformed    — pair missing `=`
 *   - pair-empty-name   — empty name
 *   - name-cap          — cookie name exceeds maxNameBytes
 *   - value-cap         — cookie value exceeds maxValueBytes
 *   - duplicate-name    — name appears >1 time (cookie-tossing class)
 *
 * Side effects:
 *   - req.cookieJar  — populated with the parsed jar (overwriteable)
 *   - audit emission — one row per detected high-severity issue
 *   - response       — refused requests get HTTP 400 + JSON body
 *
 *   var middleware = b.middleware.cookies({
 *     mode:           "enforce",     // "enforce" | "audit-only" | "log-only"
 *     audit:          b.audit,
 *     maxHeaderBytes: 8 * 1024,
 *     refuseOnHigh:   true,          // 400 if any high-severity issue
 *   });
 */

var cookies = require("../cookies");
var lazyRequire = require("../lazy-require");

var observability = lazyRequire(function () { return require("../observability"); });
void observability;

function _emitAudit(audit, action, outcome, metadata) {
  if (!audit || typeof audit.safeEmit !== "function") return;
  try {
    audit.safeEmit({
      action:   action,
      actor:    metadata.actor || { kind: "framework", id: "middleware/cookies" },
      outcome:  outcome,
      metadata: metadata,
    });
  } catch (_e) { /* drop-silent — observability sink */ }
}

/**
 * @primitive b.middleware.cookies
 * @signature b.middleware.cookies(opts)
 * @since     0.1.0
 * @related   b.cookies.parseSafe, b.middleware.csrfProtect
 *
 * Inbound `Cookie` header threat detection. Runs every request through
 * `b.cookies.parseSafe` and surfaces header-cap / control-byte /
 * malformed-pair / empty-name / name-cap / value-cap / duplicate-name
 * (cookie-tossing) issues. Sets `req.cookieJar` to the parsed jar.
 * In `mode: "enforce"` (default) high-severity issues refuse the
 * request with HTTP 400 + JSON body; `audit-only` and `log-only`
 * modes pass through but still emit audits.
 *
 * @opts
 *   {
 *     mode:           "enforce"|"audit-only"|"log-only",  // default "enforce"
 *     refuseOnHigh:   boolean,    // default true (only meaningful in enforce)
 *     maxHeaderBytes: number,
 *     maxNameBytes:   number,
 *     maxValueBytes:  number,
 *     audit:          object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.cookies({
 *     mode:           "enforce",
 *     maxHeaderBytes: b.constants.BYTES.kib(8),
 *   }));
 */
function create(opts) {
  opts = opts || {};
  var mode = opts.mode || "enforce";
  var refuseOnHigh = opts.refuseOnHigh !== false && mode === "enforce";
  var maxHeaderBytes = opts.maxHeaderBytes;
  var maxNameBytes = opts.maxNameBytes;
  var maxValueBytes = opts.maxValueBytes;
  var audit = opts.audit || null;

  return function cookiesMiddleware(req, res, next) {
    var header = req && req.headers ? req.headers.cookie : "";
    var rv = cookies.parseSafe(header || "", {
      maxHeaderBytes: maxHeaderBytes,
      maxNameBytes:   maxNameBytes,
      maxValueBytes:  maxValueBytes,
    });
    req.cookieJar = rv.jar;

    if (rv.issues.length === 0) return next();

    var hasHigh = false;
    for (var i = 0; i < rv.issues.length; i += 1) {
      var iss = rv.issues[i];
      if (iss.severity === "high") hasHigh = true;
      _emitAudit(audit, "middleware.cookies.threat-detected",
        iss.severity === "high" ? "blocked" : "audit", {
          kind:    iss.kind,
          name:    iss.name || null,
          snippet: iss.snippet,
          mode:    mode,
        });
    }

    if (hasHigh && refuseOnHigh) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({
        error:  "cookie-threat-detected",
        issues: rv.issues.map(function (i) {
          return { kind: i.kind, severity: i.severity };
        }),
      }));
      return;
    }
    return next();
  };
}

module.exports = { create: create };
