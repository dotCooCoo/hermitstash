"use strict";
/**
 * b.middleware.cspReport — Reporting-API endpoint for CSP / COEP /
 * COOP / Permissions-Policy violations.
 *
 * The framework's default CSP appends `report-to default;` (see
 * lib/middleware/security-headers.js); operators wire the matching
 * `Reporting-Endpoints: default="https://app.example.com/csp-report"`
 * header — and mount this middleware at the configured path. Browsers
 * POST batches of violations as `application/reports+json`.
 *
 *   var cspReport = b.middleware.cspReport.create({
 *     audit:     b.audit,
 *     onReport:  function (report) { metrics.count("csp.violation", 1, { directive: report.body.effectiveDirective }); },
 *     maxBytes:  C.BYTES.kib(64),
 *   });
 *   router.post("/csp-report", cspReport);
 *
 * Audit shape: `csp.violation` (failure) per report; metadata carries
 * the report.body fields (blockedURL, documentURL, effectiveDirective,
 * sample, statusCode). Sample is truncated to 200 chars.
 *
 * Validation:
 *   - Refuses non-POST methods with 405
 *   - Refuses bodies > maxBytes (default 64 KiB) with 413
 *   - Refuses non-JSON bodies with 400
 *   - Accepts `application/reports+json` AND legacy `application/csp-report`
 */

var C = require("../constants");
var lazyRequire = require("../lazy-require");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");

var audit = lazyRequire(function () { return require("../audit"); });

var DEFAULT_MAX_BYTES = C.BYTES.kib(64);
var SAMPLE_TRUNCATE = 200;

function _truncate(value) {
  if (typeof value !== "string") return value;
  if (value.length <= SAMPLE_TRUNCATE) return value;
  return value.slice(0, SAMPLE_TRUNCATE) + "…";
}

function _normalizeOne(reportLike) {
  // Reporting API shape: { type, age, url, user_agent, body: {...} }
  // Legacy CSP shape:    { "csp-report": { ... } }
  if (!reportLike || typeof reportLike !== "object") return null;
  if (reportLike["csp-report"] && typeof reportLike["csp-report"] === "object") {
    var legacy = reportLike["csp-report"];
    return {
      type: "csp-violation",
      url:  legacy["document-uri"] || null,
      body: {
        documentURL:        legacy["document-uri"] || null,
        blockedURL:         legacy["blocked-uri"] || null,
        effectiveDirective: legacy["effective-directive"] || legacy["violated-directive"] || null,
        statusCode:         legacy["status-code"] || null,
        sample:             _truncate(legacy["script-sample"] || ""),
        sourceFile:         legacy["source-file"] || null,
        lineNumber:         legacy["line-number"] || null,
      },
    };
  }
  if (reportLike.type && reportLike.body && typeof reportLike.body === "object") {
    return {
      type: reportLike.type,
      url:  reportLike.url || null,
      body: {
        documentURL:        reportLike.body.documentURL || null,
        blockedURL:         reportLike.body.blockedURL || null,
        effectiveDirective: reportLike.body.effectiveDirective || null,
        statusCode:         reportLike.body.statusCode || null,
        sample:             _truncate(reportLike.body.sample || ""),
        sourceFile:         reportLike.body.sourceFile || null,
        lineNumber:         reportLike.body.lineNumber || null,
      },
    };
  }
  return null;
}

/**
 * @primitive b.middleware.cspReport
 * @signature b.middleware.cspReport(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.cspNonce, b.middleware.securityHeaders
 *
 * Reporting-API endpoint for CSP / COEP / COOP / Permissions-Policy
 * violations. Constructed via `b.middleware.cspReport(opts)`; the
 * resulting middleware has the `(req, res, next)` shape shown above. Accepts `application/reports+json` (modern) and the
 * legacy `application/csp-report` body shapes. Refuses non-POST
 * (HTTP 405), oversized bodies (HTTP 413, default 64 KiB cap), and
 * non-JSON (HTTP 400). Each report is normalized to a uniform shape
 * (`type`, `url`, `body.{documentURL, blockedURL, effectiveDirective,
 * sample, sourceFile, lineNumber}`), audited with action
 * `csp.violation`, and forwarded to the operator's `onReport`
 * callback for metrics or alerting.
 *
 * The rejection paths (405 / 413 / 400) are otherwise empty-bodied —
 * the spec'd Reporting API (W3C Reporting API §3.1) ignores the
 * response body, so there's nothing for the browser to read. `onReject`
 * surfaces these refusals to the operator for the same metrics /
 * alerting use as `onReport`: a flood of 413s signals a misconfigured
 * `Reporting-Endpoints` URL or a report-bomb. It receives
 * `(req, res, { status, reason })` where `reason` is one of
 * `method-not-allowed` / `payload-too-large` / `invalid-json`. Invoked
 * after the rejection response is written; a throwing hook is swallowed
 * so a broken metrics sink can't crash the endpoint.
 *
 * @opts
 *   {
 *     onReport: function(report): void,
 *     onReject: function(req, res, { status, reason }): void,
 *     maxBytes: number,    // default 64 KiB
 *     audit:    boolean,   // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/csp-report", b.middleware.cspReport({
 *     maxBytes: b.constants.BYTES.kib(64),
 *     onReport: function (report) {
 *       console.log("csp violation", report.body.effectiveDirective);
 *     },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["audit", "onReport", "onReject", "maxBytes"], "middleware.cspReport");
  if (opts.onReject !== undefined && opts.onReject !== null &&
      typeof opts.onReject !== "function") {
    throw new TypeError("middleware.cspReport: opts.onReject must be a function");
  }
  validateOpts.optionalPositiveInt(opts.maxBytes, "middleware.cspReport: maxBytes");
  var maxBytes = (opts.maxBytes === undefined || opts.maxBytes === null)
    ? DEFAULT_MAX_BYTES : opts.maxBytes;
  var auditOn  = opts.audit !== false;
  var onReport = (typeof opts.onReport === "function") ? opts.onReport : null;
  var onReject = (typeof opts.onReject === "function") ? opts.onReject : null;

  // Drop-silent observability sink — the rejection response is already
  // on the wire; a throwing metrics hook must not crash the endpoint.
  function _emitReject(req, res, status, reason) {
    if (!onReject) return;
    try { onReject(req, res, { status: status, reason: reason }); }
    catch (_e) { /* hook best-effort */ }
  }

  return async function cspReport(req, res, _next) {
    if (req.method !== "POST") {
      res.writeHead(405, { "Allow": "POST" });                                     // HTTP 405 status
      res.end();
      _emitReject(req, res, 405, "method-not-allowed");
      return;
    }
    var body;
    try {
      body = await safeBuffer.collectStream(req, { maxBytes: maxBytes });
    } catch (_e) {
      res.writeHead(413);                                                         // HTTP 413 status
      res.end();
      _emitReject(req, res, 413, "payload-too-large");
      return;
    }
    var parsed;
    try { parsed = safeJson.parse(body.toString("utf8")); }
    catch (_e) {
      res.writeHead(400);                                                         // HTTP 400 status
      res.end();
      _emitReject(req, res, 400, "invalid-json");
      return;
    }
    var reports = Array.isArray(parsed) ? parsed : [parsed];
    for (var i = 0; i < reports.length; i++) {
      var normalized = _normalizeOne(reports[i]);
      if (!normalized) continue;
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "csp.violation",
            outcome: "failure",
            metadata: Object.assign({ type: normalized.type, url: normalized.url }, normalized.body),
          });
        } catch (_e) { /* audit best-effort */ }
      }
      if (onReport) {
        try { onReport(normalized); } catch (_e) { /* hook best-effort */ }
      }
    }
    res.writeHead(204);                                                           // HTTP 204 status
    res.end();
  };
}

module.exports = { create: create };
