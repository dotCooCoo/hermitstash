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

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["audit", "onReport", "maxBytes"], "middleware.cspReport");
  var maxBytes = (typeof opts.maxBytes === "number" && isFinite(opts.maxBytes) && opts.maxBytes > 0)
    ? opts.maxBytes : DEFAULT_MAX_BYTES;
  var onReport = (typeof opts.onReport === "function") ? opts.onReport : null;

  return async function cspReport(req, res, _next) {
    if (req.method !== "POST") {
      res.writeHead(405, { "Allow": "POST" });                                     // allow:raw-byte-literal — HTTP 405 status
      res.end();
      return;
    }
    var body;
    try {
      body = await safeBuffer.boundedChunkCollector(req, { maxBytes: maxBytes });
    } catch (_e) {
      res.writeHead(413);                                                         // allow:raw-byte-literal — HTTP 413 status
      res.end();
      return;
    }
    var parsed;
    try { parsed = safeJson.parse(body.toString("utf8")); }
    catch (_e) {
      res.writeHead(400);                                                         // allow:raw-byte-literal — HTTP 400 status
      res.end();
      return;
    }
    var reports = Array.isArray(parsed) ? parsed : [parsed];
    for (var i = 0; i < reports.length; i++) {
      var normalized = _normalizeOne(reports[i]);
      if (!normalized) continue;
      try {
        audit().safeEmit({
          action:  "csp.violation",
          outcome: "failure",
          metadata: Object.assign({ type: normalized.type, url: normalized.url }, normalized.body),
        });
      } catch (_e) { /* audit best-effort */ }
      if (onReport) {
        try { onReport(normalized); } catch (_e) { /* hook best-effort */ }
      }
    }
    res.writeHead(204);                                                           // allow:raw-byte-literal — HTTP 204 status
    res.end();
  };
}

module.exports = { create: create };
