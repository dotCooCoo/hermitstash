// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.middleware.nel
 * @nav        HTTP
 * @title      Network Error Logging
 * @order      125
 * @card       W3C Network Error Logging — emits the `NEL` and companion
 *             `Report-To` headers so user-agents post network-failure
 *             reports (DNS failures, TLS handshake errors, TCP resets,
 *             HTTP-error class samples) back to an operator-controlled
 *             collector. Pair with `b.middleware.cspReport` for a
 *             unified browser-side telemetry channel.
 *
 * @intro
 *   Network Error Logging (W3C draft) is the browser's native channel
 *   for surfacing failures the server never sees: TLS handshake
 *   collapse before the request body, DNS lookup misses, CDN routing
 *   resets, premature TCP teardown mid-response. The user-agent
 *   buffers these and POSTs JSON reports to a configured collector,
 *   keyed by the `report-to` group named in the `NEL` header.
 *
 *   The middleware emits two response headers on every request it
 *   sees:
 *
 *     Report-To: { "group": "default", "max_age": 86400, "endpoints":
 *       [ { "url": "https://collector.example.com/nel" } ] }
 *     NEL:       { "report_to": "default", "max_age": 86400,
 *       "include_subdomains": false, "success_fraction": 0,
 *       "failure_fraction": 1 }
 *
 *   Both header values are JSON dictionaries; the framework refuses
 *   any operator-supplied collector URL containing CR/LF/NUL so a
 *   typo can't smuggle a header-injection payload into the wire
 *   format.
 *
 *   Mount AFTER `securityHeaders` (so the response writeHead order
 *   stays predictable) and BEFORE business middleware. Pair with
 *   `b.middleware.cspReport` so a single collector receives both NEL
 *   and CSP reports — operators commonly point both at the same
 *   `/_telemetry` endpoint.
 *
 *     app.use(b.middleware.requestId());
 *     app.use(b.middleware.securityHeaders());
 *     app.use(b.middleware.nel({
 *       reportTo:           "default",
 *       collectorUrl:       "https://collector.example.com/nel",
 *       maxAge:             86400,
 *       includeSubdomains:  false,
 *       successFraction:    0,
 *       failureFraction:    1,
 *     }));
 *
 *   The `successFraction` defaults to 0 because reporting every
 *   successful request is a billing surprise on busy origins;
 *   operators tune it up (0.001, 0.01) when sampling success
 *   distribution intentionally.
 */

var validateOpts = require("../validate-opts");
var C = require("../constants");

// Per W3C draft + the practical browser implementations. successFraction
// = 1.0 reports every request — fine for a low-traffic admin surface,
// catastrophic on a high-traffic CDN. failureFraction = 1.0 is the
// security-correct default; operators only lower it when they have a
// downstream rate-limit on the collector.
var DEFAULT_REPORT_GROUP    = "default";
var DEFAULT_MAX_AGE         = C.TIME.hours(24) / C.TIME.seconds(1);  // NEL header takes seconds
var DEFAULT_SUCCESS_FRACTION = 0;
var DEFAULT_FAILURE_FRACTION = 1;

// Header injection defense — every operator-supplied string that
// reaches a header value is screened for CR/LF/NUL. The collector
// URL flows into JSON inside Report-To; a CR there would let an
// attacker forge an arbitrary follow-up header on stacks that
// concatenate header lines naively.
var INJECTION_RE = /[\r\n\0]/;

function _refuseInjection(value, label) {
  if (typeof value !== "string") return;
  if (INJECTION_RE.test(value)) {  // allow:regex-no-length-cap — CR/LF/NUL injection check, length bounded by caller
    throw new TypeError(
      "middleware.nel: " + label + " contains CR/LF/NUL — refused as a " +
      "header-injection vector");
  }
}

/**
 * @primitive b.middleware.nel
 * @signature b.middleware.nel(req, res, next)
 * @since     0.8.53
 * @status    stable
 * @related   b.middleware.cspReport, b.middleware.securityHeaders
 *
 * Builds middleware that emits the W3C Network Error Logging `NEL`
 * and companion `Report-To` headers so user-agents post failure
 * telemetry back to an operator-controlled collector. Mount near the
 * top of the chain (after `requestId` and `securityHeaders`) so every
 * response carries the headers — NEL is a long-lived browser policy,
 * not a per-route concern.
 *
 * The two header bodies are JSON dictionaries built once at construct
 * time. Operator-supplied strings flow through a CR/LF/NUL refusal
 * check so a typo in `collectorUrl` can't smuggle additional headers
 * onto the wire.
 *
 * @opts
 *   {
 *     reportTo:          string,    // group name (default "default")
 *     collectorUrl:      string,    // required — collector POST URL
 *     maxAge:            number,    // policy lifetime in seconds (default 86400)
 *     includeSubdomains: boolean,   // default false
 *     successFraction:   number,    // 0..1, default 0
 *     failureFraction:   number,    // 0..1, default 1
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.requestId());
 *   app.use(b.middleware.securityHeaders());
 *   app.use(b.middleware.nel({
 *     collectorUrl:      "https://collector.example.com/nel",
 *     maxAge:            86400,
 *     successFraction:   0,
 *     failureFraction:   1,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "reportTo", "collectorUrl", "maxAge",
    "includeSubdomains", "successFraction", "failureFraction",
  ], "middleware.nel");

  // Per-file allowlist in test/layer-0-primitives/codebase-patterns.test.js
  // for inline-require-non-empty-string-validation — the operator-readable
  // "collectorUrl is required" prose is part of the public test contract;
  // validateOpts.requireNonEmptyString would emit a generic
  // "validate-opts/missing-non-empty-string" message instead.
  if (typeof opts.collectorUrl !== "string" || opts.collectorUrl.length === 0) {
    throw new TypeError(
      "middleware.nel: opts.collectorUrl is required (the URL the user-agent " +
      "POSTs network-failure reports to)");
  }
  _refuseInjection(opts.collectorUrl, "opts.collectorUrl");

  // The collector URL must be an https:// scheme — browsers only
  // honor secure-origin report endpoints. Refusing at config-time so
  // an operator typo (`http://`) surfaces at boot, not as silent
  // never-fires-in-production.
  if (opts.collectorUrl.slice(0, 8) !== "https://") {                                       // string-prefix length, not bytes
    throw new TypeError(
      "middleware.nel: opts.collectorUrl must be https:// (browsers " +
      "ignore non-secure NEL collectors); got " + opts.collectorUrl);
  }

  var reportTo = opts.reportTo === undefined ? DEFAULT_REPORT_GROUP : opts.reportTo;
  if (typeof reportTo !== "string" || reportTo.length === 0) {
    throw new TypeError("middleware.nel: opts.reportTo must be a non-empty string");
  }
  _refuseInjection(reportTo, "opts.reportTo");

  var maxAge = opts.maxAge === undefined ? DEFAULT_MAX_AGE : opts.maxAge;
  if (typeof maxAge !== "number" || !isFinite(maxAge) || maxAge < 0) {
    throw new TypeError("middleware.nel: opts.maxAge must be a non-negative finite number (seconds)");
  }

  var includeSubdomains = opts.includeSubdomains === undefined ? false : !!opts.includeSubdomains;

  var successFraction = opts.successFraction === undefined ? DEFAULT_SUCCESS_FRACTION : opts.successFraction;
  if (typeof successFraction !== "number" || !isFinite(successFraction) ||
      successFraction < 0 || successFraction > 1) {
    throw new TypeError("middleware.nel: opts.successFraction must be a number in [0, 1]");
  }

  var failureFraction = opts.failureFraction === undefined ? DEFAULT_FAILURE_FRACTION : opts.failureFraction;
  if (typeof failureFraction !== "number" || !isFinite(failureFraction) ||
      failureFraction < 0 || failureFraction > 1) {
    throw new TypeError("middleware.nel: opts.failureFraction must be a number in [0, 1]");
  }

  // Build the two header values once at construct time. JSON.stringify
  // produces the canonical compact form; the property ordering is
  // stable per V8 spec.
  var reportToHeader = JSON.stringify({
    group:     reportTo,
    max_age:   maxAge,
    endpoints: [{ url: opts.collectorUrl }],
  });
  var nelHeader = JSON.stringify({
    report_to:          reportTo,
    max_age:            maxAge,
    include_subdomains: includeSubdomains,
    success_fraction:   successFraction,
    failure_fraction:   failureFraction,
  });

  return function nel(req, res, next) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Report-To", reportToHeader);
      res.setHeader("NEL",       nelHeader);
    }
    next();
  };
}

module.exports = {
  create:                   create,
  DEFAULT_REPORT_GROUP:     DEFAULT_REPORT_GROUP,
  DEFAULT_MAX_AGE:          DEFAULT_MAX_AGE,
  DEFAULT_SUCCESS_FRACTION: DEFAULT_SUCCESS_FRACTION,
  DEFAULT_FAILURE_FRACTION: DEFAULT_FAILURE_FRACTION,
};
