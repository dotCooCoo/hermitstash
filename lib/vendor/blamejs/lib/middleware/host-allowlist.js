// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");

var HostAllowlistError = defineClass("HostAllowlistError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("../audit"); });

function _normalizeHostEntry(s) {
  if (typeof s !== "string") return null;
  var t = s.trim().toLowerCase();
  if (t.length === 0) return null;
  return t;
}

function _matches(entry, actual) {
  if (entry === actual) return true;
  if (entry.indexOf("*.") === 0) {
    var suffix = entry.slice(1);
    var actualHost = actual.split(":")[0];
    if (actualHost.length <= suffix.length) return false;
    if (actualHost.slice(-suffix.length) !== suffix) return false;
    var prefix = actualHost.slice(0, actualHost.length - suffix.length);
    if (prefix.indexOf(".") !== -1) return false;
    return true;
  }
  if (entry.indexOf(":") === -1 && actual.indexOf(":") !== -1) {
    var actualNoPort = actual.split(":")[0];
    return entry === actualNoPort;
  }
  return false;
}

/**
 * @primitive b.middleware.hostAllowlist
 * @signature b.middleware.hostAllowlist(opts)
 * @since     0.1.0
 * @related   b.middleware.networkAllowlist, b.middleware.cors
 *
 * DNS-rebinding defense. Refuses requests whose `Host` header
 * doesn't match the operator-supplied allowlist. Wildcard-leading
 * entries (`*.example.com`) match a single label. Entries without
 * a port match any port. Refuses with HTTP 421 (Misdirected
 * Request) by default. Operators behind a CDN that rewrites the
 * Host set `hosts` to the post-rewrite values. Skip entirely for
 * services that serve arbitrary subdomains by design (anyone-can-
 * host-the-domain shapes).
 *
 * @opts
 *   {
 *     hosts:      string[],   // required, non-empty
 *     denyStatus: number,     // default 421
 *     denyBody:   string,
 *     audit:      boolean,    // default true
 *     onDeny:     function(req, res, info): void,  // own the refusal; info = { status, reason, host }
 *     problemDetails: boolean, // default false — emit RFC 9457 application/problem+json instead of text/plain
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.hostAllowlist({
 *     hosts: ["app.example.com", "*.example.com"],
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.hostAllowlist", HostAllowlistError);
  validateOpts(opts, [
    "hosts", "denyStatus", "denyBody", "audit", "onDeny", "problemDetails",
  ], "middleware.hostAllowlist");

  if (!Array.isArray(opts.hosts) || opts.hosts.length === 0) {
    throw new HostAllowlistError("host-allowlist/no-hosts",
      "middleware.hostAllowlist: opts.hosts must be a non-empty array of allowed Host header values");
  }
  var hosts = [];
  for (var i = 0; i < opts.hosts.length; i += 1) {
    var n = _normalizeHostEntry(opts.hosts[i]);
    if (!n) {
      throw new HostAllowlistError("host-allowlist/bad-host",
        "middleware.hostAllowlist: hosts[" + i + "] is not a non-empty string");
    }
    hosts.push(n);
  }

  var denyStatus = (typeof opts.denyStatus === "number") ? opts.denyStatus : 421;
  var denyBody = typeof opts.denyBody === "string" ? opts.denyBody : "Misdirected Request";
  var auditOn = opts.audit !== false;
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  return function hostAllowlistMiddleware(req, res, next) {
    var raw = requestHelpers.requestHost(req);
    if (typeof raw !== "string" || raw.length === 0) {
      _deny(req, res, "missing-host", null);
      _emitDenied(req, "missing-host");
      return;
    }
    var actual = raw.toLowerCase();
    var matched = false;
    for (var hi = 0; hi < hosts.length; hi += 1) {
      if (_matches(hosts[hi], actual)) { matched = true; break; }
    }
    if (!matched) {
      _deny(req, res, "host-not-in-allowlist", actual);
      _emitDenied(req, "host-not-in-allowlist", actual);
      return;
    }
    return next();
  };

  function _deny(req, res, reason, host) {
    if (res.headersSent) return;
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        denyStatus,
      info:          { status: denyStatus, reason: reason, host: host },
      problemCode:   "misdirected-request",
      problemTitle:  "Misdirected Request",
      problemDetail: "The request Host header is not served by this endpoint.",
      contentType:   "text/plain; charset=utf-8",
      body:          denyBody,
    });
  }

  function _emitDenied(req, reason, actual) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:  "network.host_allowlist.denied",
        outcome: "denied",
        actor:   { clientIp: requestHelpers.clientIp(req) },
        metadata: {
          reason:  reason,
          host:    actual || null,
          route:   req.url,
        },
      });
    } catch (_e) { /* drop-silent — observability sink failure */ }
  }
}

module.exports = {
  create: create,
};
