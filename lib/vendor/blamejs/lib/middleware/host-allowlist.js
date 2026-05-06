"use strict";
/**
 * host-allowlist — DNS rebinding defense.
 *
 * Refuses requests whose `Host` header doesn't match the operator-
 * supplied allowlist. The DNS rebinding attack chain is:
 *
 *   1. Attacker sets a short-TTL DNS record for evil.com pointing
 *      at their own server.
 *   2. Victim's browser visits attacker's page; the page issues
 *      fetch() requests to evil.com.
 *   3. Attacker's DNS now answers evil.com → 127.0.0.1 (or the
 *      operator's internal IP).
 *   4. Browser, applying same-origin policy on the URL string,
 *      thinks fetch() is hitting evil.com — but the connection
 *      lands on the operator's localhost / internal service.
 *   5. The operator's service serves whatever it would serve to
 *      its own admin UI; the JS reads the response.
 *
 * Defense: refuse the request unless the `Host` header (the part
 * the operator's server actually sees) matches a known origin.
 *
 *   var allow = b.middleware.hostAllowlist({
 *     hosts:        ["app.example.com", "app.example.com:443"],
 *     denyStatus:   421,           // RFC 7540 §9.1.2 "Misdirected Request"
 *     denyBody:     "Misdirected Request",
 *     audit:        true,
 *   });
 *   router.use(allow);
 *
 * Operators behind a CDN / proxy that rewrites the Host header set
 * `hosts` to the post-rewrite values. Wildcard-leading entries
 * (`*.example.com`) match any single label. Localhost is explicitly
 * allowed only when the operator lists it.
 *
 * Operators running an explicitly-public service (anyone-can-host-
 * the-domain shapes — e.g. a forum that serves arbitrary subdomains)
 * skip this middleware entirely; there's no opt-out per request.
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var HostAllowlistError = defineClass("HostAllowlistError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("../audit"); });

function _normalizeHostEntry(s) {
  // Lowercase + strip whitespace. Per RFC 7230 §5.4 the Host header is
  // case-insensitive on the host portion.
  if (typeof s !== "string") return null;
  var t = s.trim().toLowerCase();
  if (t.length === 0) return null;
  return t;
}

// Match a single allowlist entry against an actual Host header value.
// Wildcards: `*.example.com` matches `app.example.com` but not
// `app.sub.example.com` (single-label only). Exact host:port match
// is supported when the entry includes a port; entries without a port
// match any port.
function _matches(entry, actual) {
  if (entry === actual) return true;
  // Wildcard prefix
  if (entry.indexOf("*.") === 0) {
    var suffix = entry.slice(1);                 // ".example.com"
    var actualHost = actual.split(":")[0];
    if (actualHost.length <= suffix.length) return false;
    if (actualHost.slice(-suffix.length) !== suffix) return false;
    var prefix = actualHost.slice(0, actualHost.length - suffix.length);
    if (prefix.indexOf(".") !== -1) return false;  // single-label
    return true;
  }
  // Port-stripped equality — entry without port matches any port
  if (entry.indexOf(":") === -1 && actual.indexOf(":") !== -1) {
    var actualNoPort = actual.split(":")[0];
    return entry === actualNoPort;
  }
  return false;
}

function create(opts) {
  validateOpts.requireObject(opts, "middleware.hostAllowlist", HostAllowlistError);
  validateOpts(opts, [
    "hosts", "denyStatus", "denyBody", "audit",
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

  var denyStatus = (typeof opts.denyStatus === "number") ? opts.denyStatus : 421;  // allow:raw-byte-literal — HTTP 421 status
  var denyBody = typeof opts.denyBody === "string" ? opts.denyBody : "Misdirected Request";
  var auditOn = opts.audit !== false;

  return function hostAllowlistMiddleware(req, res, next) {
    var raw = req.headers && req.headers.host;
    if (typeof raw !== "string" || raw.length === 0) {
      // RFC 7230 §5.4 — a request without a Host header is malformed
      // for HTTP/1.1; HTTP/2 maps :authority into req.headers.host
      // automatically. Reject either shape.
      _deny(res, denyStatus, denyBody);
      _emitDenied(req, "missing-host");
      return;
    }
    var actual = raw.toLowerCase();
    var matched = false;
    for (var hi = 0; hi < hosts.length; hi += 1) {
      if (_matches(hosts[hi], actual)) { matched = true; break; }
    }
    if (!matched) {
      _deny(res, denyStatus, denyBody);
      _emitDenied(req, "host-not-in-allowlist", actual);
      return;
    }
    return next();
  };

  function _deny(res, status, body) {
    if (res.headersSent) return;
    res.writeHead(status, {
      "Content-Type":   "text/plain; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
    });
    res.end(body);
  }

  function _emitDenied(req, reason, actual) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:  "network.host_allowlist.denied",
        outcome: "fail",
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
