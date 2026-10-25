// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var ssrfGuard = require("../ssrf-guard");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });

var NetworkAllowlistError = defineClass("NetworkAllowlistError", { alwaysPermanent: true });
var _err = NetworkAllowlistError.factory;

function _checkedCidrs(value, field) {
  if (!Array.isArray(value)) {
    throw _err("network-allowlist/bad-opt", field + " must be an array of CIDR strings, got " + typeof value);
  }
  for (var i = 0; i < value.length; i++) {
    var entry = value[i];
    var problem = (typeof entry !== "string" || entry.indexOf("/") === -1)
      ? "is not a CIDR string (network/prefix)"
      : ssrfGuard._listEntryProblem(entry);
    if (problem !== null) {
      throw _err("network-allowlist/bad-opt",
        field + "[" + i + "] (" + JSON.stringify(entry) + ") " + problem);
    }
  }
  return value.map(ssrfGuard._canonicalListEntry);
}

/**
 * @primitive b.middleware.networkAllowlist
 * @signature b.middleware.networkAllowlist(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.hostAllowlist, b.middleware.requireAuth
 *
 * In-process CIDR fence for path-scoped admin gates. Constructed
 * via `b.middleware.networkAllowlist(opts)`; the resulting
 * middleware has the `(req, res, next)` shape shown above. Path-based
 * authorization prevents unauthorized USERS from reaching sensitive
 * routes; this middleware adds a NETWORK-layer fence so a credential
 * leak doesn't compromise the gate. Path-scoped — requests outside
 * the configured prefixes pass through hot-path-cheap. Checks the
 * resolved client IP against `deniedCidrs` and then `allowedCidrs`, and
 * refuses a denied or unlisted client with HTTP 404 by default (hides the
 * gate from probes). Throws `network-allowlist/bad-opt` at create-time on
 * malformed opts, including a `deniedCidrs` that is not an array and a
 * CIDR entry whose network is not an IP address or whose prefix is not a
 * decimal integer from 0 to 32 (IPv4) or 128 (IPv6), such as
 * `10.0.0.0/33`, `10.0.0/8`, `010.0.0.0/8` or `10.0.0.0/8x`.
 *
 * Addresses and entries are compared in their canonical form, the rules
 * `b.ssrfGuard.createAllowlist` uses. A dual-stack listener reports an IPv4
 * client as `::ffff:a.b.c.d`, and that client is compared as the IPv4
 * address; an IPv4-mapped entry with a prefix of 96 or more
 * (`::ffff:10.0.0.0/104`) is compared as the IPv4 CIDR it covers. A
 * `deniedCidrs` entry also matches an IPv4 client through its `::ffff:`
 * form, and a 6to4 (`2002::/16`) or NAT64 (`64:ff9b::/96`) client through
 * the IPv4 address it carries, so an IPv6 entry containing `::ffff:0:0/96`
 * (`::/0`) denies every IPv4 client. An `allowedCidrs` entry matches only
 * the canonical form.
 *
 * Client-IP resolution is peer-gated. By default only the socket
 * address is used — X-Forwarded-For is attacker-forgeable, so trusting
 * it bare would let a direct caller spoof an allowed IP through the
 * gate. Behind a reverse proxy, declare it with `trustedProxies`
 * (CIDRs — XFF is then honored only when the immediate peer is one of
 * them) or own resolution entirely with `clientIpResolver(req)`. A bare
 * `trustProxy` is refused at construction.
 *
 * @opts
 *   {
 *     paths:           string[],   // pathname prefixes, required
 *     allowedCidrs:    string[],   // required
 *     deniedCidrs:     string[],
 *     trustedProxies:  string[],   // CIDRs of your reverse proxies — peer-gates X-Forwarded-For
 *     clientIpResolver: function(req): string|null,  // own client-IP resolution
 *     trustProxy:      boolean|number,  // legacy; refused unless paired with trustedProxies/resolver
 *                                       // (spoofable for an access-control gate), and never contributes
 *     denyStatus:      number,     // default 404
 *     denyBody:        string,     // default "Not Found"
 *     audit:           object,
 *     onDeny:          function(req, res, info): void,  // own the refusal; info = { status, reason, clientIp, route }
 *     problemDetails:  boolean,    // default false — emit RFC 9457 application/problem+json instead of text/plain
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.networkAllowlist({
 *     paths:          ["/admin"],
 *     allowedCidrs:   ["10.0.0.0/8", "::1/128"],
 *     trustedProxies: ["10.0.0.0/8"],   // your reverse proxy's range
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "paths", "allowedCidrs", "deniedCidrs", "trustProxy", "trustedProxies", "clientIpResolver",
    "denyStatus", "denyBody", "audit", "onDeny", "problemDetails",
  ], "middleware.networkAllowlist");

  if (!Array.isArray(opts.paths) || opts.paths.length === 0) {
    throw _err("network-allowlist/bad-opt", "paths must be a non-empty array of pathname prefixes");
  }
  for (var pi = 0; pi < opts.paths.length; pi++) {
    if (typeof opts.paths[pi] !== "string" || opts.paths[pi].charAt(0) !== "/") {
      throw _err("network-allowlist/bad-opt",
        "paths[" + pi + "] must be a string starting with '/', got " + JSON.stringify(opts.paths[pi]));
    }
  }
  if (!Array.isArray(opts.allowedCidrs) || opts.allowedCidrs.length === 0) {
    throw _err("network-allowlist/bad-opt", "allowedCidrs must be a non-empty array of CIDR strings");
  }
  var allowedCidrs = _checkedCidrs(opts.allowedCidrs, "allowedCidrs");
  var deniedCidrs = (opts.deniedCidrs === undefined || opts.deniedCidrs === null)
    ? [] : _checkedCidrs(opts.deniedCidrs, "deniedCidrs");

  var _ipResolver;
  try {
    _ipResolver = requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    });
  } catch (e) { throw _err("network-allowlist/bad-opt", e.message); }
  var trustProxyOpt = opts.trustProxy === true || typeof opts.trustProxy === "number";
  if (trustProxyOpt && !_ipResolver.peerGated) {
    throw _err("network-allowlist/bad-opt",
      "trustProxy is spoofable for an access-control gate — X-Forwarded-For from a " +
      "direct caller would be trusted. Declare your reverse proxies via " +
      "trustedProxies: [\"10.0.0.0/8\", …] (peer-gated XFF) or supply clientIpResolver(req).");
  }

  var paths        = opts.paths.slice();
  var allowedCidrsAsGiven = opts.allowedCidrs.slice();
  var denyStatus   = typeof opts.denyStatus === "number" ? opts.denyStatus : 404;
  if (denyStatus < 400 || denyStatus >= 600 || Math.floor(denyStatus) !== denyStatus) {
    throw _err("network-allowlist/bad-opt", "denyStatus must be a 4xx or 5xx integer, got " + denyStatus);
  }
  var denyBody     = typeof opts.denyBody === "string" ? opts.denyBody : "Not Found";
  var auditOn      = opts.audit !== false && opts.audit != null;
  var auditInstance = opts.audit === true ? null : opts.audit;
  var onDeny       = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode  = opts.problemDetails === true;

  function _deny(req, res, ip, route) {
    _emitDeny(req, ip, route);
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        denyStatus,
      info:          { status: denyStatus, reason: "ip-not-in-allowlist", clientIp: ip, route: route },
      problemCode:   "network-gate-denied",
      problemTitle:  denyBody,
      problemDetail: "Access to this resource is restricted by network policy.",
      contentType:   "text/plain",
      body:          denyBody,
    });
  }

  function _emitDeny(req, ip, route) {
    if (!auditOn) return;
    var sink = auditInstance || audit();
    try {
      sink.safeEmit({
        action:   "network.gate.denied",
        outcome:  "denied",
        actor:    requestHelpers.extractActorContext(req),
        resource: { kind: "http.path", id: route },
        reason:   "ip-not-in-allowlist",
        metadata: { clientIp: ip, allowedCidrs: allowedCidrsAsGiven },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _matchesPath(pathname) {
    for (var i = 0; i < paths.length; i++) {
      var prefix = paths[i];
      if (pathname === prefix) return true;
      if (pathname.length > prefix.length &&
          pathname.indexOf(prefix) === 0 &&
          (prefix.charAt(prefix.length - 1) === "/" || pathname.charAt(prefix.length) === "/")) {
        return true;
      }
    }
    return false;
  }

  return function networkAllowlist(req, res, next) {
    var pathname = req.pathname || (req.url || "").split("?")[0];
    if (!_matchesPath(pathname)) return next();

    var ip = _ipResolver.resolve(req);
    if (!ip) {
      _deny(req, res, "<unknown>", pathname);
      return;
    }

    if (ssrfGuard._listMatches(deniedCidrs, ip, true) ||
        !ssrfGuard._listMatches(allowedCidrs, ip, false)) {
      _deny(req, res, ip, pathname);
      return;
    }
    return next();
  };
}

module.exports = {
  create:                 create,
  NetworkAllowlistError:  NetworkAllowlistError,
};
