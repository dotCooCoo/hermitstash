"use strict";
/**
 * network-allowlist — restrict an opt-named set of paths to operator-
 * approved CIDR ranges.
 *
 * Path-based admin gates (perms.require, requireAuth) prevent UNAUTHORIZED
 * users from reaching sensitive routes. They do NOT prevent the route
 * from being REACHABLE from the public internet — a credential leak +
 * a path-only gate is full compromise. Operators with a clear admin/
 * non-admin network split want a network-layer fence on top of the
 * application-layer gate.
 *
 * The cleanest place for that fence is the reverse proxy / NACL. This
 * middleware is the in-process equivalent for operators who don't have
 * separate infrastructure for it (small deploys, single-process apps,
 * the wiki example default).
 *
 *   var fence = b.middleware.networkAllowlist({
 *     paths:          ["/admin", "/admin/", "/healthz/internal"],
 *     allowedCidrs:   ["10.0.0.0/8", "192.168.0.0/16", "::1/128"],
 *     trustedProxies: ["10.0.0.0/8"], // peer-gate XFF to your proxy range
 *     denyStatus:     404,            // default — reveal nothing about the gate
 *     denyBody:       "Not Found",    // default
 *     audit:          b.audit,        // default: null — emits network.gate.denied
 *   });
 *
 *   router.use(fence);
 *
 * Behaviour:
 *   - The middleware is path-scoped: requests whose pathname doesn't
 *     start with any of `paths` pass through unchanged. Hot-path-cheap.
 *   - Requests on a gated path get their client IP resolved peer-gated:
 *     the socket address by default, or — when `trustedProxies` /
 *     `clientIpResolver` is set — X-Forwarded-For honored only from a
 *     trusted proxy peer. A bare `trustProxy` is refused at construction
 *     because it would let a direct caller forge an allowed address.
 *   - The IP is checked against the CIDR allowlist using
 *     b.ssrfGuard.cidrContains. A miss returns denyStatus + denyBody
 *     and audits the rejection. Default 404 hides the gate's
 *     existence from probes.
 *
 * Validation policy:
 *   - opts: throw at create() time on bad shape (not-array paths /
 *     allowedCidrs, non-CIDR strings, denyStatus outside 4xx/5xx).
 *   - Per-request: a request that looks malformed (no socket, no
 *     headers) gets denied — fail closed.
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var ssrfGuard = require("../ssrf-guard");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });

var NetworkAllowlistError = defineClass("NetworkAllowlistError", { alwaysPermanent: true });
var _err = NetworkAllowlistError.factory;

function _validateCidr(cidr) {
  // ssrfGuard.cidrContains tolerates any string at runtime (returns
  // false on garbage), but the operator means business at config time
  // — a typo'd CIDR silently disables that allow entry. Verify the
  // shape now: <ipv4-or-ipv6>/<prefix-length>.
  if (typeof cidr !== "string" || cidr.length === 0) return false;
  var slash = cidr.indexOf("/");
  if (slash < 1 || slash >= cidr.length - 1) return false;
  var prefix = parseInt(cidr.slice(slash + 1), 10);
  if (!isFinite(prefix) || prefix < 0) return false;
  // Smoke-test the implementation against a known value — if it
  // throws, the cidr is malformed.
  try { ssrfGuard.cidrContains(cidr, "127.0.0.1"); return true; }
  catch (_e) { return false; }
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
 * resolved client IP against the CIDR allowlist via
 * `b.ssrfGuard.cidrContains` and refuses misses with HTTP 404 by
 * default (hides the gate from probes). Throws at create-time on
 * malformed opts.
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
    throw _err("BAD_OPT", "paths must be a non-empty array of pathname prefixes");
  }
  for (var pi = 0; pi < opts.paths.length; pi++) {
    if (typeof opts.paths[pi] !== "string" || opts.paths[pi].charAt(0) !== "/") {
      throw _err("BAD_OPT",
        "paths[" + pi + "] must be a string starting with '/', got " + JSON.stringify(opts.paths[pi]));
    }
  }
  if (!Array.isArray(opts.allowedCidrs) || opts.allowedCidrs.length === 0) {
    throw _err("BAD_OPT", "allowedCidrs must be a non-empty array of CIDR strings");
  }
  for (var ci = 0; ci < opts.allowedCidrs.length; ci++) {
    if (!_validateCidr(opts.allowedCidrs[ci])) {
      throw _err("BAD_OPT",
        "allowedCidrs[" + ci + "] is not a valid CIDR, got " + JSON.stringify(opts.allowedCidrs[ci]));
    }
  }
  // deniedCidrs takes precedence over allowedCidrs (deny-then-allow)
  // — useful when an operator wants "10.0.0.0/8 except 10.0.99.0/24".
  // Default empty (no deny rules).
  var deniedCidrs = Array.isArray(opts.deniedCidrs) ? opts.deniedCidrs.slice() : [];
  for (var di = 0; di < deniedCidrs.length; di++) {
    if (!_validateCidr(deniedCidrs[di])) {
      throw _err("BAD_OPT",
        "deniedCidrs[" + di + "] is not a valid CIDR, got " + JSON.stringify(deniedCidrs[di]));
    }
  }

  // Client-IP resolution for an access-control gate must be peer-gated:
  // a bare `trustProxy` honors X-Forwarded-For from any caller, so a client
  // connecting directly can forge an allowed address and walk through the
  // gate. Operators behind a reverse proxy declare it via `trustedProxies`
  // (CIDRs of their proxies — XFF is then peer-gated) or own resolution
  // entirely via `clientIpResolver`. We refuse, at construction, the
  // spoofable combination of `trustProxy` without either.
  var _ipResolver;
  try {
    _ipResolver = requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    });
  } catch (e) { throw _err("BAD_OPT", e.message); }
  var trustProxyOpt = opts.trustProxy === true || typeof opts.trustProxy === "number";
  if (trustProxyOpt && !_ipResolver.peerGated) {
    throw _err("BAD_OPT",
      "trustProxy is spoofable for an access-control gate — X-Forwarded-For from a " +
      "direct caller would be trusted. Declare your reverse proxies via " +
      "trustedProxies: [\"10.0.0.0/8\", …] (peer-gated XFF) or supply clientIpResolver(req).");
  }

  var paths        = opts.paths.slice();
  var allowedCidrs = opts.allowedCidrs.slice();
  var denyStatus   = typeof opts.denyStatus === "number" ? opts.denyStatus : 404;
  if (denyStatus < 400 || denyStatus >= 600 || Math.floor(denyStatus) !== denyStatus) {
    throw _err("BAD_OPT", "denyStatus must be a 4xx or 5xx integer, got " + denyStatus);
  }
  var denyBody     = typeof opts.denyBody === "string" ? opts.denyBody : "Not Found";
  var auditOn      = opts.audit !== false && opts.audit != null;
  var auditInstance = opts.audit === true ? null : opts.audit;  // null → use lazy-required default
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
        metadata: { clientIp: ip, allowedCidrs: allowedCidrs },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _matchesPath(pathname) {
    for (var i = 0; i < paths.length; i++) {
      var prefix = paths[i];
      if (pathname === prefix) return true;
      // Boundary-aware: "/admin" matches "/admin" + "/admin/..." but
      // not "/administer" — prevents accidental shadowing of
      // similarly-named public routes.
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
      // Fail closed: a request we can't even derive an IP for shouldn't
      // bypass the gate.
      _deny(req, res, "<unknown>", pathname);
      return;
    }

    // Deny-then-allow precedence: an explicit deny entry beats any
    // allow entry that would otherwise match. Operators use this for
    // "10.0.0.0/8 EXCEPT 10.0.99.0/24" patterns.
    for (var dii = 0; dii < deniedCidrs.length; dii++) {
      try {
        if (ssrfGuard.cidrContains(deniedCidrs[dii], ip)) {
          _deny(req, res, ip, pathname);
          return;
        }
      } catch (_e) { /* skip malformed at runtime — caught at config */ }
    }
    var allowed = false;
    for (var i = 0; i < allowedCidrs.length; i++) {
      try {
        if (ssrfGuard.cidrContains(allowedCidrs[i], ip)) { allowed = true; break; }
      } catch (_e) { /* skip malformed at runtime — caught at config */ }
    }
    if (!allowed) {
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
