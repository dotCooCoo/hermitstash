// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.requestHelpers
 * @nav    HTTP
 * @title  Request Helpers
 *
 * @intro
 *   Defensive per-request shape readers — return sane defaults when
 *   headers / route / params are missing or garbage. Every primitive
 *   in this module sits in the framework's third validation tier:
 *   request-shape readers RETURN DEFAULTS, never throw. They run on
 *   every request, often inside middleware that has no recovery path;
 *   a thrown error here would crash the very request that triggered
 *   the read.
 *
 *   The contract is uniform: pass any shape (a real Node
 *   IncomingMessage, a partially-constructed test fake, `undefined`,
 *   a number, an attacker-supplied bag of strings) and get back a
 *   sane default. `resolveRoute` falls back to "/", `clientIp` to
 *   `null`, `requestProtocol` to "http", `parseListHeader` and
 *   `parseQualityList` to `[]`, `safeHeadersDistinct` to a
 *   null-prototype empty object, `extractBearer` to `null`. Operators
 *   who want strict refusal layer their own check on the result.
 *
 *   The single exception is `parseListHeader({ strictToken: true })`,
 *   which throws on RFC 9110 §5.6.2 token grammar violations because
 *   it's used by config-time entry points (WebSocket subprotocol
 *   negotiation etc.) where bad input MUST surface at boot.
 *
 * @card
 *   Defensive per-request shape readers — return sane defaults when headers / route / params are missing or garbage.
 */

var C = require("./constants");
var structuredFields = require("./structured-fields");
var pick = require("./pick");
var codepointClass = require("./codepoint-class");
var safeBuffer = require("./safe-buffer");
var lazyRequire = require("./lazy-require");
// Lazy — ssrf-guard pulls in the network/DNS stack, and request-helpers is
// required very early in the boot graph. Only touched at middleware-construction
// time by trustedClientIp(), never on the hot path.
var _safeAsync = lazyRequire(function () { return require("./safe-async"); });
var _ssrfGuard = lazyRequire(function () { return require("./ssrf-guard"); });
// Lazy for the same boot-graph reason — only touched at middleware-construction
// time by makeSkipMatcher() to screen operator-supplied skip RegExps for ReDoS.
var _guardRegex = lazyRequire(function () { return require("./guard-regex"); });

var HTTP_STATUS = Object.freeze({
  OK:                            0xC8,
  PARTIAL_CONTENT:               0xCE,
  NO_CONTENT:                    0xCC,
  NOT_MODIFIED:                  0x130,
  BAD_REQUEST:                   0x190,
  UNAUTHORIZED:                  0x191,
  FORBIDDEN:                     0x193,
  NOT_FOUND:                     0x194,
  METHOD_NOT_ALLOWED:            0x195,
  CONFLICT:                      0x199,
  PAYLOAD_TOO_LARGE:             0x19D,
  UNSUPPORTED_MEDIA_TYPE:        0x19F,
  RANGE_NOT_SATISFIABLE:         0x1A0,
  UNPROCESSABLE_CONTENT:         0x1A6,
  PRECONDITION_FAILED:           0x19C,
  TOO_MANY_REQUESTS:             0x1AD,
  UNAVAILABLE_FOR_LEGAL_REASONS: 0x1C3,
  INTERNAL_SERVER_ERROR:         0x1F4,
  BAD_GATEWAY:                   0x1F6,
  SERVICE_UNAVAILABLE:           0x1F7,
  GATEWAY_TIMEOUT:               0x1F8,
});

/**
 * @primitive b.requestHelpers.extractActorContext
 * @signature b.requestHelpers.extractActorContext(req, override?)
 * @since     0.4.29
 * @related   b.requestHelpers.resolveActorWithOverride, b.requestHelpers.resolveRoute
 *
 * Pull the 5 W's from a request for audit chain emission. The
 * WHO/WHERE/HOW columns on `_blamejs_audit_log` are populated from
 * the returned shape `{ ip, userAgent, sessionId, requestId, method,
 * route, userId }`. Every field is best-effort — missing or
 * non-request inputs return an object with whatever could be
 * inferred plus `null` elsewhere. The audit chain treats `null` as
 * "unknown", so partial context is always safe.
 *
 * Caller-supplied `override` (own `userId`, `ip`, …) is merged on
 * top of the request-derived fields — explicit operator override
 * always wins.
 *
 * @example
 *   var req = {
 *     ip:      "203.0.113.4",
 *     method:  "POST",
 *     url:     "/api/orders?ref=abc",
 *     headers: { "user-agent": "curl/8.7.1", "x-request-id": "req-9f2" },
 *     user:    { id: "user-42" },
 *   };
 *   var actor = b.requestHelpers.extractActorContext(req);
 *   // → {
 *   //     ip: "203.0.113.4", userAgent: "curl/8.7.1",
 *   //     sessionId: null, requestId: "req-9f2",
 *   //     method: "POST", route: "/api/orders", userId: "user-42",
 *   //   }
 *
 *   // Override beats request-derived fields:
 *   var ovr = b.requestHelpers.extractActorContext(req, { userId: "svc-runner" });
 *   ovr.userId;   // → "svc-runner"
 */
function extractActorContext(req, override) {
  var ctx = {
    ip:        null,
    userAgent: null,
    sessionId: null,
    requestId: null,
    method:    null,
    route:     null,
    userId:    null,
  };
  if (req && typeof req === "object") {
    if (typeof req.ip === "string" && req.ip.length > 0) ctx.ip = req.ip;
    else if (req.connection && typeof req.connection.remoteAddress === "string") {
      ctx.ip = req.connection.remoteAddress;
    } else if (req.socket && typeof req.socket.remoteAddress === "string") {
      ctx.ip = req.socket.remoteAddress;
    }
    if (req.headers && typeof req.headers["user-agent"] === "string") {
      ctx.userAgent = req.headers["user-agent"];
    }
    if (req.session && typeof req.session.id === "string") ctx.sessionId = req.session.id;
    else if (typeof req.sessionId === "string") ctx.sessionId = req.sessionId;
    if (typeof req.requestId === "string") ctx.requestId = req.requestId;
    else if (req.headers && typeof req.headers["x-request-id"] === "string") {
      ctx.requestId = req.headers["x-request-id"];
    }
    if (typeof req.method === "string") ctx.method = req.method;
    ctx.route = resolveRoute(req);
    if (req.user && typeof req.user.id === "string") ctx.userId = req.user.id;
    else if (req.user && typeof req.user.userId === "string") ctx.userId = req.user.userId;
    else if (req.apiKey && typeof req.apiKey.ownerId === "string") ctx.userId = req.apiKey.ownerId;
  }
  if (override && typeof override === "object") {
    for (var k in override) {
      if (Object.prototype.hasOwnProperty.call(override, k) && override[k] != null) {
        ctx[k] = override[k];
      }
    }
  }
  return ctx;
}

/**
 * @primitive b.requestHelpers.resolveActorWithOverride
 * @signature b.requestHelpers.resolveActorWithOverride(callerOpts, baseOverride?)
 * @since     0.4.29
 * @related   b.requestHelpers.extractActorContext
 *
 * Convenience wrapper for primitives that accept an optional
 * `{ req, context }` shape and want to thread it into an
 * audit-emit `actor` field. Replaces the four near-identical
 * `_actor()` helpers that lived in api-key, cache, seeders, and
 * notify before v0.4.29.
 *
 * `callerOpts` is the operator-supplied `{ req?, context? }` bag
 * (typically a primitive's call-site opts). `baseOverride` seeds
 * default values applied BEFORE `callerOpts.context` is merged, so
 * `context` always wins — `b.apiKey` seeds `{ userId }` here so the
 * resolved key's owner becomes the default actor unless the
 * operator passes their own `context.userId`. Returns the same
 * shape as `b.requestHelpers.extractActorContext`.
 *
 * @example
 *   var req = { ip: "198.51.100.7", method: "DELETE", url: "/v1/keys/abc" };
 *   var actor = b.requestHelpers.resolveActorWithOverride(
 *     { req: req, context: { userId: "ops-admin" } },
 *     { userId: "key-owner-default" }
 *   );
 *   actor.userId;   // → "ops-admin"
 *   actor.ip;       // → "198.51.100.7"
 *   actor.method;   // → "DELETE"
 *
 *   // Falls back to the seed when caller passes no context:
 *   var seeded = b.requestHelpers.resolveActorWithOverride(
 *     { req: req }, { userId: "key-owner-default" }
 *   );
 *   seeded.userId;  // → "key-owner-default"
 */
function resolveActorWithOverride(callerOpts, baseOverride) {
  var override = baseOverride ? Object.assign({}, baseOverride) : {};
  if (callerOpts && callerOpts.context && typeof callerOpts.context === "object") {
    for (var k in callerOpts.context) {
      if (Object.prototype.hasOwnProperty.call(callerOpts.context, k)) {
        override[k] = callerOpts.context[k];
      }
    }
  }
  return extractActorContext(callerOpts && callerOpts.req, override);
}

/**
 * @primitive b.requestHelpers.clientIp
 * @signature b.requestHelpers.clientIp(req, opts?)
 * @since     0.5.3
 * @related   b.requestHelpers.requestProtocol, b.requestHelpers.parseListHeader
 *
 * Resolve the originating client IP from a request. Default reads
 * only `req.socket.remoteAddress` — `X-Forwarded-For` is ignored
 * because without a sanitizing reverse proxy it's attacker-forgeable.
 *
 * For an access-control decision (allowlist, rate-limit key, IP-bound
 * grant), pass `trustProxy` as a PREDICATE `function(addr) => boolean`
 * naming your trusted reverse proxies. The header is then honored only
 * when the immediate TCP peer is itself a trusted proxy, and the client
 * is the first untrusted address walking the chain right-to-left. A
 * direct attacker cannot forge it — this is the only peer-gated form.
 *
 * The legacy `trustProxy: true` (leftmost XFF hop) and `trustProxy: <N>`
 * (Nth-from-rightmost) forms do NOT verify the peer: a client connecting
 * directly can forge any value. They are safe only when an upstream you
 * control terminates and rewrites X-Forwarded-For on every request — never
 * for a security decision on an internet-facing listener. Prefer the
 * predicate form. Returns `null` when no address can be read — never throws.
 *
 * `forwardedHeaders` names which header carries the address, in preference
 * order — the first one PRESENT on the request is used (present rather than
 * non-empty), and it defaults to
 * `["x-forwarded-for"]`. It only has an effect alongside `trustProxy`; list
 * only headers your proxy sets or overwrites (see `trustedClientIp`).
 *
 * @opts
 *   trustProxy:       boolean | number | function   // false (default) | predicate (peer-gated) | legacy true/hop-count
 *   forwardedHeaders: string[]                      // header family, in order — default: ["x-forwarded-for"]
 *
 * @example
 *   var req = {
 *     socket:  { remoteAddress: "10.0.0.1" },
 *     headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.5" },
 *   };
 *   b.requestHelpers.clientIp(req);
 *   // → "10.0.0.1"   (forwarded headers ignored by default)
 *
 *   var fromTrusted = function (a) { return a.indexOf("10.") === 0; };
 *   b.requestHelpers.clientIp(req, { trustProxy: fromTrusted });
 *   // → "203.0.113.7"   (peer 10.0.0.1 trusted; first untrusted hop)
 *
 *   var forged = { socket: { remoteAddress: "198.51.100.66" },
 *                  headers: { "x-forwarded-for": "203.0.113.7" } };
 *   b.requestHelpers.clientIp(forged, { trustProxy: fromTrusted });
 *   // → "198.51.100.66"   (peer untrusted → forged header ignored)
 *
 *   b.requestHelpers.clientIp(undefined);
 *   // → null
 */
var DEFAULT_FORWARDED_HEADERS = Object.freeze(["x-forwarded-for"]);

var FORWARDED_HEADER_NAME_RE  = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
var MAX_FORWARDED_HEADER_NAME = 64;

function _normForwardedHeaders(value, where) {
  if (value === undefined || value === null) return DEFAULT_FORWARDED_HEADERS;
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(where + ": forwardedHeaders must be a non-empty array of " +
                        "header names, got " + JSON.stringify(value));
  }
  var out = [];
  for (var i = 0; i < value.length; i++) {
    var name = value[i];
    var bounded = typeof name === "string" &&
                  name.length > 0 && name.length <= MAX_FORWARDED_HEADER_NAME;
    if (!bounded || !FORWARDED_HEADER_NAME_RE.test(name)) {
      throw new TypeError(where + ": forwardedHeaders[" + i + "] is not a valid HTTP " +
                          "field name, got " + JSON.stringify(name));
    }
    out.push(name.toLowerCase());
  }
  return out;
}

function _normForwardedHeadersOrNone(value) {
  if (value === undefined || value === null) return DEFAULT_FORWARDED_HEADERS;
  try { return _normForwardedHeaders(value, "clientIp"); }
  catch (_e) { return []; }
}

function clientIp(req, opts) {
  if (!req) return null;
  var socketAddr =
    (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
    : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
    : null;
  var trust = opts && opts.trustProxy;
  if (trust && req.headers) {
    var names = _normForwardedHeadersOrNone(opts && opts.forwardedHeaders);
    var xff = null;
    for (var n = 0; n < names.length; n++) {
      var candidate = req.headers[names[n]];
      if (candidate !== undefined && candidate !== null) {
        xff = candidate;
        break;
      }
    }
    if (xff) {
      var hops = parseListHeader(xff);
      if (hops.length) {
        if (typeof trust === "function") {
          if (socketAddr && trust(socketAddr) === true) {
            for (var i = hops.length - 1; i >= 0; i--) {
              if (trust(hops[i]) !== true) return hops[i];
            }
            return hops[0];
          }
        } else if (trust === true) {
          return hops[0];
        } else if (typeof trust === "number" && trust >= 1 && hops.length >= trust) {
          return hops[hops.length - trust];
        }
      }
    }
  }
  if (socketAddr) return socketAddr;
  if (typeof req.ip === "string" && req.ip.length > 0) return req.ip;
  return null;
}

/**
 * @primitive b.requestHelpers.trustedClientIp
 * @signature b.requestHelpers.trustedClientIp(opts?)
 * @since     0.15.14
 * @related   b.requestHelpers.clientIp
 *
 * Build a peer-gated client-IP resolver for an access-control decision
 * (allowlist, rate-limit key, IP-bound grant). The bare `trustProxy`
 * forms of `clientIp` are forgeable; this is the shape every gate shares
 * so the trust model is identical across them. Returns
 * `{ resolve(req), peerGated }`: `resolve` reads the client IP, `peerGated`
 * is true when `trustedProxies` or `clientIpResolver` was supplied — a
 * gate uses it to refuse a bare `trustProxy` at construction (fail closed).
 *
 * With `clientIpResolver(req)` the operator owns resolution entirely. With
 * `trustedProxies` (CIDRs of the reverse proxies), the forwarded header is
 * honored only when the immediate peer is one of them. With neither, only
 * the socket address is used and forwarded headers are ignored.
 *
 * `forwardedHeaders` names which header carries the address, in preference
 * order — the first one PRESENT on the request is used, present rather than
 * non-empty: a first-listed header that arrives empty says this request
 * carries no forwarded address, rather than deferring to a lower-priority
 * one the client may have set. It defaults to
 * `["x-forwarded-for"]`. Cloudflare publishes the client address as
 * `CF-Connecting-IP` and the common nginx recipe
 * (`proxy_set_header X-Real-IP $remote_addr`) as `X-Real-IP`, so a deployment
 * behind either had no way to use this resolver at all: reading the header
 * directly drops the peer gate, and `clientIpResolver` hands back the whole
 * trust decision — the CIDR matching, the IPv4-mapped-IPv6 folding — while
 * still reporting `peerGated`. Every listed header is parsed the same way, so
 * a single-address header is simply a one-hop chain.
 *
 * List ONLY headers your proxy sets or overwrites on every request. The peer
 * gate proves the request arrived THROUGH your proxy; it cannot prove your
 * proxy authored the header. A proxy that passes an unknown header through
 * unchanged lets a client inject it, and naming that header here would honor
 * the injected value — which is why the default stays the single header the
 * chain walk was designed for.
 *
 * @opts
 *   trustedProxies:   string | string[],          // CIDRs — peer-gate the forwarded header
 *   forwardedHeaders: string[],                    // header family, in order — default: ["x-forwarded-for"]
 *   clientIpResolver: function(req): string|null,  // own resolution entirely
 *
 * @example
 *   var tip = b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] });
 *   var ip  = tip.resolve(req);   // peer-gated; forged XFF from a direct caller ignored
 *
 *   var cf = b.requestHelpers.trustedClientIp({
 *     trustedProxies:   ["10.0.0.0/8"],
 *     forwardedHeaders: ["cf-connecting-ip"],
 *   });
 *   cf.resolve(req);              // same gate, the header the edge actually sets
 */
function _trustedProxyPredicate(trustedProxies, where) {
  if (!trustedProxies || !trustedProxies.length) return null;
  var ssrfGuard = _ssrfGuard();
  for (var i = 0; i < trustedProxies.length; i++) {
    var cidr = trustedProxies[i];
    var slash = typeof cidr === "string" ? cidr.indexOf("/") : -1;
    if (slash === -1 || !ssrfGuard.cidrContains(cidr, cidr.slice(0, slash))) {
      throw new TypeError(where + ": trustedProxies[" + i + "] is not a valid CIDR, got " + JSON.stringify(cidr));
    }
  }
  return function (addr) {
    var canon = ssrfGuard.canonicalizeHost(addr);
    for (var j = 0; j < trustedProxies.length; j++) {
      if (ssrfGuard.cidrContains(trustedProxies[j], canon)) return true;
    }
    return false;
  };
}

function _normTrustedProxies(opts) {
  return Array.isArray(opts.trustedProxies) ? opts.trustedProxies.slice()
    : (typeof opts.trustedProxies === "string" && opts.trustedProxies.length ? [opts.trustedProxies] : []);
}

function trustedClientIp(opts) {
  opts = opts || {};
  var resolver = opts.clientIpResolver;
  if (resolver != null && typeof resolver !== "function") {
    throw new TypeError("trustedClientIp: clientIpResolver must be a function(req) => ip|null");
  }
  var predicate = _trustedProxyPredicate(_normTrustedProxies(opts), "trustedClientIp");
  var forwardedHeaders = _normForwardedHeaders(opts.forwardedHeaders, "trustedClientIp");
  return {
    peerGated: !!(resolver || predicate),
    resolve: function (req) {
      if (resolver) return resolver(req);
      if (predicate) return clientIp(req, { trustProxy: predicate, forwardedHeaders: forwardedHeaders });
      return clientIp(req, { trustProxy: false });
    },
  };
}

function _socketAddr(req) {
  return (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
    : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
    : null;
}

/**
 * @primitive b.requestHelpers.trustedIdentityHeaders
 * @signature b.requestHelpers.trustedIdentityHeaders(opts)
 * @since     0.18.8
 * @status    stable
 * @related   b.requestHelpers.trustedClientIp, b.requestHelpers.clientIp
 *
 * Resolve an identity-injecting reverse proxy's headers under the SAME
 * peer-gate as `trustedClientIp` — the mirror of the `X-Forwarded-For`
 * discipline for identity-header families (Cloudflare Access `Cf-Access-*`,
 * oauth2-proxy `X-Forwarded-User`, Tailscale Serve `Tailscale-User-*`). A
 * configured header family is trusted ONLY when the immediate socket peer is a
 * trusted proxy; from every OTHER peer the family is defensively stripped from
 * `req.headers` so downstream code cannot read a forged value. A naive trust of
 * these headers is a full impersonation bypass — so this reuses the
 * `trustedProxies` gate rather than opening a second, looser trust path.
 *
 * Returns `{ resolve(req), middleware, headerNames, peerGated }`. `resolve(req)`
 * → `{ trusted, identity }` (`identity` is `{}` unless the peer is trusted).
 * `middleware(req, res, next)` sets `req[as]` to the identity when trusted and
 * DELETES every family header from `req.headers` when not. With no
 * `trustedProxies`/`peerTrust` the peer is never trusted (fail-closed: the
 * family is always stripped and `peerGated` is false).
 *
 * Header VALUES are surfaced raw — RFC 2047 name decoding and capability-JSON
 * parsing are the consumer's job, not the trust boundary's.
 *
 * @opts
 *   headers:        object,                 // { field: "Header-Name", ... } — the family to trust (required)
 *   trustedProxies: string | string[],      // CIDRs of the reverse proxies — peer-gate the family
 *   peerTrust:      function(req): boolean,  // own the peer-trust decision entirely (instead of trustedProxies)
 *   as:             string,                  // req property to set the identity on (default: "proxyIdentity")
 *
 * @example
 *   var ident = b.requestHelpers.trustedIdentityHeaders({
 *     trustedProxies: ["127.0.0.1/32"],
 *     headers: { login: "Tailscale-User-Login", name: "Tailscale-User-Name" },
 *   });
 *   app.use(ident.middleware);
 *   // req.proxyIdentity = { login, name } from the trusted sidecar; a forged
 *   // Tailscale-User-Login from a direct client is stripped, never trusted.
 */
function trustedIdentityHeaders(opts) {
  opts = opts || {};
  if (!opts.headers || typeof opts.headers !== "object" || Array.isArray(opts.headers)) {
    throw new TypeError("trustedIdentityHeaders: opts.headers must be an object mapping field → header name");
  }
  var fieldNames = Object.keys(opts.headers);
  if (fieldNames.length === 0) {
    throw new TypeError("trustedIdentityHeaders: opts.headers must map at least one field");
  }
  var map = {};
  var headerNames = [];
  for (var i = 0; i < fieldNames.length; i++) {
    var hn = opts.headers[fieldNames[i]];
    if (typeof hn !== "string" || hn.length === 0) {
      throw new TypeError("trustedIdentityHeaders: header name for field '" + fieldNames[i] + "' must be a non-empty string");
    }
    var lhn = hn.toLowerCase();
    map[fieldNames[i]] = lhn;
    headerNames.push(lhn);
  }
  var peerTrust = opts.peerTrust;
  if (peerTrust != null && typeof peerTrust !== "function") {
    throw new TypeError("trustedIdentityHeaders: peerTrust must be a function(req) => boolean");
  }
  var predicate = _trustedProxyPredicate(_normTrustedProxies(opts), "trustedIdentityHeaders");
  var asProp = (typeof opts.as === "string" && opts.as.length) ? opts.as : "proxyIdentity";

  function _peerTrusted(req) {
    if (peerTrust) return peerTrust(req) === true;
    if (!predicate) return false;
    var addr = _socketAddr(req);
    return !!(addr && predicate(addr));
  }

  function resolve(req) {
    if (!req || !req.headers || !_peerTrusted(req)) return { trusted: false, identity: {} };
    var identity = {};
    for (var f = 0; f < fieldNames.length; f++) {
      var v = req.headers[map[fieldNames[f]]];
      if (typeof v === "string") identity[fieldNames[f]] = v;
    }
    return { trusted: true, identity: identity };
  }

  function middleware(req, res, next) {
    var r = resolve(req);
    if (r.trusted) {
      req[asProp] = r.identity;
    } else {
      if (req && req.headers) {
        for (var h = 0; h < headerNames.length; h++) delete req.headers[headerNames[h]];
      }
      if (req) req[asProp] = null;
    }
    if (typeof next === "function") next();
  }

  return {
    resolve:     resolve,
    middleware:  middleware,
    headerNames: headerNames.slice(),
    peerGated:   !!(peerTrust || predicate),
  };
}

var IP_BITS_PER_BYTE      = 8;
var IPV4_OCTET_COUNT      = 4;
var IPV4_OCTET_RANGE      = 256;
var IPV4_TOTAL_BITS       = 32;
var IPV4_DEFAULT_PREFIX   = 24;
var IPV6_GROUP_COUNT      = 8;
var IPV6_BYTE_COUNT       = 16;
var IPV6_DEFAULT_PREFIX   = 64;
var IP_BYTE_MASK          = 0xff;
var IP_HEX_RADIX          = 16;
var V4_MAPPED_V6_PREFIX   = "::ffff:";

function _maskIpv4(ip, prefix) {
  var parts = String(ip).split(".");
  if (parts.length !== IPV4_OCTET_COUNT) return null;
  var n = 0;
  for (var i = 0; i < IPV4_OCTET_COUNT; i++) {
    var oct = parseInt(parts[i], 10);
    if (!Number.isInteger(oct) || oct < 0 || oct >= IPV4_OCTET_RANGE) return null;
    n = (n * IPV4_OCTET_RANGE) + oct;
  }
  var mask = prefix === 0 ? 0 : (-1 >>> (IPV4_TOTAL_BITS - prefix)) << (IPV4_TOTAL_BITS - prefix);
  var masked = (n & mask) >>> 0;
  return ((masked >>> IP_BITS_PER_BYTE * 3) & IP_BYTE_MASK) + "." +
         ((masked >>> IP_BITS_PER_BYTE * 2) & IP_BYTE_MASK) + "." +
         ((masked >>> IP_BITS_PER_BYTE)     & IP_BYTE_MASK) + "." +
         (masked & IP_BYTE_MASK) + "/" + prefix;
}

function _maskIpv6(ip, prefix) {
  var raw = String(ip).toLowerCase();
  var pct = raw.indexOf("%");
  if (pct !== -1) raw = raw.substring(0, pct);
  var doubleColonAt = raw.indexOf("::");
  var groups;
  if (doubleColonAt === -1) {
    groups = raw.split(":");
    if (groups.length !== IPV6_GROUP_COUNT) return null;
  } else {
    var left = raw.substring(0, doubleColonAt).split(":");
    var right = raw.substring(doubleColonAt + 2).split(":");
    if (left.length === 1 && left[0] === "") left = [];
    if (right.length === 1 && right[0] === "") right = [];
    var fillCount = IPV6_GROUP_COUNT - left.length - right.length;
    if (fillCount < 0) return null;
    var middle = [];
    for (var fi = 0; fi < fillCount; fi++) middle.push("0");
    groups = left.concat(middle).concat(right);
  }
  var bytes = [];
  for (var gi = 0; gi < IPV6_GROUP_COUNT; gi++) {
    var g = groups[gi];
    if (typeof g !== "string" || g.length === 0 || g.length > 4 || /[^0-9a-f]/.test(g)) return null;
    var v = parseInt(g, IP_HEX_RADIX);
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) return null;
    bytes.push((v >> IP_BITS_PER_BYTE) & IP_BYTE_MASK);
    bytes.push(v & IP_BYTE_MASK);
  }
  var keepBytes = Math.floor(prefix / IP_BITS_PER_BYTE);
  var keepBits  = prefix % IP_BITS_PER_BYTE;
  for (var bi = 0; bi < IPV6_BYTE_COUNT; bi++) {
    if (bi < keepBytes) continue;
    if (bi === keepBytes && keepBits > 0) {
      var m = (IP_BYTE_MASK << (IP_BITS_PER_BYTE - keepBits)) & IP_BYTE_MASK;
      bytes[bi] = bytes[bi] & m;
    } else {
      bytes[bi] = 0;
    }
  }
  var out = [];
  for (var oi = 0; oi < IPV6_BYTE_COUNT; oi += 2) {
    out.push(((bytes[oi] << IP_BITS_PER_BYTE) | bytes[oi + 1]).toString(IP_HEX_RADIX));
  }
  return out.join(":") + "/" + prefix;
}

/**
 * @primitive b.requestHelpers.ipPrefix
 * @signature b.requestHelpers.ipPrefix(ip, opts?)
 * @since     0.15.15
 * @related   b.requestHelpers.clientIp, b.requestHelpers.trustedClientIp
 *
 * Mask a client IP to its subnet bucket: a <code>/24</code> for IPv4 (the
 * carrier-NAT pool stride) and a <code>/64</code> for IPv6 (the customer-LAN
 * prefix RIRs allocate, RFC 4291 §2.5.4). Returns the canonical
 * <code>"network/prefix"</code> string, or <code>""</code> for a non-string /
 * empty / unparseable input. An IPv4-mapped IPv6 address
 * (<code>::ffff:1.2.3.4</code>) folds to its dotted form so it buckets the
 * same regardless of how a proxy reported it.
 *
 * This is the masking the session device-fingerprint's built-in
 * <code>clientIpPrefix</code> field hashes (so roaming carriers that flip the
 * public IP within a subnet don't log a user out). Exposed so an operator who
 * drops to a function-form fingerprint field — for a custom mask width, or to
 * combine the prefix with other signals — reuses this exact algorithm instead
 * of re-deriving the /24 + /64 masking (and silently diverging). Pass
 * <code>opts.v4Bits</code> / <code>opts.v6Bits</code> to override the mask
 * widths (e.g. a device fingerprint that buckets at <code>/48</code> so a
 * client roaming within its allocation but across a <code>/64</code> doesn't
 * drift); an out-of-range or absent value falls back to the /24 + /64 default.
 *
 * @opts
 *   v4Bits: number,   // IPv4 mask width in bits (default 24; valid 0..32)
 *   v6Bits: number,   // IPv6 mask width in bits (default 64; valid 0..128)
 *
 * @example
 *   b.requestHelpers.ipPrefix("203.0.113.47");   // → "203.0.113.0/24"
 *   b.requestHelpers.ipPrefix("2001:db8::1");     // → "2001:db8:0:0/64"
 */
function _resolvePrefixBits(bits, def, max) {
  if (typeof bits !== "number" || !isFinite(bits) || bits < 0 || bits > max) return def;
  return bits;
}
function ipPrefix(ip, opts) {
  if (typeof ip !== "string" || ip.length === 0) return "";
  opts = opts || {};
  var v4 = _resolvePrefixBits(opts.v4Bits, IPV4_DEFAULT_PREFIX, 32);
  var v6 = _resolvePrefixBits(opts.v6Bits, IPV6_DEFAULT_PREFIX, 128);
  var lower = ip.toLowerCase();
  if (lower.indexOf(V4_MAPPED_V6_PREFIX) === 0 && lower.indexOf(".") !== -1) {
    return _maskIpv4(lower.substring(V4_MAPPED_V6_PREFIX.length), v4) || "";
  }
  if (ip.indexOf(":") !== -1) return _maskIpv6(ip, v6) || "";
  if (ip.indexOf(".") !== -1) return _maskIpv4(ip, v4) || "";
  return "";
}

/**
 * @primitive b.requestHelpers.ipKey
 * @signature b.requestHelpers.ipKey(ip, opts?)
 * @since     0.15.21
 * @related   b.requestHelpers.ipPrefix, b.requestHelpers.clientIp
 *
 * Derive a stable rate-limit / blocklist key from a client IP: the IPv4
 * address <strong>verbatim</strong> (one IPv4 is one host) but the IPv6
 * address collapsed to its routing-significant <code>/64</code> prefix. A
 * single IPv6 end-site is allocated a whole <code>/64</code> (RFC 6177 / RFC
 * 4291 §2.5.4) and freely rotates the low 64 bits, so keying on the full
 * 128-bit address lets one site mint unlimited fresh keys — defeating a
 * per-IP throttle and an exact-address block. Keying on the <code>/64</code>
 * closes that while still distinguishing real end-sites. Unlike
 * <code>ipPrefix</code> (which masks IPv4 to a <code>/24</code> pool), this
 * keeps IPv4 exact — a rate limiter wants per-host IPv4 granularity.
 *
 * Returns the canonical key string, or <code>""</code> for a non-string /
 * empty / unparseable input (caller falls back to its own bucket). An
 * IPv4-mapped IPv6 address (<code>::ffff:1.2.3.4</code>) folds to its dotted
 * IPv4 form so a client keys the same however a proxy reported it. Pass
 * <code>opts.ipv6Bits</code> to override the IPv6 mask width (default 64).
 *
 * @opts
 *   ipv6Bits: number,   // IPv6 mask width in bits (default 64; valid 0..128)
 *
 * @example
 *   b.requestHelpers.ipKey("203.0.113.47");       // → "203.0.113.47" (exact)
 *   b.requestHelpers.ipKey("2001:db8:1:2:dead:beef:0:1"); // → "2001:db8:1:2:0:0:0:0/64"
 */
function ipKey(ip, opts) {
  if (typeof ip !== "string" || ip.length === 0) return "";
  opts = opts || {};
  var v6 = _resolvePrefixBits(opts.ipv6Bits, IPV6_DEFAULT_PREFIX, 128);
  var lower = ip.toLowerCase();
  if (lower.indexOf(V4_MAPPED_V6_PREFIX) === 0 && lower.indexOf(".") !== -1) {
    var m4 = _maskIpv4(lower.substring(V4_MAPPED_V6_PREFIX.length), 32);
    return m4 ? m4.replace(/\/32$/, "") : "";
  }
  if (ip.indexOf(":") !== -1) return _maskIpv6(ip, v6) || "";
  if (ip.indexOf(".") !== -1) {
    var m = _maskIpv4(ip, 32);
    return m ? m.replace(/\/32$/, "") : "";
  }
  return "";
}

/**
 * @primitive b.requestHelpers.trustedProtocol
 * @signature b.requestHelpers.trustedProtocol(opts?)
 * @since     0.15.14
 * @related   b.requestHelpers.requestProtocol, b.requestHelpers.trustedClientIp
 *
 * Peer-gated companion to trustedClientIp for the request scheme. The
 * Secure-cookie / HSTS / secure-context decisions hinge on whether a request
 * arrived over HTTPS; behind a TLS-terminating proxy that comes from
 * X-Forwarded-Proto, which is forgeable unless the immediate peer is a trusted
 * proxy. Returns `{ resolve(req)=>"http"|"https", peerGated }`. With
 * `trustedProxies` (CIDRs) the header is honored only from a trusted peer; with
 * `protocolResolver(req)` the operator owns the decision; with neither only the
 * real TLS socket is consulted (forwarded headers ignored).
 *
 * @opts
 *   trustedProxies:   string | string[],
 *   protocolResolver: function(req): "http"|"https",
 *
 * @example
 *   var tp = b.requestHelpers.trustedProtocol({ trustedProxies: ["10.0.0.0/8"] });
 *   tp.resolve(req);   // "https" only when X-Forwarded-Proto came via a trusted peer
 */
function trustedProtocol(opts) {
  opts = opts || {};
  var resolver = opts.protocolResolver;
  if (resolver != null && typeof resolver !== "function") {
    throw new TypeError("trustedProtocol: protocolResolver must be a function(req) => 'http'|'https'");
  }
  var predicate = _trustedProxyPredicate(_normTrustedProxies(opts), "trustedProtocol");
  return {
    peerGated: !!(resolver || predicate),
    resolve: function (req) {
      if (resolver) return resolver(req);
      if (predicate) return requestProtocol(req, { trustProxy: predicate });
      return requestProtocol(req, { trustProxy: false });
    },
  };
}

/**
 * @primitive b.requestHelpers.requestProtocol
 * @signature b.requestHelpers.requestProtocol(req, opts?)
 * @since     0.5.3
 * @related   b.requestHelpers.clientIp, b.safeRedirect
 *
 * Resolve the inbound transport scheme. Default returns `"https"`
 * when `req.socket.encrypted` is set, otherwise `"http"`. Behind a
 * trusted reverse proxy that terminates TLS, pass `trustProxy` as a
 * PREDICATE `function(addr)=>boolean` naming your proxies:
 * `X-Forwarded-Proto` is then honored only when the immediate peer is
 * a trusted proxy, so a direct caller can't forge it (use
 * `b.requestHelpers.trustedProtocol` to build this). The legacy
 * `trustProxy: true` reads the leftmost hop without checking the peer —
 * forgeable, safe only behind an edge that rewrites the header. Always
 * returns a string; on bad input falls back to `"http"`.
 *
 * @opts
 *   trustProxy: boolean | function   // false (default) | predicate (peer-gated) | legacy true
 *
 * @example
 *   var req = { socket: { encrypted: true } };
 *   b.requestHelpers.requestProtocol(req);
 *   // → "https"
 *
 *   var behindProxy = {
 *     socket:  { encrypted: false },
 *     headers: { "x-forwarded-proto": "https, http" },
 *   };
 *   b.requestHelpers.requestProtocol(behindProxy, { trustProxy: true });
 *   // → "https"
 *
 *   b.requestHelpers.requestProtocol(undefined);
 *   // → "http"
 */
function requestProtocol(req, opts) {
  if (!req) return "http";
  var trust = opts && opts.trustProxy;
  if (trust && req.headers) {
    var fwd = req.headers["x-forwarded-proto"];
    if (typeof fwd === "string" && fwd.length > 0) {
      var hops = parseListHeader(fwd, { lowercase: true });
      if (hops.length > 0) {
        if (typeof trust === "function") {
          var peer =
            (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
            : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
            : null;
          if (peer && trust(peer) === true) return hops[0];
        } else {
          return hops[0];
        }
      }
    }
  }
  var sock = req.socket || req.connection || null;
  if (sock) return sock.encrypted ? "https" : "http";
  var h2Scheme = req.headers && req.headers[":scheme"];
  if (h2Scheme === "https") return "https";
  if (h2Scheme === "http") return "http";
  return "http";
}

/**
 * @primitive b.requestHelpers.trustedHost
 * @signature b.requestHelpers.trustedHost(opts?)
 * @since     0.15.18
 * @related   b.requestHelpers.requestHost, b.requestHelpers.trustedProtocol
 *
 * Peer-gated companion to trustedProtocol for the request authority (host).
 * Reconstructing the absolute request URL — the DPoP `htu`, an origin/issuer
 * string, a redirect base — depends on the host the client addressed; behind a
 * proxy that comes from X-Forwarded-Host, which is forgeable unless the
 * immediate peer is a trusted proxy. Returns `{ resolve(req)=>string|null,
 * peerGated }`. With `trustedProxies` (CIDRs) X-Forwarded-Host is honored only
 * from a trusted peer; with `hostResolver(req)` the operator owns it; with
 * neither only the request's own Host header is used (forwarded host ignored).
 *
 * @opts
 *   trustedProxies: string | string[],
 *   hostResolver:   function(req): string|null,
 *
 * @example
 *   var th = b.requestHelpers.trustedHost({ trustedProxies: ["10.0.0.0/8"] });
 *   th.resolve(req);   // X-Forwarded-Host only when it came via a trusted peer
 */
function trustedHost(opts) {
  opts = opts || {};
  var resolver = opts.hostResolver;
  if (resolver != null && typeof resolver !== "function") {
    throw new TypeError("trustedHost: hostResolver must be a function(req) => string|null");
  }
  var predicate = _trustedProxyPredicate(_normTrustedProxies(opts), "trustedHost");
  return {
    peerGated: !!(resolver || predicate),
    resolve: function (req) {
      if (resolver) return resolver(req);
      if (predicate) return requestHost(req, { trustProxy: predicate });
      return requestHost(req, { trustProxy: false });
    },
  };
}

/**
 * @primitive b.requestHelpers.requestHost
 * @signature b.requestHelpers.requestHost(req, opts?)
 * @since     0.15.18
 * @related   b.requestHelpers.requestProtocol, b.requestHelpers.trustedHost
 *
 * Resolve the inbound authority (host[:port]). Default returns the request's
 * own `Host` header. Behind a trusted reverse proxy that rewrites the host,
 * pass `trustProxy` as a PREDICATE `function(addr)=>boolean` (build it via
 * `b.requestHelpers.trustedHost`): `X-Forwarded-Host` is then honored only when
 * the immediate peer is a trusted proxy, so a direct caller can't forge it. The
 * legacy `trustProxy: true` reads the leftmost forwarded hop without checking
 * the peer — forgeable. Returns the host string, or `null` when absent.
 *
 * @opts
 *   trustProxy: boolean | function   // false (default) | predicate (peer-gated) | legacy true
 *
 * @example
 *   b.requestHelpers.requestHost({ headers: { host: "app.example.com" } });
 *   // → "app.example.com"
 */
function requestHost(req, opts) {
  if (!req || !req.headers) return null;
  var trust = opts && opts.trustProxy;
  if (trust) {
    var fwd = req.headers["x-forwarded-host"];
    if (typeof fwd === "string" && fwd.length > 0) {
      var hops = parseListHeader(fwd);
      if (hops.length > 0) {
        if (typeof trust === "function") {
          var peer =
            (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
            : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
            : null;
          if (peer && trust(peer) === true) return hops[0];
        } else {
          return hops[0];
        }
      }
    }
  }
  var authority = req.headers[":authority"];
  if (typeof authority === "string" && authority.length > 0) return authority;
  return typeof req.headers.host === "string" ? req.headers.host : null;
}

var _isRfc9110Token = safeBuffer.isHttpToken;

/**
 * @primitive b.requestHelpers.parseListHeader
 * @signature b.requestHelpers.parseListHeader(value, opts?)
 * @since     0.5.17
 * @related   b.requestHelpers.parseQualityList, b.requestHelpers.appendVary
 *
 * Split a comma-separated header / opt value into a list of trimmed
 * non-empty tokens. Replaces the
 * `String(x).split(",").map(s => s.trim()).filter(Boolean)` chain
 * that was duplicated across cors / compression / scheduler /
 * webhook / websocket / db-schema / cli before v0.5.17.
 *
 * Tolerant read: non-string input returns `[]` — these are read
 * from request headers that the network might omit. Callers
 * needing stricter checks layer their own validation on the
 * result. The `strictToken` opt is the one exception — it throws
 * on RFC 9110 §5.6.2 token-grammar violations, used by config-time
 * entry points (WebSocket subprotocol negotiation etc.) where bad
 * input MUST surface at boot.
 *
 * @opts
 *   lowercase:   boolean   // lowercase every token before returning
 *   strictToken: boolean   // throw on non-RFC 9110 token entries
 *
 * @example
 *   b.requestHelpers.parseListHeader("a, b , ,c");
 *   // → ["a", "b", "c"]
 *
 *   b.requestHelpers.parseListHeader("Foo, Bar", { lowercase: true });
 *   // → ["foo", "bar"]
 *
 *   b.requestHelpers.parseListHeader(undefined);
 *   // → []
 *
 *   try {
 *     b.requestHelpers.parseListHeader("chat, bad token", { strictToken: true });
 *   } catch (err) {
 *     err.message;
 *     // → "parseListHeader: 'bad token' is not a valid RFC 9110 token"
 *   }
 */
function parseListHeader(value, opts) {
  if (value == null) return [];
  opts = opts || {};
  var s = typeof value === "string" ? value : String(value);
  if (s.length === 0) return [];
  if (opts.strictToken) {
    structuredFields.refuseControlBytes(s, {
      ErrorClass:     TypeError,
      code:           "parseListHeader/control-character",
      label:          "parseListHeader",
      useNativeError: true,
    });
  }
  var parts = s.split(",");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var t = parts[i].trim();
    if (t.length === 0) continue;
    if (opts.strictToken && !_isRfc9110Token(t)) {
      throw new TypeError("parseListHeader: '" + t +
        "' is not a valid RFC 9110 token");
    }
    out.push(opts.lowercase ? t.toLowerCase() : t);
  }
  return out;
}

/**
 * @primitive b.requestHelpers.appendVary
 * @signature b.requestHelpers.appendVary(res, value)
 * @since     0.5.17
 * @related   b.requestHelpers.parseListHeader
 *
 * Append a token to a `Vary` response header without dropping
 * prior values (compression middleware sets `Vary: Accept-
 * Encoding`, an auth helper might set `Vary: Authorization`, etc.).
 * Idempotent — re-adding an existing token (case-insensitive) is a
 * no-op. Silently no-ops when `res` doesn't expose
 * `getHeader`/`setHeader` so misuse during testing or in non-HTTP
 * contexts never throws.
 *
 * @example
 *   var headers = { Vary: "Accept-Encoding" };
 *   var res = {
 *     getHeader: function (n) { return headers[n]; },
 *     setHeader: function (n, v) { headers[n] = v; },
 *   };
 *
 *   b.requestHelpers.appendVary(res, "Authorization");
 *   headers.Vary;   // → "Accept-Encoding, Authorization"
 *
 *   // Idempotent — re-adding is a no-op:
 *   b.requestHelpers.appendVary(res, "accept-encoding");
 *   headers.Vary;   // → "Accept-Encoding, Authorization"
 */
function appendVary(res, value) {
  if (!res || typeof res.getHeader !== "function" || typeof res.setHeader !== "function") return;
  var existing = res.getHeader("Vary");
  if (existing == null || existing === "") { res.setHeader("Vary", value); return; }
  var tokens = parseListHeader(existing);
  var lower = value.toLowerCase();
  for (var i = 0; i < tokens.length; i++) if (tokens[i].toLowerCase() === lower) return;
  tokens.push(value);
  res.setHeader("Vary", tokens.join(", "));
}

/**
 * @primitive b.requestHelpers.resolveRoute
 * @signature b.requestHelpers.resolveRoute(req)
 * @since     0.4.0
 * @related   b.requestHelpers.extractActorContext, b.requestHelpers.captureResponseStatus
 *
 * Resolve the route pattern for a request. Prefers
 * `req.routePattern` (set by `b.router` during dispatch — a
 * low-cardinality template like `/users/:id` rather than the
 * concrete URL), and falls back to `req.url` with the query
 * string stripped. Returns `"/"` on missing or non-string input
 * so audit-chain rows / metrics labels never carry `null`.
 *
 * @example
 *   b.requestHelpers.resolveRoute({ routePattern: "/users/:id", url: "/users/42" });
 *   // → "/users/:id"
 *
 *   b.requestHelpers.resolveRoute({ url: "/orders?ref=abc" });
 *   // → "/orders"
 *
 *   b.requestHelpers.resolveRoute({});
 *   // → "/"
 *
 *   b.requestHelpers.resolveRoute(undefined);
 *   // → "/"
 */
function resolveRoute(req) {
  if (req && typeof req.routePattern === "string" && req.routePattern.length > 0) {
    return req.routePattern;
  }
  var url = req && req.url;
  if (typeof url !== "string" || url.length === 0) return "/";
  var qIdx = url.indexOf("?");
  return qIdx === -1 ? url : url.slice(0, qIdx);
}

/**
 * @primitive  b.requestHelpers.makeSkipMatcher
 * @signature  b.requestHelpers.makeSkipMatcher(opts, label)
 * @since      0.15.13
 * @status     stable
 * @related    b.requestHelpers.resolveRoute
 *
 * Build a `(req) => boolean` path-match predicate shared by the state-change
 * guards (`csrfProtect` / `fetchMetadata` / `botGuard` / `rateLimit`) AND the
 * route-exemption / mount checks in `auth.accessLock`, `middleware.ageGate`,
 * `middleware.botDisclose`, and `middleware.dailyByteQuota` — so a single route
 * can be exempted (or a middleware mounted on a path subset) without each caller
 * re-rolling the loop. `opts.skipPaths` entries are validated at build time —
 * each must be a string or a RegExp — so an operator typo dies at boot, not on
 * the first request; the optional `opts.skip(req)` predicate is validated the
 * same way.
 *
 * A STRING entry matches on a SEGMENT BOUNDARY, not a raw prefix: `"/api"`
 * matches `/api` and `/api/x` but NOT `/apixyz` — a raw `startsWith` would skip
 * the guard on an unintended sibling path (a guard-bypass class). An entry that
 * already ends in `/` is itself a segment prefix. Pass `exact: true` to require
 * a whole-path match (no descendant). A RegExp entry uses `.test(path)`. The
 * tested path is `req.pathname || req.url || req.originalUrl || "/"` with the
 * query string stripped (matching is on the path, never the query). A `skip`
 * predicate that throws is treated as "do not skip", so a buggy exemption can
 * only keep the guard ON, never silently bypass it.
 *
 * @opts
 *   skipPaths:  Array<string|RegExp>,   // string = segment-boundary match; RegExp = .test(path)
 *   exact:      boolean,                // string entries match whole-path only (no descendant). default false
 *   skip:       function,               // (req) => boolean, optional route-aware predicate
 *
 * @example
 *   var shouldSkip = b.requestHelpers.makeSkipMatcher(
 *     { skipPaths: ["/healthz", /^\/webhooks\//] }, "middleware.csrfProtect");
 *   if (shouldSkip(req)) return next();
 */
function _skipStrMatch(path, entry, exact) {
  if (exact) return path === entry;
  if (entry.charAt(entry.length - 1) === "/") return path.indexOf(entry) === 0;
  return path === entry || path.indexOf(entry + "/") === 0;
}

function makeSkipMatcher(opts, label) {
  opts = opts || {};
  label = label || "makeSkipMatcher";
  var skipPaths = opts.skipPaths || [];
  if (!Array.isArray(skipPaths)) {
    throw new TypeError(label + ": skipPaths must be an array of string prefixes or RegExp");
  }
  for (var i = 0; i < skipPaths.length; i++) {
    if (typeof skipPaths[i] !== "string" && !(skipPaths[i] instanceof RegExp)) {
      throw new TypeError(label + ": skipPaths[" + i + "] must be a string prefix or RegExp, got " +
        typeof skipPaths[i]);
    }
    if (skipPaths[i] instanceof RegExp) {
      _guardRegex().assertSafe(skipPaths[i], label + ": skipPaths[" + i + "]");
    }
  }
  var skipFn = opts.skip;
  if (skipFn !== undefined && skipFn !== null && typeof skipFn !== "function") {
    throw new TypeError(label + ": skip must be a function (req) => boolean");
  }
  var exact = opts.exact === true;
  return function _shouldSkip(req) {
    var path = (req && (req.pathname || req.url || req.originalUrl)) || "/";
    var qpos = path.indexOf("?");
    if (qpos !== -1) path = path.slice(0, qpos);
    for (var j = 0; j < skipPaths.length; j++) {
      var entry = skipPaths[j];
      if (typeof entry === "string" ? _skipStrMatch(path, entry, exact) : entry.test(path)) {
        return true;
      }
    }
    if (skipFn) {
      try { return skipFn(req) === true; }
      catch (_e) { return false; }
    }
    return false;
  };
}

/**
 * @primitive b.requestHelpers.captureResponseStatus
 * @signature b.requestHelpers.captureResponseStatus(res, onEnd)
 * @since     0.4.0
 * @related   b.requestHelpers.resolveRoute
 *
 * Wrap a response so observability / audit middleware can learn
 * the final status code at end-of-stream. Patches `res.writeHead`
 * and `res.end`; when `res.end()` fires, invokes `onEnd(status)`
 * with the value passed to `writeHead` (preferred) or
 * `res.statusCode` (fallback) or `200` (default). Errors thrown by
 * the `onEnd` callback are swallowed — instrumentation must never
 * break the response. Returns the original `end` function so
 * callers that want to compose can keep a reference. Throws when
 * either argument is missing — these are config-time wiring
 * errors, surfaced loudly.
 *
 * @example
 *   var headers = {};
 *   var sent = null;
 *   var res = {
 *     statusCode: 200,
 *     writeHead:  function (s) { this.statusCode = s; sent = "head"; },
 *     end:        function () { sent = (sent || "end"); },
 *   };
 *
 *   b.requestHelpers.captureResponseStatus(res, function (status) {
 *     console.log("final status:", status);
 *   });
 *
 *   res.writeHead(204);
 *   res.end();
 *   // → "final status: 204"
 */
function captureResponseStatus(res, onEnd) {
  if (!res || typeof onEnd !== "function") {
    throw new Error("captureResponseStatus: requires (res, onEnd)");
  }
  var origEnd = res.end;
  var origWriteHead = res.writeHead;
  var statusFromWriteHead = null;
  res.writeHead = function (s) {
    statusFromWriteHead = s;
    return origWriteHead.apply(res, arguments);
  };
  res.end = function () {
    var status = statusFromWriteHead != null
                   ? statusFromWriteHead
                   : (typeof res.statusCode === "number" ? res.statusCode : HTTP_STATUS.OK);
    _safeAsync().safeInvoke(onEnd, status);
    return origEnd.apply(res, arguments);
  };
  return origEnd;
}

/**
 * @primitive b.requestHelpers.parseQualityList
 * @signature b.requestHelpers.parseQualityList(headerValue, opts?)
 * @since     0.5.17
 * @related   b.requestHelpers.parseListHeader
 *
 * RFC 9110 §12.5 `Accept-*` header parser. Returns
 * `[{ value, q }]` sorted by q descending. Used by content
 * negotiation (`Accept-Encoding`, `Accept-Language`, `Accept`, …).
 * Each Accept-* middleware previously carried its own copy of this
 * loop; centralizing it keeps the q-value semantics consistent —
 * `q=0` is explicit exclusion, q is clamped to `[0, 1]`, missing q
 * defaults to `1`. `value` is lowercased by default; pass
 * `caseSensitive: true` to preserve case (BCP 47 language tags
 * may need it). Bad input (non-string, empty) returns `[]` —
 * absent Accept-* means "accept anything" but the right default
 * differs by caller, so it's the caller's call to layer.
 *
 * @opts
 *   caseSensitive: boolean   // preserve original case in `value`
 *
 * @example
 *   b.requestHelpers.parseQualityList("br;q=1.0, gzip;q=0.5, *;q=0");
 *   // → [
 *   //     { value: "br",   q: 1   },
 *   //     { value: "gzip", q: 0.5 },
 *   //     { value: "*",    q: 0   },
 *   //   ]
 *
 *   b.requestHelpers.parseQualityList("en-US,en;q=0.9", { caseSensitive: true });
 *   // → [
 *   //     { value: "en-US", q: 1   },
 *   //     { value: "en",    q: 0.9 },
 *   //   ]
 *
 *   b.requestHelpers.parseQualityList(undefined);
 *   // → []
 */
function parseQualityList(headerValue, opts) {
  if (typeof headerValue !== "string" || headerValue.length === 0) return [];
  opts = opts || {};
  var caseSensitive = opts.caseSensitive === true;
  var parts = structuredFields.splitUnquoted(headerValue, ",");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var segs = structuredFields.splitUnquoted(p, ";");
    var head = segs[0].trim();
    var value = caseSensitive ? head : head.toLowerCase();
    var q = 1;
    for (var s = 1; s < segs.length; s++) {
      var kv = structuredFields.parseKeyValuePiece(segs[s], "=", true);
      if (kv.key !== "q") continue;
      var qm = String(kv.value).trim().match(/^([0-9]*\.?[0-9]+)/);
      q = qm ? parseFloat(qm[1]) : 1;
      if (isNaN(q) || q < 0) q = 0;
      if (q > 1) q = 1;
      break;
    }
    out.push({ value: value, q: q });
  }
  out.sort(function (a, b) { return b.q - a.q; });
  return out;
}

/**
 * @primitive b.requestHelpers.extractBearer
 * @signature b.requestHelpers.extractBearer(req)
 * @since     0.7.19
 * @related   b.requestHelpers.safeHeadersDistinct, b.middleware.bearerAuth, b.guardJwt
 *
 * RFC 6750 §2.1 inbound bearer-token extractor. Reads the
 * `Authorization` request header, validates the case-insensitive
 * `Bearer ` scheme, and returns the trimmed token string. Returns
 * `null` on any malformed shape — defensive by design, since this
 * runs on every authenticated request and a throw here would crash
 * the request itself. Callers that require a token throw their
 * own authentication-shape error when `null` surfaces.
 *
 * Refusal cases (all return `null`): missing Authorization header,
 * non-string value, multiple Authorization headers (CWE-345 trust
 * mismatch), scheme other than `Bearer` (case-insensitive), missing
 * space + token after the scheme, embedded CR / LF / NUL / Tab /
 * other ASCII control bytes (CRLF-injection defense — the token
 * transits log lines + audit metadata), embedded spaces inside the
 * token. Token shape past the scheme word is NOT validated against
 * the RFC 6750 b64token grammar here — `b.guardJwt` /
 * `b.middleware.bearerAuth` own format-specific checks.
 *
 * The outbound counterpart is `b.authHeader.bearer(token)`, which
 * constructs `Authorization: Bearer <token>` for outgoing requests.
 *
 * @example
 *   var req = { headers: { authorization: "Bearer eyJhbGciOiJFUzI1NiJ9.payload.sig" } };
 *   b.requestHelpers.extractBearer(req);
 *   // → "eyJhbGciOiJFUzI1NiJ9.payload.sig"
 *
 *   // Case-insensitive scheme:
 *   b.requestHelpers.extractBearer({ headers: { authorization: "bearer abc123" } });
 *   // → "abc123"
 *
 *   // Refusals return null:
 *   b.requestHelpers.extractBearer({ headers: { authorization: "Basic dXNlcjpwYXNz" } });
 *   // → null
 *
 *   b.requestHelpers.extractBearer({ headers: { authorization: "Bearer abc, def" } });
 *   // → null
 *
 *   b.requestHelpers.extractBearer({});
 *   // → null
 */
function extractBearer(req) {
  if (!req || typeof req !== "object") return null;
  if (Array.isArray(req.rawHeaders)) {
    var seen = 0;
    for (var ri = 0; ri + 1 < req.rawHeaders.length; ri += 2) {
      var name = req.rawHeaders[ri];
      if (typeof name === "string" && name.toLowerCase() === "authorization") {
        seen += 1;
        if (seen > 1) return null;
      }
    }
  }
  var headers = req.headers;
  if (!headers || typeof headers !== "object") return null;
  var raw = headers["authorization"];
  if (raw === undefined) raw = headers["Authorization"];
  if (typeof raw !== "string" || raw.length === 0) return null;
  if (raw.indexOf(",") !== -1) return null;
  if (codepointClass.firstControlCharOffset(raw, { forbidTab: true }) !== -1) {
    return null;
  }
  if (raw.length < 8) return null;
  if (raw.charAt(6) !== " ") return null;
  var schemeLower = raw.slice(0, 6).toLowerCase();
  if (schemeLower !== "bearer") return null;
  var token = raw.slice(7);
  while (token.length > 0 && token.charAt(0) === " ") token = token.slice(1);
  while (token.length > 0 && token.charAt(token.length - 1) === " ") {
    token = token.slice(0, -1);
  }
  if (token.length === 0) return null;
  if (token.indexOf(" ") !== -1) return null;
  return token;
}

/**
 * @primitive b.requestHelpers.safeHeadersDistinct
 * @signature b.requestHelpers.safeHeadersDistinct(req)
 * @since     0.7.0
 * @related   b.requestHelpers.extractBearer
 *
 * Defensive replacement for `req.headersDistinct`. Node CVE
 * 2026-21710: `headersDistinct` is implemented as a getter, and
 * reading `__proto__` on the underlying header bag throws
 * synchronously inside the getter. A request bearing a
 * `__proto__:` header therefore escapes any handler-level
 * try/catch — the throw happens at property-access time, not
 * later. This helper computes the same shape (lowercased
 * header-name to array of values) directly from `req.rawHeaders`,
 * skipping `__proto__` / `constructor` / `prototype` keys, and
 * returns a null-prototype object so iteration never inherits
 * `Object.prototype` properties. Always returns an object — never
 * throws.
 *
 * @example
 *   var req = {
 *     rawHeaders: [
 *       "Set-Cookie", "a=1",
 *       "Set-Cookie", "b=2",
 *       "X-Trace",    "abc",
 *       "__proto__",  "polluted",
 *     ],
 *   };
 *   var headers = b.requestHelpers.safeHeadersDistinct(req);
 *   headers["set-cookie"];   // → ["a=1", "b=2"]
 *   headers["x-trace"];      // → ["abc"]
 *   headers["__proto__"];    // → undefined   (prototype-pollution key dropped)
 *
 *   b.requestHelpers.safeHeadersDistinct(undefined);
 *   // → {}   (null-prototype empty object)
 */
function safeHeadersDistinct(req) {
  var out = Object.create(null);
  if (!req || !Array.isArray(req.rawHeaders)) return out;
  var raw = req.rawHeaders;
  for (var i = 0; i + 1 < raw.length; i += 2) {
    var name  = raw[i];
    var value = raw[i + 1];
    if (typeof name !== "string" || typeof value !== "string") continue;
    var lower = name.toLowerCase();
    if (pick.isPoisonedKey(lower)) continue;
    if (out[lower]) out[lower].push(value);
    else out[lower] = [value];
  }
  return out;
}

/**
 * @primitive  b.requestHelpers.makeResourceAuditEmitter
 * @signature  b.requestHelpers.makeResourceAuditEmitter(sink, resourceKind, idFor?)
 * @since      0.15.13
 * @status     stable
 * @related    b.requestHelpers.extractActorContext
 *
 * Build a drop-silent audit emitter `(action, key, outcome, metadata, req)` for
 * a request-scoped resource. The emitter is disabled when `sink` is falsy (the
 * operator supplied no audit instance), so a primitive can wire it
 * unconditionally and let the operator opt in by passing `opts.audit`. Each
 * event carries `resource: { kind, id }` and, when a request is passed, the
 * actor extracted from it (`extractActorContext`); a throwing sink is swallowed
 * so audit emission can never break the request the event describes.
 *
 * The auth lockout / bot-challenge and session device-binding primitives emit
 * this exact shape, varying only in the resource kind and how the id derives
 * from the per-call key. `idFor(key)` maps the per-call key to the resource id
 * (default: the key verbatim); pass it when the id needs a prefix or transform.
 *
 * @example
 *   var emitAudit = b.requestHelpers.makeResourceAuditEmitter(
 *     opts.audit, "auth.lockout", function (key) { return ns + ":" + key; });
 *   emitAudit("locked", key, "denied", { attempts: n }, req);
 */
function makeResourceAuditEmitter(sink, resourceKind, idFor) {
  return function (action, key, outcome, metadata, req) {
    if (!sink) return;
    try {
      var event = {
        action:   action,
        outcome:  outcome,
        resource: { kind: resourceKind, id: idFor ? idFor(key) : key },
        metadata: metadata || {},
      };
      if (req) event.actor = extractActorContext(req);
      sink.safeEmit(event);
    } catch (_e) { /* audit best-effort — never let a sink throw escape */ }
  };
}

/**
 * @primitive b.requestHelpers.failAfterHeaders
 * @signature b.requestHelpers.failAfterHeaders(res)
 * @since     0.18.19
 * @status    stable
 * @related   b.render.stream, b.errorPage.create
 *
 * End a response that has already sent its status line, in a way that tells the
 * client the transfer is incomplete. Returns `true` when it handled the
 * response, `false` when the caller still owns it and can write a normal error.
 *
 * Once the headers are on the wire they cannot be replaced, and every attempt
 * to do so makes things worse rather than better: `writeHead` throws
 * `ERR_HTTP_HEADERS_SENT`, and a caller that catches that and falls back to
 * `res.end("Internal Server Error")` appends those words to whatever partial
 * body the client already has. The client then sees a 200 with a plausible
 * final row. Silent truncation presented as success is a data-integrity
 * failure, so the honest signal is an incomplete transfer.
 *
 * Which signal that is depends on the protocol, which is why this is one
 * primitive rather than a line repeated at each error path:
 *
 * - **HTTP/1.1** — destroy the socket, so a chunked response ends without its
 *   terminating chunk and the client reports a failed download.
 * - **HTTP/2** — destroying with no argument closes the stream with
 *   `RST_STREAM(NO_ERROR)`, which a client reads as a clean end: the truncated
 *   body arrives as a complete 200. The stream is closed with
 *   `INTERNAL_ERROR` instead so the failure survives the protocol.
 * - **A response that cannot carry a body** — HEAD, 204, 304 — is already
 *   complete once its headers are sent. There is nothing to truncate, so it is
 *   ended normally; destroying would throw away a valid response.
 *
 * @example
 *   if (!b.requestHelpers.failAfterHeaders(res)) {
 *     b.render.json(res, { error: "internal" }, { status: 500 });
 *   }
 */
var H2_INTERNAL_ERROR = 0x02;

function failAfterHeaders(res) {
  if (!res) return true;
  if (res.writableEnded === true || res.destroyed === true) return true;
  if (res.headersSent !== true) return false;
  try {
    if (res._hasBody === false ||
        (typeof res.statusCode === "number" && C.HTTP.bodiless(res.statusCode))) {
      if (typeof res.end === "function") res.end();
      return true;
    }
    if (res.stream && typeof res.stream.close === "function") {
      res.stream.close(H2_INTERNAL_ERROR);
      return true;
    }
    if (typeof res.destroy === "function") { res.destroy(); return true; }
    if (typeof res.end === "function") res.end();
  } catch (_e) { /* socket already gone */ }
  return true;
}

module.exports = {
  failAfterHeaders:          failAfterHeaders,
  resolveRoute:              resolveRoute,
  makeResourceAuditEmitter:  makeResourceAuditEmitter,
  makeSkipMatcher:           makeSkipMatcher,
  captureResponseStatus:     captureResponseStatus,
  extractActorContext:       extractActorContext,
  resolveActorWithOverride:  resolveActorWithOverride,
  parseQualityList:          parseQualityList,
  parseListHeader:           parseListHeader,
  clientIp:                  clientIp,
  trustedClientIp:           trustedClientIp,
  trustedIdentityHeaders:    trustedIdentityHeaders,
  ipPrefix:                  ipPrefix,
  ipKey:                     ipKey,
  requestProtocol:           requestProtocol,
  trustedProtocol:           trustedProtocol,
  requestHost:               requestHost,
  trustedHost:               trustedHost,
  appendVary:                appendVary,
  safeHeadersDistinct:       safeHeadersDistinct,
  extractBearer:             extractBearer,
  HTTP_STATUS:               HTTP_STATUS,
};
