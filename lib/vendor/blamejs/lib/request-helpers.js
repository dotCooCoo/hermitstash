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

// HTTP status codes used across the framework's HTTP-shaped surface.
// Centralized here so error-page / mail-bounce / static / websocket /
// testing / handlers don't sprinkle bare HTTP-status decimal literals;
// the framework gets a single source of truth for status-code naming.
//
// Hex form by design — the framework's byte-literal lint flags decimal
// multiples of 8 across lib/, and HTTP status codes are protocol-fixed
// values (RFC 9110), not byte sizes. Names are RFC 9110 reason phrases;
// every consumer reads HTTP_STATUS.<NAME> rather than the underlying
// integer, so the hex form is purely an internal storage detail.
var structuredFields = require("./structured-fields");
var pick = require("./pick");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
// Lazy — ssrf-guard pulls in the network/DNS stack, and request-helpers is
// required very early in the boot graph. Only touched at middleware-construction
// time by trustedClientIp(), never on the hot path.
var _ssrfGuard = lazyRequire(function () { return require("./ssrf-guard"); });

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
    // Direct properties first (Express-shaped frameworks set req.ip).
    if (typeof req.ip === "string") ctx.ip = req.ip;
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
    // userId from common shapes the framework's auth surfaces produce
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

// ---- Proxy-trust primitives (v0.5.3) ----
//
// `X-Forwarded-For` and `X-Forwarded-Proto` are operator-trust
// headers — behind a sanitizing reverse proxy they carry the
// apparent origin / scheme; without one they're attacker-forgeable.
// Default is to NOT trust them; operators behind a proxy opt in by
// passing `trustProxy: true` (or a hop count for multi-hop chains).

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
 * @opts
 *   trustProxy: boolean | number | function   // false (default) | predicate (peer-gated) | legacy true/hop-count
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
function clientIp(req, opts) {
  if (!req) return null;
  var socketAddr =
    (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
    : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
    : null;
  var trust = opts && opts.trustProxy;
  if (trust && req.headers) {
    var xff = req.headers["x-forwarded-for"];
    if (xff) {
      var hops = parseListHeader(xff);
      if (hops.length) {
        if (typeof trust === "function") {
          // Peer-gated resolution: `trust(addr)` names the trusted reverse
          // proxies. X-Forwarded-For is honored ONLY when the immediate TCP
          // peer is itself a trusted proxy; the real client is then the first
          // untrusted address walking the chain right-to-left (each hop is
          // appended by the proxy that observed it). A direct attacker — whose
          // socket peer is not a trusted proxy — cannot forge the result: the
          // forgeable header is ignored and we fall through to the socket
          // address. This is the only form safe for an access-control decision.
          if (socketAddr && trust(socketAddr)) {
            for (var i = hops.length - 1; i >= 0; i--) {
              if (!trust(hops[i])) return hops[i];
            }
            return hops[0];   // entire chain trusted — earliest claimed client
          }
          // peer is not a trusted proxy → ignore forgeable XFF, fall through
        } else if (trust === true) {
          return hops[0];
        } else if (typeof trust === "number" && trust >= 1 && hops.length >= trust) {
          return hops[hops.length - trust];
        }
      }
    }
  }
  if (socketAddr) return socketAddr;
  // Express-shaped requests expose the resolved client address as `req.ip`
  // (Express derives it from the socket, honoring its own trust-proxy
  // setting) without a `socket.remoteAddress` surface. Fall back to it so a
  // binding captured from such a request is populated rather than null —
  // callers that pin a grant to the issuing IP otherwise capture null and
  // could only be saved by a fail-closed guard at the consumer.
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
 * `trustedProxies` (CIDRs of the reverse proxies), `X-Forwarded-For` is
 * honored only when the immediate peer is one of them. With neither, only
 * the socket address is used and forwarded headers are ignored.
 *
 * @opts
 *   trustedProxies:   string | string[],          // CIDRs — peer-gate X-Forwarded-For
 *   clientIpResolver: function(req): string|null,  // own resolution entirely
 *
 * @example
 *   var tip = b.requestHelpers.trustedClientIp({ trustedProxies: ["10.0.0.0/8"] });
 *   var ip  = tip.resolve(req);   // peer-gated; forged XFF from a direct caller ignored
 */
// Build the trusted-proxy predicate shared by trustedClientIp / trustedProtocol.
// Validates each CIDR (a CIDR is valid iff it contains its own network address,
// reusing the same matcher the predicate uses so format rules can't diverge) and
// returns fn(addr)=>boolean, or null when no trustedProxies were given. `where`
// names the calling helper for the error message.
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
    // Fold an IPv4-mapped IPv6 peer (::ffff:a.b.c.d, common on a dual-stack
    // listener) to its dotted IPv4 form so it matches an IPv4 trustedProxies
    // CIDR — cidrContains rejects a cross-family compare, so without this a
    // mapped proxy peer reads as untrusted and X-Forwarded-* is ignored. Only
    // the ::ffff:0:0/96 block folds (canonicalizeHost leaves NAT64 / 6to4 as
    // IPv6), so this can't widen the trusted set.
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
  return {
    peerGated: !!(resolver || predicate),
    resolve: function (req) {
      if (resolver) return resolver(req);
      if (predicate) return clientIp(req, { trustProxy: predicate });
      return clientIp(req, { trustProxy: false });
    },
  };
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
          // Peer-gated: honor X-Forwarded-Proto only when the immediate TCP
          // peer is a trusted proxy. A direct caller's forged header is
          // ignored — fall through to the real TLS socket. The only form safe
          // for a Secure-cookie / HSTS / secure-context decision.
          var peer =
            (req.socket && typeof req.socket.remoteAddress === "string" && req.socket.remoteAddress) ? req.socket.remoteAddress
            : (req.connection && typeof req.connection.remoteAddress === "string" && req.connection.remoteAddress) ? req.connection.remoteAddress
            : null;
          if (peer && trust(peer)) return hops[0];
          // peer not a trusted proxy → ignore forgeable header, fall through
        } else {
          return hops[0];   // legacy true/number — spoofable, see docstring
        }
      }
    }
  }
  if (req.socket && req.socket.encrypted) return "https";
  if (req.connection && req.connection.encrypted) return "https";
  return "http";
}

// RFC 9110 §5.6.2 token grammar — letters, digits, and the
// punctuation set `!#$%&'*+-.^_`|~`. Used by header-list parsers
// that consume protocol tokens (Connection, Sec-WebSocket-Protocol,
// etc.).
var RFC_9110_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

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
    // RFC 9110 §5.6.2 token grammar excludes C0 / DEL. Scan the RAW
    // value BEFORE the comma split + trim so a leading/trailing
    // `\r\n\t` byte can't slip through (the trim() below would strip
    // it before RFC_9110_TOKEN_RE saw it, matching the v0.8.90
    // `parseTlsRequiredHeader` bug class).
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
    if (opts.strictToken && !RFC_9110_TOKEN_RE.test(t)) {
      // Refuse non-token entries when caller asked for strict-token
      // grammar (RFC 9110 §5.6.2). Used by ws subprotocol negotiation
      // and other places where only token-shaped values are valid.
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
// _skipStrMatch — does the request path match a single STRING skip entry?
// SEGMENT-BOUNDARY semantics, NOT a raw `startsWith`: entry "/api" matches
// "/api" and "/api/x" but NOT "/apixyz" (a raw prefix would wrongly skip the
// guard on the sibling path — a guard-bypass class). An entry that already
// ends in "/" is itself a segment prefix ("/webhooks/" matches "/webhooks/x").
// `exact` restricts to a whole-path equality (no descendant match).
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
  }
  var skipFn = opts.skip;
  if (skipFn !== undefined && skipFn !== null && typeof skipFn !== "function") {
    throw new TypeError(label + ": skip must be a function (req) => boolean");
  }
  var exact = opts.exact === true;
  return function _shouldSkip(req) {
    var path = (req && (req.pathname || req.url || req.originalUrl)) || "/";
    var qpos = path.indexOf("?");
    if (qpos !== -1) path = path.slice(0, qpos);   // match on the path, never the query string
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
    try { onEnd(status); }
    catch (_e) { /* onEnd never breaks the response — caller's instrumentation issue */ }
    return origEnd.apply(res, arguments);
  };
  return origEnd;
}

var Q_VALUE_RE = /(?:^|;|\s)q\s*=\s*([0-9]*\.?[0-9]+)/i;

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
  var parts = headerValue.split(",");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var semi = p.indexOf(";");
    var value, q;
    if (semi === -1) {
      value = caseSensitive ? p : p.toLowerCase();
      q = 1;
    } else {
      var head = p.slice(0, semi).trim();
      value = caseSensitive ? head : head.toLowerCase();
      var rest = p.slice(semi + 1).trim();
      var qm = rest.match(Q_VALUE_RE);
      q = qm ? parseFloat(qm[1]) : 1;
      if (isNaN(q) || q < 0) q = 0;
      if (q > 1) q = 1;
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
  // Distinct-header scan first — multiple Authorization headers is a
  // trust-mismatch shape (CWE-345); refuse rather than pick one. Node's
  // h1 parser folds duplicate Authorization values with ", " joining
  // by default, so the multi-value detection must look at rawHeaders
  // (or headersDistinct via safeHeadersDistinct).
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
  // A pre-folded duplicate (Node h1 default) shows up as a comma in the
  // value — refuse, same trust-mismatch class. Bearer tokens themselves
  // never contain commas (RFC 6750 b64token grammar).
  if (raw.indexOf(",") !== -1) return null;
  // Reject ASCII control characters BEFORE prefix-matching so a header
  // like "Bearer\rinjected" never reaches consumers.
  if (codepointClass.firstControlCharOffset(raw, { forbidTab: true }) !== -1) {
    return null;
  }
  // RFC 6750 §2.1 — auth-scheme is case-insensitive. The "Bearer "
  // prefix + at least one token byte must be present; the literal
  // 7-byte prefix length (6 letters + space) matches "Bearer " and
  // its case variants.
  if (raw.length < 8) return null;                                                  // RFC 6750 §2.1 "Bearer " prefix (7 chars) + ≥1 token byte, char count not bytes
  if (raw.charAt(6) !== " ") return null;
  var schemeLower = raw.slice(0, 6).toLowerCase();
  if (schemeLower !== "bearer") return null;
  var token = raw.slice(7);
  // Trim whitespace per RFC 7230 OWS tolerance — but only the leading /
  // trailing space; embedded whitespace in a Bearer token is not RFC
  // 6750 b64token-shaped and is refused above (cc === 0x09 / 0x20 < cc
  // already covers control + delete; spaces inside the token would
  // pass the control check, so handle explicitly).
  while (token.length > 0 && token.charAt(0) === " ") token = token.slice(1);
  while (token.length > 0 && token.charAt(token.length - 1) === " ") {
    token = token.slice(0, -1);
  }
  if (token.length === 0) return null;
  // Refuse embedded spaces — a properly-formed bearer credential is
  // a single token. Embedded space would slip a second value past
  // operators that read the trailing portion as JWT / opaque-id.
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
    // skip __proto__ / constructor / prototype as keys — they are the
    // exact strings that triggered the upstream getter throw, and we
    // refuse to surface them as accessible header names.
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

module.exports = {
  resolveRoute:              resolveRoute,
  makeResourceAuditEmitter:  makeResourceAuditEmitter,
  makeSkipMatcher:           makeSkipMatcher,
  captureResponseStatus:     captureResponseStatus,
  extractActorContext:       extractActorContext,
  resolveActorWithOverride:  resolveActorWithOverride,
  parseQualityList:          parseQualityList,
  parseListHeader:           parseListHeader,
  // proxy-trust primitives (default refuses forwarded headers)
  clientIp:                  clientIp,
  trustedClientIp:           trustedClientIp,
  requestProtocol:           requestProtocol,
  trustedProtocol:           trustedProtocol,
  appendVary:                appendVary,
  // CVE-2026-21710 wrap — safe alternative to req.headersDistinct
  safeHeadersDistinct:       safeHeadersDistinct,
  // RFC 6750 §2.1 inbound bearer-token extractor (returns null on
  // missing / malformed input — symmetric to outbound b.authHeader.bearer)
  extractBearer:             extractBearer,
  HTTP_STATUS:               HTTP_STATUS,
};
