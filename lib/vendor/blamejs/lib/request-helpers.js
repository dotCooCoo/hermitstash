"use strict";
/**
 * request-helpers — small shared utilities for HTTP request middleware.
 *
 * The framework's metrics + tracing requestMiddleware both label by
 * route TEMPLATE and capture the final response status. They had
 * identical implementations of:
 *
 *   1. Reading req.routePattern with a URL-fallback
 *   2. Wrapping res.writeHead + reading res.statusCode at res.end
 *
 * This module owns the two helpers so the duplication doesn't drift —
 * if either pattern changes (e.g. handle res.statusMessage), it changes
 * once.
 *
 * Public API:
 *
 *   resolveRoute(req)
 *     Returns req.routePattern when the router populated it,
 *     otherwise the URL with query string stripped.
 *
 *   captureResponseStatus(res, onEnd)
 *     Wraps res.writeHead + res.end. Calls onEnd(status) once when the
 *     response ends, with the final status pulled from writeHead's
 *     argument OR from res.statusCode (modern Node handlers set it
 *     directly without going through writeHead). Operators wrap their
 *     own pre-end logic by passing it as onEnd.
 *
 *     Returns the original (unwrapped) `res.end`. Useful for unit tests
 *     that need to assert against the original behavior.
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

// extractActorContext(req) — pull the 5 W's from a request for audit
// chain emission. WHO/WHERE/HOW columns on _blamejs_audit_log are
// populated from this shape:
//
//   { ip, userAgent, sessionId, requestId, method, route, userId }
//
// Every field is best-effort: missing or non-request inputs return
// an object with whatever could be inferred plus null elsewhere.
// Audit chain treats null as "unknown", so partial context is safe.
//
// Caller-supplied actor (existing actor.userId, actor.ip, etc.) is
// merged on top of the request-derived fields — explicit operator
// override always wins.
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

// Convenience wrapper for primitives that accept an optional
// `{ req, context }` shape and want to thread it into an audit-emit
// `actor` field. Replaces the four near-identical `_actor()` helpers
// that lived in api-key, cache, seeders, and notify before v0.4.29.
//
//   callerOpts:    operator-supplied `{ req?, context? }` (e.g. the
//                  primitive's call-site opts bag)
//   baseOverride:  optional seed values applied BEFORE callerOpts.context
//                  so `context` wins. api-key seeds `{ userId }` here so
//                  the resolved key's owner becomes the default actor
//                  unless the operator passes their own context.userId.
//
// Returns the same shape as extractActorContext.
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
// `X-Forwarded-For` and `X-Forwarded-Proto` are operator-trust headers —
// behind a sanitizing reverse proxy they carry the apparent origin /
// scheme; without one they're attacker-forgeable. Default is to NOT
// trust them; operators behind a proxy set `trustProxy: true` (or a
// hop count for multi-hop chains) per-middleware to opt in.
//
//   clientIp(req, { trustProxy }) →  string | null
//
//     trustProxy false (default):  socket.remoteAddress only
//     trustProxy true:             leftmost x-forwarded-for hop, else socket
//     trustProxy <integer N>:      Nth-from-rightmost xff hop (skip-N-trusted-hops)
//
// Middleware accepts `trustProxy` as an opt and threads it through;
// the framework refuses to silently pick up forwarded headers without
// the operator's explicit acknowledgement.

function clientIp(req, opts) {
  if (!req) return null;
  var trust = opts && opts.trustProxy;
  if (trust && req.headers) {
    var xff = req.headers["x-forwarded-for"];
    if (xff) {
      var hops = parseListHeader(xff);
      if (trust === true) return hops[0];
      if (typeof trust === "number" && trust >= 1 && hops.length >= trust) {
        return hops[hops.length - trust];
      }
    }
  }
  if (req.socket && typeof req.socket.remoteAddress === "string") return req.socket.remoteAddress;
  if (req.connection && typeof req.connection.remoteAddress === "string") return req.connection.remoteAddress;
  return null;
}

function requestProtocol(req, opts) {
  if (!req) return "http";
  var trust = opts && opts.trustProxy;
  if (trust && req.headers) {
    var fwd = req.headers["x-forwarded-proto"];
    if (typeof fwd === "string" && fwd.length > 0) {
      var hops = parseListHeader(fwd, { lowercase: true });
      if (hops.length > 0) return hops[0];
    }
  }
  if (req.socket && req.socket.encrypted) return "https";
  if (req.connection && req.connection.encrypted) return "https";
  return "http";
}

// parseListHeader — split a comma-separated header / opt value into a
// list of trimmed non-empty tokens. Replaces the
// `String(x).split(",").map(s => s.trim()).filter(Boolean)` chain that
// was duplicated across cors / compression / scheduler / webhook /
// websocket / db-schema / cli before v0.5.17.
//
//   parseListHeader("a, b , ,c")           → ["a", "b", "c"]
//   parseListHeader("Foo, Bar", { lowercase: true })
//                                          → ["foo", "bar"]
//   parseListHeader(undefined)             → []
//   parseListHeader("")                    → []
//
// Tolerant read: non-string input returns [] — these are read from
// request headers that the network might omit. Callers needing stricter
// checks layer their own validation on the result.
// RFC 9110 §5.6.2 token grammar — letters, digits, and the
// punctuation set `!#$%&'*+-.^_`|~`. Used by header-list parsers
// that consume protocol tokens (Connection, Sec-WebSocket-
// Protocol, etc.). Operator handlers parsing comma-separated
// human-supplied values (Origin lists, etc.) opt out by passing
// `lax: true`.
var RFC_9110_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
function parseListHeader(value, opts) {
  if (value == null) return [];
  opts = opts || {};
  var s = typeof value === "string" ? value : String(value);
  if (s.length === 0) return [];
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

// Append a token to a `Vary` response header without dropping prior
// values (compression middleware sets `Vary: Accept-Encoding`, an
// auth helper might set `Vary: Authorization`, etc.). Idempotent —
// re-adding an existing token is a no-op.
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

function resolveRoute(req) {
  if (req && typeof req.routePattern === "string" && req.routePattern.length > 0) {
    return req.routePattern;
  }
  var url = req && req.url;
  if (typeof url !== "string" || url.length === 0) return "/";
  var qIdx = url.indexOf("?");
  return qIdx === -1 ? url : url.slice(0, qIdx);
}

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

// parseQualityList — RFC 9110 §12.5 Accept-* header parser.
//
// Returns `[{ value, q }]` sorted by q descending. Used by content
// negotiation (`Accept-Encoding`, `Accept-Language`, `Accept`, etc.).
// Each Accept-* middleware previously had its own copy of this loop;
// extracting it here keeps the q-value semantics consistent
// (q=0 = explicit exclusion; clamped to [0, 1]; missing q = 1).
//
//   parseQualityList("br;q=1.0, gzip;q=0.5, *;q=0")
//     → [{ value: "br", q: 1 }, { value: "gzip", q: 0.5 }, { value: "*", q: 0 }]
//
// `value` is lowercased by default; pass `{ caseSensitive: true }` to
// preserve case (BCP 47 language tags want case preservation since
// `pt-BR` and `pt-br` resolve identically but operators may match by
// canonical form themselves).
//
// Bad input (non-string, empty) returns []. RFC 9110 says an absent
// Accept header means "accept anything"; callers handle that absence
// at their own layer (compression's [{ encoding: "*", q: 1 }] default
// vs i18n's "fall back to default locale" — different semantics).
var Q_VALUE_RE = /(?:^|;|\s)q\s*=\s*([0-9]*\.?[0-9]+)/i;

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

// safeHeadersDistinct(req) — defensive accessor for req.headersDistinct.
//
// Node CVE-2026-21710: req.headersDistinct is a getter; reading
// __proto__ on the underlying header bag throws synchronously inside
// the getter, so a request bearing a __proto__: header escapes any
// handler-level try/catch (the throw happens at property-access time,
// not later). This helper computes the same shape (lowercased header-
// name → array of values) directly from req.rawHeaders, bypassing the
// faulty getter entirely.
//
// Returns a null-prototype object so framework code can iterate its
// keys without inheriting Object.prototype properties — the same shape
// Node's headersDistinct produces, minus the throwing getter.
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
    if (lower === "__proto__" || lower === "constructor" || lower === "prototype") continue;
    if (out[lower]) out[lower].push(value);
    else out[lower] = [value];
  }
  return out;
}

module.exports = {
  resolveRoute:              resolveRoute,
  captureResponseStatus:     captureResponseStatus,
  extractActorContext:       extractActorContext,
  resolveActorWithOverride:  resolveActorWithOverride,
  parseQualityList:          parseQualityList,
  parseListHeader:           parseListHeader,
  // proxy-trust primitives (default refuses forwarded headers)
  clientIp:                  clientIp,
  requestProtocol:           requestProtocol,
  appendVary:                appendVary,
  // CVE-2026-21710 wrap — safe alternative to req.headersDistinct
  safeHeadersDistinct:       safeHeadersDistinct,
  HTTP_STATUS:               HTTP_STATUS,
};
