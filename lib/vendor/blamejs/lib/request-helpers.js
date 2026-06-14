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
 * because without a sanitizing reverse proxy it's
 * attacker-forgeable. Behind a trusted proxy, operators opt in via
 * `trustProxy: true` (use the leftmost XFF hop) or
 * `trustProxy: <N>` (skip N trusted hops from the right and return
 * the Nth-from-rightmost). Returns `null` when no address can be
 * read — never throws.
 *
 * @opts
 *   trustProxy: boolean | number   // false (default) | true | hop count
 *
 * @example
 *   var req = {
 *     socket:  { remoteAddress: "10.0.0.1" },
 *     headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.5" },
 *   };
 *   b.requestHelpers.clientIp(req);
 *   // → "10.0.0.1"   (forwarded headers ignored by default)
 *
 *   b.requestHelpers.clientIp(req, { trustProxy: true });
 *   // → "203.0.113.7"   (leftmost XFF hop)
 *
 *   b.requestHelpers.clientIp(req, { trustProxy: 1 });
 *   // → "10.0.0.5"   (1 trusted hop from the right)
 *
 *   b.requestHelpers.clientIp(undefined);
 *   // → null
 */
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
 * @primitive b.requestHelpers.requestProtocol
 * @signature b.requestHelpers.requestProtocol(req, opts?)
 * @since     0.5.3
 * @related   b.requestHelpers.clientIp, b.safeRedirect
 *
 * Resolve the inbound transport scheme. Default returns `"https"`
 * when `req.socket.encrypted` is set, otherwise `"http"`. Behind a
 * trusted reverse proxy that terminates TLS, set `trustProxy: true`
 * to read the leftmost `X-Forwarded-Proto` hop instead — without
 * the explicit opt-in the framework refuses to pick up the
 * attacker-forgeable header. Always returns a string; on bad input
 * falls back to `"http"`.
 *
 * @opts
 *   trustProxy: boolean   // false (default) | true
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
      if (hops.length > 0) return hops[0];
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
  for (var ci = 0; ci < raw.length; ci += 1) {
    var cc = raw.charCodeAt(ci);
    if (cc === 0x00 || cc === 0x0A || cc === 0x0D || cc === 0x09 || cc < 0x20 || cc === 0x7F) {
      return null;
    }
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
  // RFC 6750 §2.1 inbound bearer-token extractor (returns null on
  // missing / malformed input — symmetric to outbound b.authHeader.bearer)
  extractBearer:             extractBearer,
  HTTP_STATUS:               HTTP_STATUS,
};
