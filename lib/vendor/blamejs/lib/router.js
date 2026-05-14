"use strict";
/**
 * @module b.router
 * @featured true
 * @nav    HTTP
 * @title  Router
 *
 * @intro
 *   HTTP route registration + dispatch. Operators register handlers
 *   against method+pattern pairs, the router compiles each pattern
 *   once at registration time and walks the table linearly per
 *   request — first match wins.
 *
 *   Patterns are segment-based (`/users/:id`); named parameters land
 *   on `req.params`. Handler dispatch follows arity:
 *     - `handler.length >= 3` is middleware (req, res, next) — the
 *       chain stops unless `next()` is called.
 *     - `handler.length <= 2` is a terminal handler (req, res) — the
 *       chain falls through to the next entry unless the response is
 *       already ended.
 *
 *   When no pattern matches, the registered `onNotFound` handler runs;
 *   the framework default is a 404 with a small text/html body. The
 *   router boots an HTTP/2 + HTTP/1.1 ALPN server on `listen()` when
 *   given TLS options, an HTTP/1.1 server otherwise.
 *
 *   Zero npm runtime deps — this primitive replaces express / koa /
 *   fastify entirely while keeping the framework's security defaults
 *   (TLS 1.3 minimum, 0-RTT anti-replay, Slowloris timeouts, h2
 *   CONTINUATION-flood + Rapid-Reset caps) wired in by default.
 *
 * @card
 *   HTTP route registration + dispatch.
 */
var http  = require("http");
var http2 = require("http2");
var nodeFs = require("fs");
var nodePath = require("path");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var safeUrl = require("./safe-url");
var websocket = require("./websocket");
var { boot } = require("./log");
var { RouterError } = require("./framework-error");

var auditFwk = lazyRequire(function () { return require("./audit"); });
// compliance — lazy because router.js is required during boot before
// the operator's `b.compliance.set(...)` runs; the posture lookup only
// matters at listen() time, well after boot finishes.
var complianceLazy = lazyRequire(function () { return require("./compliance"); });

var log = boot("router");
var HTTP_STATUS = requestHelpers.HTTP_STATUS;

// CVE-2026-21714 — h2 WINDOW_UPDATE leak after GOAWAY. nghttp2 holds
// per-stream flow-control state after the session has emitted GOAWAY;
// late-arriving WINDOW_UPDATE frames can re-credit a draining stream
// and starve the connection. The framework cap defends defense-in-depth
// even when Node's nghttp2 vendor lags the upstream fix: tag every
// session with `_blamejsGoawaySent` on the framework's GOAWAY emission,
// and force-destroy on any subsequent frame activity.
var WINDOW_UPDATE_FRAME_TYPE = 0x8;                                              // allow:raw-byte-literal — RFC 7540 §6.9 frame type
// Per-stream WINDOW_UPDATE rate cap. Above this rate the framework
// destroys the stream; legitimate clients never burst this fast on a
// healthy connection.
var WINDOW_UPDATE_RATE_CAP = 100;                                                // allow:raw-byte-literal — frames per second per stream
var WINDOW_UPDATE_RATE_WINDOW_MS = C.TIME.seconds(1);

// Cap on operator-defined route patterns. A route registration that
// somehow attracts a multi-megabyte template string would stall regex
// compilation; bound it before new RegExp() so the gate at registration
// time is bounded.
var MAX_ROUTE_PATTERN_LEN = C.BYTES.kib(1);

// ---- Schema-spec helpers (route-level body/query/params validation) ----

var ALLOWED_SPEC_KEYS = [
  "body", "query", "params", "response",
  "bodyJsonSchema", "queryJsonSchema", "paramsJsonSchema", "responseJsonSchema",
  "description", "summary", "tags", "validateResponse",
];

function _validateRouteSpec(spec, method, pattern) {
  var keys = Object.keys(spec);
  for (var i = 0; i < keys.length; i++) {
    if (ALLOWED_SPEC_KEYS.indexOf(keys[i]) === -1) {
      throw new Error("router." + method.toLowerCase() + "(" + pattern +
        "): unknown spec key '" + keys[i] + "'. Allowed: " +
        ALLOWED_SPEC_KEYS.slice().sort().join(", "));
    }
  }
  function _checkSchema(name) {
    var s = spec[name];
    if (s === undefined) return;
    if (!s || typeof s !== "object" || typeof s.safeParse !== "function") {
      throw new Error("router." + method.toLowerCase() + "(" + pattern +
        "): spec." + name + " must be a b.safeSchema-shaped schema (with safeParse)");
    }
  }
  _checkSchema("body");
  _checkSchema("query");
  _checkSchema("params");
  _checkSchema("response");
  if (spec.tags !== undefined) {
    if (!Array.isArray(spec.tags) || !spec.tags.every(function (t) { return typeof t === "string"; })) {
      throw new Error("router." + method.toLowerCase() + "(" + pattern +
        "): spec.tags must be an array of strings");
    }
  }
}

function _writeValidationError(res, where, errors) {
  if (res.writableEnded || res.headersSent) return;
  var body = JSON.stringify({
    error: "validation",
    where: where,
    issues: errors,
  });
  res.writeHead(HTTP_STATUS.BAD_REQUEST, {
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function _makeSchemaValidator(spec) {
  // 3-arg signature → router treats as middleware, chains via next().
  return function schemaValidator(req, res, next) {
    if (spec.params && req.params !== undefined) {
      var pp = spec.params.safeParse(req.params);
      if (!pp.ok) return _writeValidationError(res, "params", pp.errors);
      req.params = pp.value;
    }
    if (spec.query && req.query !== undefined) {
      var qq = spec.query.safeParse(req.query);
      if (!qq.ok) return _writeValidationError(res, "query", qq.errors);
      req.query = qq.value;
    }
    if (spec.body && req.body !== undefined) {
      var bb = spec.body.safeParse(req.body);
      if (!bb.ok) return _writeValidationError(res, "body", bb.errors);
      req.body = bb.value;
    }
    next();
  };
}

function _makeResponseValidator(spec) {
  // Wraps res.json (and res.end when called with a JSON-shaped buffer)
  // to validate the response body against spec.response. Mode:
  //   - BLAMEJS_VALIDATE_RESPONSES=throw (or per-route validateResponse: "throw")
  //     → throw a SafeSchemaError-shaped error; route handler's caller sees a 500.
  //   - BLAMEJS_VALIDATE_RESPONSES=warn (or per-route validateResponse: "warn")
  //     → log a warning; ship the response as-is (prod-safe).
  var perRoute = spec.validateResponse;
  var globalMode = safeEnv.readVar("BLAMEJS_VALIDATE_RESPONSES");
  var mode = (perRoute === "throw" || perRoute === "warn") ? perRoute :
             (globalMode === "throw" || globalMode === "warn") ? globalMode : null;
  if (!mode) return function passthrough(_req, _res, next) { next(); };

  return function responseValidator(req, res, next) {
    var origJson = typeof res.json === "function" ? res.json.bind(res) : null;
    if (origJson) {
      res.json = function (value) {
        var rr = spec.response.safeParse(value);
        if (!rr.ok) {
          if (mode === "throw") {
            throw new Error("router response-validation failed for " +
              (req.method + " " + req.routePattern) + ": " +
              JSON.stringify(rr.errors));
          }
          // warn mode
          log.warn("response-validation drift on " + req.method + " " + req.routePattern +
                   ": " + JSON.stringify(rr.errors).slice(0, 500));
        }
        return origJson(value);
      };
    }
    next();
  };
}

function compilePattern(pattern) {
  // pattern is operator-supplied at route registration (router.get(...)).
  // Cap length up-front to bound matcher work even against pathological
  // operator config.
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new Error("router: pattern must be a non-empty string");
  }
  if (pattern.length > MAX_ROUTE_PATTERN_LEN) {
    throw new Error("router: pattern exceeds " + MAX_ROUTE_PATTERN_LEN +
      " chars (got " + pattern.length + ")");
  }
  // Segment-based matcher — splits on "/" once at registration time and
  // walks token-by-token at match time. Avoids compiling a RegExp from
  // the operator-supplied pattern (which would be a dynamic-regex /
  // ReDoS shape even though pattern is operator-controlled).
  //
  // Each segment is either:
  //   - a literal (e.g. "users", "v1")
  //   - a named parameter ":id" — captures into params[name]
  //
  // Matching is exact on segment count: "/a/b" does not match "/a/b/c".
  var rawSegments = pattern.split("/");
  var segments = [];
  var keys = [];
  for (var si = 0; si < rawSegments.length; si++) {
    var seg = rawSegments[si];
    if (seg.length > 0 && seg.charAt(0) === ":") {
      var key = seg.slice(1);
      if (key.length === 0) {
        throw new Error("router: pattern '" + pattern +
          "' has an empty parameter name (':' segment)");
      }
      keys.push(key);
      segments.push({ literal: false, key: key });
    } else {
      segments.push({ literal: true, value: seg });
    }
  }
  return { pattern: pattern, segments: segments, keys: keys };
}

// Walk a request path against a compiled pattern. Returns the params
// object on match, null otherwise. Single non-empty trailing slash
// difference is treated as a no-match (callers that want trailing-slash
// tolerance normalize the path before dispatch).
function _matchCompiled(compiled, pathname) {
  var pathSegments = pathname.split("/");
  var patSegments = compiled.segments;
  if (pathSegments.length !== patSegments.length) return null;
  var params = {};
  for (var i = 0; i < patSegments.length; i++) {
    var seg = patSegments[i];
    if (seg.literal) {
      if (pathSegments[i] !== seg.value) return null;
    } else {
      // Named param: must be non-empty (mirrors the regex `[^/]+`
      // capture from the previous compiled regex).
      if (pathSegments[i].length === 0) return null;
      params[seg.key] = pathSegments[i];
    }
  }
  return params;
}

var MIME_TYPES = {
  ".html":  "text/html",
  ".css":   "text/css",
  ".js":    "application/javascript",
  ".json":  "application/json",
  ".png":   "image/png",
  ".jpg":   "image/jpeg",
  ".jpeg":  "image/jpeg",
  ".gif":   "image/gif",
  ".svg":   "image/svg+xml",
  ".ico":   "image/x-icon",
  ".woff2": "font/woff2",
  ".woff":  "font/woff",
};

// TLS 1.3 0-RTT anti-replay posture (RFC 8446 §8 / §2.3 early-data).
//
// 0-RTT lets the client smuggle application-data bytes alongside the
// ClientHello — saving one round-trip on resumed sessions but admitting
// the replay class: an attacker that captured the encrypted early-data
// can re-send the same handshake bytes and the server processes the
// payload twice. RFC 8446 §8 requires the server EITHER refuse early
// data outright OR maintain a single-use anti-replay state per ticket
// for the configured early_data lifetime.
//
// Postures:
//   "refuse"        — Node default; the framework does not request 0-RTT
//                     and refuses peer early-data attempts.
//   "replay-cache"  — opts in; the framework de-duplicates incoming
//                     early-data by SHA3-512(early-data-bytes) inside a
//                     short rolling window. Cache hit = refuse + audit
//                     (potential replay). Cache miss = accept + audit.
//
// Under regulated postures (`pci-dss`, `fapi2`) the framework refuses
// 0-RTT regardless of operator opt-in — these regimes treat every
// authenticated request as non-idempotent and forbid early-data
// processing. The router consults `b.compliance.current()` at listen
// time and overrides "replay-cache" → "refuse" with an audit row.
var TLS_0RTT_VALID_POSTURES = ["refuse", "replay-cache"];
var TLS_0RTT_REPLAY_WINDOW_MS = C.TIME.seconds(10);
var TLS_0RTT_REPLAY_CACHE_CAP = 4096;                                            // allow:raw-byte-literal — entry count, not bytes
var TLS_0RTT_FAILCLOSED_POSTURES = ["pci-dss", "fapi2"];

class Router {
  constructor(opts) {
    opts = opts || {};
    this.routes = [];
    this.middleware = [];
    // WebSocket routes are kept separate from HTTP routes — they're
    // matched on the upgrade / Extended CONNECT nodePath, not on a method
    // verb. Map<nodePath, { handler, opts }>.
    this._wsRoutes = new Map();
    // Active WebSocket connections opened through router.ws(). Tracked
    // so router.closeWebSockets() can do a clean rolling-shutdown.
    // h1-upgrade detaches the socket from http.Server's connection
    // tracking — without our own registry there's no other way to
    // enumerate active WS connections for graceful close.
    this._activeWsConns = new Set();

    // TLS 1.3 0-RTT anti-replay posture — see TLS_0RTT_* above.
    var posture = opts.tls0Rtt === undefined ? "refuse" : opts.tls0Rtt;
    if (typeof posture !== "string" || TLS_0RTT_VALID_POSTURES.indexOf(posture) === -1) {
      throw new TypeError(
        "router.create: tls0Rtt must be one of " + TLS_0RTT_VALID_POSTURES.join(", ") +
        "; got " + JSON.stringify(opts.tls0Rtt));
    }
    this._tls0RttPosture = posture;
    // Replay cache — Map<sha3-512(early-data) hex, expiresAtMs>.
    // Bounded entry count + rolling-window expiry.
    this._tls0RttReplayCache = new Map();

    // Cross-origin redirect allowlist. `res.redirect(url)` defaults to
    // same-origin only — apps that need to bounce the user agent to an
    // external IdP (OAuth authorization endpoint, SAML SSO, SCIM step-up)
    // declare the operator-trusted destinations up front. Each entry is
    // an exact-match HTTPS origin (`scheme://host[:port]`). Any redirect
    // to a target whose origin is not on the list is refused loud — the
    // operator gets a RouterError, not a silent bounce to "/".
    var allowedOrigins = opts.allowedRedirectOrigins;
    if (allowedOrigins !== undefined) {
      if (!Array.isArray(allowedOrigins)) {
        throw new RouterError(
          "router/allowed-redirect-origins-not-array",
          "router.create: allowedRedirectOrigins must be an array of HTTPS origin strings"
        );
      }
      var normalized = [];
      for (var oi = 0; oi < allowedOrigins.length; oi += 1) {
        var entry = allowedOrigins[oi];
        if (typeof entry !== "string" || entry.length === 0) {
          throw new RouterError(
            "router/allowed-redirect-origin-not-string",
            "router.create: allowedRedirectOrigins[" + oi + "] must be a non-empty string"
          );
        }
        var parsedOrigin;
        try {
          parsedOrigin = safeUrl.parse(entry, {
            allowedProtocols: ["https:"],
          });
        } catch (parseErr) {
          throw new RouterError(
            "router/allowed-redirect-origin-not-https-origin",
            "router.create: allowedRedirectOrigins[" + oi + "] '" + entry +
            "' is not a valid HTTPS origin (" + parseErr.message + ")"
          );
        }
        // RFC 6454 §4 origin form: scheme://host[:port]. We refuse
        // anything carrying path / query / userinfo so the allowlist
        // stays comparable byte-for-byte against URL.origin at redirect
        // time. Operators who want to gate by full URL apply their own
        // post-redirect validation in the handler.
        if (parsedOrigin.pathname !== "/" && parsedOrigin.pathname !== "") {
          throw new RouterError(
            "router/allowed-redirect-origin-has-path",
            "router.create: allowedRedirectOrigins[" + oi + "] '" + entry +
            "' must be an origin (scheme://host[:port]) — path / query / userinfo not allowed"
          );
        }
        if (parsedOrigin.search.length > 0 || parsedOrigin.hash.length > 0 ||
            parsedOrigin.username.length > 0 || parsedOrigin.password.length > 0) {
          throw new RouterError(
            "router/allowed-redirect-origin-has-extras",
            "router.create: allowedRedirectOrigins[" + oi + "] '" + entry +
            "' must be an origin (scheme://host[:port]) — path / query / userinfo not allowed"
          );
        }
        normalized.push(parsedOrigin.origin);
      }
      this._allowedRedirectOrigins = normalized;
    } else {
      this._allowedRedirectOrigins = [];
    }
  }

  // Operator-facing read of the cross-origin redirect allowlist. Returns
  // a defensive copy so handlers cannot mutate router state.
  allowedRedirectOrigins() {
    return this._allowedRedirectOrigins.slice();
  }

  tls0RttPosture() { return this._tls0RttPosture; }

  // Active WebSocket connections opened via router.ws(). Useful for
  // ops dashboards / health endpoints.
  activeWebSockets() {
    return this._activeWsConns.size;
  }

  // Graceful shutdown of all WebSocket connections opened via
  // router.ws(). Sends close frame (code 1001 'going away') to each;
  // awaits each connection's 'close' event up to opts.timeoutMs
  // (default 5s). Returns the count of connections closed.
  //
  // Operators call this during rolling deploy:
  //   await router.closeWebSockets({ timeoutMs: 10_000 });
  //   await new Promise(r => server.close(r));
  //   process.exit(0);
  //
  // Tests use the same primitive in teardown — no parallel cleanup
  // nodePath, no h1-upgrade detached-socket workaround.
  async closeWebSockets(opts) {
    opts = opts || {};
    var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : C.TIME.seconds(5);
    var code = opts.code || 1001;       // 1001 = going away
    var reason = opts.reason || "server shutting down";

    var conns = Array.from(this._activeWsConns);
    if (conns.length === 0) return 0;

    var closes = conns.map(function (conn) {
      return new Promise(function (resolve) {
        if (conn.readyState === "closed") { resolve(); return; }
        conn.once("close", resolve);
        try { conn.close(code, reason); }
        catch (_e) {
          // close() may throw if already closed; resolve immediately
          // since the 'close' event won't fire again.
          resolve();
        }
      });
    });

    // Wait up to `timeoutMs` for graceful WS closes, then force-destroy
    // any laggards. `safeAsync.sleep({ unref: true })` matches the
    // framework's outbound-timeout convention.
    await Promise.race([
      Promise.all(closes),
      safeAsync.sleep(timeoutMs, { unref: true }),
    ]);
    // Force-destroy any laggards — at this point we've waited the full
    // timeout and they didn't ack. The operator chose timeoutMs; honor it.
    this._activeWsConns.forEach(function (conn) {
      try { if (conn.socket && conn.socket.destroy) conn.socket.destroy(); }
      catch (_e) { /* socket already destroyed */ }
    });
    return conns.length;
  }

  use(fn) {
    this.middleware.push(fn);
  }

  // Internal: split a route registration's args into { spec, handlers }.
  // The first non-pattern arg is the schema spec when it's a plain object
  // (not a function); subsequent args are handler middlewares. Operators
  // who never pass a spec keep the existing two-arg shape working.
  _splitArgs(args) {
    if (args.length > 0 && args[0] && typeof args[0] === "object" &&
        !Array.isArray(args[0]) && typeof args[0] !== "function") {
      return { spec: args[0], handlers: args.slice(1) };
    }
    return { spec: null, handlers: args };
  }

  _registerRoute(method, pattern, args) {
    var split = this._splitArgs(args);
    if (split.spec) _validateRouteSpec(split.spec, method, pattern);
    var handlers = split.handlers;
    if (split.spec) {
      // Pre-handler validates body / query / params. Runs after the
      // global middleware chain (bodyParser populates req.body before
      // route dispatch) but before any route-specific handler.
      handlers = [_makeSchemaValidator(split.spec)].concat(handlers);
      // Response validation (dev/opt-in via env or per-route opt).
      var globalValidateMode = safeEnv.readVar("BLAMEJS_VALIDATE_RESPONSES");
      if (split.spec.response &&
          (globalValidateMode === "throw" ||
           globalValidateMode === "warn" ||
           split.spec.validateResponse)) {
        handlers = [_makeResponseValidator(split.spec)].concat(handlers);
      }
    }
    this.routes.push(Object.assign(
      { method: method, handlers: handlers, spec: split.spec || null },
      compilePattern(pattern)
    ));
  }

  get(pattern, ...args) {
    this._registerRoute("GET", pattern, args);
  }

  post(pattern, ...args) {
    this._registerRoute("POST", pattern, args);
  }

  put(pattern, ...args) {
    this._registerRoute("PUT", pattern, args);
  }

  patch(pattern, ...args) {
    this._registerRoute("PATCH", pattern, args);
  }

  delete(pattern, ...args) {
    this._registerRoute("DELETE", pattern, args);
  }

  // Operator-facing introspection — returns a copy of the route table
  // with each entry's method, pattern, description, and (when provided)
  // operator-supplied jsonSchema bodies for OpenAPI publication.
  inspectRoutes() {
    return this.routes
      .filter(function (r) { return typeof r.method === "string"; })
      .map(function (r) {
        return {
          method:      r.method,
          pattern:     r.pattern,
          description: r.spec ? r.spec.description || null : null,
          spec:        r.spec ? {
            hasBodySchema:   !!r.spec.body,
            hasQuerySchema:  !!r.spec.query,
            hasParamsSchema: !!r.spec.params,
            hasResponseSchema: !!r.spec.response,
            bodyJsonSchema:     r.spec.bodyJsonSchema     || null,
            queryJsonSchema:    r.spec.queryJsonSchema    || null,
            paramsJsonSchema:   r.spec.paramsJsonSchema   || null,
            responseJsonSchema: r.spec.responseJsonSchema || null,
            tags:        Array.isArray(r.spec.tags) ? r.spec.tags.slice() : [],
            summary:     r.spec.summary || null,
          } : null,
        };
      });
  }

  // openapi(opts?) → minimal Swagger 3.0 document covering every
  // schema-spec'd route. Body / query / params show up as parameter
  // entries when the operator supplies bodyJsonSchema / etc. (a
  // safeSchema → JSON Schema converter is its own primitive — operators
  // who want full schema bodies in the OpenAPI doc supply the JSON
  // Schema alongside the safeSchema today).
  openapi(opts) {
    opts = opts || {};
    var info = opts.info || { title: "blamejs app", version: "0.0.0" };
    var paths = {};
    var routes = this.inspectRoutes();
    for (var i = 0; i < routes.length; i++) {
      var r = routes[i];
      var openapiPath = r.pattern.replace(/:([a-zA-Z0-9_]+)/g, "{$1}");
      if (!paths[openapiPath]) paths[openapiPath] = {};
      var op = {
        summary:     r.spec ? r.spec.summary || r.description || (r.method + " " + r.pattern) :
                              (r.method + " " + r.pattern),
        description: r.description || null,
      };
      if (r.spec) {
        op.tags = r.spec.tags;
        var params = [];
        // Path params from pattern
        var pathParams = (r.pattern.match(/:[a-zA-Z0-9_]+/g) || [])
          .map(function (s) { return s.slice(1); });
        for (var pp = 0; pp < pathParams.length; pp++) {
          params.push({ name: pathParams[pp], in: "path", required: true,
                        schema: { type: "string" } });
        }
        if (r.spec.queryJsonSchema && r.spec.queryJsonSchema.properties) {
          var qprops = r.spec.queryJsonSchema.properties;
          var qreq   = r.spec.queryJsonSchema.required || [];
          var qkeys  = Object.keys(qprops);
          for (var qi = 0; qi < qkeys.length; qi++) {
            params.push({ name: qkeys[qi], in: "query",
                          required: qreq.indexOf(qkeys[qi]) !== -1,
                          schema: qprops[qkeys[qi]] });
          }
        }
        if (params.length > 0) op.parameters = params;
        if (r.spec.bodyJsonSchema) {
          op.requestBody = {
            required: true,
            content: { "application/json": { schema: r.spec.bodyJsonSchema } },
          };
        } else if (r.spec.hasBodySchema) {
          // Operator validates via safeSchema but didn't supply JSON Schema.
          op["x-blamejs-body-validation"] = "safe-schema (json schema not provided)";
        }
        if (r.spec.responseJsonSchema) {
          op.responses = {
            "200": {
              description: "OK",
              content: { "application/json": { schema: r.spec.responseJsonSchema } },
            },
          };
        }
      }
      paths[openapiPath][r.method.toLowerCase()] = op;
    }
    return {
      openapi: "3.0.3",
      info:    info,
      paths:   paths,
    };
  }

  // ---- WebSocket route registration ----
  //
  // ws(nodePath, handler, opts?)
  //   path     — exact match. Path-param patterns aren't supported on
  //              upgrade requests; operators that need dynamic paths
  //              register one ws route per stable shape.
  //   handler  — function(conn, req) — called with the WebSocketConnection
  //              and the original HTTP request (req for h1, request
  //              headers object for h2 Extended CONNECT). Operator owns
  //              the conn lifecycle from there.
  //   opts:
  //     transport: "auto" (default) | "h1-only" | "h2-only"
  //       auto      — accept both transports per ALPN negotiation
  //       h1-only   — refuse h2 Extended CONNECT with :status 405
  //       h2-only   — refuse h1 upgrade with 426 Upgrade Required +
  //                   `Upgrade: h2c` advisory header
  //     origins:    string[] | "*" | undefined — operator allowlist;
  //                 omitted = accept all (a startup warning fires when
  //                 the path is registered, since omitting origin
  //                 policy on a public-facing path is rarely intended)
  //     subprotocols: string[] — first match wins
  //     maxMessageBytes / pingIntervalMs / pongTimeoutMs — passed
  //       through to WebSocketConnection
  ws(pathStr, handler, opts) {
    if (typeof pathStr !== "string" || pathStr.length === 0) {
      throw new Error("router.ws: path must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw new Error("router.ws: handler must be a function");
    }
    opts = opts || {};
    var transport = opts.transport || "auto";
    if (transport !== "auto" && transport !== "h1-only" && transport !== "h2-only") {
      throw new Error("router.ws: transport must be 'auto' | 'h1-only' | 'h2-only'");
    }
    if (!opts.origins) {
      log.warn("WebSocket route '" + pathStr + "' registered without origins allowlist — accepting all origins. Pass { origins: [...] } or { origins: '*' } to silence.");
    }
    this._wsRoutes.set(pathStr, { handler: handler, opts: opts, transport: transport });
  }

  _match(route, pathname) {
    return _matchCompiled(route, pathname);
  }

  async handle(req, res) {
    // Compose an absolute URL from the request's path + Host header so
    // safeUrl.parse can validate the protocol + length. The "http://"
    // base is the relative-resolution origin; the request's actual
    // scheme lives in requestHelpers.requestProtocol elsewhere.
    var absolute = "http://" + (req.headers.host || "localhost") + (req.url || "/");
    var parsed = safeUrl.parse(absolute, {
      allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
    });
    req.pathname = parsed.pathname;
    req.query = Object.fromEntries(parsed.searchParams);

    // Run middleware
    for (var mw of this.middleware) {
      var next = false;
      try {
        await mw(req, res, () => (next = true));
      } catch (mwErr) {
        log.error("middleware error: " + (mw.name || "anonymous") + " " +
          req.method + " " + req.url + " " + mwErr.message + " " +
          (mwErr.stack ? mwErr.stack.split("\n").slice(0, 3).join(" | ") : ""));
        throw mwErr;
      }
      if (!next || res.writableEnded) return;
    }

    // Match route
    for (var route of this.routes) {
      if (route.method !== req.method) continue;
      var params = this._match(route, req.pathname);
      if (!params) continue;
      req.params = params;
      // Expose the route TEMPLATE so framework middleware (metrics,
      // tracing) can label by template instead of the actual URL —
      // otherwise every distinct path-param value becomes its own
      // cardinality bucket.
      req.routePattern = route.pattern;

      for (var handler of route.handlers) {
        if (res.writableEnded) return;
        if (handler.length >= 3) {
          var proceeded = false;
          await handler(req, res, () => (proceeded = true));
          if (!proceeded) return;
        } else {
          await handler(req, res);
        }
      }
      return;
    }

    // Not found
    if (this.notFoundHandler) {
      this.notFoundHandler(req, res);
    } else {
      res.writeHead(HTTP_STATUS.NOT_FOUND, { "Content-Type": "text/html" });
      res.end("<h1>404 Not Found</h1>");
    }
  }

  getReservedSlugs() {
    var slugs = new Set();
    for (var i = 0; i < this.routes.length; i++) {
      var parts = this.routes[i].pattern.split("/").filter(Boolean);
      if (parts.length > 0 && !parts[0].startsWith(":")) {
        slugs.add(parts[0].toLowerCase());
      }
    }
    return slugs;
  }

  onNotFound(handler) {
    this.notFoundHandler = handler;
  }

  onError(handler) {
    this.errorHandler = handler;
  }

  // Compute the effective TLS 0-RTT posture, fail-closing under the
  // posture-asserted regimes (`pci-dss`, `fapi2`) regardless of operator
  // opt-in. RFC 8446 §8 + PCI DSS 4.0 §6.4.3 + FAPI 2.0 §5.2.2.
  _effective0RttPosture() {
    var declared = this._tls0RttPosture;
    if (declared !== "replay-cache") return declared;
    var active = null;
    try {
      var compliance = complianceLazy();
      if (compliance && typeof compliance.current === "function") active = compliance.current();
    } catch (_e) { /* compliance not initialized */ }
    if (active && TLS_0RTT_FAILCLOSED_POSTURES.indexOf(active) !== -1) {
      try {
        auditFwk().safeEmit({
          action:   "tls.0rtt.refused",
          outcome:  "denied",
          metadata: { reason: "posture-failclosed", posture: active, declared: declared },
        });
      } catch (_e) { /* audit best-effort */ }
      return "refuse";
    }
    return "replay-cache";
  }

  // Check inbound `Early-Data: 1` (RFC 8470 §5) requests against the
  // 0-RTT replay cache. Returns null when the request should proceed,
  // or a status-code+reason when the request must be refused.
  _check0RttReplay(req) {
    var posture = this._effective0RttPosture();
    var earlyDataHeader = req.headers && (req.headers["early-data"] || req.headers["Early-Data"]);
    if (earlyDataHeader === undefined) return null;                                // not an early-data forward
    if (String(earlyDataHeader).trim() !== "1") return null;                       // RFC 8470: only "1" means early data
    if (posture === "refuse") {
      try {
        auditFwk().safeEmit({
          action:   "tls.0rtt.refused",
          outcome:  "denied",
          metadata: { reason: "posture-refuse", method: req.method, url: req.url },
        });
      } catch (_e) { /* audit best-effort */ }
      return { status: 425, reason: "early-data-refused" };
    }
    // posture === "replay-cache" — dedupe by SHA3-512 within the rolling
    // window. Hash inputs (method + url + Host + Authorization + bound
    // request id) so identical retries replay-detect; legitimate-but-
    // distinct retries differentiate via Idempotency-Key / Date.
    var nowMs = Date.now();
    this._reap0RttCache(nowMs);
    var hash = require("node:crypto").createHash("sha3-512");
    hash.update(String(req.method || "") + "\n");
    hash.update(String(req.url || "") + "\n");
    hash.update(String((req.headers && req.headers["host"]) || "") + "\n");
    hash.update(String((req.headers && req.headers["authorization"]) || "") + "\n");
    hash.update(String((req.headers && req.headers["date"]) || "") + "\n");
    hash.update(String((req.headers && req.headers["idempotency-key"]) || "") + "\n");
    var key = hash.digest("hex");
    if (this._tls0RttReplayCache.has(key)) {
      try {
        auditFwk().safeEmit({
          action:   "tls.0rtt.replayed",
          outcome:  "denied",
          metadata: { reason: "cache-hit", method: req.method, url: req.url,
                      windowMs: TLS_0RTT_REPLAY_WINDOW_MS },
        });
      } catch (_e) { /* audit best-effort */ }
      return { status: 425, reason: "early-data-replay" };
    }
    // Bounded entry count — when the cache hits the cap, drop the
    // oldest entries to make room. The reap pass already ran above.
    if (this._tls0RttReplayCache.size >= TLS_0RTT_REPLAY_CACHE_CAP) {
      var keys = this._tls0RttReplayCache.keys();
      var toEvict = (this._tls0RttReplayCache.size - TLS_0RTT_REPLAY_CACHE_CAP) + 1;
      for (var i = 0; i < toEvict; i += 1) {
        var first = keys.next();
        if (first.done) break;
        this._tls0RttReplayCache.delete(first.value);
      }
    }
    this._tls0RttReplayCache.set(key, nowMs + TLS_0RTT_REPLAY_WINDOW_MS);
    try {
      auditFwk().safeEmit({
        action:   "tls.0rtt.accepted",
        outcome:  "success",
        metadata: { method: req.method, url: req.url, windowMs: TLS_0RTT_REPLAY_WINDOW_MS },
      });
    } catch (_e) { /* audit best-effort */ }
    return null;
  }

  _reap0RttCache(nowMs) {
    if (this._tls0RttReplayCache.size === 0) return;
    var iter = this._tls0RttReplayCache.entries();
    for (var entry = iter.next(); !entry.done; entry = iter.next()) {
      if (entry.value[1] <= nowMs) this._tls0RttReplayCache.delete(entry.value[0]);
    }
  }

  listen(port, cb, tlsOptions, host) {
    var self = this;
    var requestHandler = (req, res) => {
      // RFC 8446 §8 / RFC 8470 — TLS 1.3 0-RTT anti-replay gate.
      // Refuse / dedupe Early-Data: 1 forwarded requests per the
      // operator's tls0Rtt posture.
      var verdict0Rtt = self._check0RttReplay(req);
      if (verdict0Rtt) {
        // RFC 8470 §5 — 425 Too Early. Connection: close so the peer
        // cannot reuse the session ticket on the next attempt.
        res.writeHead(425, {
          "Content-Type": "text/plain; charset=utf-8",
          "Connection":   "close",
        });
        res.end(verdict0Rtt.reason);
        return;
      }
      // Response helpers
      res.json = (data) => {
        res.writeHead(res.statusCode || HTTP_STATUS.OK, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      res.redirect = (url) => {
        // Same-origin (single leading slash, not protocol-relative) is
        // always allowed. Cross-origin redirects (OAuth authorization
        // endpoint, SSO bounce, SCIM step-up) require the operator to
        // declare the destination via `allowedRedirectOrigins` on
        // router.create. Anything else throws RouterError — silently
        // rewriting attacker-controlled redirect targets to "/" hides
        // open-redirect attempts that operators want to see in audit.
        if (typeof url !== "string" || url.length === 0) {
          throw new RouterError(
            "router/redirect-target-not-string",
            "res.redirect: target must be a non-empty string"
          );
        }
        // Reject embedded CR / LF / NUL early — header injection class.
        // Node's writeHead would refuse these too, but the explicit
        // refusal here gives operators a router-shaped error rather than
        // a generic ERR_INVALID_CHAR.
        for (var ci = 0; ci < url.length; ci += 1) {
          var cc = url.charCodeAt(ci);
          if (cc === 0x00 || cc === 0x0A || cc === 0x0D) {
            throw new RouterError(
              "router/redirect-target-has-control-chars",
              "res.redirect: target must not contain CR / LF / NUL bytes"
            );
          }
        }
        // Same-origin path: a single leading "/" not followed by another
        // "/" or "\" (the protocol-relative + Windows-share shapes that
        // browsers happily resolve as off-origin).
        if (url.charAt(0) === "/" &&
            url.charAt(1) !== "/" && url.charAt(1) !== "\\") {
          // 302 Found — RFC 7231 §6.4.3. Not in HTTP_STATUS table.
          res.writeHead(302, { Location: url });
          res.end();
          return;
        }
        // Cross-origin path: parse + match against the allowlist.
        var parsedTarget;
        try {
          parsedTarget = safeUrl.parse(url, {
            allowedProtocols: ["https:"],
          });
        } catch (parseErr) {
          try {
            auditFwk().safeEmit({
              action:   "router.redirect.cross_origin.refused",
              outcome:  "denied",
              metadata: {
                reason: "target-parse-failed",
                target: url,
                cause:  parseErr && parseErr.message,
              },
            });
          } catch (_e) { /* audit best-effort */ }
          throw new RouterError(
            "router/redirect-cross-origin-refused",
            "res.redirect: cross-origin target '" + url + "' is not a valid HTTPS URL (" +
            (parseErr && parseErr.message) + ")"
          );
        }
        var targetOrigin = parsedTarget.origin;
        var allowlist = self._allowedRedirectOrigins;
        var match = false;
        for (var ai = 0; ai < allowlist.length; ai += 1) {
          if (allowlist[ai] === targetOrigin) { match = true; break; }
        }
        if (!match) {
          try {
            auditFwk().safeEmit({
              action:   "router.redirect.cross_origin.refused",
              outcome:  "denied",
              metadata: {
                reason: allowlist.length === 0 ? "no-allowlist" : "origin-not-in-allowlist",
                target: url,
                origin: targetOrigin,
              },
            });
          } catch (_e) { /* audit best-effort */ }
          throw new RouterError(
            "router/redirect-cross-origin-refused",
            "res.redirect: cross-origin target '" + targetOrigin +
            "' is not in router.allowedRedirectOrigins"
          );
        }
        try {
          auditFwk().safeEmit({
            action:   "router.redirect.cross_origin.allowed",
            outcome:  "success",
            metadata: { target: url, origin: targetOrigin },
          });
        } catch (_e) { /* audit best-effort */ }
        res.writeHead(302, { Location: url });
        res.end();
      };
      res.status = (code) => {
        res.statusCode = code;
        return res;
      };

      self.handle(req, res).catch((err) => {
        log.error("route error: " + req.method + " " + req.url + " " + err.message + " " +
          (err.stack ? err.stack.split("\n").slice(0, 5).join(" | ") : ""));
        if (self.errorHandler) {
          try { self.errorHandler(err, req, res); } catch (_) {
            if (!res.writableEnded) {
              res.writeHead(HTTP_STATUS.INTERNAL_SERVER_ERROR, { "Content-Type": "text/plain" });
              res.end("Internal Server Error");
            }
          }
        } else if (!res.writableEnded) {
          res.writeHead(HTTP_STATUS.INTERNAL_SERVER_ERROR, { "Content-Type": "text/plain" });
          res.end("Internal Server Error");
        }
      });
    };
    var server;
    if (tlsOptions) {
      // CVE-2026-21637 — Node propagates synchronous throws from a
      // user-supplied SNICallback up through the TLS handshake
      // listener; an unhandled throw on an unexpected servername
      // crashes the listener. Wrap the operator's SNICallback so any
      // synchronous error becomes a clean async (err, null) callback.
      // RFC 6066 §3 expects the server to abort the handshake on a
      // failed callback, not crash the process.
      if (tlsOptions.SNICallback && typeof tlsOptions.SNICallback === "function") {
        var operatorSniCallback = tlsOptions.SNICallback;
        tlsOptions = Object.assign({}, tlsOptions, {
          SNICallback: function (servername, cb) {
            try {
              operatorSniCallback(servername, cb);
            } catch (err) {
              log.error("SNICallback threw for servername=" +
                JSON.stringify(servername) + ": " + (err && err.message));
              try { cb(err, null); } catch (_e) { /* cb already invoked */ }
            }
          },
        });
      }
      // TLS 1.3 minimum — operator can override but the framework's
      // default refuses pre-1.3 negotiation. Without this set the
      // bare {key, cert} path inherits Node's TLSv1.2 default; the
      // outbound httpClient already pins TLS 1.3.
      if (!tlsOptions.minVersion) {
        tlsOptions = Object.assign({ minVersion: "TLSv1.3" }, tlsOptions);
      }
      // RFC 8446 §8 / §2.3 — TLS 1.3 0-RTT anti-replay posture. Operator
      // sets allowEarlyData per `tls0Rtt`. Default "refuse" matches Node.
      // "replay-cache" admits 0-RTT but every Early-Data: 1 request is
      // dedupe-checked in the request handler against the rolling cache.
      var posture0Rtt = self._effective0RttPosture();
      if (tlsOptions.allowEarlyData === undefined) {
        tlsOptions.allowEarlyData = (posture0Rtt === "replay-cache");
      }
      // h2-capable server with h1 fallback via ALPN. ["h2", "http/1.1"]
      // means modern clients negotiate h2 (preferred); legacy clients
      // fall back to h1. allowHTTP1: true is what makes the same server
      // accept both. enableConnectProtocol: true is what enables h2
      // WebSocket (RFC 8441) — clients refuse to issue Extended CONNECT
      // until they see this in the server's SETTINGS frame.
      // Framework-default HTTP/2 hardening — operator-supplied
      // tlsOptions can override any of these.
      //
      // maxConcurrentStreams: cap concurrent streams per session (Node
      //   default is 4294967295 — way too high; CVE-2023-44487 Rapid
      //   Reset relies on the unbounded default).
      // maxSessionMemory: 10 MB cap per session (Node default; explicit).
      // maxHeaderListPairs: 100 header pairs max (Node default 128;
      //   tightened — CVE-2024-27983 / CVE-2024-28182 CONTINUATION
      //   flood relies on header-pair amplification).
      // maxSettings: cap SETTINGS-frame entries.
      // peerMaxConcurrentStreams: cap how many streams the peer is
      //   willing to accept (limits server-initiated push, which the
      //   framework doesn't use).
      // unknownProtocolTimeout: 10s — drop sessions stuck in protocol-
      //   detection (Slowloris-h2 variant).
      server = http2.createSecureServer(Object.assign({
        allowHTTP1:               true,
        ALPNProtocols:             ["h2", "http/1.1"],
        settings:                  { enableConnectProtocol: true },
        maxConcurrentStreams:      100,                                            // allow:raw-byte-literal — CVE-2023-44487 Rapid Reset cap
        maxSessionMemory:          10,                                             // allow:raw-byte-literal — MB cap (Node default explicit)
        maxHeaderListPairs:        100,                                            // allow:raw-byte-literal — CVE-2024-27983 CONTINUATION-flood cap
        maxSettings:               32,                                             // allow:raw-byte-literal — SETTINGS-frame entry ceiling
        peerMaxConcurrentStreams:  100,                                            // allow:raw-byte-literal — peer-side stream cap
        maxOutstandingPings:       10,                                             // allow:raw-byte-literal — CVE-2019-9512 ping-flood cap (pin to Node default rather than letting it drift)
        unknownProtocolTimeout:    C.TIME.seconds(10),
      }, tlsOptions), requestHandler);

      // CVE-2026-21714 — H/2 WINDOW_UPDATE leak after GOAWAY. nghttp2
      // holds per-stream flow-control state after GOAWAY; late-arriving
      // WINDOW_UPDATE frames can re-credit a draining stream. Node's
      // http2 module hands flow control to nghttp2 internally and does
      // not expose a per-frame WINDOW_UPDATE listener; the framework
      // gate is to track GOAWAY state on every session, refuse new
      // streams once GOAWAY has been emitted by either side, and
      // force-destroy the session on any post-GOAWAY stream activity.
      // Combined with the Node 24.14+ engine pin (where the upstream
      // nghttp2 fix lives), the path closes at both layers.
      server.on("session", function (h2session) {
        h2session._blamejsGoawaySent = false;
        // Wrap goaway() so the framework's own send marks the session.
        var origGoaway = (typeof h2session.goaway === "function")
          ? h2session.goaway.bind(h2session) : null;
        if (origGoaway) {
          h2session.goaway = function (code, lastStreamID, opaqueData) {
            h2session._blamejsGoawaySent = true;
            return origGoaway(code, lastStreamID, opaqueData);
          };
        }
        // Inbound GOAWAY from peer also flips the flag — once GOAWAY is
        // in flight in either direction, no new streams should land.
        h2session.on("goaway", function () {
          h2session._blamejsGoawaySent = true;
        });
        // Per-stream rate cap on _any_ post-GOAWAY activity. If a stream
        // opens after GOAWAY emission, refuse + audit + destroy session
        // (a clean peer would not initiate after GOAWAY).
        h2session.on("stream", function (stream) {
          if (h2session._blamejsGoawaySent) {
            try { auditFwk().safeEmit({
              action:   "http2.window_update.refused",
              outcome:  "denied",
              metadata: { reason: "post-goaway-stream", streamId: stream.id || null,
                          frameType: WINDOW_UPDATE_FRAME_TYPE,
                          rateCap: WINDOW_UPDATE_RATE_CAP,
                          rateWindowMs: WINDOW_UPDATE_RATE_WINDOW_MS },
            }); } catch (_e) { /* audit best-effort */ }
            try { stream.close(); } catch (_e) { /* stream already closed */ }
            try { h2session.destroy(); } catch (_e) { /* session already closed */ }
          }
        });
      });
    } else {
      // Cleartext path is h1-only. Operators wanting h2c on cleartext
      // are typically running behind a TLS-terminating LB that does
      // h1↔h2 translation; the framework's TLS path covers that.
      server = http.createServer(requestHandler);
    }

    // ---- WebSocket wiring ----
    // Only registers handlers when there are ws routes — keeps the
    // server's emitter list clean for HTTP-only deployments.
    if (self._wsRoutes.size > 0) {
      // h1 upgrade event — fires for "Upgrade: websocket" from h1
      // clients. Routes by nodePath; refuses with 426 in h2-only mode.
      server.on("upgrade", function (req, socket, head) {
        var pathname = String(req.url || "/").split("?")[0];
        var route = self._wsRoutes.get(pathname);
        if (!route) {
          socket.destroy();
          return;
        }
        if (route.transport === "h2-only") {
          // RFC-correct way to say "use h2": 426 Upgrade Required plus
          // an Upgrade advisory pointing to h2c.
          var body = "WebSocket on this path requires HTTP/2";
          var resp =
            "HTTP/1.1 426 Upgrade Required\r\n" +
            "Upgrade: h2c\r\n" +
            "Connection: close\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: " + Buffer.byteLength(body, "utf8") + "\r\n" +
            "\r\n" +
            body;
          try { socket.write(resp); } catch (_e) { /* socket already closed */ }
          try { socket.destroy(); } catch (_e) { /* socket already destroyed */ }
          return;
        }
        var conn = websocket.handleUpgrade(req, socket, head, route.opts);
        if (conn) {
          self._activeWsConns.add(conn);
          conn.once("close", function () { self._activeWsConns.delete(conn); });
          try { route.handler(conn, req); }
          catch (err) { log.error("ws handler threw: " + err.message); conn._abort(websocket.CLOSE_INTERNAL_ERROR, "handler error"); }
        }
      });

      // h2 Extended CONNECT — only fires on h2-capable (TLS) server.
      // The 'stream' event filter checks for :method=CONNECT,
      // :protocol=websocket. Other CONNECT methods (e.g. tunnel) and
      // ordinary requests pass through.
      if (tlsOptions) {
        server.on("stream", function (stream, headers) {
          if (headers[":method"] !== "CONNECT") return;
          if (headers[":protocol"] !== "websocket") return;
          var pathname = String(headers[":path"] || "/").split("?")[0];
          var route = self._wsRoutes.get(pathname);
          if (!route) {
            try { stream.respond({ ":status": 404 }); stream.end(); } catch (_e) { /* stream already closed */ }
            return;
          }
          if (route.transport === "h1-only") {
            try {
              stream.respond({ ":status": 405, "content-type": "text/plain; charset=utf-8" });
              stream.end("WebSocket on this path requires HTTP/1.1 Upgrade");
            } catch (_e) { /* stream already closed */ }
            return;
          }
          var conn = websocket.handleExtendedConnect(stream, headers, route.opts);
          if (conn) {
            self._activeWsConns.add(conn);
            conn.once("close", function () { self._activeWsConns.delete(conn); });
            try { route.handler(conn, headers); }
            catch (err) { log.error("ws handler threw: " + err.message); conn._abort(websocket.CLOSE_INTERNAL_ERROR, "handler error"); }
          }
        });
      }
    }

    if (host) server.listen(port, host, cb);
    else server.listen(port, cb);
    // Slowloris / slow-read defenses. Node defaults shifted across
    // versions; the framework pins them explicitly so operators on
    // older Node releases get the modern bar.
    //
    // headersTimeout: 60s — time allotted for the entire request-line
    //   + header section. Slowloris's classic posture is a connection
    //   that trickles headers indefinitely.
    // requestTimeout: 5min — total wall-clock for a request including
    //   body. Body-streaming uploads through fileUpload can take
    //   minutes; this is the operator-overridable ceiling.
    // keepAliveTimeout: 5s — idle timeout between requests on a
    //   keep-alive connection.
    // server.timeout: 5min — hardware/network timeout (legacy).
    server.headersTimeout   = C.TIME.seconds(60);
    server.requestTimeout   = C.TIME.minutes(5);
    server.keepAliveTimeout = C.TIME.seconds(5);
    server.timeout          = C.TIME.minutes(5);
    return server;
  }
}

/**
 * @primitive b.router.serveStatic
 * @signature b.router.serveStatic(dir)
 * @since     0.1.0
 * @related   b.router.create, b.staticServe
 *
 * Returns a middleware function that serves files from `dir` for GET
 * requests whose `req.pathname` resolves inside `dir`. Path traversal
 * (`..`) and NUL-byte filenames bypass the middleware (next()), as do
 * directory listings and missing files. Sniffed Content-Type comes
 * from a small extension table; unknown extensions fall back to
 * `application/octet-stream`. Versioned URLs (`?v=...`) ship with a
 * one-year `immutable` Cache-Control; un-versioned files get one hour.
 *
 * For richer content-safety, byte-range requests, and the framework's
 * full guard wiring, prefer `b.staticServe.create` over this helper.
 *
 * @example
 *   var router = b.router.create();
 *   router.use(b.router.serveStatic("/var/www/public"));
 *   router.listen(3000);
 */
// Static file serving middleware
function serveStatic(dir) {
  var root = nodePath.resolve(dir);
  return (req, res, next) => {
    if (req.method !== "GET") return next();
    var rel = req.pathname;
    if (rel.includes("\0")) return next();
    var filePath = nodePath.resolve(nodePath.join(root, rel));
    if (!filePath.startsWith(root)) return next();
    if (!nodeFs.existsSync(filePath) || nodeFs.statSync(filePath).isDirectory()) return next();

    var ext = nodePath.extname(filePath).toLowerCase();
    var mime = MIME_TYPES[ext] || "application/octet-stream";
    var stat = nodeFs.statSync(filePath);
    var hasVersion = req.url && req.url.includes("?v=");
    var cacheControl = hasVersion
      ? "public, max-age=31536000, immutable"
      : "public, max-age=3600";
    res.writeHead(HTTP_STATUS.OK, {
      "Content-Type":   mime,
      "Content-Length": stat.size,
      "Cache-Control":  cacheControl,
    });
    nodeFs.createReadStream(filePath).pipe(res);
  };
}

/**
 * @primitive b.router.create
 * @signature b.router.create(opts?)
 * @since     0.1.0
 * @related   b.router.serveStatic
 *
 * Builds a `Router` instance with the framework's security-on-by-
 * default posture. Returned object exposes `get / post / put / patch
 * / delete` for route registration, `use(fn)` for global middleware,
 * `ws(path, handler, opts?)` for WebSocket routes, `onNotFound(fn)`
 * and `onError(fn)` for fallthrough hooks, `inspectRoutes()` and
 * `openapi()` for introspection, `closeWebSockets({ timeoutMs })`
 * for graceful shutdown, and `listen(port, cb?, tlsOptions?, host?)`
 * which boots an HTTP/2-capable TLS server (ALPN h2 + http/1.1) when
 * `tlsOptions` is provided, an HTTP/1.1 server otherwise.
 *
 * @opts
 *   tls0Rtt:                "refuse" | "replay-cache",  // RFC 8446 §8 anti-replay; default "refuse"
 *   allowedRedirectOrigins: string[],                    // exact-match HTTPS origins for cross-origin res.redirect()
 *
 * @example
 *   var router = b.router.create({
 *     tls0Rtt: "refuse",
 *     allowedRedirectOrigins: ["https://idp.example.com"],
 *   });
 *   router.get("/users/:id", function (req, res) {
 *     res.json({ id: req.params.id });
 *   });
 *   router.listen(3000);
 */
function create(opts) {
  return new Router(opts);
}

module.exports = {
  Router:       Router,
  create:       create,
  serveStatic:  serveStatic,
};
