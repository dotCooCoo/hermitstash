"use strict";
/**
 * Custom HTTP router — zero-dependency replacement for express/koa/fastify.
 *
 * Why rolled-our-own: blamejs principle #1 forbids npm runtime dependencies.
 * This router covers what a route concretely requires (path params,
 * middleware chain, static file serving, MIME sniffing) and leaves no
 * attack surface we haven't read.
 *
 * Middleware / handler dispatch (see roadmap "Naming conventions" — verb
 * conventions section, "on/off/emit" vs explicit chain control):
 *   - handler.length >= 3 → treated as middleware. Chain stops unless the
 *     handler calls next(). Using 2-arg handlers as middleware is
 *     structurally fragile and will silently fall through.
 *   - handler.length <= 2 → terminal handler. Always falls through to the
 *     next entry in the chain if it doesn't end the response.
 *
 * Patterns are compiled ONCE at registration time (compilePattern) — no
 * regex construction on the hot path. Route table is scanned linearly;
 * ordering matters (first match wins).
 */
var http  = require("http");
var http2 = require("http2");
var fs = require("fs");
var path = require("path");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var safeUrl = require("./safe-url");
var websocket = require("./websocket");
var { boot } = require("./log");

var log = boot("router");
var HTTP_STATUS = requestHelpers.HTTP_STATUS;

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

class Router {
  constructor() {
    this.routes = [];
    this.middleware = [];
    // WebSocket routes are kept separate from HTTP routes — they're
    // matched on the upgrade / Extended CONNECT path, not on a method
    // verb. Map<path, { handler, opts }>.
    this._wsRoutes = new Map();
    // Active WebSocket connections opened through router.ws(). Tracked
    // so router.closeWebSockets() can do a clean rolling-shutdown.
    // h1-upgrade detaches the socket from http.Server's connection
    // tracking — without our own registry there's no other way to
    // enumerate active WS connections for graceful close.
    this._activeWsConns = new Set();
  }

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
  // path, no h1-upgrade detached-socket workaround.
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
  // ws(path, handler, opts?)
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

  listen(port, cb, tlsOptions, host) {
    var self = this;
    var requestHandler = (req, res) => {
      // Response helpers
      res.json = (data) => {
        res.writeHead(res.statusCode || HTTP_STATUS.OK, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      res.redirect = (url) => {
        // Same-origin redirects only by default. Apps that need cross-origin
        // redirects (OAuth, SSO) wrap res.redirect with their own allowlist.
        var safe = "/";
        if (typeof url === "string" && url.startsWith("/") && !url.startsWith("//")) {
          safe = url;
        }
        // 302 Found — RFC 7231 §6.4.3. Not in HTTP_STATUS table.
        res.writeHead(302, { Location: safe });
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
        unknownProtocolTimeout:    C.TIME.seconds(10),
      }, tlsOptions), requestHandler);
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
      // clients. Routes by path; refuses with 426 in h2-only mode.
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

// Static file serving middleware
function serveStatic(dir) {
  var root = path.resolve(dir);
  return (req, res, next) => {
    if (req.method !== "GET") return next();
    var rel = req.pathname;
    if (rel.includes("\0")) return next();
    var filePath = path.resolve(path.join(root, rel));
    if (!filePath.startsWith(root)) return next();
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return next();

    var ext = path.extname(filePath).toLowerCase();
    var mime = MIME_TYPES[ext] || "application/octet-stream";
    var stat = fs.statSync(filePath);
    var hasVersion = req.url && req.url.includes("?v=");
    var cacheControl = hasVersion
      ? "public, max-age=31536000, immutable"
      : "public, max-age=3600";
    res.writeHead(HTTP_STATUS.OK, {
      "Content-Type":   mime,
      "Content-Length": stat.size,
      "Cache-Control":  cacheControl,
    });
    fs.createReadStream(filePath).pipe(res);
  };
}

module.exports = {
  Router:       Router,
  serveStatic:  serveStatic,
};
