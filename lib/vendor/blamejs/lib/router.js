// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var http  = require("node:http");
var http2 = require("node:http2");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var safeJson = require("./safe-json");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var websocket = require("./websocket");
var { boot } = require("./log");
var { RouterError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
// compliance — lazy because router.js is required during boot before
// the operator's `b.compliance.set(...)` runs; the posture lookup only
// matters at listen() time, well after boot finishes.
var compliance = lazyRequire(function () { return require("./compliance"); });
// network-tls — lazy for the same reason as compliance: it is only consulted
// at listen() time, and loading the trust store during router's own require
// would pull it in on every boot that never serves TLS.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

var log = boot("router");
var HTTP_STATUS = requestHelpers.HTTP_STATUS;

function _lastResortError(res) {
  try {
    if (requestHelpers.failAfterHeaders(res)) return;
    res.writeHead(HTTP_STATUS.INTERNAL_SERVER_ERROR, { "Content-Type": "text/plain" });
    res.end("Internal Server Error");
  } catch (_e) { /* the connection is already gone; nothing left to say */ }
}

var WINDOW_UPDATE_FRAME_TYPE = 0x8;
var WINDOW_UPDATE_RATE_CAP = 100;
var WINDOW_UPDATE_RATE_WINDOW_MS = C.TIME.seconds(1);

var MAX_ROUTE_PATTERN_LEN = C.BYTES.kib(1);

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

function _writeValidationError(req, res, where, errors) {
  if (res.writableEnded || res.headersSent) return;
  var payload = {
    error: "validation",
    where: where,
    issues: errors,
  };
  var body = JSON.stringify(payload);
  if (req && typeof req.apiEncryptEncode === "function") {
    try { body = JSON.stringify(req.apiEncryptEncode(payload)); } catch (_e) { /* plaintext body kept */ }
  }
  res.writeHead(HTTP_STATUS.BAD_REQUEST, {
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function _makeSchemaValidator(spec) {
  return function schemaValidator(req, res, next) {
    if (spec.params && req.params !== undefined) {
      var pp = spec.params.safeParse(req.params);
      if (!pp.ok) return _writeValidationError(req, res, "params", pp.errors);
      req.params = pp.value;
    }
    if (spec.query && req.query !== undefined) {
      var qq = spec.query.safeParse(req.query);
      if (!qq.ok) return _writeValidationError(req, res, "query", qq.errors);
      req.query = qq.value;
    }
    if (spec.body) {
      var bb = spec.body.safeParse(req.body);
      if (!bb.ok) return _writeValidationError(req, res, "body", bb.errors);
      req.body = bb.value;
    }
    next();
  };
}

function _bodyLooksLikeJson(text) {
  for (var i = 0; i < text.length; i += 1) {
    var ch = text.charCodeAt(i);
    if (ch === 0x20 || ch === 0x09 || ch === 0x0A || ch === 0x0D) continue;
    return ch === 0x7B || ch === 0x5B;
  }
  return false;
}

function _makeResponseValidator(spec) {
  var perRoute = spec.validateResponse;
  var globalMode = safeEnv.readVar("BLAMEJS_VALIDATE_RESPONSES");
  var mode = (perRoute === "throw" || perRoute === "warn") ? perRoute :
             (globalMode === "throw" || globalMode === "warn") ? globalMode : null;
  if (!mode) return function passthrough(_req, _res, next) { next(); };

  return function responseValidator(req, res, next) {
    var validated = false;
    function runCheck(value, headersAlreadySent) {
      var rr = spec.response.safeParse(value);
      if (rr.ok) return;
      if (mode === "throw") {
        if (!headersAlreadySent) {
          throw new Error("router response-validation failed for " +
            (req.method + " " + req.routePattern) + ": " +
            JSON.stringify(rr.errors));
        }
        log.error("response-validation failed after headers sent on " +
                  req.method + " " + req.routePattern + ": " +
                  JSON.stringify(rr.errors).slice(0, 500));
        return;
      }
      log.warn("response-validation drift on " + req.method + " " + req.routePattern +
               ": " + JSON.stringify(rr.errors).slice(0, 500));
    }

    var origJson = typeof res.json === "function" ? res.json.bind(res) : null;
    if (origJson) {
      res.json = function (value) {
        runCheck(value, false);
        validated = true;
        return origJson(value);
      };
    }

    var origEnd = typeof res.end === "function" ? res.end.bind(res) : null;
    if (origEnd) {
      res.end = function (chunk) {
        if (!validated) {
          var text = null;
          if (typeof chunk === "string") text = chunk;
          else if (Buffer.isBuffer(chunk)) text = chunk.toString("utf8");
          if (text !== null && _bodyLooksLikeJson(text)) {
            var parsed;
            var parsedOk = true;
            try { parsed = safeJson.parse(text); } catch (_e) { parsedOk = false; }
            if (parsedOk) {
              validated = true;
              runCheck(parsed, res.headersSent === true);
            }
          }
        }
        return origEnd.apply(res, arguments);
      };
    }
    next();
  };
}

function compilePattern(pattern) {
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new Error("router: pattern must be a non-empty string");
  }
  if (pattern.length > MAX_ROUTE_PATTERN_LEN) {
    throw new Error("router: pattern exceeds " + MAX_ROUTE_PATTERN_LEN +
      " chars (got " + pattern.length + ")");
  }
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

function _canonicalRequestTarget(url) {
  var t = String(url == null ? "/" : url);
  return t.charAt(0) === "/" && t.charAt(1) === "/" ? t.replace(/^\/+/, "/") : t;
}

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

var TLS_0RTT_VALID_POSTURES = ["refuse", "replay-cache"];
var TLS_0RTT_REPLAY_WINDOW_MS = C.TIME.seconds(10);
var TLS_0RTT_REPLAY_CACHE_CAP = 4096;
var TLS_0RTT_FAILCLOSED_POSTURES = ["pci-dss", "fapi2"];

class Router {
  constructor(opts) {
    opts = opts || {};
    this.routes = [];
    this.middleware = [];
    this._wsRoutes = new Map();
    this._activeWsConns = new Set();

    var posture = opts.tls0Rtt === undefined ? "refuse" : opts.tls0Rtt;
    if (typeof posture !== "string" || TLS_0RTT_VALID_POSTURES.indexOf(posture) === -1) {
      throw new TypeError(
        "router.create: tls0Rtt must be one of " + TLS_0RTT_VALID_POSTURES.join(", ") +
        "; got " + JSON.stringify(opts.tls0Rtt));
    }
    this._tls0RttPosture = posture;
    this._tls0RttReplayCache = new Map();

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

  allowedRedirectOrigins() {
    return this._allowedRedirectOrigins.slice();
  }

  tls0RttPosture() { return this._tls0RttPosture; }

  activeWebSockets() {
    return this._activeWsConns.size;
  }

  async closeWebSockets(opts) {
    opts = opts || {};
    var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : C.TIME.seconds(5);
    var code = opts.code || 1001;
    var reason = opts.reason || "server shutting down";

    var conns = Array.from(this._activeWsConns);
    if (conns.length === 0) return 0;

    var closes = conns.map(function (conn) {
      return new Promise(function (resolve) {
        if (conn.readyState === "closed") { resolve(); return; }
        conn.once("close", resolve);
        try { conn.close(code, reason); }
        catch (_e) {
          resolve();
        }
      });
    });

    await Promise.race([
      Promise.all(closes),
      safeAsync.sleep(timeoutMs, { unref: true }),
    ]);
    this._activeWsConns.forEach(function (conn) {
      try { if (conn.socket && conn.socket.destroy) conn.socket.destroy(); }
      catch (_e) { /* socket already destroyed */ }
    });
    return conns.length;
  }

  use() {
    var entries = _normalizeUseArgs(Array.prototype.slice.call(arguments));
    for (var i = 0; i < entries.length; i++) {
      this.middleware.push(entries[i]);
    }
  }

  _splitArgs(args) {
    if (args.length > 0 && args[0] && typeof args[0] === "object" &&
        !Array.isArray(args[0]) && typeof args[0] !== "function") {
      return { spec: args[0], handlers: args.slice(1) };
    }
    return { spec: null, handlers: args };
  }

  _registerRoute(method, pattern, args) {
    if (typeof pattern === "string" && /\*{4,}/.test(pattern)) {
      throw new Error(method + " " + pattern + ": route pattern refused " +
        "(CVE-2026-4923) — more than 3 consecutive '*' metacharacters");
    }
    var split = this._splitArgs(args);
    if (split.spec) _validateRouteSpec(split.spec, method, pattern);
    var handlers = split.handlers;
    if (split.spec) {
      handlers = [_makeSchemaValidator(split.spec)].concat(handlers);
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
    var reqTarget = req.url || "/";
    if (reqTarget.charAt(0) !== "/") {
      res.statusCode = 400;
      res.end("400 Bad Request: non-origin-form request target");
      return;
    }
    var canonicalTarget = _canonicalRequestTarget(reqTarget);
    if (canonicalTarget !== reqTarget) {
      reqTarget = canonicalTarget;
      req.url = reqTarget;
    }
    var absolute = "http://blamejs.invalid" + reqTarget;
    var parsed = safeUrl.parse(absolute, {
      allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
    });
    if (/%2[fF]|%5[cC]|%00/.test(parsed.pathname)) {
      res.statusCode = 400;
      res.end("400 Bad Request: encoded path separator or null byte");
      return;
    }
    try {
      req.pathname = decodeURIComponent(parsed.pathname);
    } catch (_decodeErr) {
      res.statusCode = 400;
      res.end("400 Bad Request: malformed percent-encoding in path");
      return;
    }
    var queryEntries = [];
    var queryKeyCount = 0;
    for (var pair of parsed.searchParams) {
      queryKeyCount += 1;
      if (queryKeyCount > 1000) {
        res.statusCode = 400;
        res.end("400 Bad Request: too many query keys");
        return;
      }
      queryEntries.push(pair);
    }
    req.query = Object.fromEntries(queryEntries);

    for (var entry of this.middleware) {
      if (entry.prefixSegmentsList !== null) {
        var matched = false;
        for (var pli = 0; pli < entry.prefixSegmentsList.length; pli++) {
          if (_pathMatchesPrefix(entry.prefixSegmentsList[pli], req.pathname)) {
            matched = true;
            break;
          }
        }
        if (!matched) continue;
      }
      var mw = entry.fn;
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

    for (var route of this.routes) {
      if (route.method !== req.method) continue;
      var params = this._match(route, req.pathname);
      if (!params) continue;
      req.params = params;
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

  _effective0RttPosture() {
    var declared = this._tls0RttPosture;
    if (declared !== "replay-cache") return declared;
    var active = null;
    try {
      var complianceInst = compliance();
      if (complianceInst && typeof complianceInst.current === "function") active = complianceInst.current();
    } catch (_e) { /* compliance not initialized */ }
    if (active && TLS_0RTT_FAILCLOSED_POSTURES.indexOf(active) !== -1) {
      try {
        audit().safeEmit({
          action:   "tls.0rtt.refused",
          outcome:  "denied",
          metadata: { reason: "posture-failclosed", posture: active, declared: declared },
        });
      } catch (_e) { /* audit best-effort */ }
      return "refuse";
    }
    return "replay-cache";
  }

  _check0RttReplay(req) {
    var posture = this._effective0RttPosture();
    var earlyDataHeader = req.headers && (req.headers["early-data"] || req.headers["Early-Data"]);
    if (earlyDataHeader === undefined) return null;
    if (String(earlyDataHeader).trim() !== "1") return null;
    if (posture === "refuse") {
      try {
        audit().safeEmit({
          action:   "tls.0rtt.refused",
          outcome:  "denied",
          metadata: { reason: "posture-refuse", method: req.method, url: req.url },
        });
      } catch (_e) { /* audit best-effort */ }
      return { status: C.HTTP.STATUS.TOO_EARLY, reason: "early-data-refused" };
    }
    var nowMs = Date.now();
    this._reap0RttCache(nowMs);
    var hash = require("node:crypto").createHash("sha3-512");
    hash.update(String(req.method || "") + "\n");
    hash.update(_canonicalRequestTarget(req.url) + "\n");
    hash.update(String((req.headers &&
      (req.headers[":authority"] || req.headers["host"])) || "") + "\n");
    hash.update(String((req.headers && req.headers["authorization"]) || "") + "\n");
    hash.update(String((req.headers && req.headers["date"]) || "") + "\n");
    hash.update(String((req.headers && req.headers["idempotency-key"]) || "") + "\n");
    var key = hash.digest("hex");
    if (this._tls0RttReplayCache.has(key)) {
      try {
        audit().safeEmit({
          action:   "tls.0rtt.replayed",
          outcome:  "denied",
          metadata: { reason: "cache-hit", method: req.method, url: req.url,
                      windowMs: TLS_0RTT_REPLAY_WINDOW_MS },
        });
      } catch (_e) { /* audit best-effort */ }
      return { status: C.HTTP.STATUS.TOO_EARLY, reason: "early-data-replay" };
    }
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
      audit().safeEmit({
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
      var verdict0Rtt = self._check0RttReplay(req);
      if (verdict0Rtt) {
        res.writeHead(C.HTTP.STATUS.TOO_EARLY, {
          "Content-Type": "text/plain; charset=utf-8",
          "Connection":   "close",
        });
        res.end(verdict0Rtt.reason);
        return;
      }
      res.json = (data) => {
        res.writeHead(res.statusCode || HTTP_STATUS.OK, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      res.redirect = (url) => {
        if (typeof url !== "string" || url.length === 0) {
          throw new RouterError(
            "router/redirect-target-not-string",
            "res.redirect: target must be a non-empty string"
          );
        }
        for (var ci = 0; ci < url.length; ci += 1) {
          var cc = url.charCodeAt(ci);
          if (cc === 0x00 || cc === 0x09 || cc === 0x0A || cc === 0x0D) {
            throw new RouterError(
              "router/redirect-target-has-control-chars",
              "res.redirect: target must not contain CR / LF / TAB / NUL bytes"
            );
          }
        }
        if (url.charAt(0) === "/" &&
            url.charAt(1) !== "/" && url.charAt(1) !== "\\") {
          res.writeHead(C.HTTP.STATUS.FOUND, { Location: url });
          res.end();
          return;
        }
        var parsedTarget;
        try {
          parsedTarget = safeUrl.parse(url, {
            allowedProtocols: ["https:"],
          });
        } catch (parseErr) {
          try {
            audit().safeEmit({
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
            audit().safeEmit({
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
          audit().safeEmit({
            action:   "router.redirect.cross_origin.allowed",
            outcome:  "success",
            metadata: { target: url, origin: targetOrigin },
          });
        } catch (_e) { /* audit best-effort */ }
        res.writeHead(C.HTTP.STATUS.FOUND, { Location: url });
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
            _lastResortError(res);
          }
        } else {
          _lastResortError(res);
        }
      });
    };
    var server;
    if (tlsOptions) {
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
      if (!tlsOptions.minVersion) {
        tlsOptions = Object.assign({ minVersion: "TLSv1.3" }, tlsOptions);
      }
      var posture0Rtt = self._effective0RttPosture();
      if (tlsOptions.allowEarlyData === undefined) {
        tlsOptions.allowEarlyData = (posture0Rtt === "replay-cache");
      }
      var certCompression = C.TLS_CERT_COMPRESSION();
      var h2Defaults = {
        allowHTTP1:               true,
        ALPNProtocols:             ["h2", "http/1.1"],
        settings:                  { enableConnectProtocol: true },
        maxConcurrentStreams:      100,
        maxSessionMemory:          10,
        maxHeaderListPairs:        100,
        maxSettings:               32,
        peerMaxConcurrentStreams:  100,
        maxOutstandingPings:       10,
        unknownProtocolTimeout:    C.TIME.seconds(10),
      };
      if (certCompression.length > 0) h2Defaults.certificateCompression = certCompression;
      var h2Opts = networkTls()._stripUnreachableCertCompression(
        Object.assign(h2Defaults, tlsOptions), tlsOptions);
      server = http2.createSecureServer(h2Opts, requestHandler);

      server.on("session", function (h2session) {
        h2session._blamejsGoawaySent = false;
        var origGoaway = (typeof h2session.goaway === "function")
          ? h2session.goaway.bind(h2session) : null;
        if (origGoaway) {
          h2session.goaway = function (code, lastStreamID, opaqueData) {
            h2session._blamejsGoawaySent = true;
            return origGoaway(code, lastStreamID, opaqueData);
          };
        }
        h2session.on("goaway", function () {
          h2session._blamejsGoawaySent = true;
        });
        h2session.on("stream", function (stream) {
          if (h2session._blamejsGoawaySent) {
            try { audit().safeEmit({
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
      server = http.createServer(requestHandler);
    }

    if (self._wsRoutes.size > 0) {
      server.on("upgrade", function (req, socket, head) {
        var pathname = String(req.url || "/").split("?")[0];
        var route = self._wsRoutes.get(pathname);
        if (!route) {
          socket.destroy();
          return;
        }
        if (route.transport === "h2-only") {
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
    server.headersTimeout   = C.TIME.seconds(60);
    server.requestTimeout   = C.TIME.minutes(5);
    server.keepAliveTimeout = C.TIME.seconds(5);
    server.timeout          = C.TIME.minutes(5);
    return server;
  }
}

function _compilePrefix(prefix) {
  var segments = prefix.split("/");
  if (segments.length > 1 && segments[segments.length - 1] === "") {
    segments.pop();
  }
  return segments;
}

function _pathMatchesPrefix(prefixSegments, pathname) {
  var pathSegments = pathname.split("/");
  if (pathSegments.length < prefixSegments.length) return false;
  return prefixSegments.every(function (seg, i) {
    return pathSegments[i] === seg;
  });
}

function _usePrefixesFromFirstArg(first) {
  if (typeof first === "function") return null;
  if (typeof first !== "string" && !Array.isArray(first)) {
    throw new RouterError("router/use-bad-first-arg",
      "router.use: first argument must be a middleware function, a path " +
      "prefix string, or an array of prefix strings (got " +
      (first === null ? "null" : typeof first) + ")");
  }
  var prefixes = Array.isArray(first) ? first : [first];
  if (prefixes.length === 0) {
    throw new RouterError("router/use-empty-prefix-array",
      "router.use: path-prefix array must contain at least one prefix string");
  }
  validateOpts.optionalNonEmptyStringArray(
    prefixes, "router.use: path prefix", RouterError, "router/use-prefix-not-string");
  for (var i = 0; i < prefixes.length; i++) {
    var grammarErr = _prefixGrammarError(prefixes[i]);
    if (grammarErr) throw grammarErr;
  }
  return prefixes;
}

function _prefixGrammarError(prefix) {
  if (prefix.charAt(0) !== "/") {
    return new RouterError("router/use-prefix-not-absolute",
      "router.use: path prefix '" + prefix + "' must begin with '/'");
  }
  if (prefix.length > MAX_ROUTE_PATTERN_LEN) {
    return new RouterError("router/use-prefix-too-long",
      "router.use: path prefix exceeds " + MAX_ROUTE_PATTERN_LEN +
      " chars (got " + prefix.length + ")");
  }
  return null;
}

function _firstNonFunctionIndex(fns) {
  for (var i = 0; i < fns.length; i++) {
    if (typeof fns[i] !== "function") return i;
  }
  return -1;
}

function _normalizeUseArgs(args) {
  if (args.length === 0) {
    throw new RouterError("router/use-no-args",
      "router.use: requires at least one middleware function");
  }
  var prefixes = _usePrefixesFromFirstArg(args[0]);
  var fns = (prefixes === null) ? args : args.slice(1);
  if (fns.length === 0) {
    throw new RouterError("router/use-no-middleware",
      "router.use: path-scoped mount requires at least one middleware " +
      "function after the prefix");
  }
  var nonFn = _firstNonFunctionIndex(fns);
  if (nonFn !== -1) {
    throw new RouterError("router/use-middleware-not-function",
      "router.use: middleware at position " + nonFn +
      " must be a function (got " +
      (fns[nonFn] === null ? "null" : typeof fns[nonFn]) + ")");
  }
  var segmentsList = (prefixes === null) ? null : prefixes.map(_compilePrefix);
  var label = (prefixes === null) ? null
            : (prefixes.length === 1 ? prefixes[0] : prefixes.slice());
  return fns.map(function (fn) {
    return { prefix: label, prefixSegmentsList: segmentsList, fn: fn };
  });
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
function serveStatic(dir) {
  var root = nodePath.resolve(dir);
  return (req, res, next) => {
    if (req.method !== "GET") return next();
    var rel = req.pathname;
    if (rel.includes("\0")) return next();
    var filePath = nodePath.resolve(nodePath.join(root, rel));
    if (filePath !== root && !filePath.startsWith(root + nodePath.sep)) return next();
    var fd;
    try { fd = atomicFile.openNoFollowSync(filePath); } catch (_e) { return next(); }
    var stat = nodeFs.fstatSync(fd);
    if (stat.isDirectory()) { nodeFs.closeSync(fd); return next(); }

    var ext = nodePath.extname(filePath).toLowerCase();
    var mime = MIME_TYPES[ext] || "application/octet-stream";
    var hasVersion = req.url && req.url.includes("?v=");
    var cacheControl = hasVersion
      ? "public, max-age=31536000, immutable"
      : "public, max-age=3600";
    res.writeHead(HTTP_STATUS.OK, {
      "Content-Type":   mime,
      "Content-Length": stat.size,
      "Cache-Control":  cacheControl,
    });
    nodeFs.createReadStream(filePath, { fd: fd }).pipe(res);
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
 * / delete` for route registration, `use(...)` for middleware,
 * `ws(path, handler, opts?)` for WebSocket routes, `onNotFound(fn)`
 * and `onError(fn)` for fallthrough hooks, `inspectRoutes()` and
 * `openapi()` for introspection, `closeWebSockets({ timeoutMs })`
 * for graceful shutdown, and `listen(port, cb?, tlsOptions?, host?)`
 * which boots an HTTP/2-capable TLS server (ALPN h2 + http/1.1) when
 * `tlsOptions` is provided, an HTTP/1.1 server otherwise.
 *
 * `use` has two forms. `use(mw)` (and `use(mw1, mw2, ...)`) mounts
 * global middleware that runs on every request. `use(prefix, mw1,
 * mw2, ...)` mounts path-scoped middleware that runs only when the
 * request path is at or beneath `prefix`, matched on segment
 * boundaries — `"/admin"` covers `"/admin"` and `"/admin/x"` but not
 * `"/administrator"`. The prefix may be an array of strings to scope a
 * gate to several path roots at once. Global and scoped middleware
 * interleave in registration order, so a gate registered before a
 * route still runs before it. A non-string / non-array prefix, a
 * prefix not beginning with `"/"`, or a non-function middleware throws
 * at registration time rather than dropping the gate or 500-ing every
 * request — scope a security middleware (`csrf`, `bearerAuth`,
 * `requireAal`, `requireMtls`) to a path with confidence it runs
 * exactly where mounted.
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
 *
 *   // Global middleware — runs on every request.
 *   router.use(b.middleware.securityHeaders());
 *
 *   // Path-scoped middleware — the step-up gate runs only under /admin.
 *   router.use("/admin", b.middleware.requireAal({ minimum: "AAL2" }));
 *
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
