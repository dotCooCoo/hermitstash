"use strict";
/**
 * spanHttpServer middleware — auto-creates a root span per HTTP
 * request, populates OTel SEMCONV.HTTP_* attributes, attaches
 * the span to req.span, and ends the span on response close.
 *
 *   var tracer = b.observability.tracer.create({ service: "checkout" });
 *   var exporter = b.observability.otlpExporter.create({
 *     endpoint: "https://collector.example.com/v1/traces",
 *   });
 *
 *   router.use(b.middleware.tracePropagate());      // populates req.trace
 *   router.use(b.middleware.spanHttpServer({
 *     tracer:    tracer,
 *     onEnd:     exporter.queue,
 *     ignorePaths: ["/healthz", /^\/static/],
 *     captureRequestHeaders:  ["user-agent", "x-tenant-id"],
 *     captureResponseHeaders: ["content-type", "content-length"],
 *   }));
 *
 *   app.get("/checkout", function (req, res) {
 *     // req.span is the active root server span
 *     req.span.setAttribute("checkout.cart_size", cart.items.length);
 *     var childSpan = tracer.startChildOf(req.span, "db.query");
 *     // ... do query work
 *     childSpan.end();
 *     res.json({ ok: true });
 *   });
 *
 * Span attributes auto-populated per OTel HTTP-server semconv:
 *   - http.request.method, http.route (when available)
 *   - url.scheme, url.path, url.query
 *   - server.address, client.address
 *   - user_agent.original
 *   - http.response.status_code (set when response writeHead fires)
 *
 * Span kind: "server".
 *
 * Skip paths: opts.ignorePaths accepts an array of strings (exact match)
 * or RegExp instances. Use this to keep healthz / static-asset routes
 * out of the span volume.
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var SpanHttpError = defineClass("SpanHttpError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

function _shouldIgnore(path, ignorePaths) {
  if (!ignorePaths || !Array.isArray(ignorePaths)) return false;
  for (var i = 0; i < ignorePaths.length; i++) {
    var rule = ignorePaths[i];
    if (typeof rule === "string" && rule === path) return true;
    if (rule instanceof RegExp && rule.test(path)) return true;
  }
  return false;
}

function _splitUrl(url) {
  if (typeof url !== "string" || url.length === 0) return { path: "/", query: null };
  var qIdx = url.indexOf("?");
  if (qIdx === -1) return { path: url, query: null };
  return { path: url.slice(0, qIdx), query: url.slice(qIdx + 1) };
}

function _scheme(req) {
  // Display-only: the OTel url.scheme span attribute reflects the scheme the
  // client used (forwarded), NOT a Secure/HSTS/origin trust decision. Routing
  // through trustedProtocol would drop the forwarded scheme from spans behind a
  // proxy (less accurate telemetry) for no security gain.
  // allow:raw-xfp-telemetry-only — telemetry label, not a trust sink (see above).
  var x = req.headers && (req.headers["x-forwarded-proto"] || "");
  if (typeof x === "string" && x.length > 0) {
    var first = x.split(",")[0].trim().toLowerCase();
    if (first === "http" || first === "https") return first;
  }
  return (req.socket && req.socket.encrypted) ? "https" : "http";
}

function _serverAddress(req) {
  // allow:raw-xfp-telemetry-only — display-only: server.address span attribute (telemetry),
  // not an authority trust decision. Same rationale as _scheme above.
  var hostHeader = req.headers && (req.headers["x-forwarded-host"] || req.headers.host);
  if (typeof hostHeader === "string" && hostHeader.length > 0) {
    return hostHeader.split(",")[0].trim();
  }
  return null;
}

function _captureHeaderAttrs(req, captureList, prefix) {
  if (!Array.isArray(captureList) || captureList.length === 0) return {};
  var out = Object.create(null);
  for (var i = 0; i < captureList.length; i++) {
    var name = String(captureList[i] || "").toLowerCase();
    if (!name) continue;
    var v = req.headers && req.headers[name];
    if (v === undefined) continue;
    if (Array.isArray(v)) v = v.join(", ");
    out[prefix + "." + name] = String(v);
  }
  return out;
}

function _captureResponseHeaderAttrs(res, captureList, prefix) {
  if (!Array.isArray(captureList) || captureList.length === 0) return {};
  var out = Object.create(null);
  for (var i = 0; i < captureList.length; i++) {
    var name = String(captureList[i] || "").toLowerCase();
    if (!name) continue;
    var v;
    try { v = res.getHeader(name); } catch (_e) { continue; }
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) v = v.join(", ");
    out[prefix + "." + name] = String(v);
  }
  return out;
}

/**
 * @primitive b.middleware.spanHttpServer
 * @signature b.middleware.spanHttpServer(opts)
 * @since     0.1.0
 * @related   b.middleware.tracePropagate, b.middleware.traceLogCorrelation
 *
 * Auto-creates a root OTel span per HTTP request, populates the
 * `http.request.method`, `http.route`, `url.scheme`, `url.path`,
 * `server.address`, `client.address`, `user_agent.original`, and
 * `http.response.status_code` semconv attributes, attaches the
 * span to `req.span`, and ends it on response close. Span kind is
 * `server`. `ignorePaths` (strings or RegExp) keeps `/healthz` and
 * static-asset routes out of the span volume.
 * `captureRequestHeaders` / `captureResponseHeaders` add operator-
 * chosen header attributes (e.g. `x-tenant-id`).
 *
 * @opts
 *   {
 *     tracer:                 object,                       // required
 *     onEnd:                  function(span): void,
 *     ignorePaths:            Array<string|RegExp>,
 *     captureRequestHeaders:  string[],
 *     captureResponseHeaders: string[],
 *     spanNameFn:             function(req): string,
 *     audit:                  boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var tracer = b.observability.tracer.create({ service: "checkout" });
 *   app.use(b.middleware.tracePropagate());
 *   app.use(b.middleware.spanHttpServer({
 *     tracer:      tracer,
 *     ignorePaths: ["/healthz"],
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.spanHttpServer", SpanHttpError);
  validateOpts(opts, [
    "tracer", "onEnd", "ignorePaths",
    "captureRequestHeaders", "captureResponseHeaders",
    "spanNameFn", "audit",
  ], "middleware.spanHttpServer");

  if (!opts.tracer || typeof opts.tracer.start !== "function") {
    throw new SpanHttpError("span-http/bad-tracer",
      "middleware.spanHttpServer: tracer must be a b.observability.tracer.create() instance");
  }
  validateOpts.optionalFunction(opts.onEnd,
    "middleware.spanHttpServer: onEnd", SpanHttpError, "span-http/bad-opts");
  validateOpts.optionalFunction(opts.spanNameFn,
    "middleware.spanHttpServer: spanNameFn", SpanHttpError, "span-http/bad-opts");

  var tracer            = opts.tracer;
  var onEnd             = opts.onEnd || null;
  var ignorePaths       = opts.ignorePaths || null;
  var captureReqHeaders = opts.captureRequestHeaders || null;
  var captureResHeaders = opts.captureResponseHeaders || null;
  var spanNameFn        = opts.spanNameFn || null;
  var auditOn           = opts.audit !== false;

  return function spanHttpServerMiddleware(req, res, next) {
    var SEMCONV = observability().SEMCONV;
    var url = _splitUrl(req.url || "/");
    if (_shouldIgnore(url.path, ignorePaths)) return next();

    var spanName;
    if (typeof spanNameFn === "function") {
      try { spanName = String(spanNameFn(req)); }
      catch (_e) { spanName = "http.server.request"; }
    } else {
      spanName = (req.method ? req.method.toUpperCase() + " " : "") + (url.path || "/");
    }

    var traceId = req.trace && req.trace.traceId;
    var parentId = req.trace && req.trace.parentId;
    var sampled = !req.trace || req.trace.sampled !== false;

    var span = tracer.start(spanName, {
      traceId:  traceId,
      parentId: parentId,
      sampled:  sampled,
      kind:     "server",
      attributes: Object.assign({},
        {
          [SEMCONV.HTTP_REQUEST_METHOD]: (req.method || "").toUpperCase(),
          [SEMCONV.URL_SCHEME]:          _scheme(req),
          [SEMCONV.URL_PATH]:            url.path,
        },
        url.query !== null ? { [SEMCONV.URL_QUERY]: url.query } : {},
        (function () {
          var serverAddr = _serverAddress(req);
          return serverAddr ? { [SEMCONV.SERVER_ADDRESS]: serverAddr } : {};
        })(),
        (function () {
          var clientAddr = requestHelpers.clientIp(req);
          return clientAddr ? { [SEMCONV.CLIENT_ADDRESS]: clientAddr } : {};
        })(),
        (function () {
          var ua = req.headers && req.headers["user-agent"];
          return ua ? { [SEMCONV.USER_AGENT_ORIGINAL]: String(ua) } : {};
        })(),
        _captureHeaderAttrs(req, captureReqHeaders, "http.request.header")),
    });

    req.span = span;

    var ended = false;
    function _finish(err) {
      if (ended) return;
      ended = true;
      try {
        var status = res.statusCode;
        if (typeof status === "number") {
          span.setAttribute(SEMCONV.HTTP_RESPONSE_STATUS_CODE, status);
          if (status >= 500) {
            span.setStatus("error", "HTTP " + status);
          } else if (status >= 400) {
            // Per OTel semconv: client errors don't auto-set error status
            // (they're "expected" failures). Operators that want to flag
            // 4xx as errors call span.setStatus("error", ...) themselves.
            span.setStatus("ok");
          } else {
            span.setStatus("ok");
          }
        }
        if (err) span.recordException(err);
        var resHeaders = _captureResponseHeaderAttrs(res, captureResHeaders, "http.response.header");
        var resHeaderKeys = Object.keys(resHeaders);
        for (var i = 0; i < resHeaderKeys.length; i++) {
          span.setAttribute(resHeaderKeys[i], resHeaders[resHeaderKeys[i]]);
        }
        if (req.route && req.route.path) {
          span.setAttribute(SEMCONV.HTTP_ROUTE, String(req.route.path));
        }
      } catch (_e) { /* drop-silent — observability sink */ }
      try { span.end(); }
      catch (_e) { /* drop-silent */ }
      if (typeof onEnd === "function") {
        try { onEnd(span.toJSON()); }
        catch (_e) { /* operator hook — drop-silent */ }
      }
      if (auditOn) {
        try {
          observability().safeEvent("middleware.spanHttpServer.complete", 1, {
            kind:    "server",
            sampled: span.sampled ? "1" : "0",
          });
        } catch (_e) { /* drop-silent */ }
      }
    }

    res.on("finish", function () { _finish(null); });
    res.on("close",  function () { _finish(null); });
    res.on("error",  function (e) { _finish(e); });

    return next();
  };
}

module.exports = {
  create:        create,
  SpanHttpError: SpanHttpError,
};
