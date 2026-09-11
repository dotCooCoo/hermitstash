// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.localHttp
 * @nav    HTTP
 * @title  Local-daemon HTTP
 * @order  118
 *
 * @intro
 *   An HTTP client for a LOCAL daemon reached over a non-network transport —
 *   a Unix domain socket (Docker <code>/var/run/docker.sock</code>, systemd,
 *   containerd, <code>tailscaled</code>), a Windows named pipe, or a
 *   loopback TCP port + bearer token (the sandboxed-macOS shape). Distinct
 *   from <code>b.httpClient</code>, which does DNS + TCP/TLS + the SSRF gate.
 *
 *   This client is <strong>SSRF-safe by construction</strong>: a socket-path
 *   request never resolves DNS and never touches an IP, so it cannot be
 *   steered at an internal address; the loopback-TCP mode refuses any host
 *   that is not a loopback address. It always sets the caller-chosen
 *   <code>Host</code> header (many local APIs require an exact value such as
 *   <code>local-tailscaled.sock</code>) and NEVER sends <code>Origin</code> or
 *   <code>Referer</code> — the two headers a local daemon uses to reject
 *   drive-by / DNS-rebinding requests from a browser.
 *
 *   Responses are size-bounded and typed: <code>{ statusCode, headers, body,
 *   text(), json() }</code>. The vendor glue (a tailscaled Host value,
 *   <code>.whois/.status</code> wrappers) belongs in the consumer, not here.
 *
 * @card
 *   SSRF-safe HTTP over a local Unix socket / Windows named pipe / loopback-TCP+token — caller-set Host, no Origin/Referer, bounded typed responses. For Docker / systemd / tailscaled-style local daemons.
 */

var http          = require("node:http");
var net           = require("node:net");
var safeBuffer    = require("./safe-buffer");
var safeJson      = require("./safe-json");
var numericBounds = require("./numeric-bounds");
var validateOpts  = require("./validate-opts");
var C             = require("./constants");
var { defineClass } = require("./framework-error");

var LocalHttpError = defineClass("LocalHttpError", {
  permanentClassifier: function (code) {
    return !(code === "local-http/request-error" ||
             code === "local-http/timeout" ||
             code === "local-http/response-error");
  },
});

var DEFAULT_TIMEOUT_MS       = C.TIME.seconds(10);
var DEFAULT_MAX_RESPONSE     = C.BYTES.mib(8);
var DEFAULT_HOST_HEADER      = "localhost";

var FORBIDDEN_HEADERS = ["origin", "referer"];

function _canonHost(host) {
  var h = String(host).toLowerCase().replace(/\.$/, "");
  if (h.length >= 2 && h.charAt(0) === "[" && h.charAt(h.length - 1) === "]") h = h.slice(1, -1);
  return h;
}

function _isLoopbackHost(host) {
  if (typeof host !== "string") return false;
  var h = _canonHost(host);
  var fam = net.isIP(h);
  if (fam === 6) return h === "::1";
  if (fam === 4) return /^127\./.test(h);
  return false;
}

function _lowerHeaderKeys(headers) {
  var out = {};
  if (headers && typeof headers === "object") {
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i += 1) out[keys[i].toLowerCase()] = headers[keys[i]];
  }
  return out;
}

/**
 * @primitive b.localHttp.create
 * @signature b.localHttp.create(opts)
 * @since     0.18.8
 * @status    stable
 * @related   b.localHttp.request, b.httpClient
 *
 * Build a client bound to ONE local transport. Provide EITHER
 * <code>socketPath</code> (a Unix socket path or a Windows named pipe like
 * <code>\\.\pipe\name</code>) OR <code>host</code> + <code>port</code> (which
 * must be a loopback address). Returns a client with <code>request</code>,
 * <code>get</code>, and <code>postJson</code> — every call sends the configured
 * <code>hostHeader</code> and omits <code>Origin</code>/<code>Referer</code>.
 *
 * @opts
 *   socketPath:       string,          // Unix socket path OR Windows named pipe (exclusive with host/port)
 *   host:             string,          // loopback IP LITERAL for the TCP+token mode (127.0.0.0/8 or ::1 — a hostname like "localhost" is refused)
 *   port:             number,          // TCP port (with host)
 *   hostHeader:       string,          // the Host header to send (default: "localhost")
 *   bearerToken:      string,          // Authorization: Bearer <token> on every request
 *   defaultHeaders:   object,          // headers merged into every request (Origin/Referer stripped)
 *   timeoutMs:        number,          // per-request timeout (default: 10s)
 *   maxResponseBytes: number,          // response body cap; over-cap aborts (default: 8 MiB)
 *
 * @example
 *   var d = b.localHttp.create({ socketPath: "/run/tailscale/tailscaled.sock",
 *     hostHeader: "local-tailscaled.sock" });
 *   var r = await d.get("/localapi/v0/status");
 *   // → { statusCode: 200, headers, body, text(), json() }
 */
function create(opts) {
  opts = validateOpts.requireObject(opts, "localHttp.create", LocalHttpError, "local-http/bad-opts");
  validateOpts(opts,
    ["socketPath", "host", "port", "hostHeader", "bearerToken", "defaultHeaders", "timeoutMs", "maxResponseBytes"],
    "localHttp.create");

  var hasSocket = opts.socketPath !== undefined && opts.socketPath !== null;
  var hasTcp    = opts.host !== undefined && opts.host !== null;
  if (hasSocket === hasTcp) {
    throw new LocalHttpError("local-http/bad-transport",
      "create: provide EXACTLY one of opts.socketPath OR opts.host+opts.port");
  }
  var socketPath = null;
  var host = null;
  var port = null;
  if (hasSocket) {
    validateOpts.requireNonEmptyString(opts.socketPath, "localHttp.create: opts.socketPath",
      LocalHttpError, "local-http/bad-socket-path");
    socketPath = opts.socketPath;
  } else {
    if (!_isLoopbackHost(opts.host)) {
      throw new LocalHttpError("local-http/non-loopback-host",
        "create: opts.host must be a loopback IP literal (127.0.0.0/8 or ::1; a hostname like 'localhost' is refused) — a non-loopback " +
        "host would defeat the SSRF-safe-by-construction guarantee; use b.httpClient for network hosts");
    }
    numericBounds.requirePositiveFiniteInt(opts.port, "port", LocalHttpError, "local-http/bad-port");
    if (opts.port > 65535) {
      throw new LocalHttpError("local-http/bad-port", "create: opts.port must be 1..65535");
    }
    host = _canonHost(opts.host);
    port = opts.port;
  }

  var hostHeader = opts.hostHeader !== undefined ? opts.hostHeader : DEFAULT_HOST_HEADER;
  validateOpts.requireNonEmptyString(hostHeader, "localHttp.create: opts.hostHeader",
    LocalHttpError, "local-http/bad-host-header");
  validateOpts.optionalNonEmptyString(opts.bearerToken, "localHttp.create: opts.bearerToken",
    LocalHttpError, "local-http/bad-token");
  if (opts.defaultHeaders !== undefined && (opts.defaultHeaders === null || typeof opts.defaultHeaders !== "object")) {
    throw new LocalHttpError("local-http/bad-default-headers", "create: opts.defaultHeaders must be an object");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.timeoutMs, "timeoutMs", LocalHttpError, "local-http/bad-timeout");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxResponseBytes, "maxResponseBytes", LocalHttpError, "local-http/bad-max-response");
  var timeoutMs        = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  var maxResponseBytes = typeof opts.maxResponseBytes === "number" ? opts.maxResponseBytes : DEFAULT_MAX_RESPONSE;
  var defaultHeaders   = _lowerHeaderKeys(opts.defaultHeaders);
  FORBIDDEN_HEADERS.forEach(function (h) { delete defaultHeaders[h]; });

  function request(ropts) {
    return new Promise(function (resolve, reject) {
      var r = ropts || {};
      if (typeof r.path !== "string" || r.path.length === 0 || r.path.charAt(0) !== "/") {
        reject(new LocalHttpError("local-http/bad-path", "request: opts.path must be a string beginning with '/'"));
        return;
      }
      var _pathBad = false;
      for (var _pi = 0; _pi < r.path.length; _pi += 1) {
        var _pc = r.path.charCodeAt(_pi);
        if (_pc <= 0x20 || _pc === 0x7f) { _pathBad = true; break; }
      }
      if (_pathBad) {
        reject(new LocalHttpError("local-http/bad-path", "request: opts.path contains an unescaped space or control character"));
        return;
      }
      var method = typeof r.method === "string" ? r.method.toUpperCase() : "GET";
      var headers = Object.assign({}, defaultHeaders, _lowerHeaderKeys(r.headers));
      FORBIDDEN_HEADERS.forEach(function (h) { delete headers[h]; });
      headers.host = hostHeader;
      if (opts.bearerToken !== undefined && headers.authorization === undefined) {
        headers.authorization = "Bearer " + opts.bearerToken;
      }
      var bodyBuf = null;
      if (r.body !== undefined && r.body !== null) {
        bodyBuf = Buffer.isBuffer(r.body) ? r.body
                : typeof r.body === "string" ? Buffer.from(r.body, "utf8")
                : null;
        if (!bodyBuf) { reject(new LocalHttpError("local-http/bad-body", "request: opts.body must be a Buffer or string")); return; }
        headers["content-length"] = String(bodyBuf.length);
      }
      var reqOpts = {
        method:  method,
        path:    r.path,
        headers: headers,
        setHost: false,
      };
      if (socketPath !== null) reqOpts.socketPath = socketPath;
      else { reqOpts.host = host; reqOpts.port = port; }

      var settled = false;
      var deadline = null;
      function fail(err) {
        /* c8 ignore next -- re-entry guard: fail() settles once; a second failure source racing the first (a destroy-induced socket error vs. a size/timeout abort) is not deterministically forceable */
        if (!settled) {
          settled = true;
          clearTimeout(deadline);
          /* c8 ignore next -- defensive: req.destroy() on an already-closed socket does not throw in practice */
          try { req.destroy(); } catch (_d) { /* already gone */ }
          reject(err);
        }
      }

      var req = http.request(reqOpts, function (res) {   // allow:raw-outbound-http-framework-internal — local socket / loopback transport, never a network host
        var collector = safeBuffer.boundedChunkCollector({
          maxBytes:    maxResponseBytes,
          errorClass:  LocalHttpError,
          sizeCode:    "local-http/response-too-large",
          sizeMessage: "response body exceeded maxResponseBytes (" + maxResponseBytes + ")",
        });
        res.on("data", function (chunk) {
          /* c8 ignore next -- data-after-settled race guard: once fail()/end has settled + destroyed the socket, a late buffered 'data' is not deterministically forceable */
          if (settled) return;
          try { collector.push(chunk); } catch (e) { fail(e); }
        });
        res.on("end", function () {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          var body = collector.result();
          resolve({
            statusCode: res.statusCode,
            headers:    res.headers,
            body:       body,
            text:       function () { return body.toString("utf8"); },
            json:       function () { return safeJson.parse(body.toString("utf8"), { maxBytes: maxResponseBytes }); },
          });
        });
        /* c8 ignore next -- response-stream 'error' after headers (mid-body transport fault) is not deterministically forceable; the connect/transport path is covered by req.on('error') below */
        res.on("error", function (e) { fail(new LocalHttpError("local-http/response-error", "request: response stream error: " + ((e && e.message) || String(e)))); });
      });
      req.on("error", function (e) {
        fail(new LocalHttpError("local-http/request-error",
          /* c8 ignore next -- String(e) fallback: a transport error always carries a message */
          "request: transport error: " + ((e && e.message) || String(e))));
      });
      deadline = setTimeout(function () {
        fail(new LocalHttpError("local-http/timeout", "request: exceeded the " + timeoutMs + "ms deadline"));
      }, timeoutMs);
      if (bodyBuf) req.write(bodyBuf);
      req.end();
    });
  }

  function get(path, gopts) {
    return request(Object.assign({}, gopts, { method: "GET", path: path }));
  }
  async function postJson(path, obj, popts) {
    var headers = Object.assign({}, (popts && popts.headers) || {}, { "content-type": "application/json" });
    return request(Object.assign({}, popts, { method: "POST", path: path, headers: headers, body: JSON.stringify(obj) }));
  }

  return { request: request, get: get, postJson: postJson };
}

/**
 * @primitive b.localHttp.request
 * @signature b.localHttp.request(opts)
 * @since     0.18.8
 * @status    stable
 * @related   b.localHttp.create
 *
 * One-shot convenience: build a client from the transport fields and issue a
 * single request. `opts` carries both the `create` transport fields
 * (socketPath / host+port / hostHeader / bearerToken / timeoutMs /
 * maxResponseBytes) and the per-request fields (method / path / headers /
 * body). Resolves the same typed response as the client's `request`.
 *
 * @opts
 *   socketPath:       string,          // Unix socket path OR Windows named pipe (exclusive with host/port)
 *   host:             string,          // loopback IP LITERAL for the TCP+token mode (127.0.0.0/8 or ::1 — a hostname like "localhost" is refused)
 *   port:             number,          // TCP port (with host)
 *   hostHeader:       string,          // the Host header to send (default: "localhost")
 *   bearerToken:      string,          // Authorization: Bearer <token> on the request
 *   defaultHeaders:   object,          // headers merged into the request (Origin/Referer stripped)
 *   timeoutMs:        number,          // request timeout (default: 10s)
 *   maxResponseBytes: number,          // response body cap; over-cap aborts (default: 8 MiB)
 *   method:           string,          // HTTP method (default: "GET")
 *   path:             string,          // request path (must start with "/")
 *   headers:          object,          // per-request headers (merged over defaultHeaders)
 *   body:             Buffer | string, // request body
 *
 * @example
 *   var r = await b.localHttp.request({
 *     socketPath: "/var/run/docker.sock", hostHeader: "localhost",
 *     path: "/v1.44/containers/json",
 *   });
 */
var TRANSPORT_FIELDS = ["socketPath", "host", "port", "hostHeader", "bearerToken", "defaultHeaders", "timeoutMs", "maxResponseBytes"];

function request(opts) {
  opts = validateOpts.requireObject(opts, "localHttp.request", LocalHttpError, "local-http/bad-opts");
  var createOpts = {};
  TRANSPORT_FIELDS.forEach(function (k) { if (opts[k] !== undefined) createOpts[k] = opts[k]; });
  return create(createOpts).request({ method: opts.method, path: opts.path, headers: opts.headers, body: opts.body });
}

module.exports = {
  create:         create,
  request:        request,
  LocalHttpError: LocalHttpError,
};
