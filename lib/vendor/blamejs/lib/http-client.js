// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.httpClient
 * @nav    HTTP
 * @title  Http Client
 *
 * @intro
 *   Outbound HTTP client with SSRF gate, retry, circuit breaker,
 *   wall-clock + idle timeouts, AbortSignal propagation, connection
 *   pooling, streaming, and ALPN-negotiated HTTP/2. Built on node:http,
 *   node:https, and node:http2 with zero npm runtime dependency.
 *
 *   Every outbound request flows through `b.ssrfGuard` out of the box:
 *   hostname → DNS lookup is pinned to vetted IP literals, RFC 1918 /
 *   loopback / link-local / IPv6 ULA destinations are refused, and the
 *   redirect chain is re-validated at every hop so a 302 to
 *   `http://169.254.169.254/` (cloud metadata) can't smuggle past the
 *   first-hop gate. The same DNS pinning applies to retries — there's
 *   no retry path that bypasses the guard.
 *
 *   Protocol selection is automatic. HTTPS origins handshake with
 *   ALPN `['h2', 'http/1.1']` and cache the resulting transport per
 *   `<protocol>//<hostname>:<port>`. While a transport is mid-negotiate
 *   the cache holds the in-flight Promise so concurrent calls to a new
 *   origin coalesce onto a single connection. h2 GOAWAY or session
 *   error evicts the entry; the next request reconnects.
 *
 *   Resiliency defaults: TLS 1.3 minimum, PQC-preferred `ecdhCurve`
 *   group order, split wall-clock vs zero-progress idle timeouts,
 *   request-body stream errors propagated to the returned Promise,
 *   and h2 stream cancellation via NGHTTP2_CANCEL (clean, not
 *   `stream.destroy`) when the AbortSignal fires.
 *
 * @card
 *   Outbound HTTP client with SSRF gate, retry, circuit breaker, wall-clock + idle timeouts, AbortSignal propagation, connection pooling, streaming, and ALPN-negotiated HTTP/2.
 */

var nodeFs = require("node:fs");
var http  = require("node:http");
var https = require("node:https");
var http2 = require("node:http2");
var nodeCrypto = require("node:crypto");
var nodePath = require("node:path");
var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var { URL } = require("node:url");
var atomicFile = require("./atomic-file");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var bCrypto = require("./crypto");
var pqcAgent = require("./pqc-agent");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var net       = require("node:net");
var networkProxy = require("./network-proxy");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { HttpClientError } = require("./framework-error");

var _transports = new Map();

var DEFAULT_AGENT_OPTS = Object.freeze({
  keepAlive:        true,
  keepAliveMsecs:   C.TIME.seconds(1),
  maxSockets:       C.BYTES.bytes(16),
  maxFreeSockets:   C.BYTES.bytes(8),
  scheduling:       "lifo",
});

var HTTP_CLIENT_AGENT_OPTS = Object.assign({}, DEFAULT_AGENT_OPTS);

/**
 * @primitive b.httpClient.configurePool
 * @signature b.httpClient.configurePool(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.httpClient.request
 *
 * Updates the keepAlive Agent options used for new h1 transports and
 * tears down the per-origin transport cache so subsequent requests
 * pick up the fresh values. Existing in-flight responses keep their
 * old transport. Throws on unknown keys, non-positive integers, or a
 * non-boolean `keepAlive`. Use at boot when the default 16/8 socket
 * caps don't match the operator's downstream concurrency budget.
 *
 * @opts
 *   keepAlive:      true,   // boolean — whether to reuse sockets
 *   keepAliveMsecs: 1000,   // positive integer ms between keep-alive probes
 *   maxSockets:     16,     // positive integer — concurrent sockets per origin
 *   maxFreeSockets: 8,      // positive integer — idle sockets retained per origin
 *   scheduling:     "lifo", // "lifo" | "fifo"
 *
 * @example
 *   b.httpClient.configurePool({ maxSockets: 64, maxFreeSockets: 32 });
 *   // → undefined   (cache cleared; next request builds a 64-socket pool)
 */
function configurePool(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("httpClient.configurePool: opts must be an object");
  }
  var allowed = ["keepAlive", "keepAliveMsecs", "maxSockets", "maxFreeSockets", "scheduling"];
  for (var k in opts) {
    if (!Object.prototype.hasOwnProperty.call(opts, k)) continue;
    if (allowed.indexOf(k) === -1) {
      throw new Error("httpClient.configurePool: unknown option '" + k +
        "'. Allowed: " + allowed.join(", "));
    }
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxSockets", "maxFreeSockets", "keepAliveMsecs"], "httpClient.configurePool",
    HttpClientError, "http-client/bad-opts", { permanent: true });
  if (opts.keepAlive      !== undefined && typeof opts.keepAlive !== "boolean") {
    throw new Error("httpClient.configurePool: keepAlive must be a boolean");
  }
  if (opts.scheduling     !== undefined && opts.scheduling !== "lifo" && opts.scheduling !== "fifo") {
    throw new Error("httpClient.configurePool: scheduling must be 'lifo' or 'fifo'");
  }
  Object.assign(HTTP_CLIENT_AGENT_OPTS, opts);
  _dropAllTransports();
}

function _dropAllTransports() {
  _transports.forEach(function (t) {
    if (t && t.kind === "h1" && t.agent && typeof t.agent.destroy === "function") {
      try { t.agent.destroy(); } catch (_e) { /* best-effort agent teardown */ }
    }
    if (t && t.kind === "h2" && t.session) {
      _tearDownH2Session(t.session);
    }
  });
  _transports.clear();
}

var _tearDownH2Session = require("./http2-teardown").tearDownH2Session;
var _drainH2Session    = require("./http2-teardown").drainH2Session;
// networkTls — lazy so the outbound-TLS posture is read from live state at
// dial time (an operator's preferredGroups.set must reach the next
// connection), without pulling the TLS module into this one's boot graph.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

function _h2TlsOpts() {
  return Object.assign({
    ALPNProtocols:    ["h2", "http/1.1"],
  }, networkTls().outboundPosture());
}

var DEFAULT_CONTROL_PLANE_CAP = C.BYTES.mib(16);
var DEFAULT_GET_CAP           = C.BYTES.gib(1);
var DEFAULT_IDLE_TIMEOUT_MS   = C.TIME.seconds(30);

var H2_SESSION_IDLE_TIMEOUT_MS = C.TIME.minutes(5);
var H2_RETIRED_IDLE_MS = C.TIME.seconds(5);

var DEFAULT_HTTPS_PORT = 443;
var DEFAULT_HTTP_PORT  = C.BYTES.bytes(80);

function _defaultPortFor(u) {
  return u.protocol === "https:" ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
}

function _originKey(u) {
  return u.protocol + "//" + u.hostname + ":" + (u.port || _defaultPortFor(u));
}

function _makeH1Transport(u, ips) {
  var lib = u.protocol === "https:" ? https : http;
  var agent = u.protocol === "https:"
    ? pqcAgent.create(HTTP_CLIENT_AGENT_OPTS)
    : new lib.Agent(HTTP_CLIENT_AGENT_OPTS);
  return { kind: "h1", lib: lib, agent: agent, lookup: _pinnedLookupFor(ips) };
}

function _pinnedLookupFor(ips) {
  if (!Array.isArray(ips) || ips.length === 0) return undefined;
  var families = ips.map(function (i) { return { address: i.address, family: i.family || 4 }; });
  return function pinnedLookup(hostname, options, callback) {
    if (typeof options === "function") { callback = options; options = {}; }
    options = options || {};
    if (options.all) {
      callback(null, families);
    } else {
      callback(null, families[0].address, families[0].family);
    }
  };
}

function _connectHttpsWithAlpn(u, ips) {
  return new Promise(function (resolve, reject) {
    var connectOpts = _h2TlsOpts();
    var pinned = _pinnedLookupFor(ips);
    if (pinned) connectOpts.lookup = pinned;
    // allow:outbound-tls-posture — _h2TlsOpts() merges the live posture above
    var session = http2.connect(u.protocol + "//" + u.host, connectOpts);
    var settled = false;
    function _done(t)   { if (!settled) { settled = true; resolve(t); } }
    function _fail(err) { if (!settled) { settled = true; reject(err); } }

    session.once("connect", function () {
      var alpn = session.alpnProtocol;
      if (alpn === "h2") {
        pqcAgent._auditClassicalDowngrade(session.socket, { host: u.hostname, port: u.port });
        _wireH2Session(session, _originKey(u));
        _done({ kind: "h2", session: session });
        return;
      }
      _tearDownH2Session(session);
      _done(_makeH1Transport(u, ips));
    });
    session.once("error", function (err) {
      _tearDownH2Session(session);
      if (err && err.code === "ERR_SSL_TLSV1_ALERT_NO_APPLICATION_PROTOCOL") {
        _done(_makeH1Transport(u, ips));
        return;
      }
      networkTls().annotateOutboundFailure(err, {
        host:    u.hostname,
        port:    Number(u.port) || 443,
        tlsOpts: connectOpts,
      });
      _fail(err);
    });
  });
}

function _connectH2c(u, ips) {
  return new Promise(function (resolve, reject) {
    var connectOpts = {};
    var pinned = _pinnedLookupFor(ips);
    if (pinned) connectOpts.lookup = pinned;
    // allow:outbound-tls-posture — h2c is cleartext; no TLS layer to configure
    var session = http2.connect(u.protocol + "//" + u.host, connectOpts);
    session.once("connect", function () {
      _wireH2Session(session, _originKey(u));
      resolve({ kind: "h2", session: session });
    });
    session.once("error", function (err) {
      _tearDownH2Session(session);
      reject(err);
    });
  });
}

function _wireH2Session(session, key) {
  session.setTimeout(H2_SESSION_IDLE_TIMEOUT_MS, function () {
    _tearDownH2Session(session);
  });
  function _evictIfStillOurs() {
    var current = _transports.get(key);
    if (current && current.kind === "h2" && current.session === session) {
      _transports.delete(key);
    }
  }
  session.once("close", _evictIfStillOurs);
  session.once("error", _evictIfStillOurs);
  session.once("goaway", function () {
    _evictIfStillOurs();
  });
}

function _retireTransportsForPostureChange() {
  _transports.forEach(_retireTransport);
  _transports.clear();
}

function _retireTransport(t) {
  if (t && t.kind === "h1" && t.agent) {
    try {
      t.agent.keepAlive = false;
      t.agent.maxFreeSockets = 0;
    } catch (_e) { /* best-effort — an exotic agent may freeze its options */ }
    var free = t.agent.freeSockets || {};
    Object.keys(free).forEach(function (name) {
      (free[name] || []).slice().forEach(function (sock) {
        try { sock.destroy(); } catch (_e) { /* best-effort idle-socket close */ }
      });
    });
  }
  if (t && t.kind === "h2" && t.session) {
    var session = t.session;
    try {
      session.removeAllListeners("timeout");
      session.setTimeout(H2_RETIRED_IDLE_MS, function () { _drainH2Session(session); });
    } catch (_e) {
      _drainH2Session(session);
    }
  }
}

var _transportsPostureGen = null;

function _getTransport(u, opts, ips) {
  var postureGen = networkTls().postureGeneration();
  if (_transportsPostureGen !== null && _transportsPostureGen !== postureGen) {
    _retireTransportsForPostureChange();
  }
  _transportsPostureGen = postureGen;

  var key = _originKey(u);
  var cached = _transports.get(key);
  if (cached) {
    return Promise.resolve(cached);
  }

  var promise;
  if (u.protocol === "https:") {
    promise = _connectHttpsWithAlpn(u, ips);
  } else if (opts && opts.preferH2) {
    promise = _connectH2c(u, ips);
  } else {
    promise = Promise.resolve(_makeH1Transport(u, ips));
  }

  _transports.set(key, promise);
  promise.then(
    function (t) {
      if (_transports.get(key) === promise) { _transports.set(key, t); return; }
      _retireTransport(t);
    },
    function (_err) {
      if (_transports.get(key) === promise) _transports.delete(key);
    }
  );

  return promise;
}

function _makeError(errorClass, code, message, permanent, statusCode) {
  var Cls = errorClass || HttpClientError;
  return new Cls(code, message, permanent, statusCode);
}

function _isPermanentStatus(statusCode) {
  if (C.HTTP.clientError(statusCode)) {
    return statusCode !== C.HTTP.STATUS.REQUEST_TIMEOUT &&
           statusCode !== C.HTTP.STATUS.TOO_EARLY &&
           statusCode !== C.HTTP.STATUS.TOO_MANY_REQUESTS;
  }
  return false;
}

function _rejectStreamHttpError(stream, errorClass, statusCode, statusMessage, reject) {
  var cap = C.BYTES.kib(16);
  var collector = safeBuffer.boundedChunkCollector({ maxBytes: cap });
  var done = false;
  function finish() {
    if (done) return;
    done = true;
    var e = _makeError(errorClass, "http-client/http-error",
      "HTTP " + statusCode + (statusMessage ? " " + statusMessage : ""),
      _isPermanentStatus(statusCode), statusCode);
    e.body = collector.result();
    reject(e);
  }
  stream.on("data", function (c) {
    if (done) return;
    var room = cap - collector.bytesCollected();
    if (room > 0) collector.push(c.length > room ? c.subarray(0, room) : c);
    if (collector.bytesCollected() >= cap) {
      if (typeof stream.destroy === "function") stream.destroy();
      finish();
    }
  });
  stream.on("end", finish);
  stream.on("error", finish);
}

function _toH2Headers(method, u, headers) {
  var h2Headers = Object.create(null);
  h2Headers[":method"]    = method;
  h2Headers[":path"]      = u.pathname + (u.search || "");
  h2Headers[":scheme"]    = u.protocol === "https:" ? "https" : "http";
  h2Headers[":authority"] = u.host;
  var sawAcceptEncoding = false;
  for (var k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    var lk = k.toLowerCase();
    if (lk === "connection" || lk === "host" ||
        lk === "keep-alive" || lk === "transfer-encoding" ||
        lk === "upgrade" || lk === "proxy-connection") continue;
    if (lk === "accept-encoding") sawAcceptEncoding = true;
    h2Headers[lk] = headers[k];
  }
  if (!sawAcceptEncoding) h2Headers["accept-encoding"] = "identity";
  return h2Headers;
}

function _fromH2Headers(h2Headers) {
  var out = {};
  for (var k in h2Headers) {
    if (!Object.prototype.hasOwnProperty.call(h2Headers, k)) continue;
    if (k.charAt(0) === ":") continue;
    out[k] = h2Headers[k];
  }
  return out;
}

function hostAllowed(host, allowedHosts, method) {
  if (!Array.isArray(allowedHosts)) return true;
  var wanted = String(host || "").toLowerCase();
  var verb = String(method || "GET").toUpperCase();
  for (var ai = 0; ai < allowedHosts.length; ai++) {
    var entry = allowedHosts[ai];
    var allow, allowedMethods = null;
    if (typeof entry === "object" && entry !== null) {
      allow = String(entry.host || "").toLowerCase();
      if (Array.isArray(entry.methods) && entry.methods.length > 0) {
        allowedMethods = entry.methods.map(function (m) { return String(m).toUpperCase(); });
      }
    } else {
      allow = String(entry || "").toLowerCase();
    }
    if (allow.length === 0) continue;
    if (allow.charAt(0) === "*" && allow.charAt(1) === ".") allow = allow.slice(1);
    var matched = false;
    if (allow.charAt(0) === ".") {
      if (wanted === allow.slice(1) || wanted.endsWith(allow)) matched = true;
    } else if (wanted === allow) {
      matched = true;
    }
    if (!matched) continue;
    if (allowedMethods !== null && allowedMethods.indexOf(verb) === -1) continue;
    return true;
  }
  return false;
}

function _internalWaived(host, isLiteral, allowInternal) {
  if (allowInternal === true) return true;
  if (!isLiteral || !Array.isArray(allowInternal)) return false;
  for (var i = 0; i < allowInternal.length; i += 1) {
    try { if (ssrfGuard.cidrContains(allowInternal[i], host)) return true; }
    catch (_e) { /* a malformed entry waives nothing */ }
  }
  return false;
}

/**
 * @primitive  b.httpClient.pinnedClient
 * @signature  b.httpClient.pinnedClient(client, allowedHosts)
 * @since      0.18.18
 * @status     stable
 * @related    b.httpClient.request, b.ssrfGuard.checkUrl
 *
 * Wrap an HTTP client so an <code>allowedHosts</code> pin is ENFORCED rather
 * than merely advertised, and return the wrapper.
 *
 * The contract for a caller-supplied client is a <code>request</code> method
 * and nothing more, so it need not know what <code>allowedHosts</code> on a
 * request object means. Passing the pin through as a request field therefore
 * leaves it advisory: a client that ignores the field fetches a disallowed
 * host while the operator believes the pin is in force. This wrapper checks
 * the destination itself — using the same membership test
 * <code>request()</code> applies, so an entry means the same thing either way
 * — and refuses before delegating. A destination that cannot be parsed is
 * refused rather than passed through unchecked.
 *
 * Redirects are the pin's blind spot: an allowed host can answer with a
 * redirect to a disallowed or private one, and a client that follows it
 * internally would fetch that without ever returning here. The framework's own
 * client re-checks every hop. The wrapper therefore asks for redirect
 * following to be OFF on each request it forwards — <code>maxRedirects: 0</code>,
 * <code>followRedirects: false</code> and <code>redirect: "manual"</code>,
 * covering the spellings in common use — and a redirect then comes back as an
 * ordinary 3xx response for the caller to act on. A client that follows
 * redirects regardless of all three is outside what this can enforce: it must
 * apply the pin per hop itself, exactly as it must apply anything else its own
 * transport decides.
 *
 * The pin is optional; the redirect control is not. Every caller that hands a
 * client here validated ONE url — its scheme, its host, or both — so an absent
 * pin still returns a wrapper, or a 307 from https to http would be free to
 * resend the credentials that were checked onto the first hop.
 *
 * The framework primitives that accept an injected client
 * (<code>b.auth.oauth.create</code>, <code>b.auth.ciba.client.create</code>,
 * <code>b.auth.saml.fetchMdq</code>) route it through here.
 *
 * @example
 *   var pinned = b.httpClient.pinnedClient(myClient, ["api.partner.com"]);
 *   pinned.request({ url: "https://elsewhere.example/x" });
 *   // → rejects HOST_DISALLOWED; myClient is never called
 */
function pinnedClient(client, allowedHosts) {
  var pin = Array.isArray(allowedHosts) ? allowedHosts : null;
  return {
    request: function (opts) {
      var target = opts && opts.url;
      var parsed = null;
      try { parsed = safeUrl.parse(String(target), { allowedProtocols: safeUrl.ALLOW_HTTP_ALL }); }
      catch (_e) { parsed = null; }
      if (parsed === null) {
        return Promise.reject(_makeError(opts && opts.errorClass, "http-client/host-disallowed",
          "destination '" + String(target) + "' is not a usable http(s) URL", true));
      }
      if (pin !== null && !hostAllowed(parsed.hostname, pin, opts && opts.method)) {
        return Promise.reject(_makeError(opts && opts.errorClass, "http-client/host-disallowed",
          "host '" + parsed.hostname + "' not in allowedHosts (method=" +
          String((opts && opts.method) || "GET").toUpperCase() + ")", true));
      }
      var forwarded = Object.assign({}, opts, {
        maxRedirects:    0,
        followRedirects: false,
        redirect:        "manual",
      });
      try {
        ssrfGuard.checkUrlTextual(parsed, { errorClass: opts && opts.errorClass });
        var literal = ssrfGuard.canonicalizeHost(String(parsed.hostname));
        var isLiteral = net.isIP(literal) !== 0;
        var internal = isLiteral
          ? (ssrfGuard.isPrivate(literal) || ssrfGuard.isLoopback(literal) ||
             ssrfGuard.isLinkLocal(literal) || ssrfGuard.isReserved(literal))
          : ssrfGuard.isLoopbackHost(literal);
        if (internal && !_internalWaived(literal, isLiteral, opts && opts.allowInternal)) {
          return Promise.reject(_makeError(opts && opts.errorClass, "http-client/host-disallowed",
            "destination '" + literal + "' is an internal address — pass " +
            "allowInternal to waive this deliberately", true));
        }
      } catch (e) { return Promise.reject(e); }
      return client.request(forwarded);
    },
  };
}

var REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function _attachJarCookie(headers, jar, url) {
  if (!jar) return headers;
  var jarHeader = jar.cookieHeaderFor(url);
  if (!jarHeader) return headers;
  var merged = Object.assign({}, headers || {});
  var existing = null;
  var keys = Object.keys(merged);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === "cookie") { existing = keys[i]; break; }
  }
  if (existing) merged[existing] = merged[existing] + "; " + jarHeader;
  else merged.Cookie = jarHeader;
  return merged;
}

function _buildMultipartBody(spec) {
  var boundary = "----blamejs-mp-" + bCrypto.generateToken(C.BYTES.bytes(16));
  var CRLF = "\r\n";
  var path = require("node:path");                                         // allow:inline-require — only on multipart paths that touch the filesystem

  var entries = [];
  var anyStreaming = false;
  var totalSize = 0;
  var sizeKnown = true;

  function _entryHeaderBytes(disposition, contentType) {
    var head = "--" + boundary + CRLF + disposition + CRLF;
    if (contentType) head += "Content-Type: " + contentType + CRLF;
    head += CRLF;
    return Buffer.from(head, "utf8");
  }

  function _addEntry(headerBytes, source) {
    entries.push({ header: headerBytes, source: source });
    totalSize += headerBytes.length;
    if (source.kind === "buffer") {
      totalSize += source.buf.length;
    } else if (typeof source.size === "number" && isFinite(source.size) && source.size >= 0) {
      totalSize += source.size;
    } else {
      sizeKnown = false;
    }
    totalSize += CRLF.length;
  }

  function _assertHeaderSafe(v, label) {
    if (typeof v !== "string") {
      throw new Error("multipart: " + label + " must be a string (got " +
        Object.prototype.toString.call(v) + ")");
    }
    if (safeBuffer.hasCrlfOrNul(v)) {
      throw new Error("multipart: " + label + " must not contain CR, LF, or NUL (header injection)");
    }
  }

  function _pushField(name, value) {
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("multipart: field name must be a non-empty string");
    }
    _assertHeaderSafe(name, "field name");
    var disposition = 'Content-Disposition: form-data; name="' + name + '"';
    var head = _entryHeaderBytes(disposition, null);
    var bodyBuf = Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8");
    _addEntry(head, { kind: "buffer", buf: bodyBuf });
  }

  function _pushFile(file) {
    if (!file || typeof file !== "object") throw new Error("multipart: file entries must be objects");
    if (typeof file.field !== "string" || file.field.length === 0) {
      throw new Error("multipart: file.field must be a non-empty string");
    }
    var hasContent  = file.content !== undefined && file.content !== null;
    var hasFilePath = typeof file.filePath === "string" && file.filePath.length > 0;
    var hasStream   = file.stream && typeof file.stream.pipe === "function";
    var sourceCount = (hasContent ? 1 : 0) + (hasFilePath ? 1 : 0) + (hasStream ? 1 : 0);
    if (sourceCount === 0) {
      throw new Error("multipart: file entry requires one of { content, filePath, stream }");
    }
    if (sourceCount > 1) {
      throw new Error("multipart: file entry must have exactly one of { content, filePath, stream }");
    }

    var filename;
    if (typeof file.filename === "string" && file.filename.length > 0) {
      filename = file.filename;
    } else if (hasFilePath) {
      filename = path.basename(file.filePath);
    } else {
      filename = "blob";
    }
    var mimeType = file.contentType || file.mimeType || "application/octet-stream";
    _assertHeaderSafe(file.field, "file.field");
    _assertHeaderSafe(filename, "filename");
    _assertHeaderSafe(mimeType, "contentType");
    var disposition = 'Content-Disposition: form-data; name="' + file.field + '"' +
                      '; filename="' + filename.replace(/"/g, "%22") + '"';
    var head = _entryHeaderBytes(disposition, mimeType);

    if (hasContent) {
      var content = file.content;
      if (typeof content === "string") content = Buffer.from(content, "utf8");
      if (!Buffer.isBuffer(content)) {
        throw new Error("multipart: file.content must be a Buffer or string");
      }
      _addEntry(head, { kind: "buffer", buf: content });
    } else if (hasFilePath) {
      anyStreaming = true;
      var st;
      try { st = nodeFs.statSync(file.filePath); }
      catch (e) { throw new Error("multipart: file.filePath not readable: " + e.message); }
      if (!st.isFile()) throw new Error("multipart: file.filePath is not a regular file");
      _addEntry(head, { kind: "filePath", filePath: file.filePath, size: st.size });
    } else {
      anyStreaming = true;
      var streamSize = (typeof file.size === "number" && isFinite(file.size) && file.size >= 0)
        ? file.size : null;
      _addEntry(head, { kind: "stream", stream: file.stream, size: streamSize });
    }
  }

  if (spec && spec.fields && typeof spec.fields === "object") {
    var keys = Object.keys(spec.fields);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = spec.fields[k];
      if (Array.isArray(v)) {
        for (var j = 0; j < v.length; j++) _pushField(k, v[j]);
      } else {
        _pushField(k, v);
      }
    }
  }
  if (spec && Array.isArray(spec.files)) {
    for (var fi = 0; fi < spec.files.length; fi++) _pushFile(spec.files[fi]);
  }
  var trailer = Buffer.from("--" + boundary + "--" + CRLF, "utf8");
  totalSize += trailer.length;

  if (!anyStreaming && !(spec && spec.streaming === true)) {
    var parts = [];
    for (var ei = 0; ei < entries.length; ei++) {
      parts.push(entries[ei].header);
      parts.push(entries[ei].source.buf);
      parts.push(Buffer.from(CRLF, "utf8"));
    }
    parts.push(trailer);
    return { boundary: boundary, body: Buffer.concat(parts), contentLength: totalSize };
  }

  var crlfBuf = Buffer.from(CRLF, "utf8");
  async function* _iter() {
    for (var ix = 0; ix < entries.length; ix++) {
      var entry = entries[ix];
      yield entry.header;
      if (entry.source.kind === "buffer") {
        yield entry.source.buf;
      } else if (entry.source.kind === "filePath") {
        var rs = nodeFs.createReadStream(entry.source.filePath);
        try {
          for await (var chunk of rs) yield chunk;
        } finally {
          try { rs.destroy(); } catch (_e) { /* best-effort cleanup */ }
        }
      } else {
        for await (var chunk2 of entry.source.stream) yield chunk2;
      }
      yield crlfBuf;
    }
    yield trailer;
  }
  var body = nodeStream.Readable.from(_iter());
  return {
    boundary:      boundary,
    body:          body,
    contentLength: sizeKnown ? totalSize : null,
  };
}

var SENSITIVE_HEADERS_LC = ["authorization", "cookie", "proxy-authorization"];

function _stripCrossOriginAuth(headers) {
  var keys = Object.keys(headers);
  var strip = [];
  for (var i = 0; i < keys.length; i++) {
    if (SENSITIVE_HEADERS_LC.indexOf(keys[i].toLowerCase()) !== -1) strip.push(keys[i]);
  }
  return validateOpts.assignOwnEnumerable({}, headers, strip);
}

/**
 * @primitive b.httpClient.request
 * @signature b.httpClient.request(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.httpClient.downloadStream, b.httpClient.uploadMultipartStream, b.ssrfGuard
 *
 * Promise-returning, AbortSignal-aware HTTP request. Negotiates h2 /
 * h1 per-origin via ALPN, reuses transports from the cache, runs every
 * destination through `b.ssrfGuard` before connecting, and re-validates
 * each redirect hop. Returns `{ statusCode, headers, body }` for the
 * default `"buffer"` mode; `"stream"` returns a Readable for the body.
 * Sensitive headers (Authorization / Cookie / Proxy-Authorization) are
 * stripped on cross-origin redirect. Body-stream errors propagate to
 * the rejected Promise.
 *
 * @opts
 *   method:           "GET",         // HTTP method
 *   url:              <required>,    // string or URL — destination
 *   headers:          {},            // request headers
 *   body:             undefined,     // Buffer | string | Readable | undefined
 *   timeoutMs:        undefined,     // wall-clock cap; no default — operator chooses
 *   idleTimeoutMs:    30000,         // zero-progress cap
 *   responseMode:     "buffer",      // "buffer" | "stream" | "always-resolve"
 *   maxResponseBytes: undefined,     // 16 MiB control / 1 GiB GET defaults; ignored in "stream"
 *   onChunk:          undefined,     // (chunk: Buffer) => void — fires per response chunk
 *   maxBytesPerSec:   undefined,     // token-bucket bandwidth cap (bytes/sec) — paces BOTH the download response and the upload body with backpressure
 *   downloadTransform: undefined,    // Transform | () => Transform | array — interpose on the response stream (e.g. a hashing or progress Transform)
 *   uploadTransform:  undefined,     // Transform | () => Transform | array — interpose on the request body before the wire
 *   signal:           undefined,     // AbortSignal — propagated to req / stream
 *   errorClass:       HttpClientError, // FrameworkError subclass for thrown errors
 *   observer:         undefined,     // (stage, info) => void — lifecycle hook
 *   agent:            undefined,     // override per-origin Agent (h1 only)
 *   preferH2:         false,         // attempt h2c against an HTTP origin (no ALPN)
 *   before:           undefined,     // array of (opts) => opts | Promise — request mutators
 *   after:            undefined,     // array of (response) => response | Promise — response mutators
 *   onUploadProgress: undefined,     // (bytesSent, totalBytes?) => void
 *
 * @example
 *   // requires: outbound HTTPS to the URL below
 *   var res = await b.httpClient.request({
 *     method:    "GET",
 *     url:       "https://example.com/health",
 *     timeoutMs: 5000,
 *   });
 *   // → { statusCode: 200, headers: { "content-type": "application/json", ... }, body: <Buffer> }
 */
function _throttleStream(bytesPerSec) {
  var capacity = bytesPerSec;
  var tokens   = capacity;
  var last     = Date.now();
  function refill() {
    var now = Date.now();
    if (now > last) {
      tokens = Math.min(capacity, tokens + ((now - last) / 1000) * bytesPerSec);
      last = now;
    }
  }
  return new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      var self = this;
      var offset = 0;
      function pump() {
        refill();
        if (offset >= chunk.length) { cb(); return; }
        var avail = Math.floor(tokens);
        if (avail >= 1) {
          var n = Math.min(chunk.length - offset, avail);
          tokens -= n;
          self.push(chunk.subarray(offset, offset + n));
          offset += n;
          if (offset >= chunk.length) { cb(); return; }
          setImmediate(pump);
        } else {
          var waitMs = Math.ceil(C.TIME.seconds((1 - tokens) / bytesPerSec)) + 1;
          var t = setTimeout(pump, waitMs);
          if (t && typeof t.unref === "function") t.unref();
        }
      }
      pump();
    },
  });
}

function _coerceTransforms(value, errorClass, name) {
  if (value === undefined || value === null) return { ok: [] };
  var list = Array.isArray(value) ? value : [value];
  for (var i = 0; i < list.length; i++) {
    var t = list[i];
    var isFactory   = typeof t === "function";
    var isTransform = t && typeof t.pipe === "function" && typeof t.write === "function";
    if (!isFactory && !isTransform) {
      return { err: _makeError(errorClass, "http-client/bad-arg",
        name + " must be a Transform stream or a () => Transform factory (or an array of them)", true) };
    }
  }
  return { ok: list };
}

function _resolveStage(t) { return typeof t === "function" ? t() : t; }

function _buildDownloadStream(source, emitDownload, onChunk, throttleBps, transforms) {
  var stages = [];
  if (throttleBps) stages.push(_throttleStream(throttleBps));
  for (var i = 0; i < transforms.length; i++) stages.push(_resolveStage(transforms[i]));
  if (stages.length === 0 && !emitDownload && !onChunk) return source;
  var observe = new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      if (emitDownload) emitDownload(chunk.length);
      safeAsync.safeInvoke(onChunk, chunk);
      cb(null, chunk);
    },
  });
  var chain = [source].concat(stages).concat([observe]);
  for (var c = 0; c < chain.length - 1; c++) {
    var src = chain[c], dst = chain[c + 1];
    src.on("error", (function (d) { return function (e) { d.destroy(e); }; })(dst));
    src.pipe(dst);
  }
  return observe;
}

function _uploadStages(throttleBps, transforms) {
  var stages = [];
  if (throttleBps) stages.push(_throttleStream(throttleBps));
  for (var i = 0; i < transforms.length; i++) stages.push(_resolveStage(transforms[i]));
  return stages;
}

function _pipeThrottledUpload(body, sink, stages, emitUpload, onBodyError) {
  var source = (body && typeof body.pipe === "function")
    ? body
    : nodeStream.Readable.from(Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8"));
  var observe = new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      if (emitUpload) emitUpload(chunk.length);
      cb(null, chunk);
    },
  });
  var chain = [source].concat(stages).concat([observe]);
  for (var c = 0; c < chain.length - 1; c++) {
    var s = chain[c], d = chain[c + 1];
    s.on("error", (function (dd) { return function (e) { dd.destroy(e); }; })(d));
    s.pipe(d);
  }
  observe.on("error", onBodyError);
  observe.pipe(sink);
}

function request(opts) {
  if (!opts || !opts.url) {
    return Promise.reject(_makeError(opts && opts.errorClass, "http-client/bad-arg", "url is required", true));
  }

  if (opts.before !== undefined) {
    if (!Array.isArray(opts.before) || !opts.before.every(function (f) { return typeof f === "function"; })) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "before must be an array of functions", true));
    }
  }
  if (opts.after !== undefined) {
    if (!Array.isArray(opts.after) || !opts.after.every(function (f) { return typeof f === "function"; })) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "after must be an array of functions", true));
    }
  }
  if (opts.onUploadProgress !== undefined && typeof opts.onUploadProgress !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
      "onUploadProgress must be a function", true));
  }
  if (opts.onDownloadProgress !== undefined && typeof opts.onDownloadProgress !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
      "onDownloadProgress must be a function", true));
  }
  if (opts.onChunk !== undefined && typeof opts.onChunk !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
      "onChunk must be a function (chunk: Buffer) -> void", true));
  }
  if (opts.maxBytesPerSec !== undefined && opts.maxBytesPerSec !== null) {
    if (typeof opts.maxBytesPerSec !== "number" || !isFinite(opts.maxBytesPerSec) || opts.maxBytesPerSec <= 0) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "maxBytesPerSec must be a positive finite number (bytes/sec)", true));
    }
  }
  var _dlChk = _coerceTransforms(opts.downloadTransform, opts.errorClass, "downloadTransform");
  if (_dlChk.err) return Promise.reject(_dlChk.err);
  var _ulChk = _coerceTransforms(opts.uploadTransform, opts.errorClass, "uploadTransform");
  if (_ulChk.err) return Promise.reject(_ulChk.err);
  if (opts.jar !== undefined && opts.jar !== null) {
    if (typeof opts.jar !== "object" ||
        typeof opts.jar.cookieHeaderFor !== "function" ||
        typeof opts.jar.setFromResponse !== "function") {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "jar must be a b.httpClient.cookieJar.create() instance", true));
    }
  }
  // the cache hot path itself is drop-silent (any failure falls back
  if (opts.cache !== undefined && opts.cache !== null) {
    if (typeof opts.cache !== "object" ||
        typeof opts.cache._lookup !== "function" ||
        typeof opts.cache._evaluateStorage !== "function" ||
        typeof opts.cache._store !== "function") {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "cache must be a b.httpClient.cache.create() instance", true));
    }
  }

  if (Array.isArray(opts.before) && opts.before.length > 0) {
    var working = opts;
    for (var bi = 0; bi < opts.before.length; bi++) {
      var ret;
      try { ret = opts.before[bi](working); }
      catch (e) {
        return Promise.reject(_makeError(opts.errorClass, "http-client/before-threw",
          "before[" + bi + "] threw: " + ((e && e.message) || String(e)), true));
      }
      if (ret && typeof ret === "object") working = ret;
    }
    opts = working;
  }

  if (opts.multipart) {
    if (opts.body !== undefined) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "request: pass either { body } or { multipart }, not both", true));
    }
    var built;
    try { built = _buildMultipartBody(opts.multipart); }
    catch (e) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg", e.message, true));
    }
    var mpHeaders = Object.assign({}, opts.headers || {}, {
      "Content-Type": "multipart/form-data; boundary=" + built.boundary,
    });
    if (typeof built.contentLength === "number" && isFinite(built.contentLength)) {
      mpHeaders["Content-Length"] = String(built.contentLength);
    }
    opts = Object.assign({}, opts, {
      method:    opts.method || "POST",
      body:      built.body,
      headers:   mpHeaders,
      multipart: undefined,
    });
  }

  var maxRedirects = (opts.maxRedirects === undefined || opts.maxRedirects === null)
    ? null : opts.maxRedirects;
  if (maxRedirects !== null) {
    if (typeof maxRedirects !== "number" || !isFinite(maxRedirects) || maxRedirects < 0 ||
        Math.floor(maxRedirects) !== maxRedirects) {
      return Promise.reject(_makeError(opts.errorClass, "http-client/bad-arg",
        "maxRedirects must be a non-negative integer or null", true));
    }
  }
  var afterChain = (Array.isArray(opts.after) && opts.after.length > 0) ? opts.after : null;
  function _runAfter(finalOpts, res) {
    if (!afterChain) return res;
    for (var ai = 0; ai < afterChain.length; ai++) {
      try { afterChain[ai](finalOpts, res); }
      catch (_e) { /* after hooks are best-effort — never break the response */ }
    }
    return res;
  }

  if (opts.cache && _cacheEligibleMethod(opts.method) && opts.body == null) {
    return _runWithCache(opts, maxRedirects, _runAfter);
  }

  if (maxRedirects === null || maxRedirects === 0) {
    return _requestSingle(opts).then(function (res) { return _runAfter(opts, res); });
  }

  return _requestWithRedirects(opts, maxRedirects).then(function (boxed) {
    return _runAfter(boxed.finalOpts, boxed.res);
  });
}

function _cacheEligibleMethod(method) {
  var m = String(method || "GET").toUpperCase();
  return m === "GET" || m === "HEAD";
}

function _withCacheHeaders(res, status, ageSeconds, statusHeader) {
  var headers = Object.assign({}, res.headers || {});
  var name = (statusHeader === undefined) ? "x-blamejs-cache" : statusHeader;
  if (name) headers[name] = status;
  if (typeof ageSeconds === "number" && ageSeconds >= 0) {
    headers["age"] = String(Math.floor(ageSeconds));
  }
  return Object.assign({}, res, { headers: headers });
}

function _runWithCache(opts, maxRedirects, runAfter) {
  var cache = opts.cache;
  var method = String(opts.method || "GET").toUpperCase();
  var requestHeaders = opts.headers || {};
  var nowMs = Date.now();

  // 1. Lookup. Cache lookups themselves are drop-silent; on store
  var got = null;
  try { got = cache._lookup(method, opts.url, requestHeaders); }
  catch (_e) { got = null; }

  function _doNetwork() {
    if (maxRedirects === null || maxRedirects === 0) {
      return _requestSingle(opts).then(function (res) {
        return { finalOpts: opts, res: res };
      });
    }
    return _requestWithRedirects(opts, maxRedirects);
  }

  if (!got) {
    try { cache._emit("httpclient.cache.miss", "allowed", { url: String(opts.url), method: method }); }
    catch (_e) { /* drop-silent */ }
    try { cache._obsEvent("httpclient.cache.miss", 1, { method: method }); }
    catch (_e) { /* drop-silent */ }
    return _doNetwork().then(function (boxed) {
      _maybeStore(cache, method, opts.url, requestHeaders, boxed.res);
      return runAfter(boxed.finalOpts, _withCacheHeaders(boxed.res, "MISS", undefined, cache.statusHeader));
    });
  }

  var entry = got.entry;
  var evaluation;
  try { evaluation = cache._evaluateStored(entry, nowMs); }
  catch (_e) {
    try { cache.invalidate(method, opts.url, requestHeaders); }
    catch (_e2) { /* drop-silent */ }
    return _doNetwork().then(function (boxed) {
      _maybeStore(cache, method, opts.url, requestHeaders, boxed.res);
      return runAfter(boxed.finalOpts, _withCacheHeaders(boxed.res, "MISS", undefined, cache.statusHeader));
    });
  }

  if (evaluation.fresh && !evaluation.mustRevalidate) {
    var age = cache._serveAgeSeconds(entry, nowMs);
    try { cache._emit("httpclient.cache.hit", "allowed", { url: String(opts.url), method: method, ageMs: evaluation.ageMs }); }
    catch (_e) { /* drop-silent */ }
    try { cache._obsEvent("httpclient.cache.hit", 1, { method: method }); }
    catch (_e) { /* drop-silent */ }
    var hitRes = {
      statusCode: entry.statusCode,
      headers:    Object.assign({}, entry.headers),
      body:       Buffer.isBuffer(entry.body) ? Buffer.from(entry.body) : entry.body,
      cacheStatus: "HIT",
    };
    return Promise.resolve(runAfter(opts, _withCacheHeaders(hitRes, "HIT", age, cache.statusHeader)));
  }

  var ageOverFresh = Math.max(0, evaluation.ageMs - evaluation.freshnessMs);
  var swrApplies   = !evaluation.mustRevalidate &&
                     ageOverFresh < Math.max(evaluation.swrWindowMs, evaluation.defaultStaleMs);

  if (swrApplies && cache.revalidateInBackground) {
    var ageStale = cache._serveAgeSeconds(entry, nowMs);
    try { cache._emit("httpclient.cache.stale", "allowed", { url: String(opts.url), method: method, ageMs: evaluation.ageMs, mode: "swr" }); }
    catch (_e) { /* drop-silent */ }
    try { cache._obsEvent("httpclient.cache.stale", 1, { method: method, mode: "swr" }); }
    catch (_e) { /* drop-silent */ }
    var staleRes = {
      statusCode: entry.statusCode,
      headers:    Object.assign({}, entry.headers),
      body:       Buffer.isBuffer(entry.body) ? Buffer.from(entry.body) : entry.body,
      cacheStatus: "STALE",
    };
    setImmediate(function () {
      _revalidate(cache, method, opts, entry, requestHeaders).catch(function () {
        /* background revalidation best-effort; swallow */
      });
    });
    return Promise.resolve(runAfter(opts, _withCacheHeaders(staleRes, "STALE", ageStale, cache.statusHeader)));
  }

  return _revalidate(cache, method, opts, entry, requestHeaders).then(function (rev) {
    if (rev.kind === "not-modified") {
      var ageRev = cache._serveAgeSeconds(rev.refreshed || entry, Date.now());
      var revRes = {
        statusCode: (rev.refreshed || entry).statusCode,
        headers:    Object.assign({}, (rev.refreshed || entry).headers),
        body:       Buffer.isBuffer((rev.refreshed || entry).body)
                      ? Buffer.from((rev.refreshed || entry).body)
                      : (rev.refreshed || entry).body,
        cacheStatus: "REVALIDATED",
      };
      return runAfter(opts, _withCacheHeaders(revRes, "REVALIDATED", ageRev, cache.statusHeader));
    }
    if (rev.kind === "fresh-response") {
      _maybeStore(cache, method, opts.url, requestHeaders, rev.res);
      return runAfter(rev.finalOpts || opts, _withCacheHeaders(rev.res, "MISS", undefined, cache.statusHeader));
    }
    var sieMs = (evaluation.sieWindowMs || 0);
    if (sieMs > 0 && ageOverFresh < sieMs) {
      var ageErr = cache._serveAgeSeconds(entry, Date.now());
      try { cache._emit("httpclient.cache.stale", "allowed", { url: String(opts.url), method: method, ageMs: evaluation.ageMs, mode: "sie", error: rev.error && rev.error.message }); }
      catch (_e) { /* drop-silent */ }
      try { cache._obsEvent("httpclient.cache.stale", 1, { method: method, mode: "sie" }); }
      catch (_e) { /* drop-silent */ }
      var sieRes = {
        statusCode: entry.statusCode,
        headers:    Object.assign({}, entry.headers),
        body:       Buffer.isBuffer(entry.body) ? Buffer.from(entry.body) : entry.body,
        cacheStatus: "STALE",
      };
      return runAfter(opts, _withCacheHeaders(sieRes, "STALE", ageErr, cache.statusHeader));
    }
    return Promise.reject(rev.error);
  });
}

function _conditionalHeaders(entry) {
  var out = {};
  if (entry.etag) out["If-None-Match"] = entry.etag;
  if (entry.lastModified) out["If-Modified-Since"] = entry.lastModified;
  return out;
}

function _revalidate(cache, method, opts, entry, requestHeaders) {
  var conditional = _conditionalHeaders(entry);
  var nextOpts = Object.assign({}, opts, {
    headers: Object.assign({}, requestHeaders, conditional),
    responseMode:    "always-resolve",
    cache:           undefined,
  });
  var maxRedirects = (opts.maxRedirects === undefined || opts.maxRedirects === null)
    ? null : opts.maxRedirects;
  var p = (maxRedirects === null || maxRedirects === 0)
    ? _requestSingle(nextOpts).then(function (res) { return { finalOpts: nextOpts, res: res }; })
    : _requestWithRedirects(nextOpts, maxRedirects);

  return p.then(function (boxed) {
    var res = boxed.res;
    if (res.statusCode === C.HTTP.STATUS.NOT_MODIFIED) {
      var refreshed;
      try { refreshed = cache._refreshFrom304(entry, res.headers); }
      catch (_e) { refreshed = entry; }
      try { cache._emit("httpclient.cache.revalidated", "allowed", { url: String(opts.url), method: method }); }
      catch (_e) { /* drop-silent */ }
      try { cache._obsEvent("httpclient.cache.revalidated", 1, { method: method }); }
      catch (_e) { /* drop-silent */ }
      return { kind: "not-modified", refreshed: refreshed };
    }
    return { kind: "fresh-response", res: res, finalOpts: boxed.finalOpts };
  }, function (err) {
    return { kind: "error", error: err };
  });
}

// Decide whether to store, then store. Drop-silent on any internal
function _maybeStore(cache, method, url, requestHeaders, res) {
  try {
    var evaluation = cache._evaluateStorage(method, res.statusCode, res.headers || {}, requestHeaders);
    if (!evaluation.cacheable) return;
    cache._store(method, url, requestHeaders, res.statusCode, res.headers || {}, res.body, evaluation);
  } catch (_e) { /* drop-silent — caching never breaks the request */ }
}

function _requestWithRedirects(opts, hopsLeft) {
  var originalUrl = opts.url;
  var originalOrigin = null;
  try {
    var u0 = safeUrl.parse(opts.url, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
    originalOrigin = u0.protocol + "//" + u0.host;
  } catch (_e) { /* request() will reject on next hop's parse */ }
  var onRedirect = typeof opts.onRedirect === "function" ? opts.onRedirect : null;
  var hopCount = 0;

  var current = Object.assign({}, opts, { _resolveOnRedirect: true });
  function _follow() {
    return _requestSingle(current).then(function (res) {
      if (!REDIRECT_STATUSES.has(res.statusCode) || hopsLeft <= 0) {
        return { finalOpts: current, res: res };
      }
      var loc = res.headers && (res.headers.location || res.headers.Location);
      if (!loc) return { finalOpts: current, res: res };
      hopsLeft -= 1;
      hopCount += 1;

      var nextUrl;
      try {
        nextUrl = Reflect.construct(URL, [loc, current.url]).toString();
      }
      catch (_e) {
        return Promise.reject(_makeError(opts.errorClass, "http-client/bad-redirect",
          "Location header invalid URL: " + loc, true));
      }

      var nextHeaders = current.headers || {};
      var nextOrigin;
      try {
        var nu = safeUrl.parse(nextUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
        nextOrigin = nu.protocol + "//" + nu.host;
      } catch (_e) { /* request() will reject when it tries to parse */ }
      var headersStripped = false;
      if (originalOrigin && nextOrigin && nextOrigin !== originalOrigin) {
        nextHeaders = _stripCrossOriginAuth(nextHeaders);
        headersStripped = true;
      }

      var nextMethod = current.method || "GET";
      var nextBody = current.body;
      if (res.statusCode === C.HTTP.STATUS.SEE_OTHER ||
          ((res.statusCode === C.HTTP.STATUS.MOVED_PERMANENTLY || res.statusCode === C.HTTP.STATUS.FOUND) &&
           nextMethod !== "GET" && nextMethod !== "HEAD")) {
        nextMethod = "GET";
        nextBody = undefined;
      }

      function _continueFollow() {
        current = Object.assign({}, current, {
          url:                 nextUrl,
          method:              nextMethod,
          body:                nextBody,
          headers:             nextHeaders,
          _resolveOnRedirect:  true,
        });
        return _follow();
      }

      if (onRedirect) {
        var hookEvent = Object.freeze({
          from:            current.url,
          to:              nextUrl,
          hop:             hopCount,
          statusCode:      res.statusCode,
          headersStripped: headersStripped,
          method:          nextMethod,
        });
        function _redirectAborted(e) {
          return Promise.reject(_makeError(opts.errorClass, "http-client/redirect-aborted",
            "onRedirect hook refused redirect: " + ((e && e.message) || String(e)), true));
        }
        try {
          var hookResult = onRedirect(hookEvent);
          if (hookResult && typeof hookResult.then === "function") {
            return hookResult.then(function () { return _continueFollow(); }, _redirectAborted);
          }
        } catch (e) {
          return _redirectAborted(e);
        }
      }
      return _continueFollow();
    });
  }
  void originalUrl;
  return _follow();
}

function _requestSingle(opts) {
  var u;
  try {
    u = safeUrl.parse(opts.url, {
      allowedProtocols: opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
      errorClass:       opts.errorClass,
    });
  } catch (e) {
    return Promise.reject(e);
  }

  if (Array.isArray(opts.allowedHosts)) {
    var host = u.hostname.toLowerCase();
    var method = (opts.method || "GET").toUpperCase();
    var ok = hostAllowed(host, opts.allowedHosts, method);
    if (!ok) {
      if (opts.audit && typeof opts.audit.safeEmit === "function") {
        try {
          opts.audit.safeEmit({
            action:   "system.httpclient.host_denied",
            outcome:  "denied",
            resource: { kind: "outbound.http", id: host },
            metadata: { method: method, url: opts.url, allowedHostsCount: opts.allowedHosts.length },
          });
        } catch (_e) { /* audit best-effort */ }
      }
      return Promise.reject(_makeError(opts.errorClass, "http-client/host-disallowed",
        "host '" + host + "' not in allowedHosts (method=" + method + ")", true));
    }
  }

  if (opts.jar) {
    var headersWithJar = _attachJarCookie(opts.headers, opts.jar, opts.url);
    if (headersWithJar !== opts.headers) {
      opts = Object.assign({}, opts, { headers: headersWithJar });
    }
  }

  var proxyAgent = null;
  try { proxyAgent = networkProxy.agentFor(u); } catch (_e) { proxyAgent = null; }

  var ssrfPromise;
  if (proxyAgent && opts.allowInternal === true) {
    try {
      ssrfGuard.checkUrlTextual(u, { errorClass: opts.errorClass });
    } catch (eMeta) {
      return Promise.reject(eMeta);
    }
    ssrfPromise = Promise.resolve({ ips: null });
  } else {
    ssrfPromise = ssrfGuard.checkUrl(u, {
      allowInternal: opts.allowInternal,
      errorClass:    opts.errorClass,
    });
  }

  return ssrfPromise.then(function (ssrfResult) {
    var ips = ssrfResult && ssrfResult.ips;
    if (opts.agent) {
      return _requestH1({
        kind:   "h1",
        lib:    u.protocol === "https:" ? https : http,
        agent:  opts.agent,
        lookup: _pinnedLookupFor(ips),
      }, u, opts);
    }

    if (proxyAgent) {
      return _requestH1({
        kind:   "h1",
        lib:    u.protocol === "https:" ? https : http,
        agent:  proxyAgent,
        lookup: undefined,
      }, u, opts);
    }

    return _getTransport(u, opts, ips).then(function (transport) {
      if (transport.kind === "h2") return _requestH2(transport, u, opts);
      return _requestH1(transport, u, opts);
    });
  });
}

function _requestH1(transport, u, opts) {
  var throttleBps = opts.maxBytesPerSec || null;
  var downloadTransforms = _coerceTransforms(opts.downloadTransform, opts.errorClass, "downloadTransform").ok;
  var uploadTransforms = _coerceTransforms(opts.uploadTransform, opts.errorClass, "uploadTransform").ok;
  return new Promise(function (resolve, reject) {
    var method = (opts.method || "GET").toUpperCase();
    var headers = Object.assign({}, opts.headers || {});
    var responseMode = opts.responseMode || "buffer";
    var maxResponseBytes = opts.maxResponseBytes ||
      (method === "GET" ? DEFAULT_GET_CAP : DEFAULT_CONTROL_PLANE_CAP);
    var observer = typeof opts.observer === "function" ? opts.observer : null;
    var startedAt = Date.now();

    var signal = safeAsync.withTimeoutSignal(opts.signal || null, opts.timeoutMs);
    if (signal && signal.aborted) {
      var r0 = signal.reason;
      var code0 = (r0 && r0.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
      reject(_makeError(opts.errorClass, code0,
        (r0 && r0.message) || "request aborted before start", false));
      return;
    }

    if (Buffer.isBuffer(opts.body) && uploadTransforms.length === 0) {
      headers["Content-Length"] = opts.body.length;
    }
    if (!headers["Accept-Encoding"] && !headers["accept-encoding"]) {
      headers["Accept-Encoding"] = "identity";
    }

    var reqOpts = {
      method:   method,
      hostname: u.hostname,
      port:     u.port || _defaultPortFor(u),
      path:     u.pathname + (u.search || ""),
      headers:  headers,
      agent:    transport.agent,
      timeout:  typeof opts.idleTimeoutMs === "number" ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS,
    };
    if (transport.lookup) reqOpts.lookup = transport.lookup;

    if (observer) observer("request:start", { method: method, url: String(opts.url), protocol: "h1" });

    var settled = false;
    function _resolve(value) { if (!settled) { settled = true; resolve(value); } }
    function _reject(err)    { if (!settled) { settled = true; reject(err); } }

    var onUploadProgress   = typeof opts.onUploadProgress === "function" ? opts.onUploadProgress : null;
    var onDownloadProgress = typeof opts.onDownloadProgress === "function" ? opts.onDownloadProgress : null;
    var onChunk            = typeof opts.onChunk === "function" ? opts.onChunk : null;

    var req = transport.lib.request(reqOpts, function (res) {
      if (observer) observer("response:headers", { statusCode: res.statusCode, headers: res.headers });

      if (opts.jar && res.headers && res.headers["set-cookie"]) {
        try { opts.jar.setFromResponse(opts.url, res.headers["set-cookie"]); }
        catch (_e) { /* jar is best-effort — never break the response */ }
      }

      var dlTotal = null;
      if (res.headers && typeof res.headers["content-length"] === "string") {
        var cl = parseInt(res.headers["content-length"], 10);
        if (!isNaN(cl) && cl >= 0) dlTotal = cl;
      }
      var dlLoaded = 0;
      function _emitDownload(chunkBytes) {
        if (!onDownloadProgress) return;
        dlLoaded += chunkBytes;
        safeAsync.safeInvoke(onDownloadProgress, { loaded: dlLoaded, total: dlTotal });
      }

      if (responseMode === "stream") {
        if (res.statusCode >= 400 && responseMode !== "always-resolve") {
          _rejectStreamHttpError(res, opts.errorClass, res.statusCode, res.statusMessage || "", _reject);
          return;
        }
        var body = _buildDownloadStream(
          res, onDownloadProgress ? _emitDownload : null, onChunk, throttleBps, downloadTransforms);
        return _resolve({ statusCode: res.statusCode, headers: res.headers, body: body });
      }

      var collector = safeBuffer.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      var dlSource = _buildDownloadStream(
        res, onDownloadProgress ? _emitDownload : null, onChunk, throttleBps, downloadTransforms);

      dlSource.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          req.destroy();
          _reject(_makeError(opts.errorClass, "http-client/response-too-large",
            "response body exceeds " + maxResponseBytes + " bytes", true));
          return;
        }
      });
      dlSource.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (observer) observer("response:end", {
          statusCode: res.statusCode,
          durationMs: Date.now() - startedAt,
          bytes:      buf.length,
        });
        if (res.statusCode >= 200 && res.statusCode < 300) {
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else if (opts._resolveOnRedirect && REDIRECT_STATUSES.has(res.statusCode)) {
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else if (responseMode === "always-resolve") {
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else {
          var msg = "HTTP " + res.statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "http-client/http-error", msg,
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
      });
      dlSource.on("error", function (e) {
        if (capExceeded) return;
        if (observer) observer("error", { phase: "response", message: e.message });
        _reject(_makeError(opts.errorClass, e.code || "http-client/res-error", e.message, false));
      });
    });

    req.on("timeout", function () {
      req.destroy();
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "request idle timeout (no data for " + reqOpts.timeout + "ms)", false));
    });

    req.on("error", function (e) {
      var agentTls = (reqOpts.agent && reqOpts.agent.options) || {};
      networkTls().annotateOutboundFailure(e, {
        host:    reqOpts.hostname,
        port:    Number(reqOpts.port),
        tlsOpts: agentTls,
      });
      if (observer) observer("error", { phase: "request", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "http-client/req-error", e.message, false));
    });

    if (signal) {
      var onAbort = function () {
        var r = signal.reason;
        var code = (r && r.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
        var msg = (r && r.message) || "request aborted";
        try { req.destroy(r || new Error(msg)); } catch (_e) { /* best-effort req teardown */ }
        _reject(_makeError(opts.errorClass, code, msg, false));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    var ulTotal = null;
    if (Buffer.isBuffer(opts.body)) ulTotal = opts.body.length;
    else if (typeof opts.body === "string") ulTotal = Buffer.byteLength(opts.body, "utf8");
    var ulLoaded = 0;
    function _emitUpload(chunkBytes) {
      if (!onUploadProgress) return;
      ulLoaded += chunkBytes;
      safeAsync.safeInvoke(onUploadProgress, { loaded: ulLoaded, total: ulTotal });
    }

    var ulStages = _uploadStages(throttleBps, uploadTransforms);
    if (opts.body != null && opts.body !== "" && ulStages.length > 0) {
      _pipeThrottledUpload(opts.body, req, ulStages,
        onUploadProgress ? _emitUpload : null,
        function (e) {
          try { req.destroy(); } catch (_) { /* best-effort req teardown */ }
          _reject(_makeError(opts.errorClass, "http-client/req-body-error",
            "request body stream error: " + e.message, false));
        });
    } else if (opts.body && typeof opts.body.pipe === "function") {
      if (onUploadProgress) {
        opts.body.on("data", function (c) { _emitUpload(c.length); });
      }
      opts.body.on("error", function (e) {
        try { req.destroy(); } catch (_) { /* best-effort req teardown */ }
        _reject(_makeError(opts.errorClass, "http-client/req-body-error",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(req);
    } else if (Buffer.isBuffer(opts.body) || typeof opts.body === "string") {
      var bodyBuf = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, "utf8");
      if (onUploadProgress) {
        var CHUNK = C.BYTES.kib(64);
        var off = 0;
        while (off < bodyBuf.length) {
          var slice = bodyBuf.slice(off, Math.min(off + CHUNK, bodyBuf.length));
          req.write(slice);
          _emitUpload(slice.length);
          off += slice.length;
        }
        req.end();
      } else {
        req.end(bodyBuf);
      }
    } else {
      req.end();
    }
  });
}

function _requestH2(transport, u, opts) {
  var throttleBps = opts.maxBytesPerSec || null;
  var downloadTransforms = _coerceTransforms(opts.downloadTransform, opts.errorClass, "downloadTransform").ok;
  var uploadTransforms = _coerceTransforms(opts.uploadTransform, opts.errorClass, "uploadTransform").ok;
  return new Promise(function (resolve, reject) {
    var method = (opts.method || "GET").toUpperCase();
    var responseMode = opts.responseMode || "buffer";
    var maxResponseBytes = opts.maxResponseBytes ||
      (method === "GET" ? DEFAULT_GET_CAP : DEFAULT_CONTROL_PLANE_CAP);
    var observer = typeof opts.observer === "function" ? opts.observer : null;
    var startedAt = Date.now();
    var onChunkH2 = typeof opts.onChunk === "function" ? opts.onChunk : null;

    var signal = safeAsync.withTimeoutSignal(opts.signal || null, opts.timeoutMs);
    if (signal && signal.aborted) {
      var r0 = signal.reason;
      var code0 = (r0 && r0.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
      reject(_makeError(opts.errorClass, code0,
        (r0 && r0.message) || "request aborted before start", false));
      return;
    }

    var headers = _toH2Headers(method, u, opts.headers || {});
    if (Buffer.isBuffer(opts.body) && uploadTransforms.length === 0) {
      headers["content-length"] = String(opts.body.length);
    }

    if (observer) observer("request:start", { method: method, url: String(opts.url), protocol: "h2" });

    var stream;
    try {
      stream = transport.session.request(headers, {
        endStream: opts.body == null,
      });
    } catch (e) {
      reject(_makeError(opts.errorClass, e.code || "http-client/h2-request-error", e.message, false));
      return;
    }

    var settled = false;
    function _resolve(v) { if (!settled) { settled = true; resolve(v); } }
    function _reject(e)  { if (!settled) { settled = true; reject(e); } }

    var idleMs = typeof opts.idleTimeoutMs === "number" ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
    stream.setTimeout(idleMs, function () {
      try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) { /* best-effort h2 stream cancel */ }
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "h2 stream idle timeout (no data for " + idleMs + "ms)", false));
    });

    stream.on("response", function (resHeaders) {
      var statusCode = resHeaders[":status"];
      var responseHeaders = _fromH2Headers(resHeaders);

      if (observer) observer("response:headers", { statusCode: statusCode, headers: responseHeaders });

      if (opts.jar && responseHeaders["set-cookie"]) {
        try { opts.jar.setFromResponse(opts.url, responseHeaders["set-cookie"]); }
        catch (_e) { /* jar best-effort */ }
      }

      if (responseMode === "stream") {
        if (statusCode >= 400 && responseMode !== "always-resolve") {
          _rejectStreamHttpError(stream, opts.errorClass, statusCode, "", _reject);
          return;
        }
        var bodyH2 = _buildDownloadStream(stream, null, onChunkH2, throttleBps, downloadTransforms);
        return _resolve({ statusCode: statusCode, headers: responseHeaders, body: bodyH2 });
      }

      var collector = safeBuffer.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      var dlH2 = _buildDownloadStream(stream, null, onChunkH2, throttleBps, downloadTransforms);
      if (dlH2 !== stream) {
        dlH2.on("error", function (e) {
          if (capExceeded) return;
          if (observer) observer("error", { phase: "stream", message: e.message });
          _reject(_makeError(opts.errorClass, e.code || "http-client/h2-stream-error", e.message, false));
        });
      }

      dlH2.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e2) { /* best-effort h2 stream cancel */ }
          _reject(_makeError(opts.errorClass, "http-client/response-too-large",
            "response body exceeds " + maxResponseBytes + " bytes", true));
          return;
        }
      });
      dlH2.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (observer) observer("response:end", {
          statusCode: statusCode,
          durationMs: Date.now() - startedAt,
          bytes:      buf.length,
        });
        if (C.HTTP.success(statusCode)) {
          _resolve({ statusCode: statusCode, headers: responseHeaders, body: buf });
        } else if (responseMode === "always-resolve") {
          _resolve({ statusCode: statusCode, headers: responseHeaders, body: buf });
        } else {
          var msg = "HTTP " + statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "http-client/http-error", msg,
            _isPermanentStatus(statusCode), statusCode));
        }
      });
    });

    stream.on("error", function (e) {
      if (observer) observer("error", { phase: "stream", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "http-client/h2-stream-error", e.message, false));
    });

    if (signal) {
      var onAbort = function () {
        var r = signal.reason;
        var code = (r && r.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
        var msg = (r && r.message) || "request aborted";
        try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) { /* best-effort h2 stream cancel */ }
        _reject(_makeError(opts.errorClass, code, msg, false));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    var ulStagesH2 = _uploadStages(throttleBps, uploadTransforms);
    if (opts.body != null && opts.body !== "" && ulStagesH2.length > 0) {
      _pipeThrottledUpload(opts.body, stream, ulStagesH2, null, function (e) {
        try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch (_) { /* best-effort h2 stream cancel */ }
        _reject(_makeError(opts.errorClass, "http-client/req-body-error",
          "request body stream error: " + e.message, false));
      });
    } else if (opts.body && typeof opts.body.pipe === "function") {
      opts.body.on("error", function (e) {
        try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch (_) { /* best-effort h2 stream cancel */ }
        _reject(_makeError(opts.errorClass, "http-client/req-body-error",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(stream);
    } else if (Buffer.isBuffer(opts.body)) {
      stream.end(opts.body);
    } else if (typeof opts.body === "string") {
      stream.end(Buffer.from(opts.body, "utf8"));
    }
  });
}

var ALLOWED_DOWNLOAD_HASH_ALGS = ["sha3-512", "sha-256", "sha-512", "shake256"];
var DEFAULT_DOWNLOAD_HASH_ALG  = "sha3-512";
var DEFAULT_DOWNLOAD_FILE_MODE = 0o600;

function _hcErr(code, message, statusCode) {
  return new HttpClientError(code, message, true, statusCode);
}

function _validateDownloadOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _hcErr("http-client/bad-opts", "downloadStream: opts must be an object");
  }
  validateOpts.requireNonEmptyString(opts.url, "downloadStream: url",
    HttpClientError, "http-client/bad-opts");
  validateOpts.requireNonEmptyString(opts.dest, "downloadStream: dest",
    HttpClientError, "http-client/bad-opts");
  validateOpts.optionalNonEmptyString(opts.hash, "downloadStream: hash",
    HttpClientError, "http-client/bad-opts");
  if (opts.hash !== undefined && ALLOWED_DOWNLOAD_HASH_ALGS.indexOf(opts.hash) === -1) {
    throw _hcErr("http-client/bad-opts",
      "downloadStream: hash must be one of " + ALLOWED_DOWNLOAD_HASH_ALGS.join(", ") +
      "; got " + JSON.stringify(opts.hash));
  }
  if (opts.expected !== undefined) {
    validateOpts.requireNonEmptyString(opts.expected, "downloadStream: expected",
      HttpClientError, "http-client/bad-opts");
    if (!safeBuffer.isHex(opts.expected)) {
      throw _hcErr("http-client/bad-opts",
        "downloadStream: expected must be a non-empty hex digest");
    }
  }
  validateOpts.optionalPositiveFinite(opts.timeoutMs, "downloadStream: timeoutMs",
    HttpClientError, "http-client/bad-opts");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes,
    "downloadStream: maxBytes", HttpClientError, "http-client/bad-opts", { permanent: true });
}

function _emitAudit(opts, action, outcome, metadata) {
  if (!opts || !opts.audit || typeof opts.audit.safeEmit !== "function") return;
  try {
    opts.audit.safeEmit({
      action:   action,
      outcome:  outcome,
      resource: { kind: "outbound.http", id: String(opts.url || "") },
      metadata: metadata || {},
    });
  } catch (_e) { /* audit best-effort */ }
}

/**
 * @primitive b.httpClient.downloadStream
 * @signature b.httpClient.downloadStream(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.httpClient.request, b.httpClient.uploadMultipartStream, b.atomicFile.ensureDir
 *
 * Streams a remote resource to disk while hashing the bytes in flight,
 * then atomically renames the tmp file to `opts.dest` only after the
 * hash matches `opts.expected` (when supplied). Hash mismatch deletes
 * the tmp file and throws `http-client/hash-mismatch`. Composes through
 * `request({ responseMode: "stream" })` so the SSRF gate, allowedHosts
 * filter, network proxy, and per-origin transport cache all apply.
 *
 * @opts
 *   url:       <required>,    // string — source
 *   dest:      <required>,    // absolute filesystem path — final landing
 *   hash:      "sha3-512",    // "sha3-512" | "sha-256" | "sha-512" | "shake256"
 *   expected:  undefined,     // hex digest; when set, verified before rename
 *   timeoutMs: undefined,     // wall-clock cap
 *   maxBytes:  undefined,     // positive integer — abort past this size
 *   audit:     undefined,     // audit sink with safeEmit({...})
 *
 * @example
 *   var result = await b.httpClient.downloadStream({
 *     url:      "https://example.com/release.tar.gz",
 *     dest:     "/var/lib/blamejs/release.tar.gz",
 *     hash:     "sha3-512",
 *     expected: "9f86d081884c7d65...d4e5",
 *   });
 *   // → { statusCode: 200, bytesWritten: 1048576, hash: "9f86d081884c7d65...d4e5" }
 */
async function downloadStream(opts) {
  _validateDownloadOpts(opts);
  var alg     = opts.hash || DEFAULT_DOWNLOAD_HASH_ALG;
  var dest    = opts.dest;
  var tmpPath = dest + ".tmp-" + bCrypto.generateToken(C.BYTES.bytes(8));
  var dir     = nodePath.dirname(dest);

  atomicFile.ensureDir(dir);

  var res;
  try {
    res = await request({
      method:           "GET",
      url:              opts.url,
      headers:          opts.headers || {},
      responseMode:     "stream",
      timeoutMs:        opts.timeoutMs,
      idleTimeoutMs:    opts.idleTimeoutMs,
      signal:           opts.signal,
      agent:            opts.agent,
      allowedProtocols: opts.allowedProtocols,
      allowedHosts:     opts.allowedHosts,
      allowInternal:    opts.allowInternal,
      audit:            opts.audit,
      errorClass:       HttpClientError,
    });
  } catch (e) {
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "request-failed", message: e.message, code: e.code,
    });
    throw e;
  }

  if (res.statusCode < 200 || res.statusCode >= 300) {
    if (res.body && typeof res.body.resume === "function") res.body.resume();
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "non-2xx", statusCode: res.statusCode,
    });
    throw _hcErr("http-client/http-error",
      "downloadStream: upstream returned HTTP " + res.statusCode, res.statusCode);
  }

  var hasher  = nodeCrypto.createHash(alg);
  var counter = new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      hasher.update(chunk);
      counter.bytesWritten += chunk.length;
      if (typeof opts.maxBytes === "number" && counter.bytesWritten > opts.maxBytes) {
        return cb(_hcErr("http-client/response-too-large",
          "downloadStream: response body exceeds maxBytes " + opts.maxBytes, res.statusCode));
      }
      cb(null, chunk);
    },
  });
  counter.bytesWritten = 0;

  var fileStream = nodeFs.createWriteStream(tmpPath, {
    mode:  DEFAULT_DOWNLOAD_FILE_MODE,
    flags: nodeFs.constants.O_WRONLY | nodeFs.constants.O_CREAT |
           nodeFs.constants.O_EXCL | (nodeFs.constants.O_NOFOLLOW || 0),
  });

  try {
    await streamPromises.pipeline(res.body, counter, fileStream);
  } catch (e) {
    try { nodeFs.unlinkSync(tmpPath); } catch (_u) { /* best-effort cleanup */ }
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "pipeline-failed", message: e.message, code: e.code,
    });
    if (e && e.isHttpClientError) throw e;
    throw _hcErr(e.code || "http-client/pipeline-failed",
      "downloadStream: pipeline failed: " + (e.message || String(e)), res.statusCode);
  }

  try {
    var fd = nodeFs.openSync(tmpPath, "r+");
    try { atomicFile.fsync(fd); } finally { try { nodeFs.closeSync(fd); } catch (_c) { /* best-effort fd close */ } }
  } catch (_fe) { /* fsync best-effort */ }

  var actualHex = hasher.digest("hex");
  if (typeof opts.expected === "string" && opts.expected.length > 0) {
    var expected = opts.expected.toLowerCase();
    if (actualHex.toLowerCase() !== expected) {
      try { nodeFs.unlinkSync(tmpPath); } catch (_u) { /* best-effort cleanup */ }
      _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
        reason: "hash-mismatch", alg: alg, expected: expected, actual: actualHex,
        statusCode: res.statusCode, bytesWritten: counter.bytesWritten,
      });
      throw _hcErr("http-client/hash-mismatch",
        "downloadStream: hash mismatch (alg=" + alg + ", expected=" + expected +
        ", actual=" + actualHex + ")", res.statusCode);
    }
  }

  try {
    atomicFile.renameWithRetry(tmpPath, dest);
    atomicFile.fsyncDir(dir);
  } catch (e) {
    try { nodeFs.unlinkSync(tmpPath); } catch (_u) { /* best-effort cleanup */ }
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "rename-failed", message: e.message,
    });
    throw _hcErr("http-client/rename-failed",
      "downloadStream: rename to " + dest + " failed: " + e.message, res.statusCode);
  }

  _emitAudit(opts, "system.httpclient.download_stream.completed", "allowed", {
    statusCode:   res.statusCode,
    bytesWritten: counter.bytesWritten,
    alg:          alg,
    hashVerified: typeof opts.expected === "string" && opts.expected.length > 0,
  });

  return {
    statusCode:   res.statusCode,
    bytesWritten: counter.bytesWritten,
    hash:         actualHex,
  };
}

function _validateUploadOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _hcErr("http-client/bad-opts", "uploadMultipartStream: opts must be an object");
  }
  validateOpts.requireNonEmptyString(opts.url, "uploadMultipartStream: url",
    HttpClientError, "http-client/bad-opts");
  if (!opts.file || typeof opts.file !== "object") {
    throw _hcErr("http-client/bad-opts", "uploadMultipartStream: file must be an object");
  }
  validateOpts.requireNonEmptyString(opts.file.path, "uploadMultipartStream: file.path",
    HttpClientError, "http-client/bad-opts");
  validateOpts.requireNonEmptyString(opts.file.fieldName, "uploadMultipartStream: file.fieldName",
    HttpClientError, "http-client/bad-opts");
  if (opts.fields !== undefined && (typeof opts.fields !== "object" || opts.fields === null || Array.isArray(opts.fields))) {
    throw _hcErr("http-client/bad-opts", "uploadMultipartStream: fields must be an object");
  }
  validateOpts.optionalPositiveFinite(opts.timeoutMs, "uploadMultipartStream: timeoutMs",
    HttpClientError, "http-client/bad-opts");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes,
    "uploadMultipartStream: maxBytes", HttpClientError, "http-client/bad-opts", { permanent: true });
}

/**
 * @primitive b.httpClient.uploadMultipartStream
 * @signature b.httpClient.uploadMultipartStream(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.httpClient.request, b.httpClient.downloadStream
 *
 * POSTs a file body via `multipart/form-data` without buffering the
 * file in memory. Streams from disk through the request body using
 * `fs.createReadStream` + `node:stream/promises` pipeline. Throws
 * `http-client/missing-file` when `opts.file.path` doesn't exist or
 * isn't a regular file. Composes through `request()` so SSRF gating,
 * proxy routing, and the per-origin transport cache apply unchanged.
 *
 * @opts
 *   url:       <required>,    // string — destination
 *   file:      <required>,    // { path, fieldName, filename?, contentType? }
 *   fields:    undefined,     // object — extra form fields { name: value, ... }
 *   timeoutMs: undefined,     // wall-clock cap
 *   maxBytes:  undefined,     // positive integer — refuse files larger than this
 *   audit:     undefined,     // audit sink with safeEmit({...})
 *
 * @example
 *   var res = await b.httpClient.uploadMultipartStream({
 *     url:    "https://example.com/upload",
 *     file:   {
 *       path:        "/var/lib/blamejs/release.tar.gz",
 *       fieldName:   "artifact",
 *       contentType: "application/gzip",
 *     },
 *     fields: { releaseTag: "v1.2.3" },
 *   });
 *   // → { statusCode: 200, headers: { ... }, body: <Buffer> }
 */
async function uploadMultipartStream(opts) {
  _validateUploadOpts(opts);

  var filePath = opts.file.path;
  var st;
  try { st = nodeFs.statSync(filePath); }
  catch (e) {
    _emitAudit(opts, "system.httpclient.upload_stream.refused", "denied", {
      reason: "missing-file", path: filePath, message: e.message,
    });
    throw _hcErr("http-client/missing-file",
      "uploadMultipartStream: file.path not readable: " + e.message);
  }
  if (!st.isFile()) {
    _emitAudit(opts, "system.httpclient.upload_stream.refused", "denied", {
      reason: "not-a-regular-file", path: filePath,
    });
    throw _hcErr("http-client/missing-file",
      "uploadMultipartStream: file.path is not a regular file");
  }

  var filename = (typeof opts.file.filename === "string" && opts.file.filename.length > 0)
    ? opts.file.filename
    : nodePath.basename(filePath);
  var contentType = (typeof opts.file.contentType === "string" && opts.file.contentType.length > 0)
    ? opts.file.contentType
    : "application/octet-stream";

  var fileSpec = {
    field:       opts.file.fieldName,
    filePath:    filePath,
    filename:    filename,
    contentType: contentType,
  };

  var res;
  try {
    res = await request({
      method:           "POST",
      url:              opts.url,
      headers:          opts.headers || {},
      multipart:        { fields: opts.fields || {}, files: [fileSpec], streaming: true },
      timeoutMs:        opts.timeoutMs,
      idleTimeoutMs:    opts.idleTimeoutMs,
      signal:           opts.signal,
      agent:            opts.agent,
      allowedProtocols: opts.allowedProtocols,
      allowedHosts:     opts.allowedHosts,
      allowInternal:    opts.allowInternal,
      maxResponseBytes: opts.maxResponseBytes,
      audit:            opts.audit,
      errorClass:       HttpClientError,
    });
  } catch (e) {
    _emitAudit(opts, "system.httpclient.upload_stream.refused", "denied", {
      reason: "request-failed", message: e.message, code: e.code,
    });
    throw e;
  }

  _emitAudit(opts, "system.httpclient.upload_stream.completed", "allowed", {
    statusCode: res.statusCode,
    fileBytes:  st.size,
    fieldName:  opts.file.fieldName,
    filename:   filename,
  });

  return {
    statusCode: res.statusCode,
    response:   res,
  };
}

function _resetForTest() {
  _transports.forEach(function (t) {
    if (t && t.kind === "h1" && t.agent && typeof t.agent.destroy === "function") {
      try { t.agent.destroy(); } catch (_e) { /* best-effort agent teardown */ }
    }
    if (t && t.kind === "h2" && t.session) {
      _tearDownH2Session(t.session);
    }
  });
  _transports.clear();
}

function _getCachedTransportCount() {
  return _transports.size;
}

function _getCachedTransportKind(url) {
  var u = url instanceof URL ? url : safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
  var t = _transports.get(_originKey(u));
  if (!t) return null;
  if (t.then) return "pending";
  return t.kind;
}

module.exports = {
  request:                    request,
  pinnedClient:               pinnedClient,
  downloadStream:             downloadStream,
  uploadMultipartStream:      uploadMultipartStream,
  configurePool:              configurePool,
  DEFAULT_CONTROL_PLANE_CAP:  DEFAULT_CONTROL_PLANE_CAP,
  DEFAULT_GET_CAP:            DEFAULT_GET_CAP,
  DEFAULT_AGENT_OPTS:         DEFAULT_AGENT_OPTS,
  ALLOWED_DOWNLOAD_HASH_ALGS: ALLOWED_DOWNLOAD_HASH_ALGS,
  _resetForTest:              _resetForTest,
  _getCachedTransportCount:   _getCachedTransportCount,
  _getCachedTransportKind:    _getCachedTransportKind,
  _pinnedLookupForTest:       _pinnedLookupFor,
};
