"use strict";
/**
 * HTTP client primitive — Promise-returning, AbortSignal-aware,
 * connection-pooled, streaming-capable, HTTP/2-capable.
 *
 * Built on node:http, node:https, and node:http2. Zero npm runtime
 * dependency. Same caller surface for h1 and h2; the protocol version
 * is negotiated per-origin via ALPN (h2 preferred, h1 fallback).
 *
 * Single entry point:
 *
 *   await httpClient.request({
 *     method,             // string, default GET
 *     url,                // string or URL
 *     headers,            // object, default {}
 *     body,               // Buffer | string | Readable | undefined
 *     timeoutMs,          // wall-clock cap (caller-chosen, no default)
 *     idleTimeoutMs,      // zero-progress idle cap (default 30s)
 *     responseMode,       // "buffer" (default) | "stream" | "always-resolve"
 *     maxResponseBytes,   // for buffer mode (default 16 MiB control,
 *                         //   1 GiB GET — operators with > 1 GiB
 *                         //   stored objects must use stream mode)
 *     onChunk,            // (chunk: Buffer) => void — fires for each
 *                         //   response chunk in BOTH buffer and stream
 *                         //   modes. Use to hash bytes during pipe-to-disk
 *                         //   without an extra Transform pass.
 *     signal,             // AbortSignal — propagated to req/stream
 *     errorClass,         // FrameworkError subclass
 *     observer,           // optional (stage, info) => void hook
 *     agent,              // override per-origin pool (h1 only)
 *     preferH2,           // bool — for cleartext h2 (h2c). HTTPS origins
 *                         //   already attempt h2 via ALPN; this flag is
 *                         //   for HTTP origins (internal services, tests)
 *                         //   that explicitly speak h2c.
 *   })
 *     → { statusCode, headers, body }
 *
 * Protocol selection:
 *
 *   - HTTPS origin: TLS handshake with ALPN ['h2', 'http/1.1']. If
 *     server picks 'h2', subsequent requests to that origin multiplex
 *     over the same h2 session. If server picks 'h1', the cached
 *     transport is an https.Agent with keepAlive.
 *
 *   - HTTP origin without preferH2: h1 only.
 *   - HTTP origin with preferH2: h2c (cleartext h2). No ALPN — caller
 *     attests the server speaks h2c. Used by internal services and
 *     test fixtures (mock h2 server).
 *
 * Per-origin transport cache:
 *
 *   key = "<protocol>//<hostname>:<port>"
 *   value = { kind: 'h1', lib, agent } | { kind: 'h2', session }
 *
 *   While a transport is being negotiated (TLS handshake / h2 connect)
 *   the cache holds the in-flight Promise so concurrent calls to a
 *   new origin coalesce onto the same connection.
 *
 * Resiliency:
 *   - Wall-clock + idle timeouts (split — slow-progress vs zero-progress)
 *   - AbortSignal propagated to req.destroy / stream.close
 *   - TLS 1.3 minimum + PQC ecdhCurve preference
 *   - h2 session GOAWAY / error → cache eviction; next request reconnects
 *   - h2 stream cancellation via NGHTTP2_CANCEL on abort (clean, not destroy)
 *   - Request-body stream errors propagated to Promise rejection
 */

var http  = require("http");
var https = require("https");
var http2 = require("http2");
var nodeStream = require("node:stream");
var { URL } = require("url");
var C = require("./constants");
var crypto = require("./crypto");
var pqcAgent = require("./pqc-agent");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var networkProxy = require("./network-proxy");
var { FrameworkError } = require("./framework-error");

// Per-origin transport cache. Entry is either the resolved transport
// object or a pending Promise that resolves to one. The Promise form
// lets concurrent calls to a new origin coalesce on the same connect.
//
// Transport shapes the cache currently holds:
//
//   { kind: "h1", lib, agent }            — node:http(s) + keepAlive Agent
//   { kind: "h2", session }               — node:http2 ClientHttp2Session
//
// Reserved for the future (when node:http3 ships stable — currently
// behind --experimental-quic, no http3 module yet):
//
//   { kind: "h3", session }               — node:http3 ClientHttp3Session
//
// Adding the h3 case won't change the caller-facing surface: ALPN
// negotiation gains "h3" as the highest-preference protocol over QUIC,
// _getTransport branches on the resolved transport, and a new
// _requestH3 mirrors _requestH2's stream-based shape. h3's design
// gives 0-RTT first-class (vs. h1/h2 where 0-RTT is opaque under
// node's TLS layer — see TLS_SESSION_RESUMPTION_NOTES below).
var _transports = new Map();

// TLS session resumption notes — what's automatic vs. what's not
// exposed by Node's public API:
//
//   keepAlive Agent (h1) / long-lived ClientHttp2Session (h2) means
//   the WARM-CONNECTION case is zero-handshake — better than 0-RTT.
//   We pay the TLS handshake once per origin, then amortize.
//
//   When a pool socket is recycled, node's tls layer caches session
//   tickets and does 1-RTT resumption automatically. We don't
//   expose 0-RTT (early_data) — node's https.Agent has no clean API
//   for it, and 0-RTT is REPLAY-RISKY for non-idempotent requests
//   (server can't distinguish original from replay until the
//   handshake completes). Operators who need 0-RTT for a specific
//   idempotent path can pass their own agent via opts.agent.
//
//   QUIC/h3 changes this calculus: 0-RTT is a first-class feature
//   built into the protocol, with replay protection at the QUIC
//   layer. The framework's `b.httpClient` is HTTP/1.1 + HTTP/2 only;
//   operators wanting h3 wire their own client.

// Pool tuning for the HTTP-client transport cache. Keep-alive is
// shorter than the standalone pqc-agent default (1s vs 30s) because
// the cache layer manages its own warm-connection reuse and we want
// idle sockets reaped quickly between bursts. ecdhCurve / minVersion
// come from pqc-agent and cannot be set here — the framework's
// PQC-only TLS posture is one place, in lib/pqc-agent.js.
//
// Operators tune at boot via `b.httpClient.configurePool({...})`.
// Existing transports stay on whichever values were active when they
// were created — reconfigure runs before any outbound request to take
// effect on the per-origin cache.
var DEFAULT_AGENT_OPTS = Object.freeze({
  keepAlive:        true,
  keepAliveMsecs:   C.TIME.seconds(1),
  maxSockets:       C.BYTES.bytes(16),
  maxFreeSockets:   C.BYTES.bytes(8),
  scheduling:       "lifo",
});

var HTTP_CLIENT_AGENT_OPTS = Object.assign({}, DEFAULT_AGENT_OPTS);

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
  function _requirePositiveInt(name, value) {
    if (typeof value !== "number" || !isFinite(value) || value <= 0 || Math.floor(value) !== value) {
      throw new Error("httpClient.configurePool: " + name +
        " must be a positive integer, got " + JSON.stringify(value));
    }
  }
  if (opts.maxSockets     !== undefined) _requirePositiveInt("maxSockets",     opts.maxSockets);
  if (opts.maxFreeSockets !== undefined) _requirePositiveInt("maxFreeSockets", opts.maxFreeSockets);
  if (opts.keepAliveMsecs !== undefined) _requirePositiveInt("keepAliveMsecs", opts.keepAliveMsecs);
  if (opts.keepAlive      !== undefined && typeof opts.keepAlive !== "boolean") {
    throw new Error("httpClient.configurePool: keepAlive must be a boolean");
  }
  if (opts.scheduling     !== undefined && opts.scheduling !== "lifo" && opts.scheduling !== "fifo") {
    throw new Error("httpClient.configurePool: scheduling must be 'lifo' or 'fifo'");
  }
  Object.assign(HTTP_CLIENT_AGENT_OPTS, opts);
  // Existing transports keep their old values (Agent constructor
  // copies). Drop the per-origin cache + tear down idle sockets so
  // subsequent requests build fresh transports with the new opts.
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

// HTTP/2 session teardown — see lib/http2-teardown.js for the full
// rationale. Centralised so any future sink / pool teardown gets the
// same close()-then-destroy() discipline.
var _tearDownH2Session = require("./http2-teardown").tearDownH2Session;

// h2 session connect options. Same TLS posture as h1 Agent.
var DEFAULT_H2_TLS_OPTS = {
  ALPNProtocols:    ["h2", "http/1.1"],
  ecdhCurve:        C.TLS_GROUP_CURVE_STR,
  minVersion:       "TLSv1.3",
};

var DEFAULT_CONTROL_PLANE_CAP = C.BYTES.mib(16);
var DEFAULT_GET_CAP           = C.BYTES.gib(1);
var DEFAULT_IDLE_TIMEOUT_MS   = C.TIME.seconds(30);

// h2 session idle close. After this much idle time with no streams,
// close the session — long-running processes don't pin one TLS
// connection forever.
var H2_SESSION_IDLE_TIMEOUT_MS = C.TIME.minutes(5);

// IANA-assigned default ports per RFC 9110 §4.2.
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
  // HTTPS path goes through pqcAgent.create so the framework's PQC-only
  // posture is enforced via the single primitive. Cleartext HTTP stays
  // on http.Agent because there's no TLS posture to enforce.
  var agent = u.protocol === "https:"
    ? pqcAgent.create(HTTP_CLIENT_AGENT_OPTS)
    : new lib.Agent(HTTP_CLIENT_AGENT_OPTS);
  return { kind: "h1", lib: lib, agent: agent, lookup: _pinnedLookupFor(ips) };
}

// Build a `lookup` callback that pins outbound connections to IPs the
// SSRF guard already validated. Closes the TOCTOU window between
// SSRF resolution and the kernel's connect — without this, a hostile
// (or compromised) DNS could rotate the answer between guard-check
// and connect-time and route the request to a private / metadata IP
// that bypassed the gate. ips comes from `ssrfGuard.checkUrl` — its
// classification ran on these exact addresses.
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

// Connect an h2 session to an HTTPS origin via ALPN. If the server picks
// http/1.1, fall back to an h1 transport for that origin.
function _connectHttpsWithAlpn(u, ips) {
  return new Promise(function (resolve, reject) {
    var connectOpts = Object.assign({}, DEFAULT_H2_TLS_OPTS);
    var pinned = _pinnedLookupFor(ips);
    if (pinned) connectOpts.lookup = pinned;
    var session = http2.connect(u.protocol + "//" + u.host, connectOpts);
    var settled = false;
    function _done(t)   { if (!settled) { settled = true; resolve(t); } }
    function _fail(err) { if (!settled) { settled = true; reject(err); } }

    session.once("connect", function () {
      var alpn = session.alpnProtocol;
      if (alpn === "h2") {
        _wireH2Session(session, _originKey(u));
        _done({ kind: "h2", session: session });
        return;
      }
      // Server picked http/1.1 — close the h2 session, return h1 transport.
      _tearDownH2Session(session);
      _done(_makeH1Transport(u, ips));
    });
    session.once("error", function (err) {
      _tearDownH2Session(session);
      _fail(err);
    });
  });
}

// Connect an h2c session (cleartext h2). No ALPN, no fallback — caller
// has attested via preferH2 that the server speaks h2c.
function _connectH2c(u, ips) {
  return new Promise(function (resolve, reject) {
    var connectOpts = {};
    var pinned = _pinnedLookupFor(ips);
    if (pinned) connectOpts.lookup = pinned;
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

// Common h2 session wiring — idle close + cache eviction on error/close.
function _wireH2Session(session, key) {
  session.setTimeout(H2_SESSION_IDLE_TIMEOUT_MS, function () {
    _tearDownH2Session(session);
  });
  session.once("close", function () { _transports.delete(key); });
  session.once("error", function () { _transports.delete(key); });
  session.once("goaway", function () {
    // Server signalling 'no new streams' — let in-flight finish, evict cache.
    _transports.delete(key);
  });
}

// Async transport selection. Returns Promise<transport>. `ips` is the
// validated address list returned by `ssrfGuard.checkUrl`; the transport
// uses it to pin connections so a hostile DNS rebind can't redirect
// the actual TCP connect to a private / metadata IP.
function _getTransport(u, opts, ips) {
  var key = _originKey(u);
  var cached = _transports.get(key);
  if (cached) {
    // Could be a resolved transport OR a pending Promise. Cached
    // transports keep whatever IP pinning was set when they were
    // first created — subsequent SSRF checks still gate the request,
    // and the transport's TCP socket is bound to its original IP.
    return Promise.resolve(cached);
  }

  var promise;
  if (u.protocol === "https:") {
    promise = _connectHttpsWithAlpn(u, ips);
  } else if (opts && opts.preferH2) {
    promise = _connectH2c(u, ips);
  } else {
    // HTTP without preferH2 → h1 only.
    promise = Promise.resolve(_makeH1Transport(u, ips));
  }

  // Cache the in-flight Promise immediately so concurrent calls
  // coalesce. On resolve, replace with the transport. On reject, evict.
  _transports.set(key, promise);
  promise.then(
    function (t)   { _transports.set(key, t); },
    function (_err) { _transports.delete(key); }
  );

  return promise;
}

function _makeError(errorClass, code, message, permanent, statusCode) {
  if (!errorClass) return new FrameworkError(message, code);
  return new errorClass(code, message, permanent, statusCode);
}

// RFC 9110 §15.5 4xx codes that are NOT permanent (request-timeout,
// too-early, too-many-requests — operator should retry).
var STATUS_REQUEST_TIMEOUT   = C.BYTES.bytes(408);
var STATUS_TOO_EARLY         = 425;
var STATUS_TOO_MANY_REQUESTS = 429;

function _isPermanentStatus(statusCode) {
  if (statusCode >= 400 && statusCode < 500) {
    return statusCode !== STATUS_REQUEST_TIMEOUT &&
           statusCode !== STATUS_TOO_EARLY &&
           statusCode !== STATUS_TOO_MANY_REQUESTS;
  }
  return false;
}

// h2 sends headers as lowercased keys plus :method / :path / :scheme /
// :authority pseudo-headers. Convert from h1-shaped headers.
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
    // h2 forbids the connection-specific headers
    if (lk === "connection" || lk === "host" ||
        lk === "keep-alive" || lk === "transfer-encoding" ||
        lk === "upgrade" || lk === "proxy-connection") continue;
    if (lk === "accept-encoding") sawAcceptEncoding = true;
    h2Headers[lk] = headers[k];
  }
  // CVE-2026-22036 mitigation — same identity default as the h1 path.
  // Refuse compressed responses unless the operator explicitly opts in.
  if (!sawAcceptEncoding) h2Headers["accept-encoding"] = "identity";
  return h2Headers;
}

function _fromH2Headers(h2Headers) {
  // Strip pseudo-headers from the response — caller doesn't want them
  // mixed with normal headers.
  var out = {};
  for (var k in h2Headers) {
    if (!Object.prototype.hasOwnProperty.call(h2Headers, k)) continue;
    if (k.charAt(0) === ":") continue;
    out[k] = h2Headers[k];
  }
  return out;
}

// ---- request() ----

var REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// http-client-cookie-jar is exposed on b.httpClient.cookieJar via index.js.
// http-client itself only consumes the jar shape passed by operators via
// the request opt; no direct require is needed here.

// Merge a jar-derived Cookie header with any caller-supplied Cookie
// header. Operators who override Cookie explicitly always win — the jar
// supplements rather than replaces.
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

// Build a multipart/form-data body from { fields, files } shape.
// Mirrors the wire format that lib/middleware/body-parser.js's multipart
// parser accepts so round-trip from one blamejs app's outbound to
// another's inbound is exact.
//
// Two output shapes:
//
//   - { boundary, body: Buffer, contentLength }
//       When every file entry is a Buffer / string (size known
//       up front) and no operator opted into streaming, the result
//       is a fully-materialized body. Smaller payloads avoid the
//       streaming overhead and let HTTP/1.1 KeepAlive reuse with a
//       known Content-Length.
//
//   - { boundary, body: Readable, contentLength }
//       When at least one file entry is `{ filePath }` / `{ stream }`
//       OR opts.streaming === true, the result is a Readable that
//       emits boundary headers + content + CRLF in order. Avoids the
//       Buffer.concat() OOM class on large uploads. contentLength is
//       a finite number when every source's size is statically
//       resolvable (Buffer length, fs.statSync().size, opts.size on
//       a stream entry); null otherwise — caller falls back to
//       chunked transfer.
//
// File entry shapes (all require `field`):
//
//   { field, content: Buffer | string }       — in-memory (existing)
//   { field, filePath: string }               — stream-from-disk
//   { field, stream: Readable, size?: number } — operator-supplied stream
//
// `filename` and `contentType` apply to all three shapes; for
// `filePath` entries, `filename` defaults to path.basename(filePath).
function _buildMultipartBody(spec) {
  var boundary = "----blamejs-mp-" + crypto.generateToken(C.BYTES.bytes(16));
  var CRLF = "\r\n";
  var fs = require("fs");                                             // allow:inline-require — only on multipart paths that touch the filesystem
  var path = require("path");                                         // allow:inline-require — same
  var nodeStream = require("stream");                                 // allow:inline-require — Readable subclass only when streaming

  // Each entry is { headerBytes, source } where source is one of:
  //   { kind: "buffer", buf: Buffer }
  //   { kind: "filePath", filePath: string, size: number }
  //   { kind: "stream", stream: Readable, size: number | null }
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

  function _pushField(name, value) {
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("multipart: field name must be a non-empty string");
    }
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
      try { st = fs.statSync(file.filePath); }
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

  // All-buffer fast path — return a fully-materialized body when no
  // streaming sources are involved AND the operator didn't ask for
  // streaming explicitly. Existing callers that pass small in-memory
  // payloads keep the buffer codepath.
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

  // Streaming path — produce a Readable from an async iterator that
  // yields the bytes for each entry in order.
  var crlfBuf = Buffer.from(CRLF, "utf8");
  async function* _iter() {
    for (var ix = 0; ix < entries.length; ix++) {
      var entry = entries[ix];
      yield entry.header;
      if (entry.source.kind === "buffer") {
        yield entry.source.buf;
      } else if (entry.source.kind === "filePath") {
        var rs = fs.createReadStream(entry.source.filePath);
        try {
          for await (var chunk of rs) yield chunk;
        } finally {
          try { rs.destroy(); } catch (_e) { /* best-effort cleanup */ }
        }
      } else {
        // operator-supplied stream
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

// Headers stripped on cross-origin redirect to defend against accidental
// credential exfiltration. Lower-case for header-map comparison.
var SENSITIVE_HEADERS_LC = ["authorization", "cookie", "proxy-authorization"];

function _stripCrossOriginAuth(headers) {
  var out = {};
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    if (SENSITIVE_HEADERS_LC.indexOf(keys[i].toLowerCase()) !== -1) continue;
    out[keys[i]] = headers[keys[i]];
  }
  return out;
}

function request(opts) {
  if (!opts || !opts.url) {
    return Promise.reject(_makeError(opts && opts.errorClass, "BAD_ARG", "url is required", true));
  }

  // Validate before/after shapes early — throw at call site if the
  // operator passed something un-callable so the bug surfaces here
  // rather than inside the request loop.
  if (opts.before !== undefined) {
    if (!Array.isArray(opts.before) || !opts.before.every(function (f) { return typeof f === "function"; })) {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
        "before must be an array of functions", true));
    }
  }
  if (opts.after !== undefined) {
    if (!Array.isArray(opts.after) || !opts.after.every(function (f) { return typeof f === "function"; })) {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
        "after must be an array of functions", true));
    }
  }
  if (opts.onUploadProgress !== undefined && typeof opts.onUploadProgress !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
      "onUploadProgress must be a function", true));
  }
  if (opts.onDownloadProgress !== undefined && typeof opts.onDownloadProgress !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
      "onDownloadProgress must be a function", true));
  }
  if (opts.onChunk !== undefined && typeof opts.onChunk !== "function") {
    return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
      "onChunk must be a function (chunk: Buffer) -> void", true));
  }
  if (opts.jar !== undefined && opts.jar !== null) {
    if (typeof opts.jar !== "object" ||
        typeof opts.jar.cookieHeaderFor !== "function" ||
        typeof opts.jar.setFromResponse !== "function") {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
        "jar must be a b.httpClient.cookieJar.create() instance", true));
    }
  }

  // before interceptors — run in array order. Each may return a modified
  // opts object (or return nothing to leave the running opts as-is).
  // Caller-set defaults / observability / auth header injection lands
  // here. Synchronous to keep the request hot path simple; async
  // pre-flight work (e.g. token refresh) belongs in the route handler
  // before httpClient.request is even called.
  if (Array.isArray(opts.before) && opts.before.length > 0) {
    var working = opts;
    for (var bi = 0; bi < opts.before.length; bi++) {
      var ret;
      try { ret = opts.before[bi](working); }
      catch (e) {
        return Promise.reject(_makeError(opts.errorClass, "BEFORE_THREW",
          "before[" + bi + "] threw: " + ((e && e.message) || String(e)), true));
      }
      if (ret && typeof ret === "object") working = ret;
    }
    opts = working;
  }

  // Multipart shorthand: { multipart: { fields, files } } expands to
  // body + Content-Type with the boundary parameter. Mutually exclusive
  // with caller-supplied body / Content-Type.
  if (opts.multipart) {
    if (opts.body !== undefined) {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
        "request: pass either { body } or { multipart }, not both", true));
    }
    var built;
    try { built = _buildMultipartBody(opts.multipart); }
    catch (e) {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG", e.message, true));
    }
    var mpHeaders = Object.assign({}, opts.headers || {}, {
      "Content-Type": "multipart/form-data; boundary=" + built.boundary,
    });
    // Content-Length is set when the framework can statically resolve
    // every source's byte size. Otherwise the framework omits the
    // header and Node's HTTP layer falls back to chunked transfer —
    // valid HTTP/1.1, requires no operator opt-in.
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

  // maxRedirects:
  //   undefined → today's behavior (no follow). Caller inspects 3xx.
  //   null      → today's behavior (explicit). Same as undefined.
  //   0         → no follow, but 3xx returned to caller (alias of null).
  //   N         → follow up to N hops; 3xx with no Location returned as-is.
  var maxRedirects = (opts.maxRedirects === undefined || opts.maxRedirects === null)
    ? null : opts.maxRedirects;
  if (maxRedirects !== null) {
    if (typeof maxRedirects !== "number" || !isFinite(maxRedirects) || maxRedirects < 0 ||
        Math.floor(maxRedirects) !== maxRedirects) {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
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

  if (maxRedirects === null || maxRedirects === 0) {
    return _requestSingle(opts).then(function (res) { return _runAfter(opts, res); });
  }

  return _requestWithRedirects(opts, maxRedirects).then(function (boxed) {
    return _runAfter(boxed.finalOpts, boxed.res);
  });
}

function _requestWithRedirects(opts, hopsLeft) {
  var originalUrl = opts.url;
  var originalOrigin = null;
  try {
    var u0 = safeUrl.parse(opts.url, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
    originalOrigin = u0.protocol + "//" + u0.host;
  } catch (_e) { /* request() will reject on next hop's parse */ }
  // onRedirect: function ({ from, to, hop, headersStripped, statusCode }) — called
  // BEFORE each follow. Operator can mutate the next-hop URL or abort
  // the redirect by throwing. Async hooks are awaited.
  var onRedirect = typeof opts.onRedirect === "function" ? opts.onRedirect : null;
  var hopCount = 0;

  var current = Object.assign({}, opts, { _resolveOnRedirect: true });
  function _follow() {
    return _requestSingle(current).then(function (res) {
      if (!REDIRECT_STATUSES.has(res.statusCode) || hopsLeft <= 0) {
        return { finalOpts: current, res: res };
      }
      var loc = res.headers && (res.headers.location || res.headers.Location);
      if (!loc) return { finalOpts: current, res: res };  // 3xx with no Location — operator handles
      hopsLeft -= 1;
      hopCount += 1;

      // Resolve relative Location against the just-fetched URL (the URL
      // of the request that produced the redirect, which may itself be a
      // post-redirect URL).
      var nextUrl;
      try {
        // Resolve relative Location against current URL using Node's URL
        // base-URL form. Re-validate the resolved absolute through safeUrl
        // immediately below.
        nextUrl = Reflect.construct(URL, [loc, current.url]).toString();
      }
      catch (_e) {
        return Promise.reject(_makeError(opts.errorClass, "BAD_REDIRECT",
          "Location header invalid URL: " + loc, true));
      }

      // Cross-origin auth-header strip.
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

      // 303 → always GET; body dropped. 301/302 → historical clients
      // also coerce non-GET bodies (we follow that convention). 307/308
      // → preserve method + body.
      var nextMethod = current.method || "GET";
      var nextBody = current.body;
      if (res.statusCode === 303 ||
          ((res.statusCode === 301 || res.statusCode === 302) &&
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

      // Caller-supplied redirect hook fires here. The hook can throw
      // (sync) or reject (async) to abort the follow with a custom
      // error; otherwise we proceed to the next hop. We pre-bind the
      // values the hook gets and pass them in a frozen object so a
      // caller can't mutate the in-flight pipeline by side-effect.
      if (onRedirect) {
        var hookEvent = Object.freeze({
          from:            current.url,
          to:              nextUrl,
          hop:             hopCount,
          statusCode:      res.statusCode,
          headersStripped: headersStripped,
          method:          nextMethod,
        });
        try {
          var hookResult = onRedirect(hookEvent);
          if (hookResult && typeof hookResult.then === "function") {
            return hookResult.then(function () { return _continueFollow(); });
          }
        } catch (e) {
          return Promise.reject(_makeError(opts.errorClass, "REDIRECT_ABORTED",
            "onRedirect hook refused redirect: " + ((e && e.message) || String(e)), true));
        }
      }
      return _continueFollow();
    });
  }
  void originalUrl;
  return _follow();
}

function _requestSingle(opts) {
  // Validate scheme + shape via url-safe. Default is HTTPS-only — the
  // framework refuses to silently drop bytes on the wire as cleartext.
  // Callers with cleartext endpoints (h2c, internal services, test
  // fixtures) explicitly opt in via opts.allowedProtocols
  // (safeUrl.ALLOW_HTTP_ALL accepts both http: and https:).
  var u;
  try {
    u = safeUrl.parse(opts.url, {
      allowedProtocols: opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
      errorClass:       opts.errorClass,
    });
  } catch (e) {
    return Promise.reject(e);
  }

  // Optional outbound destination allowlist. When opts.allowedHosts
  // is set, only URLs whose hostname is on the list are permitted.
  // Layer above safeUrl (scheme/userinfo gate) and above ssrfGuard
  // (IP-class gate) — operators with strict egress policies pin the
  // outbound destinations the app is allowed to talk to so a
  // compromised process can't reach arbitrary upstreams.
  //
  // Entry forms (each entry is a string OR an object):
  //   "api.partner.com"            — exact host match
  //   ".partner.com"               — suffix match: "api.partner.com" yes,
  //                                  "evilpartner.com" no
  //   "*.partner.com"              — same as ".partner.com" (DNS-glob shape
  //                                  operators expect from firewall configs)
  //   { host: "api.x.com", methods: ["GET","HEAD"] }
  //                                — method-restricted entry; methods omitted
  //                                  = any method
  //
  // A disallowed call rejects with HOST_DISALLOWED AND emits an
  // audit event when opts.audit is wired (operator gets a structured
  // signal that the application tried to reach somewhere it shouldn't).
  if (Array.isArray(opts.allowedHosts) && opts.allowedHosts.length > 0) {
    var host = u.hostname.toLowerCase();
    var method = (opts.method || "GET").toUpperCase();
    var ok = false;
    for (var ai = 0; ai < opts.allowedHosts.length; ai++) {
      var entry = opts.allowedHosts[ai];
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
      // Normalise "*.x.com" to ".x.com" for the suffix match path.
      if (allow.charAt(0) === "*" && allow.charAt(1) === ".") allow = allow.slice(1);
      var matched = false;
      if (allow.charAt(0) === ".") {
        if (host === allow.slice(1) || host.endsWith(allow)) matched = true;
      } else if (host === allow) {
        matched = true;
      }
      if (!matched) continue;
      if (allowedMethods !== null && allowedMethods.indexOf(method) === -1) continue;
      ok = true;
      break;
    }
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
      return Promise.reject(_makeError(opts.errorClass, "HOST_DISALLOWED",
        "host '" + host + "' not in allowedHosts (method=" + method + ")", true));
    }
  }

  // Attach jar-derived Cookie header BEFORE the request fires; record
  // Set-Cookie response headers AFTER. Both halves run when opts.jar
  // is set; redirect-following naturally re-runs both paths per hop
  // because each hop calls _requestSingle.
  if (opts.jar) {
    var headersWithJar = _attachJarCookie(opts.headers, opts.jar, opts.url);
    if (headersWithJar !== opts.headers) {
      opts = Object.assign({}, opts, { headers: headersWithJar });
    }
  }

  // SSRF gate — refuse private / loopback / link-local / cloud-metadata
  // / reserved IP destinations by default. The returned `ips` are
  // threaded into transport creation so the actual TCP connect pins
  // to those exact addresses, closing the DNS-rebinding TOCTOU window.
  return ssrfGuard.checkUrl(u, {
    allowInternal: opts.allowInternal,
    errorClass:    opts.errorClass,
  }).then(function (ssrfResult) {
    var ips = ssrfResult && ssrfResult.ips;
    // Caller-supplied agent bypasses transport cache (h1 only). The
    // operator owns the agent's connection pool — we still pass the
    // pinned lookup through per-request so the SSRF check's IPs win.
    if (opts.agent) {
      return _requestH1({
        kind:   "h1",
        lib:    u.protocol === "https:" ? https : http,
        agent:  opts.agent,
        lookup: _pinnedLookupFor(ips),
      }, u, opts);
    }

    var proxyAgent = null;
    try { proxyAgent = networkProxy.agentFor(u); } catch (_e) { proxyAgent = null; }
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

// ---- _requestH1: existing node:http(s) path ----

function _requestH1(transport, u, opts) {
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

    if (Buffer.isBuffer(opts.body)) {
      headers["Content-Length"] = opts.body.length;
    }
    // CVE-2026-22036 mitigation — refuse compressed responses by
    // default. The framework's http-client returns raw bytes capped
    // at maxResponseBytes; if a server sends gzip/br/zstd the cap is
    // on-wire bytes only, and any operator-side decompression is the
    // operator's responsibility to bound. Identity by default closes
    // the decompression-bomb amplification class. Operators who DO
    // want compressed responses opt in by passing an explicit
    // Accept-Encoding header (lowercase or canonical form).
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
    // Pin DNS to the IPs the SSRF guard validated. Closes the
    // rebinding TOCTOU between guard-check and actual TCP connect.
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

      // Save Set-Cookie into the jar (if wired) BEFORE delivering the
      // response object — operator inspecting the response can already
      // count on the jar carrying the new state.
      if (opts.jar && res.headers && res.headers["set-cookie"]) {
        try { opts.jar.setFromResponse(opts.url, res.headers["set-cookie"]); }
        catch (_e) { /* jar is best-effort — never break the response */ }
      }

      // Download total: Content-Length when present, null otherwise.
      var dlTotal = null;
      if (res.headers && typeof res.headers["content-length"] === "string") {
        var cl = parseInt(res.headers["content-length"], 10);
        if (!isNaN(cl) && cl >= 0) dlTotal = cl;
      }
      var dlLoaded = 0;
      function _emitDownload(chunkBytes) {
        if (!onDownloadProgress) return;
        dlLoaded += chunkBytes;
        try { onDownloadProgress({ loaded: dlLoaded, total: dlTotal }); }
        catch (_e) { /* progress hooks are best-effort */ }
      }

      if (responseMode === "stream") {
        if (res.statusCode >= 400 && responseMode !== "always-resolve") {
          res.resume();
          return _reject(_makeError(opts.errorClass, "HTTP_ERROR",
            "HTTP " + res.statusCode + " " + (res.statusMessage || ""),
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
        if (onDownloadProgress || onChunk) {
          // Wrap the stream so chunks emit progress + onChunk to the
          // operator. The framework's contract is to hand back the
          // response stream unmodified; fix-up via a passthrough keeps
          // that contract while observing the chunk sizes. onChunk
          // gets the buffer itself (for hash-as-you-go); a throw from
          // it is caught and dropped so a hash-mismatch detector can
          // raise without breaking the response stream — caller
          // surfaces the error through their own pipe handler.
          var passthrough = new nodeStream.PassThrough();
          res.on("data", function (chunk) {
            _emitDownload(chunk.length);
            if (onChunk) {
              try { onChunk(chunk); }
              catch (_e) { /* operator-supplied hook — drop-silent */ }
            }
            passthrough.write(chunk);
          });
          res.on("end",  function () { passthrough.end(); });
          res.on("error", function (e) { passthrough.destroy(e); });
          return _resolve({ statusCode: res.statusCode, headers: res.headers, body: passthrough });
        }
        return _resolve({ statusCode: res.statusCode, headers: res.headers, body: res });
      }

      var collector = safeBuffer.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      res.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          req.destroy();
          _reject(_makeError(opts.errorClass, "RESPONSE_TOO_LARGE",
            "response body exceeds " + maxResponseBytes + " bytes", true));
          return;
        }
        _emitDownload(chunk.length);
        if (onChunk) {
          try { onChunk(chunk); }
          catch (_e) { /* operator-supplied hook — drop-silent */ }
        }
      });
      res.on("end", function () {
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
          // Redirect-following layer needs the response object intact so
          // it can inspect Location and re-issue. The caller-facing
          // request() never sets _resolveOnRedirect — operator code that
          // didn't ask for redirect-following keeps seeing 3xx as errors.
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else if (responseMode === "always-resolve") {
          // Operator opted in to "give me the full response object
          // regardless of status." Caller branches on statusCode in
          // their own code path — useful for proxies / forwarders /
          // health-checkers / probe libraries that want to surface
          // the upstream response structurally instead of via an
          // error message string.
          _resolve({ statusCode: res.statusCode, headers: res.headers, body: buf });
        } else {
          var msg = "HTTP " + res.statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "HTTP_ERROR", msg,
            _isPermanentStatus(res.statusCode), res.statusCode));
        }
      });
      res.on("error", function (e) {
        if (capExceeded) return;
        if (observer) observer("error", { phase: "response", message: e.message });
        _reject(_makeError(opts.errorClass, e.code || "RES_ERROR", e.message, false));
      });
    });

    req.on("timeout", function () {
      req.destroy();
      _reject(_makeError(opts.errorClass, "ETIMEDOUT",
        "request idle timeout (no data for " + reqOpts.timeout + "ms)", false));
    });

    req.on("error", function (e) {
      if (observer) observer("error", { phase: "request", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "REQ_ERROR", e.message, false));
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

    // Upload progress: emit { loaded, total } as body bytes go to the
    // wire. Buffer / string bodies are sliced into chunks ourselves so
    // operators see incremental progress; Readable bodies emit on each
    // 'data' event from the source stream.
    var ulTotal = null;
    if (Buffer.isBuffer(opts.body)) ulTotal = opts.body.length;
    else if (typeof opts.body === "string") ulTotal = Buffer.byteLength(opts.body, "utf8");
    var ulLoaded = 0;
    function _emitUpload(chunkBytes) {
      if (!onUploadProgress) return;
      ulLoaded += chunkBytes;
      try { onUploadProgress({ loaded: ulLoaded, total: ulTotal }); }
      catch (_e) { /* progress hooks are best-effort */ }
    }

    if (opts.body && typeof opts.body.pipe === "function") {
      if (onUploadProgress) {
        opts.body.on("data", function (c) { _emitUpload(c.length); });
      }
      opts.body.on("error", function (e) {
        try { req.destroy(); } catch (_) { /* best-effort req teardown */ }
        _reject(_makeError(opts.errorClass, "REQ_BODY_ERROR",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(req);
    } else if (Buffer.isBuffer(opts.body) || typeof opts.body === "string") {
      var bodyBuf = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, "utf8");
      if (onUploadProgress) {
        // Chunked write so progress reports land before req.end().
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

// ---- _requestH2: node:http2 path ----

function _requestH2(transport, u, opts) {
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
    if (Buffer.isBuffer(opts.body)) headers["content-length"] = String(opts.body.length);

    if (observer) observer("request:start", { method: method, url: String(opts.url), protocol: "h2" });

    var stream;
    try {
      stream = transport.session.request(headers, {
        endStream: opts.body == null,
      });
    } catch (e) {
      reject(_makeError(opts.errorClass, e.code || "H2_REQUEST_ERROR", e.message, false));
      return;
    }

    var settled = false;
    function _resolve(v) { if (!settled) { settled = true; resolve(v); } }
    function _reject(e)  { if (!settled) { settled = true; reject(e); } }

    // Idle timeout for the stream itself (zero-progress detector).
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

      // Save Set-Cookie to the jar (h2 set-cookie comes through as
      // either a single string or array, same shape as h1).
      if (opts.jar && responseHeaders["set-cookie"]) {
        try { opts.jar.setFromResponse(opts.url, responseHeaders["set-cookie"]); }
        catch (_e) { /* jar best-effort */ }
      }

      if (responseMode === "stream") {
        if (statusCode >= 400 && responseMode !== "always-resolve") {
          stream.resume();
          return _reject(_makeError(opts.errorClass, "HTTP_ERROR",
            "HTTP " + statusCode, _isPermanentStatus(statusCode), statusCode));
        }
        if (onChunkH2) {
          var passthroughH2 = new nodeStream.PassThrough();
          stream.on("data", function (chunk) {
            try { onChunkH2(chunk); }
            catch (_e) { /* operator-supplied hook — drop-silent */ }
            passthroughH2.write(chunk);
          });
          stream.on("end",  function () { passthroughH2.end(); });
          stream.on("error", function (e) { passthroughH2.destroy(e); });
          return _resolve({ statusCode: statusCode, headers: responseHeaders, body: passthroughH2 });
        }
        return _resolve({ statusCode: statusCode, headers: responseHeaders, body: stream });
      }

      var collector = safeBuffer.boundedChunkCollector({ maxBytes: maxResponseBytes });
      var capExceeded = false;

      stream.on("data", function (chunk) {
        if (capExceeded) return;
        try { collector.push(chunk); }
        catch (_e) {
          capExceeded = true;
          try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e2) { /* best-effort h2 stream cancel */ }
          _reject(_makeError(opts.errorClass, "RESPONSE_TOO_LARGE",
            "response body exceeds " + maxResponseBytes + " bytes", true));
          return;
        }
        if (onChunkH2) {
          try { onChunkH2(chunk); }
          catch (_e) { /* operator-supplied hook — drop-silent */ }
        }
      });
      stream.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (observer) observer("response:end", {
          statusCode: statusCode,
          durationMs: Date.now() - startedAt,
          bytes:      buf.length,
        });
        if (statusCode >= 200 && statusCode < 300) {
          _resolve({ statusCode: statusCode, headers: responseHeaders, body: buf });
        } else if (responseMode === "always-resolve") {
          _resolve({ statusCode: statusCode, headers: responseHeaders, body: buf });
        } else {
          var msg = "HTTP " + statusCode + ": " + buf.toString("utf8").slice(0, 500);
          _reject(_makeError(opts.errorClass, "HTTP_ERROR", msg,
            _isPermanentStatus(statusCode), statusCode));
        }
      });
    });

    stream.on("error", function (e) {
      if (observer) observer("error", { phase: "stream", message: e.message });
      _reject(_makeError(opts.errorClass, e.code || "H2_STREAM_ERROR", e.message, false));
    });

    if (signal) {
      var onAbort = function () {
        var r = signal.reason;
        var code = (r && r.name === "TimeoutError") ? "ETIMEDOUT" : "ABORT";
        var msg = (r && r.message) || "request aborted";
        // NGHTTP2_CANCEL is the protocol-level "I gave up" signal —
        // cleaner than destroying the stream.
        try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) { /* best-effort h2 stream cancel */ }
        _reject(_makeError(opts.errorClass, code, msg, false));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    if (opts.body && typeof opts.body.pipe === "function") {
      opts.body.on("error", function (e) {
        try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch (_) { /* best-effort h2 stream cancel */ }
        _reject(_makeError(opts.errorClass, "REQ_BODY_ERROR",
          "request body stream error: " + e.message, false));
      });
      opts.body.pipe(stream);
    } else if (Buffer.isBuffer(opts.body)) {
      stream.end(opts.body);
    } else if (typeof opts.body === "string") {
      stream.end(Buffer.from(opts.body, "utf8"));
    }
    // If body is null/undefined, endStream:true was set in session.request()
  });
}

// ---- Test helpers ----

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

// Diagnostic — returns 'h1' | 'h2' | null for a given URL's cached transport.
function _getCachedTransportKind(url) {
  var u = url instanceof URL ? url : safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
  var t = _transports.get(_originKey(u));
  if (!t) return null;
  if (t.then) return "pending";
  return t.kind;
}

module.exports = {
  request:                    request,
  configurePool:              configurePool,
  DEFAULT_CONTROL_PLANE_CAP:  DEFAULT_CONTROL_PLANE_CAP,
  DEFAULT_GET_CAP:            DEFAULT_GET_CAP,
  DEFAULT_AGENT_OPTS:         DEFAULT_AGENT_OPTS,
  _resetForTest:              _resetForTest,
  _getCachedTransportCount:   _getCachedTransportCount,
  _getCachedTransportKind:    _getCachedTransportKind,
  // Test-only — exposes the SSRF-pinned DNS lookup builder so unit
  // tests can confirm the callback shape matches Node's documented
  // `lookup(hostname, options, callback)` contract.
  _pinnedLookupForTest:       _pinnedLookupFor,
};
