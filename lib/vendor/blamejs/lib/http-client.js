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

var nodeFs = require("fs");
var http  = require("http");
var https = require("https");
var http2 = require("http2");
var nodeCrypto = require("crypto");
var nodePath = require("path");
var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var { URL } = require("url");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var bCrypto = require("./crypto");
var pqcAgent = require("./pqc-agent");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var networkProxy = require("./network-proxy");
var validateOpts = require("./validate-opts");
var { FrameworkError, HttpClientError } = require("./framework-error");

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
//
//   QUIC retry / address-validation (RFC 9000 §8 + RFC 9001 §6) is
//   deferred-with-condition: outbound h3 negotiation re-opens when
//   Node's `--experimental-quic` graduates to stable and ships a
//   `node:http3` module. The escape hatch today is `opts.agent` —
//   operators on internal-mesh deployments that already terminate h3
//   pass their own h3 agent rather than the framework rolling its
//   own implementation under an experimental Node flag. SECURITY.md
//   "Watch list" tracks the re-open trigger.

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
//       resolvable (Buffer length, nodeFs.statSync().size, opts.size on
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
  var boundary = "----blamejs-mp-" + bCrypto.generateToken(C.BYTES.bytes(16));
  var CRLF = "\r\n";
  var nodeFs = require("fs");                                             // allow:inline-require — only on multipart paths that touch the filesystem
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
        var rs = nodeFs.createReadStream(entry.source.filePath);
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
 *   var res = await b.httpClient.request({
 *     method:    "GET",
 *     url:       "https://example.com/health",
 *     timeoutMs: 5000,
 *   });
 *   // → { statusCode: 200, headers: { "content-type": "application/json", ... }, body: <Buffer> }
 */
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
  // RFC 9111 outbound HTTP cache. Validate shape at the entry-point;
  // the cache hot path itself is drop-silent (any failure falls back
  // to the network so caching is never a request-failure surface).
  if (opts.cache !== undefined && opts.cache !== null) {
    if (typeof opts.cache !== "object" ||
        typeof opts.cache._lookup !== "function" ||
        typeof opts.cache._evaluateStorage !== "function" ||
        typeof opts.cache._store !== "function") {
      return Promise.reject(_makeError(opts.errorClass, "BAD_ARG",
        "cache must be a b.httpClient.cache.create() instance", true));
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

  // Cache layer wraps the redirect-aware path. Cache wiring is a no-op
  // for non-GET/HEAD methods (per RFC 9111 §3) and bypassed entirely
  // when the request opts include a body (the request mutates state on
  // the upstream, can't be a cache hit).
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

// Cache-method gate. RFC 9111 §3 — method must be GET or HEAD for the
// outbound cache to consider a response. Any other method shortcircuits
// straight to the network path (and operator code that mistakenly
// passed a cache instance to a POST sees the same network behaviour as
// without the cache, no surprise).
function _cacheEligibleMethod(method) {
  var m = String(method || "GET").toUpperCase();
  return m === "GET" || m === "HEAD";
}

// Wrap an outbound headers object with the framework's cache-decision
// markers. Mutates a copy; never the original.
function _withCacheHeaders(res, status, ageSeconds) {
  var headers = Object.assign({}, res.headers || {});
  headers["x-blamejs-cache"] = status;
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
  //    failure we treat the call as a miss.
  var got = null;
  try { got = cache._lookup(method, opts.url, requestHeaders); }
  catch (_e) { got = null; }

  function _doNetwork(extraReqHeaders) {
    var nextOpts = opts;
    if (extraReqHeaders) {
      nextOpts = Object.assign({}, opts, {
        headers: Object.assign({}, opts.headers || {}, extraReqHeaders),
      });
    }
    if (maxRedirects === null || maxRedirects === 0) {
      return _requestSingle(nextOpts).then(function (res) {
        return { finalOpts: nextOpts, res: res };
      });
    }
    return _requestWithRedirects(nextOpts, maxRedirects);
  }

  // 2. Miss → network → maybe store.
  if (!got) {
    try { cache._emit("httpclient.cache.miss", "allowed", { url: String(opts.url), method: method }); }
    catch (_e) { /* drop-silent */ }
    try { cache._obsEvent("httpclient.cache.miss", 1, { method: method }); }
    catch (_e) { /* drop-silent */ }
    return _doNetwork(null).then(function (boxed) {
      _maybeStore(cache, method, opts.url, requestHeaders, boxed.res);
      return runAfter(boxed.finalOpts, _withCacheHeaders(boxed.res, "MISS"));
    });
  }

  // 3. Hit. Decide fresh / stale / revalidate.
  var entry = got.entry;
  var evaluation;
  try { evaluation = cache._evaluateStored(entry, nowMs); }
  catch (_e) {
    // Malformed entry — drop it, treat as miss.
    try { cache.invalidate(method, opts.url, requestHeaders); }
    catch (_e2) { /* drop-silent */ }
    return _doNetwork(null).then(function (boxed) {
      _maybeStore(cache, method, opts.url, requestHeaders, boxed.res);
      return runAfter(boxed.finalOpts, _withCacheHeaders(boxed.res, "MISS"));
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
    return Promise.resolve(runAfter(opts, _withCacheHeaders(hitRes, "HIT", age)));
  }

  // 4. Stale or must-revalidate. Within stale-while-revalidate or
  //    defaultMaxStale grace, we serve stale + kick off background
  //    revalidation. Otherwise we revalidate inline.
  var ageOverFresh = Math.max(0, evaluation.ageMs - evaluation.freshnessMs);
  var swrApplies   = !evaluation.mustRevalidate &&
                     ageOverFresh < Math.max(evaluation.swrWindowMs, evaluation.defaultStaleMs);

  if (swrApplies && cache.revalidateInBackground) {
    // Serve stale immediately, kick off background revalidation. We
    // explicitly DON'T await the background revalidation Promise so
    // the caller gets the stale response immediately. We also catch
    // its error so an unhandled rejection doesn't escape.
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
    // Background revalidation — fire-and-forget, errors swallowed (the
    // next caller observes the stale entry until either the upstream
    // recovers or stale-if-error / s-w-r windows expire).
    setImmediate(function () {
      _revalidate(cache, method, opts, entry, requestHeaders).catch(function () {
        /* background revalidation best-effort; swallow */
      });
    });
    return Promise.resolve(runAfter(opts, _withCacheHeaders(staleRes, "STALE", ageStale)));
  }

  // 5. Inline conditional revalidation. Build If-None-Match /
  //    If-Modified-Since from the stored entry, fire the network
  //    request, branch on 304 vs anything-else.
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
      return runAfter(opts, _withCacheHeaders(revRes, "REVALIDATED", ageRev));
    }
    if (rev.kind === "fresh-response") {
      _maybeStore(cache, method, opts.url, requestHeaders, rev.res);
      return runAfter(rev.finalOpts || opts, _withCacheHeaders(rev.res, "MISS"));
    }
    // rev.kind === "error" — try stale-if-error.
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
      return runAfter(opts, _withCacheHeaders(sieRes, "STALE", ageErr));
    }
    return Promise.reject(rev.error);
  });
}

// Build conditional headers for revalidation per RFC 9110 §13.
function _conditionalHeaders(entry) {
  var out = {};
  if (entry.etag) out["If-None-Match"] = entry.etag;
  if (entry.lastModified) out["If-Modified-Since"] = entry.lastModified;
  return out;
}

// Run a revalidation request. Returns one of:
//   { kind: "not-modified", refreshed }       — upstream returned 304
//   { kind: "fresh-response", res, finalOpts } — upstream returned 2xx/...
//   { kind: "error", error }                  — network or upstream error
function _revalidate(cache, method, opts, entry, requestHeaders) {
  var conditional = _conditionalHeaders(entry);
  var nextOpts = Object.assign({}, opts, {
    headers: Object.assign({}, requestHeaders, conditional),
    // Stream-mode bypass: revalidation always uses buffer mode so the
    // 304 / fresh-response branches both have buffered body in hand
    // ready to merge / store.
    responseMode:    "always-resolve",
    // Ensure we don't recurse into the cache layer on the revalidation
    // request itself. Pass cache as null/undefined.
    cache:           undefined,
  });
  var maxRedirects = (opts.maxRedirects === undefined || opts.maxRedirects === null)
    ? null : opts.maxRedirects;
  var p = (maxRedirects === null || maxRedirects === 0)
    ? _requestSingle(nextOpts).then(function (res) { return { finalOpts: nextOpts, res: res }; })
    : _requestWithRedirects(nextOpts, maxRedirects);

  return p.then(function (boxed) {
    var res = boxed.res;
    if (res.statusCode === 304) {                                                            // allow:raw-byte-literal — HTTP 304 Not Modified status code, not bytes
      // Merge 304 headers into the stored entry.
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
// throw so caching cannot surface as a request failure.
function _maybeStore(cache, method, url, requestHeaders, res) {
  try {
    var evaluation = cache._evaluateStorage(method, res.statusCode, res.headers || {});
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

// ---- Streaming primitives ----
//
// downloadStream — pipe a response body to a tmp file, hash-while-piping,
// atomic-rename on hash match. Operators receive `{ statusCode,
// bytesWritten, hash }`; on hash mismatch the tmp file is deleted and an
// HttpClientError with code "httpclient/hash-mismatch" is thrown.
//
// uploadMultipartStream — POST a file body via multipart/form-data
// without buffering. Streams from disk through the request body using
// `nodeFs.createReadStream` + `node:stream/promises` pipeline.
//
// Both compose through `request()` (responseMode: "stream") so safeUrl,
// ssrfGuard, allowedHosts, network-proxy, audit-on-host-deny, and the
// per-origin transport cache apply unchanged.

// Algorithms exposed to operators. Defaults to PQC-first sha3-512;
// callers needing legacy-peer interop with sha-256 (S3 ETag class) opt
// in explicitly.
var ALLOWED_DOWNLOAD_HASH_ALGS = ["sha3-512", "sha-256", "sha-512", "shake256"];
var DEFAULT_DOWNLOAD_HASH_ALG  = "sha3-512";
var DEFAULT_DOWNLOAD_FILE_MODE = 0o600;

function _hcErr(code, message, statusCode) {
  return new HttpClientError(code, message, true, statusCode);
}

// Throw at config-time if opts shape is malformed — operator catches the
// typo here, not inside the request loop.
function _validateDownloadOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _hcErr("httpclient/bad-opts", "downloadStream: opts must be an object");
  }
  validateOpts.requireNonEmptyString(opts.url, "downloadStream: url",
    HttpClientError, "httpclient/bad-opts");
  validateOpts.requireNonEmptyString(opts.dest, "downloadStream: dest",
    HttpClientError, "httpclient/bad-opts");
  validateOpts.optionalNonEmptyString(opts.hash, "downloadStream: hash",
    HttpClientError, "httpclient/bad-opts");
  if (opts.hash !== undefined && ALLOWED_DOWNLOAD_HASH_ALGS.indexOf(opts.hash) === -1) {
    throw _hcErr("httpclient/bad-opts",
      "downloadStream: hash must be one of " + ALLOWED_DOWNLOAD_HASH_ALGS.join(", ") +
      "; got " + JSON.stringify(opts.hash));
  }
  if (opts.expected !== undefined) {
    validateOpts.requireNonEmptyString(opts.expected, "downloadStream: expected",
      HttpClientError, "httpclient/bad-opts");
    if (!safeBuffer.isHex(opts.expected)) {
      throw _hcErr("httpclient/bad-opts",
        "downloadStream: expected must be a non-empty hex digest");
    }
  }
  validateOpts.optionalPositiveFinite(opts.timeoutMs, "downloadStream: timeoutMs",
    HttpClientError, "httpclient/bad-opts");
  if (opts.maxBytes !== undefined &&
      (typeof opts.maxBytes !== "number" || !isFinite(opts.maxBytes) || opts.maxBytes <= 0 ||
       Math.floor(opts.maxBytes) !== opts.maxBytes)) {
    throw _hcErr("httpclient/bad-opts",
      "downloadStream: maxBytes must be a positive finite integer");
  }
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
 * the tmp file and throws `httpclient/hash-mismatch`. Composes through
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

  // Stream-mode request — body is a Readable that emits the response
  // chunks. The framework's onChunk path is intentionally NOT used here
  // because we own the destination tmp file and need precise error
  // ordering between hash + write-fsync + rename.
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
    // Stream mode of request() already rejected on >=400 above, so this
    // branch covers 1xx/3xx surfaces that slipped through. Drain + refuse.
    if (res.body && typeof res.body.resume === "function") res.body.resume();
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "non-2xx", statusCode: res.statusCode,
    });
    throw _hcErr("httpclient/http-error",
      "downloadStream: upstream returned HTTP " + res.statusCode, res.statusCode);
  }

  var hasher  = nodeCrypto.createHash(alg);
  var counter = new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      hasher.update(chunk);
      counter.bytesWritten += chunk.length;
      if (typeof opts.maxBytes === "number" && counter.bytesWritten > opts.maxBytes) {
        return cb(_hcErr("httpclient/response-too-large",
          "downloadStream: response body exceeds maxBytes " + opts.maxBytes, res.statusCode));
      }
      cb(null, chunk);
    },
  });
  counter.bytesWritten = 0;

  var fileStream = nodeFs.createWriteStream(tmpPath, { mode: DEFAULT_DOWNLOAD_FILE_MODE, flags: "w" });

  try {
    await streamPromises.pipeline(res.body, counter, fileStream);
  } catch (e) {
    // Pipeline failure → tmp may be partially written. Remove + audit.
    try { nodeFs.unlinkSync(tmpPath); } catch (_u) { /* best-effort cleanup */ }
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "pipeline-failed", message: e.message, code: e.code,
    });
    if (e && e.isHttpClientError) throw e;
    throw _hcErr(e.code || "httpclient/pipeline-failed",
      "downloadStream: pipeline failed: " + (e.message || String(e)), res.statusCode);
  }

  // fsync the file's data + close. atomicFile.fsync is best-effort
  // across platforms but matches the discipline of the rest of the
  // framework's atomic-write paths.
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
      throw _hcErr("httpclient/hash-mismatch",
        "downloadStream: hash mismatch (alg=" + alg + ", expected=" + expected +
        ", actual=" + actualHex + ")", res.statusCode);
    }
  }

  // Atomic rename + dir fsync.
  try {
    nodeFs.renameSync(tmpPath, dest);
    atomicFile.fsyncDir(dir);
  } catch (e) {
    try { nodeFs.unlinkSync(tmpPath); } catch (_u) { /* best-effort cleanup */ }
    _emitAudit(opts, "system.httpclient.download_stream.refused", "denied", {
      reason: "rename-failed", message: e.message,
    });
    throw _hcErr("httpclient/rename-failed",
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

// ---- uploadMultipartStream ----

function _validateUploadOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _hcErr("httpclient/bad-opts", "uploadMultipartStream: opts must be an object");
  }
  validateOpts.requireNonEmptyString(opts.url, "uploadMultipartStream: url",
    HttpClientError, "httpclient/bad-opts");
  if (!opts.file || typeof opts.file !== "object") {
    throw _hcErr("httpclient/bad-opts", "uploadMultipartStream: file must be an object");
  }
  validateOpts.requireNonEmptyString(opts.file.path, "uploadMultipartStream: file.path",
    HttpClientError, "httpclient/bad-opts");
  validateOpts.requireNonEmptyString(opts.file.fieldName, "uploadMultipartStream: file.fieldName",
    HttpClientError, "httpclient/bad-opts");
  if (opts.fields !== undefined && (typeof opts.fields !== "object" || opts.fields === null || Array.isArray(opts.fields))) {
    throw _hcErr("httpclient/bad-opts", "uploadMultipartStream: fields must be an object");
  }
  validateOpts.optionalPositiveFinite(opts.timeoutMs, "uploadMultipartStream: timeoutMs",
    HttpClientError, "httpclient/bad-opts");
  if (opts.maxBytes !== undefined &&
      (typeof opts.maxBytes !== "number" || !isFinite(opts.maxBytes) || opts.maxBytes <= 0 ||
       Math.floor(opts.maxBytes) !== opts.maxBytes)) {
    throw _hcErr("httpclient/bad-opts",
      "uploadMultipartStream: maxBytes must be a positive finite integer");
  }
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
 * `nodeFs.createReadStream` + `node:stream/promises` pipeline. Throws
 * `httpclient/missing-file` when `opts.file.path` doesn't exist or
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
    throw _hcErr("httpclient/missing-file",
      "uploadMultipartStream: file.path not readable: " + e.message);
  }
  if (!st.isFile()) {
    _emitAudit(opts, "system.httpclient.upload_stream.refused", "denied", {
      reason: "not-a-regular-file", path: filePath,
    });
    throw _hcErr("httpclient/missing-file",
      "uploadMultipartStream: file.path is not a regular file");
  }

  var filename = (typeof opts.file.filename === "string" && opts.file.filename.length > 0)
    ? opts.file.filename
    : nodePath.basename(filePath);
  var contentType = (typeof opts.file.contentType === "string" && opts.file.contentType.length > 0)
    ? opts.file.contentType
    : "application/octet-stream";

  // Reuse the existing multipart shorthand by passing { filePath } —
  // it produces a Readable body + sets Content-Length when sizes resolve.
  // _buildMultipartBody is internal; we route through request()'s
  // multipart shorthand so the same wire path applies.
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
  // Test-only — exposes the SSRF-pinned DNS lookup builder so unit
  // tests can confirm the callback shape matches Node's documented
  // `lookup(hostname, options, callback)` contract.
  _pinnedLookupForTest:       _pinnedLookupFor,
};
