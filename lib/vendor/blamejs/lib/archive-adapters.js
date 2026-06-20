"use strict";
/**
 * @module b.archive.adapters
 * @nav    Tools
 * @title  Archive Adapters
 *
 * @intro
 *   Source-bytes adapter contract for the `b.archive.read` family.
 *   Unifies how bytes flow into the reader regardless of where they
 *   live — a local file, an object-store bucket, an HTTP endpoint with
 *   Range support, an in-memory Buffer, or a trusted Readable.
 *
 *   Two contract shapes, picked by the caller's use case:
 *
 *     - **Random-access** — `{ size, range(offset, length) → Buffer }`
 *       Required for the read primitive's CD-walk path (the canonical
 *       adversarial-safe ZIP read). The reader fetches the EOCD
 *       trailer first (last ~64 KiB), walks the central directory,
 *       then per-entry seeks the LFH + compressed bytes. Defends the
 *       LFH/CD-skew + Zip-Slip + zip-bomb classes by validating every
 *       claim before decompressing.
 *
 *     - **Trusted sequential** — `{ readable: <Readable> }`
 *       Forward-scan-only fallback for operators who control both ends
 *       (e.g. piping the framework's own `b.archive.zip().toStream()`
 *       back into a reader 30 seconds later). The reader walks local
 *       file headers in order; the CD/LFH skew defense + the
 *       "entries hidden from LFH but present in CD" attack class are
 *       OFF in this mode because there's no central directory to
 *       compare against. The trust boundary is in the API surface
 *       name — operators reaching for `trustedStream` are declaring
 *       they own the producer.
 *
 *   AbortSignal is propagated end-to-end: every adapter accepts an
 *   `opts.signal` parameter; in-flight `range` calls abort when the
 *   caller cancels. Adapters refuse to return short reads silently —
 *   a 5-byte request that fulfills 3 bytes throws `adapter/short-read`
 *   so the reader can decide whether to refuse the archive or surface
 *   the truncation.
 *
 *   Shipped adapters:
 *
 *     b.archive.adapters.fs(path, opts?)          — local file
 *     b.archive.adapters.buffer(buf, opts?)       — in-memory
 *     b.archive.adapters.objectStore(client, key, opts?)
 *                                                 — composes b.objectStore
 *                                                   Range-GET path
 *     b.archive.adapters.http(url, opts?)         — composes b.httpClient
 *                                                   with Range: bytes= …
 *     b.archive.adapters.trustedStream(readable, opts?)
 *                                                 — Readable fallback
 *
 *   `objectStore` + `http` are composition entry points — operators
 *   wire their own `b.objectStore` client / `b.httpClient` instance in
 *   so the adapter inherits the framework's SSRF guard / TLS posture /
 *   audit chain without duplicating that surface here.
 *
 * @card
 *   Source-bytes adapter contract for the b.archive read family — fs / objectStore / http / buffer / trustedStream.
 */

var nodeFs = require("node:fs");
var nodeStream = require("node:stream");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var { defineClass } = require("./framework-error");

void numericBounds;
void validateOpts;

var AdapterError = defineClass("AdapterError", { alwaysPermanent: true });

// Lazy because httpClient + objectStore pull in TLS / SSRF surface
// the adapter caller may not need (e.g. tests that only use the fs +
// buffer adapters).
var httpClient = lazyRequire(function () { return require("./http-client"); });
void httpClient;

// ---- Shared validation helpers --------------------------------------------

function _assertNonNegativeInteger(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
    throw new AdapterError("adapter/bad-arg",
      label + " must be a non-negative integer (got " + value + ")");
  }
}

function _assertPositiveInteger(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
    throw new AdapterError("adapter/bad-arg",
      label + " must be a positive integer (got " + value + ")");
  }
}

function _checkSignal(signal, where) {
  if (signal && signal.aborted) {
    var reason = signal.reason || new AdapterError("adapter/aborted", where + ": adapter aborted by operator");
    throw reason;
  }
}

// ---- fs adapter -----------------------------------------------------------

/**
 * @primitive b.archive.adapters.fs
 * @signature b.archive.adapters.fs(path, opts?)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.adapters.objectStore, b.archive.adapters.http, b.archive.adapters.buffer
 *
 * Local-file random-access adapter. Opens a read-only file descriptor
 * + fstats the size at adapter-create time so the reader's CD walk
 * can begin with the trailer offset known up-front. Subsequent
 * `range(offset, length)` calls reuse the same fd — operators
 * extracting an archive don't pay a fresh open per range. `close()`
 * is idempotent + safe to call after errors.
 *
 * @opts
 *   signal:   AbortSignal,        // propagates to in-flight read()s
 *
 * @example
 *   var adapter = b.archive.adapters.fs("/var/uploads/payload.zip");
 *   try {
 *     var reader = b.archive.read.zip(adapter);
 *     var entries = await reader.inspect();
 *   } finally {
 *     await adapter.close();
 *   }
 */
function fs(path, opts) {
  if (typeof path !== "string" || path.length === 0) {
    throw new AdapterError("adapter/bad-arg", "fs: path must be a non-empty string");
  }
  opts = opts || {};
  var signal = opts.signal || null;

  var fd = nodeFs.openSync(path, "r");
  var stat = nodeFs.fstatSync(fd);
  var size = stat.size;
  var closed = false;

  function close() {
    if (closed) return;
    closed = true;
    try { nodeFs.closeSync(fd); } catch (_e) { /* drop-silent — file already gone */ }
  }

  function range(offset, length) {
    return new Promise(function (resolve, reject) {
      try {
        _checkSignal(signal, "fs.range");
        _assertNonNegativeInteger(offset, "fs.range: offset");
        _assertPositiveInteger(length, "fs.range: length");
        if (closed) throw new AdapterError("adapter/closed", "fs.range: adapter is closed");
        if (offset + length > size) {
          throw new AdapterError("adapter/out-of-range",
            "fs.range: read past EOF (offset=" + offset + " length=" + length + " size=" + size + ")");
        }
        var buf = Buffer.allocUnsafe(length);
        nodeFs.read(fd, buf, 0, length, offset, function (err, bytesRead) {
          if (err) return reject(err);
          if (bytesRead !== length) {
            return reject(new AdapterError("adapter/short-read",
              "fs.range: short read (requested=" + length + " got=" + bytesRead + ")"));
          }
          resolve(buf);
        });
      } catch (e) { reject(e); }
    });
  }

  return {
    kind:   "random-access",
    name:   "fs",
    size:   size,
    range:  range,
    close:  close,
    signal: signal,
  };
}

// ---- Buffer adapter -------------------------------------------------------

/**
 * @primitive b.archive.adapters.buffer
 * @signature b.archive.adapters.buffer(buf, opts?)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.adapters.fs
 *
 * In-memory random-access adapter — slices a Buffer on `range()`.
 * Useful for tests, small operator-uploaded payloads already in
 * memory, and round-tripping `b.archive.zip().toBuffer()` output
 * back through the reader without touching disk.
 *
 * @opts
 *   signal:   AbortSignal,
 *
 * @example
 *   var produced = b.archive.zip();
 *   produced.addFile("readme.txt", "Hello\n");
 *   var bytes = produced.toBuffer();
 *   var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes));
 *   var entries = await reader.inspect();
 */
function buffer(buf, opts) {
  if (!Buffer.isBuffer(buf)) {
    throw new AdapterError("adapter/bad-arg", "buffer: arg must be a Buffer");
  }
  opts = opts || {};
  var signal = opts.signal || null;
  var size = buf.length;

  function close() { /* nothing to release */ }

  function range(offset, length) {
    return new Promise(function (resolve, reject) {
      try {
        _checkSignal(signal, "buffer.range");
        _assertNonNegativeInteger(offset, "buffer.range: offset");
        _assertPositiveInteger(length, "buffer.range: length");
        if (offset + length > size) {
          throw new AdapterError("adapter/out-of-range",
            "buffer.range: read past EOF (offset=" + offset + " length=" + length + " size=" + size + ")");
        }
        // .slice shares the underlying ArrayBuffer; copy so the
        // caller can mutate without surprising the next range() call.
        var out = Buffer.allocUnsafe(length);
        buf.copy(out, 0, offset, offset + length);
        resolve(out);
      } catch (e) { reject(e); }
    });
  }

  return {
    kind:   "random-access",
    name:   "buffer",
    size:   size,
    range:  range,
    close:  close,
    signal: signal,
  };
}

// ---- objectStore adapter --------------------------------------------------

/**
 * @primitive b.archive.adapters.objectStore
 * @signature b.archive.adapters.objectStore(client, key, opts?)
 * @since     0.12.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.archive.adapters.fs, b.archive.adapters.http, b.objectStore
 *
 * Random-access adapter backed by an operator-supplied
 * `b.objectStore` client. The adapter calls `client.get(key, { range:
 * [start, end] })` for every `range()` request and reads the response
 * body into a Buffer. Composes the framework's existing SSRF guard /
 * TLS posture / audit chain — adapter behaviour follows whatever the
 * client was configured with.
 *
 * The client is expected to expose:
 *   client.head(key) → { size: <number> }   (or similar size accessor)
 *   client.get(key, opts) → AsyncIterable<Buffer> | { body: Readable }
 *                                           (Range opt honored)
 *
 * Operators using bucket implementations that don't expose `.head()`
 * pass `opts.size` explicitly.
 *
 * @opts
 *   size:    number,         // override size (skips head() call)
 *   signal:  AbortSignal,
 *   audit:   b.audit,        // forwarded to client.get
 *
 * @example
 *   var client  = { get: async function () { return Buffer.alloc(0); }, head: async function () { return { size: 0 }; } };
 *   var adapter = b.archive.adapters.objectStore(client, "incoming/payload.zip");
 *   var reader  = b.archive.read.zip(adapter);
 *   var policy  = b.guardArchive.zipBombPolicy({ maxTotalDecompressedBytes: 268435456 });
 *   void reader; void policy;
 */
function objectStore(client, key, opts) {
  if (!client || typeof client.get !== "function") {
    throw new AdapterError("adapter/bad-arg",
      "objectStore: client must expose a .get(key, opts) method");
  }
  if (typeof key !== "string" || key.length === 0) {
    throw new AdapterError("adapter/bad-arg", "objectStore: key must be a non-empty string");
  }
  opts = opts || {};
  var signal = opts.signal || null;
  var sizeOverride = opts.size;
  var size = null;

  async function _resolveSize() {
    if (size !== null) return size;
    if (typeof sizeOverride === "number") {
      _assertNonNegativeInteger(sizeOverride, "objectStore.size opt");
      size = sizeOverride;
      return size;
    }
    if (typeof client.head !== "function") {
      throw new AdapterError("adapter/no-size",
        "objectStore: client has no .head(key) — pass opts.size explicitly");
    }
    var meta = await client.head(key, { signal: signal });
    if (!meta || typeof meta.size !== "number") {
      throw new AdapterError("adapter/no-size",
        "objectStore: client.head(key) did not return { size: <number> }");
    }
    _assertNonNegativeInteger(meta.size, "objectStore.head(key).size");
    size = meta.size;
    return size;
  }

  async function range(offset, length) {
    _checkSignal(signal, "objectStore.range");
    _assertNonNegativeInteger(offset, "objectStore.range: offset");
    _assertPositiveInteger(length, "objectStore.range: length");
    var s = await _resolveSize();
    if (offset + length > s) {
      throw new AdapterError("adapter/out-of-range",
        "objectStore.range: read past EOF (offset=" + offset + " length=" + length + " size=" + s + ")");
    }
    // HTTP Range is inclusive on both endpoints.
    var resp = await client.get(key, {
      range:  [offset, offset + length - 1],
      signal: signal,
      audit:  opts.audit,
    });
    var body = resp && (resp.body || resp);
    if (Buffer.isBuffer(body)) {
      if (body.length !== length) {
        throw new AdapterError("adapter/short-read",
          "objectStore.range: short read (requested=" + length + " got=" + body.length + ")");
      }
      return body;
    }
    if (body && typeof body[Symbol.asyncIterator] === "function") {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:   length,
        errorClass: AdapterError,
        sizeCode:   "adapter/over-read",
      });
      for await (var chunk of body) {
        collector.push(chunk);
      }
      if (collector.bytesCollected() !== length) {
        throw new AdapterError("adapter/short-read",
          "objectStore.range: short read (requested=" + length +
          " got=" + collector.bytesCollected() + ")");
      }
      return collector.result();
    }
    throw new AdapterError("adapter/bad-response",
      "objectStore.range: client.get(key) returned neither Buffer nor AsyncIterable<Buffer>");
  }

  function close() { /* the client owns its connection pool */ }

  return {
    kind:    "random-access",
    name:    "objectStore",
    range:   range,
    close:   close,
    signal:  signal,
    // size is a property accessor — the reader awaits it before
    // the first range() call so the head() round-trip is folded into
    // the first interaction rather than the constructor.
    get size() { return size; },
    resolveSize: _resolveSize,
  };
}

// ---- HTTP adapter ---------------------------------------------------------

/**
 * @primitive b.archive.adapters.http
 * @signature b.archive.adapters.http(url, opts?)
 * @since     0.12.7
 * @status    stable
 * @compliance gdpr, hipaa, pci-dss
 * @related   b.archive.adapters.objectStore, b.httpClient
 *
 * Random-access adapter backed by HTTP Range requests. Composes the
 * framework's `b.httpClient` (SSRF guard + TLS posture + audit chain
 * + PQC-hybrid agent) so the adapter inherits the operator's network
 * surface configuration without duplicating it here.
 *
 * First call issues a HEAD to determine size + verify the server
 * accepts Range requests (`Accept-Ranges: bytes`). Servers without
 * Range support are refused with `adapter/no-range` — operators
 * downloading the full byte stream first and feeding `b.archive.
 * adapters.buffer` is the appropriate fallback in that case.
 *
 * @opts
 *   client:  b.httpClient,     // override the default (must already exist)
 *   headers: { ... },
 *   timeoutMs: number,         // per-request
 *   signal:  AbortSignal,
 *   audit:   b.audit,
 *
 * @example
 *   var adapter = b.archive.adapters.http("https://artifact-host.example.com/release.zip", {
 *     timeoutMs: 60_000,
 *   });
 *   var reader = b.archive.read.zip(adapter);
 *   var entries = await reader.inspect();
 */
function http(url, opts) {
  if (typeof url !== "string" || url.length === 0) {
    throw new AdapterError("adapter/bad-arg", "http: url must be a non-empty string");
  }
  opts = opts || {};
  var signal = opts.signal || null;
  var client = opts.client || httpClient();
  var headers = Object.assign({}, opts.headers || {});
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(30);
  var size = null;

  async function _resolveSize() {
    if (size !== null) return size;
    _checkSignal(signal, "http.head");
    var res = await client.request({
      method:  "HEAD",
      url:     url,
      headers: headers,
      timeoutMs: timeoutMs,
      signal:  signal,
      audit:   opts.audit,
    });
    if (!res || !res.headers) {
      throw new AdapterError("adapter/bad-response", "http: HEAD returned no headers");
    }
    var acceptRanges = res.headers["accept-ranges"];
    if (!acceptRanges || String(acceptRanges).toLowerCase() !== "bytes") {
      throw new AdapterError("adapter/no-range",
        "http: server does not advertise 'Accept-Ranges: bytes' (got " + JSON.stringify(acceptRanges) + ")");
    }
    var lenHdr = res.headers["content-length"];
    if (!lenHdr) {
      throw new AdapterError("adapter/no-size",
        "http: server did not send Content-Length on HEAD");
    }
    var parsed = Number(lenHdr);
    _assertNonNegativeInteger(parsed, "http: parsed content-length");
    size = parsed;
    return size;
  }

  async function range(offset, length) {
    _checkSignal(signal, "http.range");
    _assertNonNegativeInteger(offset, "http.range: offset");
    _assertPositiveInteger(length, "http.range: length");
    var s = await _resolveSize();
    if (offset + length > s) {
      throw new AdapterError("adapter/out-of-range",
        "http.range: read past EOF (offset=" + offset + " length=" + length + " size=" + s + ")");
    }
    var rangeHdr = "bytes=" + offset + "-" + (offset + length - 1);
    var hdrs = Object.assign({}, headers, { "Range": rangeHdr });
    var res = await client.request({
      method:    "GET",
      url:       url,
      headers:   hdrs,
      timeoutMs: timeoutMs,
      signal:    signal,
      audit:     opts.audit,
    });
    if (!res || (res.status !== 206 && res.status !== 200)) {
      throw new AdapterError("adapter/bad-response",
        "http.range: expected 206 Partial Content, got " + (res && res.status));
    }
    var body = res.body;
    if (Buffer.isBuffer(body)) {
      if (body.length !== length) {
        throw new AdapterError("adapter/short-read",
          "http.range: short read (requested=" + length + " got=" + body.length + ")");
      }
      return body;
    }
    if (body && typeof body[Symbol.asyncIterator] === "function") {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:   length,
        errorClass: AdapterError,
        sizeCode:   "adapter/over-read",
      });
      for await (var chunk of body) {
        collector.push(chunk);
      }
      if (collector.bytesCollected() !== length) {
        throw new AdapterError("adapter/short-read",
          "http.range: short read (requested=" + length +
          " got=" + collector.bytesCollected() + ")");
      }
      return collector.result();
    }
    throw new AdapterError("adapter/bad-response",
      "http.range: response body is neither Buffer nor AsyncIterable<Buffer>");
  }

  function close() { /* httpClient owns its connection pool */ }

  return {
    kind:        "random-access",
    name:        "http",
    range:       range,
    close:       close,
    signal:      signal,
    get size()   { return size; },
    resolveSize: _resolveSize,
  };
}

// ---- trustedStream adapter ------------------------------------------------

/**
 * @primitive b.archive.adapters.trustedStream
 * @signature b.archive.adapters.trustedStream(readable, opts?)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.adapters.fs, b.archive.adapters.buffer
 *
 * Forward-scan-only adapter for trusted Readable sources. The reader
 * walks local file headers in order; the CD/LFH skew defense and the
 * "entries hidden from LFH but present in CD" attack class are OFF
 * in this mode because there's no central directory to compare
 * against. Operators reaching for this primitive are declaring they
 * own the producer (e.g. piping their own
 * `b.archive.zip().toStream()` output back into a reader 30 seconds
 * later for round-trip verification).
 *
 * Adversarial input MUST use `b.archive.adapters.fs` / `buffer` /
 * `objectStore` / `http` — the random-access path is the only
 * adversarial-safe one.
 *
 * @opts
 *   signal:  AbortSignal,
 *
 * @example
 *   var produced = fs.createReadStream("./own-export.zip");
 *   var reader   = b.archive.read.zip.fromTrustedStream(produced);
 *   var entries  = [];
 *   for await (var e of reader.entries()) entries.push(e);
 */
function trustedStream(readable, opts) {
  validateOpts.requireMethods(readable, ["pipe", "on"],
    "trustedStream: arg (Readable / pipe-on-compatible stream)", AdapterError, "adapter/bad-arg");
  if (!(readable instanceof nodeStream.Readable) && !readable.readable) {
    // Accept stream-like duck-typed objects; many libraries return
    // Readable-flavored bytes via Symbol.asyncIterator only.
  }
  opts = opts || {};
  var signal = opts.signal || null;

  function close() {
    if (typeof readable.destroy === "function") {
      try { readable.destroy(); } catch (_e) { /* drop-silent */ }
    }
  }

  return {
    kind:     "trusted-sequential",
    name:     "trustedStream",
    readable: readable,
    signal:   signal,
    close:    close,
  };
}

// ---- Adapter shape predicates --------------------------------------------

/**
 * @primitive b.archive.adapters.isRandomAccessAdapter
 * @signature b.archive.adapters.isRandomAccessAdapter(a)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.adapters.fs, b.archive.adapters.objectStore
 *
 * Type-predicate: returns `true` when `a` is the random-access shape
 * (`{ kind: "random-access", range, ... }`) produced by `fs` / `buffer`
 * / `objectStore` / `http`. Operators routing through `b.archive.read.zip`
 * compose this to refuse trusted-stream adapters at the wrong entry
 * point.
 *
 * @example
 *   var ok = b.archive.adapters.isRandomAccessAdapter(adapter);
 *   if (!ok) throw new Error("need random-access adapter");
 */
function isRandomAccessAdapter(a) {
  return !!(a && a.kind === "random-access" && typeof a.range === "function");
}

/**
 * @primitive b.archive.adapters.isTrustedStreamAdapter
 * @signature b.archive.adapters.isTrustedStreamAdapter(a)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.adapters.trustedStream
 *
 * Type-predicate: returns `true` when `a` is the trusted-sequential
 * shape (`{ kind: "trusted-sequential", readable, ... }`) produced by
 * `trustedStream`. Operators routing through `b.archive.read.zip.
 * fromTrustedStream` compose this to refuse random-access adapters
 * at the wrong entry point.
 *
 * @example
 *   var ok = b.archive.adapters.isTrustedStreamAdapter(adapter);
 *   if (!ok) throw new Error("need trusted-stream adapter");
 */
function isTrustedStreamAdapter(a) {
  return !!(a && a.kind === "trusted-sequential" && a.readable);
}

module.exports = {
  fs:                     fs,
  buffer:                 buffer,
  objectStore:            objectStore,
  http:                   http,
  trustedStream:          trustedStream,
  isRandomAccessAdapter:  isRandomAccessAdapter,
  isTrustedStreamAdapter: isTrustedStreamAdapter,
  AdapterError:           AdapterError,
};
