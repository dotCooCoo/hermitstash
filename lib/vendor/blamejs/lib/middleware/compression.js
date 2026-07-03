// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * compression — gzip + brotli response compression.
 *
 * Intercepts the response stream and pipes it through node:zlib's
 * Brotli or gzip transform when the client supports it. Brotli is
 * preferred (better ratio for text); gzip is the fallback. Operators
 * tune which Content-Types are eligible, the size threshold below
 * which compression is skipped (overhead-of-compression > savings),
 * and the per-encoding quality knobs.
 *
 * The middleware wraps res.writeHead, res.write, and res.end. On the
 * first call to whichever of those happens first, it inspects the
 * response shape (Accept-Encoding, Content-Type, Content-Length,
 * existing Content-Encoding, status code, operator filter) and
 * decides:
 *
 *   - "compress with brotli/gzip" → set Content-Encoding, drop
 *     Content-Length (chunked output), pipe writes through a zlib
 *     transform stream
 *   - "skip"                       → pass through unchanged
 *
 * This decision happens once per response. After it's made, every
 * subsequent write/end uses the chosen path.
 *
 *   var compress = b.middleware.compression({
 *     // Bytes — don't compress responses smaller than this when
 *     // Content-Length is known. Absent Content-Length, compress.
 *     threshold:    1024,
 *     // Encodings considered, in fallback order. Operators who don't
 *     // want brotli (older clients in their fleet, etc.) drop it.
 *     encodings:    ["br", "gzip"],
 *     // Content-Type allowlist. Anything matching is compressed;
 *     // anything outside (image/*, video/*, application/zip etc.)
 *     // is left alone — they're already entropy-dense.
 *     contentTypes: [
 *       "text/*",
 *       "application/json",
 *       "application/xml",
 *       "application/javascript",
 *       "application/wasm",
 *       "image/svg+xml",
 *       "application/x-blamejs-bundle",
 *     ],
 *     // gzip level 1 (fast) – 9 (max). Default 6 matches zlib default.
 *     gzipLevel:    6,
 *     // Brotli quality 0 (fast) – 11 (max). Default 4 is the standard
 *     // HTTP-server tradeoff: noticeable ratio improvement vs gzip
 *     // without the latency cost of higher levels.
 *     brotliQuality: 4,
 *     // Operator escape hatch — return false to skip compression for
 *     // this request specifically (e.g. server-sent events, where
 *     // chunked compression breaks the eventstream framing).
 *     filter:       function (req, res) { return true; },
 *   });
 *   router.use(compress);
 *
 * What the middleware skips automatically:
 *   - Status 204 / 304 (no body)
 *   - Response already has Content-Encoding (operator pre-compressed)
 *   - Content-Type doesn't match the allowlist
 *   - Content-Length present AND < threshold
 *   - No supported encoding in Accept-Encoding (q=0 also respected)
 *   - filter(req, res) returned false
 *
 * Why both encodings ship by default:
 *   - Brotli is universally supported by every browser shipped after
 *     2017 and gives ~20% better ratio on JSON/HTML than gzip.
 *   - gzip is universal; it's the fallback for any client that
 *     doesn't advertise brotli support (rare but possible — internal
 *     curl usage, ancient libraries, prom scrapers, etc.).
 *
 * Headers set on a compressed response:
 *   Content-Encoding: br | gzip
 *   Vary:             Accept-Encoding (so caches don't serve wrong)
 *   (Content-Length is removed; chunked transfer is used)
 *
 * Wire-format: chunked transfer; that's standard for compressed
 * responses since the compressed length isn't known until the
 * compressor flushes.
 *
 * Out of scope for v1 (with structural reasons):
 *   - deflate encoding: superseded by gzip + brotli; no operator we
 *     know wants it. Adding it later is one constant + one Transform.
 *   - zstd: not in browser HTTP yet (Cloudflare ships it for
 *     server-to-server only); revisit when broadly supported.
 *   - dictionary compression (br with shared dictionaries): no operator
 *     demand yet; the spec is still being finalized.
 */

var zlib = require("node:zlib");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var CompressionError = defineClass("CompressionError", { alwaysPermanent: true });

var DEFAULT_OPTS = Object.freeze({
  threshold:    C.BYTES.kib(1),
  encodings:    ["br", "gzip"],
  contentTypes: [
    "text/*",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/wasm",
    "image/svg+xml",
    "application/x-blamejs-bundle",
  ],
  gzipLevel:     6,
  brotliQuality: 4,
});

// Encodings the framework knows how to produce. Adding "deflate" or
// "zstd" later is: extend this map, the createCompressor switch, and
// the encodings default.
var SUPPORTED_ENCODINGS = new Set(["br", "gzip"]);

var HTTP_STATUS = requestHelpers.HTTP_STATUS;
// 205 Reset Content is rarely-used — local hex constant rather than
// expanding the framework's HTTP_STATUS table for a single call site.
var HTTP_RESET_CONTENT = 0xCD;

// Status codes that NEVER carry a body — RFC 7230 §3.3.3.
var NO_BODY_STATUS = new Set([HTTP_STATUS.NO_CONTENT, HTTP_RESET_CONTENT, HTTP_STATUS.NOT_MODIFIED]);

// Parse Accept-Encoding into [{ encoding, q }] sorted by q descending.
// Built on the shared `requestHelpers.parseQualityList` (RFC 9110
// §12.5). Per RFC: absent header = client accepts any encoding, which
// the negotiator handles via the `*` wildcard fallthrough — so an empty
// parsed array becomes [{ encoding: "*", q: 1 }] here for downstream
// uniformity. q=0 explicitly excludes an encoding (RFC 9110 §12.4.2).
function _parseAcceptEncoding(headerValue) {
  if (typeof headerValue !== "string" || headerValue.length === 0) {
    return [{ encoding: "*", q: 1 }];
  }
  var parsed = requestHelpers.parseQualityList(headerValue);
  // Re-key to the legacy field name so the rest of compression.js
  // doesn't need to change. Field renaming would churn tests for no
  // operator-visible benefit.
  var out = new Array(parsed.length);
  for (var i = 0; i < parsed.length; i++) {
    out[i] = { encoding: parsed[i].value, q: parsed[i].q };
  }
  return out;
}

// Pick the highest-q encoding from `available` that the client accepts.
// `available` is the operator's preferred ordering ["br", "gzip"];
// matching against the parsed Accept-Encoding respects q=0 exclusions.
function _negotiateEncoding(parsed, available) {
  // Build a quick lookup: encoding → q
  var clientQ = {};
  var hasStar = false;
  var starQ = 0;
  for (var i = 0; i < parsed.length; i++) {
    if (parsed[i].encoding === "*") {
      hasStar = true;
      starQ = parsed[i].q;
    } else {
      clientQ[parsed[i].encoding] = parsed[i].q;
    }
  }
  // Walk the operator's preference list. The first encoding the client
  // accepts (q > 0) wins — we don't pick max-q across all options
  // because the operator's order encodes their priority (brotli first
  // for text-y workloads).
  for (var j = 0; j < available.length; j++) {
    var enc = available[j];
    if (Object.prototype.hasOwnProperty.call(clientQ, enc)) {
      if (clientQ[enc] > 0) return enc;
      // q=0 explicitly excludes this encoding even if "*" would match.
      continue;
    }
    if (hasStar && starQ > 0) return enc;
  }
  return null;
}

function _typeMatches(actual, allowed) {
  if (typeof actual !== "string") return false;
  // Drop charset / boundary parameters — we match on the type alone.
  var semi = actual.indexOf(";");
  var bare = (semi === -1 ? actual : actual.slice(0, semi)).trim().toLowerCase();
  for (var i = 0; i < allowed.length; i++) {
    var a = allowed[i].toLowerCase();
    if (a === bare) return true;
    var slash = a.indexOf("/");
    if (slash !== -1 && a.slice(slash + 1) === "*") {
      var prefix = a.slice(0, slash + 1);
      if (bare.indexOf(prefix) === 0) return true;
    }
  }
  return false;
}

function _createCompressor(encoding, opts) {
  if (encoding === "br") {
    return zlib.createBrotliCompress({
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: opts.brotliQuality,
        [zlib.constants.BROTLI_PARAM_MODE]:    zlib.constants.BROTLI_MODE_TEXT,
      },
    });
  }
  if (encoding === "gzip") {
    return zlib.createGzip({ level: opts.gzipLevel });
  }
  throw new CompressionError("compression/unsupported-encoding",
    "no compressor available for encoding '" + encoding + "'");
}

function _appendVary(existing, token) {
  if (!existing) return token;
  var lc = String(existing).toLowerCase();
  if (lc === "*") return "*"; // Vary: * already stops caches; don't dilute.
  var parts = requestHelpers.parseListHeader(existing);
  var lcToken = token.toLowerCase();
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].toLowerCase() === lcToken) return String(existing);
  }
  parts.push(token);
  return parts.join(", ");
}

/**
 * @primitive b.middleware.compression
 * @signature b.middleware.compression(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.sse
 *
 * Brotli + gzip response compression. Constructed via
 * `b.middleware.compression(opts)`; the resulting middleware has
 * the `(req, res, next)` shape shown above. Intercepts the response stream
 * and pipes it through `node:zlib`'s transform when the client
 * supports it. Brotli is preferred (better ratio for text), gzip is
 * the fallback. Skips small responses (below `threshold`),
 * already-encoded responses, 204/304 status codes, server-sent
 * events streams (chunked compression breaks SSE framing), and
 * Content-Types outside the allowlist (image/* / video/* / archives
 * are already entropy-dense). Operators with custom skip logic wire
 * a `filter(req, res)` predicate.
 *
 * @opts
 *   {
 *     threshold:     number,            // default 1024 bytes
 *     encodings:     string[],          // default ["br", "gzip"]
 *     contentTypes:  string[],          // allowlist of MIME types
 *     gzipLevel:     number,            // 1..9, default 6
 *     brotliQuality: number,            // 0..11, default 4
 *     filter:        function(req, res): boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.compression({
 *     threshold:    1024,
 *     encodings:    ["br", "gzip"],
 *     contentTypes: ["text/*", "application/json"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "threshold", "encodings", "contentTypes",
    "gzipLevel", "brotliQuality", "filter",
  ], "middleware.compression");
  var threshold;
  if (opts.threshold === undefined) {
    threshold = DEFAULT_OPTS.threshold;
  } else if (numericBounds.isNonNegativeFiniteInt(opts.threshold)) {
    threshold = opts.threshold;
  } else {
    throw new CompressionError("compression/bad-opt",
      "middleware.compression: threshold must be a non-negative finite integer; got " +
        numericBounds.shape(opts.threshold));
  }
  var encodings     = Array.isArray(opts.encodings) && opts.encodings.length > 0
                        ? opts.encodings.slice() : DEFAULT_OPTS.encodings.slice();
  var contentTypes  = Array.isArray(opts.contentTypes) && opts.contentTypes.length > 0
                        ? opts.contentTypes.slice() : DEFAULT_OPTS.contentTypes.slice();
  var gzipLevel     = typeof opts.gzipLevel === "number"     ? opts.gzipLevel     : DEFAULT_OPTS.gzipLevel;
  var brotliQuality = typeof opts.brotliQuality === "number" ? opts.brotliQuality : DEFAULT_OPTS.brotliQuality;
  var filter        = typeof opts.filter === "function"      ? opts.filter        : null;

  for (var i = 0; i < encodings.length; i++) {
    if (!SUPPORTED_ENCODINGS.has(encodings[i])) {
      throw new CompressionError("compression/bad-encoding",
        "encoding '" + encodings[i] + "' is not supported (allowed: " +
        Array.from(SUPPORTED_ENCODINGS).join(", ") + ")");
    }
  }

  return function compression(req, res, next) {
    if (filter) {
      try { if (!filter(req, res)) return next(); }
      catch (_e) { /* operator filter threw — fall through and skip compression */ return next(); }
    }

    // Negotiate encoding up-front from Accept-Encoding. If the client
    // doesn't accept anything we produce, skip immediately — no need
    // to wrap res at all.
    var accept = _parseAcceptEncoding(req.headers && req.headers["accept-encoding"]);
    var encoding = _negotiateEncoding(accept, encodings);
    if (!encoding) return next();

    // Capture the original methods. We replace each method with a
    // version that decides (on first invocation) whether to compress;
    // once decided, subsequent calls take the fast path.
    var originalWriteHead   = res.writeHead;
    var originalWrite       = res.write;
    var originalEnd         = res.end;
    var originalSetHeader   = res.setHeader   ? res.setHeader.bind(res)   : null;
    var originalGetHeader   = res.getHeader   ? res.getHeader.bind(res)   : null;
    var originalRemoveHdr   = res.removeHeader ? res.removeHeader.bind(res) : null;

    var decided   = false;       // has the compress/skip decision been made?
    var compress  = false;       // outcome of the decision
    var compressor = null;       // zlib transform when compressing

    function _decide(statusCode, headersObj) {
      if (decided) return;
      decided = true;

      // Status precludes body? skip.
      if (NO_BODY_STATUS.has(statusCode)) { compress = false; return; }

      // 206 Partial Content / any Content-Range response must pass through
      // UNtransformed (RFC 7233 §4.1) — compressing it drops Content-Length but
      // leaves Content-Range advertising an uncompressed byte interval over a
      // now-compressed body, corrupting range-assembling clients.
      if (statusCode === 206) { compress = false; return; }
      var crRange = (headersObj && headersObj["content-range"]) ||
                    (originalGetHeader && originalGetHeader("Content-Range"));
      if (crRange) { compress = false; return; }

      // Already compressed by the handler / earlier middleware? skip.
      var existingCE = (headersObj && headersObj["content-encoding"]) ||
                       (originalGetHeader && originalGetHeader("Content-Encoding"));
      if (existingCE) { compress = false; return; }

      // Content-Type allowlist
      var ct = (headersObj && headersObj["content-type"]) ||
               (originalGetHeader && originalGetHeader("Content-Type"));
      if (!_typeMatches(ct, contentTypes)) { compress = false; return; }

      // Content-Length below threshold? skip. If absent, compress.
      var clRaw = (headersObj && headersObj["content-length"]) ||
                  (originalGetHeader && originalGetHeader("Content-Length"));
      if (clRaw != null) {
        var cl = parseInt(clRaw, 10);
        if (!isNaN(cl) && cl < threshold) { compress = false; return; }
      }

      compress = true;
    }

    function _wireCompressor() {
      compressor = _createCompressor(encoding, { gzipLevel: gzipLevel, brotliQuality: brotliQuality });
      // Pipe compressed bytes back to the original socket via the
      // pre-wrap res.write. We bypass our wrapped res.write on purpose
      // — the wrapped version would re-feed into the compressor and
      // create a loop.
      compressor.on("data", function (chunk) {
        originalWrite.call(res, chunk);
      });
      compressor.on("end", function () {
        originalEnd.call(res);
      });
      compressor.on("error", function () {
        // On compressor error the response is already half-written;
        // there's not much we can do beyond closing the underlying
        // socket. Best-effort end the response.
        try { originalEnd.call(res); } catch (_e) { /* response already ended */ }
      });
      // Forward drain. Without this, source streams piped into our
      // wrapped res (e.g. fs.createReadStream from staticServe) stall:
      // when compressor's internal buffer hits highWaterMark,
      // compressor.write returns false, our wrapped res.write returns
      // false, and pipe pauses the source waiting for res 'drain' —
      // which never fires unless we emit it ourselves.
      compressor.on("drain", function () {
        if (typeof res.emit === "function") res.emit("drain");
      });
    }

    // Normalize header object keys to lowercase for consistent inspection.
    function _lowerObj(o) {
      if (!o) return null;
      var out = {};
      var keys = Object.keys(o);
      for (var i = 0; i < keys.length; i++) out[keys[i].toLowerCase()] = o[keys[i]];
      return out;
    }

    // Apply the compression-side header tweaks (Content-Encoding,
    // Vary, drop Content-Length) right before the headers go on the
    // wire. We modify either the writeHead-supplied `headers` object,
    // or fall back to res.setHeader / res.removeHeader for the
    // implicit-headers path.
    function _applyCompressedHeaders(headersObj) {
      if (headersObj) {
        // Walk and remove existing Content-Length (any case).
        var hk = Object.keys(headersObj);
        for (var i = 0; i < hk.length; i++) {
          if (hk[i].toLowerCase() === "content-length") delete headersObj[hk[i]];
        }
        headersObj["Content-Encoding"] = encoding;
        // Vary: append Accept-Encoding without clobbering an operator-set Vary.
        var existingVary = headersObj["Vary"] || headersObj["vary"];
        headersObj["Vary"] = _appendVary(existingVary, "Accept-Encoding");
      } else {
        if (originalRemoveHdr) {
          try { originalRemoveHdr("Content-Length"); } catch (_e) { /* header may not be set */ }
        }
        if (originalSetHeader) {
          try { originalSetHeader("Content-Encoding", encoding); } catch (_e) { /* headers already sent */ }
          var existing = originalGetHeader && originalGetHeader("Vary");
          try { originalSetHeader("Vary", _appendVary(existing, "Accept-Encoding")); } catch (_e) { /* headers already sent */ }
        }
      }
    }

    res.writeHead = function (statusCode, statusMessageOrHeaders, headersIfMessage) {
      // Node accepts: writeHead(status), writeHead(status, headers),
      // writeHead(status, statusMessage, headers).
      var headersObj = null;
      if (headersIfMessage && typeof headersIfMessage === "object") {
        headersObj = headersIfMessage;
      } else if (statusMessageOrHeaders && typeof statusMessageOrHeaders === "object" && !Array.isArray(statusMessageOrHeaders)) {
        headersObj = statusMessageOrHeaders;
      }
      _decide(statusCode, _lowerObj(headersObj));
      if (compress) _applyCompressedHeaders(headersObj);
      return originalWriteHead.apply(res, arguments);
    };

    res.write = function (chunk, encArg, cbArg) {
      if (!decided) {
        // Implicit header path — handler did res.write() before
        // res.writeHead(). Use the implicit Content-Type from setHeader
        // (or absence) to decide. Default Node behavior triggers
        // writeHead with statusCode=200 here; we mirror that.
        _decide(HTTP_STATUS.OK, null);
        if (compress) _applyCompressedHeaders(null);
      }
      if (!compress) return originalWrite.call(res, chunk, encArg, cbArg);
      if (!compressor) _wireCompressor();
      // Coerce string→Buffer with the operator-supplied encoding so
      // the compressor sees raw bytes consistently.
      var buf;
      if (Buffer.isBuffer(chunk)) buf = chunk;
      else if (typeof chunk === "string") buf = Buffer.from(chunk, typeof encArg === "string" ? encArg : "utf8");
      else if (chunk != null) buf = Buffer.from(String(chunk));
      else buf = null;
      var ret = buf ? compressor.write(buf) : true;
      if (typeof cbArg === "function") cbArg();
      else if (typeof encArg === "function") encArg();
      return ret;
    };

    res.end = function (chunk, encArg, cbArg) {
      if (!decided) {
        _decide(HTTP_STATUS.OK, null);
        if (compress) _applyCompressedHeaders(null);
      }
      if (!compress) return originalEnd.call(res, chunk, encArg, cbArg);
      if (!compressor) _wireCompressor();
      if (chunk != null) {
        var buf;
        if (Buffer.isBuffer(chunk)) buf = chunk;
        else if (typeof chunk === "string") buf = Buffer.from(chunk, typeof encArg === "string" ? encArg : "utf8");
        else buf = Buffer.from(String(chunk));
        compressor.write(buf);
      }
      compressor.end();
      if (typeof cbArg === "function") cbArg();
      else if (typeof encArg === "function") encArg();
      return res;
    };

    return next();
  };
}

module.exports = {
  create:           create,
  CompressionError: CompressionError,
  // Internal helpers exposed for tests.
  _parseAcceptEncoding: _parseAcceptEncoding,
  _negotiateEncoding:   _negotiateEncoding,
  _typeMatches:         _typeMatches,
  _appendVary:          _appendVary,
  SUPPORTED_ENCODINGS:  SUPPORTED_ENCODINGS,
};
