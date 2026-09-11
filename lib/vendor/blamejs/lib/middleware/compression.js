// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

var SUPPORTED_ENCODINGS = new Set(["br", "gzip"]);

var HTTP_STATUS = requestHelpers.HTTP_STATUS;
var HTTP_RESET_CONTENT = 0xCD;

var NO_BODY_STATUS = new Set([HTTP_STATUS.NO_CONTENT, HTTP_RESET_CONTENT, HTTP_STATUS.NOT_MODIFIED]);

function _parseAcceptEncoding(headerValue) {
  if (typeof headerValue !== "string" || headerValue.length === 0) {
    return [{ encoding: "*", q: 1 }];
  }
  var parsed = requestHelpers.parseQualityList(headerValue);
  var out = new Array(parsed.length);
  for (var i = 0; i < parsed.length; i++) {
    out[i] = { encoding: parsed[i].value, q: parsed[i].q };
  }
  return out;
}

function _negotiateEncoding(parsed, available) {
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
  for (var j = 0; j < available.length; j++) {
    var enc = available[j];
    if (Object.prototype.hasOwnProperty.call(clientQ, enc)) {
      if (clientQ[enc] > 0) return enc;
      continue;
    }
    if (hasStar && starQ > 0) return enc;
  }
  return null;
}

function _typeMatches(actual, allowed) {
  if (typeof actual !== "string") return false;
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
  if (lc === "*") return "*";
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
      catch (_e) {  return next(); }
    }

    var accept = _parseAcceptEncoding(req.headers && req.headers["accept-encoding"]);
    var encoding = _negotiateEncoding(accept, encodings);
    if (!encoding) return next();

    var originalWriteHead   = res.writeHead;
    var originalWrite       = res.write;
    var originalEnd         = res.end;
    var originalSetHeader   = res.setHeader   ? res.setHeader.bind(res)   : null;
    var originalGetHeader   = res.getHeader   ? res.getHeader.bind(res)   : null;
    var originalRemoveHdr   = res.removeHeader ? res.removeHeader.bind(res) : null;

    var decided   = false;
    var compress  = false;
    var compressor = null;

    function _decide(statusCode, headersObj) {
      if (decided) return;
      decided = true;

      if (NO_BODY_STATUS.has(statusCode)) { compress = false; return; }

      if (statusCode === C.HTTP.STATUS.PARTIAL_CONTENT) { compress = false; return; }
      var crRange = (headersObj && headersObj["content-range"]) ||
                    (originalGetHeader && originalGetHeader("Content-Range"));
      if (crRange) { compress = false; return; }

      var existingCE = (headersObj && headersObj["content-encoding"]) ||
                       (originalGetHeader && originalGetHeader("Content-Encoding"));
      if (existingCE) { compress = false; return; }

      var ct = (headersObj && headersObj["content-type"]) ||
               (originalGetHeader && originalGetHeader("Content-Type"));
      if (!_typeMatches(ct, contentTypes)) { compress = false; return; }

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
      compressor.on("data", function (chunk) {
        originalWrite.call(res, chunk);
      });
      compressor.on("end", function () {
        originalEnd.call(res);
      });
      compressor.on("error", function () {
        try { originalEnd.call(res); } catch (_e) { /* response already ended */ }
      });
      compressor.on("drain", function () {
        if (typeof res.emit === "function") res.emit("drain");
      });
    }

    function _lowerObj(o) {
      if (!o) return null;
      var out = {};
      var keys = Object.keys(o);
      for (var i = 0; i < keys.length; i++) out[keys[i].toLowerCase()] = o[keys[i]];
      return out;
    }

    function _applyCompressedHeaders(headersObj) {
      if (headersObj) {
        var hk = Object.keys(headersObj);
        for (var i = 0; i < hk.length; i++) {
          if (hk[i].toLowerCase() === "content-length") delete headersObj[hk[i]];
        }
        headersObj["Content-Encoding"] = encoding;
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
        _decide(HTTP_STATUS.OK, null);
        if (compress) _applyCompressedHeaders(null);
      }
      if (!compress) return originalWrite.call(res, chunk, encArg, cbArg);
      if (!compressor) _wireCompressor();
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
  _parseAcceptEncoding: _parseAcceptEncoding,
  _negotiateEncoding:   _negotiateEncoding,
  _typeMatches:         _typeMatches,
  _appendVary:          _appendVary,
  SUPPORTED_ENCODINGS:  SUPPORTED_ENCODINGS,
};
