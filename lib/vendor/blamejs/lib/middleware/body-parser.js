"use strict";
/**
 * body-parser — request-body buffering + parsing middleware.
 *
 * Populates `req.body` for body-bearing methods (POST, PUT, PATCH,
 * DELETE) based on the request's Content-Type. Five sub-parsers ship,
 * each with its own size-cap, encoding handling, and pollution defense:
 *
 *   application/json                       → req.body = parsed object
 *                                            (via safe-json — POISONED_KEYS
 *                                            stripped, depth + size caps)
 *   application/x-www-form-urlencoded      → req.body = { field: value }
 *   text/plain                             → req.body = string
 *   application/octet-stream               → req.body = Buffer (raw)
 *   multipart/form-data                    → req.body = { field: value }
 *                                            req.files = [{ field, filename,
 *                                            mimeType, path, size, hash }]
 *                                            req.filesRejected = [{ field,
 *                                            filename, mimeType, code, message }]
 *
 * Multipart parses incrementally — file parts stream to a tmp dir
 * rather than buffering in memory. Per-file + total-request size caps
 * enforced. Filename sanitization strips path components + traversal.
 * Per-file SHA3-512 hash computed during streaming. Tmp files cleaned
 * on response end (whether the handler returned or threw).
 *
 *   var bp = b.middleware.bodyParser({
 *     json: {
 *       limit:        b.constants.BYTES.mib(1),
 *       strict:       true,                  // require the body to start with {/[
 *       parseHook:    function (parsed) { ... return validatedShape; },
 *     },
 *     urlencoded: {
 *       limit:        b.constants.BYTES.mib(1),
 *       arrayLimit:   100,                   // for ?tag=a&tag=b → tag: ["a","b"]
 *     },
 *     text:        { limit: b.constants.BYTES.mib(1), charset: "utf-8" },
 *     raw:         { limit: b.constants.BYTES.mib(10), contentTypes: ["application/octet-stream"] },
 *     multipart: {
 *       tmpDir:       os.tmpdir(),
 *       fileSize:     b.constants.BYTES.mib(10),
 *       totalSize:    b.constants.BYTES.mib(50),
 *       fileCount:    20,
 *       fieldCount:   100,
 *       fieldSize:    b.constants.BYTES.mib(1),
 *       mimeAllowlist: ["image/jpeg", "image/png", "application/pdf"], // null = any
 *
 *       // Per-part predicate. Runs after sanitization + MIME checks but
 *       // BEFORE the tmp file opens. Rejected parts are SKIPPED — the body
 *       // bytes are consumed (we still must scan past them to find the
 *       // next boundary) but never written to disk; the part metadata
 *       // lands in req.filesRejected. Surviving files appear in req.files
 *       // as usual. Sync only — async filtering goes in the route handler.
 *       fileFilter: function (part) {
 *         // part = { field, filename, mimeType, partHeaders }
 *         // return true / undefined → accept
 *         // return false → reject silently (entry in req.filesRejected)
 *         // return { reject: true, code, message } → reject with custom info
 *         return part.field === "avatar" && part.mimeType.startsWith("image/");
 *       },
 *
 *       // Per-field overrides. maxBytes overrides global fileSize for file
 *       // parts and fieldSize for text parts. mimeTypes overrides the
 *       // global mimeAllowlist for the named field; other fields still
 *       // use the global list.
 *       fields: {
 *         avatar:   { maxBytes: b.constants.BYTES.mib(2),  mimeTypes: ["image/jpeg", "image/png"] },
 *         document: { maxBytes: b.constants.BYTES.mib(25) },
 *       },
 *
 *       // When wired, fileFilter rejections emit body-parser.multipart.file_rejected
 *       // on the audit chain with the field, filename, mime, and reason.
 *       audit: b.audit,
 *     },
 *     // Stash the raw bytes for webhook-signature paths that need to
 *     // verify the wire bytes rather than the parsed shape.
 *     keepRawBody:  false,
 *   });
 *   router.use(bp);
 *
 * Set any sub-parser to `false` to disable it entirely (the body is
 * left untouched for those Content-Types — operator handles them).
 *
 * Failure modes — all return responses, do NOT call next(err):
 *   413 Payload Too Large       size-cap exceeded (incl. multipart
 *                               file/total/field caps)
 *   415 Unsupported Media Type  Content-Type doesn't match any enabled
 *                               sub-parser AND the request has a body
 *   400 Bad Request             malformed JSON / multipart / urlencoded;
 *                               filename traversal; MIME not on allowlist
 *
 * Security guarantees:
 *   - All parsers enforce size caps BEFORE buffering the full body, so
 *     a large body can't OOM the process.
 *   - JSON path goes through safe-json — POISONED_KEYS stripped, depth
 *     + size caps applied at parse, no prototype pollution downstream.
 *   - Urlencoded uses URLSearchParams with a key-count cap, refuses
 *     POISONED_KEYS as field names (returns 400).
 *   - Multipart filename: path components stripped (basename), traversal
 *     dots collapsed, control characters stripped, length capped at 255.
 *     Tmp file path is generated by the framework, never derived from
 *     the operator-supplied filename — so a malicious filename can't
 *     collide with a sensitive path.
 *   - Multipart parser refuses fields whose `name` is in POISONED_KEYS
 *     (consistent with the JSON path).
 *   - Tmp files set with mode 0o600, parent dir created with 0o700.
 *   - Cleanup on response end always fires (response close, finish, or
 *     error) so a crashing handler doesn't leak files.
 */

var nodeFs = require("node:fs");
var os = require("node:os");
var nodePath = require("node:path");
var nodeCrypto = require("node:crypto");
var atomicFile      = require("../atomic-file");
var bCrypto         = require("../crypto");
var lazyRequire     = require("../lazy-require");
var requestHelpers  = require("../request-helpers");
var safeBuffer      = require("../safe-buffer");
var safeJson        = require("../safe-json");
var structuredFields = require("../structured-fields");
var validateOpts    = require("../validate-opts");
var C = require("../constants");
var { defineClass } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });

// Node's HTTP parser surfaces malformed chunked-transfer-encoding via a
// stable family of HPE_* codes. RFC 9112 §7.1 — when a server rejects a
// chunked decode the connection MUST close so a downstream proxy can't
// reuse the socket with the next request's body bytes still pending.
// HPE_INVALID_CHUNK_SIZE / HPE_CHUNK_EXTENSIONS_OVERFLOW (Node 24+) /
// HPE_INVALID_TRANSFER_ENCODING / HPE_INVALID_EOF_STATE (chunk truncated)
// all land here. The framework's Connection: close + audit emit closes
// the smuggling-adjacent socket-reuse path that bare 400-only handling
// leaves open.
var CHUNKED_MALFORMED_CODES = new Set([
  "HPE_INVALID_CHUNK_SIZE",
  "HPE_INVALID_TRANSFER_ENCODING",
  "HPE_INVALID_EOF_STATE",
  "HPE_INVALID_CONSTANT",
  "HPE_CHUNK_EXTENSIONS_OVERFLOW",
  "HPE_UNEXPECTED_CONTENT_LENGTH",
  "ERR_HTTP_INVALID_CHUNK",
]);
function _isChunkedMalformed(e) {
  if (!e) return false;
  if (typeof e.code === "string" && CHUNKED_MALFORMED_CODES.has(e.code)) return true;
  if (typeof e.code === "string" && e.code.indexOf("HPE_") === 0 &&
      typeof e.message === "string" && /chunk/i.test(e.message)) return true;
  return false;
}

var HTTP_STATUS = requestHelpers.HTTP_STATUS;
var BodyParserError = defineClass("BodyParserError", { withStatusCode: true });

// Mirrors safe-json.js + safe-schema.js. Field names that match these
// are refused at the parse boundary regardless of which sub-parser is
// in play — consistent prototype-pollution defense across the framework.
var POISONED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// ---- defaults ----

var DEFAULTS = Object.freeze({
  json: {
    limit:        C.BYTES.mib(1),
    strict:       true,
    contentTypes: ["application/json", "application/json; charset=utf-8"],
    charset:      "utf-8",
  },
  urlencoded: {
    limit:        C.BYTES.mib(1),
    arrayLimit:   100,
    contentTypes: ["application/x-www-form-urlencoded"],
    charset:      "utf-8",
  },
  text: {
    limit:        C.BYTES.mib(1),
    charset:      "utf-8",
    contentTypes: ["text/plain"],
  },
  raw: {
    limit:        C.BYTES.mib(10),
    contentTypes: ["application/octet-stream"],
  },
  multipart: {
    tmpDir:        null,             // resolved per-instance from os.tmpdir()
    fileSize:      C.BYTES.mib(10),
    totalSize:     C.BYTES.mib(50),
    fileCount:     20,
    fieldCount:    100,
    fieldSize:     C.BYTES.mib(1),
    mimeAllowlist: null,
    fileFilter:    null,             // fn({ field, filename, mimeType, partHeaders }) → bool | { reject, code, message }
    fields:        null,             // per-field overrides: { name: { maxBytes?, mimeTypes? } }
    audit:         null,             // when wired, file-rejection emits an audit event
    contentTypes:  ["multipart/form-data"],
  },
});

var BODY_BEARING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Headroom on top of arrayLimit before declaring a key-bomb. Sized so a
// reasonable form (a few hundred fields with repeated names) fits without
// tripping the cap.
var URLENCODED_KEY_HEADROOM = C.BYTES.bytes(1000);

// ---- helpers ----

function _contentType(req) {
  var ct = req.headers && req.headers["content-type"];
  if (typeof ct !== "string") return { type: "", params: {} };
  var idx = ct.indexOf(";");
  var type = (idx === -1 ? ct : ct.slice(0, idx)).trim().toLowerCase();
  var params = {};
  if (idx !== -1) {
    var rest = ct.slice(idx + 1);
    // RFC 9110 §8.3 + §5.6.6 — parameter values may be quoted-string
    // (e.g. `boundary="foo;bar"`, `charset="x;y"`). Bare `.split(";")`
    // would slice through quoted commas/semicolons and corrupt the
    // multipart boundary. Use the shared quote-aware splitter that
    // tracks RFC 8941 §3.3.3 quoted-string state with backslash-escape.
    var parts = structuredFields.splitTopLevel(rest, ";");
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      var eq = p.indexOf("=");
      if (eq === -1) continue;
      var k = p.slice(0, eq).trim().toLowerCase();
      var v = p.slice(eq + 1).trim();
      var _unq = structuredFields.unquoteSfString(v);
      if (_unq !== null) v = _unq;
      params[k] = v;
    }
  }
  return { type: type, params: params };
}

function _typeMatches(actual, allowed) {
  for (var i = 0; i < allowed.length; i++) {
    var a = allowed[i].toLowerCase();
    // Match either exact type or "type/*" prefix
    if (a === actual) return true;
    var slash = a.indexOf("/");
    if (slash !== -1 && a.slice(slash + 1) === "*" &&
        actual.indexOf(a.slice(0, slash + 1)) === 0) return true;
  }
  return false;
}

// RFC 9112 §6.1: Content-Length MUST be a sequence of decimal digits with
// no whitespace, sign, or trailing garbage. parseInt("123abc") returning
// 123 is the lenient parse that lets malformed headers slip past the
// preflight cap; the strict regex catches them at the boundary.
var STRICT_CONTENT_LENGTH = /^\d+$/;

function _parseContentLength(cl) {
  if (typeof cl !== "string" || !STRICT_CONTENT_LENGTH.test(cl)) return null;
  var n = Number(cl);
  return isFinite(n) ? n : null;
}

function _hasBody(req) {
  if (!BODY_BEARING_METHODS.has(req.method)) return false;
  var cl = req.headers && req.headers["content-length"];
  if (typeof cl === "string") {
    var clNum = _parseContentLength(cl);
    // Spec-shaped zero (the only RFC 9112 §6.1 zero) → no body. Malformed
    // values (non-decimal-digits) flow through as "yes, has body" so the
    // downstream _bufferBody call rejects with 400 — silently treating
    // a malformed header as "no body" would let the request slip past
    // the parser entirely.
    if (clNum === 0) return false;
    return true;
  }
  var te = req.headers && req.headers["transfer-encoding"];
  if (typeof te === "string" && te.length > 0) return true;
  return false;
}

// HTTP request-smuggling defense per RFC 9112 §6.1 — covers the
// CVE-2022-31394 / CVE-2024-27316 / CL.TE / TE.CL / TE.TE class.
// Returns null on clean; { status, code, message } on smuggling-shaped
// request that the caller MUST reject with 400 + Connection: close.
function _detectSmuggling(req) {
  var headers = req.headers || {};
  var cl = headers["content-length"];
  var te = headers["transfer-encoding"];

  // 1. Both Content-Length AND Transfer-Encoding present — RFC 9112
  //    §6.1 says receiver MUST reject; the dual presence is the canonical
  //    CL.TE / TE.CL smuggling shape.
  if (typeof cl === "string" && cl.length > 0 &&
      typeof te === "string" && te.length > 0) {
    return {
      status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/te-cl-conflict",
      message: "request has both Content-Length and Transfer-Encoding " +
               "headers (RFC 9112 §6.1 — request-smuggling vector)",
    };
  }

  // 2. Multiple Content-Length values. Node's http parser collapses
  //    duplicate headers into a comma-separated string — `cl.indexOf(",")`
  //    catches it.
  if (typeof cl === "string" && cl.indexOf(",") !== -1) {
    return {
      status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/multiple-content-length",
      message: "request has multiple Content-Length values (RFC 9112 §6.1)",
    };
  }

  // 3. Transfer-Encoding present — final coding MUST be `chunked`
  //    (RFC 9112 §6.1). Anything else is a smuggling vector or
  //    server-side decode error.
  if (typeof te === "string" && te.length > 0) {
    var tokens = te.toLowerCase().split(",").map(function (t) { return t.trim(); });               // allow:bare-split-on-quoted-header — RFC 9112 §6.1 Transfer-Encoding values (chunked / gzip / deflate / identity) are token-only; no quoted-string in the grammar
    var last = tokens[tokens.length - 1];
    if (last !== "chunked") {
      return {
        status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/te-not-chunked",
        message: "request has Transfer-Encoding but final coding is not " +
                 "`chunked` (RFC 9112 §6.1 requires chunked be last)",
      };
    }
    // 4. Duplicate `chunked` token (TE: chunked, chunked) — explicitly
    //    forbidden by RFC 9112 §6.1.
    var chunkedCount = 0;
    for (var i = 0; i < tokens.length; i += 1) {
      if (tokens[i] === "chunked") chunkedCount += 1;
    }
    if (chunkedCount > 1) {
      return {
        status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/duplicate-chunked",
        message: "Transfer-Encoding lists `chunked` more than once " +
                 "(RFC 9112 §6.1 — TE.TE smuggling vector)",
      };
    }
  }

  return null;
}

function _writeError(res, status, message, code) {
  if (res.headersSent) return;
  var body = JSON.stringify({ error: message, code: code });
  res.writeHead(status, {
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

// Buffer the raw body up to `limit`. If Content-Length is known and
// exceeds limit, reject IMMEDIATELY without reading any bytes.
function _bufferBody(req, limit) {
  return new Promise(function (resolve, reject) {
    var cl = req.headers && req.headers["content-length"];
    if (typeof cl === "string") {
      var clNum = _parseContentLength(cl);
      if (clNum === null) {
        // RFC 9112 §6.1 — malformed Content-Length is a 400.
        reject(new BodyParserError(
          "body-parser/bad-content-length",
          "Content-Length is not a sequence of decimal digits: " + JSON.stringify(cl),
          true, HTTP_STATUS.BAD_REQUEST
        ));
        return;
      }
      if (clNum > limit) {
        reject(new BodyParserError(
          "body-parser/too-large",
          "request body exceeds limit (" + clNum + " > " + limit + ")",
          true, HTTP_STATUS.PAYLOAD_TOO_LARGE
        ));
        return;
      }
    }
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    limit,
      errorClass:  BodyParserError,
      sizeCode:    "body-parser/too-large",
      sizeMessage: "request body exceeds limit",
    });
    var done = false;
    req.on("data", function (chunk) {
      if (done) return;
      try { collector.push(chunk); }
      catch (e) {
        done = true;
        try { req.destroy(); } catch (_e) { /* socket already closed */ }
        if (e && e.isBodyParserError) e.statusCode = HTTP_STATUS.PAYLOAD_TOO_LARGE;
        reject(e);
        return;
      }
    });
    req.on("end", function () { if (!done) { done = true; resolve(collector.result()); } });
    req.on("error", function (e) { if (!done) { done = true; reject(e); } });
  });
}

// ---- JSON parser ----

async function _parseJson(req, opts) {
  var buf = await _bufferBody(req, opts.limit);
  if (buf.length === 0) return undefined;
  var text = buf.toString(opts.charset);
  if (opts.strict) {
    var head = text.replace(/^[\s\u00A0\uFEFF]+/, "")[0];
    if (head !== "{" && head !== "[") {
      throw new BodyParserError(
        "body-parser/json-strict",
        "JSON body must start with '{' or '[' (strict mode)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
  }
  var parsed;
  try {
    // safe-json strips POISONED_KEYS and enforces depth + byte caps.
    parsed = safeJson.parse(text, { maxBytes: opts.limit });
  } catch (e) {
    throw new BodyParserError(
      "body-parser/json-malformed",
      "JSON parse failed: " + ((e && e.message) || String(e)),
      true, HTTP_STATUS.BAD_REQUEST
    );
  }
  if (typeof opts.parseHook === "function") {
    try { parsed = opts.parseHook(parsed); }
    catch (e) {
      throw new BodyParserError(
        "body-parser/json-hook",
        "JSON parseHook failed: " + ((e && e.message) || String(e)),
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
  }
  return parsed;
}

// ---- urlencoded parser ----

async function _parseUrlencoded(req, opts) {
  var buf = await _bufferBody(req, opts.limit);
  if (buf.length === 0) return {};
  var text = buf.toString(opts.charset);
  var sp;
  try { sp = new URLSearchParams(text); }
  catch (e) {
    throw new BodyParserError(
      "body-parser/urlencoded-malformed",
      "urlencoded parse failed: " + ((e && e.message) || String(e)),
      true, HTTP_STATUS.BAD_REQUEST
    );
  }
  var out = {};
  var keyCount = 0;
  // Track repeated keys so [a=1, a=2] becomes a: ["1","2"] rather than overwriting.
  var seen = Object.create(null);
  var keys = [];
  sp.forEach(function (value, key) { keys.push([key, value]); });
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i][0];
    var v = keys[i][1];
    if (POISONED_KEYS.has(k)) {
      throw new BodyParserError(
        "body-parser/urlencoded-poisoned-key",
        "urlencoded body contains forbidden key '" + k + "' (prototype-pollution defense)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
    keyCount++;
    if (keyCount > opts.arrayLimit + URLENCODED_KEY_HEADROOM) { // soft cap on total keys
      throw new BodyParserError(
        "body-parser/urlencoded-too-many-fields",
        "urlencoded body has too many fields",
        true, 413
      );
    }
    if (Object.prototype.hasOwnProperty.call(seen, k)) {
      if (Array.isArray(out[k])) {
        if (out[k].length >= opts.arrayLimit) {
          throw new BodyParserError(
            "body-parser/urlencoded-array-too-large",
            "urlencoded array '" + k + "' exceeds arrayLimit (" + opts.arrayLimit + ")",
            true, 413
          );
        }
        out[k].push(v);
      } else {
        out[k] = [out[k], v];
      }
    } else {
      out[k] = v;
      seen[k] = true;
    }
  }
  return out;
}

// ---- text parser ----

async function _parseText(req, opts) {
  var buf = await _bufferBody(req, opts.limit);
  return buf.toString(opts.charset);
}

// ---- raw parser ----

async function _parseRaw(req, opts) {
  return await _bufferBody(req, opts.limit);
}

// ---- multipart parser ----
//
// Streaming RFC 7578 multipart/form-data parser. Walks an incoming
// request stream byte-by-byte (well, chunk-by-chunk with a sliding
// look-ahead window) and emits parts as they're encountered. File
// parts stream straight to disk; field parts buffer in memory up to
// fieldSize.
//
// State machine:
//   INITIAL   skip preamble until first boundary
//   AFTER_BD  just consumed a boundary; check next two bytes for
//             "--" (end-of-multipart) or "\r\n" (next part)
//   HEADERS   reading per-part headers until \r\n\r\n
//   BODY      streaming part body; watch for \r\n--<boundary>
//   DONE      all parts read

var MP_INITIAL  = 0;
var MP_AFTER_BD = 1;
var MP_HEADERS  = 2;
var MP_BODY     = 3;
var MP_DONE     = 4;

function _sanitizeFilename(name) {
  if (typeof name !== "string") return null;
  // Strip every path component — keep only basename (last segment).
  // Both POSIX and Windows separators handled, plus URL-encoded.
  var s = name.replace(/\\/g, "/");
  var idx = s.lastIndexOf("/");
  if (idx !== -1) s = s.slice(idx + 1);
  // Drop control characters, NUL, leading/trailing dots.
  s = s.replace(/\p{Cc}/gu, "");
  // Trojan Source CVE-2021-42574 class — strip BiDi formatting +
  // zero-width codepoints from the filename. An attacker uploading
  // `Photo01By‮gpj.SCR` displays as `Photo01By.jpg` in audit
  // logs while the OS opens `.SCR`. Universal-refuse on these
  // codepoints; operators with legitimate need pass the raw filename
  // through `b.guardFilename` with explicit BiDi opt-in.
  // BiDi formatting (U+202A..U+202E, U+2066..U+2069), zero-width
  // (U+200B..U+200D, U+2060), BOM (U+FEFF) — Unicode escapes so the
  // regex itself contains no irregular whitespace.
  s = s.replace(/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/g, "");
  s = s.replace(/^\.+/, "").replace(/\.+$/, "");
  if (s.length === 0) return null;
  if (s.length > 255) s = s.slice(0, 255);
  // Refuse any remaining traversal artifact.
  if (s === "." || s === "..") return null;
  return s;
}

function _parseMultipartHeaders(rawHeaders) {
  // Each line is `Header-Name: value`. Common headers: Content-Disposition,
  // Content-Type, Content-Transfer-Encoding. Unknown headers are ignored.
  // RFC 9112 §5.2 — line folding (obs-fold) is OBSOLETE in HTTP messages;
  // a continuation line beginning with SP/HTAB MUST be refused. RFC 9110
  // §5.5 — header field values MUST NOT contain CR, LF, or NUL bytes.
  // We refuse the part outright (caller surfaces the throw as 400 + drop).
  var lines = rawHeaders.split("\r\n");
  var out = {};
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var first = line.charCodeAt(0);
    if (first === 32 || first === 9) {                                            // allow:raw-byte-literal — SP/HTAB obs-fold sentinels
      throw new BodyParserError(
        "body-parser/multipart-obs-fold",
        "multipart part header uses obsolete line folding (RFC 9112 §5.2)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
    var idx = line.indexOf(":");
    if (idx === -1) continue;
    var k = line.slice(0, idx).trim().toLowerCase();
    var v = line.slice(idx + 1).trim();
    for (var j = 0; j < v.length; j++) {
      var c = v.charCodeAt(j);
      if (c === 0 || c === 10 || c === 13) {                                      // allow:raw-byte-literal — NUL/LF/CR forbidden in field-value (RFC 9110 §5.5)
        throw new BodyParserError(
          "body-parser/multipart-bad-header-value",
          "multipart part header `" + k + "` contains CR/LF/NUL (RFC 9110 §5.5)",
          true, HTTP_STATUS.BAD_REQUEST
        );
      }
    }
    out[k] = v;
  }
  return out;
}

// RFC 5987 / 8187 — `filename*=UTF-8''percent%20encoded.txt` extended
// parameter form for non-ASCII filenames. Charset MUST be `UTF-8`
// (case-insensitive); we refuse other charsets to keep the decode
// path single-encoding. Language tag (between the two `'`s) is
// permitted but ignored.
function _decodeRfc5987(raw) {
  if (typeof raw !== "string") return null;
  var firstTick  = raw.indexOf("'");
  if (firstTick === -1) return null;
  var secondTick = raw.indexOf("'", firstTick + 1);
  if (secondTick === -1) return null;
  var charset = raw.slice(0, firstTick).toLowerCase();
  if (charset !== "utf-8") return null;       // RFC 5987 mandated charset; refuse anything else
  var encoded = raw.slice(secondTick + 1);
  try {
    return decodeURIComponent(encoded);
  } catch (_e) {
    return null;
  }
}

function _parseHeaderParams(headerValue) {
  // Content-Disposition: form-data; name="field"; filename="x.txt"
  // Returns { _value: "form-data", name: "field", filename: "x.txt" }
  // RFC 5987 / 8187 — when a `filename*=UTF-8''...` extended parameter
  // is present, it takes precedence over the legacy `filename=`
  // companion (RFC 6266 §4.3). We surface the decoded value at
  // `filename` so downstream consumers don't need parser-aware code.
  var out = { _value: "" };
  if (!headerValue) return out;
  // RFC 6266 §4.1 + RFC 9110 §5.6.6 — parameter values may be
  // quoted-string (e.g. `filename="weird;name.txt"`). Bare
  // `.split(";")` would slice through the quoted semicolon and
  // corrupt the filename. Quote-aware shared splitter.
  var parts = structuredFields.splitTopLevel(headerValue, ";");
  out._value = parts[0].trim().toLowerCase();
  var extName = null;
  for (var i = 1; i < parts.length; i++) {
    var p = parts[i].trim();
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var k = p.slice(0, eq).trim().toLowerCase();
    var v = p.slice(eq + 1).trim();
    var _unq = structuredFields.unquoteSfString(v);
    if (_unq !== null) v = _unq;
    if (k.charAt(k.length - 1) === "*") {
      var decoded = _decodeRfc5987(v);
      if (decoded !== null) {
        var bareKey = k.slice(0, -1);
        if (bareKey === "filename") extName = decoded;
        out[bareKey] = decoded;
      }
      continue;
    }
    out[k] = v;
  }
  if (extName !== null) out.filename = extName;
  return out;
}

async function _parseMultipart(req, opts, ctParams) {
  var boundary = ctParams.boundary;
  if (typeof boundary !== "string" || boundary.length === 0) {
    throw new BodyParserError(
      "body-parser/multipart-no-boundary",
      "multipart Content-Type missing boundary parameter",
      true, HTTP_STATUS.BAD_REQUEST
    );
  }
  // RFC 2046 §5.1.1 — boundary length 1-70 chars, bcharsnospace
  // grammar. Pathological boundaries (zero-length / very long /
  // newlines) drive quadratic match cost in scanners. Refuse at
  // the parse boundary so the rest of the engine doesn't have to
  // defend against them.
  if (boundary.length > 70 ||                                                                  // allow:raw-byte-literal — RFC 2046 §5.1.1 boundary length cap
      !/^[A-Za-z0-9'()+_,\-./:=?]{1,70}$/.test(boundary)) {                                   // allow:raw-byte-literal — RFC 2046 §5.1.1 bchars + cap
    throw new BodyParserError(
      "body-parser/multipart-bad-boundary",
      "multipart boundary violates RFC 2046 §5.1.1 (1-70 chars, bcharsnospace grammar)",
      true, HTTP_STATUS.BAD_REQUEST
    );
  }
  // Resolve tmpDir per-request so directory-creation failure surfaces as a
  // structured error rather than a deferred fs throw.
  var tmpDir = opts.tmpDir || nodePath.join(os.tmpdir(), "blamejs-uploads");
  try { atomicFile.ensureDir(tmpDir, 0o700); }
  catch (e) {
    throw new BodyParserError(
      "body-parser/multipart-tmpdir",
      "could not create multipart tmp dir '" + tmpDir + "': " + ((e && e.message) || String(e)),
      true, 500
    );
  }

  var boundaryBuf      = Buffer.from("--" + boundary);
  var boundaryDelimBuf = Buffer.from("\r\n--" + boundary);

  var fields = {};
  var files = [];
  var filesRejected = [];
  var totalRead = 0;
  var fileCount = 0;
  var fieldCount = 0;
  var fileSize  = opts.fileSize;
  var totalSize = opts.totalSize;
  var fileLimit = opts.fileCount;
  var fieldLimit = opts.fieldCount;
  var fieldSize = opts.fieldSize;
  var mimeAllowlist = Array.isArray(opts.mimeAllowlist) ? opts.mimeAllowlist : null;
  var fileFilter   = typeof opts.fileFilter === "function" ? opts.fileFilter : null;
  var perField     = (opts.fields && typeof opts.fields === "object") ? opts.fields : null;
  var auditInst    = (opts.audit && typeof opts.audit.safeEmit === "function") ? opts.audit : null;

  var state = MP_INITIAL;
  var pending = Buffer.alloc(0);
  var currentHeaders = null;
  var currentField = null;
  var currentFilename = null;
  var currentMime = null;
  var currentTmpPath = null;
  var currentFd = null;
  var currentSize = 0;
  var currentHash = null;
  var currentBuf = null; // for fields (in-memory accumulator)
  var currentDiscarded = false; // true when fileFilter rejected the part — body bytes are
                                // still consumed (we have to read past them to find the next
                                // boundary) but never written to disk.
  var currentEffectiveLimit = 0; // per-field-or-global cap; recomputed at part start.

  function _resetCurrent() {
    currentHeaders = null;
    currentField = null;
    currentFilename = null;
    currentMime = null;
    currentTmpPath = null;
    if (currentFd !== null) { try { nodeFs.closeSync(currentFd); } catch (_e) { /* fd already closed */ } currentFd = null; }
    currentSize = 0;
    currentHash = null;
    currentBuf = null;
    currentDiscarded = false;
    currentEffectiveLimit = 0;
  }

  function _emitRejection(field, filename, mimeType, code, message) {
    filesRejected.push({
      field:    field,
      filename: filename,
      mimeType: mimeType,
      code:     code,
      message:  message || null,
    });
    if (auditInst) {
      try {
        auditInst.safeEmit({
          action:   "body-parser.multipart.file_rejected",
          outcome:  "denied",
          resource: { kind: "multipart.file", id: field + (filename ? ":" + filename : "") },
          metadata: { field: field, filename: filename, mimeType: mimeType, code: code, message: message || null },
        });
      } catch (_e) { /* audit best-effort */ }
    }
  }

  function _cleanup() {
    if (currentFd !== null) { try { nodeFs.closeSync(currentFd); } catch (_e) { /* fd already closed */ } currentFd = null; }
    if (currentTmpPath) { try { nodeFs.unlinkSync(currentTmpPath); } catch (_e) { /* tmp file already removed */ } }
    for (var i = 0; i < files.length; i++) {
      try { nodeFs.unlinkSync(files[i].path); } catch (_e) { /* tmp file already removed */ }
    }
  }

  try {
    return await new Promise(function (resolve, reject) {
      function done(err, value) {
        // De-dup completion — req error + req end can both fire.
        if (resolved) return;
        resolved = true;
        if (err) {
          _cleanup();
          reject(err);
        } else {
          resolve(value);
        }
      }
      var resolved = false;

      function processBuffer() {
        // Re-enter the state machine until we can't make progress.
        while (true) {
          if (state === MP_INITIAL) {
            // Find the first boundary marker (without the leading \r\n
            // since the preamble may begin with the boundary directly).
            var firstIdx = pending.indexOf(boundaryBuf);
            if (firstIdx === -1) {
              // Need more data.
              if (pending.length > boundary.length + 100) {
                // Drop preamble bytes to bound memory; keep the last
                // boundary.length+4 bytes as look-ahead.
                pending = pending.slice(pending.length - boundary.length - 4);
              }
              return;
            }
            pending = pending.slice(firstIdx + boundaryBuf.length);
            state = MP_AFTER_BD;
            continue;
          }
          if (state === MP_AFTER_BD) {
            if (pending.length < 2) return;
            if (pending[0] === 0x2d && pending[1] === 0x2d) { // "--"
              state = MP_DONE;
              done(null, { fields: fields, files: files, filesRejected: filesRejected });
              return;
            }
            if (pending[0] === 0x0d && pending[1] === 0x0a) { // "\r\n"
              pending = pending.slice(2);
              state = MP_HEADERS;
              continue;
            }
            // Tolerate transport-added \n only.
            if (pending[0] === 0x0a) {
              pending = pending.slice(1);
              state = MP_HEADERS;
              continue;
            }
            done(new BodyParserError("body-parser/multipart-malformed",
              "expected --, \\r\\n, or \\n after boundary", true, HTTP_STATUS.BAD_REQUEST));
            return;
          }
          if (state === MP_HEADERS) {
            // Read until \r\n\r\n.
            var headEnd = pending.indexOf("\r\n\r\n");
            if (headEnd === -1) {
              if (pending.length > C.BYTES.kib(16)) {
                done(new BodyParserError("body-parser/multipart-headers-too-large",
                  "multipart part headers exceed 16KB", true, 413));
                return;
              }
              return;
            }
            // Count the per-part header bytes toward totalSize so a
            // burst of small parts can't slip past the request-level
            // cap. Without this, fileCount: 20 + fieldCount: 100
            // gives an attacker ~120 × 16 KiB = ~1.9 MiB of pending
            // header state per request, multiplied across concurrent
            // requests.
            totalRead += headEnd + 4;
            if (totalRead > totalSize) {
              done(new BodyParserError("body-parser/multipart-too-large",
                "multipart total request size exceeds totalSize (" + totalSize + ")",
                true, HTTP_STATUS.PAYLOAD_TOO_LARGE));
              return;
            }
            try {
              currentHeaders = _parseMultipartHeaders(pending.slice(0, headEnd).toString("utf8"));
            } catch (parseErr) {
              done(parseErr);
              return;
            }
            pending = pending.slice(headEnd + 4);
            // Decode Content-Disposition.
            var cd = _parseHeaderParams(currentHeaders["content-disposition"]);
            if (cd._value !== "form-data" || typeof cd.name !== "string" || cd.name.length === 0) {
              done(new BodyParserError("body-parser/multipart-bad-disposition",
                "multipart part missing form-data Content-Disposition", true, HTTP_STATUS.BAD_REQUEST));
              return;
            }
            if (POISONED_KEYS.has(cd.name)) {
              done(new BodyParserError("body-parser/multipart-poisoned-field",
                "multipart field '" + cd.name + "' is forbidden (prototype-pollution defense)",
                true, HTTP_STATUS.BAD_REQUEST));
              return;
            }
            currentField = cd.name;
            if (typeof cd.filename === "string") {
              currentFilename = _sanitizeFilename(cd.filename);
              if (!currentFilename) {
                done(new BodyParserError("body-parser/multipart-bad-filename",
                  "multipart part filename did not survive sanitization (path traversal or empty)",
                  true, HTTP_STATUS.BAD_REQUEST));
                return;
              }
              currentMime = currentHeaders["content-type"] || "application/octet-stream";
              // Per-field MIME allowlist takes precedence over the global one
              // for this field; global applies to fields without an entry.
              var fieldRule = perField ? perField[currentField] : null;
              var perFieldMime = (fieldRule && Array.isArray(fieldRule.mimeTypes))
                                    ? fieldRule.mimeTypes : null;
              if (perFieldMime) {
                if (perFieldMime.indexOf(currentMime) === -1) {
                  done(new BodyParserError("body-parser/multipart-mime-not-allowed",
                    "multipart file '" + currentField + "' MIME '" + currentMime +
                    "' is not on the per-field allowlist",
                    true, 415));
                  return;
                }
              } else if (mimeAllowlist && mimeAllowlist.indexOf(currentMime) === -1) {
                done(new BodyParserError("body-parser/multipart-mime-not-allowed",
                  "multipart file MIME '" + currentMime + "' is not on the allowlist",
                  true, 415));
                return;
              }
              fileCount++;
              if (fileCount > fileLimit) {
                done(new BodyParserError("body-parser/multipart-too-many-files",
                  "multipart fileCount exceeds limit (" + fileLimit + ")",
                  true, 413));
                return;
              }
              // Per-field cap overrides global fileSize for this field.
              currentEffectiveLimit = (fieldRule && typeof fieldRule.maxBytes === "number")
                                          ? fieldRule.maxBytes : fileSize;

              // fileFilter runs AFTER sanitize + MIME checks but BEFORE the
              // tmp file opens. Synchronous so the parser can decide between
              // disk-write and discard-bytes without buffering the part.
              if (fileFilter) {
                var filterVerdict;
                try {
                  filterVerdict = fileFilter({
                    field:       currentField,
                    filename:    currentFilename,
                    mimeType:    currentMime,
                    partHeaders: currentHeaders,
                  });
                } catch (e) {
                  done(new BodyParserError("body-parser/multipart-file-filter-throw",
                    "fileFilter threw: " + ((e && e.message) || String(e)),
                    true, 500));
                  return;
                }
                if (filterVerdict === false ||
                    (filterVerdict && typeof filterVerdict === "object" && filterVerdict.reject)) {
                  var rejCode    = (filterVerdict && filterVerdict.code)    || "fileFilter";
                  var rejMessage = (filterVerdict && filterVerdict.message) || null;
                  _emitRejection(currentField, currentFilename, currentMime, rejCode, rejMessage);
                  // Read past the body bytes (we still must find the next
                  // boundary) but never open a tmp file or push to req.files.
                  currentDiscarded = true;
                  fileCount--; // doesn't count toward the limit since it didn't land
                  currentSize = 0;
                  state = MP_BODY;
                  continue;
                }
              }

              // Generate the tmp path — never derived from the
              // operator-supplied filename.
              var unique = bCrypto.generateToken(C.BYTES.bytes(16));
              currentTmpPath = nodePath.join(tmpDir, "blamejs-up-" + unique);
              try {
                currentFd = nodeFs.openSync(currentTmpPath, "wx", 0o600);
              } catch (e) {
                done(new BodyParserError("body-parser/multipart-tmp-open",
                  "could not open multipart tmp file: " + ((e && e.message) || String(e)),
                  true, 500));
                return;
              }
              currentHash = nodeCrypto.createHash("sha3-512");
              currentSize = 0;
            } else {
              fieldCount++;
              if (fieldCount > fieldLimit) {
                done(new BodyParserError("body-parser/multipart-too-many-fields",
                  "multipart fieldCount exceeds limit (" + fieldLimit + ")",
                  true, 413));
                return;
              }
              // Per-field cap overrides global fieldSize for text parts too.
              var textFieldRule = perField ? perField[currentField] : null;
              currentEffectiveLimit = (textFieldRule && typeof textFieldRule.maxBytes === "number")
                                          ? textFieldRule.maxBytes : fieldSize;
              currentBuf = [];
              currentSize = 0;
            }
            state = MP_BODY;
            continue;
          }
          if (state === MP_BODY) {
            // Look for the next boundary. The marker we want is
            //   \r\n--<boundary>
            // Anything before it is part body. We need to keep at least
            // boundary.length + 4 bytes in `pending` so we don't emit a
            // partial match as body bytes.
            var bdIdx = pending.indexOf(boundaryDelimBuf);
            var emitLen;
            if (bdIdx === -1) {
              // No marker yet — emit everything except the trailing
              // boundary-length+4 bytes (might be the start of the marker).
              if (pending.length <= boundaryDelimBuf.length) return;
              emitLen = pending.length - boundaryDelimBuf.length;
            } else {
              emitLen = bdIdx;
            }
            if (emitLen > 0) {
              var bodyChunk = pending.slice(0, emitLen);
              if (currentDiscarded) {
                // fileFilter rejected this part — read past the bytes to find
                // the next boundary but never write to disk. totalSize still
                // applies as a per-request DoS guard.
                totalRead += bodyChunk.length;
                if (totalRead > totalSize) {
                  done(new BodyParserError("body-parser/multipart-total-too-large",
                    "multipart total request size exceeds totalSize (" + totalSize + ")",
                    true, 413));
                  return;
                }
              } else if (currentFd !== null) {
                // File part — write to disk.
                currentSize += bodyChunk.length;
                if (currentSize > currentEffectiveLimit) {
                  var perFieldFile = (perField && perField[currentField] &&
                                      typeof perField[currentField].maxBytes === "number");
                  done(new BodyParserError("body-parser/multipart-file-too-large",
                    "multipart file '" + currentField + "' exceeds " +
                    (perFieldFile ? "per-field maxBytes" : "fileSize") +
                    " (" + currentEffectiveLimit + ")",
                    true, 413));
                  return;
                }
                totalRead += bodyChunk.length;
                if (totalRead > totalSize) {
                  done(new BodyParserError("body-parser/multipart-total-too-large",
                    "multipart total request size exceeds totalSize (" + totalSize + ")",
                    true, 413));
                  return;
                }
                try {
                  var written = 0;
                  while (written < bodyChunk.length) {
                    written += nodeFs.writeSync(currentFd, bodyChunk, written, bodyChunk.length - written);
                  }
                } catch (e) {
                  done(new BodyParserError("body-parser/multipart-tmp-write",
                    "multipart tmp write failed: " + ((e && e.message) || String(e)),
                    true, 500));
                  return;
                }
                currentHash.update(bodyChunk);
              } else {
                // Field part — buffer in memory up to per-field-or-global cap.
                currentSize += bodyChunk.length;
                if (currentSize > currentEffectiveLimit) {
                  var perFieldText = (perField && perField[currentField] &&
                                      typeof perField[currentField].maxBytes === "number");
                  done(new BodyParserError("body-parser/multipart-field-too-large",
                    "multipart field '" + currentField + "' exceeds " +
                    (perFieldText ? "per-field maxBytes" : "fieldSize") +
                    " (" + currentEffectiveLimit + ")",
                    true, 413));
                  return;
                }
                totalRead += bodyChunk.length;
                if (totalRead > totalSize) {
                  done(new BodyParserError("body-parser/multipart-total-too-large",
                    "multipart total request size exceeds totalSize (" + totalSize + ")",
                    true, 413));
                  return;
                }
                currentBuf.push(bodyChunk);
              }
              pending = pending.slice(emitLen);
            }
            if (bdIdx === -1) return; // need more data
            // Consume the boundary delimiter; transition to AFTER_BD.
            pending = pending.slice(boundaryDelimBuf.length);
            // Finalize the current part.
            if (currentDiscarded) {
              // fileFilter rejected — already recorded in filesRejected; no
              // tmp file was opened, nothing to clean up here.
            } else if (currentFd !== null) {
              try { nodeFs.closeSync(currentFd); } catch (_e) { /* fd already closed */ }
              currentFd = null;
              files.push({
                field:    currentField,
                filename: currentFilename,
                mimeType: currentMime,
                path:     currentTmpPath,
                size:     currentSize,
                hash:     currentHash.digest("hex"),
              });
            } else {
              // Field part — flatten + decode UTF-8.
              var fbuf = Buffer.concat(currentBuf);
              var text = fbuf.toString("utf8");
              // Repeated field name → array, matching urlencoded parser.
              if (Object.prototype.hasOwnProperty.call(fields, currentField)) {
                // lgtm[js/remote-property-injection] — `currentField` is gated
                // upstream at lib/middleware/body-parser.js:867 by
                // POISONED_KEYS (__proto__ / constructor / prototype) which
                // refuses the multipart part with a 400 BodyParserError before
                // `currentField` is ever assigned. Reachable values cannot
                // pollute the prototype chain.
                if (Array.isArray(fields[currentField])) fields[currentField].push(text);
                else fields[currentField] = [fields[currentField], text];
              } else {
                // lgtm[js/remote-property-injection] — see upstream POISONED_KEYS
                // gate at lib/middleware/body-parser.js:867.
                fields[currentField] = text;
              }
            }
            currentHeaders = null;
            currentField = null;
            currentFilename = null;
            currentMime = null;
            currentTmpPath = null;
            currentSize = 0;
            currentHash = null;
            currentBuf = null;
            currentDiscarded = false;
            currentEffectiveLimit = 0;
            state = MP_AFTER_BD;
            continue;
          }
          if (state === MP_DONE) return;
        }
      }

      req.on("data", function (chunk) {
        if (resolved) return;
        pending = Buffer.concat([pending, chunk]);
        try { processBuffer(); }
        catch (e) {
          done(new BodyParserError("body-parser/multipart-internal",
            "multipart internal parse error: " + ((e && e.message) || String(e)),
            true, 500));
        }
      });
      req.on("end", function () {
        if (resolved) return;
        if (state !== MP_DONE) {
          done(new BodyParserError("body-parser/multipart-truncated",
            "multipart stream ended before final boundary", true, HTTP_STATUS.BAD_REQUEST));
          return;
        }
      });
      req.on("error", function (e) {
        if (resolved) return;
        done(new BodyParserError("body-parser/multipart-stream",
          "multipart stream error: " + ((e && e.message) || String(e)), true, HTTP_STATUS.BAD_REQUEST));
      });
    });
  } catch (e) {
    // Already cleaned up via done(err).
    throw e;
  }
}

// ---- main middleware factory ----

/**
 * @primitive b.middleware.bodyParser
 * @signature b.middleware.bodyParser(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.bodyParser.raw, b.parsers.json, b.parsers.multipart
 *
 * Buffers and parses request bodies based on Content-Type.
 * Constructed via `b.middleware.bodyParser(opts)`; the resulting
 * middleware has the `(req, res, next)` shape shown above. Five
 * sub-parsers ship: JSON (via `safe-json` — POISONED_KEYS stripped,
 * depth + size caps), urlencoded, text, raw octet-stream, and
 * multipart/form-data. Multipart streams file parts to a tmp dir
 * with per-file + total-request size caps, filename sanitization,
 * SHA3-512 hashing during streaming, and tmp-file cleanup on
 * response end. Defends against RFC 9112 §6.1 request smuggling
 * before any body bytes are read. Each sub-parser can be disabled
 * by passing `false` in its slot.
 *
 * @opts
 *   {
 *     json:        false | { limit, strict, charset, parseHook, contentTypes },
 *     urlencoded:  false | { limit, arrayLimit, contentTypes },
 *     text:        false | { limit, charset, contentTypes },
 *     raw:         false | { limit, contentTypes },
 *     multipart:   false | {
 *       tmpDir, fileSize, totalSize, fileCount, fieldCount, fieldSize,
 *       mimeAllowlist, fileFilter, fields, audit, contentTypes,
 *     },
 *     keepRawBody: boolean,    // expose req.bodyRaw for webhook signing
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.bodyParser({
 *     json:       { limit: b.constants.BYTES.mib(1) },
 *     urlencoded: { limit: b.constants.BYTES.mib(1) },
 *     multipart:  false,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "json", "urlencoded", "text", "raw", "multipart", "keepRawBody",
  ], "middleware.bodyParser");

  function _resolve(name) {
    if (opts[name] === false) return null; // disabled
    return Object.assign({}, DEFAULTS[name], opts[name] || {});
  }
  var jsonOpts        = _resolve("json");
  var urlencodedOpts  = _resolve("urlencoded");
  var textOpts        = _resolve("text");
  var rawOpts         = _resolve("raw");
  var multipartOpts   = _resolve("multipart");
  var keepRawBody     = !!opts.keepRawBody;

  return async function bodyParser(req, res, next) {
    // RFC 9112 §6.1 request-smuggling defense — runs BEFORE _hasBody
    // so the smuggling shape is rejected even if the request would
    // otherwise short-circuit as no-body. Reject with 400 +
    // Connection: close so the upstream proxy doesn't reuse the socket.
    var smug = _detectSmuggling(req);
    if (smug) {
      if (!res.headersSent) {
        var smugBody = JSON.stringify({ error: smug.message, code: smug.code });
        res.writeHead(smug.status, {
          "Content-Type":   "application/json; charset=utf-8",
          "Content-Length": Buffer.byteLength(smugBody),
          "Connection":     "close",
        });
        res.end(smugBody);
      }
      return;
    }
    if (!_hasBody(req)) return next();
    if (req.body !== undefined) return next(); // already parsed by an earlier middleware

    var ct = _contentType(req);

    try {
      if (jsonOpts && _typeMatches(ct.type, jsonOpts.contentTypes)) {
        if (keepRawBody) {
          var rawBuf = await _bufferBody(req, jsonOpts.limit);
          req.bodyRaw = rawBuf;
          req.body = rawBuf.length === 0 ? undefined : await _parseJsonFromBuf(rawBuf, jsonOpts);
        } else {
          req.body = await _parseJson(req, jsonOpts);
        }
        return next();
      }
      if (urlencodedOpts && _typeMatches(ct.type, urlencodedOpts.contentTypes)) {
        req.body = await _parseUrlencoded(req, urlencodedOpts);
        return next();
      }
      if (multipartOpts && _typeMatches(ct.type, multipartOpts.contentTypes)) {
        var mpResult = await _parseMultipart(req, multipartOpts, ct.params);
        req.body = mpResult.fields;
        req.files = mpResult.files;
        req.filesRejected = mpResult.filesRejected || [];
        // Cleanup tmp files when the response finishes / closes / errors,
        // regardless of whether the handler returned cleanly. Operators
        // who want to KEEP a file move it elsewhere inside the handler.
        var cleanedUp = false;
        function cleanup() {
          if (cleanedUp) return;
          cleanedUp = true;
          for (var i = 0; i < mpResult.files.length; i++) {
            try { nodeFs.unlinkSync(mpResult.files[i].path); } catch (_e) { /* tmp file already removed */ }
          }
        }
        res.on("finish", cleanup);
        res.on("close",  cleanup);
        return next();
      }
      if (textOpts && _typeMatches(ct.type, textOpts.contentTypes)) {
        req.body = await _parseText(req, textOpts);
        return next();
      }
      if (rawOpts && _typeMatches(ct.type, rawOpts.contentTypes)) {
        req.body = await _parseRaw(req, rawOpts);
        return next();
      }
      // Body present but no enabled sub-parser matches the Content-Type.
      // Don't reject silently — operators with a custom parser opted in
      // by NOT enabling any sub-parser for this Content-Type would skip
      // bodyParser entirely. Reaching here means: enabled parsers exist
      // but none match this body. 415 is honest about the mismatch.
      _writeError(res, 415,
        "Unsupported Content-Type '" + ct.type + "'. Enable a matching sub-parser or send a different type.",
        "body-parser/unsupported-content-type"
      );
    } catch (e) {
      // RFC 9112 §7.1 — a server that rejects a chunked-decoded body
      // MUST close the connection so the upstream proxy cannot reuse
      // the socket with the next request's bytes still in flight. The
      // smuggling-shape pre-flight at top of the request already
      // catches the static TE/CL conflict cases; this catch handles
      // mid-stream parser failure (HPE_INVALID_CHUNK_SIZE etc. surfaced
      // by Node's HTTP parser as the body bytes arrive). Set
      // Connection: close + audit + 400.
      if (_isChunkedMalformed(e)) {
        // CVE-2026-33870 — chunked-encoding extension smuggling. When
        // Node's parser surfaces HPE_CHUNK_EXTENSIONS_OVERFLOW the
        // chunk-extension parameters exceeded llhttp's cap; the
        // framework emits a distinct audit action so operators can
        // alert on extension-smuggling specifically. RFC 9112 §7.1.1
        // chunk-ext is `; chunk-ext-name [= chunk-ext-val]` per chunk;
        // multi-`;` and `;param=value` shapes reach this code path
        // when the operator sets a tighter
        // `--max-http-header-size` / per-chunk extension cap.
        var chunkAction = (e && e.code === "HPE_CHUNK_EXTENSIONS_OVERFLOW")
          ? "http.chunked.extension.refused"
          : "http.chunked.malformed.refused";
        try {
          audit().safeEmit({
            action:  chunkAction,
            outcome: "denied",
            metadata: {
              code:    e.code || null,
              message: (e && e.message) ? String(e.message).slice(0, 256) : "",                                  // allow:raw-byte-literal — diagnostic-message clamp characters, not bytes
            },
          });
        } catch (_e) { /* audit best-effort */ }
        if (!res.headersSent) {
          var malformedBody = JSON.stringify({
            error: "malformed chunked transfer-encoding (RFC 9112 §7.1 — connection closed)",
            code:  "http/chunked-malformed",
          });
          res.writeHead(HTTP_STATUS.BAD_REQUEST, {
            "Content-Type":   "application/json; charset=utf-8",
            "Content-Length": Buffer.byteLength(malformedBody),
            "Connection":     "close",
          });
          res.end(malformedBody);
        }
        try { req.destroy(); } catch (_e) { /* socket already closed */ }
        return;
      }
      var status = (e && typeof e.statusCode === "number") ? e.statusCode : HTTP_STATUS.BAD_REQUEST;
      var code   = (e && typeof e.code === "string") ? e.code : "body-parser/error";
      var message = (e && e.message) ? e.message : String(e);
      _writeError(res, status, message, code);
    }
  };
}

// Helper used by keepRawBody path — re-uses the JSON pipeline but
// works from an already-buffered Buffer (so we don't read req twice).
async function _parseJsonFromBuf(buf, opts) {
  var text = buf.toString(opts.charset);
  if (opts.strict) {
    var head = text.replace(/^[\s\u00A0\uFEFF]+/, "")[0];
    if (head !== "{" && head !== "[") {
      throw new BodyParserError("body-parser/json-strict",
        "JSON body must start with '{' or '[' (strict mode)", true, HTTP_STATUS.BAD_REQUEST);
    }
  }
  var parsed;
  try { parsed = safeJson.parse(text, { maxBytes: opts.limit }); }
  catch (e) {
    throw new BodyParserError("body-parser/json-malformed",
      "JSON parse failed: " + ((e && e.message) || String(e)), true, HTTP_STATUS.BAD_REQUEST);
  }
  if (typeof opts.parseHook === "function") {
    try { parsed = opts.parseHook(parsed); }
    catch (e) {
      throw new BodyParserError("body-parser/json-hook",
        "JSON parseHook failed: " + ((e && e.message) || String(e)), true, HTTP_STATUS.BAD_REQUEST);
    }
  }
  return parsed;
}

// raw — convenience wrapper that returns a middleware which buffers
// the request body as a Buffer regardless of Content-Type. Webhook
// signature-verification routes use this — the HMAC is computed over
// the literal body bytes, so JSON-parsing first would change them.
//
//   router.post("/hooks/in", b.middleware.bodyParser.raw(), function (req, res) {
//     verifier.verify(req.headers["x-signature"], req.body);  // req.body is a Buffer
//   });
//
// Accepts the same `raw`-section opts as create() (limit, contentTypes).
// contentTypes default expands to `["*/*"]` so any Content-Type lands
// as raw bytes.

/**
 * @primitive b.middleware.bodyParser.raw
 * @signature b.middleware.bodyParser.raw(opts)
 * @since     0.1.0
 * @related   b.middleware.bodyParser
 *
 * Convenience factory that mounts only the raw-bytes sub-parser of
 * `bodyParser`. Sets `req.body` to a Buffer regardless of
 * `Content-Type`. Use on webhook-signature routes where the HMAC is
 * computed over the literal body bytes — JSON-parsing first would
 * change them. The `contentTypes` default expands to `["*\/*"]` so
 * any inbound type is captured.
 *
 * @opts
 *   {
 *     limit:        number,    // default ~10 MiB
 *     contentTypes: string[],  // default ["*\/*"]
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/hooks/in", b.middleware.bodyParser.raw({
 *     limit: b.constants.BYTES.mib(1),
 *   }), function (req, res) {
 *     // req.body is a Buffer of the raw request bytes
 *     res.end(String(req.body.length));
 *   });
 */
function raw(opts) {
  opts = opts || {};
  return create({
    json:        false,
    urlencoded:  false,
    text:        false,
    multipart:   false,
    raw: {
      limit:        opts.limit != null ? opts.limit : DEFAULTS.raw.limit,
      contentTypes: opts.contentTypes || ["*/*"],
    },
  });
}

// Attach raw onto create so b.middleware.bodyParser.raw() works
// (middleware/index.js exports the create function as the namespace
// itself, so static helpers hang off it).
create.raw = raw;

// ---- Standalone async parsers ----
//
// `parseJsonStandalone(req, opts)` and `parseMultipartStandalone(req, opts)`
// are the same parsing pipelines the middleware uses, exposed for handlers
// that lazy-parse — code that decides parser shape from a route flag, or
// bypasses the middleware for streaming endpoints. The middleware composes
// these so there's no parallel pipeline to drift.
//
// Throws BodyParserError on caps / malformed shapes — operator handles in
// a try/catch around `await b.parsers.json(req, ...)` /
// `await b.parsers.multipart(req, ...)`. Validation tier is config-time
// (throw at create on bad opts) + observable (throw on bad input — the
// handler is awaiting the call, not a request lifecycle hook).

function _resolveStandaloneJsonOpts(opts) {
  opts = opts || {};
  var maxBytes = (opts.maxBytes !== undefined) ? opts.maxBytes : DEFAULTS.json.limit;
  validateOpts.optionalPositiveFinite(maxBytes, "parsers.json: opts.maxBytes",
    BodyParserError, "body-parser/bad-max-bytes");
  var strict = (opts.strict !== undefined) ? !!opts.strict : DEFAULTS.json.strict;
  var charset = (typeof opts.charset === "string") ? opts.charset : DEFAULTS.json.charset;
  return {
    limit:     maxBytes,
    strict:    strict,
    charset:   charset,
    parseHook: (typeof opts.parseHook === "function") ? opts.parseHook : undefined,
  };
}

function _resolveStandaloneMultipartOpts(opts, ct) {
  opts = opts || {};
  var resolved = Object.assign({}, DEFAULTS.multipart);
  validateOpts.optionalPositiveFinite(opts.maxBytes, "parsers.multipart: opts.maxBytes",
    BodyParserError, "body-parser/bad-max-bytes");
  if (opts.maxBytes !== undefined) {
    resolved.totalSize = opts.maxBytes;
    // Per-file cap clamps to maxBytes so a single field can't exceed the
    // request total — operator opts in to a smaller fileSize via opts.fileSize.
    if (resolved.fileSize > opts.maxBytes) resolved.fileSize = opts.maxBytes;
  }
  if (opts.maxFiles !== undefined) {
    var mf = opts.maxFiles;
    var mfBad = typeof mf !== "number" || !isFinite(mf) || mf <= 0 || Math.floor(mf) !== mf;
    if (mfBad) {
      throw new BodyParserError("body-parser/bad-max-files",
        "parsers.multipart: opts.maxFiles must be a positive integer",
        true, HTTP_STATUS.BAD_REQUEST);
    }
    resolved.fileCount = mf;
  }
  // Pass-through overrides for the multipart-specific knobs the middleware
  // accepts. parsers.multipart is a thin wrapper, not a feature subset.
  ["tmpDir", "fileSize", "fieldCount", "fieldSize", "mimeAllowlist",
   "fileFilter", "fields", "audit"].forEach(function (k) {
    if (opts[k] !== undefined) resolved[k] = opts[k];
  });
  // ct is the parsed Content-Type; required for the boundary parameter.
  if (!ct || typeof ct.type !== "string" || ct.type !== "multipart/form-data") {
    throw new BodyParserError("body-parser/standalone-not-multipart",
      "parsers.multipart: request Content-Type must be multipart/form-data, got " +
      JSON.stringify(ct ? ct.type : null),
      true, HTTP_STATUS.BAD_REQUEST);
  }
  return resolved;
}

async function parseJsonStandalone(req, opts) {
  var resolved = _resolveStandaloneJsonOpts(opts);
  return _parseJson(req, resolved);
}

async function parseMultipartStandalone(req, opts) {
  var ct = _contentType(req);
  var resolved = _resolveStandaloneMultipartOpts(opts, ct);
  // Returns { fields, files, filesRejected } — same shape the middleware
  // attaches to req. Handlers that already-accepted the upload wire
  // cleanup themselves (move file off tmp / unlink).
  return _parseMultipart(req, resolved, ct.params);
}

module.exports = {
  create:           create,
  raw:              raw,
  BodyParserError:  BodyParserError,
  // Standalone async helpers — surfaced via b.parsers.{json,multipart}.
  // The middleware composes these so the request-handling pipeline and
  // the operator-callable surface share one parsing nodePath.
  parseJson:        parseJsonStandalone,
  parseMultipart:   parseMultipartStandalone,
  // Internal helpers exposed for tests + the csrf-protect refactor.
  _contentType:     _contentType,
  _hasBody:         _hasBody,
  _sanitizeFilename: _sanitizeFilename,
  POISONED_KEYS:    POISONED_KEYS,
};
