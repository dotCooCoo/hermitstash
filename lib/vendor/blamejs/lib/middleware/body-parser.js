// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeFs = require("node:fs");
var pick = require("../pick");
var numericBounds = require("../numeric-bounds");
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
var codepointClass  = require("../codepoint-class");
var C = require("../constants");
var { defineClass } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });

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

function _mapFromPairs(pairs) {
  var safe = [];
  for (var i = 0; i < pairs.length; i++) {
    if (pick.isPoisonedKey(pairs[i][0])) continue;
    safe.push(pairs[i]);
  }
  return Object.assign(Object.create(null), Object.fromEntries(safe));
}

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
    storage:       "disk",
    tmpDir:        null,
    fileSize:      C.BYTES.mib(10),
    totalSize:     C.BYTES.mib(50),
    fileCount:     20,
    fieldCount:    100,
    fieldSize:     C.BYTES.mib(1),
    mimeAllowlist: null,
    fileFilter:    null,
    fields:        null,
    audit:         null,
    filenameCharsets: ["utf-8"],
    contentTypes:  ["multipart/form-data"],
  },
});

var BODY_BEARING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

var URLENCODED_KEY_HEADROOM = C.BYTES.bytes(1000);

function _contentType(req) {
  var ct = req.headers && req.headers["content-type"];
  if (typeof ct !== "string") return { type: "", params: {} };
  var idx = ct.indexOf(";");
  var type = (idx === -1 ? ct : ct.slice(0, idx)).trim().toLowerCase();
  var paramPairs = [];
  if (idx !== -1) {
    var rest = ct.slice(idx + 1);
    var kvps = structuredFields.parseKeyValuePieces(
      structuredFields.splitTopLevel(rest, ";"));
    structuredFields.forEachKeyValue(kvps, function (key, v) {
      var _unq = structuredFields.unquoteSfString(v);
      if (_unq !== null) v = _unq;
      paramPairs.push([key, v]);
    });
  }
  return { type: type, params: _mapFromPairs(paramPairs) };
}

function _typeMatches(actual, allowed) {
  var ab = actual.split("/");
  for (var i = 0; i < allowed.length; i++) {
    var a = allowed[i].toLowerCase();
    if (a === actual) return true;
    var pb = a.split("/");
    if (pb.length === 2 && ab.length === 2 &&
        (pb[0] === "*" || pb[0] === ab[0]) &&
        (pb[1] === "*" || pb[1] === ab[1])) return true;
  }
  return false;
}

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
    if (clNum === 0) return false;
    return true;
  }
  var te = req.headers && req.headers["transfer-encoding"];
  if (typeof te === "string" && te.length > 0) return true;
  return false;
}

function _detectSmuggling(req) {
  var headers = req.headers || {};
  var cl = headers["content-length"];
  var te = headers["transfer-encoding"];

  if (typeof cl === "string" && cl.length > 0 &&
      typeof te === "string" && te.length > 0) {
    return {
      status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/te-cl-conflict",
      message: "request has both Content-Length and Transfer-Encoding " +
               "headers (RFC 9112 §6.1 — request-smuggling vector)",
    };
  }

  if (typeof cl === "string" && cl.indexOf(",") !== -1) {
    return {
      status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/multiple-content-length",
      message: "request has multiple Content-Length values (RFC 9112 §6.1)",
    };
  }

  if (typeof te === "string" && te.length > 0) {
    var tokens = te.toLowerCase().split(",").map(function (t) { return t.trim(); });
    var last = tokens[tokens.length - 1];
    if (last !== "chunked") {
      return {
        status: HTTP_STATUS.BAD_REQUEST, code: "smuggling/te-not-chunked",
        message: "request has Transfer-Encoding but final coding is not " +
                 "`chunked` (RFC 9112 §6.1 requires chunked be last)",
      };
    }
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

var _GENERIC_REASON = {};
_GENERIC_REASON[HTTP_STATUS.BAD_REQUEST]            = "Bad Request";
_GENERIC_REASON[HTTP_STATUS.PAYLOAD_TOO_LARGE]      = "Payload Too Large";
_GENERIC_REASON[HTTP_STATUS.UNSUPPORTED_MEDIA_TYPE] = "Unsupported Media Type";
_GENERIC_REASON[HTTP_STATUS.INTERNAL_SERVER_ERROR]  = "Internal Server Error";
function _genericReason(status) {
  return _GENERIC_REASON[status] || (status >= 500 ? "Internal Server Error" : "Bad Request");
}

function _writeError(res, status, message, code) {
  if (res.headersSent) return;
  var body = JSON.stringify({ error: message, code: code });
  res.writeHead(status, {
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Connection":     "close",
  });
  res.end(body);
}

function _bufferBody(req, limit) {
  return new Promise(function (resolve, reject) {
    var cl = req.headers && req.headers["content-length"];
    if (typeof cl === "string") {
      var clNum = _parseContentLength(cl);
      if (clNum === null) {
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
    safeBuffer.collectStream(req, {
      maxBytes:    limit,
      errorClass:  BodyParserError,
      sizeCode:    "body-parser/too-large",
      sizeMessage: "request body exceeds limit",
    }).then(resolve, function (e) {
      if (e && e.isBodyParserError) e.statusCode = HTTP_STATUS.PAYLOAD_TOO_LARGE;
      reject(e);
    });
  });
}

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
    catch (_e) {
      throw new BodyParserError(
        "body-parser/json-hook",
        "request body rejected by parse hook",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
  }
  return parsed;
}

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
  var seen = Object.create(null);
  var keys = [];
  sp.forEach(function (value, key) { keys.push([key, value]); });
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i][0];
    var v = keys[i][1];
    if (pick.isPoisonedKey(k)) {
      throw new BodyParserError(
        "body-parser/urlencoded-poisoned-key",
        "urlencoded body contains forbidden key '" + k + "' (prototype-pollution defense)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
    keyCount++;
    if (keyCount > opts.arrayLimit + URLENCODED_KEY_HEADROOM) {
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

async function _parseText(req, opts) {
  var buf = await _bufferBody(req, opts.limit);
  return buf.toString(opts.charset);
}

async function _parseRaw(req, opts) {
  return await _bufferBody(req, opts.limit);
}

var MP_INITIAL  = 0;
var MP_AFTER_BD = 1;
var MP_HEADERS  = 2;
var MP_BODY     = 3;
var MP_DONE     = 4;

function _sanitizeFilename(name) {
  if (typeof name !== "string") return null;
  var s = name.replace(/\\/g, "/");
  var idx = s.lastIndexOf("/");
  if (idx !== -1) s = s.slice(idx + 1);
  s = s.replace(/\p{Cc}/gu, "");
  s = s.replace(/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/g, "");
  s = codepointClass.trimTrailingChars(s.replace(/^\.+/, ""), ".");
  if (s.length === 0) return null;
  if (s.length > 255) s = s.slice(0, 255);
  if (s === "." || s === "..") return null;
  return s;
}

function _parseMultipartHeaders(rawHeaders) {
  var lines = rawHeaders.split("\r\n");
  var headerPairs = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var first = line.charCodeAt(0);
    if (first === 32 || first === 9) {
      throw new BodyParserError(
        "body-parser/multipart-obs-fold",
        "multipart part header uses obsolete line folding (RFC 9112 §5.2)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) continue;
    var k = khv.key;
    var v = khv.value.trim();
    if (safeBuffer.hasCrlfOrNul(v)) {
      throw new BodyParserError(
        "body-parser/multipart-bad-header-value",
        "multipart part header `" + k + "` contains CR/LF/NUL (RFC 9110 §5.5)",
        true, HTTP_STATUS.BAD_REQUEST
      );
    }
    headerPairs.push([k, v]);
  }
  return _mapFromPairs(headerPairs);
}

function _percentDecodeLatin1(encoded) {
  var out = "";
  for (var i = 0; i < encoded.length; i += 1) {
    var ch = encoded.charAt(i);
    if (ch === "%") {
      var hex = encoded.substr(i + 1, 2);
      if (hex.length !== 2 || !codepointClass.HEX_PAIR_RE.test(hex)) return null;
      out += String.fromCharCode(parseInt(hex, 16));
      i += 2;
    } else {
      out += ch;
    }
  }
  return out;
}

function _decodeRfc5987(raw, allowed) {
  if (typeof raw !== "string") return null;
  var firstTick  = raw.indexOf("'");
  if (firstTick === -1) return null;
  var secondTick = raw.indexOf("'", firstTick + 1);
  if (secondTick === -1) return null;
  var charset = raw.slice(0, firstTick).toLowerCase();
  var encoded = raw.slice(secondTick + 1);
  if (charset === "utf-8") {
    try {
      return decodeURIComponent(encoded);
    } catch (_e) {
      return null;
    }
  }
  if (charset === "iso-8859-1" && allowed && allowed.indexOf("iso-8859-1") !== -1) {
    return _percentDecodeLatin1(encoded);
  }
  return null;
}

function _parseHeaderParams(headerValue, filenameCharsets) {
  if (!headerValue) return _mapFromPairs([["_value", ""]]);
  var parts = structuredFields.splitTopLevel(headerValue, ";");
  var paramPairs = [["_value", parts[0].trim().toLowerCase()]];
  var extName = null;
  var kvps = structuredFields.parseKeyValuePieces(parts, 1);
  structuredFields.forEachKeyValue(kvps, function (k, v) {
    var _unq = structuredFields.unquoteSfString(v);
    if (_unq !== null) v = _unq;
    if (k.charAt(k.length - 1) === "*") {
      var decoded = _decodeRfc5987(v, filenameCharsets);
      if (decoded !== null) {
        var bareKey = k.slice(0, -1);
        if (bareKey === "filename") extName = decoded;
        paramPairs.push([bareKey, decoded]);
      }
      return;
    }
    paramPairs.push([k, v]);
  });
  if (extName !== null) paramPairs.push(["filename", extName]);
  return _mapFromPairs(paramPairs);
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
  if (boundary.length > 70 ||
      !/^[A-Za-z0-9'()+_,\-./:=?]{1,70}$/.test(boundary)) {
    throw new BodyParserError(
      "body-parser/multipart-bad-boundary",
      "multipart boundary violates RFC 2046 §5.1.1 (1-70 chars, bcharsnospace grammar)",
      true, HTTP_STATUS.BAD_REQUEST
    );
  }
  var filenameCharsets = ["utf-8"];
  if (Array.isArray(opts.filenameCharsets)) {
    filenameCharsets = opts.filenameCharsets.map(function (c) {
      return String(c).toLowerCase();
    });
    if (filenameCharsets.indexOf("utf-8") === -1) filenameCharsets.push("utf-8");
  }
  var useMemory = opts.storage === "memory";
  var tmpDir = useMemory ? null : (opts.tmpDir || nodePath.join(os.tmpdir(), "blamejs-uploads"));
  if (!useMemory) {
    try { atomicFile.ensureDir(tmpDir, 0o700); }
    catch (e) {
      throw new BodyParserError(
        "body-parser/multipart-tmpdir",
        "could not create multipart tmp dir '" + tmpDir + "': " + ((e && e.message) || String(e)),
        true, 500
      );
    }
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
  var currentBuf = null;
  var currentIsFile = false;
  var currentDiscarded = false;
  var currentEffectiveLimit = 0;

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
      if (files[i].path) { try { nodeFs.unlinkSync(files[i].path); } catch (_e) { /* tmp file already removed */ } }
    }
  }

  try {
    return await new Promise(function (resolve, reject) {
      function done(err, value) {
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
        while (true) {
          if (state === MP_INITIAL) {
            var firstIdx = pending.indexOf(boundaryBuf);
            if (firstIdx === -1) {
              if (pending.length > boundary.length + 100) {
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
            if (pending[0] === 0x2d && pending[1] === 0x2d) {
              state = MP_DONE;
              done(null, { fields: fields, files: files, filesRejected: filesRejected });
              return;
            }
            if (pending[0] === 0x0d && pending[1] === 0x0a) {
              pending = pending.slice(2);
              state = MP_HEADERS;
              continue;
            }
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
            var headEnd = pending.indexOf("\r\n\r\n");
            if (headEnd === -1) {
              if (safeBuffer.byteLengthOf(pending) > C.BYTES.kib(16)) {
                done(new BodyParserError("body-parser/multipart-headers-too-large",
                  "multipart part headers exceed 16KB", true, 413));
                return;
              }
              return;
            }
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
            var cd = _parseHeaderParams(currentHeaders["content-disposition"], filenameCharsets);
            if (cd._value !== "form-data" || typeof cd.name !== "string" || cd.name.length === 0) {
              done(new BodyParserError("body-parser/multipart-bad-disposition",
                "multipart part missing form-data Content-Disposition", true, HTTP_STATUS.BAD_REQUEST));
              return;
            }
            if (pick.isPoisonedKey(cd.name)) {
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
              currentEffectiveLimit = (fieldRule && typeof fieldRule.maxBytes === "number")
                                          ? fieldRule.maxBytes : fileSize;

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
                  currentDiscarded = true;
                  fileCount--;
                  currentSize = 0;
                  state = MP_BODY;
                  continue;
                }
              }

              currentIsFile = true;
              if (useMemory) {
                currentBuf = [];
              } else {
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
            var bdIdx = pending.indexOf(boundaryDelimBuf);
            var emitLen;
            if (bdIdx === -1) {
              if (pending.length <= boundaryDelimBuf.length) return;
              emitLen = pending.length - boundaryDelimBuf.length;
            } else {
              emitLen = bdIdx;
            }
            if (emitLen > 0) {
              var bodyChunk = pending.slice(0, emitLen);
              if (currentDiscarded) {
                totalRead += bodyChunk.length;
                if (totalRead > totalSize) {
                  done(new BodyParserError("body-parser/multipart-total-too-large",
                    "multipart total request size exceeds totalSize (" + totalSize + ")",
                    true, 413));
                  return;
                }
              } else if (currentIsFile) {
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
                if (currentFd !== null) {
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
                } else {
                  currentBuf.push(bodyChunk);
                }
                currentHash.update(bodyChunk);
              } else {
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
            if (bdIdx === -1) return;
            pending = pending.slice(boundaryDelimBuf.length);
            if (currentDiscarded) {
              // fileFilter rejected — already recorded in filesRejected; no
              // tmp file was opened, nothing to clean up here.
            } else if (currentIsFile) {
              var fileEntry = {
                field:    currentField,
                filename: currentFilename,
                mimeType: currentMime,
                path:     null,
                buffer:   null,
                size:     currentSize,
                hash:     currentHash.digest("hex"),
              };
              if (currentFd !== null) {
                try { nodeFs.closeSync(currentFd); } catch (_e) { /* fd already closed */ }
                currentFd = null;
                fileEntry.path = currentTmpPath;
              } else {
                fileEntry.buffer = Buffer.concat(currentBuf);
              }
              files.push(fileEntry);
            } else {
              var fbuf = Buffer.concat(currentBuf);
              var text = fbuf.toString("utf8");
              var fieldName = currentField;
              var prior = Object.prototype.hasOwnProperty.call(fields, fieldName)
                            ? fields[fieldName] : undefined;
              var nextValue;
              if (prior === undefined) {
                nextValue = text;
              } else if (Array.isArray(prior)) {
                prior.push(text);
                nextValue = prior;
              } else {
                nextValue = [prior, text];
              }
              Object.assign(fields, Object.fromEntries([[fieldName, nextValue]]));
            }
            currentHeaders = null;
            currentField = null;
            currentFilename = null;
            currentMime = null;
            currentTmpPath = null;
            currentSize = 0;
            currentHash = null;
            currentBuf = null;
            currentIsFile = false;
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
    throw e;
  }
}

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
 * (`storage: "disk"`, default) or buffers them in RAM
 * (`storage: "memory"` — for read-only / serverless filesystems,
 * exposing `req.files[].buffer` instead of `.path`), with per-file +
 * total-request size caps, filename sanitization, SHA3-512 hashing
 * during streaming, and tmp-file cleanup on response end. Defends
 * against RFC 9112 §6.1 request smuggling before any body bytes are
 * read. Each sub-parser can be disabled by passing `false` in its slot.
 *
 * @opts
 *   {
 *     json:        false | { limit, strict, charset, parseHook, contentTypes },
 *     urlencoded:  false | { limit, arrayLimit, contentTypes },
 *     text:        false | { limit, charset, contentTypes },
 *     raw:         false | { limit, contentTypes },
 *     multipart:   false | {
 *       storage, tmpDir, fileSize, totalSize, fileCount, fieldCount,
 *       fieldSize, mimeAllowlist, fileFilter, fields, audit,
 *       filenameCharsets, contentTypes,
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
    if (opts[name] === false) return null;
    return Object.assign({}, DEFAULTS[name], opts[name] || {});
  }
  var jsonOpts        = _resolve("json");
  var urlencodedOpts  = _resolve("urlencoded");
  var textOpts        = _resolve("text");
  var rawOpts         = _resolve("raw");
  var multipartOpts   = _resolve("multipart");
  if (multipartOpts && multipartOpts.storage !== "disk" && multipartOpts.storage !== "memory") {
    throw new TypeError(
      "middleware.bodyParser: multipart.storage must be \"disk\" or \"memory\" (got " +
      JSON.stringify(multipartOpts.storage) + ")");
  }
  var keepRawBody     = !!opts.keepRawBody;

  return async function bodyParser(req, res, next) {
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
    if (req.body !== undefined) return next();

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
        var cleanedUp = false;
        function cleanup() {
          if (cleanedUp) return;
          cleanedUp = true;
          for (var i = 0; i < mpResult.files.length; i++) {
            if (mpResult.files[i].path) {
              try { nodeFs.unlinkSync(mpResult.files[i].path); } catch (_e) { /* tmp file already removed */ }
            }
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
      _writeError(res, 415,
        "Unsupported Content-Type '" + ct.type + "'. Enable a matching sub-parser or send a different type.",
        "body-parser/unsupported-content-type"
      );
    } catch (e) {
      if (_isChunkedMalformed(e)) {
        var chunkAction = (e && e.code === "HPE_CHUNK_EXTENSIONS_OVERFLOW")
          ? "http.chunked.extension.refused"
          : "http.chunked.malformed.refused";
        try {
          audit().safeEmit({
            action:  chunkAction,
            outcome: "denied",
            metadata: {
              code:    e.code || null,
              message: (e && e.message) ? String(e.message).slice(0, 256) : "",
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
      var eo = Object(e);
      var clientMessage = (eo.isBodyParserError === true && status < 500 && typeof eo.message === "string")
        ? eo.message
        : _genericReason(status);
      try {
        audit().safeEmit({
          action:  "body-parser.error",
          outcome: status >= 500 ? "failure" : "denied",
          metadata: {
            status:  status,
            code:    code,
            message: (e && e.message) ? String(e.message).slice(0, 256) : "",
          },
        });
      } catch (_e) { /* audit best-effort — never mask the response */ }
      _writeError(res, status, clientMessage, code);
    }
  };
}

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
    catch (_e) {
      throw new BodyParserError("body-parser/json-hook",
        "request body rejected by parse hook", true, HTTP_STATUS.BAD_REQUEST);
    }
  }
  return parsed;
}

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

create.raw = raw;

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
    if (resolved.fileSize > opts.maxBytes) resolved.fileSize = opts.maxBytes;
  }
  if (opts.maxFiles !== undefined) {
    var mf = opts.maxFiles;
    numericBounds.requirePositiveFiniteInt(mf,
      "parsers.multipart: opts.maxFiles", BodyParserError, "body-parser/bad-max-files",
      null, { permanent: true, statusCode: HTTP_STATUS.BAD_REQUEST });
    resolved.fileCount = mf;
  }
  var STANDALONE_MULTIPART_EXCLUDE = { totalSize: true, fileCount: true, contentTypes: true };
  Object.keys(DEFAULTS.multipart).forEach(function (k) {
    if (STANDALONE_MULTIPART_EXCLUDE[k]) return;
    if (opts[k] !== undefined) resolved[k] = opts[k];
  });
  if (resolved.storage !== "disk" && resolved.storage !== "memory") {
    throw new TypeError(
      "parsers.multipart: storage must be \"disk\" or \"memory\" (got " +
      JSON.stringify(resolved.storage) + ")");
  }
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
  return _parseMultipart(req, resolved, ct.params);
}

module.exports = {
  create:           create,
  raw:              raw,
  BodyParserError:  BodyParserError,
  parseJson:        parseJsonStandalone,
  parseMultipart:   parseMultipartStandalone,
  _contentType:     _contentType,
  _hasBody:         _hasBody,
  _sanitizeFilename: _sanitizeFilename,
  POISONED_KEYS:    new Set(pick.POISONED_KEYS),
};
