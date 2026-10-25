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
    parseHook:    null,
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

var MULTIPART_FILENAME_CHARSETS = ["utf-8", "iso-8859-1"];
var FIELD_RULE_KEYS = ["maxBytes", "mimeTypes"];
var INT_OPT_ERROR = { permanent: true, statusCode: HTTP_STATUS.BAD_REQUEST };

function _bpError(code, message) {
  return new BodyParserError(code, message, true, HTTP_STATUS.BAD_REQUEST);
}

function _requireBpInt(value, label, code) {
  numericBounds.requirePositiveFiniteInt(value, label, BodyParserError, code, null, INT_OPT_ERROR);
}

function _requireCharset(value, label) {
  if (typeof value !== "string" || !Buffer.isEncoding(value)) {
    throw _bpError("body-parser/bad-charset",
      label + " must be an encoding Node's Buffer supports, got " + JSON.stringify(value));
  }
}

function _requireContentTypes(value, label) {
  validateOpts.optionalNonEmptyStringArray(value, label, BodyParserError, "body-parser/bad-content-types");
  if (!Array.isArray(value)) {
    throw _bpError("body-parser/bad-content-types", label + " must be an array of media types");
  }
}

function _validateFieldRules(fields, label) {
  if (fields === null) return;
  validateOpts.optionalPlainObject(fields, label, BodyParserError, "body-parser/bad-fields",
    "must be a plain object of per-field rules");
  Object.keys(fields).forEach(function (name) {
    var rule = fields[name];
    var ruleLabel = label + "." + name;
    validateOpts.optionalPlainObject(rule, ruleLabel, BodyParserError, "body-parser/bad-fields",
      "must be a plain object { maxBytes?, mimeTypes? }");
    if (rule === null || rule === undefined) {
      throw _bpError("body-parser/bad-fields", ruleLabel + " must be a plain object { maxBytes?, mimeTypes? }");
    }
    validateOpts.checkOrThrow(rule, FIELD_RULE_KEYS, ruleLabel, BodyParserError, "body-parser/bad-fields");
    if (rule.maxBytes !== undefined) _requireBpInt(rule.maxBytes, ruleLabel + ".maxBytes", "body-parser/bad-fields");
    validateOpts.optionalNonEmptyStringArray(rule.mimeTypes, ruleLabel + ".mimeTypes",
      BodyParserError, "body-parser/bad-fields");
  });
}

function _validateMultipartShared(o, label) {
  if (o.storage !== "disk" && o.storage !== "memory") {
    throw new TypeError(label + ": storage must be \"disk\" or \"memory\" (got " +
      JSON.stringify(o.storage) + ")");
  }
  if (o.tmpDir !== null) {
    validateOpts.requireNonEmptyString(o.tmpDir, label + ": tmpDir", BodyParserError, "body-parser/bad-tmp-dir");
  }
  _requireBpInt(o.fileSize,   label + ": fileSize",   "body-parser/bad-file-size");
  _requireBpInt(o.fieldCount, label + ": fieldCount", "body-parser/bad-field-count");
  _requireBpInt(o.fieldSize,  label + ": fieldSize",  "body-parser/bad-field-size");
  validateOpts.optionalNonEmptyStringArray(o.mimeAllowlist, label + ": mimeAllowlist",
    BodyParserError, "body-parser/bad-mime-allowlist");
  validateOpts.optionalFunction(o.fileFilter, label + ": fileFilter", BodyParserError, "body-parser/bad-file-filter");
  validateOpts.auditShape(o.audit, label, BodyParserError, "body-parser/bad-audit");
  _validateFieldRules(o.fields, label + ": fields");
  if (!Array.isArray(o.filenameCharsets) || o.filenameCharsets.some(function (c) {
    return typeof c !== "string" || MULTIPART_FILENAME_CHARSETS.indexOf(c.toLowerCase()) === -1;
  })) {
    throw _bpError("body-parser/bad-filename-charsets",
      label + ": filenameCharsets must be an array naming only \"utf-8\" and \"iso-8859-1\", got " +
      JSON.stringify(o.filenameCharsets));
  }
}

function _slotLabel(name) {
  return "middleware.bodyParser: " + name;
}

function _mergeSlot(name, value) {
  var label = _slotLabel(name);
  if (value === false) return null;
  if (value === undefined || value === true) return Object.assign({}, DEFAULTS[name]);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw _bpError("body-parser/bad-opts", label + " must be false, true or an options object");
  }
  validateOpts.checkOrThrow(value, Object.keys(DEFAULTS[name]), label, BodyParserError, "body-parser/bad-opts");
  return validateOpts.applyDefaults(value, DEFAULTS[name]);
}

function _checkBufferedSlot(o, label) {
  _requireContentTypes(o.contentTypes, label + ".contentTypes");
  _requireBpInt(o.limit, label + ".limit", "body-parser/bad-limit");
}

function _resolveJsonSlot(value) {
  var o = _mergeSlot("json", value);
  if (!o) return null;
  var label = _slotLabel("json");
  _checkBufferedSlot(o, label);
  _requireCharset(o.charset, label + ".charset");
  validateOpts.optionalBoolean(o.strict, label + ".strict", BodyParserError, "body-parser/bad-strict");
  validateOpts.optionalFunction(o.parseHook, label + ".parseHook", BodyParserError, "body-parser/bad-parse-hook");
  return o;
}

function _resolveUrlencodedSlot(value) {
  var o = _mergeSlot("urlencoded", value);
  if (!o) return null;
  var label = _slotLabel("urlencoded");
  _checkBufferedSlot(o, label);
  _requireCharset(o.charset, label + ".charset");
  _requireBpInt(o.arrayLimit, label + ".arrayLimit", "body-parser/bad-array-limit");
  return o;
}

function _resolveTextSlot(value) {
  var o = _mergeSlot("text", value);
  if (!o) return null;
  var label = _slotLabel("text");
  _checkBufferedSlot(o, label);
  _requireCharset(o.charset, label + ".charset");
  return o;
}

function _resolveRawSlot(value) {
  var o = _mergeSlot("raw", value);
  if (!o) return null;
  _checkBufferedSlot(o, _slotLabel("raw"));
  return o;
}

function _resolveMultipartSlot(value) {
  var o = _mergeSlot("multipart", value);
  if (!o) return null;
  var label = _slotLabel("multipart");
  _requireContentTypes(o.contentTypes, label + ".contentTypes");
  _validateMultipartShared(o, label);
  _requireBpInt(o.totalSize, label + ".totalSize", "body-parser/bad-total-size");
  _requireBpInt(o.fileCount, label + ".fileCount", "body-parser/bad-file-count");
  return o;
}

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
var MP_MAX_HEADER_BYTES = C.BYTES.kib(16);

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
  var filenameCharsets = opts.filenameCharsets.map(function (c) { return c.toLowerCase(); });
  if (filenameCharsets.indexOf("utf-8") === -1) filenameCharsets.push("utf-8");
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
  var mimeAllowlist = opts.mimeAllowlist;
  var fileFilter   = opts.fileFilter;
  var perField     = opts.fields;
  var auditInst    = opts.audit;

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
          action:   "bodyparser.multipart.file_rejected",
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
            if ((headEnd === -1 ? pending.length : headEnd) > MP_MAX_HEADER_BYTES) {
              done(new BodyParserError("body-parser/multipart-headers-too-large",
                "multipart part headers exceed 16KB", true, 413));
              return;
            }
            if (headEnd === -1) return;
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
              if (!currentDiscarded && currentIsFile) {
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
              } else if (!currentDiscarded) {
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
        totalRead += chunk.length;
        if (totalRead > totalSize) {
          done(new BodyParserError("body-parser/multipart-total-too-large",
            "multipart total request size exceeds totalSize (" + totalSize + ")",
            true, HTTP_STATUS.PAYLOAD_TOO_LARGE));
          return;
        }
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
 * read. Each sub-parser can be disabled by passing `false` in its slot,
 * and `true` or an omitted slot takes its defaults.
 *
 * The options are checked when the middleware is built, and a bad one
 * throws a `BodyParserError`. An unknown top-level option, a slot that is
 * not `false`, `true` or an object, or an unknown key inside a slot throws
 * `body-parser/bad-opts`. A `limit` that is not a positive integer throws
 * `body-parser/bad-limit`, a `contentTypes` that is not an array of
 * non-empty strings throws `body-parser/bad-content-types`, and a
 * `charset` that Node's `Buffer` does not support throws
 * `body-parser/bad-charset`. For `json`, a `strict` that is not a boolean
 * throws `body-parser/bad-strict` and a `parseHook` that is not a function
 * throws `body-parser/bad-parse-hook`. For `urlencoded`, an `arrayLimit`
 * that is not a positive integer throws `body-parser/bad-array-limit`. A
 * `keepRawBody` that is not a boolean throws
 * `body-parser/bad-keep-raw-body`.
 *
 * For `multipart`, a `totalSize`, `fileCount`, `fileSize`, `fieldCount` or
 * `fieldSize` that is not a positive integer throws
 * `body-parser/bad-total-size`, `body-parser/bad-file-count`,
 * `body-parser/bad-file-size`, `body-parser/bad-field-count` or
 * `body-parser/bad-field-size`. A `mimeAllowlist` that is not an array of
 * non-empty strings throws `body-parser/bad-mime-allowlist`, a
 * `fileFilter` that is not a function throws
 * `body-parser/bad-file-filter`, an `audit` without a `safeEmit` function
 * throws `body-parser/bad-audit`, a malformed `fields` throws
 * `body-parser/bad-fields`, a `filenameCharsets` naming anything other
 * than `"utf-8"` and `"iso-8859-1"` throws
 * `body-parser/bad-filename-charsets`, and an empty `tmpDir` throws
 * `body-parser/bad-tmp-dir`. A `storage` other than `"disk"` or
 * `"memory"` throws a `TypeError`. These are the rules
 * `b.parsers.multipart` applies to the same options.
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
  validateOpts.checkOrThrow(opts, [
    "json", "urlencoded", "text", "raw", "multipart", "keepRawBody",
  ], "middleware.bodyParser", BodyParserError, "body-parser/bad-opts");
  opts = opts || {};
  validateOpts.optionalBoolean(opts.keepRawBody, "middleware.bodyParser: keepRawBody",
    BodyParserError, "body-parser/bad-keep-raw-body");
  return _buildBodyParser({
    json:       _resolveJsonSlot(opts.json),
    urlencoded: _resolveUrlencodedSlot(opts.urlencoded),
    text:       _resolveTextSlot(opts.text),
    raw:        _resolveRawSlot(opts.raw),
    multipart:  _resolveMultipartSlot(opts.multipart),
  }, opts.keepRawBody === true);
}

function _buildBodyParser(slots, keepRawBody) {
  var jsonOpts        = slots.json;
  var urlencodedOpts  = slots.urlencoded;
  var textOpts        = slots.text;
  var rawOpts         = slots.raw;
  var multipartOpts   = slots.multipart;

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
          action:  "bodyparser.error",
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
 * An option other than `limit` and `contentTypes` throws
 * `body-parser/bad-opts`. A `limit` that is not a positive integer throws
 * `body-parser/bad-limit`, and a `contentTypes` that is not an array of
 * non-empty strings throws `body-parser/bad-content-types`.
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
  validateOpts.checkOrThrow(opts, ["limit", "contentTypes"], "middleware.bodyParser.raw",
    BodyParserError, "body-parser/bad-opts");
  opts = opts || {};
  return _buildBodyParser({
    json:       null,
    urlencoded: null,
    text:       null,
    multipart:  null,
    raw: _resolveRawSlot({
      limit:        opts.limit != null ? opts.limit : DEFAULTS.raw.limit,
      contentTypes: opts.contentTypes || ["*/*"],
    }),
  }, false);
}

create.raw = raw;

var STANDALONE_JSON_KEYS = ["maxBytes", "strict", "charset", "parseHook"];

function _resolveStandaloneJsonOpts(opts) {
  validateOpts.checkOrThrow(opts, STANDALONE_JSON_KEYS, "parsers.json", BodyParserError, "body-parser/bad-opts");
  opts = opts || {};
  var maxBytes = (opts.maxBytes !== undefined) ? opts.maxBytes : DEFAULTS.json.limit;
  _requireBpInt(maxBytes, "parsers.json: opts.maxBytes", "body-parser/bad-max-bytes");
  validateOpts.optionalBoolean(opts.strict, "parsers.json: opts.strict", BodyParserError, "body-parser/bad-strict");
  var strict = (opts.strict !== undefined && opts.strict !== null) ? opts.strict : DEFAULTS.json.strict;
  var charset = (opts.charset !== undefined) ? opts.charset : DEFAULTS.json.charset;
  _requireCharset(charset, "parsers.json: opts.charset");
  validateOpts.optionalFunction(opts.parseHook, "parsers.json: opts.parseHook",
    BodyParserError, "body-parser/bad-parse-hook");
  return {
    limit:     maxBytes,
    strict:    strict,
    charset:   charset,
    parseHook: opts.parseHook || undefined,
  };
}

var STANDALONE_MULTIPART_SHARED = Object.keys(DEFAULTS.multipart).filter(function (k) {
  return ["totalSize", "fileCount", "contentTypes"].indexOf(k) === -1;
});
var STANDALONE_MULTIPART_KEYS = ["maxBytes", "maxFiles"].concat(STANDALONE_MULTIPART_SHARED);

function _resolveStandaloneMultipartOpts(opts, ct) {
  validateOpts.checkOrThrow(opts, STANDALONE_MULTIPART_KEYS, "parsers.multipart",
    BodyParserError, "body-parser/bad-opts");
  opts = opts || {};
  var resolved = Object.assign({}, DEFAULTS.multipart);
  if (opts.maxBytes !== undefined) {
    _requireBpInt(opts.maxBytes, "parsers.multipart: opts.maxBytes", "body-parser/bad-max-bytes");
    resolved.totalSize = opts.maxBytes;
    if (resolved.fileSize > opts.maxBytes) resolved.fileSize = opts.maxBytes;
  }
  if (opts.maxFiles !== undefined) {
    _requireBpInt(opts.maxFiles, "parsers.multipart: opts.maxFiles", "body-parser/bad-max-files");
    resolved.fileCount = opts.maxFiles;
  }
  STANDALONE_MULTIPART_SHARED.forEach(function (k) {
    if (opts[k] !== undefined) resolved[k] = opts[k];
  });
  _validateMultipartShared(resolved, "parsers.multipart");
  if (!ct || typeof ct.type !== "string" || ct.type !== "multipart/form-data") {
    throw new BodyParserError("body-parser/standalone-not-multipart",
      "parsers.multipart: request Content-Type must be multipart/form-data, got " +
      JSON.stringify(ct ? ct.type : null),
      true, HTTP_STATUS.BAD_REQUEST);
  }
  return resolved;
}

/**
 * @primitive b.parsers.json
 * @signature b.parsers.json(req, opts?)
 * @since     0.8.45
 * @status    stable
 * @related   b.middleware.bodyParser, b.safeJson.parse
 *
 * Read one request's body as JSON, without mounting middleware. This is
 * for a handler that parses its own route, where
 * `b.middleware.bodyParser` parses every route.
 *
 * The body is read under a byte cap and parsed through `b.safeJson`. A key
 * named after a prototype does not reach the value: `__proto__` and
 * `constructor` are dropped, their siblings come through, and the object's
 * prototype is its own. A body over the cap is refused with
 * `body-parser/too-large`, and one that does not parse is refused with
 * `body-parser/json-malformed` rather than answered with a partial value. In
 * strict mode a body that does not start with `{` or `[` is refused with
 * `body-parser/json-strict` before it is parsed, and a body the operator's
 * parse hook rejects is refused with `body-parser/json-hook`, which keeps that
 * decision distinguishable from a malformed one. A request whose
 * `Content-Length` header is not a non-negative integer is refused with
 * `body-parser/bad-content-length` before the body is read.
 *
 * The options are checked before the body is read, and a bad one rejects
 * the returned promise. A `maxBytes` that is not a positive integer rejects
 * with `body-parser/bad-max-bytes`, a `strict` that is not a boolean with
 * `body-parser/bad-strict`, a `charset` that Node's `Buffer` does not
 * support with `body-parser/bad-charset`, and a `parseHook` that is not a
 * function with `body-parser/bad-parse-hook`. An `opts` that is not an
 * object, or an option not listed below, rejects with
 * `body-parser/bad-opts`.
 *
 * @opts
 *   maxBytes:  number,     // ceiling on the body read
 *   strict:    boolean,    // require a JSON object or array at the top level
 *   charset:   string,     // charset assumed when the request names none
 *   parseHook: function,   // (value) → value, run after parsing
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/orders", async function (req, res) {
 *     var body = await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(64) });
 *     res.end(String(body.id));
 *   });
 */
async function parseJsonStandalone(req, opts) {
  var resolved = _resolveStandaloneJsonOpts(opts);
  return _parseJson(req, resolved);
}

/**
 * @primitive b.parsers.multipart
 * @signature b.parsers.multipart(req, opts?)
 * @since     0.8.45
 * @status    stable
 * @related   b.parsers.json, b.fileUpload.create
 *
 * Read one request's `multipart/form-data` body, without mounting
 * middleware, and answer its fields and files.
 *
 * A request whose `Content-Type` is not `multipart/form-data` is refused
 * with `body-parser/standalone-not-multipart` rather than parsed as
 * something else. `maxBytes` caps the whole body and `maxFiles` caps how
 * many parts carry one, so a request with thousands of tiny parts is
 * refused on the count rather than only on the total size.
 *
 * It parses; it does not decide whether a file is safe to keep. Hand the
 * parts to `b.fileUpload` for that.
 *
 * The options are checked before any of the body is read, and a bad one
 * rejects the returned promise. A `maxBytes` or `maxFiles` that is not a
 * positive integer rejects with `body-parser/bad-max-bytes` or
 * `body-parser/bad-max-files`, and a `fileSize`, `fieldCount` or
 * `fieldSize` that is not a positive integer rejects with
 * `body-parser/bad-file-size`, `body-parser/bad-field-count` or
 * `body-parser/bad-field-size`. A `mimeAllowlist` that is not an array of
 * non-empty strings rejects with `body-parser/bad-mime-allowlist`, a
 * `fileFilter` that is not a function rejects with
 * `body-parser/bad-file-filter`, and an `audit` without a `safeEmit`
 * function rejects with `body-parser/bad-audit`. A `fields` that is not a
 * plain object, or a rule in it that is not a plain object holding only a
 * positive-integer `maxBytes` and a string-array `mimeTypes`, rejects with
 * `body-parser/bad-fields`. A `filenameCharsets` that is not an array
 * naming only `"utf-8"` and `"iso-8859-1"` rejects with
 * `body-parser/bad-filename-charsets`, and an empty `tmpDir` rejects with
 * `body-parser/bad-tmp-dir`. An `opts` that is not an object, or an option
 * not listed below, rejects with `body-parser/bad-opts`. A `storage` other
 * than `"disk"` or `"memory"` rejects with a `TypeError`.
 *
 * The promise also rejects with a `BodyParserError` when the body breaks
 * the multipart grammar or one of the limits, and the error's
 * `statusCode` holds the HTTP status for the refusal. A `Content-Type`
 * without a `boundary` parameter rejects with
 * `body-parser/multipart-no-boundary`, and a boundary longer than 70
 * characters or with a character outside the RFC 2046 `bcharsnospace`
 * set rejects with `body-parser/multipart-bad-boundary`. A boundary line
 * followed by anything other than `--`, CRLF or LF rejects with
 * `body-parser/multipart-malformed`. A body that ends before the closing
 * boundary rejects with `body-parser/multipart-truncated`, and an `error`
 * event on the request stream rejects with `body-parser/multipart-stream`.
 *
 * A part whose header block is longer than 16 KiB rejects with
 * `body-parser/multipart-headers-too-large`. A part header line that
 * starts with a space or a tab (obsolete line folding) rejects with
 * `body-parser/multipart-obs-fold`, and a header value that contains CR,
 * LF or NUL rejects with `body-parser/multipart-bad-header-value`. A part
 * without a `form-data` `Content-Disposition` that names its field
 * rejects with `body-parser/multipart-bad-disposition`. A field named
 * `__proto__`, `constructor`, `prototype`, or a key registered with
 * `b.pick.registerPoisonedKeys` rejects with
 * `body-parser/multipart-poisoned-field`. A filename that is empty once
 * its directory part, control characters, bidirectional and zero-width
 * characters, and leading and trailing dots are removed rejects with
 * `body-parser/multipart-bad-filename`.
 *
 * The parser counts every byte it receives up to the closing boundary:
 * the preamble before the first boundary, the boundary lines, the part
 * headers and the part content. When that count passes `maxBytes`, the
 * promise rejects with `body-parser/multipart-total-too-large`. A file
 * part larger than
 * `fields[name].maxBytes`, or than `fileSize` when the field sets no
 * `maxBytes`, rejects with `body-parser/multipart-file-too-large`. A text
 * field larger than `fields[name].maxBytes`, or than `fieldSize`, rejects
 * with `body-parser/multipart-field-too-large`. More file parts than
 * `maxFiles` reject with `body-parser/multipart-too-many-files`, and more
 * text fields than `fieldCount` reject with
 * `body-parser/multipart-too-many-fields`. A file whose part
 * `Content-Type` is not in `fields[name].mimeTypes`, or in
 * `mimeAllowlist` when the field has no list of its own, rejects with
 * `body-parser/multipart-mime-not-allowed`.
 *
 * A `fileFilter` that throws rejects the promise with
 * `body-parser/multipart-file-filter-throw`. With `storage: "disk"`, a
 * temporary directory that cannot be created rejects with
 * `body-parser/multipart-tmpdir`, a temporary file that cannot be opened
 * rejects with `body-parser/multipart-tmp-open`, and a failed write to
 * one rejects with `body-parser/multipart-tmp-write`. Any other error
 * raised while the parser processes a chunk rejects with
 * `body-parser/multipart-internal`. When the promise rejects, the parser
 * removes the temporary files it wrote for the request.
 *
 * @opts
 *   maxBytes:         number,     // ceiling on the whole body; default 50 MiB
 *   maxFiles:         number,     // ceiling on the number of file parts; default 20
 *   fileSize:         number,     // ceiling on one file part; default 10 MiB, or maxBytes when smaller
 *   fieldCount:       number,     // ceiling on the number of text fields; default 100
 *   fieldSize:        number,     // ceiling on one text field; default 1 MiB
 *   storage:          string,     // "disk" (default) writes files to tmpDir; "memory" keeps them in files[].buffer
 *   tmpDir:           string,     // directory for disk storage; default blamejs-uploads under the OS temp directory
 *   mimeAllowlist:    string[],   // file part Content-Type values accepted when the field has no mimeTypes
 *   fields:           object,     // per-field rules { [name]: { maxBytes?, mimeTypes? } }
 *   fileFilter:       function,   // ({ field, filename, mimeType, partHeaders }) → false or { reject, code?, message? } skips the file
 *   audit:            object,     // an audit instance; each skipped file is emitted through its safeEmit
 *   filenameCharsets: string[],   // charsets decoded in filename*=: "utf-8" (always decoded) and "iso-8859-1"; default ["utf-8"]
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/import", async function (req, res) {
 *     var body = await b.parsers.multipart(req, { maxFiles: 1 });
 *     res.end(String(Object.keys(body.fields).length));
 *   });
 */
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
