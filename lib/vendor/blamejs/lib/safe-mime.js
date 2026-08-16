// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.safeMime
 * @nav        Parsers
 * @title      Safe MIME
 * @order      120
 *
 * @intro
 *   Bounded MIME parser substrate for the mail stack. Walks RFC 5322 +
 *   2045 / 2046 / 2047 / 6532 (EAI) / 6533 (i18n-DSN) message structure
 *   into a part tree with caps on every dimension an attacker can grow
 *   to DoS the framework.
 *
 *   Foundation for everything above:
 *
 *     - `b.mailStore.appendMessage` parses inbound bytes via
 *       `b.safeMime.parse(...)` to extract headers + body parts before
 *       sealing per-column.
 *     - `b.mail.server.mx` runs every received message through
 *       `b.safeMime.parse` before SPF / DKIM / DMARC / ARC verification.
 *     - `b.guardEmail.validateMessage` already operates on raw bytes
 *       at the line-shape level; `b.safeMime.parse` is the structured
 *       follow-up that lets `b.guardHtml` / `b.guardArchive` /
 *       `b.guardSvg` inspect individual MIME parts.
 *     - `b.mail.crypto.{pgp,smime}` (v0.9.34a) parses signed/encrypted
 *       containers via this primitive before reaching the underlying
 *       crypto.
 *
 *   Defends `CVE-2024-39929` (Exim MIME multipart parser) and
 *   `CVE-2026-26312` (Stalwart nested `message/rfc822` MIME OOM) by capping
 *   total parts, nesting depth, boundary length, header bytes,
 *   header-line bytes, decoded body bytes, message bytes — plus
 *   charset + transfer-encoding allowlists.
 *
 *   Throws `SafeMimeError` on every cap exceeded, malformed boundary,
 *   unknown charset, unknown transfer-encoding, NUL byte in headers,
 *   bidi/control chars in header values.
 *
 *   The parser is purely functional — no I/O, no async, no side
 *   effects. Operators run it in `b.workerPool` workers for any
 *   incoming message above a threshold.
 *
 * @card
 *   Bounded MIME parser — walks RFC 5322 + 2045 / 2046 / 2047 + EAI message structure into a part tree with hard caps on depth, part count, body size, header bytes, and charset / transfer-encoding allowlists. Defends CVE-2024-39929 + CVE-2026-26312.
 */

var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");
var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");
var pick = require("./pick");

var SafeMimeError = defineClass("SafeMimeError", { alwaysPermanent: true });

var DEFAULT_MAX_PARTS         = 64;                          // total parts cap, not bytes
var DEFAULT_MAX_NESTING_DEPTH = 16;
var DEFAULT_MAX_BOUNDARY      = 70;                          // RFC 2046 §5.1.1
var DEFAULT_MAX_HEADER_BYTES  = C.BYTES.kib(64);
// RFC 5322 §2.1.1 line cap. The spec defines TWO limits: a SHOULD of
// 78 bytes (the readability target) and a MUST of 998 bytes (the
// hard ceiling). The 78-byte SHOULD is intentionally NOT enforced
// here — modern senders routinely emit header lines longer than 78
// bytes (long URLs in List-Unsubscribe, EAI display names) and a
// strict 78-byte refusal would reject legitimate mail. We enforce
// only the 998-byte MUST. Future drift attempting to "fix" this to
// 78 would be a regression and should fail the audit gate.
var DEFAULT_MAX_HEADER_LINE   = 998;                         // RFC 5322 §2.1.1 MUST (998); the SHOULD (78) is by design not enforced
// Per-message header-count cap. RFC 5322 places no upper bound on
// the number of headers in a message; without one, a sender can pack
// tens of thousands of one-byte headers into the maxHeaderBytes budget
// and force O(N²) lookup cost across every consumer that walks the
// header list (DKIM verify, IMAP FETCH, JMAP serializer). Mainstream
// MTAs (Postfix `header_size_limit`, Exim `received_headers_max`,
// Microsoft 365 `MaxRecipientEnvelopePerMessage`) cap in the low
// hundreds; the framework picks 512 as a generous default with
// `maxHeaderCount` exposed for operators that legitimately need more.
var DEFAULT_MAX_HEADER_COUNT  = 512;                         // DoS bound, not bytes
var DEFAULT_MAX_BODY_BYTES    = C.BYTES.mib(25);
var DEFAULT_MAX_MESSAGE_BYTES = C.BYTES.mib(50);

var DEFAULT_CHARSETS = Object.freeze([
  "utf-8", "us-ascii", "ascii",
  "iso-8859-1", "latin1", "windows-1252", "cp1252",
  "iso-8859-2", "iso-8859-15",
  "utf-16", "utf-16le", "utf-16be",
  "gb2312", "gbk", "big5",
  "shift_jis", "shift-jis", "iso-2022-jp",
  "euc-kr", "euc-jp",
]);

// RFC 3030 §3 — `binary` CTE on receive REQUIRES the receiving MTA
// to have advertised BINARYMIME during ESMTP negotiation. Inbound
// flows without explicit BINARYMIME wiring must refuse `binary`
// because consumers downstream (DKIM canonicalization, message
// rewriting) assume CRLF line structure that `binary` doesn't
// guarantee. Operators that wire BINARYMIME end-to-end opt back in
// via `transferEncodingAllowlist: ["7bit", ..., "binary"]`.
var DEFAULT_TRANSFER_ENCODINGS = Object.freeze([
  "7bit", "8bit", "quoted-printable", "base64",
]);

/**
 * @primitive b.safeMime.parse
 * @signature b.safeMime.parse(bytes, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.walk, b.safeMime.extractText, b.guardEmail.validateMessage
 *
 * Parse `bytes` into a MIME part tree. Returns
 * `{ headers, parts, leaf, decoded }`. Multipart parts have non-null
 * `parts`; leaf parts have non-null `leaf` carrying decoded body.
 *
 * Throws `SafeMimeError` with codes:
 *   `safe-mime/oversize-message` / `oversize-part-count` /
 *   `oversize-nesting` / `oversize-boundary` / `oversize-headers` /
 *   `oversize-header-line` / `oversize-body` / `unknown-charset` /
 *   `unknown-transfer-encoding` / `malformed-boundary` /
 *   `too-many-headers` / `malformed-headers` /
 *   `control-char-in-header` / `bad-input`.
 *
 * @opts
 *   maxParts:                 number,     // default 64
 *   maxNestingDepth:          number,     // default 16
 *   maxBoundary:              number,     // default 70 (RFC 2046 §5.1.1)
 *   maxHeaderBytes:           number,     // default 64 KiB
 *   maxHeaderLineBytes:       number,     // default 998 (RFC 5322 §2.1.1)
 *   maxHeaderCount:           number,     // default 512 (DoS bound)
 *   maxBodyBytes:             number,     // default 25 MiB
 *   maxMessageBytes:          number,     // default 50 MiB
 *   charsetAllowlist:         string[],   // default UTF-8 / US-ASCII / common legacy 8-bit
 *   transferEncodingAllowlist: string[],  // default 7bit/8bit/quoted-printable/base64 (binary is opt-in, RFC 3030 BINARYMIME)
 *
 * @example
 *   var msg = b.safeMime.parse(messageBuffer);
 *   msg.headers.get("subject");
 *   msg.parts.length;
 *   msg.parts[0].leaf.body.toString("utf8");
 */
function parse(bytes, opts) {
  opts = opts || {};
  var maxParts        = _intOpt(opts, "maxParts",        DEFAULT_MAX_PARTS);
  var maxNestingDepth = _intOpt(opts, "maxNestingDepth", DEFAULT_MAX_NESTING_DEPTH);
  var maxBoundary     = _intOpt(opts, "maxBoundary",     DEFAULT_MAX_BOUNDARY);
  var maxHeaderBytes  = _intOpt(opts, "maxHeaderBytes",  DEFAULT_MAX_HEADER_BYTES);
  var maxHeaderLine   = _intOpt(opts, "maxHeaderLineBytes", DEFAULT_MAX_HEADER_LINE);
  var maxHeaderCount  = _intOpt(opts, "maxHeaderCount",  DEFAULT_MAX_HEADER_COUNT);
  var maxBodyBytes    = _intOpt(opts, "maxBodyBytes",    DEFAULT_MAX_BODY_BYTES);
  var maxMessageBytes = _intOpt(opts, "maxMessageBytes", DEFAULT_MAX_MESSAGE_BYTES);
  var charsets        = _normalizeStringSet(opts.charsetAllowlist || DEFAULT_CHARSETS);
  var encodings       = _normalizeStringSet(opts.transferEncodingAllowlist || DEFAULT_TRANSFER_ENCODINGS);

  var buf = _toBuffer(bytes);
  if (safeBuffer.byteLengthOf(buf) > maxMessageBytes) {
    throw new SafeMimeError("safe-mime/oversize-message",
      "safeMime.parse: message size " + buf.length + " exceeds maxMessageBytes " + maxMessageBytes);
  }

  var ctx = {
    maxParts:        maxParts,
    maxNestingDepth: maxNestingDepth,
    maxBoundary:     maxBoundary,
    maxHeaderBytes:  maxHeaderBytes,
    maxHeaderLine:   maxHeaderLine,
    maxHeaderCount:  maxHeaderCount,
    maxBodyBytes:    maxBodyBytes,
    charsets:        charsets,
    encodings:       encodings,
    partCount:       0,
  };

  return _parsePart(buf, ctx, 0);
}

/**
 * @primitive b.safeMime.walk
 * @signature b.safeMime.walk(tree, visitor)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.parse, b.safeMime.findFirst
 *
 * Depth-first walk. Invokes `visitor(part, path)` for every part where
 * `path` is the position array (`[]` for root, `[0]` for first child).
 * Visitor returning `false` short-circuits.
 *
 * @example
 *   b.safeMime.walk(tree, function (part) {
 *     if (part.leaf && part.leaf.contentType === "application/pdf") {
 *       console.log("pdf", part.leaf.body.length);
 *     }
 *   });
 */
function walk(tree, visitor) {
  if (!tree) return;
  if (typeof visitor !== "function") {
    throw new TypeError("safeMime.walk: visitor must be a function");
  }
  return _walkRec(tree, visitor, []);
}

function _walkRec(part, visitor, path) {
  var result = visitor(part, path.slice());
  if (result === false) return false;
  if (part.parts) {
    for (var i = 0; i < part.parts.length; i += 1) {
      var sub = _walkRec(part.parts[i], visitor, path.concat([i]));
      if (sub === false) return false;
    }
  }
  return true;
}

/**
 * @primitive b.safeMime.findFirst
 * @signature b.safeMime.findFirst(tree, predicate)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.walk
 *
 * Return the first part for which `predicate(part)` is truthy, or
 * `null`. Common use: pull the first `text/plain` or `text/html`.
 *
 * @example
 *   var t = b.safeMime.findFirst(tree, function (p) {
 *     return p.leaf && p.leaf.contentType === "text/plain";
 *   });
 */
function findFirst(tree, predicate) {
  if (typeof predicate !== "function") {
    throw new TypeError("safeMime.findFirst: predicate must be a function");
  }
  var found = null;
  walk(tree, function (part) {
    if (predicate(part)) { found = part; return false; }
  });
  return found;
}

/**
 * @primitive b.safeMime.extractText
 * @signature b.safeMime.extractText(tree, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.parse, b.safeMime.findFirst
 *
 * Pull the rendering-preferred text payload. Honors RFC 2046 §5.1.4
 * "last wins" semantics for `multipart/alternative`. Returns
 * `{ contentType, charset, body }` (body is decoded string) or `null`.
 *
 * @opts
 *   prefer:  "plain" | "html" | "any",   // default "plain"
 *
 * @example
 *   var tree = b.safeMime.parse(messageBuffer);
 *   var text = b.safeMime.extractText(tree, { prefer: "plain" });
 *   text.body;          // → "Hello, world!"
 *   text.contentType;   // → "text/plain"
 */
function extractText(tree, opts) {
  opts = opts || {};
  var prefer = opts.prefer || "plain";

  if (tree && _startsWithFolded(_ct(tree), "multipart/alternative")) {
    var parts = tree.parts || [];
    for (var i = parts.length - 1; i >= 0; i -= 1) {
      var p = parts[i];
      if (!p.leaf) continue;
      var ct = p.leaf.contentType;
      if (prefer === "plain" && ct === "text/plain") return _materializeText(p);
      if (prefer === "html"  && ct === "text/html")  return _materializeText(p);
      if (prefer === "any"   && _isTextType(ct))     return _materializeText(p);
    }
    for (var j = 0; j < parts.length; j += 1) {
      var q = parts[j];
      if (q.leaf && _isTextType(q.leaf.contentType)) return _materializeText(q);
    }
    return null;
  }

  var preferred = findFirst(tree, function (p) {
    return p.leaf && p.leaf.contentType === (prefer === "html" ? "text/html" : "text/plain");
  });
  if (preferred) return _materializeText(preferred);
  var anyText = findFirst(tree, function (p) {
    return p.leaf && _isTextType(p.leaf.contentType);
  });
  return anyText ? _materializeText(anyText) : null;
}

/**
 * @primitive b.safeMime.extractAttachments
 * @signature b.safeMime.extractAttachments(tree, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.parse, b.guardArchive, b.fileType
 *
 * Return array of attachment-shaped parts. Each entry is
 * `{ filename, contentType, body, headers }`. Operators pipe each
 * attachment through `b.fileType.detect` then through the per-type
 * guard (`b.guardArchive` / `b.guardPdf` / etc.).
 *
 * @opts
 *   includeInline: boolean,    // default false — Content-Disposition: inline skipped
 *
 * @example
 *   var tree = b.safeMime.parse(messageBuffer);
 *   var atts = b.safeMime.extractAttachments(tree);
 *   atts[0].filename;       // → "report.pdf"
 *   atts[0].contentType;    // → "application/pdf"
 *   atts[0].body.length;    // → 12345 (decoded bytes)
 */
function extractAttachments(tree, opts) {
  opts = opts || {};
  var includeInline = opts.includeInline === true;
  var out = [];
  walk(tree, function (part) {
    if (!part.leaf) return;
    var cd = (part.headers.get("content-disposition") || "").toLowerCase();
    var isAttachment = cd.indexOf("attachment") === 0;
    var isInline     = cd.indexOf("inline") === 0;
    if (!isAttachment && !includeInline) return;
    if (!isAttachment && isInline && !includeInline) return;
    out.push({
      filename:    _filenameFromHeaders(part.headers),
      contentType: part.leaf.contentType,
      body:        part.leaf.body,
      headers:     part.headers,
    });
  });
  return out;
}

// ---- Internal --------------------------------------------------------------

function _parsePart(buf, ctx, depth) {
  if (depth > ctx.maxNestingDepth) {
    throw new SafeMimeError("safe-mime/oversize-nesting",
      "safeMime.parse: nesting depth exceeded maxNestingDepth=" + ctx.maxNestingDepth +
      " (CVE-2024-39929 class defense)");
  }
  ctx.partCount += 1;
  if (ctx.partCount > ctx.maxParts) {
    throw new SafeMimeError("safe-mime/oversize-part-count",
      "safeMime.parse: total parts exceeded maxParts=" + ctx.maxParts +
      " (CVE-2024-39929 class defense)");
  }

  var sep = _findHeaderBodySep(buf);
  if (sep < 0) sep = buf.length;
  if (sep > ctx.maxHeaderBytes) {
    throw new SafeMimeError("safe-mime/oversize-headers",
      "safeMime.parse: header section " + sep + " bytes exceeds maxHeaderBytes=" + ctx.maxHeaderBytes);
  }
  var headerBytes = buf.subarray(0, sep);
  // Skip the blank-line separator. `_findHeaderBodySep` returns the
  // position of the FIRST CR (or LF) of the blank-line pair; the body
  // starts AFTER both CRLFs (or both LFs).
  var bodyStart = sep;
  if (buf[bodyStart] === 0x0D && buf[bodyStart + 1] === 0x0A) bodyStart += 2;
  else if (buf[bodyStart] === 0x0A) bodyStart += 1;
  if (buf[bodyStart] === 0x0D && buf[bodyStart + 1] === 0x0A) bodyStart += 2;
  else if (buf[bodyStart] === 0x0A) bodyStart += 1;
  var bodyBytes = buf.subarray(bodyStart);

  var headers = _parseHeaders(headerBytes, ctx);
  var contentTypeHeader = headers.get("content-type") || "text/plain";
  var ctInfo = _parseContentType(contentTypeHeader);
  var contentType = ctInfo.type;
  var params      = ctInfo.params;

  if (contentType.indexOf("multipart/") === 0) {
    var boundary = params.boundary;
    if (typeof boundary !== "string" || boundary.length === 0) {
      throw new SafeMimeError("safe-mime/malformed-boundary",
        "safeMime.parse: multipart content-type lacks boundary param");
    }
    if (boundary.length > ctx.maxBoundary) {
      throw new SafeMimeError("safe-mime/oversize-boundary",
        "safeMime.parse: boundary length " + boundary.length + " exceeds maxBoundary=" + ctx.maxBoundary +
        " (RFC 2046 §5.1.1)");
    }
    // RFC 2046 §5.1.1 — boundary value MUST match the `bcharsnospace
    // *bchars` grammar (max 70 chars, no CR/LF/NUL, no leading or
    // trailing SP). A boundary containing newline bytes lets an
    // attacker confuse multipart engines that re-split on different
    // EOL forms downstream.
    if (!_isValidMimeBoundary(boundary)) {
      throw new SafeMimeError("safe-mime/malformed-boundary",
        "safeMime.parse: multipart boundary does not match RFC 2046 §5.1.1 bcharsnospace *bchars grammar");
    }
    var partBuffers = _splitMultipart(bodyBytes, boundary);
    var parts = [];
    for (var i = 0; i < partBuffers.length; i += 1) {
      parts.push(_parsePart(partBuffers[i], ctx, depth + 1));
    }
    return {
      headers:    headers,
      parts:      parts,
      leaf:       null,
      decoded:    null,
      _contentType: contentType,
    };
  }

  if (safeBuffer.byteLengthOf(bodyBytes) > ctx.maxBodyBytes) {
    throw new SafeMimeError("safe-mime/oversize-body",
      "safeMime.parse: body " + bodyBytes.length + " bytes exceeds maxBodyBytes=" + ctx.maxBodyBytes);
  }
  var encoding = String(headers.get("content-transfer-encoding") || "7bit").toLowerCase().trim();
  if (!ctx.encodings[encoding]) {
    throw new SafeMimeError("safe-mime/unknown-transfer-encoding",
      "safeMime.parse: content-transfer-encoding '" + encoding + "' not in allowlist; refused");
  }
  var charset = String(params.charset || "us-ascii").toLowerCase();
  if (!ctx.charsets[_normalizeCharsetName(charset)]) {
    throw new SafeMimeError("safe-mime/unknown-charset",
      "safeMime.parse: charset '" + charset + "' not in allowlist; refused");
  }
  var decodedBody = _decodeBody(bodyBytes, encoding);
  if (safeBuffer.byteLengthOf(decodedBody) > ctx.maxBodyBytes) {
    throw new SafeMimeError("safe-mime/oversize-body",
      "safeMime.parse: decoded body " + decodedBody.length +
      " bytes exceeds maxBodyBytes=" + ctx.maxBodyBytes);
  }
  return {
    headers: headers,
    parts:   null,
    leaf:    {
      contentType: contentType,
      charset:     charset,
      encoding:    encoding,
      body:        decodedBody,
    },
    decoded:      _materializeTextValue(decodedBody, charset),
    _contentType: contentType,
  };
}

function _findHeaderBodySep(buf) {
  for (var i = 0; i < buf.length - 1; i += 1) {
    if (buf[i] === 0x0D && buf[i + 1] === 0x0A &&
        buf[i + 2] === 0x0D && buf[i + 3] === 0x0A) {
      return i;
    }
    if (buf[i] === 0x0A && buf[i + 1] === 0x0A) {
      return i;
    }
  }
  return -1;
}

function _parseHeaders(buf, ctx) {
  var lines = _splitHeaderLines(buf, ctx);
  // Per-message header-count cap (DoS bound). RFC 5322 does not bound
  // header count; without a cap, a sender packs many short headers
  // into the byte budget and forces quadratic walk cost downstream.
  if (lines.length > ctx.maxHeaderCount) {
    throw new SafeMimeError("safe-mime/too-many-headers",
      "safeMime.parse: header count " + lines.length +
      " exceeds maxHeaderCount=" + ctx.maxHeaderCount);
  }
  var headerMap = Object.create(null);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) {
      throw new SafeMimeError("safe-mime/malformed-headers",
        "safeMime.parse: header line missing colon: " + _previewBytes(line));
    }
    var name  = khv.key;
    var value = khv.value.trim();
    // Refuse NUL, CR, LF, and other C0 control chars in header values.
    // Tab (0x09) is allowed (header folding). C1 control range
    // (0x80-0x9F) NOT refused — legitimate non-ASCII via EAI/RFC 2047
    // decoded-words can produce bytes in that range. Error metadata
    // surfaces the BYTE offset (via `Buffer.byteLength` on the JS
    // string prefix) rather than the UTF-16 code-unit index, so the
    // operator audit log lines up with the wire-level byte stream
    // they're inspecting.
    var hci = codepointClass.firstControlCharOffset(value);                                          // C0 control char (except TAB) + DEL refusal
    if (hci !== -1) {
      var byteOffset = Buffer.byteLength(value.slice(0, hci), "utf8");
      throw new SafeMimeError("safe-mime/control-char-in-header",
        "safeMime.parse: header '" + name + "' contains control char 0x" +
        value.charCodeAt(hci).toString(16) + " at byte offset " + byteOffset);                            // toString radix 16 hex, not bytes
    }
    value = _decodeRfc2047Words(value);
    if (pick.isPoisonedKey(name)) continue;
    if (!headerMap[name]) headerMap[name] = [];
    headerMap[name].push(value);
  }
  return {
    get:    function (n) {
      var arr = headerMap[String(n).toLowerCase()];
      return arr && arr.length > 0 ? arr[0] : null;
    },
    getAll: function (n) { return (headerMap[String(n).toLowerCase()] || []).slice(); },
    names:  function () { return Object.keys(headerMap); },
    raw:    headerMap,
  };
}

var _splitLines = codepointClass.splitLines;

// Does `s` begin with `prefix`, ignoring ASCII case? Media types are
// case-insensitive per RFC 2045 §5.1.
function _startsWithFolded(s, prefix) {
  return typeof s === "string" && s.length >= prefix.length &&
         codepointClass.containsFolded(s.slice(0, prefix.length), prefix);
}

function _isTextType(contentType) {
  return typeof contentType === "string" && contentType.slice(0, 5) === "text/";
}

function _splitHeaderLines(buf, ctx) {
  var s = buf.toString("utf8");
  var rawLines = _splitLines(s);
  var unfolded = [];
  for (var i = 0; i < rawLines.length; i += 1) {
    var line = rawLines[i];
    if (line.length === 0) continue;
    if (line.length > ctx.maxHeaderLine) {
      throw new SafeMimeError("safe-mime/oversize-header-line",
        "safeMime.parse: header line " + line.length +
        " bytes exceeds maxHeaderLineBytes=" + ctx.maxHeaderLine +
        " (RFC 5322 §2.1.1)");
    }
    if ((line.charCodeAt(0) === 0x20 || line.charCodeAt(0) === 0x09) &&
        unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " +
        codepointClass.trimRanges(line, codepointClass.WHITESPACE_RANGES,
                                  { trailing: false });
    } else {
      unfolded.push(line);
    }
  }
  return unfolded;
}

// RFC 2045 quoted-string body: a backslash escapes the character after it. A
// trailing backslash stands for itself, and so does one before a line
// terminator — the `.` in the pattern this replaced never matched LF, CR or
// the two Unicode line separators, so `\` before one was left in place, and a
// bare CR does reach this parser.
function _unescapeQuotedString(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x5C) continue;                          // "\"
    if (i + 1 >= s.length) break;                                    // trailing backslash
    if (codepointClass.inRanges(s.charCodeAt(i + 1),
                                codepointClass.LINE_TERMINATOR_RANGES)) continue;
    out += s.slice(keepFrom, i) + s.charAt(i + 1);
    keepFrom = i + 2;
    i += 1;
  }
  return keepFrom === 0 ? s : out + s.slice(keepFrom);
}

function _parseContentType(value) {
  var parts = String(value).split(";");
  var type  = parts[0].toLowerCase().trim();
  var params = Object.create(null);
  var kvps = structuredFields.parseKeyValuePieces(parts, 1);
  structuredFields.forEachKeyValue(kvps, function (k, v) {
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = _unescapeQuotedString(v.slice(1, -1));
    }
    if (pick.isPoisonedKey(k)) return;
    params[k] = v;
  });
  return { type: type, params: params };
}

function _splitMultipart(buf, boundary) {
  var delimiter = Buffer.from("--" + boundary);
  var parts = [];
  var pos = 0;
  while (pos < buf.length) {
    // Per RFC 2046 §5.1.1 a boundary delimiter is `--<value>` preceded
    // by CRLF (or LF) — OR at the very start of the body. A boundary-
    // shaped sequence elsewhere in a part's body MUST NOT be treated
    // as a delimiter.
    var idx = _findBoundaryAtLineStart(buf, delimiter, pos);
    if (idx < 0) break;
    if (buf[idx + delimiter.length] === 0x2D && buf[idx + delimiter.length + 1] === 0x2D) {
      // Final delimiter — close out preceding part.
      if (parts.length > 0) {
        var prev = parts[parts.length - 1];
        var prevEnd = idx;
        if (prevEnd >= 2 && buf[prevEnd - 2] === 0x0D && buf[prevEnd - 1] === 0x0A) prevEnd -= 2;
        else if (prevEnd >= 1 && buf[prevEnd - 1] === 0x0A) prevEnd -= 1;
        // RFC 2046 §5.1.1 — a malformed body where a final boundary
        // immediately follows the opening of a part (no body bytes
        // between them) MUST NOT produce a negative-length slice.
        // Clamp to the part's start so the slice is well-formed.
        if (prevEnd < prev.start) prevEnd = prev.start;
        parts[parts.length - 1] = buf.subarray(prev.start, prevEnd);
      }
      break;
    }
    var lineEnd = _indexOfLineEnd(buf, idx);
    if (lineEnd < 0) break;
    if (parts.length > 0) {
      var prev2 = parts[parts.length - 1];
      var prevEnd2 = idx;
      if (prevEnd2 >= 2 && buf[prevEnd2 - 2] === 0x0D && buf[prevEnd2 - 1] === 0x0A) prevEnd2 -= 2;
      else if (prevEnd2 >= 1 && buf[prevEnd2 - 1] === 0x0A) prevEnd2 -= 1;
      if (prevEnd2 < prev2.start) prevEnd2 = prev2.start;
      parts[parts.length - 1] = buf.subarray(prev2.start, prevEnd2);
    }
    parts.push({ start: lineEnd });
    pos = lineEnd;
  }
  return parts.map(function (p) {
    if (Buffer.isBuffer(p)) return p;
    return buf.subarray(p.start);
  });
}

// RFC 2046 §5.1.1 — boundary param grammar is `bcharsnospace *bchars`
// where `bcharsnospace = DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" /
// "," / "-" / "." / "/" / ":" / "=" / "?"` and `bchars = bcharsnospace
// / " "` (max 70 chars). Without validating against this set the
// parser would happily accept a boundary containing CR / LF / NUL /
// `--` which can be wielded to confuse downstream multipart engines.
var _BOUNDARY_PUNCTUATION = "'()+_,./:=?-";
var MAX_BOUNDARY_LENGTH = 70;                                                       // RFC 2046 §5.1.1 bound

function _isBcharNoSpace(cc) {
  return (cc >= 0x30 && cc <= 0x39) ||                                              // 0-9
         (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A) ||                // A-Z a-z
         _BOUNDARY_PUNCTUATION.indexOf(String.fromCharCode(cc)) !== -1;
}

function _isValidMimeBoundary(value) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > MAX_BOUNDARY_LENGTH) return false;
  // First char MUST be bcharsnospace; the middle MAY include SP; the last
  // char MUST be bcharsnospace again (no trailing SP).
  if (!_isBcharNoSpace(value.charCodeAt(0))) return false;
  if (!_isBcharNoSpace(value.charCodeAt(value.length - 1))) return false;
  for (var i = 1; i < value.length - 1; i += 1) {
    var cc = value.charCodeAt(i);
    if (cc !== 0x20 && !_isBcharNoSpace(cc)) return false;
  }
  return true;
}

// Find `--<boundary>` at a position preceded by CRLF, LF, or buf start.
// Walks via indexOf scans + verifies the line-start invariant; loops
// past non-line-start hits.
function _findBoundaryAtLineStart(buf, delimiter, from) {
  var pos = from;
  while (pos < buf.length) {
    var idx = buf.indexOf(delimiter, pos);
    if (idx < 0) return -1;
    var atLineStart =
      idx === 0 ||
      (idx >= 1 && buf[idx - 1] === 0x0A) ||
      (idx >= 2 && buf[idx - 2] === 0x0D && buf[idx - 1] === 0x0A);
    if (atLineStart) return idx;
    pos = idx + 1;
  }
  return -1;
}

function _indexOfLineEnd(buf, fromIndex) {
  for (var i = fromIndex; i < buf.length; i += 1) {
    if (buf[i] === 0x0A) return i + 1;
    if (buf[i] === 0x0D && buf[i + 1] === 0x0A) return i + 2;
  }
  return -1;
}

function _decodeBody(buf, encoding) {
  switch (encoding) {
    case "7bit":
    case "8bit":
    case "binary":
      return buf;
    case "base64":
      var compact = codepointClass.stripRanges(buf.toString("ascii"),
                                               codepointClass.WHITESPACE_RANGES);
      return Buffer.from(compact, "base64");
    case "quoted-printable":
      return _decodeQuotedPrintable(buf);
    /* istanbul ignore next */
    default:
      throw new SafeMimeError("safe-mime/unknown-transfer-encoding",
        "safeMime.parse: unknown encoding '" + encoding + "'");
  }
}

function _isHexDigit(cc) {
  return (cc >= 0x30 && cc <= 0x39) || (cc >= 0x41 && cc <= 0x46) ||
         (cc >= 0x61 && cc <= 0x66);
}

var QP_HEX_RADIX = 16;

// Remove the soft line breaks — `=` followed by CRLF or LF — and nothing else.
function _removeSoftLineBreaks(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x3D) continue;                            // "="
    var next = s.charCodeAt(i + 1);
    var width = next === 0x0A ? 2
              : (next === 0x0D && s.charCodeAt(i + 2) === 0x0A) ? 3 : 0;
    if (width === 0) continue;
    out += s.slice(keepFrom, i);
    keepFrom = i + width;
    i += width - 1;
  }
  return keepFrom === 0 ? s : out + s.slice(keepFrom);
}

// Decode `=XX` to the byte those hex digits name; anything else stands.
function _decodeHexEscapes(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x3D) continue;                            // "="
    if (!_isHexDigit(s.charCodeAt(i + 1)) || !_isHexDigit(s.charCodeAt(i + 2))) continue;
    out += s.slice(keepFrom, i) +
           String.fromCharCode(parseInt(s.substr(i + 1, 2), QP_HEX_RADIX));
    keepFrom = i + 3;
    i += 2;
  }
  return keepFrom === 0 ? s : out + s.slice(keepFrom);
}

// The two steps run in sequence, not interleaved: removing a soft break can
// JOIN text into a hex escape (`=3=\r\nD` becomes `=3D`), and only a second
// pass over the joined text decodes it. A single pass that removes the break
// and moves on never revisits the boundary, and a wrapped message decodes
// differently from the same message unwrapped.
function _decodeQuotedPrintable(buf) {
  return Buffer.from(_decodeHexEscapes(_removeSoftLineBreaks(buf.toString("binary"))),
                     "binary");
}

// One RFC 2047 encoded word starting at `at`: `=?charset?Q-or-B?text?=`,
// where neither the charset nor the text may contain a `?`. Returns the three
// parts plus where the word ends, or null.
function _encodedWordAt(s, at) {
  if (s.charAt(at) !== "=" || s.charAt(at + 1) !== "?") return null;
  var charsetEnd = s.indexOf("?", at + 2);
  if (charsetEnd === -1 || charsetEnd === at + 2) return null;       // charset is 1+ chars
  var mode = s.charAt(charsetEnd + 1);
  if ("QqBb".indexOf(mode) === -1 || mode === "") return null;
  if (s.charAt(charsetEnd + 2) !== "?") return null;
  var textStart = charsetEnd + 3;
  var textEnd = s.indexOf("?", textStart);
  if (textEnd === -1 || s.charAt(textEnd + 1) !== "=") return null;
  return {
    charset: s.slice(at + 2, charsetEnd),
    mode:    mode,
    text:    s.slice(textStart, textEnd),
    next:    textEnd + 2,
  };
}

// Q-encoding: `_` is a space and `=XX` is the byte those hex digits name.
function _decodeQEncoding(text) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc === 0x5F) {                                               // "_"
      out += text.slice(keepFrom, i) + " ";
      keepFrom = i + 1;
      continue;
    }
    if (cc !== 0x3D) continue;                                       // "="
    if (!_isHexDigit(text.charCodeAt(i + 1)) ||
        !_isHexDigit(text.charCodeAt(i + 2))) continue;
    out += text.slice(keepFrom, i) +
           String.fromCharCode(parseInt(text.substr(i + 1, 2), QP_HEX_RADIX));
    keepFrom = i + 3;
    i += 2;
  }
  return keepFrom === 0 ? text : out + text.slice(keepFrom);
}

function _decodeRfc2047Words(value) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < value.length; i += 1) {
    if (value.charCodeAt(i) !== 0x3D) continue;                      // "="
    var word = _encodedWordAt(value, i);
    if (word === null) continue;
    out += value.slice(keepFrom, i) + _decodeEncodedWord(word);
    keepFrom = word.next;
    i = word.next - 1;
  }
  return keepFrom === 0 ? value : out + value.slice(keepFrom);
}

function _decodeEncodedWord(word) {
  var raw;
  if (word.mode === "B" || word.mode === "b") {
    raw = Buffer.from(word.text, "base64");
  } else {
    raw = Buffer.from(_decodeQEncoding(word.text), "binary");
  }
  // RFC 2047 §5 encoded-word header-injection defense — after the base64 or
  // Q-encoded decode, check the DECODED bytes for header separators (CR, LF,
  // NUL). A sender that base64-encodes `\r\nBcc: attacker@x.com` would
  // otherwise reach the consumer's header parser as a fresh header line.
  for (var bi = 0; bi < raw.length; bi += 1) {
    var b = raw[bi];
    if (b === 0x0d /* CR */ || b === 0x0a /* LF */ || b === 0x00 /* NUL */) {
      throw new SafeMimeError("safe-mime/rfc2047-header-injection",
        "RFC 2047 encoded-word decoded to bytes containing CR/LF/NUL " +
        "(byte index " + bi + "); refusing per RFC 2047 §5 (encoded-word header injection)");
    }
  }
  return _decodeBufferAs(raw, word.charset);
}

function _decodeBufferAs(buf, charset) {
  var c = String(charset || "us-ascii").toLowerCase();
  if (c === "utf-8" || c === "utf8") return buf.toString("utf8");
  if (c === "us-ascii" || c === "ascii") return buf.toString("ascii");
  if (c === "iso-8859-1" || c === "latin1") return buf.toString("latin1");
  if (c === "utf-16le") return buf.toString("utf16le");
  if (c === "utf-16be") return _decodeUtf16BE(buf);
  if (c === "utf-16") {
    // RFC 2781 §3.3 — `utf-16` with a leading BOM (FE FF = BE, FF FE
    // = LE). When no BOM is present the spec defaults to BE; Node
    // doesn't speak BE natively so we transcode either way.
    if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
      return buf.subarray(2).toString("utf16le");
    }
    if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
      return _decodeUtf16BE(buf.subarray(2));
    }
    return _decodeUtf16BE(buf);   // RFC 2781 §3.3 BE default with no BOM
  }
  return buf.toString("utf8");
}

// utf-16be → utf-16le swap (Node has no direct utf-16be decoder).
// Byte-pair endian flip into a temporary buffer, then decode as
// utf-16le. Allocates a single buffer (no per-character churn).
function _decodeUtf16BE(buf) {
  var n = buf.length & ~1;                                                                                // pair alignment mask
  var swapped = Buffer.alloc(n);
  for (var i = 0; i < n; i += 2) {
    swapped[i]     = buf[i + 1];
    swapped[i + 1] = buf[i];
  }
  return swapped.toString("utf16le");
}

function _materializeText(part) {
  return {
    contentType: part.leaf.contentType,
    charset:     part.leaf.charset,
    body:        _materializeTextValue(part.leaf.body, part.leaf.charset),
  };
}

function _materializeTextValue(buf, charset) {
  return _decodeBufferAs(buf, charset);
}

function _ct(part) {
  return part && part._contentType ? part._contentType : "";
}

// The value of the first `filename=` or `filename*=` parameter in a
// Content-Disposition header, up to the next `;`, or null. The parameter name
// is matched without regard to ASCII case.
function _filenameParamValue(cd) {
  var s = String(cd);
  // Scanned against the ORIGINAL string, not a lower-cased copy: case folding
  // is not length-preserving — U+0130 lower-cases to two code units — so an
  // index found in the folded copy names a different position in the header,
  // and the value sliced from it is a different filename.
  var NAME = "filename";
  var at = -1;
  for (var i = 0; i + NAME.length <= s.length; i += 1) {
    if (!codepointClass.containsFolded(s.slice(i, i + NAME.length), NAME)) continue;
    var after = i + NAME.length;
    if (s.charAt(after) === "*") after += 1;
    if (s.charAt(after) === "=") { at = after + 1; break; }
  }
  if (at === -1) return null;
  var semi = s.indexOf(";", at);
  var value = semi === -1 ? s.slice(at) : s.slice(at, semi);
  return value.length === 0 ? null : value.trim();
}

// An RFC 2231 / 5987 ext-value prefix: `charset'language'`, where both parts
// are drawn from the token set and either may be empty after the first.
function _hasRfc2231CharsetPrefix(raw) {
  var i = 0;
  while (i < raw.length && _isExtValueTokenChar(raw.charCodeAt(i))) i += 1;
  if (i === 0 || raw.charAt(i) !== "'") return false;                // needs 1+ charset chars
  i += 1;
  while (i < raw.length && _isExtValueTokenChar(raw.charCodeAt(i))) i += 1;
  return raw.charAt(i) === "'";                                      // language may be empty
}

function _isExtValueTokenChar(cc) {
  return (cc >= 0x30 && cc <= 0x39) || (cc >= 0x41 && cc <= 0x5A) ||
         (cc >= 0x61 && cc <= 0x7A) || cc === 0x5F || cc === 0x2D;   // "_" "-"
}

function _filenameFromHeaders(headers) {
  var cd = headers.get("content-disposition");
  if (cd) {
    var raw = _filenameParamValue(cd);
    if (raw !== null) {
      if (raw.length >= 2 && raw.charAt(0) === '"' && raw.charAt(raw.length - 1) === '"') {
        raw = raw.slice(1, -1);
      }
      if (_hasRfc2231CharsetPrefix(raw)) {
        var enc = raw.split("'");
        // RFC 2231 / 5987 ext-value percent-decode. A hostile
        // `filename*=UTF-8''%` (truncated %-escape, non-hex digits, or a
        // %-escape sequence that isn't valid UTF-8) makes decodeURIComponent
        // throw a raw URIError, which would escape the SafeMimeError contract
        // and crash the attachment walk. Degrade to the still-encoded segment
        // — best-effort, and downstream filename guards handle the raw form —
        // matching every other decodeURIComponent site in the framework.
        try {
          return decodeURIComponent(enc[2]);
        } catch (_e) {
          return enc[2];
        }
      }
      return raw;
    }
  }
  var ct = headers.get("content-type");
  if (ct) {
    var nameAt = codepointClass.indexOfFolded(ct, "name=");
    if (nameAt !== -1) {
      // The parameter runs to the next `;`, or to the end of the value.
      var valueStart = nameAt + "name=".length;
      var valueEnd = ct.indexOf(";", valueStart);
      var v = ct.slice(valueStart, valueEnd === -1 ? ct.length : valueEnd).trim();
      if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
        v = v.slice(1, -1);
      }
      return v;
    }
  }
  return null;
}

function _toBuffer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === "string") return Buffer.from(input, "utf8");
  if (input instanceof Uint8Array) return Buffer.from(input);
  throw new SafeMimeError("safe-mime/bad-input",
    "safeMime.parse: input must be Buffer, Uint8Array, or string (got " + typeof input + ")");
}

function _intOpt(opts, key, fallback) {
  if (opts[key] === undefined || opts[key] === null) return fallback;
  numericBounds.requirePositiveFiniteInt(opts[key],
    "safeMime.parse: opts." + key, SafeMimeError, "safe-mime/bad-opt");
  return opts[key];
}

function _normalizeStringSet(arr) {
  var set = Object.create(null);
  for (var i = 0; i < arr.length; i += 1) {
    set[String(arr[i]).toLowerCase()] = true;
  }
  return set;
}

function _normalizeCharsetName(c) {
  var s = String(c).toLowerCase().trim();
  if (s === "utf8") return "utf-8";
  if (s === "ascii") return "us-ascii";
  if (s === "latin1") return "iso-8859-1";
  if (s === "cp1252") return "windows-1252";
  if (s === "shift-jis") return "shift_jis";
  return s;
}

function _previewBytes(line) {
  if (typeof line !== "string") line = String(line);
  return line.length > 64 ? line.slice(0, 64) + "..." : line;                                       // log-preview length cap
}

module.exports = {
  parse:               parse,
  walk:                walk,
  findFirst:           findFirst,
  extractText:         extractText,
  extractAttachments:  extractAttachments,
  SafeMimeError:       SafeMimeError,
  // The parsing walks, exposed so the test can compare each against the
  // pattern it replaced rather than only through a whole-message parse.
  _shapesForTest: {
    splitLines:              _splitLines,
    isValidMimeBoundary:     _isValidMimeBoundary,
    decodeQuotedPrintable:   _decodeQuotedPrintable,
    decodeRfc2047Words:      _decodeRfc2047Words,
    unescapeQuotedString:    _unescapeQuotedString,
    filenameParamValue:      _filenameParamValue,
    hasRfc2231CharsetPrefix: _hasRfc2231CharsetPrefix,
  },
  DEFAULTS: Object.freeze({
    maxParts:                  DEFAULT_MAX_PARTS,
    maxNestingDepth:           DEFAULT_MAX_NESTING_DEPTH,
    maxBoundary:               DEFAULT_MAX_BOUNDARY,
    maxHeaderBytes:            DEFAULT_MAX_HEADER_BYTES,
    maxHeaderLineBytes:        DEFAULT_MAX_HEADER_LINE,
    maxHeaderCount:            DEFAULT_MAX_HEADER_COUNT,
    maxBodyBytes:              DEFAULT_MAX_BODY_BYTES,
    maxMessageBytes:           DEFAULT_MAX_MESSAGE_BYTES,
    charsetAllowlist:          DEFAULT_CHARSETS,
    transferEncodingAllowlist: DEFAULT_TRANSFER_ENCODINGS,
  }),
};
