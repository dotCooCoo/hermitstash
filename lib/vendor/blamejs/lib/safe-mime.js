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

var nodeTypes = require("node:util").types;
var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");
var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");
var pick = require("./pick");

var SafeMimeError = defineClass("SafeMimeError", { alwaysPermanent: true });

var DEFAULT_MAX_PARTS         = 64;
var DEFAULT_MAX_NESTING_DEPTH = 16;
var DEFAULT_MAX_BOUNDARY      = 70;
var DEFAULT_MAX_HEADER_BYTES  = C.BYTES.kib(64);
var DEFAULT_MAX_HEADER_LINE   = 998;
var DEFAULT_MAX_HEADER_COUNT  = 512;
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
 * A leaf's `charset` is the effective one, defaulting to `us-ascii` per RFC
 * 2045 section 5.2 when the header names none. Its `contentTypeParams` is
 * the frozen parameter map exactly as the header wrote it, so a caller can
 * tell a written `charset` from a defaulted one and can read the other
 * parameters, `format` and `delsp` (RFC 3676) among them.
 *
 * Throws `SafeMimeError`. The input itself is refused with
 * `safe-mime/bad-input` for bytes it cannot take and `safe-mime/bad-opt` for an
 * option it does not accept.
 *
 * Every budget has its own code, so an oversize message says which bound it
 * crossed: `safe-mime/oversize-message`, `safe-mime/oversize-part-count`,
 * `safe-mime/oversize-nesting`, `safe-mime/oversize-boundary`,
 * `safe-mime/oversize-headers`, `safe-mime/oversize-header-line`,
 * `safe-mime/oversize-body` and `safe-mime/too-many-headers`.
 *
 * The structure is refused with `safe-mime/malformed-boundary`,
 * `safe-mime/malformed-content-type`, `safe-mime/malformed-headers`,
 * `safe-mime/bad-header-name`, `safe-mime/control-char-in-header` for a control
 * byte inside a header, and `safe-mime/rfc2047-header-injection` for an encoded
 * word carrying a header break. An unreadable encoding is refused with
 * `safe-mime/unknown-charset` or `safe-mime/unknown-transfer-encoding` rather
 * than decoded as bytes.
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
 *   structureOnly:            boolean,    // default false — walk the tree without decoding bodies
 *
 * `structureOnly` answers what SHAPE a message has, for a caller that wants
 * the part tree, the content types, the filenames or whether there is an
 * attachment, and not the content. Each leaf's `body` is `null` and its
 * `encodedSize` is the size on the wire; `decoded` is `null`. Every cap and
 * allowlist still applies, so a hostile shape is refused as it would be in
 * the ordinary mode. `b.mailStore` records the attachment facts this way at
 * append, which is the one moment the answer is free.
 *
 * @example
 *   var msg = b.safeMime.parse(messageBuffer);
 *   msg.headers.get("subject");
 *   msg.parts.length;
 *   msg.parts[0].leaf.body.toString("utf8");
 *
 *   var shape = b.safeMime.parse(messageBuffer, { structureOnly: true });
 *   b.safeMime.extractAttachments(shape).length;   // → 2, without decoding either file
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
    structureOnly:   opts.structureOnly === true,
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
  var selection = selectBodyParts(tree);
  var wanted = prefer === "html" ? selection.html : selection.text;
  var other  = prefer === "html" ? selection.text : selection.html;
  if (prefer === "any") {
    wanted = selection.preferred === null ? [] : [selection.preferred];
    other  = [];
  }
  if (wanted.length > 0) return _materializeText(wanted[0].part);
  if (prefer !== "any") {
    var wantType = prefer === "html" ? "text/html" : "text/plain";
    var anywhere = findFirst(tree, function (p) {
      return p.leaf && p.leaf.contentType === wantType &&
        !_isAttachedPart(p) && !_isSelectedAsFile(selection, p);
    });
    if (anywhere) return _materializeText(anywhere);
  }
  if (other.length > 0) return _materializeText(other[0].part);
  if (prefer === "any" && tree &&
      String(tree._contentType || "").toLowerCase().indexOf("multipart/alternative") === 0) {
    var richest = null;
    walk(tree, function (p) {
      if (p.leaf && _isTextType(p.leaf.contentType)) richest = p;
    });
    if (richest) return _materializeText(richest);
  }
  var anyText = findFirst(tree, function (p) {
    return p.leaf && _isTextType(p.leaf.contentType) && !_isAttachedPart(p);
  });
  if (anyText) return _materializeText(anyText);
  var attachedText = findFirst(tree, function (p) {
    return p.leaf && _isTextType(p.leaf.contentType);
  });
  return attachedText ? _materializeText(attachedText) : null;
}

/**
 * @primitive b.safeMime.extractAttachments
 * @signature b.safeMime.extractAttachments(tree, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime.parse, b.guardArchive, b.fileType
 *
 * Return array of attachment-shaped parts. Each entry is
 * `{ filename, contentType, body, headers, path }`. Operators pipe each
 * attachment through `b.fileType.detect` then through the per-type
 * guard (`b.guardArchive` / `b.guardPdf` / etc.).
 *
 * A part is a file when the sender marked it `Content-Disposition:
 * attachment`, when it is `inline` and carries a name, or when it is a leaf
 * that is not displayed body text, which is the classification
 * `b.safeMime.selectBodyParts` applies and RFC 8621 section 4.1.4
 * describes. `includeInline` answers with every leaf in the tree instead, in
 * document order, including the parts a reader displays and the ones an
 * alternative nobody displays carries: it is the caller asking for the parts
 * rather than for the files.
 *
 * `path` is the part's position in the tree, the same array
 * `b.safeMime.walk` hands its visitor: indices from the root, so
 * `tree.parts[path[0]].parts[path[1]]` reaches the part an entry came from.
 * A consumer serving one part at a URL keys on it rather than running a
 * second walk and pairing the two lists by index.
 *
 * @opts
 *   includeInline: boolean,    // default false: the displayed body is not a file
 *
 * @example
 *   var tree = b.safeMime.parse(messageBuffer);
 *   var atts = b.safeMime.extractAttachments(tree);
 *   atts[0].filename;       // → "report.pdf"
 *   atts[0].contentType;    // → "application/pdf"
 *   atts[0].body.length;    // → 12345 (decoded bytes)
 *   atts[0].path;           // → [1] (tree.parts[1])
 */
function extractAttachments(tree, opts) {
  opts = opts || {};
  var out = [];
  if (opts.includeInline === true) {
    walk(tree, function (part, path) {
      if (!part.leaf) return;
      out.push(_attachmentEntry(_displayEntry(part, path)));
    });
    return out;
  }
  var selection = selectBodyParts(tree);
  for (var i = 0; i < selection.files.length; i += 1) {
    out.push(_attachmentEntry(selection.files[i]));
  }
  return out;
}


function _attachmentEntry(entry) {
  return {
    filename:    entry.filename,
    contentType: entry.part.leaf.contentType,
    body:        entry.part.leaf.body,
    headers:     entry.part.headers,
    path:        entry.path,
  };
}

function _isAttachedPart(part) {
  if (!part || !part.headers) return false;
  return String(part.headers.get("content-disposition") || "")
    .toLowerCase().indexOf("attachment") === 0;
}

function _isSelectedAsFile(selection, part) {
  for (var i = 0; i < selection.files.length; i += 1) {
    if (selection.files[i].part === part) return true;
  }
  return false;
}

function _suppliesUnnamedBody(part) {
  if (!part || _isAttachedPart(part)) return false;
  if (part.parts && part.parts.length > 0) {
    var subtype = String(part._contentType || "").toLowerCase();
    if (subtype.indexOf("multipart/related") === 0) {
      var rootIndex = _declaredRootIndex(part);
      return _suppliesUnnamedBody(part.parts[rootIndex === -1 ? 0 : rootIndex]);
    }
    for (var i = 0; i < part.parts.length; i += 1) {
      if (_suppliesUnnamedBody(part.parts[i])) return true;
    }
    return false;
  }
  if (!part.leaf || !part.headers) return false;
  var type = String(part.leaf.contentType || "").toLowerCase();
  if (type !== "text/plain" && type !== "text/html") return false;
  var name = _filenameFromHeaders(part.headers);
  return name === null || name === "";
}

function _unnamedBodySuppliers(parts) {
  var flags = [];
  var total = 0;
  for (var i = 0; i < parts.length; i += 1) {
    var supplies = _suppliesUnnamedBody(parts[i]);
    flags.push(supplies);
    if (supplies) total += 1;
  }
  return { flags: flags, total: total };
}

function _hasUnnamedTextSibling(suppliers, selfIndex) {
  return (suppliers.total - (suppliers.flags[selfIndex] ? 1 : 0)) > 0;
}

function _displayEntry(part, path, index, parentSubtype, otherBody) {
  var cd = (part.headers.get("content-disposition") || "").toLowerCase();
  var filename = _filenameFromHeaders(part.headers);
  var leafType = String((part.leaf && part.leaf.contentType) || "").toLowerCase();
  return {
    part:     part,
    path:     path,
    filename: filename,
    attached: cd.indexOf("attachment") === 0,
    representation: false,
    kind:     _displayKindOf(cd, leafType, filename, index, parentSubtype, otherBody),
  };
}

function _displayKindOf(cd, leafType, filename, index, parentSubtype, otherBody) {
  if (cd.indexOf("attachment") === 0) return "file";
  if (leafType !== "text/plain" && leafType !== "text/html") return "file";
  var named = filename !== null && filename !== "";
  var displayed;
  if (parentSubtype === "related") {
    displayed = index === 0;
  } else {
    displayed = !named || (index === 0 && otherBody !== true);
  }
  if (!displayed) return "file";
  return leafType === "text/plain" ? "text" : "html";
}

function _emptySelection() { return { text: [], html: [], files: [], preferred: null }; }

function _appendSelection(into, from) {
  for (var i = 0; i < from.text.length; i += 1) into.text.push(from.text[i]);
  for (var j = 0; j < from.html.length; j += 1) into.html.push(from.html[j]);
  for (var k = 0; k < from.files.length; k += 1) into.files.push(from.files[k]);
}

function _contentIdValue(value) {
  if (typeof value !== "string") return null;
  var text = value.trim();
  if (text.charAt(0) === "<" && text.charAt(text.length - 1) === ">") {
    text = text.slice(1, -1).trim();
  }
  return text.length > 0 ? text : null;
}

function _declaredRootIndex(part) {
  var header = part.headers && part.headers.getWire
    ? part.headers.getWire("content-type") : null;
  if (typeof header !== "string") return -1;
  var start = _contentIdValue(_parseContentType(header).params.start);
  if (start === null) return -1;
  for (var i = 0; i < part.parts.length; i += 1) {
    var child = part.parts[i];
    if (!child || !child.headers || !child.headers.getWire) continue;
    if (_contentIdValue(child.headers.getWire("content-id")) === start) return i;
  }
  return -1;
}

function _selectAsFiles(part, path, into) {
  if (part.parts && part.parts.length > 0) {
    for (var i = 0; i < part.parts.length; i += 1) {
      _selectAsFiles(part.parts[i], path.concat([i]), into);
    }
    return;
  }
  if (!part.leaf) return;
  var entry = _displayEntry(part, path, 1, "related");
  entry.kind = "file";
  into.files.push(entry);
}

function _selectInto(part, path, into, index, parentSubtype, otherBody) {
  if (parentSubtype === "related" && index !== undefined && index !== 0) {
    _selectAsFiles(part, path, into);
    return;
  }
  if (part.parts && part.parts.length > 0) {
    if (_isAttachedPart(part)) {
      _selectAsFiles(part, path, into);
      return;
    }
    var subtype = String(part._contentType || "").toLowerCase();
    var ownSubtype = subtype.indexOf("multipart/") === 0
      ? subtype.slice("multipart/".length) : subtype;
    if (subtype === "multipart/alternative") {
      _selectAlternative(part, path, into);
      return;
    }
    var rootIndex = ownSubtype === "related" ? _declaredRootIndex(part) : -1;
    var suppliers = _unnamedBodySuppliers(part.parts);
    for (var i = 0; i < part.parts.length; i += 1) {
      var childIndex = rootIndex === -1 ? i : (i === rootIndex ? 0 : i + 1);
      _selectInto(part.parts[i], path.concat([i]), into, childIndex, ownSubtype,
                  _hasUnnamedTextSibling(suppliers, i));
    }
    return;
  }
  if (!part.leaf) return;
  var entry = _displayEntry(part, path, index === undefined ? 0 : index, parentSubtype,
                            otherBody);
  if (entry.kind === "text") into.text.push(entry);
  else if (entry.kind === "html") into.html.push(entry);
  else { into.files.push(entry); return; }
  if (into.preferred === null) into.preferred = entry;
}

function _markAsRepresentation(entries) {
  for (var i = 0; i < entries.length; i += 1) entries[i].representation = true;
}

function _richestTextOf(one) {
  if (one.preferred !== null) return one.preferred;
  for (var i = one.files.length - 1; i >= 0; i -= 1) {
    var entry = one.files[i];
    if (entry.attached) continue;
    if (entry.part && entry.part.leaf && _isTextType(entry.part.leaf.contentType)) return entry;
  }
  return null;
}

function _selectAlternative(part, path, into) {
  var takenText = false;
  var takenHtml = false;
  var kept = [];
  var richest = null;
  var suppliers = _unnamedBodySuppliers(part.parts);
  for (var i = part.parts.length - 1; i >= 0; i -= 1) {
    var one = _emptySelection();
    _selectInto(part.parts[i], path.concat([i]), one, i, "alternative",
                _hasUnnamedTextSibling(suppliers, i));
    if (richest === null) richest = _richestTextOf(one);
    if (one.text.length === 0 && one.html.length === 0) { kept.unshift(one); continue; }
    var wantText = one.text.length > 0 && !takenText;
    var wantHtml = one.html.length > 0 && !takenHtml;
    if (!wantText && !wantHtml) {
      if (one.files.length > 0) {
        kept.unshift({ text: [], html: [], files: one.files });
      }
      continue;
    }
    if (wantText) takenText = true;
    if (wantHtml) takenHtml = true;
    kept.unshift({
      text:  wantText ? one.text : [],
      html:  wantHtml ? one.html : [],
      files: one.files,
    });
  }
  for (var k = 0; k < kept.length; k += 1) {
    if (takenText && takenHtml) {
      _markAsRepresentation(kept[k].text);
      _markAsRepresentation(kept[k].html);
    }
    _appendSelection(into, kept[k]);
  }
  if (into.preferred === null) into.preferred = richest;
}

/**
 * @primitive b.safeMime.selectBodyParts
 * @signature b.safeMime.selectBodyParts(tree)
 * @since     0.20.32
 * @status    stable
 * @related   b.safeMime.parse, b.safeMime.extractAttachments
 *
 * Sort a parsed tree's leaves into the text a reader displays, the HTML it
 * displays, and the files it offers. Returns `{ text, html, files }`, each an
 * array of `{ part, path, filename, kind }` in document order.
 *
 * The parts of a `multipart/alternative` are one body written several ways,
 * ordered simplest to richest (RFC 2046 section 5.1.4), so the LAST
 * representation offering plain text and the last offering HTML are the
 * displayed ones. A representation wrapped in another multipart counts as
 * that one choice, keeping all of its sections and its files.
 *
 * Which representation is displayed decides what the BODY is, not which
 * leaves exist: the files of a representation nobody displays are offered
 * like any other, whichever branch they sit in. The superseded text and HTML
 * themselves are the body written again and are offered as neither.
 *
 * A leaf is a file when its disposition is `attachment`, when it is `inline`
 * and carries a name, or when it is not displayed body text, which is the
 * classification RFC 8621 section 4.1.4 describes.
 *
 * @example
 *   var tree = b.safeMime.parse(bytes);
 *   b.safeMime.selectBodyParts(tree).files.length;
 *   // → 1
 */
function selectBodyParts(tree) {
  var out = _emptySelection();
  if (tree && typeof tree === "object") _selectInto(tree, [], out);
  return out;
}

function _parsePart(buf, ctx, depth, enclosingSubtype) {
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
  var bodyStart = sep;
  if (buf[bodyStart] === 0x0D && buf[bodyStart + 1] === 0x0A) bodyStart += 2;
  else if (buf[bodyStart] === 0x0A) bodyStart += 1;
  if (buf[bodyStart] === 0x0D && buf[bodyStart + 1] === 0x0A) bodyStart += 2;
  else if (buf[bodyStart] === 0x0A) bodyStart += 1;
  var bodyBytes = buf.subarray(bodyStart);

  var headers = _parseHeaders(headerBytes, ctx);
  var impliedType = enclosingSubtype === "digest" ? "message/rfc822" : "text/plain";
  var contentTypeHeader = headers.getWire("content-type") || impliedType;
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
    if (!_isValidMimeBoundary(boundary)) {
      throw new SafeMimeError("safe-mime/malformed-boundary",
        "safeMime.parse: multipart boundary does not match RFC 2046 §5.1.1 bcharsnospace *bchars grammar");
    }
    var partBuffers = _splitMultipart(bodyBytes, boundary);
    var parts = [];
    var ownSubtype = contentType.slice("multipart/".length);
    for (var i = 0; i < partBuffers.length; i += 1) {
      parts.push(_parsePart(partBuffers[i], ctx, depth + 1, ownSubtype));
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
  var contentTypeParams = Object.freeze(params);
  if (ctx.structureOnly) {
    return {
      headers: headers,
      parts:   null,
      leaf:    {
        contentType:       contentType,
        charset:           charset,
        contentTypeParams: contentTypeParams,
        encoding:          encoding,
        body:              null,
        encodedSize:       safeBuffer.byteLengthOf(bodyBytes),
      },
      decoded:      null,
      _contentType: contentType,
      _params:      params,
    };
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
      contentType:       contentType,
      charset:           charset,
      contentTypeParams: contentTypeParams,
      encoding:          encoding,
      body:              decodedBody,
      encodedSize:       safeBuffer.byteLengthOf(bodyBytes),
    },
    decoded:      _materializeTextValue(decodedBody, charset),
    _contentType: contentType,
    _params:      params,
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
  if (lines.length > ctx.maxHeaderCount) {
    throw new SafeMimeError("safe-mime/too-many-headers",
      "safeMime.parse: header count " + lines.length +
      " exceeds maxHeaderCount=" + ctx.maxHeaderCount);
  }
  var headerMap = Object.create(null);
  var wireMap   = Object.create(null);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) {
      throw new SafeMimeError("safe-mime/malformed-headers",
        "safeMime.parse: header line missing colon: " + _previewBytes(line));
    }
    var name  = khv.key;
    var value = khv.value.trim();
    var rawName = line.slice(0, line.indexOf(":"));
    var nameBad = _firstNonFtextOffset(rawName);
    if (nameBad !== -1) {
      throw new SafeMimeError("safe-mime/bad-header-name",
        "safeMime.parse: header name is not RFC 5322 3.6.8 ftext: " +
        (rawName.length === 0
          ? "the name is empty"
          : "byte 0x" + rawName.charCodeAt(nameBad).toString(16) +
            " at offset " + nameBad + " of " + rawName.length) +
        " (name shown escaped: " + _previewBytes(rawName) + ")");
    }
    var hci = codepointClass.firstControlCharOffset(value);
    if (hci !== -1) {
      var byteOffset = Buffer.byteLength(value.slice(0, hci), "utf8");
      throw new SafeMimeError("safe-mime/control-char-in-header",
        "safeMime.parse: header '" + _previewBytes(name) + "' contains control char 0x" +
        value.charCodeAt(hci).toString(16) + " at byte offset " + byteOffset);
    }
    if (pick.isPoisonedKey(name)) continue;
    if (!headerMap[name]) headerMap[name] = [];
    if (!wireMap[name]) wireMap[name] = [];
    wireMap[name].push(value);
    headerMap[name].push(_decodeRfc2047Words(value));
  }
  return {
    get:    function (n) {
      var arr = headerMap[String(n).toLowerCase()];
      return arr && arr.length > 0 ? arr[0] : null;
    },
    getAll: function (n) { return (headerMap[String(n).toLowerCase()] || []).slice(); },
    getWire: function (n) {
      var arr = wireMap[String(n).toLowerCase()];
      return arr && arr.length > 0 ? arr[0] : null;
    },
    names:  function () { return Object.keys(headerMap); },
    raw:    headerMap,
  };
}

var _splitLines = codepointClass.splitLines;


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
    var lineBytes = safeBuffer.byteLengthOf(line);
    if (lineBytes > ctx.maxHeaderLine) {
      throw new SafeMimeError("safe-mime/oversize-header-line",
        "safeMime.parse: header line " + lineBytes +
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

function _unescapeQuotedString(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x5C) continue;
    if (i + 1 >= s.length) break;
    if (codepointClass.inRanges(s.charCodeAt(i + 1),
                                codepointClass.LINE_TERMINATOR_RANGES)) continue;
    out += s.slice(keepFrom, i) + s.charAt(i + 1);
    keepFrom = i + 2;
    i += 1;
  }
  return keepFrom === 0 ? s : out + s.slice(keepFrom);
}

var DISPLAY_NAME_PARAMS = { name: true, filename: true };

var RFC5322_COMMENTS = Object.freeze({ comments: true });

function _parseContentType(value) {
  var text = String(value);
  if (structuredFields.endsInsideQuotedString(text, RFC5322_COMMENTS)) {
    throw new SafeMimeError("safe-mime/malformed-content-type",
      "safeMime.parse: Content-Type ends inside a quoted string (RFC 2045 section 5.1)");
  }
  var parts = structuredFields.splitTopLevel(text, ";", RFC5322_COMMENTS);
  var type  = (parts.length > 0 ? parts[0] : "").toLowerCase().trim();
  var params = Object.create(null);
  var kvps = structuredFields.parseKeyValuePieces(parts, 1);
  structuredFields.forEachKeyValue(kvps, function (k, v) {
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = _unescapeQuotedString(v.slice(1, -1));
    }
    if (pick.isPoisonedKey(k)) return;
    params[k] = DISPLAY_NAME_PARAMS[k] === true ? _decodeRfc2047Words(v) : v;
  });
  return { type: type, params: params };
}

function _splitMultipart(buf, boundary) {
  var delimiter = Buffer.from("--" + boundary);
  var parts = [];
  var pos = 0;
  while (pos < buf.length) {
    var idx = _findBoundaryAtLineStart(buf, delimiter, pos);
    if (idx < 0) break;
    if (buf[idx + delimiter.length] === 0x2D && buf[idx + delimiter.length + 1] === 0x2D) {
      if (parts.length > 0) {
        var prev = parts[parts.length - 1];
        var prevEnd = idx;
        if (prevEnd >= 2 && buf[prevEnd - 2] === 0x0D && buf[prevEnd - 1] === 0x0A) prevEnd -= 2;
        else if (prevEnd >= 1 && buf[prevEnd - 1] === 0x0A) prevEnd -= 1;
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

var _BOUNDARY_PUNCTUATION = "'()+_,./:=?-";
var MAX_BOUNDARY_LENGTH = 70;

function _isBcharNoSpace(cc) {
  return (cc >= 0x30 && cc <= 0x39) ||
         (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A) ||
         _BOUNDARY_PUNCTUATION.indexOf(String.fromCharCode(cc)) !== -1;
}

function _isValidMimeBoundary(value) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > MAX_BOUNDARY_LENGTH) return false;
  if (!_isBcharNoSpace(value.charCodeAt(0))) return false;
  if (!_isBcharNoSpace(value.charCodeAt(value.length - 1))) return false;
  for (var i = 1; i < value.length - 1; i += 1) {
    var cc = value.charCodeAt(i);
    if (cc !== 0x20 && !_isBcharNoSpace(cc)) return false;
  }
  return true;
}

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

function _removeSoftLineBreaks(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x3D) continue;
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

function _decodeHexEscapes(s) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) !== 0x3D) continue;
    if (!_isHexDigit(s.charCodeAt(i + 1)) || !_isHexDigit(s.charCodeAt(i + 2))) continue;
    out += s.slice(keepFrom, i) +
           String.fromCharCode(parseInt(s.substr(i + 1, 2), QP_HEX_RADIX));
    keepFrom = i + 3;
    i += 2;
  }
  return keepFrom === 0 ? s : out + s.slice(keepFrom);
}

function _decodeQuotedPrintable(buf) {
  return Buffer.from(_decodeHexEscapes(_removeSoftLineBreaks(buf.toString("binary"))),
                     "binary");
}

function _encodedWordAt(s, at) {
  if (s.charAt(at) !== "=" || s.charAt(at + 1) !== "?") return null;
  var charsetEnd = s.indexOf("?", at + 2);
  if (charsetEnd === -1 || charsetEnd === at + 2) return null;
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

function _decodeQEncoding(text) {
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc === 0x5F) {
      out += text.slice(keepFrom, i) + " ";
      keepFrom = i + 1;
      continue;
    }
    if (cc !== 0x3D) continue;
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
    if (value.charCodeAt(i) !== 0x3D) continue;
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
  for (var bi = 0; bi < raw.length; bi += 1) {
    var b = raw[bi];
    if (b === 0x0d  || b === 0x0a  || b === 0x00 ) {
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
    if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
      return buf.subarray(2).toString("utf16le");
    }
    if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
      return _decodeUtf16BE(buf.subarray(2));
    }
    return _decodeUtf16BE(buf);
  }
  return buf.toString("utf8");
}

function _decodeUtf16BE(buf) {
  var n = buf.length & ~1;
  var swapped = Buffer.alloc(n);
  for (var i = 0; i < n; i += 2) {
    swapped[i]     = buf[i + 1];
    swapped[i + 1] = buf[i];
  }
  return swapped.toString("utf16le");
}

function _materializeText(part) {
  if (part.leaf.body === null || part.leaf.body === undefined) {
    throw new SafeMimeError("safe-mime/structure-only",
      "safeMime.extractText: this tree was parsed with structureOnly, which keeps no bodies");
  }
  return {
    contentType: part.leaf.contentType,
    charset:     part.leaf.charset,
    body:        _materializeTextValue(part.leaf.body, part.leaf.charset),
  };
}

function _materializeTextValue(buf, charset) {
  return _decodeBufferAs(buf, charset);
}


function _paramValueEndAt(s, at) {
  var inQuotes = false;
  for (var i = at; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (inQuotes) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "\"") inQuotes = false;
      continue;
    }
    if (ch === "\"") { inQuotes = true; continue; }
    if (ch === ";") return i;
  }
  return s.length;
}

function _filenameSegments(s) {
  var NAME = "filename";
  var found = [];
  var inQuotes = false;
  var atParamStart = true;
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (inQuotes) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "\"") inQuotes = false;
      continue;
    }
    if (ch === "\"") { inQuotes = true; atParamStart = false; continue; }
    if (ch === ";") { atParamStart = true; continue; }
    if (ch === " " || ch === "\t") continue;
    var here = atParamStart;
    atParamStart = false;
    if (!here) continue;
    if (i + NAME.length > s.length) continue;
    if (!codepointClass.containsFolded(s.slice(i, i + NAME.length), NAME)) continue;
    var after = i + NAME.length;
    if (s.charAt(after) !== "*") continue;
    after += 1;
    var digitsFrom = after;
    while (after < s.length && s.charCodeAt(after) >= 0x30 && s.charCodeAt(after) <= 0x39) {
      after += 1;
    }
    if (after === digitsFrom) continue;
    var index = parseInt(s.slice(digitsFrom, after), 10);
    var extended = s.charAt(after) === "*";
    if (extended) after += 1;
    while (after < s.length && (s.charAt(after) === " " || s.charAt(after) === "\t")) {
      after += 1;
    }
    if (s.charAt(after) !== "=") continue;
    var valueAt = after + 1;
    var end = _paramValueEndAt(s, valueAt);
    found.push({ index: index, extended: extended, raw: s.slice(valueAt, end).trim() });
  }
  return found;
}

function _filenameParamAt(s, wantExtended) {
  var NAME = "filename";
  var inQuotes = false;
  var atParamStart = true;
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (inQuotes) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "\"") inQuotes = false;
      continue;
    }
    if (ch === "\"") { inQuotes = true; atParamStart = false; continue; }
    if (ch === ";") { atParamStart = true; continue; }
    if (ch === " " || ch === "\t") continue;
    var here = atParamStart;
    atParamStart = false;
    if (!here) continue;
    if (i + NAME.length > s.length) continue;
    if (!codepointClass.containsFolded(s.slice(i, i + NAME.length), NAME)) continue;
    var after = i + NAME.length;
    var extended = s.charAt(after) === "*";
    if (extended) after += 1;
    while (after < s.length && (s.charAt(after) === " " || s.charAt(after) === "\t")) {
      after += 1;
    }
    if (s.charAt(after) !== "=") continue;
    if (extended !== wantExtended) continue;
    return after + 1;
  }
  return -1;
}

function _hexNibble(cc) {
  if (cc >= 0x30 && cc <= 0x39) return cc - 0x30;
  if (cc >= 0x41 && cc <= 0x46) return cc - 0x37;
  if (cc >= 0x61 && cc <= 0x66) return cc - 0x57;
  return -1;
}

function _isAsciiText(s) {
  for (var i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) > 0x7F) return false;
  }
  return true;
}

function _percentDecodeToBytes(s) {
  var out = [];
  for (var i = 0; i < s.length; i += 1) {
    if (s.charAt(i) === "%" && i + 2 < s.length) {
      var hi = _hexNibble(s.charCodeAt(i + 1));
      var lo = _hexNibble(s.charCodeAt(i + 2));
      if (hi !== -1 && lo !== -1) { out.push((hi << 4) | lo); i += 2; continue; }
    }
    out.push(s.charCodeAt(i) & 0xFF);
  }
  return Buffer.from(out);
}

function _assembledContinuation(s) {
  var segs = _filenameSegments(s);
  if (segs.length === 0) return null;
  segs.sort(function (a, c) { return a.index - c.index; });
  for (var i = 0; i < segs.length; i += 1) {
    if (segs[i].index !== i) return null;
  }
  var charset = null;
  var out = "";
  var run = [];
  function _flushRun() {
    if (run.length === 0) return;
    out += _decodeBufferAs(Buffer.concat(run), charset || "utf-8");
    run = [];
  }
  for (var j = 0; j < segs.length; j += 1) {
    var raw = segs[j].raw;
    if (raw.length >= 2 && raw.charAt(0) === "\"" && raw.charAt(raw.length - 1) === "\"") {
      raw = _unescapeQuotedString(raw.slice(1, -1));
    }
    if (!segs[j].extended) {
      if (_isAsciiText(raw)) { run.push(Buffer.from(raw, "latin1")); continue; }
      _flushRun();
      out += raw;
      continue;
    }
    if (j === 0 && _hasRfc2231CharsetPrefix(raw)) {
      var enc = raw.split("'");
      charset = enc[0] || null;
      raw = enc.slice(2).join("'");
    }
    run.push(_percentDecodeToBytes(raw));
  }
  _flushRun();
  return out.length === 0 ? null : out;
}

function _filenameParamValue(cd) {
  var s = String(cd);
  var extended = true;
  var at = _filenameParamAt(s, true);
  if (at === -1) { extended = false; at = _filenameParamAt(s, false); }
  if (at === -1) return null;
  var semi = -1;
  var inQuotes = false;
  for (var i = at; i < s.length; i += 1) {
    var ch = s.charAt(i);
    if (inQuotes) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "\"") inQuotes = false;
      continue;
    }
    if (ch === "\"") { inQuotes = true; continue; }
    if (ch === ";") { semi = i; break; }
  }
  var value = semi === -1 ? s.slice(at) : s.slice(at, semi);
  if (value.length === 0) return null;
  return { raw: value.trim(), extended: extended };
}

function _hasRfc2231CharsetPrefix(raw) {
  var i = 0;
  while (i < raw.length && _isExtValueTokenChar(raw.charCodeAt(i))) i += 1;
  if (raw.charAt(i) !== "'") return false;
  i += 1;
  while (i < raw.length && _isExtValueTokenChar(raw.charCodeAt(i))) i += 1;
  return raw.charAt(i) === "'";
}

function _isExtValueTokenChar(cc) {
  return (cc >= 0x30 && cc <= 0x39) || (cc >= 0x41 && cc <= 0x5A) ||
         (cc >= 0x61 && cc <= 0x7A) || cc === 0x5F || cc === 0x2D;
}

/**
 * @primitive b.safeMime.filenameFromHeaders
 * @signature b.safeMime.filenameFromHeaders(headers)
 * @since     0.20.32
 * @status    stable
 * @related   b.safeMime.extractAttachments, b.safeMime.walk, b.staticServe.attachmentDisposition
 *
 * Read the filename a part declares, from its `Content-Disposition` or, when
 * that carries none, from the `name` parameter of its `Content-Type`.
 * Returns `null` when neither names one.
 *
 * The extended `filename*` wins over the plain `filename` when both are
 * present, which is the pairing RFC 6266 section 4.3 asks a sender for and
 * writes in that order, and its RFC 8187 ext-value is percent-decoded. A
 * sender that left an apostrophe unescaped in that value, which is what
 * `encodeURIComponent` does, still reads back whole.
 *
 * A name split across RFC 2231 section 3 continuations (`filename*0*`,
 * `filename*1*`, …) is assembled in index order first, with the
 * charset'language' prefix on the first segment as section 4.1 writes it and
 * each `*`-flagged segment percent-decoded. A run missing a segment names
 * nothing, so it reads as `null` rather than as the pieces that did arrive.
 *
 * `extractAttachments` reads filenames with this, so a caller walking the
 * tree itself gets the same answer rather than writing another
 * `Content-Disposition` reader.
 *
 * @example
 *   b.safeMime.walk(tree, function (part) {
 *     if (part.leaf) console.log(b.safeMime.filenameFromHeaders(part.headers));
 *   });
 */
function _filenameFromHeaders(headers) {
  var cd = (headers.getWire && headers.getWire("content-disposition")) ||
           headers.get("content-disposition");
  if (cd) {
    var joined = _assembledContinuation(cd);
    if (joined !== null) return joined;
    var param = _filenameParamValue(cd);
    if (param !== null) {
      var raw = param.raw;
      if (raw.length >= 2 && raw.charAt(0) === '"' && raw.charAt(raw.length - 1) === '"') {
        raw = _unescapeQuotedString(raw.slice(1, -1));
      }
      raw = _decodeRfc2047Words(raw);
      if (param.extended && _hasRfc2231CharsetPrefix(raw)) {
        var enc = raw.split("'");
        var valueChars = enc.slice(2).join("'");
        try {
          return decodeURIComponent(valueChars);
        } catch (_e) {
          return valueChars;
        }
      }
      return raw;
    }
  }
  var ct = (headers.getWire && headers.getWire("content-type")) ||
           headers.get("content-type");
  if (ct) {
    var named = _parseContentType(ct).params.name;
    if (typeof named === "string" && named.length > 0) return named;
  }
  return null;
}

function _toBuffer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === "string") return Buffer.from(input, "utf8");
  if (nodeTypes.isUint8Array(input)) return Buffer.from(input);
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
  return safeBuffer.previewText(line);
}

function _firstNonFtextOffset(name) {
  if (name.length === 0) return 0;
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c < 33 || c > 126 || c === 58) return i;
  }
  return -1;
}

/**
 * @primitive b.safeMime.isHeaderFieldName
 * @signature b.safeMime.isHeaderFieldName(name)
 * @since     0.20.32
 * @status    stable
 * @related   b.safeMime.parse, b.mail.server.jmap.create
 *
 * Is this the RFC 5322 section 2.2 name of a header field: one or more
 * `ftext`, the printable US-ASCII characters 33 through 126 except the
 * colon? The bytes are read as they were carried, so the space in
 * `From : ops@example.com` reads false, which is what a receiving parser
 * makes of it: a line that is not a field at all.
 *
 * `parse` applies this to every field it reads. It is exported because a
 * consumer reading a header block itself has the same question to answer,
 * and answering it a second way is how two readers come to disagree about
 * which fields a message carries.
 *
 * @example
 *   b.safeMime.isHeaderFieldName("From");                            // → true
 *   b.safeMime.isHeaderFieldName("From ");                           // → false
 */
function isHeaderFieldName(name) {
  if (typeof name !== "string") return false;
  return _firstNonFtextOffset(name) === -1;
}

module.exports = {
  parse:               parse,
  isHeaderFieldName:   isHeaderFieldName,
  walk:                walk,
  findFirst:           findFirst,
  extractText:         extractText,
  extractAttachments:  extractAttachments,
  selectBodyParts:     selectBodyParts,
  filenameFromHeaders: _filenameFromHeaders,
  SafeMimeError:       SafeMimeError,
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
