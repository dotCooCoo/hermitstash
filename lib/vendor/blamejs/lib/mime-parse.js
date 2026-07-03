// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mime-parse — minimal RFC 5322 + RFC 2045 + RFC 2046 reader shared by
 * lib/mail-bounce.js (RFC 3464 DSN parser) and lib/mail-mdn.js (RFC
 * 3798 MDN parser).
 *
 * Scope:
 *
 *   parseHeaderBlock(text)        — split a header section into
 *                                   [{name, value}] with RFC 5322 §2.2.3
 *                                   continuation-line unfolding.
 *   splitHeadersAndBody(text)     — bisect at the empty line per RFC
 *                                   5322 §2.1; tolerate CRLF and LF
 *                                   line endings (real-world MTA chains
 *                                   normalize differently).
 *   findHeader(headers, name)     — case-insensitive header lookup;
 *                                   returns the value of the first
 *                                   match or null.
 *   parseContentType(value)       — `type/subtype; param=value;
 *                                   param="quoted value"` reader.
 *                                   Returns `{ type, params }`.
 *   splitMimeParts(body, boundary) — partition a multipart body on
 *                                   `--<boundary>` markers per RFC
 *                                   2046 §5.1.1; consumes the trailing
 *                                   `--<boundary>--` close.
 *
 * Out of scope (intentionally): MIME word-decoding (RFC 2047), QP /
 * base64 decoding (operators take the part body as-is and decode if
 * Content-Transfer-Encoding asks them to), nested multipart recursion
 * (DSN + MDN reports are flat by spec), full RFC 5322 address-list
 * parsing (mail.js owns the From/To/Cc parser).
 *
 * The reader is byte-encoding-agnostic — strings come in, slices come
 * out. UTF-8 inputs ride through unchanged (RFC 6533 EAI / RFC 6532
 * SMTPUTF8 messages parse correctly). Operator-supplied bytes are
 * length-capped by the calling primitive (mail-bounce: 1 MiB, mail-
 * mdn: 1 MiB) so this module's hot-path doesn't add its own cap.
 */

var pick = require("./pick");

function classifyHeaderBlock(text) {
  // RFC 5322 §2.2 — every line of a header section is either a header field
  // (`name: value`), a folding continuation (leading WSP), or the empty line
  // that ends the section. Anything else is MALFORMED — and a colon-less line
  // sitting in the header section is the header-injection / SMTP-smuggling
  // signal (attacker content on a bare line followed by an injected
  // Bcc/To/From header). `fields` is the parsed headers (boundary-aware,
  // continuation-unfolded); `malformed` is the injection/structure evidence the
  // silent-skip parsers (email, mime, dsn, arc) all dropped on the floor.
  var lines = String(text == null ? "" : text).split(/\r?\n/);
  var unfolded = [];                                                            // [{ line, lineIndex }]
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) break;                                              // header/body boundary
    if ((line.charAt(0) === " " || line.charAt(0) === "\t") && unfolded.length > 0) {
      unfolded[unfolded.length - 1].line += " " + line.replace(/^\s+/, "");
    } else {
      unfolded.push({ line: line, lineIndex: i });
    }
  }
  var fields = [];
  var malformed = [];
  for (var j = 0; j < unfolded.length; j += 1) {
    var entry = unfolded[j];
    var colonAt = entry.line.indexOf(":");
    if (colonAt === -1) {
      malformed.push({ lineIndex: entry.lineIndex, line: entry.line, reason: "no-colon" });
      continue;
    }
    fields.push({
      name:  entry.line.slice(0, colonAt).trim(),
      value: entry.line.slice(colonAt + 1).trim(),
    });
  }
  return { fields: fields, malformed: malformed };
}

function parseHeaderBlock(text) {
  // The fields view of the shared classifier — kept for every caller that only
  // wants the parsed headers (the malformed lines are reached via
  // classifyHeaderBlock for structure/injection validation).
  return classifyHeaderBlock(text).fields;
}

function splitHeadersAndBody(text) {
  // RFC 5322 §2.1 — header / body separator is one empty line. Real-
  // world MTAs disagree on CRLF vs LF; accept both, prefer CRLF when
  // present (the canonical wire form).
  var sepCrlf = text.indexOf("\r\n\r\n");
  var sepLf   = text.indexOf("\n\n");
  var sep, sepLen;
  if (sepCrlf !== -1 && (sepLf === -1 || sepCrlf < sepLf)) {
    sep = sepCrlf; sepLen = 4;
  } else if (sepLf !== -1) {
    sep = sepLf; sepLen = 2;
  } else {
    sep = -1; sepLen = 0;
  }
  if (sep === -1) {
    return { headers: parseHeaderBlock(text), body: "" };
  }
  return {
    headers: parseHeaderBlock(text.slice(0, sep)),
    body:    text.slice(sep + sepLen),
  };
}

function findHeader(headers, name) {
  var target = String(name).toLowerCase();
  for (var i = 0; i < headers.length; i += 1) {
    if (headers[i].name.toLowerCase() === target) return headers[i].value;
  }
  return null;
}

function parseContentType(value) {
  // RFC 2045 §5.1 — `type/subtype` followed by zero or more
  // `; param=value` pairs. Parameter values may be quoted-string with
  // backslash-escaped DQUOTE.
  if (typeof value !== "string") return { type: "", params: {} };
  var semi = value.indexOf(";");
  var typePart = (semi === -1 ? value : value.slice(0, semi)).trim().toLowerCase();
  var rest = semi === -1 ? "" : value.slice(semi + 1);
  var params = {};
  var i = 0;
  while (i < rest.length) {
    while (i < rest.length && (rest.charAt(i) === " " || rest.charAt(i) === "\t" || rest.charAt(i) === ";")) i += 1;
    if (i >= rest.length) break;
    var eq = rest.indexOf("=", i);
    if (eq === -1) break;
    var pname = rest.slice(i, eq).trim().toLowerCase();
    var j = eq + 1;
    while (j < rest.length && (rest.charAt(j) === " " || rest.charAt(j) === "\t")) j += 1;
    var pval;
    if (rest.charAt(j) === '"') {
      var end = j + 1;
      var buf = "";
      while (end < rest.length) {
        var ch = rest.charAt(end);
        if (ch === "\\" && end + 1 < rest.length) {
          buf += rest.charAt(end + 1);
          end += 2;
          continue;
        }
        if (ch === '"') break;
        buf += ch;
        end += 1;
      }
      pval = buf;
      i = end + 1;
    } else {
      var endTok = j;
      while (endTok < rest.length && rest.charAt(endTok) !== ";") endTok += 1;
      pval = rest.slice(j, endTok).trim();
      i = endTok;
    }
    if (!pick.isPoisonedKey(pname)) params[pname] = pval;
  }
  return { type: typePart, params: params };
}

function splitMimeParts(body, boundary) {
  // RFC 2046 §5.1.1 — multipart parts are separated by `--<boundary>`
  // delimiter lines. The closing delimiter is `--<boundary>--`.
  // Preamble (before the first delimiter) and epilogue (after the
  // close) are discarded.
  var parts = [];
  if (typeof boundary !== "string" || boundary.length === 0) return parts;
  var marker = "--" + boundary;
  var lines = String(body).split(/\r?\n/);
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line === marker || line === marker + "--") {
      if (current !== null) parts.push(current.join("\r\n"));
      if (line === marker + "--") { current = null; break; }
      current = [];
      continue;
    }
    if (current !== null) current.push(line);
  }
  return parts;
}

// stripAddressType — RFC 3464 §2.3.1 / RFC 6533 §3.2 / RFC 3798 §3.2.3.
// `addr-type;recipient` -> `recipient`. The type prefix (rfc822 /
// utf-8 / x-* on extension) is consumed by the caller for byte-
// encoding decisions but discarded from the returned recipient.
function stripAddressType(value) {
  if (typeof value !== "string") return null;
  var semi = value.indexOf(";");
  if (semi === -1) return value.trim();
  return value.slice(semi + 1).trim();
}

// addressType — symmetric helper for the BUILD path. RFC 6533 EAI
// awareness: any non-ASCII byte in the recipient flips the address-
// type to utf-8 so the wire form names the encoding correctly.
function addressType(addr) {
  if (typeof addr !== "string") return "rfc822";
  for (var i = 0; i < addr.length; i += 1) {
    if (addr.charCodeAt(i) > 0x7F) return "utf-8";
  }
  return "rfc822";
}

module.exports = {
  parseHeaderBlock:    parseHeaderBlock,
  classifyHeaderBlock: classifyHeaderBlock,
  splitHeadersAndBody: splitHeadersAndBody,
  findHeader:          findHeader,
  parseContentType:    parseContentType,
  splitMimeParts:      splitMimeParts,
  stripAddressType:    stripAddressType,
  addressType:         addressType,
};
