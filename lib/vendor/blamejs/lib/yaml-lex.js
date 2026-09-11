// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

function _isSpace(code) { return code === 0x20 || code === 0x09; }

function _isPlainSpace(ch) { return ch === " " || ch === "\t"; }

function _isPropertySigil(ch) { return ch === "!" || ch === "&" || ch === "*"; }

function _blockHeaderEnd(line, at) {
  var ch = line.charAt(at);
  if (ch !== "|" && ch !== ">") return null;
  var i = at + 1;
  var declared = 0, sawChomp = false;
  while (i < line.length) {
    var c = line.charAt(i);
    if (c >= "1" && c <= "9" && !declared) { declared = Number(c); i += 1; continue; }
    if ((c === "-" || c === "+") && !sawChomp) { sawChomp = true; i += 1; continue; }
    break;
  }
  var j = i;
  while (j < line.length && _isPlainSpace(line.charAt(j))) j += 1;
  if (j < line.length && line.charAt(j) !== "#") return null;
  return { end: i, declared: declared };
}

function _isVerbatimLine(line, indent) {
  if (line.charAt(0) === "%") return true;
  if (indent !== 0) return false;
  if (line.indexOf("---") === 0 &&
      (line.length === 3 || _isPlainSpace(line.charAt(3)))) return true;
  if (line.indexOf("...") === 0 &&
      (line.length === 3 || _isPlainSpace(line.charAt(3)))) return true;
  return false;
}

function maskNonStructural(text) {
  return lexLines(text).masked;
}

function lexLines(text) {
  var src = String(text == null ? "" : text);
  var lines = src.split("\n");
  var out = [];
  var nodeStarts = new Uint8Array(src.length);
  var lineBase = 0;
  var blockOwner = -1;
  var blockBody  = -1;
  var openQuote = null;
  var flowDepth = 0;
  var plainOpen = -1;
  var plainFromDash = false;

  for (var li = 0; li < lines.length; li += 1) {
    if (li > 0) lineBase += lines[li - 1].length + 1;
    var raw = lines[li];
    var cr = raw.length && raw.charAt(raw.length - 1) === "\r";
    var line = cr ? raw.slice(0, raw.length - 1) : raw;
    var indent = 0;
    while (indent < line.length && _isSpace(line.charCodeAt(indent))) indent += 1;
    var blank = indent === line.length;

    var resumeAt = -1;
    var resumePrefix = "";
    if (openQuote !== null) {
      var cont = _maskQuotedBody(line, 0, openQuote);
      if (!cont.closed) {
        out.push(cont.masked + (cr ? "\r" : ""));
        continue;
      }
      openQuote = null;
      resumeAt = cont.end;
      resumePrefix = cont.masked;
    }

    if (resumeAt === -1) {
      if (blockOwner >= 0) {
        if (blank) { out.push(_blanked(line) + (cr ? "\r" : "")); continue; }
        if (blockBody === -1) {
          if (indent > blockOwner) {
            blockBody = indent;
            out.push(_blanked(line) + (cr ? "\r" : ""));
            continue;
          }
          blockOwner = -1;
        } else if (indent >= blockBody) {
          out.push(_blanked(line) + (cr ? "\r" : ""));
          continue;
        } else {
          blockOwner = -1;
          blockBody  = -1;
        }
      }
      if (blank) { out.push(raw); continue; }
      if (_isVerbatimLine(line, indent)) {
        out.push(_maskTrailingComment(line) + (cr ? "\r" : ""));
        flowDepth = 0;
        plainOpen = -1;
        plainFromDash = false;
        blockOwner = -1;
        blockBody = -1;
        continue;
      }
    }

    var masked = resumeAt === -1 ? line.slice(0, indent) : resumePrefix;
    var i = resumeAt === -1 ? indent : resumeAt;
    var continuesPlain = resumeAt === -1 && plainOpen >= 0 && !blank &&
                         (plainFromDash ? indent >= plainOpen : indent > plainOpen);
    var atNodeStart = resumeAt === -1 && !continuesPlain;
    var nodeIndent = indent;
    var dashIndent = -1;
    var prevWasJsonKey = false;
    var sawPlainToEol = false;
    var plainStartCol = -1;

    while (i < line.length) {
      var ch = line.charAt(i);
      var jsonKeyBefore = prevWasJsonKey;
      prevWasJsonKey = false;

      if (atNodeStart && !_isPlainSpace(ch) && ch !== "#") {
        nodeStarts[lineBase + i] = 1;
      }

      if (ch === "#" && (i === indent || _isPlainSpace(line.charAt(i - 1)))) {
        masked += _blanked(line.slice(i));
        break;
      }

      if (_isPlainSpace(ch)) {
        masked += ch; i += 1; prevWasJsonKey = jsonKeyBefore; continue;
      }

      if (ch === "{" || ch === "[") {
        masked += ch; i += 1; flowDepth += 1; atNodeStart = true; continue;
      }
      if (ch === "}" || ch === "]") {
        masked += ch; i += 1; if (flowDepth > 0) flowDepth -= 1;
        atNodeStart = false;
        prevWasJsonKey = true;
        continue;
      }
      if (ch === ",") { masked += ch; i += 1; atNodeStart = true; continue; }
      if (ch === "-" && (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)))) {
        masked += ch; i += 1; atNodeStart = true;
        var afterDash = i;
        while (afterDash < line.length && _isPlainSpace(line.charAt(afterDash))) afterDash += 1;
        if (afterDash < line.length) nodeIndent = afterDash;
        dashIndent = i - 1;
        continue;
      }
      if (ch === "?" && (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)))) {
        masked += ch; i += 1; atNodeStart = true; continue;
      }
      if (ch === ":" &&
          (i + 1 >= line.length || _isPlainSpace(line.charAt(i + 1)) ||
           (flowDepth > 0 && ",}]".indexOf(line.charAt(i + 1)) !== -1) ||
           (flowDepth > 0 && jsonKeyBefore))) {
        masked += ch; i += 1; atNodeStart = true; continue;
      }

      if (atNodeStart && _isPropertySigil(ch)) {
        var pEnd = i + 1;
        if (ch === "!" && line.charAt(pEnd) === "!") pEnd += 1;
        while (pEnd < line.length && !_isPlainSpace(line.charAt(pEnd)) &&
               (flowDepth === 0 || ",}]".indexOf(line.charAt(pEnd)) === -1)) pEnd += 1;
        masked += line.slice(i, pEnd);
        i = pEnd;
        continue;
      }

      if (ch === '"' || ch === "'") {
        var qr = _maskQuotedBody(line, i + 1, ch);
        masked += ch + qr.masked;
        i = qr.end;
        if (!qr.closed) { openQuote = ch; break; }
        atNodeStart = false;
        prevWasJsonKey = true;
        continue;
      }

      var bHead = _blockHeaderEnd(line, i);
      if (bHead) {
        masked += line.slice(i, bHead.end);
        blockOwner = (dashIndent >= 0 && i === nodeIndent) ? dashIndent : nodeIndent;
        blockBody = bHead.declared ? blockOwner + bHead.declared : -1;
        i = bHead.end;
        atNodeStart = false;
        continue;
      }

      var s = i;
      while (s < line.length) {
        var c3 = line.charAt(s);
        if (c3 === "#" && _isPlainSpace(line.charAt(s - 1))) break;
        if (c3 === ":" &&
            (s + 1 >= line.length || _isPlainSpace(line.charAt(s + 1)) ||
             (flowDepth > 0 && ",}]".indexOf(line.charAt(s + 1)) !== -1))) break;
        if (flowDepth > 0 && ",}][{".indexOf(c3) !== -1) break;
        s += 1;
      }
      masked += _blanked(line.slice(i, s));
      plainStartCol = i;
      i = s;
      atNodeStart = false;
      sawPlainToEol = s >= line.length;
    }
    if (sawPlainToEol && openQuote === null && blockOwner < 0) {
      if (!continuesPlain) {
        plainOpen = nodeIndent;
        plainFromDash = dashIndent >= 0 && plainStartCol === nodeIndent;
      }
    } else {
      plainOpen = -1;
      plainFromDash = false;
    }
    out.push(masked + (cr ? "\r" : ""));
  }
  return { masked: out.join("\n"), nodeStarts: nodeStarts };
}

function _maskTrailingComment(line) {
  for (var i = 0; i < line.length; i += 1) {
    if (line.charAt(i) !== "#") continue;
    if (i !== 0 && !_isPlainSpace(line.charAt(i - 1))) continue;
    return line.slice(0, i) + _blanked(line.slice(i));
  }
  return line;
}

function _maskQuotedBody(line, at, quote) {
  var body = "";
  var k = at;
  while (k < line.length) {
    var c = line.charAt(k);
    if (quote === '"' && c === "\\" && k + 1 < line.length) { body += "  "; k += 2; continue; }
    if (c === quote) {
      if (quote === "'" && line.charAt(k + 1) === "'") { body += "  "; k += 2; continue; }
      return { masked: body + quote, end: k + 1, closed: true };
    }
    body += c === "\t" ? "\t" : " ";
    k += 1;
  }
  return { masked: body, end: k, closed: false };
}

function _blanked(s) {
  var o = "";
  for (var i = 0; i < s.length; i += 1) o += s.charAt(i) === "\t" ? "\t" : " ";
  return o;
}

module.exports = {
  maskNonStructural: maskNonStructural,
  lexLines:          lexLines,
};
