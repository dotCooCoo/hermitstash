// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var pick = require("./pick");

function classifyHeaderBlock(text) {
  var lines = String(text == null ? "" : text).split(/\r?\n/);
  var unfolded = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) break;
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
  return classifyHeaderBlock(text).fields;
}

function splitHeadersAndBody(text) {
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

function stripAddressType(value) {
  if (typeof value !== "string") return null;
  var semi = value.indexOf(";");
  if (semi === -1) return value.trim();
  return value.slice(semi + 1).trim();
}

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
