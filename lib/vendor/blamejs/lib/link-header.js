"use strict";
/**
 * @module b.linkHeader
 * @nav    HTTP
 * @title  Link header
 *
 * @intro
 *   Parse and build the HTTP <code>Link</code> header (RFC 8288 Web
 *   Linking) — the standard way to convey relations between resources,
 *   most visibly REST pagination
 *   (<code>Link: &lt;…?page=2&gt;; rel="next"</code>). A header carries
 *   one or more comma-separated links, each an angle-bracketed URI
 *   reference followed by <code>;</code>-separated parameters
 *   (<code>rel</code>, <code>title</code>, <code>type</code>, …).
 *
 *   <code>parse</code> returns one object per link with its
 *   <code>uri</code>, the (space-split) <code>rel</code> relation types,
 *   and the remaining <code>params</code>; <code>serialize</code> is the
 *   inverse. The comma split and quoted-parameter unwrapping reuse the
 *   framework's RFC 8941 structured-field helpers so a comma inside a
 *   quoted <code>title</code> never fake-splits the list.
 *
 * @card
 *   HTTP Link header codec (RFC 8288 Web Linking) — parse and build
 *   <code>Link: &lt;uri&gt;; rel="next"</code> relations, the standard
 *   REST pagination mechanism. Quote-aware so a comma inside a quoted
 *   parameter never splits the list.
 */

var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");

var LinkHeaderError = defineClass("LinkHeaderError", { alwaysPermanent: true });

var MAX_HEADER_BYTES = 16384;                                // allow:raw-byte-literal — defensive cap on a parsed Link header

// Split a Link header on the commas that separate links — those OUTSIDE
// a <uri-reference> and outside a quoted-string. structuredFields'
// splitter is quote-aware but not angle-bracket-aware, so a comma inside
// a URI (`<https://x/a,b>`) must not split the list (RFC 8288 §3.5).
function _splitLinks(s) {
  var out = [], start = 0, inUri = false, inQuote = false, esc = false;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (esc) { esc = false; continue; }
    if (inQuote) { if (c === "\\") esc = true; else if (c === "\"") inQuote = false; continue; }
    if (c === "\"") { inQuote = true; }
    else if (c === "<") { inUri = true; }
    else if (c === ">") { inUri = false; }
    else if (c === "," && !inUri) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out;
}

/**
 * @primitive b.linkHeader.parse
 * @signature b.linkHeader.parse(headerValue)
 * @since     0.12.57
 * @status    stable
 * @related   b.linkHeader.serialize, b.pagination.cursor
 *
 * Parse an HTTP <code>Link</code> header value (RFC 8288) into an array
 * of <code>{ uri, rel, params }</code> — one per link. <code>uri</code>
 * is the angle-bracketed target, <code>rel</code> is the array of
 * (space-separated) relation types, and <code>params</code> is the
 * remaining parameters with quoted values unwrapped. A comma inside a
 * quoted parameter value does not split the list. A link without a
 * bracketed URI is refused.
 *
 * @example
 *   b.linkHeader.parse('<https://api/x?page=2>; rel="next", <https://api/x?page=9>; rel="last"');
 *   // → [ { uri: "https://api/x?page=2", rel: ["next"], params: {} },
 *   //     { uri: "https://api/x?page=9", rel: ["last"], params: {} } ]
 */
function parse(headerValue) {
  if (typeof headerValue !== "string") throw new LinkHeaderError("link-header/bad-input", "linkHeader.parse: headerValue must be a string");
  if (headerValue.length > MAX_HEADER_BYTES) throw new LinkHeaderError("link-header/too-large", "linkHeader.parse: Link header exceeds " + MAX_HEADER_BYTES + " bytes");
  structuredFields.refuseControlBytes(headerValue, { ErrorClass: LinkHeaderError, code: "link-header/bad-input", label: "Link header" });
  var out = [];
  var members = _splitLinks(headerValue);
  for (var i = 0; i < members.length; i++) {
    var raw = members[i].trim();
    if (raw === "") continue;
    if (raw.charAt(0) !== "<") throw new LinkHeaderError("link-header/bad-link", "linkHeader.parse: link must start with a <uri-reference>");
    var close = raw.indexOf(">");
    if (close === -1) throw new LinkHeaderError("link-header/bad-link", "linkHeader.parse: unterminated <uri-reference>");
    var uri = raw.slice(1, close);
    var rest = raw.slice(close + 1);
    var paramParts = structuredFields.splitTopLevel(rest, ";");
    var rel = [], relSet = false, params = Object.create(null);
    for (var p = 0; p < paramParts.length; p++) {
      var piece = paramParts[p].trim();
      if (piece === "") continue;
      var eq = piece.indexOf("=");
      var name = (eq === -1 ? piece : piece.slice(0, eq)).trim().toLowerCase();
      if (name === "") continue;
      var value = eq === -1 ? "" : structuredFields.unquoteSfString(piece.slice(eq + 1).trim());
      if (value === null) throw new LinkHeaderError("link-header/bad-link", "linkHeader.parse: unterminated quoted parameter on '" + name + "'");
      // RFC 8288 §3.3 / §3.4: a repeated rel (or any parameter) keeps the
      // FIRST occurrence; later ones are ignored.
      if (name === "rel") { if (!relSet) { rel = value.split(/\s+/).filter(Boolean); relSet = true; } continue; }
      if (!(name in params)) params[name] = value;
    }
    out.push({ uri: uri, rel: rel, params: params });
  }
  return out;
}

// Quote every parameter value (always valid RFC 8288, and required for
// space-separated multi-rel and non-token values like "text/html"); the
// common convention (RFC 8288 examples, REST pagination) quotes too.
function _serParam(name, value) {
  if (value === "" || value === true) return name;            // valueless parameter
  return name + "=\"" + String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

/**
 * @primitive b.linkHeader.serialize
 * @signature b.linkHeader.serialize(links)
 * @since     0.12.57
 * @status    stable
 * @related   b.linkHeader.parse
 *
 * Build an HTTP <code>Link</code> header value from an array of
 * <code>{ uri, rel, params? }</code> (or a single such object). The URI
 * is angle-bracketed, <code>rel</code> (string or array) is emitted
 * first, and parameters are token-valued when they fit RFC 7230 token
 * grammar or double-quoted otherwise. Useful for emitting standard REST
 * pagination links.
 *
 * @example
 *   b.linkHeader.serialize([
 *     { uri: "https://api/x?page=2", rel: "next" },
 *     { uri: "https://api/x?page=9", rel: "last", params: { title: "end" } },
 *   ]);
 *   // → '<https://api/x?page=2>; rel="next", <https://api/x?page=9>; rel="last"; title="end"'
 */
function serialize(links) {
  var arr = Array.isArray(links) ? links : [links];
  var parts = [];
  for (var i = 0; i < arr.length; i++) {
    var link = arr[i];
    if (!link || typeof link !== "object" || typeof link.uri !== "string" || link.uri === "") {
      throw new LinkHeaderError("link-header/bad-link", "linkHeader.serialize: links[" + i + "] requires a non-empty uri");
    }
    if (link.uri.indexOf(">") !== -1 || link.uri.indexOf("<") !== -1) {
      throw new LinkHeaderError("link-header/bad-link", "linkHeader.serialize: uri must not contain angle brackets");
    }
    var seg = "<" + link.uri + ">";
    var rel = Array.isArray(link.rel) ? link.rel.join(" ") : (link.rel || "");
    if (rel !== "") seg += "; " + _serParam("rel", rel);
    if (link.params && typeof link.params === "object") {
      var keys = Object.keys(link.params);
      for (var k = 0; k < keys.length; k++) {
        if (keys[k].toLowerCase() === "rel") continue;        // rel is emitted from link.rel
        seg += "; " + _serParam(keys[k].toLowerCase(), link.params[keys[k]]);
      }
    }
    parts.push(seg);
  }
  return parts.join(", ");
}

module.exports = {
  parse:           parse,
  serialize:       serialize,
  LinkHeaderError: LinkHeaderError,
};
