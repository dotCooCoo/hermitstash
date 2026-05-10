"use strict";
// symbol-index — build-time harvest of every primitive signature
// documented in the wiki, keyed by `b.X.Y` for client-side autocomplete.
//
// Walks the page seeders under seeders/prod/pages/, parses every
// <h2>/<h3> heading, extracts the leading `b.X.Y(...)` signature
// (matching the same pattern the primitive-section validator uses),
// and produces a JSON manifest of:
//
//   [ { sig: "b.crypto.encryptEnvelope", page: "crypto-vault",
//       anchor: "b-crypto-encryptenvelope", title: "Crypto & Vault" },
//     ... ]
//
// Loaded by the buildApp boot sequence at app start. The wiki exposes
// the manifest at /api/symbols.json so the client autocomplete reads
// it as a static JSON resource.

var HEADING_RE = /<h([23])(?:\s+[^>]*)?>([\s\S]*?)<\/h\1>/g;
var SIG_RE     = /b\.[a-zA-Z][a-zA-Z0-9_.]*(?:\s*\([^)]*\))?/g;
var ID_ATTR_RE = /\bid\s*=\s*"([^"]+)"/;

function _stripAnchorMarkup(s) {
  return String(s)
    .replace(/<a\s+class="anchor"[^>]*>[\s\S]*?<\/a>/g, "")
    .replace(/<\/?code>/g, "")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .replace(/^\s+|\s+$/g, "");
}

function _slugFromSig(sig) {
  return String(sig)
    .replace(/^\s*b\./, "")
    .replace(/\([^)]*\)/g, "")
    .replace(/\s+\/\s+/g, "-")
    .replace(/[^a-zA-Z0-9_]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
}

function _findHeadings(body) {
  var rows = [];
  HEADING_RE.lastIndex = 0;
  var m;
  while ((m = HEADING_RE.exec(body)) !== null) {
    var idMatch = ID_ATTR_RE.exec(m[0]);
    rows.push({
      level: parseInt(m[1], 10),
      idAttr: idMatch ? idMatch[1] : null,
      inner: m[2],
    });
  }
  return rows;
}

function _signaturesIn(innerHtml) {
  var stripped = _stripAnchorMarkup(innerHtml);
  if (stripped.indexOf("b.") !== 0) return [];
  SIG_RE.lastIndex = 0;
  var sigs = [];
  var m;
  while ((m = SIG_RE.exec(stripped)) !== null) {
    var sig = m[0].replace(/\s+/g, " ");
    sigs.push(sig);
  }
  return sigs;
}

function build(pages) {
  if (!Array.isArray(pages)) throw new TypeError("build: pages array required");
  var manifest = [];
  for (var i = 0; i < pages.length; i++) {
    var page = pages[i];
    if (!page || typeof page.body !== "string") continue;
    var headings = _findHeadings(page.body);
    for (var h = 0; h < headings.length; h++) {
      var heading = headings[h];
      var sigs = _signaturesIn(heading.inner);
      if (sigs.length === 0) continue;
      var anchor = heading.idAttr || _slugFromSig(sigs[0]);
      for (var s = 0; s < sigs.length; s++) {
        manifest.push({
          sig:     sigs[s],
          sigBare: sigs[s].replace(/\([^)]*\)/g, "").replace(/\s+/g, ""),
          page:    page.slug,
          title:   page.title || page.slug,
          anchor:  anchor,
          level:   heading.level,
        });
      }
    }
  }
  manifest.sort(function (a, b) {
    if (a.sigBare < b.sigBare) return -1;
    if (a.sigBare > b.sigBare) return 1;
    return 0;
  });
  return manifest;
}

function groupByNamespace(manifest) {
  var groups = {};
  for (var i = 0; i < manifest.length; i++) {
    var entry = manifest[i];
    var parts = entry.sigBare.split(".");
    var ns = parts.length >= 2 ? parts[1] : "_root";
    if (!groups[ns]) groups[ns] = [];
    groups[ns].push(entry);
  }
  return groups;
}

module.exports = {
  build:            build,
  groupByNamespace: groupByNamespace,
  _findHeadings:    _findHeadings,
  _signaturesIn:    _signaturesIn,
  _slugFromSig:     _slugFromSig,
};
