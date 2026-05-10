"use strict";
// auto-site-entries — derive site.config entries directly from
// @module blocks in lib/. Each namespace whose @module block carries
// @nav + @card metadata produces one site.config entry automatically.
//
// Supported @module tags:
//
//   @module b.X              — namespace identifier (REQUIRED)
//   @nav     <Group Name>    — sidebar concern group (e.g. "Tools",
//                              "Validation"). When omitted, falls
//                              into the "Other" group.
//   @title   <Display Name>  — sidebar label + page <h1>. When
//                              omitted, defaults to "b.X".
//   @card    <description>   — multi-line; description for the
//                              landing-page card. When omitted, no
//                              card is rendered (page still exists).
//   @slug    <url-slug>      — optional URL slug override. Default
//                              kebab-cases the namespace.
//
// Example:
//
//   /**
//    * @module b.csv
//    * @nav    Tools
//    * @title  CSV
//    *
//    * @intro
//    *   RFC 4180 parser and serializer with anti-DoS bounds.
//    *
//    * @card
//    *   RFC 4180 parser and serializer. Trusted-source emission only;
//    *   route user-supplied cells through b.guardCsv.
//    */
//
// The derivation runs every page-generator pass. New @module blocks
// land in the wiki on the next boot — no edits to site.config.js
// required.

var parser = require("./source-doc-parser");

function _kebab(ns) {
  return ns
    .replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); })
    .replace(/\./g, "-");                                                              // flatten nested namespaces (b.middleware.clearSiteData → middleware-clear-site-data)
}

function _moduleNs(modTag) {
  return String(modTag || "").replace(/^\s*b\./, "").trim();
}

// Build entries from every @module block parsed under libDir.
// Returns an array shaped like ENTRIES rows: { slug, title, group,
// namespaces: [ns], card?: { description } }.
function deriveFromLib(libDir, opts) {
  opts = opts || {};
  var docs = parser.parseTree(libDir);
  var entries = [];
  var seenSlugs = {};
  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    if (!rec.module) return;
    var modTags = rec.module.tags || {};
    var ns = _moduleNs(modTags.module);
    if (!ns) return;
    // Don't auto-derive for namespaces that are just helper bundles
    // — only those with at least one @primitive block.
    if (!rec.primitives || rec.primitives.length === 0) return;
    var slug = modTags.slug || _kebab(ns);
    if (seenSlugs[slug]) return;
    seenSlugs[slug] = true;
    // Within-group sort key. Default 100 (mid-range); operators bump
    // priority items DOWN (e.g. @order 10 puts a primary primitive
    // near the top of its group). Non-numeric values fall back to 100.
    var orderRaw = modTags.order != null ? parseInt(modTags.order, 10) : NaN;
    var order = isFinite(orderRaw) ? orderRaw : 100;

    var entry = {
      slug:       slug,
      title:      modTags.title || ("b." + ns),
      group:      modTags.nav || "Other",
      order:      order,
      namespaces: [ns],
      // Marker for the home-card filter — auto-derived entries default
      // to NOT featured. Without this gate every annotated namespace
      // would land a card on the home page (150+ tiles of identical
      // text). Hand-authored entries don't carry this flag.
      _autoDerived: true,
      featured: false,
    };
    if (modTags.card) {
      entry.card = {
        description: String(modTags.card).replace(/\s+/g, " ").replace(/^\s+|\s+$/g, ""),
      };
    }
    // `@featured true` opts the namespace into the home-page card
    // grid. Operators curate the home by marking ~1 representative
    // namespace per concern group as featured.
    if (modTags.featured && /^(true|yes|1)$/i.test(modTags.featured)) {
      entry.featured = true;
    }
    entries.push(entry);
  });
  // Stable order: by group then slug.
  entries.sort(function (a, b) {
    if (a.group < b.group) return -1;
    if (a.group > b.group) return 1;
    if (a.slug < b.slug) return -1;
    if (a.slug > b.slug) return 1;
    return 0;
  });
  return entries;
}

// Merge auto-derived entries with hand-authored entries, preferring
// hand-authored when slugs collide. Hand-authored entries win because
// they may carry overrides (custom card description, alternative
// group, hand-tuned title).
function merge(handAuthored, autoDerived) {
  var bySlug = {};
  handAuthored.forEach(function (e) { bySlug[e.slug] = e; });
  autoDerived.forEach(function (e) {
    if (bySlug[e.slug]) return;     // hand-authored override wins
    // Also skip if a hand-authored entry already covers the same
    // namespace (same primitives), under a different slug — prevents
    // double-listing.
    var alreadyCovered = handAuthored.some(function (h) {
      if (!Array.isArray(h.namespaces) || !Array.isArray(e.namespaces)) return false;
      return h.namespaces.some(function (ns) { return e.namespaces.indexOf(ns) !== -1; });
    });
    if (alreadyCovered) return;
    bySlug[e.slug] = e;
  });
  return Object.keys(bySlug).map(function (k) { return bySlug[k]; });
}

module.exports = {
  deriveFromLib: deriveFromLib,
  merge:         merge,
};
