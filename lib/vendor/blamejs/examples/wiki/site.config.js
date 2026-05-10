"use strict";
// site.config.js — single source of truth for the wiki's navigation,
// home-page cards, and source-driven page generation.
//
// Most entries are AUTO-DERIVED from `@module` blocks in lib/. This
// file only carries the small curated set that doesn't auto-derive
// from a lib namespace:
//
//   - Welcome (the framework intro / getting started)
//   - Concept narrative pages (lib/wiki-concepts.js @concept blocks)
//   - Reference pages backed by a harvester module
//
// Every other namespace appears via lib/auto-site-entries.js, which
// walks the framework's lib/ for `@module` blocks carrying:
//
//     @module     b.<namespace>
//     @nav        <Sidebar Group>     (else: "Other")
//     @title      <Display Name>      (else: "b.<namespace>")
//     @card       <description>       (else: no home-page card)
//     @order      <number>            (default 100; lower = earlier
//                                      within the sidebar group)
//     @featured   true                (opt into the home-card grid)
//
// Hand-authored entries below ALWAYS win when slugs collide.

var path = require("node:path");

var ENTRIES = [
  // ============================================================
  // Welcome — framework intro / getting started.
  // ============================================================
  { slug: "welcome", title: "Welcome", group: null, concept: "welcome",
    card: { description: "Start here — what blamejs is, how to install, how to read this site." } },

  // ============================================================
  // Concepts — narrative pages from lib/wiki-concepts.js @concept
  // ============================================================
  { slug: "concepts-security-defaults", title: "Security defaults",
    group: "Concepts", concept: "security-defaults",
    card: { description: "Security defaults are not opt-in. CSRF / origin / bot-guard / sealed storage / audit chain — all wired into the request lifecycle, not behind config flags." } },
  { slug: "concepts-envelope-versioning", title: "Envelope versioning",
    group: "Concepts", concept: "envelope-versioning",
    card: { description: "How crypto algorithms roll forward without breaking on-disk data. Versioned envelope, kid rotation, AAD-bound ciphertext." } },
  { slug: "concepts-validation-discipline", title: "Validation discipline",
    group: "Concepts", concept: "validation-discipline",
    card: { description: "Three-tier policy: throw at config-time, drop-silent on hot paths, return defaults on request-shape reads." } },
  { slug: "concepts-compliance-postures", title: "Compliance postures",
    group: "Concepts", concept: "compliance-postures",
    card: { description: "Union-of-bars strategy for HIPAA / PCI / GDPR / SOC 2 / DORA / NIS 2 / CRA. Strictest-wins by default." } },
  { slug: "concepts-modernity-posture", title: "Modernity posture",
    group: "Concepts", concept: "modernity-posture",
    card: { description: "TLS 1.3 minimum, ML-KEM-1024 hybrid, SLH-DSA audit signatures, Argon2id passwords. No classical-only fallbacks." } },

  // ============================================================
  // Reference — auto-generated tables from harvester modules
  // ============================================================
  { slug: "api", title: "API index", group: "Reference", handAuthored: true,
    card: { description: "Every operator-facing primitive across all namespaces, alphabetical, deep-linked. Search via the sidebar (or `/`)." } },
  { slug: "reference-errors", title: "Error catalog",
    group: "Reference", harvest: "errors",
    card: { description: "Every framework error class registered via b.frameworkError.defineClass — code, message shape, callsites." } },
  { slug: "reference-env-vars", title: "Environment variables",
    group: "Reference", harvest: "env-vars",
    card: { description: "Every BLAMEJS_* / WIKI_* env var the framework reads, with default + type schema, harvested from safeEnv.readVar calls." } },
  { slug: "reference-vendored-deps", title: "Vendored dependencies",
    group: "Reference", harvest: "vendored-deps",
    card: { description: "Every package vendored under lib/vendor/ — version, license, source URL, SHA-256, framework consumers." } },
  { slug: "reference-cli", title: "CLI commands",
    group: "Reference", harvest: "cli",
    card: { description: "Every blamejs CLI subcommand harvested from lib/cli.js — args, flags, exit codes, examples." } },
];

// ---- Auto-derived entries -----------------------------------------
//
// Every @module block in lib/ that carries @nav + @title + @card
// metadata produces a site.config entry automatically. New namespaces
// land in the wiki on the next boot — no edits to site.config.js
// required. Hand-authored ENTRIES above always win when slugs collide.
var autoSiteEntries;
var autoEntries = null;
function _allEntries() {
  if (autoEntries === null) {
    try {
      autoSiteEntries = require("./lib/auto-site-entries");
      var libDir = path.join(__dirname, "..", "..", "lib");
      var derived = autoSiteEntries.deriveFromLib(libDir);
      autoEntries = autoSiteEntries.merge(ENTRIES, derived);
    } catch (e) {
       
      console.warn("[site.config] auto-derive failed; falling back to hand-authored ENTRIES only:", e && e.message); // allow:console-direct — wiki seeder helper, runs at boot before b.log is wired
      autoEntries = ENTRIES;
    }
  }
  return autoEntries;
}

// ---- Derived views ----

function navGroups() {
  var groups = [];
  var byName = {};
  _allEntries().forEach(function (e) {
    if (e.hidden) return;
    if (!e.group) return;
    if (!byName[e.group]) {
      byName[e.group] = { name: e.group, items: [] };
      groups.push(byName[e.group]);
    }
    byName[e.group].items.push({
      slug:  e.slug,
      title: e.title,
      order: typeof e.order === "number" ? e.order : 100,
    });
  });
  groups.forEach(function (g) {
    g.items.sort(function (a, b) {
      if (a.order !== b.order) return a.order - b.order;
      var at = a.title.toLowerCase();
      var bt = b.title.toLowerCase();
      return at < bt ? -1 : at > bt ? 1 : 0;
    });
    g.items = g.items.map(function (it) { return { slug: it.slug, title: it.title }; });
  });
  // Stable group order — keep editorial flow even though the entries
  // themselves are auto-derived. New groups land at the end.
  var GROUP_ORDER = [
    "Welcome", "Concepts", "Identity", "Crypto", "Data", "HTTP",
    "Validation", "Communication", "Mail", "Network", "AI",
    "Tools", "API Contracts", "Compliance", "Observability",
    "Production", "Guards", "Other", "Reference",
  ];
  groups.sort(function (a, b) {
    var ai = GROUP_ORDER.indexOf(a.name); if (ai === -1) ai = 999;
    var bi = GROUP_ORDER.indexOf(b.name); if (bi === -1) bi = 999;
    if (ai !== bi) return ai - bi;
    return a.name < b.name ? -1 : 1;
  });
  return groups;
}

function groupForPath(pathname) {
  if (typeof pathname !== "string") return null;
  var clean = pathname.replace(/^\/+/, "").replace(/\/+$/, "").split("?")[0];
  var slug = clean.split("/")[0];
  if (!slug) return null;
  var entries = _allEntries();
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].slug === slug && entries[i].group) return entries[i].group;
  }
  return null;
}

// Home-page card filter:
//   - Hand-authored entries (concepts, harvesters): card.description
//     IS the curation signal; included by default.
//   - Auto-derived entries: only show on the home when explicitly
//     marked `@featured true` in the source @module block. Without
//     the opt-in, every annotated namespace would land a card and
//     the home would be 150+ tiles of indistinguishable text.
function homeCards() {
  return _allEntries()
    .filter(function (e) {
      if (e.hidden) return false;
      if (!e.card || !e.card.description) return false;
      if (e._autoDerived) return e.featured === true;
      return true;
    })
    .map(function (e) {
      return { slug: e.slug, title: e.title, description: e.card.description };
    });
}

function curationPages() {
  return _allEntries()
    .filter(function (e) { return e.concept || Array.isArray(e.namespaces) || e.harvest; })
    .map(function (e) {
      var spec = { slug: e.slug, title: e.title };
      if (e.concept) spec.concept = e.concept;
      if (Array.isArray(e.namespaces)) spec.namespaces = e.namespaces;
      if (e.harvest) spec.harvest = e.harvest;
      return spec;
    });
}

function expectedSlugs() {
  return _allEntries().map(function (e) { return e.slug; });
}

module.exports = {
  get ENTRIES() { return _allEntries(); },
  navGroups:      navGroups,
  groupForPath:   groupForPath,
  homeCards:      homeCards,
  curationPages:  curationPages,
  expectedSlugs:  expectedSlugs,
};
