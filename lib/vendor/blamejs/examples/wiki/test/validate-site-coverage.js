"use strict";
// validate-site-coverage — enforce that nav, cards, page seeders, and
// curation entries are all consistent with site.config.js.
//
// Invariants checked:
//
//   1. Every entry in site.config.js's ENTRIES array resolves to one
//      seeded page in the DB (groupName=slug, slug="index").
//
//   2. Every seeded DB page is referenced by at least one ENTRIES
//      entry. Orphan rows fail the gate (catch when a hand-authored
//      seeder is added but never registered in site.config).
//
//   3. Every nav-group entry (group !== null AND !hidden) maps to an
//      existing page slug.
//
//   4. Every home-card entry (card.description set) resolves to an
//      existing page slug.
//
//   5. Every concept entry's `concept` value resolves to a @concept
//      block somewhere under lib/. The page-generator's missing-block
//      placeholder is INTENTIONAL behavior to surface drift; the
//      validator promotes it to a hard fail.
//
//   6. Every namespaces entry has at least one @primitive block under
//      a matching b.X namespace in lib/.
//
//   7. Every harvest entry resolves to a harvester module
//      (examples/wiki/lib/harvest-<id>.js) that exports both
//      `harvest()` and `render()`.
//
//   8. Every nav group has ≥1 visible entry (no empty groups).
//
//   9. Every entry has either `handAuthored` OR exactly one of
//      `concept` / `namespaces` / `harvest` (no double-typing).
//
// Run standalone (boots in-process via buildApp to read the seeded
// DB; or pass --db-path to point at an existing data dir):
//   node examples/wiki/test/validate-site-coverage.js
//   node examples/wiki/test/validate-site-coverage.js --db-path=./data
//   node examples/wiki/test/validate-site-coverage.js --report

var fs   = require("node:fs");
var path = require("node:path");

var site = require("../site.config");

var REPORT_ONLY = process.argv.indexOf("--report") !== -1;
var DB_PATH_ARG = process.argv.find(function (a) { return a.indexOf("--db-path=") === 0; });
var DB_PATH = DB_PATH_ARG ? DB_PATH_ARG.split("=")[1] : path.join(__dirname, "..", "data", "blamejs.db");

var LIB_DIR = path.join(__dirname, "..", "..", "..", "lib");

function _seededSlugs(dbPath) {
  // Pages table holds (groupName, slug). Landing pages have
  // slug="index" and groupName=<page-slug>; that's the slug we want.
  // Use node:sqlite directly to avoid needing the framework boot.
  var sqlite = require("node:sqlite");
  var db;
  try { db = new sqlite.DatabaseSync(dbPath); }
  catch (e) {
    return { ok: false, reason: "cannot open " + dbPath + ": " + (e && e.message) };
  }
  try {
    var rows = db.prepare("SELECT groupName, slug FROM pages WHERE slug = 'index'").all();
    return { ok: true, slugs: rows.map(function (r) { return r.groupName; }) };
  } finally {
    db.close();
  }
}

function _libConceptIds() {
  var ids = {};
  var parser = require("../lib/source-doc-parser");
  var docs = parser.parseTree(LIB_DIR);
  Object.keys(docs).forEach(function (file) {
    (docs[file].concepts || []).forEach(function (c) {
      if (c.tags && c.tags.concept) ids[c.tags.concept] = file;
    });
  });
  return ids;
}

function _libNamespacesWithPrimitives() {
  var ns = {};
  var parser = require("../lib/source-doc-parser");
  var docs = parser.parseTree(LIB_DIR);
  Object.keys(docs).forEach(function (file) {
    (docs[file].primitives || []).forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (!sig) return;
      // Index every prefix of the bare path so a curated namespace
      // entry like `httpClient.cache` / `middleware.clearSiteData` /
      // `mail.bimi` resolves to the @primitive block whose bare path
      // equals OR descends from the namespace. Plain first-segment
      // matching only covers `httpClient` / `middleware` / `mail` and
      // rejects every nested-namespace curation entry.
      var bare = String(sig).replace(/\([^)]*\)/g, "").replace(/\s+/g, "")
        .replace(/^b\./, "");
      var parts = bare.split(".");
      for (var i = 1; i <= parts.length; i += 1) {
        ns[parts.slice(0, i).join(".")] = true;
      }
    });
  });
  return ns;
}

function _resolveHarvester(id) {
  var p = path.join(__dirname, "..", "lib", "harvest-" + id + ".js");
  if (!fs.existsSync(p)) return { ok: false, reason: "module not found at " + path.relative(process.cwd(), p) };
  var mod;
  try { mod = require(p); }
  catch (e) { return { ok: false, reason: "module load error: " + (e && e.message) }; }
  if (typeof mod.harvest !== "function") return { ok: false, reason: "module does not export harvest()" };
  if (typeof mod.render !== "function") return { ok: false, reason: "module does not export render()" };
  return { ok: true };
}

function validate(opts) {
  var findings = [];
  var dbPath = (opts && opts.dbPath) || DB_PATH;
  var entries = site.ENTRIES;
  var entryBySlug = {};
  entries.forEach(function (e) { entryBySlug[e.slug] = e; });

  // 9. Schema: each entry has exactly one source-of-truth declaration.
  entries.forEach(function (e) {
    var kindCount =
      (e.handAuthored ? 1 : 0) +
      (e.concept ? 1 : 0) +
      (Array.isArray(e.namespaces) ? 1 : 0) +
      (e.harvest ? 1 : 0);
    if (kindCount === 0) {
      findings.push({ kind: "schema", slug: e.slug, msg: "entry has no kind — set one of `handAuthored`, `concept`, `namespaces`, or `harvest`" });
    }
    if (kindCount > 1) {
      findings.push({ kind: "schema", slug: e.slug, msg: "entry has multiple kinds set — pick exactly one" });
    }
  });

  // 5. Concept references resolve.
  var conceptIds = _libConceptIds();
  entries.forEach(function (e) {
    if (e.concept && !conceptIds[e.concept]) {
      findings.push({
        kind: "concept-missing", slug: e.slug,
        msg: "@concept `" + e.concept + "` not found anywhere under lib/",
      });
    }
  });

  // 6. Namespace references have at least one @primitive.
  var nsWith = _libNamespacesWithPrimitives();
  entries.forEach(function (e) {
    if (Array.isArray(e.namespaces)) {
      e.namespaces.forEach(function (ns) {
        if (!nsWith[ns]) {
          findings.push({
            kind: "namespace-missing", slug: e.slug,
            msg: "namespace `b." + ns + "` has no @primitive blocks anywhere under lib/",
          });
        }
      });
    }
  });

  // 7. Harvester modules exist + export the right surface.
  entries.forEach(function (e) {
    if (e.harvest) {
      var r = _resolveHarvester(e.harvest);
      if (!r.ok) {
        findings.push({
          kind: "harvest-missing", slug: e.slug,
          msg: "harvester `" + e.harvest + "`: " + r.reason,
        });
      }
    }
  });

  // 4. Card references — homeCards() filters to entries with
  //    card.description; verify each card resolves to a real entry.
  site.homeCards().forEach(function (c) {
    if (!entryBySlug[c.slug]) {
      findings.push({ kind: "card-orphan", slug: c.slug, msg: "home card slug has no matching entry" });
    }
    if (!c.description || c.description.length < 5) {
      findings.push({ kind: "card-empty", slug: c.slug, msg: "home card description is missing or too short" });
    }
  });

  // 8. No empty nav groups.
  site.navGroups().forEach(function (g) {
    if (g.items.length === 0) {
      findings.push({ kind: "empty-nav-group", slug: "(group:" + g.name + ")", msg: "nav group has zero visible items" });
    }
  });

  // 1+2. DB ↔ ENTRIES correspondence.
  var seeded = _seededSlugs(dbPath);
  if (!seeded.ok) {
    findings.push({
      kind: "db-unavailable", slug: "(db)",
      msg: seeded.reason + ". Run the wiki app once to seed, or pass --db-path=<path>.",
    });
  } else {
    var seededSet = {};
    seeded.slugs.forEach(function (s) { seededSet[s] = true; });
    entries.forEach(function (e) {
      if (!seededSet[e.slug]) {
        findings.push({
          kind: "page-missing", slug: e.slug,
          msg: "site.config entry has no corresponding seeded page in the DB (page-generator failed or seeder skipped)",
        });
      }
    });
    seeded.slugs.forEach(function (s) {
      if (!entryBySlug[s]) {
        findings.push({
          kind: "page-orphan", slug: s,
          msg: "DB has a seeded page with no entry in site.config — register it (handAuthored) or remove the seeder",
        });
      }
    });
  }

  return findings;
}

function _report(findings) {
  if (findings.length === 0) {
    var entries = site.ENTRIES;
    var groups = site.navGroups();
    var cards  = site.homeCards();
    var curation = site.curationPages();
    console.log("[validate-site-coverage] OK");
    console.log("  " + entries.length + " entries; " + groups.length + " nav groups; " + cards.length + " cards; " + curation.length + " generated pages");
    return 0;
  }
  console.log("[validate-site-coverage] " + findings.length + " finding(s):");
  findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.slug);
    console.log("     " + f.msg);
  });
  return REPORT_ONLY ? 0 : 1;
}

if (require.main === module) {
  process.exit(_report(validate()));
}

module.exports = { validate: validate };
