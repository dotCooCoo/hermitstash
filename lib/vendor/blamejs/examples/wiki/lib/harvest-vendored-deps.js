"use strict";
// harvest-vendored-deps — build-time harvest of every vendored dependency
// declared in lib/vendor/MANIFEST.json (the canonical source of truth per
// CLAUDE.md hard-rule §1: "Zero npm runtime deps. Vendor under lib/vendor/
// with MANIFEST.json").
//
// For each manifest entry we walk lib/**/*.js and record which framework
// files require() the vendor's bundle file, plus a hand-authored
// human-readable purpose string ("usedFor"). The shape returned by
// harvest() is:
//
//   { deps: [
//       { name, version, license, sourceUrl, sha256, files,
//         usedBy: [ "lib/crypto.js", ... ],
//         usedFor: "XChaCha20-Poly1305 AEAD cipher",
//         category: "Crypto" | "PKI" | "WebAuthn" | "Other" },
//       ...
//     ] }
//
// render(manifest) returns the wiki-page HTML body — a category-grouped
// table of (Package | Used for | License | Source) with hyperlinks for
// the upstream source URL.

var fs   = require("node:fs");
var path = require("node:path");

var REPO_ROOT     = path.resolve(__dirname, "..", "..", "..");
var MANIFEST_PATH = path.join(REPO_ROOT, "lib", "vendor", "MANIFEST.json");
var LIB_ROOT      = path.join(REPO_ROOT, "lib");

// Hand-authored purpose strings — the manifest's _about field is prose
// for operators reading the JSON; render() needs a tight one-liner per
// dependency for the table cell. Keyed by manifest package name.
var USED_FOR = {
  "@noble/ciphers":               "XChaCha20-Poly1305 AEAD cipher",
  "@noble/post-quantum":          "ML-KEM / ML-DSA / SLH-DSA via FIPS 203 / 204 / 205",
  "@simplewebauthn/server":       "WebAuthn / passkey registration and authentication",
  "SecLists-common-passwords-top-10000":
                                  "NIST 800-63B §5.1.1.2 breached-password list",
  "peculiar-pki":                 "Pure-JS X.509 + PKCS#12 CA engine for b.mtlsCa",
};

// Category bucketing. Every manifest entry MUST resolve to one of the
// four categories — Other is the explicit fallback, not a silent default.
var CATEGORY = {
  "@noble/ciphers":               "Crypto",
  "@noble/post-quantum":          "Crypto",
  "@simplewebauthn/server":       "WebAuthn",
  "SecLists-common-passwords-top-10000":
                                  "Other",
  "peculiar-pki":                 "PKI",
};

var CATEGORY_ORDER = ["Crypto", "PKI", "WebAuthn", "Other"];

// ---------------------------------------------------------------------
// _walkLibJs — recursive lister of every .js file under lib/, returned
// as repo-relative POSIX paths ("lib/crypto.js", "lib/auth/passkey.js").
// Skips lib/vendor/ itself: vendor bundles re-require nothing inside the
// framework, and the goal is "which framework files consume the vendor".
// ---------------------------------------------------------------------
function _walkLibJs() {
  var out = [];
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var ent = entries[i];
      var abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "vendor") continue;
        walk(abs);
        continue;
      }
      if (!ent.isFile()) continue;
      if (!/\.js$/.test(ent.name)) continue;
      var rel = path.relative(REPO_ROOT, abs).split(path.sep).join("/");
      out.push(rel);
    }
  }
  walk(LIB_ROOT);
  out.sort();
  return out;
}

// ---------------------------------------------------------------------
// _bundleBaseFor — given a manifest entry, return the bundle filename
// minus its extension (eg "noble-ciphers" from "lib/vendor/noble-ciphers
// .cjs"). Used to match require("./vendor/noble-ciphers.cjs") and
// require("../vendor/noble-ciphers.cjs") regardless of caller depth.
// ---------------------------------------------------------------------
function _bundleBaseFor(entry) {
  if (!entry || !entry.files || typeof entry.files.server !== "string") return null;
  var server = entry.files.server;                       // "lib/vendor/foo.cjs"
  var base   = path.basename(server);                    // "foo.cjs"
  return base.replace(/\.[^.]+$/, "");                   // "foo"
}

// ---------------------------------------------------------------------
// _findUsedBy — scan every framework .js file for require()/path.join()
// references to the vendor bundle's base name and return the consuming
// files in repo-relative POSIX form.
// ---------------------------------------------------------------------
function _findUsedBy(libFiles, bundleBase) {
  if (!bundleBase) return [];
  // Match either require("…/vendor/<base>.<ext>") or
  // path.join(__dirname, "…", "vendor", "<base>.<ext>") forms. Anchored
  // on /vendor/ + the bundle base to avoid accidental name-overlap.
  // allow:dynamic-regex — bundleBase is harvested from MANIFEST.json (framework-controlled), regex-escaped above
  var requireRe = new RegExp(
    "require\\(\\s*[\"'][^\"']*\\bvendor/" +
      bundleBase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      "\\.[A-Za-z0-9]+[\"']\\s*\\)"
  );
  // allow:dynamic-regex — bundleBase is harvested from MANIFEST.json (framework-controlled), regex-escaped above
  var pathJoinRe = new RegExp(
    "[\"']vendor[\"']\\s*,\\s*[\"']" +
      bundleBase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      "\\.[A-Za-z0-9]+[\"']"
  );
  var hits = [];
  for (var i = 0; i < libFiles.length; i++) {
    var rel = libFiles[i];
    var abs = path.join(REPO_ROOT, rel);
    var src;
    try { src = fs.readFileSync(abs, "utf8"); }
    catch (_e) { continue; }
    if (requireRe.test(src) || pathJoinRe.test(src)) hits.push(rel);
  }
  return hits;
}

// ---------------------------------------------------------------------
// _shortSha — manifest stores "sha256:<64hex>"; the rendered table only
// has room for a fingerprint, so render the first 12 hex digits with an
// ellipsis. The full hash stays in the structured manifest for
// programmatic consumers.
// ---------------------------------------------------------------------
function _shortSha(sha256) {
  if (typeof sha256 !== "string") return "";
  var hex = sha256.replace(/^sha256:/, "");
  if (hex.length <= 12) return hex;
  return hex.slice(0, 12) + "…";
}

function _escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------
// harvest() — read MANIFEST.json, scan lib/, return the structured
// manifest. Throws if MANIFEST.json is missing or malformed (config-time
// entry-point — operators catch typos at boot, per the three-tier
// validation policy).
// ---------------------------------------------------------------------
function harvest() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  var doc = JSON.parse(raw); // allow:bare-json-parse — reads framework's own vendor MANIFEST.json (not operator input)
  if (!doc || typeof doc !== "object" || !doc.packages || typeof doc.packages !== "object") {
    throw new Error("harvest-vendored-deps: MANIFEST.json missing 'packages' object");
  }
  var libFiles = _walkLibJs();
  var deps     = [];
  var names    = Object.keys(doc.packages).sort();
  for (var i = 0; i < names.length; i++) {
    var name  = names[i];
    var entry = doc.packages[name];
    var bundleBase = _bundleBaseFor(entry);
    var usedBy = _findUsedBy(libFiles, bundleBase);
    // Special case: the SecLists password file is a .txt, not a require()
    // target — find consumers by literal filename match.
    if (usedBy.length === 0 && entry && entry.files && typeof entry.files.server === "string") {
      var serverBase = path.basename(entry.files.server);
      for (var f = 0; f < libFiles.length; f++) {
        var abs = path.join(REPO_ROOT, libFiles[f]);
        var src;
        try { src = fs.readFileSync(abs, "utf8"); }
        catch (_e) { continue; }
        if (src.indexOf(serverBase) !== -1) usedBy.push(libFiles[f]);
      }
    }
    deps.push({
      name:      name,
      version:   entry.version || "",
      license:   entry.license || "",
      author:    entry.author  || "",
      sourceUrl: entry.source  || "",
      sha256:    (entry.hashes && entry.hashes.server) || "",
      files:     entry.files || {},
      bundledAt: entry.bundledAt || "",
      bundler:   entry.bundler   || "",
      exports:   Array.isArray(entry.exports) ? entry.exports.slice() : [],
      usedBy:    usedBy,
      usedFor:   USED_FOR[name] || (entry._about ? String(entry._about).split(/\.\s/)[0] + "." : ""),
      category:  CATEGORY[name] || "Other",
    });
  }
  return { deps: deps };
}

// ---------------------------------------------------------------------
// _groupByCategory — preserve CATEGORY_ORDER and emit only categories
// that have at least one dep. Within a category, deps stay
// alphabetically sorted.
// ---------------------------------------------------------------------
function _groupByCategory(deps) {
  var buckets = {};
  for (var i = 0; i < deps.length; i++) {
    var d = deps[i];
    if (!buckets[d.category]) buckets[d.category] = [];
    buckets[d.category].push(d);
  }
  var groups = [];
  for (var c = 0; c < CATEGORY_ORDER.length; c++) {
    var cat = CATEGORY_ORDER[c];
    if (buckets[cat] && buckets[cat].length > 0) {
      groups.push({ category: cat, deps: buckets[cat] });
    }
  }
  return groups;
}

function _renderRow(dep) {
  var srcUrl = dep.sourceUrl;
  var srcCell = srcUrl
    ? "<a href=\"" + _escapeHtml(srcUrl) + "\" rel=\"noopener noreferrer\">" +
      _escapeHtml(srcUrl.replace(/^https?:\/\//, "")) + "</a>"
    : "";
  var pkgCell =
    "<code>" + _escapeHtml(dep.name) + "</code>" +
    (dep.version ? " <span class=\"version\">" + _escapeHtml(dep.version) + "</span>" : "");
  return (
    "<tr>" +
      "<td>" + pkgCell + "</td>" +
      "<td>" + _escapeHtml(dep.usedFor) + "</td>" +
      "<td>" + _escapeHtml(dep.license) + "</td>" +
      "<td>" + srcCell + "</td>" +
    "</tr>"
  );
}

function _renderUsedByList(dep) {
  if (!dep.usedBy || dep.usedBy.length === 0) return "";
  var items = "";
  for (var i = 0; i < dep.usedBy.length; i++) {
    items += "<li><code>" + _escapeHtml(dep.usedBy[i]) + "</code></li>";
  }
  return (
    "<details class=\"vendor-usedby\">" +
      "<summary>Required by " + dep.usedBy.length +
      " framework file" + (dep.usedBy.length === 1 ? "" : "s") + "</summary>" +
      "<ul>" + items + "</ul>" +
    "</details>"
  );
}

function _renderTable(group) {
  var rows = "";
  var details = "";
  for (var i = 0; i < group.deps.length; i++) {
    rows    += _renderRow(group.deps[i]);
    details += _renderUsedByList(group.deps[i]);
  }
  return (
    "<h2 id=\"vendor-" + _escapeHtml(group.category.toLowerCase()) + "\">" +
      _escapeHtml(group.category) + "</h2>" +
    "<table class=\"vendor-table\">" +
      "<thead><tr>" +
        "<th>Package</th>" +
        "<th>Used for</th>" +
        "<th>License</th>" +
        "<th>Source</th>" +
      "</tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
    "</table>" +
    details
  );
}

// ---------------------------------------------------------------------
// render(manifest) — produce the wiki-page HTML body. Caller wraps it
// in the page chrome via examples/wiki/lib/page-generator.js.
// ---------------------------------------------------------------------
function render(manifest) {
  if (!manifest || !Array.isArray(manifest.deps)) {
    throw new TypeError("render: manifest.deps array required");
  }
  var groups = _groupByCategory(manifest.deps);
  var body = "";
  body += "<h1>Vendored dependencies</h1>";
  body += "<p>blamejs ships with <strong>zero npm runtime dependencies</strong>. " +
          "Every third-party package the framework relies on is bundled under " +
          "<code>lib/vendor/</code> and committed to the repository, with its " +
          "version, license, source URL and SHA-256 recorded in " +
          "<code>lib/vendor/MANIFEST.json</code>. Refreshes go through " +
          "<code>scripts/vendor-update.sh</code>; the SHA-256 changes whenever " +
          "the bundle changes, so supply-chain drift is observable in <code>git diff</code>.</p>";
  body += "<p>This page is generated at build time from " +
          "<code>lib/vendor/MANIFEST.json</code> — the canonical source of truth — " +
          "enriched with the framework files that <code>require()</code> each " +
          "vendor bundle. The categories below mirror the security domains " +
          "operators reason about when they audit the supply chain.</p>";
  for (var i = 0; i < groups.length; i++) body += _renderTable(groups[i]);
  return body;
}

module.exports = {
  harvest:           harvest,
  render:            render,
  USED_FOR:          USED_FOR,
  CATEGORY:          CATEGORY,
  CATEGORY_ORDER:    CATEGORY_ORDER,
  _walkLibJs:        _walkLibJs,
  _bundleBaseFor:    _bundleBaseFor,
  _findUsedBy:       _findUsedBy,
  _shortSha:         _shortSha,
  _groupByCategory:  _groupByCategory,
};
