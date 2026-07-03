// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vendor-currency gate.
 *
 * Reads lib/vendor/MANIFEST.json and asserts that every npm-mapped
 * vendored package matches the latest release on the public npm
 * registry. Intended to fire as a CI gate so a stale vendored bundle
 * (a security-relevant transitive bumped its version while we sat
 * pinned) becomes a release blocker, not a quietly-aging tarball.
 *
 * Run locally:
 *   node scripts/check-vendor-currency.js
 *   node scripts/check-vendor-currency.js --json     // structured output
 *   node scripts/check-vendor-currency.js --warn     // exit 0, print only
 *
 * Run in CI:
 *   set BLAMEJS_VENDOR_CURRENCY_REQUIRED=1 in the workflow env to
 *   convert "stale" findings into a non-zero exit. Default behaviour
 *   is fail-on-stale; the env var is for operators who want to gate
 *   on a transient-network registry response (CI sometimes hangs on
 *   registry mirrors) without losing the signal — pair with --warn
 *   for advisory-only mode.
 *
 * Out-of-band packages (SecLists corpus is a GitHub raw download,
 * peculiar-pki is a meta-bundle composed of multiple npm packages)
 * are checked against their declared upstream sources where
 * possible, otherwise reported as "skipped" with a reason. Skipped
 * packages do NOT trip the gate by design — the gate is for
 * version drift on packages we COULD have shipped fresh.
 */

var fs   = require("fs");
var path = require("path");
var https = require("https");

var MANIFEST_PATH = path.join(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var REGISTRY_BASE = "https://registry.npmjs.org/";

// Operator overrides via env. Both default off.
var WARN_ONLY      = process.argv.indexOf("--warn") !== -1;
var JSON_OUT       = process.argv.indexOf("--json") !== -1;
var TIMEOUT_MS     = 10000;

// Per-package mapping table. Keys are MANIFEST.json keys; values
// describe how to currency-check the entry. Missing entries are
// treated as "the manifest key is the npm name verbatim" — the
// common case for scoped packages like @noble/ciphers.
//
// shape:
//   { type: "npm", name: "<npm-package>" }     — query registry, compare version
//   { type: "npm-meta", components: [...] }    — meta-bundle: each component must be current
//   { type: "github-raw", note: "..." }        — GitHub raw download (no version semantics)
//   { type: "skip", reason: "..." }            — skip with documented reason
//   { type: "http-content", url, localFile, commitRe?, versionRe? }
//                                              — data file tracked off a
//                                                bare upstream URL (no
//                                                version semantics); compare
//                                                an embedded COMMIT/VERSION
var SPECIAL_MAP = {
  "publicsuffix-list": {
    type: "http-content",
    url: "https://publicsuffix.org/list/public_suffix_list.dat",
    localFile: "public-suffix-list.dat",
    // The PSL embeds an immutable git COMMIT sha and a VERSION timestamp
    // in its header; either changes iff the list changed. Comparing them
    // is robust to our appended canary block — a plain content hash is
    // not (the canary makes our copy hash differ from upstream forever).
    commitRe:  /^\/\/ COMMIT:\s*([0-9a-f]{7,40})/m,
    versionRe: /^\/\/ VERSION:\s*(\S+)/m
  },
  "bimi-trust-anchors": {
    type: "skip",
    reason: "operator-managed VMC/CMC trust anchors — empty source-tree default by design; operators populate + refresh per the file-header procedure, so there is no single upstream version to track"
  },
  "SecLists-common-passwords-top-10000": {
    type: "github-master",
    owner: "danielmiessler",
    repo:  "SecLists",
    branch: "master",
    path:  "Passwords/Common-Credentials/10k-most-common.txt"
  },
  "peculiar-pki": {
    type: "npm-meta",
    components: [
      { manifestField: "components.@peculiar/x509", npm: "@peculiar/x509", versionRe: /(\d+\.\d+\.\d+)/ },
      { manifestField: "components.pkijs",           npm: "pkijs",           versionRe: /pkijs-(\d+\.\d+\.\d+)/ }
    ]
  }
};

function _githubLatestCommit(owner, repo, branch, filePath) {
  // GitHub Commits API: most recent commit touching <filePath> on
  // <branch>. Returns ISO8601 commit date string. Unauthenticated
  // requests are limited to 60/hour per IP — fine for the framework's
  // single-digit vendored entry count, even on a busy CI runner.
  return new Promise(function (resolve, reject) {
    var qp = "?path=" + encodeURIComponent(filePath) + "&sha=" + encodeURIComponent(branch) + "&per_page=1";
    var url = "https://api.github.com/repos/" + owner + "/" + repo + "/commits" + qp;
    var req = https.get(url, { timeout: TIMEOUT_MS,
      headers: {
        "User-Agent": "blamejs-vendor-currency/1",
        "Accept":     "application/vnd.github+json"
      }
    }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error("github " + owner + "/" + repo + " status " + res.statusCode));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        try {
          var doc = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!Array.isArray(doc) || doc.length === 0 || !doc[0].commit) {
            return reject(new Error("github " + owner + "/" + repo + " no commits on " + branch + " touching " + filePath));
          }
          resolve({
            sha:  doc[0].sha,
            date: doc[0].commit.author && doc[0].commit.author.date,
          });
        } catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("github " + owner + "/" + repo + " timed out")); });
    req.on("error", reject);
  });
}

function _registryFetch(name) {
  // Direct node:https for portability — does NOT route through
  // b.httpClient because the gate runs from scripts/ before any
  // framework state exists. node:https with TLS 1.3 is sufficient
  // for a public-registry GET — no SSRF / cert-pin posture needed
  // to talk to registry.npmjs.org over public DNS.
  return new Promise(function (resolve, reject) {
    var url = REGISTRY_BASE + encodeURIComponent(name).replace("%40", "@") + "/latest";
    var req = https.get(url, { timeout: TIMEOUT_MS,
      headers: { "User-Agent": "blamejs-vendor-currency/1", "Accept": "application/json" }
    }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error("registry " + name + " status " + res.statusCode));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        try {
          var doc = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!doc || typeof doc.version !== "string") {
            return reject(new Error("registry " + name + " returned no .version"));
          }
          resolve(doc.version);
        } catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("registry " + name + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

function _httpGetText(url, redirectsLeft) {
  // Plain text GET that follows redirects (publicsuffix.org has issued
  // 30x to a CDN host in the past). Same node:https rationale as
  // _registryFetch — the gate runs before any framework state exists.
  if (redirectsLeft === undefined) redirectsLeft = 5;
  return new Promise(function (resolve, reject) {
    var req = https.get(url, { timeout: TIMEOUT_MS,
      headers: { "User-Agent": "blamejs-vendor-currency/1", "Accept": "text/plain,*/*" }
    }, function (res) {
      var sc = res.statusCode;
      if (sc >= 300 && sc < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error("too many redirects for " + url));
        var next;
        try { next = new URL(res.headers.location, url).toString(); }
        catch (e) { return reject(e); }
        return resolve(_httpGetText(next, redirectsLeft - 1));
      }
      if (sc !== 200) {
        res.resume();
        return reject(new Error("GET " + url + " status " + sc));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    });
    req.on("timeout", function () { req.destroy(new Error("GET " + url + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

// Pure comparison for content-tracked data-file vendors (no semver,
// no npm registry). Extracted so it is unit-testable without network:
// feed it the upstream + local file text and the SPECIAL_MAP entry.
//
// Primary signal is an immutable upstream identifier embedded in the
// file (the PSL ships `// COMMIT: <sha>`); the fallback is a version/
// timestamp header (`// VERSION: <ts>`). Both survive our appended
// canary block and trailing-whitespace churn — they change iff the
// upstream data changed. Returns { stale, basis, upstreamId, localId }
// or throws when neither side yields a comparable identifier (the
// caller maps that to "registry-error" so an upstream-format change
// surfaces loudly instead of silently passing the gate).
// Parse a "YYYY-MM-DD_HH-MM-SS_UTC" version header (the PSL's) into ms, or
// null when it isn't that timestamp shape.
function _parseVersionTs(v) {
  var m = String(v || "").match(/^(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})_UTC$/);
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

function _classifyContentCurrency(upstreamText, localText, special) {
  function pick(text, re) { var m = re && text.match(re); return (m && m[1]) || null; }
  var uCommit = pick(upstreamText, special.commitRe);
  var lCommit = pick(localText,    special.commitRe);
  var uVer    = pick(upstreamText, special.versionRe);
  var lVer    = pick(localText,    special.versionRe);
  // Timestamp-versioned source (the PSL ships `// VERSION: <ts>`): "stale"
  // means our bundle is genuinely BEHIND upstream, not merely different.
  // publicsuffix.org is CDN-served and different edges can return an OLDER
  // cached copy than the one we vendored; an exact commit/version inequality
  // would then mis-flag our (newer) bundle as stale and fail the release gate
  // non-deterministically. When both sides carry a parseable VERSION
  // timestamp, compare them directionally — only a bundle older than upstream
  // is stale; newer-or-equal is current. (The COMMIT remains the displayed
  // identifier but cannot order two revisions, so it is not the staleness
  // basis here.)
  var uTs = _parseVersionTs(uVer);
  var lTs = _parseVersionTs(lVer);
  if (uTs !== null && lTs !== null) {
    return { stale: lTs < uTs, basis: "version-timestamp", upstreamId: uVer, localId: lVer,
             upstreamVersion: uVer, localVersion: lVer };
  }
  if (uCommit && lCommit) {
    return { stale: uCommit !== lCommit, basis: "commit", upstreamId: uCommit, localId: lCommit,
             upstreamVersion: uVer, localVersion: lVer };
  }
  if (uVer && lVer) {
    return { stale: uVer !== lVer, basis: "version", upstreamId: uVer, localId: lVer,
             upstreamVersion: uVer, localVersion: lVer };
  }
  throw new Error("no comparable COMMIT/VERSION identifier in upstream or local copy");
}

function _semverParse(v) {
  // Strip leading "v" + any pre-release tail. Returns [maj, min, pat]
  // as numbers, or null if not parseable.
  var m = String(v).match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

function _walkDots(obj, dotPath) {
  var parts = dotPath.split(".");
  var node = obj;
  for (var i = 0; i < parts.length; i++) {
    if (node == null || typeof node !== "object") return undefined;
    node = node[parts[i]];
  }
  return node;
}

async function _checkOne(key, manifestEntry) {
  var special = SPECIAL_MAP[key];
  if (special && special.type === "skip") {
    return { key: key, status: "skipped", reason: special.reason };
  }
  if (special && special.type === "github-master") {
    // Compare upstream master/main commit date against the manifest's
    // bundledAt date. If upstream has commits newer than bundledAt,
    // the vendored copy is stale even though no semver bumped.
    try {
      var commit = await _githubLatestCommit(special.owner, special.repo, special.branch, special.path);
      var bundledAt = manifestEntry.bundledAt;
      // Both are ISO date strings — Date.parse for comparison.
      var upstreamMs = Date.parse(commit.date);
      var bundledMs  = Date.parse(bundledAt);
      var stale = isFinite(upstreamMs) && isFinite(bundledMs) && upstreamMs > bundledMs;
      return {
        key:        key,
        upstream:   special.owner + "/" + special.repo + "@" + special.branch + ":" + special.path,
        bundledAt:  bundledAt,
        upstreamAt: commit.date,
        upstreamSha: commit.sha,
        status:     stale ? "stale" : "current",
      };
    } catch (e) {
      return {
        key:    key,
        status: "registry-error",
        error:  (e && e.message) || String(e),
      };
    }
  }
  if (special && special.type === "http-content") {
    // Data file tracked off a bare upstream URL (e.g. the PSL). Fetch
    // upstream, read our bundled copy, compare embedded COMMIT/VERSION.
    try {
      var upstreamText = await _httpGetText(special.url);
      var localPath = path.join(__dirname, "..", "lib", "vendor", special.localFile);
      var localText = fs.readFileSync(localPath, "utf8");
      var verdict = _classifyContentCurrency(upstreamText, localText, special);
      return {
        key:        key,
        upstream:   special.url,
        bundledAt:  verdict.localVersion || verdict.localId,
        upstreamAt: verdict.upstreamVersion || verdict.upstreamId,
        basis:      verdict.basis,
        status:     verdict.stale ? "stale" : "current",
      };
    } catch (e) {
      return {
        key:    key,
        status: "registry-error",
        error:  (e && e.message) || String(e),
      };
    }
  }
  if (special && special.type === "npm-meta") {
    // Check each component independently. Aggregate results.
    var componentResults = [];
    for (var i = 0; i < special.components.length; i++) {
      var comp = special.components[i];
      var raw = _walkDots(manifestEntry, comp.manifestField);
      // The component field value may be a URL (current shape) or a
      // version string (operator-promoted shape). Either way we try to
      // pull a x.y.z out of it.
      var current = null;
      if (typeof raw === "string") {
        var m = raw.match(comp.versionRe || /(\d+\.\d+\.\d+)/);
        if (m) current = m[1];
      }
      // Also try the manifest's top-level "version" string for the
      // composite — peculiar-pki ships "2.0.0+pkijs-3.4.0".
      if (!current && typeof manifestEntry.version === "string") {
        var m2 = manifestEntry.version.match(comp.versionRe || /(\d+\.\d+\.\d+)/);
        if (m2) current = m2[1];
      }
      try {
        var latest = await _registryFetch(comp.npm);
        var cmp = _semverCompare(_semverParse(current), _semverParse(latest));
        componentResults.push({
          component: comp.npm,
          current:   current || "(unparseable)",
          latest:    latest,
          status:    cmp === 0 ? "current" : (cmp < 0 ? "stale" : "ahead"),
        });
      } catch (e) {
        componentResults.push({
          component: comp.npm,
          current:   current || "(unparseable)",
          status:    "registry-error",
          error:     (e && e.message) || String(e),
        });
      }
    }
    var anyStale = componentResults.some(function (r) { return r.status === "stale"; });
    var anyError = componentResults.some(function (r) { return r.status === "registry-error"; });
    return {
      key:      key,
      status:   anyStale ? "stale" : (anyError ? "registry-error" : "current"),
      components: componentResults,
    };
  }
  // Default: manifest key IS the npm package name.
  var npmName = (special && special.type === "npm" && special.name) || key;
  var npmCurrent = manifestEntry.version;
  try {
    var npmLatest = await _registryFetch(npmName);
    var npmCmp = _semverCompare(_semverParse(npmCurrent), _semverParse(npmLatest));
    return {
      key:     key,
      npm:     npmName,
      current: npmCurrent,
      latest:  npmLatest,
      status:  npmCmp === 0 ? "current" : (npmCmp < 0 ? "stale" : "ahead"),
    };
  } catch (e) {
    return {
      key:     key,
      npm:     npmName,
      current: npmCurrent,
      status:  "registry-error",
      error:   (e && e.message) || String(e),
    };
  }
}

async function main() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  var manifest = JSON.parse(raw);
  var pkgs = manifest.packages || {};
  var keys = Object.keys(pkgs);
  var results = [];
  // Sequential — npm registry is fine with serial polite traffic, and
  // the total package count is small (single digits). Parallel would
  // burn open sockets for no measurable gain.
  for (var i = 0; i < keys.length; i++) {
    results.push(await _checkOne(keys[i], pkgs[keys[i]]));
  }

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    process.stdout.write("[vendor-currency] " + keys.length + " vendored package(s) inspected:\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"      ? "OK"
                : r.status === "stale"        ? "STALE"
                : r.status === "ahead"        ? "AHEAD"
                : r.status === "registry-error" ? "ERR"
                : r.status === "skipped"      ? "skip"
                :                                r.status;
      var line = "  [" + label + "] " + r.key;
      if (r.current && r.latest) line += "  " + r.current + " -> " + r.latest;
      else if (r.current)        line += "  " + r.current;
      else if (r.bundledAt && r.upstreamAt) line += "  bundled " + r.bundledAt + " -> upstream " + r.upstreamAt;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (registry: " + r.error + ")";
      process.stdout.write(line + "\n");
      if (Array.isArray(r.components)) {
        for (var k = 0; k < r.components.length; k++) {
          var c = r.components[k];
          var clabel = c.status === "current" ? "OK"
                     : c.status === "stale"   ? "STALE"
                     : c.status === "ahead"   ? "AHEAD"
                     : c.status === "registry-error" ? "ERR"
                     :                          c.status;
          var cline = "    [" + clabel + "] " + c.component + "  " + (c.current || "?") + " -> " + (c.latest || "?");
          if (c.error) cline += "  (" + c.error + ")";
          process.stdout.write(cline + "\n");
        }
      }
    }
  }

  // Failure policy: any "stale" result fails the gate. registry-error
  // results are advisory unless BLAMEJS_VENDOR_CURRENCY_STRICT=1 is
  // set (which converts them into hard fails too). --warn flips the
  // whole exit policy to "always 0" — useful for opt-in advisory
  // runs locally.
  var stale = results.filter(function (r) {
    if (r.status === "stale") return true;
    if (Array.isArray(r.components)) {
      return r.components.some(function (c) { return c.status === "stale"; });
    }
    return false;
  });
  var errored = results.filter(function (r) { return r.status === "registry-error"; });

  if (WARN_ONLY) {
    if (stale.length || errored.length) process.stdout.write("[vendor-currency] --warn: " + stale.length + " stale, " + errored.length + " errored — exit 0 anyway\n");
    process.exit(0);
  }

  var strictErrors = process.env.BLAMEJS_VENDOR_CURRENCY_STRICT === "1";
  if (stale.length > 0 || (strictErrors && errored.length > 0)) {
    process.stdout.write("[vendor-currency] FAIL — " + stale.length + " stale, " + errored.length + " registry-error(s)\n");
    process.exit(1);
  }
  process.stdout.write("[vendor-currency] OK — every checked package matches the latest registry version\n");
  process.exit(0);
}

// Exported for hermetic unit tests (the content-currency classifier is
// pure — no network — and is the load-bearing logic for PSL drift).
module.exports = {
  _classifyContentCurrency: _classifyContentCurrency,
  _semverParse: _semverParse,
  _semverCompare: _semverCompare,
  SPECIAL_MAP: SPECIAL_MAP,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[vendor-currency] script crashed: " + (e && e.stack || e) + "\n");
    process.exit(2);
  });
}
