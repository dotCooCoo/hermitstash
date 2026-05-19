"use strict";
// Build a CycloneDX 1.6 SBOM covering lib/vendor/* bundles.
//
// Run via:
//   node scripts/build-vendored-sbom.js > sbom.vendored.cdx.json
//
// Wired into .github/workflows/npm-publish.yml. The primary SBOM
// (sbom.cdx.json) describes the npm package's (empty) runtime deps;
// this doc describes the actual code shipping inside the tarball.

var fs       = require("node:fs");
var path     = require("node:path");
var crypto   = require("node:crypto");

var manifestPath = path.resolve(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var manifest;
try {
  var raw = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  // MANIFEST.json shape: { _comment, packages: { key: entry, ... } }
  manifest = raw.packages || raw;
} catch (e) {
  process.stderr.write("[build-vendored-sbom] failed to read MANIFEST.json: " + e.message + "\n");
  process.exit(1);
}

var rootPkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8"));

// CycloneDX 1.6 §4.2 requires serialNumber to be a UUID
// uniquely identifying the BOM artifact. Deriving the UUID from the
// rootPkg.version made every rebuild of the SAME version produce the
// same serialNumber — BOM-diff tools (Dependency-Track, Snyk SBOM
// Monitor) couldn't distinguish rebuilds that should be independent
// artifacts (different timestamps, different lifecycles). Switch to
// crypto.randomUUID() per invocation; downstream consumers rely on
// serialNumber-per-build identity, not version-stable identity.
var serialNumber = "urn:uuid:" + crypto.randomUUID();

// CycloneDX 1.6 §4.4 (metadata.supplier) + SLSA v1.0
// provenance attestation require a `supplier` block on every BOM the
// build pipeline emits. `gh attestation verify` walks the chain and
// fails closed when the SBOM omits metadata.supplier. The supplier
// for blamejs framework artifacts is the framework maintainer
// publisher identity.
var FRAMEWORK_SUPPLIER = {
  "name": "blamejs",
  "url":  ["https://blamejs.com/"],
};

// CycloneDX 1.6 §4.4.2 — metadata.lifecycles[] entries
// MAY carry externalReferences pointing at the build pipeline that
// produced this BOM. Provenance walkers (Sigstore, SLSA verifiers)
// reach for these when correlating the BOM to its build run.
// GITHUB_SERVER_URL + GITHUB_REPOSITORY + GITHUB_RUN_ID are populated
// by Actions; absent locally the externalRef is omitted.
function _githubActionsRunUrl() {
  var server = process.env.GITHUB_SERVER_URL;                       // allow:raw-process-env — read by env-driven script
  var repo   = process.env.GITHUB_REPOSITORY;                       // allow:raw-process-env — read by env-driven script
  var runId  = process.env.GITHUB_RUN_ID;                           // allow:raw-process-env — read by env-driven script
  if (typeof server === "string" && server.length > 0 &&
      typeof repo === "string" && repo.length > 0 &&
      typeof runId === "string" && runId.length > 0) {
    return server + "/" + repo + "/actions/runs/" + runId;
  }
  return null;
}

// CycloneDX 1.6 §4.6 — license.id MUST be a valid SPDX
// license-list identifier. Non-SPDX prose ("BIMI Group / per-issuer")
// falls into license.name (the free-text fallback) so consumers
// parsing SBOM-as-SPDX don't reject the whole BOM on an unknown
// identifier. Keep the validator narrow — full SPDX list has
// hundreds of entries; we cover the common SPDX identifiers used by
// the framework's vendored deps, then anything else routes to
// license.name with `license_is_spdx: false` honoring the manifest's
// explicit override.
var SPDX_LICENSE_IDS = Object.freeze({
  "0BSD": 1, "Apache-2.0": 1, "BSD-2-Clause": 1, "BSD-3-Clause": 1,
  "CC0-1.0": 1, "CC-BY-3.0": 1, "CC-BY-4.0": 1, "CC-BY-SA-4.0": 1,
  "GPL-2.0-only": 1, "GPL-2.0-or-later": 1, "GPL-3.0-only": 1,
  "GPL-3.0-or-later": 1, "LGPL-2.1-only": 1, "LGPL-2.1-or-later": 1,
  "LGPL-3.0-only": 1, "LGPL-3.0-or-later": 1, "ISC": 1, "MIT": 1,
  "MIT-0": 1, "MPL-2.0": 1, "Unlicense": 1, "WTFPL": 1, "Zlib": 1,
});

function _licenseFor(entry) {
  if (typeof entry.license !== "string" || entry.license.length === 0) return null;
  // Operator-explicit non-SPDX flag takes precedence.
  if (entry.license_is_spdx === false) {
    return [{ license: { name: entry.license } }];
  }
  // SPDX identifier check — license-list match goes to `id`, free text
  // to `name`. Spec-conformant SBOM consumers reject license.id =
  // "BIMI Group / per-issuer" since it isn't on the SPDX list.
  if (SPDX_LICENSE_IDS[entry.license]) {
    return [{ license: { id: entry.license } }];
  }
  return [{ license: { name: entry.license } }];
}

function _purlFor(entry, key) {
  // Manifest key IS the npm package name for npm-mapped entries.
  if (/^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(key) && entry.source && /npm|github\.com\//.test(entry.source)) {
    // If source looks like a github repo, prefer pkg:github
    if (/^https?:\/\/github\.com\//.test(entry.source)) {
      var m = /^https?:\/\/github\.com\/([^/]+)\/([^/]+)/.exec(entry.source);
      if (m && !/^@/.test(key)) {
        // Use github purl when not a scoped npm package
        return "pkg:github/" + m[1] + "/" + m[2].replace(/\.git$/, "") +
               "@" + entry.version;
      }
    }
    return "pkg:npm/" + key.replace(/^@/, "%40").replace("/", "%2F") +
           "@" + entry.version;
  }
  return "pkg:generic/" + key + "@" + entry.version;
}

function _hashesFor(entry) {
  var rv = [];
  if (entry.sha256) {
    rv.push({ alg: "SHA-256", content: entry.sha256 });
    return rv;
  }
  // MANIFEST.json shape: hashes: { server: "sha256:<hex>", ... }
  if (entry.hashes && typeof entry.hashes === "object") {
    Object.keys(entry.hashes).forEach(function (slot) {
      var v = entry.hashes[slot];
      if (typeof v !== "string") return;
      var m = /^sha256:([a-f0-9]{64})$/i.exec(v);
      if (m) rv.push({ alg: "SHA-256", content: m[1] });
    });
  }
  return rv;
}

// CycloneDX 1.6 §4.7 — sub-component dependsOn graph.
// Entries shaped like `peculiar-pki` carry a `components` map of
// inner sub-bundles ({ "@peculiar/x509": <vcs-url>, "pkijs": <vcs-url> }).
// Emit each as its own SBOM component + register the parent's
// dependsOn so Dependency-Track / Snyk SBOM Monitor see the inner
// bundle structure (otherwise the peculiar-pki bundle appears as a
// monolithic component and its sub-vulnerabilities can't be CVE-mapped).
var _subDeps = [];   // [{ parentRef, childRef }, ...]

function _buildComponent(key, entry) {
  var c = {
    "type":      "library",
    "bom-ref":   key + "@" + entry.version,
    "name":      key,
    "version":   entry.version,
    "purl":      _purlFor(entry, key),
    "scope":     "required",
  };
  if (entry.author) {
    c.author = entry.author;
    // CycloneDX 1.6 §4.5.2 — per-component supplier
    // mirrors metadata.supplier. `gh attestation verify` walks each
    // component's supplier when reconciling provenance; an absent
    // per-component supplier falls back to metadata.supplier but
    // SLSA v1.0 prefers explicit attribution at the component level.
    c.supplier = { "name": entry.author };
  }
  if (entry.description) c.description = entry.description;
  var licenses = _licenseFor(entry);
  if (licenses) c.licenses = licenses;
  // CycloneDX 1.6 §4.5 — cpe field. CISA/NVD CVE-matching
  // pipelines rely on the CPE 2.3 identifier; absent it, ~30% of NVD
  // entries (CPE-only feed; no purl mirror) miss the match. MANIFEST
  // entries supply `cpe: "cpe:2.3:a:vendor:product:version:..."` per
  // CPE 2.3 Naming Specification (NIST IR 7695).
  if (typeof entry.cpe === "string" && entry.cpe.length > 0) {
    c.cpe = entry.cpe;
  }
  if (entry.source) {
    c.externalReferences = [{ type: "vcs", url: entry.source }];
  }
  var hashes = _hashesFor(entry);
  if (hashes.length > 0) c.hashes = hashes;
  if (entry.bundledAt) {
    c.properties = [{ name: "blamejs:bundledAt", value: entry.bundledAt }];
  }
  return c;
}

var components = [];
Object.keys(manifest).filter(function (key) {
  // Skip MANIFEST.json's _comment and any other underscore-prefixed metadata
  if (key.charAt(0) === "_") return false;
  var entry = manifest[key];
  return entry && typeof entry === "object" && typeof entry.version === "string";
}).forEach(function (key) {
  var entry = manifest[key];
  var parent = _buildComponent(key, entry);
  components.push(parent);

  // sub-component expansion. `entry.components` is a map keyed by
  // sub-component name. Each value is EITHER:
  //   - a bare string `"<vcs-url>"` (legacy form; sub inherits the
  //     parent's version), OR
  //   - an object `{ url, version }` where `version` is the actual
  //     upstream version of the sub-component (preferred form for
  //     meta-bundles whose parent version is a composite tag like
  //     `2.0.0+pkijs-3.4.0` — the parent version doesn't match
  //     ANY sub-component's real upstream version, so a CVE matcher
  //     keying off component version produces false negatives on
  //     the children unless we report each sub-component's real
  //     version here).
  // Each becomes a child component sharing the parent's license +
  // bundledAt context, with its own purl + externalReferences +
  // bom-ref so downstream CVE walkers see the inner structure.
  if (entry.components && typeof entry.components === "object" && !Array.isArray(entry.components)) {
    var subKeys = Object.keys(entry.components);
    for (var si = 0; si < subKeys.length; si++) {
      var subName  = subKeys[si];
      var subValue = entry.components[subName];
      var subUrl;
      var subVersion;
      if (typeof subValue === "string") {
        subUrl     = subValue;
        subVersion = entry.version;   // legacy form — inherit parent
      } else if (subValue && typeof subValue === "object" &&
                 typeof subValue.url === "string") {
        subUrl     = subValue.url;
        subVersion = typeof subValue.version === "string" && subValue.version.length > 0
                     ? subValue.version
                     : entry.version;
      } else {
        continue;
      }
      if (subUrl.length === 0) continue;
      // Sub-component inherits parent license + bundledAt; uses its
      // own version (when supplied) or falls back to parent.
      // bom-ref namespaced under the parent so two parents that bundle
      // the same sub-name don't collide.
      var subEntry = {
        version:    subVersion,
        license:    entry.license,
        license_is_spdx: entry.license_is_spdx,
        author:     entry.author,
        source:     subUrl,
        bundledAt:  entry.bundledAt,
      };
      var subKey = key + "/" + subName;
      var sub = _buildComponent(subKey, subEntry);
      components.push(sub);
      _subDeps.push({ parentRef: parent["bom-ref"], childRef: sub["bom-ref"] });
    }
  }
});

// CycloneDX 1.6 §4.4.2 — metadata.lifecycles[].externalReferences[]
// points at the GH Actions run URL when the build ran in CI. Provenance
// walkers (Sigstore, SLSA verifiers) reach for this when correlating
// the BOM to its build run. Locally-generated SBOMs omit (no run id).
var _buildLifecycle = { "phase": "build" };
var _runUrl = _githubActionsRunUrl();
if (_runUrl) {
  _buildLifecycle.externalReferences = [{ type: "build-meta", url: _runUrl }];
}

// assemble the dependency graph. Top-level entries depend
// on the framework's vendored-bundle; sub-components depend on their
// parent component. Result is a directed graph downstream tools walk
// to reach every inner sub-bundle CVE.
//
// Top-level refs are derived by exclusion: a component is top-level
// iff its bom-ref never appears as a child in _subDeps. The earlier
// substring-heuristic on "/" misclassified scoped packages like
// `@peculiar/x509` and any future sub-component naming scheme.
var _childRefs = Object.create(null);
for (var di = 0; di < _subDeps.length; di++) _childRefs[_subDeps[di].childRef] = true;
var _topLevelRefs = components
  .map(function (c) { return c["bom-ref"]; })
  .filter(function (ref) { return !_childRefs[ref]; });

var _dependencies = [
  {
    "ref":       "@blamejs/core@" + rootPkg.version + "/vendored-bundle",
    "dependsOn": _topLevelRefs,
  },
];
// Aggregate sub-deps per parent so each parent emits a single
// dependencies[] entry with its full child list.
var _byParent = Object.create(null);
for (var pi = 0; pi < _subDeps.length; pi++) {
  var pd = _subDeps[pi];
  if (!_byParent[pd.parentRef]) _byParent[pd.parentRef] = [];
  _byParent[pd.parentRef].push(pd.childRef);
}
var _parents = Object.keys(_byParent);
for (var pj = 0; pj < _parents.length; pj++) {
  _dependencies.push({ ref: _parents[pj], dependsOn: _byParent[_parents[pj]] });
}

var doc = {
  "$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat":    "CycloneDX",
  "specVersion":  "1.6",
  "serialNumber": serialNumber,
  "version":      1,
  "metadata": {
    "timestamp": new Date().toISOString(),
    "lifecycles": [_buildLifecycle],
    "supplier":  FRAMEWORK_SUPPLIER,
    "tools": [
      {
        "vendor":  "blamejs",
        "name":    "build-vendored-sbom.js",
        "version": rootPkg.version,
      },
    ],
    "component": {
      "bom-ref":     "@blamejs/core@" + rootPkg.version + "/vendored-bundle",
      "type":        "library",
      "name":        "blamejs-vendored-bundle",
      "version":     rootPkg.version,
      "description": "Vendored runtime deps bundled inside @blamejs/core (CommonJS rollups under lib/vendor/).",
      "supplier":    FRAMEWORK_SUPPLIER,
    },
  },
  "components":   components,
  "dependencies": _dependencies,
};

process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
