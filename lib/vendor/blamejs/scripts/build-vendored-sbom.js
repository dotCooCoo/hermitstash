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

var serialUuid = crypto.createHash("sha256")
  .update("blamejs-vendored-sbom:" + rootPkg.version)
  .digest("hex");
var serialNumber = "urn:uuid:" +
  serialUuid.slice(0,  8) + "-" +
  serialUuid.slice(8,  12) + "-" +
  serialUuid.slice(12, 16) + "-" +
  serialUuid.slice(16, 20) + "-" +
  serialUuid.slice(20, 32);

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

var components = Object.keys(manifest).filter(function (key) {
  // Skip MANIFEST.json's _comment and any other underscore-prefixed metadata
  if (key.charAt(0) === "_") return false;
  var entry = manifest[key];
  return entry && typeof entry === "object" && typeof entry.version === "string";
}).map(function (key) {
  var entry = manifest[key];
  var c = {
    "type":      "library",
    "bom-ref":   key + "@" + entry.version,
    "name":      key,
    "version":   entry.version,
    "purl":      _purlFor(entry, key),
    "scope":     "required",
  };
  if (entry.author)      c.author = entry.author;
  if (entry.description) c.description = entry.description;
  if (entry.license) {
    c.licenses = [{ license: { id: entry.license } }];
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
});

var doc = {
  "$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat":    "CycloneDX",
  "specVersion":  "1.6",
  "serialNumber": serialNumber,
  "version":      1,
  "metadata": {
    "timestamp": new Date().toISOString(),
    "lifecycles": [{ "phase": "build" }],
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
    },
  },
  "components":   components,
  "dependencies": [
    {
      "ref":       "@blamejs/core@" + rootPkg.version + "/vendored-bundle",
      "dependsOn": components.map(function (c) { return c["bom-ref"]; }),
    },
  ],
};

process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
