"use strict";
/**
 * scripts/refresh-api-snapshot.js
 *
 * Captures the framework's public API surface and writes it to
 * api-snapshot.json at the repo root. The CI gate runs
 * b.apiSnapshot.compare(loaded, fresh) on every PR; breaking changes
 * (removed members or type changes) fail the build, additive changes
 * are logged for visibility.
 *
 * Run this script:
 *   - Locally before tagging a release that intentionally changes the
 *     surface (new primitive, renamed export, removed deprecated method).
 *   - After every release commit so the baseline tracks the published
 *     version.
 *
 * Usage:
 *   node scripts/refresh-api-snapshot.js
 */
var path = require("path");
var b = require("../index.js");
var pkg = require("../package.json");

var snapshot = b.apiSnapshot.capture(b, {
  frameworkVersion: pkg.version,
});

var outPath = path.join(__dirname, "..", "api-snapshot.json");
b.apiSnapshot.write(snapshot, outPath);
console.log("[refresh-api-snapshot] wrote " + outPath +
  " (frameworkVersion=" + snapshot.frameworkVersion + ")");
