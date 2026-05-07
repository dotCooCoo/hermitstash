"use strict";
/**
 * scripts/check-api-snapshot.js
 *
 * CI gate. Captures the current framework surface and compares it to
 * the committed api-snapshot.json baseline. Fails on breaking changes
 * (removed members, type changes); logs additive changes for visibility.
 *
 * Exit codes:
 *   0  — no breaking changes (additive changes printed but not failing)
 *   1  — breaking changes detected
 *   2  — script-level error (missing baseline, IO failure, etc.)
 *
 * Operators see this gate in the SECURITY.md checklist as a CI promise:
 * "removed methods or changed signatures fail the build before they
 * reach a published release."
 *
 * Usage:
 *   node scripts/check-api-snapshot.js
 */
var path = require("path");
var b = require("../index.js");
var pkg = require("../package.json");

try {
  var baselinePath = path.join(__dirname, "..", "api-snapshot.json");
  var baseline;
  try {
    baseline = b.apiSnapshot.read(baselinePath);
  } catch (e) {
    console.error("[check-api-snapshot] baseline missing or unreadable: " +
      ((e && e.message) || String(e)));
    console.error("[check-api-snapshot] generate one with `node scripts/refresh-api-snapshot.js` " +
      "and commit it.");
    process.exit(2);
  }

  var current = b.apiSnapshot.capture(b, {
    frameworkVersion: pkg.version,
  });
  var diff = b.apiSnapshot.compare(baseline, current);

  console.log(b.apiSnapshot.formatDiff(diff));

  if (diff.breaking.length > 0) {
    console.error("[check-api-snapshot] BREAKING changes detected. If intentional, " +
      "regenerate the baseline with `node scripts/refresh-api-snapshot.js` and commit it " +
      "alongside a major-version bump per the LTS calendar.");
    process.exit(1);
  }

  if (diff.additive.length > 0) {
    console.log("[check-api-snapshot] " + diff.additive.length +
      " additive change(s) — refresh the baseline at the next release " +
      "(`node scripts/refresh-api-snapshot.js`) so the new surfaces " +
      "are tracked.");
  }
  process.exit(0);
} catch (e) {
  console.error("[check-api-snapshot] error: " + ((e && e.stack) || e));
  process.exit(2);
}
