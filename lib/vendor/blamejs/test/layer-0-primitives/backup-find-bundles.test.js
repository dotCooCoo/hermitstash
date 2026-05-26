"use strict";
/**
 * Layer 0 — bundleAdapterStorage.findBundles predicate-based
 * filtering over listBundles.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function _mkStorageWithMixedBundles() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "fb-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "fb-dest-"));
  fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
  var tarStorage = b.backup.bundleAdapterStorage({
    adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    format:  "tar",
  });
  await tarStorage.writeBundle("2026-05-24T15-00-00-000Z-aabb1100", src);
  var tarGzStorage = b.backup.bundleAdapterStorage({
    adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    format:  "tar.gz",
  });
  await tarGzStorage.writeBundle("2026-05-24T15-15-00-000Z-aabb1101", src);
  await tarGzStorage.writeBundle("2026-05-24T15-30-00-000Z-aabb1102", src);
  return { storage: tarStorage, src: src, dest: dest };
}

async function testFindByFormat() {
  var ctx = await _mkStorageWithMixedBundles();
  try {
    var tarOnly = await ctx.storage.findBundles(function (entry) {
      return entry.format === "tar";
    });
    check("findBundles: format filter returns matching bundles only",
      tarOnly.length === 1 && tarOnly[0].format === "tar");
    var tarGzOnly = await ctx.storage.findBundles(function (entry) {
      return entry.format === "tar.gz";
    });
    check("findBundles: tar.gz filter returns both tar.gz bundles",
      tarGzOnly.length === 2);
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testFindWithStatsBySize() {
  var ctx = await _mkStorageWithMixedBundles();
  try {
    var withSize = await ctx.storage.findBundles(function (entry) {
      return entry.size > 0;
    }, { withStats: true });
    check("findBundles({ withStats }): size predicate matches all populated bundles",
      withSize.length === 3 && withSize.every(function (b) { return typeof b.size === "number"; }));
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testFindEmptyMatch() {
  var ctx = await _mkStorageWithMixedBundles();
  try {
    var nope = await ctx.storage.findBundles(function () { return false; });
    check("findBundles: predicate-false-always returns empty array",
      Array.isArray(nope) && nope.length === 0);
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testFindRefusesNonFunctionPredicate() {
  var ctx = await _mkStorageWithMixedBundles();
  try {
    var refused = null;
    try { await ctx.storage.findBundles("not-a-function"); } catch (e) { refused = e; }
    check("findBundles: non-function predicate refused with bad-arg",
      refused && /bad-arg/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(ctx.src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(ctx.dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testFindByFormat();
  await testFindWithStatsBySize();
  await testFindEmptyMatch();
  await testFindRefusesNonFunctionPredicate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-find-bundles] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
