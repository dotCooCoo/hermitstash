// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — bundleAdapterStorage.cloneBundle copies a bundle's
 * adapter payload to a new bundleId without touching the
 * envelope or inner archive.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testCloneTarGzPlaintext() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "cb-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "cb-dest-"));
  var verify = path.join(os.tmpdir(), "cb-v-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var srcId = "2026-05-24T11-00-00-000Z-aabbccdd";
    var dstId = "2026-05-24T11-15-00-000Z-11223344";
    await storage.writeBundle(srcId, src);
    var clone = await storage.cloneBundle(srcId, dstId);
    check("cloneBundle: returns srcBundleId + dstBundleId",
      clone.srcBundleId === srcId && clone.dstBundleId === dstId);
    check("cloneBundle: format propagated", clone.format === "tar.gz");
    check("cloneBundle: keysCopied + bytesCopied populated",
      clone.keysCopied === 1 && clone.bytesCopied > 0);
    await storage.readBundle(dstId, verify);
    check("cloneBundle: cloned bundle restores identically",
      fs.readFileSync(path.join(verify, "a.json"), "utf-8") === "{\"v\":1}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testCloneRefusesExistingDst() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "cb-ex-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "cb-ex-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var srcId = "2026-05-24T12-00-00-000Z-ee112233";
    var dstId = "2026-05-24T12-15-00-000Z-ee445566";
    await storage.writeBundle(srcId, src);
    await storage.cloneBundle(srcId, dstId);
    var refused = null;
    try { await storage.cloneBundle(srcId, dstId); } catch (e) { refused = e; }
    check("cloneBundle: existing dst refused without overwrite",
      refused && /clone-dst-exists/.test(refused.code || refused.message));
    // overwrite: true should succeed
    var second = await storage.cloneBundle(srcId, dstId, { overwrite: true });
    check("cloneBundle: opts.overwrite=true succeeds on existing dst",
      second.keysCopied === 1);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testCloneRefusesSameId() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "cb-same-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var refused = null;
    try {
      await storage.cloneBundle("2026-05-24T13-00-00-000Z-aaaaaaaa",
                                "2026-05-24T13-00-00-000Z-aaaaaaaa");
    } catch (e) { refused = e; }
    check("cloneBundle: src === dst refused with clone-same-id",
      refused && /clone-same-id/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testCloneOverwritePurgesStaleKeys() {
  // Codex P1 on v0.12.23 PR #174 — overwrite=true must purge
  // existing dst keys before writing the new ones. Otherwise a
  // dst=tar bundle overwritten by a src=directory clone keeps
  // both formats present + bundleInfo reads the stale tar.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "cb-ow-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "cb-ow-dest-"));
  try {
    fs.writeFileSync(path.join(src, "manifest.json"), "{\"v\":1}", { mode: 0o600 });
    fs.writeFileSync(path.join(src, "data"), "directory-bundle-payload", { mode: 0o600 });
    // Write a tar.gz bundle at dst first.
    var tarStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var dstId = "2026-05-24T14-00-00-000Z-bbaa9988";
    var srcSrc = fs.mkdtempSync(path.join(os.tmpdir(), "cb-ow-srcsrc-"));
    fs.writeFileSync(path.join(srcSrc, "x"), "y", { mode: 0o600 });
    await tarStorage.writeBundle(dstId, srcSrc);  // dst now has bundle.tar.gz
    // Write a directory bundle that will become the clone source.
    var dirStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "directory",
    });
    var srcId = "2026-05-24T14-15-00-000Z-ccbb7766";
    await dirStorage.writeBundle(srcId, src);
    // Clone src (directory) over dst (tar.gz) with overwrite=true.
    await dirStorage.cloneBundle(srcId, dstId, { overwrite: true });
    // Verify dst no longer has the stale bundle.tar.gz key —
    // bundleInfo should report directory format.
    var info = await dirStorage.bundleInfo(dstId);
    check("cloneBundle: overwrite=true purged stale tar.gz before writing new directory keys",
      info.format === "directory");
    // Also verify no bundle.tar.gz file lingers on disk.
    var staleTarGzExists = fs.existsSync(path.join(dest, dstId, "bundle.tar.gz"));
    check("cloneBundle: stale bundle.tar.gz key removed from storage",
      staleTarGzExists === false);
    try { fs.rmSync(srcSrc, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testClonePreservesEnvelope() {
  // Verify the clone preserves a recipient-wrapped bundle's
  // envelope bytes exactly — operators using cloneBundle for
  // pre-rotation snapshots get a verbatim payload copy.
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "cb-enc-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "cb-enc-dest-"));
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"id\":42}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var srcId = "2026-05-24T13-30-00-000Z-deadbeef";
    var dstId = "2026-05-24T13-45-00-000Z-cafef00d";
    await storage.writeBundle(srcId, src);
    await storage.cloneBundle(srcId, dstId);
    // Compare bytes directly — the clone should be byte-identical.
    var srcBytes = fs.readFileSync(path.join(dest, srcId, "bundle.tar.gz"));
    var dstBytes = fs.readFileSync(path.join(dest, dstId, "bundle.tar.gz"));
    check("cloneBundle: encrypted bundle bytes copied verbatim (envelope preserved)",
      srcBytes.equals(dstBytes));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testCloneTarGzPlaintext();
  await testCloneRefusesExistingDst();
  await testCloneRefusesSameId();
  await testCloneOverwritePurgesStaleKeys();
  await testClonePreservesEnvelope();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-clone-bundle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
