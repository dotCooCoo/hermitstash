// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backup.bundleAdapterStorage#bundleInfo + listBundles
 * format inference + v0.12.17 envelopeKind probe.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testBundleInfoTarGzRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-r-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-r-"));
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"id\":42}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bid = "2026-05-23T23-00-00-000Z-deadbeef";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: format inferred from storage layout", info.format === "tar.gz");
    check("bundleInfo: envelopeKind probed from payload magic",
      info.envelopeKind === "recipient");
    check("bundleInfo: sizeBytes carries payload length", info.sizeBytes > 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoTarPassphrase() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-p-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-p-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    var bid = "2026-05-23T23-15-00-000Z-cafef00d";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: tar format inferred", info.format === "tar");
    check("bundleInfo: passphrase envelope detected",
      info.envelopeKind === "passphrase");
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoPlaintext() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bi-src-n-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-n-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bid = "2026-05-23T23-30-00-000Z-ba5eba11";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: plaintext bundle yields envelopeKind \"none\"",
      info.envelopeKind === "none");
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoNotFound() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bi-dest-nf-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var refused = null;
    try {
      await storage.bundleInfo("2026-05-23T23-45-00-000Z-feedface");
    } catch (e) { refused = e; }
    check("bundleInfo: nonexistent bundle refused with bundle-not-found",
      refused && /bundle-not-found/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoLargeBundleUsesPartialRead() {
  // Codex P1 on v0.12.17 PR #168 — bundleInfo's envelope probe
  // claimed 5 bytes but read the full payload. With a 1 MiB
  // bundle + readPartial-capable adapter, the probe should consume
  // at most 16 bytes; verify by mocking an adapter whose readFile
  // throws "DO NOT CALL" but whose readPartial returns the magic.
  var calls = { readFile: 0, readPartial: 0 };
  var sealedHead = Buffer.concat([Buffer.from("BAWRP"), Buffer.alloc(11)]);   // 16 bytes
  var mockAdapter = {
    writeFile: async function () {},
    readFile:  async function () { calls.readFile += 1; throw new Error("readFile MUST NOT be called for the probe"); },
    listKeys:  async function () { return []; },
    deleteKey: async function () {},
    hasKey:    async function (key) { return /bundle\.tar\.gz$/.test(key); },
    readPartial: async function (key, length) {
      calls.readPartial += 1;
      return sealedHead.slice(0, length);
    },
    statKey:   async function () { return { size: 1024 * 1024, mtimeMs: 0 }; },
  };
  var storage = b.backup.bundleAdapterStorage({ adapter: mockAdapter });
  var info = await storage.bundleInfo("2026-05-23T23-00-00-000Z-bbbbbbbb");
  check("bundleInfo: probe routes through readPartial when adapter exposes it",
    calls.readPartial === 1 && calls.readFile === 0);
  check("bundleInfo: envelopeKind correctly identified from partial read",
    info.envelopeKind === "recipient");
  check("bundleInfo: sizeBytes from statKey", info.sizeBytes === 1024 * 1024);
}

async function testListBundlesTarGzWinsOverTar() {
  // Codex P2 on v0.12.17 PR #168 — when both bundle.tar and
  // bundle.tar.gz exist for the same bundleId (e.g. operator
  // migration in progress), listBundles must report tar.gz to
  // align with readBundle's precedence. Verify by injecting both
  // keys via a mock adapter.
  var mockAdapter = {
    writeFile: async function () {},
    readFile:  async function () { return Buffer.alloc(0); },
    listKeys:  async function () {
      // Return keys in tar-first order; tar.gz should still win.
      return [
        "2026-05-23T22-00-00-000Z-aabbccdd/bundle.tar",
        "2026-05-23T22-00-00-000Z-aabbccdd/bundle.tar.gz",
      ];
    },
    deleteKey: async function () {},
    hasKey:    async function () { return false; },
  };
  var storage = b.backup.bundleAdapterStorage({ adapter: mockAdapter });
  var list = await storage.listBundles();
  check("listBundles: tar.gz precedence applied when both formats exist",
    list.length === 1 && list[0].format === "tar.gz");
}

async function testListBundlesWithStats() {
  // v0.12.18 — listBundles({ withStats: true }) populates
  // createdAt + size from statKey when the adapter exposes it.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "lbws-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "lbws-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bid = "2026-05-24T00-00-00-000Z-99887766";
    await storage.writeBundle(bid, src);
    var noStats = await storage.listBundles();
    check("listBundles: default call leaves size + createdAt null",
      noStats[0].size === null && noStats[0].createdAt === null);
    var withStats = await storage.listBundles({ withStats: true });
    check("listBundles({ withStats: true }): size populated",
      typeof withStats[0].size === "number" && withStats[0].size > 0);
    check("listBundles({ withStats: true }): createdAt is ISO string",
      typeof withStats[0].createdAt === "string" &&
      /^\d{4}-\d{2}-\d{2}T/.test(withStats[0].createdAt));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoDirectoryCreatedAt() {
  // Codex P2 on v0.12.18 PR #169 — directory-format bundles MUST
  // populate createdAt from the manifest.json (parity with
  // listBundles({ withStats })). Previously the stat lookup was
  // gated inside `if (payloadKey !== null)` which skipped
  // directory bundles entirely.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bidir-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bidir-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    fs.writeFileSync(path.join(src, "manifest.json"), "{\"version\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "directory",
    });
    var bid = "2026-05-24T00-45-00-000Z-aaaa9999";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: directory-format bundle reports createdAt from manifest",
      typeof info.createdAt === "string" && /^\d{4}-\d{2}-\d{2}T/.test(info.createdAt));
    check("bundleInfo: directory-format bundle reports format \"directory\"",
      info.format === "directory");
    var list = await storage.listBundles({ withStats: true });
    check("listBundles+withStats vs bundleInfo: createdAt parity for directory format",
      list[0].createdAt === info.createdAt);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBundleInfoCreatedAt() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bica-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bica-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar",
    });
    var bid = "2026-05-24T00-30-00-000Z-aabbccdd";
    await storage.writeBundle(bid, src);
    var info = await storage.bundleInfo(bid);
    check("bundleInfo: createdAt is ISO string from statKey.mtimeMs",
      typeof info.createdAt === "string" && /^\d{4}-\d{2}-\d{2}T/.test(info.createdAt));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testListBundlesCarriesFormat() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "lb-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "lb-dest-"));
  try {
    fs.writeFileSync(path.join(src, "data.json"), "{\"v\":1}", { mode: 0o600 });
    var tarStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar",
    });
    await tarStorage.writeBundle("2026-05-23T23-50-00-000Z-a1b2c3d4", src);
    var tarGzStorage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    await tarGzStorage.writeBundle("2026-05-23T23-55-00-000Z-e5f6a7b8", src);
    var list = await tarStorage.listBundles();
    check("listBundles: returns 2 bundles", list.length === 2);
    var byFormat = {};
    for (var i = 0; i < list.length; i += 1) byFormat[list[i].format] = (byFormat[list[i].format] || 0) + 1;
    check("listBundles: format inferred per bundle (tar + tar.gz)",
      byFormat.tar === 1 && byFormat["tar.gz"] === 1);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testBundleInfoTarGzRecipient();
  await testBundleInfoTarPassphrase();
  await testBundleInfoPlaintext();
  await testBundleInfoNotFound();
  await testBundleInfoLargeBundleUsesPartialRead();
  await testListBundlesTarGzWinsOverTar();
  await testListBundlesCarriesFormat();
  await testListBundlesWithStats();
  await testBundleInfoCreatedAt();
  await testBundleInfoDirectoryCreatedAt();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-bundle-info] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
