// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backup.bundleAdapterStorage.objectStoreAdapter +
 * end-to-end round-trip via b.objectStore local backend +
 * combined with v0.12.10 recipient + v0.12.11 passphrase wrap.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _mkSrc(name, contents) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-src-"));
  fs.writeFileSync(path.join(dir, name), contents);
  return dir;
}

async function testObjectStoreAdapterRoundTrip() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-root-"));
  var src = _mkSrc("data.json", "{\"v\":1}");
  var verify = path.join(os.tmpdir(), "bjs-os-verify-" + Date.now());
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "test-prefix" }),
      format:  "tar.gz",
    });
    var bundleId = "2026-05-23T22-00-00-000Z-aaaa1111";
    await storage.writeBundle(bundleId, src);
    check("objectStoreAdapter: hasBundle true after write",
      await storage.hasBundle(bundleId));
    await storage.readBundle(bundleId, verify);
    check("objectStoreAdapter: bundle round-trips after fs-backed objectStore put + get",
      fs.readFileSync(path.join(verify, "data.json"), "utf-8") === "{\"v\":1}");
    var diskKey = path.join(rootDir, "test-prefix", bundleId, "bundle.tar.gz");
    check("objectStoreAdapter: prefix applied — key lands under operator-specified root",
      fs.existsSync(diskKey));
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(src,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testObjectStoreAdapterWithRecipient() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-root-r-"));
  var src = _mkSrc("phi.json", "{\"patient\":42}");
  var verify = path.join(os.tmpdir(), "bjs-os-verify-r-" + Date.now());
  try {
    var pair = b.crypto.generateEncryptionKeyPair();
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.objectStoreAdapter(client),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bundleId = "2026-05-23T22-15-00-000Z-aaaa2222";
    await storage.writeBundle(bundleId, src);
    var sealed = fs.readFileSync(path.join(rootDir, bundleId, "bundle.tar.gz"));
    check("objectStoreAdapter + recipient: bundle carries BAWRP envelope magic on disk",
      sealed.slice(0, 5).toString("ascii") === "BAWRP");
    await storage.readBundle(bundleId, verify);
    check("objectStoreAdapter + recipient: round-trips through unwrap + gunzip + untar",
      fs.readFileSync(path.join(verify, "phi.json"), "utf-8") === "{\"patient\":42}");
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(src,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testObjectStoreAdapterRefusesBadClient() {
  var refused = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter({});  // missing put/get/etc
  } catch (e) { refused = e; }
  check("objectStoreAdapter: missing methods refused upfront",
    refused && refused.code === "backup/bad-adapter" && /must expose a \w+\(\) method/.test(refused.message || ""));
  var refused2 = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter(null);
  } catch (e) { refused2 = e; }
  check("objectStoreAdapter: null client refused upfront",
    refused2 && refused2.code === "backup/bad-adapter" && /must be an object exposing/.test(refused2.message || ""));
}

async function testObjectStoreAdapterPagination() {
  // Codex P1 on v0.12.13 PR #164 — listKeys must follow
  // truncated / continuationToken pages. Mock a client that
  // returns 3 pages then exhausts.
  var pages = [
    { items: [{ key: "p/a" }, { key: "p/b" }], truncated: true, continuationToken: "tok1" },
    { items: [{ key: "p/c" }, { key: "p/d" }], truncated: true, continuationToken: "tok2" },
    { items: [{ key: "p/e" }],                  truncated: false, continuationToken: null  },
  ];
  var calls = [];
  var client = {
    put:    async function () { return { size: 0 }; },
    get:    async function () { return Buffer.alloc(0); },
    head:   async function () { return { size: 0 }; },
    delete: async function () { return true; },
    list:   async function (prefix, opts) {
      calls.push({ prefix: prefix, token: (opts && opts.continuationToken) || null });
      return pages.shift();
    },
  };
  var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "p" });
  var keys = await adapter.listKeys("");
  check("objectStoreAdapter.listKeys: walks all paginated pages",
    keys.length === 5 && keys.join(",") === "a,b,c,d,e");
  check("objectStoreAdapter.listKeys: forwarded continuationToken across calls",
    calls.length === 3 && calls[1].token === "tok1" && calls[2].token === "tok2");
}

async function testObjectStoreAdapterPaginationRunaway() {
  // A misbehaving backend that returns truncated:true forever
  // must trip the safety cap rather than spin.
  var client = {
    put:    async function () { return { size: 0 }; },
    get:    async function () { return Buffer.alloc(0); },
    head:   async function () { return { size: 0 }; },
    delete: async function () { return true; },
    list:   async function () {
      return { items: [{ key: "k" }], truncated: true, continuationToken: "ever" };
    },
  };
  var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client);
  var refused = null;
  try { await adapter.listKeys(""); } catch (e) { refused = e; }
  check("objectStoreAdapter.listKeys: runaway pagination refused with typed error",
    refused && /list-pagination-runaway/.test(refused.code || refused.message));
}

async function testObjectStoreAdapterPrefixTraversalRefused() {
  var client = b.objectStore.buildBackend({
    protocol: "local",
    rootDir:  fs.mkdtempSync(path.join(os.tmpdir(), "bjs-os-trav-")),
  });
  var refused = null;
  try {
    b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "../escape" });
  } catch (e) { refused = e; }
  check("objectStoreAdapter: prefix with traversal segment refused upfront",
    refused && /traversal/.test(refused.message || ""));
}

async function run() {
  await testObjectStoreAdapterRoundTrip();
  await testObjectStoreAdapterWithRecipient();
  await testObjectStoreAdapterRefusesBadClient();
  await testObjectStoreAdapterPagination();
  await testObjectStoreAdapterPaginationRunaway();
  await testObjectStoreAdapterPrefixTraversalRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-object-store-adapter] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
