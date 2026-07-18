// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — lib/backup/index.js branch coverage.
 *
 * Targets input-validation / option-default / error-handling branches
 * not exercised by test/00-primitives.js (create/recommendedFiles/
 * run round-trip), backup-object-store-adapter, backup-find-bundles,
 * backup-worker, or backup-residency-posture:
 *
 *   - diskStorage direct: bad root, bad bundleId, bundle-exists,
 *     bundle-not-found, empty/filtered listBundles, delete/has no-op.
 *   - create(): residencyTag validation, schedule/scheduleTest
 *     wiring + arg validation, requireFlush hard-fail, HIPAA
 *     encrypt:false refusal.
 *   - verifyManifestSignature: bad-target / no-manifest / bad-manifest
 *     / parsed-object / on-disk string path.
 *   - bundleAdapterStorage: format / crypto-strategy / recipient /
 *     passphrase / entropy-floor / maxBundleBytes validation,
 *     bundle-too-large, opt-in posture gate, directory-format
 *     round-trip, bundleInfo / verifyBundle.
 *   - fsAdapter: traversal-key refusal, readPartial / statKey /
 *     hasKey / deleteKey.
 *   - migrate(): bad-from / bad-to / bad bundleId, directory->tar
 *     round-trip + idempotency.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

var VALID_ID  = "2026-04-27T14-00-00-123Z-a8f30b21";
var VALID_ID2 = "2026-04-27T14-30-00-456Z-b1c2d3e4";
var ABSENT_ID = "2026-04-27T09-00-00-000Z-ffffffff";
var ID_A = "2026-05-01T10-00-00-000Z-11111111";
var ID_B = "2026-05-01T10-05-00-000Z-22222222";
var ID_C = "2026-05-01T10-10-00-000Z-33333333";

// A strong passphrase that clears the default 80-bit entropy floor for
// the wrapWithPassphrase consumer path (matches the sibling backup
// crypto tests).
var STRONG_PP = "aLongCorrectHorseBatteryStaple9876!Phrase";

// A minimal in-memory adapter implementing ONLY the five required
// contract methods (no readPartial / statKey). Drives the "legacy
// adapter" branches: bundleInfo -> envelopeKind "unknown", listBundles
// with no per-bundle stat, etc. This is a legitimate custom-adapter
// consumer path, not a mock of a helper-provided fixture.
function _memAdapter() {
  var store = new Map();
  return {
    async writeFile(key, bytes) { store.set(key, Buffer.from(bytes)); },
    async readFile(key) {
      if (!store.has(key)) {
        var e = new b.backup.BackupError("backup/no-key", "mem: no key " + key);
        throw e;
      }
      return Buffer.from(store.get(key));
    },
    async listKeys(prefix) {
      var out = [];
      store.forEach(function (_v, k) {
        if (!prefix || k.indexOf(prefix) === 0) out.push(k);
      });
      return out;
    },
    async deleteKey(key) { store.delete(key); },
    async hasKey(key) { return store.has(key); },
  };
}

function _tmp(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bidx-" + tag + "-"));
}
function _rm(p) {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
}
function _mkSrcDir(files) {
  var dir = _tmp("src");
  Object.keys(files).forEach(function (rel) {
    var full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, files[rel]);
  });
  return dir;
}
function _errOf(e) { return (e && (e.code || e.message)) || String(e); }

// ---- diskStorage ----

function testDiskStorageValidatesRoot() {
  var threw = null;
  try { b.backup.diskStorage({}); } catch (e) { threw = e; }
  check("diskStorage: missing root refused with no-storage-root",
    threw && threw.code === "backup/no-storage-root");
  var threw2 = null;
  try { b.backup.diskStorage({ root: "" }); } catch (e) { threw2 = e; }
  check("diskStorage: empty root refused",
    threw2 && threw2.code === "backup/no-storage-root");
}

async function testDiskStorageBadBundleId() {
  var root = _tmp("ds-badid");
  try {
    var ds = b.backup.diskStorage({ root: root });
    var src = _mkSrcDir({ "manifest.json": "{}" });
    try {
      var threw = null;
      try { await ds.writeBundle("not-a-valid-id", src); } catch (e) { threw = e; }
      check("diskStorage.writeBundle: bad bundleId refused",
        threw && threw.code === "backup/bad-bundle-id");
    } finally { _rm(src); }
  } finally { _rm(root); }
}

async function testDiskStorageBundleExistsAndNotFound() {
  var root = _tmp("ds-exists");
  var src = _mkSrcDir({ "manifest.json": "{\"v\":1}", "files/a.enc": "AAA" });
  try {
    var ds = b.backup.diskStorage({ root: root });
    await ds.writeBundle(VALID_ID, src);
    check("diskStorage.hasBundle: true after write", await ds.hasBundle(VALID_ID));

    var threw = null;
    try { await ds.writeBundle(VALID_ID, src); } catch (e) { threw = e; }
    check("diskStorage.writeBundle: duplicate id refused with bundle-exists",
      threw && threw.code === "backup/bundle-exists");

    var threw2 = null;
    try { await ds.readBundle(ABSENT_ID, path.join(root, "out")); } catch (e) { threw2 = e; }
    check("diskStorage.readBundle: absent bundle refused with bundle-not-found",
      threw2 && threw2.code === "backup/bundle-not-found");
  } finally { _rm(root); _rm(src); }
}

async function testDiskStorageListFiltersAndEmpty() {
  // listBundles on a non-existent root returns [].
  var missing = path.join(os.tmpdir(), "bidx-missing-" + Date.now());
  var dsMissing = b.backup.diskStorage({ root: missing });
  var empty = await dsMissing.listBundles();
  check("diskStorage.listBundles: non-existent root returns []",
    Array.isArray(empty) && empty.length === 0);

  // listBundles skips non-bundle-id directories + stray files.
  var root = _tmp("ds-list");
  var src = _mkSrcDir({ "manifest.json": "{}", "files/a.enc": "A" });
  try {
    var ds = b.backup.diskStorage({ root: root });
    await ds.writeBundle(VALID_ID, src);
    fs.mkdirSync(path.join(root, "not-a-bundle-dir"));
    fs.writeFileSync(path.join(root, "loose-file.txt"), "junk");
    var listed = await ds.listBundles();
    check("diskStorage.listBundles: only the valid bundle id is returned",
      listed.length === 1 && listed[0].bundleId === VALID_ID);
    check("diskStorage.listBundles: entry carries size + createdAt",
      typeof listed[0].size === "number" && typeof listed[0].createdAt === "string");
  } finally { _rm(root); _rm(src); }
}

async function testDiskStorageDeleteAndHasNoop() {
  var root = _tmp("ds-del");
  try {
    var ds = b.backup.diskStorage({ root: root });
    // deleteBundle on an absent-but-valid id is a silent no-op.
    var threw = null;
    try { await ds.deleteBundle(ABSENT_ID); } catch (e) { threw = e; }
    check("diskStorage.deleteBundle: absent id is a no-op (no throw)", threw === null);
    check("diskStorage.hasBundle: false for absent id", (await ds.hasBundle(ABSENT_ID)) === false);
    // hasBundle on a malformed id refuses via _bundlePath.
    var threw2 = null;
    try { await ds.hasBundle("bad id"); } catch (e) { threw2 = e; }
    check("diskStorage.hasBundle: malformed id returns false (swallowed)", threw2 === null);
  } finally { _rm(root); }
}

// ---- create(): validation + wiring branches ----

function _createOpts(dataDir, root, extra) {
  fs.writeFileSync(path.join(dataDir, "db.enc"), Buffer.from([1, 2, 3]));
  var opts = {
    dataDir:      dataDir,
    storage:      b.backup.diskStorage({ root: root }),
    passphrase:   Buffer.from("operator-backup-passphrase"),
    files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
    vaultKeyJson: '{"v":1}',
    audit:        false,
  };
  if (extra) Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; });
  return opts;
}

function testCreateResidencyTagValidation() {
  var data = _tmp("res-data");
  var root = _tmp("res-root");
  try {
    var threw = null;
    try { b.backup.create(_createOpts(data, root, { residencyTag: 123 })); } catch (e) { threw = e; }
    check("create: non-string residencyTag refused with bad-residency-tag",
      threw && threw.code === "backup/bad-residency-tag");

    var threw2 = null;
    try { b.backup.create(_createOpts(data, root, { residencyTag: "" })); } catch (e) { threw2 = e; }
    check("create: empty residencyTag refused",
      threw2 && threw2.code === "backup/bad-residency-tag");

    // null residencyTag is accepted (means "undeclared").
    var eng = b.backup.create(_createOpts(data, root, { residencyTag: null }));
    check("create: null residencyTag accepted", eng && typeof eng.run === "function");
  } finally { _rm(data); _rm(root); }
}

function testCreateScheduleRequiresScheduler() {
  var data = _tmp("sch-data");
  var root = _tmp("sch-root");
  try {
    var eng = b.backup.create(_createOpts(data, root));
    var threw = null;
    try { eng.schedule({ cron: "0 3 * * *" }); } catch (e) { threw = e; }
    check("create: schedule() without a scheduler refused with no-scheduler",
      threw && threw.code === "backup/no-scheduler");
    var threw2 = null;
    try { eng.scheduleTest({ cron: "0 3 * * *", restoreTo: "/x", verify: function () {} }); } catch (e) { threw2 = e; }
    check("create: scheduleTest() without a scheduler refused with no-scheduler",
      threw2 && threw2.code === "backup/no-scheduler");
  } finally { _rm(data); _rm(root); }
}

function testCreateScheduleArgValidation() {
  var data = _tmp("scha-data");
  var root = _tmp("scha-root");
  try {
    var scheduled = [];
    var fakeScheduler = {
      create: function () {
        return { schedule: function (spec) { scheduled.push(spec); } };
      },
    };
    var eng = b.backup.create(_createOpts(data, root, { scheduler: fakeScheduler }));

    var threw = null;
    try { eng.schedule({}); } catch (e) { threw = e; }
    check("create: schedule() without cron refused with bad-schedule",
      threw && threw.code === "backup/bad-schedule");

    var handle = eng.schedule({ cron: "0 3 * * *", name: "nightly" });
    check("create: schedule() returns { name, instance }",
      handle && handle.name === "nightly" && handle.instance);
    check("create: schedule() registered a job on the scheduler instance",
      scheduled.length === 1 && scheduled[0].cron === "0 3 * * *" &&
      typeof scheduled[0].run === "function");

    var t1 = null;
    try { eng.scheduleTest({}); } catch (e) { t1 = e; }
    check("create: scheduleTest() without cron refused",
      t1 && t1.code === "backup/bad-test-schedule");
    var t2 = null;
    try { eng.scheduleTest({ cron: "0 3 * * *" }); } catch (e) { t2 = e; }
    check("create: scheduleTest() without restoreTo refused",
      t2 && t2.code === "backup/bad-test-restore-to");
    var t3 = null;
    try { eng.scheduleTest({ cron: "0 3 * * *", restoreTo: "/x" }); } catch (e) { t3 = e; }
    check("create: scheduleTest() without verify fn refused",
      t3 && t3.code === "backup/bad-test-verify");

    var testHandle = eng.scheduleTest({ cron: "0 3 * * *", restoreTo: "/x", verify: function () {} });
    check("create: scheduleTest() returns a handle with default name",
      testHandle && testHandle.name === "blamejs.backup.test");
  } finally { _rm(data); _rm(root); }
}

async function testCreateRequireFlushHardFails() {
  var data = _tmp("rf-data");
  var root = _tmp("rf-root");
  try {
    var eng = b.backup.create(_createOpts(data, root, {
      requireFlush:      true,
      flushBeforeBackup: function () { throw new Error("flush-broke"); },
    }));
    var threw = null;
    try { await eng.run(); } catch (e) { threw = e; }
    check("create: requireFlush + failing flush aborts run with flush-required-failed",
      threw && threw.code === "backup/flush-required-failed");
    // No bundle should have landed in storage.
    var listed = await eng.list();
    check("create: aborted flush leaves no bundle in storage", listed.length === 0);
  } finally { _rm(data); _rm(root); }
}

function testCreateHipaaRefusesUnencrypted() {
  var data = _tmp("hip-data");
  var root = _tmp("hip-root");
  b.compliance.clear();
  b.compliance.set("hipaa");
  try {
    var threw = null;
    try { b.backup.create(_createOpts(data, root, { encrypt: false })); } catch (e) { threw = e; }
    check("create: HIPAA posture + encrypt:false refused with encryption-required",
      threw && threw.code === "backup/encryption-required");
    // Default (encrypt on) still constructs under HIPAA.
    var eng = b.backup.create(_createOpts(data, root));
    check("create: HIPAA posture + default encryption constructs",
      eng && typeof eng.run === "function");
  } finally {
    b.compliance.clear();
    _rm(data); _rm(root);
  }
}

// ---- verifyManifestSignature ----

function testVerifyManifestSignatureBadTarget() {
  var t1 = null;
  try { b.backup.verifyManifestSignature(12345); } catch (e) { t1 = e; }
  check("verifyManifestSignature: numeric target refused with bad-target",
    t1 && t1.code === "backup/bad-target");
  var t2 = null;
  try { b.backup.verifyManifestSignature(null); } catch (e) { t2 = e; }
  check("verifyManifestSignature: null target refused with bad-target",
    t2 && t2.code === "backup/bad-target");
}

function testVerifyManifestSignatureNoManifest() {
  var dir = _tmp("vms-none");
  try {
    var threw = null;
    try { b.backup.verifyManifestSignature(dir); } catch (e) { threw = e; }
    check("verifyManifestSignature: missing manifest.json refused with no-manifest",
      threw && threw.code === "backup/no-manifest");
  } finally { _rm(dir); }
}

function testVerifyManifestSignatureBadManifest() {
  var dir = _tmp("vms-bad");
  try {
    fs.writeFileSync(path.join(dir, "manifest.json"), "{ this is not valid json ");
    var threw = null;
    try { b.backup.verifyManifestSignature(dir); } catch (e) { threw = e; }
    check("verifyManifestSignature: unparseable manifest refused with bad-manifest",
      threw && threw.code === "backup/bad-manifest");
  } finally { _rm(dir); }
}

function testVerifyManifestSignatureParsedObject() {
  // A parsed manifest object (version number) with no signature block is
  // NOT a throw — it returns a verdict the caller branches on.
  var verdict = b.backup.verifyManifestSignature({ version: 1 });
  check("verifyManifestSignature: unsigned parsed manifest returns ok:false verdict",
    verdict && verdict.ok === false && typeof verdict.reason === "string");
  // { manifest } wrapper form takes the same path.
  var verdict2 = b.backup.verifyManifestSignature({ manifest: { version: 1 } });
  check("verifyManifestSignature: { manifest } wrapper returns a verdict",
    verdict2 && verdict2.ok === false);
}

async function testVerifyManifestSignatureOnDiskStringPath() {
  // Drive the on-disk string-path reader end-to-end through a real
  // create()/read() bundle (the branch is otherwise integration-only).
  var data = _tmp("vms-disk-data");
  var root = _tmp("vms-disk-root");
  var pull = path.join(os.tmpdir(), "bidx-vms-pull-" + Date.now());
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("ENC"));
    var eng = b.backup.create({
      dataDir:      data,
      storage:      b.backup.diskStorage({ root: root }),
      passphrase:   Buffer.from("pp"),
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}',
      audit:        false,
    });
    var r = await eng.run();
    await eng.read(r.bundleId, pull);
    var verdict = b.backup.verifyManifestSignature(pull);
    check("verifyManifestSignature: on-disk manifest parses + returns a verdict object",
      verdict && typeof verdict.ok === "boolean");
    // Pinning a fingerprint the manifest can't satisfy returns ok:false,
    // not a throw.
    var pinned = b.backup.verifyManifestSignature(pull, {
      expectedFingerprint: "de".repeat(64),
    });
    check("verifyManifestSignature: unmatchable pinned fingerprint returns ok:false",
      pinned && pinned.ok === false);
  } finally { _rm(data); _rm(root); _rm(pull); }
}

// ---- bundleAdapterStorage: construction validation ----

function _fsAdapter(tag) {
  return b.backup.bundleAdapterStorage.fsAdapter({ root: _tmp(tag) });
}

function testAdapterStorageConstructionValidation() {
  var t;

  t = null;
  try { b.backup.bundleAdapterStorage({ adapter: {} }); } catch (e) { t = e; }
  check("bundleAdapterStorage: adapter missing methods refused with bad-adapter",
    t && t.code === "backup/bad-adapter");

  t = null;
  try { b.backup.bundleAdapterStorage({ adapter: _fsAdapter("f1"), format: "zip" }); } catch (e) { t = e; }
  check("bundleAdapterStorage: unknown format refused with bad-format",
    t && t.code === "backup/bad-format");

  t = null;
  try { b.backup.bundleAdapterStorage({ adapter: _fsAdapter("f2"), cryptoStrategy: "rot13" }); } catch (e) { t = e; }
  check("bundleAdapterStorage: unknown cryptoStrategy refused with bad-crypto-strategy",
    t && t.code === "backup/bad-crypto-strategy");

  t = null;
  try { b.backup.bundleAdapterStorage({ adapter: _fsAdapter("f3"), cryptoStrategy: "recipient" }); } catch (e) { t = e; }
  check("bundleAdapterStorage: recipient strategy without recipient refused with no-recipient",
    t && t.code === "backup/no-recipient");

  t = null;
  try { b.backup.bundleAdapterStorage({ adapter: _fsAdapter("f4"), cryptoStrategy: "passphrase" }); } catch (e) { t = e; }
  check("bundleAdapterStorage: passphrase strategy without passphrase refused with no-passphrase",
    t && t.code === "backup/no-passphrase");

  t = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter: _fsAdapter("f5"), cryptoStrategy: "recipient", recipient: {}, format: "directory",
    });
  } catch (e) { t = e; }
  check("bundleAdapterStorage: recipient + directory format refused (envelope needs bundled format)",
    t && t.code === "backup/recipient-strategy-needs-bundled-format");
}

function testAdapterStorageEntropyFloorValidation() {
  // NaN / Infinity / negative passphraseMinEntropyBits must be refused
  // upfront so the HIPAA/PCI-DSS 128-bit floor can't be NaN'd out.
  ["nan", "inf", "neg"].forEach(function (kind) {
    var val = kind === "nan" ? NaN : kind === "inf" ? Infinity : -10;
    var t = null;
    try {
      b.backup.bundleAdapterStorage({
        adapter: _fsAdapter("ent-" + kind),
        cryptoStrategy: "passphrase",
        passphrase: "x",
        passphraseMinEntropyBits: val,
      });
    } catch (e) { t = e; }
    check("bundleAdapterStorage: passphraseMinEntropyBits=" + kind + " refused with bad-arg",
      t && t.code === "backup/bad-arg");
  });
}

function testAdapterStorageMaxBundleBytesValidation() {
  ["nan", "neg", "zero"].forEach(function (kind) {
    var val = kind === "nan" ? NaN : kind === "neg" ? -1 : 0;
    var t = null;
    try {
      b.backup.bundleAdapterStorage({ adapter: _fsAdapter("mbb-" + kind), maxBundleBytes: val });
    } catch (e) { t = e; }
    check("bundleAdapterStorage: maxBundleBytes=" + kind + " refused with bad-arg",
      t && t.code === "backup/bad-arg");
  });
}

function testAdapterStoragePostureGateOptIn() {
  // The posture gate is opt-in via opts.posture (see the reported
  // asymmetry with create(), which reads the ambient posture). When
  // opts.posture names a regulated posture, cryptoStrategy:"none" is
  // refused.
  var t = null;
  try {
    b.backup.bundleAdapterStorage({ adapter: _fsAdapter("pg"), posture: "hipaa", cryptoStrategy: "none" });
  } catch (e) { t = e; }
  check("bundleAdapterStorage: opts.posture=hipaa + cryptoStrategy none refused",
    t && t.code === "backup/posture-requires-encryption");
}

async function testAdapterStorageBundleTooLarge() {
  var root = _tmp("tl-root");
  var src = _mkSrcDir({ "big.bin": Buffer.alloc(2048) });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "tar",
      maxBundleBytes: 512,
    });
    var threw = null;
    try { await storage.writeBundle(VALID_ID, src); } catch (e) { threw = e; }
    check("bundleAdapterStorage.writeBundle: oversize source refused with bundle-too-large",
      threw && threw.code === "backup/bundle-too-large");
  } finally { _rm(root); _rm(src); }
}

async function testAdapterStoragePassphraseFloorEnforcedOnWrite() {
  // An explicit high entropy floor makes a weak passphrase fail at
  // write time (drives the real wrapWithPassphrase consumer path).
  var root = _tmp("pf-root");
  var src = _mkSrcDir({ "a.txt": "data" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "tar",
      cryptoStrategy: "passphrase",
      passphrase: "ab",
      passphraseMinEntropyBits: 256,
    });
    var threw = null;
    try { await storage.writeBundle(VALID_ID, src); } catch (e) { threw = e; }
    check("bundleAdapterStorage: weak passphrase below entropy floor refused on write",
      threw && /weak-passphrase|entropy/i.test(_errOf(threw)));
  } finally { _rm(root); _rm(src); }
}

// ---- bundleAdapterStorage: directory-format round-trip ----

async function testAdapterStorageDirectoryRoundTrip() {
  var root = _tmp("dir-root");
  var src = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/a.enc": "AAA" });
  var dest = path.join(os.tmpdir(), "bidx-dir-dest-" + Date.now());
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "directory",
    });
    await storage.writeBundle(VALID_ID, src);
    check("adapter/directory: hasBundle true after write", await storage.hasBundle(VALID_ID));

    var info = await storage.bundleInfo(VALID_ID);
    check("adapter/directory: bundleInfo reports directory format + no envelope",
      info.format === "directory" && info.envelopeKind === "none");

    var listed = await storage.listBundles();
    check("adapter/directory: listBundles reports the bundle with directory format",
      listed.length === 1 && listed[0].bundleId === VALID_ID && listed[0].format === "directory");

    var vb = await storage.verifyBundle(VALID_ID);
    check("adapter/directory: verifyBundle ok:true (manifest presence is the check)",
      vb.ok === true && vb.format === "directory" && vb.entryCount === null);

    await storage.readBundle(VALID_ID, dest);
    check("adapter/directory: readBundle recovers the file bytes",
      fs.readFileSync(path.join(dest, "files", "a.enc"), "utf8") === "AAA");

    var dupe = null;
    try { await storage.writeBundle(VALID_ID, src); } catch (e) { dupe = e; }
    check("adapter/directory: duplicate write refused with bundle-exists",
      dupe && dupe.code === "backup/bundle-exists");

    var de = null;
    try { await storage.readBundle(VALID_ID, dest); } catch (e) { de = e; }
    check("adapter/directory: readBundle into existing dest refused with dest-exists",
      de && de.code === "backup/dest-exists");

    await storage.deleteBundle(VALID_ID);
    check("adapter/directory: hasBundle false after delete",
      (await storage.hasBundle(VALID_ID)) === false);
  } finally { _rm(root); _rm(src); _rm(dest); }
}

async function testAdapterStorageTarVerifyAndMissing() {
  var root = _tmp("tar-root");
  var src = _mkSrcDir({ "x.txt": "hello", "y.txt": "world" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "tar",
    });
    await storage.writeBundle(VALID_ID, src);
    var vb = await storage.verifyBundle(VALID_ID);
    check("adapter/tar: verifyBundle walks tar entries + counts them",
      vb.ok === true && vb.format === "tar" && vb.entryCount === 2);

    var nf = null;
    try { await storage.bundleInfo(ABSENT_ID); } catch (e) { nf = e; }
    check("adapter/tar: bundleInfo on absent bundle refused with bundle-not-found",
      nf && nf.code === "backup/bundle-not-found");

    var ns = null;
    try { await storage.writeBundle(VALID_ID2, path.join(os.tmpdir(), "no-such-src-" + Date.now())); } catch (e) { ns = e; }
    check("adapter/tar: writeBundle with missing sourceDir refused with no-source",
      ns && ns.code === "backup/no-source");
  } finally { _rm(root); _rm(src); }
}

// ---- fsAdapter capabilities ----

async function testFsAdapterTraversalRefused() {
  var root = _tmp("fsad-trav");
  try {
    var adapter = b.backup.bundleAdapterStorage.fsAdapter({ root: root });
    var t = null;
    try { await adapter.writeFile("../escape", Buffer.from("x")); } catch (e) { t = e; }
    check("fsAdapter.writeFile: traversal key refused with bad-key",
      t && t.code === "backup/bad-key");

    // A '..'-only pre-screen missed the absolute / drive-letter / NTFS-stream
    // class the key resolves through under root. Each must be refused so a key
    // built from untrusted input can't escape root or write a file's data
    // stream. Sibling of the manifest.validate / bundle.create path checks.
    var badKeys = {
      "absolute key":     "/etc/shadow",
      "drive-letter key": "C:" + "\\" + "Windows" + "\\" + "evil",
      "NTFS-ADS key":     "blob.enc:evil",
      // Cross-platform: a backslash-traversal key is a harmless literal filename
      // under POSIX path semantics but climbs out of root when the portable
      // store is later read on Windows, so it is gated under win32 semantics on
      // every host. A host-only resolve would accept these on POSIX.
      "backslash-parent key":    ".." + "\\" + "evil",
      "backslash-traversal key": "a" + "\\" + ".." + "\\" + ".." + "\\" + "evil",
    };
    for (var label in badKeys) {
      if (!Object.prototype.hasOwnProperty.call(badKeys, label)) continue;
      var te = null;
      try { await adapter.writeFile(badKeys[label], Buffer.from("x")); } catch (e) { te = e; }
      check("fsAdapter.writeFile: " + label + " refused with bad-key",
        te && te.code === "backup/bad-key");
    }
  } finally { _rm(root); }
}

async function testFsAdapterReadPartialAndStat() {
  var root = _tmp("fsad-rp");
  try {
    var adapter = b.backup.bundleAdapterStorage.fsAdapter({ root: root });
    await adapter.writeFile("k1", Buffer.from("hello-world"));
    var head = await adapter.readPartial("k1", 5);
    check("fsAdapter.readPartial: returns only the requested leading bytes",
      Buffer.isBuffer(head) && head.toString() === "hello");

    var st = await adapter.statKey("k1");
    check("fsAdapter.statKey: reports size + mtimeMs for an existing key",
      st && st.size === 11 && typeof st.mtimeMs === "number");
    check("fsAdapter.statKey: null for a missing key", (await adapter.statKey("nope")) === null);
    check("fsAdapter.hasKey: true for existing / false for missing",
      (await adapter.hasKey("k1")) === true && (await adapter.hasKey("nope")) === false);

    var t = null;
    try { await adapter.readPartial("nope", 4); } catch (e) { t = e; }
    check("fsAdapter.readPartial: missing key refused with no-key",
      t && t.code === "backup/no-key");

    var delThrew = null;
    try { await adapter.deleteKey("nope"); } catch (e) { delThrew = e; }
    check("fsAdapter.deleteKey: absent key is a silent no-op", delThrew === null);
  } finally { _rm(root); }
}

// ---- migrate ----

async function testMigrateValidation() {
  var t1 = null;
  try { await b.backup.migrate({ from: {}, to: {} }); } catch (e) { t1 = e; }
  check("migrate: bad from backend refused with bad-from",
    t1 && t1.code === "backup/bad-from");

  var t2 = null;
  try {
    await b.backup.migrate({
      from: { readBundle: function () {}, listBundles: function () {} },
      to:   {},
    });
  } catch (e) { t2 = e; }
  check("migrate: bad to backend refused with bad-to",
    t2 && t2.code === "backup/bad-to");

  var t3 = null;
  try {
    await b.backup.migrate({
      from: { readBundle: function () {}, listBundles: function () {} },
      to:   { writeBundle: function () {}, hasBundle: function () {} },
      bundleId: "not-valid",
    });
  } catch (e) { t3 = e; }
  check("migrate: malformed bundleId refused with bad-bundle-id",
    t3 && t3.code === "backup/bad-bundle-id");
}

async function testMigrateDirectoryToTarRoundTrip() {
  var fromRoot = _tmp("mig-from");
  var toRoot = _tmp("mig-to");
  var src = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/d.enc": "DDD" });
  try {
    var from = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: fromRoot }),
      format:  "directory",
    });
    var to = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: toRoot }),
      format:  "tar",
    });
    await from.writeBundle(VALID_ID, src);

    var result = await b.backup.migrate({ from: from, to: to });
    check("migrate: directory->tar migrates the bundle",
      result.migrated === 1 && result.skipped === 0 && result.total === 1);
    check("migrate: destination now holds the bundle", await to.hasBundle(VALID_ID));
    var toInfo = await to.bundleInfo(VALID_ID);
    check("migrate: destination bundle is tar format", toInfo.format === "tar");

    // Re-running is idempotent: destination already has it → skipped.
    var again = await b.backup.migrate({ from: from, to: to });
    check("migrate: re-run is idempotent (skipped, not re-migrated)",
      again.migrated === 0 && again.skipped === 1);
  } finally { _rm(fromRoot); _rm(toRoot); _rm(src); }
}

// ---- recommendedFiles ----

function testRecommendedFiles() {
  // Default (encrypted + wrapped): db.enc + db.key.enc + vault.key.sealed
  // + audit-sign key sealed.
  var def = b.backup.recommendedFiles();
  check("recommendedFiles: encrypted default includes db.enc + db.key.enc",
    def[0].relativePath === "db.enc" && def[1].relativePath === "db.key.enc");
  check("recommendedFiles: wrapped vault sealed + audit-sign sealed",
    /vault\.key\.sealed$/.test(def[2].relativePath) && /\.sealed$/.test(def[3].relativePath) &&
    def[3].required === false);

  // Plain DB + plaintext vault: live db file + unsealed vault + unsealed
  // audit key.
  var plain = b.backup.recommendedFiles({ atRest: "plain", vaultMode: "plaintext", dbName: "app.db" });
  check("recommendedFiles: plain at-rest uses the live db filename",
    plain[0].relativePath === "app.db");
  check("recommendedFiles: plaintext vault mode uses unsealed key names",
    !/\.sealed$/.test(plain[1].relativePath) && !/\.sealed$/.test(plain[2].relativePath));

  // Operator-supplied additional sealed files append as vault-sealed.
  var extra = b.backup.recommendedFiles({ additionalSealed: ["ca.key.sealed", "tls/privkey.pem.sealed"] });
  var tail = extra.slice(-2);
  check("recommendedFiles: additionalSealed appended as vault-sealed entries",
    tail[0].relativePath === "ca.key.sealed" && tail[0].kind === "vault-sealed" &&
    tail[1].relativePath === "tls/privkey.pem.sealed" && tail[1].required === false);
}

// ---- create(): run() happy path + retention + error branches ----

async function testCreateRunRoundTripAndRetention() {
  var data = _tmp("run-data");
  var root = _tmp("run-root");
  var pull = path.join(os.tmpdir(), "bidx-run-pull-" + Date.now());
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("PAYLOAD-1"));
    var eng = b.backup.create({
      dataDir:      data,
      storage:      b.backup.diskStorage({ root: root }),
      passphrase:   Buffer.from("operator-backup-passphrase-256bit"),
      files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
      // Async vaultKeyJson resolver drives the promise-await branch.
      vaultKeyJson: async function () { return '{"version":1}'; },
      retention:    { keep: 1 },
      audit:        false,
    });
    var r1 = await eng.run({ metadata: { reason: "first" } });
    check("create.run: returns a summary with bundleId + fileCount + durationMs",
      typeof r1.bundleId === "string" && typeof r1.fileCount === "number" &&
      typeof r1.durationMs === "number" && r1.storage === "local");
    // Second run trips retention keep:1 -> the older bundle is swept.
    var r2 = await eng.run();
    check("create.run: retention swept the older bundle (keep:1)",
      typeof r2.retentionPurged !== "undefined" && r2.retentionPurged.length === 1);
    var listed = await eng.list();
    check("create.run: exactly one bundle remains after retention sweep",
      listed.length === 1 && listed[0].bundleId === r2.bundleId);

    // read() the surviving bundle back through the consumer path.
    await eng.read(r2.bundleId, pull);
    check("create.read: recovers the bundle manifest",
      fs.existsSync(path.join(pull, "manifest.json")));

    // delete() through the consumer path.
    await eng.delete(r2.bundleId);
    check("create.delete: bundle gone after delete",
      (await eng.list()).length === 0);
  } finally { _rm(data); _rm(root); _rm(pull); }
}

async function testCreateRunFlushWarningBestEffort() {
  // requireFlush omitted (best-effort): a failing flush logs a warning
  // but the run continues to produce a bundle.
  var data = _tmp("fw2-data");
  var root = _tmp("fw2-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    var eng = b.backup.create({
      dataDir:           data,
      storage:           b.backup.diskStorage({ root: root }),
      passphrase:        "pp",
      files:             [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson:      '{"v":1}',
      flushBeforeBackup: function () { throw new Error("flush-broke-but-soft"); },
      audit:             false,
    });
    var r = await eng.run();
    check("create.run: best-effort flush failure does NOT abort the run",
      typeof r.bundleId === "string" && (await eng.list()).length === 1);
  } finally { _rm(data); _rm(root); }
}

async function testCreateRunVaultKeyJsonFailures() {
  var data = _tmp("vk-data");
  var root = _tmp("vk-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    // vaultKeyJson function returning an empty string -> bad-vault-key.
    var eng1 = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: root }),
      passphrase: "pp", files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: function () { return ""; }, audit: false,
    });
    var t1 = null;
    try { await eng1.run(); } catch (e) { t1 = e; }
    check("create.run: vaultKeyJson fn returning empty string refused with bad-vault-key",
      t1 && t1.code === "backup/bad-vault-key");

    // vaultKeyJson of the wrong type (number, not string/function) is
    // accepted at construction (!== undefined) but fails inside run().
    var eng2 = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: root }),
      passphrase: "pp", files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: 12345, audit: false,
    });
    var t2 = null;
    try { await eng2.run(); } catch (e) { t2 = e; }
    check("create.run: non-string/non-fn vaultKeyJson refused with no-vault-key-json",
      t2 && t2.code === "backup/no-vault-key-json");
  } finally { _rm(data); _rm(root); }
}

async function testCreateRunBackupBundleFailure() {
  // A required include file that doesn't exist makes backupBundle.create
  // throw; run() cleans staging + rethrows.
  var data = _tmp("bb-data");
  var root = _tmp("bb-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    var eng = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: root }),
      passphrase: "pp",
      files: [{ relativePath: "does-not-exist.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', audit: false,
    });
    var threw = null;
    try { await eng.run(); } catch (e) { threw = e; }
    check("create.run: missing required include file aborts the run",
      threw !== null);
    check("create.run: no bundle landed after bundle-build failure",
      (await eng.list()).length === 0);
  } finally { _rm(data); _rm(root); }
}

async function testCreateRunStorageWriteFailure() {
  var data = _tmp("sw-data");
  var root = _tmp("sw-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    var base = b.backup.diskStorage({ root: root });
    var storage = Object.assign({}, base, {
      writeBundle: async function () { throw new Error("disk-full"); },
    });
    var eng = b.backup.create({
      dataDir: data, storage: storage, passphrase: "pp",
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', audit: false,
    });
    var threw = null;
    try { await eng.run(); } catch (e) { threw = e; }
    check("create.run: storage.writeBundle failure surfaces as storage-write-failed",
      threw && threw.code === "backup/storage-write-failed");
  } finally { _rm(data); _rm(root); }
}

async function testCreateRetentionSweepFailure() {
  // A storage whose listBundles throws makes purgeOlder throw; the
  // retention sweep is best-effort so the run still SUCCEEDS.
  var data = _tmp("rs-data");
  var root = _tmp("rs-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    var base = b.backup.diskStorage({ root: root });
    var listCalls = 0;
    var storage = Object.assign({}, base, {
      listBundles: async function () {
        listCalls += 1;
        // First call is the retention sweep inside run() -> throw so the
        // sweep fails; later direct list() calls succeed.
        if (listCalls === 1) throw new Error("list-transient");
        return base.listBundles();
      },
    });
    var eng = b.backup.create({
      dataDir: data, storage: storage, passphrase: "pp",
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', retention: { keep: 2 }, audit: false,
    });
    var r = await eng.run();
    check("create.run: retention sweep failure does not fail the run",
      typeof r.bundleId === "string" && typeof r.retentionPurged === "undefined");
    check("create.run: the bundle is still written despite sweep failure",
      (await eng.list()).length === 1);
  } finally { _rm(data); _rm(root); }
}

async function testCreatePurgeOlderPerBundleDeleteFailure() {
  // purgeOlder swallows per-bundle delete failures (best-effort) and
  // reports only the ids it managed to delete.
  var data = _tmp("pg-data");
  var root = _tmp("pg-root");
  try {
    var base = b.backup.diskStorage({ root: root });
    var storage = Object.assign({}, base, {
      deleteBundle: async function () { throw new Error("delete-denied"); },
    });
    // Seed two bundles directly so purgeOlder has something to sweep.
    var srcDir = _mkSrcDir({ "manifest.json": "{}" });
    await base.writeBundle(ID_A, srcDir);
    await base.writeBundle(ID_B, srcDir);
    _rm(srcDir);
    var eng = b.backup.create({
      dataDir: (fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X")), data),
      storage: storage, passphrase: "pp",
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', audit: false,
    });
    var res = await eng.purgeOlder({ keep: 0 });
    check("create.purgeOlder: delete failures leave deleted list empty (best-effort)",
      res.kept === 0 && res.deleted.length === 0);
  } finally { _rm(data); _rm(root); }
}

async function testCreateDeleteReadBadId() {
  var data = _tmp("dr-data");
  var root = _tmp("dr-root");
  try {
    var eng = b.backup.create(_createOpts(data, root));
    var t1 = null;
    try { await eng.delete("not-a-valid-id"); } catch (e) { t1 = e; }
    check("create.delete: malformed bundleId refused with bad-bundle-id",
      t1 && t1.code === "backup/bad-bundle-id");
    var t2 = null;
    try { await eng.read("not-a-valid-id", "/x"); } catch (e) { t2 = e; }
    check("create.read: malformed bundleId refused with bad-bundle-id",
      t2 && t2.code === "backup/bad-bundle-id");
  } finally { _rm(data); _rm(root); }
}

// ---- create(): residency posture branches (no db needed) ----

function testCreateResidencyUndeclaredWarning() {
  var data = _tmp("ru-data");
  var root = _tmp("ru-root");
  b.compliance.clear();
  b.compliance.set("gdpr");
  try {
    // Under a regulated posture with NO residencyTag + no db residency,
    // create() emits an advisory (undeclared) warning and constructs.
    var eng = b.backup.create(_createOpts(data, root));
    check("create: gdpr posture + undeclared residency constructs (advisory only)",
      eng && typeof eng.run === "function");
  } finally { b.compliance.clear(); _rm(data); _rm(root); }
}

function testCreateResidencyPerRowCrossBorder() {
  var data = _tmp("rp-data");
  var root = _tmp("rp-root");
  b.compliance.clear();
  b.compliance.set("gdpr");
  // Declare a per-row-residency table that admits rows in a region other
  // than the backup destination; create() surfaces the per-row
  // cross-border advisory (policy-based; no db / row scan needed).
  b.cryptoField.declarePerRowResidency("bidx_residents", {
    residencyColumn: "region",
    allowedTags:     ["eu-west-1", "us-east-1", "global"],
  });
  try {
    var eng = b.backup.create(_createOpts(data, root, { residencyTag: "eu-west-1" }));
    check("create: gdpr + declared per-row cross-border region constructs (advisory)",
      eng && typeof eng.run === "function");
    // Confirm the declaration is what the create() path reads.
    var declared = b.cryptoField.listPerRowResidency();
    check("create: per-row residency declaration is visible to the residency gate",
      declared.some(function (t) { return t.table === "bidx_residents"; }));
  } finally {
    b.compliance.clear();
    _rm(data); _rm(root);
  }
}

// ---- bundleAdapterStorage: tar.gz / recipient / passphrase round-trips ----

async function testAdapterTarGzRoundTrip() {
  var root = _tmp("tgz-root");
  var src = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/a.enc": "AAAA" });
  var dest = path.join(os.tmpdir(), "bidx-tgz-dest-" + Date.now());
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "tar.gz",
    });
    await storage.writeBundle(VALID_ID, src);
    var info = await storage.bundleInfo(VALID_ID);
    check("adapter/tar.gz: bundleInfo reports tar.gz format + none envelope + size",
      info.format === "tar.gz" && info.envelopeKind === "none" &&
      typeof info.sizeBytes === "number" && info.sizeBytes > 0);
    var vb = await storage.verifyBundle(VALID_ID);
    check("adapter/tar.gz: verifyBundle walks the gz-wrapped tar entries",
      vb.ok === true && vb.format === "tar.gz" && vb.entryCount === 2);
    await storage.readBundle(VALID_ID, dest);
    check("adapter/tar.gz: readBundle recovers the file bytes",
      fs.readFileSync(path.join(dest, "files", "a.enc"), "utf8") === "AAAA");
  } finally { _rm(root); _rm(src); _rm(dest); }
}

async function testAdapterPassphraseRoundTrip() {
  var root = _tmp("pp-rt-root");
  var src = _mkSrcDir({ "a.txt": "secret-payload" });
  var dest = path.join(os.tmpdir(), "bidx-pp-dest-" + Date.now());
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     STRONG_PP,
    });
    await storage.writeBundle(VALID_ID, src);
    var info = await storage.bundleInfo(VALID_ID);
    check("adapter/passphrase: bundleInfo reports passphrase envelope",
      info.envelopeKind === "passphrase" && info.format === "tar");
    var vb = await storage.verifyBundle(VALID_ID);
    check("adapter/passphrase: verifyBundle decrypts + walks entries",
      vb.ok === true && vb.envelopeKind === "passphrase" && vb.entryCount === 1);
    await storage.readBundle(VALID_ID, dest);
    check("adapter/passphrase: readBundle decrypts under the configured passphrase",
      fs.readFileSync(path.join(dest, "a.txt"), "utf8") === "secret-payload");
  } finally { _rm(root); _rm(src); _rm(dest); }
}

async function testAdapterRecipientRoundTrip() {
  var root = _tmp("rcp-rt-root");
  var src = _mkSrcDir({ "phi.json": "{\"patient\":7}" });
  var dest = path.join(os.tmpdir(), "bidx-rcp-dest-" + Date.now());
  try {
    var pair = b.crypto.generateEncryptionKeyPair();
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    await storage.writeBundle(VALID_ID, src);
    var info = await storage.bundleInfo(VALID_ID);
    check("adapter/recipient: bundleInfo reports recipient envelope",
      info.envelopeKind === "recipient" && info.format === "tar.gz");
    var vb = await storage.verifyBundle(VALID_ID);
    check("adapter/recipient: verifyBundle unwraps + walks entries",
      vb.ok === true && vb.envelopeKind === "recipient" && vb.entryCount === 1);
    await storage.readBundle(VALID_ID, dest);
    check("adapter/recipient: readBundle unwraps under the configured recipient",
      fs.readFileSync(path.join(dest, "phi.json"), "utf8") === "{\"patient\":7}");
  } finally { _rm(root); _rm(src); _rm(dest); }
}

async function testAdapterListBundlesWithStats() {
  var root = _tmp("ls-stat-root");
  var src = _mkSrcDir({ "a.txt": "x" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:  "tar",
    });
    await storage.writeBundle(VALID_ID, src);
    var listed = await storage.listBundles({ withStats: true });
    check("adapter.listBundles({withStats}): fans out statKey for size + createdAt",
      listed.length === 1 && typeof listed[0].size === "number" && listed[0].size > 0 &&
      typeof listed[0].createdAt === "string");
  } finally { _rm(root); _rm(src); }
}

async function testAdapterVerifyBundleErrorBranches() {
  var root = _tmp("vb-err-root");
  var src = _mkSrcDir({ "a.txt": "data" });
  try {
    var pair = b.crypto.generateEncryptionKeyPair();
    // Absent bundle -> bundleInfo throws -> verifyBundle returns ok:false.
    var plain = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }), format: "tar",
    });
    var vAbsent = await plain.verifyBundle(ABSENT_ID);
    check("verifyBundle: absent bundle -> ok:false with an error entry",
      vAbsent.ok === false && vAbsent.errors.length === 1);

    // Write a recipient bundle, then verify it through a store with NO
    // recipient -> no-recipient-for-verify.
    var recStore = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format: "tar", cryptoStrategy: "recipient", recipient: pair,
    });
    await recStore.writeBundle(VALID_ID, src);
    var noKeyRec = await plain.verifyBundle(VALID_ID);
    check("verifyBundle: recipient bundle without a recipient -> no-recipient-for-verify",
      noKeyRec.ok === false && noKeyRec.errors.indexOf("backup/no-recipient-for-verify") !== -1);

    // Write a passphrase bundle, verify through a store with no passphrase.
    var ppStore = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format: "tar", cryptoStrategy: "passphrase", passphrase: STRONG_PP,
    });
    await ppStore.writeBundle(VALID_ID2, src);
    var noKeyPp = await plain.verifyBundle(VALID_ID2);
    check("verifyBundle: passphrase bundle without a passphrase -> no-passphrase-for-verify",
      noKeyPp.ok === false && noKeyPp.errors.indexOf("backup/no-passphrase-for-verify") !== -1);

    // Corrupt a tar.gz payload (invalid gzip magic) -> the decompress
    // step throws -> verifyBundle returns ok:false with the error captured.
    var corruptRoot = _tmp("vb-corrupt-root");
    try {
      var adapter = b.backup.bundleAdapterStorage.fsAdapter({ root: corruptRoot });
      var cStore = b.backup.bundleAdapterStorage({ adapter: adapter, format: "tar.gz" });
      await cStore.writeBundle(ID_A, src);
      await adapter.writeFile(ID_A + "/bundle.tar.gz", Buffer.from("definitely-not-gzip-bytes"));
      var vCorrupt = await cStore.verifyBundle(ID_A);
      check("verifyBundle: corrupt tar.gz payload -> ok:false with a captured error",
        vCorrupt.ok === false && vCorrupt.errors.length === 1);
    } finally { _rm(corruptRoot); }
  } finally { _rm(root); _rm(src); }
}

async function testAdapterFindBundles() {
  var root = _tmp("find-root");
  var src = _mkSrcDir({ "a.txt": "x" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }), format: "tar",
    });
    var bad = null;
    try { await storage.findBundles("not-a-fn"); } catch (e) { bad = e; }
    check("findBundles: non-function predicate refused with bad-arg",
      bad && bad.code === "backup/bad-arg");

    await storage.writeBundle(ID_A, src);
    await storage.writeBundle(ID_B, src);
    var found = await storage.findBundles(function (entry) { return entry.bundleId === ID_B; });
    check("findBundles: returns only entries the predicate accepts",
      found.length === 1 && found[0].bundleId === ID_B);
  } finally { _rm(root); _rm(src); }
}

async function testAdapterCloneBundle() {
  var root = _tmp("clone-root");
  var src = _mkSrcDir({ "a.txt": "clone-me" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }), format: "tar",
    });
    await storage.writeBundle(ID_A, src);

    var same = null;
    try { await storage.cloneBundle(ID_A, ID_A); } catch (e) { same = e; }
    check("cloneBundle: same src/dst id refused with clone-same-id",
      same && same.code === "backup/clone-same-id");

    var res = await storage.cloneBundle(ID_A, ID_B);
    check("cloneBundle: tar clone copies the single payload key",
      res.format === "tar" && res.keysCopied === 1 && res.bytesCopied > 0 &&
      (await storage.hasBundle(ID_B)));

    var dstExists = null;
    try { await storage.cloneBundle(ID_A, ID_B); } catch (e) { dstExists = e; }
    check("cloneBundle: existing dst without overwrite refused with clone-dst-exists",
      dstExists && dstExists.code === "backup/clone-dst-exists");

    // overwrite:true purges the destination first, then re-copies.
    var res2 = await storage.cloneBundle(ID_A, ID_B, { overwrite: true });
    check("cloneBundle: overwrite:true replaces the destination bytes",
      res2.keysCopied === 1 && (await storage.hasBundle(ID_B)));

    // Directory-format clone walks every key under the source prefix.
    var dirRoot = _tmp("clone-dir-root");
    try {
      var dirStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dirRoot }), format: "directory",
      });
      var dsrc = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/a.enc": "DD" });
      try {
        await dirStore.writeBundle(ID_A, dsrc);
        var dres = await dirStore.cloneBundle(ID_A, ID_C);
        check("cloneBundle: directory clone copies every key under the prefix",
          dres.format === "directory" && dres.keysCopied >= 2 && (await dirStore.hasBundle(ID_C)));
      } finally { _rm(dsrc); }
    } finally { _rm(dirRoot); }
  } finally { _rm(root); _rm(src); }
}

async function testAdapterRewrapBundleBranches() {
  var src = _mkSrcDir({ "a.txt": "rewrap-me" });
  try {
    // format-not-wrappable: a directory bundle carries no envelope.
    var dirRoot = _tmp("rw-dir-root");
    try {
      var dirStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dirRoot }), format: "directory",
      });
      var dsrc = _mkSrcDir({ "manifest.json": "{}" });
      try {
        await dirStore.writeBundle(VALID_ID, dsrc);
        var nf = null;
        try { await dirStore.rewrapBundle(VALID_ID, {}); } catch (e) { nf = e; }
        check("rewrapBundle: directory bundle refused with format-not-wrappable",
          nf && nf.code === "backup/format-not-wrappable");
      } finally { _rm(dsrc); }
    } finally { _rm(dirRoot); }

    // no-envelope-to-rewrap: a plaintext tar bundle has envelopeKind none.
    var plainRoot = _tmp("rw-plain-root");
    try {
      var plainStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: plainRoot }), format: "tar",
      });
      await plainStore.writeBundle(VALID_ID, src);
      var ne = null;
      try { await plainStore.rewrapBundle(VALID_ID, {}); } catch (e) { ne = e; }
      check("rewrapBundle: plaintext tar bundle refused with no-envelope-to-rewrap",
        ne && ne.code === "backup/no-envelope-to-rewrap");
    } finally { _rm(plainRoot); }

    // passphrase rewrap: missing newPassphrase, then a real rotation.
    var ppRoot = _tmp("rw-pp-root");
    var ppVerify = path.join(os.tmpdir(), "bidx-rw-pp-v-" + Date.now());
    try {
      var oldPp = b.crypto.generateBytes(24).toString("hex");
      var newPp = b.crypto.generateBytes(24).toString("hex");
      var ppStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: ppRoot }),
        format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp,
      });
      await ppStore.writeBundle(VALID_ID, src);
      var noNew = null;
      try { await ppStore.rewrapBundle(VALID_ID, {}); } catch (e) { noNew = e; }
      check("rewrapBundle: passphrase rotation without newPassphrase refused",
        noNew && noNew.code === "backup/no-new-passphrase");
      var rw = await ppStore.rewrapBundle(VALID_ID, { newPassphrase: newPp });
      check("rewrapBundle: passphrase rotation returns passphrase envelope kinds",
        rw.oldEnvelopeKind === "passphrase" && rw.newEnvelopeKind === "passphrase" &&
        rw.bytesRewritten > 0);
      var rotated = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: ppRoot }),
        format: "tar", cryptoStrategy: "passphrase", passphrase: newPp,
      });
      await rotated.readBundle(VALID_ID, ppVerify);
      check("rewrapBundle: bundle restores under the NEW passphrase after rotation",
        fs.readFileSync(path.join(ppVerify, "a.txt"), "utf8") === "rewrap-me");
    } finally { _rm(ppRoot); _rm(ppVerify); }

    // recipient rewrap: missing newRecipient, then a real rotation.
    var rcpRoot = _tmp("rw-rcp-root");
    try {
      var oldPair = b.crypto.generateEncryptionKeyPair();
      var newPair = b.crypto.generateEncryptionKeyPair();
      var rcpStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: rcpRoot }),
        format: "tar.gz", cryptoStrategy: "recipient", recipient: oldPair,
      });
      await rcpStore.writeBundle(VALID_ID, src);
      var noNewR = null;
      try { await rcpStore.rewrapBundle(VALID_ID, {}); } catch (e) { noNewR = e; }
      check("rewrapBundle: recipient rotation without newRecipient refused",
        noNewR && noNewR.code === "backup/no-new-recipient");
      var rwR = await rcpStore.rewrapBundle(VALID_ID, { newRecipient: newPair });
      check("rewrapBundle: recipient rotation returns recipient envelope kinds",
        rwR.oldEnvelopeKind === "recipient" && rwR.newEnvelopeKind === "recipient");
    } finally { _rm(rcpRoot); }
  } finally { _rm(src); }
}

async function testAdapterKeyRotationBranches() {
  var src = _mkSrcDir({ "a.txt": "rotate" });
  try {
    // dualWrap unsupported.
    var noneRoot = _tmp("kr-none-root");
    try {
      var noneStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: noneRoot }), format: "tar",
      });
      var dw = null;
      try { await noneStore.keyRotation({ dualWrap: true }); } catch (e) { dw = e; }
      check("keyRotation: dualWrap refused with dual-wrap-unsupported",
        dw && dw.code === "backup/dual-wrap-unsupported");
      var noEnv = null;
      try { await noneStore.keyRotation({}); } catch (e) { noEnv = e; }
      check("keyRotation: cryptoStrategy none refused with no-envelope-to-rewrap",
        noEnv && noEnv.code === "backup/no-envelope-to-rewrap");
    } finally { _rm(noneRoot); }

    // recipient storage without newRecipient.
    var rcpRoot = _tmp("kr-rcp-root");
    try {
      var rcpStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: rcpRoot }),
        format: "tar.gz", cryptoStrategy: "recipient", recipient: b.crypto.generateEncryptionKeyPair(),
      });
      var noR = null;
      try { await rcpStore.keyRotation({}); } catch (e) { noR = e; }
      check("keyRotation: recipient strategy without newRecipient refused with no-recipient",
        noR && noR.code === "backup/no-recipient");
    } finally { _rm(rcpRoot); }

    // passphrase storage without newPassphrase, then a full rotation +
    // post-rotation verify (composes rewrapAllBundles + verifyAllBundles).
    var ppRoot = _tmp("kr-pp-root");
    try {
      var oldPp = b.crypto.generateBytes(24).toString("hex");
      var newPp = b.crypto.generateBytes(24).toString("hex");
      var ppStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: ppRoot }),
        format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp, audit: false,
      });
      var badPp = null;
      try { await ppStore.keyRotation({}); } catch (e) { badPp = e; }
      check("keyRotation: passphrase strategy without newPassphrase refused with bad-passphrase",
        badPp && badPp.code === "backup/bad-passphrase");

      await ppStore.writeBundle(ID_A, src);
      await ppStore.writeBundle(ID_B, src);
      var report = await ppStore.keyRotation({ newPassphrase: newPp });
      check("keyRotation: rotates every passphrase bundle + verifies under the new key",
        report.total === 2 && report.rotated === 2 && report.failed === 0 &&
        report.verified === 2 && report.verifyFailed === 0 &&
        /^rotation-/.test(report.rotationId));

      var fresh = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: ppRoot }),
        format: "tar", cryptoStrategy: "passphrase", passphrase: newPp,
      });
      var v = await fresh.verifyAllBundles();
      check("keyRotation: fresh new-key storage verifies all rotated bundles",
        v.total === 2 && v.ok === 2 && v.failed === 0);
    } finally { _rm(ppRoot); }
  } finally { _rm(src); }
}

// ---- legacy (minimal) in-memory adapter branches ----

async function testMemAdapterLegacyBranches() {
  var src = _mkSrcDir({ "a.txt": "mem-payload", "b/c.txt": "nested" });
  var dest = path.join(os.tmpdir(), "bidx-mem-dest-" + Date.now());
  try {
    var storage = b.backup.bundleAdapterStorage({ adapter: _memAdapter(), format: "tar" });
    await storage.writeBundle(VALID_ID, src);
    check("memAdapter: hasBundle true after write", await storage.hasBundle(VALID_ID));

    // bundleInfo on an adapter without readPartial -> envelopeKind unknown,
    // sizeBytes null (no statKey).
    var info = await storage.bundleInfo(VALID_ID);
    check("memAdapter: bundleInfo reports envelopeKind unknown (no readPartial capability)",
      info.envelopeKind === "unknown" && info.sizeBytes === null && info.format === "tar");

    // listBundles without statKey -> size/createdAt stay null even with
    // withStats requested.
    var listed = await storage.listBundles({ withStats: true });
    check("memAdapter: listBundles leaves size/createdAt null without statKey",
      listed.length === 1 && listed[0].size === null && listed[0].createdAt === null);

    await storage.readBundle(VALID_ID, dest);
    check("memAdapter: readBundle recovers a nested file through the tar path",
      fs.readFileSync(path.join(dest, "b", "c.txt"), "utf8") === "nested");

    await storage.deleteBundle(VALID_ID);
    check("memAdapter: hasBundle false after delete",
      (await storage.hasBundle(VALID_ID)) === false);
  } finally { _rm(src); _rm(dest); }
}

// ---- objectStoreAdapter (local b.objectStore backend; no network) ----

function testObjectStoreAdapterPrefixValidation() {
  var rootDir = _tmp("os-prefix-root");
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var t1 = null;
    try { b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: 123 }); } catch (e) { t1 = e; }
    check("objectStoreAdapter: non-string prefix refused with bad-arg",
      t1 && t1.code === "backup/bad-arg");
    var t2 = null;
    try { b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "../evil" }); } catch (e) { t2 = e; }
    check("objectStoreAdapter: traversal prefix refused with bad-arg",
      t2 && t2.code === "backup/bad-arg");
    // Bad client (missing methods) refused with bad-adapter.
    var t3 = null;
    try { b.backup.bundleAdapterStorage.objectStoreAdapter({}); } catch (e) { t3 = e; }
    check("objectStoreAdapter: client missing methods refused with bad-adapter",
      t3 && t3.code === "backup/bad-adapter");
  } finally { _rm(rootDir); }
}

async function testObjectStoreAdapterKeyValidationAndMisses() {
  var rootDir = _tmp("os-key-root");
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    // Trailing-slash prefix is stripped; adapter still round-trips.
    var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "scoped///" });

    var empty = null;
    try { await adapter.writeFile("", Buffer.from("x")); } catch (e) { empty = e; }
    check("objectStoreAdapter.writeFile: empty key refused with bad-key",
      empty && empty.code === "backup/bad-key");
    var trav = null;
    try { await adapter.writeFile("../escape", Buffer.from("x")); } catch (e) { trav = e; }
    check("objectStoreAdapter.writeFile: traversal key refused with bad-key",
      trav && trav.code === "backup/bad-key");
    var badBytes = null;
    try { await adapter.writeFile("k1", "not-a-buffer"); } catch (e) { badBytes = e; }
    check("objectStoreAdapter.writeFile: non-Buffer bytes refused with bad-arg",
      badBytes && badBytes.code === "backup/bad-arg");

    // Missing-key contract across the read family.
    var missRead = null;
    try { await adapter.readFile("nope"); } catch (e) { missRead = e; }
    check("objectStoreAdapter.readFile: missing key -> no-key", missRead && missRead.code === "backup/no-key");
    var missPartial = null;
    try { await adapter.readPartial("nope", 4); } catch (e) { missPartial = e; }
    check("objectStoreAdapter.readPartial: missing key -> no-key", missPartial && missPartial.code === "backup/no-key");
    check("objectStoreAdapter.statKey: null for a missing key", (await adapter.statKey("nope")) === null);
    check("objectStoreAdapter.hasKey: false for a missing key", (await adapter.hasKey("nope")) === false);
    var delMiss = null;
    try { await adapter.deleteKey("nope"); } catch (e) { delMiss = e; }
    check("objectStoreAdapter.deleteKey: missing key is a silent no-op", delMiss === null);

    // Round-trip a real key through the scoped prefix.
    await adapter.writeFile("k1", Buffer.from("hello-object-store"));
    var back = await adapter.readFile("k1");
    check("objectStoreAdapter: writeFile/readFile round-trips under the stripped prefix",
      back.toString() === "hello-object-store");
    var head = await adapter.readPartial("k1", 5);
    check("objectStoreAdapter.readPartial: returns the leading bytes via range GET",
      head.toString() === "hello");
    var st = await adapter.statKey("k1");
    check("objectStoreAdapter.statKey: reports size for an existing key", st && st.size === 18);
    var keys = await adapter.listKeys("");
    check("objectStoreAdapter.listKeys: enumerates keys with the prefix stripped",
      keys.indexOf("k1") !== -1);
  } finally { _rm(rootDir); }
}

async function testObjectStoreAdapterBundleRoundTrip() {
  var rootDir = _tmp("os-bundle-root");
  var src = _mkSrcDir({ "data.json": "{\"v\":9}" });
  var dest = path.join(os.tmpdir(), "bidx-os-dest-" + Date.now());
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: "bkp" }),
      format:  "tar.gz",
    });
    await storage.writeBundle(VALID_ID, src);
    check("objectStoreAdapter: hasBundle true after put", await storage.hasBundle(VALID_ID));
    var info = await storage.bundleInfo(VALID_ID);
    check("objectStoreAdapter: bundleInfo reports tar.gz + size via head()",
      info.format === "tar.gz" && typeof info.sizeBytes === "number" && info.sizeBytes > 0);
    var listed = await storage.listBundles({ withStats: true });
    check("objectStoreAdapter: listBundles({withStats}) reports size from head()",
      listed.length === 1 && typeof listed[0].size === "number");
    await storage.readBundle(VALID_ID, dest);
    check("objectStoreAdapter: bundle round-trips through the local object store",
      fs.readFileSync(path.join(dest, "data.json"), "utf8") === "{\"v\":9}");
    await storage.deleteBundle(VALID_ID);
    check("objectStoreAdapter: hasBundle false after deleteBundle",
      (await storage.hasBundle(VALID_ID)) === false);
  } finally { _rm(rootDir); _rm(src); _rm(dest); }
}

// ---- migrate: single-bundle + deleteSourceOnSuccess ----

async function testMigrateSingleIdAndDeleteSource() {
  var fromRoot = _tmp("migs-from");
  var toRoot = _tmp("migs-to");
  var src = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/d.enc": "DD" });
  try {
    var from = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: fromRoot }), format: "directory",
    });
    var to = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: toRoot }), format: "tar",
    });
    await from.writeBundle(ID_A, src);
    await from.writeBundle(ID_B, src);

    // Single-bundle migrate targets only the named id.
    var one = await b.backup.migrate({ from: from, to: to, bundleId: ID_A });
    check("migrate: single bundleId migrates exactly that bundle",
      one.total === 1 && one.migrated === 1 && (await to.hasBundle(ID_A)) &&
      (await to.hasBundle(ID_B)) === false);

    // deleteSourceOnSuccess removes the source bundle after a successful
    // write.
    var two = await b.backup.migrate({
      from: from, to: to, bundleId: ID_B, deleteSourceOnSuccess: true,
    });
    check("migrate: deleteSourceOnSuccess prunes the migrated source bundle",
      two.migrated === 1 && (await to.hasBundle(ID_B)) &&
      (await from.hasBundle(ID_B)) === false);
  } finally { _rm(fromRoot); _rm(toRoot); _rm(src); }
}

// ---- runInWorker ----

function _writeWorker(name, body) {
  var dir = _tmp("wk-" + name);
  var file = path.join(dir, "worker.js");
  fs.writeFileSync(file, body);
  return { dir: dir, file: file };
}

async function testRunInWorkerValidation() {
  var noScript = null;
  try { await b.backup.runInWorker({}); } catch (e) { noScript = e; }
  check("runInWorker: missing workerScript rejects with no-worker-script",
    noScript && noScript.code === "backup/no-worker-script");

  var badTimeout = null;
  try {
    await b.backup.runInWorker({ workerScript: "/tmp/x.js", timeoutMs: -5 });
  } catch (e) { badTimeout = e; }
  check("runInWorker: negative timeoutMs rejects with bad-timeout",
    badTimeout && badTimeout.code === "backup/bad-timeout");
}

async function testRunInWorkerLifecycle() {
  await helpers.withTestTimeout("runInWorker lifecycle", async function () {
    // Worker that posts a message -> resolve.
    var okW = _writeWorker("ok",
      "var wt = require('node:worker_threads'); wt.parentPort.postMessage({ echoed: wt.workerData });");
    try {
      var msg = await b.backup.runInWorker({ workerScript: okW.file, args: { mode: "full" } });
      check("runInWorker: resolves with the worker's posted message",
        msg && msg.echoed && msg.echoed.mode === "full");
    } finally { _rm(okW.dir); }

    // Worker that throws on load -> rejects via the error event.
    var errW = _writeWorker("err", "throw new Error('worker-load-boom');");
    try {
      var errThrown = null;
      try { await b.backup.runInWorker({ workerScript: errW.file }); } catch (e) { errThrown = e; }
      check("runInWorker: a worker that throws on load rejects the promise",
        errThrown && /worker-load-boom/.test(errThrown.message));
    } finally { _rm(errW.dir); }

    // Worker that exits non-zero with no message -> worker-nonzero-exit.
    var exitW = _writeWorker("exit", "process.exit(3);");
    try {
      var exitErr = null;
      try { await b.backup.runInWorker({ workerScript: exitW.file }); } catch (e) { exitErr = e; }
      check("runInWorker: a non-zero worker exit rejects with worker-nonzero-exit",
        exitErr && exitErr.code === "backup/worker-nonzero-exit");
    } finally { _rm(exitW.dir); }

    // Worker that never posts/exits -> timeoutMs terminates it.
    var hangW = _writeWorker("hang", "setInterval(function () {}, 100000);");
    try {
      var toErr = null;
      try { await b.backup.runInWorker({ workerScript: hangW.file, timeoutMs: 150 }); } catch (e) { toErr = e; }
      check("runInWorker: a hung worker is terminated with worker-timeout",
        toErr && toErr.code === "backup/worker-timeout");
    } finally { _rm(hangW.dir); }
  }, { timeoutMs: 20000 });
}

// ---- scheduleTest drill closure (failure paths, no signed manifest) ----

function _capturingScheduler() {
  var specs = [];
  return {
    specs: specs,
    create: function () {
      return { schedule: function (spec) { specs.push(spec); return spec; } };
    },
  };
}

async function testScheduleTestDrillFailurePaths() {
  var data = _tmp("drill-data");
  var root = _tmp("drill-root");
  var restore = _tmp("drill-restore");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));

    // (a) listBundles throws inside the drill -> backup.test.failed, no throw.
    var listThrowSched = _capturingScheduler();
    var base = b.backup.diskStorage({ root: root });
    var listThrowStorage = Object.assign({}, base, {
      listBundles: async function () { throw new Error("list-down"); },
    });
    var eng1 = b.backup.create({
      dataDir: data, storage: listThrowStorage, passphrase: "pp",
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', scheduler: listThrowSched, audit: false,
    });
    eng1.scheduleTest({ cron: "0 3 * * *", restoreTo: restore, verify: function () { return true; } });
    var drill1 = null;
    try { await listThrowSched.specs[0].run(); } catch (e) { drill1 = e; }
    check("scheduleTest drill: listBundles failure is swallowed (no throw out of the tick)",
      drill1 === null);

    // (b) empty storage -> "no bundles" failure, no throw.
    var emptySched = _capturingScheduler();
    var eng2 = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: _tmp("drill-empty") }),
      passphrase: "pp", files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', scheduler: emptySched, audit: false,
    });
    eng2.scheduleTest({ cron: "0 3 * * *", restoreTo: restore, verify: function () { return true; } });
    var drill2 = null;
    try { await emptySched.specs[0].run(); } catch (e) { drill2 = e; }
    check("scheduleTest drill: no bundles in storage is handled (no throw)", drill2 === null);

    // (c) a real (unsigned-manifest) bundle -> signature verify fails ->
    //     backup.test.failed with the operator notify hook invoked.
    var okSched = _capturingScheduler();
    var storeRoot = _tmp("drill-store");
    var eng3 = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: storeRoot }),
      passphrase: "pp", files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', scheduler: okSched, audit: false,
    });
    await eng3.run();
    var verifyCalled = false;
    var notifyInfo = [];
    eng3.scheduleTest({
      cron: "0 3 * * *", restoreTo: restore,
      verify: function () { verifyCalled = true; return true; },
      notify: function (info) { notifyInfo.push(info); },
    });
    var drill3 = null;
    try { await okSched.specs[0].run(); } catch (e) { drill3 = e; }
    check("scheduleTest drill: unsigned-manifest bundle fails signature verify without throwing",
      drill3 === null && verifyCalled === false);
    check("scheduleTest drill: operator notify hook fired with a failure outcome",
      notifyInfo.length === 1 && notifyInfo[0].outcome === "failure");

    // (d) stagingDir already exists -> the drill refuses to overwrite.
    var existsSched = _capturingScheduler();
    var eng4 = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: storeRoot }),
      passphrase: "pp", files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', scheduler: existsSched, audit: false,
    });
    var bundles = await eng4.list();
    var collideDir = path.join(restore, "test-" + bundles[0].bundleId.replace(/[:.]/g, "-"));
    fs.mkdirSync(collideDir, { recursive: true });
    eng4.scheduleTest({ cron: "0 3 * * *", restoreTo: restore, verify: function () { return true; } });
    var drill4 = null;
    try { await existsSched.specs[0].run(); } catch (e) { drill4 = e; }
    check("scheduleTest drill: pre-existing staging dir is refused (no throw)", drill4 === null);
  } finally { _rm(data); _rm(root); _rm(restore); }
}

async function testDiskStorageReadDestExists() {
  var root = _tmp("ds-de-root");
  var src = _mkSrcDir({ "manifest.json": "{}" });
  var dest = _tmp("ds-de-dest");   // pre-existing destination
  try {
    var ds = b.backup.diskStorage({ root: root });
    await ds.writeBundle(VALID_ID, src);
    var threw = null;
    try { await ds.readBundle(VALID_ID, dest); } catch (e) { threw = e; }
    check("diskStorage.readBundle: pre-existing destDir refused with dest-exists",
      threw && threw.code === "backup/dest-exists");
  } finally { _rm(root); _rm(src); _rm(dest); }
}

function testCreateConstructionValidation() {
  var root = _tmp("cv-root");
  try {
    var storage = b.backup.diskStorage({ root: root });
    var t1 = null;
    try { b.backup.create({ storage: storage }); } catch (e) { t1 = e; }
    check("create: missing dataDir refused with no-datadir",
      t1 && t1.code === "backup/no-datadir");

    var data = _tmp("cv-data");
    try {
      var t2 = null;
      try { b.backup.create({ dataDir: data, storage: storage, passphrase: 123, files: [{}], vaultKeyJson: "{}" }); } catch (e) { t2 = e; }
      check("create: non-Buffer/non-string passphrase refused with no-passphrase",
        t2 && t2.code === "backup/no-passphrase");

      var t3 = null;
      try { b.backup.create({ dataDir: data, storage: storage, passphrase: "pp", files: [], vaultKeyJson: "{}" }); } catch (e) { t3 = e; }
      check("create: empty files array refused with no-files",
        t3 && t3.code === "backup/no-files");

      var t4 = null;
      try { b.backup.create({ dataDir: data, storage: storage, passphrase: "pp", files: [{ relativePath: "x" }] }); } catch (e) { t4 = e; }
      check("create: missing vaultKeyJson refused with no-vault-key-json",
        t4 && t4.code === "backup/no-vault-key-json");
    } finally { _rm(data); }
  } finally { _rm(root); }
}

async function testCreateScheduleClosureRuns() {
  var data = _tmp("scc-data");
  var root = _tmp("scc-root");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("X"));
    var captured = [];
    var fakeScheduler = {
      create: function () {
        return { schedule: function (spec) { captured.push(spec); } };
      },
    };
    var eng = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: root }), passphrase: "pp",
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"v":1}', scheduler: fakeScheduler, audit: false,
    });
    eng.schedule({ cron: "0 3 * * *", name: "nightly" });
    // Fire the registered run closure directly — it invokes run() and
    // swallows errors (errors are audited inside run()).
    await captured[0].run();
    check("create.schedule: the registered run closure produces a bundle",
      (await eng.list()).length === 1);
  } finally { _rm(data); _rm(root); }
}

async function testAdapterHipaaPassphraseFloorAndBadId() {
  var root = _tmp("hpf-root");
  var src = _mkSrcDir({ "a.txt": "x" });
  var dest = path.join(os.tmpdir(), "bidx-hpf-dest-" + Date.now());
  try {
    // Explicit posture:"hipaa" raises the passphrase entropy floor to 128
    // bits at construction. A high-entropy passphrase still writes/reads.
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     b.crypto.generateBytes(32).toString("hex"),
      posture:        "hipaa",
    });
    // A malformed bundleId is refused by the shared _ensureBundleId guard.
    var badId = null;
    try { await storage.writeBundle("not-valid", src); } catch (e) { badId = e; }
    check("adapter.writeBundle: malformed bundleId refused with bad-bundle-id",
      badId && badId.code === "backup/bad-bundle-id");

    await storage.writeBundle(VALID_ID, src);
    await storage.readBundle(VALID_ID, dest);
    check("adapter/hipaa passphrase: 128-bit-floor bundle round-trips with a strong passphrase",
      fs.readFileSync(path.join(dest, "a.txt"), "utf8") === "x");
  } finally { _rm(root); _rm(src); _rm(dest); }
}

async function testAdapterReadBundleNotFoundAndCryptoTarReads() {
  var src = _mkSrcDir({ "a.txt": "cryptotar" });
  try {
    // readBundle on an absent bundle -> bundle-not-found.
    var nfRoot = _tmp("rb-nf-root");
    try {
      var nfStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: nfRoot }), format: "tar",
      });
      var nf = null;
      try { await nfStore.readBundle(ABSENT_ID, path.join(nfRoot, "out")); } catch (e) { nf = e; }
      check("adapter.readBundle: absent bundle refused with bundle-not-found",
        nf && nf.code === "backup/bundle-not-found");
    } finally { _rm(nfRoot); }

    // tar.gz + passphrase read path (gz unwrapWithPassphrase branch).
    var tgzRoot = _tmp("rb-tgz-root");
    var tgzDest = path.join(os.tmpdir(), "bidx-rb-tgz-" + Date.now());
    try {
      var tgz = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: tgzRoot }),
        format: "tar.gz", cryptoStrategy: "passphrase", passphrase: STRONG_PP,
      });
      await tgz.writeBundle(VALID_ID, src);
      await tgz.readBundle(VALID_ID, tgzDest);
      check("adapter.readBundle: tar.gz + passphrase decrypts + gunzips on restore",
        fs.readFileSync(path.join(tgzDest, "a.txt"), "utf8") === "cryptotar");
    } finally { _rm(tgzRoot); _rm(tgzDest); }

    // tar (non-gz) + recipient read path (hasTar recipient-unwrap branch).
    var tarRoot = _tmp("rb-tar-root");
    var tarDest = path.join(os.tmpdir(), "bidx-rb-tar-" + Date.now());
    try {
      var pair = b.crypto.generateEncryptionKeyPair();
      var tarStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: tarRoot }),
        format: "tar", cryptoStrategy: "recipient", recipient: pair,
      });
      await tarStore.writeBundle(VALID_ID, src);
      await tarStore.readBundle(VALID_ID, tarDest);
      check("adapter.readBundle: tar + recipient unwraps on restore",
        fs.readFileSync(path.join(tarDest, "a.txt"), "utf8") === "cryptotar");
    } finally { _rm(tarRoot); _rm(tarDest); }
  } finally { _rm(src); }
}

async function testAdapterDirectoryListWithStats() {
  var root = _tmp("dls-root");
  var src = _mkSrcDir({ "manifest.json": "{\"version\":1}", "files/a.enc": "AA" });
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }), format: "directory",
    });
    await storage.writeBundle(VALID_ID, src);
    var listed = await storage.listBundles({ withStats: true });
    check("adapter/directory: listBundles({withStats}) stats the manifest key for size",
      listed.length === 1 && listed[0].format === "directory" &&
      typeof listed[0].size === "number" && typeof listed[0].createdAt === "string");
    // bundleInfo on a directory bundle stats the manifest too.
    var info = await storage.bundleInfo(VALID_ID);
    check("adapter/directory: bundleInfo stats manifest for size + createdAt",
      info.format === "directory" && typeof info.sizeBytes === "number" &&
      typeof info.createdAt === "string");
  } finally { _rm(root); _rm(src); }
}

async function testAdapterRewrapUnknownAndMissingKeys() {
  var src = _mkSrcDir({ "a.txt": "rw2" });
  try {
    // A legacy adapter (no readPartial) makes bundleInfo report
    // envelopeKind "unknown"; rewrap falls back to sniffing the loaded
    // sealed bytes.
    var oldPp = b.crypto.generateBytes(24).toString("hex");
    var newPp = b.crypto.generateBytes(24).toString("hex");
    var mem = _memAdapter();
    var memStore = b.backup.bundleAdapterStorage({
      adapter: mem, format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp,
    });
    await memStore.writeBundle(VALID_ID, src);
    var infoUnknown = await memStore.bundleInfo(VALID_ID);
    check("rewrap-precondition: legacy adapter bundleInfo reports envelopeKind unknown",
      infoUnknown.envelopeKind === "unknown");
    var rw = await memStore.rewrapBundle(VALID_ID, {
      newPassphrase: newPp,
      passphraseMinEntropyBits: 200,   // higher than the storage floor -> effectiveFloor raise
    });
    check("rewrapBundle: unknown-envelope bundle is sniffed + rotated as passphrase",
      rw.oldEnvelopeKind === "passphrase" && rw.newEnvelopeKind === "passphrase");

    // no-old-recipient: recipient envelope, explicit null old key.
    var rcpRoot = _tmp("rw2-rcp-root");
    try {
      var pair = b.crypto.generateEncryptionKeyPair();
      var newPair = b.crypto.generateEncryptionKeyPair();
      var rcpStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: rcpRoot }),
        format: "tar.gz", cryptoStrategy: "recipient", recipient: pair,
      });
      await rcpStore.writeBundle(VALID_ID, src);
      var noOldR = null;
      try { await rcpStore.rewrapBundle(VALID_ID, { oldRecipient: null, newRecipient: newPair }); } catch (e) { noOldR = e; }
      check("rewrapBundle: recipient rotation with a null old key refused with no-old-recipient",
        noOldR && noOldR.code === "backup/no-old-recipient");
    } finally { _rm(rcpRoot); }

    // no-old-passphrase: passphrase envelope, explicit null old key.
    var ppRoot = _tmp("rw2-pp-root");
    try {
      var ppStore = b.backup.bundleAdapterStorage({
        adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: ppRoot }),
        format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp,
      });
      await ppStore.writeBundle(VALID_ID, src);
      var noOldP = null;
      try { await ppStore.rewrapBundle(VALID_ID, { oldPassphrase: null, newPassphrase: newPp }); } catch (e) { noOldP = e; }
      check("rewrapBundle: passphrase rotation with a null old key refused with no-old-passphrase",
        noOldP && noOldP.code === "backup/no-old-passphrase");
    } finally { _rm(ppRoot); }
  } finally { _rm(src); }
}

async function testAdapterBatchPools() {
  var root = _tmp("batch-root");
  var src = _mkSrcDir({ "a.txt": "batch" });
  var oldPp = b.crypto.generateBytes(24).toString("hex");
  var newPp = b.crypto.generateBytes(24).toString("hex");
  try {
    var fsA = b.backup.bundleAdapterStorage.fsAdapter({ root: root });
    var ppStore = b.backup.bundleAdapterStorage({
      adapter: fsA, format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp, audit: false,
    });
    // Three passphrase bundles (wrappable).
    await ppStore.writeBundle(ID_A, src);
    await ppStore.writeBundle(ID_B, src);
    await ppStore.writeBundle(ID_C, src);
    // A plaintext tar bundle (no envelope -> skipped by rewrapAllBundles).
    var plainStore = b.backup.bundleAdapterStorage({ adapter: fsA, format: "tar" });
    await plainStore.writeBundle("2026-05-01T11-00-00-000Z-44444444", src);
    // A directory bundle (format-not-wrappable -> skipped in _spawn).
    var dirStore = b.backup.bundleAdapterStorage({ adapter: fsA, format: "directory" });
    var dsrc = _mkSrcDir({ "manifest.json": "{\"version\":1}" });
    try { await dirStore.writeBundle("2026-05-01T11-05-00-000Z-55555555", dsrc); }
    finally { _rm(dsrc); }

    // rewrapAllBundles with concurrency:1 drives the drain+refill loop and
    // both skip paths (directory format + no-envelope).
    var rot = await ppStore.rewrapAllBundles({ newPassphrase: newPp, concurrency: 1 });
    check("rewrapAllBundles: rotates the three passphrase bundles",
      rot.total === 5 && rot.rotated === 3);
    check("rewrapAllBundles: skips the directory + plaintext-tar bundles",
      rot.skipped === 2 && rot.failed === 0);

    // verifyAllBundles under the NEW key, concurrency:1 (drain+refill).
    var freshOk = b.backup.bundleAdapterStorage({
      adapter: fsA, format: "tar", cryptoStrategy: "passphrase", passphrase: newPp,
    });
    var vAll = await freshOk.verifyAllBundles({ concurrency: 1 });
    check("verifyAllBundles: reports a per-bundle result for every bundle",
      vAll.total === 5 && vAll.results.length === 5);

    // A store holding the WRONG passphrase makes the rotated bundles fail
    // verification -> the failed counter increments (stopOnFirstFailure).
    var wrongKey = b.backup.bundleAdapterStorage({
      adapter: fsA, format: "tar", cryptoStrategy: "passphrase",
      passphrase: b.crypto.generateBytes(24).toString("hex"),
    });
    var vFail = await wrongKey.verifyAllBundles({ stopOnFirstFailure: true });
    check("verifyAllBundles: a wrong-key store reports at least one failed bundle",
      vFail.failed >= 1);
  } finally { _rm(root); _rm(src); }
}

async function testObjectStoreAdapterNoPrefixList() {
  var rootDir = _tmp("os-np-root");
  try {
    var client = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    // No prefix -> listKeys returns keys verbatim (the else branch).
    var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client);
    await adapter.writeFile("k1", Buffer.from("a"));
    await adapter.writeFile("k2", Buffer.from("bb"));
    var keys = await adapter.listKeys("");
    check("objectStoreAdapter.listKeys: no-prefix adapter returns keys verbatim",
      keys.indexOf("k1") !== -1 && keys.indexOf("k2") !== -1);
    // Uint8Array bytes are accepted + normalized to Buffer.
    await adapter.writeFile("k3", new Uint8Array([1, 2, 3]));
    var back = await adapter.readFile("k3");
    check("objectStoreAdapter.writeFile: accepts Uint8Array bytes",
      Buffer.isBuffer(back) && back.length === 3);
  } finally { _rm(rootDir); }
}

async function testObjectStoreAdapterRethrowsUnexpectedErrors() {
  // A client that throws a NON-NOT_FOUND error must NOT be swallowed —
  // the adapter's NOT_FOUND translation is deliberately narrow.
  var boom = new Error("upstream-503");
  var client = {
    put:    async function () { throw boom; },
    get:    async function () { throw boom; },
    head:   async function () { throw boom; },
    delete: async function () { throw boom; },
    list:   async function () { throw boom; },
  };
  var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client);
  var checks = [
    ["readFile",    function () { return adapter.readFile("k"); }],
    ["deleteKey",   function () { return adapter.deleteKey("k"); }],
    ["hasKey",      function () { return adapter.hasKey("k"); }],
    ["readPartial", function () { return adapter.readPartial("k", 4); }],
    ["statKey",     function () { return adapter.statKey("k"); }],
  ];
  for (var i = 0; i < checks.length; i += 1) {
    var name = checks[i][0];
    var thrown = null;
    try { await checks[i][1](); } catch (e) { thrown = e; }
    check("objectStoreAdapter." + name + ": a non-NOT_FOUND error is rethrown, not swallowed",
      thrown === boom);
  }

  // A client whose delete raises the framework's NOT_FOUND convention is
  // treated as an idempotent no-op (the adapter delete contract).
  var notFound = Object.assign(new Error("gone"), { code: "NOT_FOUND" });
  var nfClient = {
    put: async function () {}, get: async function () {}, head: async function () {},
    delete: async function () { throw notFound; }, list: async function () { return { items: [] }; },
  };
  var nfAdapter = b.backup.bundleAdapterStorage.objectStoreAdapter(nfClient);
  var delThrew = null;
  try { await nfAdapter.deleteKey("k"); } catch (e) { delThrew = e; }
  check("objectStoreAdapter.deleteKey: a NOT_FOUND delete is swallowed (idempotent)",
    delThrew === null);
}

async function testObjectStoreAdapterPaginationRunaway() {
  // A misbehaving backend that reports truncated:true forever (with a
  // continuation token) is refused after the pagination cap rather than
  // spinning indefinitely.
  var calls = 0;
  var client = {
    put:    async function () {},
    get:    async function () { return Buffer.alloc(0); },
    head:   async function () { return { size: 0 }; },
    delete: async function () {},
    list:   async function () {
      calls += 1;
      return { items: [{ key: "runaway/key" }], truncated: true, continuationToken: "next" };
    },
  };
  var adapter = b.backup.bundleAdapterStorage.objectStoreAdapter(client);
  var thrown = null;
  try { await adapter.listKeys(""); } catch (e) { thrown = e; }
  check("objectStoreAdapter.listKeys: runaway pagination refused with list-pagination-runaway",
    thrown && thrown.code === "backup/list-pagination-runaway" && calls > 1000);
}

async function testRewrapAllBundlesFailedPath() {
  // A bundle whose passphrase payload is corrupt makes rewrapBundle fail
  // with a crypto (non "no-envelope") error -> rewrapAllBundles records
  // it in the failed bucket (stopOnFirstFailure aborts the walk).
  var root = _tmp("rwa-fail-root");
  var src = _mkSrcDir({ "a.txt": "x" });
  var oldPp = b.crypto.generateBytes(24).toString("hex");
  var newPp = b.crypto.generateBytes(24).toString("hex");
  try {
    var adapter = b.backup.bundleAdapterStorage.fsAdapter({ root: root });
    var store = b.backup.bundleAdapterStorage({
      adapter: adapter, format: "tar", cryptoStrategy: "passphrase", passphrase: oldPp, audit: false,
    });
    await store.writeBundle(ID_A, src);
    // Corrupt the sealed AEAD body while preserving the passphrase
    // envelope magic header — the bundle is still detected as a
    // passphrase envelope but authentication fails on unwrap, so
    // rewrapBundle rejects with a crypto (non "no-envelope") error.
    var sealed = await adapter.readFile(ID_A + "/bundle.tar");
    var corrupt = Buffer.from(sealed);
    for (var ci = corrupt.length - 8; ci < corrupt.length; ci += 1) corrupt[ci] = corrupt[ci] ^ 0xff;
    await adapter.writeFile(ID_A + "/bundle.tar", corrupt);
    var rep = await store.rewrapAllBundles({ newPassphrase: newPp, stopOnFirstFailure: true });
    check("rewrapAllBundles: a crypto failure lands in the failed bucket",
      rep.failed >= 1 && rep.rotated === 0);
  } finally { _rm(root); _rm(src); }
}

// ---- db-backed: residency mismatch + signed-manifest restore drill ----

// setupTestDb doesn't expose dataResidency, so this mirrors its
// reset+init sequence but declares a db residency region. A real
// vault + audit chain means backupBundle.create signs the manifest,
// which the drill's signature-verify step needs to reach the PASSED
// path. Runs LAST + tears the framework fully back down.
async function testDbBackedResidencyAndDrillPass() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bidx-db-"));
  helpers.setTestPassphraseEnv();
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir:             tmpDir,
    tmpDir:              path.join(tmpDir, "tmpfs"),
    allowNonTmpfsTmpDir: true,
    dataResidency:       { region: "eu-west-1" },
    schema:              [],
  });

  var data = _tmp("db-data");
  var root = _tmp("db-root");
  var root2 = _tmp("db-root2");
  var storeRoot = _tmp("db-store");
  var restore = _tmp("db-restore");
  var PP = Buffer.from("operator-backup-passphrase-256bit-entropy-here");
  try {
    fs.writeFileSync(path.join(data, "db.enc"), Buffer.from("ENVELOPE-BYTES"));
    fs.writeFileSync(path.join(data, "db.key.enc"), Buffer.from("SEALED-DEK-BYTES"));

    // Residency mismatch: db region eu-west-1 vs backup residencyTag
    // us-east-1 under gdpr posture, no allowCrossBorder -> refused.
    b.compliance.clear();
    b.compliance.set("gdpr");
    var mismatch = null;
    try {
      b.backup.create({
        dataDir: data, storage: b.backup.diskStorage({ root: root }), passphrase: PP,
        files: [{ relativePath: "db.enc", kind: "raw", required: true }],
        vaultKeyJson: '{"version":1}', residencyTag: "us-east-1",
      });
    } catch (e) { mismatch = e; }
    check("create: gdpr + db residency != backup residencyTag refused with residency-mismatch",
      mismatch && mismatch.code === "backup/residency-mismatch");

    // allowCrossBorder + legalBasis suppresses the mismatch throw.
    var okCross = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: root2 }), passphrase: PP,
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"version":1}', residencyTag: "us-east-1",
      allowCrossBorder: true, legalBasis: "EU SCCs 2021/914",
    });
    check("create: allowCrossBorder + legalBasis suppresses the residency mismatch",
      okCross && typeof okCross.run === "function");
    b.compliance.clear();

    // Signed-manifest restore drill -> PASSED path (no posture so the
    // create() residency gate stays out of the way of the run).
    var sched = _capturingScheduler();
    var eng = b.backup.create({
      dataDir: data, storage: b.backup.diskStorage({ root: storeRoot }), passphrase: PP,
      files: [
        { relativePath: "db.enc",     kind: "raw", required: true },
        { relativePath: "db.key.enc", kind: "raw", required: true },
      ],
      vaultKeyJson: '{"version":1,"kid":"k1"}', scheduler: sched,
    });
    var r = await eng.run();
    var manifest = JSON.parse(
      fs.readFileSync(path.join(storeRoot, r.bundleId, "manifest.json"), "utf8"));
    check("db-drill: the stored manifest carries a real signature block",
      manifest.signature && typeof manifest.signature.value === "string" &&
      manifest.signature.value.length > 0);

    var verifyCtx = null;
    var notify = [];
    eng.scheduleTest({
      cron: "0 3 * * 0", restoreTo: restore, posture: "hipaa",
      verify: async function (ctx) { verifyCtx = ctx; return true; },
      notify: async function (info) { notify.push(info); },
    });
    await sched.specs[0].run();
    check("db-drill: PASSED path handed the operator a verified-signature manifest + fingerprint",
      verifyCtx !== null && verifyCtx.bundleId === r.bundleId &&
      typeof verifyCtx.sigFingerprint === "string" && verifyCtx.sigFingerprint.length > 0 &&
      verifyCtx.manifest && verifyCtx.manifest.version === 1);
    check("db-drill: notify hook fired with a success outcome on the passing drill",
      notify.length === 1 && notify[0].outcome === "success" && notify[0].bundleId === r.bundleId);
    check("db-drill: the drill cleaned its staging dir after a passing run",
      !fs.existsSync(verifyCtx.outDir));
  } finally {
    b.compliance.clear();
    _rm(data); _rm(root); _rm(root2); _rm(storeRoot); _rm(restore);
    await helpers.teardownTestDb(tmpDir);
  }
}

async function run() {
  testDiskStorageValidatesRoot();
  await testDiskStorageBadBundleId();
  await testDiskStorageBundleExistsAndNotFound();
  await testDiskStorageListFiltersAndEmpty();
  await testDiskStorageDeleteAndHasNoop();

  testCreateResidencyTagValidation();
  testCreateScheduleRequiresScheduler();
  testCreateScheduleArgValidation();
  await testCreateRequireFlushHardFails();
  testCreateHipaaRefusesUnencrypted();

  testVerifyManifestSignatureBadTarget();
  testVerifyManifestSignatureNoManifest();
  testVerifyManifestSignatureBadManifest();
  testVerifyManifestSignatureParsedObject();
  await testVerifyManifestSignatureOnDiskStringPath();

  testAdapterStorageConstructionValidation();
  testAdapterStorageEntropyFloorValidation();
  testAdapterStorageMaxBundleBytesValidation();
  testAdapterStoragePostureGateOptIn();
  await testAdapterStorageBundleTooLarge();
  await testAdapterStoragePassphraseFloorEnforcedOnWrite();
  await testAdapterStorageDirectoryRoundTrip();
  await testAdapterStorageTarVerifyAndMissing();

  await testFsAdapterTraversalRefused();
  await testFsAdapterReadPartialAndStat();

  await testMigrateValidation();
  await testMigrateDirectoryToTarRoundTrip();

  testRecommendedFiles();
  await testDiskStorageReadDestExists();
  testCreateConstructionValidation();
  await testCreateScheduleClosureRuns();

  await testCreateRunRoundTripAndRetention();
  await testCreateRunFlushWarningBestEffort();
  await testCreateRunVaultKeyJsonFailures();
  await testCreateRunBackupBundleFailure();
  await testCreateRunStorageWriteFailure();
  await testCreateRetentionSweepFailure();
  await testCreatePurgeOlderPerBundleDeleteFailure();
  await testCreateDeleteReadBadId();
  testCreateResidencyUndeclaredWarning();
  testCreateResidencyPerRowCrossBorder();

  await testAdapterTarGzRoundTrip();
  await testAdapterPassphraseRoundTrip();
  await testAdapterRecipientRoundTrip();
  await testAdapterListBundlesWithStats();
  await testAdapterVerifyBundleErrorBranches();
  await testAdapterFindBundles();
  await testAdapterCloneBundle();
  await testAdapterRewrapBundleBranches();
  await testAdapterKeyRotationBranches();
  await testMemAdapterLegacyBranches();
  await testAdapterHipaaPassphraseFloorAndBadId();
  await testAdapterReadBundleNotFoundAndCryptoTarReads();
  await testAdapterDirectoryListWithStats();
  await testAdapterRewrapUnknownAndMissingKeys();
  await testAdapterBatchPools();

  await testRewrapAllBundlesFailedPath();

  testObjectStoreAdapterPrefixValidation();
  await testObjectStoreAdapterKeyValidationAndMisses();
  await testObjectStoreAdapterBundleRoundTrip();
  await testObjectStoreAdapterNoPrefixList();
  await testObjectStoreAdapterRethrowsUnexpectedErrors();
  await testObjectStoreAdapterPaginationRunaway();

  await testMigrateSingleIdAndDeleteSource();

  await testRunInWorkerValidation();
  await testRunInWorkerLifecycle();

  await testScheduleTestDrillFailurePaths();

  // db-backed group — runs last, tears the framework fully back down.
  await testDbBackedResidencyAndDrillPass();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-index] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
