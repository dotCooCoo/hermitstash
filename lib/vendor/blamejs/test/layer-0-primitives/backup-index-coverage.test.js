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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-index-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
