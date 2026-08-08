// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backupBundle.create refusal-path coverage.
 *
 * The include list is operator-supplied, so every malformed entry fails
 * closed before anything is written: a missing relativePath, a directory
 * where a file was named, an unknown blob kind. Signing is best-effort by
 * design — a process outside the framework's boot sequence emits an unsigned
 * bundle rather than failing — but any OTHER signer failure is fatal unless
 * the caller explicitly opts into tolerating it.
 *
 * A progress callback is operator code running inside the bundler, so it is
 * isolated: a throwing callback must not abort a backup in flight.
 */

var nodeFs = require("node:fs");
var nodeOs = require("node:os");
var nodePath = require("node:path");
var helpers = require("../helpers");

var b = helpers.b;
var check = helpers.check;

var PASSPHRASE = "operator passphrase";
var VAULT_KEY_JSON = "{\"publicKey\":\"pk\",\"privateKey\":\"sk\"}";

var _tmpDirs = [];

// A data dir holding one real file plus a subdirectory (for the
// directory-named-as-a-file case).
function _makeDataDir() {
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "bbc-data-"));
  _tmpDirs.push(dir);
  nodeFs.writeFileSync(nodePath.join(dir, "db.enc"), "database-bytes", { mode: 0o600 });
  nodeFs.mkdirSync(nodePath.join(dir, "subdir"));
  return dir;
}

// A path that does NOT exist yet — create() refuses to overwrite.
function _freshOutDir() {
  var base = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "bbc-out-"));
  _tmpDirs.push(base);
  return nodePath.join(base, "bundle");
}

function _baseOpts(over) {
  var opts = {
    dataDir:      _makeDataDir(),
    outDir:       _freshOutDir(),
    passphrase:   PASSPHRASE,
    vaultKeyJson: VAULT_KEY_JSON,
    files:        [{ relativePath: "db.enc", kind: "raw", required: true }],
  };
  return Object.assign(opts, over || {});
}

async function _refuses(label, opts, code) {
  var err = null;
  try { await b.backupBundle.create(opts); } catch (e) { err = e; }
  check(label, !!err && err.name === "BackupBundleError" && err.code === code);
}

async function testRequiredOptionGuards() {
  await _refuses("create: no arguments at all is refused",
    undefined, "backup-bundle/no-datadir");

  await _refuses("create: a missing dataDir is refused",
    _baseOpts({ dataDir: nodePath.join(nodeOs.tmpdir(), "bbc-does-not-exist-" + process.pid) }),
    "backup-bundle/no-datadir");
  await _refuses("create: a non-string dataDir is refused",
    _baseOpts({ dataDir: 42 }), "backup-bundle/no-datadir");

  await _refuses("create: a numeric passphrase is refused",
    _baseOpts({ passphrase: 12345 }), "backup-bundle/no-passphrase");
  await _refuses("create: an absent passphrase is refused",
    _baseOpts({ passphrase: undefined }), "backup-bundle/no-passphrase");

  await _refuses("create: an absent vaultKeyJson is refused",
    _baseOpts({ vaultKeyJson: undefined }), "backup-bundle/no-vault-key-json");
  await _refuses("create: an empty vaultKeyJson is refused",
    _baseOpts({ vaultKeyJson: "" }), "backup-bundle/no-vault-key-json");
  await _refuses("create: a non-string vaultKeyJson is refused",
    _baseOpts({ vaultKeyJson: { publicKey: "pk" } }), "backup-bundle/no-vault-key-json");

  await _refuses("create: an empty include list is refused",
    _baseOpts({ files: [] }), "backup-bundle/no-files");
  await _refuses("create: a non-array include list is refused",
    _baseOpts({ files: "db.enc" }), "backup-bundle/no-files");

  // Refusing to overwrite an existing outDir is what stops a second run from
  // silently merging into (or clobbering) a previous bundle.
  var existing = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "bbc-exists-"));
  _tmpDirs.push(existing);
  await _refuses("create: an outDir that already exists is refused",
    _baseOpts({ outDir: existing }), "backup-bundle/outdir-exists");
}

async function testIncludeEntryGuards() {
  await _refuses("create: an include entry without relativePath is refused",
    _baseOpts({ files: [{ kind: "raw" }] }), "backup-bundle/bad-include");
  await _refuses("create: a null include entry is refused",
    _baseOpts({ files: [null] }), "backup-bundle/bad-include");
  await _refuses("create: an empty relativePath is refused",
    _baseOpts({ files: [{ relativePath: "" }] }), "backup-bundle/bad-include");
  await _refuses("create: a non-string relativePath is refused",
    _baseOpts({ files: [{ relativePath: 7 }] }), "backup-bundle/bad-include");

  // Traversal, absolute, and data-stream shapes are refused before the path
  // is resolved against dataDir.
  await _refuses("create: a parent-traversal relativePath is refused",
    _baseOpts({ files: [{ relativePath: "../outside.txt" }] }), "backup-bundle/bad-include");
  await _refuses("create: a leading-slash relativePath is refused",
    _baseOpts({ files: [{ relativePath: "/etc/passwd" }] }), "backup-bundle/bad-include");
  await _refuses("create: a leading-backslash relativePath is refused",
    _baseOpts({ files: [{ relativePath: "\\windows\\system32" }] }), "backup-bundle/bad-include");
  await _refuses("create: a drive-letter relativePath is refused",
    _baseOpts({ files: [{ relativePath: "C:/secrets.txt" }] }), "backup-bundle/bad-include");
  await _refuses("create: an NTFS data-stream relativePath is refused",
    _baseOpts({ files: [{ relativePath: "db.enc:evil" }] }), "backup-bundle/bad-include");

  // A directory is not a file — the bundler takes a flat list, so naming one
  // is a caller error rather than a silent recursive sweep.
  await _refuses("create: a directory named as a file is refused",
    _baseOpts({ files: [{ relativePath: "subdir", required: true }] }),
    "backup-bundle/not-a-file");

  // An unknown blob kind is refused rather than defaulted — kind drives how a
  // restore treats the blob.
  await _refuses("create: an unknown blob kind is refused",
    _baseOpts({ files: [{ relativePath: "db.enc", kind: "bogus" }] }),
    "backup-bundle/bad-kind");
}

async function testMissingFileHandling() {
  // A required file that is absent aborts the backup.
  await _refuses("create: an absent REQUIRED file aborts the bundle",
    _baseOpts({ files: [{ relativePath: "nope.dat", required: true }] }),
    "backup-bundle/missing-required");

  // An absent optional file is skipped and announced.
  var events = [];
  var res = await b.backupBundle.create(_baseOpts({
    files: [
      { relativePath: "nope.dat", required: false },
      { relativePath: "db.enc", required: true },
    ],
    progressCallback: function (ev) { events.push(ev); },
  }));
  check("create: an absent OPTIONAL file is skipped, not fatal", res.fileCount === 1);
  check("create: the skip is announced with its path",
    events.some(function (e) { return e.phase === "skip_missing" && e.relativePath === "nope.dat"; }));
  check("create: the bundled file is the one that existed",
    res.manifest.files.length === 1 && res.manifest.files[0].relativePath === "db.enc");

  // If every entry is skipped there is nothing to back up — emitting an empty
  // manifest would look like a successful backup of nothing.
  await _refuses("create: a bundle where every entry was skipped is refused",
    _baseOpts({ files: [{ relativePath: "nope.dat", required: false }] }),
    "backup-bundle/empty");
}

async function testProgressCallbackIsIsolated() {
  // Operator code inside the bundler must not be able to abort a backup.
  var calls = 0;
  var res = await b.backupBundle.create(_baseOpts({
    progressCallback: function () { calls++; throw new Error("callback exploded"); },
  }));
  check("progress: a throwing callback does not abort the bundle", res.fileCount === 1);
  check("progress: the throwing callback was actually invoked", calls > 0);
  check("progress: the manifest was still written",
    nodeFs.existsSync(res.manifestPath));

  // A non-function progressCallback is ignored rather than called.
  var res2 = await b.backupBundle.create(_baseOpts({ progressCallback: "not-a-function" }));
  check("progress: a non-function callback is ignored", res2.fileCount === 1);
}

async function testSigningPosture() {
  var origSign = b.auditSign.sign;
  try {
    // Outside the framework's boot sequence there is no signer yet. That is
    // an expected posture for CLI tooling, so the bundle is emitted unsigned
    // and the reason is announced rather than failing the backup.
    b.auditSign.sign = function () {
      throw new Error("auditSign.init() must be awaited before sign/verify");
    };
    var events = [];
    var unsigned = await b.backupBundle.create(_baseOpts({
      progressCallback: function (ev) { events.push(ev); },
    }));
    check("signing: an uninitialized signer yields an unsigned bundle",
      unsigned.manifest.signature === undefined);
    check("signing: the unsigned bundle announces the uninitialized signer",
      events.some(function (e) {
        return e.phase === "manifest-unsigned" && e.reason === "audit-sign-not-initialized";
      }));

    // Any OTHER signer failure is fatal by default — an operator who asked
    // for a signed bundle must not silently receive an unsigned one.
    b.auditSign.sign = function () { throw new Error("hsm offline"); };
    await _refuses("signing: an unexpected signer failure is fatal by default",
      _baseOpts({}), "backup-bundle/sign-failed");

    // ...unless the caller explicitly accepts an unsigned bundle.
    var optEvents = [];
    var tolerated = await b.backupBundle.create(_baseOpts({
      signOptional:     true,
      progressCallback: function (ev) { optEvents.push(ev); },
    }));
    check("signing: signOptional tolerates the failure and emits unsigned",
      tolerated.manifest.signature === undefined);
    check("signing: the tolerated failure reports the underlying cause",
      optEvents.some(function (e) {
        return e.phase === "manifest-unsigned" && /hsm offline/.test(e.reason || "");
      }));

    // sign:false skips signing entirely — the signer is never consulted.
    var consulted = 0;
    b.auditSign.sign = function () { consulted++; throw new Error("should not be called"); };
    var notSigned = await b.backupBundle.create(_baseOpts({ sign: false }));
    check("signing: sign:false emits an unsigned bundle",
      notSigned.manifest.signature === undefined);
    check("signing: sign:false never consults the signer at all", consulted === 0);
  } finally {
    b.auditSign.sign = origSign;
  }
}

async function testBundleShape() {
  var events = [];
  var res = await b.backupBundle.create(_baseOpts({
    metadata:         { reason: "coverage" },
    progressCallback: function (ev) { events.push(ev); },
  }));

  check("bundle: the manifest is written last, as the completeness tell",
    nodeFs.existsSync(res.manifestPath));
  check("bundle: the blob is written under files/ with an .enc stride",
    res.manifest.files[0].encryptedPath === "files/db.enc.enc" &&
    nodeFs.existsSync(nodePath.join(res.outDir, "files", "db.enc.enc")));
  check("bundle: metadata is carried into the manifest",
    res.manifest.metadata && res.manifest.metadata.reason === "coverage");
  check("bundle: blobs are marked as bound to their path",
    res.manifest.aadBound === true);
  check("bundle: the plaintext size is recorded, not the ciphertext size",
    res.manifest.files[0].size === Buffer.byteLength("database-bytes"));
  check("bundle: the ciphertext is larger than the plaintext (nonce + tag)",
    res.manifest.files[0].encryptedSize > res.manifest.files[0].size);
  check("bundle: the blob on disk is not the plaintext",
    nodeFs.readFileSync(nodePath.join(res.outDir, "files", "db.enc.enc")).indexOf("database-bytes") === -1);
  check("bundle: the reported size is the total ciphertext written",
    res.bundleSize === res.manifest.files[0].encryptedSize);
  check("bundle: progress reports the terminal phase with a file count",
    events.some(function (e) { return e.phase === "done" && e.fileCount === 1; }));
}

async function run() {
  try {
    await testRequiredOptionGuards();
    await testIncludeEntryGuards();
    await testMissingFileHandling();
    await testProgressCallbackIsIsolated();
    await testSigningPosture();
    await testBundleShape();
  } finally {
    _tmpDirs.forEach(function (d) {
      try { nodeFs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
    });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-bundle-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
