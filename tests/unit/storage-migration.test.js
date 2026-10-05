var scratch = require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * migrateStorage("local-to-s3") reads each local object through
 * storage.getFileStream with no key: the file is opened with O_NOFOLLOW and
 * read as a stream, and a file larger than storage.LOCAL_READ_CAP fails. A
 * symlink at an upload path is refused, and the file it points to is not
 * uploaded.
 *
 * The symlink case needs a host that can create symbolic links, so it runs on
 * Linux CI and in Docker and is skipped where creating one fails.
 */
var fs = require("node:fs");
var path = require("node:path");
process.env.HERMITSTASH_DATA_DIR = scratch.dir;
process.env.UPLOAD_DIR = path.join(scratch.dir, "uploads");
process.env.MOCK_S3_STORE = path.join(scratch.dir, "mock-s3.json");
fs.mkdirSync(process.env.UPLOAD_DIR, { recursive: true });

// Replaces lib/s3-client with the file-backed mock for every later require.
require("../helpers/mock-s3-preload");

var { describe, it, before } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var vault = require("../../lib/vault");
var config = require("../../lib/config");
var filesRepo = require("../../app/data/repositories/files.repo");
var migration = require("../../app/domain/admin/storage-migration.service");

var BUCKET = "hs-migration-test";
var OVER_64_MIB = b.constants.BYTES.mib(64) + 1;

var canSymlink = (function () {
  try {
    var probeDir = fs.mkdtempSync(path.join(scratch.dir, "probe-"));
    fs.writeFileSync(path.join(probeDir, "t"), "x");
    fs.symlinkSync(path.join(probeDir, "t"), path.join(probeDir, "l"));
    return true;
  } catch (_e) { return false; }
})();

function storedObject(key) {
  var store = JSON.parse(fs.readFileSync(process.env.MOCK_S3_STORE, "utf8"));
  var b64 = store[BUCKET] && store[BUCKET][key];
  return b64 == null ? null : Buffer.from(b64, "base64");
}

function seedFile(shareId, storagePath) {
  return filesRepo.create({
    shareId: shareId, bundleShareId: "bundle-" + shareId, bundleId: "b-" + shareId,
    originalName: path.basename(storagePath), relativePath: path.basename(storagePath),
    storagePath: storagePath, status: "complete", size: 1, createdAt: new Date().toISOString(),
  });
}

function writeUpload(storagePath, data) {
  var abs = path.join(process.env.UPLOAD_DIR, storagePath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, data);
  return abs;
}

var smallData = Buffer.from("small ciphertext");
var outsideSecret = path.join(scratch.dir, "outside-secret.txt");
var linkPath = null;
var result;

before(async function () {
  await vault.init();
  config.storage.s3 = { bucket: BUCKET, accessKey: "test-access", secretKey: "test-secret", endpoint: "", region: "us-east-1" };

  writeUpload("bundles/a/small.bin", smallData);
  seedFile("migsmall0001", "bundles/a/small.bin");

  if (canSymlink) {
    fs.writeFileSync(outsideSecret, "outside the upload directory");
    linkPath = path.join(process.env.UPLOAD_DIR, "bundles/b/link.bin");
    fs.mkdirSync(path.dirname(linkPath), { recursive: true });
    fs.symlinkSync(outsideSecret, linkPath);
    seedFile("miglink00001", "bundles/b/link.bin");
  }

  writeUpload("bundles/c/large.bin", Buffer.alloc(OVER_64_MIB, 7));
  seedFile("miglarge0001", "bundles/c/large.bin");

  result = await migration.migrateStorage("local-to-s3");
});

describe("local-to-S3 storage migration", function () {
  it("copies a local object to S3, records its S3 path and removes the local copy", function () {
    assert.ok(storedObject("bundles/a/small.bin").equals(smallData));
    assert.strictEqual(filesRepo.findByShareId("migsmall0001").storagePath, "s3://" + BUCKET + "/bundles/a/small.bin");
    assert.strictEqual(fs.existsSync(path.join(process.env.UPLOAD_DIR, "bundles/a/small.bin")), false);
  });

  it("migrates an object larger than 64 MiB", function () {
    var got = storedObject("bundles/c/large.bin");
    assert.ok(got, "the object reached S3: " + JSON.stringify(result.errors));
    assert.strictEqual(got.length, OVER_64_MIB);
    assert.strictEqual(filesRepo.findByShareId("miglarge0001").storagePath, "s3://" + BUCKET + "/bundles/c/large.bin");
  });

  it("refuses a symlink planted at an upload path and uploads nothing for it", { skip: !canSymlink && "this host cannot create symbolic links" }, function () {
    assert.strictEqual(storedObject("bundles/b/link.bin"), null, "the linked file must not reach S3");
    assert.strictEqual(filesRepo.findByShareId("miglink00001").storagePath, "bundles/b/link.bin");
    assert.ok(result.errors.some(function (e) { return e.file === "miglink00001"; }), JSON.stringify(result.errors));
    assert.strictEqual(fs.readFileSync(outsideSecret, "utf8"), "outside the upload directory");
    assert.ok(fs.lstatSync(linkPath).isSymbolicLink(), "the planted link is left in place");
  });

  it("migrates both regular files and fails only the planted link", function () {
    assert.strictEqual(result.migrated, 2, JSON.stringify(result));
    assert.deepStrictEqual(result.errors.map(function (e) { return e.file; }),
      canSymlink ? ["miglink00001"] : [], JSON.stringify(result));
  });
});

describe("a file larger than the local read cap", function () {
  var capResult;

  before(async function () {
    var storage = require("../../lib/storage");
    writeUpload("bundles/d/over-cap.bin", Buffer.alloc(2048, 9));
    seedFile("migovercap01", "bundles/d/over-cap.bin");
    var savedCap = storage.LOCAL_READ_CAP;
    storage.LOCAL_READ_CAP = 1024;
    try {
      capResult = await migration.migrateStorage("local-to-s3");
    } finally {
      storage.LOCAL_READ_CAP = savedCap;
    }
  });

  it("is not uploaded, stays on local disk and is reported as failed", function () {
    assert.strictEqual(storedObject("bundles/d/over-cap.bin"), null, "the file must not reach S3");
    assert.strictEqual(filesRepo.findByShareId("migovercap01").storagePath, "bundles/d/over-cap.bin");
    assert.ok(fs.existsSync(path.join(process.env.UPLOAD_DIR, "bundles/d/over-cap.bin")), "the local copy stays");
    var failure = capResult.errors.find(function (e) { return e.file === "migovercap01"; });
    assert.ok(failure && /larger than 1024 bytes/.test(failure.error), JSON.stringify(capResult.errors));
  });
});
