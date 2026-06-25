/**
 * Integration tests for the backup → restore upload-blob path.
 *
 * Drives the real lib/backup-worker.js and lib/restore-worker.js as worker
 * threads against a file-backed in-memory S3 stand-in (tests/helpers/
 * mock-s3-preload.js), so the production worker code paths run unchanged.
 *
 * Coverage:
 *   - upload blobs are content-addressed by checksum (backups/uploads/<sha3>)
 *     so a rotated-in-place ciphertext never overwrites a blob an older
 *     generation still references;
 *   - restore verifies each upload blob's checksum before writing — a corrupt
 *     blob drives failedUploads + a non-success outcome + pre-restore rollback,
 *     never a silent success.
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var { Worker } = require("node:worker_threads");

var REPO_ROOT = path.resolve(__dirname, "..", "..");
var PRELOAD = path.join(REPO_ROOT, "tests", "helpers", "mock-s3-preload.js");
var b = require(path.join(REPO_ROOT, "lib", "vendor", "blamejs"));
var { generateEncryptionKeyPair } = require(path.join(REPO_ROOT, "lib", "crypto"));

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-upload-integrity-" + tag + "-"));
}
function cleanup(d) {
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

// Run a worker script with the mock-S3 preload, returning the single posted
// message (or rejecting on worker error / nonzero exit).
function runWorker(script, workerData, storePath) {
  return new Promise(function (resolve, reject) {
    var w = new Worker(path.join(REPO_ROOT, "lib", script), {
      workerData: workerData,
      execArgv: ["--require", PRELOAD],
      env: Object.assign({}, process.env, { MOCK_S3_STORE: storePath, ARGON2_FAST: "1" }),
    });
    var settled = false;
    w.on("message", function (m) { if (!settled) { settled = true; resolve(m); } });
    w.on("error", function (e) { if (!settled) { settled = true; reject(e); } });
    w.on("exit", function (code) {
      if (!settled && code !== 0) { settled = true; reject(new Error("worker exit " + code)); }
    });
  });
}

function workerPaths(dataDir) {
  return {
    dataDir: dataDir,
    vaultKey: path.join(dataDir, "vault.key"),
    dbEnc: path.join(dataDir, "hermitstash.db.enc"),
    dbKeyEnc: path.join(dataDir, "db.key.enc"),
    caKey: path.join(dataDir, "ca.key"),
    caCert: path.join(dataDir, "ca.crt"),
    tlsDir: path.join(dataDir, "tls"),
  };
}

var PASSPHRASE = "upload-integrity-test-passphrase";
var S3_CONFIG = { bucket: "backup-bucket", region: "us-east-1", accessKey: "x", secretKey: "y", endpoint: "http://mock" };

// Seed a full-scope backup with one upload file. Returns the backup manifest.
async function seedBackup(dataDir, uploadDir, storePath, relName, content) {
  fs.writeFileSync(path.join(uploadDir, relName), content);
  var keys = generateEncryptionKeyPair();
  var manifest = await runWorker("backup-worker.js", {
    passphrase: PASSPHRASE,
    paths: workerPaths(dataDir),
    vaultKeyJson: JSON.stringify(keys),
    dbEncSnapshot: Buffer.from([0x02].concat(Array(24).fill(0)).concat([...Buffer.from("db-content")])),
    s3Config: S3_CONFIG,
    scope: "full",
    retention: 7,
    storageBackend: "local",
    s3StorageConfig: null,
    uploadDir: uploadDir,
    version: "test",
  }, storePath).then(function (m) { return m.manifest || (function () { throw new Error("backup failed: " + (m && m.error)); })(); });
  return manifest;
}

describe("backup upload blobs are content-addressed by checksum", function () {
  var dataDir, uploadDir, storePath;
  beforeEach(function () { dataDir = tmpDir("ca"); uploadDir = path.join(dataDir, "uploads"); fs.mkdirSync(uploadDir); storePath = path.join(dataDir, "store.json"); });
  afterEach(function () { cleanup(dataDir); });

  it("keys the blob by its sha3 checksum, not the shared relPath", async function () {
    var manifest = await seedBackup(dataDir, uploadDir, storePath, "f.bin", Buffer.from("hello-upload"));
    var entry = manifest.uploads["f.bin"];
    assert.ok(entry, "manifest records the upload");
    var expectedKey = "backups/uploads/" + entry.checksum;
    assert.strictEqual(entry.s3Key, expectedKey, "blob is content-addressed by checksum");
    // The blob exists at the content-addressed key in the backup bucket.
    var store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.ok(store["backup-bucket"][expectedKey], "blob stored at the checksum key");
  });
});

describe("restore verifies upload-blob checksums and fails closed", function () {
  var dataDir, uploadDir, storePath;
  beforeEach(function () { dataDir = tmpDir("rv"); uploadDir = path.join(dataDir, "uploads"); fs.mkdirSync(uploadDir); storePath = path.join(dataDir, "store.json"); });
  afterEach(function () { cleanup(dataDir); });

  it("a corrupt upload blob → non-success + pre-restore rollback (DB/vault reverted)", async function () {
    var manifest = await seedBackup(dataDir, uploadDir, storePath, "doc.bin", Buffer.from("original-bytes"));

    // Establish a distinct live pre-restore state so we can prove rollback
    // reverted the committed DB/vault files rather than leaving the restored
    // versions in place.
    fs.writeFileSync(path.join(dataDir, "vault.key"), "LIVE-VAULT", { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, "db.key.enc"), "LIVE-DBKEY", { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, "hermitstash.db.enc"), "LIVE-DBENC", { mode: 0o600 });

    // Corrupt the upload blob in the backup bucket (bitrot / tamper).
    var blobKey = manifest.uploads["doc.bin"].s3Key;
    var store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    store["backup-bucket"][blobKey] = Buffer.from("TAMPERED-DIFFERENT-BYTES").toString("base64");
    fs.writeFileSync(storePath, JSON.stringify(store));

    var msg = await runWorker("restore-worker.js", {
      passphrase: PASSPHRASE,
      timestamp: manifest.timestamp,
      paths: workerPaths(dataDir),
      uploadDir: uploadDir,
      s3Config: S3_CONFIG,
      scope: "full",
      currentStorageBackend: "local",
      s3StorageConfig: null,
      dryRun: false,
      vaultPassphraseMode: "disabled",
      currentVaultPassphrase: null,
    }, storePath);

    // The restore must NOT report success on a corrupt upload.
    assert.strictEqual(msg.type, "error", "corrupt upload → type:error, not success");
    assert.match(msg.error, /upload files could not be restored|checksum/i);

    // Rollback reverted the committed DB/vault material to the live pre-restore
    // bytes — no torn state pointing at the partial restore.
    assert.strictEqual(fs.readFileSync(path.join(dataDir, "vault.key"), "utf8"), "LIVE-VAULT");
    assert.strictEqual(fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8"), "LIVE-DBKEY");
    assert.strictEqual(fs.readFileSync(path.join(dataDir, "hermitstash.db.enc"), "utf8"), "LIVE-DBENC");
  });

  it("an intact backup restores the upload bytes verbatim and reports success", async function () {
    var manifest = await seedBackup(dataDir, uploadDir, storePath, "doc.bin", Buffer.from("original-bytes"));
    // Remove the live upload so we can confirm restore re-creates it.
    fs.rmSync(path.join(uploadDir, "doc.bin"));

    var msg = await runWorker("restore-worker.js", {
      passphrase: PASSPHRASE,
      timestamp: manifest.timestamp,
      paths: workerPaths(dataDir),
      uploadDir: uploadDir,
      s3Config: S3_CONFIG,
      scope: "full",
      currentStorageBackend: "local",
      s3StorageConfig: null,
      dryRun: false,
      vaultPassphraseMode: "disabled",
      currentVaultPassphrase: null,
    }, storePath);

    assert.strictEqual(msg.type, "success", "intact backup restores cleanly: " + (msg && msg.error));
    assert.strictEqual(msg.stats.failedUploads, 0);
    assert.strictEqual(fs.readFileSync(path.join(uploadDir, "doc.bin"), "utf8"), "original-bytes");
  });
});
