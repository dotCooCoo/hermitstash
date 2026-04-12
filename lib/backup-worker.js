"use strict";

/**
 * Backup worker — runs in a worker_thread to avoid blocking the main event loop.
 *
 * Receives: { passphrase, dataDir, s3Config, scope, retention, storageBackend, uploadDir, version }
 * Posts back: { manifest } on success, { error } on failure.
 */

var { parentPort, workerData } = require("worker_threads");
var fs = require("fs/promises");
var fsSync = require("fs");
var path = require("path");
var crypto = require("crypto");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var argon2 = require("./vendor/argon2");
var S3Client = require("./s3-client");

var DATA_DIR = workerData.dataDir;

// ---- SHA3-512 hash (standalone, no lib/crypto dependency) ----

function sha3Hash(data) {
  return crypto.createHash("sha3-512").update(data).digest("hex");
}

// ---- Vault key encryption ----

async function encryptVaultKey(passphrase) {
  var vaultKeyData = await fs.readFile(path.join(DATA_DIR, "vault.key"), "utf8");

  var salt = crypto.randomBytes(32);
  var hash = await argon2.hash(passphrase, {
    type: 2,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    salt: salt,
    hashLength: 32,
    raw: true,
  });

  var nonce = crypto.randomBytes(24);
  var plaintext = Buffer.from(vaultKeyData, "utf8");
  var ct = xchacha20poly1305(new Uint8Array(hash), nonce).encrypt(new Uint8Array(plaintext));

  return {
    encrypted: Buffer.concat([nonce, Buffer.from(ct)]),
    salt: salt.toString("hex"),
  };
}

// ---- Checksum ----

function bufferChecksum(buf) { return sha3Hash(buf); }

// ---- Walk uploads directory ----

async function walkUploads(dir) {
  var results = [];
  try {
    var entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (_e) { return results; }
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) {
      var sub = await walkUploads(full);
      results.push.apply(results, sub);
    } else if (entries[i].isFile()) {
      results.push(full);
    }
  }
  return results;
}

// ---- Run backup ----

async function runBackup() {
  var t0 = Date.now();
  var passphrase = workerData.passphrase;
  var scope = workerData.scope || "db";
  var retention = workerData.retention || 7;
  var backend = new S3Client(workerData.s3Config);

  var timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  var prefix = "backups/" + timestamp + "/";

  var manifest = {
    version: 1,
    timestamp: new Date().toISOString(),
    scope: scope,
    hermitstashVersion: workerData.version,
    argon2Salt: null,
    files: {},
    uploads: {},
    stats: { dbFiles: 0, uploadFiles: 0, totalSize: 0, durationMs: 0 },
  };

  // 1. Encrypt vault.key with passphrase
  var vaultResult = await encryptVaultKey(passphrase);
  manifest.argon2Salt = vaultResult.salt;

  await backend.put(prefix + "vault.key.enc", vaultResult.encrypted);
  manifest.files["vault.key.enc"] = { s3Key: prefix + "vault.key.enc", size: vaultResult.encrypted.length, checksum: bufferChecksum(vaultResult.encrypted) };
  manifest.stats.dbFiles++;
  manifest.stats.totalSize += vaultResult.encrypted.length;

  // 2. Copy db.key.enc (already vault-sealed)
  var dbKeyPath = path.join(DATA_DIR, "db.key.enc");
  try {
    var dbKeyBuf = await fs.readFile(dbKeyPath);
    await backend.put(prefix + "db.key.enc", dbKeyBuf);
    manifest.files["db.key.enc"] = { s3Key: prefix + "db.key.enc", size: dbKeyBuf.length, checksum: bufferChecksum(dbKeyBuf) };
    manifest.stats.dbFiles++;
    manifest.stats.totalSize += dbKeyBuf.length;
  } catch (_e) { /* db.key.enc may not exist */ }

  // 3. Copy hermitstash.db.enc (already encrypted)
  var dbEncPath = path.join(DATA_DIR, "hermitstash.db.enc");
  try {
    var dbEncBuf = await fs.readFile(dbEncPath);
    await backend.put(prefix + "hermitstash.db.enc", dbEncBuf);
    manifest.files["hermitstash.db.enc"] = { s3Key: prefix + "hermitstash.db.enc", size: dbEncBuf.length, checksum: bufferChecksum(dbEncBuf) };
    manifest.stats.dbFiles++;
    manifest.stats.totalSize += dbEncBuf.length;
  } catch (_e) { /* db file may not exist */ }

  // 4. Upload files (if full scope, local storage only)
  if (scope === "full" && workerData.storageBackend === "local") {
    var uploadDir = workerData.uploadDir;

    // Load previous manifest for incremental diff
    var prevUploads = {};
    try {
      var manifests = await backend.list("backups/");
      var manifestKeys = manifests.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();
      if (manifestKeys.length > 0) {
        var prevData = await backend.getBuffer(manifestKeys[manifestKeys.length - 1]);
        var prevManifest = JSON.parse(prevData.toString("utf8"));
        prevUploads = prevManifest.uploads || {};
      }
    } catch (_e) { /* no previous manifest */ }

    var files = await walkUploads(uploadDir);
    for (var i = 0; i < files.length; i++) {
      var relPath = path.relative(uploadDir, files[i]).replace(/\\/g, "/");
      var fileBuf = await fs.readFile(files[i]);
      var checksum = sha3Hash(fileBuf);
      var s3Key = "backups/uploads/" + relPath;

      if (prevUploads[relPath] && prevUploads[relPath].checksum === checksum) {
        manifest.uploads[relPath] = prevUploads[relPath];
        manifest.stats.uploadFiles++;
        continue;
      }

      await backend.put(s3Key, fileBuf);
      manifest.uploads[relPath] = { s3Key: s3Key, size: fileBuf.length, checksum: checksum, backedUpAt: new Date().toISOString() };
      manifest.stats.uploadFiles++;
      manifest.stats.totalSize += fileBuf.length;
    }
  }

  // Note: full scope with s3 storage backend is not supported in the worker
  // because it requires DB access. This falls back to db-only scope.

  // 5. Upload manifest
  manifest.stats.durationMs = Date.now() - t0;
  var manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
  await backend.put(prefix + "manifest.json", manifestBuf);

  // 6. Verify manifest
  var verifyBuf = await backend.getBuffer(prefix + "manifest.json");
  if (bufferChecksum(verifyBuf) !== bufferChecksum(manifestBuf)) {
    throw new Error("Manifest verification failed");
  }

  // 7. Retention pruning
  await pruneBackups(backend, retention);

  return manifest;
}

// ---- Retention pruning ----

async function pruneBackups(backend, retention) {
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();
  if (manifestKeys.length <= retention) return;

  var toDelete = manifestKeys.slice(0, manifestKeys.length - retention);
  var keepUploads = new Set();
  var keepManifests = manifestKeys.slice(manifestKeys.length - retention);

  for (var i = 0; i < keepManifests.length; i++) {
    try {
      var data = await backend.getBuffer(keepManifests[i]);
      var m = JSON.parse(data.toString("utf8"));
      if (m.uploads) Object.keys(m.uploads).forEach(function (k) { if (m.uploads[k].s3Key) keepUploads.add(m.uploads[k].s3Key); });
    } catch (_e) {}
  }

  for (var j = 0; j < toDelete.length; j++) {
    var manifestPrefix = toDelete[j].replace("manifest.json", "");
    var prefixKeys = allKeys.filter(function (k) { return k.startsWith(manifestPrefix); });
    for (var k = 0; k < prefixKeys.length; k++) await backend.del(prefixKeys[k]);
  }

  var uploadKeys = allKeys.filter(function (k) { return k.startsWith("backups/uploads/"); });
  for (var l = 0; l < uploadKeys.length; l++) {
    if (!keepUploads.has(uploadKeys[l])) await backend.del(uploadKeys[l]);
  }
}

// ---- Entry point ----

runBackup()
  .then(function (manifest) { parentPort.postMessage({ manifest: manifest }); })
  .catch(function (err) { parentPort.postMessage({ error: err.message }); });
