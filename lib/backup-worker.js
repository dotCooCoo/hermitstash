"use strict";

/**
 * Backup worker — runs in a worker_thread to avoid blocking the main event loop.
 *
 * Receives: { passphrase, dataDir, s3Config, scope, retention, storageBackend, s3StorageBucket, uploadDir, version }
 * Posts back: { manifest } on success, { error } on failure.
 */

var { parentPort, workerData } = require("worker_threads");
var fs = require("fs/promises");
var fsSync = require("fs");
var path = require("path");
var S3Client = require("./s3-client");
var { sha3Hash, bufferChecksum, encryptVaultKey, encryptWithPassphrase, decryptWithPassphrase, TLS_FILES } = require("./backup-crypto");

// Worker receives resolved paths from the parent. Workers can't import
// lib/constants (different thread) so the parent passes a pre-resolved subset.
var PATHS = workerData.paths || {};
var DATA_DIR = PATHS.dataDir;

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
  if (!workerData.passphrase || typeof workerData.passphrase !== "string" || !workerData.passphrase.trim()) {
    throw new Error("Backup passphrase is required and cannot be empty");
  }
  var t0 = Date.now();
  var passphrase = workerData.passphrase;
  var scope = workerData.scope || "db";
  var retention = workerData.retention || 7;
  var backend = new S3Client(workerData.s3Config);

  var timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  var prefix = "backups/" + timestamp + "/";

  var manifest = {
    version: 2,
    timestamp: new Date().toISOString(),
    scope: scope,
    hermitstashVersion: workerData.version,
    storageBackend: workerData.storageBackend || "local",
    storageBucket: (workerData.s3StorageConfig && workerData.s3StorageConfig.bucket) || null,
    argon2Salt: null,
    files: {},
    uploads: {},
    stats: { dbFiles: 0, uploadFiles: 0, totalSize: 0, durationMs: 0 },
  };

  // 1. Encrypt vault.key with passphrase
  var vaultResult = await encryptVaultKey(passphrase, DATA_DIR);
  manifest.argon2Salt = vaultResult.salt;

  await backend.put(prefix + "vault.key.enc", vaultResult.encrypted);
  manifest.files["vault.key.enc"] = { s3Key: prefix + "vault.key.enc", size: vaultResult.encrypted.length, checksum: bufferChecksum(vaultResult.encrypted) };
  manifest.stats.dbFiles++;
  manifest.stats.totalSize += vaultResult.encrypted.length;

  // 2. Copy db.key.enc (already vault-sealed)
  var dbKeyPath = PATHS.dbKeyEnc;
  try {
    var dbKeyBuf = await fs.readFile(dbKeyPath);
    await backend.put(prefix + "db.key.enc", dbKeyBuf);
    manifest.files["db.key.enc"] = { s3Key: prefix + "db.key.enc", size: dbKeyBuf.length, checksum: bufferChecksum(dbKeyBuf) };
    manifest.stats.dbFiles++;
    manifest.stats.totalSize += dbKeyBuf.length;
  } catch (_e) { /* db.key.enc may not exist */ }

  // 3. Copy hermitstash.db.enc (already encrypted)
  var dbEncPath = PATHS.dbEnc;
  try {
    var dbEncBuf = await fs.readFile(dbEncPath);
    await backend.put(prefix + "hermitstash.db.enc", dbEncBuf);
    manifest.files["hermitstash.db.enc"] = { s3Key: prefix + "hermitstash.db.enc", size: dbEncBuf.length, checksum: bufferChecksum(dbEncBuf) };
    manifest.stats.dbFiles++;
    manifest.stats.totalSize += dbEncBuf.length;
  } catch (_e) { /* db file may not exist */ }

  // 3b. Encrypt and copy TLS certificates and mTLS CA (if they exist)
  for (var t = 0; t < TLS_FILES.length; t++) {
    var tlsPath = path.join(DATA_DIR, TLS_FILES[t].local);
    try {
      if (fsSync.existsSync(tlsPath)) {
        var tlsBuf = await fs.readFile(tlsPath);
        var tlsEnc = await encryptWithPassphrase(tlsBuf, passphrase, vaultResult.salt);
        await backend.put(prefix + TLS_FILES[t].key, tlsEnc);
        manifest.files[TLS_FILES[t].key] = { s3Key: prefix + TLS_FILES[t].key, size: tlsEnc.length, checksum: bufferChecksum(tlsEnc) };
        manifest.stats.dbFiles++;
        manifest.stats.totalSize += tlsEnc.length;
      }
    } catch (_e) {}
  }

  // 4. Upload files (if full scope)
  if (scope === "full") {
    // Load previous manifest for incremental diff
    var prevUploads = {};
    try {
      var manifests = await backend.list("backups/");
      var encKeys = manifests.filter(function (k) { return k.endsWith("/manifest.enc"); }).sort();
      var plainKeys = manifests.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();
      var prevManifest = null;
      if (encKeys.length > 0) {
        var prevHeaderKey = encKeys[encKeys.length - 1].replace("manifest.enc", "manifest.json");
        var prevHeader = JSON.parse((await backend.getBuffer(prevHeaderKey)).toString("utf8"));
        var prevEnc = await backend.getBuffer(encKeys[encKeys.length - 1]);
        prevManifest = JSON.parse((await decryptWithPassphrase(prevEnc, passphrase, prevHeader.argon2Salt)).toString("utf8"));
      } else if (plainKeys.length > 0) {
        var prevData = await backend.getBuffer(plainKeys[plainKeys.length - 1]);
        prevManifest = JSON.parse(prevData.toString("utf8"));
      }
      if (prevManifest) prevUploads = prevManifest.uploads || {};
    } catch (_e) { /* no previous manifest or decryption failed */ }

    if (workerData.storageBackend === "local") {
      // Local storage: walk filesystem
      var uploadDir = workerData.uploadDir;
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
    } else if (workerData.storageBackend === "s3" && workerData.s3StorageConfig) {
      // S3 storage: list objects from storage bucket, copy to backup bucket
      var storageS3 = new S3Client(workerData.s3StorageConfig);
      // List all storage objects — bundles/, vault/, and any other prefixes
      var storageKeys = await storageS3.list("");
      for (var i = 0; i < storageKeys.length; i++) {
        var relPath = storageKeys[i];
        var s3Key = "backups/uploads/" + relPath;

        // Incremental: skip if checksum matches previous backup
        if (prevUploads[relPath] && prevUploads[relPath].checksum) {
          // Download and check — S3 list doesn't return checksums
          var fileBuf = await storageS3.getBuffer(relPath);
          var checksum = sha3Hash(fileBuf);
          if (prevUploads[relPath].checksum === checksum) {
            manifest.uploads[relPath] = prevUploads[relPath];
            manifest.stats.uploadFiles++;
            continue;
          }
          await backend.put(s3Key, fileBuf);
          manifest.uploads[relPath] = { s3Key: s3Key, size: fileBuf.length, checksum: checksum, backedUpAt: new Date().toISOString() };
          manifest.stats.uploadFiles++;
          manifest.stats.totalSize += fileBuf.length;
        } else {
          var fileBuf = await storageS3.getBuffer(relPath);
          var checksum = sha3Hash(fileBuf);
          await backend.put(s3Key, fileBuf);
          manifest.uploads[relPath] = { s3Key: s3Key, size: fileBuf.length, checksum: checksum, backedUpAt: new Date().toISOString() };
          manifest.stats.uploadFiles++;
          manifest.stats.totalSize += fileBuf.length;
        }
      }
    }
  }

  // 5. Upload manifest
  manifest.stats.durationMs = Date.now() - t0;

  // 5a. Encrypted manifest (contains file paths, checksums, bucket names)
  var manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
  var manifestEnc = await encryptWithPassphrase(manifestBuf, passphrase, vaultResult.salt);
  await backend.put(prefix + "manifest.enc", manifestEnc);

  // 5b. Public header (no sensitive data)
  var header = {
    version: manifest.version,
    timestamp: manifest.timestamp,
    scope: manifest.scope,
    hermitstashVersion: manifest.hermitstashVersion,
    storageBackend: manifest.storageBackend,
    storageBucket: manifest.storageBucket ? "configured" : null,
    argon2Salt: manifest.argon2Salt,
    stats: manifest.stats,
    encrypted: true,
  };
  var headerBuf = Buffer.from(JSON.stringify(header, null, 2), "utf8");
  await backend.put(prefix + "manifest.json", headerBuf);

  // 6. Verify encrypted manifest
  var verifyBuf = await backend.getBuffer(prefix + "manifest.enc");
  if (bufferChecksum(verifyBuf) !== bufferChecksum(manifestEnc)) {
    throw new Error("Manifest verification failed");
  }

  // 7. Retention pruning
  await pruneBackups(backend, retention, passphrase);

  return manifest;
}

// ---- Retention pruning ----

async function pruneBackups(backend, retention, passphrase) {
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();
  if (manifestKeys.length <= retention) return;

  var toDelete = manifestKeys.slice(0, manifestKeys.length - retention);
  var keepUploads = new Set();
  var keepManifests = manifestKeys.slice(manifestKeys.length - retention);

  for (var i = 0; i < keepManifests.length; i++) {
    try {
      var encKey = keepManifests[i].replace("manifest.json", "manifest.enc");
      var parsed = null;
      if (allKeys.indexOf(encKey) !== -1) {
        var headerData = await backend.getBuffer(keepManifests[i]);
        var hdr = JSON.parse(headerData.toString("utf8"));
        var encData = await backend.getBuffer(encKey);
        parsed = JSON.parse((await decryptWithPassphrase(encData, passphrase, hdr.argon2Salt)).toString("utf8"));
      } else {
        var data = await backend.getBuffer(keepManifests[i]);
        parsed = JSON.parse(data.toString("utf8"));
      }
      if (parsed && parsed.uploads) Object.keys(parsed.uploads).forEach(function (k) { if (parsed.uploads[k].s3Key) keepUploads.add(parsed.uploads[k].s3Key); });
    } catch (_decryptErr) {
      // If we can't decrypt the manifest, keep ALL upload files for safety
      // (passphrase may have changed — don't delete what we can't verify)
      allKeys.forEach(function (k) { if (k.startsWith("backups/uploads/")) keepUploads.add(k); });
      console.error("[backup] Pruning: could not decrypt manifest " + keepManifests[i] + " — keeping all uploads for safety");
      break;
    }
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
