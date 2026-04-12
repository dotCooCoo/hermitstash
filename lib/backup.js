"use strict";

/**
 * Backup module — encrypted off-site backups to S3-compatible storage.
 *
 * Backs up: vault.key (passphrase-encrypted), db.key.enc, hermitstash.db.enc.
 * Optionally backs up all upload files (incremental, manifest-based).
 *
 * Uses lib/s3-client.js for S3 operations — same client as primary storage,
 * instantiated with backup-specific credentials.
 */

var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var config = require("./config");
var audit = require("./audit");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var argon2 = require("./vendor/argon2");
var { sha3Hash } = require("./crypto");
var S3Client = require("./s3-client");

var DATA_DIR = path.join(__dirname, "..", "data");

// ---- Backend factory ----

function getBackend(overrideConfig) {
  var cfg = overrideConfig || config.backup.s3;
  if (!cfg.bucket || !cfg.accessKey || !cfg.secretKey) {
    throw new Error("Backup S3 credentials not configured");
  }
  return new S3Client(cfg);
}

// ---- Vault key encryption ----

async function encryptVaultKey(passphrase) {
  var vaultKeyPath = path.join(DATA_DIR, "vault.key");
  var vaultKeyData = fs.readFileSync(vaultKeyPath, "utf8");

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
function fileChecksum(filePath) { return sha3Hash(fs.readFileSync(filePath)); }

// ---- Walk uploads directory ----

function walkUploads(dir) {
  var results = [];
  if (!fs.existsSync(dir)) return results;
  var entries = fs.readdirSync(dir, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) results.push.apply(results, walkUploads(full));
    else if (entries[i].isFile()) results.push(full);
  }
  return results;
}

// ---- Run backup ----

async function runBackup(passphrase) {
  var t0 = Date.now();
  var scope = config.backup.scope || "db";
  var retention = config.backup.retention || 7;
  var backend = getBackend();

  audit.log(audit.ACTIONS.BACKUP_STARTED, { performedBy: "system", details: "Backup started: scope=" + scope });

  var timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  var prefix = "backups/" + timestamp + "/";

  var manifest = {
    version: 1,
    timestamp: new Date().toISOString(),
    scope: scope,
    hermitstashVersion: require("./constants").version,
    argon2Salt: null,
    files: {},
    uploads: {},
    stats: { dbFiles: 0, uploadFiles: 0, totalSize: 0, durationMs: 0 },
  };

  try {
    // 1. Flush DB encryption
    var db = require("./db");
    if (typeof db.flushEncryption === "function") db.flushEncryption();

    // 2. Encrypt vault.key with passphrase
    var vaultResult = await encryptVaultKey(passphrase);
    manifest.argon2Salt = vaultResult.salt;

    await backend.put(prefix + "vault.key.enc", vaultResult.encrypted);
    manifest.files["vault.key.enc"] = { s3Key: prefix + "vault.key.enc", size: vaultResult.encrypted.length, checksum: bufferChecksum(vaultResult.encrypted) };
    manifest.stats.dbFiles++;
    manifest.stats.totalSize += vaultResult.encrypted.length;

    // 3. Copy db.key.enc (already vault-sealed)
    var dbKeyPath = path.join(DATA_DIR, "db.key.enc");
    if (fs.existsSync(dbKeyPath)) {
      var dbKeyBuf = fs.readFileSync(dbKeyPath);
      await backend.put(prefix + "db.key.enc", dbKeyBuf);
      manifest.files["db.key.enc"] = { s3Key: prefix + "db.key.enc", size: dbKeyBuf.length, checksum: bufferChecksum(dbKeyBuf) };
      manifest.stats.dbFiles++;
      manifest.stats.totalSize += dbKeyBuf.length;
    }

    // 4. Copy hermitstash.db.enc (already encrypted)
    var dbEncPath = path.join(DATA_DIR, "hermitstash.db.enc");
    if (fs.existsSync(dbEncPath)) {
      var dbEncBuf = fs.readFileSync(dbEncPath);
      await backend.put(prefix + "hermitstash.db.enc", dbEncBuf);
      manifest.files["hermitstash.db.enc"] = { s3Key: prefix + "hermitstash.db.enc", size: dbEncBuf.length, checksum: bufferChecksum(dbEncBuf) };
      manifest.stats.dbFiles++;
      manifest.stats.totalSize += dbEncBuf.length;
    }

    // 5. Upload files (if full scope)
    if (scope === "full") {
      var uploadDir = path.resolve(config.storage.uploadDir || "./uploads");

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

      if (config.storage.backend === "local") {
        var files = walkUploads(uploadDir);
        for (var i = 0; i < files.length; i++) {
          var relPath = path.relative(uploadDir, files[i]).replace(/\\/g, "/");
          var checksum = fileChecksum(files[i]);
          var s3Key = "backups/uploads/" + relPath;

          if (prevUploads[relPath] && prevUploads[relPath].checksum === checksum) {
            manifest.uploads[relPath] = prevUploads[relPath];
            manifest.stats.uploadFiles++;
            continue;
          }

          var fileBuf = fs.readFileSync(files[i]);
          await backend.put(s3Key, fileBuf);
          manifest.uploads[relPath] = { s3Key: s3Key, size: fileBuf.length, checksum: checksum, backedUpAt: new Date().toISOString() };
          manifest.stats.uploadFiles++;
          manifest.stats.totalSize += fileBuf.length;

          if (i % 10 === 0) await new Promise(function (r) { setImmediate(r); });
        }
      } else if (config.storage.backend === "s3") {
        var filesDb = require("./db").files;
        var allFiles = filesDb.find({});
        for (var j = 0; j < allFiles.length; j++) {
          var file = allFiles[j];
          if (!file.storagePath) continue;
          var storagePath = file.storagePath.replace(/^s3:\/\/[^/]+\//, "");
          var s3KeyUpload = "backups/uploads/" + storagePath;

          if (prevUploads[storagePath] && prevUploads[storagePath].checksum === (file.checksum || "")) {
            manifest.uploads[storagePath] = prevUploads[storagePath];
            manifest.stats.uploadFiles++;
            continue;
          }

          try {
            var storage = require("./storage");
            var stream = await storage.getFileStream(file.storagePath, file.encryptionKey);
            var chunks = [];
            await new Promise(function (resolve, reject) {
              stream.on("data", function (c) { chunks.push(c); });
              stream.on("end", resolve);
              stream.on("error", reject);
            });
            var fileData = Buffer.concat(chunks);
            await backend.put(s3KeyUpload, fileData);
            manifest.uploads[storagePath] = { s3Key: s3KeyUpload, size: fileData.length, checksum: file.checksum || bufferChecksum(fileData), backedUpAt: new Date().toISOString() };
            manifest.stats.uploadFiles++;
            manifest.stats.totalSize += fileData.length;
          } catch (_e) { /* skip unreadable files */ }

          if (j % 10 === 0) await new Promise(function (r) { setImmediate(r); });
        }
      }
    }

    // 6. Upload manifest
    manifest.stats.durationMs = Date.now() - t0;
    var manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
    await backend.put(prefix + "manifest.json", manifestBuf);

    // 7. Verify manifest
    var verifyBuf = await backend.getBuffer(prefix + "manifest.json");
    if (bufferChecksum(verifyBuf) !== bufferChecksum(manifestBuf)) {
      throw new Error("Manifest verification failed");
    }

    // 8. Retention pruning
    await pruneBackups(backend, retention);

    audit.log(audit.ACTIONS.BACKUP_COMPLETED, {
      performedBy: "system",
      details: "Backup completed: " + manifest.stats.dbFiles + " db files, " + manifest.stats.uploadFiles + " upload files, " + (manifest.stats.totalSize / 1048576).toFixed(1) + " MB, " + manifest.stats.durationMs + " ms",
    });

    return manifest;
  } catch (err) {
    audit.log(audit.ACTIONS.BACKUP_FAILED, { performedBy: "system", details: "Backup failed: " + err.message });
    throw err;
  }
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

// ---- History ----

async function getBackupHistory() {
  var backend = getBackend();
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort().reverse();

  var history = [];
  for (var i = 0; i < Math.min(manifestKeys.length, 20); i++) {
    try {
      var data = await backend.getBuffer(manifestKeys[i]);
      var m = JSON.parse(data.toString("utf8"));
      history.push({ timestamp: m.timestamp, scope: m.scope, version: m.hermitstashVersion, dbFiles: m.stats.dbFiles, uploadFiles: m.stats.uploadFiles, totalSize: m.stats.totalSize, durationMs: m.stats.durationMs, status: "completed" });
    } catch (_e) {
      history.push({ timestamp: manifestKeys[i], status: "corrupt" });
    }
  }
  return history;
}

// ---- Test connection ----

async function testConnection(s3Config) {
  var client = new S3Client(s3Config);
  await client.testConnection();
  return true;
}

// ---- Verify passphrase ----

async function verifyPassphrase(passphrase) {
  if (!config.backup.passphraseHash) return false;
  return argon2.verify(config.backup.passphraseHash, passphrase);
}

module.exports = { runBackup: runBackup, getBackupHistory: getBackupHistory, testConnection: testConnection, verifyPassphrase: verifyPassphrase, getBackend: getBackend };
