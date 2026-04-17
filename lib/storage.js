var fs = require("fs");
var path = require("path");
var config = require("./config");
var vault = require("./vault");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var { Readable } = require("stream");
var S3Client = require("./s3-client");

// Resolve upload directory
var uploadDir = path.isAbsolute(config.storage.uploadDir)
  ? config.storage.uploadDir
  : path.resolve(__dirname, "..", config.storage.uploadDir);

if (config.storage.backend === "local") {
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
}

// ---- File encryption (XChaCha20-Poly1305 with per-file keys) ----

function encryptBuffer(buffer) {
  var key = generateBytes(32);
  var packed = encryptPacked(buffer, key);
  var sealedKey = vault.seal(key.toString("base64"));
  return { data: packed, encryptionKey: sealedKey };
}

function decryptBuffer(packed, sealedKey) {
  var key = Buffer.from(vault.unseal(sealedKey), "base64");
  return decryptPacked(packed, key);
}

// ---- Public API ----

/**
 * Save a file — encrypts with XChaCha20-Poly1305, key sealed with ML-KEM-1024 + P-384 hybrid vault.
 * When S3 direct mode is on, skips app encryption and uses S3 SSE instead.
 * Returns { path, encryptionKey } — caller must store encryptionKey in DB.
 */
async function saveFile(buffer, storagePath) {
  // S3 direct mode: no app-level encryption, rely on S3 server-side encryption
  if (config.storage.backend === "s3" && config.storage.s3DirectDownloads) {
    await s3Put(storagePath, buffer, { "x-amz-server-side-encryption": "AES256" });
    return { path: "s3://" + config.storage.s3.bucket + "/" + storagePath, encryptionKey: null };
  }
  var enc = encryptBuffer(buffer);
  if (config.storage.backend === "s3") {
    await s3Put(storagePath, enc.data);
    return { path: "s3://" + config.storage.s3.bucket + "/" + storagePath, encryptionKey: enc.encryptionKey };
  }
  var fullPath = path.join(uploadDir, storagePath);
  var dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fullPath, enc.data);
  return { path: fullPath, encryptionKey: enc.encryptionKey };
}

/**
 * Get a readable stream of decrypted file data.
 * If encryptionKey is null (legacy unencrypted file), returns raw stream.
 */
async function getFileStream(storagePath, encryptionKey) {
  if (!encryptionKey) {
    // Legacy unencrypted file
    if (config.storage.backend === "s3") return s3Get(storagePath);
    return fs.createReadStream(path.join(uploadDir, storagePath));
  }
  // Read encrypted file, decrypt, return as stream
  var packed;
  if (config.storage.backend === "s3") {
    packed = await s3GetBuffer(storagePath);
  } else {
    packed = fs.readFileSync(path.join(uploadDir, storagePath));
  }
  var decrypted = decryptBuffer(packed, encryptionKey);
  return Readable.from(decrypted);
}

async function deleteFile(storagePath) {
  if (config.storage.backend === "s3") return s3Delete(storagePath);
  var fullPath = path.join(uploadDir, storagePath);
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
}

// ---- S3 client (shared S3Client module) ----

var _s3 = null;
function getS3() {
  if (!_s3) _s3 = new S3Client(config.storage.s3);
  return _s3;
}
function resetS3Client() { _s3 = null; }

// Invalidate cached S3 client when any S3 config changes at runtime
var _s3Keys = ["s3Bucket", "s3Region", "s3AccessKey", "s3SecretKey", "s3Endpoint"];
require("./config").onReset(function (changed) {
  for (var i = 0; i < changed.length; i++) {
    if (_s3Keys.indexOf(changed[i]) !== -1) { _s3 = null; return; }
  }
});

function s3Put(key, buffer, extraHeaders) { return getS3().put(key, buffer, extraHeaders); }
function s3Get(key) { return getS3().getStream(key); }
function s3GetBuffer(key) { return getS3().getBuffer(key); }
function s3Delete(key) { return getS3().del(key); }

/**
 * Generate a time-limited pre-signed S3 download URL.
 * Returns null if backend is not S3 or direct downloads are off.
 */
function getPresignedUrl(storagePath, filename, mimeType) {
  if (config.storage.backend !== "s3" || !config.storage.s3DirectDownloads) return null;
  var expires = config.storage.s3PresignExpiry || 3600;
  var safeName = (filename || "download").replace(/"/g, '\\"');
  return getS3().signPresigned(storagePath, expires, {
    contentDisposition: 'attachment; filename="' + safeName + '"',
    contentType: mimeType || "application/octet-stream",
  });
}

module.exports = { saveFile: saveFile, getFileStream: getFileStream, deleteFile: deleteFile, getPresignedUrl: getPresignedUrl, uploadDir: uploadDir, resetS3Client: resetS3Client };
