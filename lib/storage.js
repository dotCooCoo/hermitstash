var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var https = require("https");
var config = require("./config");
var vault = require("./vault");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var { Readable } = require("stream");

// Resolve upload directory
var uploadDir = path.isAbsolute(config.storage.uploadDir)
  ? config.storage.uploadDir
  : path.resolve(__dirname, "..", config.storage.uploadDir);

if (config.storage.backend === "local") {
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
}

// ---- File encryption (XChaCha20-Poly1305 with per-file keys) ----
// Version byte 0x02 marks XChaCha20 format; absence = legacy AES-256-GCM

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
 * Save a file — encrypts with AES-256-GCM, key sealed with ML-KEM-768.
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

// ---- S3 client (AWS Signature V4) ----

function getS3Host() {
  if (config.storage.s3.endpoint) return new URL(config.storage.s3.endpoint).host;
  return config.storage.s3.bucket + ".s3." + config.storage.s3.region + ".amazonaws.com";
}

function getS3Path(key) {
  var encoded = key.split("/").map(encodeURIComponent).join("/");
  if (config.storage.s3.endpoint) return "/" + config.storage.s3.bucket + "/" + encoded;
  return "/" + encoded;
}

// ---- AWS S3 Signature V4 helpers (SHA-256 required by AWS spec) ----

function hmac(key, data) { return crypto.createHmac("sha256", key).update(data).digest(); }
function sha256(data) { return crypto.createHash("sha256").update(data).digest("hex"); }

// Single call to toISOString avoids cross-day-boundary bug if called at midnight
function s3Timestamp() {
  var iso = new Date().toISOString();
  var dateStamp = iso.replace(/[-:T]/g, "").slice(0, 8);
  var amzDate = dateStamp + "T" + iso.replace(/[-:]/g, "").slice(9, 15) + "Z";
  return { dateStamp: dateStamp, amzDate: amzDate };
}

function s3SigningKey(dateStamp) {
  var region = config.storage.s3.region;
  return hmac(hmac(hmac(hmac("AWS4" + config.storage.s3.secretKey, dateStamp), region), "s3"), "aws4_request");
}

function signV4(method, key, body, extraHeaders) {
  var ts = s3Timestamp();
  var region = config.storage.s3.region;
  var host = getS3Host();
  var uri = getS3Path(key);
  var payloadHash = sha256(body || "");
  var headers = Object.assign({ host: host, "x-amz-date": ts.amzDate, "x-amz-content-sha256": payloadHash }, extraHeaders || {});
  var signedHeaderKeys = Object.keys(headers).sort();
  var signedHeaders = signedHeaderKeys.join(";");
  var canonicalHeaders = signedHeaderKeys.map(function (k) { return k + ":" + headers[k] + "\n"; }).join("");
  var canonicalRequest = [method, uri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  var scope = ts.dateStamp + "/" + region + "/s3/aws4_request";
  var stringToSign = ["AWS4-HMAC-SHA256", ts.amzDate, scope, sha256(canonicalRequest)].join("\n");
  var signature = crypto.createHmac("sha256", s3SigningKey(ts.dateStamp)).update(stringToSign).digest("hex");
  headers.authorization = "AWS4-HMAC-SHA256 Credential=" + config.storage.s3.accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
  return { host: host, path: uri, headers: headers };
}

function s3Put(key, buffer, extraHeaders) {
  return new Promise(function (resolve, reject) {
    var headers = { "content-length": String(buffer.length), "content-type": "application/octet-stream" };
    if (extraHeaders) Object.assign(headers, extraHeaders);
    var s = signV4("PUT", key, buffer, headers);
    var req = https.request({ hostname: s.host, path: s.path, method: "PUT", headers: s.headers }, function (res) {
      var data = ""; res.on("data", function (c) { data += c; });
      res.on("end", function () { res.statusCode < 300 ? resolve() : reject(new Error("S3 PUT " + res.statusCode)); });
    });
    req.on("error", reject); req.write(buffer); req.end();
  });
}

function s3Get(key) {
  return new Promise(function (resolve, reject) {
    var s = signV4("GET", key, "");
    var req = https.request({ hostname: s.host, path: s.path, method: "GET", headers: s.headers }, function (res) {
      if (res.statusCode >= 300) { var d = ""; res.on("data", function (c) { d += c; }); res.on("end", function () { reject(new Error("S3 GET " + res.statusCode)); }); }
      else resolve(res);
    });
    req.on("error", reject); req.end();
  });
}

function s3GetBuffer(key) {
  return new Promise(function (resolve, reject) {
    s3Get(key).then(function (stream) {
      var chunks = []; stream.on("data", function (c) { chunks.push(c); });
      stream.on("end", function () { resolve(Buffer.concat(chunks)); });
      stream.on("error", reject);
    }).catch(reject);
  });
}

function s3Delete(key) {
  return new Promise(function (resolve, reject) {
    var s = signV4("DELETE", key, "");
    var req = https.request({ hostname: s.host, path: s.path, method: "DELETE", headers: s.headers }, function (res) {
      var d = ""; res.on("data", function (c) { d += c; }); res.on("end", function () { resolve(); });
    });
    req.on("error", reject); req.end();
  });
}

// ---- S3 Pre-Signed URLs (AWS Signature V4 query-string signing) ----

function uriEncode(str) {
  return encodeURIComponent(str)
    .replace(/'/g, "%27").replace(/!/g, "%21")
    .replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
}

function signV4PreSignedUrl(key, expires, responseHeaders) {
  var ts = s3Timestamp();
  var region = config.storage.s3.region;
  var s3Host = getS3Host();
  var uri = getS3Path(key);
  var encodedUri = uri.split("/").map(function (seg) { return seg ? uriEncode(seg) : seg; }).join("/");

  var credentialScope = ts.dateStamp + "/" + region + "/s3/aws4_request";
  var credential = config.storage.s3.accessKey + "/" + credentialScope;

  var params = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": credential,
    "X-Amz-Date": ts.amzDate,
    "X-Amz-Expires": String(Math.min(Math.max(expires, 1), 604800)),
    "X-Amz-SignedHeaders": "host",
  };
  if (responseHeaders) {
    if (responseHeaders.contentDisposition) params["response-content-disposition"] = responseHeaders.contentDisposition;
    if (responseHeaders.contentType) params["response-content-type"] = responseHeaders.contentType;
  }

  var sortedKeys = Object.keys(params).sort();
  var canonicalQS = sortedKeys.map(function (k) { return uriEncode(k) + "=" + uriEncode(params[k]); }).join("&");

  var canonicalRequest = ["GET", encodedUri, canonicalQS, "host:" + s3Host, "", "host", "UNSIGNED-PAYLOAD"].join("\n");
  var stringToSign = ["AWS4-HMAC-SHA256", ts.amzDate, credentialScope, sha256(canonicalRequest)].join("\n");
  var signature = crypto.createHmac("sha256", s3SigningKey(ts.dateStamp)).update(stringToSign).digest("hex");

  var protocol = config.storage.s3.endpoint ? new URL(config.storage.s3.endpoint).protocol : "https:";
  return protocol + "//" + s3Host + encodedUri + "?" + canonicalQS + "&X-Amz-Signature=" + signature;
}

/**
 * Generate a time-limited pre-signed S3 download URL.
 * Returns null if backend is not S3 or direct downloads are off.
 */
function getPresignedUrl(storagePath, filename, mimeType) {
  if (config.storage.backend !== "s3" || !config.storage.s3DirectDownloads) return null;
  var expires = config.storage.s3PresignExpiry || 3600;
  var safeName = (filename || "download").replace(/"/g, '\\"');
  return signV4PreSignedUrl(storagePath, expires, {
    contentDisposition: 'attachment; filename="' + safeName + '"',
    contentType: mimeType || "application/octet-stream",
  });
}

module.exports = { saveFile: saveFile, getFileStream: getFileStream, deleteFile: deleteFile, getPresignedUrl: getPresignedUrl, uploadDir: uploadDir };
