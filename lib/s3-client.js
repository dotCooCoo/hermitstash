"use strict";

/**
 * S3 client — AWS Signature V4 for any S3-compatible endpoint.
 *
 * Accepts credentials as constructor params so the same client
 * can be used for primary storage, backup storage, or any other S3 target.
 *
 * Usage:
 *   var client = new S3Client({ bucket, region, accessKey, secretKey, endpoint });
 *   await client.put("path/key", buffer);
 *   var buf = await client.getBuffer("path/key");
 *   var stream = await client.getStream("path/key");
 *   await client.del("path/key");
 *   var keys = await client.list("prefix/");
 */

var crypto = require("crypto");
var https = require("https");
var { agent: pqcAgent } = require("./pqc-agent");

function hmac(key, data) { return crypto.createHmac("sha256", key).update(data).digest(); }
function sha256(data) { return crypto.createHash("sha256").update(data).digest("hex"); }

function S3Client(opts) {
  this._bucket = opts.bucket;
  this._region = opts.region || "us-east-1";
  this._accessKey = opts.accessKey;
  this._secretKey = opts.secretKey;
  this._endpoint = opts.endpoint;
}

S3Client.prototype.host = function () {
  if (this._endpoint) return new URL(this._endpoint).host;
  return this._bucket + ".s3." + this._region + ".amazonaws.com";
};

S3Client.prototype.path = function (key) {
  var encoded = key.split("/").map(encodeURIComponent).join("/");
  if (this._endpoint) return "/" + this._bucket + "/" + encoded;
  return "/" + encoded;
};

S3Client.prototype._timestamp = function () {
  var iso = new Date().toISOString();
  var dateStamp = iso.replace(/[-:T]/g, "").slice(0, 8);
  var amzDate = dateStamp + "T" + iso.replace(/[-:]/g, "").slice(9, 15) + "Z";
  return { dateStamp: dateStamp, amzDate: amzDate };
};

S3Client.prototype._signingKey = function (dateStamp) {
  return hmac(hmac(hmac(hmac("AWS4" + this._secretKey, dateStamp), this._region), "s3"), "aws4_request");
};

S3Client.prototype.sign = function (method, key, body, extraHeaders) {
  var ts = this._timestamp();
  var host = this.host();
  var uri = this.path(key);
  var payloadHash = sha256(body || "");
  var headers = Object.assign({ host: host, "x-amz-date": ts.amzDate, "x-amz-content-sha256": payloadHash }, extraHeaders || {});
  var signedHeaderKeys = Object.keys(headers).sort();
  var signedHeaders = signedHeaderKeys.join(";");
  var canonicalHeaders = signedHeaderKeys.map(function (k) { return k + ":" + headers[k] + "\n"; }).join("");
  var canonicalRequest = [method, uri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  var scope = ts.dateStamp + "/" + this._region + "/s3/aws4_request";
  var stringToSign = ["AWS4-HMAC-SHA256", ts.amzDate, scope, sha256(canonicalRequest)].join("\n");
  var signature = crypto.createHmac("sha256", this._signingKey(ts.dateStamp)).update(stringToSign).digest("hex");
  headers.authorization = "AWS4-HMAC-SHA256 Credential=" + this._accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
  return { host: host, path: uri, headers: headers };
};

S3Client.prototype.signPresigned = function (key, expires, responseHeaders) {
  var ts = this._timestamp();
  var host = this.host();
  var uri = this.path(key);
  var expiry = Math.min(Math.max(expires || 3600, 1), 604800);
  var scope = ts.dateStamp + "/" + this._region + "/s3/aws4_request";
  var params = [
    "X-Amz-Algorithm=AWS4-HMAC-SHA256",
    "X-Amz-Credential=" + encodeURIComponent(this._accessKey + "/" + scope),
    "X-Amz-Date=" + ts.amzDate,
    "X-Amz-Expires=" + expiry,
    "X-Amz-SignedHeaders=host",
  ];
  if (responseHeaders) {
    if (responseHeaders.contentDisposition) params.push("response-content-disposition=" + encodeURIComponent(responseHeaders.contentDisposition));
    if (responseHeaders.contentType) params.push("response-content-type=" + encodeURIComponent(responseHeaders.contentType));
  }
  params.sort();
  var query = params.join("&");
  var canonicalRequest = ["GET", uri, query, "host:" + host + "\n", "host", "UNSIGNED-PAYLOAD"].join("\n");
  var stringToSign = ["AWS4-HMAC-SHA256", ts.amzDate, scope, sha256(canonicalRequest)].join("\n");
  var signature = crypto.createHmac("sha256", this._signingKey(ts.dateStamp)).update(stringToSign).digest("hex");
  var protocol = this._endpoint ? new URL(this._endpoint).protocol : "https:";
  return protocol + "//" + host + uri + "?" + query + "&X-Amz-Signature=" + signature;
};

S3Client.prototype.put = function (key, buffer, extraHeaders) {
  var self = this;
  return new Promise(function (resolve, reject) {
    var headers = { "content-length": String(buffer.length), "content-type": "application/octet-stream" };
    if (extraHeaders) Object.assign(headers, extraHeaders);
    var s = self.sign("PUT", key, buffer, headers);
    var req = https.request({ hostname: s.host, path: s.path, method: "PUT", headers: s.headers, agent: pqcAgent }, function (res) {
      var d = ""; res.on("data", function (c) { d += c; });
      res.on("end", function () { res.statusCode < 300 ? resolve() : reject(new Error("S3 PUT " + res.statusCode + ": " + d.substring(0, 2000))); });
    });
    req.on("error", reject); req.write(buffer); req.end();
  });
};

S3Client.prototype.getStream = function (key) {
  var self = this;
  return new Promise(function (resolve, reject) {
    var s = self.sign("GET", key, "");
    var req = https.request({ hostname: s.host, path: s.path, method: "GET", headers: s.headers, agent: pqcAgent }, function (res) {
      if (res.statusCode >= 300) { res.resume(); reject(new Error("S3 GET " + res.statusCode)); return; }
      resolve(res);
    });
    req.on("error", reject); req.end();
  });
};

S3Client.prototype.getBuffer = function (key) {
  return this.getStream(key).then(function (stream) {
    return new Promise(function (resolve, reject) {
      var chunks = []; stream.on("data", function (c) { chunks.push(c); });
      stream.on("end", function () { resolve(Buffer.concat(chunks)); });
      stream.on("error", reject);
    });
  });
};

S3Client.prototype.del = function (key) {
  var self = this;
  return new Promise(function (resolve, reject) {
    var s = self.sign("DELETE", key, "");
    var req = https.request({ hostname: s.host, path: s.path, method: "DELETE", headers: s.headers, agent: pqcAgent }, function (res) {
      res.resume(); res.on("end", function () { resolve(); });
    });
    req.on("error", reject); req.end();
  });
};

S3Client.prototype.list = function (prefix) {
  var self = this;
  var allKeys = [];

  function fetchPage(continuationToken) {
    return new Promise(function (resolve, reject) {
      var queryParts = ["list-type=2", "max-keys=1000", "prefix=" + encodeURIComponent(prefix)];
      if (continuationToken) queryParts.push("continuation-token=" + encodeURIComponent(continuationToken));
      queryParts.sort();
      var query = queryParts.join("&");
      var ts = self._timestamp();
      var host = self.host();
      var uri = self._endpoint ? "/" + self._bucket + "/" : "/";
      var payloadHash = sha256("");
      var headers = { host: host, "x-amz-date": ts.amzDate, "x-amz-content-sha256": payloadHash };
      var signedHeaderKeys = Object.keys(headers).sort();
      var signedHeaders = signedHeaderKeys.join(";");
      var canonicalHeaders = signedHeaderKeys.map(function (k) { return k + ":" + headers[k] + "\n"; }).join("");
      var canonicalRequest = ["GET", uri, query, canonicalHeaders, signedHeaders, payloadHash].join("\n");
      var scope = ts.dateStamp + "/" + self._region + "/s3/aws4_request";
      var stringToSign = ["AWS4-HMAC-SHA256", ts.amzDate, scope, sha256(canonicalRequest)].join("\n");
      var signature = crypto.createHmac("sha256", self._signingKey(ts.dateStamp)).update(stringToSign).digest("hex");
      headers.authorization = "AWS4-HMAC-SHA256 Credential=" + self._accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

      var req = https.request({ hostname: host, path: uri + "?" + query, method: "GET", headers: headers, agent: pqcAgent }, function (res) {
        var d = ""; res.on("data", function (c) { d += c; });
        res.on("end", function () {
          if (res.statusCode >= 300) return reject(new Error("S3 LIST " + res.statusCode));
          var keys = [];
          var re = /<Key>([^<]+)<\/Key>/g;
          var m;
          while ((m = re.exec(d)) !== null) keys.push(m[1]);
          allKeys = allKeys.concat(keys);

          var truncated = /<IsTruncated>true<\/IsTruncated>/i.test(d);
          var tokenMatch = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(d);
          if (truncated && tokenMatch) {
            resolve(fetchPage(tokenMatch[1]));
          } else {
            resolve(allKeys);
          }
        });
      });
      req.on("error", reject); req.end();
    });
  }

  return fetchPage(null);
};

S3Client.prototype.testConnection = function () {
  var testKey = ".connection-test-" + Date.now();
  var self = this;
  return self.put(testKey, Buffer.from("ok")).then(function () {
    return self.del(testKey);
  });
};

module.exports = S3Client;
