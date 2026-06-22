"use strict";

/**
 * S3 client — HermitStash facade over `b.objectStore.buildBackend`.
 *
 * The AWS SigV4 implementation, request/retry plumbing, SDK-shaped
 * put/get/list/delete, AND presigned-URL signing now live in
 * blamejs's object-store module (sigv4 backend, ≥ 0.8.56 with
 * `responseHeaders` support). This file translates between HS's
 * call-site shape and blamejs's:
 *
 *   - HS:       `new S3Client({ accessKey, secretKey, ... })`
 *     blamejs:  `b.objectStore.buildBackend({ accessKeyId, secretAccessKey, ... })`
 *   - HS:       `client.del(key)` / `client.getBuffer(key)`
 *     blamejs:  `backend.delete(key)` / `backend.get(key)`
 *   - HS:       `client.list(prefix)` → `[keys...]` (auto-paginated)
 *     blamejs:  `backend.list(prefix)` → `{ items, truncated, continuationToken }` per page
 *
 * The pagination wrapper and `testConnection` round-trip helper are
 * HS-specific extras blamejs doesn't expose; everything else is a thin
 * name-translation.
 */

var b = require("./vendor/blamejs");

function S3Client(opts) {
  this._bucket = opts.bucket;
  this._region = opts.region || "us-east-1";
  this._accessKey = opts.accessKey;
  this._secretKey = opts.secretKey;
  this._endpoint = opts.endpoint;
  this._backend = b.objectStore.buildBackend({
    protocol:        "sigv4",
    bucket:          this._bucket,
    region:          this._region,
    accessKeyId:     this._accessKey,
    secretAccessKey: this._secretKey,
    endpoint:        this._endpoint,
  });
}

S3Client.prototype.put = function (key, buffer, extraHeaders) {
  return this._backend.put(key, buffer, extraHeaders ? { headers: extraHeaders } : undefined);
};

S3Client.prototype.getStream = function (key) {
  return Promise.resolve(this._backend.getStream(key));
};

S3Client.prototype.getBuffer = function (key) {
  return this._backend.get(key);
};

S3Client.prototype.del = function (key) {
  return this._backend.delete(key);
};

// Auto-paginated list — HS callers expect a flat array of keys, not the
// per-page `{ items, truncated, continuationToken }` shape blamejs's
// list returns. Loop here until the bucket is exhausted.
S3Client.prototype.list = async function (prefix) {
  var allKeys = [];
  var continuationToken = null;
  do {
    var page = await this._backend.list(prefix, continuationToken ? { continuationToken: continuationToken } : undefined);
    for (var i = 0; i < page.items.length; i++) allKeys.push(page.items[i].key);
    continuationToken = page.truncated ? page.continuationToken : null;
  } while (continuationToken);
  return allKeys;
};

// Round-trip put + delete to verify the bucket is reachable + writable +
// the credentials are accepted. Operators run this from the admin UI
// before saving an S3 backup config so a typo surfaces synchronously.
S3Client.prototype.testConnection = async function () {
  var testKey = ".connection-test-" + Date.now();
  await this.put(testKey, Buffer.from("ok", "utf8"));
  await this.del(testKey);
};

module.exports = S3Client;
