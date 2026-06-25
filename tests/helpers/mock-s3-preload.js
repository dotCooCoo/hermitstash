"use strict";

/**
 * Worker/child preload that replaces lib/s3-client.js with a file-backed
 * in-memory S3 stand-in, so backup/restore worker tests can exercise the
 * real worker code paths without a live S3 bucket.
 *
 * Objects are persisted as base64 entries in a shared JSON file named by
 * MOCK_S3_STORE (one file per logical bucket via a per-bucket sub-key), so a
 * seed process and a separate restore worker process observe the same store.
 *
 * Activated by requiring this file before the worker's own requires:
 *   new Worker(script, { execArgv: ["--require", thisFile] })
 * or `node --require thisFile ...`.
 */

var Module = require("node:module");
var fs = require("node:fs");
var path = require("node:path");

var STORE_PATH = process.env.MOCK_S3_STORE;

function load() {
  try { return JSON.parse(fs.readFileSync(STORE_PATH, "utf8")); }
  catch (_e) { return {}; }
}
function save(obj) {
  fs.writeFileSync(STORE_PATH, JSON.stringify(obj));
}
function bucketOf(opts) { return (opts && opts.bucket) || "__default__"; }

function MockS3Client(opts) {
  this._bucket = bucketOf(opts);
}
MockS3Client.prototype.put = function (key, buffer) {
  var store = load();
  if (!store[this._bucket]) store[this._bucket] = {};
  store[this._bucket][key] = Buffer.from(buffer).toString("base64");
  save(store);
  return Promise.resolve();
};
MockS3Client.prototype.getBuffer = function (key) {
  var store = load();
  var b64 = store[this._bucket] && store[this._bucket][key];
  if (b64 == null) return Promise.reject(new Error("MockS3: no such key: " + key));
  return Promise.resolve(Buffer.from(b64, "base64"));
};
MockS3Client.prototype.getStream = function (key) {
  return this.getBuffer(key);
};
MockS3Client.prototype.del = function (key) {
  var store = load();
  if (store[this._bucket]) delete store[this._bucket][key];
  save(store);
  return Promise.resolve();
};
MockS3Client.prototype.list = function (prefix) {
  var store = load();
  var keys = Object.keys(store[this._bucket] || {});
  return Promise.resolve(keys.filter(function (k) { return k.indexOf(prefix || "") === 0; }));
};
MockS3Client.prototype.testConnection = function () { return Promise.resolve(true); };

// Intercept require("./s3-client") (and any absolute resolution of it) so the
// worker's `var S3Client = require("./s3-client")` returns the mock.
var origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "./s3-client" ||
      (typeof request === "string" && request.replace(/\\/g, "/").endsWith("/lib/s3-client"))) {
    return MockS3Client;
  }
  if (parent && parent.filename) {
    try {
      var resolved = path.resolve(path.dirname(parent.filename), request);
      if (resolved.replace(/\\/g, "/").endsWith("/lib/s3-client.js") ||
          resolved.replace(/\\/g, "/").endsWith("/lib/s3-client")) {
        return MockS3Client;
      }
    } catch (_e) { /* fall through to real loader */ }
  }
  return origLoad.call(this, request, parent, isMain);
};
