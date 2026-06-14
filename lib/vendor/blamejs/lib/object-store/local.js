"use strict";
/**
 * Local-filesystem protocol adapter for object-store.
 *
 * Implements the uniform protocol surface (put / get / getStream / delete /
 * head / list) against a directory tree. Streaming is via Node's native
 * fs.createReadStream / createWriteStream — no in-memory buffering of
 * full files.
 *
 * Path safety: every key resolves under the configured rootDir, with an
 * alphanumeric + `_-./` charset whitelist and explicit rejection of any
 * path that escapes rootDir after resolution.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var cluster = require("../cluster");
var { ObjectStoreError } = require("../framework-error");

var SAFE_KEY = /^[A-Za-z0-9_\-./]+$/;

function _resolveSafe(rootDir, key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "key must be a non-empty string", true);
  }
  if (key.includes("\0")) throw _err("INVALID_KEY", "null byte in key", true);
  if (nodePath.isAbsolute(key)) throw _err("INVALID_KEY", "absolute key not allowed", true);
  if (!SAFE_KEY.test(key)) throw _err("INVALID_KEY", "invalid characters in key", true);
  var full = nodePath.resolve(rootDir, key);
  var withSep = rootDir.endsWith(nodePath.sep) ? rootDir : rootDir + nodePath.sep;
  if (full !== rootDir && !full.startsWith(withSep)) {
    throw _err("INVALID_KEY", "key escapes rootDir", true);
  }
  return full;
}

var _err = ObjectStoreError.factory;

function create(config) {
  if (!config || !config.rootDir) {
    throw new Error("local protocol requires { rootDir }");
  }
  var rootDir = nodePath.resolve(config.rootDir);
  if (!nodeFs.existsSync(rootDir)) nodeFs.mkdirSync(rootDir, { recursive: true });

  function put(key, body, _opts) {
    cluster.requireLeader();
    var full = _resolveSafe(rootDir, key);
    var dir = nodePath.dirname(full);
    if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });

    if (Buffer.isBuffer(body)) {
      atomicFile.writeSync(full, body);
      return Promise.resolve({ size: body.length });
    }
    if (body && typeof body.pipe === "function") {
      // Streaming put — pipe directly to disk
      return new Promise(function (resolve, reject) {
        var ws = nodeFs.createWriteStream(full);
        var bytes = 0;
        body.on("data", function (chunk) { bytes += chunk.length; });
        body.pipe(ws);
        ws.on("finish", function () { resolve({ size: bytes }); });
        ws.on("error", reject);
        body.on("error", reject);
      });
    }
    if (typeof body === "string") {
      var buf = Buffer.from(body, "utf8");
      atomicFile.writeSync(full, buf);
      return Promise.resolve({ size: buf.length });
    }
    return Promise.reject(_err("INVALID_BODY", "put body must be Buffer, Readable, or string", true));
  }

  function get(key) {
    var full = _resolveSafe(rootDir, key);
    if (!nodeFs.existsSync(full)) {
      return Promise.reject(_err("NOT_FOUND", "key not found: " + key, true));
    }
    return Promise.resolve(nodeFs.readFileSync(full));
  }

  function getStream(key) {
    var full = _resolveSafe(rootDir, key);
    if (!nodeFs.existsSync(full)) {
      throw _err("NOT_FOUND", "key not found: " + key, true);
    }
    return nodeFs.createReadStream(full);
  }

  function head(key) {
    var full = _resolveSafe(rootDir, key);
    if (!nodeFs.existsSync(full)) {
      return Promise.reject(_err("NOT_FOUND", "key not found: " + key, true));
    }
    var stat = nodeFs.statSync(full);
    return Promise.resolve({
      size:         stat.size,
      lastModified: stat.mtimeMs,
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    // A filesystem has no object versions; a versioned-delete request can only
    // be a caller mistake. Refuse loudly rather than unlink the single on-disk
    // file and report a version was erased.
    if (opts.versionId) {
      throw _err("VERSIONID_UNSUPPORTED",
        "deleteKey: versioned delete (opts.versionId) is not supported on the " +
        "filesystem backend — a local file has no version history. Use a sigv4 " +
        "(S3 Object-Lock) backend for version erasure.", true);
    }
    cluster.requireLeader();
    var full = _resolveSafe(rootDir, key);
    if (!nodeFs.existsSync(full)) return Promise.resolve(false);
    nodeFs.unlinkSync(full);
    return Promise.resolve(true);
  }

  function list(prefix, opts) {
    opts = opts || {};
    var max = opts.maxResults || 1000;
    var prefixDir = prefix ? _resolveSafe(rootDir, prefix.replace(/\/$/, "")) : rootDir;
    var results = [];
    function walk(dir, base) {
      if (results.length >= max) return;
      var entries = atomicFile.listDir(dir, { includeStat: true });
      for (var i = 0; i < entries.length; i++) {
        if (results.length >= max) break;
        var entry = entries[i];
        var rel = base ? base + "/" + entry.name : entry.name;
        if (entry.isDirectory) walk(entry.fullPath, rel);
        else results.push({ key: rel, size: entry.sizeBytes, lastModified: entry.mtimeMs });
      }
    }
    var basePrefix = prefix ? prefix.replace(/\/$/, "") : "";
    walk(prefixDir, basePrefix);
    return Promise.resolve({ items: results, truncated: results.length >= max });
  }

  function _presignNotSupported(direction) {
    return function (_opts) {
      throw _err("PRESIGN_NOT_SUPPORTED",
        "local backend does not issue presigned " + direction + " URLs — " +
        "clients on the same host should call storage." +
        (direction === "upload" ? "saveFile" : "getFileBuffer") + "() directly",
        true);
    };
  }

  return {
    protocol:  "local",
    rootDir:   rootDir,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
    presignedUploadUrl:    _presignNotSupported("upload"),
    presignedDownloadUrl:  _presignNotSupported("download"),
    presignedUploadPolicy: function () {
      throw _err("PRESIGN_NOT_SUPPORTED",
        "local backend does not issue presigned upload policies — " +
        "clients on the same host should call storage.saveFile() directly " +
        "with their own size validation", true);
    },
  };
}

module.exports = { create: create };
