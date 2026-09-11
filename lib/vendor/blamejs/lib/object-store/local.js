// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var cluster = require("../cluster");
var { ObjectStoreError } = require("../framework-error");

var SAFE_KEY = /^[A-Za-z0-9_\-./]+$/;

function _resolveSafe(rootDir, key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("objectstore/invalid-key", "key must be a non-empty string", true);
  }
  if (key.includes("\0")) throw _err("objectstore/invalid-key", "null byte in key", true);
  if (nodePath.isAbsolute(key)) throw _err("objectstore/invalid-key", "absolute key not allowed", true);
  if (!SAFE_KEY.test(key)) throw _err("objectstore/invalid-key", "invalid characters in key", true);
  var full = nodePath.resolve(rootDir, key);
  var withSep = rootDir.endsWith(nodePath.sep) ? rootDir : rootDir + nodePath.sep;
  if (full !== rootDir && !full.startsWith(withSep)) {
    throw _err("objectstore/invalid-key", "key escapes rootDir", true);
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
      return atomicFile.writeStream(full, body, {
        fileMode: 0o600,
        maxBytes: C.BYTES.gib(64),
      }).then(function (r) { return { size: r.bytesWritten }; });
    }
    if (typeof body === "string") {
      var buf = Buffer.from(body, "utf8");
      atomicFile.writeSync(full, buf);
      return Promise.resolve({ size: buf.length });
    }
    return Promise.reject(_err("objectstore/invalid-body", "put body must be Buffer, Readable, or string", true));
  }

  function get(key) {
    var full = _resolveSafe(rootDir, key);
    try {
      return Promise.resolve(atomicFile.fdSafeReadSync(full, {
        maxBytes: C.BYTES.mib(64),
        errorFor: function (kind, detail) {
          if (kind === "enoent") return _err("objectstore/not-found", "key not found: " + key, true);
          if (kind === "too-large") {
            return _err("objectstore/object-too-large", "object " + key + " exceeds the buffered-get read cap (" +
              detail.size + " > " + detail.max + " bytes) — use getStream()", true);
          }
          return _err("objectstore/read-failed", "failed to read " + key, true);
        },
      }));
    } catch (e) { return Promise.reject(e); }
  }

  function getStream(key) {
    var full = _resolveSafe(rootDir, key);
    var fd;
    try { fd = nodeFs.openSync(full, "r"); }
    catch (e) {
      if (e && e.code === "ENOENT") throw _err("objectstore/not-found", "key not found: " + key, true);
      throw e;
    }
    return nodeFs.createReadStream(full, { fd: fd });
  }

  function head(key) {
    var full = _resolveSafe(rootDir, key);
    if (!nodeFs.existsSync(full)) {
      return Promise.reject(_err("objectstore/not-found", "key not found: " + key, true));
    }
    var stat = nodeFs.statSync(full);
    return Promise.resolve({
      size:         stat.size,
      lastModified: stat.mtimeMs,
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    if (opts.versionId) {
      throw _err("objectstore/versionid-unsupported",
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
      throw _err("objectstore/presign-not-supported",
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
      throw _err("objectstore/presign-not-supported",
        "local backend does not issue presigned upload policies — " +
        "clients on the same host should call storage.saveFile() directly " +
        "with their own size validation", true);
    },
  };
}

module.exports = { create: create };
