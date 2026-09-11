// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var zlib = require("node:zlib");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var { boot } = require("./log");
var time = require("./time");
var { LogStreamError } = require("./framework-error");

var log = boot("log-stream-local");

var DEFAULTS = {
  maxFileBytes:      C.BYTES.mib(100),
  maxFileAgeMs:      C.TIME.days(7),
  keepRotations:     30,
  compressRotations: true,
  fileMode:          0o600,
  fileNamePrefix:    "blamejs",
};

var _err = LogStreamError.factory;

function create(config) {
  if (!config || !config.dir) throw new Error("log-stream local requires { dir }");
  var cfg = Object.assign({}, DEFAULTS, config);
  var dir = nodePath.resolve(cfg.dir);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var activePath = nodePath.join(dir, cfg.fileNamePrefix + ".log");
  var fd = null;
  var openedAt = 0;
  var bytesWritten = 0;

  function _open() {
    try {
      fd = atomicFile.openAppendNoFollowSync(activePath, cfg.fileMode);
    } catch (e) {
      if (e && e.code === "ELOOP") {
        throw _err("log-stream-local/symlink-refused",
          "refusing to open log at a symlink: " + activePath, true);
      }
      throw e;
    }
    openedAt = Date.now();
    try {
      var stat = nodeFs.fstatSync(fd);
      bytesWritten = stat.size;
    } catch (_e) {
      bytesWritten = 0;
    }
  }
  _open();

  function _shouldRotate() {
    if (cfg.maxFileBytes && bytesWritten >= cfg.maxFileBytes) return true;
    if (cfg.maxFileAgeMs && (Date.now() - openedAt) >= cfg.maxFileAgeMs) return true;
    return false;
  }

  function _rotate() {
    try {
      if (fd != null) {
        try { nodeFs.closeSync(fd); }
        catch (e) { log.warn("rotate-close-failed: " + e.message); }
        fd = null;
      }
      var stamp = time.toIso8601NoMs(new Date()).replace(/[-:]/g, "");
      var rotated = nodePath.join(dir, cfg.fileNamePrefix + "-" + stamp + ".log");
      if (nodeFs.existsSync(activePath)) {
        atomicFile.renameWithRetry(activePath, rotated);
        if (cfg.compressRotations) {
          var data = nodeFs.readFileSync(rotated);
          var gz = zlib.gzipSync(data);
          atomicFile.writeSync(rotated + ".gz", gz, { fileMode: cfg.fileMode });
          nodeFs.unlinkSync(rotated);
        }
      }
      _pruneOld();
    } finally {
      _open();
    }
  }

  function _pruneOld() {
    if (!cfg.keepRotations || cfg.keepRotations <= 0) return;
    var entries = atomicFile.listDir(dir, {
      filter: function (f) {
        return f.startsWith(cfg.fileNamePrefix + "-") &&
          (f.endsWith(".log") || f.endsWith(".log.gz"));
      },
      includeStat: true,
    }).sort(function (a, b) { return b.mtimeMs - a.mtimeMs; });
    for (var i = cfg.keepRotations; i < entries.length; i++) {
      try { nodeFs.unlinkSync(entries[i].fullPath); } catch (_e) { /* best effort */ }
    }
  }

  function emit(record) {
    if (_shouldRotate()) _rotate();
    var line = JSON.stringify(record) + "\n";
    var buf = Buffer.from(line, "utf8");
    nodeFs.writeSync(fd, buf, 0, buf.length, null);
    bytesWritten += buf.length;
    return Promise.resolve({ bytes: buf.length });
  }

  function close() {
    if (fd != null) {
      try { nodeFs.fsyncSync(fd); } catch (_e) { /* best effort */ }
      try { nodeFs.closeSync(fd); }
      catch (e) { log.warn("close-failed: " + e.message); }
      fd = null;
    }
    return Promise.resolve();
  }

  function getActivePath() { return activePath; }

  return {
    protocol:      "local",
    emit:          emit,
    close:         close,
    rotate:        function () { _rotate(); return Promise.resolve(); },
    getActivePath: getActivePath,
  };
}

module.exports = { create: create };
