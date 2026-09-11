// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var atomicFile = require("./atomic-file");
var C = require("./constants");

function isLivePid(pid) {
  if (typeof pid !== "number" || !isFinite(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return !!(e && e.code === "EPERM"); }
}

function readPidFile(pidFile) {
  try {
    var raw = atomicFile.fdSafeReadSync(pidFile, {
      maxBytes: C.BYTES.kib(1), refuseSymlink: true, encoding: "utf8",
    });
    var pid = parseInt(String(raw).trim(), 10);
    return isFinite(pid) && pid > 0 ? pid : null;
  } catch (_e) { return null; }
}

module.exports = {
  isLivePid:   isLivePid,
  readPidFile: readPidFile,
};
