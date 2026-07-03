// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.atomicFile.renameWithRetry — the bounded retry on a Windows-transient
// destination lock (EPERM/EACCES/EBUSY from AV / search indexer / Dropbox /
// OneDrive briefly holding the target). #146: httpClient.downloadStream and
// every other final temp->dest rename route through this instead of a bare
// nodeFs.renameSync, so a transient lock is retried, not surfaced as a hard
// failure. A non-transient error (ENOENT, etc.) still throws immediately.

var nodeFs = require("node:fs");
var os     = require("node:os");
var path   = require("node:path");
var helpers = require("../helpers");
var check   = helpers.check;
var atomicFile = require("../../lib/atomic-file");

function run() {
  check("renameWithRetry is exported", typeof atomicFile.renameWithRetry === "function");

  var dir = nodeFs.mkdtempSync(path.join(os.tmpdir(), "renameretry-"));
  var realRename = nodeFs.renameSync;

  // ---- transient EPERM is retried, then the rename succeeds ----
  var src1 = path.join(dir, "a.tmp");
  var dst1 = path.join(dir, "a.dst");
  nodeFs.writeFileSync(src1, "payload");
  var calls = 0;
  nodeFs.renameSync = function (from, to) {
    calls += 1;
    if (calls < 3) { var e = new Error("transient lock"); e.code = "EPERM"; throw e; }
    return realRename(from, to);
  };
  try { atomicFile.renameWithRetry(src1, dst1); }
  finally { nodeFs.renameSync = realRename; }
  check("renameWithRetry retries past a transient EPERM (3 attempts)", calls === 3);
  check("renameWithRetry: the rename ultimately succeeds",
    nodeFs.existsSync(dst1) && !nodeFs.existsSync(src1));

  // ---- a non-transient error throws immediately, with NO retry ----
  var attempts = 0;
  nodeFs.renameSync = function () {
    attempts += 1;
    var e = new Error("no such file"); e.code = "ENOENT"; throw e;
  };
  var threw = null;
  try { atomicFile.renameWithRetry(path.join(dir, "missing"), path.join(dir, "x")); }
  catch (e) { threw = e; }
  finally { nodeFs.renameSync = realRename; }
  check("renameWithRetry rethrows a non-transient error", threw !== null && threw.code === "ENOENT");
  check("renameWithRetry does NOT retry a non-transient error", attempts === 1);

  // ---- a persistently-transient lock eventually gives up (does not hang) ----
  var stuck = 0;
  nodeFs.renameSync = function () {
    stuck += 1;
    var e = new Error("still locked"); e.code = "EBUSY"; throw e;
  };
  var stuckThrew = null;
  try { atomicFile.renameWithRetry(path.join(dir, "s"), path.join(dir, "d")); }
  catch (e) { stuckThrew = e; }
  finally { nodeFs.renameSync = realRename; }
  check("renameWithRetry gives up after the bounded attempts (no infinite loop)",
    stuckThrew !== null && stuckThrew.code === "EBUSY" && stuck === 5);
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[atomic-file-rename-retry] OK"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
