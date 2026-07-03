// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Cluster fixture helpers.
 *
 * _setupClusterGateFixture: init cluster mode, then immediately shut it
 * down. The local node becomes a follower (isLeader returns false) so
 * write-side gate tests can verify NotLeaderError.
 *
 * _expectNotLeaderError: assertion helper that handles both sync throw
 * and async rejection paths uniformly.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../../index.js");
var { setupTestDb, teardownTestDb } = require("./db");
var { _makeSqliteDriver } = require("./drivers");
var { check } = require("./check");

async function _setupClusterGateFixture() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-gate-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);

  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: {
      "ops": { connect: driver.connect, query: driver.query, close: driver.close },
    },
  });
  await b.cluster.init({
    nodeId:            "gate-test-node",
    externalDbBackend: "ops",
    dialect:           "sqlite",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
  });
  await b.cluster.shutdown();

  return {
    tmpDir: tmpDir,
    teardown: async function () {
      try { await b.externalDb.shutdown(); } catch (_e) {}
      driver._close();
      await teardownTestDb(tmpDir);
    },
  };
}

function _expectNotLeaderError(label, fn) {
  var threw = null;
  try {
    var maybePromise = fn();
    if (maybePromise && typeof maybePromise.then === "function") {
      return maybePromise.then(function () {
        check(label + " — should have thrown", false);
      }, function (e) {
        check(label + " — throws NotLeaderError", e && e.code === "NOT_LEADER");
      });
    }
  } catch (e) { threw = e; }
  check(label + " — throws NotLeaderError", threw && threw.code === "NOT_LEADER");
}

module.exports = {
  _setupClusterGateFixture: _setupClusterGateFixture,
  _expectNotLeaderError:    _expectNotLeaderError,
};
