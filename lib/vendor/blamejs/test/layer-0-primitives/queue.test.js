// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * queue.bootFromEnv — env-driven queue init mirroring
 * network.bootFromEnv. Reads BLAMEJS_QUEUE_* from a supplied fixture env
 * and wires a single `default` backend; idempotent; throws INVALID_CONFIG
 * on an unknown protocol or a redis selection with no URL.
 *
 * Run standalone: `node test/layer-0-primitives/queue.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function testBootFromEnvRejectsUnknownProtocol() {
  b.queue._resetForTest();
  var threw = null;
  try { b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "wibble" } }); } catch (e) { threw = e; }
  check("queue.bootFromEnv rejects an unknown protocol", threw && threw.code === "INVALID_CONFIG");
  // The failed boot left the queue uninitialized (the throw was pre-init).
  var listThrew = null;
  try { b.queue.listBackends(); } catch (e) { listThrew = e; }
  check("queue stays uninitialized after a rejected boot",
        listThrew && listThrew.code === "NOT_INITIALIZED");
}

function testBootFromEnvRedisRequiresUrl() {
  b.queue._resetForTest();
  var threw = null;
  try { b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "redis" } }); } catch (e) { threw = e; }
  check("queue.bootFromEnv redis without URL throws INVALID_CONFIG",
        threw && threw.code === "INVALID_CONFIG");
}

function testBootFromEnvLocalDefault() {
  b.queue._resetForTest();
  try {
    b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "local" } });
    var backends = b.queue.listBackends();
    check("queue.bootFromEnv local wires exactly one backend", backends.length === 1);
    check("queue.bootFromEnv local backend is named 'default' with protocol 'local'",
          backends[0].name === "default" && backends[0].protocol === "local");

    // Idempotent — a second boot after init is a no-op.
    b.queue.bootFromEnv({ env: { BLAMEJS_QUEUE_PROTOCOL: "local" } });
    check("queue.bootFromEnv is idempotent after init",
          b.queue.listBackends().length === 1);
  } finally {
    b.queue._resetForTest();
  }
}

function testBootFromEnvDefaultsToLocal() {
  b.queue._resetForTest();
  try {
    // No BLAMEJS_QUEUE_PROTOCOL → defaults to the local protocol.
    b.queue.bootFromEnv({ env: {} });
    var backends = b.queue.listBackends();
    check("queue.bootFromEnv defaults to the local protocol when unset",
          backends.length === 1 && backends[0].protocol === "local");
  } finally {
    b.queue._resetForTest();
  }
}

async function run() {
  testBootFromEnvRejectsUnknownProtocol();
  testBootFromEnvRedisRequiresUrl();
  testBootFromEnvLocalDefault();
  testBootFromEnvDefaultsToLocal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[queue] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
