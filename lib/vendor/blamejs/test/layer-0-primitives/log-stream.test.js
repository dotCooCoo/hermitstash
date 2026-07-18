// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.logStream — dispatcher introspection (listSinks), the debug level
 * wrapper, and env-driven boot (bootFromEnv).
 *
 * Run standalone: `node test/layer-0-primitives/log-stream.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;

var OTLP_URL = "https://collector.example.com:4318/v1/logs";

function _resetLogStream() { b.logStream._resetForTest(); }
function _mkTmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-logstream-")); }
function _rmTmp(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ } }

// ---- listSinks ----

function testListSinksEmptyBeforeInit() {
  _resetLogStream();
  var snap = b.logStream.listSinks();
  check("logStream.listSinks: returns [] before init (health endpoints call it unconditionally)",
        Array.isArray(snap) && snap.length === 0);
}

async function testListSinksReportsConfiguredSinks() {
  _resetLogStream();
  var dir = _mkTmp();
  try {
    b.logStream.init({
      minLevel: "info",
      sinks: {
        file:   { protocol: "local", dir: dir },
        remote: { protocol: "otlp",  url: OTLP_URL, serviceName: "checkout" },
      },
    });
    var snap = b.logStream.listSinks();
    check("listSinks: one descriptor per configured sink", snap.length === 2);
    var byName = {};
    snap.forEach(function (d) { byName[d.name] = d; });
    check("listSinks: descriptor carries name + protocol (local)",
          byName.file && byName.file.protocol === "local");
    check("listSinks: a sink without a stats() method reports stats: null",
          byName.file.stats === null);
    check("listSinks: descriptor carries name + protocol (otlp)",
          byName.remote && byName.remote.protocol === "otlp");
    check("listSinks: a sink exposing stats() reports through it",
          byName.remote.stats && typeof byName.remote.stats === "object" &&
          byName.remote.stats.url === OTLP_URL);
  } finally {
    await b.logStream.shutdown();
    _resetLogStream();
    _rmTmp(dir);
  }
}

// ---- debug ----

async function testDebugEmitsWhenMinLevelDebug() {
  _resetLogStream();
  var dir = _mkTmp();
  try {
    b.logStream.init({ minLevel: "debug", sinks: { file: { protocol: "local", dir: dir } } });
    b.logStream.debug("cache lookup", { shard: 3, hit: false });
    await b.logStream.shutdown();   // drains in-flight fire-and-forget emits before close
    var body = fs.readFileSync(path.join(dir, "blamejs.log"), "utf8");
    var rows = body.trim().split("\n").filter(Boolean).map(function (l) { return JSON.parse(l); });
    check("logStream.debug: record reaches the sink at minLevel debug", rows.length === 1);
    check("logStream.debug: record level is 'debug'", rows[0].level === "debug");
    check("logStream.debug: message preserved", rows[0].message === "cache lookup");
    check("logStream.debug: non-sensitive meta preserved through redaction", rows[0].meta.shard === 3);
  } finally {
    _resetLogStream();
    _rmTmp(dir);
  }
}

async function testDebugDroppedBelowDefaultMinLevel() {
  _resetLogStream();
  var dir = _mkTmp();
  try {
    // Default minLevel is "info" — debug records drop before the sink.
    b.logStream.init({ sinks: { file: { protocol: "local", dir: dir } } });
    b.logStream.debug("debug-should-drop", { shard: 1 });
    b.logStream.info("info-should-keep", { shard: 2 });
    await b.logStream.shutdown();
    var body = fs.readFileSync(path.join(dir, "blamejs.log"), "utf8");
    check("logStream.debug: dropped below default minLevel (never written)",
          body.indexOf("debug-should-drop") === -1);
    check("logStream.debug: sibling info at/above minLevel is written",
          body.indexOf("info-should-keep") !== -1);
  } finally {
    _resetLogStream();
    _rmTmp(dir);
  }
}

// ---- bootFromEnv ----

function testBootFromEnvSkipsWhenProtocolUnset() {
  _resetLogStream();
  var wired = b.logStream.bootFromEnv({ env: {} });
  check("logStream.bootFromEnv: returns false when BLAMEJS_LOG_STREAM_PROTOCOL unset", wired === false);
  check("logStream.bootFromEnv: no sink wired on skip", b.logStream.listSinks().length === 0);
  _resetLogStream();
}

async function testBootFromEnvWiresSinkFromProcessEnv() {
  _resetLogStream();
  // Exercise the default process.env branch (no opts.env). Snapshot the
  // exact keys touched and restore them in finally so the test leaks no env.
  var KEYS = [
    "BLAMEJS_LOG_STREAM_PROTOCOL",
    "BLAMEJS_LOG_STREAM_URL",
    "BLAMEJS_LOG_STREAM_SERVICE_NAME",
    "BLAMEJS_LOG_STREAM_MIN_LEVEL",
  ];
  var saved = {};
  KEYS.forEach(function (k) { saved[k] = process.env[k]; });
  try {
    process.env.BLAMEJS_LOG_STREAM_PROTOCOL     = "otlp";
    process.env.BLAMEJS_LOG_STREAM_URL          = OTLP_URL;
    process.env.BLAMEJS_LOG_STREAM_SERVICE_NAME = "checkout";
    process.env.BLAMEJS_LOG_STREAM_MIN_LEVEL    = "info";

    var wired = b.logStream.bootFromEnv();   // reads process.env
    check("bootFromEnv: returns true when protocol set", wired === true);
    var snap = b.logStream.listSinks();
    check("bootFromEnv: wires exactly one sink named 'primary'",
          snap.length === 1 && snap[0].name === "primary");
    check("bootFromEnv: sink protocol matches env", snap[0].protocol === "otlp");
    check("bootFromEnv: otlp sink carries the configured URL",
          snap[0].stats && snap[0].stats.url === OTLP_URL);
  } finally {
    await b.logStream.shutdown();
    KEYS.forEach(function (k) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    });
    _resetLogStream();
  }
}

async function testBootFromEnvWiresLocalSinkEndToEnd() {
  _resetLogStream();
  var dir = _mkTmp();
  try {
    // The local sink is directory-based; BLAMEJS_LOG_STREAM_PATH names that
    // directory. bootFromEnv must map it to the sink's `dir` config so the
    // documented `local` protocol actually wires (not throw at init).
    var wired = b.logStream.bootFromEnv({
      env: {
        BLAMEJS_LOG_STREAM_PROTOCOL:  "local",
        BLAMEJS_LOG_STREAM_PATH:      dir,
        BLAMEJS_LOG_STREAM_MIN_LEVEL: "debug",
      },
    });
    check("bootFromEnv: local protocol wires a sink from BLAMEJS_LOG_STREAM_PATH", wired === true);
    var snap = b.logStream.listSinks();
    check("bootFromEnv: local sink registered", snap.length === 1 && snap[0].protocol === "local");

    b.logStream.info("boot-from-env-local", { shard: 7 });
    await b.logStream.shutdown();
    var body = fs.readFileSync(path.join(dir, "blamejs.log"), "utf8");
    check("bootFromEnv: the env-wired local sink actually wrote the record",
          body.indexOf("boot-from-env-local") !== -1);
  } finally {
    _resetLogStream();
    _rmTmp(dir);
  }
}

function testBootFromEnvThrowsUnknownProtocol() {
  _resetLogStream();
  var threw = null;
  try { b.logStream.bootFromEnv({ env: { BLAMEJS_LOG_STREAM_PROTOCOL: "kafka" } }); }
  catch (e) { threw = e; }
  check("bootFromEnv: unknown protocol throws a loud boot error",
        threw && /not one of/.test(threw.message));
  _resetLogStream();
}

async function run() {
  testListSinksEmptyBeforeInit();
  await testListSinksReportsConfiguredSinks();
  await testDebugEmitsWhenMinLevelDebug();
  await testDebugDroppedBelowDefaultMinLevel();
  testBootFromEnvSkipsWhenProtocolUnset();
  await testBootFromEnvWiresSinkFromProcessEnv();
  await testBootFromEnvWiresLocalSinkEndToEnd();
  testBootFromEnvThrowsUnknownProtocol();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("log-stream tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
