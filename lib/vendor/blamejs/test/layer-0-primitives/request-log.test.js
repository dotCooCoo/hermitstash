// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.requestLog — HTTP access-log middleware.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _captureLogger() {
  var entries = [];
  function _make(level) {
    return function () {
      var args = Array.prototype.slice.call(arguments);
      entries.push({ level: level, args: args });
    };
  }
  return {
    info:  _make("info"),
    warn:  _make("warn"),
    error: _make("error"),
    debug: _make("debug"),
    _entries: entries,
  };
}

function _mockReq(over) {
  return Object.assign({
    method:  "GET",
    url:     "/api/widget?id=42",
    pathname: "/api/widget",
    headers: { "user-agent": "test-agent" },
    socket:  { remoteAddress: "127.0.0.1" },
  }, over || {});
}

function _mockRes() {
  var statusFromWriteHead = null;
  var ended = false;
  var listeners = {};
  var bodyChunks = [];
  return {
    statusCode: 200,
    writeHead: function (s) { statusFromWriteHead = s; },
    write:     function (c) { if (c != null) bodyChunks.push(c); return true; },
    end:       function (c) { if (c != null) bodyChunks.push(c); ended = true;
                              if (listeners.finish) listeners.finish();
                              if (listeners.close) listeners.close(); },
    on:        function (e, fn) { listeners[e] = fn; },
    once:      function (e, fn) { listeners[e] = fn; },
    _captured: function () { return { statusFromWriteHead: statusFromWriteHead, ended: ended, body: bodyChunks }; },
  };
}

function _drive(mw, req, res) {
  return new Promise(function (resolve) {
    mw(req, res, function () {
      res.statusCode = res.statusCode || 200;
      res.end("ok");
      resolve();
    });
  });
}

async function run() {
  // ---- Surface ----
  check("b.middleware.requestLog is fn",  typeof b.middleware.requestLog === "function");

  // ---- create() rejects bad opts ----
  function rejects(label, fn, re) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("rejects: " + label, threw && re.test(threw.message || ""));
  }
  rejects("missing logger",          function () { b.middleware.requestLog(); }, /logger must be/);
  rejects("non-logger logger",       function () { b.middleware.requestLog({ logger: {} }); }, /logger must be/);
  rejects("bad skipPaths entry",     function () { b.middleware.requestLog({ logger: _captureLogger(), skipPaths: [42] }); }, /skipPaths/);
  rejects("ReDoS skipPaths RegExp",  function () { b.middleware.requestLog({ logger: _captureLogger(), skipPaths: [/((a)+)+$/] }); }, /./);

  // ---- Happy path: 200 → info ----
  var logger = _captureLogger();
  var mw = b.middleware.requestLog({ logger: logger });
  var req = _mockReq();
  var res = _mockRes();
  await _drive(mw, req, res);
  check("requestLog: emitted 1 entry",       logger._entries.length === 1);
  check("requestLog: 200 → info level",      logger._entries[0].level === "info");
  var entry = logger._entries[0].args[1];
  check("requestLog: method captured",       entry.method === "GET");
  check("requestLog: path captured",         entry.path === "/api/widget");
  check("requestLog: status captured",       entry.status === 200);
  check("requestLog: durationMs is number",  typeof entry.durationMs === "number");
  check("requestLog: bytes counted",         entry.bytes === 2);   // "ok"
  check("requestLog: actorIp from socket",   entry.actorIp === "127.0.0.1");
  check("requestLog: userAgent captured",    entry.userAgent === "test-agent");

  // ---- 4xx → warn, 5xx → error ----
  var logger2 = _captureLogger();
  var mw2 = b.middleware.requestLog({ logger: logger2 });
  var req2 = _mockReq();
  var res2 = _mockRes();
  res2.statusCode = 404;
  await _drive(mw2, req2, res2);
  check("requestLog: 404 → warn",  logger2._entries[0].level === "warn");

  var logger3 = _captureLogger();
  var mw3 = b.middleware.requestLog({ logger: logger3 });
  var req3 = _mockReq();
  var res3 = _mockRes();
  res3.statusCode = 500;
  await _drive(mw3, req3, res3);
  check("requestLog: 500 → error",  logger3._entries[0].level === "error");

  // ---- skipPaths ----
  var logger4 = _captureLogger();
  var mw4 = b.middleware.requestLog({
    logger:    logger4,
    skipPaths: ["/healthz", /^\/static/],
  });
  await _drive(mw4, _mockReq({ pathname: "/healthz", url: "/healthz" }), _mockRes());
  await _drive(mw4, _mockReq({ pathname: "/static/x.css", url: "/static/x.css" }), _mockRes());
  await _drive(mw4, _mockReq(), _mockRes());
  check("requestLog: skipPaths string skips",  logger4._entries.length === 1);
  check("requestLog: skipPaths regex skips",   logger4._entries[0].args[1].path === "/api/widget");

  // ---- custom level (static) ----
  var logger5 = _captureLogger();
  var mw5 = b.middleware.requestLog({ logger: logger5, level: "debug" });
  await _drive(mw5, _mockReq(), _mockRes());
  check("requestLog: static level applied",     logger5._entries[0].level === "debug");

  // ---- levelFn ----
  var logger6 = _captureLogger();
  var mw6 = b.middleware.requestLog({
    logger:  logger6,
    levelFn: function (status) { return status >= 200 && status < 300 ? "warn" : "info"; },
  });
  await _drive(mw6, _mockReq(), _mockRes());
  check("requestLog: levelFn applied",          logger6._entries[0].level === "warn");

  // ---- trustProxy honored ----
  var logger7 = _captureLogger();
  var mw7 = b.middleware.requestLog({ logger: logger7, trustProxy: true });
  var reqXff = _mockReq({ headers: { "user-agent": "ua", "x-forwarded-for": "203.0.113.5, 10.0.0.1" } });
  await _drive(mw7, reqXff, _mockRes());
  check("requestLog: trustProxy reads XFF",     logger7._entries[0].args[1].actorIp === "203.0.113.5");

  // ---- trustProxy false (default) ignores XFF ----
  var logger8 = _captureLogger();
  var mw8 = b.middleware.requestLog({ logger: logger8 });
  var reqXff2 = _mockReq({ headers: { "user-agent": "ua", "x-forwarded-for": "203.0.113.5" } });
  await _drive(mw8, reqXff2, _mockRes());
  check("requestLog: default refuses XFF",      logger8._entries[0].args[1].actorIp === "127.0.0.1");

  // ---- fields filter ----
  var logger9 = _captureLogger();
  var mw9 = b.middleware.requestLog({ logger: logger9, fields: ["method", "status"] });
  await _drive(mw9, _mockReq(), _mockRes());
  var f = logger9._entries[0].args[1];
  check("requestLog: fields filter keeps listed", f.method && f.status);
  check("requestLog: fields filter drops others", f.actorIp === undefined && f.bytes === undefined);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
