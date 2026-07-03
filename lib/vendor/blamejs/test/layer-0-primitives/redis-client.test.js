// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * RESP protocol parser + URL parsing tests. These cover the bespoke
 * client's pure functions (no socket needed). Live Redis round-trip
 * coverage lives in queue-redis.test.js (which skips cleanly when
 * BLAMEJS_TEST_REDIS_URL is not set).
 */
var net = require("node:net");
var helpers = require("../helpers");
var check = helpers.check;
var redis = require("../../lib/redis-client");

function _bytes(s) { return Buffer.from(s, "utf8"); }

function _listen(onConn) {
  return new Promise(function (resolve) {
    var server = net.createServer(function (sock) {
      sock.on("error", function () { /* absorb server-side socket errors */ });
      if (onConn) onConn(sock);
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({ port: server.address().port, server: server,
                close: function () { return new Promise(function (r) { server.close(r); }); } });
    });
  });
}

async function run() {
  // ---- _parseRedisUrl ----
  var u1 = redis._parseRedisUrl("redis://localhost:6379/0");
  check("url: defaults", u1.host === "localhost" && u1.port === 6379 && u1.tls === false && u1.db === 0);

  var u2 = redis._parseRedisUrl("rediss://user:pw@cache.example.com:6380/3");
  check("url: rediss + auth + db", u2.host === "cache.example.com" && u2.port === 6380 &&
                                    u2.tls === true && u2.username === "user" &&
                                    u2.password === "pw" && u2.db === 3);

  var u3 = redis._parseRedisUrl("redis://:secretonly@h:6379");
  check("url: legacy single-arg AUTH (empty user, password)",
        u3.username === null && u3.password === "secretonly");

  var u4 = redis._parseRedisUrl("redis://h:6379/15");
  check("url: max db 15 OK", u4.db === 15);

  var threwBadDb = false;
  try { redis._parseRedisUrl("redis://h:6379/16"); } catch (_e) { threwBadDb = true; }
  check("url: db > 15 throws", threwBadDb);

  var threwBadProto = false;
  try { redis._parseRedisUrl("http://h:6379/0"); } catch (_e) { threwBadProto = true; }
  check("url: non-redis protocol throws", threwBadProto);

  // ---- _encodeCommand ----
  var enc1 = redis._encodeCommand(["SET", "key", "value"]);
  check("encode: SET key value", enc1.toString("utf8") === "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");

  var enc2 = redis._encodeCommand(["GET", "x"]);
  check("encode: short cmd", enc2.toString("utf8") === "*2\r\n$3\r\nGET\r\n$1\r\nx\r\n");

  // Binary-safe: a Buffer arg with embedded NULs survives
  var binArg = Buffer.from([0x00, 0xff, 0x10, 0x42]);
  var enc3 = redis._encodeCommand(["HSET", "k", "field", binArg]);
  // *4\r\n            (4)
  // $4\r\nHSET\r\n    (10)
  // $1\r\nk\r\n       (7)
  // $5\r\nfield\r\n   (11)
  // $4\r\n<bin>\r\n   (4 + 4 + 2 = 10)
  check("encode: binary arg length", enc3.length === 4 + 10 + 7 + 11 + 10);
  // Find the binary blob — last 6 bytes should be "<bin>\r\n"
  check("encode: binary arg bytes preserved",
        enc3.slice(enc3.length - 6, enc3.length - 2).equals(binArg));

  var threwNull = false;
  try { redis._encodeCommand(["SET", "k", null]); } catch (_e) { threwNull = true; }
  check("encode: null arg throws", threwNull);

  // ---- _parseFrame ----
  // Simple string
  var f1 = redis._parseFrame(_bytes("+OK\r\n"), 0);
  check("parse: +OK", f1.type === "string" && f1.value === "OK" && f1.consumed === 5);

  // Error
  var f2 = redis._parseFrame(_bytes("-ERR wrong type\r\n"), 0);
  check("parse: error", f2.type === "error" && f2.value === "ERR wrong type");

  // Integer
  var f3 = redis._parseFrame(_bytes(":12345\r\n"), 0);
  check("parse: integer", f3.type === "int" && f3.value === 12345);

  // Bulk
  var f4 = redis._parseFrame(_bytes("$5\r\nhello\r\n"), 0);
  check("parse: bulk", f4.type === "bulk" && f4.value.toString("utf8") === "hello");

  // Nil bulk
  var f5 = redis._parseFrame(_bytes("$-1\r\n"), 0);
  check("parse: nil bulk", f5.type === "bulk" && f5.value === null);

  // Array
  var f6 = redis._parseFrame(_bytes("*3\r\n$3\r\nfoo\r\n$3\r\nbar\r\n:42\r\n"), 0);
  var v6 = redis._frameToValue(f6);
  check("parse: array of 3", Array.isArray(v6) && v6.length === 3 &&
                              v6[0].toString("utf8") === "foo" &&
                              v6[1].toString("utf8") === "bar" &&
                              v6[2] === 42);

  // Nested array
  var f7 = redis._parseFrame(_bytes("*2\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n:7\r\n"), 0);
  var v7 = redis._frameToValue(f7);
  check("parse: nested array", Array.isArray(v7) && Array.isArray(v7[0]) &&
                                 v7[0][0].toString() === "a" && v7[1] === 7);

  // Pathologically deep nesting — a hostile/compromised server can stream
  // an arbitrarily deep nest of single-element arrays to overflow the V8
  // stack out of the socket 'data' handler. The decoder now caps nesting
  // and throws a typed PROTOCOL error rather than recursing to a crash.
  var deepResp = _bytes("*1\r\n".repeat(2000) + ":0\r\n");
  var deepErr = null;
  try { redis._parseFrame(deepResp, 0); } catch (e) { deepErr = e; }
  check("parse: deep RESP nesting throws typed PROTOCOL (not RangeError)",
        deepErr && deepErr.code === "PROTOCOL" && /nesting/.test(deepErr.message || ""));
  // A legitimately nested array (well under the cap) still parses.
  var shallow = redis._parseFrame(_bytes("*1\r\n*1\r\n*1\r\n:9\r\n"), 0);
  check("parse: shallow nested array still parses",
        shallow.type === "array" && shallow.value[0].type === "array");

  // Incomplete frame (mid-bulk)
  var f8 = redis._parseFrame(_bytes("$10\r\nabc"), 0);
  check("parse: incomplete bulk", f8.type === "incomplete");

  // Incomplete frame (no CRLF after marker)
  var f9 = redis._parseFrame(_bytes("+OK"), 0);
  check("parse: incomplete simple string", f9.type === "incomplete");

  // Empty bulk ($0)
  var f10 = redis._parseFrame(_bytes("$0\r\n\r\n"), 0);
  check("parse: empty bulk", f10.type === "bulk" && f10.value.length === 0);

  // Pipelined frames — parse two from one buffer
  var pipelined = _bytes("+OK\r\n:5\r\n");
  var pf1 = redis._parseFrame(pipelined, 0);
  var pf2 = redis._parseFrame(pipelined, pf1.consumed);
  check("parse: pipelined frame 1", pf1.value === "OK");
  check("parse: pipelined frame 2", pf2.value === 5);

  // ---- error frame surfaced via _frameToValue ----
  var efv = redis._frameToValue(redis._parseFrame(_bytes("-ERR boom\r\n"), 0));
  check("frameToValue: error becomes _redisError marker",
        efv && efv._redisError === true && efv.message === "ERR boom");

  // ---- create() config-time opt validation ----
  // db / connectTimeoutMs / commandTimeoutMs / maxReconnectAttempts were
  // coerced with bare Number() + falsy fallback: a bad type silently became
  // the default (or, for a negative timeout, sailed into setTimeout; for a
  // non-numeric maxReconnectAttempts, NaN made the `>= 0` reconnect cap
  // false and disabled the bound entirely). They now throw at the entry
  // point. db and maxReconnectAttempts must still allow 0.
  function _createThrows(label, badOpts) {
    var threw = false;
    var msg = "";
    try { redis.create(Object.assign({ url: "redis://127.0.0.1:1/0" }, badOpts)); }
    catch (e) { threw = true; msg = (e && e.message) || ""; }
    check("create rejects " + label, threw);
    check("create rejects " + label + " with a clear message",
          threw && msg.length > 0 && /must be/.test(msg));
  }

  _createThrows("connectTimeoutMs:\"abc\"", { connectTimeoutMs: "abc" });
  _createThrows("connectTimeoutMs:-1", { connectTimeoutMs: -1 });
  _createThrows("connectTimeoutMs:0", { connectTimeoutMs: 0 });
  _createThrows("commandTimeoutMs:\"abc\"", { commandTimeoutMs: "abc" });
  _createThrows("commandTimeoutMs:-5", { commandTimeoutMs: -5 });
  _createThrows("db:\"3\"", { db: "3" });
  _createThrows("db:-1", { db: -1 });
  _createThrows("db:1.5", { db: 1.5 });
  _createThrows("maxReconnectAttempts:\"abc\"", { maxReconnectAttempts: "abc" });
  _createThrows("maxReconnectAttempts:-1", { maxReconnectAttempts: -1 });
  _createThrows("maxReconnectAttempts:2.5", { maxReconnectAttempts: 2.5 });

  // Absent opts keep the documented defaults.
  var cDefaults = redis.create({ url: "redis://127.0.0.1:6379/0" });
  var sDefaults = cDefaults._state();
  check("create default connectTimeoutMs is 5000", sDefaults.connectTimeoutMs === 5000);
  check("create default commandTimeoutMs is 10000", sDefaults.commandTimeoutMs === 10000);
  check("create default maxReconnectAttempts is 10", sDefaults.maxReconnectAttempts === 10);
  check("create default db comes from url (0)", sDefaults.db === 0);

  // Valid values flow through unchanged.
  var cValid = redis.create({
    url: "redis://127.0.0.1:6379/0",
    db: 7, connectTimeoutMs: 3000, commandTimeoutMs: 8000, maxReconnectAttempts: 3,
  });
  var sValid = cValid._state();
  check("create accepts valid db", sValid.db === 7);
  check("create accepts valid connectTimeoutMs", sValid.connectTimeoutMs === 3000);
  check("create accepts valid commandTimeoutMs", sValid.commandTimeoutMs === 8000);
  check("create accepts valid maxReconnectAttempts", sValid.maxReconnectAttempts === 3);

  // 0 is a legitimate value for both db and maxReconnectAttempts and must
  // NOT throw. db:0 = no SELECT on connect; maxReconnectAttempts:0 = give
  // up immediately (the `reconnectAttempt >= maxReconnectAttempts` gate is
  // true on the first reconnect call) — both preserved from prior behavior.
  var cZero = redis.create({
    url: "redis://127.0.0.1:6379/0", db: 0, maxReconnectAttempts: 0,
  });
  var sZero = cZero._state();
  check("create accepts db:0", sZero.db === 0);
  check("create accepts maxReconnectAttempts:0 (give-up-immediately bound)",
        sZero.maxReconnectAttempts === 0);

  // ---- close()/reconnect leak guard (v0.13.40) ----
  // After close(), a reconnect timer scheduled during backoff must be
  // cancelled and _connect() must refuse to re-open — otherwise a post-
  // close reconnect leaks a fresh socket (and the un-unref'd backoff timer
  // would hold the event loop alive). We test the closing guard directly:
  // connect() after close() is a no-op, so no socket is opened. (The timer
  // is also tracked + unref'd + cleared in close(), mirroring ws-client.)
  var client = redis.create({ url: "redis://127.0.0.1:1/0" });   // port 1 — nothing listens
  await client.close();
  check("redis: closing flag set after close()", client._state().closing === true);
  try { await client.connect(); } catch (_e) { /* closing guard should prevent any connect attempt */ }
  check("redis: connect() after close is a no-op (closing guard — no socket opened)",
        client._state().connected === false);

  // ---- connect-failure does not wedge subsequent callers ----
  // A connect that errors before the connection is fully ready (the socket
  // drops mid-AUTH) must (a) reject the connect promise, (b) clear the
  // shared connect promise so the next connect() starts fresh, and (c)
  // NOT leave connected=true on a torn-down socket. A command issued after
  // the give-up must settle (reject) rather than wedge in the backlog
  // forever.
  {
    var dropMidAuth = await _listen(function (sock) {
      sock.once("data", function () { sock.destroy(); });  // got AUTH → drop
    });
    var c2 = redis.create({
      url: "redis://127.0.0.1:" + dropMidAuth.port + "/0",
      password: "secret", connectTimeoutMs: 1000, commandTimeoutMs: 500,
      maxReconnectAttempts: 0,   // give up immediately on disconnect
    });
    var connErr = null;
    try { await c2.connect(); } catch (e) { connErr = e; }
    check("redis: failed connect (drop mid-AUTH) rejects", connErr !== null);
    var st2 = c2._state();
    check("redis: failed connect leaves connected=false", st2.connected === false);
    check("redis: failed connect clears the shared connect promise (connecting=false)",
          st2.connecting === false);

    // A command after give-up must settle, not hang. Bound the await so a
    // regression surfaces as a timeout instead of a stuck test.
    var cmdSettled = false;
    var cmdErr = null;
    await helpers.withTestTimeout("redis: post-give-up command settles", async function () {
      try { await c2.command("PING"); } catch (e) { cmdErr = e; }
      cmdSettled = true;
    }, { timeoutMs: 4000 });
    check("redis: command after give-up settles (does not wedge)", cmdSettled === true);
    check("redis: command after give-up rejects with RECONNECT_GAVE_UP",
          cmdErr !== null && cmdErr.code === "RECONNECT_GAVE_UP");
    await c2.close();
    await dropMidAuth.close();
  }

  // ---- a backlogged command times out if connect never completes ----
  // Queued-while-disconnected commands must NOT outlive commandTimeoutMs —
  // a backend that never comes up settles the caller with a clear error.
  {
    var c3 = redis.create({
      url: "redis://127.0.0.1:1/0",   // nothing listens; reconnect stays pending
      connectTimeoutMs: 200, commandTimeoutMs: 150, maxReconnectAttempts: 5,
    });
    c3.connect().catch(function () { /* will keep retrying in the background */ });
    var c3Err = null, c3Settled = false;
    await helpers.withTestTimeout("redis: backlogged command times out", async function () {
      try { await c3.command("GET", "k"); } catch (e) { c3Err = e; }
      c3Settled = true;
    }, { timeoutMs: 4000 });
    check("redis: backlogged command settles (does not wedge)", c3Settled === true);
    check("redis: backlogged command rejects with COMMAND_TIMEOUT",
          c3Err !== null && c3Err.code === "COMMAND_TIMEOUT");
    await c3.close();
  }

  // ---- single-flight reconnect: error+close schedule ONE reconnect ----
  // A lost socket surfaces as both an `error` and a `close` event (and the
  // error handler destroys the socket, re-firing close). Each must NOT
  // schedule its own reconnect timer — that doubles the backoff rate and
  // opens redundant sockets. We count distinct inbound connections: after
  // one induced drop, the first reconnect lands as connection #2 (not #3).
  {
    var conns = 0;
    var firstSock = null;
    var reconnectSrv = await _listen(function (sock) {
      conns += 1;
      if (conns === 1) {
        firstSock = sock;
        // Reset the first connection so the client sees error AND close.
        if (sock.resetAndDestroy) sock.resetAndDestroy(); else sock.destroy();
      }
      // Reconnect (conns >= 2): hold open — no further failures.
    });
    var c4 = redis.create({
      url: "redis://127.0.0.1:" + reconnectSrv.port + "/0",
      connectTimeoutMs: 1000, commandTimeoutMs: 500, maxReconnectAttempts: 10,
    });
    await c4.connect().catch(function () {});
    // The first backoff is 100ms; wait until exactly one reconnect lands
    // (connection #2). If error AND close had each scheduled, the budget
    // would have produced a SECOND reconnect (#3) at the bumped delay.
    await helpers.waitUntil(function () { return conns >= 2; },
      { timeoutMs: 3000, label: "redis single-flight: first reconnect connects" });
    var stallObserved = await helpers.passiveObserve(350,
      "redis single-flight: no second reconnect from the same failure")
      .then(function () { return conns; });
    check("redis: single failure schedules exactly one reconnect (no double-schedule)",
          stallObserved === 2);
    check("redis: reconnect count reset toward stable after one successful reconnect",
          c4._state().reconnectPending === false);
    void firstSock;
    await c4.close();
    await reconnectSrv.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
