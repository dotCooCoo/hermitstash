// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * RESP protocol parser + URL parsing tests. These cover the bespoke
 * client's pure functions (no socket needed). Live Redis round-trip
 * coverage lives in queue-redis.test.js (which skips cleanly when
 * BLAMEJS_TEST_REDIS_URL is not set).
 */
var fs = require("node:fs");
var net = require("node:net");
var path = require("node:path");
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

// Fake RESP server. Parses each inbound command (the client sends a RESP
// array of bulk strings) with the client's own frame decoder, then hands
// the decoded arg strings to onCommand(args, sock) so a test can script
// per-command replies / pushes / socket resets. Reusing _parseFrame here
// keeps the fixture honest against the exact wire format the encoder emits.
function _respServer(onCommand) {
  return _listen(function (sock) {
    var buf = Buffer.alloc(0);
    sock.on("data", function (chunk) {
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      while (buf.length > 0) {
        var f;
        try { f = redis._parseFrame(buf, 0); }
        catch (_e) { try { sock.destroy(); } catch (_e2) { /* best-effort */ } return; }
        if (f.type === "incomplete") return;
        var val = redis._frameToValue(f);
        buf = buf.slice(f.consumed);
        var args = Array.isArray(val)
          ? val.map(function (x) { return Buffer.isBuffer(x) ? x.toString("utf8") : String(x); })
          : [];
        try { onCommand(args, sock); } catch (_e3) { /* fixture handler error */ }
      }
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

  // ---- _encodeCommand rejects a non-array / empty-array argv ----
  // The argv must be a non-empty array — an empty array (no command) or a
  // non-array both throw BAD_ARGS at the encoder rather than emit a
  // malformed `*0` frame or crash on `.length` of a non-array.
  var encEmpty = null;
  try { redis._encodeCommand([]); } catch (e) { encEmpty = e; }
  check("encode: empty argv throws BAD_ARGS", encEmpty && encEmpty.code === "BAD_ARGS");
  var encNotArr = null;
  try { redis._encodeCommand("PING"); } catch (e) { encNotArr = e; }
  check("encode: non-array argv throws BAD_ARGS", encNotArr && encNotArr.code === "BAD_ARGS");

  // ---- _parseFrame malformed-header + edge frames ----
  // A caller offset already at/after the buffer end is "need more bytes",
  // not an out-of-range read.
  check("parse: offset at buffer end is incomplete",
        redis._parseFrame(_bytes("+OK\r\n"), 5).type === "incomplete");

  // Non-finite length/value headers are a hostile/garbled server, not a
  // silent NaN — each throws a typed PROTOCOL error so _onData tears the
  // socket down instead of parsing a bogus frame.
  function _parseThrows(label, wire, needle) {
    var e = null;
    try { redis._parseFrame(_bytes(wire), 0); } catch (x) { e = x; }
    check("parse: " + label + " throws PROTOCOL",
          e && e.code === "PROTOCOL" && (!needle || needle.test(e.message || "")));
  }
  _parseThrows("non-finite integer reply", ":9x9\r\n", /integer reply not finite/);
  _parseThrows("non-finite bulk length",   "$9x\r\n",  /bulk length not finite/);
  _parseThrows("non-finite array length",  "*9x\r\n",  /array length not finite/);
  _parseThrows("unknown reply marker",     "%2\r\n",   /unknown reply marker/);

  // Null (RESP2 `*-1`) array — distinct from an empty array — decodes to a
  // frame carrying value:null, and _frameToValue collapses it to JS null.
  var nullArrFrame = redis._parseFrame(_bytes("*-1\r\n"), 0);
  check("parse: null array frame", nullArrFrame.type === "array" && nullArrFrame.value === null);
  check("frameToValue: null array becomes null",
        redis._frameToValue(nullArrFrame) === null);

  // Array header promising more elements than the buffer holds is
  // incomplete — the decoder waits for the rest rather than indexing past
  // the end.
  check("parse: array with a truncated element is incomplete",
        redis._parseFrame(_bytes("*2\r\n:1\r\n"), 0).type === "incomplete");

  // _frameToValue on a frame type it never emits as a value (an
  // "incomplete" sentinel handed in directly) is a typed PROTOCOL fault,
  // never an undefined return that a caller would treat as a nil reply.
  var ftvBad = null;
  try { redis._frameToValue({ type: "incomplete" }); } catch (e) { ftvBad = e; }
  check("frameToValue: unhandled frame type throws PROTOCOL",
        ftvBad && ftvBad.code === "PROTOCOL" && /unknown frame type/.test(ftvBad.message || ""));

  // ---- create() with no argument uses the `opts || {}` default, then
  // fails the required-url check with a clear message (not a TypeError on
  // reading opts.url of undefined).
  var noOpts = null;
  try { redis.create(); } catch (e) { noOpts = e; }
  check("create: no opts throws a typed error (opts || {} default)",
        noOpts && noOpts.code === "BAD_OPTS");

  // ---- create() honors an explicit tls opt over the url scheme ----
  // opts.tls (when defined) wins over the redis:/rediss: scheme, in both
  // directions.
  check("create: opts.tls:true overrides redis:// scheme",
        redis.create({ url: "redis://127.0.0.1:6379/0", tls: true })._state().tls === true);
  check("create: opts.tls:false overrides rediss:// scheme",
        redis.create({ url: "rediss://127.0.0.1:6379/0", tls: false })._state().tls === false);

  // ---- _parseRedisUrl edge cases ----
  // A string new URL() rejects surfaces as a typed BAD_URL, not a raw
  // TypeError out of the URL constructor.
  var badUrl = null;
  try { redis._parseRedisUrl("not-a-valid-url"); } catch (e) { badUrl = e; }
  check("url: unparseable string throws BAD_URL", badUrl && badUrl.code === "BAD_URL");

  // Missing host / missing port fall back to 127.0.0.1 / 6379.
  var uNoHostPort = redis._parseRedisUrl("redis:///3");
  check("url: empty host defaults to 127.0.0.1", uNoHostPort.host === "127.0.0.1");
  check("url: empty port defaults to 6379", uNoHostPort.port === 6379);
  check("url: db still parsed from path when host omitted", uNoHostPort.db === 3);
  var uNoPort = redis._parseRedisUrl("redis://example.test/0");
  check("url: host present but port omitted defaults to 6379",
        uNoPort.host === "example.test" && uNoPort.port === 6379);

  // ---- pickClientOpts ----
  // A non-object cfg yields an empty bag rather than throwing on property
  // reads.
  check("pickClientOpts: null cfg → {}",
        Object.keys(redis.pickClientOpts(null)).length === 0);
  check("pickClientOpts: non-object cfg → {}",
        Object.keys(redis.pickClientOpts("nope")).length === 0);
  // Unprefixed: keys read straight off the bag.
  var pcoPlain = redis.pickClientOpts({
    url: "redis://h/0", password: "pw", username: "u", tls: true,
    connectTimeoutMs: 1234,
  });
  check("pickClientOpts: unprefixed reads keys directly",
        pcoPlain.url === "redis://h/0" && pcoPlain.password === "pw" &&
        pcoPlain.username === "u" && pcoPlain.tls === true &&
        pcoPlain.connectTimeoutMs === 1234);
  // Prefixed: camel-cased `redis`+Key lookup.
  var pcoPrefixed = redis.pickClientOpts({
    redisUrl: "redis://h/1", redisPassword: "pw2", redisMaxReconnectAttempts: 4,
  }, "redis");
  check("pickClientOpts: prefixed reads redis<Key> keys",
        pcoPrefixed.url === "redis://h/1" && pcoPrefixed.password === "pw2" &&
        pcoPrefixed.maxReconnectAttempts === 4);
  check("pickClientOpts: prefixed ignores the unprefixed key",
        pcoPrefixed.username === undefined);

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

  // ---- successful connect drives AUTH (ACL username form) + SELECT ----
  // A url-supplied db (>0) plus opts.username+password exercises the
  // ACL-style three-arg AUTH and the SELECT that a non-zero db requires,
  // then a live PING round-trips a simple-string reply through _onData's
  // resolve path. A second connect() on an already-open client is a no-op
  // that resolves immediately (never a second dial). close() on a live
  // socket walks the socket-present teardown.
  {
    var authArgsSeen = null;
    var selectArgsSeen = null;
    var rt = await _respServer(function (args, sock) {
      var cmd = (args[0] || "").toUpperCase();
      if (cmd === "AUTH")   { authArgsSeen = args.slice();   sock.write(_bytes("+OK\r\n")); return; }
      if (cmd === "SELECT") { selectArgsSeen = args.slice(); sock.write(_bytes("+OK\r\n")); return; }
      if (cmd === "PING")   { sock.write(_bytes("+PONG\r\n")); return; }
      sock.write(_bytes("+OK\r\n"));
    });
    var cRt = redis.create({
      url: "redis://127.0.0.1:" + rt.port + "/3",
      username: "acluser", password: "aclpass",
      connectTimeoutMs: 2000, commandTimeoutMs: 2000, maxReconnectAttempts: 0,
    });
    await cRt.connect();
    check("redis: connect resolves against a live RESP server", cRt.isOpen());
    check("redis: AUTH uses the three-arg ACL form when a username is set",
          authArgsSeen && authArgsSeen.length === 3 &&
          authArgsSeen[1] === "acluser" && authArgsSeen[2] === "aclpass");
    check("redis: non-zero url db drives SELECT on connect",
          selectArgsSeen && selectArgsSeen[1] === "3");
    var pong = await cRt.command("PING");
    check("redis: PING round-trips a simple-string reply", pong === "PONG");
    var reconnPromise = cRt.connect();   // already connected → immediate resolve
    check("redis: connect() while connected returns a resolved no-op",
          reconnPromise instanceof Promise);
    await reconnPromise;
    check("redis: still open after the no-op connect()", cRt.isOpen());
    await cRt.close();
    check("redis: close() on a live socket reports closed", !cRt.isOpen());
    await rt.close();
  }

  // ---- a server error reply rejects the in-flight command ----
  // A `-ERR ...` line to a pending command surfaces as a REDIS_REPLY
  // rejection carrying the server text — the FIFO slot is consumed as a
  // reply, not misrouted as a push.
  {
    var errSrv = await _respServer(function (args, sock) {
      var cmd = (args[0] || "").toUpperCase();
      if (cmd === "GET") { sock.write(_bytes("-WRONGTYPE not a string\r\n")); return; }
      sock.write(_bytes("+OK\r\n"));
    });
    var cErr = redis.create({
      url: "redis://127.0.0.1:" + errSrv.port + "/0",
      commandTimeoutMs: 2000, maxReconnectAttempts: 0,
    });
    await cErr.connect();
    var replyErr = null;
    try { await cErr.command("GET", "k"); } catch (e) { replyErr = e; }
    check("redis: server -ERR reply rejects with REDIS_REPLY",
          replyErr && replyErr.code === "REDIS_REPLY" && /WRONGTYPE/.test(replyErr.message || ""));
    check("redis: client stays connected after a server-side error reply",
          cErr.isOpen());
    await cErr.close();
    await errSrv.close();
  }

  // ---- pub/sub push frames route to onPushMessage, not the FIFO ----
  // A server-initiated `message` 3-tuple and `pmessage` 4-tuple are
  // demultiplexed to the push hook (channel/pattern/payload) instead of
  // consuming a pending request slot.
  {
    var pushes = [];
    var pushSrv = await _respServer(function (args, sock) {
      sock.write(_bytes("+OK\r\n"));   // reply to the SUBSCRIBE ack
      sock.write(_bytes("*3\r\n$7\r\nmessage\r\n$3\r\nch1\r\n$5\r\nhello\r\n"));
      sock.write(_bytes("*4\r\n$8\r\npmessage\r\n$2\r\np*\r\n$3\r\nch1\r\n$5\r\nworld\r\n"));
    });
    var cPush = redis.create({
      url: "redis://127.0.0.1:" + pushSrv.port + "/0", maxReconnectAttempts: 0,
      onPushMessage: function (m) { pushes.push(m); },
    });
    await cPush.connect();
    var subAck = await cPush.command("SUBSCRIBE", "ch1");
    check("redis: SUBSCRIBE ack still flows through the FIFO", subAck === "OK");
    await helpers.waitUntil(function () { return pushes.length >= 2; },
      { timeoutMs: 3000, label: "redis pub/sub: both push frames delivered" });
    var pm = pushes[0], ppm = pushes[1];
    check("redis: `message` push → null pattern + channel + payload",
          pm.pattern === null && pm.channel === "ch1" &&
          Buffer.isBuffer(pm.payload) && pm.payload.toString() === "hello");
    check("redis: `pmessage` push → pattern + channel + payload",
          ppm.pattern === "p*" && ppm.channel === "ch1" &&
          Buffer.isBuffer(ppm.payload) && ppm.payload.toString() === "world");
    await cPush.close();
    await pushSrv.close();
  }

  // ---- an orphan frame with no pending request is dropped, FIFO intact ----
  // A server that pushes an unsolicited reply while nothing is in flight
  // (no onPushMessage wired) must drop it without crashing or shifting a
  // non-existent pending entry — a later command still gets its own reply.
  {
    var orphanSrv = await _listen(function (sock) {
      // Push before the client issues anything → pending is empty.
      sock.write(_bytes("+ORPHAN\r\n"));
      sock.on("data", function () { sock.write(_bytes("+LATEOK\r\n")); });
    });
    var cOrphan = redis.create({
      url: "redis://127.0.0.1:" + orphanSrv.port + "/0",
      commandTimeoutMs: 2000, maxReconnectAttempts: 0,
    });
    await cOrphan.connect();
    // Let the orphan arrive + be dropped while pending is empty.
    await helpers.passiveObserve(120, "redis: orphan frame dropped with empty pending");
    check("redis: client survives an orphan frame (no pending)",
          cOrphan.isOpen() && cOrphan._state().pending === 0);
    var lateRv = await cOrphan.command("PING");
    check("redis: FIFO intact after dropping an orphan frame", lateRv === "LATEOK");
    await cOrphan.close();
    await orphanSrv.close();
  }

  // ---- a reply split across two socket reads is reassembled ----
  // The receive buffer concatenates a partial frame with the next chunk;
  // an incomplete parse defers until the rest arrives. The server sends the
  // reply marker, then the remainder after a gap, forcing two `data` events.
  {
    var splitSrv = await _respServer(function (args, sock) {
      sock.write(_bytes("+"));                                        // partial: marker only
      setTimeout(function () { sock.write(_bytes("SPLITOK\r\n")); }, 40);
    });
    var cSplit = redis.create({
      url: "redis://127.0.0.1:" + splitSrv.port + "/0",
      commandTimeoutMs: 3000, maxReconnectAttempts: 0,
    });
    await cSplit.connect();
    var splitRv = await helpers.withTestTimeout("redis: split reply reassembles",
      function () { return cSplit.command("PING"); }, { timeoutMs: 4000 });
    check("redis: reply split across two reads is reassembled", splitRv === "SPLITOK");
    await cSplit.close();
    await splitSrv.close();
  }

  // ---- a malformed reply frame tears the socket down (no host crash) ----
  // An unknown reply marker must not throw out of the `data` handler; it is
  // a fatal connection fault that rejects the in-flight command with the
  // typed PROTOCOL error and disconnects.
  {
    var badSrv = await _respServer(function (args, sock) { sock.write(_bytes("?garbage\r\n")); });
    var cBad = redis.create({
      url: "redis://127.0.0.1:" + badSrv.port + "/0",
      commandTimeoutMs: 2000, maxReconnectAttempts: 0,
    });
    await cBad.connect();
    var badErr = null;
    try { await cBad.command("PING"); } catch (e) { badErr = e; }
    check("redis: malformed reply rejects the command with PROTOCOL",
          badErr && badErr.code === "PROTOCOL");
    check("redis: client disconnects after a protocol fault",
          cBad._state().connected === false);
    await cBad.close();
    await badSrv.close();
  }

  // ---- a peer reset on an established connection surfaces as a socket
  // error (the `error` event path, distinct from a graceful close). The
  // in-flight command rejects and the socket is torn down.
  {
    var resetSrv = await _respServer(function (args, sock) {
      var cmd = (args[0] || "").toUpperCase();
      if (cmd === "BOOM") {
        if (sock.resetAndDestroy) sock.resetAndDestroy(); else sock.destroy();
        return;
      }
      sock.write(_bytes("+OK\r\n"));
    });
    var cReset = redis.create({
      url: "redis://127.0.0.1:" + resetSrv.port + "/0",
      commandTimeoutMs: 2000, maxReconnectAttempts: 0,
    });
    await cReset.connect();
    var resetErr = null;
    try { await cReset.command("BOOM"); } catch (e) { resetErr = e; }
    check("redis: peer reset rejects the in-flight command (socket error path)",
          resetErr && (resetErr.code === "SOCKET" || resetErr.code === "SOCKET_CLOSED"));
    check("redis: client disconnects after a peer reset",
          cReset._state().connected === false);
    await cReset.close();
    await resetSrv.close();
  }

  // ---- concurrent connect() calls share one in-flight dial ----
  // Two _connect() calls issued before the first settles must return the
  // very same promise (not launch two parallel dials).
  {
    var cxSrv = await _respServer(function (args, sock) { sock.write(_bytes("+OK\r\n")); });
    var cCx = redis.create({
      url: "redis://127.0.0.1:" + cxSrv.port + "/0", maxReconnectAttempts: 0,
    });
    var cp1 = cCx.connect();
    var cp2 = cCx.connect();
    check("redis: concurrent connect() returns the same in-flight promise", cp1 === cp2);
    await Promise.all([cp1, cp2]);
    check("redis: concurrent connect() resolves connected", cCx.isOpen());
    await cCx.close();
    await cxSrv.close();
  }

  // ---- a refused dial (nothing listening) rejects with CONNECT ----
  // The connect-phase error handler destroys the half-open socket and
  // rejects with the typed CONNECT error.
  {
    var slot = await _listen(function () {});
    var deadPort = slot.port;
    await slot.close();   // port now guaranteed closed → connection refused
    var cRef = redis.create({
      url: "redis://127.0.0.1:" + deadPort + "/0",
      connectTimeoutMs: 1000, maxReconnectAttempts: 0,
    });
    var refErr = null;
    try { await cRef.connect(); } catch (e) { refErr = e; }
    check("redis: a refused dial rejects with CONNECT", refErr && refErr.code === "CONNECT");
    await cRef.close();
  }

  // ---- a stalled TLS handshake hits the connect-timeout, ca opt applied ----
  // rediss:// against a plain-TCP server never completes the TLS handshake;
  // the connect-timeout fires and destroys the pending socket. The ca
  // bundle is a real (vendored) PEM so tls.connect builds a secure context
  // rather than throwing on a bogus trust root — verification is never
  // weakened (no rejectUnauthorized:false).
  {
    var caBundle = fs.readFileSync(
      path.join(__dirname, "..", "..", "lib", "vendor", "bimi-trust-anchors.pem"));
    var stallSrv = await _listen(function (sock) {
      sock.on("data", function () { /* absorb the ClientHello, never reply */ });
    });
    var cTls = redis.create({
      url: "rediss://localhost:" + stallSrv.port + "/0",
      ca: caBundle, connectTimeoutMs: 300, maxReconnectAttempts: 0,
    });
    check("redis: rediss:// url sets the tls flag", cTls._state().tls === true);
    var tlsErr = null;
    try { await cTls.connect(); } catch (e) { tlsErr = e; }
    check("redis: stalled TLS handshake rejects with CONNECT_TIMEOUT",
          tlsErr && tlsErr.code === "CONNECT_TIMEOUT");
    await cTls.close();
    await stallSrv.close();
  }

  // ---- AUTH that never gets a reply times out the connect ----
  // The connect-time AUTH send is bounded by commandTimeoutMs; a server
  // that accepts but never answers AUTH settles the connect with a
  // COMMAND_TIMEOUT rejection (the pending AUTH slot is evicted).
  {
    var muteSrv = await _listen(function (sock) {
      sock.on("data", function () { /* accept the AUTH bytes, never reply */ });
    });
    var cAuth = redis.create({
      url: "redis://127.0.0.1:" + muteSrv.port + "/0",
      password: "pw", connectTimeoutMs: 1000, commandTimeoutMs: 150, maxReconnectAttempts: 0,
    });
    var authTimeoutErr = null;
    try { await cAuth.connect(); } catch (e) { authTimeoutErr = e; }
    check("redis: unanswered AUTH rejects connect with COMMAND_TIMEOUT",
          authTimeoutErr && authTimeoutErr.code === "COMMAND_TIMEOUT");
    await cAuth.close();
    await muteSrv.close();
  }

  // ---- command() after close() rejects with CLOSED ----
  {
    var cClosed = redis.create({ url: "redis://127.0.0.1:1/0" });
    await cClosed.close();
    var closedErr = null;
    try { await cClosed.command("PING"); } catch (e) { closedErr = e; }
    check("redis: command() after close() rejects with CLOSED",
          closedErr && closedErr.code === "CLOSED");
  }

  await testConnectHandshakeLeavesNoArmedTimer();
}

// The connect handshake issues AUTH (when a password is set) and SELECT (when
// the db is non-zero) through the client's own send path. Those commands must
// clear their command timeout when the reply lands: an un-cleared, un-unref'd
// timer keeps the event loop alive for the whole timeout after the work is
// finished, so a short-lived process that talks to a password-protected redis
// lingers instead of exiting. Counting live Timeout resources is exact — no
// sleeping and no wall-clock threshold to tune.
async function testConnectHandshakeLeavesNoArmedTimer() {
  function _timers() {
    return process.getActiveResourcesInfo().filter(function (r) { return r === "Timeout"; }).length;
  }

  // A long timeout makes a leaked timer unmistakable, and cannot be confused
  // with one that simply expired while the test ran.
  var srv = await _respServer(function (args, sock) { sock.write(_bytes("+OK\r\n")); });
  try {
    var before = _timers();
    var c = redis.create({
      url:              "redis://127.0.0.1:" + srv.port + "/1",   // non-zero db -> SELECT
      password:         "pw",                                     // -> AUTH
      commandTimeoutMs: 60000,
    });
    await c.connect();
    check("handshake: the client is connected after AUTH + SELECT",
      c._state().connected === true);
    await c.close();
    check("handshake: AUTH and SELECT leave no armed command timer behind",
      _timers() <= before);
  } finally {
    await srv.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
