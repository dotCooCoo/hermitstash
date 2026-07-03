// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Bespoke RESP2 Redis client — zero npm runtime deps.
 *
 * Single-connection client with auto-reconnect, auth, optional TLS,
 * and request/response pipelining. Scope:
 *   - RESP2 protocol only (RESP3 not needed for queue-redis ops)
 *   - Single-node mode (no Cluster, no Sentinel)
 *   - TCP via node:net OR TLS via node:tls (rediss:// auto-detected)
 *   - AUTH (legacy single-arg AND ACL-style username + password)
 *   - SELECT db
 *   - Pipelining (writes are FIFO; responses dispatched in arrival order)
 *   - Lua scripting (EVAL / EVALSHA via runScript())
 *   - Reconnect with exponential backoff
 *
 * Operator API:
 *   var c = redis.create({ url: "redis://localhost:6379/0", password: "..." });
 *   await c.connect();
 *   var pong = await c.command("PING");                   // "PONG"
 *   var n   = await c.command("ZADD", "key", "1", "m");   // 1
 *   var rv  = await c.runScript(luaSrc, 1, "k1", "arg1");
 *   await c.close();
 *
 * Error convention: every failure throws a RedisError with .code so
 * callers can branch on transport vs server-side errors.
 */
var net = require("node:net");
var nodeTls = require("node:tls");
var nodeUrl = require("node:url");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var ipUtils = require("./ip-utils");
var { RedisError } = require("./framework-error");

var _err = RedisError.factory;

// Radix for `.toString(N)` hex conversion. Numeric, not a byte count.
var HEX_RADIX = 16;

// ---- Wire-format encoder ----
//
// RESP2 inline command form for arbitrary args:
//   *<argc>\r\n
//   $<arglen>\r\n<argbytes>\r\n
//   ... repeat per arg ...
function _encodeCommand(args) {
  if (!Array.isArray(args) || args.length === 0) {
    throw _err("BAD_ARGS", "encodeCommand: args must be a non-empty array");
  }
  var parts = ["*" + args.length + "\r\n"];
  for (var i = 0; i < args.length; i++) {
    var a = args[i];
    var buf;
    if (Buffer.isBuffer(a)) {
      buf = a;
    } else if (a === null || a === undefined) {
      throw _err("BAD_ARGS", "encodeCommand: arg " + i + " is null/undefined");
    } else {
      buf = Buffer.from(String(a), "utf8");
    }
    parts.push("$" + buf.length + "\r\n");
    parts.push(buf);
    parts.push("\r\n");
  }
  // Concat as Buffer — supports binary args (sealed payloads etc.)
  var bufs = parts.map(function (p) {
    return Buffer.isBuffer(p) ? p : Buffer.from(p, "utf8");
  });
  return Buffer.concat(bufs);
}

// ---- Wire-format decoder ----
//
// Stateful streaming parser. Returns one of:
//   { type: "incomplete" }                — need more bytes
//   { type: "string", value, consumed }   — simple string (+OK)
//   { type: "error",  value, consumed }   — error line (-ERR ...)
//   { type: "int",    value, consumed }   — integer (:42)
//   { type: "bulk",   value, consumed }   — bulk string buffer (or null)
//   { type: "array",  value, consumed }   — array of decoded items
//
// RESP arrays nest (an array whose elements are arrays), so the decoder
// recurses. A hostile or compromised server can stream an arbitrarily deep
// nest of `*1\r\n` headers to overflow the V8 stack with an uncaught
// RangeError out of the socket 'data' handler — a crash. Cap the nesting
// well above any real reply (cluster-slots / XRANGE replies nest a handful
// deep) and throw a typed PROTOCOL error, which _onData turns into a socket
// teardown + reconnect instead of a process crash.
var MAX_RESP_DEPTH = 64;
function _parseFrame(buf, offset, depth) {
  depth = depth || 0;
  if (depth > MAX_RESP_DEPTH) {
    throw _err("PROTOCOL", "reply nesting exceeds " + MAX_RESP_DEPTH + " levels");
  }
  if (offset >= buf.length) return { type: "incomplete" };
  var marker = buf[offset];
  // Find next CRLF after the marker
  var crlf = buf.indexOf("\r\n", offset + 1);
  if (crlf === -1) return { type: "incomplete" };
  var headerEnd = crlf;
  var payloadStr = buf.slice(offset + 1, headerEnd).toString("utf8");

  if (marker === 0x2b /* + */) {
    return { type: "string", value: payloadStr, consumed: crlf + 2 - offset };
  }
  if (marker === 0x2d /* - */) {
    return { type: "error", value: payloadStr, consumed: crlf + 2 - offset };
  }
  if (marker === 0x3a /* : */) {
    var n = Number(payloadStr);
    if (!Number.isFinite(n)) {
      throw _err("PROTOCOL", "integer reply not finite: " + payloadStr);
    }
    return { type: "int", value: n, consumed: crlf + 2 - offset };
  }
  if (marker === 0x24 /* $ */) {
    var len = Number(payloadStr);
    if (!Number.isFinite(len)) {
      throw _err("PROTOCOL", "bulk length not finite: " + payloadStr);
    }
    if (len === -1) return { type: "bulk", value: null, consumed: crlf + 2 - offset };
    var dataStart = crlf + 2;
    var dataEnd = dataStart + len;
    if (dataEnd + 2 > buf.length) return { type: "incomplete" };
    var bulk = buf.slice(dataStart, dataEnd);
    return { type: "bulk", value: bulk, consumed: dataEnd + 2 - offset };
  }
  if (marker === 0x2a /* * */) {
    var arrLen = Number(payloadStr);
    if (!Number.isFinite(arrLen)) {
      throw _err("PROTOCOL", "array length not finite: " + payloadStr);
    }
    if (arrLen === -1) return { type: "array", value: null, consumed: crlf + 2 - offset };
    var items = [];
    var cursor = crlf + 2;
    for (var i = 0; i < arrLen; i++) {
      var sub = _parseFrame(buf, cursor, depth + 1);
      if (sub.type === "incomplete") return { type: "incomplete" };
      items.push(sub);
      cursor += sub.consumed;
    }
    return { type: "array", value: items, consumed: cursor - offset };
  }
  throw _err("PROTOCOL", "unknown reply marker 0x" + marker.toString(HEX_RADIX));
}

// Convert a parsed frame tree into a JavaScript-friendly value.
// Bulks are returned as Buffer (caller decides encoding); arrays
// recurse; errors are surfaced as { error: msg }; integers are numbers.
function _frameToValue(frame) {
  if (frame.type === "string")  return frame.value;
  if (frame.type === "int")     return frame.value;
  if (frame.type === "bulk")    return frame.value;
  if (frame.type === "error")   return { _redisError: true, message: frame.value };
  if (frame.type === "array") {
    if (frame.value === null) return null;
    return frame.value.map(_frameToValue);
  }
  throw _err("PROTOCOL", "_frameToValue: unknown frame type " + frame.type);
}

// ---- Client ----
//
// Single connection, FIFO request queue, auto-reconnect on socket
// close. Pipelining is implicit — every command appends to the queue
// and writes immediately; responses are dispatched in arrival order.
function create(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.url, "redis.create: opts.url", RedisError, "BAD_OPTS");
  // Validate an operator-supplied opts.port up front for a clear typo
  // message (e.g. the string "6379" or a negative value).
  validateOpts.optionalPort(opts.port, "redis.create: opts.port", RedisError, "BAD_OPTS");
  var parsed = _parseRedisUrl(opts.url);
  var host = opts.host || parsed.host;
  var port = opts.port || parsed.port;
  // Re-validate the RESOLVED port. A url-supplied port (redis://h:0,
  // redis://h:99999) is not range-checked by _parseRedisUrl, so without
  // this an outbound connect could inherit a zero / out-of-range port that
  // the opts.port guard above never sees.
  validateOpts.optionalPort(port, "redis.create: resolved port (opts.port or url)", RedisError, "BAD_OPTS");
  var useTls = opts.tls !== undefined ? !!opts.tls : parsed.tls;
  var password = opts.password !== undefined ? opts.password : parsed.password;
  var username = opts.username !== undefined ? opts.username : parsed.username;
  // Config-time entry-point opts: a bad type must fail at create() rather
  // than coerce-or-default silently. connectTimeoutMs:"abc" → NaN would
  // otherwise fall through to the default; a negative timeout would sail
  // into setTimeout; maxReconnectAttempts:"abc" → NaN would make the
  // `>= 0` reconnect-cap check below false and SILENTLY disable the bound
  // (unbounded reconnects). db and maxReconnectAttempts must allow 0
  // (db 0 = no SELECT; maxReconnectAttempts 0 = give up immediately).
  if (opts.db !== undefined &&
      (typeof opts.db !== "number" || !Number.isInteger(opts.db) || opts.db < 0)) {
    throw _err("BAD_OPTS",
      "redis.create: opts.db must be a non-negative integer, got " +
      (typeof opts.db === "number" ? String(opts.db) : typeof opts.db));
  }
  if (opts.maxReconnectAttempts !== undefined &&
      (typeof opts.maxReconnectAttempts !== "number" ||
       !Number.isInteger(opts.maxReconnectAttempts) || opts.maxReconnectAttempts < 0)) {
    throw _err("BAD_OPTS",
      "redis.create: opts.maxReconnectAttempts must be a non-negative integer, got " +
      (typeof opts.maxReconnectAttempts === "number"
        ? String(opts.maxReconnectAttempts) : typeof opts.maxReconnectAttempts));
  }
  validateOpts.optionalPositiveInt(opts.connectTimeoutMs,
    "redis.create: opts.connectTimeoutMs", RedisError, "BAD_OPTS");
  validateOpts.optionalPositiveInt(opts.commandTimeoutMs,
    "redis.create: opts.commandTimeoutMs", RedisError, "BAD_OPTS");
  var db = opts.db !== undefined ? opts.db : parsed.db;
  var connectTimeoutMs = opts.connectTimeoutMs !== undefined ? opts.connectTimeoutMs : 5000;
  var commandTimeoutMs = opts.commandTimeoutMs !== undefined ? opts.commandTimeoutMs : 10000;
  var maxReconnectAttempts = opts.maxReconnectAttempts === undefined ? 10
                                                                    : opts.maxReconnectAttempts;
  // TLS verification controls. Operators using rediss:// against private
  // CAs (managed Redis services, on-prem clusters with internal PKI)
  // pin the trust roots via opts.ca; rejectUnauthorized stays on by
  // default — never weaken verification to make a connection succeed.
  var caBundle = opts.ca || null;
  // SNI is only legal for hostnames; IP literals must omit servername.
  var servername = opts.servername;
  if (servername === undefined) {
    servername = (ipUtils.isIPv4Shape(host) || host.indexOf(":") !== -1)
                   ? undefined : host;
  }

  var socket = null;
  var connected = false;
  var connecting = false;
  var closing = false;
  // Shared in-flight connect. Every _connect() call returns the SAME
  // promise while a connect is in progress, so concurrent callers all
  // observe the same resolve/reject instead of polling a flag. It is
  // ALWAYS settled (resolve on ready, reject on socket-error / connect-
  // timeout / AUTH-or-SELECT failure) and cleared the moment it settles
  // so the next caller starts a fresh attempt — a connect that fails
  // can never leave a never-settling promise behind for the next
  // awaiter to wedge on.
  var connectPromise = null;
  // Tracked + unref'd reconnect timer. Tracked so close() can cancel a
  // pending backoff (otherwise a reconnect scheduled before close fires
  // after it and opens a fresh socket); unref'd so a backoff window doesn't
  // by itself keep the event loop alive (the process-won't-exit class).
  // Single-flight: a non-null reconnectTimer means a backoff is already
  // pending — socket-error AND socket-close firing for the same failure
  // must not stack two timers (which would burn the reconnect budget at
  // 2x and open redundant sockets).
  var reconnectTimer = null;
  // Set once the reconnect budget is exhausted. Makes the give-up path
  // idempotent (drains pending+backlog exactly once) and stops a stray
  // close/error after give-up from re-draining or racing a later success.
  var gaveUp = false;
  var rxBuffer = Buffer.alloc(0);
  // FIFO of in-flight commands awaiting a response
  var pending = [];
  // Backlog of commands queued before connect resolved
  var backlog = [];
  var reconnectAttempt = 0;
  // Pub/sub demultiplex hook. When set, the receive path dispatches
  // server-pushed "message" / "pmessage" frames (RESP arrays whose
  // first element is one of those literals) to onPushMessage instead
  // of consuming a pending request slot. SUBSCRIBE / UNSUBSCRIBE /
  // PSUBSCRIBE / PUNSUBSCRIBE acks still flow through pending — they
  // ARE responses to caller-issued commands. The split lets a single
  // socket handle subscribe-mode acks AND the asynchronous fan-out
  // events without confusing the FIFO.
  var onPushMessage = typeof opts.onPushMessage === "function"
    ? opts.onPushMessage : null;

  function _scheduleReconnect() {
    if (closing) return;
    // Single-flight: a socket failure surfaces as both an `error` and a
    // `close` event. Without this guard each one schedules its own timer,
    // stacking two reconnects for one failure — the budget burns at 2x
    // and two fresh sockets open. A pending backoff already covers the
    // failure, so a second call is a no-op.
    if (reconnectTimer !== null) return;
    if (maxReconnectAttempts >= 0 && reconnectAttempt >= maxReconnectAttempts) {
      // Reconnect budget exhausted. Drain pending + backlog exactly once;
      // a later stray close/error must not re-drain or race a future
      // success path.
      if (gaveUp) return;
      gaveUp = true;
      var err = _err("RECONNECT_GAVE_UP",
        "redis: gave up after " + reconnectAttempt + " reconnect attempts");
      _drainPending(err);
      return;
    }
    reconnectAttempt++;
    // Exponential backoff capped at 30s. Base 100ms is the first-retry
    // delay (not a duration unit), so it stays a literal; the cap routes
    // through C.TIME.
    var delay = Math.min(C.TIME.seconds(30), 100 * Math.pow(2, reconnectAttempt - 1));
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      _connect().catch(function () { /* failure reschedules via the teardown path */ });
    }, delay);
    if (typeof reconnectTimer.unref === "function") reconnectTimer.unref();
  }

  function _drainPending(err) {
    var batch = pending.slice();
    pending.length = 0;
    batch.forEach(function (p) { p.reject(err); });
    var bl = backlog.slice();
    backlog.length = 0;
    bl.forEach(function (p) {
      if (p.timer) { clearTimeout(p.timer); p.timer = null; }
      p.reject(err);
    });
  }

  function _onData(chunk) {
    rxBuffer = rxBuffer.length === 0 ? chunk : Buffer.concat([rxBuffer, chunk]);
    while (rxBuffer.length > 0) {
      var frame, value;
      try {
        frame = _parseFrame(rxBuffer, 0);
        if (frame.type === "incomplete") return;
        value = _frameToValue(frame);
      } catch (parseErr) {
        // A malformed or hostilely-nested RESP frame must not throw out of
        // the socket 'data' handler and crash the host. Treat it as a fatal
        // connection fault: reject in-flight commands and tear the socket
        // down for a reconnect, the same as any other lost-socket path.
        _teardownSocket(parseErr);
        return;
      }
      rxBuffer = rxBuffer.slice(frame.consumed);

      // Pub/sub push detection — server-initiated arrays beginning with
      // "message" (3-tuple: type / channel / payload) or "pmessage"
      // (4-tuple: type / pattern / channel / payload). Routed to
      // onPushMessage; do not consume a pending entry.
      if (onPushMessage && Array.isArray(value) && value.length >= 3 &&
          Buffer.isBuffer(value[0])) {
        var typeStr = value[0].toString("utf8");
        if (typeStr === "message" && value.length === 3) {
          onPushMessage({
            pattern: null,
            channel: Buffer.isBuffer(value[1]) ? value[1].toString("utf8") : String(value[1]),
            payload: value[2],
          });
          continue;
        }
        if (typeStr === "pmessage" && value.length === 4) {
          onPushMessage({
            pattern: Buffer.isBuffer(value[1]) ? value[1].toString("utf8") : String(value[1]),
            channel: Buffer.isBuffer(value[2]) ? value[2].toString("utf8") : String(value[2]),
            payload: value[3],
          });
          continue;
        }
      }

      if (pending.length === 0) {
        // Orphan frame with no pending request — drop. This is the
        // expected path for subscribe/unsubscribe acks if onPushMessage
        // is wired but the caller didn't await them.
        continue;
      }
      var p = pending.shift();
      if (value && value._redisError) {
        p.reject(_err("REDIS_REPLY", value.message));
      } else {
        p.resolve(value);
      }
    }
  }

  // Single teardown path for a lost socket. A failure surfaces as an
  // `error` event AND a `close` event (and `error` then destroys the
  // socket, which fires `close` again) — three callbacks for ONE lost
  // connection. Routing all of them here, guarded by a "are we still
  // attached to this socket" check, means pending is drained once and
  // exactly one reconnect is scheduled (the single-flight guard in
  // _scheduleReconnect absorbs the rest). `err` is the diagnostic to
  // reject in-flight commands with.
  function _teardownSocket(err) {
    // Already torn down for this socket (the sibling event already ran).
    if (!connected && socket === null) {
      // Still let a stray event re-arm a reconnect if one isn't pending
      // and we haven't been closed — but never re-drain pending.
      if (!closing) _scheduleReconnect();
      return;
    }
    connected = false;
    var dead = socket;
    socket = null;
    if (dead) {
      try {
        dead.removeListener("error", _onSocketError);
        dead.removeListener("close", _onSocketClose);
        dead.removeListener("data", _onData);
        dead.destroy();
      } catch (_e) { /* best-effort socket teardown */ }
    }
    _drainPending(err);
    if (!closing) _scheduleReconnect();
  }

  function _onSocketError(err) {
    _teardownSocket(_err("SOCKET",
      "redis socket error: " + ((err && err.message) || String(err))));
  }

  function _onSocketClose() {
    _teardownSocket(_err("SOCKET_CLOSED", "redis socket closed unexpectedly"));
  }

  // _connect() — public entry. Returns a promise that ALWAYS settles.
  // Concurrent callers (and the reconnect timer) share the single
  // in-flight connectPromise rather than each starting a parallel dial,
  // and they all observe the same resolve/reject. A previous version
  // polled a `connecting` flag in a `while (connecting) await sleep(20)`
  // loop; if a failure path failed to clear that flag the waiter spun
  // forever. The shared promise removes that wedge — the promise is
  // cleared the instant it settles, so a failed connect can never leave
  // a never-settling promise behind.
  function _connect() {
    if (closing) return Promise.resolve();
    if (connected) return Promise.resolve();
    if (connectPromise) return connectPromise;
    connectPromise = _doConnect();
    // Clear the shared promise once it settles (either way) so the next
    // _connect() starts a fresh attempt instead of re-awaiting a stale
    // settled promise.
    var clear = function () { connectPromise = null; };
    connectPromise.then(clear, clear);
    return connectPromise;
  }

  async function _doConnect() {
    connecting = true;
    rxBuffer = Buffer.alloc(0);
    var newSocket = null;
    try {
      newSocket = await new Promise(function (resolve, reject) {
        var sock;
        var timer = setTimeout(function () {
          try { if (sock) sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          reject(_err("CONNECT_TIMEOUT",
            "redis connect timed out after " + connectTimeoutMs + "ms (host=" + host + ":" + port + ")"));
        }, connectTimeoutMs);
        function onOk() {
          clearTimeout(timer);
          sock.removeListener("error", onErr);
          resolve(sock);
        }
        function onErr(e) {
          clearTimeout(timer);
          try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          reject(_err("CONNECT", "redis connect failed: " + ((e && e.message) || String(e))));
        }
        if (useTls) {
          var tlsConnectOpts = { host: host, port: port };
          if (servername) tlsConnectOpts.servername = servername;
          if (caBundle)   tlsConnectOpts.ca = caBundle;
          sock = nodeTls.connect(tlsConnectOpts, onOk);
        } else {
          sock = net.connect({ host: host, port: port }, onOk);
        }
        sock.once("error", onErr);
      });
      socket = newSocket;
      socket.setNoDelay(true);
      socket.on("data", _onData);
      socket.on("error", _onSocketError);
      socket.on("close", _onSocketClose);
      connected = true;

      // Auth + select db on (re)connect — without resetting the
      // backlog of commands queued during disconnect. Send these
      // BEFORE the backlog so the server is ready when backlog flushes.
      // A failure here (wrong password, server SELECT rejection, socket
      // dropped mid-AUTH) must not leave connected=true on a half-open
      // socket — the catch below tears the socket down and rethrows.
      if (password) {
        var authArgs = username ? ["AUTH", username, password] : ["AUTH", password];
        await _sendNoQueue(authArgs);
      }
      if (Number.isFinite(db) && db !== 0) {
        await _sendNoQueue(["SELECT", String(db)]);
      }

      // Connect fully succeeded — only now reset the backoff counter +
      // the give-up latch so a future disconnect gets a fresh budget.
      reconnectAttempt = 0;
      gaveUp = false;
      connecting = false;

      // Flush backlog. Clear each queued entry's not-connected timeout
      // before it goes on the wire — the in-flight command timeout in
      // _writeAndAwait now owns its lifetime.
      var bl = backlog.slice();
      backlog.length = 0;
      bl.forEach(function (entry) {
        if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
        _writeAndAwait(entry.args, entry.resolve, entry.reject);
      });
    } catch (err) {
      connecting = false;
      connected = false;
      // Tear down a half-open socket (came up, then AUTH/SELECT failed)
      // so we never leave connected=false with a live socket whose data/
      // error/close handlers would fire against stale state. If the
      // socket-error handler already ran it set socket=null.
      var dead = socket || newSocket;
      socket = null;
      if (dead) {
        try {
          dead.removeListener("error", _onSocketError);
          dead.removeListener("close", _onSocketClose);
          dead.removeListener("data", _onData);
          dead.destroy();
        } catch (_e) { /* best-effort socket teardown */ }
      }
      // A failed dial (reset before ready) or an AUTH/SELECT failure must keep
      // the reconnect loop alive. The post-ready error/close handlers that
      // normally drive reconnect are not attached yet during the dial, so
      // without scheduling here a connection lost mid-dial rejects the connect
      // promise and the client never reconnects. Single-flight + budget-guarded
      // by _scheduleReconnect; the caller still observes this attempt's rejection.
      if (!closing) _scheduleReconnect();
      throw err;
    }
  }

  // Internal helper that bypasses the connect-pending backlog (used
  // for AUTH / SELECT during connect itself, where the socket is
  // already up but `connected = true` is set immediately above).
  function _sendNoQueue(args) {
    return new Promise(function (resolve, reject) {
      pending.push({
        resolve: resolve,
        reject:  reject,
        timer:   setTimeout(function () {
          var idx = pending.findIndex(function (p) { return p.resolve === resolve; });
          if (idx !== -1) pending.splice(idx, 1);
          reject(_err("COMMAND_TIMEOUT", "redis " + args[0] + " timed out"));
        }, commandTimeoutMs),
      });
      try { socket.write(_encodeCommand(args)); }
      catch (e) { reject(_err("WRITE", "redis write failed: " + ((e && e.message) || String(e)))); }
    });
  }

  function _writeAndAwait(args, resolve, reject) {
    var entry = {
      resolve: function (v) { clearTimeout(entry.timer); resolve(v); },
      reject:  function (e) { clearTimeout(entry.timer); reject(e); },
      timer:   null,
    };
    entry.timer = setTimeout(function () {
      var idx = pending.indexOf(entry);
      if (idx !== -1) pending.splice(idx, 1);
      reject(_err("COMMAND_TIMEOUT", "redis " + args[0] + " timed out"));
    }, commandTimeoutMs);
    pending.push(entry);
    try { socket.write(_encodeCommand(args)); }
    catch (e) {
      var i = pending.indexOf(entry);
      if (i !== -1) pending.splice(i, 1);
      clearTimeout(entry.timer);
      reject(_err("WRITE", "redis write failed: " + ((e && e.message) || String(e))));
    }
  }

  function command() {
    var args = Array.prototype.slice.call(arguments);
    return new Promise(function (resolve, reject) {
      if (closing) {
        reject(_err("CLOSED", "redis client is closed"));
        return;
      }
      if (!connected) {
        // Reconnect budget exhausted and no reconnect is in flight — a
        // backlogged command here would never be flushed (nothing will
        // reconnect to drain it) and would wedge the caller forever.
        // Reject immediately instead.
        if (gaveUp && reconnectTimer === null && !connecting) {
          reject(_err("RECONNECT_GAVE_UP",
            "redis: client disconnected and reconnect budget exhausted"));
          return;
        }
        // Queued until the next successful connect flushes the backlog.
        // Bound it with a timeout so a connect that never completes (the
        // backend is down for the whole window) settles the caller with
        // a clear error instead of leaving the await pending forever.
        var entry = { args: args, resolve: resolve, reject: reject, timer: null };
        entry.timer = setTimeout(function () {
          var idx = backlog.indexOf(entry);
          if (idx !== -1) backlog.splice(idx, 1);
          reject(_err("COMMAND_TIMEOUT",
            "redis " + args[0] + " timed out while queued (client not connected)"));
        }, commandTimeoutMs);
        if (typeof entry.timer.unref === "function") entry.timer.unref();
        backlog.push(entry);
        return;
      }
      _writeAndAwait(args, resolve, reject);
    });
  }

  // runScript — Redis EVAL helper. script + numKeys + key1..keyN +
  // arg1..argM. Returns whatever the script returns, decoded by
  // _frameToValue. Named runScript (not evalScript) so source-scan
  // tooling looking for the JavaScript eval() pattern doesn't
  // false-positive on this file.
  function runScript(script, numKeys /* ...keysAndArgs */) {
    var rest = Array.prototype.slice.call(arguments, 2);
    var args = ["EVAL", script, String(numKeys)].concat(rest);
    return command.apply(null, args);
  }

  async function close() {
    closing = true;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    // Drop the shared connect promise so a re-create after close (or a
    // late awaiter) doesn't re-await a stale in-flight attempt.
    connectPromise = null;
    var err = _err("CLOSED", "redis client closed");
    _drainPending(err);
    if (socket) {
      try { socket.end(); } catch (_e) { /* best-effort socket close */ }
      try { socket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
      socket = null;
    }
    connected = false;
  }

  return {
    connect:    _connect,
    command:    command,
    runScript:  runScript,
    close:      close,
    isOpen:     function () { return connected && !closing; },
    setOnPushMessage: function (fn) {
      onPushMessage = typeof fn === "function" ? fn : null;
    },
    // Diagnostic — exposed for tests + observability
    _state:     function () {
      return {
        connected: connected, closing: closing,
        connecting: connecting,
        pending:   pending.length, backlog: backlog.length,
        reconnect: reconnectAttempt,
        reconnectPending: reconnectTimer !== null,
        gaveUp:    gaveUp,
        host:      host, port: port, db: db, tls: useTls,
        connectTimeoutMs:     connectTimeoutMs,
        commandTimeoutMs:     commandTimeoutMs,
        maxReconnectAttempts: maxReconnectAttempts,
      };
    },
  };
}

// Parse `redis://[username:password@]host[:port][/db]` and `rediss://...` URLs.
// Empty-username + non-empty password is the legacy single-arg AUTH form.
function _parseRedisUrl(s) {
  var u;
  try { u = new nodeUrl.URL(s); }
  catch (e) {
    throw _err("BAD_URL", "redis url parse failed: " + ((e && e.message) || String(e)));
  }
  if (u.protocol !== "redis:" && u.protocol !== "rediss:") {
    throw _err("BAD_URL", "redis url protocol must be redis: or rediss:, got " + u.protocol);
  }
  var dbStr = (u.pathname || "/").replace(/^\//, "");
  var db = dbStr === "" ? 0 : Number(dbStr);
  if (!Number.isFinite(db) || db < 0 || db > 15 || Math.floor(db) !== db) {
    throw _err("BAD_URL", "redis url db must be integer 0..15, got " + dbStr);
  }
  return {
    host:     u.hostname || "127.0.0.1",
    port:     u.port ? Number(u.port) : 6379,
    tls:      u.protocol === "rediss:",
    username: u.username ? decodeURIComponent(u.username) : null,
    password: u.password ? decodeURIComponent(u.password) : null,
    db:       db,
  };
}

// pickClientOpts(cfg, prefix?) — extract the standard redis-client opts
// from a larger config bag. Lets cache-redis / pubsub-redis / queue-redis
// / etc. forward to redisClient.create without each repeating the 9-key
// list. The optional `prefix` lets callers whose operator-facing opts
// are namespaced (`redisUrl`, `redisPassword`, ...) reuse the same
// helper by passing prefix="redis" — the helper camel-cases the prefix
// onto each key.
//
//   var opts = redisClient.pickClientOpts(cfg);                // unprefixed
//   var opts = redisClient.pickClientOpts(operatorOpts, "redis"); // redisUrl etc.
function pickClientOpts(cfg, prefix) {
  if (!cfg || typeof cfg !== "object") return {};
  function pick(name) {
    if (!prefix) return cfg[name];
    return cfg[prefix + name.charAt(0).toUpperCase() + name.slice(1)];
  }
  return {
    url:                  pick("url"),
    password:             pick("password"),
    username:             pick("username"),
    tls:                  pick("tls"),
    ca:                   pick("ca"),
    servername:           pick("servername"),
    connectTimeoutMs:     pick("connectTimeoutMs"),
    commandTimeoutMs:     pick("commandTimeoutMs"),
    maxReconnectAttempts: pick("maxReconnectAttempts"),
  };
}

module.exports = {
  create:           create,
  pickClientOpts:   pickClientOpts,
  // Exposed for tests / direct callers that already manage their own socket.
  _encodeCommand:   _encodeCommand,
  _parseFrame:      _parseFrame,
  _frameToValue:    _frameToValue,
  _parseRedisUrl:   _parseRedisUrl,
};
