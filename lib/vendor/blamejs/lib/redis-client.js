// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var net = require("node:net");
var nodeTls = require("node:tls");
var nodeUrl = require("node:url");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var ipUtils = require("./ip-utils");
var { RedisError } = require("./framework-error");
// networkTls — lazy so the outbound-TLS posture is read from live state at
// dial time (an operator's preferredGroups.set must reach the next
// connection), without pulling the TLS module into this one's boot graph.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

var _err = RedisError.factory;

var HEX_RADIX = 16;

function _encodeCommand(args) {
  if (!Array.isArray(args) || args.length === 0) {
    throw _err("redis-client/bad-args", "encodeCommand: args must be a non-empty array");
  }
  var parts = ["*" + args.length + "\r\n"];
  for (var i = 0; i < args.length; i++) {
    var a = args[i];
    var buf;
    if (Buffer.isBuffer(a)) {
      buf = a;
    } else if (a === null || a === undefined) {
      throw _err("redis-client/bad-args", "encodeCommand: arg " + i + " is null/undefined");
    } else {
      buf = Buffer.from(String(a), "utf8");
    }
    parts.push("$" + buf.length + "\r\n");
    parts.push(buf);
    parts.push("\r\n");
  }
  var bufs = parts.map(function (p) {
    return Buffer.isBuffer(p) ? p : Buffer.from(p, "utf8");
  });
  return Buffer.concat(bufs);
}

var MAX_RESP_DEPTH = 64;
function _parseFrame(buf, offset, depth) {
  depth = depth || 0;
  if (depth > MAX_RESP_DEPTH) {
    throw _err("redis-client/protocol", "reply nesting exceeds " + MAX_RESP_DEPTH + " levels");
  }
  if (offset >= buf.length) return { type: "incomplete" };
  var marker = buf[offset];
  var crlf = buf.indexOf("\r\n", offset + 1);
  if (crlf === -1) return { type: "incomplete" };
  var headerEnd = crlf;
  var payloadStr = buf.slice(offset + 1, headerEnd).toString("utf8");

  if (marker === 0x2b ) {
    return { type: "string", value: payloadStr, consumed: crlf + 2 - offset };
  }
  if (marker === 0x2d ) {
    return { type: "error", value: payloadStr, consumed: crlf + 2 - offset };
  }
  if (marker === 0x3a ) {
    var n = Number(payloadStr);
    if (!Number.isFinite(n)) {
      throw _err("redis-client/protocol", "integer reply not finite: " + payloadStr);
    }
    return { type: "int", value: n, consumed: crlf + 2 - offset };
  }
  if (marker === 0x24 ) {
    var len = Number(payloadStr);
    if (!Number.isFinite(len)) {
      throw _err("redis-client/protocol", "bulk length not finite: " + payloadStr);
    }
    if (len === -1) return { type: "bulk", value: null, consumed: crlf + 2 - offset };
    var dataStart = crlf + 2;
    var dataEnd = dataStart + len;
    if (dataEnd + 2 > buf.length) return { type: "incomplete" };
    var bulk = buf.slice(dataStart, dataEnd);
    return { type: "bulk", value: bulk, consumed: dataEnd + 2 - offset };
  }
  if (marker === 0x2a ) {
    var arrLen = Number(payloadStr);
    if (!Number.isFinite(arrLen)) {
      throw _err("redis-client/protocol", "array length not finite: " + payloadStr);
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
  throw _err("redis-client/protocol", "unknown reply marker 0x" + marker.toString(HEX_RADIX));
}

function _frameToValue(frame) {
  if (frame.type === "string")  return frame.value;
  if (frame.type === "int")     return frame.value;
  if (frame.type === "bulk")    return frame.value;
  if (frame.type === "error")   return { _redisError: true, message: frame.value };
  if (frame.type === "array") {
    if (frame.value === null) return null;
    return frame.value.map(_frameToValue);
  }
  throw _err("redis-client/protocol", "_frameToValue: unknown frame type " + frame.type);
}

function create(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.url, "redis.create: opts.url", RedisError, "redis-client/bad-opts");
  validateOpts.optionalPort(opts.port, "redis.create: opts.port", RedisError, "redis-client/bad-opts");
  var parsed = _parseRedisUrl(opts.url);
  var host = opts.host || parsed.host;
  var port = opts.port || parsed.port;
  validateOpts.optionalPort(port, "redis.create: resolved port (opts.port or url)", RedisError, "redis-client/bad-opts");
  var useTls = opts.tls !== undefined ? !!opts.tls : parsed.tls;
  var password = opts.password !== undefined ? opts.password : parsed.password;
  var username = opts.username !== undefined ? opts.username : parsed.username;
  if (opts.db !== undefined &&
      (typeof opts.db !== "number" || !Number.isInteger(opts.db) || opts.db < 0)) {
    throw _err("redis-client/bad-opts",
      "redis.create: opts.db must be a non-negative integer, got " +
      (typeof opts.db === "number" ? String(opts.db) : typeof opts.db));
  }
  if (opts.maxReconnectAttempts !== undefined &&
      (typeof opts.maxReconnectAttempts !== "number" ||
       !Number.isInteger(opts.maxReconnectAttempts) || opts.maxReconnectAttempts < 0)) {
    throw _err("redis-client/bad-opts",
      "redis.create: opts.maxReconnectAttempts must be a non-negative integer, got " +
      (typeof opts.maxReconnectAttempts === "number"
        ? String(opts.maxReconnectAttempts) : typeof opts.maxReconnectAttempts));
  }
  validateOpts.optionalPositiveInt(opts.connectTimeoutMs,
    "redis.create: opts.connectTimeoutMs", RedisError, "redis-client/bad-opts");
  validateOpts.optionalPositiveInt(opts.commandTimeoutMs,
    "redis.create: opts.commandTimeoutMs", RedisError, "redis-client/bad-opts");
  var db = opts.db !== undefined ? opts.db : parsed.db;
  var connectTimeoutMs = opts.connectTimeoutMs !== undefined ? opts.connectTimeoutMs : 5000;
  var commandTimeoutMs = opts.commandTimeoutMs !== undefined ? opts.commandTimeoutMs : 10000;
  var maxReconnectAttempts = opts.maxReconnectAttempts === undefined ? 10
                                                                    : opts.maxReconnectAttempts;
  var caBundle = opts.ca || null;
  var servername = opts.servername;
  if (servername === undefined) {
    servername = (ipUtils.isIPv4Shape(host) || host.indexOf(":") !== -1)
                   ? undefined : host;
  }

  var socket = null;
  var connected = false;
  var connecting = false;
  var closing = false;
  var connectPromise = null;
  var reconnectTimer = null;
  var gaveUp = false;
  var rxBuffer = Buffer.alloc(0);
  var pending = [];
  var backlog = [];
  var reconnectAttempt = 0;
  var onPushMessage = typeof opts.onPushMessage === "function"
    ? opts.onPushMessage : null;

  function _scheduleReconnect() {
    if (closing) return;
    if (reconnectTimer !== null) return;
    if (maxReconnectAttempts >= 0 && reconnectAttempt >= maxReconnectAttempts) {
      if (gaveUp) return;
      gaveUp = true;
      var err = _err("redis-client/reconnect-gave-up",
        "redis: gave up after " + reconnectAttempt + " reconnect attempts");
      _drainPending(err);
      return;
    }
    reconnectAttempt++;
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
        _teardownSocket(parseErr);
        return;
      }
      rxBuffer = rxBuffer.slice(frame.consumed);

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
        continue;
      }
      var p = pending.shift();
      if (value && value._redisError) {
        p.reject(_err("redis-client/redis-reply", value.message));
      } else {
        p.resolve(value);
      }
    }
  }

  function _teardownSocket(err) {
    if (!connected && socket === null) {
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
    _teardownSocket(_err("redis-client/socket",
      "redis socket error: " + ((err && err.message) || String(err))));
  }

  function _onSocketClose() {
    _teardownSocket(_err("redis-client/socket-closed", "redis socket closed unexpectedly"));
  }

  function _connect() {
    if (closing) return Promise.resolve();
    if (connected) return Promise.resolve();
    if (connectPromise) return connectPromise;
    connectPromise = _doConnect();
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
          reject(_err("redis-client/connect-timeout",
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
          reject(_err("redis-client/connect", "redis connect failed: " + ((e && e.message) || String(e))));
        }
        if (useTls) {
          var tlsConnectOpts = Object.assign({ host: host, port: port },
            networkTls().outboundPosture());
          if (servername) tlsConnectOpts.servername = servername;
          if (caBundle)   tlsConnectOpts.ca = caBundle;
          sock = nodeTls.connect(tlsConnectOpts, onOk);
        } else {
          sock = net.connect({ host: host, port: port }, onOk);
        }
        sock.once("error", function (err) {
          if (useTls) {
            networkTls().annotateOutboundFailure(err, {
              host:    host,
              port:    port,
              tlsOpts: tlsConnectOpts,
            });
          }
          onErr(err);
        });
      });
      socket = newSocket;
      socket.setNoDelay(true);
      socket.on("data", _onData);
      socket.on("error", _onSocketError);
      socket.on("close", _onSocketClose);
      connected = true;

      if (password) {
        var authArgs = username ? ["AUTH", username, password] : ["AUTH", password];
        await _sendNoQueue(authArgs);
      }
      if (Number.isFinite(db) && db !== 0) {
        await _sendNoQueue(["SELECT", String(db)]);
      }

      reconnectAttempt = 0;
      gaveUp = false;
      connecting = false;

      var bl = backlog.slice();
      backlog.length = 0;
      bl.forEach(function (entry) {
        if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
        _writeAndAwait(entry.args, entry.resolve, entry.reject);
      });
    } catch (err) {
      connecting = false;
      connected = false;
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
      if (!closing) _scheduleReconnect();
      throw err;
    }
  }

  function _sendNoQueue(args) {
    return new Promise(function (resolve, reject) {
      _writeAndAwait(args, resolve, reject);
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
      reject(_err("redis-client/command-timeout", "redis " + args[0] + " timed out"));
    }, commandTimeoutMs);
    pending.push(entry);
    try { socket.write(_encodeCommand(args)); }
    catch (e) {
      var i = pending.indexOf(entry);
      if (i !== -1) pending.splice(i, 1);
      clearTimeout(entry.timer);
      reject(_err("redis-client/write", "redis write failed: " + ((e && e.message) || String(e))));
    }
  }

  function command() {
    var args = Array.prototype.slice.call(arguments);
    return new Promise(function (resolve, reject) {
      if (closing) {
        reject(_err("redis-client/closed", "redis client is closed"));
        return;
      }
      if (!connected) {
        if (gaveUp && reconnectTimer === null && !connecting) {
          reject(_err("redis-client/reconnect-gave-up",
            "redis: client disconnected and reconnect budget exhausted"));
          return;
        }
        var entry = { args: args, resolve: resolve, reject: reject, timer: null };
        entry.timer = setTimeout(function () {
          var idx = backlog.indexOf(entry);
          if (idx !== -1) backlog.splice(idx, 1);
          reject(_err("redis-client/command-timeout",
            "redis " + args[0] + " timed out while queued (client not connected)"));
        }, commandTimeoutMs);
        if (typeof entry.timer.unref === "function") entry.timer.unref();
        backlog.push(entry);
        return;
      }
      _writeAndAwait(args, resolve, reject);
    });
  }

  function runScript(script, numKeys ) {
    var rest = Array.prototype.slice.call(arguments, 2);
    var args = ["EVAL", script, String(numKeys)].concat(rest);
    return command.apply(null, args);
  }

  async function close() {
    closing = true;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    connectPromise = null;
    var err = _err("redis-client/closed", "redis client closed");
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

function _parseRedisUrl(s) {
  var u;
  try { u = new nodeUrl.URL(s); }
  catch (e) {
    throw _err("redis-client/bad-url", "redis url parse failed: " + ((e && e.message) || String(e)));
  }
  if (u.protocol !== "redis:" && u.protocol !== "rediss:") {
    throw _err("redis-client/bad-url", "redis url protocol must be redis: or rediss:, got " + u.protocol);
  }
  var dbStr = (u.pathname || "/").replace(/^\//, "");
  var db = dbStr === "" ? 0 : Number(dbStr);
  if (!Number.isFinite(db) || db < 0 || db > 15 || Math.floor(db) !== db) {
    throw _err("redis-client/bad-url", "redis url db must be integer 0..15, got " + dbStr);
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
  _encodeCommand:   _encodeCommand,
  _parseFrame:      _parseFrame,
  _frameToValue:    _frameToValue,
  _parseRedisUrl:   _parseRedisUrl,
};
