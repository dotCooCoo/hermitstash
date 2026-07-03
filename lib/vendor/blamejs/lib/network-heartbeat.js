// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var net = require("node:net");

var C = require("./constants");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var { defineClass } = require("./framework-error");

var HeartbeatError = defineClass("HeartbeatError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var ntpCheck = lazyRequire(function () { return require("./ntp-check"); });

var DEFAULT_INTERVAL_MS = C.TIME.seconds(15);
var DEFAULT_TIMEOUT_MS  = C.TIME.seconds(5);
var DEFAULT_THRESHOLD   = 3;

// Passive heartbeats — caller (typically a WebSocket / SSE / long-poll
// handler) records each inbound ping/pong and the framework fires
// `onTimeout` once when the keepalive grace window elapses without a
// recordPong call. Distinct from `start()`, which runs an active
// outbound probe loop.
var DEFAULT_PASSIVE_TIMEOUT_MS = C.TIME.seconds(90);

var TARGETS = new Map();

function _validateTarget(t, idx) {
  if (!t || typeof t !== "object") {
    throw new HeartbeatError("heartbeat/bad-target", "targets[" + idx + "] must be an object");
  }
  if (typeof t.name !== "string" || t.name.length === 0) {
    throw new HeartbeatError("heartbeat/bad-name", "targets[" + idx + "].name required (string)");
  }
  if (t.type !== "http" && t.type !== "tcp" && t.type !== "ntp") {
    throw new HeartbeatError("heartbeat/bad-type",
      "targets[" + idx + "].type must be 'http' | 'tcp' | 'ntp', got " + JSON.stringify(t.type));
  }
  if (t.type === "http" && (typeof t.url !== "string" || t.url.length === 0)) {
    throw new HeartbeatError("heartbeat/bad-url", "targets[" + idx + "].url required for http heartbeat");
  }
  if (t.type === "tcp" && (typeof t.host !== "string" || typeof t.port !== "number")) {
    throw new HeartbeatError("heartbeat/bad-tcp", "targets[" + idx + "] tcp heartbeat requires host (string) + port (number)");
  }
  if (t.type === "ntp" && typeof t.server !== "string") {
    throw new HeartbeatError("heartbeat/bad-ntp", "targets[" + idx + "] ntp heartbeat requires server (string)");
  }
  if (t.intervalMs !== undefined && (typeof t.intervalMs !== "number" || !isFinite(t.intervalMs) || t.intervalMs <= 0)) {
    throw new HeartbeatError("heartbeat/bad-interval", "targets[" + idx + "].intervalMs must be a positive number");
  }
  if (t.timeoutMs !== undefined && (typeof t.timeoutMs !== "number" || !isFinite(t.timeoutMs) || t.timeoutMs <= 0)) {
    throw new HeartbeatError("heartbeat/bad-timeout", "targets[" + idx + "].timeoutMs must be a positive number");
  }
  if (t.threshold !== undefined && (typeof t.threshold !== "number" || t.threshold < 1 || Math.floor(t.threshold) !== t.threshold)) {
    throw new HeartbeatError("heartbeat/bad-threshold", "targets[" + idx + "].threshold must be a positive integer");
  }
}

function _probeHttp(target, timeoutMs) {
  return new Promise(function (resolve) {
    var startMs = Date.now();
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      resolve({ ok: false, latencyMs: Date.now() - startMs, error: "timeout" });
    }, timeoutMs);
    try {
      var p = httpClient().request({
        url:        target.url,
        method:     target.method || "GET",
        timeoutMs:  timeoutMs,
        // Forward the target's protocol/host allowlists so an operator who
        // opts a cleartext http:// heartbeat in (allowedProtocols:
        // b.safeUrl.ALLOW_HTTP_ALL) is honoured. Left undefined, httpClient
        // applies its https-only default (ALLOW_HTTP_TLS) — so an http://
        // target with no opt-in is still rejected, not silently probed.
        allowedProtocols: target.allowedProtocols,
        allowedHosts:     target.allowedHosts,
        allowInternal: target.allowInternal === true ? true : target.allowInternal,
      });
      p.then(function (res) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        var ok = !target.expectStatus
          ? (res.statusCode >= 200 && res.statusCode < 400)
          : res.statusCode === target.expectStatus;
        resolve({ ok: ok, latencyMs: Date.now() - startMs, statusCode: res.statusCode });
      }, function (err) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: false, latencyMs: Date.now() - startMs, error: (err && err.message) || String(err) });
      });
    } catch (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: false, latencyMs: Date.now() - startMs, error: e.message });
    }
  });
}

function _probeTcp(target, timeoutMs) {
  return new Promise(function (resolve) {
    var startMs = Date.now();
    var settled = false;
    var sock = net.connect({ host: target.host, port: target.port });
    sock.unref && sock.unref();
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
      resolve({ ok: false, latencyMs: Date.now() - startMs, error: "timeout" });
    }, timeoutMs);
    sock.once("connect", function () {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.end(); } catch (_e) { /* best-effort socket close */ }
      resolve({ ok: true, latencyMs: Date.now() - startMs });
    });
    sock.once("error", function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: false, latencyMs: Date.now() - startMs, error: e.message });
    });
  });
}

async function _probeNtp(target, timeoutMs) {
  var startMs = Date.now();
  try {
    var r = await ntpCheck().querySingle(target.server, { timeoutMs: timeoutMs });
    return { ok: true, latencyMs: Date.now() - startMs, driftMs: r.driftMs };
  } catch (e) {
    return { ok: false, latencyMs: Date.now() - startMs, error: e.message || String(e) };
  }
}

function _probe(target, timeoutMs) {
  if (target.type === "http") return _probeHttp(target, timeoutMs);
  if (target.type === "tcp")  return _probeTcp(target, timeoutMs);
  return _probeNtp(target, timeoutMs);
}

async function _runProbe(entry) {
  var result = await _probe(entry.target, entry.timeoutMs);
  entry.lastResult = result;
  entry.lastProbeAt = Date.now();
  if (result.ok) {
    entry.consecutiveFailures = 0;
    entry.consecutiveSuccess += 1;
  } else {
    entry.consecutiveFailures += 1;
    entry.consecutiveSuccess = 0;
  }
  var prevState = entry.state;
  if (entry.consecutiveFailures >= entry.threshold) {
    entry.state = "down";
  } else if (entry.consecutiveFailures > 0) {
    entry.state = "degraded";
  } else if (entry.consecutiveSuccess >= entry.threshold) {
    entry.state = "healthy";
  }
  _emitObsProbe(entry, result);
  if (prevState !== entry.state) {
    _emitAuditStateChange(entry, prevState);
    if (typeof entry.onStateChange === "function") {
      try { entry.onStateChange({ name: entry.target.name, prevState: prevState, state: entry.state, result: result }); }
      catch (_e) { /* operator callback best-effort */ }
    }
  }
  if (typeof entry.onResult === "function") {
    try { entry.onResult({ name: entry.target.name, state: entry.state, result: result }); } catch (_e) { /* operator callback best-effort */ }
  }
}

function _scheduleNext(entry) {
  if (entry.stopped) return;
  entry.timer = setTimeout(function () {
    _runProbe(entry).then(function () { _scheduleNext(entry); }, function () { _scheduleNext(entry); });
  }, entry.intervalMs);
  entry.timer.unref && entry.timer.unref();
}

function start(opts) {
  opts = opts || {};
  validateOpts(opts, ["targets", "onResult", "onStateChange"], "heartbeat.start");
  if (!Array.isArray(opts.targets) || opts.targets.length === 0) {
    throw new HeartbeatError("heartbeat/no-targets", "heartbeat.start: targets required (non-empty array)");
  }
  for (var i = 0; i < opts.targets.length; i++) _validateTarget(opts.targets[i], i);
  var started = [];
  for (var j = 0; j < opts.targets.length; j++) {
    var t = opts.targets[j];
    boundedMap.requireAbsent(TARGETS, t.name, function () {
      throw new HeartbeatError("heartbeat/duplicate", "heartbeat target '" + t.name + "' already started");
    });
    var entry = {
      target:              t,
      intervalMs:          t.intervalMs || DEFAULT_INTERVAL_MS,
      timeoutMs:           t.timeoutMs  || DEFAULT_TIMEOUT_MS,
      threshold:           t.threshold  || DEFAULT_THRESHOLD,
      onResult:            opts.onResult,
      onStateChange:       opts.onStateChange,
      consecutiveFailures: 0,
      consecutiveSuccess:  0,
      state:               "healthy",
      lastResult:          null,
      lastProbeAt:         null,
      timer:               null,
      stopped:             false,
    };
    TARGETS.set(t.name, entry);
    _runProbe(entry).then(function (e) { return function () { _scheduleNext(e); }; }(entry),
                          function (e) { return function () { _scheduleNext(e); }; }(entry));
    started.push(t.name);
  }
  return started;
}

function stop(name) {
  var entry = TARGETS.get(name);
  if (!entry) return false;
  entry.stopped = true;
  if (entry.timer) { try { clearTimeout(entry.timer); } catch (_e) { /* best-effort timer teardown */ } }
  TARGETS.delete(name);
  return true;
}

function stopAll() {
  var names = Array.from(TARGETS.keys());
  for (var i = 0; i < names.length; i++) stop(names[i]);
  return names;
}

function status(name) {
  var entry = TARGETS.get(name);
  if (!entry) return null;
  return {
    name:                 name,
    state:                entry.state,
    consecutiveFailures:  entry.consecutiveFailures,
    consecutiveSuccess:   entry.consecutiveSuccess,
    lastResult:           entry.lastResult,
    lastProbeAt:          entry.lastProbeAt,
  };
}

function statuses() {
  var names = Array.from(TARGETS.keys());
  return names.map(function (n) { return status(n); });
}

function _emitObsProbe(entry, result) {
  try {
    observability().safeEvent("network.heartbeat.probe", 1, {
      name:      entry.target.name,
      type:      entry.target.type,
      ok:        result.ok,
      latencyMs: result.latencyMs,
    });
  } catch (_e) { /* obs best-effort */ }
}

function _emitAuditStateChange(entry, prevState) {
  var sink;
  try { sink = audit(); } catch (_e) { return; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  try {
    sink.safeEmit({
      action:   "network.heartbeat.state_change",
      outcome:  entry.state === "healthy" ? "success" : "failure",
      metadata: {
        name:                entry.target.name,
        type:                entry.target.type,
        prevState:           prevState,
        state:               entry.state,
        consecutiveFailures: entry.consecutiveFailures,
        consecutiveSuccess:  entry.consecutiveSuccess,
        lastResult:          entry.lastResult,
      },
    });
  } catch (_e) { /* audit best-effort — never break the caller */ }
}

// b.network.heartbeat.passive(opts) — passive (server-pushes-pings)
// keepalive watchdog. Caller invokes the returned `recordPong()` each
// time a heartbeat frame arrives from the peer; if `timeoutMs` elapses
// with no `recordPong`, the watchdog fires `onTimeout()` exactly once
// and stops. Operator restarts surveillance by calling `passive()`
// again — the primitive deliberately doesn't auto-rearm because the
// post-timeout strategy (close socket, re-handshake, retry, alert) is
// caller-specific.
//
// Returns:
//   { recordPong, stop }
//
// `onPong` is the per-pong observability hook (optional). `onTimeout`
// is the callback fired when the timeout elapses (required). Both
// callbacks are invoked outside try/catch — operator callbacks throw
// only if the operator wants the host process to crash.
function passive(opts) {
  opts = opts || {};
  validateOpts(opts, ["onPong", "timeoutMs", "onTimeout"], "heartbeat.passive");
  if (typeof opts.onTimeout !== "function") {
    throw new HeartbeatError("heartbeat/bad-on-timeout",
      "heartbeat.passive: onTimeout must be a function");
  }
  validateOpts.optionalFunction(opts.onPong, "heartbeat.passive: onPong",
    HeartbeatError, "heartbeat/bad-on-pong");
  var timeoutMs = opts.timeoutMs === undefined ? DEFAULT_PASSIVE_TIMEOUT_MS : opts.timeoutMs;
  if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new HeartbeatError("heartbeat/bad-timeout",
      "heartbeat.passive: timeoutMs must be a positive finite number");
  }

  var state = {
    timer:        null,
    stopped:      false,
    timedOut:     false,
    startMs:      Date.now(),
    lastPongMs:   null,
    pongCount:    0,
    onPong:       opts.onPong || null,
    onTimeout:    opts.onTimeout,
    timeoutMs:    timeoutMs,
  };

  function _arm() {
    state.timer = setTimeout(_fire, state.timeoutMs);
    if (state.timer && typeof state.timer.unref === "function") state.timer.unref();
  }

  function _fire() {
    if (state.stopped || state.timedOut) return;
    state.timedOut = true;
    state.stopped  = true;
    state.timer    = null;
    _emitObsTimeout(state);
    _emitAuditPassiveTimeout(state);
    try { state.onTimeout({ pongCount: state.pongCount, lastPongMs: state.lastPongMs, timeoutMs: state.timeoutMs }); }
    catch (_e) { /* operator callback best-effort */ }
  }

  function recordPong() {
    if (state.stopped || state.timedOut) return false;
    state.pongCount += 1;
    state.lastPongMs = Date.now();
    if (state.timer) {
      try { clearTimeout(state.timer); } catch (_e) { /* best-effort timer teardown */ }
      state.timer = null;
    }
    _emitObsPong(state);
    if (typeof state.onPong === "function") {
      try { state.onPong({ pongCount: state.pongCount, lastPongMs: state.lastPongMs }); }
      catch (_e) { /* operator callback best-effort */ }
    }
    _arm();
    return true;
  }

  function stop() {
    if (state.stopped) return false;
    state.stopped = true;
    if (state.timer) {
      try { clearTimeout(state.timer); } catch (_e) { /* best-effort timer teardown */ }
      state.timer = null;
    }
    return true;
  }

  _arm();
  return { recordPong: recordPong, stop: stop };
}

function _emitObsPong(state) {
  try {
    observability().safeEvent("network.heartbeat.passive.pong", 1, {
      pongCount:  state.pongCount,
      timeoutMs:  state.timeoutMs,
    });
  } catch (_e) { /* obs best-effort */ }
}

function _emitObsTimeout(state) {
  try {
    observability().safeEvent("network.heartbeat.passive.timeout", 1, {
      pongCount:  state.pongCount,
      lastPongMs: state.lastPongMs,
      timeoutMs:  state.timeoutMs,
    });
  } catch (_e) { /* obs best-effort */ }
}

function _emitAuditPassiveTimeout(state) {
  var sink;
  try { sink = audit(); } catch (_e) { return; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  try {
    sink.safeEmit({
      action:   "networkheartbeat.passive.timeout",
      outcome:  "failure",
      metadata: {
        pongCount:  state.pongCount,
        lastPongMs: state.lastPongMs,
        timeoutMs:  state.timeoutMs,
        startMs:    state.startMs,
      },
    });
  } catch (_e) { /* audit best-effort — never break the caller */ }
}

function _resetForTest() {
  stopAll();
}

module.exports = {
  start:           start,
  stop:            stop,
  stopAll:         stopAll,
  status:          status,
  statuses:        statuses,
  passive:         passive,
  HeartbeatError:  HeartbeatError,
  _resetForTest:   _resetForTest,
};
