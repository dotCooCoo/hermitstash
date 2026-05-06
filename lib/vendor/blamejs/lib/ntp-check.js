"use strict";
/**
 * Minimal SNTP client for boot-time clock-drift verification.
 *
 * Why: the audit chain's monotonicCounter orders events deterministically
 * even if the wall clock jumps, but recordedAt is the human-readable
 * timestamp auditors will rely on. A clock that's silently off by hours
 * (container with no RTC sync, NTP daemon stopped) makes the audit trail
 * misleading.
 *
 * What this does:
 *   - Sends a single SNTPv4 query to a configured server (default
 *     pool.ntp.org) over UDP port 123.
 *   - Computes drift = (server's transmit timestamp) - (local clock).
 *   - Returns the drift in milliseconds.
 *
 * What this does NOT do:
 *   - Continuous synchronization (use the OS NTP daemon for that).
 *   - Authenticated NTP (NTS, autokey).
 *   - Querying multiple servers and taking median (single-shot only).
 *
 * The framework's policy in db.init():
 *   - drift |x| < 5min        → log info, continue
 *   - drift |x| in [5min,1hr) → log warning, continue
 *   - drift |x| >= 1hr        → log fatal, exit (BLAMEJS_NTP_STRICT=1) or warn
 *   - NTP unreachable         → log warning, continue (network may not allow UDP/123)
 */
var dgram = require("dgram");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

// NTP epoch: 1900-01-01. Unix epoch: 1970-01-01. Offset: 70 years incl. 17
// leap days = 2,208,988,800 seconds.
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

var DEFAULT_SERVERS = ["pool.ntp.org", "time.cloudflare.com"];
var DEFAULT_PORT    = 123;
var DEFAULT_TIMEOUT_MS = C.TIME.seconds(3);
var NTP_PACKET_BYTES = C.BYTES.bytes(48);  // RFC 5905 §7.3

var DEFAULT_DRIFT_WARN_MS  = C.TIME.minutes(5);
var DEFAULT_DRIFT_FATAL_MS = C.TIME.hours(1);

var thresholds = {
  warnMs:  DEFAULT_DRIFT_WARN_MS,
  fatalMs: DEFAULT_DRIFT_FATAL_MS,
};

function setThresholds(opts) {
  opts = opts || {};
  if (opts.warnMs !== undefined) {
    if (typeof opts.warnMs !== "number" || !isFinite(opts.warnMs) || opts.warnMs < 0) {
      throw new TypeError("ntpCheck.setThresholds: warnMs must be non-negative finite number, got " + JSON.stringify(opts.warnMs));
    }
    thresholds.warnMs = opts.warnMs;
  }
  if (opts.fatalMs !== undefined) {
    if (typeof opts.fatalMs !== "number" || !isFinite(opts.fatalMs) || opts.fatalMs < 0) {
      throw new TypeError("ntpCheck.setThresholds: fatalMs must be non-negative finite number, got " + JSON.stringify(opts.fatalMs));
    }
    thresholds.fatalMs = opts.fatalMs;
  }
  if (thresholds.warnMs > thresholds.fatalMs && thresholds.fatalMs > 0) {
    throw new RangeError("ntpCheck.setThresholds: warnMs (" + thresholds.warnMs +
      ") must be <= fatalMs (" + thresholds.fatalMs + ")");
  }
}

function getThresholds() {
  return { warnMs: thresholds.warnMs, fatalMs: thresholds.fatalMs };
}

function _resetThresholdsForTest() {
  thresholds.warnMs  = DEFAULT_DRIFT_WARN_MS;
  thresholds.fatalMs = DEFAULT_DRIFT_FATAL_MS;
}

/**
 * Query an NTP server once. Resolves with { driftMs, serverTimeMs } or
 * rejects with { code, message } where code is one of:
 *   'ntp/timeout'   — server didn't reply within timeoutMs
 *   'ntp/refused'   — DNS/connection error
 *   'ntp/bad-reply' — packet structure wrong
 */
function querySingle(server, opts) {
  opts = opts || {};
  var port = opts.port || DEFAULT_PORT;
  var timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;

  return new Promise(function (resolve, reject) {
    // udp6 for IPv6 literals (`::1`, `fd00::…`), udp4 otherwise. Without
    // this branch a query to an IPv6 NTP host fails with EINVAL because
    // you can't send IPv6 packets through a udp4 socket.
    var family = server.indexOf(":") !== -1 ? "udp6" : "udp4";
    var socket = dgram.createSocket(family);
    var settled = false;

    function done(err, result) {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (_e) { /* ignored */ }
      if (err) reject(err); else resolve(result);
    }

    var timer = setTimeout(function () {
      done({ code: "ntp/timeout", message: "no reply from " + server + " within " + timeoutMs + "ms" });
    }, timeoutMs);
    timer.unref();

    // SNTPv4 client request: NTP_PACKET_BYTES buffer, byte 0 = 0b00_100_011 = 0x23
    //   LI=0 (no warning), VN=4, Mode=3 (client). Other bytes zero.
    var req = Buffer.alloc(NTP_PACKET_BYTES);
    req[0] = 0x23;
    var sendTimeMs = Date.now();

    socket.on("error", function (e) {
      clearTimeout(timer);
      done({ code: "ntp/refused", message: server + ": " + e.message });
    });

    socket.on("message", function (msg) {
      clearTimeout(timer);
      var receiveTimeMs = Date.now();
      if (!Buffer.isBuffer(msg) || msg.length < NTP_PACKET_BYTES) {
        return done({ code: "ntp/bad-reply", message: "reply too short (" + (msg && msg.length) + " bytes)" });
      }
      // Bytes 40-47 = Transmit Timestamp (NTP epoch seconds.fraction)
      var ntpSeconds  = msg.readUInt32BE(40);                                    // allow:raw-byte-literal — NTP packet offset
      var ntpFraction = msg.readUInt32BE(44);                                    // allow:raw-byte-literal — NTP packet offset
      // Refuse a reply whose Transmit Timestamp is zero or earlier than
      // the NTP epoch (1900-01-01). RFC 5905 §7.3 — a Stratum-16
      // unsynchronized server emits 0 here; fed to the Unix-offset
      // subtraction it produces a large-negative serverUnixSeconds
      // that crashes downstream C.TIME helpers (which require non-
      // negative finite). Treat as "unsynchronized peer — no drift
      // measurement possible" rather than throw out of the dgram
      // 'message' handler.
      if (ntpSeconds < NTP_TO_UNIX_OFFSET_SECONDS) {
        return done({ code: "ntp/unsynchronized",
          message: "server returned NTP transmit timestamp < Unix epoch (likely Stratum-16 unsynchronized)" });
      }
      var serverUnixSeconds = ntpSeconds - NTP_TO_UNIX_OFFSET_SECONDS;
      var fracMs = Math.round(C.TIME.seconds(ntpFraction / 0x100000000));       // allow:raw-byte-literal — NTP fraction divisor (2^32)
      var serverTimeMs = C.TIME.seconds(serverUnixSeconds) + fracMs;

      // Round-trip-corrected drift: assume the server's reply transmit
      // timestamp is approximately at the midpoint of our send/receive.
      var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
      var driftMs = serverTimeMs - midpointMs;

      done(null, { driftMs: driftMs, serverTimeMs: serverTimeMs, server: server });
    });

    socket.send(req, 0, req.length, port, server, function (err) {
      if (err) {
        clearTimeout(timer);
        done({ code: "ntp/refused", message: "send to " + server + ": " + err.message });
      }
    });
  });
}

/**
 * Try each server in turn; return the first successful drift measurement.
 * Resolves null if all servers fail (caller decides whether that's fatal).
 */
async function checkDrift(opts) {
  opts = opts || {};
  var servers = opts.servers || DEFAULT_SERVERS;
  var lastError = null;
  for (var i = 0; i < servers.length; i++) {
    try {
      return await querySingle(servers[i], opts);
    } catch (e) {
      lastError = e;
    }
  }
  return { driftMs: null, error: lastError };
}

/**
 * Boot-time check that integrates with the framework's logging policy.
 * Returns a result object with { ok, driftMs, severity, message }.
 * Caller (db.init) decides whether to exit.
 */
async function bootCheck(opts) {
  opts = opts || {};
  var result = await checkDrift(opts);
  if (result.driftMs === null) {
    return {
      ok:       true,             // unreachable NTP isn't a hard failure
      severity: "warning",
      driftMs:  null,
      message:  "NTP unreachable: " + (result.error && result.error.message) +
                " (continuing — set BLAMEJS_NTP_STRICT=1 to fail closed)",
    };
  }
  var absMs = Math.abs(result.driftMs);
  var driftStr = (result.driftMs >= 0 ? "+" : "") + result.driftMs + "ms";
  var fatalMs = (opts && typeof opts.driftFatalMs === "number") ? opts.driftFatalMs : thresholds.fatalMs;
  var warnMs  = (opts && typeof opts.driftWarnMs  === "number") ? opts.driftWarnMs  : thresholds.warnMs;
  if (fatalMs > 0 && absMs >= fatalMs) {
    return {
      ok:       false,
      severity: "fatal",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  "clock drift " + driftStr + " from " + result.server +
                " (>= " + fatalMs + "ms) — refuse to boot",
    };
  }
  if (warnMs > 0 && absMs >= warnMs) {
    return {
      ok:       true,
      severity: "warning",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  "clock drift " + driftStr + " from " + result.server +
                " (>= " + warnMs + "ms) — investigate",
    };
  }
  return {
    ok:       true,
    severity: "info",
    driftMs:  result.driftMs,
    server:   result.server,
    message:  "clock drift " + driftStr + " from " + result.server,
  };
}

// Periodic drift monitor — runs checkDrift on a schedule and emits
// audit + observability events on threshold crossings. Returns a
// handle with `.stop()` for graceful shutdown.
//
//   var mon = b.ntpCheck.monitor({
//     intervalMs:    C.TIME.minutes(15),
//     servers:       ["time.cloudflare.com", "pool.ntp.org"],
//     driftWarnMs:   C.TIME.seconds(2),
//     driftFatalMs:  C.TIME.seconds(30),
//     onDrift: function (result) { /* operator hook — drift > warn */ },
//   });
//   ...
//   await mon.stop();
//
// Audit emissions:
//   system.ntp.checked     — every check, success or fail
//   system.ntp.drift_warn  — drift exceeds warn threshold
//   system.ntp.drift_fatal — drift exceeds fatal threshold
//   system.ntp.unreachable — every server in the list failed to respond
//
// Observability events: ntp.drift_ms (gauge) on every successful check.
function monitor(opts) {
  opts = opts || {};
  var intervalMs = opts.intervalMs || C.TIME.minutes(15);
  var auditOn = opts.audit !== false;
  if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs <= 0) {
    throw new TypeError("ntpCheck.monitor: intervalMs must be a positive finite number");
  }

  function _emit(action, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  metadata && metadata.severity === "fatal" ? "fail" : "ok",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  async function _tick() {
    var res;
    try { res = await bootCheck(opts); }
    catch (e) {
      _emit("system.ntp.checked", { severity: "fatal", error: (e && e.message) || String(e) });
      return;
    }
    if (res.driftMs === null) {
      _emit("system.ntp.unreachable", { severity: "warning", message: res.message });
      return;
    }
    try { observability().safeEvent("ntp.drift_ms", res.driftMs, { server: res.server || "unknown" }); }
    catch (_e) { /* drop-silent */ }
    _emit("system.ntp.checked", { severity: res.severity, driftMs: res.driftMs, server: res.server });
    if (res.severity === "fatal") {
      _emit("system.ntp.drift_fatal", { driftMs: res.driftMs, server: res.server });
    } else if (res.severity === "warning") {
      _emit("system.ntp.drift_warn", { driftMs: res.driftMs, server: res.server });
    }
    if (typeof opts.onDrift === "function" && res.severity !== "info") {
      try { await opts.onDrift(res); } catch (_e) { /* operator hook — drop-silent */ }
    }
  }

  var handle = safeAsync.repeating(_tick, intervalMs, { name: "ntp-monitor" });
  return {
    stop: function () { if (handle) { handle.stop(); handle = null; } },
  };
}

module.exports = {
  querySingle:               querySingle,
  checkDrift:                checkDrift,
  bootCheck:                 bootCheck,
  monitor:                   monitor,
  setThresholds:             setThresholds,
  getThresholds:             getThresholds,
  DEFAULT_SERVERS:           DEFAULT_SERVERS,
  DEFAULT_DRIFT_WARN_MS:     DEFAULT_DRIFT_WARN_MS,
  DEFAULT_DRIFT_FATAL_MS:    DEFAULT_DRIFT_FATAL_MS,
  NTP_TO_UNIX_OFFSET_SECONDS: NTP_TO_UNIX_OFFSET_SECONDS,
  _resetThresholdsForTest:   _resetThresholdsForTest,
};
