"use strict";
/**
 * @module b.ntpCheck
 * @nav    Production
 * @title  NTP Check
 *
 * @intro
 *   Boot-time clock-drift verification against an external NTP / NTS-KE
 *   reference. The audit chain's `monotonicCounter` orders events
 *   deterministically even when the wall clock jumps, but `recordedAt`
 *   is the human-readable timestamp auditors rely on — a clock silently
 *   off by hours (container with no RTC sync, NTP daemon stopped)
 *   makes the audit trail misleading without ever surfacing as an
 *   error.
 *
 *   What this does: sends a single SNTPv4 query over UDP/123 (RFC 5905)
 *   to one or more configured servers, computes drift as
 *   `serverTransmit - localMidpoint` (round-trip-corrected), returns
 *   the drift in milliseconds. Falls through a server list in order;
 *   the first success wins.
 *
 *   What this does NOT do: continuous synchronization (the host OS's
 *   NTP daemon does that), authenticated NTP / NTS / autokey (the
 *   external reference is trust-on-first-query), or median-of-N
 *   server reconciliation (single-shot only).
 *
 *   Policy thresholds at boot — wired into `b.db.init`:
 *
 *     drift |x| < warnMs (5 min default)        → info, continue
 *     drift |x| in [warnMs, fatalMs)            → warning, continue
 *     drift |x| >= fatalMs (1 hr default)       → refuse to boot
 *                                                 (BLAMEJS_NTP_STRICT=1)
 *     NTP unreachable                           → warning, continue
 *                                                 (network may not allow
 *                                                 UDP/123 outbound)
 *
 *   `b.ntpCheck.monitor` runs the same check on a recurring interval
 *   after boot and emits `system.ntp.checked` /
 *   `system.ntp.drift_warn` / `system.ntp.drift_fatal` /
 *   `system.ntp.unreachable` audit events plus an `ntp.drift_ms`
 *   observability gauge — so silent clock drift mid-flight surfaces
 *   in the same evidence stream as boot drift.
 *
 * @card
 *   Boot-time clock-drift verification against an external NTP / NTS-KE reference.
 */
var dgram = require("node:dgram");
var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

// Config-time misuse (a bad opts.port) throws a typed, permanent error so an
// operator catches the typo at boot rather than as a Promise rejection.
var NtpCheckError = defineClass("NtpCheckError", { alwaysPermanent: true });

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

/**
 * @primitive b.ntpCheck.setThresholds
 * @signature b.ntpCheck.setThresholds(opts)
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.getThresholds, b.ntpCheck.bootCheck
 *
 * Override the warn / fatal drift thresholds applied by `bootCheck`
 * and `monitor`. Validates that both values are non-negative finite
 * numbers and that `warnMs <= fatalMs` (a fatal floor below the
 * warning threshold would mean every warning is also fatal — likely
 * a typo). Throws `TypeError` on bad shapes and `RangeError` on the
 * ordering invariant.
 *
 * @opts
 *   warnMs:  300000,    // ms; absolute drift at-or-above this logs warn
 *   fatalMs: 3600000,   // ms; absolute drift at-or-above this refuses boot
 *
 * @example
 *   b.ntpCheck.setThresholds({
 *     warnMs:  60000,
 *     fatalMs: 600000,
 *   });
 *   var t = b.ntpCheck.getThresholds();
 *   // → { warnMs: 60000, fatalMs: 600000 }
 */
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

/**
 * @primitive b.ntpCheck.getThresholds
 * @signature b.ntpCheck.getThresholds()
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.setThresholds
 *
 * Read the currently-effective warn / fatal drift thresholds. Returns
 * a fresh object so mutating the result doesn't accidentally rewrite
 * framework state.
 *
 * @example
 *   var t = b.ntpCheck.getThresholds();
 *   // → { warnMs: 300000, fatalMs: 3600000 }
 */
function getThresholds() {
  return { warnMs: thresholds.warnMs, fatalMs: thresholds.fatalMs };
}

function _resetThresholdsForTest() {
  thresholds.warnMs  = DEFAULT_DRIFT_WARN_MS;
  thresholds.fatalMs = DEFAULT_DRIFT_FATAL_MS;
}

/**
 * @primitive b.ntpCheck.querySingle
 * @signature b.ntpCheck.querySingle(server, opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.checkDrift, b.ntpCheck.bootCheck
 *
 * Send one SNTPv4 query to a named server over UDP/123 and resolve
 * with `{ driftMs, serverTimeMs, server }` (round-trip-corrected
 * drift). Rejects with `{ code, message }` where `code` is one of
 * `ntp/timeout` (no reply within `timeoutMs`), `ntp/refused`
 * (DNS / connection error), `ntp/bad-reply` (packet too short), or
 * `ntp/unsynchronized` (Stratum-16 peer with zero transmit
 * timestamp). IPv4 / IPv6 socket family is selected from the host
 * literal so an `fd00::...` server doesn't fail with EINVAL.
 *
 * @opts
 *   port:      123,    // UDP port (almost always 123)
 *   timeoutMs: 3000,   // single-query timeout
 *
 * @example
 *   b.ntpCheck.querySingle("time.cloudflare.com", { timeoutMs: 2000 })
 *     .then(function (r) { console.log("drift", r.driftMs, "ms"); })
 *     .catch(function (e) { console.error("ntp", e.code, e.message); });
 */
function querySingle(server, opts) {
  opts = opts || {};
  validateOpts.optionalPort(opts.port, "ntpCheck.querySingle: opts.port", NtpCheckError, "ntp/bad-port");
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
    // RFC 5905 §8 client-cookie: put a random 64-bit nonce in the request's
    // Transmit Timestamp (bytes 40-47). A conformant server copies it verbatim
    // into the reply's Originate Timestamp (bytes 24-31). Verifying that echo
    // rejects an off-path spoofed reply — without it ANY 48-byte UDP datagram
    // reaching our ephemeral port becomes the authoritative time, letting a
    // spoofer force a fatal-drift refuse-to-boot under BLAMEJS_NTP_STRICT.
    var originCookie = nodeCrypto.randomBytes(8);
    originCookie.copy(req, 40);
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
      // Origin-cookie echo (RFC 5905 §8): the reply's Originate Timestamp
      // (bytes 24-31) MUST equal the nonce we sent. An off-path spoofer can't
      // know it, so this is the primary reply-authenticity check.
      if (!bCrypto.timingSafeEqual(msg.subarray(24, 32), originCookie)) {
        return done({ code: "ntp/origin-mismatch",
          message: server + ": reply Originate Timestamp does not echo the request nonce (spoofed/stale reply)" });
      }
      // Reject a non-server mode, an unsynchronized/kiss-o'-death stratum
      // (0 or >= 16), or LI=3 (alarm — clock not synchronized): such a peer
      // cannot supply a trustworthy time and must not drive drift.
      var mode = msg[0] & 0x07;
      var li = (msg[0] >> 6) & 0x03;
      var stratum = msg[1];
      if (mode !== 4 || li === 3 || stratum === 0 || stratum >= 16) {
        return done({ code: "ntp/unsynchronized",
          message: server + ": reply mode=" + mode + " stratum=" + stratum + " LI=" + li +
            " is not a synchronized server response" });
      }
      // Bytes 40-47 = Transmit Timestamp (NTP epoch seconds.fraction)
      var ntpSeconds  = msg.readUInt32BE(40);                                    // NTP packet offset
      var ntpFraction = msg.readUInt32BE(44);                                    // NTP packet offset
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
      var fracMs = Math.round(C.TIME.seconds(ntpFraction / 0x100000000));       // NTP fraction divisor (2^32)
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
 * @primitive b.ntpCheck.checkDrift
 * @signature b.ntpCheck.checkDrift(opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.querySingle, b.ntpCheck.bootCheck
 *
 * Walk a server list in order; resolve with the first successful
 * drift measurement (`{ driftMs, serverTimeMs, server }`). When
 * every server in the list fails, resolves with
 * `{ driftMs: null, error }` so the caller — typically `bootCheck` —
 * can decide whether unreachable NTP is fatal or a soft warning.
 *
 * @opts
 *   servers:   ["time.cloudflare.com", "pool.ntp.org"],
 *   port:      123,
 *   timeoutMs: 3000,
 *
 * @example
 *   var result = await b.ntpCheck.checkDrift({
 *     servers: ["time.cloudflare.com", "pool.ntp.org"],
 *   });
 *   // → { driftMs: 12, serverTimeMs: 1714694400000, server: "time.cloudflare.com" }
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
 * @primitive b.ntpCheck.bootCheck
 * @signature b.ntpCheck.bootCheck(opts)
 * @since     0.0.7
 * @status    stable
 * @related   b.ntpCheck.checkDrift, b.ntpCheck.monitor, b.ntpCheck.setThresholds
 *
 * Boot-time clock-drift check that integrates with the framework's
 * logging policy. Resolves with
 * `{ ok, severity, driftMs, server, message }` where `severity` is
 * `info` / `warning` / `fatal`. The framework's `b.db.init` calls
 * this and refuses to boot when `ok === false` and the operator has
 * set `BLAMEJS_NTP_STRICT=1`. NTP unreachable returns
 * `severity: "warning"` (network may not allow UDP/123 outbound) so
 * the boot doesn't fail closed without operator intent.
 *
 * @opts
 *   servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *   port:         123,
 *   timeoutMs:    3000,
 *   driftWarnMs:  300000,    // override registered warn threshold
 *   driftFatalMs: 3600000,   // override registered fatal threshold
 *
 * @example
 *   var result = await b.ntpCheck.bootCheck({
 *     servers:      ["time.cloudflare.com"],
 *     driftWarnMs:  60000,
 *     driftFatalMs: 600000,
 *   });
 *   // → { ok: true, severity: "info", driftMs: 12,
 *   //     server: "time.cloudflare.com",
 *   //     message: "clock drift +12ms from time.cloudflare.com" }
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

/**
 * @primitive b.ntpCheck.monitor
 * @signature b.ntpCheck.monitor(opts)
 * @since     0.7.30
 * @status    stable
 * @related   b.ntpCheck.bootCheck, b.audit.safeEmit, b.observability.safeEvent
 *
 * Periodic drift monitor — runs `bootCheck` on a recurring interval
 * and emits audit + observability events on threshold crossings.
 * Returns a handle with `.stop()` for graceful shutdown. Audit
 * emissions: `system.ntp.checked` on every tick,
 * `system.ntp.drift_warn` and `system.ntp.drift_fatal` on threshold
 * crossings, `system.ntp.unreachable` when every server in the list
 * failed. Observability gauge `ntp.drift_ms` rides every successful
 * check. The optional `onDrift` hook fires only when `severity`
 * is `warning` or `fatal`, so operators can page on drift without
 * inspecting every healthy tick.
 *
 * @opts
 *   intervalMs:   900000,                            // tick cadence
 *   servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *   driftWarnMs:  2000,
 *   driftFatalMs: 30000,
 *   audit:        true,                              // emit audit events
 *   onDrift:      function (result) {},              // operator hook
 *
 * @example
 *   var mon = b.ntpCheck.monitor({
 *     intervalMs:   900000,
 *     servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *     driftWarnMs:  2000,
 *     driftFatalMs: 30000,
 *     onDrift: function (r) { console.warn("ntp drift", r.driftMs); },
 *   });
 *   await mon.stop();
 */
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
  NtpCheckError:             NtpCheckError,
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
