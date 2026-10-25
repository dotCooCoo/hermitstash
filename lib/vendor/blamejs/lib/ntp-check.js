// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   Plain SNTP replies are unauthenticated. `ntsServers` names NTS-KE
 *   endpoints (RFC 8915) that are queried first through
 *   `b.network.ntp.nts`, and a reading from one carries
 *   `authenticated: true`; `requireNts` refuses the unauthenticated
 *   fallback.
 *
 *   What this does NOT do: continuous synchronization (the host OS's
 *   NTP daemon does that), NTP autokey, or median-of-N server
 *   reconciliation (single-shot only).
 *
 *   Policy thresholds at boot — wired into `b.db.init`:
 *
 *     drift |x| < warnMs (5 min default)        → info, continue
 *     drift |x| in [warnMs, fatalMs)            → warning, continue
 *     drift |x| >= fatalMs (1 hr default)       → refuse to boot
 *                                                 (BLAMEJS_NTP_STRICT=0
 *                                                  downgrades to a log line)
 *     NTP unreachable                           → warning, continue
 *                                                 (network may not allow
 *                                                  UDP/123 outbound;
 *                                                  BLAMEJS_NTP_REQUIRE_REACHABLE=1
 *                                                  refuses the boot instead)
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
var net = require("node:net");
var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
// Lazy: the NTS client pulls in the outbound-TLS posture, and this module is
// reached at boot before that is necessarily settled. Only the authenticated
// path needs it, and most hosts never take that path.
var networkNts = lazyRequire(function () { return require("./network-nts"); });
var networkDns = require("./network-dns");
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var NtpCheckError = defineClass("NtpCheckError", { alwaysPermanent: true });

var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;
var NTP_ERA_SECONDS = 0x100000000;
var NTP_ERA_MSB     = 0x80000000;
var TIMER_MAX_MS = 0x7FFFFFFF;

var DEFAULT_SERVERS = ["pool.ntp.org", "time.cloudflare.com"];
var DEFAULT_PORT    = 123;
var DEFAULT_TIMEOUT_MS = C.TIME.seconds(3);
var NTP_PACKET_BYTES = C.BYTES.bytes(48);
var NTP_ORIGIN_OFFSET   = C.BYTES.bytes(24);
var NTP_TRANSMIT_OFFSET = C.BYTES.bytes(40);
var NTP_TIMESTAMP_BYTES = C.BYTES.bytes(8);
var NTP_MODE_SERVER  = 4;
var NTP_LI_ALARM     = 3;
var NTP_STRATUM_MAX  = 15;

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

function _ntpToUnixMs(seconds, fraction) {
  var unixSeconds = seconds >= NTP_ERA_MSB
    ? seconds - NTP_TO_UNIX_OFFSET_SECONDS
    : seconds + NTP_ERA_SECONDS - NTP_TO_UNIX_OFFSET_SECONDS;
  return C.TIME.seconds(unixSeconds) + Math.round(C.TIME.seconds(fraction / NTP_ERA_SECONDS));
}

function _decodeServerReply(msg, opts) {
  var versions = (opts && opts.versions) || [3, 4];
  var li = (msg[0] >> 6) & 0x03;
  var vn = (msg[0] >> 3) & 0x07;
  var mode = msg[0] & 0x07;
  var stratum = msg[1];
  var seconds  = msg.readUInt32BE(NTP_TRANSMIT_OFFSET);
  var fraction = msg.readUInt32BE(NTP_TRANSMIT_OFFSET + 4);
  var out = { ok: false, li: li, vn: vn, mode: mode, stratum: stratum, reason: null, serverTimeMs: null };
  if (mode !== NTP_MODE_SERVER) {
    out.reason = "mode " + mode + " is not a server reply";
  } else if (versions.indexOf(vn) === -1) {
    out.reason = "version " + vn + " is not accepted (accepted: " + versions.join(", ") + ")";
  } else if (li === NTP_LI_ALARM) {
    out.reason = "leap indicator 3 marks the server unsynchronized";
  } else if (stratum === 0 || stratum > NTP_STRATUM_MAX) {
    out.reason = "stratum " + stratum + " is not a synchronized server";
  } else if (seconds === 0 && fraction === 0) {
    out.reason = "the transmit timestamp is zero";
  }
  if (out.reason !== null) return out;
  out.ok = true;
  out.serverTimeMs = _ntpToUnixMs(seconds, fraction);
  return out;
}

function _timeoutMs(value, label, errorClass, code, defaultMs) {
  validateOpts.optionalPositiveFinite(value, label, errorClass, code);
  if (value === undefined || value === null) return defaultMs;
  if (value > TIMER_MAX_MS) {
    throw new errorClass(code, label + " must be at most " + TIMER_MAX_MS + " ms, got " + value);
  }
  return value;
}

function _canonicalAddress(addr) {
  if (typeof addr !== "string") return null;
  var bare = addr.charAt(0) === "[" && addr.charAt(addr.length - 1) === "]" ? addr.slice(1, -1) : addr;
  var zone = bare.indexOf("%");
  if (zone !== -1) bare = bare.slice(0, zone);
  var fam = net.isIP(bare);
  if (fam === 0) return addr.toLowerCase();
  try {
    return new net.SocketAddress({ address: bare, family: fam === 6 ? "ipv6" : "ipv4" }).address;
  } catch (_e) {
    return bare.toLowerCase();
  }
}

function _sameAddress(a, b) {
  var ca = _canonicalAddress(a);
  return ca !== null && ca === _canonicalAddress(b);
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
 * drift). A host name is resolved first and the socket family follows
 * the address it resolves to; a name with both an IPv4 and an IPv6
 * address is queried over IPv4.
 *
 * A datagram that does not come from the queried address and port, is
 * shorter than 48 bytes, or does not echo the request's Originate
 * Timestamp is discarded, and the query keeps waiting for the server's
 * reply. A reply that echoes the request but is not from a synchronized
 * server (mode other than 4, version other than 3 or 4, leap indicator
 * 3, stratum 0 or above 15, or a zero transmit timestamp) settles the
 * query as `ntp/unsynchronized`. Transmit timestamps after the NTP era
 * rollover on 2036-02-07 are read as era 1 (RFC 4330 section 3).
 *
 * Rejects with `{ code, message }` where `code` is one of `ntp/timeout`
 * (no acceptable reply within `timeoutMs`; when a datagram was
 * discarded, the code of the last discard, `ntp/bad-reply` or
 * `ntp/origin-mismatch`, is reported instead), `ntp/refused` (DNS or
 * socket error), or `ntp/unsynchronized`.
 *
 * An empty or non-string `server` throws `ntp/bad-server`, a `port`
 * outside 1-65535 throws `ntp/bad-port`, and a `timeoutMs` that is not a
 * positive number of at most 2147483647 throws `ntp/bad-timeout`, each
 * synchronously, before the socket opens, rather than rejecting like the
 * codes above.
 *
 * @opts
 *   port:      123,    // UDP port (almost always 123)
 *   timeoutMs: 3000,   // single-query timeout
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the server named below
 *   b.ntpCheck.querySingle("time.cloudflare.com", { timeoutMs: 2000 })
 *     .then(function (r) { console.log("drift", r.driftMs, "ms"); })
 *     .catch(function (e) { console.error("ntp", e.code, e.message); });
 */
function querySingle(server, opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(server, "ntpCheck.querySingle: server", NtpCheckError, "ntp/bad-server");
  validateOpts.optionalPort(opts.port, "ntpCheck.querySingle: opts.port", NtpCheckError, "ntp/bad-port");
  var timeoutMs = _timeoutMs(opts.timeoutMs, "ntpCheck.querySingle: opts.timeoutMs",
    NtpCheckError, "ntp/bad-timeout", DEFAULT_TIMEOUT_MS);
  return _exchange(server, opts.port || DEFAULT_PORT, timeoutMs);
}

function _exchange(server, port, timeoutMs) {
  return new Promise(function (resolve, reject) {
    var req = Buffer.alloc(NTP_PACKET_BYTES);
    req[0] = 0x23;
    var originCookie = nodeCrypto.randomBytes(NTP_TIMESTAMP_BYTES);
    originCookie.copy(req, NTP_TRANSMIT_OFFSET);

    var socket = null;
    var settled = false;
    var lastDiscard = null;

    var timer = setTimeout(function () {
      done(lastDiscard || { code: "ntp/timeout", message: "no reply from " + server + " within " + timeoutMs + "ms" });
    }, timeoutMs);
    timer.unref();

    function done(err, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket) { try { socket.close(); } catch (_e) { /* ignored */ } }
      if (err) reject(err); else resolve(result);
    }

    networkDns._resolveUdpTarget(server).then(function (target) {
      if (settled) return;
      socket = dgram.createSocket(target.family === 6 ? "udp6" : "udp4");
      var sendTimeMs = Date.now();

      socket.on("error", function (e) {
        done({ code: "ntp/refused", message: server + ": " + e.message });
      });

      socket.on("message", function (msg, rinfo) {
        var receiveTimeMs = Date.now();
        if (!rinfo || rinfo.port !== port || !_sameAddress(rinfo.address, target.address)) {
          lastDiscard = { code: "ntp/bad-reply",
            message: server + ": discarded a datagram from " + (rinfo && rinfo.address) + ":" +
              (rinfo && rinfo.port) + ", which is not the queried address" };
          return;
        }
        if (!Buffer.isBuffer(msg) || msg.length < NTP_PACKET_BYTES) {
          lastDiscard = { code: "ntp/bad-reply",
            message: server + ": reply too short (" + (msg && msg.length) + " bytes)" };
          return;
        }
        if (!bCrypto.timingSafeEqual(
              msg.subarray(NTP_ORIGIN_OFFSET, NTP_ORIGIN_OFFSET + NTP_TIMESTAMP_BYTES), originCookie)) {
          lastDiscard = { code: "ntp/origin-mismatch",
            message: server + ": reply Originate Timestamp does not echo the request nonce (spoofed/stale reply)" };
          return;
        }
        var decoded = _decodeServerReply(msg, { versions: [3, 4] });
        if (!decoded.ok) {
          return done({ code: "ntp/unsynchronized",
            message: server + ": reply mode=" + decoded.mode + " version=" + decoded.vn +
              " stratum=" + decoded.stratum + " LI=" + decoded.li +
              " is not a synchronized server response: " + decoded.reason });
        }
        var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
        done(null, {
          driftMs:      decoded.serverTimeMs - midpointMs,
          serverTimeMs: decoded.serverTimeMs,
          server:       server,
        });
      });

      try {
        socket.send(req, 0, req.length, port, target.address, function (err) {
          if (err) done({ code: "ntp/refused", message: "send to " + server + ": " + err.message });
        });
      } catch (e) {
        done({ code: "ntp/refused", message: "send to " + server + ": " + e.message });
      }
    }, function (e) {
      done({ code: "ntp/refused", message: server + ": " + ((e && e.message) || String(e)) });
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
 * The result says which kind of answer it is: `authenticated: true` when it
 * came from an NTS server (RFC 8915), `false` from plain SNTP. Named NTS
 * servers are tried first; `requireNts` makes a failed authenticated query the
 * answer rather than a reason to fall back to an unauthenticated one.
 *
 * @opts
 *   servers:    ["time.cloudflare.com", "pool.ntp.org"],
 *   ntsServers: ["time.cloudflare.com", "nts.example:4460", "[2001:db8::1]:4460"],   // array; host, host:port or [v6]:port — tried first, authenticated (RFC 8915)
 *   requireNts: false,                     // boolean; no unauthenticated fallback when true
 *   port:      123,
 *   timeoutMs: 3000,
 *   driftWarnMs:  2000,                    // accepted and ignored here; carried so one config object
 *   driftFatalMs: 30000,                   //   passes to b.ntpCheck.monitor, which reads them
 *   intervalMs:   900000,                  //   (checkDrift measures drift; it does not judge or
 *   audit:        true,                    //    schedule it, and the caller deciding that is
 *   onDrift:      function (result) {},    //    typically bootCheck or monitor)
 *
 * Opts are validated against a schema. A field present with the wrong type is
 * refused rather than read as absent: a string `requireNts` would otherwise
 * drop the authenticated reading, a non-array `ntsServers` would attempt no
 * authenticated query at all, and a string `servers` has a length and indexes,
 * so it was walked CHARACTER BY CHARACTER — the configured server never
 * contacted, the result an ordinary unreachable warning. A key the schema does
 * not declare is refused too, so a typo cannot be silently consumed;
 * `bootCheck` and `monitor` forward their own opts through here and those are
 * allowed, validated where they are read.
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
 *   var result = await b.ntpCheck.checkDrift({
 *     servers: ["time.cloudflare.com", "pool.ntp.org"],
 *   });
 *   // → { driftMs: 12, serverTimeMs: 1714694400000,
 *   //     server: "time.cloudflare.com", authenticated: false }
 */
function _parseEndpoint(entry) {
  var s = String(entry || "").trim();
  if (s === "") throw _badEndpoint(entry, "the entry is empty");
  if (s.charAt(0) === "[") {
    var close = s.indexOf("]");
    if (close === -1) throw _badEndpoint(entry, "the bracketed address is not closed");
    var host6 = s.slice(1, close);
    if (host6 === "") throw _badEndpoint(entry, "the bracketed address is empty");
    var rest = s.slice(close + 1);
    if (rest === "") return { host: host6, port: undefined };
    if (rest.charAt(0) !== ":") {
      throw _badEndpoint(entry, "trailing text after the closing bracket: " + JSON.stringify(rest));
    }
    return { host: host6, port: _requirePort(entry, rest.slice(1)) };
  }
  var first = s.indexOf(":");
  if (first === -1 || s.indexOf(":", first + 1) !== -1) return { host: s, port: undefined };
  if (first === 0) throw _badEndpoint(entry, "the host is empty");
  return { host: s.slice(0, first), port: _requirePort(entry, s.slice(first + 1)) };
}
function _requirePort(entry, text) {
  if (!/^[0-9]{1,5}$/.test(text)) {                                                                    // allow:regex-no-length-cap — bounded by the 1-5 quantifier
    throw _badEndpoint(entry, "the port must be digits, got " + JSON.stringify(text));
  }
  var p = parseInt(text, 10);
  if (p < 1 || p > 65535) {                                                                            // allow:raw-byte-literal — the IANA port range
    throw _badEndpoint(entry, "the port must be 1-65535, got " + p);
  }
  return p;
}
function _badEndpoint(entry, why) {
  return new NtpCheckError(
    "ntp/bad-nts-endpoint",
    "invalid NTS server entry " + JSON.stringify(String(entry)) + ": " + why +
    ". Expected host, host:port, or [ipv6]:port");
}

var CHECK_DRIFT_SCHEMA = {
  servers:    { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers: { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts: { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:       { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:  { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
};
var CHECK_DRIFT_FORWARDED = ["driftWarnMs", "driftFatalMs", "intervalMs", "audit", "onDrift"];

var BOOT_CHECK_SCHEMA = {
  servers:      { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers:   { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts:   { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:         { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:    { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
  driftWarnMs:  { rule: "optional-non-negative",    code: "ntp/bad-threshold" },
  driftFatalMs: { rule: "optional-non-negative",    code: "ntp/bad-threshold" },
};
var BOOT_CHECK_FORWARDED = ["intervalMs", "audit", "onDrift"];

var MONITOR_SCHEMA = {
  servers:      { rule: "optional-string-array",    code: "ntp/bad-servers" },
  ntsServers:   { rule: "optional-string-array",    code: "ntp/bad-nts-servers" },
  requireNts:   { rule: "optional-boolean",         code: "ntp/bad-require-nts" },
  port:         { rule: "optional-port",            code: "ntp/bad-port" },
  timeoutMs:    { rule: "optional-positive-finite", code: "ntp/bad-timeout" },
  intervalMs:   { rule: "optional-positive-finite", code: "ntp/bad-interval" },
  driftWarnMs:  { rule: "optional-non-negative", code: "ntp/bad-threshold" },
  driftFatalMs: { rule: "optional-non-negative", code: "ntp/bad-threshold" },
  audit:        { rule: "optional-boolean",         code: "ntp/bad-audit" },
  onDrift:      { rule: "optional-function",        code: "ntp/bad-on-drift" },
};

async function checkDrift(opts) {
  opts = opts || {};
  validateOpts.shape(opts, CHECK_DRIFT_SCHEMA, "ntpCheck.checkDrift",
    NtpCheckError, "ntp/bad-opts", { allow: CHECK_DRIFT_FORWARDED });
  var timeoutMs = _timeoutMs(opts.timeoutMs, "ntpCheck.checkDrift: opts.timeoutMs",
    NtpCheckError, "ntp/bad-timeout", DEFAULT_TIMEOUT_MS);
  var port = opts.port || DEFAULT_PORT;
  var servers = opts.servers || DEFAULT_SERVERS;
  var lastError = null;

  var ntsServers = Array.isArray(opts.ntsServers) ? opts.ntsServers : [];
  var ntsEndpoints = ntsServers.map(_parseEndpoint);
  for (var n = 0; n < ntsServers.length; n += 1) {
    try {
      var ep = ntsEndpoints[n];
      var authed = await networkNts().query({
        host: ep.host, kePort: ep.port, timeoutMs: opts.timeoutMs,
      });
      return {
        driftMs:       authed.driftMs,
        serverTimeMs:  authed.serverTimeMs,
        server:        ntsServers[n],
        authenticated: true,
      };
    } catch (e) { lastError = e; }
  }
  if (opts.requireNts === true) {
    return { driftMs: null, error: lastError, authenticated: false };
  }

  for (var i = 0; i < servers.length; i++) {
    try {
      var plain = await _exchange(servers[i], port, timeoutMs);
      plain.authenticated = false;
      return plain;
    } catch (e) {
      lastError = e;
    }
  }
  return { driftMs: null, error: lastError, authenticated: false };
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
 * `{ ok, severity, driftMs, server, authenticated, message }` where
 * `severity` is `info` / `warning` / `fatal` and `authenticated` says
 * whether the reading came from an authenticated (RFC 8915) server or
 * a plain SNTP reply anyone on the path could have written. The
 * framework's `b.db.init` calls this. Drift past the fatal threshold
 * refuses the boot by default, and `BLAMEJS_NTP_STRICT=0` downgrades
 * that refusal to a log line.
 *
 * Opts are forwarded to `checkDrift`, so `ntsServers` and `requireNts`
 * apply here as well, and they are validated against a schema: a field
 * present with the wrong type is refused rather than ignored. That includes
 * the two threshold overrides, which were read with a `typeof` test and
 * silently dropped when they were not numbers — the boot then ran against the
 * registered threshold rather than the one passed. Zero remains valid on
 * both: it disables that threshold.
 *
 * An unreachable server is a different question and answers
 * `severity: "warning"` with `ok: true`, because a network that does not allow
 * outbound UDP/123 is ordinary and refusing every such host by
 * default would be a boot failure nobody asked for. An operator who
 * does want it refused sets `BLAMEJS_NTP_REQUIRE_REACHABLE=1`, which `bootCheck`
 * reads: the same unanswered query then answers `ok: false` with
 * `severity: "fatal"`, and `b.db.init` turns that into `db/ntp-unreachable`.
 * Its own refusals are `ntp/bad-opts` for an option of the wrong type or a
 * name it does not accept, `ntp/bad-port` for a port outside 1-65535, and
 * `ntp/bad-timeout` for a `timeoutMs` that is not a positive number of at
 * most 2147483647. `BLAMEJS_NTP_REQUIRE_REACHABLE` is the only setting that turns an unanswered query into a refusal, and
 * `BLAMEJS_NTP_STRICT` has no bearing on it. Either way the result carries
 * `unreachableReason`, the reason no reading was obtained.
 *
 * @opts
 *   servers:      ["time.cloudflare.com", "pool.ntp.org"],
 *   port:         123,
 *   timeoutMs:    3000,
 *   driftWarnMs:  300000,    // override registered warn threshold
 *   driftFatalMs: 3600000,   // override registered fatal threshold
 *   ntsServers:   ["time.cloudflare.com:4460"],  // NTS-KE endpoints tried BEFORE the plain `servers`,
 *                            // each "host", "host:port" or "[v6]:port"; a malformed entry raises
 *                            // ntp/bad-nts-endpoint. A reading from one of these carries
 *                            // authenticated: true
 *   requireNts:   false,     // with it true, the plain `servers` are not consulted at all, so if
 *                            // every NTS endpoint fails the result is { driftMs: null,
 *                            // authenticated: false } carrying the last error rather than an
 *                            // unauthenticated reading
 *   intervalMs:   900000,    // accepted and ignored here; carried so one config object passes to
 *   audit:        true,      //   b.ntpCheck.monitor, which reads them. bootCheck takes a single
 *   onDrift:      function (result) {},  // reading at startup and does not schedule or hook
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
 *   var result = await b.ntpCheck.bootCheck({
 *     servers:      ["time.cloudflare.com"],
 *     driftWarnMs:  60000,
 *     driftFatalMs: 600000,
 *   });
 *   // → { ok: true, severity: "info", driftMs: 12,
 *   //     server: "time.cloudflare.com", authenticated: false,
 *   //     message: "clock drift +12ms from time.cloudflare.com" }
 */
async function bootCheck(opts) {
  opts = opts || {};
  validateOpts.shape(opts, BOOT_CHECK_SCHEMA, "ntpCheck.bootCheck",
    NtpCheckError, "ntp/bad-opts", { allow: BOOT_CHECK_FORWARDED });
  var result = await checkDrift(opts);
  var authenticated = result.authenticated === true;
  if (result.driftMs === null) {
    var reason = String((result.error && result.error.message) || "no server answered");
    if (safeEnv.readVar("BLAMEJS_NTP_REQUIRE_REACHABLE", { default: "" }) === "1") {
      return {
        ok:       false,
        severity: "fatal",
        driftMs:  null,
        authenticated: authenticated,
        unreachableReason: reason,
        message:  "NTP unreachable: " + reason +
                  " (BLAMEJS_NTP_REQUIRE_REACHABLE=1 refuses the boot rather than " +
                  "run on an unverified clock)",
      };
    }
    return {
      ok:       true,
      severity: "warning",
      driftMs:  null,
      authenticated: authenticated,
      unreachableReason: reason,
      message:  "NTP unreachable: " + reason +
                " (continuing; set BLAMEJS_NTP_REQUIRE_REACHABLE=1 to refuse the boot instead)",
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
      authenticated: authenticated,
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
      authenticated: authenticated,
      message:  "clock drift " + driftStr + " from " + result.server +
                " (>= " + warnMs + "ms) — investigate",
    };
  }
  return {
    ok:       true,
    severity: "info",
    driftMs:  result.driftMs,
    server:   result.server,
    authenticated: authenticated,
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
 *   port:         123,                               // UDP port for the plain `servers`; a value
 *                           // outside 1-65535 raises ntp/bad-port
 *   timeoutMs:    3000,                              // per-query ceiling, applied to an NTS endpoint
 *                           // and a plain server alike; a value above 2147483647 raises
 *                           // ntp/bad-timeout
 *   ntsServers:   ["time.cloudflare.com:4460"],      // NTS-KE endpoints tried BEFORE the plain
 *                           // `servers`, each "host", "host:port" or "[v6]:port"; a malformed entry
 *                           // raises ntp/bad-nts-endpoint. A reading from one carries authenticated: true
 *   requireNts:   false,                             // with it true, the plain `servers` are not
 *                           // consulted at all, so if every NTS endpoint fails the tick reports
 *                           // { driftMs: null, authenticated: false } with the last error rather
 *                           // than an unauthenticated reading
 *
 * @example
 *   // requires: outbound NTP (udp/123) to the servers named below
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
  validateOpts.shape(opts, MONITOR_SCHEMA, "ntpCheck.monitor",
    NtpCheckError, "ntp/bad-opts");
  _timeoutMs(opts.timeoutMs, "ntpCheck.monitor: opts.timeoutMs", NtpCheckError, "ntp/bad-timeout", DEFAULT_TIMEOUT_MS);

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
    _emit("system.ntp.checked", {
      severity: res.severity, driftMs: res.driftMs, server: res.server,
      authenticated: res.authenticated === true,
    });
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
  _decodeServerReply:        _decodeServerReply,
  _ntpToUnixMs:              _ntpToUnixMs,
  _sameAddress:              _sameAddress,
  _timeoutMs:                _timeoutMs,
  _resetThresholdsForTest:   _resetThresholdsForTest,
  _parseEndpointForTest:     _parseEndpoint,
};
