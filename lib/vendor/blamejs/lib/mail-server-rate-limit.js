"use strict";
/**
 * @module     b.mail.server.rateLimit
 * @nav        Mail
 * @title      Mail Server Rate Limit
 * @order      544
 *
 * @intro
 *   Per-IP DoS defenses shared by `b.mail.server.mx` and
 *   `b.mail.server.submission`. Both listeners boot with sensible
 *   defaults; operators tighten or relax per-deployment via the
 *   `rateLimit` opt on either listener.
 *
 *   Defenses:
 *
 *   - **Per-IP concurrent connections** — bounded to
 *     `maxConcurrentConnectionsPerIp` (default 10). A single hostile
 *     peer cannot open thousands of TCP slots and starve legitimate
 *     senders. Sliding-window kernel-level limits (iptables connlimit,
 *     ELB connection cap) are still recommended upstream — this is
 *     the framework's own ceiling for when the kernel limit isn't
 *     wired.
 *
 *   - **Per-IP connection rate** — bounded to
 *     `connectionsPerIpPerMinute` (default 60). Rapid reconnect /
 *     scan attacks tripped here; legitimate retry-with-backoff
 *     traffic stays under the cap.
 *
 *   - **Per-IP AUTH-failure budget** — bounded to
 *     `authFailuresPerIpPer15Min` (default 10; submission listener
 *     only). Credential-stuffing class — RFC 4954 §6 codes AUTH
 *     refusals as 535 5.7.8; we count those per remote IP in a
 *     rolling 15-minute window and refuse new AUTH attempts past
 *     the cap with 421 4.7.0. The framework's authenticator is
 *     unaware of this layer; the rate-limit lives at the wire-
 *     protocol boundary so a credential leak past the listener is
 *     still bounded.
 *
 *   - **Slow-loris / minBytesPerSecond on DATA** — bounded to
 *     `minBytesPerSecond` (default 100 bytes/sec) during the DATA-
 *     body phase. The state machine's idleTimeoutMs already cuts
 *     fully-stalled connections; this floor cuts a hostile peer
 *     trickling one byte per minute to hold a connection for hours
 *     within the idle window.
 *
 *   ## What this module is NOT
 *
 *   - **Not an HTTP rate-limiter.** `b.middleware.rateLimit` covers
 *     the HTTP request-response shape; this module covers the
 *     SMTP-transactional state machine where rate-limits apply at
 *     the connection-boundary + the AUTH command + the DATA byte-
 *     rate, not per-request.
 *   - **Not a replacement for kernel / proxy-level limits.** This
 *     module is the in-process belt; iptables / NFTables / ELB /
 *     CloudFlare / haproxy / nginx-stream stay the suspenders. A
 *     framework-level limiter sees only what reaches the process;
 *     the kernel sees the connection floods before they cost an
 *     event-loop tick.
 *
 *   ## Wire-up
 *
 *   ```js
 *   var rateLimit = b.mail.server.rateLimit.create({
 *     maxConcurrentConnectionsPerIp:  10,
 *     connectionsPerIpPerMinute:      60,
 *     authFailuresPerIpPer15Min:      10,
 *     minBytesPerSecond:              100,
 *   });
 *
 *   var mx = b.mail.server.mx.create({ tlsContext, rateLimit, ... });
 *   ```
 *
 *   The listener calls `rateLimit.admitConnection(ip)` in the
 *   net.createServer callback and refuses new connections with
 *   `421 4.7.0 Too many connections` when the verdict is no. AUTH-
 *   failure budgeting (`noteAuthFailure` + `checkAuthAdmit`) is
 *   wired in the submission listener's AUTH handler. The slow-loris
 *   defense is wired in the DATA-body collector.
 *
 * @card
 *   Per-IP DoS defenses for b.mail.server.mx and b.mail.server.submission:
 *   concurrent-connection cap, connection-rate cap, AUTH-failure budget
 *   (submission), slow-loris min-bytes-per-second on DATA. Belt-and-
 *   suspenders to kernel/proxy-level limits.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerRateLimitError = defineClass("MailServerRateLimitError", { alwaysPermanent: true });

var DEFAULTS = Object.freeze({
  maxConcurrentConnectionsPerIp: 10,
  connectionsPerIpPerMinute:     60,                                                                  // allow:raw-time-literal — per-minute connection rate 60; time-derived (per-minute) single source of truth, C.TIME N/A as a count
  authFailuresPerIpPer15Min:     10,
  minBytesPerSecond:             100,                                                                 // slow-loris byte-rate floor
  // RCPT-TO recipient-failure cap defends against the 550-vs-250
  // enumeration shape (RFC 5321 §3.5 — RCPT-TO surfaces the
  // mailbox-exists oracle; an attacker that hammers RCPT TO can
  // enumerate a domain's mailbox map without ever sending DATA).
  // Per-IP, per-minute. Tuned higher than auth-failure since
  // legitimate senders can RCPT-TO multiple recipients per message;
  // operator overrides via `rcptFailuresPerIpPerMinute`.
  rcptFailuresPerIpPerMinute:    50,                                                                  // RCPT enumeration bound
  disabled:                      false,
});

var CONNECTION_RATE_WINDOW_MS = C.TIME.minutes(1);
var AUTH_FAILURE_WINDOW_MS    = C.TIME.minutes(15);
var RCPT_FAILURE_WINDOW_MS    = C.TIME.minutes(1);

/**
 * @primitive b.mail.server.rateLimit.create
 * @signature b.mail.server.rateLimit.create(opts?)
 * @since     0.9.47
 * @status    stable
 * @related   b.mail.server.mx.create, b.mail.server.submission.create
 *
 * Build a rate-limit handle. The listeners compose this internally
 * with the framework defaults; operators override caps by passing
 * their own `rateLimit` opt to `b.mail.server.mx.create` or
 * `b.mail.server.submission.create`. Direct construction is for
 * operators sharing one budget across multiple listeners (e.g. an
 * MX + a submission server on the same IP space).
 *
 * @opts
 *   maxConcurrentConnectionsPerIp: number,   // default 10
 *   connectionsPerIpPerMinute:     number,   // default 60
 *   authFailuresPerIpPer15Min:     number,   // default 10
 *   minBytesPerSecond:             number,   // default 100 (DATA-body slow-loris floor)
 *   rcptFailuresPerIpPerMinute:    number,   // default 50 (RCPT 550 enumeration bound)
 *   disabled:                      boolean,  // default false — test escape hatch
 *
 * @example
 *   var rl = b.mail.server.rateLimit.create({
 *     maxConcurrentConnectionsPerIp: 5,
 *     connectionsPerIpPerMinute:     30,
 *   });
 *   var ok = rl.admitConnection("192.0.2.1");
 *   // → { ok: true } or { ok: false, reason: "concurrent-per-ip" | "rate-per-ip" }
 */
function create(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new MailServerRateLimitError("mail-server-rate-limit/bad-opts",
      "b.mail.server.rateLimit.create: opts must be a plain object");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts, [
    "maxConcurrentConnectionsPerIp",
    "connectionsPerIpPerMinute",
    "authFailuresPerIpPer15Min",
    "minBytesPerSecond",
    "rcptFailuresPerIpPerMinute",
  ], "b.mail.server.rateLimit.create.", MailServerRateLimitError, "mail-server-rate-limit/bad-bound");
  validateOpts.optionalBoolean(opts.disabled,
    "b.mail.server.rateLimit.create: opts.disabled",
    MailServerRateLimitError, "mail-server-rate-limit/bad-disabled");

  var cfg = {
    maxConcurrentConnectionsPerIp: opts.maxConcurrentConnectionsPerIp === undefined
      ? DEFAULTS.maxConcurrentConnectionsPerIp : opts.maxConcurrentConnectionsPerIp,
    connectionsPerIpPerMinute: opts.connectionsPerIpPerMinute === undefined
      ? DEFAULTS.connectionsPerIpPerMinute : opts.connectionsPerIpPerMinute,
    authFailuresPerIpPer15Min: opts.authFailuresPerIpPer15Min === undefined
      ? DEFAULTS.authFailuresPerIpPer15Min : opts.authFailuresPerIpPer15Min,
    minBytesPerSecond: opts.minBytesPerSecond === undefined
      ? DEFAULTS.minBytesPerSecond : opts.minBytesPerSecond,
    rcptFailuresPerIpPerMinute: opts.rcptFailuresPerIpPerMinute === undefined
      ? DEFAULTS.rcptFailuresPerIpPerMinute : opts.rcptFailuresPerIpPerMinute,
    disabled: opts.disabled === true,
  };

  // Per-IP state. Maps key on the remote IP string; entries are
  // pruned lazily on read (any entry whose window has fully expired
  // is removed instead of returned). Operators with extreme connection
  // counts can wire a periodic gc() externally; the lazy prune keeps
  // memory bounded under normal load.
  var concurrentByIp   = new Map();        // ip → integer count
  var connectionTimes  = new Map();        // ip → [timestampMs, ...]
  var authFailureTimes = new Map();        // ip → [timestampMs, ...]
  var rcptFailureTimes = new Map();        // ip → [timestampMs, ...]

  function _pruneWindow(arr, windowMs) {
    var cutoff = Date.now() - windowMs;
    var i = 0;
    while (i < arr.length && arr[i] < cutoff) i += 1;
    if (i > 0) arr.splice(0, i);
  }

  function _audit(action, outcome, metadata) {
    try {
      audit().safeEmit({ action: action, outcome: outcome || "denied", metadata: metadata || {} });
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }

  function admitConnection(ip) {
    if (cfg.disabled) return { ok: true };
    var concurrent = concurrentByIp.get(ip) || 0;
    if (concurrent >= cfg.maxConcurrentConnectionsPerIp) {
      _audit("mail.server.rate_limit.refused", "denied",
        { reason: "concurrent-per-ip", ip: ip, cap: cfg.maxConcurrentConnectionsPerIp });
      return { ok: false, reason: "concurrent-per-ip" };
    }
    var times = connectionTimes.get(ip);
    if (!times) { times = []; connectionTimes.set(ip, times); }
    _pruneWindow(times, CONNECTION_RATE_WINDOW_MS);
    if (times.length >= cfg.connectionsPerIpPerMinute) {
      _audit("mail.server.rate_limit.refused", "denied",
        { reason: "rate-per-ip", ip: ip, cap: cfg.connectionsPerIpPerMinute });
      return { ok: false, reason: "rate-per-ip" };
    }
    times.push(Date.now());
    concurrentByIp.set(ip, concurrent + 1);
    return { ok: true };
  }

  function releaseConnection(ip) {
    if (cfg.disabled) return;
    var concurrent = concurrentByIp.get(ip) || 0;
    if (concurrent <= 1) concurrentByIp.delete(ip);
    else concurrentByIp.set(ip, concurrent - 1);
    // CWE-400. authFailureTimes auto-deletes when its array
    // empties in checkAuthAdmit; connectionTimes was the asymmetric
    // case. Sweep this IP's rate-window now that it has released its
    // last concurrent slot: if the per-minute window has fully
    // expired AND there's no live connection, drop the entry so a
    // botnet of unique IPs cannot grow the Map without bound.
    if (!concurrentByIp.has(ip)) {
      var arr = connectionTimes.get(ip);
      if (arr) {
        _pruneWindow(arr, CONNECTION_RATE_WINDOW_MS);
        if (arr.length === 0) connectionTimes.delete(ip);
      }
    }
  }

  function checkAuthAdmit(ip) {
    if (cfg.disabled) return { ok: true };
    var times = authFailureTimes.get(ip);
    if (!times) return { ok: true };
    _pruneWindow(times, AUTH_FAILURE_WINDOW_MS);
    if (times.length === 0) {
      authFailureTimes.delete(ip);
      return { ok: true };
    }
    if (times.length >= cfg.authFailuresPerIpPer15Min) {
      _audit("mail.server.rate_limit.auth_refused", "denied",
        { reason: "auth-failures-per-ip", ip: ip, cap: cfg.authFailuresPerIpPer15Min });
      return { ok: false, reason: "auth-failures-per-ip" };
    }
    return { ok: true };
  }

  function noteAuthFailure(ip) {
    if (cfg.disabled) return;
    var times = authFailureTimes.get(ip);
    if (!times) { times = []; authFailureTimes.set(ip, times); }
    times.push(Date.now());
  }

  // RFC 5321 §3.5 — RCPT TO 550 vs 250 responses surface a mailbox-
  // existence oracle. An IP that issues many RCPT-TO commands receiving
  // 550 should hit the same admit / refuse shape used for AUTH failures.
  // checkRcptAdmit returns ok=false once the per-minute cap is reached;
  // listeners then return a transient 421 (close + back off) instead of
  // continuing to surface the per-recipient oracle.
  function checkRcptAdmit(ip) {
    if (cfg.disabled) return { ok: true };
    var times = rcptFailureTimes.get(ip);
    if (!times) return { ok: true };
    _pruneWindow(times, RCPT_FAILURE_WINDOW_MS);
    if (times.length === 0) {
      rcptFailureTimes.delete(ip);
      return { ok: true };
    }
    if (times.length >= cfg.rcptFailuresPerIpPerMinute) {
      _audit("mail.server.rate_limit.rcpt_refused", "denied",
        { reason: "rcpt-failures-per-ip", ip: ip, cap: cfg.rcptFailuresPerIpPerMinute });
      return { ok: false, reason: "rcpt-failures-per-ip" };
    }
    return { ok: true };
  }

  function noteRcptFailure(ip) {
    if (cfg.disabled) return;
    var times = rcptFailureTimes.get(ip);
    if (!times) { times = []; rcptFailureTimes.set(ip, times); }
    times.push(Date.now());
  }

  function minBytesPerSecond() { return cfg.disabled ? 0 : cfg.minBytesPerSecond; }
  function isDisabled() { return cfg.disabled; }

  return {
    admitConnection:    admitConnection,
    releaseConnection:  releaseConnection,
    checkAuthAdmit:     checkAuthAdmit,
    noteAuthFailure:    noteAuthFailure,
    checkRcptAdmit:     checkRcptAdmit,
    noteRcptFailure:    noteRcptFailure,
    minBytesPerSecond:  minBytesPerSecond,
    isDisabled:         isDisabled,
  };
}

module.exports = {
  create:                       create,
  MailServerRateLimitError:     MailServerRateLimitError,
  DEFAULTS:                     DEFAULTS,
};
