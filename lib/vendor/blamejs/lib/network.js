"use strict";
/**
 * @module b.network
 * @featured true
 * @nav    Network
 * @title  Network
 *
 * @intro
 *   Framework network helpers — DNS-over-HTTPS dispatch, TLS
 *   configuration, OCSP/CT validation, NTP/NTS-KE bootstrap.
 *
 *   `b.network` is the umbrella facade over the framework's outbound-
 *   network surface: DNS (default DoH on, optional DoT, lookup cache
 *   with TTL bound), TLS trust store (CA bundle / system trust /
 *   ignored-cert opt-in), proxy resolution from `HTTP_PROXY` /
 *   `HTTPS_PROXY` / `NO_PROXY`, NTP / NTS-KE drift checks, SMTP
 *   policy (MTA-STS / DANE / TLS-RPT), heartbeat watchdog, byte
 *   quota, SSRF allowlist, and socket-level defaults
 *   (TCP_NODELAY / SO_KEEPALIVE).
 *
 *   `bootFromEnv` reads BLAMEJS_* environment variables once at
 *   startup and applies the union to the live facade — operators
 *   wire it from a process-supervisor's env without touching code.
 *   `snapshot` returns a redacted view of the current configuration
 *   for the operations dashboard. `applyToSocket` is the per-socket
 *   tuning hook for primitives building their own server (`tls`,
 *   `wsServer`, etc.).
 *
 * @card
 *   Framework network helpers — DNS-over-HTTPS dispatch, TLS configuration, OCSP/CT validation, NTP/NTS-KE bootstrap.
 */

var byteQuota = require("./network-byte-quota");
var ntpCheck = require("./ntp-check");
var nts      = require("./network-nts");
var networkDns = require("./network-dns");
networkDns.resolver = require("./network-dns-resolver");
networkDns.dnssec = require("./network-dnssec");
networkDns.dane = require("./network-dane");
networkDns.tsig = require("./network-tsig");
var networkProxy = require("./network-proxy");
var networkTls = require("./network-tls");
var heartbeat = require("./network-heartbeat");
var smtpPolicy = require("./network-smtp-policy");
var ssrfGuard  = require("./ssrf-guard");

var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var NetworkError = defineClass("NetworkError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });

var SOCKET_DEFAULTS = {
  noDelay:           true,
  keepAlive:         true,
  keepAliveInitialDelayMs: 0,
};

function _setSocketNoDelay(value) {
  if (typeof value !== "boolean") {
    throw new NetworkError("socket/bad-no-delay", "socket.setDefaultNoDelay: expected boolean, got " + typeof value);
  }
  SOCKET_DEFAULTS.noDelay = value;
}

function _setSocketKeepAlive(opts) {
  opts = opts || {};
  validateOpts(opts, ["enable", "initialDelayMs"], "socket.setDefaultKeepAlive");
  if (opts.enable !== undefined) {
    if (typeof opts.enable !== "boolean") {
      throw new NetworkError("socket/bad-keepalive", "socket.setDefaultKeepAlive: enable must be boolean");
    }
    SOCKET_DEFAULTS.keepAlive = opts.enable;
  }
  if (opts.initialDelayMs !== undefined) {
    if (typeof opts.initialDelayMs !== "number" || !isFinite(opts.initialDelayMs) || opts.initialDelayMs < 0) {
      throw new NetworkError("socket/bad-keepalive-delay", "socket.setDefaultKeepAlive: initialDelayMs must be non-negative finite number");
    }
    SOCKET_DEFAULTS.keepAliveInitialDelayMs = opts.initialDelayMs;
  }
}

// SO_LINGER is intentionally NOT exposed: Node's net.Socket has no
// public setLinger() method (the option is tracked at
// nodejs/node#27293 / rejected for the public surface). Reaching into
// socket._handle to call setLinger is an unstable internal API. The
// closest operator-exposed semantic is socket.destroy() (RST = "abort
// on close") vs socket.end() (graceful FIN). Operators needing true
// SO_LINGER should use a native binding outside the framework. This
// stub stays in the export with throw-on-call so a future Node release
// that exposes setLinger can be wired without an API addition.
function _setSocketLinger(_opts) {
  throw new NetworkError("socket/linger-not-supported",
    "socket.setDefaultLinger: SO_LINGER is not exposed by Node's public net.Socket API " +
    "(see nodejs/node#27293). Use socket.destroy() (abort) vs socket.end() (graceful) " +
    "to control close semantics, or a native binding if true SO_LINGER is required.");
}

function _socketDefaults() {
  return {
    noDelay:                 SOCKET_DEFAULTS.noDelay,
    keepAlive:               SOCKET_DEFAULTS.keepAlive,
    keepAliveInitialDelayMs: SOCKET_DEFAULTS.keepAliveInitialDelayMs,
  };
}

/**
 * @primitive b.network.socket.applyToSocket
 * @signature b.network.socket.applyToSocket(socket)
 * @since     0.7.68
 * @related   b.network.bootFromEnv, b.network.snapshot
 *
 * Apply the framework's socket defaults (`TCP_NODELAY`,
 * `SO_KEEPALIVE` + initial-delay) to a freshly-created
 * `net.Socket` / `tls.TLSSocket`. Best-effort: a socket that has
 * already errored, lacks the setter methods, or rejects the call
 * is left as-is. Returns the same socket. Used by primitives that
 * build their own server (`b.tls`, `b.wsServer`, `b.smtp`) so
 * every socket on the wire follows the same tuning.
 *
 * @example
 *   var net = require("net");
 *   var s   = new net.Socket();
 *   var ret = b.network.socket.applyToSocket(s);
 *   ret === s;
 *   // → true
 *   s.destroy();
 */
function applyToSocket(socket) {
  if (!socket) return socket;
  try {
    if (typeof socket.setNoDelay === "function") socket.setNoDelay(SOCKET_DEFAULTS.noDelay);
    if (typeof socket.setKeepAlive === "function") {
      socket.setKeepAlive(SOCKET_DEFAULTS.keepAlive, SOCKET_DEFAULTS.keepAliveInitialDelayMs || 0);
    }
  } catch (_e) { /* best-effort socket-tuning — apply or skip */ }
  return socket;
}

var ntpFacade = {
  querySingle:    ntpCheck.querySingle,
  checkDrift:     ntpCheck.checkDrift,
  bootCheck:      ntpCheck.bootCheck,
  setThresholds:  ntpCheck.setThresholds,
  getThresholds:  ntpCheck.getThresholds,
  setServers:     function (list) {
    if (!Array.isArray(list) || list.length === 0) {
      throw new NetworkError("ntp/bad-servers", "ntp.setServers: expected non-empty array");
    }
    ntpFacade._defaultServers = list.slice();
    _emitObs("network.ntp.servers.set", { count: list.length });
  },
  getServers:     function () {
    return (ntpFacade._defaultServers || ntpCheck.DEFAULT_SERVERS).slice();
  },
  _defaultServers: null,
  nts:            nts,
};

/**
 * @primitive b.network.bootFromEnv
 * @signature b.network.bootFromEnv(opts)
 * @since     0.7.68
 * @related   b.network.snapshot, b.network.socket.applyToSocket
 *
 * Read `BLAMEJS_*` environment variables once and apply the union to
 * the live network facade. Recognised keys cover NTP servers /
 * timeout / drift thresholds, DNS servers / result-order / family /
 * lookup-timeout / cache-TTL / DoH URL or provider / DoT host+port,
 * `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, extra-CA file or
 * directory, `BLAMEJS_USE_SYSTEM_TRUST`, and the socket
 * `TCP_NODELAY` / `SO_KEEPALIVE` defaults. Returns an `applied`
 * report — exactly which keys took effect. Audits
 * `network.boot.from_env` unless `opts.audit:false`.
 *
 * @opts
 *   env:    object,    // default process.env — pass a fixture object in tests
 *   audit:  boolean,   // default true — emit `network.boot.from_env`
 *
 * @example
 *   var applied = b.network.bootFromEnv({
 *     env:   { BLAMEJS_NTP_SERVERS: "time.cloudflare.com,time.google.com" },
 *     audit: false,
 *   });
 *   applied.ntp.servers;
 *   // → 2
 */
function bootFromEnv(opts) {
  opts = opts || {};
  validateOpts(opts, ["env", "audit"], "network.bootFromEnv");
  var env = opts.env || process.env;
  var applied = { ntp: {}, dns: {}, proxy: false, tls: {}, heartbeat: 0, socket: {} };

  if (env.BLAMEJS_NTP_SERVERS) {
    var list = String(env.BLAMEJS_NTP_SERVERS).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (list.length > 0) { ntpFacade.setServers(list); applied.ntp.servers = list.length; }
  }
  var ntpTimeout = env.BLAMEJS_NTP_TIMEOUT_MS;
  if (ntpTimeout) {
    var t = parseInt(ntpTimeout, 10);
    if (isFinite(t) && t > 0) { ntpFacade._defaultTimeoutMs = t; applied.ntp.timeoutMs = t; }
  }
  var ntpWarn = env.BLAMEJS_NTP_DRIFT_WARN_MS;
  var ntpFatal = env.BLAMEJS_NTP_DRIFT_FATAL_MS;
  if (ntpWarn || ntpFatal) {
    var thr = {};
    if (ntpWarn)  { thr.warnMs  = parseInt(ntpWarn, 10);  applied.ntp.warnMs  = thr.warnMs; }
    if (ntpFatal) { thr.fatalMs = parseInt(ntpFatal, 10); applied.ntp.fatalMs = thr.fatalMs; }
    ntpCheck.setThresholds(thr);
  }

  var dnsServers = env.BLAMEJS_DNS_SERVERS;
  if (dnsServers) {
    var dl = String(dnsServers).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (dl.length > 0) { networkDns.setServers(dl); applied.dns.servers = dl.length; }
  }
  if (env.BLAMEJS_DNS_RESULT_ORDER)  { networkDns.setResultOrder(env.BLAMEJS_DNS_RESULT_ORDER); applied.dns.resultOrder = env.BLAMEJS_DNS_RESULT_ORDER; }
  if (env.BLAMEJS_DNS_FAMILY)        { networkDns.setFamily(parseInt(env.BLAMEJS_DNS_FAMILY, 10)); applied.dns.family = parseInt(env.BLAMEJS_DNS_FAMILY, 10); }
  if (env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS) { networkDns.setLookupTimeoutMs(parseInt(env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS, 10)); applied.dns.lookupTimeoutMs = parseInt(env.BLAMEJS_DNS_LOOKUP_TIMEOUT_MS, 10); }
  if (env.BLAMEJS_DNS_CACHE_TTL_MS)      { networkDns.setCacheTtlMs(parseInt(env.BLAMEJS_DNS_CACHE_TTL_MS, 10)); applied.dns.cacheTtlMs = parseInt(env.BLAMEJS_DNS_CACHE_TTL_MS, 10); }
  if (env.BLAMEJS_DOH_URL)               { networkDns.useDnsOverHttps({ url: env.BLAMEJS_DOH_URL }); applied.dns.doh = env.BLAMEJS_DOH_URL; }
  else if (env.BLAMEJS_DOH_PROVIDER)     { networkDns.useDnsOverHttps({ provider: env.BLAMEJS_DOH_PROVIDER }); applied.dns.dohProvider = env.BLAMEJS_DOH_PROVIDER; }
  if (env.BLAMEJS_DOT_HOST)              { networkDns.useDnsOverTls({ host: env.BLAMEJS_DOT_HOST, port: env.BLAMEJS_DOT_PORT ? parseInt(env.BLAMEJS_DOT_PORT, 10) : 853 }); applied.dns.dot = env.BLAMEJS_DOT_HOST; }

  if (env.HTTP_PROXY || env.http_proxy || env.HTTPS_PROXY || env.https_proxy ||
      env.NO_PROXY  || env.no_proxy  || env.ALL_PROXY    || env.all_proxy) {
    applied.proxy = networkProxy.fromEnv(env);
  }

  if (env.BLAMEJS_EXTRA_CA_CERTS) {
    networkTls.addCa(env.BLAMEJS_EXTRA_CA_CERTS, { label: "BLAMEJS_EXTRA_CA_CERTS" });
    applied.tls.fileLoaded = env.BLAMEJS_EXTRA_CA_CERTS;
  }
  if (env.BLAMEJS_EXTRA_CA_CERTS_DIR) {
    networkTls.addCaBundle(env.BLAMEJS_EXTRA_CA_CERTS_DIR, { label: "BLAMEJS_EXTRA_CA_CERTS_DIR" });
    applied.tls.dirLoaded = env.BLAMEJS_EXTRA_CA_CERTS_DIR;
  }
  if (env.BLAMEJS_USE_SYSTEM_TRUST === "1" || env.BLAMEJS_USE_SYSTEM_TRUST === "true") {
    networkTls.useSystemTrust(true);
    applied.tls.systemTrust = true;
  }

  if (env.BLAMEJS_SOCKET_NO_DELAY)             _setSocketNoDelay(env.BLAMEJS_SOCKET_NO_DELAY === "1" || env.BLAMEJS_SOCKET_NO_DELAY === "true");
  if (env.BLAMEJS_SOCKET_KEEPALIVE)            _setSocketKeepAlive({ enable: env.BLAMEJS_SOCKET_KEEPALIVE === "1" || env.BLAMEJS_SOCKET_KEEPALIVE === "true" });
  if (env.BLAMEJS_SOCKET_KEEPALIVE_DELAY_MS)   _setSocketKeepAlive({ initialDelayMs: parseInt(env.BLAMEJS_SOCKET_KEEPALIVE_DELAY_MS, 10) });
  applied.socket = _socketDefaults();

  var auditOn = opts.audit !== false;
  if (auditOn) {
    var sink;
    try { sink = audit(); } catch (_e) { sink = null; }
    if (sink && typeof sink.safeEmit === "function") {
      try {
        sink.safeEmit({
          action:   "network.boot.from_env",
          outcome:  "success",
          metadata: applied,
        });
      } catch (_e) { /* audit best-effort — never break boot */ }
    }
  }
  _emitObs("network.boot.from_env", { source: "env" });
  return applied;
}

/**
 * @primitive b.network.snapshot
 * @signature b.network.snapshot()
 * @since     0.7.68
 * @related   b.network.bootFromEnv
 *
 * Return a redacted snapshot of the network facade's current
 * configuration: NTP servers + drift thresholds, DNS state (servers,
 * result-order, family, DoH/DoT, cache TTL), proxy resolution, TLS
 * trust-store size + system-trust flag, heartbeat statuses, and
 * socket defaults. Cheap; safe to call from a `/healthz` or
 * operations endpoint. No secrets are returned.
 *
 * @example
 *   var snap = b.network.snapshot();
 *   typeof snap.tls.caCount;
 *   // → "number"
 */
function snapshot() {
  return {
    ntp: {
      servers:     ntpFacade.getServers(),
      thresholds:  ntpCheck.getThresholds(),
    },
    dns: networkDns._stateForTest(),
    proxy: networkProxy.snapshot(),
    tls:  {
      systemTrust: networkTls.isSystemTrustEnabled(),
      caCount:     networkTls.getTrustStore().length,
    },
    heartbeat: heartbeat.statuses(),
    socket: _socketDefaults(),
  };
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) { /* obs best-effort */ }
}

function _resetForTest() {
  ntpFacade._defaultServers = null;
  ntpFacade._defaultTimeoutMs = null;
  if (typeof ntpCheck._resetThresholdsForTest === "function") ntpCheck._resetThresholdsForTest();
  networkDns._resetForTest();
  networkProxy._resetForTest();
  networkTls._resetForTest();
  heartbeat._resetForTest();
  SOCKET_DEFAULTS.noDelay = true;
  SOCKET_DEFAULTS.keepAlive = true;
  SOCKET_DEFAULTS.keepAliveInitialDelayMs = 0;
}

module.exports = {
  ntp:        ntpFacade,
  dns:        networkDns,
  proxy:      networkProxy,
  tls:        networkTls,
  heartbeat:  heartbeat,
  smtp: {
    policy:    smtpPolicy,
    mtaSts:    smtpPolicy.mtaSts,
    dane:      smtpPolicy.dane,
    tlsRpt:    smtpPolicy.tlsRpt,
  },
  allowlist:  { create: ssrfGuard.createAllowlist },
  byteQuota: {
    create: byteQuota.create,
    ByteQuotaError: byteQuota.ByteQuotaError,
  },
  socket: {
    setDefaultNoDelay:   _setSocketNoDelay,
    setDefaultKeepAlive: _setSocketKeepAlive,
    setDefaultLinger:    _setSocketLinger,
    defaults:            _socketDefaults,
    applyToSocket:       applyToSocket,
  },
  bootFromEnv:    bootFromEnv,
  snapshot:       snapshot,
  NetworkError:   NetworkError,
  _resetForTest:  _resetForTest,
};
