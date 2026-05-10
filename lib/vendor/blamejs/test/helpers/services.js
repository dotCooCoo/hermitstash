"use strict";
/**
 * Service config + readiness helpers for integration tests that
 * connect to the docker-compose.test.yml stack.
 *
 * Both plain and TLS endpoints are exposed for every backend that
 * supports TLS in the test stack. The framework targets PQC-first
 * crypto on its own internal surfaces; these external service URLs
 * are what tests use to exercise the framework's connect-over-TLS code
 * paths against a real handshake (where applicable, with X25519MLKEM768
 * hybrid groups requested in the cipher list).
 *
 * Public API:
 *   var svcs = require("./services");
 *
 *   svcs.URLS.redis           — plain redis://...:6379
 *   svcs.URLS.redisTls        — TLS rediss://...:6380
 *   svcs.URLS.postgres        — postgres://... (sslmode picked client-side)
 *   svcs.URLS.postgresTls     — same host:port + ?sslmode=require
 *   svcs.URLS.mysql, .mysqlTls, .mongodb, .mongodbTls, .minio, .minioTls,
 *   svcs.URLS.rabbitmq, .rabbitmqTls, .nats, .natsTls, .syslog, .syslogTls,
 *   svcs.URLS.mailpit, .mailpitTls, .ntp, .haproxy, .caddy, .caddyTls,
 *   svcs.URLS.mitmproxy, .mitmproxyWeb, .squid
 *
 *   await svcs.requireService("redis")
 *     // { ok: true, url, host, port, scheme }
 *     // { ok: false, reason }
 *
 *   await svcs.requireAll()
 *     // throws when any service is unreachable
 *
 *   svcs.CA_CERT_PATH          // host-side path that mirrors the
 *                              // certs volume's ca.crt; null until
 *                              // svcs.exportCaCert() is called
 *   await svcs.exportCaCert()  // copies /certs/ca.crt out of the
 *                              // pki-init volume so node:tls clients
 *                              // can pin against it
 *
 * Test-side usage pattern:
 *   var svc = await svcs.requireService("redisTls");
 *   if (!svc.ok) {
 *     console.log("[skip] redis-tls: " + svc.reason);
 *     return;
 *   }
 *   // svc.url is safe to pass to b.redisClient.create({ url: svc.url, ca: svcs.CA_CERT_PATH })
 */
var fs   = require("node:fs");
var net  = require("node:net");
var os   = require("node:os");
var path = require("node:path");
var tls  = require("node:tls");
var dgram = require("node:dgram");

// Every endpoint exposes IPv4 and IPv6 forms — the docker-compose.test.yml
// dual-binds every host port onto both 127.0.0.1 and [::1]. Tests that
// want to exercise both address families iterate { foo, fooV6 } pairs.
var DEFAULTS = {
  // ---- backends, plain (IPv4) ----
  redis:        "redis://127.0.0.1:6379",
  postgres:     "postgres://blamejs:blamejs_test@127.0.0.1:5432/blamejs_test",
  mysql:        "mysql://blamejs:blamejs_test@127.0.0.1:3306/blamejs_test",
  mongodb:      "mongodb://blamejs:blamejs_test@127.0.0.1:27017/?authSource=admin",
  minio:        "http://blamejs:blamejs_test_password@127.0.0.1:9000",
  rabbitmq:     "amqp://blamejs:blamejs_test@127.0.0.1:5672",
  nats:         "nats://127.0.0.1:4222",
  syslog:       "tcp://127.0.0.1:5514",
  ntp:          "ntp://127.0.0.1:12300",
  mailpit:      "smtp://127.0.0.1:1025",

  // ---- backends, plain (IPv6) ----
  redisV6:      "redis://[::1]:6379",
  postgresV6:   "postgres://blamejs:blamejs_test@[::1]:5432/blamejs_test",
  mysqlV6:      "mysql://blamejs:blamejs_test@[::1]:3306/blamejs_test",
  mongodbV6:    "mongodb://blamejs:blamejs_test@[::1]:27017/?authSource=admin",
  minioV6:      "http://blamejs:blamejs_test_password@[::1]:9000",
  rabbitmqV6:   "amqp://blamejs:blamejs_test@[::1]:5672",
  natsV6:       "nats://[::1]:4222",
  syslogV6:     "tcp://[::1]:5514",
  ntpV6:        "ntp://[::1]:12300",
  mailpitV6:    "smtp://[::1]:1025",

  // ---- backends, TLS (IPv4) ----
  redisTls:     "rediss://127.0.0.1:6380",
  postgresTls:  "postgres://blamejs:blamejs_test@127.0.0.1:5432/blamejs_test?sslmode=require",
  mysqlTls:     "mysql://blamejs:blamejs_test@127.0.0.1:3306/blamejs_test?ssl=true",
  mongodbTls:   "mongodb://blamejs:blamejs_test@127.0.0.1:27017/?authSource=admin&tls=true",
  minioTls:     "https://blamejs:blamejs_test_password@127.0.0.1:9443",
  rabbitmqTls:  "amqps://blamejs:blamejs_test@127.0.0.1:5671",
  natsTls:      "tls://127.0.0.1:4222",
  syslogTls:    "tcp+tls://127.0.0.1:6514",
  // mailpit uses STARTTLS on the plain :1025 port — there is no native
  // SMTPS listener. Use URLS.mailpit and let the framework's smtpTransport
  // negotiate the TLS upgrade via EHLO/STARTTLS.

  // ---- backends, TLS (IPv6) ----
  redisTlsV6:    "rediss://[::1]:6380",
  postgresTlsV6: "postgres://blamejs:blamejs_test@[::1]:5432/blamejs_test?sslmode=require",
  mysqlTlsV6:    "mysql://blamejs:blamejs_test@[::1]:3306/blamejs_test?ssl=true",
  mongodbTlsV6:  "mongodb://blamejs:blamejs_test@[::1]:27017/?authSource=admin&tls=true",
  minioTlsV6:    "https://blamejs:blamejs_test_password@[::1]:9443",
  rabbitmqTlsV6: "amqps://blamejs:blamejs_test@[::1]:5671",
  natsTlsV6:     "tls://[::1]:4222",
  syslogTlsV6:   "tcp+tls://[::1]:6514",

  // ---- DNS resolver (plain + DoT + DoH) ----
  dns:          "dns://127.0.0.1:1053",
  dnsV6:        "dns://[::1]:1053",
  dnsTls:       "dns+tls://127.0.0.1:1853",
  dnsTlsV6:     "dns+tls://[::1]:1853",
  dnsHttps:     "https://127.0.0.1:8053/dns-query",
  dnsHttpsV6:   "https://[::1]:8053/dns-query",
  dnsHealth:    "http://127.0.0.1:8054/health",
  dnsHealthV6:  "http://[::1]:8054/health",

  // ---- proxies + DPI (IPv4) ----
  haproxy:      "https://127.0.0.1:8443",
  haproxyStats: "http://127.0.0.1:8404/stats",
  haproxyRedis: "tcp://127.0.0.1:6390",
  caddy:        "http://127.0.0.1:8080",
  caddyTls:     "https://127.0.0.1:8444",
  mitmproxy:    "http://127.0.0.1:8090",
  mitmproxyWeb: "http://127.0.0.1:8091",
  squid:        "http://127.0.0.1:3128",

  // ---- federated authentication (Keycloak — OIDC OP + SAML IdP) ----
  keycloak:     "http://127.0.0.1:18080",
  keycloakV6:   "http://[::1]:18080",

  // ---- proxies + DPI (IPv6) ----
  haproxyV6:      "https://[::1]:8443",
  haproxyStatsV6: "http://[::1]:8404/stats",
  haproxyRedisV6: "tcp://[::1]:6390",
  caddyV6:        "http://[::1]:8080",
  caddyTlsV6:     "https://[::1]:8444",
  mitmproxyV6:    "http://[::1]:8090",
  mitmproxyWebV6: "http://[::1]:8091",
  squidV6:        "http://[::1]:3128",
};

function _envOverride(name) {
  var key = "BLAMEJS_" + name.replace(/[A-Z]/g, function (c) { return "_" + c; }).toUpperCase() + "_URL";
  var v = process.env[key];
  return (typeof v === "string" && v.length > 0) ? v : null;
}

var URLS = {};
Object.keys(DEFAULTS).forEach(function (name) {
  URLS[name] = _envOverride(name) || DEFAULTS[name];
});

var CA_CERT_PATH = null;

// Copy /certs/ca.crt out of the pki-init named volume into a temp file
// the host can read (named volumes aren't directly host-accessible).
// Idempotent — caches the path on the module exports.
async function exportCaCert() {
  if (CA_CERT_PATH && fs.existsSync(CA_CERT_PATH)) return CA_CERT_PATH;
  var dest = path.join(os.tmpdir(), "blamejs-test-ca.crt");
  // Use docker cp via child_process — but the framework forbids depending
  // on shell-out from test helpers. Instead, copy via a one-shot exec
  // through a known-running container. The pki-init container has
  // already exited; pick any running container that has /certs mounted.
  // Simpler: run `docker cp` via spawn since this helper is dev-only
  // and dev tooling is allowed shell access.
  var spawn = require("node:child_process").spawn;
  return await new Promise(function (resolve, reject) {
    var p = spawn("docker", ["cp", "blamejs-test-redis:/certs/ca.crt", dest], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    var err = "";
    p.stderr.on("data", function (b) { err += b.toString(); });
    p.on("close", function (code) {
      if (code !== 0) {
        return reject(new Error("docker cp ca.crt failed (exit " + code + "): " + err.trim()));
      }
      CA_CERT_PATH = dest;
      module.exports.CA_CERT_PATH = dest;
      resolve(dest);
    });
    p.on("error", function (e) { reject(e); });
  });
}

// Parse a URL down to { scheme, host, port } for TCP probing without
// hauling in node:url quirks for non-standard schemes. Handles bracketed
// IPv6 hosts: scheme://[::1]:port/...
function _hostPort(name, urlStr) {
  // Bracketed IPv6 form first (must come before the bare-host fallback).
  var m6 = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/]*@)?\[([0-9a-f:]+)\](?::(\d+))?/i.exec(urlStr);
  if (m6) {
    var scheme6 = m6[1].toLowerCase();
    var port6 = m6[3] ? Number(m6[3]) : _defaultPort(scheme6);
    if (!Number.isFinite(port6) || port6 <= 0) {
      return { ok: false, reason: "services: no port for " + name + " in " + urlStr };
    }
    return { ok: true, scheme: scheme6, host: m6[2], port: port6, family: 6 };
  }
  var m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/]*@)?([^/:?#[]+)(?::(\d+))?/i.exec(urlStr);
  if (!m) {
    return { ok: false, reason: "services: cannot parse URL for " + name + ": " + urlStr };
  }
  var scheme = m[1].toLowerCase();
  var host = m[2];
  var port = m[3] ? Number(m[3]) : _defaultPort(scheme);
  if (!Number.isFinite(port) || port <= 0) {
    return { ok: false, reason: "services: no port for " + name + " in " + urlStr };
  }
  return { ok: true, scheme: scheme, host: host, port: port, family: 4 };
}

function _defaultPort(scheme) {
  switch (scheme) {
    case "redis":     return 6379;
    case "rediss":    return 6380;
    case "postgres":  return 5432;
    case "postgresql":return 5432;
    case "mysql":     return 3306;
    case "mongodb":   return 27017;
    case "amqp":      return 5672;
    case "amqps":     return 5671;
    case "nats":      return 4222;
    case "tls":       return 4222;
    case "ntp":       return 123;
    case "smtp":      return 25;
    case "smtps":     return 465;
    case "http":      return 80;
    case "https":     return 443;
    default:          return null;
  }
}

function _probeTcp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var family = host.indexOf(":") !== -1 ? 6 : 4;
    var sock = net.connect({ host: host, port: port, family: family });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tcp connect timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.end(); } catch (_e) {}
      resolve({ ok: true });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "tcp connect failed: " + msg });
    });
  });
}

function _probeTls(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var done = false;
    var family = host.indexOf(":") !== -1 ? 6 : 4;
    var sock = tls.connect({
      host: host,
      port: port,
      family: family,
      rejectUnauthorized: false,
      // SNI is not legal for IP literals — drop servername for both
      // IPv4 and IPv6 hosts.
      servername: undefined,
    });
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tls handshake timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("secureConnect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var info = { protocol: sock.getProtocol(), cipher: (sock.getCipher() || {}).name };
      try { sock.end(); } catch (_e) {}
      resolve({ ok: true, info: info });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "tls handshake failed: " + msg });
    });
  });
}

function _probeUdp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = dgram.createSocket(host.indexOf(":") !== -1 ? "udp6" : "udp4");
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_e) {}
      // For UDP we can't tell "down" vs "no reply" from a single send.
      // The probe succeeds when no error fires synchronously.
      resolve({ ok: true, soft: true });
    }, timeoutMs);
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch (_e) {}
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "udp probe error: " + msg });
    });
    sock.send(Buffer.alloc(1), 0, 1, port, host, function (err) {
      if (err && !done) {
        done = true;
        clearTimeout(timer);
        try { sock.close(); } catch (_e) {}
        var msg = (err && err.code) || (err && err.message) || String(err);
        resolve({ ok: false, reason: "udp send error: " + msg });
      }
    });
  });
}

async function requireService(name, opts) {
  opts = opts || {};
  var timeoutMs = Number(opts.timeoutMs) || 2000;
  var url = URLS[name];
  if (!url) {
    return { ok: false, reason: "services: unknown service '" + name +
      "' (valid: " + Object.keys(URLS).join(", ") + ")" };
  }
  var hp = _hostPort(name, url);
  if (!hp.ok) return hp;

  var probe;
  if (hp.scheme === "ntp") {
    probe = await _probeUdp(hp.host, hp.port, timeoutMs);
  } else if (hp.scheme === "rediss" || hp.scheme === "amqps" || hp.scheme === "smtps" ||
             hp.scheme === "https"  || (hp.scheme === "tls" && hp.port === 4222)) {
    probe = await _probeTls(hp.host, hp.port, timeoutMs);
  } else {
    probe = await _probeTcp(hp.host, hp.port, timeoutMs);
  }
  if (!probe.ok) {
    return { ok: false, reason: name + " unreachable at " + hp.host + ":" + hp.port +
      " (" + probe.reason + ")", url: url, host: hp.host, port: hp.port, scheme: hp.scheme };
  }
  return { ok: true, url: url, host: hp.host, port: hp.port, scheme: hp.scheme,
           tlsInfo: probe.info || null };
}

async function requireAll(opts) {
  var names = Object.keys(URLS);
  var results = await Promise.all(names.map(function (n) {
    return requireService(n, opts).then(function (r) { return { name: n, result: r }; });
  }));
  var failed = results.filter(function (r) { return !r.result.ok; });
  if (failed.length === 0) return results.map(function (r) { return r.result; });
  var msg = "services: " + failed.length + " of " + names.length + " unreachable: " +
    failed.map(function (f) { return f.name + " (" + f.result.reason + ")"; }).join("; ") +
    " — bring the stack up with `docker compose -f docker-compose.test.yml up -d --wait`";
  var err = new Error(msg);
  err.code = "BLAMEJS_SERVICES_UNREACHABLE";
  err.failed = failed.map(function (f) { return f.name; });
  throw err;
}

module.exports = {
  URLS:           URLS,
  DEFAULTS:       DEFAULTS,
  CA_CERT_PATH:   CA_CERT_PATH,
  exportCaCert:   exportCaCert,
  requireService: requireService,
  requireAll:     requireAll,
};
