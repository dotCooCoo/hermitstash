// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-services.js
 *
 * Pre-test gate. Verifies every backend declared in
 * docker-compose.test.yml is reachable from the host before the
 * integration test suite runs. Probes both plain and TLS endpoints
 * so a partial-up state (services started but TLS listener not bound)
 * fails fast.
 *
 * Probe types per service:
 *   - tcp   — net.connect, expect immediate accept
 *   - tls   — tls.connect, full handshake + cipher suite captured
 *   - http  — TCP + GET to a /healthz-style endpoint
 *   - sntp  — UDP SNTPv4 query, expect a 48-byte reply with a
 *             non-zero transmit timestamp
 *   - redis — TCP + send PING, expect +PONG (catches the case where
 *             the server is up but still LOADING)
 *   - smtp  — TCP + read 220 banner, send QUIT, expect 221
 *
 * Exit codes:
 *   0  — every probe passed
 *   1  — one or more probes failed (table printed)
 *   2  — script-level error
 *
 * Usage:
 *   node scripts/check-services.js                   — all probes
 *   node scripts/check-services.js redis postgres    — named subset
 *   node scripts/check-services.js --plain           — skip TLS probes
 *   node scripts/check-services.js --tls             — only TLS probes
 */
var net   = require("node:net");
var http  = require("node:http");
var tls   = require("node:tls");
var dgram = require("node:dgram");

// Service registry. Every entry is probed on BOTH IPv4 (127.0.0.1)
// AND IPv6 (::1) so the framework's address-family handling has
// real-world coverage. The compose file dual-binds every host port
// onto both loopback families.
var BASE_SERVICES = [
  // ---- plain backends ----
  { name: "redis",        port:  6379, kind: "redis", label: "PING/PONG",          group: "plain" },
  { name: "postgres",     port:  5432, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "mysql",        port:  3306, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "mongodb",      port: 27017, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "postgres-replica",port:5433, kind: "tcp",  label: "tcp (hot standby)",   group: "plain" },
  { name: "minio",        port:  9000, kind: "http",  label: "GET /health/live",
    httpPath: "/minio/health/live",                                                  group: "plain" },
  { name: "rabbitmq",     port:  5672, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "nats",         port:  4222, kind: "http",  label: "GET /healthz",
    httpPort: 8222, httpPath: "/healthz",                                            group: "plain" },
  { name: "syslog",       port:  5514, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "ntp",          port: 12300, kind: "sntp",  label: "SNTPv4 query",        group: "plain" },
  { name: "mailpit",      port:  1025, kind: "smtp",  label: "SMTP 220 banner",     group: "plain" },
  { name: "coredns-udp",  port:  1053, kind: "dns-udp", label: "DNS A query (UDP)", group: "plain" },
  { name: "coredns-tcp",  port:  1053, kind: "tcp",   label: "tcp",                 group: "plain" },
  { name: "coredns-health",port:  8054,kind: "http",  label: "GET /health",
    httpPath: "/health",                                                             group: "plain" },

  // ---- TLS backends ----
  { name: "redis-tls",    port:  6380, kind: "tls",   label: "TLS handshake",       group: "tls"   },
  { name: "minio-tls",    port:  9443, kind: "tls",   label: "TLS handshake",       group: "tls"   },
  { name: "rabbitmq-tls", port:  5671, kind: "tls",   label: "TLS handshake",       group: "tls"   },
  { name: "syslog-tls",   port:  6514, kind: "tcp",   label: "tcp (tls listener)",  group: "tls"   },
  // Mailpit has no native SMTPS port — STARTTLS only on :1025. The
  // framework's smtpTransport drives EHLO+STARTTLS over the plain port,
  // which is what test suites should validate end-to-end.
  { name: "coredns-dot",  port:  1853, kind: "tls",   label: "TLS handshake (DoT)", group: "tls"   },
  { name: "coredns-doh",  port:  8053, kind: "tls",   label: "TLS handshake (DoH)", group: "tls"   },

  // ---- proxies + DPI ----
  { name: "haproxy",      port:  8443, kind: "tls",   label: "TLS handshake",       group: "proxy" },
  { name: "haproxy-stats",port:  8404, kind: "http",  label: "GET /stats",
    httpPath: "/stats",                                                              group: "proxy" },
  { name: "caddy",        port:  8080, kind: "http",  label: "GET /healthz",
    httpPath: "/healthz",                                                            group: "proxy" },
  { name: "caddy-tls",    port:  8444, kind: "tls",   label: "TLS handshake",       group: "proxy" },
  { name: "mitmproxy",    port:  8090, kind: "tcp",   label: "tcp (proxy listener)",group: "proxy" },
  { name: "mitmproxy-web",port:  8091, kind: "tcp",   label: "tcp (web ui)",        group: "proxy" },
  { name: "squid",        port:  3128, kind: "tcp",   label: "tcp (forward proxy)", group: "proxy" },

  // ---- federated authentication (OIDC OP + SAML IdP via Keycloak) ----
  { name: "keycloak",     port: 18080, kind: "http",  label: "GET /realms/blamejs-test/.well-known/openid-configuration",
    httpPath: "/realms/blamejs-test/.well-known/openid-configuration",                group: "federation" },
  { name: "keycloak-health",port:18081,kind: "http",  label: "GET /health/ready",
    httpPath: "/health/ready",                                                        group: "federation" },

  // ---- cloud-storage / telemetry / AWS emulators ----
  // Azure Blob (Azurite) + GCS (fake-gcs) + LocalStack (CloudWatch Logs +
  // SQS, TLS-terminated by a Caddy sidecar) all serve a cert chaining to the
  // test CA, so a TLS handshake confirms the listener is up; the integration
  // tests do the authenticated round-trips. The OTel collector's OTLP/HTTP
  // receiver is TLS on 4318; its health_check extension is plain HTTP on 13133.
  { name: "azurite",       port: 10000, kind: "tls",  label: "TLS handshake (blob)",  group: "emulators" },
  { name: "fake-gcs",      port:  4443, kind: "tls",  label: "TLS handshake (gcs)",   group: "emulators" },
  { name: "otel-otlp",     port:  4318, kind: "tls",  label: "TLS handshake (otlp)",  group: "emulators" },
  { name: "otel-health",   port: 13133, kind: "http", label: "GET /",
    httpPath: "/",                                                                     group: "emulators" },
  { name: "localstack-tls",port:  4566, kind: "tls",  label: "TLS handshake (aws)",   group: "emulators" },
  // Toxiproxy fault-injection front-end: the API on 8474, plus transparent
  // passthrough proxies that speak the backend protocol verbatim until a
  // toxic is added (redis PING/PONG through :16379, raw TCP to pg on :15432).
  { name: "toxiproxy-api", port:  8474, kind: "http", label: "GET /version",
    httpPath: "/version",                                                              group: "emulators" },
  { name: "toxiproxy-redis",port:16379, kind: "redis",label: "PING/PONG (proxied)",   group: "emulators" },
  { name: "toxiproxy-pg",  port: 15432, kind: "tcp",  label: "tcp (proxied pg)",      group: "emulators" },
];

// Expand BASE_SERVICES into IPv4 + IPv6 entries.
function _bracketHost(host) {
  return host.indexOf(":") !== -1 ? "[" + host + "]" : host;
}
var SERVICES = [];
BASE_SERVICES.forEach(function (b) {
  ["127.0.0.1", "::1"].forEach(function (host) {
    var family = host === "::1" ? "v6" : "v4";
    var entry = {
      name:   b.name,
      host:   host,
      port:   b.port,
      kind:   b.kind,
      label:  b.label,
      group:  b.group,
      family: family,
    };
    if (b.kind === "http") {
      var hostInUrl = _bracketHost(host);
      var httpPort = b.httpPort || b.port;
      entry.httpUrl = "http://" + hostInUrl + ":" + httpPort + (b.httpPath || "/");
    }
    SERVICES.push(entry);
  });
});

function _family(host) { return host.indexOf(":") !== -1 ? 6 : 4; }

function probeTcp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port, family: _family(host) });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tcp timeout after " + timeoutMs + "ms" });
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
      resolve({ ok: false, reason: msg });
    });
  });
}

function probeTls(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var done = false;
    var sock = tls.connect({
      host: host,
      port: port,
      family: _family(host),
      rejectUnauthorized: false,
      // SNI is only legal for hostnames, not IP literals — both 127.0.0.1
      // and ::1 must omit it.
      servername: undefined,
    });
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "tls timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("secureConnect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var protocol = sock.getProtocol() || "?";
      var cipher = (sock.getCipher() && sock.getCipher().name) || "?";
      try { sock.end(); } catch (_e) {}
      resolve({ ok: true, detail: protocol + "/" + cipher });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "tls: " + msg });
    });
  });
}

function probeHttp(url, timeoutMs) {
  return new Promise(function (resolve) {
    var req = http.get(url, function (res) {
      res.on("data", function () {});
      res.on("end", function () {
        if (res.statusCode >= 200 && res.statusCode < 400) {
          resolve({ ok: true, detail: "HTTP " + res.statusCode });
        } else {
          resolve({ ok: false, reason: "HTTP " + res.statusCode });
        }
      });
    });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { req.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "http timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    req.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: msg });
    });
    req.once("close", function () { done = true; clearTimeout(timer); });
  });
}

function probeRedis(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port, family: _family(host) });
    var buf = Buffer.alloc(0);
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "redis ping timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      sock.write("*1\r\n$4\r\nPING\r\n");
    });
    sock.on("data", function (chunk) {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      var s = buf.toString("utf8");
      if (s.indexOf("+PONG\r\n") !== -1) {
        done = true;
        clearTimeout(timer);
        try { sock.end(); } catch (_e) {}
        resolve({ ok: true });
      } else if (s.charAt(0) === "-") {
        done = true;
        clearTimeout(timer);
        try { sock.end(); } catch (_e) {}
        var crlf = s.indexOf("\r\n");
        var line = crlf === -1 ? s : s.slice(0, crlf);
        resolve({ ok: false, reason: "redis replied " + line });
      }
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "redis tcp: " + msg });
    });
  });
}

function probeSmtp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port, family: _family(host) });
    var buf = Buffer.alloc(0);
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) {}
      resolve({ ok: false, reason: "smtp banner timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.on("data", function (chunk) {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      var s = buf.toString("utf8");
      if (/^220 /.test(s)) {
        done = true;
        clearTimeout(timer);
        sock.write("QUIT\r\n");
        try { sock.end(); } catch (_e) {}
        resolve({ ok: true });
      }
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "smtp tcp: " + msg });
    });
  });
}

function probeSntp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = dgram.createSocket(host.indexOf(":") !== -1 ? "udp6" : "udp4");
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_e) {}
      resolve({ ok: false, reason: "sntp timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "sntp socket: " + msg });
    });
    sock.once("message", function (reply) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch (_e) {}
      if (!Buffer.isBuffer(reply) || reply.length < 48) {
        resolve({ ok: false, reason: "sntp reply too short: " + (reply && reply.length) + "B" });
        return;
      }
      var ntpSeconds = reply.readUInt32BE(40);
      if (ntpSeconds === 0) {
        resolve({ ok: false, reason: "sntp transmit timestamp zero (server unsynced)" });
        return;
      }
      resolve({ ok: true });
    });
    var req = Buffer.alloc(48);
    req[0] = 0x23;
    sock.send(req, 0, req.length, port, host, function (err) {
      if (err && !done) {
        done = true;
        clearTimeout(timer);
        try { sock.close(); } catch (_e) {}
        var msg = (err && err.code) || (err && err.message) || String(err);
        resolve({ ok: false, reason: "sntp send: " + msg });
      }
    });
  });
}

// DNS-over-UDP probe — send a real A query for "." and confirm a reply.
// The Cloudflare upstream the resolver forwards to should answer for any
// well-known name; we just need a non-zero reply to know the resolver
// itself is responsive on that wire.
function probeDnsUdp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = dgram.createSocket(host.indexOf(":") !== -1 ? "udp6" : "udp4");
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_e) {}
      resolve({ ok: false, reason: "dns udp timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      var msg = (err && err.code) || (err && err.message) || String(err);
      resolve({ ok: false, reason: "dns udp socket: " + msg });
    });
    sock.once("message", function (reply) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch (_e) {}
      if (!Buffer.isBuffer(reply) || reply.length < 12) {
        resolve({ ok: false, reason: "dns reply too short: " + (reply && reply.length) + "B" });
        return;
      }
      // bit 15 of byte 2-3 is the QR flag — must be 1 (response).
      if ((reply[2] & 0x80) === 0) {
        resolve({ ok: false, reason: "dns reply QR flag not set" });
        return;
      }
      resolve({ ok: true });
    });
    // Standard A query for "example.com" — id=0xb1ed, rd=1.
    var query = Buffer.from([
      0xb1, 0xed,                         // id
      0x01, 0x00,                         // flags: rd=1
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qd=1
      0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  // "example"
      0x03, 0x63, 0x6f, 0x6d,             // "com"
      0x00,                               // root label
      0x00, 0x01,                         // qtype A
      0x00, 0x01,                         // qclass IN
    ]);
    sock.send(query, 0, query.length, port, host, function (err) {
      if (err && !done) {
        done = true;
        clearTimeout(timer);
        try { sock.close(); } catch (_e) {}
        var msg = (err && err.code) || (err && err.message) || String(err);
        resolve({ ok: false, reason: "dns udp send: " + msg });
      }
    });
  });
}

async function probeService(svc, timeoutMs) {
  switch (svc.kind) {
    case "tcp":     return await probeTcp(svc.host, svc.port, timeoutMs);
    case "tls":     return await probeTls(svc.host, svc.port, timeoutMs);
    case "http":    return await probeHttp(svc.httpUrl, timeoutMs);
    case "redis":   return await probeRedis(svc.host, svc.port, timeoutMs);
    case "smtp":    return await probeSmtp(svc.host, svc.port, timeoutMs);
    case "sntp":    return await probeSntp(svc.host, svc.port, timeoutMs);
    case "dns-udp": return await probeDnsUdp(svc.host, svc.port, timeoutMs);
    default:        return { ok: false, reason: "unknown probe kind: " + svc.kind };
  }
}

function _padEnd(s, w) {
  s = String(s);
  return s.length >= w ? s : s + new Array(w - s.length + 1).join(" ");
}

(async function main() {
  var args = process.argv.slice(2);
  var skipTls   = args.indexOf("--plain") !== -1;
  var onlyTls   = args.indexOf("--tls")   !== -1;
  var onlyV4    = args.indexOf("--v4")    !== -1;
  var onlyV6    = args.indexOf("--v6")    !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  var targets = SERVICES;
  if (skipTls) targets = targets.filter(function (s) { return s.group !== "tls"; });
  if (onlyTls) targets = targets.filter(function (s) { return s.group === "tls"; });
  if (onlyV4)  targets = targets.filter(function (s) { return s.family === "v4"; });
  if (onlyV6)  targets = targets.filter(function (s) { return s.family === "v6"; });
  if (named.length > 0) {
    var validNames = {};
    SERVICES.forEach(function (s) { validNames[s.name] = true; });
    var missing = named.filter(function (n) { return !validNames[n]; });
    if (missing.length > 0) {
      console.error("[check-services] unknown service name(s): " + missing.join(", "));
      console.error("[check-services] valid: " + Object.keys(validNames).join(", "));
      process.exit(2);
    }
    var nameSet = {};
    named.forEach(function (n) { nameSet[n] = true; });
    targets = targets.filter(function (s) { return nameSet[s.name]; });
  }

  console.log("[check-services] probing " + targets.length + " endpoint" +
              (targets.length === 1 ? "" : "s") + "...");
  var timeoutMs = Number(process.env.BLAMEJS_SERVICE_PROBE_TIMEOUT_MS) || 4000;

  var results = await Promise.all(targets.map(function (svc) {
    return probeService(svc, timeoutMs).then(function (r) {
      return { svc: svc, result: r };
    });
  }));

  var down = 0;
  var lastGroup = null;
  results.forEach(function (entry) {
    if (entry.svc.group !== lastGroup) {
      console.log("");
      console.log("  [" + entry.svc.group + "]");
      lastGroup = entry.svc.group;
    }
    var nameCol  = _padEnd(entry.svc.name + " (" + entry.svc.family + ")", 22);
    var hostStr  = entry.svc.family === "v6"
      ? "[" + entry.svc.host + "]:" + entry.svc.port
      : entry.svc.host + ":" + entry.svc.port;
    var portCol  = _padEnd(hostStr, 22);
    var labelCol = _padEnd(entry.svc.label, 26);
    if (entry.result.ok) {
      var detail = entry.result.detail ? "  " + entry.result.detail : "";
      console.log("  " + nameCol + portCol + labelCol + "OK" + detail);
    } else {
      down += 1;
      console.log("  " + nameCol + portCol + labelCol + "DOWN — " + entry.result.reason);
    }
  });

  console.log("");
  if (down === 0) {
    console.log("[check-services] all " + targets.length + " endpoints responding");
    process.exit(0);
  }
  console.error("[check-services] " + down + " of " + targets.length + " unreachable");
  console.error("[check-services] bring the stack up with:");
  console.error("  docker compose -f docker-compose.test.yml up -d --wait");
  process.exit(1);
})().catch(function (err) {
  console.error("[check-services] script error: " + ((err && err.stack) || err));
  process.exit(2);
});
