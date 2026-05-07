"use strict";
/**
 * Live DNS round-trip against the docker-compose CoreDNS fixture.
 * Exercises all three resolution modes — plain UDP/TCP, DoT (port 1853),
 * DoH (port 8053) — with strict TLS verification against the test CA.
 *
 * No security bypass: rejectUnauthorized stays on, the test exports the
 * pki-init CA out of the docker volume and passes it via the framework's
 * `ca` option on useDnsOverTls / useDnsOverHttps. A failure to verify
 * surfaces as a DnsError on the lookup, NOT an unhandled rejection.
 */
var fs = require("node:fs");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var svc = await services.requireService("dns");
  if (!svc.ok) throw new Error("coredns unreachable: " + svc.reason);

  var dns = (b.network && b.network.dns) || b.networkDns;
  if (!dns) throw new Error("framework does not expose b.network.dns");

  // Pull the test CA out of the docker volume so we can pin against it.
  var caPath = await services.exportCaCert();
  var caPem = fs.readFileSync(caPath, "utf8");
  check("CA cert exported from docker volume",
        caPem.indexOf("-----BEGIN CERTIFICATE-----") === 0);

  // ---- baseline: lookup against system resolvers works ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.setLookupTimeoutMs(4000);
  var sys = await dns.lookup("example.com");
  check("baseline lookup: returns object",     typeof sys === "object" && sys !== null);
  check("baseline lookup: address non-empty",  typeof sys.address === "string" && sys.address.length > 0);
  check("baseline lookup: family is 4 or 6",   sys.family === 4 || sys.family === 6);

  // ---- DoT against our CoreDNS, pinned to test CA ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.useDnsOverTls({
    host:       "127.0.0.1",
    port:       1853,
    servername: "coredns",
    ca:         caPem,
  });
  dns.setLookupTimeoutMs(5000);

  var dotResults = await dns.resolve4("example.com");
  check("DoT: resolve4 returned array",
        Array.isArray(dotResults));
  check("DoT: resolve4 returned at least one address",
        dotResults.length > 0);
  check("DoT: every address is dotted-quad IPv4",
        dotResults.every(function (a) { return /^\d+\.\d+\.\d+\.\d+$/.test(a); }));

  // ---- DoT IPv6 (AAAA) ----
  var dotV6 = await dns.resolveAaaa("example.com");
  check("DoT: resolveAaaa returned array (may be empty for some names)",
        Array.isArray(dotV6));

  // ---- DoT: bad servername surfaces as DnsError, not unhandled rejection ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.useDnsOverTls({
    host:       "127.0.0.1",
    port:       1853,
    servername: "wrong-name-not-in-cert",
    ca:         caPem,
  });
  dns.setLookupTimeoutMs(5000);
  var threwBad = null;
  try { await dns.resolve4("example.com"); }
  catch (e) { threwBad = e; }
  check("DoT: bad servername throws DnsError",
        threwBad && threwBad.code && /handshake|tls|verify|hostname/i.test(threwBad.code + " " + threwBad.message));

  // ---- DoH against our CoreDNS, pinned to test CA ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.useDnsOverHttps({
    url:    "https://localhost:8053/dns-query",
    method: "POST",
    ca:     caPem,
  });
  dns.setLookupTimeoutMs(5000);

  var dohResults = await dns.resolve4("example.com");
  check("DoH: resolve4 returned non-empty array",
        Array.isArray(dohResults) && dohResults.length > 0);
  check("DoH: every address is dotted-quad IPv4",
        dohResults.every(function (a) { return /^\d+\.\d+\.\d+\.\d+$/.test(a); }));

  // ---- DoH GET path (under URL length cap) ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.useDnsOverHttps({
    url:    "https://localhost:8053/dns-query",
    method: "GET",
    ca:     caPem,
  });
  dns.setLookupTimeoutMs(5000);
  var dohGet = await dns.resolve4("example.com");
  check("DoH GET: resolve4 returned non-empty array",
        Array.isArray(dohGet) && dohGet.length > 0);

  // ---- cache: second lookup hits the cache ----
  if (typeof dns._resetForTest === "function") dns._resetForTest();
  dns.setLookupTimeoutMs(4000);
  dns.setCacheTtlMs(60000);
  var first = await dns.lookup("example.com");
  var second = await dns.lookup("example.com");
  check("cache: second lookup returns same address",
        first.address === second.address);

  if (typeof dns._resetForTest === "function") dns._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
