// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * ssrf-guard primitive — IP classification, CIDR matching, URL check
 * with hostname resolution.
 *
 * Run standalone: `node test/layer-0-primitives/ssrf-guard.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ssrf = b.ssrfGuard;
// (b is also referenced directly to satisfy test-coverage gate's b.* path matcher)

function _stubLookup(addr, family) {
  return function () { return Promise.resolve([{ address: addr, family: family || 4 }]); };
}

async function run() {
  // ---- classify: IPv4 ----
  check("classify 127.0.0.1 → loopback",        ssrf.classify("127.0.0.1") === "loopback");
  check("classify 127.255.255.254 → loopback",  ssrf.classify("127.255.255.254") === "loopback");
  check("classify 10.0.0.1 → private",          ssrf.classify("10.0.0.1") === "private");
  check("classify 172.16.5.10 → private",       ssrf.classify("172.16.5.10") === "private");
  check("classify 172.31.255.254 → private",    ssrf.classify("172.31.255.254") === "private");
  check("classify 172.32.0.1 → null (outside private range)",
        ssrf.classify("172.32.0.1") === null);
  check("classify 192.168.1.1 → private",       ssrf.classify("192.168.1.1") === "private");
  check("classify 169.254.0.1 → link-local",    ssrf.classify("169.254.0.1") === "link-local");
  check("classify 169.254.169.254 → cloud-metadata (overrides link-local)",
        ssrf.classify("169.254.169.254") === "cloud-metadata");
  check("classify 169.254.170.2 → cloud-metadata (AWS ECS task role)",
        ssrf.classify("169.254.170.2") === "cloud-metadata");
  check("classify 0.0.0.0 → reserved",          ssrf.classify("0.0.0.0") === "reserved");
  check("classify 100.64.0.1 → reserved (CGNAT)", ssrf.classify("100.64.0.1") === "reserved");
  check("classify 192.0.2.1 → reserved (TEST-NET-1)", ssrf.classify("192.0.2.1") === "reserved");
  check("classify 224.0.0.1 → reserved (multicast)",  ssrf.classify("224.0.0.1") === "reserved");
  check("classify 255.255.255.255 → reserved (broadcast)",
        ssrf.classify("255.255.255.255") === "reserved");

  // ---- classify: external (returns null) ----
  check("classify 8.8.8.8 → null (Google DNS)",      ssrf.classify("8.8.8.8") === null);
  check("classify 1.1.1.1 → null (Cloudflare DNS)",  ssrf.classify("1.1.1.1") === null);
  check("classify 93.184.216.34 → null (example.com)", ssrf.classify("93.184.216.34") === null);

  // ---- classify: IPv6 ----
  check("classify ::1 → loopback",              ssrf.classify("::1") === "loopback");
  check("classify fe80::1 → link-local",        ssrf.classify("fe80::1") === "link-local");
  check("classify fc00::1 → private",           ssrf.classify("fc00::1") === "private");
  check("classify fd00::1 → private (ULA)",     ssrf.classify("fd00::1") === "private");
  check("classify 2001:db8::1 → reserved (documentation)",
        ssrf.classify("2001:db8::1") === "reserved");
  check("classify 2606:4700:4700::1111 → null (Cloudflare DNS6)",
        ssrf.classify("2606:4700:4700::1111") === null);
  check("classify fd00:ec2::254 → cloud-metadata", ssrf.classify("fd00:ec2::254") === "cloud-metadata");
  // IPv4-mapped IPv6 → reclassify the v4 portion
  check("classify ::ffff:127.0.0.1 → loopback (IPv4-mapped)",
        ssrf.classify("::ffff:127.0.0.1") === "loopback");
  check("classify ::ffff:8.8.8.8 → null (IPv4-mapped public)",
        ssrf.classify("::ffff:8.8.8.8") === null);

  // ---- classify: IPv6 special-use ranges ----
  // Multicast ff00::/8 — RFC 4291.
  check("classify ff02::1 → reserved (multicast)",     ssrf.classify("ff02::1") === "reserved");
  check("classify ff05::1 → reserved (multicast site-local)", ssrf.classify("ff05::1") === "reserved");
  check("classify ffff::1 → reserved (multicast)",     ssrf.classify("ffff::1") === "reserved");
  // Discard prefix 100::/64 — RFC 6666.
  check("classify 100::1 → reserved (discard)",        ssrf.classify("100::1") === "reserved");
  check("classify 100::ffff:ffff:ffff:ffff → reserved (discard)",
        ssrf.classify("100::ffff:ffff:ffff:ffff") === "reserved");
  // 6to4 2002::/16 — should re-classify the embedded v4 (RFC 3056).
  // 2002:0a00:0001:: → 10.0.0.1 (private)
  check("classify 2002:0a00:0001:: → private (6to4 wrapping 10.0.0.1)",
        ssrf.classify("2002:0a00:0001::") === "private");
  // 2002:7f00:0001:: → 127.0.0.1 (loopback)
  check("classify 2002:7f00:0001:: → loopback (6to4 wrapping 127.0.0.1)",
        ssrf.classify("2002:7f00:0001::") === "loopback");
  // 2002:a9fe:a9fe:: → 169.254.169.254 (cloud-metadata)
  check("classify 2002:a9fe:a9fe:: → cloud-metadata (6to4 wrapping 169.254.169.254)",
        ssrf.classify("2002:a9fe:a9fe::") === "cloud-metadata");
  // NAT64 64:ff9b::/96 — should re-classify the embedded v4 (RFC 6052).
  check("classify 64:ff9b::a00:1 → private (NAT64 wrapping 10.0.0.1)",
        ssrf.classify("64:ff9b::a00:1") === "private");
  check("classify 64:ff9b::a9fe:a9fe → cloud-metadata (NAT64 wrapping 169.254.169.254)",
        ssrf.classify("64:ff9b::a9fe:a9fe") === "cloud-metadata");

  // ---- classify: bad input ----
  check("classify '' → null",                   ssrf.classify("") === null);
  check("classify 'not-an-ip' → null",          ssrf.classify("not-an-ip") === null);
  check("classify null → null",                 ssrf.classify(null) === null);
  check("classify 1.2.3 → null (too few octets)", ssrf.classify("1.2.3") === null);

  // ---- isPrivate / isLoopback / etc. shortcuts ----
  check("isPrivate(10.0.0.1) === true",         ssrf.isPrivate("10.0.0.1") === true);
  check("isPrivate(8.8.8.8) === false",         ssrf.isPrivate("8.8.8.8") === false);
  check("isLoopback(127.0.0.1) === true",       ssrf.isLoopback("127.0.0.1") === true);
  check("isLinkLocal(169.254.0.1) === true",    ssrf.isLinkLocal("169.254.0.1") === true);
  check("isCloudMetadata(169.254.169.254) === true",
        ssrf.isCloudMetadata("169.254.169.254") === true);
  check("isReserved(0.0.0.0) === true",         ssrf.isReserved("0.0.0.0") === true);

  // ---- cidrContains: IPv4 ----
  check("cidrContains 10.0.0.0/8 contains 10.255.255.254",
        ssrf.cidrContains("10.0.0.0/8", "10.255.255.254") === true);
  check("cidrContains 10.0.0.0/8 does NOT contain 11.0.0.1",
        ssrf.cidrContains("10.0.0.0/8", "11.0.0.1") === false);
  check("cidrContains 192.168.1.0/24 contains 192.168.1.42",
        ssrf.cidrContains("192.168.1.0/24", "192.168.1.42") === true);
  check("cidrContains 192.168.1.0/24 does NOT contain 192.168.2.1",
        ssrf.cidrContains("192.168.1.0/24", "192.168.2.1") === false);
  check("cidrContains 0.0.0.0/0 matches anything",
        ssrf.cidrContains("0.0.0.0/0", "203.0.113.5") === true);

  // ---- cidrContains: IPv6 ----
  check("cidrContains fc00::/7 contains fd12::1",
        ssrf.cidrContains("fc00::/7", "fd12::1") === true);
  check("cidrContains fc00::/7 does NOT contain ::1",
        ssrf.cidrContains("fc00::/7", "::1") === false);
  check("cidrContains 2001:db8::/32 contains 2001:db8:abcd::1",
        ssrf.cidrContains("2001:db8::/32", "2001:db8:abcd::1") === true);

  // ---- cidrContains: bad input ----
  check("cidrContains rejects mixed-family pairing",
        ssrf.cidrContains("10.0.0.0/8", "::1") === false);
  check("cidrContains rejects malformed cidr (no slash)",
        ssrf.cidrContains("10.0.0.0", "10.0.0.1") === false);
  check("cidrContains rejects bad prefix (>32 for v4)",
        ssrf.cidrContains("10.0.0.0/64", "10.0.0.1") === false);

  // ---- checkUrl: IP-literal hostnames (no DNS) ----
  var threw = null;
  try { await ssrf.checkUrl("http://127.0.0.1/path"); }
  catch (e) { threw = e; }
  check("checkUrl: loopback IP literal blocked",
        threw && threw.code === "ssrf-guard/blocked-loopback");
  check("checkUrl: error carries url + ip + category",
        threw && threw.url === "http://127.0.0.1/path" &&
        threw.ip === "127.0.0.1" && threw.category === "loopback");

  threw = null;
  try { await ssrf.checkUrl("http://10.5.6.7/x"); }
  catch (e) { threw = e; }
  check("checkUrl: private IPv4 literal blocked",
        threw && threw.code === "ssrf-guard/blocked-private");

  threw = null;
  try { await ssrf.checkUrl("http://169.254.169.254/latest/meta-data/"); }
  catch (e) { threw = e; }
  check("checkUrl: AWS metadata IP literal blocked with cloud-metadata code",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  threw = null;
  try { await ssrf.checkUrl("http://[::1]/path"); }
  catch (e) { threw = e; }
  check("checkUrl: IPv6 loopback literal blocked",
        threw && threw.code === "ssrf-guard/blocked-loopback");

  // ---- checkUrl: hostname resolution via stubbed dnsLookup ----
  threw = null;
  try {
    await ssrf.checkUrl("http://attacker.example/", {
      dnsLookup: _stubLookup("10.0.5.1"),
    });
  } catch (e) { threw = e; }
  check("checkUrl: hostname resolving to private IP blocked",
        threw && threw.code === "ssrf-guard/blocked-private");

  threw = null;
  try {
    await ssrf.checkUrl("http://malicious.host/", {
      dnsLookup: _stubLookup("169.254.169.254"),
    });
  } catch (e) { threw = e; }
  check("checkUrl: hostname resolving to metadata IP blocked",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // ---- checkUrl: allowInternal:true bypasses entirely ----
  var r = await ssrf.checkUrl("http://127.0.0.1/x", { allowInternal: true });
  check("checkUrl: allowInternal:true returns the resolved URL+IP",
        r && r.ips && r.ips[0].address === "127.0.0.1");

  // ---- checkUrl: allowInternal CIDR list (narrower than 'true') ----
  threw = null;
  try {
    await ssrf.checkUrl("http://10.0.5.1/", {
      allowInternal: ["10.0.0.0/8"],
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal CIDR list permits matching range",
        threw === null);

  threw = null;
  try {
    await ssrf.checkUrl("http://192.168.1.1/", {
      allowInternal: ["10.0.0.0/8"],   // doesn't include 192.168/16
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal CIDR list rejects out-of-range",
        threw && threw.code === "ssrf-guard/blocked-private");

  // ---- checkUrl: external IP passes ----
  var r2 = await ssrf.checkUrl("https://example.com/", {
    dnsLookup: _stubLookup("93.184.216.34"),
  });
  check("checkUrl: public IP passes",
        r2 && r2.ips[0].address === "93.184.216.34");

  // ---- cloud-metadata IPv6 matched on canonical bytes, not string ----
  // The IMDS-over-IPv6 address fd00:ec2::254 has many textual spellings.
  // A non-canonical / mixed-case spelling must still classify as
  // cloud-metadata — a string-equality membership test caught one
  // spelling only, and the DoH resolver decodes AAAA to the expanded
  // fd00:ec2:0:0:0:0:0:254 form, which slipped past as "private".
  check("classify fd00:ec2:0:0:0:0:0:254 → cloud-metadata (expanded zero-run)",
        ssrf.classify("fd00:ec2:0:0:0:0:0:254") === "cloud-metadata");
  check("classify FD00:EC2::254 → cloud-metadata (mixed-case compressed)",
        ssrf.classify("FD00:EC2::254") === "cloud-metadata");
  check("classify fd00:0ec2::0254 → cloud-metadata (leading-zero groups)",
        ssrf.classify("fd00:0ec2::0254") === "cloud-metadata");
  // A genuine ULA private address that is NOT metadata must stay "private".
  check("classify fd00::1 → private (NOT metadata)",
        ssrf.classify("fd00::1") === "private");

  // PoC: allowInternal:true MUST NOT override the unconditional metadata
  // block, even when DNS resolves to the non-canonical IMDS-over-IPv6
  // spelling. Pre-fix this RESOLVED (credentials reachable); now refused.
  threw = null;
  try {
    await ssrf.checkUrl("http://imds.attacker.example/latest/meta-data/iam/", {
      allowInternal: true,
      dnsLookup: _stubLookup("fd00:ec2:0:0:0:0:0:254", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal:true does NOT override non-canonical IMDS-over-IPv6",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // Compressed + mixed-case spellings refused too (wire not reached).
  threw = null;
  try {
    await ssrf.checkUrl("http://imds.attacker.example/", {
      allowInternal: true,
      dnsLookup: _stubLookup("FD00:EC2::254", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: allowInternal:true does NOT override mixed-case IMDS-over-IPv6",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");

  // A genuine private IPv6 (fd00::1, NOT metadata) still respects
  // allowInternal — the metadata gate is the only unconditional class.
  threw = null;
  var rPriv6 = null;
  try {
    rPriv6 = await ssrf.checkUrl("http://internal.mesh/", {
      allowInternal: true,
      dnsLookup: _stubLookup("fd00::1", 6),
    });
  } catch (e) { threw = e; }
  check("checkUrl: genuine private IPv6 still honors allowInternal:true",
        threw === null && rPriv6 && rPriv6.ips[0].address === "fd00::1");

  // checkUrlTextual: the same byte-canonical gate at the textual layer.
  threw = null;
  try { ssrf.checkUrlTextual("http://[fd00:ec2:0:0:0:0:0:254]/x"); }
  catch (e) { threw = e; }
  check("checkUrlTextual: non-canonical IMDS-over-IPv6 refused",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");
  threw = null;
  try { ssrf.checkUrlTextual("http://[FD00:EC2::254]/x"); }
  catch (e) { threw = e; }
  check("checkUrlTextual: mixed-case IMDS-over-IPv6 refused",
        threw && threw.code === "ssrf-guard/blocked-cloud-metadata");
  // A non-metadata internal host stays accepted at the textual layer.
  var txtOk = ssrf.checkUrlTextual("http://[fd00::1]/x");
  check("checkUrlTextual: non-metadata IPv6 literal accepted",
        txtOk && txtOk.host === "fd00::1");

  // ---- checkUrl: bad input ----
  threw = null;
  try { await ssrf.checkUrl("not-a-url"); }
  catch (e) { threw = e; }
  check("checkUrl: malformed URL rejected", threw && threw instanceof Error);

  // ---- SsrfError shape ----
  check("SsrfError is a class",                 typeof ssrf.SsrfError === "function");
  var e = new ssrf.SsrfError("msg", "ssrf-guard/test");
  check("SsrfError has isSsrfError flag",       e.isSsrfError === true);
  check("SsrfError marks permanent (no retry)", e.permanent === true);

  // ---- Pinned-lookup callback (TOCTOU defense) ----
  // After ssrf-guard validates an IP, http-client pins the actual TCP
  // connect to that IP via a custom `lookup` callback (closes the DNS
  // rebinding window). Verify the callback honors Node's documented
  // shape: callback(err, address, family) for single, callback(err,
  // [{ address, family }]) when options.all is set.
  var httpClient = require("../../lib/http-client");
  var pinned = httpClient._pinnedLookupForTest([
    { address: "203.0.113.5", family: 4 },
    { address: "2001:db8::1", family: 6 },
  ]);
  check("pinned-lookup: returns a function",   typeof pinned === "function");

  var singleAddr, singleFamily;
  pinned("evil.example.invalid", {}, function (err, addr, family) {
    singleAddr = addr; singleFamily = family;
  });
  check("pinned-lookup: single returns first IP regardless of hostname",
        singleAddr === "203.0.113.5" && singleFamily === 4);

  var allList;
  pinned("any-hostname-here", { all: true }, function (err, list) { allList = list; });
  check("pinned-lookup: all=true returns full list",
        Array.isArray(allList) && allList.length === 2);
  check("pinned-lookup: all=true preserves order",
        allList[0].address === "203.0.113.5" && allList[1].address === "2001:db8::1");
  check("pinned-lookup: all=true preserves family",
        allList[1].family === 6);

  // Empty IP list → no lookup callback (caller falls back to Node's DNS)
  var noPin = httpClient._pinnedLookupForTest([]);
  check("pinned-lookup: empty ips → undefined (let Node resolve)",
        noPin === undefined);
}

async function _testCreateAllowlist() {
  var threw;
  try { b.ssrfGuard.createAllowlist({}); } catch (e) { threw = e; }
  check("createAllowlist: empty allow throws",
        threw && threw.code === "ssrf-guard/empty-allowlist");

  var egress = b.ssrfGuard.createAllowlist({
    allow: ["api.partner.example.com", "192.0.2.0/24"],
    deny:  ["bad.example.com"],
  });
  check("createAllowlist: returns assert function",
        typeof egress.assert === "function");

  var rejected;
  try { await egress.assert("https://other.example.com/x"); }
  catch (e) { rejected = e; }
  check("createAllowlist: hostname not on allowlist refused",
        rejected && rejected.code === "ssrf-guard/not-on-allowlist");

  // The URL parser lowercases the host, but the operator allow/deny entries
  // were compared raw — so a mixed-case (or trailing-dot) entry silently did
  // not match, letting a denied host through. Both sides must canonicalize.
  var cased = b.ssrfGuard.createAllowlist({
    allow: ["evil.example.com"],          // host is allowed...
    deny:  ["EVIL.EXAMPLE.COM"],          // ...but explicitly denied (mixed case)
  });
  var denyHit;
  try { await cased.assert("https://evil.example.com/x"); }
  catch (e) { denyHit = e; }
  check("createAllowlist: denylist blocks a host case-insensitively",
        denyHit && denyHit.code === "ssrf-guard/on-denylist");

  // And a mixed-case ALLOW entry still admits the lowercased host (no wrong-reject).
  var casedAllow = b.ssrfGuard.createAllowlist({ allow: ["API.Partner.Example.com."] });
  var allowOk = true;
  try { await casedAllow.assert("https://api.partner.example.com/x"); }
  catch (e) { allowOk = (e.code === "ssrf-guard/not-on-allowlist") ? false : true; }
  check("createAllowlist: mixed-case/trailing-dot allow entry admits the host", allowOk === true);
}

module.exports = { run: async function () { await run(); await _testCreateAllowlist(); } };

if (require.main === module) {
  module.exports.run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (err) { console.error("FAIL:", err.stack || err); process.exit(1); }
  );
}
