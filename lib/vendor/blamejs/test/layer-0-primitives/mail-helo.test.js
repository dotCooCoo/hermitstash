"use strict";
/**
 * b.mail.helo — RFC 5321 §4.1.1.1 HELO/EHLO validation + RFC 8601
 * §2.7.6 FCrDNS verifier. Uses a fake resolver so no real DNS leaves
 * the box.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeResolver(map) {
  return {
    query: function (name, type) {
      var key = name + "|" + type;
      if (map[key] === "__nx__") {
        var e = new Error("NXDOMAIN");
        e.code = "resolver/nxdomain-or-error";
        return Promise.reject(e);
      }
      return map[key] ? Promise.resolve(map[key]) : Promise.reject(_nx());
    },
    queryA:   function (n) { return this.query(n, "A"); },
    queryAaaa: function (n) { return this.query(n, "AAAA"); },
    queryPtr: function (n) { return this.query(n, "PTR"); },
  };
}

function _nx() {
  var e = new Error("NXDOMAIN");
  e.code = "resolver/nxdomain-or-error";
  return e;
}

function _aRr(decoded) { return { rrs: [{ type: 1, typeName: "A", decoded: decoded, ttl: 300 }] }; }
function _ptrRr(decoded) { return { rrs: [{ type: 12, typeName: "PTR", decoded: decoded, ttl: 300 }] }; }
function _aaaaRr(decoded) { return { rrs: [{ type: 28, typeName: "AAAA", decoded: decoded, ttl: 300 }] }; }

function testSurface() {
  check("evaluate is fn",          typeof b.mail.helo.evaluate === "function");
  check("compliancePosture is fn", typeof b.mail.helo.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.mail.helo.PROFILES));
  check("GENERIC_RDNS_PATTERNS",   Array.isArray(b.mail.helo.GENERIC_RDNS_PATTERNS));
  check("MailHeloError is fn",     typeof b.mail.helo.MailHeloError === "function");
}

async function testAcceptsValidFqdn() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "mail.example.com",
  });
  check("FQDN accept",              v.action === "accept");
  check("FQDN shape",               v.shape === "domain");
}

async function testRejectsLocalhostClaim() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "localhost",
  });
  check("localhost reject",         v.action === "reject-shape");
  check("localhost reason",         v.reason.indexOf("localhost") !== -1);
}

async function testRejectsBareHost() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "barehost",
  });
  check("bare host reject",         v.action === "reject-shape");
  check("bare host shape",          v.shape === "bare-host");
}

async function testAcceptsAddressLiteralV4Match() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "[203.0.113.42]",
  });
  check("addr-lit v4 match accept", v.action === "accept");
  check("addr-lit v4 shape",        v.shape === "address-literal-v4");
}

async function testRefusesAddressLiteralV4Mismatch() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "[198.51.100.99]",
  });
  check("addr-lit v4 mismatch",     v.action === "literal-mismatch");
}

async function testAcceptsAddressLiteralV6Match() {
  var v = await b.mail.helo.evaluate({
    ip:          "2001:db8::1",
    claimedName: "[IPv6:2001:db8::1]",
  });
  check("addr-lit v6 match accept", v.action === "accept");
  check("addr-lit v6 shape",        v.shape === "address-literal-v6");
}

async function testAddrLitV6CompressedExpandedEquivalent() {
  // [IPv6:2001:0db8:0000:0000:0000:0000:0000:0001] should match
  // a connection IP of 2001:db8::1 (RFC 5952 canonical form).
  var v = await b.mail.helo.evaluate({
    ip:          "2001:db8::1",
    claimedName: "[IPv6:2001:0db8:0000:0000:0000:0000:0000:0001]",
  });
  check("addr-lit v6 expanded == compressed", v.action === "accept");
}

async function testRefusesSelfNameClaim() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "our-mx.example.com",
  }, { selfNames: ["our-mx.example.com"] });
  check("self-name claim refused",  v.action === "match-self-refused");
}

async function testRefusesNonLdhLabel() {
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "bad_label.example.com",
  });
  check("non-LDH refused",          v.action === "reject-shape");
  check("non-LDH shape=invalid",    v.shape === "invalid");
}

async function testRefusesOversize() {
  var long = "a".repeat(300);
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: long,
  });
  check("oversize refused",         v.action === "reject-shape");
}

async function testFcrdnsPasses() {
  var resolver = _fakeResolver({
    "42.113.0.203.in-addr.arpa|PTR": _ptrRr("mail.example.com"),
    "mail.example.com|A":            _aRr("203.0.113.42"),
  });
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "mail.example.com",
    resolver:    resolver,
  });
  check("fcrdns passes",            v.action === "accept");
  check("fcrdns.passed=true",        v.fcrdns.passed === true);
  check("fcrdns matched IP",         v.fcrdns.matchedIp === "203.0.113.42");
}

async function testFcrdnsSoftFails() {
  var resolver = _fakeResolver({
    "42.113.0.203.in-addr.arpa|PTR": _ptrRr("rogue.example.com"),
    "rogue.example.com|A":           _aRr("198.51.100.99"),
  });
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "mail.example.com",
    resolver:    resolver,
  });
  check("fcrdns soft-fails",         v.action === "soft-fail-fcrdns");
  check("fcrdns.passed=false",        v.fcrdns.passed === false);
}

async function testFcrdnsNxRevDns() {
  var resolver = _fakeResolver({
    "42.113.0.203.in-addr.arpa|PTR": "__nx__",
  });
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "mail.example.com",
    resolver:    resolver,
  });
  check("fcrdns NX → soft-fail",     v.action === "soft-fail-fcrdns");
  check("fcrdns.rdnsNames empty",     v.fcrdns.rdnsNames.length === 0);
}

async function testFcrdnsIpv6() {
  // Expanded: 2001:0db8:0000:0000:0000:0000:0000:0001
  // ip6.arpa reverse: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
  var ptrName = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
  var map = {};
  map[ptrName + "|PTR"] = _ptrRr("v6.example.com");
  map["v6.example.com|AAAA"] = _aaaaRr("2001:db8::1");
  var resolver = _fakeResolver(map);
  var v = await b.mail.helo.evaluate({
    ip:          "2001:db8::1",
    claimedName: "v6.example.com",
    resolver:    resolver,
  });
  check("ipv6 fcrdns passes",       v.action === "accept");
}

async function testFcrdnsSkippedForV6OnBalanced() {
  // Balanced profile: fcrdnsRequiredFor = ["v4"]; an IPv6 connection
  // skips the FCrDNS gate and accepts on shape alone.
  var resolver = _fakeResolver({});  // would NX everything
  var v = await b.mail.helo.evaluate({
    ip:          "2001:db8::1",
    claimedName: "v6.example.com",
    resolver:    resolver,
  }, { profile: "balanced" });
  check("balanced v6 skips FCrDNS",  v.action === "accept");
  check("balanced v6 fcrdns null",    v.fcrdns === null);
}

async function testGenericRdnsFlag() {
  var resolver = _fakeResolver({
    "42.113.0.203.in-addr.arpa|PTR": _ptrRr("pool-203-0-113-42.dynamic.example.com"),
    "pool-203-0-113-42.dynamic.example.com|A": _aRr("203.0.113.42"),
  });
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "mail.example.com",
    resolver:    resolver,
  });
  check("generic rdns flagged",     v.genericRdns === true);
}

async function testRefusesReDoSGenericRdnsPattern() {
  // A nested-quantifier (catastrophic-backtracking) operator pattern is
  // screened at evaluate() build time — refused before any match runs.
  // Input kept short/harmless so the test never actually backtracks.
  var threw = null;
  try {
    await b.mail.helo.evaluate({
      ip:          "203.0.113.42",
      claimedName: "mail.example.com",
    }, { genericRdnsPatterns: [/((a)+)+$/] });
  } catch (e) { threw = e; }
  check("ReDoS genericRdnsPattern refused", threw && threw.code === "mail-helo/unsafe-pattern");
}

async function testRefusesBadInput() {
  var threw1 = null;
  try { await b.mail.helo.evaluate(null); }
  catch (e) { threw1 = e; }
  check("null ctx refused",         threw1 && threw1.code === "mail-helo/bad-input");

  var threw2 = null;
  try { await b.mail.helo.evaluate({ ip: "203.0.113.42" }); }
  catch (e) { threw2 = e; }
  check("missing claimedName",      threw2 && threw2.code === "mail-helo/bad-input");

  var threw3 = null;
  try { await b.mail.helo.evaluate({ claimedName: "mail.example.com" }); }
  catch (e) { threw3 = e; }
  check("missing ip",               threw3 && threw3.code === "mail-helo/bad-input");
}

async function testProfileAndPosture() {
  // Permissive: bare-host accepted
  var v = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "barehost",
  }, { profile: "permissive" });
  check("permissive accepts bare-host", v.action === "accept");

  // Posture: hipaa pins strict
  var v2 = await b.mail.helo.evaluate({
    ip:          "203.0.113.42",
    claimedName: "barehost",
  }, { posture: "hipaa" });
  check("hipaa posture refuses bare-host", v2.action === "reject-shape");

  check("compliancePosture hipaa", b.mail.helo.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.mail.helo.compliancePosture("foo") === null);
}

async function run() {
  testSurface();
  await testAcceptsValidFqdn();
  await testRejectsLocalhostClaim();
  await testRejectsBareHost();
  await testAcceptsAddressLiteralV4Match();
  await testRefusesAddressLiteralV4Mismatch();
  await testAcceptsAddressLiteralV6Match();
  await testAddrLitV6CompressedExpandedEquivalent();
  await testRefusesSelfNameClaim();
  await testRefusesNonLdhLabel();
  await testRefusesOversize();
  await testFcrdnsPasses();
  await testFcrdnsSoftFails();
  await testFcrdnsNxRevDns();
  await testFcrdnsIpv6();
  await testFcrdnsSkippedForV6OnBalanced();
  await testGenericRdnsFlag();
  await testRefusesReDoSGenericRdnsPattern();
  await testRefusesBadInput();
  await testProfileAndPosture();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
