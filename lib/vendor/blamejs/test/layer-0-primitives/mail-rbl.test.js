"use strict";
/**
 * b.mail.rbl — RFC 5782 DNSBL + DNSWL query primitive. Tests use a
 * fake resolver so no real DNS traffic leaves the box.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Fake resolver mimicking b.network.dns.resolver.create() — operator
// programs query responses by name.
function _fakeResolver(map) {
  var calls = [];
  return {
    query: function (name, type) {
      calls.push({ name: name, type: type });
      var key = name + "|" + type;
      if (typeof map[key] === "function") return Promise.resolve(map[key]());
      if (map[key] === "__nxdomain__") {
        var e = new Error("nx");
        e.code = "resolver/nxdomain-or-error";
        return Promise.reject(e);
      }
      if (map[key] === "__throw__") return Promise.reject(new Error("upstream-down"));
      return map[key] ? Promise.resolve(map[key]) : Promise.reject(_mkNxd());
    },
    queryA:   function (name) { return this.query(name, "A"); },
    queryTxt: function (name) { return this.query(name, "TXT"); },
    _calls:   calls,
  };
}

function _mkNxd() {
  var e = new Error("NXDOMAIN");
  e.code = "resolver/nxdomain-or-error";
  return e;
}

function _aResponse(decoded) {
  return { rrs: [{ type: 1, typeName: "A", decoded: decoded, ttl: 300 }] };
}

function _txtResponse(strings) {
  return { rrs: [{ type: 16, typeName: "TXT", decoded: strings, ttl: 300 }] };
}

function testSurface() {
  check("create is fn",            typeof b.mail.rbl.create === "function");
  check("reverseIp is fn",         typeof b.mail.rbl.reverseIp === "function");
  check("compliancePosture is fn", typeof b.mail.rbl.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.mail.rbl.PROFILES));
  check("MailRblError is fn",      typeof b.mail.rbl.MailRblError === "function");
}

function testReverseIpv4() {
  check("ipv4: 192.0.2.99",         b.mail.rbl.reverseIp("192.0.2.99") === "99.2.0.192");
  check("ipv4: 127.0.0.1",          b.mail.rbl.reverseIp("127.0.0.1") === "1.0.0.127");
  check("ipv4: 0.0.0.0",            b.mail.rbl.reverseIp("0.0.0.0") === "0.0.0.0");
  check("ipv4: 255.255.255.255",    b.mail.rbl.reverseIp("255.255.255.255") === "255.255.255.255");
}

function testReverseIpv6() {
  // RFC 5782 §2.4 example: 2001:db8:1:2:3:4:567:89ab against ugly.example.com.
  var expected = "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2";
  check("ipv6: RFC 5782 §2.4 example", b.mail.rbl.reverseIp("2001:db8:1:2:3:4:567:89ab") === expected);

  // Compressed loopback ::1 → 32 nibbles reversed
  var loopback = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0";
  check("ipv6: loopback ::1",       b.mail.rbl.reverseIp("::1") === loopback);

  // 2001:db8::1
  var compressed = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2";
  check("ipv6: 2001:db8::1",        b.mail.rbl.reverseIp("2001:db8::1") === compressed);
}

function testReverseIpRefusesBadInput() {
  var threw = null;
  try { b.mail.rbl.reverseIp(""); }
  catch (e) { threw = e; }
  check("empty refused",            threw && threw.code === "mail-rbl/bad-input");

  var bad = null;
  try { b.mail.rbl.reverseIp("not-an-ip"); }
  catch (e) { bad = e; }
  check("non-IP refused",           bad && bad.code === "mail-rbl/bad-input");

  var oversize = null;
  try { b.mail.rbl.reverseIp("a".repeat(100)); }
  catch (e) { oversize = e; }
  check("oversize refused",         oversize && oversize.code === "mail-rbl/bad-input");

  var doubleColon = null;
  try { b.mail.rbl.reverseIp("2001::db8::1"); }
  catch (e) { doubleColon = e; }
  check("multiple :: refused",      doubleColon && doubleColon.code === "mail-rbl/bad-input");
}

function testCreateRefusesBadInput() {
  var noResolver = null;
  try { b.mail.rbl.create({ blocklists: ["bl.example.com"] }); }
  catch (e) { noResolver = e; }
  check("no resolver refused",      noResolver && noResolver.code === "mail-rbl/bad-resolver");

  var noLists = null;
  try { b.mail.rbl.create({ resolver: _fakeResolver({}) }); }
  catch (e) { noLists = e; }
  check("no lists refused",         noLists && noLists.code === "mail-rbl/no-lists");

  var badProfile = null;
  try {
    b.mail.rbl.create({
      resolver: _fakeResolver({}),
      blocklists: ["bl.example.com"],
      profile: "yolo",
    });
  } catch (e) { badProfile = e; }
  check("bad profile refused",      badProfile && badProfile.code === "mail-rbl/bad-profile");

  var badZone = null;
  try {
    b.mail.rbl.create({
      resolver: _fakeResolver({}),
      blocklists: ["bl..example.com"],
    });
  } catch (e) { badZone = e; }
  check("malformed zone refused",   badZone && badZone.code === "mail-rbl/bad-zone");

  var tooMany = null;
  var manyLists = [];
  for (var i = 0; i < 20; i += 1) manyLists.push("list" + i + ".example.com");
  try {
    b.mail.rbl.create({
      resolver: _fakeResolver({}),
      blocklists: manyLists,
    });
  } catch (e) { tooMany = e; }
  check("too many lists refused",   tooMany && tooMany.code === "mail-rbl/too-many-lists");
}

async function testQueryListed() {
  var resolver = _fakeResolver({
    "99.2.0.192.bl.example.com|A": _aResponse("127.0.0.2"),
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["bl.example.com"],
  });
  var v = await rbl.query("192.0.2.99");
  check("listed: count 1",          v.listed.length === 1);
  check("listed: zone",             v.listed[0].list === "bl.example.com");
  check("listed: return code",      v.listed[0].returnCode === "127.0.0.2");
  check("listed: kind=block",       v.listed[0].kind === "block");
  check("listed: no errors",        v.errors.length === 0);
}

async function testQueryListedWithReason() {
  var resolver = _fakeResolver({
    "99.2.0.192.bl.example.com|A":  _aResponse("127.0.0.4"),
    "99.2.0.192.bl.example.com|TXT": _txtResponse(["Listed: spam source 2026-05-15"]),
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["bl.example.com"],
  });
  var v = await rbl.query("192.0.2.99", { withReason: true });
  check("listed: reason fetched",   v.listed[0].reason === "Listed: spam source 2026-05-15");
}

async function testNotListedIsNeutral() {
  // No match (NXDOMAIN) — neutral verdict, not error.
  var resolver = _fakeResolver({
    "1.0.0.127.bl.example.com|A": "__nxdomain__",
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["bl.example.com"],
  });
  var v = await rbl.query("127.0.0.1");
  check("not listed: 0 listed",     v.listed.length === 0);
  check("not listed: 1 neutral",    v.neutral.length === 1);
  check("not listed: 0 errors",     v.errors.length === 0);
}

async function testAllowlistVerdict() {
  // DNSWL: A=127.0.0.x means allowed (not blocked).
  var resolver = _fakeResolver({
    "99.2.0.192.list.dnswl.org|A": _aResponse("127.0.5.1"),
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    allowlists: ["list.dnswl.org"],
  });
  var v = await rbl.query("192.0.2.99");
  check("allowlist: 1 allowed",     v.allowed.length === 1);
  check("allowlist: 0 listed",      v.listed.length === 0);
  check("allowlist: kind=allow",    v.allowed[0].kind === "allow");
}

async function testQueryDomain() {
  // Domain blocklist (Spamhaus DBL pattern) — no reverse.
  var resolver = _fakeResolver({
    "evil.example.com.dbl.example.com|A": _aResponse("127.0.1.2"),
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["dbl.example.com"],
  });
  var v = await rbl.queryDomain("evil.example.com");
  check("domain listed: 1 listed",  v.listed.length === 1);
  check("domain listed: zone",      v.listed[0].list === "dbl.example.com");
}

async function testWalksMultipleLists() {
  var resolver = _fakeResolver({
    "99.2.0.192.bl1.example.com|A": _aResponse("127.0.0.2"),
    "99.2.0.192.bl2.example.com|A": "__nxdomain__",
    "99.2.0.192.bl3.example.com|A": _aResponse("127.0.0.4"),
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["bl1.example.com", "bl2.example.com", "bl3.example.com"],
  });
  var v = await rbl.query("192.0.2.99");
  check("multi: 2 listed",          v.listed.length === 2);
  check("multi: 1 neutral",         v.neutral.length === 1);
  var zones = v.listed.map(function (r) { return r.list; }).sort();
  check("multi: zones bl1+bl3",     zones[0] === "bl1.example.com" && zones[1] === "bl3.example.com");
}

async function testUpstreamErrorSurfacesAsErrorEntry() {
  var resolver = _fakeResolver({
    "99.2.0.192.bl.example.com|A": "__throw__",
  });
  var rbl = b.mail.rbl.create({
    resolver:   resolver,
    blocklists: ["bl.example.com"],
  });
  var v = await rbl.query("192.0.2.99");
  check("upstream error: 0 listed", v.listed.length === 0);
  check("upstream error: 1 error",  v.errors.length === 1);
  check("upstream error: zone",     v.errors[0].list === "bl.example.com");
}

async function testCompliancePosture() {
  check("hipaa → strict",   b.mail.rbl.compliancePosture("hipaa") === "strict");
  check("unknown → null",   b.mail.rbl.compliancePosture("foo") === null);
}

async function run() {
  testSurface();
  testReverseIpv4();
  testReverseIpv6();
  testReverseIpRefusesBadInput();
  testCreateRefusesBadInput();
  await testQueryListed();
  await testQueryListedWithReason();
  await testNotListedIsNeutral();
  await testAllowlistVerdict();
  await testQueryDomain();
  await testWalksMultipleLists();
  await testUpstreamErrorSurfacesAsErrorEntry();
  await testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
