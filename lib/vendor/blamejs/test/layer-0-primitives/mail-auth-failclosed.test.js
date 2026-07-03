// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mail-auth fail-closed / header-safety regressions.
 *
 * 1. b.mail.spf.verify — an ip4: mechanism whose CIDR prefix is non-numeric
 *    (`ip4:192.0.2.0/xx`, or an empty `.../`) fed parseInt → NaN. _ipv4InCidr
 *    guarded only `mask < 0 || mask > 32` (NaN passes both), so the NaN mask
 *    reached `BigInt(32 - NaN)` and threw RangeError. spf.verify runs inside
 *    b.mail.inbound.verify, whose contract is that message-derived faults
 *    surface as a permerror/temperror verdict, NEVER a throw: the throw was
 *    caught upstream (mail-server-mx) as a pipeline temperror, which
 *    onTemperror:"accept" would then admit for the spoofed sender (fail-open),
 *    and a hostile SPF record is a cheap uncaught-throw DoS. _ipv6InCidr
 *    already carried the `!isFinite(mask)` guard; ip4 lacked it. Fix: mirror
 *    the finite guard so a malformed mask is a non-match (fail-closed), not a
 *    crash.
 *
 * 2. b.mail.authResults.emit — opts.authservId was screened for CR/LF/NUL but
 *    opts.version was String()-coerced and interpolated verbatim onto the
 *    `Authentication-Results:` header line. A version carrying CRLF smuggled an
 *    arbitrary header (RFC 5322 header injection). Fix: run version through the
 *    same CR/LF/NUL refusal as authservId.
 *
 * Network-free: DNS is supplied via an operator dnsLookup mock.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A TXT dnsLookup fake bound to a single sender domain returning one record.
function dnsTxt(record) {
  return async function (host, type) {
    if (type === "TXT" && host === "s.example") return [[record]];
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
}

// ---- SPF ip4: malformed CIDR mask is a verdict, never a throw ----

async function testSpfIp4NonNumericMaskFailsClosed() {
  // `ip4:192.0.2.0/xx` — parseInt("xx") is NaN. The connecting IP is inside
  // 192.0.2.0/24, so a matched mechanism would authorize it; the malformed
  // mask must instead be a non-match → the -all fallthrough → fail.
  var dns = dnsTxt("v=spf1 ip4:192.0.2.0/xx -all");
  var rv = null, threw = null;
  try {
    rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  } catch (e) { threw = e; }
  check("spf.verify: ip4 non-numeric CIDR mask does NOT throw (content fault → verdict, not crash)",
        threw === null);
  check("spf.verify: ip4 non-numeric CIDR mask → fail-closed verdict, not pass",
        rv !== null && rv.result !== "pass");
}

async function testSpfIp4EmptyMaskFailsClosed() {
  // `ip4:192.0.2.0/` — parseInt("") is NaN as well.
  var dns = dnsTxt("v=spf1 ip4:192.0.2.0/ -all");
  var rv = null, threw = null;
  try {
    rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  } catch (e) { threw = e; }
  check("spf.verify: ip4 empty CIDR mask does NOT throw", threw === null);
  check("spf.verify: ip4 empty CIDR mask → fail-closed verdict, not pass",
        rv !== null && rv.result !== "pass");
}

async function testSpfIp4ValidMaskStillMatches() {
  // Control: a well-formed mask still authorizes an in-range IP (the finite
  // guard didn't over-broaden into rejecting valid masks).
  var dns = dnsTxt("v=spf1 ip4:192.0.2.0/24 -all");
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: valid ip4:192.0.2.0/24 with in-range IP → pass", rv.result === "pass");
}

async function testSpfIp6BadMaskFailsClosed() {
  // Sibling parity: ip6 already guarded the non-finite mask; assert it too
  // resolves to a fail-closed verdict rather than throwing.
  var dns = dnsTxt("v=spf1 ip6:2001:db8::/zz -all");
  var rv = null, threw = null;
  try {
    rv = await b.mail.spf.verify({ ip: "2001:db8::5", mailFrom: "a@s.example", dnsLookup: dns });
  } catch (e) { threw = e; }
  check("spf.verify: ip6 non-numeric CIDR mask does NOT throw", threw === null);
  check("spf.verify: ip6 non-numeric CIDR mask → fail-closed verdict, not pass",
        rv !== null && rv.result !== "pass");
}

// ---- authResults.emit — version field screened for header-injection bytes ----

function testAuthResultsVersionCrlfRefused() {
  var E = b.mail.authResults.emit;
  var out = null, threw = null;
  try {
    out = E({ authservId: "mx.a", version: "1\r\nInjected: evil",
              results: [{ method: "spf", result: "pass" }] });
  } catch (e) { threw = e; }
  check("authResults.emit: CR/LF in version → ar-bad-version throw (no header injection)",
        threw && /ar-bad-version/.test(threw.code || ""));
  check("authResults.emit: CRLF version never produces an injected header line",
        out === null);
}

function testAuthResultsVersionNulRefused() {
  var E = b.mail.authResults.emit;
  var threw = null;
  try {
    E({ authservId: "mx.a", version: "2" + String.fromCharCode(0) + "x",
        results: [{ method: "spf", result: "pass" }] });
  } catch (e) { threw = e; }
  check("authResults.emit: NUL in version → ar-bad-version throw",
        threw && /ar-bad-version/.test(threw.code || ""));
}

function testAuthResultsValidVersionStillEmits() {
  // Control: a well-formed non-'1' version still appends cleanly, and the
  // default '1' is still elided — the guard rejects only control characters.
  var E = b.mail.authResults.emit;
  var ver2 = E({ authservId: "mx.a", version: "2", results: [{ method: "spf", result: "pass" }] });
  check("authResults.emit: valid version '2' still appended after authserv-id",
        ver2.indexOf("Authentication-Results: mx.a 2;") === 0);
  var ver1 = E({ authservId: "mx.a", results: [{ method: "spf", result: "pass" }] });
  check("authResults.emit: default version '1' elided",
        ver1.indexOf("Authentication-Results: mx.a;") === 0);
}

async function run() {
  await testSpfIp4NonNumericMaskFailsClosed();
  await testSpfIp4EmptyMaskFailsClosed();
  await testSpfIp4ValidMaskStillMatches();
  await testSpfIp6BadMaskFailsClosed();
  testAuthResultsVersionCrlfRefused();
  testAuthResultsVersionNulRefused();
  testAuthResultsValidVersionStillEmits();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
