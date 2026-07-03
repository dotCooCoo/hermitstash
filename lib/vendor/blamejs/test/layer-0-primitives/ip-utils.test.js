// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * lib/ip-utils — internal IP-address textual helpers shared across the
 * mail (greylist / rbl / helo), guard-domain, and safe-schema consumers.
 * Covers the strict dotted-quad IPv4 validator, the RFC 5321 bracketed
 * address-literal form, and the bounded loose-IPv6 pre-filter that were
 * consolidated here from five hand-rolled regex spellings.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var ip      = require("../../lib/ip-utils");

function run() {
  // ---- isIPv4 / IPV4_RE — strict RFC 791 dotted-quad ----
  ["0.0.0.0", "255.255.255.255", "1.2.3.4", "192.168.0.1", "10.0.0.255",
   "203.0.113.42", "9.9.9.9", "199.199.199.199", "250.250.250.250"]
    .forEach(function (s) {
      check("isIPv4 accepts " + s, ip.isIPv4(s) === true);
      check("IPV4_RE matches isIPv4 for " + s, ip.IPV4_RE.test(s) === ip.isIPv4(s));
    });

  ["256.0.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.256", "300.1.1.1",
   "", "abc", "1.2.3.4 ", " 1.2.3.4", "1.2.3.x", "999.0.0.0", "1.2.3.04",
   "0xC0.0.0.1"]
    .forEach(function (s) {
      check("isIPv4 rejects " + JSON.stringify(s), ip.isIPv4(s) === false);
    });

  // Non-string inputs never throw, always false.
  [null, undefined, 1234, {}, [], Buffer.from("1.2.3.4")].forEach(function (v) {
    check("isIPv4 false on non-string " + Object.prototype.toString.call(v),
      ip.isIPv4(v) === false);
  });

  // ---- IPV4_ADDR_LITERAL_RE — RFC 5321 §4.1.3 bracketed form ----
  var lit = "[203.0.113.42]".match(ip.IPV4_ADDR_LITERAL_RE);
  check("IPV4_ADDR_LITERAL_RE matches bracketed literal", lit !== null);
  check("IPV4_ADDR_LITERAL_RE captures inner dotted-quad", lit && lit[1] === "203.0.113.42");
  check("IPV4_ADDR_LITERAL_RE rejects out-of-range octet",
    ip.IPV4_ADDR_LITERAL_RE.test("[256.0.0.1]") === false);
  check("IPV4_ADDR_LITERAL_RE rejects unbracketed", ip.IPV4_ADDR_LITERAL_RE.test("1.2.3.4") === false);

  // ---- looksLikeIPv6Hex — bounded hex-colon pre-filter ----
  ["::1", "2001:db8::1", "fe80::1", "0:0:0:0:0:0:0:0",
   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]   // 39 chars — the upper bound
    .forEach(function (s) {
      check("looksLikeIPv6Hex accepts " + s, ip.looksLikeIPv6Hex(s) === true);
    });
  check("looksLikeIPv6Hex boundary is exactly 39",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".length === ip.IPV6_TEXT_MAX_LEN);

  ["::ffff:1.2.3.4",                              // dotted IPv4-mapped tail — excluded
   "gggg::1", "nothex", "", "1.2.3.4",
   "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"]  // 44 chars — over the bound
    .forEach(function (s) {
      check("looksLikeIPv6Hex rejects " + JSON.stringify(s), ip.looksLikeIPv6Hex(s) === false);
    });
  [null, undefined, 42, {}].forEach(function (v) {
    check("looksLikeIPv6Hex false on non-string", ip.looksLikeIPv6Hex(v) === false);
  });

  // A valid IPv6 that passes the pre-filter still expands cleanly.
  check("pre-filter then expandIpv6Hex parses ::1",
    ip.looksLikeIPv6Hex("::1") && ip.expandIpv6Hex("::1") === "00000000000000000000000000000001");

  // ---- regression: existing helpers unchanged ----
  check("isIPv4Shape loose still true for 999.0.0.0", ip.isIPv4Shape("999.0.0.0") === true);
  check("isIPv4Shape false for non-dotted", ip.isIPv4Shape("notip") === false);
  check("expandIpv6Hex(bad) null", ip.expandIpv6Hex("bad") === null);
  check("expandIpv6Groups ::1", JSON.stringify(ip.expandIpv6Groups("::1")) === JSON.stringify([0, 0, 0, 0, 0, 0, 0, 1]));

  return Promise.resolve();
}

module.exports = { run: run };

if (require.main === module) run().then(function () {
  process.stdout.write("OK — ip-utils\n");
}).catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
