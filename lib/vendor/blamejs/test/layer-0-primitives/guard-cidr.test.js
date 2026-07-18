// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function _kinds(rv) {
  return rv.issues.map(function (i) { return i.kind; });
}

function testValidate() {
  // Benign: a public /24 with zero host bits is clean under strict.
  var okRv = b.guardCidr.validate("8.8.8.0/24", { profile: "strict" });
  check("guardCidr.validate benign ok",             okRv.ok === true);
  check("guardCidr.validate benign no issues",      okRv.issues.length === 0);

  // Hostile: RFC 1918 private range — refused as reserved-range under strict.
  var reserved = b.guardCidr.validate("10.0.0.0/8", { profile: "strict" });
  check("guardCidr.validate reserved refused",      reserved.ok === false);
  check("guardCidr.validate reserved-range kind",
    _kinds(reserved).indexOf("reserved-range") !== -1);

  // Mask out of range for IPv4 (>32) — mask-cap high.
  var maskCap = b.guardCidr.validate("8.8.8.0/40", { profile: "strict" });
  check("guardCidr.validate mask-cap refused",      maskCap.ok === false);
  check("guardCidr.validate mask-cap kind",
    _kinds(maskCap).indexOf("mask-cap") !== -1);

  // Not a valid IPv4 dotted-decimal or IPv6 hex-group form — address-shape.
  var badShape = b.guardCidr.validate("not.an.ip/24", { profile: "strict" });
  check("guardCidr.validate address-shape refused", badShape.ok === false);
  check("guardCidr.validate address-shape kind",
    _kinds(badShape).indexOf("address-shape") !== -1);

  // RFC 4291 §2.2 — a "::" adjacent to a full 8 explicit groups compresses zero
  // groups and is malformed IPv6 (net.isIP rejects it). The parser must not
  // admit the non-canonical spelling into CIDR matching as a valid address.
  ["1:2:3:4:5:6:7:8::/64", "::1:2:3:4:5:6:7:8/64", "1:2:3:4:5:6:7::8/64"]
    .forEach(function (c) {
      var zc = b.guardCidr.validate(c, { profile: "strict" });
      check("guardCidr.validate rejects zero-group '::' " + c, zc.ok === false);
      check("guardCidr.validate zero-group '::' is address-shape " + c,
        _kinds(zc).indexOf("address-shape") !== -1);
    });

  // Host bits set under the mask — network-misaligned (common typo class).
  var misaligned = b.guardCidr.validate("10.0.0.1/24", { profile: "strict" });
  check("guardCidr.validate misaligned refused",    misaligned.ok === false);
  check("guardCidr.validate network-misaligned kind",
    _kinds(misaligned).indexOf("network-misaligned") !== -1);

  // IPv4-mapped IPv6 — dual-stack allowlist confusion (CVE-2021-22931 class).
  var mapped = b.guardCidr.validate("::ffff:0:0/96", { profile: "strict" });
  check("guardCidr.validate ipv4-mapped refused",   mapped.ok === false);
  check("guardCidr.validate ipv4-mapped-ipv6 kind",
    _kinds(mapped).indexOf("ipv4-mapped-ipv6") !== -1);

  // Bare IP with no /mask — refused under strict (reject-bare-ip).
  var bare = b.guardCidr.validate("8.8.8.8", { profile: "strict" });
  check("guardCidr.validate bare-ip refused",       bare.ok === false);
  check("guardCidr.validate bare-ip kind",
    _kinds(bare).indexOf("bare-ip") !== -1);
}

function testSanitize() {
  // Benign IPv6 with uppercase hex groups — permissive allows the
  // documentation range; sanitize lowercases the hex so a case-varying
  // allowlist key can't slip a duplicate past a case-sensitive matcher.
  var lowered = b.guardCidr.sanitize("2001:DB8::/32", { profile: "permissive" });
  check("guardCidr.sanitize lowercases IPv6",       lowered === "2001:db8::/32");
  check("guardCidr.sanitize output neutralized",    lowered !== "2001:DB8::/32");
  check("guardCidr.sanitize output revalidates ok",
    b.guardCidr.validate(lowered, { profile: "permissive" }).ok === true);

  // IPv4 has no canonical casing — returned unchanged when clean.
  var v4 = b.guardCidr.sanitize("8.8.8.0/24", { profile: "strict" });
  check("guardCidr.sanitize IPv4 unchanged",        v4 === "8.8.8.0/24");

  // Hostile: reserved private range REFUSED (thrown), never returned — an
  // allowlist gate must not silently normalize a reserved range into place.
  var err = expectThrows("guardCidr.sanitize reserved throws",
    function () { b.guardCidr.sanitize("10.0.0.0/8", { profile: "strict" }); },
    "cidr.reserved-range");
  check("guardCidr.sanitize reserved GuardCidrError",
    err instanceof b.guardCidr.GuardCidrError);
}

function testIpv6ReservedNibbleMisaligned() {
  // IPv6 reserved-range membership is a bit-prefix relation, not a hex-nibble
  // one. ULA fc00::/7 (7 bits) and link-local fe80::/10 (10 bits) do not fall
  // on a 4-bit nibble boundary, so a hex-string startsWith("fc") / ("fe8")
  // match silently misses every reserved address whose partial nibble differs
  // — most importantly fd00::/8, the HALF of fc00::/7 that real deployments
  // actually assign (RFC 4193 L=1). Under strict, reservedRangesPolicy is
  // "reject", so a missed reserved range fails OPEN: a private/link-local
  // range validates as clean and can be added to an allowlist as if public.
  var strict = { profile: "strict" };

  // fc00::/7 ULA — BOTH halves must be caught. fd00::/8 is the assigned one.
  ["fc00::/8", "fd00::/8", "fdab:cd12::/32"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr ULA " + c + " refused", rv.ok === false);
    check("guardCidr ULA " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });

  // fe80::/10 link-local — the whole /10 must be caught, not just fe8x.
  ["fe80::/16", "fe90::/16", "fea0::/16", "feb0::/16"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr link-local " + c + " refused", rv.ok === false);
    check("guardCidr link-local " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });

  // Regression — the fix must not OVER-match. fec0::/10 (deprecated site-local)
  // is NOT in the reserved table and shares only the fe8x visual prefix's
  // sibling nibble; it must stay clean, as must genuine public space.
  ["fec0::/16", "2606:4700::/32", "2001:4860::/32"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr public/site-local " + c + " clean", rv.ok === true);
  });

  // Regression — nibble-aligned reserved prefixes stay caught.
  ["ff02::1/128", "2001:db8::/32", "::1/128"].forEach(function (c) {
    var rv = b.guardCidr.validate(c, strict);
    check("guardCidr aligned-reserved " + c + " refused", rv.ok === false);
    check("guardCidr aligned-reserved " + c + " reserved-range kind",
      _kinds(rv).indexOf("reserved-range") !== -1);
  });
}

async function run() {
  testValidate();
  testSanitize();
  testIpv6ReservedNibbleMisaligned();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
