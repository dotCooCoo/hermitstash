// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeDns — bounded DNS-response parser. Substrate for v0.9.31
 * b.network.dns.resolver. Tests every cap + every type decoder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _hdr(id, flags, qd, an, ns, ar) {
  var h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(flags, 2);
  h.writeUInt16BE(qd, 4);
  h.writeUInt16BE(an, 6);
  h.writeUInt16BE(ns, 8);
  h.writeUInt16BE(ar, 10);
  return h;
}

// Encode a domain name in DNS wire format (length-prefixed labels + 0 terminator)
function _encName(name) {
  var labels = name.split(".").filter(Boolean);
  var parts = [];
  labels.forEach(function (l) {
    var b2 = Buffer.from(l, "ascii");
    parts.push(Buffer.from([b2.length]));
    parts.push(b2);
  });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function _q(name, qtype) {
  var nm = _encName(name);
  var tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2); // class IN
  return Buffer.concat([nm, tail]);
}

function _rr(name, rtype, rdata) {
  var nm = _encName(name);
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(rtype, 0);
  fixed.writeUInt16BE(1, 2);        // class IN
  fixed.writeUInt32BE(300, 4);      // ttl
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nm, fixed, rdata]);
}

function testSurface() {
  check("safeDns.parseResponse is fn",        typeof b.safeDns.parseResponse === "function");
  check("safeDns.boundEdns0 is fn",           typeof b.safeDns.boundEdns0 === "function");
  check("safeDns.checkCnameChainDepth is fn", typeof b.safeDns.checkCnameChainDepth === "function");
  check("safeDns.compliancePosture is fn",    typeof b.safeDns.compliancePosture === "function");
  check("safeDns.PROFILES frozen",            Object.isFrozen(b.safeDns.PROFILES));
  check("safeDns.RTYPE_NAMES frozen",         Object.isFrozen(b.safeDns.RTYPE_NAMES));
  check("safeDns.SafeDnsError is fn",         typeof b.safeDns.SafeDnsError === "function");
  check("safeDns.PROFILES.strict exists",     typeof b.safeDns.PROFILES.strict === "object");
  check("safeDns.PROFILES.balanced exists",   typeof b.safeDns.PROFILES.balanced === "object");
  check("safeDns.PROFILES.permissive exists", typeof b.safeDns.PROFILES.permissive === "object");
}

function testParsesARecord() {
  var resp = Buffer.concat([
    _hdr(0x1234, 0x8180, 1, 1, 0, 0),
    _q("example.com", 1),
    _rr("example.com", 1, Buffer.from([192, 0, 2, 1])),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("A: id round-trip",         p.id === 0x1234);
  check("A: rcode=0 NOERROR",       p.rcode === 0);
  check("A: question count 1",      p.question.length === 1);
  check("A: question name",         p.question[0].name === "example.com");
  check("A: question typeName=A",   p.question[0].typeName === "A");
  check("A: answer count 1",        p.answer.length === 1);
  check("A: answer typeName=A",     p.answer[0].typeName === "A");
  check("A: decoded dotted-quad",   p.answer[0].decoded === "192.0.2.1");
  check("A: rdata bytes",           p.answer[0].rdata.length === 4);
}

function _aaaa(g0, g1, g2, g3, g4, g5, g6, g7) {
  var b16 = Buffer.alloc(16);
  b16.writeUInt16BE(g0, 0);  b16.writeUInt16BE(g1, 2);
  b16.writeUInt16BE(g2, 4);  b16.writeUInt16BE(g3, 6);
  b16.writeUInt16BE(g4, 8);  b16.writeUInt16BE(g5, 10);
  b16.writeUInt16BE(g6, 12); b16.writeUInt16BE(g7, 14);
  return b16;
}

function testParsesAaaaRecordRfc5952() {
  // 2001:db8::1 — canonical RFC 5952 form with single longest-zero compression.
  var rdata = _aaaa(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001);
  var resp = Buffer.concat([
    _hdr(0xbeef, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: typeName",                p.answer[0].typeName === "AAAA");
  check("AAAA: canonical 2001:db8::1",   p.answer[0].decoded === "2001:db8::1");
}

function testAaaaLoopback() {
  // ::1 — all zeros except last group.
  var rdata = _aaaa(0, 0, 0, 0, 0, 0, 0, 1);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: loopback ::1", p.answer[0].decoded === "::1");
}

function testAaaaUnspecified() {
  // :: — all zeros.
  var rdata = _aaaa(0, 0, 0, 0, 0, 0, 0, 0);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: unspecified ::", p.answer[0].decoded === "::");
}

function testAaaaLongestRunWins() {
  // 1:0:0:1:0:0:0:1 — second zero run (3 groups) is longer than first (2).
  var rdata = _aaaa(1, 0, 0, 1, 0, 0, 0, 1);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: longest run wins (1:0:0:1::1)", p.answer[0].decoded === "1:0:0:1::1");
}

function testAaaaSingleZeroGroupNotCompressed() {
  // 1:2:3:4:5:6:0:8 — single-zero group MUST NOT be compressed per RFC 5952 §4.2.2.
  var rdata = _aaaa(1, 2, 3, 4, 5, 6, 0, 8);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: single-zero NOT compressed", p.answer[0].decoded === "1:2:3:4:5:6:0:8");
}

function testAaaaIpv4Mapped() {
  // ::ffff:192.0.2.1 — RFC 5952 §5 IPv4-mapped form.
  var rdata = _aaaa(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("v6.example.com", 28),
    _rr("v6.example.com", 28, rdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("AAAA: IPv4-mapped dotted-quad", p.answer[0].decoded === "::ffff:192.0.2.1");
}

function testIp6ArpaPtrName() {
  // Reverse-IPv6 PTR — nibble-reversed name ending in .ip6.arpa.
  // For 2001:db8::1 → 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
  var ptrTarget = "host.example.com";
  var ptrRdata = _encName(ptrTarget);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", 12),
    _rr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", 12, ptrRdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("ip6.arpa PTR: question name preserved", p.question[0].name.indexOf(".ip6.arpa") !== -1);
  check("ip6.arpa PTR: typeName=PTR",            p.answer[0].typeName === "PTR");
  check("ip6.arpa PTR: target",                  p.answer[0].decoded === ptrTarget);
}

function testParsesMxAndTxt() {
  var mxRdata = Buffer.concat([Buffer.from([0, 10]), _encName("mail.example.com")]);
  var txt1 = "v=spf1 -all";
  var txtRdata = Buffer.concat([Buffer.from([txt1.length]), Buffer.from(txt1, "ascii")]);
  var resp = Buffer.concat([
    _hdr(0xcafe, 0x8180, 1, 2, 0, 0),
    _q("example.com", 15),
    _rr("example.com", 15, mxRdata),
    _rr("example.com", 16, txtRdata),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("MX: typeName",           p.answer[0].typeName === "MX");
  check("MX: preference",         p.answer[0].decoded.preference === 10);
  check("MX: exchange",           p.answer[0].decoded.exchange === "mail.example.com");
  check("TXT: typeName",          p.answer[1].typeName === "TXT");
  check("TXT: single string",     p.answer[1].decoded.length === 1);
  check("TXT: value",             p.answer[1].decoded[0] === txt1);
}

function testRefusesOversizeResponse() {
  // Build a response well over strict cap (4 KiB).
  var oversize = Buffer.alloc(b.safeDns.PROFILES.strict.maxResponseBytes + 1);
  oversize.writeUInt16BE(0, 0);                // valid header start
  var threw = null;
  try { b.safeDns.parseResponse(oversize); }
  catch (e) { threw = e; }
  check("oversize-response: throws",     threw !== null);
  check("oversize-response: code",       threw && threw.code === "safe-dns/oversize-response");
}

function testRefusesTruncatedHeader() {
  var truncated = Buffer.from([0, 1, 2, 3]);
  var threw = null;
  try { b.safeDns.parseResponse(truncated); }
  catch (e) { threw = e; }
  check("truncated-header: throws",      threw !== null);
  check("truncated-header: code",        threw && threw.code === "safe-dns/truncated-header");
}

function testRefusesOversizeAnswerRrs() {
  // Set ancount past strict cap (64) — parser refuses before walking RRs
  var hdr = _hdr(0xaaaa, 0x8180, 0, 999, 0, 0);
  var threw = null;
  try { b.safeDns.parseResponse(hdr); }
  catch (e) { threw = e; }
  check("oversize-answer-rrs: throws",   threw !== null);
  check("oversize-answer-rrs: code",     threw && threw.code === "safe-dns/oversize-answer-rrs");
}

function testRefusesOversizeLabel() {
  // Build a response with a 200-byte label (RFC 1035 cap 63).
  var bad = Buffer.alloc(300);
  bad.writeUInt16BE(0, 0);                 // id
  bad.writeUInt16BE(0x8180, 2);
  bad.writeUInt16BE(1, 4);                 // qdcount=1
  bad.writeUInt16BE(0, 6);
  bad.writeUInt16BE(0, 8);
  bad.writeUInt16BE(0, 10);
  bad[12] = 100;                           // label length 100 (top 2 bits 01, reserved range — falls through label-size check; > 63 RFC 1035 cap)
  var threw = null;
  try { b.safeDns.parseResponse(bad); }
  catch (e) { threw = e; }
  check("oversize-label: throws",        threw !== null);
  check("oversize-label: code",          threw && threw.code === "safe-dns/oversize-label");
}

function testRefusesPointerLoop() {
  // Build a name with a compression pointer that loops back to itself.
  // Pointer at offset 12 → offset 12. Repeated jumps trip pointer-depth cap.
  var bad = Buffer.alloc(20);
  bad.writeUInt16BE(0, 0);
  bad.writeUInt16BE(0x8180, 2);
  bad.writeUInt16BE(1, 4);                 // qdcount=1
  bad.writeUInt16BE(0, 6);
  bad.writeUInt16BE(0, 8);
  bad.writeUInt16BE(0, 10);
  bad[12] = 0xc0; bad[13] = 12;            // pointer to self
  var threw = null;
  try { b.safeDns.parseResponse(bad); }
  catch (e) { threw = e; }
  check("pointer-loop: throws",          threw !== null);
  check("pointer-loop: code",            threw && threw.code === "safe-dns/oversize-pointer-depth");
}

function testRefusesMalformedRdlength() {
  // An RR whose RDLENGTH runs past message end.
  var hdr = _hdr(0, 0x8180, 0, 1, 0, 0);
  var nm = _encName("a.test");
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(1, 0);                // type A
  fixed.writeUInt16BE(1, 2);                // class IN
  fixed.writeUInt32BE(0, 4);                // ttl
  fixed.writeUInt16BE(9999, 8);             // RDLENGTH way past end
  var resp = Buffer.concat([hdr, nm, fixed]);
  var threw = null;
  try { b.safeDns.parseResponse(resp); }
  catch (e) { threw = e; }
  check("malformed-rdlength: throws",    threw !== null);
  check("malformed-rdlength: code",      threw && threw.code === "safe-dns/malformed-rdlength");
}

function testBoundEdns0() {
  var p = b.safeDns.PROFILES.strict;
  check("boundEdns0: under cap returns advertised", b.safeDns.boundEdns0(1024) === 1024);
  check("boundEdns0: over cap clamps to profile",   b.safeDns.boundEdns0(p.maxEdns0Bytes * 2) === p.maxEdns0Bytes);
  var threw = null;
  try { b.safeDns.boundEdns0(65536); }
  catch (e) { threw = e; }
  check("boundEdns0: hard-max refused",  threw && threw.code === "safe-dns/oversize-edns0");
  var bad = null;
  try { b.safeDns.boundEdns0("nope"); }
  catch (e) { bad = e; }
  check("boundEdns0: bad input refused", bad && bad.code === "safe-dns/bad-input");
}

function testCheckCnameChainDepth() {
  b.safeDns.checkCnameChainDepth(0);
  b.safeDns.checkCnameChainDepth(b.safeDns.PROFILES.strict.maxCnameDepth);
  var threw = null;
  try { b.safeDns.checkCnameChainDepth(b.safeDns.PROFILES.strict.maxCnameDepth + 1); }
  catch (e) { threw = e; }
  check("cnameChainDepth: over cap throws", threw && threw.code === "safe-dns/oversize-cname-depth");
}

function testCompliancePosture() {
  check("posture hipaa -> strict",     b.safeDns.compliancePosture("hipaa") === "strict");
  check("posture pci-dss -> strict",   b.safeDns.compliancePosture("pci-dss") === "strict");
  check("posture gdpr -> strict",      b.safeDns.compliancePosture("gdpr") === "strict");
  check("posture soc2 -> strict",      b.safeDns.compliancePosture("soc2") === "strict");
  check("posture unknown -> null",     b.safeDns.compliancePosture("hippa-typo") === null);
}

function testParsesEdns0Opt() {
  // OPT pseudo-RR carries advertised UDP size in CLASS field.
  var nm = Buffer.from([0]);                // root name
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(41, 0);                // type OPT
  fixed.writeUInt16BE(1232, 2);              // advertised buffer size 1232
  fixed.writeUInt32BE(0, 4);                 // ttl: ext-RCODE=0, version=0, no DO
  fixed.writeUInt16BE(0, 8);                 // RDLENGTH=0
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 0, 0, 0, 1),
    nm, fixed,
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("OPT: edns0 surfaced",           p.edns0 !== null);
  check("OPT: advertised size",          p.edns0.advertisedUdpSize === 1232);
  check("OPT: not in additional",        p.additional.length === 0);
  check("OPT: DO bit absent",            p.edns0.dnssecOk === false);
}

function testParsesEdns0OptWithDoBit() {
  var nm = Buffer.from([0]);
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(41, 0);
  fixed.writeUInt16BE(1232, 2);
  // DO bit = high bit of low 16-bit half = 0x8000
  fixed.writeUInt32BE(0x8000, 4);
  fixed.writeUInt16BE(0, 8);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 0, 0, 0, 1),
    nm, fixed,
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("OPT-DO: DO bit set",            p.edns0.dnssecOk === true);
}

function testRefusesEdns0OversizeAdvertised() {
  var nm = Buffer.from([0]);
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(41, 0);
  fixed.writeUInt16BE(60000, 2);             // way over strict cap
  fixed.writeUInt32BE(0, 4);
  fixed.writeUInt16BE(0, 8);
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 0, 0, 0, 1),
    nm, fixed,
  ]);
  var threw = null;
  try { b.safeDns.parseResponse(resp); }
  catch (e) { threw = e; }
  check("OPT-oversize: refused",         threw && threw.code === "safe-dns/oversize-edns0");
}

function testRefusesBadInput() {
  var threw = null;
  try { b.safeDns.parseResponse("not-a-buffer"); }
  catch (e) { threw = e; }
  check("bad-input: throws",             threw && threw.code === "safe-dns/bad-input");
}

function testParsesCname() {
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("alias.example.com", 5),
    _rr("alias.example.com", 5, _encName("real.example.com")),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("CNAME: typeName",       p.answer[0].typeName === "CNAME");
  check("CNAME: decoded target", p.answer[0].decoded === "real.example.com");
}

function testParsesNs() {
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q("example.com", 2),
    _rr("example.com", 2, _encName("ns1.example.com")),
  ]);
  var p = b.safeDns.parseResponse(resp);
  check("NS: typeName",       p.answer[0].typeName === "NS");
  check("NS: decoded target", p.answer[0].decoded === "ns1.example.com");
}

function testProfileBalanced() {
  // balanced profile allows 16 KiB response.
  var caps = b.safeDns.PROFILES.balanced;
  check("balanced.maxResponseBytes 16K", caps.maxResponseBytes === 16 * 1024);
  check("balanced.maxAnswerRrs",         caps.maxAnswerRrs === 128);
}

function testProfilePermissive() {
  var caps = b.safeDns.PROFILES.permissive;
  check("permissive.maxResponseBytes 64K", caps.maxResponseBytes === 64 * 1024);
  check("permissive.maxAnswerRrs",         caps.maxAnswerRrs === 256);
}

function testBadProfileRefused() {
  var resp = Buffer.concat([
    _hdr(0, 0x8180, 0, 0, 0, 0),
  ]);
  var threw = null;
  try { b.safeDns.parseResponse(resp, { profile: "lax" }); }
  catch (e) { threw = e; }
  check("bad profile refused",     threw && threw.code === "safe-dns/bad-profile");
}

// Capture the error code a thrown SafeDnsError carries (or null on success).
function _codeOf(fn) {
  try { fn(); return null; }
  catch (e) { return e && e.code; }
}

// n length-prefixed labels each 63 bytes of 'a' (0x61) — max-width labels.
function _wideLabels(n) {
  var parts = [];
  for (var i = 0; i < n; i += 1) { parts.push(Buffer.from([63])); parts.push(Buffer.alloc(63, 0x61)); }
  return Buffer.concat(parts);
}

// n length-prefixed 1-byte labels ('a') — smallest legal label.
function _tinyLabels(n) {
  var parts = [];
  for (var i = 0; i < n; i += 1) { parts.push(Buffer.from([1])); parts.push(Buffer.from("a", "ascii")); }
  return Buffer.concat(parts);
}

// RED — a compression-pointer chain must not decompress to a name larger
// than the RFC 1035 §3.1 255-octet cap. Question name is a pointer to block A
// (3 x 63-octet labels), block A ends in a pointer to block B (3 more), which
// terminates. Each block alone is under 255 octets, but the composite
// decompressed name is ~385 octets. Before the accountants threaded through
// the chain, the parser returned a 383-char name (cap bypassed); it must
// instead fail closed with oversize-name.
function testRefusesCompressionNameByteBomb() {
  var h     = _hdr(0, 0x8180, 1, 0, 0, 0);
  var qptr  = Buffer.from([0xc0, 18]);                     // question name -> block A at offset 18
  var qtail = Buffer.alloc(4); qtail.writeUInt16BE(1, 0); qtail.writeUInt16BE(1, 2);
  var blockA = _wideLabels(3);                             // offsets 18..209 (192 octets)
  var ptrAB  = Buffer.from([0xc0, 212]);                   // block A tail -> block B at offset 212
  var blockB = _wideLabels(3);                             // offsets 212..403
  var term   = Buffer.from([0]);
  var buf    = Buffer.concat([h, qptr, qtail, blockA, ptrAB, blockB, term]);
  var code = _codeOf(function () { b.safeDns.parseResponse(buf); });
  check("compression byte-bomb: fails closed (oversize-name)", code === "safe-dns/oversize-name");
}

// RED — the maxLabels cap (127) must also thread through compression. Two
// 100-label blocks joined by a pointer: each block is under the cap, the
// composite is 200 labels. Before the fix the parser returned a 200-label
// name; it must refuse the over-cap composite.
function testRefusesCompressionLabelBomb() {
  var h     = _hdr(0, 0x8180, 1, 0, 0, 0);
  var qptr  = Buffer.from([0xc0, 18]);                     // question name -> block A at offset 18
  var qtail = Buffer.alloc(4); qtail.writeUInt16BE(1, 0); qtail.writeUInt16BE(1, 2);
  var blockA = _tinyLabels(100);                           // offsets 18..217 (200 octets, 100 labels)
  var ptrAB  = Buffer.from([0xc0, 220]);                   // block A tail -> block B at offset 220
  var blockB = _tinyLabels(100);
  var term   = Buffer.from([0]);
  var buf    = Buffer.concat([h, qptr, qtail, blockA, ptrAB, blockB, term]);
  var code = _codeOf(function () { b.safeDns.parseResponse(buf); });
  check("compression label-bomb: fails closed (oversize-labels)", code === "safe-dns/oversize-labels");
}

// A legitimate compression pointer (composite name well under the caps) must
// still decompress correctly — the fix must not over-reject. The answer RR's
// NAME is a pointer back to the question name.
function testCompressionPointerResolves() {
  var h     = _hdr(0, 0x8180, 1, 1, 0, 0);
  var qn    = _encName("example.com");                    // offsets 12..24 (13 octets)
  var qtail = Buffer.alloc(4); qtail.writeUInt16BE(1, 0); qtail.writeUInt16BE(1, 2);
  var aptr  = Buffer.from([0xc0, 12]);                    // answer name -> question name
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(1, 0); fixed.writeUInt16BE(1, 2); fixed.writeUInt32BE(300, 4); fixed.writeUInt16BE(4, 8);
  var rdata = Buffer.from([192, 0, 2, 7]);
  var buf   = Buffer.concat([h, qn, qtail, aptr, fixed, rdata]);
  var p = b.safeDns.parseResponse(buf);
  check("compression resolve: answer name decompressed", p.answer[0].name === "example.com");
  check("compression resolve: A decoded",                p.answer[0].decoded === "192.0.2.7");
}

function testRefusesTruncatedNameLabelPastEnd() {
  // Question label claims 5 bytes but the buffer ends after 2.
  var buf = Buffer.concat([_hdr(0, 0x8180, 1, 0, 0, 0), Buffer.from([5, 0x61, 0x62])]);
  check("truncated-name (label past end)",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/truncated-name");
}

function testRefusesTruncatedNamePointerByte() {
  // A compression-pointer's high byte is the last byte in the message.
  var buf = Buffer.concat([_hdr(0, 0x8180, 1, 0, 0, 0), Buffer.from([0xc0])]);
  check("truncated-name (pointer truncated)",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/truncated-name");
}

function testRefusesPointerOffsetPastEnd() {
  // Pointer resolves to offset 255, past the 14-byte message.
  var buf = Buffer.concat([_hdr(0, 0x8180, 1, 0, 0, 0), Buffer.from([0xc0, 0xff])]);
  check("truncated-name (pointer offset past end)",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/truncated-name");
}

function testRefusesTruncatedRrFixedPrefix() {
  // Answer RR: valid name, then fewer than 10 octets of the fixed prefix.
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _encName("a.b"), Buffer.from([0, 1, 0])]);
  check("truncated-rr (mid fixed-prefix)",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/truncated-rr");
}

function testRefusesOversizeAuthorityRrs() {
  check("oversize-authority-rrs",
    _codeOf(function () { b.safeDns.parseResponse(_hdr(0, 0x8180, 0, 0, 999, 0)); }) ===
      "safe-dns/oversize-authority-rrs");
}

function testRefusesOversizeAdditionalRrs() {
  check("oversize-additional-rrs",
    _codeOf(function () { b.safeDns.parseResponse(_hdr(0, 0x8180, 0, 0, 0, 999)); }) ===
      "safe-dns/oversize-additional-rrs");
}

function testRefusesTxtCharStringPastRdata() {
  // TXT character-string length byte (5) overruns the 3-octet rdata.
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 16, Buffer.from([5, 0x61, 0x62]))]);
  check("txt char-string past rdata -> malformed-rdlength",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/malformed-rdlength");
}

function testRefusesSoaTailTruncated() {
  // SOA rdata carries both names but fewer than the 20-octet fixed tail.
  var soaRdata = Buffer.concat([_encName("m.ex"), _encName("r.ex"), Buffer.alloc(5)]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 6, soaRdata)]);
  check("soa tail truncated -> malformed-rdlength",
    _codeOf(function () { b.safeDns.parseResponse(buf); }) === "safe-dns/malformed-rdlength");
}

function testDecodesSrv() {
  var srvRdata = Buffer.concat([Buffer.from([0, 1, 0, 5, 0x1f, 0x90]), _encName("srv.example.com")]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 33, srvRdata)]);
  var d = b.safeDns.parseResponse(buf).answer[0].decoded;
  check("SRV: priority", d.priority === 1);
  check("SRV: weight",   d.weight === 5);
  check("SRV: port",     d.port === 8080);
  check("SRV: target",   d.target === "srv.example.com");
}

function testDecodesDs() {
  var dsRdata = Buffer.concat([Buffer.from([0x12, 0x34, 8, 2]), Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 43, dsRdata)]);
  var d = b.safeDns.parseResponse(buf).answer[0].decoded;
  check("DS: keyTag",      d.keyTag === 0x1234);
  check("DS: algorithm",   d.algorithm === 8);
  check("DS: digestType",  d.digestType === 2);
  check("DS: digest bytes", d.digest.length === 4 && d.digest[0] === 0xde);
}

function testDecodesDnskey() {
  var dnskeyRdata = Buffer.concat([Buffer.from([0x01, 0x00, 3, 8]), Buffer.from([0xaa, 0xbb])]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 48, dnskeyRdata)]);
  var d = b.safeDns.parseResponse(buf).answer[0].decoded;
  check("DNSKEY: flags",     d.flags === 256);
  check("DNSKEY: protocol",  d.protocol === 3);
  check("DNSKEY: algorithm", d.algorithm === 8);
  check("DNSKEY: publicKey", d.publicKey.length === 2 && d.publicKey[0] === 0xaa);
}

function testDecodesTlsa() {
  var tlsaRdata = Buffer.concat([Buffer.from([3, 1, 1]), Buffer.from([0xca, 0xfe])]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 52, tlsaRdata)]);
  var d = b.safeDns.parseResponse(buf).answer[0].decoded;
  check("TLSA: usage",        d.usage === 3);
  check("TLSA: selector",     d.selector === 1);
  check("TLSA: matchingType", d.matchingType === 1);
  check("TLSA: certData",     d.certData.length === 2 && d.certData[0] === 0xca);
}

function testDecodesRrsig() {
  var fixed = Buffer.alloc(18);
  fixed.writeUInt16BE(1, 0);      // typeCovered = A
  fixed.writeUInt8(8, 2);         // algorithm
  fixed.writeUInt8(2, 3);         // labels
  fixed.writeUInt32BE(3600, 4);   // originalTtl
  fixed.writeUInt32BE(1000, 8);   // sigExpiry
  fixed.writeUInt32BE(500, 12);   // sigInception
  fixed.writeUInt16BE(0xabcd, 16); // keyTag
  var rrsigRdata = Buffer.concat([fixed, _encName("ex.com"), Buffer.from([0x11, 0x22, 0x33])]);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 46, rrsigRdata)]);
  var d = b.safeDns.parseResponse(buf).answer[0].decoded;
  check("RRSIG: typeCovered",  d.typeCovered === 1);
  check("RRSIG: keyTag",       d.keyTag === 0xabcd);
  check("RRSIG: signerName",   d.signerName === "ex.com");
  check("RRSIG: signature",    d.signature.length === 3 && d.signature[0] === 0x11);
}

function testFormatIpv6NoCompression() {
  // No zero run of length >= 2 — every group emitted, no "::".
  var rdata = _aaaa(1, 2, 3, 4, 5, 6, 7, 8);
  var buf = Buffer.concat([_hdr(0, 0x8180, 0, 1, 0, 0), _rr("ex.com", 28, rdata)]);
  check("AAAA: no-compression full form",
    b.safeDns.parseResponse(buf).answer[0].decoded === "1:2:3:4:5:6:7:8");
}

function testParseResponsePostureResolvesStrict() {
  // ancount=100 is under balanced/permissive answer caps but over strict (64).
  // posture "hipaa" maps to strict, so it must refuse.
  check("posture hipaa -> strict answer cap fires",
    _codeOf(function () { b.safeDns.parseResponse(_hdr(0, 0x8180, 0, 100, 0, 0), { posture: "hipaa" }); }) ===
      "safe-dns/oversize-answer-rrs");
  // posture wins over an explicit profile (resolver checks posture first).
  check("posture beats profile (permissive+hipaa still strict)",
    _codeOf(function () { b.safeDns.parseResponse(_hdr(0, 0x8180, 0, 100, 0, 0), { profile: "permissive", posture: "hipaa" }); }) ===
      "safe-dns/oversize-answer-rrs");
  // permissive alone accepts ancount=100 (cap 256) — it fails later on the
  // empty RR body, not on the answer-count guard.
  check("permissive alone does not trip answer cap at 100",
    _codeOf(function () { b.safeDns.parseResponse(_hdr(0, 0x8180, 0, 100, 0, 0), { profile: "permissive" }); }) !==
      "safe-dns/oversize-answer-rrs");
}

function testBoundEdns0NegativeAndNonFinite() {
  check("boundEdns0 negative refused",  _codeOf(function () { b.safeDns.boundEdns0(-1); }) === "safe-dns/bad-input");
  check("boundEdns0 Infinity refused",  _codeOf(function () { b.safeDns.boundEdns0(Infinity); }) === "safe-dns/bad-input");
  check("boundEdns0 NaN refused",       _codeOf(function () { b.safeDns.boundEdns0(NaN); }) === "safe-dns/bad-input");
  check("boundEdns0 exactly at cap",    b.safeDns.boundEdns0(b.safeDns.PROFILES.strict.maxEdns0Bytes) === b.safeDns.PROFILES.strict.maxEdns0Bytes);
}

function testCheckCnameChainDepthBadInput() {
  check("cnameDepth negative refused", _codeOf(function () { b.safeDns.checkCnameChainDepth(-1); }) === "safe-dns/bad-input");
  check("cnameDepth NaN refused",      _codeOf(function () { b.safeDns.checkCnameChainDepth(NaN); }) === "safe-dns/bad-input");
  check("cnameDepth string refused",   _codeOf(function () { b.safeDns.checkCnameChainDepth("5"); }) === "safe-dns/bad-input");
}

function run() {
  testSurface();
  testParsesARecord();
  testParsesAaaaRecordRfc5952();
  testAaaaLoopback();
  testAaaaUnspecified();
  testAaaaLongestRunWins();
  testAaaaSingleZeroGroupNotCompressed();
  testAaaaIpv4Mapped();
  testIp6ArpaPtrName();
  testParsesMxAndTxt();
  testRefusesOversizeResponse();
  testRefusesTruncatedHeader();
  testRefusesOversizeAnswerRrs();
  testRefusesOversizeLabel();
  testRefusesPointerLoop();
  testRefusesMalformedRdlength();
  testBoundEdns0();
  testCheckCnameChainDepth();
  testCompliancePosture();
  testParsesEdns0Opt();
  testParsesEdns0OptWithDoBit();
  testRefusesEdns0OversizeAdvertised();
  testRefusesBadInput();
  testParsesCname();
  testParsesNs();
  testProfileBalanced();
  testProfilePermissive();
  testBadProfileRefused();
  testRefusesCompressionNameByteBomb();
  testRefusesCompressionLabelBomb();
  testCompressionPointerResolves();
  testRefusesTruncatedNameLabelPastEnd();
  testRefusesTruncatedNamePointerByte();
  testRefusesPointerOffsetPastEnd();
  testRefusesTruncatedRrFixedPrefix();
  testRefusesOversizeAuthorityRrs();
  testRefusesOversizeAdditionalRrs();
  testRefusesTxtCharStringPastRdata();
  testRefusesSoaTailTruncated();
  testDecodesSrv();
  testDecodesDs();
  testDecodesDnskey();
  testDecodesTlsa();
  testDecodesRrsig();
  testFormatIpv6NoCompression();
  testParseResponsePostureResolvesStrict();
  testBoundEdns0NegativeAndNonFinite();
  testCheckCnameChainDepthBadInput();
}

module.exports = { run: run };

if (require.main === module) run();
