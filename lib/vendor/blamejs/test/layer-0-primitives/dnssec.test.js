"use strict";
/**
 * Layer 0 — b.network.dns.dnssec (local DNSSEC RRSIG verification).
 * The oracles are REAL captured DNSKEY responses (Cloudflare DoH,
 * application/dns-message) for an ECDSA-P256 zone (cloudflare.com) and
 * an RSA/SHA-256 zone (verisign.com): a byte off in the RFC 4034
 * canonicalisation would fail these real-world signatures. Verified at a
 * fixed instant inside each RRSIG's window so the fixture never expires.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

// Real `cloudflare.com` DNSKEY response (ECDSA P-256 / alg 13), captured
// via Cloudflare DoH with the DO bit set.
var CF_HEX = "000081a000010003000000010a636c6f7564666c61726503636f6d0000300001c00c003000010000071200440100030da09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a9957d1bcc18f98cd71f1f1806b65e148c00c003000010000071200440101030d99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19c00c002e000100000712006200300d0200000e106a604d3e6a0fe1be09430a636c6f7564666c61726503636f6d008a40d46e9ff1d7eae7a3824de100af4eba33c5cc88751c29fb7bf1a931d68ab1d25c19c8be0f06da464aebaad3f171be9ed92e20ae1b1bf25e54cc18939a2a5e00002904d0000080000000";
// Real `verisign.com` DNSKEY response (RSA/SHA-256 / alg 8).
var VS_HEX = "000081a0000100040000000108766572697369676e03636f6d0000300001c00c0030000100000cb900880100030803010001a24a87ea79dcc74adda5bad2b0ad3e5514b06c30dd14dcfe1ef3503e1591ccd67a486bf4d87e496c9c5f7009f6796eb54324157d5baa5815063816323bd2f1d2846d278c34c551cd4cf67c1adf21427836603e37c4230bc47ce59845fb697f53471a824be691e683580b92020f12c7a8efeb02f12fc475dbdeca65a0bb0a4f6fc00c0030000100000cb900880100030803010001cc288a535db6a1b542355d84ad07d77cd1729f6eb191b24698becb69ec43aaddbc1714102fd9a8745683d211a33bc88103e96a893e83cff7d27bce7cfeafc6ac2b3b85d0f95e2952d8c413a54aaeee378701f8627805ac97a778a0cd323ce1585139a3a84a9e5a28850ed427e8038fd2f0600f96e0188f46f33acede7811d711c00c0030000100000cb901080101030803010001bfb6a7aca1ef6f910e6dc358935f7132dd3a6fc716550739861b28f4c06ab0e6a4d8082bc7615fa898ed12594cb03e8c89d918d3c2c0d1036bfeae7b73f831ac49634c46cdb3d0c307dd53298f32c52fc16764729b133c105a4ec701ba2a3fbbb60ee6cf9c21dcc0ffbb270e3bc5e6bbf4cf1d07d1b00f50655c5d8e7724f951b3ac69d748265351aa014269ffd31678248ce15168aed3fcfbb1a32704743d76b15fc1abdb157c17b3d7deee5a6742019c32ee87a9bce449281122f586964d3f23cd502fbbb2c0504611876c50ca780ea958313dc9f7dec485aa90cd15bf42a66d80da99df2c46c3974ead4f88332a810b83d6e2a416d7ee8318f3c4c671eaa3c00c002e000100000cb901200030080200000e106a3b146f6a13876fd7a408766572697369676e03636f6d0075ae4e787092f2120d8592cf56d3cd87f06813e38aadd90111ba7e656e90ee1c969591cda2ed4838db2648a68326fa04cbd3886ff2fd48f954284bff78459c8a78c4ecb8b2462f0bd1636555dd96b1e83f7cf322d1a4806480eef57e16b65cf5d2229184cab0c573f30a16f5af94b4cd15c05a04c62cd2ca8afc2f39c6067ec2fed95cc044f88f4a746388de20fe58decccda4b1cbc50d8f011cd56055c56c375464b9999e3e04d6a7180ca5fce5801b445cfc9f33b6fdac4f5c9d9714deaa77420ee4f147f1fefb63187230cfb93c2a3c218130c707fb42dfb4d445a33197ebfbf00087d1012f2dc0f4b29857908a2de33aef8ebbcc326cf4e1ef60181cf82a00002904d0000080000000";

function _rdName(buf, off) {
  var ls = [], jumped = false, end = off;
  for (;;) {
    var len = buf[off];
    if (len === 0) { off++; if (!jumped) end = off; break; }
    if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; continue; }
    off++; ls.push(buf.slice(off, off + len).toString("ascii")); off += len;
  }
  return { name: ls.join(".") + (ls.length ? "." : ""), end: end };
}

// Parse a DNSKEY DoH response → { keys: [{rdata, alg, pubkey}], rrsig }.
function _parse(hex) {
  var buf = Buffer.from(hex, "hex");
  var qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6), off = 12;
  for (var q = 0; q < qd; q++) off = _rdName(buf, off).end + 4;
  var keys = [], rrsig = null;
  for (var i = 0; i < an; i++) {
    off = _rdName(buf, off).end;
    var type = buf.readUInt16BE(off), rdlen = buf.readUInt16BE(off + 8);
    off += 10;
    var rd = buf.slice(off, off + rdlen); off += rdlen;
    if (type === 48) keys.push({ rdata: rd, alg: rd[3], pubkey: rd.slice(4) });
    else if (type === 46) {
      var sn = _rdName(rd, 18);
      rrsig = { algorithm: rd[2], labels: rd[3], originalTtl: rd.readUInt32BE(4), expiration: rd.readUInt32BE(8), inception: rd.readUInt32BE(12), keyTag: rd.readUInt16BE(16), signerName: sn.name, signature: rd.slice(sn.end) };
    }
  }
  return { keys: keys, rrsig: rrsig };
}

function _vector(hex, zone) {
  var p = _parse(hex);
  var ksk = p.keys.find(function (k) { return b.network.dns.dnssec.keyTag(k.rdata) === p.rrsig.keyTag; });
  return { zone: zone, keys: p.keys, rrsig: p.rrsig, ksk: ksk, at: new Date(p.rrsig.inception * 1000 + 1000) };
}

function testSurface() {
  check("b.network.dns.dnssec.verifyRrset is a function", typeof b.network.dns.dnssec.verifyRrset === "function");
  check("b.network.dns.dnssec.verifyDs is a function", typeof b.network.dns.dnssec.verifyDs === "function");
  check("b.network.dns.dnssec.keyTag is a function", typeof b.network.dns.dnssec.keyTag === "function");
  check("b.network.dns.dnssec.verifyDenial is a function", typeof b.network.dns.dnssec.verifyDenial === "function");
  check("b.network.dns.dnssec.nsec3Hash is a function", typeof b.network.dns.dnssec.nsec3Hash === "function");
  check("b.network.dns.dnssec.verifyChain is a function", typeof b.network.dns.dnssec.verifyChain === "function");
  check("b.network.dns.dnssec.DEFAULT_ROOT_ANCHORS includes the IANA KSK tags", Array.isArray(b.network.dns.dnssec.DEFAULT_ROOT_ANCHORS) && b.network.dns.dnssec.DEFAULT_ROOT_ANCHORS.some(function (a) { return a.keyTag === 20326; }));
}

function testRealVectors() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  check("keyTag computes the real RRSIG key tag (ECDSA)", cf.ksk !== undefined);
  var ecOut = b.network.dns.dnssec.verifyRrset({ name: cf.zone, type: "DNSKEY", rdatas: cf.keys.map(function (k) { return k.rdata; }), rrsig: cf.rrsig, dnskey: { algorithm: cf.ksk.alg, publicKey: cf.ksk.pubkey }, at: cf.at });
  check("verifyRrset: real cloudflare.com DNSKEY self-sig verifies (ECDSAP256SHA256)", ecOut.ok && ecOut.algorithm === "ECDSAP256SHA256");

  var vs = _vector(VS_HEX, "verisign.com");
  check("keyTag computes the real RRSIG key tag (RSA)", vs.ksk !== undefined);
  var rsaOut = b.network.dns.dnssec.verifyRrset({ name: vs.zone, type: "DNSKEY", rdatas: vs.keys.map(function (k) { return k.rdata; }), rrsig: vs.rrsig, dnskey: { algorithm: vs.ksk.alg, publicKey: vs.ksk.pubkey }, at: vs.at });
  check("verifyRrset: real verisign.com DNSKEY self-sig verifies (RSASHA256)", rsaOut.ok && rsaOut.algorithm === "RSASHA256");
}

function testRefusals() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var base = { name: cf.zone, type: "DNSKEY", rrsig: cf.rrsig, dnskey: { algorithm: cf.ksk.alg, publicKey: cf.ksk.pubkey }, at: cf.at };
  function withRdatas(rd) { return Object.assign({}, base, { rdatas: rd }); }

  var tampered = cf.keys.map(function (k) { return Buffer.from(k.rdata); });
  tampered[0][tampered[0].length - 1] ^= 0xff;
  check("verifyRrset: tampered RRset refused", code(function () { b.network.dns.dnssec.verifyRrset(withRdatas(tampered)); }) === "dnssec/bad-signature");

  var rd = cf.keys.map(function (k) { return k.rdata; });
  check("verifyRrset: expired RRSIG refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date((cf.rrsig.expiration + 60) * 1000) })); }) === "dnssec/expired");
  check("verifyRrset: not-yet-valid RRSIG refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date((cf.rrsig.inception - 60) * 1000) })); }) === "dnssec/not-yet-valid");
  check("verifyRrset: invalid opts.at refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date("nope") })); }) === "dnssec/bad-at");
  check("verifyRrset: name-bearing RR type refused (not mis-validated)", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { type: "NS", rdatas: rd })); }) === "dnssec/uncanonicalizable-type");
  check("verifyRrset: DNSKEY/RRSIG algorithm mismatch refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, dnskey: { algorithm: 8, publicKey: cf.ksk.pubkey } })); }) === "dnssec/alg-mismatch");
}

function testVerifyDs() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  var nodeCrypto = require("node:crypto");
  // Build the SHA-256 DS digest over (canonical owner name || DNSKEY rdata),
  // then confirm verifyDs accepts it and rejects a tampered digest / key tag.
  function canonName(name) {
    var n = name.replace(/\.$/, ""), parts = [];
    n.split(".").forEach(function (l) { var b2 = Buffer.from(l.toLowerCase(), "ascii"); parts.push(Buffer.from([b2.length]), b2); });
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
  }
  var tag = b.network.dns.dnssec.keyTag(cf.ksk.rdata);
  var digest = nodeCrypto.createHash("sha256").update(Buffer.concat([canonName("cloudflare.com"), cf.ksk.rdata])).digest();
  var ds = { keyTag: tag, algorithm: cf.ksk.alg, digestType: 2, digest: digest };
  check("verifyDs: matching DS accepted", b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: ds }).ok === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var badDigest = Buffer.from(digest); badDigest[0] ^= 0xff;
  check("verifyDs: tampered digest refused", code(function () { b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: Object.assign({}, ds, { digest: badDigest }) }); }) === "dnssec/ds-mismatch");
  check("verifyDs: key-tag mismatch refused", code(function () { b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: Object.assign({}, ds, { keyTag: (tag + 1) & 0xffff }) }); }) === "dnssec/keytag-mismatch");
}

// --- Denial of existence (NSEC / NSEC3) ---

var B32H = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
function b32hDecode(s) {
  s = s.toUpperCase();
  var bits = 0, val = 0, out = [];
  for (var i = 0; i < s.length; i++) { val = (val << 5) | B32H.indexOf(s[i]); bits += 5; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); } }
  return Buffer.from(out);
}
var TY = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, RRSIG: 46, DNSKEY: 48, NSEC3PARAM: 51, CAA: 257, SRV: 33, DS: 43 };
function encodeBitmap(names) {
  if (!names.length) return Buffer.alloc(0);
  var byWin = {};
  names.forEach(function (nm) { var t = TY[nm]; (byWin[t >> 8] = byWin[t >> 8] || {})[t & 0xff] = 1; });
  var parts = [];
  Object.keys(byWin).map(Number).sort(function (a, c) { return a - c; }).forEach(function (w) {
    var bitsSet = Object.keys(byWin[w]).map(Number);
    var len = (Math.max.apply(null, bitsSet) >> 3) + 1, bm = Buffer.alloc(len);
    bitsSet.forEach(function (bit) { bm[bit >> 3] |= 0x80 >> (bit & 7); });
    parts.push(Buffer.from([w, len]), bm);
  });
  return Buffer.concat(parts);
}
function nsec3Rdata(opts) {
  var salt = opts.salt || Buffer.alloc(0);
  var next = Buffer.isBuffer(opts.next) ? opts.next : b32hDecode(opts.next);
  return Buffer.concat([
    Buffer.from([opts.hashAlg === undefined ? 1 : opts.hashAlg, opts.flags || 0, (opts.iterations >> 8) & 0xff, opts.iterations & 0xff, salt.length]),
    salt, Buffer.from([next.length]), next, encodeBitmap(opts.types || []),
  ]);
}
function nsecRdata(nextName, types) {
  var labels = nextName.replace(/\.$/, "").split(".");
  var parts = [];
  labels.forEach(function (l) { var bb = Buffer.from(l, "ascii"); parts.push(Buffer.from([bb.length]), bb); });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts.concat([encodeBitmap(types)]));
}
function bufInc(buf, delta) { var b2 = Buffer.from(buf); b2[b2.length - 1] = (b2[b2.length - 1] + delta) & 0xff; return b2; }

// Real `iana.org` NXDOMAIN proof (NSEC3, SHA-1, 0 iterations, empty salt),
// captured via Cloudflare DoH for nonexistent-blamejs-test-xyz.iana.org.
var IANA_NSEC3 = [
  { owner: "uqk2hjod270o42j2v1hoi7qtr945lhmb.iana.org", next: "VAVBTBDJ8O7H3CJCP1HL1CDPRTFQP46L", types: [] },
  { owner: "mvnqhoigoa305s1i78hp6cdv5n7lcutc.iana.org", next: "NGJOKE6KAKN5BC83M0IAPQVRBAJKQI3M", types: ["A", "NS", "SOA", "MX", "TXT", "AAAA", "RRSIG", "DNSKEY", "NSEC3PARAM", "CAA"] },
  { owner: "0d5cbi611aogl6kk8jjsopfic6dcb42t.iana.org", next: "26CS5JG5RASD1SS5VNTJ9PSC7FDVQIEO", types: ["CNAME", "RRSIG"] },
];
function ianaRecords() {
  return IANA_NSEC3.map(function (r) { return { owner: r.owner, rdata: nsec3Rdata({ iterations: 0, next: r.next, types: r.types }) }; });
}

function testNsec3Real() {
  // The NSEC3 hash of the apex equals the real apex owner label byte-exact.
  var h = b.network.dns.dnssec.nsec3Hash("iana.org", { salt: Buffer.alloc(0), iterations: 0 });
  check("nsec3Hash: matches the real iana.org apex owner label", Buffer.compare(h, b32hDecode("MVNQHOIGOA305S1I78HP6CDV5N7LCUTC")) === 0);

  var out = b.network.dns.dnssec.verifyDenial({ qname: "nonexistent-blamejs-test-xyz.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords() });
  check("verifyDenial: real iana.org NXDOMAIN proven (NSEC3)", out.ok && out.proof === "nxdomain" && out.mechanism === "nsec3" && out.closestEncloser === "iana.org." && out.optOut === false);

  // Apex NODATA: the apex NSEC3 matches iana.org; a type absent from its
  // bitmap is proven NODATA, a type present is refused.
  var nodata = b.network.dns.dnssec.verifyDenial({ qname: "iana.org", qtype: "SRV", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() });
  check("verifyDenial: real iana.org NODATA for absent type proven", nodata.ok && nodata.proof === "nodata" && nodata.matched === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: NODATA refused when type IS present", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "iana.org", qtype: "A", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/denial-not-proven");
  // Removing the next-closer cover breaks the NXDOMAIN proof.
  check("verifyDenial: NXDOMAIN refused without a covering NSEC3", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "nonexistent-blamejs-test-xyz.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: [ianaRecords()[1]] }); }) === "dnssec/denial-not-proven");
}

function testNsec3Caps() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  // Iterations beyond the cap are refused (iterated-SHA-1 DoS bound).
  var heavy = [{ owner: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.x", rdata: nsec3Rdata({ iterations: 9999, next: b32hDecode("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") }) }];
  check("verifyDenial: excessive NSEC3 iterations refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "q.x", proof: "nxdomain", zone: "x", nsec3: heavy }); }) === "dnssec/nsec3-iterations-excessive");
  // Unsupported hash algorithm refused.
  var badHash = [{ owner: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.x", rdata: nsec3Rdata({ hashAlg: 2, iterations: 0, next: b32hDecode("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") }) }];
  check("verifyDenial: unsupported NSEC3 hash algorithm refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "q.x", proof: "nxdomain", zone: "x", nsec3: badHash }); }) === "dnssec/unsupported-nsec3-hash");
}

function testNsec3OptOut() {
  // Construct an Opt-Out NXDOMAIN: matching apex + opt-out next-closer
  // cover + covered wildcard, using real hashes of chosen names.
  var salt = Buffer.alloc(0);
  function H(n) { return b.network.dns.dnssec.nsec3Hash(n, { salt: salt, iterations: 0 }); }
  var hT = H("test"), hX = H("x.test"), hW = H("*.test");
  function b32hEncode(buf) {
    var bits = 0, val = 0, out = "";
    for (var i = 0; i < buf.length; i++) { val = (val << 8) | buf[i]; bits += 8; while (bits >= 5) { bits -= 5; out += B32H[(val >> bits) & 31]; } }
    if (bits > 0) out += B32H[(val << (5 - bits)) & 31];
    return out;
  }
  var recs = [
    { owner: b32hEncode(hT) + ".test", rdata: nsec3Rdata({ flags: 0, iterations: 0, next: bufInc(hT, 1), types: ["NS", "SOA"] }) },
    { owner: b32hEncode(bufInc(hX, -1)) + ".test", rdata: nsec3Rdata({ flags: 1, iterations: 0, next: bufInc(hX, 1) }) },
    { owner: b32hEncode(bufInc(hW, -1)) + ".test", rdata: nsec3Rdata({ flags: 0, iterations: 0, next: bufInc(hW, 1) }) },
  ];
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: Opt-Out NXDOMAIN refused by default", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.test", proof: "nxdomain", zone: "test", nsec3: recs }); }) === "dnssec/denial-opt-out");
  var out = b.network.dns.dnssec.verifyDenial({ qname: "x.test", proof: "nxdomain", zone: "test", nsec3: recs, allowOptOut: true });
  check("verifyDenial: Opt-Out NXDOMAIN accepted with allowOptOut", out.ok && out.optOut === true);
}

function testWildcardMatchRejected() {
  // NXDOMAIN must NOT be accepted when the wildcard at the closest
  // encloser EXISTS (matches). A forged NXDOMAIN could otherwise suppress
  // data that wildcard expansion should have synthesised.
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var salt = Buffer.alloc(0);
  function H(n) { return b.network.dns.dnssec.nsec3Hash(n, { salt: salt, iterations: 0 }); }
  function enc(buf) {
    var bits = 0, val = 0, out = "";
    for (var i = 0; i < buf.length; i++) { val = (val << 8) | buf[i]; bits += 8; while (bits >= 5) { bits -= 5; out += B32H[(val >> bits) & 31]; } }
    if (bits > 0) out += B32H[(val << (5 - bits)) & 31];
    return out;
  }
  var hT = H("test"), hX = H("x.test"), hW = H("*.test");
  var recs = [
    { owner: enc(hT) + ".test", rdata: nsec3Rdata({ iterations: 0, next: bufInc(hT, 1), types: ["NS", "SOA"] }) },
    { owner: enc(bufInc(hX, -1)) + ".test", rdata: nsec3Rdata({ iterations: 0, next: bufInc(hX, 1) }) },
    { owner: enc(hW) + ".test", rdata: nsec3Rdata({ iterations: 0, next: bufInc(hW, 1), types: ["A"] }) }, // wildcard EXISTS (matches)
  ];
  check("verifyDenial: NSEC3 NXDOMAIN refused when wildcard matches (exists)", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.test", proof: "nxdomain", zone: "test", nsec3: recs }); }) === "dnssec/denial-not-proven");

  // NSEC equivalent: the wildcard owner exists in the chain.
  var nsec = [
    { owner: "example.com", rdata: nsecRdata("*.example.com", ["A", "NS", "SOA", "RRSIG", "DNSKEY"]) },
    { owner: "*.example.com", rdata: nsecRdata("a.example.com", ["A", "RRSIG"]) },
    { owner: "a.example.com", rdata: nsecRdata("example.com", ["A", "RRSIG"]) },
  ];
  check("verifyDenial: NSEC NXDOMAIN refused when wildcard owner exists", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "b.example.com", proof: "nxdomain", zone: "example.com", nsec: nsec }); }) === "dnssec/denial-not-proven");
}

function testNsec() {
  // Synthetic NSEC zone: apex + one name, both with bitmaps.
  var recs = [
    { owner: "example.com", rdata: nsecRdata("a.example.com", ["A", "NS", "SOA", "RRSIG", "DNSKEY"]) },
    { owner: "a.example.com", rdata: nsecRdata("example.com", ["A", "RRSIG"]) },
  ];
  var nx = b.network.dns.dnssec.verifyDenial({ qname: "b.example.com", proof: "nxdomain", zone: "example.com", nsec: recs });
  check("verifyDenial: NSEC NXDOMAIN proven (covering + wildcard)", nx.ok && nx.mechanism === "nsec" && nx.closestEncloser === "example.com.");

  var nd = b.network.dns.dnssec.verifyDenial({ qname: "example.com", qtype: "MX", proof: "nodata", zone: "example.com", nsec: recs });
  check("verifyDenial: NSEC NODATA proven for absent type", nd.ok && nd.matched === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: NSEC NODATA refused when type present", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "example.com", qtype: "A", proof: "nodata", zone: "example.com", nsec: recs }); }) === "dnssec/denial-not-proven");
}

function testDenialArgs() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: bad proof value refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.iana.org", proof: "maybe", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
  check("verifyDenial: zone not a suffix of qname refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.example.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
  check("verifyDenial: both nsec and nsec3 supplied refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords(), nsec: [{ owner: "iana.org", rdata: nsecRdata("a.iana.org", []) }] }); }) === "dnssec/bad-arg");
  check("verifyDenial: nodata without qtype refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "iana.org", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
}

// --- Chain validation (verifyChain) ---

// Real root→org DNSSEC chain captured via Cloudflare DoH: the root DNSKEY
// RRset (signed by the IANA KSK), the org DS RRset (served + signed by the
// root), and the org DNSKEY RRset (signed by org's KSK).
var ROOT_DNSKEY_HEX = "123481a00001000400000001000030000100003000010000000e01080100030803010001be5d0d87dfa60009f155062f042d5973e5416b2320526d08cd34fd768a53ef259fea1f6a1dead8ac44223bf3420fa7a9dc518fef1e9ad3e77b59ad61c6c558fe10f44f839e23892cad3d474e45bb3bc66eb1bb0c37510d45ff71e745755ecef29144018a49a98351f4109320057def70ced9b89ab8a480df56fb23694aff0a31a11d6d7f972a27848c6c952f8ae1e2700128522d804ecc25a193567794f9b619841599f1171ec3e5480a098ee87e54bbf8653b74d27012d9859d66151131cdd241d7573e9a82ea2e680669ef4e985cd22847f893810866b11ed75fec0bd19f103362f1408c94eaf459d3a232b8930644c8b0912b861256ee9b206dd762596eb500003000010000000e01080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010000000e01080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d8700002e00010000000e0113003008000002a3006a29fa806a0e4b004f66003eb63aef891c6aa08533d04c2e51d08c1a6834df2a30af63d3fec27ec4ac17dfc21384c03bc1c1df400af2f1c2ab80788e20f8383a3dfd8eb01f48b8d4430d191e58baddb7fcdeec2cf381d042d094535b7595071c082aa88794db2c0d56fda210a29df0b7f456699235921050261075ecb2ab6c63e716768c0b5db2def27eb62958808a5a2dddde98a2375e2bd9ed6e89f34fea1f222fb7fa70032c1e9357dafc378ab72207826c9d7674584679a743825e68146d759c0e886a2de996daf752aa5ae00f8297842aef9eac3bd27a698ec475719f22ac9ee8345e3b07a2a67aedee0a406309744bb7907ed1de6e266bad02f9e2caa297277e7715d77ce7d2772f00002904d0000080000000";
var ORG_DS_HEX = "123481a00001000200000001036f726700002b0001c00c002b0001000112ef0024695e08024fede294c53f438a158c41d39489cd78a86beb0d8a0aeaff14745c0d16e1de32c00c002e0001000112ef0113002b0801000151806a24fad06a13c940d4790018af430b9631a0da77f1b652ce2a45e82d045e6efb87d9b9e90e25d463a73ae86001e74a171f1c43a23115c4ab9192939cddc1a90c4405998c8d508f0ec5b345a11a64b7d9ea660b497bb629c8ed908c69ed982301cdc5b108272b06aa9626cd5174028f9ac03609d1c560fb96309b6c5166653b21b7a197a5c30678b5be18dd8e405df36414e04ca33658b7a1da402bd2f0e2a31c84c01385ca70cf6492ec2f2e6c04085308a1ac112638d6f286f66f0b726bacad46ea75f4221b173008db2d21f412cecbc085893f273110d4afc485e804ba80a96d7729ba84bddb684d502fd0041f8285306874860cb9cda0da394426b5df50debf57ef6d0f9261d8d7576300002904d0000080000000";
var ORG_DNSKEY_HEX = "123481a00001000400000001036f72670000300001c00c003000010000013200880100030803010001b1ac5fd2e78ca6b3eeb87e59ae4826bbdbaaddc35318f337942d3f207026d95c135d8e35863309bcd365a5c46223c90a6305467dfd6c3a874eb952ae11c7a9e5f177ae31ce9c0f6eeff1b331fcad3e32683cc254f38de0d92ef8188669ea9b7f30d78e82e8e6961dd390673941d67f397df95bd00859ec2306924eee737ec62bc00c003000010000013200880100030803010001d737ce87b2f7a67133bcf13a4c21b78ea38fa07bf278dbd919161afcaeafca081b1e1e01bcfe237f0dd929f7c695dea6c5e19853935224f6034b52c9eeb255a0b797304b771bf466d28f38b0e039276e90c673d7901a3937e9a3294e4d78ce1f9c26ff722e1b68b735bc680b405221ef6cd6a4da982778ee42d0db2bfd8031f1c00c003000010000013201080101030803010001ec5927fd707f2342c4d3eb4d98b3686ed49626c684ff80ca8811e9baa3a6d2b0784804e200fc1b1450264b7e167e690a836ace69b56671282aabe6f77b8e62d6ca918403187f96ebd27ae8c48aa602324be993ff889a5e7fa5a5be68f7d97fb1fee51cc6bdef93bf7ea37a68f5259788546cdd93d4b1efe87cd0b900ad351240f231c6c17e6ad0d32687667ec9a1ba07d70849eae37bd9792fe203db2749eb35eab98b5ea0852f5f6c73aa75c27473d2bc3fa82fa47fc1e5beb73b5d152d61a24ff5cf7b67e4dce671a38b965f675e7882a331292c51063ecc32beda615a0098848f1b053aa152c2307c8c0b481413120da8097eec4b909b5e0e383aac21216fc00c002e00010000013201170030080100000e106a258d3e6a09cfae695e036f726700831ed0c4fcc15125bfdd584858c72a88c4f837d8c15e7e276976417a3de45fe6ed14418035accd04081facdc0a0091bde55164a4e820514b49857155c2163b7ab07bf6d7d41003cd7971154bbf345f10ef04e9aa88e861c727c63d3f0ac2c484916360a1efa3ebef5cead2092b7c61ed8ebfccb40a79bce9d0082892d097cbd5541256ccaa09c96117e45ccdbd4d45b46145f902a81d660441f6e28ce6ec2cc83e773508947a7892cd2b1c91f8de73ed13f4199e7f3c097cb979c97bd97a34cfd0011647037c2c23da4a865960aa0f55a1d7a1c3817f0fb2f1bb7d6380eb5da578898fb0aebd5a9383ac5a1b76d6013a1a20832c53ea46ae5c6d35a06e6cc50300002904d0000080000000";

function _readN(buf, off) {
  var ls = [], jumped = false, end = off, g = 0;
  for (;;) { if (++g > 128) throw new Error("name guard"); var len = buf[off]; if (len === 0) { off++; if (!jumped) end = off; break; } if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; continue; } off++; ls.push(buf.slice(off, off + len).toString("ascii")); off += len; }
  return { name: ls.join(".") + (ls.length ? "." : "."), end: end };
}
function parseAnswer(hex) {
  var buf = Buffer.from(hex, "hex");
  var qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6), off = 12;
  for (var i = 0; i < qd; i++) off = _readN(buf, off).end + 4;
  var out = { dnskeys: [], ds: [], rrsig: {} };
  for (var j = 0; j < an; j++) {
    off = _readN(buf, off).end;
    var type = buf.readUInt16BE(off), rdlen = buf.readUInt16BE(off + 8); off += 10;
    var rd = buf.slice(off, off + rdlen); off += rdlen;
    if (type === 48) out.dnskeys.push(rd);
    else if (type === 43) out.ds.push(rd);
    else if (type === 46) { var sn = _readN(rd, 18); out.rrsig[rd.readUInt16BE(0)] = { algorithm: rd[2], labels: rd[3], originalTtl: rd.readUInt32BE(4), expiration: rd.readUInt32BE(8), inception: rd.readUInt32BE(12), keyTag: rd.readUInt16BE(16), signerName: sn.name, signature: rd.slice(sn.end) }; }
  }
  return out;
}

function testVerifyChain() {
  var root = parseAnswer(ROOT_DNSKEY_HEX), orgDs = parseAnswer(ORG_DS_HEX), orgDk = parseAnswer(ORG_DNSKEY_HEX);
  var maxInc = Math.max(root.rrsig[48].inception, orgDs.rrsig[43].inception, orgDk.rrsig[48].inception);
  var at = new Date((maxInc + 60) * 1000);
  function rootLink() { return { zone: ".", dnskeys: root.dnskeys, dnskeyRrsig: root.rrsig[48] }; }
  function orgLink() { return { zone: "org.", dnskeys: orgDk.dnskeys, dnskeyRrsig: orgDk.rrsig[48], dsRdatas: orgDs.ds, dsRrsig: orgDs.rrsig[43] }; }

  var out = b.network.dns.dnssec.verifyChain({ links: [rootLink(), orgLink()], at: at });
  check("verifyChain: real root→org chain validates to the pinned IANA anchor", out.ok && out.zone === "org." && out.path.join(",") === ".,org." && out.keys.length === 3);

  // Root link alone validates against the default anchor.
  var rootOnly = b.network.dns.dnssec.verifyChain({ links: [rootLink()], at: at });
  check("verifyChain: root DNSKEY alone validates against the default anchor", rootOnly.ok && rootOnly.zone === ".");

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  // A bogus trust anchor breaks the chain at the root.
  var badAnchor = [{ keyTag: 20326, algorithm: 8, digestType: 2, digest: Buffer.alloc(32, 0xff) }];
  check("verifyChain: wrong trust anchor refused", code(function () { b.network.dns.dnssec.verifyChain({ links: [rootLink()], at: at, trustAnchors: badAnchor }); }) === "dnssec/chain-anchor-mismatch");
  // A tampered org DS digest breaks the DS RRset signature.
  check("verifyChain: tampered DS RRset refused", code(function () {
    var bad = orgLink(); bad.dsRdatas = [Buffer.from(orgDs.ds[0])]; bad.dsRdatas[0][bad.dsRdatas[0].length - 1] ^= 0xff;
    b.network.dns.dnssec.verifyChain({ links: [rootLink(), bad], at: at });
  }) === "dnssec/bad-signature");
  // Expired (at past every window).
  check("verifyChain: expired link refused", code(function () { b.network.dns.dnssec.verifyChain({ links: [rootLink()], at: new Date((root.rrsig[48].expiration + 86400) * 1000) }); }) === "dnssec/expired");
  // Empty links refused.
  check("verifyChain: empty links refused", code(function () { b.network.dns.dnssec.verifyChain({ links: [] }); }) === "dnssec/bad-arg");

  // Key-tag collision: two keys in the SIGNED DNSKEY RRset share a tag
  // (16-bit tags collide, RFC 4034 App B). The non-signing one sorts
  // first; verifyChain must try every matching key (RFC 4035 §5.3.1) and
  // not return a false bad-signature.
  testKeyTagCollision();
}

var nodeCrypto = require("node:crypto");
function _ecDnskey(pubKey) {
  var jwk = pubKey.export({ format: "jwk" });
  var x = Buffer.from(jwk.x, "base64url"), y = Buffer.from(jwk.y, "base64url");
  return Buffer.concat([Buffer.from([0x01, 0x01, 3, 13]), x, y]); // flags 257 (KSK/SEP), proto 3, alg 13 (ECDSAP256SHA256)
}
function _canonName(name) {
  var n = name.replace(/\.$/, ""), parts = [];
  if (n !== "") n.split(".").forEach(function (l) { var bb = Buffer.from(l.toLowerCase(), "ascii"); parts.push(Buffer.from([bb.length]), bb); });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
function _u16b(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }
function _u32b(n) { var b2 = Buffer.alloc(4); b2.writeUInt32BE(n >>> 0, 0); return b2; }
// Build an RRSIG over a DNSKEY RRset signed by an EC P-256 key (mirrors
// the RFC 4034 §3.1.8.1 signed-data form verifyRrset reconstructs).
function _signDnskeyRrset(zone, rdatas, priv, signerRdata, inc, exp) {
  var owner = _canonName(zone), ttl = _u32b(3600), labels = zone.replace(/\.$/, "") === "" ? 0 : zone.replace(/\.$/, "").split(".").length;
  var keyTag = b.network.dns.dnssec.keyTag(signerRdata);
  var sorted = rdatas.slice().sort(Buffer.compare);
  var rrs = [];
  sorted.forEach(function (rd) { rrs.push(owner, _u16b(48), _u16b(1), ttl, _u16b(rd.length), rd); });
  var prefix = Buffer.concat([_u16b(48), Buffer.from([13, labels]), ttl, _u32b(exp), _u32b(inc), _u16b(keyTag), _canonName(zone)]);
  var signed = Buffer.concat([prefix].concat(rrs));
  var signature = nodeCrypto.sign("sha256", signed, { key: priv, dsaEncoding: "ieee-p1363" });
  return { algorithm: 13, labels: labels, originalTtl: 3600, expiration: exp, inception: inc, keyTag: keyTag, signerName: zone, signature: signature };
}
function testKeyTagCollision() {
  // Generate EC P-256 keypairs until two DNSKEYs collide on key tag.
  var byTag = {}, a = null, b2 = null;
  for (var i = 0; i < 4000 && !b2; i++) {
    var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    var rd = _ecDnskey(kp.publicKey);
    var t = b.network.dns.dnssec.keyTag(rd);
    if (byTag[t]) { a = byTag[t]; b2 = { rd: rd, priv: kp.privateKey }; } else byTag[t] = { rd: rd, priv: kp.privateKey };
  }
  check("test generated a key-tag collision", b2 !== null);
  if (!b2) return;
  // `a` is the signer; `b2` (same tag, different key) sorts into the set.
  var rdatas = [a.rd, b2.rd];
  var now = Math.floor(Date.now() / 1000);
  var rrsig = _signDnskeyRrset("test.", rdatas, a.priv, a.rd, now - 60, now + 86400);
  // Trust anchor = DS of the signer (SHA-256 over owner + DNSKEY rdata).
  var digest = nodeCrypto.createHash("sha256").update(Buffer.concat([_canonName("test."), a.rd])).digest();
  var anchor = { keyTag: b.network.dns.dnssec.keyTag(a.rd), algorithm: 13, digestType: 2, digest: digest };
  // Order the set so the non-signing colliding key is tried first.
  var ordered = (b.network.dns.dnssec.keyTag(rdatas[0]) === rrsig.keyTag && rdatas[0] !== a.rd) ? rdatas : [b2.rd, a.rd];
  var out = b.network.dns.dnssec.verifyChain({ links: [{ zone: "test.", dnskeys: ordered, dnskeyRrsig: rrsig }], trustAnchors: [anchor], at: new Date((now) * 1000) });
  check("verifyChain: validates despite a colliding-tag key in the signed set", out.ok === true);
}

// Sign a DS RRset (type 43) with a parent EC key — mirrors
// _signDnskeyRrset but for the DS record type.
function _signDsRrset(zone, dsRdatas, parentPriv, parentSignerRdata, inc, exp) {
  var owner = _canonName(zone), ttl = _u32b(3600);
  var labels = zone.replace(/\.$/, "") === "" ? 0 : zone.replace(/\.$/, "").split(".").length;
  var keyTag = b.network.dns.dnssec.keyTag(parentSignerRdata);
  var sorted = dsRdatas.slice().sort(Buffer.compare);
  var rrs = [];
  sorted.forEach(function (rd) { rrs.push(owner, _u16b(43), _u16b(1), ttl, _u16b(rd.length), rd); });
  var prefix = Buffer.concat([_u16b(43), Buffer.from([13, labels]), ttl, _u32b(exp), _u32b(inc), _u16b(keyTag), _canonName(zone)]);
  var signed = Buffer.concat([prefix].concat(rrs));
  var signature = nodeCrypto.sign("sha256", signed, { key: parentPriv, dsaEncoding: "ieee-p1363" });
  return { algorithm: 13, labels: labels, originalTtl: 3600, expiration: exp, inception: inc, keyTag: keyTag, signerName: zone, signature: signature };
}
function _dsRdata(tag, alg, digest) {
  return Buffer.concat([_u16b(tag), Buffer.from([alg, 2]), digest]);   // keyTag || alg || digestType=2(SHA-256) || digest
}

// The per-response signature-validation budget scales with chain depth, so
// a legitimate deep delegation (here 11 links → ~21 verifies, well past the
// old fixed 16) validates rather than hitting dnssec/validation-budget-
// exceeded (the regression Codex flagged on PR #236).
function testDeepChainBudget() {
  var now = Math.floor(Date.now() / 1000), inc = now - 60, exp = now + 86400;
  var N = 11;
  var keys = [];
  for (var i = 0; i < N; i++) {
    var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    keys.push({ rd: _ecDnskey(kp.publicKey), priv: kp.privateKey, zone: "z" + i + "." });
  }
  var links = [];
  for (var j = 0; j < N; j++) {
    var k = keys[j];
    var link = {
      zone:        k.zone,
      dnskeys:     [k.rd],
      dnskeyRrsig: _signDnskeyRrset(k.zone, [k.rd], k.priv, k.rd, inc, exp),
    };
    if (j > 0) {
      // DS of THIS zone's key, signed by the PARENT (previous link's key).
      var digest = nodeCrypto.createHash("sha256").update(Buffer.concat([_canonName(k.zone), k.rd])).digest();
      var dsRd = _dsRdata(b.network.dns.dnssec.keyTag(k.rd), 13, digest);
      link.dsRdatas = [dsRd];
      link.dsRrsig  = _signDsRrset(k.zone, [dsRd], keys[j - 1].priv, keys[j - 1].rd, inc, exp);
    }
    links.push(link);
  }
  // Trust anchor = DS digest of the root (link 0) key.
  var rootDigest = nodeCrypto.createHash("sha256").update(Buffer.concat([_canonName(keys[0].zone), keys[0].rd])).digest();
  var anchor = [{ keyTag: b.network.dns.dnssec.keyTag(keys[0].rd), algorithm: 13, digestType: 2, digest: rootDigest }];
  var out = b.network.dns.dnssec.verifyChain({ links: links, trustAnchors: anchor, at: new Date(now * 1000) });
  check("deep chain (11 links, ~21 verifies) validates under the depth-scaled budget",
    out.ok === true && out.path.length === N);
}

// KeyTrap (CVE-2023-50387) amplification caps. The caps fire on COUNT
// checks before any signature verification, so a single real EC DNSKEY
// rdata repeated to hit each threshold is enough.
function testKeyTrapCaps() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rd = _ecDnskey(kp.publicKey);
  var tag = b.network.dns.dnssec.keyTag(rd);
  var now = Math.floor(Date.now() / 1000);
  var rrsig = { algorithm: 13, labels: 1, originalTtl: 3600, expiration: now + 86400,
    inception: now - 60, keyTag: tag, signerName: "test.", signature: Buffer.alloc(64) };
  var anchor = [{ keyTag: tag, algorithm: 13, digestType: 2, digest: Buffer.alloc(32) }];

  // > MAX_COLLIDING_KEYS (4) keys sharing one tag (5 identical rdatas all
  // resolve to the same tag) → refused before any verify.
  var fiveSameTag = [rd, rd, rd, rd, rd];
  check("KeyTrap: >4 same-tag DNSKEY candidates refused",
    code(function () { b.network.dns.dnssec.verifyChain({
      links: [{ zone: "test.", dnskeys: fiveSameTag, dnskeyRrsig: rrsig }],
      trustAnchors: anchor, at: new Date(now * 1000) }); }) === "dnssec/too-many-colliding-keys");

  // > MAX_DNSKEYS_PER_ZONE (64) in one zone's RRset → refused.
  var bigSet = []; for (var i = 0; i < 65; i++) bigSet.push(rd);
  check("KeyTrap: oversize DNSKEY RRset (>64) refused",
    code(function () { b.network.dns.dnssec.verifyChain({
      links: [{ zone: "test.", dnskeys: bigSet, dnskeyRrsig: rrsig }],
      trustAnchors: anchor, at: new Date(now * 1000) }); }) === "dnssec/too-many-dnskeys");

  // A name encoding to > 255 octets (128 single-char labels = 257 octets)
  // is refused at canonicalization (RFC 1035 §2.3.4) — bounds the NSEC3
  // closest-encloser label enumeration.
  var longName = new Array(129).join("a.") + "a";   // 129 labels of "a"
  check("KeyTrap: name exceeding 255 octets refused",
    code(function () { b.network.dns.dnssec.verifyDs({ ownerName: longName,
      dnskeyRdata: rd, ds: { keyTag: tag, algorithm: 13, digestType: 2, digest: Buffer.alloc(32) } }); }) === "dnssec/bad-name");
}

async function run() {
  testSurface();
  testRealVectors();
  testRefusals();
  testVerifyDs();
  testVerifyChain();
  testKeyTrapCaps();
  testDeepChainBudget();
  testNsec3Real();
  testNsec3Caps();
  testNsec3OptOut();
  testWildcardMatchRejected();
  testNsec();
  testDenialArgs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dnssec] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
