"use strict";
/**
 * b.selfUpdate.standaloneVerifier — ECDSA signature-encoding dispatch.
 *
 * The standalone verifier must choose the ECDSA signature encoding
 * (DER ASN.1 SEQUENCE vs IEEE-P1363 raw r||s) by STRUCTURE, not by
 * byte length. A P-384 DER signature whose r and s both encode short
 * can total exactly 96 bytes — the same length as a raw P-384 sig — so
 * a length-only heuristic mis-decodes the valid DER signature as raw
 * and spuriously rejects an otherwise-valid update.
 *
 * RED before the fix: a forged-but-genuine 96-byte DER P-384 signature
 * verifies as DER yet is rejected by the length-based dispatch.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var nc = require("node:crypto");

// ---------------------------------------------------------------------------
// Minimal P-384 (secp384r1) math, BigInt-only (no deps), used solely to
// FORGE a valid signature with chosen short coordinates so its DER form is
// exactly 96 bytes. A genuine 96-byte DER P-384 signature is astronomically
// rare from random signing (coordinates are ~48 bytes), so we construct one:
// given chosen (r, s) and the message hash e, we solve for a public key Q
// such that (r, s) is a valid ECDSA signature — Q = r^-1 (s*R - e*G), where
// R is a curve point with x-coordinate r. The resulting (asset, sig, pubkey)
// triple verifies as DER under node:crypto.
// ---------------------------------------------------------------------------
var P_P  = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
var P_A  = P_P - 3n;
var P_B  = BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
var P_N  = BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
var P_GX = BigInt("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
var P_GY = BigInt("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
var P_G  = [P_GX, P_GY];

function _mod(x, m) { var r = x % m; return r < 0n ? r + m : r; }
function _modpow(base, exp, m) {
  base = _mod(base, m);
  var r = 1n;
  while (exp > 0n) { if (exp & 1n) r = _mod(r * base, m); base = _mod(base * base, m); exp >>= 1n; }
  return r;
}
function _inv(x, m) { return _modpow(_mod(x, m), m - 2n, m); }
function _double(pt) {
  if (pt === null) return null;
  var x = pt[0], y = pt[1];
  if (y === 0n) return null;
  var s = _mod((3n * x * x + P_A) * _inv(2n * y, P_P), P_P);
  var xr = _mod(s * s - 2n * x, P_P);
  var yr = _mod(s * (x - xr) - y, P_P);
  return [xr, yr];
}
function _add(pt1, pt2) {
  if (pt1 === null) return pt2;
  if (pt2 === null) return pt1;
  var x1 = pt1[0], y1 = pt1[1], x2 = pt2[0], y2 = pt2[1];
  if (x1 === x2) { if (_mod(y1 + y2, P_P) === 0n) return null; return _double(pt1); }
  var s = _mod((y2 - y1) * _inv(x2 - x1, P_P), P_P);
  var xr = _mod(s * s - x1 - x2, P_P);
  var yr = _mod(s * (x1 - xr) - y1, P_P);
  return [xr, yr];
}
function _neg(pt) { return pt === null ? null : [pt[0], _mod(-pt[1], P_P)]; }
function _scalarMul(k, pt) {
  k = _mod(k, P_N);
  var r = null, q = pt;
  while (k > 0n) { if (k & 1n) r = _add(r, q); q = _double(q); k >>= 1n; }
  return r;
}
function _liftX(xr) {
  var rhs = _mod(xr * xr * xr + P_A * xr + P_B, P_P);
  var y = _modpow(rhs, (P_P + 1n) / 4n, P_P);   // p % 4 === 3
  if (_mod(y * y, P_P) !== rhs) return null;
  return [xr, y];
}
function _beToBig(buf) { var x = 0n; for (var i = 0; i < buf.length; i++) x = (x << 8n) | BigInt(buf[i]); return x; }
function _bigToFixed(x, len) {
  var h = x.toString(16);
  if (h.length < len * 2) h = "0".repeat(len * 2 - h.length) + h;
  return Buffer.from(h, "hex");
}
function _derInt(x) {
  var h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  var bts = Buffer.from(h, "hex");
  var i = 0;
  while (i < bts.length - 1 && bts[i] === 0) i++;
  bts = bts.subarray(i);
  if (bts[0] & 0x80) bts = Buffer.concat([Buffer.from([0]), bts]);
  return Buffer.concat([Buffer.from([0x02, bts.length]), bts]);
}
function _derSig(r, s) {
  var body = Buffer.concat([_derInt(r), _derInt(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
// SPKI DER prefix for an EC P-384 public key (the fixed ASN.1 header that
// precedes the 97-byte uncompressed point 0x04 || X || Y).
var _EC_P384_SPKI_PREFIX = Buffer.from("3076301006072a8648ce3d020106052b81040022036200", "hex");
function _pubKeyFromPoint(pt) {
  var point = Buffer.concat([Buffer.from([0x04]), _bigToFixed(pt[0], 48), _bigToFixed(pt[1], 48)]);
  var spki = Buffer.concat([_EC_P384_SPKI_PREFIX, point]);
  return nc.createPublicKey({ key: spki, format: "der", type: "spki" });
}
// Leftmost 384 bits of the SHA3-512 digest (the field ECDSA-P384 verifies on).
function _hashToE(asset) {
  var d = nc.createHash("sha3-512").update(asset).digest();
  return _beToBig(d) >> (8n * (BigInt(d.length) - 48n));
}

// Forge a verifying 96-byte DER P-384 signature over `asset`.
// Returns { pubPem, sig (DER, 96 bytes) }.
function _forge96ByteDerSig(asset) {
  var e = _hashToE(asset);
  // Find a curve point R whose x-coordinate r is exactly 45 bytes long with
  // its top bit clear (so its DER INTEGER needs no sign-pad: 2 + 45 bytes).
  var base = 1n << BigInt(8 * 44);   // smallest 45-byte value, top byte 0x01
  var r = null, R = null;
  for (var d = 0n; d < 200000n; d++) {
    var cand = base + d;
    if (cand <= 0n || cand >= P_N) continue;
    var lifted = _liftX(_mod(cand, P_P));
    if (lifted) { r = cand; R = lifted; break; }
  }
  if (r === null) throw new Error("test setup: could not find a 45-byte r on the curve");
  // s: a fixed 45-byte value (top byte 0x01, top bit clear) -> DER INTEGER 2 + 45.
  var s = (1n << (8n * 44n)) + 12345n;
  // Q = r^-1 (s*R - e*G)
  var Q = _scalarMul(_inv(r, P_N), _add(_scalarMul(s, R), _neg(_scalarMul(e, P_G))));
  var pub = _pubKeyFromPoint(Q);
  var sig = _derSig(r, s);
  return { pubPem: pub.export({ type: "spki", format: "pem" }), key: pub, sig: sig };
}

function _scratch(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sv-enc-" + label + "-"));
}
function _write(dir, name, data) {
  var p = path.join(dir, name);
  fs.writeFileSync(p, data);
  return p;
}

// The core RED case: a valid 96-byte DER P-384 signature must verify.
function testEcdsaP384Der96Bytes() {
  var dir = _scratch("der96");
  try {
    var asset = Buffer.from("blamejs release artifact — 96-byte DER P-384 case");
    var forged = _forge96ByteDerSig(asset);

    // Sanity on the crafted artifact (the test's own preconditions).
    check("setup: forged sig is exactly 96 bytes", forged.sig.length === 96);
    check("setup: forged sig is a DER SEQUENCE (0x30)", forged.sig[0] === 0x30);
    var sanity = nc.createVerify("sha3-512");
    sanity.update(asset);
    check("setup: forged sig verifies as DER under node:crypto",
          sanity.verify({ key: forged.key, dsaEncoding: "der" }, forged.sig) === true);

    var assetPath = _write(dir, "asset", asset);
    var sigPath = _write(dir, "asset.sig", forged.sig);

    var r = b.selfUpdate.standaloneVerifier.verify(assetPath, sigPath, forged.pubPem);
    check("96-byte DER P-384: verify SUCCEEDS (encoding detected by structure, not length)",
          r.ok === true);
    check("96-byte DER P-384: alg detected", r.alg === "ecdsa-p384");
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

// A genuine raw IEEE-P1363 96-byte signature must still verify (no regression).
function testEcdsaP384RawStillVerifies() {
  var dir = _scratch("raw96");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = Buffer.from("blamejs raw ieee-p1363 P-384 case");
    var assetPath = _write(dir, "asset", asset);
    var sign = nc.createSign("sha3-512");
    sign.update(asset);
    var sigBytes = sign.sign({ key: kp.privateKey, dsaEncoding: "ieee-p1363" });
    check("setup: raw sig is exactly 96 bytes", sigBytes.length === 96);
    check("setup: raw sig is NOT a DER SEQUENCE", sigBytes[0] !== 0x30);
    var sigPath = _write(dir, "asset.sig", sigBytes);
    var r = b.selfUpdate.standaloneVerifier.verify(assetPath, sigPath, pub);
    check("raw 96-byte IEEE-P1363 P-384: verify SUCCEEDS", r.ok === true);
    check("raw 96-byte IEEE-P1363 P-384: alg detected", r.alg === "ecdsa-p384");
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

// A standard (>96 byte) DER signature must still verify (no regression).
function testEcdsaP384DerDefaultStillVerifies() {
  var dir = _scratch("derdefault");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = Buffer.from("blamejs default DER P-384 case");
    var assetPath = _write(dir, "asset", asset);
    var sign = nc.createSign("sha3-512");
    sign.update(asset);
    var sigBytes = sign.sign(kp.privateKey);   // default DER
    check("setup: default DER sig length != 96", sigBytes.length !== 96);
    check("setup: default DER sig is a SEQUENCE", sigBytes[0] === 0x30);
    var sigPath = _write(dir, "asset.sig", sigBytes);
    var r = b.selfUpdate.standaloneVerifier.verify(assetPath, sigPath, pub);
    check("default DER P-384: verify SUCCEEDS", r.ok === true);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

// A forged/tampered signature is still rejected (fail-closed preserved).
function testForgedSigRejected() {
  var dir = _scratch("forged");
  try {
    var asset = Buffer.from("blamejs release — forged-sig rejection case");
    var forged = _forge96ByteDerSig(asset);
    // Flip a byte inside the DER signature body (corrupt s) — must NOT verify.
    var bad = Buffer.from(forged.sig);
    bad[bad.length - 1] ^= 0xff;
    var assetPath = _write(dir, "asset", asset);
    var sigPath = _write(dir, "asset.sig", bad);
    var threw = null;
    try { b.selfUpdate.standaloneVerifier.verify(assetPath, sigPath, forged.pubPem); }
    catch (e) { threw = e; }
    check("forged 96-byte DER sig: rejected (fail-closed)",
          threw && /signature INVALID/.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

// A 96-byte buffer that is neither a valid DER SEQUENCE nor a verifying raw
// sig is rejected (no acceptance leak from the structural dispatch).
function testGarbage96BytesRejected() {
  var dir = _scratch("garbage");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = Buffer.from("blamejs garbage-96 case");
    var assetPath = _write(dir, "asset", asset);
    var garbage = Buffer.alloc(96, 0x41);   // not 0x30, not a real raw sig
    var sigPath = _write(dir, "asset.sig", garbage);
    var threw = null;
    try { b.selfUpdate.standaloneVerifier.verify(assetPath, sigPath, pub); }
    catch (e) { threw = e; }
    check("garbage 96-byte sig: rejected (fail-closed)", threw !== null);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function run() {
  testEcdsaP384Der96Bytes();
  testEcdsaP384RawStillVerifies();
  testEcdsaP384DerDefaultStillVerifies();
  testForgedSigRejected();
  testGarbage96BytesRejected();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
