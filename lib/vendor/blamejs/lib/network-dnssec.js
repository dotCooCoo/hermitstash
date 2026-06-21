"use strict";
/**
 * @module b.network.dns.dnssec
 * @nav    Network
 * @title  DNSSEC validation
 *
 * @intro
 *   Local DNSSEC signature verification (RFC 4033–4035 / 6605 / 8080) —
 *   the cryptographic core that lets a resolver client verify a DNS
 *   answer itself instead of trusting the upstream resolver's AD bit.
 *   <code>b.network.dns.resolver</code> checks the AD flag; this module
 *   verifies the actual RRSIG signature over the canonicalised RRset,
 *   defending against a compromised or on-path resolver.
 *
 *   <code>verifyRrset</code> reconstructs the RFC 4034 §3.1.8.1 signed
 *   data (the RRSIG RDATA without the signature, followed by the RRset
 *   in canonical form — owner names lowercased, RRs ordered by canonical
 *   RDATA, the RRSIG's Original TTL) and verifies it with the DNSKEY,
 *   enforcing the signature's inception / expiration window. The DNSKEY
 *   algorithms are RSA/SHA-256 (8), ECDSA P-256/SHA-256 (13), ECDSA
 *   P-384/SHA-384 (14), and Ed25519 (15) — the modern, deployed set.
 *   <code>verifyDs</code> checks a delegation-signer digest against a
 *   DNSKEY (SHA-256 / SHA-384), and <code>keyTag</code> computes the
 *   RFC 4034 Appendix B key tag.
 *
 *   <strong>Scope.</strong> This is the verification core. RR types that
 *   carry domain names in their RDATA (NS, CNAME, SOA, MX, SRV, …) need
 *   name-lowercasing inside the RDATA (RFC 4034 §6.2) that this version
 *   does not perform, so they are refused with
 *   <code>dnssec/uncanonicalizable-type</code> rather than mis-validated
 *   — the security-critical DNSKEY / DS and the name-free address /
 *   text types (A, AAAA, TXT, …) are fully supported. The recursive
 *   chain-walk (root → TLD → zone via <code>verifyChain</code> against the
 *   bundled IANA root trust anchors) and NSEC / NSEC3 denial-of-existence
 *   (<code>verifyDenial</code> / <code>nsec3Hash</code>) ship alongside the
 *   per-RRset verification core.
 *
 * @card
 *   Local DNSSEC verification (RFC 4035 / 4034 / 5155) — verify an RRSIG
 *   over a canonicalised RRset against a DNSKEY (RSA / ECDSA P-256·P-384 /
 *   Ed25519) + DS-digest + key-tag, walk the root→zone chain to the IANA
 *   trust anchors, and check NSEC / NSEC3 denial of existence. Don't trust
 *   the upstream AD bit; verify the signature. Name-bearing RR types are
 *   refused, not mis-validated.
 */

var nodeCrypto = require("node:crypto");
var numericBounds = require("./numeric-bounds");
var bCrypto = require("./crypto");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DnssecError = defineClass("DnssecError", { alwaysPermanent: true });

// DNSSEC algorithm numbers (IANA DNSSEC Algorithm Numbers) → verify params.
var ALGS = {
  8:  { name: "RSASHA256",        kind: "rsa",   hash: "sha256" },                          // IANA DNSSEC algorithm number
  13: { name: "ECDSAP256SHA256",  kind: "ec",    hash: "sha256", crv: "P-256", coord: 32 },   // P-256 coordinate size
  14: { name: "ECDSAP384SHA384",  kind: "ec",    hash: "sha384", crv: "P-384", coord: 48 },   // P-384 coordinate size
  15: { name: "ED25519",          kind: "okp",   hash: null,     crv: "Ed25519" },
};

// DS digest algorithms (IANA) → node hash.
var DS_DIGESTS = { 2: "sha256", 4: "sha384" };

// RR types whose RDATA contains NO embedded domain name that needs
// downcasing, so the wire RDATA is already in canonical form (RFC 4034
// §6.2 needs no rewrite). Name-bearing types are refused rather than
// silently mis-canonicalised. NSEC (47) is included because RFC 6840
// §5.1 corrected RFC 4034 §6.2: the NSEC Next Domain Name field is NOT
// downcased for DNSSEC canonical form, so its uncompressed RDATA is
// verbatim-canonical. NSEC3 (50) carries a hashed next-owner, not a name.
// (type numbers IANA): A 1, AAAA 28, TXT 16, DNSKEY 48, DS 43, CAA 257,
// TLSA 52, SSHFP 44, HINFO 13, CDS 59, CDNSKEY 60, OPENPGPKEY 61, SMIMEA
// 53, NSEC 47, NSEC3 50.
var NAME_FREE_TYPE_NUMS = [1, 28, 16, 48, 43, 257, 52, 44, 13, 59, 60, 61, 53, 47, 50];  // allow:raw-time-literal — IANA DNS type numbers (no downcased embedded names)
var TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  DS: 43, SSHFP: 44, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52,            // allow:raw-time-literal — IANA DNS type numbers
  SMIMEA: 53, CDS: 59, CDNSKEY: 60, OPENPGPKEY: 61, CAA: 257, HINFO: 13,
};

// DNSSEC wire data is bytes, never text (allowString:false).
var _bytes = safeBuffer.makeByteCoercer({
  errorClass:    DnssecError,
  typeCode:      "dnssec/bad-bytes",
  messagePrefix: "dnssec: ",
  messageSuffix: " must be a Buffer",
  allowString:   false,
});

// Canonical wire form of a domain name (RFC 4034 §6.2): each label
// length-prefixed, ASCII lowercased, terminated by the root label.
function _canonicalName(name) {
  if (typeof name !== "string") throw new DnssecError("dnssec/bad-name", "dnssec: name must be a string");
  var n = name.replace(/\.$/, "");
  if (n === "") return Buffer.from([0]);
  var labels = n.split(".");
  var parts = [];
  for (var i = 0; i < labels.length; i++) {
    var lab = Buffer.from(labels[i].toLowerCase(), "ascii");
    if (lab.length === 0 || lab.length > 63) {                                          // DNS label length cap (RFC 1035)
      throw new DnssecError("dnssec/bad-name", "dnssec: invalid label in '" + name + "'");
    }
    parts.push(Buffer.from([lab.length]), lab);
  }
  parts.push(Buffer.from([0]));
  var wire = Buffer.concat(parts);
  // RFC 1035 §2.3.4 — a domain name is at most 255 octets on the wire.
  // Enforcing it here also bounds the per-label count (and thus the NSEC3
  // closest-encloser candidate enumeration, CVE-2023-50868 class), since
  // each label costs at least 2 octets.
  if (wire.length > 255) {                                                               // RFC 1035 total-name octet cap
    throw new DnssecError("dnssec/bad-name",
      "dnssec: name '" + name + "' encodes to " + wire.length + " octets, exceeds RFC 1035 cap of 255");
  }
  return wire;
}

function _u16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }                    // 16-bit big-endian split
function _u32(n) {
  var b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function _typeNumber(type) {
  if (typeof type === "number") return type;
  var t = TYPE_NUM[String(type).toUpperCase()];
  if (t === undefined) throw new DnssecError("dnssec/unknown-type", "dnssec: unknown RR type '" + type + "'");
  return t;
}

// DNSKEY public-key RDATA → JWK (kty/crv allowlisted; RFC 3110 RSA,
// RFC 6605 ECDSA, RFC 8080 Ed25519). publicKey is the key bytes after
// the DNSKEY flags/protocol/algorithm fields.
function _dnskeyToKey(algId, publicKey) {
  var alg = ALGS[algId];
  if (!alg) throw new DnssecError("dnssec/unsupported-alg", "dnssec: unsupported DNSKEY algorithm " + algId);
  var pk = _bytes(publicKey, "dnskey publicKey");
  if (alg.kind === "rsa") {
    // RFC 3110: exponent length is 1 byte, or (if that byte is 0) the
    // next 2 bytes; then exponent, then modulus.
    var off = 0, explen = pk[0];
    off = 1;
    if (explen === 0) { explen = (pk[1] << 8) | pk[2]; off = 3; }                        // RFC 3110 3-byte exponent length
    if (explen === 0 || off + explen >= pk.length) {
      throw new DnssecError("dnssec/bad-key", "dnssec: malformed RSA DNSKEY public key");
    }
    var exponent = pk.slice(off, off + explen);
    var modulus = pk.slice(off + explen);
    return _jwkKey({ kty: "RSA", n: modulus.toString("base64url"), e: exponent.toString("base64url") });
  }
  if (alg.kind === "ec") {
    if (pk.length !== alg.coord * 2) {
      throw new DnssecError("dnssec/bad-key", "dnssec: " + alg.crv + " key must be " + (alg.coord * 2) + " bytes (x||y)");
    }
    return _jwkKey({ kty: "EC", crv: alg.crv, x: pk.slice(0, alg.coord).toString("base64url"), y: pk.slice(alg.coord).toString("base64url") });
  }
  // Ed25519
  if (pk.length !== 32) throw new DnssecError("dnssec/bad-key", "dnssec: Ed25519 key must be 32 bytes");   // Ed25519 key size
  return _jwkKey({ kty: "OKP", crv: "Ed25519", x: pk.toString("base64url") });
}
function _jwkKey(jwk) {
  return bCrypto.importPublicJwk(jwk, {
    errorClass:    DnssecError,
    code:          "dnssec/bad-key",
    messagePrefix: "dnssec: could not import DNSKEY: ",
  });
}

/**
 * @primitive b.network.dns.dnssec.keyTag
 * @signature b.network.dns.dnssec.keyTag(dnskeyRdata)
 * @since     0.12.48
 * @status    stable
 * @related   b.network.dns.dnssec.verifyDs, b.network.dns.dnssec.verifyRrset
 *
 * Compute the RFC 4034 Appendix B key tag of a DNSKEY from its full
 * RDATA (flags || protocol || algorithm || public key) — the 16-bit
 * identifier an RRSIG / DS references to select the signing key.
 *
 * @example
 *   var tag = b.network.dns.dnssec.keyTag(dnskeyRdata);
 */
function keyTag(dnskeyRdata) {
  var rd = _bytes(dnskeyRdata, "dnskeyRdata");
  var acc = 0;
  for (var i = 0; i < rd.length; i++) {
    acc += (i & 1) ? rd[i] : (rd[i] << 8);                                               // RFC 4034 App B key-tag accumulation
  }
  acc += (acc >> 16) & 0xffff;                                                           // App B fold
  return acc & 0xffff;                                                                   // App B 16-bit tag
}

/**
 * @primitive b.network.dns.dnssec.verifyDs
 * @signature b.network.dns.dnssec.verifyDs(opts)
 * @since     0.12.48
 * @status    stable
 * @related   b.network.dns.dnssec.verifyRrset
 *
 * Verify a DS (Delegation Signer) record against a child DNSKEY — the
 * link that lets a parent zone vouch for a child's key. The DS digest
 * (SHA-256 / SHA-384) is recomputed over the owner name plus the DNSKEY
 * RDATA and compared to the DS, with the key tag and algorithm checked.
 *
 * @opts
 *   {
 *     ownerName:    string,   // the child zone name (the DNSKEY owner)
 *     dnskeyRdata:  Buffer,   // full DNSKEY RDATA (flags||protocol||alg||publicKey)
 *     ds: { keyTag, algorithm, digestType, digest: Buffer },  // the parent DS
 *   }
 *
 * @example
 *   b.network.dns.dnssec.verifyDs({ ownerName: "example.com", dnskeyRdata: ksk, ds: parentDs });
 */
function verifyDs(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyDs", DnssecError);
  validateOpts(opts, ["ownerName", "dnskeyRdata", "ds"], "dnssec.verifyDs");
  var ds = opts.ds;
  if (!ds || typeof ds !== "object") throw new DnssecError("dnssec/bad-ds", "dnssec.verifyDs: opts.ds is required");
  var hashName = DS_DIGESTS[ds.digestType];
  if (!hashName) throw new DnssecError("dnssec/unsupported-digest", "dnssec.verifyDs: unsupported DS digest type " + ds.digestType);
  var rd = _bytes(opts.dnskeyRdata, "dnskeyRdata");
  if (keyTag(rd) !== ds.keyTag) {
    throw new DnssecError("dnssec/keytag-mismatch", "dnssec.verifyDs: DNSKEY key tag does not match the DS");
  }
  var digestInput = Buffer.concat([_canonicalName(opts.ownerName), rd]);
  var expected = nodeCrypto.createHash(hashName).update(digestInput).digest();
  var actual = _bytes(ds.digest, "ds.digest");
  if (!bCrypto.timingSafeEqual(expected, actual)) {
    throw new DnssecError("dnssec/ds-mismatch", "dnssec.verifyDs: DS digest does not match the DNSKEY");
  }
  return { ok: true, keyTag: ds.keyTag, digestType: ds.digestType };
}

/**
 * @primitive b.network.dns.dnssec.verifyRrset
 * @signature b.network.dns.dnssec.verifyRrset(opts)
 * @since     0.12.48
 * @status    stable
 * @compliance soc2
 * @related   b.network.dns.dnssec.verifyDs, b.network.dns.resolver.create
 *
 * Verify an RRSIG over an RRset against a DNSKEY (RFC 4035 §5.3). The
 * signed data is reconstructed in canonical form — the RRSIG RDATA
 * without the signature, then the RRset's records ordered by canonical
 * RDATA with the RRSIG Original TTL — and the signature is verified with
 * the DNSKEY (RSA/SHA-256, ECDSA P-256/384, Ed25519). The signature's
 * inception / expiration window is enforced against <code>opts.at</code>.
 * RR types carrying embedded domain names are refused
 * (<code>dnssec/uncanonicalizable-type</code>) rather than mis-validated.
 *
 * @opts
 *   {
 *     name:    string,    // owner name of the RRset
 *     type:    string|number, // RR type (e.g. "DNSKEY", "A")
 *     class?:  number,    // default 1 (IN)
 *     rdatas:  Buffer[],  // each record's wire-format RDATA
 *     rrsig: {            // the RRSIG covering the RRset
 *       algorithm, labels, originalTtl, expiration, inception, keyTag,
 *       signerName: string, signature: Buffer,
 *     },
 *     dnskey: { algorithm, publicKey: Buffer },  // the signing DNSKEY (publicKey = bytes after flags/proto/alg)
 *     at?:     Date,      // validity instant (default now); must be a valid Date
 *   }
 *
 * @example
 *   b.network.dns.dnssec.verifyRrset({ name: "example.com", type: "DNSKEY", rdatas: keys, rrsig: sig, dnskey: ksk });
 */
function verifyRrset(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyRrset", DnssecError);
  validateOpts(opts, ["name", "type", "class", "rdatas", "rrsig", "dnskey", "at"], "dnssec.verifyRrset");
  var rrsig = opts.rrsig;
  var dnskey = opts.dnskey;
  if (!rrsig || typeof rrsig !== "object") throw new DnssecError("dnssec/bad-rrsig", "dnssec.verifyRrset: opts.rrsig is required");
  if (!dnskey || typeof dnskey !== "object") throw new DnssecError("dnssec/bad-key", "dnssec.verifyRrset: opts.dnskey is required");
  if (!Array.isArray(opts.rdatas) || opts.rdatas.length === 0) {
    throw new DnssecError("dnssec/empty-rrset", "dnssec.verifyRrset: opts.rdatas must be a non-empty array");
  }
  var alg = ALGS[rrsig.algorithm];
  if (!alg) throw new DnssecError("dnssec/unsupported-alg", "dnssec.verifyRrset: unsupported algorithm " + rrsig.algorithm);
  if (dnskey.algorithm !== rrsig.algorithm) {
    throw new DnssecError("dnssec/alg-mismatch", "dnssec.verifyRrset: DNSKEY algorithm does not match the RRSIG");
  }

  var typeNum = _typeNumber(opts.type);
  if (NAME_FREE_TYPE_NUMS.indexOf(typeNum) === -1) {
    throw new DnssecError("dnssec/uncanonicalizable-type",
      "dnssec.verifyRrset: RR type " + typeNum + " carries embedded names; RDATA-name canonicalisation is not supported (refused, not mis-validated)");
  }

  // Validity window (fail closed on a bad opts.at).
  validateOpts.optionalDate(opts.at, "dnssec.verifyRrset: opts.at", DnssecError, "dnssec/bad-at");
  var atMs = (opts.at !== undefined && opts.at !== null) ? opts.at.getTime() : Date.now();
  var nowSec = Math.floor(atMs / 1000);
  if (nowSec < (rrsig.inception >>> 0)) throw new DnssecError("dnssec/not-yet-valid", "dnssec.verifyRrset: RRSIG inception is in the future");
  if (nowSec > (rrsig.expiration >>> 0)) throw new DnssecError("dnssec/expired", "dnssec.verifyRrset: RRSIG has expired");

  var klass = typeof opts.class === "number" ? opts.class : 1;
  var ownerWire = _canonicalName(opts.name);
  var ttl = _u32(rrsig.originalTtl);

  // Canonical RRset (RFC 4034 §6.3): order records by canonical RDATA.
  var rdatas = opts.rdatas.map(function (r, i) { return _bytes(r, "rdatas[" + i + "]"); });
  var sorted = rdatas.slice().sort(Buffer.compare);
  var rrParts = [];
  for (var i = 0; i < sorted.length; i++) {
    rrParts.push(ownerWire, _u16(typeNum), _u16(klass), ttl, _u16(sorted[i].length), sorted[i]);
  }

  // RRSIG RDATA without the signature (RFC 4034 §3.1.8.1).
  var rrsigPrefix = Buffer.concat([
    _u16(typeNum), Buffer.from([rrsig.algorithm & 0xff, rrsig.labels & 0xff]),           // single-octet alg + labels fields
    _u32(rrsig.originalTtl), _u32(rrsig.expiration), _u32(rrsig.inception),
    _u16(rrsig.keyTag), _canonicalName(rrsig.signerName),
  ]);
  var signedData = Buffer.concat([rrsigPrefix].concat(rrParts));

  var key = _dnskeyToKey(dnskey.algorithm, dnskey.publicKey);
  var signature = _bytes(rrsig.signature, "rrsig.signature");
  var ok;
  try {
    if (alg.kind === "okp") {
      ok = nodeCrypto.verify(null, signedData, key, signature);
    } else if (alg.kind === "ec") {
      ok = nodeCrypto.verify(alg.hash, signedData, { key: key, dsaEncoding: "ieee-p1363" }, signature);
    } else {
      ok = nodeCrypto.verify(alg.hash, signedData, key, signature);
    }
  } catch (e) {
    throw new DnssecError("dnssec/verify-threw", "dnssec.verifyRrset: signature verification threw: " + ((e && e.message) || e));
  }
  if (!ok) throw new DnssecError("dnssec/bad-signature", "dnssec.verifyRrset: RRSIG signature did not verify");
  return { ok: true, algorithm: alg.name, keyTag: rrsig.keyTag, signerName: rrsig.signerName };
}

// ---------------------------------------------------------------------------
// Denial of existence (RFC 4034 §4 NSEC, RFC 5155 NSEC3).
//
// These helpers prove a name (or a name+type) DOES NOT EXIST from the
// signed NSEC / NSEC3 records a server returns in the Authority section.
// They operate on records the caller has ALREADY verified with
// verifyRrset — like verifyDs, this is the relation check, not the
// signature check. Passing unverified records proves nothing.
// ---------------------------------------------------------------------------

var BASE32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV";          // RFC 4648 §7 extended-hex alphabet (RFC number in comment)
var TYPE_DS = 43;                                            // IANA RR type DS
var TYPE_CNAME = 5;
var NSEC3_HASH_SHA1 = 1;                                     // RFC 5155 §5 — the only registered NSEC3 hash
var DEFAULT_MAX_NSEC3_ITERATIONS = 150;

// KeyTrap (CVE-2023-50387) amplification caps. A hostile zone can publish
// many DNSKEYs sharing one 16-bit key tag and many RRSIGs, forcing a
// validator into O(keys x sigs) full signature verifications from a single
// query. Bound both factors: the colliding-candidate fan-out per RRSIG, and
// the total signature-validation work. Matches the BIND
// `max-key-tag-collisions` + Unbound validation-budget mitigations.
//
// The per-response budget SCALES with declared chain depth so a legitimate
// deep delegation isn't false-rejected: a valid N-link chain does ~2N-1
// signature verifies (1 root DNSKEY + parent-DS + child-DNSKEY per child),
// so the budget is links.length * MAX_VALIDATIONS_PER_LINK (= 2 RRSIGs/link
// x MAX_COLLIDING_KEYS candidates), which always covers the legitimate work
// while still bounding the bounded-collision amplification. Chain length
// itself is capped (a delegation can't be deeper than a DNS name's label
// count, RFC 1035), so the scaled budget can't be inflated arbitrarily.
var MAX_COLLIDING_KEYS       = 4;                            // same-tag DNSKEY candidates tried per RRSIG
var MAX_VALIDATIONS_PER_LINK = 8;                            // 2 RRSIGs/link x MAX_COLLIDING_KEYS; budget = links.length x this
var MAX_CHAIN_LINKS          = 128;                          // max delegation depth (>= RFC 1035 max label count)
var MAX_DNSKEYS_PER_ZONE     = 64;                           // DNSKEY RRset size cap per zone link
var MAX_DS_RECORDS           = 16;                           // DS RRset size cap (parent-supplied)

// RFC 4648 §7 base32hex decode (no padding, case-insensitive) — the
// label encoding of an NSEC3 owner-name hash.
function _base32hexDecode(s, label) {
  var up = String(s).toUpperCase();
  var bits = 0, value = 0, out = [];
  for (var i = 0; i < up.length; i++) {
    var idx = BASE32HEX.indexOf(up[i]);
    if (idx === -1) throw new DnssecError("dnssec/bad-nsec3", "dnssec: " + label + " is not valid base32hex");
    value = (value << 5) | idx;                              // base32 5-bit group
    bits += 5;                                               // base32 5-bit group
    if (bits >= 8) { bits -= 8; out.push((value >> bits) & 0xff); }   // emit a full octet
  }
  return Buffer.from(out);
}

// RFC 4034 §4.1.2 / RFC 5155 §3.2.1 type bitmap → Set of type numbers.
function _parseTypeBitmaps(buf, off, end) {
  var types = new Set();
  var i = off;
  while (i + 2 <= end) {
    var win = buf[i], len = buf[i + 1];
    i += 2;
    if (len < 1 || len > 32 || i + len > end) {              // bitmap window ≤ 256 bits = 32 octets (RFC 4034 §4.1.2)
      throw new DnssecError("dnssec/bad-bitmap", "dnssec: malformed NSEC type bitmap");
    }
    for (var j = 0; j < len; j++) {
      var octet = buf[i + j];
      for (var bit = 0; bit < 8; bit++) {                    // 8 bits per octet
        if (octet & (0x80 >> bit)) types.add(win * 256 + j * 8 + bit);   // bit→type-number (window*256 + octet*8 + bit)
      }
    }
    i += len;
  }
  return types;
}

// Read an uncompressed wire-format domain name (compression pointers are
// illegal in signed RDATA). Returns { name, end }.
function _readWireName(buf, off) {
  var labels = [];
  var i = off;
  for (;;) {
    if (i >= buf.length) throw new DnssecError("dnssec/bad-name", "dnssec: truncated name in RDATA");
    var len = buf[i];
    if (len === 0) { i++; break; }
    if ((len & 0xc0) !== 0) throw new DnssecError("dnssec/bad-name", "dnssec: compression pointer in signed RDATA");   // RFC 1035 label-length top-two-bits flag
    i++;
    labels.push(buf.slice(i, i + len).toString("ascii"));
    i += len;
  }
  return { name: labels.length ? labels.join(".") + "." : ".", end: i };
}

function _parseNsec3Rdata(rd) {
  if (rd.length < 6) throw new DnssecError("dnssec/bad-nsec3", "dnssec: NSEC3 RDATA too short");   // fixed NSEC3 header octets
  var hashAlg = rd[0], flags = rd[1], iterations = rd.readUInt16BE(2), saltLen = rd[4];
  var off = 5 + saltLen;
  if (off + 1 > rd.length) throw new DnssecError("dnssec/bad-nsec3", "dnssec: NSEC3 salt overruns RDATA");
  var salt = rd.slice(5, 5 + saltLen);
  var hashLen = rd[off]; off += 1;
  if (off + hashLen > rd.length) throw new DnssecError("dnssec/bad-nsec3", "dnssec: NSEC3 next-hashed-owner overruns RDATA");
  var nextHashed = rd.slice(off, off + hashLen);
  return { hashAlg: hashAlg, flags: flags, iterations: iterations, salt: salt, nextHashed: nextHashed, types: _parseTypeBitmaps(rd, off + hashLen, rd.length) };
}

function _parseNsecRdata(rd) {
  var n = _readWireName(rd, 0);
  return { nextName: n.name, types: _parseTypeBitmaps(rd, n.end, rd.length) };
}

// RFC 5155 §5 iterated hash: IH(salt, x, 0)=SHA-1(x‖salt);
// IH(salt, x, k)=SHA-1(IH(salt,x,k-1)‖salt). SHA-1 is the only NSEC3
// hash IANA defines — a wire-protocol constant, not a framework default.
function _nsec3HashWire(nameWire, salt, iterations) {
  var h = nodeCrypto.createHash("sha1").update(Buffer.concat([nameWire, salt])).digest();
  for (var k = 0; k < iterations; k++) {
    h = nodeCrypto.createHash("sha1").update(Buffer.concat([h, salt])).digest();
  }
  return h;
}

function _nameLabels(name) {
  var n = String(name).replace(/\.$/, "");
  return n === "" ? [] : n.split(".");
}

// RFC 4034 §6.1 canonical name ordering: compare label sequences from
// the least-significant (rightmost) label, octets lowercased.
function _canonicalNameCompare(a, b) {
  var la = _nameLabels(a).reverse(), lb = _nameLabels(b).reverse();
  var min = Math.min(la.length, lb.length);
  for (var i = 0; i < min; i++) {
    var c = Buffer.compare(Buffer.from(la[i].toLowerCase(), "ascii"), Buffer.from(lb[i].toLowerCase(), "ascii"));
    if (c !== 0) return c;
  }
  return la.length - lb.length;
}

// Closest-encloser candidates: proper suffixes of qname from longest
// (qname minus one label) down to the zone apex, longest first.
function _closestEncloserCandidates(qname, zone) {
  var ql = _nameLabels(qname), zl = _nameLabels(zone);
  var out = [];
  for (var k = ql.length - 1; k >= zl.length; k--) {
    out.push(ql.slice(ql.length - k).join(".") + ".");
  }
  return out;
}

// The "next closer" name: the closest encloser with one more label of
// qname prepended (RFC 5155 §1.3).
function _nextCloser(qname, ce) {
  var ql = _nameLabels(qname), n = _nameLabels(ce).length + 1;
  return ql.slice(ql.length - n).join(".") + ".";
}

/**
 * @primitive b.network.dns.dnssec.nsec3Hash
 * @signature b.network.dns.dnssec.nsec3Hash(name, opts)
 * @since     0.12.49
 * @status    stable
 * @related   b.network.dns.dnssec.verifyDenial
 *
 * Compute the RFC 5155 §5 NSEC3 hash of a name — iterated SHA-1 over the
 * canonical (lowercased, root-terminated) wire form with the zone's salt.
 * The result is the unencoded hash; the NSEC3 owner label is its
 * base32hex encoding. SHA-1 is the only hash IANA registers for NSEC3,
 * so this is a wire-protocol constant, not a cryptographic default.
 *
 * @opts
 *   {
 *     salt:        Buffer,  // zone NSEC3 salt (may be empty)
 *     iterations:  number,  // additional hash iterations (>= 0)
 *   }
 *
 * @example
 *   var h = b.network.dns.dnssec.nsec3Hash("a.example.com", { salt: salt, iterations: 0 });
 */
function nsec3Hash(name, opts) {
  validateOpts.requireObject(opts, "dnssec.nsec3Hash", DnssecError);
  validateOpts(opts, ["salt", "iterations"], "dnssec.nsec3Hash");
  var salt = _bytes(opts.salt, "salt");
  var iters = opts.iterations;
  if (!numericBounds.isNonNegativeFiniteInt(iters)) {
    throw new DnssecError("dnssec/bad-iterations", "dnssec.nsec3Hash: iterations must be a non-negative integer");
  }
  return _nsec3HashWire(_canonicalName(name), salt, iters);
}

/**
 * @primitive b.network.dns.dnssec.verifyDenial
 * @signature b.network.dns.dnssec.verifyDenial(opts)
 * @since     0.12.49
 * @status    stable
 * @compliance soc2
 * @related   b.network.dns.dnssec.verifyRrset, b.network.dns.dnssec.nsec3Hash
 *
 * Prove that a name does not exist (NXDOMAIN) or that a name has no
 * records of a given type (NODATA) from the signed NSEC (RFC 4034 §4) or
 * NSEC3 (RFC 5155) records in a response's Authority section. This is the
 * other half of "verify the answer yourself": <code>verifyRrset</code>
 * proves a positive answer, <code>verifyDenial</code> proves a negative.
 *
 * The records MUST already be verified with <code>verifyRrset</code> —
 * this checks the denial RELATION (closest-encloser, covering ranges,
 * type-bitmap absence), not the signatures. For NSEC3, the iterated-hash
 * count is capped (<code>opts.maxIterations</code>, default 500) to bound
 * the SHA-1 work an attacker can force. An NXDOMAIN proof that relies on
 * an Opt-Out NSEC3 (RFC 5155 §6) is refused unless
 * <code>opts.allowOptOut</code> — opt-out only proves "no signed records",
 * not non-existence.
 *
 * @opts
 *   {
 *     qname:   string,        // the queried name
 *     qtype:   string|number, // queried type (required for proof "nodata")
 *     proof:   string,        // "nxdomain" | "nodata"
 *     zone:    string,        // the signer zone apex (a suffix of qname)
 *     nsec3?:  [ { owner: string, rdata: Buffer } ],  // NSEC3 records (owner = base32hex-label.zone)
 *     nsec?:   [ { owner: string, rdata: Buffer } ],  // NSEC records
 *     maxIterations?: number, // NSEC3 iteration cap (default 500)
 *     allowOptOut?:   boolean, // accept an Opt-Out NXDOMAIN proof (default false)
 *   }
 *
 * @example
 *   b.network.dns.dnssec.verifyDenial({
 *     qname: "nope.example.com", proof: "nxdomain", zone: "example.com", nsec3: records,
 *   });
 */
function verifyDenial(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyDenial", DnssecError);
  validateOpts(opts, ["qname", "qtype", "proof", "zone", "nsec3", "nsec", "maxIterations", "allowOptOut"], "dnssec.verifyDenial");
  if (typeof opts.qname !== "string" || opts.qname === "") throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: opts.qname is required");
  if (typeof opts.zone !== "string" || opts.zone === "") throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: opts.zone is required");
  if (opts.proof !== "nxdomain" && opts.proof !== "nodata") throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: opts.proof must be 'nxdomain' or 'nodata'");
  var zl = _nameLabels(opts.zone), ql = _nameLabels(opts.qname);
  if (zl.length > ql.length || zl.join(".").toLowerCase() !== ql.slice(ql.length - zl.length).join(".").toLowerCase()) {
    throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: opts.zone must be a suffix of opts.qname");
  }
  var qtypeNum;
  if (opts.proof === "nodata") {
    if (opts.qtype === undefined || opts.qtype === null) throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: opts.qtype is required for a nodata proof");
    qtypeNum = _typeNumber(opts.qtype);
  } else if (opts.qtype !== undefined && opts.qtype !== null) {
    qtypeNum = _typeNumber(opts.qtype);
  }

  var hasNsec3 = Array.isArray(opts.nsec3) && opts.nsec3.length > 0;
  var hasNsec = Array.isArray(opts.nsec) && opts.nsec.length > 0;
  if (hasNsec3 === hasNsec) {
    throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: supply exactly one of opts.nsec3 or opts.nsec");
  }
  return hasNsec3 ? _verifyNsec3Denial(opts, qtypeNum) : _verifyNsecDenial(opts, qtypeNum);
}

function _verifyNsec3Denial(opts, qtypeNum) {
  var maxIter = typeof opts.maxIterations === "number" ? opts.maxIterations : DEFAULT_MAX_NSEC3_ITERATIONS;
  if (typeof maxIter !== "number" || !isFinite(maxIter) || maxIter < 0) throw new DnssecError("dnssec/bad-arg", "dnssec.verifyDenial: maxIterations must be a non-negative number");

  // Parse + sanity-check every NSEC3 record; the chain shares one salt /
  // iteration / hash-algorithm tuple.
  var recs = opts.nsec3.map(function (r, i) {
    if (!r || typeof r.owner !== "string") throw new DnssecError("dnssec/bad-nsec3", "dnssec.verifyDenial: nsec3[" + i + "].owner must be a string");
    var rd = _bytes(r.rdata, "nsec3[" + i + "].rdata");
    var p = _parseNsec3Rdata(rd);
    if (p.hashAlg !== NSEC3_HASH_SHA1) throw new DnssecError("dnssec/unsupported-nsec3-hash", "dnssec.verifyDenial: NSEC3 hash algorithm " + p.hashAlg + " is not supported (only SHA-1 / 1 is defined)");
    if (p.iterations > maxIter) throw new DnssecError("dnssec/nsec3-iterations-excessive", "dnssec.verifyDenial: NSEC3 iterations " + p.iterations + " exceed the cap " + maxIter);
    var firstLabel = _nameLabels(r.owner)[0];
    if (!firstLabel) throw new DnssecError("dnssec/bad-nsec3", "dnssec.verifyDenial: nsec3[" + i + "].owner has no hash label");
    return { ownerHash: _base32hexDecode(firstLabel, "nsec3[" + i + "].owner"), p: p };
  });
  var salt = recs[0].p.salt, iterations = recs[0].p.iterations;
  for (var s = 1; s < recs.length; s++) {
    if (recs[s].p.iterations !== iterations || Buffer.compare(recs[s].p.salt, salt) !== 0) {
      throw new DnssecError("dnssec/nsec3-param-mismatch", "dnssec.verifyDenial: NSEC3 records disagree on salt / iterations");
    }
  }

  function hashOf(name) { return _nsec3HashWire(_canonicalName(name), salt, iterations); }
  function findMatch(name) {
    var h = hashOf(name);
    for (var i = 0; i < recs.length; i++) if (Buffer.compare(recs[i].ownerHash, h) === 0) return recs[i];
    return null;
  }
  function findCover(name) {
    var h = hashOf(name);
    for (var i = 0; i < recs.length; i++) {
      var owner = recs[i].ownerHash, next = recs[i].p.nextHashed;
      var oc = Buffer.compare(owner, next);
      var covered = oc < 0
        ? (Buffer.compare(owner, h) < 0 && Buffer.compare(h, next) < 0)
        : (Buffer.compare(owner, h) < 0 || Buffer.compare(h, next) < 0);   // last NSEC3 wraps past the apex
      if (covered) return recs[i];
    }
    return null;
  }

  if (opts.proof === "nodata") {
    // RFC 5155 §8.5 — a matching NSEC3 with the type (and CNAME) absent.
    var m = findMatch(opts.qname);
    if (m) {
      if (qtypeNum === TYPE_DS) {
        if (m.p.types.has(TYPE_DS)) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: DS is present in the matching NSEC3 bitmap");
        return { ok: true, proof: "nodata", mechanism: "nsec3", matched: true };
      }
      if (m.p.types.has(qtypeNum)) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: type " + qtypeNum + " is present in the matching NSEC3 bitmap");
      if (m.p.types.has(TYPE_CNAME)) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: name is a CNAME (query should have been redirected)");
      return { ok: true, proof: "nodata", mechanism: "nsec3", matched: true };
    }
    // RFC 5155 §8.6 — Opt-Out DS NODATA: a covering NSEC3 with Opt-Out set
    // proves an insecure delegation has no DS.
    if (qtypeNum === TYPE_DS) {
      var ce = _nsec3ClosestEncloser(opts, recs, findMatch);
      if (ce) {
        var nc = _nextCloser(opts.qname, ce);
        var cov = findCover(nc);
        if (cov && (cov.p.flags & 1) === 1) return { ok: true, proof: "nodata", mechanism: "nsec3", matched: false, optOut: true };
      }
    }
    // RFC 5155 §8.7 — wildcard NODATA: closest encloser proof + a matching
    // wildcard NSEC3 with the type absent.
    var ce2 = _nsec3ClosestEncloser(opts, recs, findMatch);
    if (ce2) {
      var wc = findMatch("*." + ce2);
      if (wc && !wc.p.types.has(qtypeNum) && !wc.p.types.has(TYPE_CNAME)) {
        return { ok: true, proof: "nodata", mechanism: "nsec3", matched: false, wildcard: true, closestEncloser: ce2 };
      }
    }
    throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: no matching NSEC3 proves NODATA for the queried type");
  }

  // NXDOMAIN (RFC 5155 §8.4): matching closest encloser + covered next
  // closer + covered wildcard. Opt-Out on the next-closer cover only
  // proves "no signed records", so it is refused unless allowOptOut.
  var ceName = _nsec3ClosestEncloser(opts, recs, findMatch);
  if (!ceName) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: no NSEC3 matches any closest-encloser candidate");
  var nextCloser = _nextCloser(opts.qname, ceName);
  var ncCover = findCover(nextCloser);
  if (!ncCover) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: the next-closer name is not covered by any NSEC3");
  var optOut = (ncCover.p.flags & 1) === 1;
  if (optOut && !opts.allowOptOut) throw new DnssecError("dnssec/denial-opt-out", "dnssec.verifyDenial: NXDOMAIN relies on an Opt-Out NSEC3 (set allowOptOut to accept it as 'no signed records')");
  // The wildcard at the closest encloser must be proven NON-EXISTENT
  // (covered). A MATCHING wildcard means it exists, so the name should
  // have been wildcard-synthesised and NXDOMAIN would be a forgery.
  if (!findCover("*." + ceName)) {
    throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: the wildcard at the closest encloser is not covered (a matching wildcard would mean the name should have been synthesised)");
  }
  return { ok: true, proof: "nxdomain", mechanism: "nsec3", closestEncloser: ceName, optOut: optOut };
}

function _nsec3ClosestEncloser(opts, recs, findMatch) {
  var cands = _closestEncloserCandidates(opts.qname, opts.zone);
  for (var i = 0; i < cands.length; i++) if (findMatch(cands[i])) return cands[i];
  return null;
}

function _verifyNsecDenial(opts, qtypeNum) {
  var recs = opts.nsec.map(function (r, i) {
    if (!r || typeof r.owner !== "string") throw new DnssecError("dnssec/bad-nsec", "dnssec.verifyDenial: nsec[" + i + "].owner must be a string");
    return { owner: r.owner, p: _parseNsecRdata(_bytes(r.rdata, "nsec[" + i + "].rdata")) };
  });
  function findMatch(name) {
    for (var i = 0; i < recs.length; i++) if (_canonicalNameCompare(recs[i].owner, name) === 0) return recs[i];
    return null;
  }
  function findCover(name) {
    for (var i = 0; i < recs.length; i++) {
      var owner = recs[i].owner, next = recs[i].p.nextName;
      var oc = _canonicalNameCompare(owner, next);
      var afterOwner = _canonicalNameCompare(owner, name) < 0;
      var covered = oc < 0
        ? (afterOwner && _canonicalNameCompare(name, next) < 0)
        : afterOwner;   // last NSEC (next wraps to apex): any name after owner
      if (covered) return recs[i];
    }
    return null;
  }

  if (opts.proof === "nodata") {
    var m = findMatch(opts.qname);
    if (!m) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: no NSEC matches the queried name");
    if (m.p.types.has(qtypeNum)) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: type " + qtypeNum + " is present in the matching NSEC bitmap");
    if (qtypeNum !== TYPE_CNAME && m.p.types.has(TYPE_CNAME)) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: name is a CNAME (query should have been redirected)");
    return { ok: true, proof: "nodata", mechanism: "nsec", matched: true };
  }

  // NXDOMAIN (RFC 4035 §5.4): an NSEC covering qname AND an NSEC proving
  // the source-of-synthesis wildcard does not exist.
  var cover = findCover(opts.qname);
  if (!cover) throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: no NSEC covers the queried name");
  // The closest encloser is the longest common ancestor of qname and the
  // covering NSEC's owner/next; the wildcard sits one label below it.
  var ce = _nsecClosestEncloser(opts.qname, cover);
  // The source-of-synthesis wildcard must be proven NON-EXISTENT
  // (covered). A MATCHING wildcard owner means it exists, so the query
  // should have been answered by wildcard expansion, not NXDOMAIN.
  var wildcard = "*." + ce;
  if (!findCover(wildcard)) {
    throw new DnssecError("dnssec/denial-not-proven", "dnssec.verifyDenial: the wildcard at the closest encloser is not covered (a matching wildcard would mean the name should have been synthesised)");
  }
  return { ok: true, proof: "nxdomain", mechanism: "nsec", closestEncloser: ce };
}

// The closest encloser for an NSEC NXDOMAIN proof is the longest name
// that is a suffix of qname and an ancestor of both the covering NSEC's
// owner and its next name (RFC 4035 §5.3.4 / §5.4).
function _nsecClosestEncloser(qname, cover) {
  var ql = _nameLabels(qname);
  var a = _commonSuffixLen(qname, cover.owner);
  var b = _commonSuffixLen(qname, cover.p.nextName);
  var ceLen = Math.max(a, b);
  return ql.slice(ql.length - ceLen).join(".") + ".";
}

function _commonSuffixLen(a, b) {
  var la = _nameLabels(a).reverse(), lb = _nameLabels(b).reverse();
  var n = 0, min = Math.min(la.length, lb.length);
  while (n < min && la[n].toLowerCase() === lb[n].toLowerCase()) n++;
  return n;
}

// ---------------------------------------------------------------------------
// Chain validation (RFC 4035 §5) — walk a delegation chain root → … → zone,
// anchoring at a pinned trust anchor.
// ---------------------------------------------------------------------------

// IANA root zone trust anchors (DS / SHA-256). KSK-2017 (tag 20326) and
// KSK-2024 (tag 38696), published at data.iana.org/root-anchors. An
// operator pins their own via opts.trustAnchors.
var DEFAULT_ROOT_ANCHORS = [
  { keyTag: 20326, algorithm: 8, digestType: 2, digest: Buffer.from("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "hex") },   // IANA root KSK-2017 DS
  { keyTag: 38696, algorithm: 8, digestType: 2, digest: Buffer.from("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", "hex") },   // IANA root KSK-2024 DS
];

function _dnskeyParts(rdata, what) {
  var rd = _bytes(rdata, what || "dnskey rdata");
  if (rd.length < 4) throw new DnssecError("dnssec/bad-key", "dnssec: DNSKEY RDATA too short");   // DNSKEY fixed header octets
  return { flags: rd.readUInt16BE(0), algorithm: rd[3], publicKey: rd.slice(4) };
}
function _parseDsRdata(rd) {
  if (rd.length < 5) throw new DnssecError("dnssec/bad-ds", "dnssec: DS RDATA too short");   // DS fixed header octets
  return { keyTag: rd.readUInt16BE(0), algorithm: rd[2], digestType: rd[3], digest: rd.slice(4) };
}
// ALL DNSKEYs whose key tag matches — 16-bit key tags collide (RFC 4034
// App B), so a verifier must try every candidate, not just the first.
function _keysByTag(dnskeys, tag) {
  var out = [];
  for (var i = 0; i < dnskeys.length; i++) if (keyTag(dnskeys[i]) === tag) out.push(dnskeys[i]);
  return out;
}

// Verify an RRset against EVERY DNSKEY whose tag matches the RRSIG,
// returning the key that validated. A wrong colliding key yields
// `dnssec/bad-signature` — that is not terminal, the next candidate is
// tried; any other error (expired, alg) is terminal. RFC 4035 §5.3.1.
function _verifyRrsetWithAnyKey(rrsetBase, rrsig, candidates, noKeyCode, noKeyMsg, budget) {
  if (candidates.length === 0) throw new DnssecError(noKeyCode, noKeyMsg);
  // KeyTrap (CVE-2023-50387): refuse an absurd same-tag fan-out outright —
  // legitimate zones have 1-2 keys per tag; hundreds is an amplification
  // attack, not a real collision.
  if (candidates.length > MAX_COLLIDING_KEYS) {
    throw new DnssecError("dnssec/too-many-colliding-keys",
      "dnssec.verifyChain: " + candidates.length + " DNSKEYs share key tag " +
      rrsig.keyTag + " (cap " + MAX_COLLIDING_KEYS +
      ") — refused as a KeyTrap (CVE-2023-50387) amplification vector");
  }
  var lastErr = null;
  for (var i = 0; i < candidates.length; i++) {
    var kp = _dnskeyParts(candidates[i]);
    if (kp.algorithm !== rrsig.algorithm) { lastErr = new DnssecError("dnssec/alg-mismatch", "dnssec.verifyChain: candidate key algorithm does not match the RRSIG"); continue; }
    // Per-response signature-validation budget — bound the total expensive
    // pubkey verifies across the whole chain walk, not just per RRSIG.
    if (budget) {
      if (budget.remaining <= 0) {
        throw new DnssecError("dnssec/validation-budget-exceeded",
          "dnssec.verifyChain: per-response signature-validation budget " +
          "exhausted — refused as a KeyTrap (CVE-2023-50387) amplification vector");
      }
      budget.remaining -= 1;
    }
    try {
      verifyRrset(Object.assign({}, rrsetBase, { rrsig: rrsig, dnskey: { algorithm: kp.algorithm, publicKey: kp.publicKey } }));
      return candidates[i];
    } catch (e) {
      if (e && e.code === "dnssec/bad-signature") { lastErr = e; continue; }   // colliding non-signing key — try the next
      throw e;
    }
  }
  throw lastErr;
}

/**
 * @primitive b.network.dns.dnssec.verifyChain
 * @signature b.network.dns.dnssec.verifyChain(opts)
 * @since     0.12.50
 * @status    stable
 * @compliance soc2
 * @related   b.network.dns.dnssec.verifyRrset, b.network.dns.dnssec.verifyDs
 *
 * Validate a DNSSEC delegation chain from the root down to a zone, against
 * a pinned trust anchor (RFC 4035 §5). For each link, the zone's DNSKEY
 * RRset must be self-signed by one of its keys; that signing key must be
 * vouched for either by a pinned anchor (root) or by a DS record served by
 * the already-trusted parent. The DS RRset itself is verified against the
 * parent's keys, so trust flows root → TLD → zone with no gap. The default
 * anchors are the IANA root KSKs; override with <code>opts.trustAnchors</code>.
 *
 * This composes <code>verifyRrset</code> + <code>verifyDs</code> + the key
 * tag; it returns the leaf zone's trusted DNSKEY set, which the caller then
 * passes to <code>verifyRrset</code> / <code>verifyDenial</code> for the
 * actual answer.
 *
 * KeyTrap (CVE-2023-50387) amplification is bounded with non-configurable
 * caps: at most 4 same-tag DNSKEY candidates are tried per RRSIG, at most
 * 64 DNSKEYs per zone link and 16 DS records per delegation are accepted,
 * the chain is at most 128 links deep, and the whole response is held to a
 * signature-validation budget that scales with chain depth (so a
 * legitimate deep delegation always fits while bounded collisions stay
 * bounded). A hostile zone publishing many colliding keys / signatures is
 * refused with <code>dnssec/too-many-colliding-keys</code> /
 * <code>dnssec/too-many-dnskeys</code> / <code>dnssec/too-many-ds</code> /
 * <code>dnssec/too-many-links</code> /
 * <code>dnssec/validation-budget-exceeded</code> rather than driving
 * O(keys x sigs) verifications. (NSEC3 iteration counts are separately
 * capped at 150 per RFC 9276 / the CVE-2023-50868 fix.)
 *
 * @opts
 *   {
 *     links: [ {                        // ordered root-first
 *       zone:        string,
 *       dnskeys:     Buffer[],          // the zone's DNSKEY RRset RDATAs
 *       dnskeyRrsig: { algorithm, labels, originalTtl, expiration, inception, keyTag, signerName, signature },
 *       dsRdatas?:   Buffer[],          // DS RRset for this zone (served by parent; omit for root)
 *       dsRrsig?:    { ... },           // RRSIG over the DS RRset (signed by parent; omit for root)
 *     } ],
 *     trustAnchors?: [ { keyTag, algorithm, digestType, digest: Buffer } ],  // default IANA root
 *     at?:           Date,             // validity instant (default now)
 *   }
 *
 * @example
 *   var trusted = b.network.dns.dnssec.verifyChain({ links: [rootLink, orgLink] });
 *   // → { ok: true, zone: "org.", keys: [ ...trusted org DNSKEY rdatas ] }
 */
function verifyChain(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyChain", DnssecError);
  validateOpts(opts, ["links", "trustAnchors", "at"], "dnssec.verifyChain");
  if (!Array.isArray(opts.links) || opts.links.length === 0) throw new DnssecError("dnssec/bad-arg", "dnssec.verifyChain: opts.links must be a non-empty array");
  // Cap delegation depth — a real chain can't be deeper than a DNS name's
  // label count (RFC 1035), and the per-response validation budget below
  // scales with this, so it must be bounded.
  if (opts.links.length > MAX_CHAIN_LINKS) {
    throw new DnssecError("dnssec/too-many-links",
      "dnssec.verifyChain: " + opts.links.length + " chain links (cap " +
      MAX_CHAIN_LINKS + ") — refused as an amplification vector");
  }
  var anchors = opts.trustAnchors !== undefined ? opts.trustAnchors : DEFAULT_ROOT_ANCHORS;
  if (!Array.isArray(anchors) || anchors.length === 0) throw new DnssecError("dnssec/bad-arg", "dnssec.verifyChain: opts.trustAnchors must be a non-empty array");

  // KeyTrap budget shared across every signature-validation in this
  // response, scaled to the declared chain depth so a legitimate deep
  // delegation (2N-1 verifies) always fits while bounded collisions stay
  // bounded. Chain length is capped above, so this can't be inflated.
  var budget = { remaining: opts.links.length * MAX_VALIDATIONS_PER_LINK };

  var trustedKeys = null, path = [];
  for (var i = 0; i < opts.links.length; i++) {
    var link = opts.links[i];
    if (!link || typeof link.zone !== "string" || link.zone === "") throw new DnssecError("dnssec/bad-link", "dnssec.verifyChain: links[" + i + "].zone is required");
    if (!Array.isArray(link.dnskeys) || link.dnskeys.length === 0) throw new DnssecError("dnssec/bad-link", "dnssec.verifyChain: links[" + i + "].dnskeys must be a non-empty array");
    // KeyTrap: bound the DNSKEY RRset size per zone so a giant key set
    // can't blow up the key-tag scan / candidate fan-out.
    if (link.dnskeys.length > MAX_DNSKEYS_PER_ZONE) {
      throw new DnssecError("dnssec/too-many-dnskeys",
        "dnssec.verifyChain: links[" + i + "] has " + link.dnskeys.length +
        " DNSKEYs (cap " + MAX_DNSKEYS_PER_ZONE + ") — refused as a KeyTrap (CVE-2023-50387) amplification vector");
    }
    if (!link.dnskeyRrsig || typeof link.dnskeyRrsig !== "object") throw new DnssecError("dnssec/bad-link", "dnssec.verifyChain: links[" + i + "].dnskeyRrsig is required");

    // 1. The DNSKEY RRset is self-signed by one of its own keys (trying
    //    every key whose tag matches, since tags collide).
    var signer = _verifyRrsetWithAnyKey(
      { name: link.zone, type: "DNSKEY", rdatas: link.dnskeys, at: opts.at },
      link.dnskeyRrsig,
      _keysByTag(link.dnskeys, link.dnskeyRrsig.keyTag),
      "dnssec/chain-no-signing-key", "dnssec.verifyChain: no DNSKEY in '" + link.zone + "' verifies the DNSKEY RRSIG",
      budget
    );

    // 2. Establish trust in the signing key.
    var signerTag = keyTag(signer);
    if (i === 0) {
      // Root: the signing key must match a pinned anchor's DS digest.
      var matched = false;
      for (var a = 0; a < anchors.length; a++) {
        if (anchors[a].keyTag !== signerTag) continue;
        try { verifyDs({ ownerName: link.zone, dnskeyRdata: signer, ds: anchors[a] }); matched = true; break; } catch (_e) { /* try the next anchor */ }
      }
      if (!matched) throw new DnssecError("dnssec/chain-anchor-mismatch", "dnssec.verifyChain: root DNSKEY does not match any pinned trust anchor");
    } else {
      // Delegation: the parent (already trusted) signed a DS RRset for this
      // zone, and the signing KSK matches one of those DS records.
      if (!Array.isArray(link.dsRdatas) || link.dsRdatas.length === 0 || !link.dsRrsig || typeof link.dsRrsig !== "object") {
        throw new DnssecError("dnssec/bad-link", "dnssec.verifyChain: links[" + i + "] needs dsRdatas + dsRrsig (DS served by the parent)");
      }
      // Bound the parent-supplied DS RRset — the DS-match loop below
      // iterates it, and an oversize set is an amplification vector.
      if (link.dsRdatas.length > MAX_DS_RECORDS) {
        throw new DnssecError("dnssec/too-many-ds",
          "dnssec.verifyChain: links[" + i + "] has " + link.dsRdatas.length +
          " DS records (cap " + MAX_DS_RECORDS + ") — refused as an amplification vector");
      }
      _verifyRrsetWithAnyKey(
        { name: link.zone, type: "DS", rdatas: link.dsRdatas, at: opts.at },
        link.dsRrsig,
        _keysByTag(trustedKeys, link.dsRrsig.keyTag),
        "dnssec/chain-no-parent-key", "dnssec.verifyChain: no trusted parent key verifies the DS RRSIG for '" + link.zone + "'",
        budget
      );
      var dsMatched = false;
      for (var d = 0; d < link.dsRdatas.length; d++) {
        var dsObj = _parseDsRdata(_bytes(link.dsRdatas[d], "dsRdatas[" + d + "]"));
        if (dsObj.keyTag !== signerTag) continue;
        try { verifyDs({ ownerName: link.zone, dnskeyRdata: signer, ds: dsObj }); dsMatched = true; break; } catch (_e) { /* try the next DS */ }
      }
      if (!dsMatched) throw new DnssecError("dnssec/chain-ds-mismatch", "dnssec.verifyChain: the signing KSK of '" + link.zone + "' matches no parent-signed DS");
    }

    trustedKeys = link.dnskeys;
    path.push(link.zone);
  }
  return { ok: true, zone: opts.links[opts.links.length - 1].zone, keys: trustedKeys, path: path };
}

module.exports = {
  verifyRrset:        verifyRrset,
  verifyDs:           verifyDs,
  verifyDenial:       verifyDenial,
  verifyChain:        verifyChain,
  nsec3Hash:          nsec3Hash,
  keyTag:             keyTag,
  ALGORITHMS:         ALGS,
  DEFAULT_ROOT_ANCHORS: DEFAULT_ROOT_ANCHORS,
  DnssecError:        DnssecError,
};
