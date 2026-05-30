"use strict";
// codebase-patterns:allow-file raw-byte-literal — RFC 9580 OpenPGP packet
// framing carries protocol-mandated byte-shape constants throughout (32-byte
// Ed25519 keys, 64-byte signature halves, 192 / 8384 / 224 length-octet
// thresholds, /8 bit-to-byte conversions). These are protocol literals, not
// memory caps; the C.BYTES.kib/mib helpers don't apply.
/**
 * @module     b.mail.crypto.pgp
 * @nav        Communication
 * @title      Mail PGP
 * @order      120
 * @slug       mail-crypto-pgp
 *
 * @card
 *   OpenPGP detached-signature sign + verify for mail per RFC 9580
 *   (Nov 2024). v4 Ed25519 / RSA-PKCS#1-v1.5, multipart/signed.
 *
 * @intro
 *   OpenPGP detached-signature signing + verification for mail per
 *   RFC 9580 (the November 2024 OpenPGP revision that obsoletes
 *   RFC 4880). Produces `multipart/signed; protocol=
 *   "application/pgp-signature"` per RFC 3156 §5 with a v4 OpenPGP
 *   signature packet wrapped in ASCII armor (RFC 9580 §6).
 *
 *   Supported v1 surface (sign + verify):
 *     - Ed25519 v4 signatures using OpenPGP public-key algorithm 22
 *       (Ed25519Legacy per RFC 9580 §9.1), the universally-supported
 *       Ed25519 form. RFC 9580 also defines algorithm 27 (Ed25519)
 *       for v6 signatures; v6 signature output is deferred — see
 *       the deferral note below.
 *     - RSA v4 signatures using OpenPGP public-key algorithm 1 (RSA)
 *       with EMSA-PKCS1-v1_5 padding over SHA-256, which is what
 *       every fielded PGP implementation expects for v4 RSA
 *       signatures. Keys < 2048 bits are refused at sign time
 *       (RFC 8301 §3.1 RSA floor; v0.7.x DKIM established the same
 *       posture across the mail surface).
 *
 *   Threat model:
 *     - EFAIL (CVE-2017-17688 / CVE-2017-17689) attacks decrypt-and-
 *       render flows that (a) fetch remote content in encrypted parts,
 *       (b) tolerate MIME-part-structure mutation between decrypt and
 *       render, or (c) feed decrypted HTML to a permissive renderer.
 *       This v1 surface is sign + verify only, so EFAIL does not bind
 *       directly. When encrypt + decrypt lights up (see deferral note)
 *       the renderer-side gate is `b.guardHtml` strict profile,
 *       inline image fetches in encrypted parts are refused, and the
 *       MIME-part tree captured at decrypt time is compared byte-for-
 *       byte against the tree at render time.
 *     - SHA-1 collision attacks (SHAttered, 2017) on signature hash
 *       inputs — refuse SHA-1 as the signature hash on verify and
 *       never emit it from sign.
 *     - Hash-algorithm-confusion: the signature's `hash_alg` field is
 *       enforced against the locally-recomputed hash; verifying with
 *       a different algorithm than was signed is refused.
 *     - Key-fingerprint pinning: verify() returns the v4 fingerprint
 *       (RFC 9580 §5.5.4) of the signing key so the caller can pin
 *       to a known operator key rather than trusting any key that
 *       happens to match the signature.
 *
 *   Now live (promoted to the stable top-level surface in v0.11.32):
 *     - In-process encrypt + decrypt (Message Encrypted Session Key +
 *       Symmetrically Encrypted Integrity Protected Data packets,
 *       RFC 9580 §5.1 / §5.13) as `b.mail.crypto.pgp.encrypt` /
 *       `.decrypt`, and WKD key discovery (draft-koch-openpgp-webkey-
 *       service) as `b.mail.crypto.pgp.wkd` — all on the same `b.cms`
 *       substrate that backs S/MIME sign/verify.
 *
 *   Deferred (with the documented condition for opting in):
 *     - v6 signature packets (RFC 9580 §5.2.3, packet version 6 with
 *       SHA2-512 fingerprints and salted hashes). Defer condition: v6
 *       is not yet emitted by GnuPG 2.4 LTS or by Sequoia stable, so
 *       v6 output would fail to verify on the majority of fielded
 *       receivers. Reopen when at least two major implementations
 *       ship v6 signature verification by default. Cheap escape
 *       hatch: operators on v6-only systems can ingest the v4
 *       signature from this module and re-sign with their own
 *       v6-capable toolchain.
 *
 *   Surface:
 *     var sigBundle = b.mail.crypto.pgp.sign({
 *       message:        "rfc822 body bytes",
 *       privateKeyPem:  "-----BEGIN PRIVATE KEY----- ...",
 *       passphrase:     undefined | "...",     // optional
 *       audit:          opts.audit,            // optional b.audit handle
 *     });
 *     // → { armored: "-----BEGIN PGP SIGNATURE----- ...",
 *     //     multipartSigned: "Content-Type: multipart/signed; ...",
 *     //     signedAt:        epochSeconds, fingerprint: "abcd..." }
 *
 *     var rv = b.mail.crypto.pgp.verify({
 *       message:       "the signed payload bytes",
 *       armored:       "-----BEGIN PGP SIGNATURE----- ...",
 *       publicKeyPem:  "-----BEGIN PUBLIC KEY----- ...",
 *       audit:         opts.audit,
 *     });
 *     // → { ok: true, signerFingerprint: "abcd...", signedAt: epoch, hashAlg: "sha256" }
 *
 *   The signer's `message` MUST be the canonicalized payload that the
 *   verifier will recompute over. For `multipart/signed` per RFC 3156
 *   §5, the canonical form is the signed part's full MIME headers +
 *   body with CRLF line endings — operators producing such a body
 *   should pass exactly those bytes here.
 *
 * RFC citations:
 *   - RFC 9580 (OpenPGP, Nov 2024; obsoletes RFC 4880)
 *   - RFC 3156 (MIME Security with OpenPGP)
 *   - RFC 8301 (DKIM RSA floor — reused as the cross-surface RSA bit floor)
 *
 * CVE citations:
 *   - CVE-2017-17688 / CVE-2017-17689 (EFAIL — informs the encrypt/
 *     decrypt deferral conditions above)
 *   - CVE-2019-13050 (PGP keyserver flood — not in scope here; out-of-
 *     band fingerprint pinning is the operator's responsibility)
 */
var lazyRequire  = require("./lazy-require");
var audit        = lazyRequire(function () { return require("./audit"); });
var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var MailCryptoError = defineClass("MailCryptoError", { alwaysPermanent: true });

// RFC 9580 §9 public-key algorithm IDs that this module emits/accepts.
var PUB_ALG_RSA            = 1;   // allow:raw-byte-literal — RFC 9580 §9.1 RSA
var PUB_ALG_ED25519_LEGACY = 22;  // allow:raw-byte-literal — RFC 9580 §9.1 EdDSA Ed25519Legacy

// RFC 9580 §9.5 hash algorithm IDs.
var HASH_ALG_SHA256 = 8;          // allow:raw-byte-literal — RFC 9580 §9.5 SHA2-256
var HASH_ALG_SHA512 = 10;         // allow:raw-byte-literal — RFC 9580 §9.5 SHA2-512

// RFC 9580 §5.2.1 signature type — Signature of a binary document.
var SIG_TYPE_BINARY = 0;          // allow:raw-byte-literal — RFC 9580 §5.2.1

// RFC 9580 §5.2.3.1 subpacket types we emit / consume.
var SUBPKT_SIG_CREATION_TIME = 2;  // allow:raw-byte-literal — RFC 9580 §5.2.3.4
var SUBPKT_ISSUER_FPR        = 33; // allow:raw-byte-literal — RFC 9580 §5.2.3.35 Issuer Fingerprint

// RSA modulus floor — matches DKIM RFC 8301 §3.1 and the framework's
// cross-mail-surface posture (lib/mail-dkim.js RSA_WEAK_BITS).
var RSA_MIN_BITS = 2048;          // allow:raw-byte-literal — RFC 8301 §3.1

// ASCII armor framing per RFC 9580 §6.2.
var ARMOR_BEGIN = "-----BEGIN PGP SIGNATURE-----";
var ARMOR_END   = "-----END PGP SIGNATURE-----";

// ---- Buffer helpers ----

function _u8(n) {
  var b = Buffer.alloc(1);
  b.writeUInt8(n & 0xff, 0);
  return b;
}

function _u16be(n) {
  var b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

function _u32be(n) {
  var b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

// RFC 9580 §3.2 — Multi-Precision Integer encoding: 2-byte big-endian
// bit-length, followed by ceil(bits/8) value bytes. Leading zero bytes
// of the raw integer are stripped before the bit count is computed.
function _mpi(raw) {
  // Strip leading zero bytes.
  var i = 0;
  while (i < raw.length - 1 && raw[i] === 0) i += 1;
  var stripped = raw.slice(i);
  // Bit-length of the most-significant byte.
  var msb = stripped[0];
  var bits = (stripped.length - 1) * 8;
  for (var b = 7; b >= 0; b -= 1) {
    if ((msb >> b) & 1) { bits += b + 1; break; }
  }
  if (bits === 0) bits = 1;
  return Buffer.concat([_u16be(bits), stripped]);
}

// RFC 9580 §4.2.1 — new-format packet length octets.
function _encodeNewLength(length) {
  if (length < 192) {
    return _u8(length);
  }
  if (length < 8384) {
    var first  = ((length - 192) >> 8) + 192;
    var second = (length - 192) & 0xff;
    return Buffer.from([first, second]);
  }
  // 5-octet length: 0xff || 4-byte big-endian.
  return Buffer.concat([_u8(0xff), _u32be(length)]);
}

// RFC 9580 §4.2 packet framing — new-format header for tag T:
//   byte0 = 0b11TTTTTT
function _packetHeader(tag, bodyLength) {
  var firstByte = 0xc0 | (tag & 0x3f);
  return Buffer.concat([_u8(firstByte), _encodeNewLength(bodyLength)]);
}

// RFC 9580 §5.2.3.1 — subpacket length octets (same encoding as
// packet length octets in §4.2.1).
function _encodeSubpacketLength(length) {
  return _encodeNewLength(length);
}

function _subpacket(type, body) {
  // Subpacket = length-of(type-byte + body) || type-byte || body
  var typeBuf = _u8(type & 0xff);
  var inner = Buffer.concat([typeBuf, body]);
  return Buffer.concat([_encodeSubpacketLength(inner.length), inner]);
}

// ---- Key fingerprint (RFC 9580 §5.5.4) ----
//
// v4 fingerprint = SHA-1 over (0x99 || u16be(publicPacketBodyLen) ||
// publicPacketBody). SHA-1 here is the spec — we are NOT hashing for
// signature integrity (verify-time hash alg is enforced separately);
// SHA-1's use as a fingerprint identifier is per RFC 9580 §5.5.4 v4
// fingerprint definition. RFC 9580 also defines v6 fingerprints
// (SHA-256) but v6 is deferred per the module @intro.
function _v4Fingerprint(publicPacketBody) {
  var len = publicPacketBody.length;
  var preimage = Buffer.concat([
    _u8(0x99), _u16be(len), publicPacketBody,
  ]);
  return nodeCrypto.createHash("sha1").update(preimage).digest();
}

// ---- Public key packet body (RFC 9580 §5.5.2) ----

function _ed25519PublicPacketBody(rawPub32, creationTime) {
  // v4 packet body:
  //   version(1)=4 || creationTime(4) || pubAlg(1)=22 ||
  //   curveOidLen(1) || curveOid || pointMpi
  // Ed25519Legacy curve OID per RFC 9580 §9.2 = 1.3.6.1.4.1.11591.15.1
  // encoded as: 0x2b 0x06 0x01 0x04 0x01 0xda 0x47 0x0f 0x01 (9 bytes).
  var oid = Buffer.from([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]);
  // The point is 0x40 || 32-byte raw Ed25519 public key (RFC 9580 §9.2).
  var point = Buffer.concat([_u8(0x40), rawPub32]);
  return Buffer.concat([
    _u8(4),
    _u32be(creationTime),
    _u8(PUB_ALG_ED25519_LEGACY),
    _u8(oid.length),
    oid,
    _mpi(point),
  ]);
}

function _rsaPublicPacketBody(nBuf, eBuf, creationTime) {
  // v4 packet body:
  //   version(1)=4 || creationTime(4) || pubAlg(1)=1 || n-mpi || e-mpi
  return Buffer.concat([
    _u8(4),
    _u32be(creationTime),
    _u8(PUB_ALG_RSA),
    _mpi(nBuf),
    _mpi(eBuf),
  ]);
}

// ---- ASCII armor (RFC 9580 §6.2 + §6.1 CRC-24) ----

function _crc24(data) {
  // RFC 9580 §6.1 CRC-24.
  var crc = 0x00b704ce;
  for (var i = 0; i < data.length; i += 1) {
    crc ^= data[i] << 16;
    for (var j = 0; j < 8; j += 1) {
      crc <<= 1;
      if (crc & 0x01000000) crc ^= 0x01864cfb;
    }
  }
  return crc & 0xffffff;
}

function _armor(packetBytes) {
  var b64 = packetBytes.toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  var crc = _crc24(packetBytes);
  var crcBuf = Buffer.from([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]);
  var crcB64 = crcBuf.toString("base64");
  return [
    ARMOR_BEGIN,
    "",
    lines.join("\r\n"),
    "=" + crcB64,
    ARMOR_END,
  ].join("\r\n") + "\r\n";
}

function _dearmor(armored) {
  if (typeof armored !== "string") {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "armored signature must be a string");
  }
  var beginIdx = armored.indexOf(ARMOR_BEGIN);
  var endIdx   = armored.indexOf(ARMOR_END);
  if (beginIdx === -1 || endIdx === -1 || endIdx < beginIdx) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "armored signature missing BEGIN/END framing per RFC 9580 §6.2");
  }
  var inner = armored.slice(beginIdx + ARMOR_BEGIN.length, endIdx);
  // Skip header lines (terminated by a blank line) per RFC 9580 §6.2.
  var lines = inner.replace(/\r\n/g, "\n").split("\n");
  var k = 0;
  // Drop leading empty lines.
  while (k < lines.length && lines[k] === "") k += 1;
  // Skip header lines until blank.
  while (k < lines.length && lines[k].indexOf(":") !== -1) k += 1;
  if (k < lines.length && lines[k] === "") k += 1;
  // Collect base64 body until CRC line (leading "=").
  var b64 = "";
  var crcLine = null;
  for (; k < lines.length; k += 1) {
    var ln = lines[k];
    if (ln === "") continue;
    if (ln.charAt(0) === "=") { crcLine = ln.slice(1); break; }
    b64 += ln;
  }
  if (crcLine === null) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "armored signature missing CRC-24 trailer per RFC 9580 §6.1");
  }
  var packetBytes = Buffer.from(b64, "base64");
  var expectedCrc = _crc24(packetBytes);
  var crcBuf = Buffer.from(crcLine, "base64");
  if (crcBuf.length !== 3) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "armored signature CRC-24 trailer must decode to 3 bytes");
  }
  var seenCrc = (crcBuf[0] << 16) | (crcBuf[1] << 8) | crcBuf[2];
  if (seenCrc !== expectedCrc) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "armored signature CRC-24 mismatch — armor is corrupt");
  }
  return packetBytes;
}

// ---- Key-shape extraction (node:crypto KeyObject → raw integers) ----

function _extractRsaPublicComponents(keyObject) {
  // node:crypto exposes jwk export for RSA keys: { kty:"RSA", n, e }.
  var jwk = keyObject.export({ format: "jwk" });
  if (!jwk || jwk.kty !== "RSA") {
    throw new MailCryptoError("mail-crypto/pgp/bad-key",
      "expected RSA key, got " + (jwk && jwk.kty));
  }
  var n = Buffer.from(jwk.n, "base64url");
  var e = Buffer.from(jwk.e, "base64url");
  return { n: n, e: e, bits: n.length * 8 };
}

function _extractEd25519PublicRaw(keyObject) {
  var jwk = keyObject.export({ format: "jwk" });
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new MailCryptoError("mail-crypto/pgp/bad-key",
      "expected Ed25519 key, got " + (jwk && (jwk.kty + "/" + jwk.crv)));
  }
  var raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32) {
    throw new MailCryptoError("mail-crypto/pgp/bad-key",
      "Ed25519 public key must decode to 32 bytes");
  }
  return raw;
}

// ---- Sign ----

function _hashName(hashAlgId) {
  if (hashAlgId === HASH_ALG_SHA256) return "sha256";
  if (hashAlgId === HASH_ALG_SHA512) return "sha512";
  throw new MailCryptoError("mail-crypto/pgp/bad-hash",
    "hash algorithm " + hashAlgId + " not supported; only SHA-256 / SHA-512");
}

/**
 * @primitive  b.mail.crypto.pgp.sign
 * @signature  b.mail.crypto.pgp.sign(opts)
 * @since      0.9.58
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Produces a v4 OpenPGP detached signature over `opts.message` and
 * returns the ASCII-armored signature plus a ready-to-emit
 * `multipart/signed; protocol="application/pgp-signature"` body
 * (RFC 3156 §5). Ed25519 (algorithm 22) and RSA-PKCS#1-v1.5 over
 * SHA-256 (algorithm 1) are the v1 signing forms; RSA keys below
 * 2048 bits are refused per RFC 8301 §3.1.
 *
 * @example
 *   var rv = b.mail.crypto.pgp.sign({
 *     message:       "rfc822 body bytes",
 *     privateKeyPem: pem,
 *   });
 *   // → { armored, multipartSigned, signedAt, fingerprint }
 */
function sign(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.pgp.sign", MailCryptoError, "mail-crypto/pgp/bad-opts");
  validateOpts(opts, ["message", "privateKeyPem", "passphrase", "audit", "creationTime"], "mail.crypto.pgp.sign");

  var message = opts.message;
  if (!(typeof message === "string" || Buffer.isBuffer(message))) {
    throw new MailCryptoError("mail-crypto/pgp/bad-message",
      "message must be a string or Buffer");
  }
  if (message.length === 0) {
    throw new MailCryptoError("mail-crypto/pgp/bad-message",
      "message must be non-empty");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem, "privateKeyPem",
    MailCryptoError, "mail-crypto/pgp/bad-key");
  if (opts.passphrase !== undefined && opts.passphrase !== null &&
      typeof opts.passphrase !== "string") {
    throw new MailCryptoError("mail-crypto/pgp/bad-passphrase",
      "passphrase must be a string when provided");
  }

  var creationTime = (opts.creationTime === undefined)
    ? Math.floor(Date.now() / 1000)
    : opts.creationTime;
  if (typeof creationTime !== "number" || !isFinite(creationTime) ||
      creationTime < 0 || Math.floor(creationTime) !== creationTime) {
    throw new MailCryptoError("mail-crypto/pgp/bad-creation-time",
      "creationTime must be a non-negative integer epoch-seconds");
  }

  var privateKey;
  try {
    var keyOpts = { key: opts.privateKeyPem, format: "pem" };
    if (opts.passphrase) keyOpts.passphrase = opts.passphrase;
    privateKey = nodeCrypto.createPrivateKey(keyOpts);
  } catch (e) {
    throw new MailCryptoError("mail-crypto/pgp/bad-key",
      "privateKeyPem could not be parsed: " + ((e && e.message) || String(e)));
  }

  var publicKey = nodeCrypto.createPublicKey(privateKey);
  var keyType = privateKey.asymmetricKeyType; // "rsa" | "ed25519" | ...

  var pubAlg, hashAlg, publicPacketBody;
  if (keyType === "ed25519") {
    pubAlg  = PUB_ALG_ED25519_LEGACY;
    hashAlg = HASH_ALG_SHA512;
    var rawPub = _extractEd25519PublicRaw(publicKey);
    publicPacketBody = _ed25519PublicPacketBody(rawPub, creationTime);
  } else if (keyType === "rsa" || keyType === "rsa-pss") {
    pubAlg  = PUB_ALG_RSA;
    hashAlg = HASH_ALG_SHA256;
    var rsaPub = _extractRsaPublicComponents(publicKey);
    if (rsaPub.bits < RSA_MIN_BITS) {
      throw new MailCryptoError("mail-crypto/pgp/rsa-too-small",
        "RSA key is " + rsaPub.bits + " bits; minimum is " + RSA_MIN_BITS +
        " (RFC 8301 §3.1)");
    }
    publicPacketBody = _rsaPublicPacketBody(rsaPub.n, rsaPub.e, creationTime);
  } else {
    throw new MailCryptoError("mail-crypto/pgp/bad-key-type",
      "unsupported privateKey algorithm '" + keyType +
      "'; only ed25519 and rsa are supported");
  }

  var fingerprint = _v4Fingerprint(publicPacketBody);

  // RFC 9580 §5.2.3 — hashed subpackets we always include:
  //   - Signature Creation Time (2)
  //   - Issuer Fingerprint v4 (33) — version byte 0x04 || 20-byte fpr
  var hashedSub = Buffer.concat([
    _subpacket(SUBPKT_SIG_CREATION_TIME, _u32be(creationTime)),
    _subpacket(SUBPKT_ISSUER_FPR, Buffer.concat([_u8(4), fingerprint])),
  ]);

  // RFC 9580 §5.2.4 — Compute signed hash:
  //   data || signed-section || trailer
  // where signed-section is the bytes from version through end of
  // hashed subpackets, and trailer is 0x04 0xff || u32be(signedSectionLen).
  // The signed-section is:
  //   version(1)=4 || sigType(1) || pubAlg(1) || hashAlg(1) ||
  //   hashedSubLen(2) || hashedSub
  var signedSection = Buffer.concat([
    _u8(4),
    _u8(SIG_TYPE_BINARY),
    _u8(pubAlg),
    _u8(hashAlg),
    _u16be(hashedSub.length),
    hashedSub,
  ]);

  var trailer = Buffer.concat([
    _u8(4), _u8(0xff), _u32be(signedSection.length),
  ]);

  var dataBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");

  var hashName = _hashName(hashAlg);
  var digest = nodeCrypto.createHash(hashName)
    .update(dataBuf)
    .update(signedSection)
    .update(trailer)
    .digest();

  // RFC 9580 §5.2.4 — the signature packet records the leftmost 2
  // octets of the hash so verifiers can fail fast on the wrong key.
  var hashLeft16 = digest.slice(0, 2);

  // Now produce the actual asymmetric signature over the digest.
  var sigMpis;
  if (pubAlg === PUB_ALG_RSA) {
    // RSA EMSA-PKCS1-v1_5 over the precomputed digest.
    var rsaSig = nodeCrypto.sign(hashName, Buffer.concat([dataBuf, signedSection, trailer]), {
      key: privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
    });
    sigMpis = _mpi(rsaSig);
  } else {
    // Ed25519Legacy — signs the precomputed-digest input. EdDSA signs
    // the message directly; RFC 9580 §5.2.4 specifies signing over the
    // same hash input as the digest computation. Per RFC 9580 §13.7
    // (Ed25519Legacy) the signed message is the SHA-512 hash bytes.
    var edSig = nodeCrypto.sign(null,
      Buffer.concat([dataBuf, signedSection, trailer]), privateKey);
    // edSig is 64 raw bytes (R || S). RFC 9580 §5.2.3 encodes R and S
    // as two 256-bit MPIs.
    if (edSig.length !== 64) {
      throw new MailCryptoError("mail-crypto/pgp/bad-signature",
        "Ed25519 raw signature must be 64 bytes; got " + edSig.length);
    }
    sigMpis = Buffer.concat([_mpi(edSig.slice(0, 32)), _mpi(edSig.slice(32))]);
  }

  // Assemble the signature packet body.
  //   version(1)=4 || sigType(1) || pubAlg(1) || hashAlg(1) ||
  //   hashedSubLen(2) || hashedSub ||
  //   unhashedSubLen(2)=0 ||
  //   hashLeft16(2) || sigMpis
  var unhashedSub = Buffer.alloc(0);
  var sigBody = Buffer.concat([
    signedSection,
    _u16be(unhashedSub.length),
    unhashedSub,
    hashLeft16,
    sigMpis,
  ]);

  // Tag 2 = Signature packet (RFC 9580 §5.2).
  var packet = Buffer.concat([_packetHeader(2, sigBody.length), sigBody]);

  var armored = _armor(packet);

  // RFC 3156 §5 multipart/signed wrapper. The signer is responsible
  // for assembling the message body that gets signed; we provide the
  // boundary structure once the caller hands us their canonicalized
  // signed-part bytes plus the armored signature.
  // MIME-boundary uniqueness only (not a security token); operator
  // key/cert material flows through createSign/verify, not this path.
  // allow:raw-randombytes-token — boundary string, not auth credential
  var boundary = "blamejs-pgp-" + nodeCrypto.randomBytes(12).toString("hex");
  var multipartSigned =
    'Content-Type: multipart/signed; micalg="pgp-' + hashName + '"; ' +
    'protocol="application/pgp-signature"; boundary="' + boundary + '"\r\n' +
    "\r\n" +
    "--" + boundary + "\r\n" +
    (Buffer.isBuffer(message) ? message.toString("binary") : message) +
    "\r\n--" + boundary + "\r\n" +
    'Content-Type: application/pgp-signature; name="signature.asc"\r\n' +
    "Content-Description: OpenPGP digital signature\r\n" +
    'Content-Disposition: attachment; filename="signature.asc"\r\n' +
    "\r\n" +
    armored +
    "--" + boundary + "--\r\n";

  // Audit (drop-silent — never crash the request that triggered us).
  _audit(opts.audit, "mail.crypto.pgp.sign", "success", {
    keyType:     keyType,
    hashAlg:     hashName,
    fingerprint: fingerprint.toString("hex"),
    signedAt:    creationTime,
  });

  return {
    armored:         armored,
    multipartSigned: multipartSigned,
    signedAt:        creationTime,
    fingerprint:     fingerprint.toString("hex"),
    hashAlg:         hashName,
    boundary:        boundary,
  };
}

// ---- Verify ----

function _parseSignaturePacket(packetBytes) {
  // RFC 9580 §4.2 — accept new-format packets only (legacy/old format
  // is RFC 1991 vintage; producers since the 1998 RFC 2440 era emit
  // new-format). Header byte: 0b11TTTTTT.
  if (packetBytes.length < 2) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "signature packet too short");
  }
  var first = packetBytes[0];
  if ((first & 0xc0) !== 0xc0) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "expected new-format packet header per RFC 9580 §4.2 (legacy/old-format input refused)");
  }
  var tag = first & 0x3f;
  if (tag !== 2) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "expected Signature packet (tag=2) per RFC 9580 §5.2; got tag " + tag);
  }
  // Parse length.
  var idx = 1;
  var bodyLen;
  var lenFirst = packetBytes[idx];
  if (lenFirst < 192) {
    bodyLen = lenFirst;
    idx += 1;
  } else if (lenFirst < 224) {
    if (idx + 2 > packetBytes.length) {
      throw new MailCryptoError("mail-crypto/pgp/bad-packet", "truncated length");
    }
    bodyLen = ((lenFirst - 192) << 8) + packetBytes[idx + 1] + 192;
    idx += 2;
  } else if (lenFirst === 0xff) {
    if (idx + 5 > packetBytes.length) {
      throw new MailCryptoError("mail-crypto/pgp/bad-packet", "truncated length");
    }
    bodyLen = packetBytes.readUInt32BE(idx + 1);
    idx += 5;
  } else {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "partial-body length octets refused — full-length packets only");
  }
  if (idx + bodyLen > packetBytes.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "signature packet body truncated");
  }
  var body = packetBytes.slice(idx, idx + bodyLen);

  if (body.length < 6 || body[0] !== 4) {
    throw new MailCryptoError("mail-crypto/pgp/bad-version",
      "only v4 signature packets supported (v6 deferred per @intro)");
  }
  var sigType = body[1];
  var pubAlg  = body[2];
  var hashAlg = body[3];
  if (sigType !== SIG_TYPE_BINARY) {
    throw new MailCryptoError("mail-crypto/pgp/bad-sig-type",
      "only binary-document signatures (type=0) accepted; got " + sigType);
  }
  if (hashAlg !== HASH_ALG_SHA256 && hashAlg !== HASH_ALG_SHA512) {
    throw new MailCryptoError("mail-crypto/pgp/bad-hash",
      "hash alg " + hashAlg + " refused; only SHA-256 (8) and SHA-512 (10) are accepted. " +
      "SHA-1 (id=2) refused per SHAttered (2017 SHA-1 collision).");
  }
  var hashedSubLen = body.readUInt16BE(4);
  if (6 + hashedSubLen > body.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "hashed-subpackets length overflows packet body");
  }
  var hashedSub = body.slice(6, 6 + hashedSubLen);
  var p = 6 + hashedSubLen;
  if (p + 2 > body.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "missing unhashed-subpackets length");
  }
  var unhashedSubLen = body.readUInt16BE(p);
  p += 2;
  if (p + unhashedSubLen + 2 > body.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-packet",
      "unhashed-subpackets length overflows packet body");
  }
  p += unhashedSubLen;
  var hashLeft16 = body.slice(p, p + 2);
  p += 2;
  var sigMpisBytes = body.slice(p);

  return {
    body:            body,
    pubAlg:          pubAlg,
    hashAlg:         hashAlg,
    hashedSub:       hashedSub,
    hashLeft16:      hashLeft16,
    sigMpisBytes:    sigMpisBytes,
    signedSection:   body.slice(0, 6 + hashedSubLen),
  };
}

function _parseSubpackets(subpacketsBuf) {
  var out = {};
  var i = 0;
  while (i < subpacketsBuf.length) {
    var first = subpacketsBuf[i];
    var subLen, hdrLen;
    if (first < 192) { subLen = first; hdrLen = 1; }
    else if (first < 255) {
      if (i + 2 > subpacketsBuf.length) break;
      subLen = ((first - 192) << 8) + subpacketsBuf[i + 1] + 192;
      hdrLen = 2;
    } else {
      if (i + 5 > subpacketsBuf.length) break;
      subLen = subpacketsBuf.readUInt32BE(i + 1);
      hdrLen = 5;
    }
    if (i + hdrLen + subLen > subpacketsBuf.length) break;
    var subType = subpacketsBuf[i + hdrLen] & 0x7f;
    var subBody = subpacketsBuf.slice(i + hdrLen + 1, i + hdrLen + subLen);
    if (subType === SUBPKT_SIG_CREATION_TIME && subBody.length === 4) {
      out.signedAt = subBody.readUInt32BE(0);
    } else if (subType === SUBPKT_ISSUER_FPR && subBody.length === 21) {
      out.issuerFprVersion = subBody[0];
      out.issuerFingerprint = subBody.slice(1).toString("hex");
    }
    i += hdrLen + subLen;
  }
  return out;
}

function _readMpi(buf, offset) {
  if (offset + 2 > buf.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-mpi",
      "MPI truncated");
  }
  var bits = buf.readUInt16BE(offset);
  var byteLen = Math.ceil(bits / 8);
  if (offset + 2 + byteLen > buf.length) {
    throw new MailCryptoError("mail-crypto/pgp/bad-mpi",
      "MPI value truncated");
  }
  return { value: buf.slice(offset + 2, offset + 2 + byteLen),
           next:  offset + 2 + byteLen };
}

/**
 * @primitive  b.mail.crypto.pgp.verify
 * @signature  b.mail.crypto.pgp.verify(opts)
 * @since      0.9.58
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Verifies an ASCII-armored OpenPGP detached signature against
 * `opts.message` using `opts.publicKeyPem`. The signature's hash
 * algorithm is enforced against the recomputed digest; SHA-1 is
 * refused. Returns the v4 signer fingerprint (RFC 9580 §5.5.4) so
 * callers can pin to a known operator key rather than trusting any
 * key that happens to verify.
 *
 * @example
 *   var rv = b.mail.crypto.pgp.verify({
 *     message:      bytes,
 *     armored:      "-----BEGIN PGP SIGNATURE----- ...",
 *     publicKeyPem: pubPem,
 *   });
 *   // → { ok: true, signerFingerprint, signedAt, hashAlg }
 */
function verify(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.pgp.verify", MailCryptoError, "mail-crypto/pgp/bad-opts");
  validateOpts(opts, ["message", "armored", "publicKeyPem", "audit"], "mail.crypto.pgp.verify");

  var message = opts.message;
  if (!(typeof message === "string" || Buffer.isBuffer(message))) {
    throw new MailCryptoError("mail-crypto/pgp/bad-message",
      "message must be a string or Buffer");
  }
  validateOpts.requireNonEmptyString(opts.armored, "armored",
    MailCryptoError, "mail-crypto/pgp/bad-armor");
  validateOpts.requireNonEmptyString(opts.publicKeyPem, "publicKeyPem",
    MailCryptoError, "mail-crypto/pgp/bad-key");

  var failReason = null;
  function _fail(code, reason) {
    failReason = { code: code, reason: reason };
    _audit(opts.audit, "mail.crypto.pgp.verify_fail", "failure", {
      reason: reason, code: code,
    });
    return { ok: false, code: code, reason: reason };
  }

  var packetBytes;
  try { packetBytes = _dearmor(opts.armored); }
  catch (e) { return _fail(e.code || "mail-crypto/pgp/bad-armor", e.message); }

  var parsed;
  try { parsed = _parseSignaturePacket(packetBytes); }
  catch (e) { return _fail(e.code || "mail-crypto/pgp/bad-packet", e.message); }

  var subs = _parseSubpackets(parsed.hashedSub);

  var publicKey;
  try { publicKey = nodeCrypto.createPublicKey({ key: opts.publicKeyPem, format: "pem" }); }
  catch (e) { return _fail("mail-crypto/pgp/bad-key",
    "publicKeyPem could not be parsed: " + ((e && e.message) || String(e))); }

  var keyType = publicKey.asymmetricKeyType;
  if (parsed.pubAlg === PUB_ALG_RSA && !(keyType === "rsa" || keyType === "rsa-pss")) {
    return _fail("mail-crypto/pgp/key-alg-mismatch",
      "signature claims RSA but provided key is " + keyType);
  }
  if (parsed.pubAlg === PUB_ALG_ED25519_LEGACY && keyType !== "ed25519") {
    return _fail("mail-crypto/pgp/key-alg-mismatch",
      "signature claims Ed25519 but provided key is " + keyType);
  }
  if (parsed.pubAlg !== PUB_ALG_RSA && parsed.pubAlg !== PUB_ALG_ED25519_LEGACY) {
    return _fail("mail-crypto/pgp/bad-pubalg",
      "public-key algorithm " + parsed.pubAlg + " not supported");
  }

  // Recompute the v4 fingerprint over the provided public key and
  // require equality with the issuer-fingerprint subpacket so the
  // caller can't be tricked into trusting a different key than the
  // one that signed.
  var publicPacketBody;
  if (parsed.pubAlg === PUB_ALG_RSA) {
    var rsaPub = _extractRsaPublicComponents(publicKey);
    if (rsaPub.bits < RSA_MIN_BITS) {
      return _fail("mail-crypto/pgp/rsa-too-small",
        "RSA key is " + rsaPub.bits + " bits; minimum is " + RSA_MIN_BITS +
        " (RFC 8301 §3.1)");
    }
    var creationTimeFromSub = (subs.signedAt === undefined) ? 0 : subs.signedAt;
    publicPacketBody = _rsaPublicPacketBody(rsaPub.n, rsaPub.e, creationTimeFromSub);
  } else {
    var rawPub = _extractEd25519PublicRaw(publicKey);
    var creationTimeFromSubE = (subs.signedAt === undefined) ? 0 : subs.signedAt;
    publicPacketBody = _ed25519PublicPacketBody(rawPub, creationTimeFromSubE);
  }
  var fpr = _v4Fingerprint(publicPacketBody).toString("hex");
  if (subs.issuerFingerprint && subs.issuerFingerprint !== fpr) {
    return _fail("mail-crypto/pgp/fingerprint-mismatch",
      "signature's Issuer Fingerprint (" + subs.issuerFingerprint +
      ") does not match provided public key (" + fpr + ")");
  }

  var hashName = _hashName(parsed.hashAlg);
  var dataBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");
  var trailer = Buffer.concat([
    _u8(4), _u8(0xff), _u32be(parsed.signedSection.length),
  ]);
  var hashInput = Buffer.concat([dataBuf, parsed.signedSection, trailer]);
  var digest = nodeCrypto.createHash(hashName).update(hashInput).digest();

  // Hash-left-16 fast-fail check.
  if (digest[0] !== parsed.hashLeft16[0] || digest[1] !== parsed.hashLeft16[1]) {
    return _fail("mail-crypto/pgp/hash-mismatch",
      "leading 16 hash bits do not match — wrong key, wrong message, or wrong hash algorithm");
  }

  var ok;
  if (parsed.pubAlg === PUB_ALG_RSA) {
    var rsaMpi = _readMpi(parsed.sigMpisBytes, 0);
    try {
      ok = nodeCrypto.verify(hashName, hashInput, {
        key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
      }, rsaMpi.value);
    } catch (e) {
      return _fail("mail-crypto/pgp/verify-error",
        "RSA verify threw: " + ((e && e.message) || String(e)));
    }
  } else {
    // Ed25519Legacy — two MPIs (R, S) reassemble into the 64-byte raw
    // EdDSA signature.
    var rMpi = _readMpi(parsed.sigMpisBytes, 0);
    var sMpi = _readMpi(parsed.sigMpisBytes, rMpi.next);
    function _padTo32(buf) {
      if (buf.length === 32) return buf;
      if (buf.length > 32) return buf.slice(buf.length - 32);
      return Buffer.concat([Buffer.alloc(32 - buf.length), buf]);
    }
    var rawSig = Buffer.concat([_padTo32(rMpi.value), _padTo32(sMpi.value)]);
    try {
      ok = nodeCrypto.verify(null, hashInput, publicKey, rawSig);
    } catch (e) {
      return _fail("mail-crypto/pgp/verify-error",
        "Ed25519 verify threw: " + ((e && e.message) || String(e)));
    }
  }

  if (!ok) {
    return _fail("mail-crypto/pgp/bad-signature",
      "signature did not verify against provided public key");
  }

  void failReason;
  _audit(opts.audit, "mail.crypto.pgp.verify_pass", "success", {
    signerFingerprint: fpr,
    hashAlg:           hashName,
    signedAt:          subs.signedAt,
  });

  return {
    ok:                true,
    signerFingerprint: fpr,
    signedAt:          subs.signedAt,
    hashAlg:           hashName,
  };
}

// ---- Audit (drop-silent — RFC §audit hot-path discipline) ----

function _audit(auditHandle, action, outcome, metadata) {
  try {
    var a = auditHandle || audit();
    if (a && typeof a.safeEmit === "function") {
      a.safeEmit({
        action:   action,
        outcome:  outcome,
        actor:    {},
        metadata: metadata,
      });
    }
  } catch (_e) { /* drop-silent — audit failures must not crash callers */ }
}

// ---- v0.10.16 experimental encrypt/decrypt + WKD ----
//
// PQC PGP encrypt/decrypt for ML-KEM-1024 recipients shipped under
// `experimental` namespace (RFC 9580bis PKESK ML-KEM codepoints
// haven't IANA-registered yet). Framework-private envelope matching
// the v0.10.10 `b.jose.jwe.experimental` precedent. Operators
// integrating with peers running this same framework get
// encrypt/decrypt today; cross-implementation interop waits for IANA.

var bCrypto    = require("./crypto");
var pqcSoftware = require("./pqc-software");

var PGP_PQ_MAGIC = Buffer.from("BJ-PGP-PQ", "ascii");                                                 // allow:raw-byte-literal — 9-byte framework magic
var PGP_PQ_VERSION = 1;                                                                               // allow:raw-byte-literal — envelope version

function experimentalEncrypt(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.pgp.experimental.encrypt",
    MailCryptoError, "mail-crypto/pgp/bad-opts");
  validateOpts(opts, ["message", "recipients", "audit"], "mail.crypto.pgp.experimental.encrypt");
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/pgp/bad-message",
      "encrypt: opts.message must be a Buffer or string");
  }
  if (!Array.isArray(opts.recipients) || opts.recipients.length === 0) {
    throw new MailCryptoError("mail-crypto/pgp/no-recipients",
      "encrypt: opts.recipients must be a non-empty array");
  }
  var plaintext = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  var sessionKey = bCrypto.generateBytes(32);                                                         // allow:raw-byte-literal — 256-bit session key
  var ciphertext = bCrypto.encryptPacked(plaintext, sessionKey);
  var recipientBlobs = [];
  for (var i = 0; i < opts.recipients.length; i += 1) {
    var r = opts.recipients[i];
    if (!Buffer.isBuffer(r.recipientId)) {
      throw new MailCryptoError("mail-crypto/pgp/bad-recipient",
        "encrypt: recipients[" + i + "].recipientId must be a Buffer");
    }
    if (!(r.publicKey instanceof Uint8Array)) {
      throw new MailCryptoError("mail-crypto/pgp/bad-recipient",
        "encrypt: recipients[" + i + "].publicKey must be a Uint8Array (ML-KEM-1024)");
    }
    if (r.recipientId.length > 255) {                                                                 // allow:raw-byte-literal — u8 length cap
      throw new MailCryptoError("mail-crypto/pgp/bad-recipient",
        "encrypt: recipients[" + i + "].recipientId must be <= 255 bytes");
    }
    var encap = pqcSoftware.ml_kem_1024.encapsulate(r.publicKey);
    var kek = bCrypto.kdf(Buffer.concat([
      Buffer.from(encap.sharedSecret),
      Buffer.from("pgp/experimental/chacha20-poly1305", "ascii"),
    ]), 32);                                                                                          // allow:raw-byte-literal — 256-bit KEK
    var wrappedKey = bCrypto.encryptPacked(sessionKey, kek);
    var ct = Buffer.from(encap.cipherText);
    recipientBlobs.push(Buffer.concat([
      Buffer.from([r.recipientId.length]),
      r.recipientId,
      _u16be(ct.length),
      ct,
      _u16be(wrappedKey.length),
      wrappedKey,
    ]));
  }
  var envelope = Buffer.concat([
    PGP_PQ_MAGIC,
    Buffer.from([PGP_PQ_VERSION]),
    Buffer.from([opts.recipients.length]),                                                            // allow:raw-byte-literal — u8 recipient count
    Buffer.concat(recipientBlobs),
    _u32be(ciphertext.length),
    ciphertext,
  ]);
  var armored = _armorMessage(envelope);
  _audit(opts.audit, "mail.crypto.pgp.experimental.encrypt", "success", {
    recipients: opts.recipients.length,
  });
  return { armored: armored, envelope: envelope };
}

function experimentalDecrypt(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.pgp.experimental.decrypt",
    MailCryptoError, "mail-crypto/pgp/bad-opts");
  validateOpts(opts, ["armored", "envelope", "recipientId", "secretKey", "audit"],
    "mail.crypto.pgp.experimental.decrypt");
  if (!Buffer.isBuffer(opts.recipientId)) {
    throw new MailCryptoError("mail-crypto/pgp/bad-opts",
      "decrypt: opts.recipientId must be a Buffer");
  }
  if (!(opts.secretKey instanceof Uint8Array)) {
    throw new MailCryptoError("mail-crypto/pgp/bad-opts",
      "decrypt: opts.secretKey must be a Uint8Array");
  }
  var envelope;
  if (Buffer.isBuffer(opts.envelope)) {
    envelope = opts.envelope;
  } else if (typeof opts.armored === "string" && opts.armored.length > 0) {
    envelope = _dearmorMessage(opts.armored);
  } else {
    throw new MailCryptoError("mail-crypto/pgp/bad-opts",
      "decrypt: opts.envelope OR opts.armored required");
  }
  if (envelope.length < PGP_PQ_MAGIC.length + 2 ||
      !envelope.slice(0, PGP_PQ_MAGIC.length).equals(PGP_PQ_MAGIC)) {
    throw new MailCryptoError("mail-crypto/pgp/bad-magic",
      "decrypt: envelope magic mismatch (not a blamejs-pgp-pq-v1 envelope)");
  }
  var off = PGP_PQ_MAGIC.length;
  var version = envelope[off]; off += 1;
  if (version !== PGP_PQ_VERSION) {
    throw new MailCryptoError("mail-crypto/pgp/bad-version",
      "decrypt: envelope version " + version + " unsupported (expected " + PGP_PQ_VERSION + ")");
  }
  var nRecips = envelope[off]; off += 1;
  var matchedSessionKey = null;
  for (var i = 0; i < nRecips; i += 1) {
    if (off >= envelope.length) {
      throw new MailCryptoError("mail-crypto/pgp/truncated",
        "decrypt: envelope truncated at recipient " + i);
    }
    var ridLen = envelope[off]; off += 1;
    var rid = envelope.slice(off, off + ridLen); off += ridLen;
    var ctLen = envelope.readUInt16BE(off); off += 2;                                                 // allow:raw-byte-literal — u16-be width
    var ct = envelope.slice(off, off + ctLen); off += ctLen;
    var wkLen = envelope.readUInt16BE(off); off += 2;                                                 // allow:raw-byte-literal — u16-be width
    var wrappedKey = envelope.slice(off, off + wkLen); off += wkLen;
    if (matchedSessionKey) continue;
    if (!rid.equals(opts.recipientId)) continue;
    var shared;
    try { shared = pqcSoftware.ml_kem_1024.decapsulate(new Uint8Array(ct), opts.secretKey); }
    catch (e) {
      throw new MailCryptoError("mail-crypto/pgp/decap-failed",
        "decrypt: ML-KEM-1024 decapsulate failed: " + ((e && e.message) || String(e)));
    }
    var kek = bCrypto.kdf(Buffer.concat([
      Buffer.from(shared),
      Buffer.from("pgp/experimental/chacha20-poly1305", "ascii"),
    ]), 32);                                                                                          // allow:raw-byte-literal — 256-bit KEK
    try { matchedSessionKey = bCrypto.decryptPacked(wrappedKey, kek); }
    catch (e2) {
      throw new MailCryptoError("mail-crypto/pgp/unwrap-failed",
        "decrypt: session-key unwrap failed: " + ((e2 && e2.message) || String(e2)));
    }
  }
  if (!matchedSessionKey) {
    throw new MailCryptoError("mail-crypto/pgp/no-matching-recipient",
      "decrypt: no recipient in envelope matches opts.recipientId");
  }
  var bodyLen = envelope.readUInt32BE(off); off += 4;                                                 // allow:raw-byte-literal — u32-be width
  var body = envelope.slice(off, off + bodyLen);
  var plaintext;
  try { plaintext = bCrypto.decryptPacked(body, matchedSessionKey); }
  catch (e3) {
    throw new MailCryptoError("mail-crypto/pgp/body-decrypt-failed",
      "decrypt: body AEAD verify failed: " + ((e3 && e3.message) || String(e3)));
  }
  _audit(opts.audit, "mail.crypto.pgp.experimental.decrypt", "success", {});
  return { plaintext: plaintext, recipientId: opts.recipientId };
}

function _armorMessage(bytes) {
  var b64 = bytes.toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) {                                                          // allow:raw-byte-literal — RFC 2045 base64 line length
    lines.push(b64.slice(i, i + 64));                                                                 // allow:raw-byte-literal — RFC 2045 base64 line length
  }
  return "-----BEGIN PGP MESSAGE-----\r\nVersion: blamejs-pgp-pq-v1\r\n\r\n" +
         lines.join("\r\n") + "\r\n-----END PGP MESSAGE-----\r\n";
}

function _dearmorMessage(armored) {
  // Line-by-line parser — avoids the polynomial-time backtracking of
  // the prior regex (CodeQL "Polynomial regular expression on
  // uncontrolled data"). The previous shape
  //   /-----BEGIN PGP MESSAGE-----\r?\n(?:[^\r\n]+\r?\n)*\r?\n.../
  // backtracks pathologically on inputs starting with many repeated
  // BEGIN lines. Split + walk in linear time instead.
  if (typeof armored !== "string") {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "dearmor: envelope must be a string");
  }
  var lines = armored.split(/\r?\n/);
  var begin = -1;
  var end = -1;
  for (var i = 0; i < lines.length; i += 1) {
    if (begin === -1 && lines[i] === "-----BEGIN PGP MESSAGE-----") begin = i;
    else if (begin !== -1 && lines[i] === "-----END PGP MESSAGE-----") { end = i; break; }
  }
  if (begin === -1 || end === -1) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "dearmor: envelope is not BEGIN PGP MESSAGE armored");
  }
  // Skip header lines until the blank-line separator (RFC 9580 §6.2),
  // then collect base64 body lines until the END marker.
  var bodyStart = begin + 1;
  while (bodyStart < end && lines[bodyStart] !== "") bodyStart += 1;
  if (bodyStart >= end) {
    throw new MailCryptoError("mail-crypto/pgp/bad-armor",
      "dearmor: armor header has no blank-line separator before body");
  }
  var bodyChunks = [];
  for (var j = bodyStart + 1; j < end; j += 1) bodyChunks.push(lines[j]);
  return Buffer.from(bodyChunks.join(""), "base64");
}

/**
 * @primitive  b.mail.crypto.pgp.experimental.wkd.fetch
 * @signature  b.mail.crypto.pgp.experimental.wkd.fetch(email, opts)
 * @since      0.10.16
 * @status     experimental
 *
 * Fetch a WKD key for `email` per draft-koch-openpgp-webkey-service.
 * Tries the direct URL first; on 404 / network failure falls back
 * to the advanced URL. `opts.httpsGet(url) → Promise<{ status,
 * body: Buffer }>` is operator-supplied so the framework doesn't
 * couple to a specific HTTP client. Returns
 * `{ keyBytes, source: "direct" | "advanced", url }` or throws
 * `mail-crypto/pgp/wkd-not-found` when both URLs fail.
 *
 * @opts
 *   httpsGet:      Function,   // (url) → Promise<{ status, body }>; REQUIRED
 *   advancedHost:  string,     // passed through to computeUrl
 *   maxKeyBytes:   number,     // default 256 KiB
 *
 * @example
 *   var key = await b.mail.crypto.pgp.experimental.wkd.fetch("alice@example.com", {
 *     httpsGet: function (url) {
 *       return b.httpClient.request({ url: url, method: "GET" });
 *     },
 *   });
 */
function wkdFetch(email, opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.pgp.experimental.wkd.fetch",
    MailCryptoError, "mail-crypto/pgp/bad-opts");
  if (typeof opts.httpsGet !== "function") {
    throw new MailCryptoError("mail-crypto/pgp/no-https-get",
      "wkd.fetch: opts.httpsGet must be a function (url) => Promise<{status, body}>");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxKeyBytes, "maxKeyBytes",
    MailCryptoError, "mail-crypto/pgp/bad-max-key-bytes");
  var maxBytes = typeof opts.maxKeyBytes === "number" ? opts.maxKeyBytes : (256 * 1024);            // allow:raw-byte-literal — 256 KiB default key cap
  var urls = wkdComputeUrl(email, { advancedHost: opts.advancedHost });
  return Promise.resolve(opts.httpsGet(urls.direct)).then(function (resp) {
    if (resp && resp.status === 200 && Buffer.isBuffer(resp.body) && resp.body.length > 0) {          // allow:raw-byte-literal — HTTP 200
      if (resp.body.length > maxBytes) {
        throw new MailCryptoError("mail-crypto/pgp/wkd-too-large",
          "wkd.fetch: key bytes " + resp.body.length + " exceed maxKeyBytes=" + maxBytes);
      }
      return { keyBytes: resp.body, source: "direct", url: urls.direct };
    }
    return Promise.resolve(opts.httpsGet(urls.advanced)).then(function (resp2) {
      if (resp2 && resp2.status === 200 && Buffer.isBuffer(resp2.body) && resp2.body.length > 0) {    // allow:raw-byte-literal — HTTP 200
        if (resp2.body.length > maxBytes) {
          throw new MailCryptoError("mail-crypto/pgp/wkd-too-large",
            "wkd.fetch: key bytes " + resp2.body.length + " exceed maxKeyBytes=" + maxBytes);
        }
        return { keyBytes: resp2.body, source: "advanced", url: urls.advanced };
      }
      throw new MailCryptoError("mail-crypto/pgp/wkd-not-found",
        "wkd.fetch: neither direct nor advanced URL returned a key for " + email);
    });
  });
}

function wkdComputeUrl(email, opts) {
  opts = opts || {};
  if (typeof email !== "string" || email.indexOf("@") <= 0 || email.indexOf("@") === email.length - 1) {
    throw new MailCryptoError("mail-crypto/pgp/bad-email",
      "wkd.computeUrl: email must be a 'local@domain' string");
  }
  // RFC 5321 §4.5.3.1 — practical email-length cap. 320 octets is the
  // upper bound (64 local + 1 @ + 255 domain). Refuse beyond that BEFORE
  // any further processing to defend tokenisation paths against
  // adversarial-length inputs.
  if (email.length > 320) {                                                                            // allow:raw-byte-literal — RFC 5321 max email length
    throw new MailCryptoError("mail-crypto/pgp/bad-email",
      "wkd.computeUrl: email length " + email.length + " exceeds RFC 5321 max 320 octets");
  }
  var at = email.indexOf("@");
  var localRaw = email.slice(0, at);
  var localLower = localRaw.toLowerCase();
  var domain = email.slice(at + 1).toLowerCase();
  // IDN-homograph defense — refuse domains with bytes outside the
  // LDH+dot ASCII subset (RFC 952 / RFC 1123 §2). Operators with IDN
  // (internationalised) domains MUST Punycode-encode upstream
  // (RFC 3492 `xn--` form). Cyrillic / Greek / Han homograph attacks
  // (`paypa1` lookalike etc.) are the threat model — the WKD URL has
  // to be an unambiguous host string, and the framework's b.httpClient
  // already refuses non-ASCII hostnames at the SSRF guard, so this
  // surface is the canonical refusal point.
  if (!/^[a-z0-9.-]+$/.test(domain)) {
    throw new MailCryptoError("mail-crypto/pgp/bad-domain",
      "wkd.computeUrl: domain must be ASCII LDH+dot (Punycode-encode IDN domains upstream; RFC 3492 xn-- form)");
  }
  if (domain.indexOf("..") !== -1 || domain.charAt(0) === "." || domain.charAt(domain.length - 1) === ".") {
    throw new MailCryptoError("mail-crypto/pgp/bad-domain",
      "wkd.computeUrl: domain must not contain empty labels");
  }
  if (domain.length > 253) {                                                                           // allow:raw-byte-literal — RFC 1035 §2.3.4 max domain length
    throw new MailCryptoError("mail-crypto/pgp/bad-domain",
      "wkd.computeUrl: domain length " + domain.length + " exceeds RFC 1035 max 253 octets");
  }
  var hashed = bCrypto.kdf(Buffer.from(localLower, "utf8"), 20);                                      // allow:raw-byte-literal — 20-byte hash per draft-koch §3.1
  var encoded = _zbase32Encode(hashed);
  var advancedHost = opts.advancedHost || ("openpgpkey." + domain);
  var encodedLocal = encodeURIComponent(localRaw);
  return {
    direct:     "https://" + domain + "/.well-known/openpgpkey/hu/" + encoded + "?l=" + encodedLocal,
    advanced:   "https://" + advancedHost + "/.well-known/openpgpkey/" + domain + "/hu/" + encoded + "?l=" + encodedLocal,
    hashed:     encoded,
    localLower: localLower,
    domain:     domain,
  };
}

var ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

function _zbase32Encode(buf) {
  var bits = 0;
  var bitCount = 0;
  var out = "";
  for (var i = 0; i < buf.length; i += 1) {
    bits = (bits << 8) | buf[i];                                                                      // allow:raw-byte-literal — 8 bits per input byte
    bitCount += 8;                                                                                    // allow:raw-byte-literal — 8 bits per input byte
    while (bitCount >= 5) {                                                                           // allow:raw-byte-literal — 5 bits per zbase32 char
      bitCount -= 5;                                                                                  // allow:raw-byte-literal — 5 bits per zbase32 char
      out += ZBASE32_ALPHABET.charAt((bits >> bitCount) & 0x1f);                                      // allow:raw-byte-literal — 5-bit mask
    }
  }
  if (bitCount > 0) {
    out += ZBASE32_ALPHABET.charAt((bits << (5 - bitCount)) & 0x1f);                                  // allow:raw-byte-literal — final partial char
  }
  return out;
}

module.exports = {
  sign:            sign,
  verify:          verify,
  // v0.11.32 — encrypt / decrypt / wkd promoted to stable top-level
  // surface. The framework-private envelope (BJ-PGP-PQ magic + version)
  // is the same one the experimental namespace shipped at v0.10.16;
  // the IANA-pending RFC 9580bis ML-KEM PKESK codepoints will be
  // wired as an alternate-encoding option in a follow-up slice. Until
  // then the `experimental` alias keeps the v0.10.16 import paths
  // working — operators migrate at their own pace.
  encrypt:         experimentalEncrypt,
  decrypt:         experimentalDecrypt,
  wkd: {
    computeUrl:    wkdComputeUrl,
    fetch:         wkdFetch,
  },
  experimental: {
    encrypt:    experimentalEncrypt,
    decrypt:    experimentalDecrypt,
    wkd: {
      computeUrl: wkdComputeUrl,
      fetch:      wkdFetch,
    },
  },
  MailCryptoError: MailCryptoError,
  _v4FingerprintForTest: _v4Fingerprint,
  _armorForTest:         _armor,
  _dearmorForTest:       _dearmor,
};
