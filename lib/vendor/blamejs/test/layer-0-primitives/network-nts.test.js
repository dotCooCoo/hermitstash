// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.ntp.nts — NTS (RFC 8915) key-establishment + protected NTPv4
 * exchange. This canonical suite drives the UNCOVERED error / adversarial /
 * defensive / option-default branches of the primitive through its real
 * consumer path:
 *
 *   - AES-SIV-CMAC (RFC 5297) encrypt/decrypt roundtrip + bad-key +
 *     tamper-detection, exercising the s2v/cmac/ctr internals for 32/48/64
 *     byte keys and both short- and long-plaintext code paths.
 *   - performKeHandshake against a loopback TLS "ntske/1" server that
 *     returns each adversarial record shape (error record, missing/short
 *     AEAD, unsupported AEAD, no cookies, over-long record) plus the
 *     success path (real TLS exporter keys) and the fail-closed guards
 *     (bad ALPN, wall-clock timeout, socket reset).
 *   - querySingle against a loopback UDP server that crafts each hostile
 *     reply (too-short, unique-id mismatch, malformed extension, missing/
 *     truncated/overlong authenticator, AEAD verification failure) plus
 *     authenticated success for BOTH AEADs, exercising cookie rotation and
 *     the encrypted-extension walk.
 *   - query end-to-end: a loopback KE server exports the same TLS keying
 *     material its sibling UDP server uses to authenticate the reply, so
 *     the full govern→handshake→protected-query path resolves.
 *
 * No real network is touched — every server is a 127.0.0.1 listener and
 * every key is injected. Adversarial packets assert the primitive fails
 * closed with an `nts/*` typed error.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeTls    = require("node:tls");
var dgram      = require("node:dgram");
var net        = require("node:net");
var nodeCrypto = require("node:crypto");

// NTS-KE record types (RFC 8915 §4) and NTPv4 extension-field types
// (§5.3-5.7). Mirrored here so the test constructs on-wire bytes without
// reaching into the module's private encoders.
var REC_END           = 0;
var REC_NEXT_PROTOCOL = 1;
var REC_ERROR         = 2;
var REC_WARNING       = 3;
var REC_AEAD          = 4;
var REC_NEW_COOKIE    = 5;
var REC_NTPV4_SERVER  = 6;
var REC_NTPV4_PORT    = 7;

var EXT_UNIQUE = 0x0104;
var EXT_COOKIE = 0x0204;
var EXT_AUTH   = 0x0404;

var NTP_HEADER_BYTES  = 48;
var NTP_EPOCH_OFFSET  = 2208988800;
var EXPORTER_LABEL    = "EXPORTER-network-time-security";

// ---------------------------------------------------------------------------
// On-wire byte builders (test-local; the lib's encoders are private).
// ---------------------------------------------------------------------------

function _u16(v) { var buf = Buffer.alloc(2); buf.writeUInt16BE(v, 0); return buf; }

// NTS-KE record: u16 (critical<<15 | type) || u16 body-len || body.
function _rec(critical, type, body) {
  var hdr = Buffer.alloc(4);
  var tf = type & 0x7fff;
  if (critical) tf |= 0x8000;
  hdr.writeUInt16BE(tf, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

// NTPv4 extension field, RFC 7822 4-byte alignment (matches the module's
// private _encodeExtensionField): u16 type || u16 (paddedBody+4) || body.
function _ext(type, body) {
  var padLen = (4 - (body.length % 4)) % 4;
  var padded = padLen === 0 ? body : Buffer.concat([body, Buffer.alloc(padLen)]);
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(padded.length + 4, 2);
  return Buffer.concat([hdr, padded]);
}

// Raw extension with a caller-chosen length field — for adversarial replies
// whose declared length disagrees with the body (truncated / overrun).
function _rawExt(type, len, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(len, 2);
  return Buffer.concat([hdr, body]);
}

// Locate an extension body inside a request/reply, walking from startOff.
function _findExtBody(msg, startOff, type) {
  var off = startOff;
  while (off + 4 <= msg.length) {
    var t = msg.readUInt16BE(off);
    var len = msg.readUInt16BE(off + 2);
    if (len < 4 || off + len > msg.length) break;
    if (t === type) return msg.slice(off + 4, off + len);
    off += len;
  }
  return null;
}

// Mirror of the module's private _aeadEncrypt so a test UDP server can forge
// an authenticator the client will actually verify. Uses the public
// aesSivEncrypt primitive for the SIV branch.
function _aeadEncryptMirror(aeadId, key, nonce, plaintext, aad) {
  if (aeadId === b.network.ntp.nts.AEAD_AES_SIV_CMAC_256) {
    return b.network.ntp.nts.aesSivEncrypt(key, plaintext, [aad, nonce]);
  }
  var c = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: plaintext.length });
  var ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}

// Build a fully-formed protected NTPv4 reply: NTP header || unique-id ext ||
// authenticator ext, with the authenticator computed over the packet prefix
// exactly as the client recomputes its AAD (msg up to the authenticator).
function _buildReply(opts) {
  var ntp = Buffer.alloc(NTP_HEADER_BYTES);
  var secs = (Math.floor(Date.now() / 1000) + NTP_EPOCH_OFFSET) >>> 0;
  ntp.writeUInt32BE(secs, 40);
  ntp.writeUInt32BE(0, 44);
  var uniqueExt = _ext(EXT_UNIQUE, opts.uniqueId);
  var prefix = Buffer.concat([ntp, uniqueExt]);
  var isSiv = opts.aeadId === b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  var nonce = nodeCrypto.randomBytes(isSiv ? 16 : 12);
  var plaintext = opts.plaintext || Buffer.alloc(0);
  var ct = _aeadEncryptMirror(opts.aeadId, opts.s2cKey, nonce, plaintext, prefix);
  if (opts.corruptCt) { ct = Buffer.from(ct); ct[ct.length - 1] ^= 0xff; }
  var authBody = Buffer.alloc(4 + nonce.length + ct.length);
  authBody.writeUInt16BE(nonce.length, 0);
  authBody.writeUInt16BE(ct.length, 2);
  nonce.copy(authBody, 4);
  ct.copy(authBody, 4 + nonce.length);
  return Buffer.concat([prefix, _ext(EXT_AUTH, authBody)]);
}

// ---------------------------------------------------------------------------
// Loopback listeners.
// ---------------------------------------------------------------------------

async function _makeCert() {
  var ca = await b.mtlsEngine.generateCa({ name: "nts-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "localhost",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return { ca: ca, leaf: leaf };
}

// cfg.onData(sock) → Buffer (written back) or null (stay silent). cfg.setAlpn
// false omits ALPNProtocols so the client sees a non-"ntske/1" negotiation.
function _startKeServer(cert, cfg) {
  return new Promise(function (resolve) {
    var tlsOpts = {
      key:        cert.leaf.key,
      cert:       cert.leaf.cert,
      minVersion: "TLSv1.3",
      maxVersion: "TLSv1.3",
    };
    if (cfg.setAlpn !== false) tlsOpts.ALPNProtocols = ["ntske/1"];
    var server = nodeTls.createServer(tlsOpts, function (sock) {
      sock.on("error", function () { /* client tears down on the reject path */ });
      sock.once("data", function () {
        var resp = cfg.onData ? cfg.onData(sock) : null;
        if (resp && resp.length) { try { sock.write(resp); } catch (_e) { /* raced teardown */ } }
      });
    });
    server.on("error", function () { /* best-effort loopback listener */ });
    server.listen(0, "127.0.0.1", function () {
      resolve({ server: server, port: server.address().port });
    });
  });
}

function _startUdpServer(onMessage) {
  return new Promise(function (resolve) {
    var sock = dgram.createSocket("udp4");
    sock.on("error", function () { /* best-effort loopback listener */ });
    sock.on("message", function (msg, rinfo) { onMessage(msg, rinfo, sock); });
    sock.bind(0, "127.0.0.1", function () {
      resolve({ sock: sock, port: sock.address().port });
    });
  });
}

// ---------------------------------------------------------------------------
// AES-SIV-CMAC crypto internals (RFC 5297).
// ---------------------------------------------------------------------------

function testAesSivRoundtrip() {
  var K = nodeCrypto.randomBytes(32);
  var ad = [Buffer.from("associated-one"), Buffer.from("associated-two")];

  // Plaintext > one AES block exercises the s2v head/tail xor path.
  var longPt = Buffer.from("the quick brown fox jumps over the lazy dog twice");
  var ct = b.network.ntp.nts.aesSivEncrypt(K, longPt, ad);
  check("SIV roundtrip 32-byte key, multi-block plaintext",
        b.network.ntp.nts.aesSivDecrypt(K, ct, ad).equals(longPt));

  // Plaintext < one AES block exercises the s2v pad-and-double path.
  var shortPt = Buffer.from("hi");
  var ctShort = b.network.ntp.nts.aesSivEncrypt(K, shortPt, ad);
  check("SIV roundtrip sub-block plaintext",
        b.network.ntp.nts.aesSivDecrypt(K, ctShort, ad).equals(shortPt));

  // 48- and 64-byte keys (AES-192/256 halves).
  var K48 = nodeCrypto.randomBytes(48);
  check("SIV roundtrip 48-byte key",
        b.network.ntp.nts.aesSivDecrypt(K48, b.network.ntp.nts.aesSivEncrypt(K48, longPt, ad), ad).equals(longPt));
  var K64 = nodeCrypto.randomBytes(64);
  check("SIV roundtrip 64-byte key",
        b.network.ntp.nts.aesSivDecrypt(K64, b.network.ntp.nts.aesSivEncrypt(K64, longPt, ad), ad).equals(longPt));

  // Omitted associatedData → the `associatedData || []` default path.
  var ctNoAd = b.network.ntp.nts.aesSivEncrypt(K, longPt);
  check("SIV roundtrip with no associated data",
        b.network.ntp.nts.aesSivDecrypt(K, ctNoAd).equals(longPt));
}

function testAesSivBadKey() {
  var caught = null;
  try { b.network.ntp.nts.aesSivEncrypt(nodeCrypto.randomBytes(31), Buffer.from("x"), []); }
  catch (e) { caught = e; }
  check("SIV bad-key is NtsError-typed", caught instanceof b.network.ntp.nts.NtsError);
  check("SIV bad-key code", caught && caught.code === "nts/bad-key");
}

function testAesSivTamperFailsClosed() {
  var K = nodeCrypto.randomBytes(32);
  var pt = Buffer.from("authenticate me if you can");
  var ct = Buffer.from(b.network.ntp.nts.aesSivEncrypt(K, pt, []));
  ct[0] ^= 0xff; // corrupt the synthetic IV (V)
  var caught = null;
  try { b.network.ntp.nts.aesSivDecrypt(K, ct, []); }
  catch (e) { caught = e; }
  check("SIV tamper rejects", caught !== null);
  check("SIV tamper code is nts/auth-failed", caught && caught.code === "nts/auth-failed");
}

// ---------------------------------------------------------------------------
// performKeHandshake / querySingle synchronous input validation.
// ---------------------------------------------------------------------------

function testKeInputValidation() {
  var e1 = null;
  try { b.network.ntp.nts.performKeHandshake({}); } catch (e) { e1 = e; }
  check("KE missing host is nts/bad-host", e1 && e1.code === "nts/bad-host");

  var e2 = null;
  try { b.network.ntp.nts.performKeHandshake({ host: "h", port: 70000 }); } catch (e) { e2 = e; }
  check("KE out-of-range port is nts/bad-ke-port", e2 && e2.code === "nts/bad-ke-port");

  var e3 = null;
  try { b.network.ntp.nts.performKeHandshake({ host: "h", bogus: 1 }); } catch (e) { e3 = e; }
  check("KE unknown opt rejected", e3 && /unknown option/.test(e3.message));
}

function testQuerySingleInputValidation() {
  var buf = Buffer.alloc(4);
  var e1 = null;
  try { b.network.ntp.nts.querySingle({ host: "h", port: 99999, c2sKey: buf, s2cKey: buf, cookies: [buf] }); }
  catch (e) { e1 = e; }
  check("querySingle out-of-range port is nts/bad-ntp-port", e1 && e1.code === "nts/bad-ntp-port");

  var e2 = null;
  try { b.network.ntp.nts.querySingle({ host: "h" }); } catch (e) { e2 = e; }
  check("querySingle missing c2sKey", e2 && e2.code === "nts/no-c2s-key");

  var e3 = null;
  try { b.network.ntp.nts.querySingle({ host: "h", c2sKey: buf }); } catch (e) { e3 = e; }
  check("querySingle missing s2cKey", e3 && e3.code === "nts/no-s2c-key");

  var e4 = null;
  try { b.network.ntp.nts.querySingle({ host: "h", c2sKey: buf, s2cKey: buf }); } catch (e) { e4 = e; }
  check("querySingle missing cookies", e4 && e4.code === "nts/no-cookies");
}

// ---------------------------------------------------------------------------
// performKeHandshake network paths.
// ---------------------------------------------------------------------------

async function _connectKeExpectReject(cert, ke, expectedCode, label, timeoutMs) {
  var caught = null;
  try {
    await helpers.withTestTimeout(label, function () {
      return b.network.ntp.nts.performKeHandshake({
        host:       "127.0.0.1",
        port:       ke.port,
        servername: "localhost",
        ca:         cert.ca.caCertPem,
        timeoutMs:  timeoutMs || 4000,
      });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  check(label + " rejects", caught !== null);
  check(label + " code=" + expectedCode, caught && caught.code === expectedCode);
}

async function testKeBadAlpn(cert) {
  var ke = await _startKeServer(cert, { setAlpn: false, onData: null });
  try { await _connectKeExpectReject(cert, ke, "nts/bad-alpn", "KE non-ntske ALPN"); }
  finally { try { ke.server.close(); } catch (_e) { /* best-effort */ } }
}

async function testKeAdversarialRecords(cert) {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;

  var cases = [
    { label: "KE server error record", code: "nts/ke-error", onData: function () {
        return Buffer.concat([_rec(true, REC_ERROR, _u16(1)), _rec(true, REC_END, Buffer.alloc(0))]);
      } },
    { label: "KE missing AEAD record", code: "nts/no-aead", onData: function () {
        return _rec(true, REC_END, Buffer.alloc(0));
      } },
    { label: "KE short AEAD body", code: "nts/no-aead", onData: function () {
        return Buffer.concat([_rec(true, REC_AEAD, Buffer.alloc(1)), _rec(true, REC_END, Buffer.alloc(0))]);
      } },
    { label: "KE unsupported AEAD", code: "nts/unsupported-aead", onData: function () {
        return Buffer.concat([
          _rec(true, REC_AEAD, _u16(99)),
          _rec(false, REC_NEW_COOKIE, nodeCrypto.randomBytes(16)),
          _rec(true, REC_END, Buffer.alloc(0)),
        ]);
      } },
    { label: "KE no cookies", code: "nts/no-cookies", onData: function () {
        return Buffer.concat([_rec(true, REC_AEAD, _u16(aeadId)), _rec(true, REC_END, Buffer.alloc(0))]);
      } },
    { label: "KE over-long record", code: "nts/bad-record", onData: function () {
        var h = Buffer.alloc(4);
        h.writeUInt16BE(REC_NEW_COOKIE & 0x7fff, 0);
        h.writeUInt16BE(0xffff, 2); // claims 64 KiB body, sends none
        return h;
      } },
  ];

  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var ke = await _startKeServer(cert, { onData: c.onData });
    try { await _connectKeExpectReject(cert, ke, c.code, c.label); }
    finally { try { ke.server.close(); } catch (_e) { /* best-effort */ } }
  }
}

async function testKeSuccess(cert) {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  // No REC_NTPV4_SERVER / REC_NTPV4_PORT → the defaults (opts.host, 123)
  // branches; a warning record → the warnings-capture branch.
  var ke = await _startKeServer(cert, { onData: function () {
    return Buffer.concat([
      _rec(true, REC_NEXT_PROTOCOL, _u16(0)),
      _rec(true, REC_AEAD, _u16(aeadId)),
      _rec(false, REC_WARNING, _u16(7)),
      _rec(false, REC_NEW_COOKIE, nodeCrypto.randomBytes(32)),
      _rec(true, REC_END, Buffer.alloc(0)),
    ]);
  } });
  try {
    var res = await helpers.withTestTimeout("KE handshake success", function () {
      return b.network.ntp.nts.performKeHandshake({
        host: "127.0.0.1", port: ke.port, servername: "localhost",
        ca: cert.ca.caCertPem, timeoutMs: 4000,
      });
    });
    check("KE success negotiates SIV", res.aeadId === aeadId);
    check("KE success exports 32-byte c2sKey", Buffer.isBuffer(res.c2sKey) && res.c2sKey.length === 32);
    check("KE success exports 32-byte s2cKey", Buffer.isBuffer(res.s2cKey) && res.s2cKey.length === 32);
    check("KE success returns one cookie", res.cookies.length === 1);
    check("KE success defaults ntpServer to host", res.ntpServer === "127.0.0.1");
    check("KE success defaults ntpPort to 123", res.ntpPort === 123);
    check("KE success captures the warning", res.warnings.length === 1 && res.warnings[0] === 7);
  } finally { try { ke.server.close(); } catch (_e) { /* best-effort */ } }
}

async function testKeTimeout(cert) {
  var ke = await _startKeServer(cert, { onData: null }); // ALPN ok, never sends REC_END
  try { await _connectKeExpectReject(cert, ke, "nts/ke-timeout", "KE wall-clock timeout", 300); }
  finally { try { ke.server.close(); } catch (_e) { /* best-effort */ } }
}

async function testKeByteCapFailsClosed(cert) {
  // 128 KiB of well-formed non-END cookie records, no REC_END — the read
  // accumulator must fail closed at the 64 KiB ceiling (memory bound), not
  // hang until the wall-clock timer (time bound) fires.
  var one = _rec(false, REC_NEW_COOKIE, Buffer.alloc(1020, 0x41)); // 1024 bytes
  var chunks = [];
  for (var i = 0; i < 128; i++) chunks.push(one);
  var big = Buffer.concat(chunks);
  var ke = await _startKeServer(cert, { onData: function () { return big; } });
  try { await _connectKeExpectReject(cert, ke, "nts/ke-too-large", "KE handshake byte cap"); }
  finally { try { ke.server.close(); } catch (_e) { /* best-effort */ } }
}

async function testKeSocketError() {
  var srv = net.createServer(function (s) { s.destroy(); }); // reset mid-TLS
  await new Promise(function (res) { srv.listen(0, "127.0.0.1", res); });
  var port = srv.address().port;
  var caught = null;
  try {
    await helpers.withTestTimeout("KE socket reset", function () {
      return b.network.ntp.nts.performKeHandshake({
        host: "127.0.0.1", port: port, servername: "localhost", timeoutMs: 4000,
      });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  try { srv.close(); } catch (_e) { /* best-effort */ }
  check("KE socket reset rejects", caught !== null);
  check("KE socket reset code is nts/ke-socket", caught && caught.code === "nts/ke-socket");
}

// ---------------------------------------------------------------------------
// querySingle network paths.
// ---------------------------------------------------------------------------

async function _udpExpectReject(makeReply, aeadId, expectedCode, label) {
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var reply = makeReply(msg);
    if (reply) s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  var caught = null;
  try {
    await helpers.withTestTimeout(label, function () {
      return b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.port, aeadId: aeadId,
        c2sKey: nodeCrypto.randomBytes(32), s2cKey: nodeCrypto.randomBytes(32),
        cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 4000,
      });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  try { udp.sock.close(); } catch (_e) { /* best-effort */ }
  check(label + " rejects", caught !== null);
  check(label + " code=" + expectedCode, caught && caught.code === expectedCode);
}

async function testQuerySingleAdversarialReplies() {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;

  await _udpExpectReject(function () { return Buffer.alloc(10); },
    aeadId, "nts/bad-reply", "querySingle short reply");

  await _udpExpectReject(function () { return Buffer.alloc(NTP_HEADER_BYTES); },
    aeadId, "nts/unique-mismatch", "querySingle no unique-id");

  await _udpExpectReject(function () {
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _rawExt(EXT_UNIQUE, 2, Buffer.alloc(0))]);
  }, aeadId, "nts/bad-extension", "querySingle extension len<4");

  await _udpExpectReject(function () {
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _rawExt(EXT_UNIQUE, 40, Buffer.alloc(0))]);
  }, aeadId, "nts/bad-extension", "querySingle extension overrun");

  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u)]);
  }, aeadId, "nts/no-authenticator", "querySingle missing authenticator");

  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    return Buffer.concat([
      Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u),
      _rawExt(EXT_AUTH, 6, Buffer.from([0xaa, 0xbb])), // 2-byte body < 4
    ]);
  }, aeadId, "nts/bad-authenticator", "querySingle truncated authenticator");

  await _udpExpectReject(function (msg) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    var ab = Buffer.alloc(8);
    ab.writeUInt16BE(100, 0); // nonceLen
    ab.writeUInt16BE(100, 2); // ctLen — 4+100+100 >> 8
    return Buffer.concat([Buffer.alloc(NTP_HEADER_BYTES), _ext(EXT_UNIQUE, u), _ext(EXT_AUTH, ab)]);
  }, aeadId, "nts/bad-authenticator", "querySingle overlong authenticator lengths");
}

async function testQuerySingleAuthFailed() {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  var s2cKey = nodeCrypto.randomBytes(32);
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var reply = _buildReply({ aeadId: aeadId, s2cKey: s2cKey, uniqueId: u, plaintext: Buffer.alloc(0), corruptCt: true });
    s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  var caught = null;
  try {
    await helpers.withTestTimeout("querySingle authenticator forgery", function () {
      return b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.port, aeadId: aeadId,
        c2sKey: nodeCrypto.randomBytes(32), s2cKey: s2cKey,
        cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 4000,
      });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  try { udp.sock.close(); } catch (_e) { /* best-effort */ }
  check("querySingle forged authenticator rejects", caught !== null);
  check("querySingle forged authenticator code", caught && caught.code === "nts/auth-failed");
}

async function testQuerySingleUnsupportedAeadEncrypt() {
  // An aeadId the request-side AEAD encoder does not recognise fails closed
  // before any packet leaves the socket — no server required.
  var caught = null;
  try {
    await b.network.ntp.nts.querySingle({
      host: "127.0.0.1", port: 65000, aeadId: 99,
      c2sKey: nodeCrypto.randomBytes(32), s2cKey: nodeCrypto.randomBytes(32),
      cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 1000,
    });
  } catch (e) { caught = e; }
  check("querySingle unsupported aead rejects", caught !== null);
  check("querySingle unsupported aead code is nts/aead-unsupported",
        caught && caught.code === "nts/aead-unsupported");
}

async function testQuerySingleTimeout() {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  var udp = await _startUdpServer(function () { /* never reply */ });
  var caught = null;
  try {
    await helpers.withTestTimeout("querySingle timeout", function () {
      return b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.port, aeadId: aeadId,
        c2sKey: nodeCrypto.randomBytes(32), s2cKey: nodeCrypto.randomBytes(32),
        cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 300,
      });
    }, { timeoutMs: 9000 });
  } catch (e) { caught = e; }
  try { udp.sock.close(); } catch (_e) { /* best-effort */ }
  check("querySingle timeout rejects", caught !== null);
  check("querySingle timeout code is nts/timeout", caught && caught.code === "nts/timeout");
}

async function testQuerySingleSivSuccess() {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  var s2cKey = nodeCrypto.randomBytes(32);
  var newCookie = nodeCrypto.randomBytes(32);
  // Encrypted extensions: one non-cookie ext (skipped) + one cookie ext
  // (rotated in) — exercises both sides of the cookie-type predicate.
  var plaintext = Buffer.concat([_ext(EXT_UNIQUE, Buffer.alloc(4, 0xaa)), _ext(EXT_COOKIE, newCookie)]);
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var reply = _buildReply({ aeadId: aeadId, s2cKey: s2cKey, uniqueId: u, plaintext: plaintext });
    s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  try {
    // Cookie length 30 (not 4-aligned) exercises the extension padding path.
    var res = await helpers.withTestTimeout("querySingle SIV success", function () {
      return b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.port, aeadId: aeadId,
        c2sKey: nodeCrypto.randomBytes(32), s2cKey: s2cKey,
        cookies: [nodeCrypto.randomBytes(30)], timeoutMs: 4000,
      });
    });
    check("SIV querySingle authenticated", res.authenticated === true);
    check("SIV querySingle drift is numeric", typeof res.driftMs === "number" && isFinite(res.driftMs));
    check("SIV querySingle rotated one new cookie", res.newCookieCount === 1);
    check("SIV querySingle cookie pool stays at one", res.cookiesRemaining === 1);
  } finally { try { udp.sock.close(); } catch (_e) { /* best-effort */ } }
}

async function testQuerySingleChaChaSuccess() {
  var aeadId = b.network.ntp.nts.AEAD_CHACHA20_POLY1305;
  var s2cKey = nodeCrypto.randomBytes(32);
  // A 4-byte-but-malformed encrypted extension: length >= 4 reaches the
  // inner walk, whose throw is swallowed → zero cookies extracted.
  var plaintext = Buffer.from([0x02, 0x04, 0x00, 0x02]);
  var udp = await _startUdpServer(function (msg, rinfo, s) {
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var reply = _buildReply({ aeadId: aeadId, s2cKey: s2cKey, uniqueId: u, plaintext: plaintext });
    s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });
  try {
    var res = await helpers.withTestTimeout("querySingle ChaCha success", function () {
      return b.network.ntp.nts.querySingle({
        host: "127.0.0.1", port: udp.port, aeadId: aeadId,
        c2sKey: nodeCrypto.randomBytes(32), s2cKey: s2cKey,
        cookies: [nodeCrypto.randomBytes(32)], timeoutMs: 4000,
      });
    });
    check("ChaCha querySingle authenticated", res.authenticated === true);
    check("ChaCha querySingle extracts no cookie from malformed exts", res.newCookieCount === 0);
    check("ChaCha querySingle cookie pool unchanged", res.cookiesRemaining === 1);
  } finally { try { udp.sock.close(); } catch (_e) { /* best-effort */ } }
}

// ---------------------------------------------------------------------------
// query — end-to-end KE + protected query, keyed off shared TLS exporter.
// ---------------------------------------------------------------------------

async function testQueryFullFlow(cert) {
  var aeadId = b.network.ntp.nts.AEAD_AES_SIV_CMAC_256;
  var shared = { s2cKey: null };

  var udp = await _startUdpServer(function (msg, rinfo, s) {
    if (!shared.s2cKey) return;
    var u = _findExtBody(msg, NTP_HEADER_BYTES, EXT_UNIQUE);
    if (!u) return;
    var plaintext = _ext(EXT_COOKIE, nodeCrypto.randomBytes(32));
    var reply = _buildReply({ aeadId: aeadId, s2cKey: shared.s2cKey, uniqueId: u, plaintext: plaintext });
    s.send(reply, 0, reply.length, rinfo.port, rinfo.address);
  });

  var ke = await _startKeServer(cert, { onData: function (sock) {
    // The KE server exports the SAME s2c keying material the client derives
    // (symmetric TLS 1.3 exporter), so its UDP sibling can authenticate.
    var ctxS2C = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x01]);
    shared.s2cKey = sock.exportKeyingMaterial(32, EXPORTER_LABEL, ctxS2C);
    return Buffer.concat([
      _rec(true, REC_NEXT_PROTOCOL, _u16(0)),
      _rec(true, REC_AEAD, _u16(aeadId)),
      _rec(false, REC_NEW_COOKIE, nodeCrypto.randomBytes(30)),
      _rec(false, REC_NTPV4_SERVER, Buffer.from("127.0.0.1", "ascii")),
      _rec(false, REC_NTPV4_PORT, _u16(udp.port)),
      _rec(true, REC_END, Buffer.alloc(0)),
    ]);
  } });

  try {
    var res = await helpers.withTestTimeout("nts query end-to-end", function () {
      return b.network.ntp.nts.query({
        host: "127.0.0.1", kePort: ke.port, servername: "localhost",
        ca: cert.ca.caCertPem, timeoutMs: 4000,
      });
    });
    check("query resolves authenticated", res.authenticated === true);
    check("query surfaces negotiated aeadId", res.aeadId === aeadId);
    check("query drift is numeric", typeof res.driftMs === "number" && isFinite(res.driftMs));
    check("query reports cookieCount", typeof res.cookieCount === "number" && res.cookieCount >= 1);
    check("query routed to the KE-advertised NTP server", res.server === "127.0.0.1");
  } finally {
    try { ke.server.close(); } catch (_e) { /* best-effort */ }
    try { udp.sock.close(); } catch (_e) { /* best-effort */ }
  }
}

// Handles finalize asynchronously past a forked worker's grace window; poll
// until every TCP/UDP handle this suite opened has actually closed so none
// outlives run() and holds the event loop open on a slow runner.
async function _drainHandles() {
  if (typeof process.getActiveResourcesInfo !== "function") return;
  try {
    await helpers.waitUntil(function () {
      return process.getActiveResourcesInfo().filter(function (t) {
        return t === "TCPSocketWrap" || t === "TCPServerWrap" || t === "UDPWrap";
      }).length === 0;
    }, { timeoutMs: 5000, label: "network-nts: TCP/UDP handle drain" });
  } catch (_e) { /* explicit closes already issued; best-effort settle */ }
}

async function run() {
  try {
    // Pure-crypto + synchronous validation (no listeners).
    testAesSivRoundtrip();
    testAesSivBadKey();
    testAesSivTamperFailsClosed();
    testKeInputValidation();
    testQuerySingleInputValidation();

    // One cert reused across every TLS listener.
    var cert = await _makeCert();

    await testKeBadAlpn(cert);
    await testKeAdversarialRecords(cert);
    await testKeSuccess(cert);
    await testKeByteCapFailsClosed(cert);
    await testKeTimeout(cert);
    await testKeSocketError();

    await testQuerySingleAdversarialReplies();
    await testQuerySingleAuthFailed();
    await testQuerySingleUnsupportedAeadEncrypt();
    await testQuerySingleTimeout();
    await testQuerySingleSivSuccess();
    await testQuerySingleChaChaSuccess();

    await testQueryFullFlow(cert);
  } finally {
    await _drainHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
