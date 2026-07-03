// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeTls = require("node:tls");
var dgram = require("node:dgram");
var nodeCrypto = require("node:crypto");

var C = require("./constants");
var { timingSafeEqual } = require("./crypto");
var validateOpts = require("./validate-opts");
var safeBuffer = require("./safe-buffer");
var { defineClass } = require("./framework-error");

var NtsError = defineClass("NtsError", { alwaysPermanent: false });

var NTS_KE_DEFAULT_PORT = 4460;
var NTPV4_DEFAULT_PORT  = 123;
// Upper bound on accumulated NTS-KE handshake bytes before a REC_END
// record terminates the exchange. A conformant NTS-KE response is a few
// hundred bytes (RFC 8915 §4); 64 KiB is generous. Without this ceiling
// a malicious or buggy server that streams non-END records fast enough
// OOMs the process before the wall-clock timer fires (it bounds time,
// not memory). Mirrors the ws-client handshake header cap.
var NTS_KE_HANDSHAKE_MAX_BYTES = C.BYTES.kib(64);
// RFC 5905 §6 — seconds between 1900-01-01T00:00Z (NTP epoch) and
// 1970-01-01T00:00Z (Unix epoch). Protocol-fixed (not a tunable).
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

// Protocol-fixed byte counts and offsets — every numeric literal that
// represents a wire-format size or position routes through C.BYTES.bytes
// (a value-passthrough) so the codebase has a single source of truth
// for "what shape is this number".
var AES_BLOCK_BYTES   = C.BYTES.bytes(16);   // AES-128/192/256 block size (RFC 3962)
var NTP_PACKET_BYTES  = C.BYTES.bytes(48);   // RFC 5905 §7.3 packet header length
var NTP_TX_TIMESTAMP_OFFSET = C.BYTES.bytes(40);  // RFC 5905 §7.3 — Transmit Timestamp
var POLY1305_TAG_BYTES = C.BYTES.bytes(16);  // RFC 8439 §2.5 tag length
var SIV_KEY_32_BYTES  = C.BYTES.bytes(32);
var SIV_KEY_48_BYTES  = C.BYTES.bytes(48);
var SIV_KEY_64_BYTES  = C.BYTES.bytes(64);
var UNIQUE_ID_BYTES   = C.BYTES.bytes(32);   // RFC 8915 §5.3 unique-identifier extension
var CHACHA20_NONCE_BYTES = C.BYTES.bytes(12);

// Bits per byte — used to derive the AES key bit-width from the byte
// length (16-byte key → 128-bit cipher → "aes-128-..." suffix).
var BITS_PER_BYTE = 8;

var REC_END                  = 0;
var REC_NEXT_PROTOCOL        = 1;
var REC_ERROR                = 2;
var REC_WARNING              = 3;
var REC_AEAD_ALGORITHM       = 4;
var REC_NEW_COOKIE           = 5;
var REC_NTPV4_SERVER         = 6;
var REC_NTPV4_PORT           = 7;

var NTPV4_PROTOCOL_ID = 0;

var AEAD_AES_SIV_CMAC_256    = 15;
var AEAD_CHACHA20_POLY1305   = 30;

var EXTENSION_UNIQUE_IDENTIFIER         = 0x0104;
var EXTENSION_NTS_COOKIE                 = 0x0204;
var EXTENSION_NTS_AUTHENTICATOR_AND_ENC  = 0x0404;

function _u16be(v) { var b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b; }

function _encodeRecord(critical, type, body) {
  var hdr = Buffer.alloc(4);
  var typeField = type & 0x7fff;
  if (critical) typeField |= 0x8000;
  hdr.writeUInt16BE(typeField, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function _decodeRecords(buf) {
  var out = [];
  var off = 0;
  while (off + 4 <= buf.length) {
    var t = buf.readUInt16BE(off);
    var critical = (t & 0x8000) !== 0;
    var type = t & 0x7fff;
    var len = buf.readUInt16BE(off + 2);
    off += 4;
    if (off + len > buf.length) {
      throw new NtsError("nts/bad-record", "NTS-KE record body length " + len + " exceeds buffer");
    }
    var body = buf.slice(off, off + len);
    off += len;
    out.push({ critical: critical, type: type, body: body });
    if (type === REC_END) break;
  }
  return out;
}

function _aesEncryptBlock(key, block) {
  // key.length is in bytes (16/24/32); multiply by BITS_PER_BYTE to get
  // the OpenSSL cipher-name suffix (128/192/256).
  var c = nodeCrypto.createCipheriv("aes-" + (key.length * BITS_PER_BYTE) + "-ecb", key, Buffer.alloc(0));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

function _shl1(buf) {
  var out = Buffer.alloc(buf.length);
  var carry = 0;
  for (var i = buf.length - 1; i >= 0; i--) {
    var v = (buf[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (v >> 8) & 1;
  }
  return out;
}

function _xorBuf(a, b) {
  var out = Buffer.alloc(a.length);
  for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function _cmacSubkeys(key) {
  var L = _aesEncryptBlock(key, Buffer.alloc(AES_BLOCK_BYTES, 0));
  var Rb = Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87]);
  var K1 = _shl1(L);
  if (L[0] & 0x80) K1 = _xorBuf(K1, Rb);
  var K2 = _shl1(K1);
  if (K1[0] & 0x80) K2 = _xorBuf(K2, Rb);
  return { K1: K1, K2: K2 };
}

function _cmac(key, message) {
  var subkeys = _cmacSubkeys(key);
  var n = Math.ceil(message.length / AES_BLOCK_BYTES);
  if (n === 0) n = 1;
  var lastIsComplete = (message.length > 0) && (message.length % AES_BLOCK_BYTES === 0);
  var blocks = [];
  for (var i = 0; i < n - 1; i++) {
    blocks.push(message.slice(i * AES_BLOCK_BYTES, i * AES_BLOCK_BYTES + AES_BLOCK_BYTES));
  }
  var lastBlock;
  if (lastIsComplete) {
    lastBlock = _xorBuf(message.slice((n - 1) * AES_BLOCK_BYTES, n * AES_BLOCK_BYTES), subkeys.K1);
  } else {
    var rem = message.slice((n - 1) * AES_BLOCK_BYTES);
    var padded = Buffer.alloc(AES_BLOCK_BYTES);
    rem.copy(padded);
    padded[rem.length] = 0x80;
    lastBlock = _xorBuf(padded, subkeys.K2);
  }
  blocks.push(lastBlock);
  var X = Buffer.alloc(AES_BLOCK_BYTES, 0);
  for (var b = 0; b < blocks.length; b++) {
    X = _aesEncryptBlock(key, _xorBuf(X, blocks[b]));
  }
  return X;
}

function _dbl(buf) {
  var Rb = Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87]);
  var shifted = _shl1(buf);
  if (buf[0] & 0x80) shifted = _xorBuf(shifted, Rb);
  return shifted;
}

function _s2v(K, strings, plaintext) {
  var D = _cmac(K, Buffer.alloc(AES_BLOCK_BYTES, 0));
  for (var i = 0; i < strings.length; i++) {
    D = _xorBuf(_dbl(D), _cmac(K, strings[i]));
  }
  var T;
  if (plaintext.length >= AES_BLOCK_BYTES) {
    var head = plaintext.slice(0, plaintext.length - AES_BLOCK_BYTES);
    var tail = plaintext.slice(plaintext.length - AES_BLOCK_BYTES);
    var xored = _xorBuf(tail, D);
    T = Buffer.concat([head, xored]);
  } else {
    var padded = Buffer.alloc(AES_BLOCK_BYTES);
    plaintext.copy(padded);
    padded[plaintext.length] = 0x80;
    T = _xorBuf(_dbl(D), padded);
  }
  return _cmac(K, T);
}

function _aesCtr(key, iv, data) {
  var ivCopy = Buffer.from(iv);
  // Clear the high bit of the 8th and 12th counter octets per RFC 5297 §2.6.
  ivCopy[8]  &= 0x7f;
  ivCopy[12] &= 0x7f;
  var c = nodeCrypto.createCipheriv("aes-" + (key.length * BITS_PER_BYTE) + "-ctr", key, ivCopy);
  return Buffer.concat([c.update(data), c.final()]);
}

function aesSivEncrypt(K, plaintext, associatedData) {
  if (K.length !== SIV_KEY_32_BYTES && K.length !== SIV_KEY_48_BYTES && K.length !== SIV_KEY_64_BYTES) {
    throw new NtsError("nts/bad-key", "AES-SIV key must be 32/48/64 bytes, got " + K.length);
  }
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = _s2v(K1, associatedData || [], plaintext);
  var ct = _aesCtr(K2, V, plaintext);
  return Buffer.concat([V, ct]);
}

function aesSivDecrypt(K, ciphertextWithIv, associatedData) {
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = ciphertextWithIv.slice(0, AES_BLOCK_BYTES);
  var ct = ciphertextWithIv.slice(AES_BLOCK_BYTES);
  var pt = _aesCtr(K2, V, ct);
  var Vcheck = _s2v(K1, associatedData || [], pt);
  if (!timingSafeEqual(V, Vcheck)) {
    throw new NtsError("nts/auth-failed", "AES-SIV authentication failed");
  }
  return pt;
}

function _negotiateAead(preferList) {
  var defaultList = [AEAD_AES_SIV_CMAC_256, AEAD_CHACHA20_POLY1305];
  var list = (preferList && preferList.length > 0) ? preferList : defaultList;
  var body = Buffer.alloc(list.length * 2);
  for (var i = 0; i < list.length; i++) body.writeUInt16BE(list[i], i * 2);
  return body;
}

function _buildKeRequest(opts) {
  var aeadBody = _negotiateAead(opts.aead);
  var nextProto = _u16be(NTPV4_PROTOCOL_ID);
  var records = [
    _encodeRecord(true, REC_NEXT_PROTOCOL, nextProto),
    _encodeRecord(true, REC_AEAD_ALGORITHM, aeadBody),
    _encodeRecord(true, REC_END, Buffer.alloc(0)),
  ];
  return Buffer.concat(records);
}

function _exportKeys(socket, aeadId) {
  var label = "EXPORTER-network-time-security";
  var contextC2S = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x00]);
  var contextS2C = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x01]);
  var keyLen = aeadId === AEAD_AES_SIV_CMAC_256 ? SIV_KEY_32_BYTES : SIV_KEY_32_BYTES;
  var c2s = socket.exportKeyingMaterial(keyLen, label, contextC2S);
  var s2c = socket.exportKeyingMaterial(keyLen, label, contextS2C);
  return { c2s: c2s, s2c: s2c };
}

function performKeHandshake(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "servername", "aead", "ca", "timeoutMs"], "nts.performKeHandshake");
  validateOpts.requireNonEmptyString(opts.host, "nts.performKeHandshake: host", NtsError, "nts/bad-host");
  validateOpts.optionalPort(opts.port, "nts.performKeHandshake: opts.port", NtsError, "nts/bad-ke-port");
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(10);
  return new Promise(function (resolve, reject) {
    var settled = false;
    function done(err, result) {
      if (settled) return;
      settled = true;
      if (err) reject(err); else resolve(result);
    }
    var connectOpts = {
      host:           opts.host,
      port:           opts.port || NTS_KE_DEFAULT_PORT,
      servername:     opts.servername || opts.host,
      ALPNProtocols:  ["ntske/1"],
      minVersion:     "TLSv1.3",
      ecdhCurve:      C.TLS_GROUP_CURVE_STR,
    };
    if (opts.ca) connectOpts.ca = opts.ca;
    var sock = nodeTls.connect(connectOpts);
    var timer = setTimeout(function () {
      try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
      done(new NtsError("nts/ke-timeout", "NTS-KE handshake timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
    timer.unref && timer.unref();
    sock.on("error", function (e) {
      clearTimeout(timer);
      done(new NtsError("nts/ke-socket", "NTS-KE socket error: " + e.message));
    });
    sock.on("secureConnect", function () {
      if (sock.alpnProtocol !== "ntske/1") {
        clearTimeout(timer);
        try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        done(new NtsError("nts/bad-alpn",
          "NTS-KE server did not negotiate ALPN 'ntske/1', got " + JSON.stringify(sock.alpnProtocol)));
        return;
      }
      var req = _buildKeRequest(opts);
      sock.write(req);
    });
    var got = Buffer.alloc(0);
    var warnings = [];
    sock.on("data", function (chunk) {
      got = Buffer.concat([got, chunk]);
      if (safeBuffer.byteLengthOf(got) > NTS_KE_HANDSHAKE_MAX_BYTES) {
        clearTimeout(timer);
        try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        done(new NtsError("nts/ke-too-large",
          "NTS-KE handshake exceeded " + NTS_KE_HANDSHAKE_MAX_BYTES +
          " bytes before a REC_END record"));
        return;
      }
      try {
        var records = _decodeRecords(got);
        var endRec = records.find(function (r) { return r.type === REC_END; });
        if (!endRec) return;
        clearTimeout(timer);
        var errRec  = records.find(function (r) { return r.type === REC_ERROR; });
        if (errRec) {
          try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          done(new NtsError("nts/ke-error", "NTS-KE server returned error code " + errRec.body.readUInt16BE(0)));
          return;
        }
        var warnRecs = records.filter(function (r) { return r.type === REC_WARNING; });
        if (warnRecs.length > 0) {
          warnings = warnRecs.map(function (r) {
            return r.body.length >= 2 ? r.body.readUInt16BE(0) : null;
          }).filter(function (v) { return v != null; });
        }
        var aeadRec = records.find(function (r) { return r.type === REC_AEAD_ALGORITHM; });
        if (!aeadRec || aeadRec.body.length < 2) {
          try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          done(new NtsError("nts/no-aead", "NTS-KE response missing AEAD algorithm"));
          return;
        }
        var aeadId = aeadRec.body.readUInt16BE(0);
        if (aeadId !== AEAD_AES_SIV_CMAC_256 && aeadId !== AEAD_CHACHA20_POLY1305) {
          try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          done(new NtsError("nts/unsupported-aead", "NTS-KE server selected unsupported AEAD " + aeadId));
          return;
        }
        var cookies = records.filter(function (r) { return r.type === REC_NEW_COOKIE; })
                              .map(function (r) { return r.body; });
        if (cookies.length === 0) {
          try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          done(new NtsError("nts/no-cookies", "NTS-KE response contained no cookies"));
          return;
        }
        var ntpServer = opts.host;
        var ntpPort   = NTPV4_DEFAULT_PORT;
        var srvRec = records.find(function (r) { return r.type === REC_NTPV4_SERVER; });
        if (srvRec) ntpServer = srvRec.body.toString("ascii");
        var portRec = records.find(function (r) { return r.type === REC_NTPV4_PORT; });
        if (portRec && portRec.body.length >= 2) ntpPort = portRec.body.readUInt16BE(0);
        var keys = _exportKeys(sock, aeadId);
        try { sock.end(); } catch (_e) { /* best-effort socket close */ }
        done(null, {
          aeadId:    aeadId,
          c2sKey:    keys.c2s,
          s2cKey:    keys.s2c,
          cookies:   cookies,
          ntpServer: ntpServer,
          ntpPort:   ntpPort,
          warnings:  warnings,
        });
      } catch (e) {
        clearTimeout(timer);
        try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        done(e);
      }
    });
  });
}

function _encodeExtensionField(type, body) {
  var padLen = (4 - (body.length % 4)) % 4;
  var padded = padLen === 0 ? body : Buffer.concat([body, Buffer.alloc(padLen)]);
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(padded.length + 4, 2);
  return Buffer.concat([hdr, padded]);
}

function _aeadEncrypt(aeadId, key, nonce, plaintext, aad) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) {
    var ad = aad ? [aad, nonce] : [nonce];
    return aesSivEncrypt(key, plaintext, ad);
  }
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    var c = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: POLY1305_TAG_BYTES });
    if (aad) c.setAAD(aad, { plaintextLength: plaintext.length });
    var ct = Buffer.concat([c.update(plaintext), c.final()]);
    var tag = c.getAuthTag();
    return Buffer.concat([ct, tag]);
  }
  throw new NtsError("nts/aead-unsupported", "aeadEncrypt: unsupported aead " + aeadId);
}

function _aeadDecrypt(aeadId, key, nonce, ciphertext, aad) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) {
    var ad = aad ? [aad, nonce] : [nonce];
    return aesSivDecrypt(key, ciphertext, ad);
  }
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    var ct = ciphertext.slice(0, ciphertext.length - POLY1305_TAG_BYTES);
    var tag = ciphertext.slice(ciphertext.length - POLY1305_TAG_BYTES);
    var d = nodeCrypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: POLY1305_TAG_BYTES });
    if (aad) d.setAAD(aad, { plaintextLength: ct.length });
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  }
  throw new NtsError("nts/aead-unsupported", "aeadDecrypt: unsupported aead " + aeadId);
}

function _nonceForAead(aeadId) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) return nodeCrypto.randomBytes(AES_BLOCK_BYTES);
  return nodeCrypto.randomBytes(CHACHA20_NONCE_BYTES);
}

function _walkExtensions(msg, startOff) {
  var exts = [];
  var off = startOff;
  while (off + 4 <= msg.length) {
    var t = msg.readUInt16BE(off);
    var len = msg.readUInt16BE(off + 2);
    if (len < 4 || off + len > msg.length) {
      throw new NtsError("nts/bad-extension", "NTS extension length " + len + " at offset " + off + " exceeds buffer");
    }
    exts.push({ type: t, start: off, len: len, body: msg.slice(off + 4, off + len) });
    off += len;
  }
  return exts;
}

function querySingle(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "aeadId", "c2sKey", "s2cKey", "cookies", "timeoutMs"], "nts.querySingle");
  validateOpts.optionalPort(opts.port, "nts.querySingle: opts.port", NtsError, "nts/bad-ntp-port");
  if (!Buffer.isBuffer(opts.c2sKey) || opts.c2sKey.length === 0) {
    throw new NtsError("nts/no-c2s-key", "nts.querySingle: c2sKey required (Buffer)");
  }
  if (!Buffer.isBuffer(opts.s2cKey) || opts.s2cKey.length === 0) {
    throw new NtsError("nts/no-s2c-key", "nts.querySingle: s2cKey required (Buffer)");
  }
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(5);
  if (!Array.isArray(opts.cookies) || opts.cookies.length === 0) {
    throw new NtsError("nts/no-cookies", "nts.querySingle: cookies array required");
  }
  return new Promise(function (resolve, reject) {
    var sock = dgram.createSocket("udp4");
    var settled = false;
    function done(err, result) {
      if (settled) return;
      settled = true;
      try { sock.close(); } catch (_e) { /* best-effort socket close */ }
      if (err) reject(err); else resolve(result);
    }
    var unique = nodeCrypto.randomBytes(UNIQUE_ID_BYTES);
    var cookie = opts.cookies[0];
    var packet = Buffer.alloc(NTP_PACKET_BYTES);
    packet[0] = 0x23;
    var ext1 = _encodeExtensionField(EXTENSION_UNIQUE_IDENTIFIER, unique);
    var ext2 = _encodeExtensionField(EXTENSION_NTS_COOKIE, cookie);
    var aeadHeader = Buffer.concat([packet, ext1, ext2]);
    var nonce = _nonceForAead(opts.aeadId);
    var encrypted = _aeadEncrypt(opts.aeadId, opts.c2sKey, nonce, Buffer.alloc(0), aeadHeader);
    var nonceLen = nonce.length;
    var ctLen = encrypted.length;
    var authBody = Buffer.alloc(4 + nonceLen + ctLen);
    authBody.writeUInt16BE(nonceLen, 0);
    authBody.writeUInt16BE(ctLen, 2);
    nonce.copy(authBody, 4);
    encrypted.copy(authBody, 4 + nonceLen);
    var ext3 = _encodeExtensionField(EXTENSION_NTS_AUTHENTICATOR_AND_ENC, authBody);
    var fullPacket = Buffer.concat([packet, ext1, ext2, ext3]);
    var sendTimeMs = Date.now();
    var timer = setTimeout(function () {
      done(new NtsError("nts/timeout", "NTS query timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
    timer.unref && timer.unref();
    sock.on("error", function (e) {
      clearTimeout(timer);
      done(new NtsError("nts/socket", "NTS udp error: " + e.message));
    });
    sock.on("message", function (msg) {
      clearTimeout(timer);
      var receiveTimeMs = Date.now();
      try {
        if (msg.length < NTP_PACKET_BYTES) {
          done(new NtsError("nts/bad-reply", "NTS reply too short"));
          return;
        }
        var exts;
        try { exts = _walkExtensions(msg, NTP_PACKET_BYTES); }
        catch (e) { done(e); return; }
        var uniqueExt = exts.find(function (e) { return e.type === EXTENSION_UNIQUE_IDENTIFIER; });
        if (!uniqueExt || uniqueExt.body.length < UNIQUE_ID_BYTES ||
            !timingSafeEqual(uniqueExt.body.slice(0, UNIQUE_ID_BYTES), unique)) {
          done(new NtsError("nts/unique-mismatch", "NTS reply unique-identifier mismatch (replay or spoof)"));
          return;
        }
        var authExt = exts.find(function (e) { return e.type === EXTENSION_NTS_AUTHENTICATOR_AND_ENC; });
        if (!authExt) {
          done(new NtsError("nts/no-authenticator", "NTS reply missing AUTHENTICATOR_AND_ENC extension (server not authenticated — unverifiable)"));
          return;
        }
        if (authExt.body.length < 4) {
          done(new NtsError("nts/bad-authenticator", "NTS authenticator body truncated"));
          return;
        }
        var replyNonceLen = authExt.body.readUInt16BE(0);
        var replyCtLen    = authExt.body.readUInt16BE(2);
        if (4 + replyNonceLen + replyCtLen > authExt.body.length) {
          done(new NtsError("nts/bad-authenticator", "NTS authenticator nonce+ct exceed body length"));
          return;
        }
        var replyNonce = authExt.body.slice(4, 4 + replyNonceLen);
        var replyCt    = authExt.body.slice(4 + replyNonceLen, 4 + replyNonceLen + replyCtLen);
        var aad = msg.slice(0, authExt.start);
        var encryptedExtPlain;
        try {
          encryptedExtPlain = _aeadDecrypt(opts.aeadId, opts.s2cKey, replyNonce, replyCt, aad);
        } catch (e) {
          done(new NtsError("nts/auth-failed", "NTS authenticator AEAD verification failed: " + e.message));
          return;
        }
        var newCookies = [];
        if (encryptedExtPlain && encryptedExtPlain.length >= 4) {
          var encExts;
          try { encExts = _walkExtensions(encryptedExtPlain, 0); }
          catch (_e) { encExts = []; }
          for (var ei = 0; ei < encExts.length; ei++) {
            if (encExts[ei].type === EXTENSION_NTS_COOKIE) {
              newCookies.push(Buffer.from(encExts[ei].body));
            }
          }
        }
        if (newCookies.length > 0) {
          opts.cookies.shift();
          for (var ci = 0; ci < newCookies.length; ci++) opts.cookies.push(newCookies[ci]);
        }
        var ntpSeconds  = msg.readUInt32BE(NTP_TX_TIMESTAMP_OFFSET);
        var ntpFraction = msg.readUInt32BE(NTP_TX_TIMESTAMP_OFFSET + 4);
        var serverUnixSeconds = ntpSeconds - NTP_TO_UNIX_OFFSET_SECONDS;
        var fracMs = Math.round(C.TIME.seconds(ntpFraction / 0x100000000));
        var serverTimeMs = C.TIME.seconds(serverUnixSeconds) + fracMs;
        var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
        var driftMs = serverTimeMs - midpointMs;
        done(null, {
          driftMs:        driftMs,
          serverTimeMs:   serverTimeMs,
          server:         opts.host,
          authenticated:  true,
          newCookieCount: newCookies.length,
          cookiesRemaining: opts.cookies.length,
        });
      } catch (e) {
        done(new NtsError("nts/bad-reply", "NTS reply processing failed: " + e.message));
      }
    });
    sock.send(fullPacket, 0, fullPacket.length, opts.port || NTPV4_DEFAULT_PORT, opts.host, function (err) {
      if (err) {
        clearTimeout(timer);
        done(new NtsError("nts/send", "NTS send failed: " + err.message));
      }
    });
  });
}

async function query(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "kePort", "ntpPort", "aead", "ca", "timeoutMs", "servername"], "nts.query");
  validateOpts.optionalPort(opts.kePort, "nts.query: opts.kePort", NtsError, "nts/bad-ke-port");
  validateOpts.optionalPort(opts.ntpPort, "nts.query: opts.ntpPort", NtsError, "nts/bad-ntp-port");
  var ke = await performKeHandshake({
    host:       opts.host,
    port:       opts.kePort,
    servername: opts.servername,
    aead:       opts.aead,
    ca:         opts.ca,
    timeoutMs:  opts.timeoutMs,
  });
  var result = await querySingle({
    host:     ke.ntpServer,
    port:     opts.ntpPort || ke.ntpPort,
    aeadId:   ke.aeadId,
    c2sKey:   ke.c2sKey,
    s2cKey:   ke.s2cKey,
    cookies:  ke.cookies,
    timeoutMs: opts.timeoutMs,
  });
  return Object.assign({}, result, { aeadId: ke.aeadId, cookieCount: ke.cookies.length });
}

module.exports = {
  performKeHandshake:    performKeHandshake,
  querySingle:           querySingle,
  query:                 query,
  aesSivEncrypt:         aesSivEncrypt,
  aesSivDecrypt:         aesSivDecrypt,
  AEAD_AES_SIV_CMAC_256: AEAD_AES_SIV_CMAC_256,
  AEAD_CHACHA20_POLY1305: AEAD_CHACHA20_POLY1305,
  NtsError:              NtsError,
};
