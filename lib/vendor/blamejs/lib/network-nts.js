// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeTls = require("node:tls");
var net = require("node:net");
var dgram = require("node:dgram");
var nodeCrypto = require("node:crypto");

var lazyRequire = require("./lazy-require");
var C = require("./constants");
var { timingSafeEqual } = require("./crypto");
var validateOpts = require("./validate-opts");
var safeBuffer = require("./safe-buffer");
var ipUtils = require("./ip-utils");
var ntpCheck = require("./ntp-check");
var networkDns = require("./network-dns");
var { defineClass } = require("./framework-error");
// networkTls — lazy so the outbound-TLS posture is read from live state at
// dial time (an operator's preferredGroups.set must reach the next
// connection), without pulling the TLS module into this one's boot graph.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

var NtsError = defineClass("NtsError", { alwaysPermanent: false });

var NTS_KE_DEFAULT_PORT = 4460;
var NTPV4_DEFAULT_PORT  = 123;
var NTS_KE_HANDSHAKE_MAX_BYTES = C.BYTES.kib(64);
var KE_DEFAULT_TIMEOUT_MS    = C.TIME.seconds(10);
var QUERY_DEFAULT_TIMEOUT_MS = C.TIME.seconds(5);

var AES_BLOCK_BYTES   = C.BYTES.bytes(16);
var NTP_PACKET_BYTES  = C.BYTES.bytes(48);
var NTP_REFID_OFFSET  = C.BYTES.bytes(12);
var POLY1305_TAG_BYTES = C.BYTES.bytes(16);
var SIV_KEY_32_BYTES  = C.BYTES.bytes(32);
var SIV_KEY_48_BYTES  = C.BYTES.bytes(48);
var SIV_KEY_64_BYTES  = C.BYTES.bytes(64);
var UNIQUE_ID_BYTES   = C.BYTES.bytes(32);
var CHACHA20_KEY_BYTES   = C.BYTES.bytes(32);
var CHACHA20_NONCE_BYTES = C.BYTES.bytes(12);
var HOSTNAME_MAX_BYTES = C.BYTES.bytes(253);
var LABEL_MAX_BYTES    = C.BYTES.bytes(63);

var BITS_PER_BYTE = 8;

var REC_END                 = 0;
var REC_NEXT_PROTOCOL        = 1;
var REC_ERROR                = 2;
var REC_WARNING              = 3;
var REC_AEAD_ALGORITHM       = 4;
var REC_NEW_COOKIE           = 5;
var REC_NTPV4_SERVER         = 6;
var REC_NTPV4_PORT           = 7;
var KNOWN_KE_RECORD_TYPES = [REC_END, REC_NEXT_PROTOCOL, REC_ERROR, REC_WARNING,
  REC_AEAD_ALGORITHM, REC_NEW_COOKIE, REC_NTPV4_SERVER, REC_NTPV4_PORT];

var NTPV4_PROTOCOL_ID = 0;

var EXTENSION_UNIQUE_IDENTIFIER         = 0x0104;
var EXTENSION_NTS_COOKIE                 = 0x0204;
var EXTENSION_NTS_AUTHENTICATOR_AND_ENC  = 0x0404;

var COOKIE_FIELDS_SENT = 1;

var KOD_NTS_NAK = "NTSN";

function _u16be(v) { var b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b; }
function _pad4(n) { return (n + 3) & ~3; }

function _encodeRecord(critical, type, body) {
  var hdr = Buffer.alloc(4);
  var typeField = type & 0x7fff;
  if (critical) typeField |= 0x8000;
  hdr.writeUInt16BE(typeField, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function _decodeRecords(buf, baseOffset) {
  var out = [];
  var off = 0;
  for (;;) {
    if (off + 4 > buf.length) return { records: out, consumed: off, need: 4, complete: false };
    var t = buf.readUInt16BE(off);
    var len = buf.readUInt16BE(off + 2);
    var end = off + 4 + len;
    if (baseOffset + end > NTS_KE_HANDSHAKE_MAX_BYTES) {
      throw new NtsError("nts/ke-too-large",
        "NTS-KE record ending at byte " + (baseOffset + end) + " exceeds the " + NTS_KE_HANDSHAKE_MAX_BYTES +
        "-byte handshake limit");
    }
    if (end > buf.length) return { records: out, consumed: off, need: 4 + len, complete: false };
    var type = t & 0x7fff;
    out.push({ critical: (t & 0x8000) !== 0, type: type, body: buf.slice(off + 4, end) });
    off = end;
    if (type === REC_END) return { records: out, consumed: off, need: 0, complete: true };
  }
}

function _keTooLarge() {
  return new NtsError("nts/ke-too-large",
    "NTS-KE handshake exceeded " + NTS_KE_HANDSHAKE_MAX_BYTES + " bytes before a REC_END record");
}

function _pendingCollector(remainingBytes) {
  if (remainingBytes <= 0) return null;
  return safeBuffer.boundedChunkCollector({
    maxBytes:    remainingBytes,
    errorClass:  NtsError,
    sizeCode:    "nts/ke-too-large",
    sizeMessage: _keTooLarge().message,
  });
}

function _createKeReader() {
  var pending = _pendingCollector(NTS_KE_HANDSHAKE_MAX_BYTES);
  var baseOffset = 0;
  var need = 4;
  var records = [];
  return {
    push: function (chunk) {
      if (!pending) throw _keTooLarge();
      pending.push(chunk);
      if (pending.bytesCollected() < need) return null;
      var buf = pending.result();
      var decoded = _decodeRecords(buf, baseOffset);
      for (var i = 0; i < decoded.records.length; i++) records.push(decoded.records[i]);
      if (decoded.complete) return records;
      baseOffset += decoded.consumed;
      need = decoded.need;
      pending = _pendingCollector(NTS_KE_HANDSHAKE_MAX_BYTES - baseOffset);
      if (pending && decoded.consumed < buf.length) pending.push(buf.subarray(decoded.consumed));
      return null;
    },
  };
}

function _aesEncryptBlock(key, block) {
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
  ivCopy[8]  &= 0x7f;
  ivCopy[12] &= 0x7f;
  var c = nodeCrypto.createCipheriv("aes-" + (key.length * BITS_PER_BYTE) + "-ctr", key, ivCopy);
  return Buffer.concat([c.update(data), c.final()]);
}

function _requireSivKey(K) {
  if (!Buffer.isBuffer(K) ||
      (K.length !== SIV_KEY_32_BYTES && K.length !== SIV_KEY_48_BYTES && K.length !== SIV_KEY_64_BYTES)) {
    throw new NtsError("nts/bad-key", "AES-SIV key must be a 32, 48 or 64 byte Buffer, got " +
      (Buffer.isBuffer(K) ? K.length + " bytes" : (K === null ? "null" : typeof K)));
  }
}

var SIV_MAX_AD_COMPONENTS = 126;

function _sivAssociatedData(associatedData) {
  if (associatedData === undefined || associatedData === null) return [];
  if (!Array.isArray(associatedData)) {
    throw new NtsError("nts/bad-input",
      "AES-SIV associated data must be an array of Buffers, got " +
      (Buffer.isBuffer(associatedData) ? "a Buffer" : "a " + typeof associatedData));
  }
  if (associatedData.length > SIV_MAX_AD_COMPONENTS) {
    throw new NtsError("nts/bad-input", "AES-SIV takes at most " + SIV_MAX_AD_COMPONENTS +
      " associated data components, got " + associatedData.length);
  }
  for (var i = 0; i < associatedData.length; i++) {
    if (!Buffer.isBuffer(associatedData[i])) {
      throw new NtsError("nts/bad-input", "AES-SIV associated data component " + i + " must be a Buffer, got " +
        (associatedData[i] === null ? "null" : "a " + typeof associatedData[i]));
    }
  }
  return associatedData;
}

function aesSivEncrypt(K, plaintext, associatedData) {
  _requireSivKey(K);
  if (!Buffer.isBuffer(plaintext)) {
    throw new NtsError("nts/bad-input", "AES-SIV plaintext must be a Buffer, got " +
      (plaintext === null ? "null" : "a " + typeof plaintext));
  }
  var ad = _sivAssociatedData(associatedData);
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = _s2v(K1, ad, plaintext);
  var ct = _aesCtr(K2, V, plaintext);
  return Buffer.concat([V, ct]);
}

function aesSivDecrypt(K, ciphertextWithIv, associatedData) {
  _requireSivKey(K);
  var ad = _sivAssociatedData(associatedData);
  if (!Buffer.isBuffer(ciphertextWithIv) || ciphertextWithIv.length < AES_BLOCK_BYTES) {
    throw new NtsError("nts/auth-failed", "AES-SIV authentication failed");
  }
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = ciphertextWithIv.slice(0, AES_BLOCK_BYTES);
  var ct = ciphertextWithIv.slice(AES_BLOCK_BYTES);
  var pt = _aesCtr(K2, V, ct);
  var Vcheck = _s2v(K1, ad, pt);
  if (!timingSafeEqual(V, Vcheck)) {
    throw new NtsError("nts/auth-failed", "AES-SIV authentication failed");
  }
  return pt;
}

function _chachaSeal(key, nonce, plaintext, aad) {
  var c = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: POLY1305_TAG_BYTES });
  c.setAAD(aad, { plaintextLength: plaintext.length });
  var ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}

function _chachaOpen(key, nonce, ciphertext, aad) {
  if (ciphertext.length < POLY1305_TAG_BYTES) {
    throw new NtsError("nts/auth-failed", "ciphertext is shorter than the ChaCha20-Poly1305 tag");
  }
  var ct = ciphertext.slice(0, ciphertext.length - POLY1305_TAG_BYTES);
  var tag = ciphertext.slice(ciphertext.length - POLY1305_TAG_BYTES);
  var d = nodeCrypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: POLY1305_TAG_BYTES });
  d.setAAD(aad, { plaintextLength: ct.length });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

var AEAD_AES_SIV_CMAC_256  = 15;
var AEAD_CHACHA20_POLY1305 = 29;
// registry: https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
var AEADS = Object.create(null);
AEADS[AEAD_AES_SIV_CMAC_256] = {
  name:       "AEAD_AES_SIV_CMAC_256",
  keyBytes:   SIV_KEY_32_BYTES,
  nonceBytes: AES_BLOCK_BYTES,
  seal: function (key, nonce, plaintext, aad) { return aesSivEncrypt(key, plaintext, [aad, nonce]); },
  open: function (key, nonce, ciphertext, aad) { return aesSivDecrypt(key, ciphertext, [aad, nonce]); },
};
AEADS[AEAD_CHACHA20_POLY1305] = {
  name:       "AEAD_CHACHA20_POLY1305",
  keyBytes:   CHACHA20_KEY_BYTES,
  nonceBytes: CHACHA20_NONCE_BYTES,
  seal:       _chachaSeal,
  open:       _chachaOpen,
};
var DEFAULT_AEAD_OFFER = [AEAD_AES_SIV_CMAC_256, AEAD_CHACHA20_POLY1305];

function _aeadFor(id) {
  return (typeof id === "number" && Object.prototype.hasOwnProperty.call(AEADS, id)) ? AEADS[id] : null;
}

function _aeadNames(list) {
  return list.map(function (id) { return id + " (" + AEADS[id].name + ")"; }).join(", ");
}

function _describeId(v) {
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  return v === null ? "null" : "a " + typeof v;
}

function _aeadOffer(list, label) {
  if (list === undefined || list === null) return DEFAULT_AEAD_OFFER.slice();
  if (!Array.isArray(list) || list.length === 0) {
    throw new NtsError("nts/bad-aead", label + " must be a non-empty array of AEAD ids, got " +
      (Array.isArray(list) ? "an empty array" : typeof list));
  }
  for (var i = 0; i < list.length; i++) {
    if (!_aeadFor(list[i])) {
      throw new NtsError("nts/bad-aead", label + "[" + i + "] " + _describeId(list[i]) +
        " is not an AEAD this client implements (" + _aeadNames(DEFAULT_AEAD_OFFER) + ")");
    }
    if (list.indexOf(list[i]) !== i) {
      throw new NtsError("nts/bad-aead", label + " lists AEAD " + list[i] + " more than once");
    }
  }
  return list.slice();
}

function _buildKeRequest(offer) {
  var aeadBody = Buffer.alloc(offer.length * 2);
  for (var i = 0; i < offer.length; i++) aeadBody.writeUInt16BE(offer[i], i * 2);
  return Buffer.concat([
    _encodeRecord(true, REC_NEXT_PROTOCOL, _u16be(NTPV4_PROTOCOL_ID)),
    _encodeRecord(true, REC_AEAD_ALGORITHM, aeadBody),
    _encodeRecord(true, REC_END, Buffer.alloc(0)),
  ]);
}

function _exportKeys(socket, aeadId) {
  var label = "EXPORTER-network-time-security";
  var contextC2S = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x00]);
  var contextS2C = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x01]);
  var keyLen = AEADS[aeadId].keyBytes;
  return {
    c2s: socket.exportKeyingMaterial(keyLen, label, contextC2S),
    s2c: socket.exportKeyingMaterial(keyLen, label, contextS2C),
  };
}

function _ofType(records, type) {
  return records.filter(function (r) { return r.type === type; });
}

function _isLdhHostname(s) {
  var name = s.charAt(s.length - 1) === "." ? s.slice(0, -1) : s;
  if (name.length === 0 || name.length > HOSTNAME_MAX_BYTES) return false;
  var labels = name.split(".");
  for (var i = 0; i < labels.length; i++) {
    var label = labels[i];
    if (label.length === 0 || label.length > LABEL_MAX_BYTES) return false;
    if (label.charAt(0) === "-" || label.charAt(label.length - 1) === "-") return false;
    for (var j = 0; j < label.length; j++) {
      var c = label.charCodeAt(j);
      var ok = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2d;
      if (!ok) return false;
    }
  }
  return true;
}

function _ntpServerFromRecord(body) {
  if (body.length === 0) {
    throw new NtsError("nts/bad-ntp-server", "NTS-KE NTPv4 Server record is empty");
  }
  for (var i = 0; i < body.length; i++) {
    if (body[i] < 0x21 || body[i] > 0x7e) {
      throw new NtsError("nts/bad-ntp-server",
        "NTS-KE NTPv4 Server record holds a byte outside printable ASCII at offset " + i);
    }
  }
  var s = body.toString("ascii");
  if (s.indexOf("%") !== -1) {
    throw new NtsError("nts/bad-ntp-server",
      "NTS-KE NTPv4 Server record " + JSON.stringify(s) + " carries a zone identifier");
  }
  if (net.isIP(s) !== 0) return s;
  if (!_isLdhHostname(s)) {
    throw new NtsError("nts/bad-ntp-server",
      "NTS-KE NTPv4 Server record " + JSON.stringify(s) + " is neither an IP address nor a host name");
  }
  return s.charAt(s.length - 1) === "." ? s : s + ".";
}

function _readKeResponse(records, offer) {
  var unknown = records.find(function (r) { return r.critical && KNOWN_KE_RECORD_TYPES.indexOf(r.type) === -1; });
  if (unknown) {
    throw new NtsError("nts/unrecognized-critical",
      "NTS-KE response carried critical record type " + unknown.type + ", which this client does not implement");
  }

  var errRecs = _ofType(records, REC_ERROR);
  if (errRecs.length > 0) {
    if (errRecs[0].body.length !== 2) {
      throw new NtsError("nts/bad-record",
        "NTS-KE Error record body must be 2 octets, got " + errRecs[0].body.length);
    }
    var errCode = errRecs[0].body.readUInt16BE(0);
    var keErr = new NtsError("nts/ke-error", "NTS-KE server returned error code " + errCode);
    keErr.ntsErrorCode = errCode;
    throw keErr;
  }

  var warnRecs = _ofType(records, REC_WARNING);
  if (warnRecs.length > 0) {
    if (warnRecs[0].body.length !== 2) {
      throw new NtsError("nts/bad-record",
        "NTS-KE Warning record body must be 2 octets, got " + warnRecs[0].body.length);
    }
    var warnCode = warnRecs[0].body.readUInt16BE(0);
    var keWarn = new NtsError("nts/ke-warning",
      "NTS-KE server returned warning code " + warnCode + ", which this client does not recognize");
    keWarn.ntsWarningCode = warnCode;
    throw keWarn;
  }

  var npRecs = _ofType(records, REC_NEXT_PROTOCOL);
  if (npRecs.length !== 1) {
    throw new NtsError("nts/bad-next-protocol",
      "NTS-KE response must carry exactly one Next Protocol record, got " + npRecs.length);
  }
  var np = npRecs[0];
  if (!np.critical) {
    throw new NtsError("nts/bad-next-protocol", "NTS-KE Next Protocol record does not have the critical bit set");
  }
  if (np.body.length % 2 !== 0) {
    throw new NtsError("nts/bad-next-protocol",
      "NTS-KE Next Protocol record body has odd length " + np.body.length);
  }
  if (np.body.length === 0) {
    throw new NtsError("nts/no-ntpv4", "NTS-KE server declined NTPv4");
  }
  for (var p = 0; p < np.body.length; p += 2) {
    var protocolId = np.body.readUInt16BE(p);
    if (protocolId !== NTPV4_PROTOCOL_ID) {
      throw new NtsError("nts/bad-next-protocol",
        "NTS-KE Next Protocol record names protocol " + protocolId + ", which the client did not offer");
    }
  }

  var aeadRecs = _ofType(records, REC_AEAD_ALGORITHM);
  if (aeadRecs.length === 0) {
    throw new NtsError("nts/no-aead", "NTS-KE response missing AEAD algorithm");
  }
  if (aeadRecs.length > 1) {
    throw new NtsError("nts/bad-record", "NTS-KE response carried " + aeadRecs.length + " AEAD records");
  }
  var aeadBody = aeadRecs[0].body;
  if (aeadBody.length === 0) {
    throw new NtsError("nts/no-aead",
      "NTS-KE server supports none of the offered AEAD algorithms (" + _aeadNames(offer) + ")");
  }
  if (aeadBody.length !== 2) {
    throw new NtsError("nts/bad-aead-response",
      "NTS-KE AEAD record must name one algorithm, got a " + aeadBody.length + "-byte body");
  }
  var aeadId = aeadBody.readUInt16BE(0);
  if (offer.indexOf(aeadId) === -1) {
    throw new NtsError("nts/bad-aead-response",
      "NTS-KE server selected AEAD " + aeadId + ", which the client did not offer (" + _aeadNames(offer) + ")");
  }

  var cookies = _ofType(records, REC_NEW_COOKIE).map(function (r) { return Buffer.from(r.body); });
  if (cookies.length === 0) {
    throw new NtsError("nts/no-cookies", "NTS-KE response contained no cookies");
  }

  var srvRecs = _ofType(records, REC_NTPV4_SERVER);
  if (srvRecs.length > 1) {
    throw new NtsError("nts/bad-ntp-server",
      "NTS-KE response carried " + srvRecs.length + " NTPv4 Server records");
  }
  var ntpServer = srvRecs.length === 1 ? _ntpServerFromRecord(srvRecs[0].body) : null;

  var portRecs = _ofType(records, REC_NTPV4_PORT);
  if (portRecs.length > 1) {
    throw new NtsError("nts/bad-ntp-port",
      "NTS-KE response carried " + portRecs.length + " NTPv4 Port records");
  }
  var ntpPort = NTPV4_DEFAULT_PORT;
  if (portRecs.length === 1) {
    if (portRecs[0].body.length !== 2) {
      throw new NtsError("nts/bad-ntp-port",
        "NTS-KE NTPv4 Port record body must be 2 octets, got " + portRecs[0].body.length);
    }
    ntpPort = portRecs[0].body.readUInt16BE(0);
    if (ntpPort === 0) {
      throw new NtsError("nts/bad-ntp-port", "NTS-KE NTPv4 Port record names port 0");
    }
  }

  return { aeadId: aeadId, cookies: cookies, ntpServer: ntpServer, ntpPort: ntpPort };
}

function performKeHandshake(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "servername", "aead", "ca", "timeoutMs"], "nts.performKeHandshake");
  validateOpts.requireNonEmptyString(opts.host, "nts.performKeHandshake: host", NtsError, "nts/bad-host");
  validateOpts.optionalPort(opts.port, "nts.performKeHandshake: opts.port", NtsError, "nts/bad-ke-port");
  var offer = _aeadOffer(opts.aead, "nts.performKeHandshake: opts.aead");
  var timeoutMs = ntpCheck._timeoutMs(opts.timeoutMs, "nts.performKeHandshake: opts.timeoutMs",
    NtsError, "nts/bad-timeout", KE_DEFAULT_TIMEOUT_MS);
  networkTls()._assertCaNotCompromised(opts.ca, {
    errorClass: NtsError, code: "nts/compromised-key", label: "nts.performKeHandshake: opts.ca",
  });
  var keHost = ipUtils.dialHost(opts.host);
  var identity = networkTls().identityFor(keHost, opts.servername, {
    label: "nts.performKeHandshake: opts.servername", errorClass: NtsError, code: "nts/bad-servername",
  });
  var request = _buildKeRequest(offer);
  return new Promise(function (resolve, reject) {
    var settled = false;
    var sock = null;
    var timer = null;
    function done(err, result) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (err && sock) { try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ } }
      if (err) reject(err); else resolve(result);
    }
    var connectOpts = Object.assign({
      host:           keHost,
      port:           opts.port || NTS_KE_DEFAULT_PORT,
      ALPNProtocols:  ["ntske/1"],
    }, identity, networkTls().outboundPosture(), {
      checkServerIdentity: networkTls()._withCompromisedChainCheck(undefined, opts.ca || undefined),
    });
    var anchors = networkTls()._clientTrustAnchors(opts.ca || undefined);
    if (anchors !== undefined) connectOpts.ca = anchors;
    try { sock = nodeTls.connect(connectOpts); }
    catch (e) {
      done(new NtsError("nts/ke-socket", "NTS-KE connect failed: " + ((e && e.message) || String(e))));
      return;
    }
    timer = setTimeout(function () {
      done(new NtsError("nts/ke-timeout", "NTS-KE handshake timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
    timer.unref && timer.unref();
    sock.on("error", function (e) {
      done(new NtsError(e && e.code === "tls/compromised-key" ? "nts/compromised-key" : "nts/ke-socket",
        "NTS-KE socket error: " + e.message));
    });
    var secured = false;
    sock.on("secureConnect", function () {
      secured = true;
      if (sock.alpnProtocol !== "ntske/1") {
        done(new NtsError("nts/bad-alpn",
          "NTS-KE server did not negotiate ALPN 'ntske/1', got " + JSON.stringify(sock.alpnProtocol)));
        return;
      }
      sock.write(request);
    });
    function onPeerClosed() {
      done(secured
        ? new NtsError("nts/ke-closed", "server closed the NTS-KE connection before End of Message")
        : new NtsError("nts/ke-socket", "NTS-KE server closed the connection before the TLS handshake completed"));
    }
    sock.on("end", function () { if (secured) onPeerClosed(); });
    sock.on("close", onPeerClosed);
    var reader = _createKeReader();
    sock.on("data", function (chunk) {
      if (settled) return;
      var result;
      var keys;
      try {
        var records = reader.push(chunk);
        if (!records) return;
        result = _readKeResponse(records, offer);
        keys = _exportKeys(sock, result.aeadId);
      } catch (e) {
        done(e instanceof NtsError ? e
          : new NtsError("nts/bad-record", "NTS-KE response processing failed: " + ((e && e.message) || String(e))));
        return;
      }
      var ntpServer = result.ntpServer || sock.remoteAddress || opts.host;
      done(null, {
        aeadId:    result.aeadId,
        c2sKey:    keys.c2s,
        s2cKey:    keys.s2c,
        cookies:   result.cookies,
        ntpServer: ntpServer,
        ntpPort:   result.ntpPort,
      });
      try { sock.end(); } catch (_e) { /* best-effort socket close */ }
    });
  });
}

function _encodeExtensionField(type, body) {
  var padLen = _pad4(body.length) - body.length;
  var padded = padLen === 0 ? body : Buffer.concat([body, Buffer.alloc(padLen)]);
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(padded.length + 4, 2);
  return Buffer.concat([hdr, padded]);
}

function _authenticatorBody(nonce, ciphertext) {
  var nonceField = _pad4(nonce.length);
  var body = Buffer.alloc(4 + nonceField + ciphertext.length);
  body.writeUInt16BE(nonce.length, 0);
  body.writeUInt16BE(ciphertext.length, 2);
  nonce.copy(body, 4);
  ciphertext.copy(body, 4 + nonceField);
  return body;
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

function _isNtsNak(msg) {
  return msg[1] === 0 &&
    msg.slice(NTP_REFID_OFFSET, NTP_REFID_OFFSET + KOD_NTS_NAK.length).toString("latin1") === KOD_NTS_NAK;
}

function _readReply(msg, ctx) {
  if (msg.length < NTP_PACKET_BYTES) {
    return { discard: new NtsError("nts/bad-reply", "NTS reply too short") };
  }
  var exts;
  try { exts = _walkExtensions(msg, NTP_PACKET_BYTES); }
  catch (e) { return { discard: e }; }
  var uniqueExt = exts.find(function (e) { return e.type === EXTENSION_UNIQUE_IDENTIFIER; });
  if (!uniqueExt || uniqueExt.body.length < UNIQUE_ID_BYTES ||
      !timingSafeEqual(uniqueExt.body.slice(0, UNIQUE_ID_BYTES), ctx.unique)) {
    return { discard: new NtsError("nts/unique-mismatch", "NTS reply unique-identifier mismatch (replay or spoof)") };
  }
  var authExt = exts.find(function (e) { return e.type === EXTENSION_NTS_AUTHENTICATOR_AND_ENC; });
  if (!authExt) {
    if (_isNtsNak(msg)) {
      return { discard: new NtsError("nts/nak", "NTS server sent an NTS NAK; run NTS-KE again for fresh cookies") };
    }
    return { discard: new NtsError("nts/no-authenticator",
      "NTS reply carries no NTS Authenticator extension, so it cannot be verified") };
  }
  if (authExt.body.length < 4) {
    return { discard: new NtsError("nts/bad-authenticator", "NTS authenticator body truncated") };
  }
  var replyNonceLen   = authExt.body.readUInt16BE(0);
  var replyCtLen      = authExt.body.readUInt16BE(2);
  var replyNonceField = _pad4(replyNonceLen);
  if (4 + replyNonceField + replyCtLen > authExt.body.length) {
    return { discard: new NtsError("nts/bad-authenticator", "NTS authenticator nonce+ct exceed body length") };
  }
  var replyNonce = authExt.body.slice(4, 4 + replyNonceLen);
  var replyCt    = authExt.body.slice(4 + replyNonceField, 4 + replyNonceField + replyCtLen);
  var plaintext;
  try {
    plaintext = ctx.aead.open(ctx.s2cKey, replyNonce, replyCt, msg.slice(0, authExt.start));
  } catch (e) {
    return { discard: new NtsError("nts/auth-failed",
      "NTS authenticator AEAD verification failed: " + ((e && e.message) || String(e))) };
  }

  var newCookies = [];
  if (plaintext && plaintext.length >= 4) {
    var encExts;
    try { encExts = _walkExtensions(plaintext, 0); }
    catch (_e) { encExts = []; }
    for (var ei = 0; ei < encExts.length && newCookies.length < COOKIE_FIELDS_SENT; ei++) {
      if (encExts[ei].type === EXTENSION_NTS_COOKIE) newCookies.push(Buffer.from(encExts[ei].body));
    }
  }
  var decoded = ntpCheck._decodeServerReply(msg, { versions: [4] });
  if (!decoded.ok) {
    return { newCookies: newCookies, fail: new NtsError("nts/unsynchronized",
      "NTS reply mode=" + decoded.mode + " version=" + decoded.vn + " stratum=" + decoded.stratum +
      " LI=" + decoded.li + " is not a synchronized NTPv4 server response: " + decoded.reason) };
  }
  return { newCookies: newCookies, reply: { serverTimeMs: decoded.serverTimeMs } };
}

function querySingle(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "aeadId", "c2sKey", "s2cKey", "cookies", "timeoutMs"], "nts.querySingle");
  validateOpts.requireNonEmptyString(opts.host, "nts.querySingle: host", NtsError, "nts/bad-host");
  validateOpts.optionalPort(opts.port, "nts.querySingle: opts.port", NtsError, "nts/bad-ntp-port");
  if (!Buffer.isBuffer(opts.c2sKey) || opts.c2sKey.length === 0) {
    throw new NtsError("nts/no-c2s-key", "nts.querySingle: c2sKey required (Buffer)");
  }
  if (!Buffer.isBuffer(opts.s2cKey) || opts.s2cKey.length === 0) {
    throw new NtsError("nts/no-s2c-key", "nts.querySingle: s2cKey required (Buffer)");
  }
  if (!Array.isArray(opts.cookies) || opts.cookies.length === 0 ||
      !Buffer.isBuffer(opts.cookies[0]) || opts.cookies[0].length === 0) {
    throw new NtsError("nts/no-cookies", "nts.querySingle: cookies array of non-empty Buffers required");
  }
  var aead = _aeadFor(opts.aeadId);
  if (!aead) {
    throw new NtsError("nts/unsupported-aead", "nts.querySingle: aeadId " + _describeId(opts.aeadId) +
      " is not an AEAD this client implements (" + _aeadNames(DEFAULT_AEAD_OFFER) + ")");
  }
  if (opts.c2sKey.length !== aead.keyBytes || opts.s2cKey.length !== aead.keyBytes) {
    throw new NtsError("nts/bad-key", "nts.querySingle: " + aead.name + " keys must be " + aead.keyBytes +
      " bytes, got c2sKey " + opts.c2sKey.length + " and s2cKey " + opts.s2cKey.length);
  }
  var timeoutMs = ntpCheck._timeoutMs(opts.timeoutMs, "nts.querySingle: opts.timeoutMs",
    NtsError, "nts/bad-timeout", QUERY_DEFAULT_TIMEOUT_MS);
  var port = opts.port || NTPV4_DEFAULT_PORT;

  var unique = nodeCrypto.randomBytes(UNIQUE_ID_BYTES);
  var packet = Buffer.alloc(NTP_PACKET_BYTES);
  packet[0] = 0x23;
  var ext1 = _encodeExtensionField(EXTENSION_UNIQUE_IDENTIFIER, unique);
  var ext2 = _encodeExtensionField(EXTENSION_NTS_COOKIE, opts.cookies[0]);
  var aeadHeader = Buffer.concat([packet, ext1, ext2]);
  var nonce = nodeCrypto.randomBytes(aead.nonceBytes);
  var sealed = aead.seal(opts.c2sKey, nonce, Buffer.alloc(0), aeadHeader);
  var ext3 = _encodeExtensionField(EXTENSION_NTS_AUTHENTICATOR_AND_ENC, _authenticatorBody(nonce, sealed));
  var fullPacket = Buffer.concat([aeadHeader, ext3]);
  opts.cookies.shift();
  var ctx = { unique: unique, aead: aead, s2cKey: opts.s2cKey };

  return new Promise(function (resolve, reject) {
    var sock = null;
    var settled = false;
    var lastDiscard = null;
    var timer = setTimeout(function () {
      done(lastDiscard || new NtsError("nts/timeout", "NTS query timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
    timer.unref && timer.unref();
    function done(err, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (sock) { try { sock.close(); } catch (_e) { /* best-effort socket close */ } }
      if (err) reject(err); else resolve(result);
    }

    networkDns._resolveUdpTarget(opts.host).then(function (target) {
      if (settled) return;
      sock = dgram.createSocket(target.family === 6 ? "udp6" : "udp4");
      var sendTimeMs = Date.now();
      sock.on("error", function (e) {
        done(new NtsError("nts/socket", "NTS udp error: " + e.message));
      });
      sock.on("message", function (msg, rinfo) {
        if (settled) return;
        var receiveTimeMs = Date.now();
        if (!rinfo || rinfo.port !== port || !ntpCheck._sameAddress(rinfo.address, target.address)) {
          lastDiscard = new NtsError("nts/bad-reply", "NTS query discarded a datagram from " +
            (rinfo && rinfo.address) + ":" + (rinfo && rinfo.port) + ", which is not the queried server");
          return;
        }
        var outcome;
        try { outcome = _readReply(msg, ctx); }
        catch (e) {
          outcome = { discard: new NtsError("nts/bad-reply",
            "NTS reply processing failed: " + ((e && e.message) || String(e))) };
        }
        if (outcome.discard) { lastDiscard = outcome.discard; return; }
        for (var ci = 0; ci < outcome.newCookies.length; ci++) opts.cookies.push(outcome.newCookies[ci]);
        if (outcome.fail) { done(outcome.fail); return; }
        var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
        done(null, {
          driftMs:          outcome.reply.serverTimeMs - midpointMs,
          serverTimeMs:     outcome.reply.serverTimeMs,
          server:           opts.host,
          authenticated:    true,
          newCookieCount:   outcome.newCookies.length,
          cookiesRemaining: opts.cookies.length,
        });
      });
      try {
        sock.send(fullPacket, 0, fullPacket.length, port, target.address, function (err) {
          if (err) done(new NtsError("nts/send", "NTS send failed: " + err.message));
        });
      } catch (e) {
        done(new NtsError("nts/send", "NTS send failed: " + e.message));
      }
    }, function (e) {
      done(new NtsError("nts/send", "NTS could not resolve " + JSON.stringify(opts.host) + ": " +
        ((e && e.message) || String(e))));
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
    servername: opts.servername,   // allow:tls-servername-not-dialed (performKeHandshake passes it through identityFor)
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
  _createKeReader:       _createKeReader,
};
