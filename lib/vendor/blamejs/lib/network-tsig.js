"use strict";
/**
 * @module b.network.dns.tsig
 * @nav    Network
 * @title  DNS TSIG
 *
 * @intro
 *   Sign and verify DNS messages with <a
 *   href="https://www.rfc-editor.org/rfc/rfc8945">RFC 8945</a> TSIG
 *   (Transaction SIGnature) — the shared-key HMAC that authenticates the
 *   transaction between a resolver and a server (zone transfers, dynamic
 *   updates, and any query/response pair) and proves it was not tampered
 *   with in flight. TSIG complements the existing DNSSEC and DANE
 *   primitives: DNSSEC authenticates zone <em>data</em> end-to-end, while
 *   TSIG authenticates a single hop's <em>transaction</em> with a
 *   pre-shared key.
 *
 *   <code>sign(message, opts)</code> appends a TSIG resource record to a
 *   DNS message and returns the signed wire bytes;
 *   <code>verify(message, opts)</code> locates the TSIG record, recomputes
 *   the HMAC over the RFC 8945 §4.3.3 digest, compares it in constant time,
 *   and checks the time window (the signature is only valid within
 *   <code>fudge</code> seconds of <code>timeSigned</code>). The default MAC
 *   algorithm is HMAC-SHA-256; SHA-384 / SHA-512 are available, and the
 *   broken HMAC-MD5 / HMAC-SHA-1 algorithms are refused unless
 *   <code>allowLegacy</code> is set. Signing a response chains the
 *   request's MAC into the digest (<code>requestMac</code>) per §5.4.1.
 *
 * @card
 *   RFC 8945 DNS TSIG — shared-key HMAC transaction authentication for DNS
 *   messages (sign / verify, constant-time MAC compare, time-window check,
 *   HMAC-SHA-256 default). The transaction-level companion to DNSSEC + DANE.
 */

var nodeCrypto = require("node:crypto");
var validateOpts = require("./validate-opts");
var { timingSafeEqual } = require("./crypto");
var { defineClass } = require("./framework-error");

var TsigError = defineClass("TsigError", { alwaysPermanent: true });

var TYPE_TSIG = 250;                                        // IANA RR type TSIG
var CLASS_ANY = 255;                                        // TSIG RRs use CLASS ANY
var DEFAULT_FUDGE = 300;

// Algorithm name → Node hash. The strong HMAC-SHA-2 family is the safe set;
// HMAC-MD5 and HMAC-SHA-1 are refused unless allowLegacy (kept only for
// interop with legacy nameservers).
var ALGORITHMS = {
  "hmac-sha256": "sha256",
  "hmac-sha384": "sha384",
  "hmac-sha512": "sha512",
  "hmac-sha224": "sha224",
};
var LEGACY_ALGORITHMS = {
  "hmac-sha1": "sha1",
  "hmac-md5": "md5",
};
// RFC 8945 §5.2.2.1 — TSIG error RCODEs.
var ERROR = { NOERROR: 0, BADSIG: 16, BADKEY: 17, BADTIME: 18, BADTRUNC: 22 };   // RFC 8945 extended-RCODE values

function _normAlg(name, allowLegacy) {
  var key = String(name || "hmac-sha256").toLowerCase().replace(/\.$/, "");
  if (ALGORITHMS[key]) return { name: key, hash: ALGORITHMS[key] };
  if (LEGACY_ALGORITHMS[key]) {
    if (!allowLegacy) throw new TsigError("tsig/legacy-algorithm", "tsig: algorithm '" + key + "' is broken; pass allowLegacy:true to permit it for legacy interop");
    return { name: key, hash: LEGACY_ALGORITHMS[key] };
  }
  throw new TsigError("tsig/bad-algorithm", "tsig: unknown algorithm '" + key + "'");
}

function _secretBuf(secret) {
  if (Buffer.isBuffer(secret)) return secret;
  if (typeof secret === "string") {
    // TSIG keys are conventionally transported as base64.
    var b = Buffer.from(secret, "base64");
    if (b.length === 0 && secret.length > 0) throw new TsigError("tsig/bad-secret", "tsig: secret must be base64 or a Buffer");
    return b;
  }
  throw new TsigError("tsig/bad-secret", "tsig: secret must be a base64 string or Buffer");
}

// Encode a domain name to uncompressed wire form (labels), lower-casing is
// NOT applied — TSIG uses the names as presented (key names are
// conventionally lower-case already; algorithm names are canonical).
function _encodeName(name) {
  var n = String(name).replace(/\.$/, "");
  if (n === "") return Buffer.from([0]);
  var parts = n.split(".");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var lab = Buffer.from(parts[i], "ascii");
    if (lab.length === 0 || lab.length > 63) throw new TsigError("tsig/bad-name", "tsig: invalid label in name '" + name + "'");   // RFC 1035 max label length
    out.push(Buffer.from([lab.length]), lab);
  }
  out.push(Buffer.from([0]));
  return Buffer.concat(out);
}

// Read a domain name starting at off, returning { name, end }. Handles a
// compression pointer as a terminal jump (TSIG only needs the END offset to
// keep walking; the pointed-at labels are resolved for the name string).
function _readName(buf, off) {
  var labels = [];
  var i = off;
  var end = -1;
  var jumps = 0;
  for (;;) {
    if (i >= buf.length) throw new TsigError("tsig/truncated", "tsig: truncated name in message");
    var len = buf[i];
    if (len === 0) { if (end === -1) end = i + 1; break; }
    if ((len & 0xc0) === 0xc0) {                            // RFC 1035 §4.1.4 compression-pointer flag
      if (i + 1 >= buf.length) throw new TsigError("tsig/truncated", "tsig: truncated compression pointer");
      if (end === -1) end = i + 2;
      var ptr = ((len & 0x3f) << 8) | buf[i + 1];           // 14-bit pointer offset
      if (++jumps > 128) throw new TsigError("tsig/bad-name", "tsig: compression-pointer loop");   // pointer-chase cap
      i = ptr;
      continue;
    }
    if ((len & 0xc0) !== 0) throw new TsigError("tsig/bad-name", "tsig: reserved label-length bits set");   // RFC 1035 label top-bits
    i++;
    labels.push(buf.slice(i, i + len).toString("ascii"));
    i += len;
  }
  return { name: labels.length ? labels.join(".") + "." : ".", end: end };
}

// Skip a name, returning the offset after it (compression-pointer aware).
function _skipName(buf, off) {
  var i = off;
  for (;;) {
    if (i >= buf.length) throw new TsigError("tsig/truncated", "tsig: truncated name");
    var len = buf[i];
    if (len === 0) return i + 1;
    if ((len & 0xc0) === 0xc0) return i + 2;                // compression pointer is terminal
    if ((len & 0xc0) !== 0) throw new TsigError("tsig/bad-name", "tsig: reserved label-length bits set");   // RFC 1035 label top-bits
    i += 1 + len;
  }
}

// Walk the message to the start of the LAST resource record, which a
// TSIG-bearing message requires to be the TSIG RR (RFC 8945 §5.1).
function _findTsigRr(buf) {
  if (buf.length < 12) throw new TsigError("tsig/truncated", "tsig: message shorter than the 12-byte header");   // DNS header length
  var qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6), ns = buf.readUInt16BE(8), ar = buf.readUInt16BE(10);
  if (ar < 1) throw new TsigError("tsig/no-tsig", "tsig: message has no additional records (no TSIG)");
  var off = 12;                                             // past the DNS header
  var q;
  for (q = 0; q < qd; q++) { off = _skipName(buf, off); off += 4; }   // QTYPE + QCLASS
  var total = an + ns + ar;
  var rrStart = -1;
  for (var r = 0; r < total; r++) {
    rrStart = off;
    off = _skipName(buf, off);
    if (off + 10 > buf.length) throw new TsigError("tsig/truncated", "tsig: truncated RR header");   // type+class+ttl+rdlength
    var rdlen = buf.readUInt16BE(off + 8);                  // rdlength offset within RR header
    off += 10 + rdlen;                                      // RR fixed header before RDATA
  }
  if (off !== buf.length) throw new TsigError("tsig/trailing-bytes", "tsig: trailing bytes after the final record");
  return rrStart;
}

// Build the TSIG-variables byte block (RFC 8945 §4.3.3).
function _tsigVariables(keyName, algName, timeSigned, fudge, error, otherData) {
  var time = Buffer.alloc(6);                               // 48-bit time-signed field
  time.writeUIntBE(timeSigned, 0, 6);                       // 48-bit big-endian
  var head = Buffer.alloc(6);                               // CLASS(2) + TTL(4)
  head.writeUInt16BE(CLASS_ANY, 0);
  head.writeUInt32BE(0, 2);                                 // TTL is always 0 (4 bytes)
  var tail = Buffer.alloc(6);                               // fudge(2)+error(2)+otherlen(2)
  tail.writeUInt16BE(fudge, 0);
  tail.writeUInt16BE(error, 2);
  tail.writeUInt16BE(otherData.length, 4);
  // DNS names are case-insensitive and the TSIG digest uses their canonical
  // (lower-cased) form (RFC 8945 §4.3.3 / RFC 4034 §6.2) — the on-the-wire
  // RR may carry any case, but both signer and verifier digest the
  // lower-cased name, so the MAC is stable across case differences.
  return Buffer.concat([_encodeName(String(keyName).toLowerCase()), head, _encodeName(String(algName).toLowerCase()), time, tail, otherData]);
}

function _requestMacPrefix(requestMac) {
  if (!requestMac) return Buffer.alloc(0);
  var len = Buffer.alloc(2);
  len.writeUInt16BE(requestMac.length, 0);
  return Buffer.concat([len, requestMac]);
}

/**
 * @primitive  b.network.dns.tsig.sign
 * @signature  b.network.dns.tsig.sign(message, opts)
 * @since      0.12.70
 * @status     stable
 * @related    b.network.dns.tsig.verify
 *
 * Append a TSIG resource record to a DNS message (a Buffer of wire bytes)
 * and return the signed wire Buffer. The MAC is the HMAC over the message
 * plus the RFC 8945 §4.3.3 TSIG variables. Returns
 * <code>{ wire, mac }</code> — <code>wire</code> is the message with the
 * TSIG RR appended and ARCOUNT incremented, and <code>mac</code> is the raw
 * HMAC (keep it to verify the matching response).
 *
 * @opts
 *   keyName:     string,            // REQUIRED — the shared-key name
 *   secret:      string | Buffer,   // REQUIRED — base64 string or raw bytes
 *   algorithm:   string,            // default: "hmac-sha256"
 *   fudge:       number,            // default: 300 (seconds)
 *   time:        number,            // default: now (Unix seconds)
 *   originalId:  number,            // default: the message's own ID
 *   requestMac:  Buffer,            // when signing a response (§5.4.1)
 *   error:       number,            // default: 0 (NOERROR)
 *   otherData:   Buffer,            // default: empty
 *   allowLegacy: boolean,           // permit HMAC-MD5 / HMAC-SHA-1
 *
 * @example
 *   var signed = b.network.dns.tsig.sign(queryWire, {
 *     keyName: "update.key.", secret: "<base64-secret>",
 *   });
 *   socket.send(signed.wire);
 */
function sign(message, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(message) || message.length < 12) throw new TsigError("tsig/bad-message", "tsig.sign: message must be a DNS wire Buffer");
  validateOpts.requireNonEmptyString(opts.keyName, "tsig.sign: keyName", TsigError, "tsig/bad-opt");
  var alg = _normAlg(opts.algorithm, opts.allowLegacy === true);
  var secret = _secretBuf(opts.secret);
  var fudge = opts.fudge == null ? DEFAULT_FUDGE : opts.fudge;
  if (typeof fudge !== "number" || !isFinite(fudge) || fudge < 0 || fudge > 0xffff) throw new TsigError("tsig/bad-opt", "tsig.sign: fudge must be 0..65535 seconds");   // 16-bit fudge field
  var time = opts.time == null ? Math.floor(Date.now() / 1000) : opts.time;
  if (typeof time !== "number" || !isFinite(time) || time < 0) throw new TsigError("tsig/bad-opt", "tsig.sign: time must be a non-negative Unix-seconds number");
  var error = opts.error == null ? 0 : opts.error;
  var otherData = Buffer.isBuffer(opts.otherData) ? opts.otherData : Buffer.alloc(0);
  var originalId = opts.originalId == null ? message.readUInt16BE(0) : opts.originalId;
  var algName = alg.name + ".";

  var digest = Buffer.concat([
    _requestMacPrefix(opts.requestMac),
    message,
    _tsigVariables(opts.keyName, algName, time, fudge, error, otherData),
  ]);
  var mac = nodeCrypto.createHmac(alg.hash, secret).update(digest).digest();

  // TSIG RDATA: algorithm name, time signed, fudge, MAC size + MAC,
  // original ID, error, other len + other data.
  var rtime = Buffer.alloc(6); rtime.writeUIntBE(time, 0, 6);   // 48-bit time-signed
  var fixed = Buffer.alloc(4);                                  // fudge(2)+macsize(2)
  fixed.writeUInt16BE(fudge, 0);
  fixed.writeUInt16BE(mac.length, 2);
  var trailer = Buffer.alloc(6);                                // origid(2)+error(2)+otherlen(2)
  trailer.writeUInt16BE(originalId, 0);
  trailer.writeUInt16BE(error, 2);
  trailer.writeUInt16BE(otherData.length, 4);
  var rdata = Buffer.concat([_encodeName(algName), rtime, fixed, mac, trailer, otherData]);

  var rrHead = Buffer.alloc(10);                               // type+class+ttl+rdlength
  rrHead.writeUInt16BE(TYPE_TSIG, 0);
  rrHead.writeUInt16BE(CLASS_ANY, 2);
  rrHead.writeUInt32BE(0, 4);                                  // TTL 0
  rrHead.writeUInt16BE(rdata.length, 8);                      // rdlength offset within the 10-byte RR header
  var tsigRr = Buffer.concat([_encodeName(opts.keyName), rrHead, rdata]);

  var out = Buffer.from(message);                             // copy so we can bump ARCOUNT
  out.writeUInt16BE(out.readUInt16BE(10) + 1, 10);            // ARCOUNT offset
  return { wire: Buffer.concat([out, tsigRr]), mac: mac };
}

function _parseTsigRr(buf, rrStart) {
  var n = _readName(buf, rrStart);
  var off = n.end;
  var type = buf.readUInt16BE(off);
  if (type !== TYPE_TSIG) throw new TsigError("tsig/not-tsig", "tsig: the final record is not a TSIG RR (type " + type + ")");
  // The MAC digest hard-codes CLASS ANY / TTL 0, so the on-wire CLASS and
  // TTL are outside the signed data — they MUST be validated explicitly or
  // an attacker could flip them in transit and still verify (RFC 8945 §4.2:
  // CLASS = ANY, TTL = 0).
  var rrClass = buf.readUInt16BE(off + 2);                   // CLASS offset within RR header
  var rrTtl = buf.readUInt32BE(off + 4);                     // TTL offset within RR header
  if (rrClass !== CLASS_ANY) throw new TsigError("tsig/bad-rr", "tsig: TSIG RR CLASS must be ANY (255), got " + rrClass);
  if (rrTtl !== 0) throw new TsigError("tsig/bad-rr", "tsig: TSIG RR TTL must be 0, got " + rrTtl);
  off += 8;                                                  // type(2)+class(2)+ttl(4)
  var rdlen = buf.readUInt16BE(off); off += 2;
  var rdStart = off;
  var alg = _readName(buf, off); off = alg.end;
  var timeSigned = buf.readUIntBE(off, 6); off += 6;         // 48-bit time-signed
  var fudge = buf.readUInt16BE(off); off += 2;
  var macSize = buf.readUInt16BE(off); off += 2;
  var mac = buf.slice(off, off + macSize); off += macSize;
  var originalId = buf.readUInt16BE(off); off += 2;
  var error = buf.readUInt16BE(off); off += 2;
  var otherLen = buf.readUInt16BE(off); off += 2;
  var otherData = buf.slice(off, off + otherLen); off += otherLen;
  if (off !== rdStart + rdlen) throw new TsigError("tsig/bad-rdata", "tsig: RDATA length mismatch");
  return {
    keyName: n.name, algName: alg.name.replace(/\.$/, ""), timeSigned: timeSigned, fudge: fudge,
    mac: mac, originalId: originalId, error: error, otherData: otherData, rrStart: rrStart,
  };
}

/**
 * @primitive  b.network.dns.tsig.verify
 * @signature  b.network.dns.tsig.verify(message, opts)
 * @since      0.12.70
 * @status     stable
 * @related    b.network.dns.tsig.sign
 *
 * Verify the TSIG record on a DNS message: locate the trailing TSIG RR,
 * recompute the HMAC over the RFC 8945 §4.3.3 digest, compare it in
 * constant time, and check that <code>now</code> is within
 * <code>fudge</code> seconds of <code>timeSigned</code>. Returns
 * <code>{ valid, keyName, algorithm, timeSigned, fudge, error, macValid,
 * timeValid, reason }</code>; <code>valid</code> is true only when the MAC
 * matches, the time window holds, and the embedded error is NOERROR. Never
 * throws for an authentication failure — only for a malformed message or
 * unknown key shape.
 *
 * @opts
 *   keys:        object,            // { "<keyName>": { secret, algorithm } }
 *   keyName:     string,            // single-key form (with secret)
 *   secret:      string | Buffer,   // single-key form
 *   algorithm:   string,            // expected algorithm (single-key form)
 *   now:         number,            // default: now (Unix seconds)
 *   requestMac:  Buffer,            // when verifying a response (§5.4.1)
 *   allowLegacy: boolean,
 *
 * @example
 *   var r = b.network.dns.tsig.verify(received, {
 *     keys: { "update.key.": { secret: "<base64>" } },
 *   });
 *   if (!r.valid) refuse(r.reason);
 */
function verify(message, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(message) || message.length < 12) throw new TsigError("tsig/bad-message", "tsig.verify: message must be a DNS wire Buffer");
  var rrStart = _findTsigRr(message);
  var rr = _parseTsigRr(message, rrStart);

  // Resolve the key for this RR's owner name. DNS names are
  // case-insensitive, so match the lower-cased, dot-trimmed forms.
  function _normName(s) { return String(s).toLowerCase().replace(/\.$/, ""); }
  var rrKeyNorm = _normName(rr.keyName);
  var keyEntry = null;
  if (opts.keys && typeof opts.keys === "object") {
    var ks = Object.keys(opts.keys);
    for (var ki = 0; ki < ks.length; ki++) {
      if (_normName(ks[ki]) === rrKeyNorm) { keyEntry = opts.keys[ks[ki]]; break; }
    }
  } else if (opts.keyName != null && _normName(opts.keyName) === rrKeyNorm) {
    keyEntry = { secret: opts.secret, algorithm: opts.algorithm };
  }
  if (!keyEntry) {
    return { valid: false, keyName: rr.keyName, algorithm: rr.algName, timeSigned: rr.timeSigned, fudge: rr.fudge, error: ERROR.BADKEY, macValid: false, timeValid: false, reason: "unknown key '" + rr.keyName + "'" };
  }
  var alg = _normAlg(keyEntry.algorithm || rr.algName, opts.allowLegacy === true);
  // The RR's algorithm must match the key's expected algorithm
  // (case-insensitive — _normAlg already lower-cases alg.name).
  if (alg.name !== rr.algName.toLowerCase()) {
    return { valid: false, keyName: rr.keyName, algorithm: rr.algName, timeSigned: rr.timeSigned, fudge: rr.fudge, error: ERROR.BADKEY, macValid: false, timeValid: false, reason: "algorithm mismatch (key expects " + alg.name + ", message used " + rr.algName + ")" };
  }
  var secret = _secretBuf(keyEntry.secret);

  // Reconstruct the digested message: bytes before the TSIG RR, with
  // ARCOUNT decremented and the ID restored to the original ID.
  var digestMsg = Buffer.from(message.slice(0, rrStart));
  digestMsg.writeUInt16BE(rr.originalId, 0);
  digestMsg.writeUInt16BE(digestMsg.readUInt16BE(10) - 1, 10);   // ARCOUNT offset

  var digest = Buffer.concat([
    _requestMacPrefix(opts.requestMac),
    digestMsg,
    _tsigVariables(rr.keyName, rr.algName + ".", rr.timeSigned, rr.fudge, rr.error, rr.otherData),
  ]);
  var expected = nodeCrypto.createHmac(alg.hash, secret).update(digest).digest();

  // Constant-time compare. A truncated MAC (macSize < full) is only valid
  // down to the RFC 8945 §5.2.2.1 floor of max(10, fullLen/2) octets.
  var macValid = false;
  if (rr.mac.length === expected.length) {
    macValid = timingSafeEqual(rr.mac, expected);
  } else if (rr.mac.length >= Math.max(10, expected.length / 2) && rr.mac.length < expected.length) {   // RFC 8945 §5.2.2.1 minimum truncated-MAC length
    macValid = timingSafeEqual(rr.mac, expected.slice(0, rr.mac.length));
  }

  var now = opts.now == null ? Math.floor(Date.now() / 1000) : opts.now;
  var timeValid = Math.abs(now - rr.timeSigned) <= rr.fudge;

  var reason = null;
  if (!macValid) reason = "MAC mismatch";
  else if (!timeValid) reason = "time outside fudge window";
  else if (rr.error !== ERROR.NOERROR) reason = "TSIG error code " + rr.error;

  return {
    valid: macValid && timeValid && rr.error === ERROR.NOERROR,
    keyName: rr.keyName, algorithm: rr.algName, timeSigned: rr.timeSigned, fudge: rr.fudge,
    error: macValid ? (timeValid ? rr.error : ERROR.BADTIME) : ERROR.BADSIG,
    macValid: macValid, timeValid: timeValid, reason: reason,
  };
}

module.exports = {
  sign:        sign,
  verify:      verify,
  ALGORITHMS:  ALGORITHMS,
  ERROR:       ERROR,
  TsigError:   TsigError,
};
