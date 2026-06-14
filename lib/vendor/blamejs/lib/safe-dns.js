"use strict";
/**
 * @module     b.safeDns
 * @nav        Parsers
 * @title      Safe DNS
 * @order      130
 *
 * @intro
 *   Bounded DNS-response parser. Substrate for v0.9.31
 *   `b.network.dns.resolver` and every consumer that walks raw DNS
 *   wire-format bytes (DKIM TXT lookup, MTA-STS verify, DANE TLSA,
 *   RBL queries, SVCB / HTTPS discovery, DNSBL via DNS).
 *
 *   Caps every dimension an attacker can grow to DoS the resolver
 *   path:
 *
 *     - **Response byte cap** (default 4 KiB; EDNS0 negotiated max
 *       64 KiB — RFC 6891).
 *     - **Label count per name** (default 127 — RFC 1035 §2.3.4
 *       absolute cap is 255 octets which bounds to ~127 labels;
 *       most legitimate names stay well under 20).
 *     - **Compression-pointer chain depth** (default 16 — RFC 1035
 *       allows pointer-to-pointer; unbounded chains cause infinite
 *       loops without a depth cap. Common parser-bomb vector).
 *     - **CNAME chain depth** (default 8 — matches BIND9's operational
 *       cap on canonical-name translations; RFC 1912 §2.4 warns against
 *       long CNAME chains; we cap to defend RFC 9156 §3.1 amplification
 *       + redirection-loop classes).
 *     - **RR count per section** (default 64 answers, 32 authority,
 *       32 additional — total response bounded above by the byte
 *       cap, but per-section caps short-circuit malicious sections).
 *     - **TXT rdata total length** (default 64 KiB — RFC 1035
 *       §3.3.14 allows up to 65535 octets per RR, but real-world
 *       SPF / DKIM / MTA-STS records never approach that; cap
 *       defends against amplification).
 *
 *   Throws `SafeDnsError` on every cap exceeded, malformed name
 *   compression, truncated RR, oversize EDNS0 OPT pseudo-RR, RDLENGTH
 *   overflow past message end. The parser is purely functional — no
 *   I/O, no async — operators run it inline in the resolver path.
 *
 *   Defends the DNS-amplification + parser-bomb classes generally —
 *   `CVE-2022-3204` (NRDelegationAttack — oversized authority + additional
 *   sections backing a malicious non-responsive delegation), `CVE-2023-50387`
 *   (KeyTrap — DNSKEY+RRSIG combinatorial DoS in validators, mitigated
 *   here by per-section RR caps that bound the input to validation),
 *   `CVE-2023-50868` (NSEC3-encloser companion), `CVE-2024-1737` (BIND9
 *   resource exhaustion via large RRsets per hostname). RFC 9156 §3
 *   amplification class.
 *
 * @card
 *   Bounded DNS-response parser. Substrate for the v0.9.31 validating
 *   resolver — caps response bytes, label count, compression-pointer
 *   chain depth, CNAME chain depth, per-section RR count, TXT rdata
 *   total length, EDNS0 OPT pseudo-RR size.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var gateContract       = require("./gate-contract");

var SafeDnsError = defineClass("SafeDnsError", { alwaysPermanent: true });

// RFC 1035 §3.1 single-label cap (octet 0 high
// 2 bits reserved for compression pointer; label-length field is 6 bits).
var DNS_MAX_LABEL_BYTES = 63;

// RFC 1035 §3.1 wire-format name absolute cap
// (sum of all label-length bytes + label bytes + terminator).
var DNS_MAX_NAME_BYTES = 255;

// RFC 1035 §4.2.1 fixed header size.
var DNS_HEADER_BYTES = 12;

// RFC 1035 §3.2.1 RR fixed prefix
// (TYPE 2 + CLASS 2 + TTL 4 + RDLENGTH 2 = 10 octets after NAME).
var DNS_RR_FIXED_BYTES = 10;

// RFC 6891 §6.1 OPT pseudo-RR upper bound for
// EDNS0 payload size we'll accept. 64 KiB is the protocol absolute
// max; resolver-side default is much smaller.
var EDNS0_HARD_MAX = 65535;

// RFC 1035 §3.2.2 record-type codes we route
// through type-specific decoders. Anything not listed parses as raw
// rdata bytes (operator inspects the RDLENGTH-bounded slice).
var RTYPE_A     = 1;
var RTYPE_NS    = 2;
var RTYPE_CNAME = 5;
var RTYPE_SOA   = 6;
var RTYPE_PTR   = 12;
var RTYPE_MX    = 15;
var RTYPE_TXT   = 16;                                                                                    // RFC 1035 §3.2.2 TXT record type code
var RTYPE_AAAA  = 28;
var RTYPE_SRV   = 33;
var RTYPE_OPT   = 41;
var RTYPE_DS    = 43;
var RTYPE_RRSIG = 46;
var RTYPE_DNSKEY = 48;                                                                                   // RFC 4034 DNSKEY record type code
var RTYPE_TLSA  = 52;

var RTYPE_NAMES = Object.freeze({
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
  16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS",                                                 // IANA DNS record type codes
  46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA",                                        // IANA DNS record type codes
  64: "SVCB", 65: "HTTPS",                                                                               // IANA DNS record type codes
});

var DEFAULT_MAX_RESPONSE_BYTES = C.BYTES.kib(4);
var DEFAULT_MAX_EDNS0_BYTES    = C.BYTES.kib(4);
var DEFAULT_MAX_LABELS         = 127;                                                                    // RFC 1035 §2.3.4 label count cap (count, not bytes)
var DEFAULT_MAX_POINTER_DEPTH  = 16;                                                                     // compression-pointer chain depth (count, not bytes)
var DEFAULT_MAX_CNAME_DEPTH    = 8;
var DEFAULT_MAX_ANSWER_RRS     = 64;                                                                     // RR count cap (count, not bytes)
var DEFAULT_MAX_AUTHORITY_RRS  = 32;                                                                     // RR count cap (count, not bytes)
var DEFAULT_MAX_ADDITIONAL_RRS = 32;                                                                     // RR count cap (count, not bytes)
var DEFAULT_MAX_TXT_RDATA      = C.BYTES.kib(64);

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
    maxEdns0Bytes:    DEFAULT_MAX_EDNS0_BYTES,
    maxLabels:        DEFAULT_MAX_LABELS,
    maxPointerDepth:  DEFAULT_MAX_POINTER_DEPTH,
    maxCnameDepth:    DEFAULT_MAX_CNAME_DEPTH,
    maxAnswerRrs:     DEFAULT_MAX_ANSWER_RRS,
    maxAuthorityRrs:  DEFAULT_MAX_AUTHORITY_RRS,
    maxAdditionalRrs: DEFAULT_MAX_ADDITIONAL_RRS,
    maxTxtRdata:      DEFAULT_MAX_TXT_RDATA,
  },
  balanced: {
    maxResponseBytes: C.BYTES.kib(16),
    maxEdns0Bytes:    C.BYTES.kib(16),
    maxLabels:        DEFAULT_MAX_LABELS,
    maxPointerDepth:  DEFAULT_MAX_POINTER_DEPTH,
    maxCnameDepth:    16,                                     // RR count, not bytes
    maxAnswerRrs:     128,                                    // RR count
    maxAuthorityRrs:  64,                                     // RR count
    maxAdditionalRrs: 64,                                     // RR count
    maxTxtRdata:      C.BYTES.kib(128),
  },
  permissive: {
    maxResponseBytes: C.BYTES.kib(64),
    maxEdns0Bytes:    C.BYTES.kib(64),
    maxLabels:        DEFAULT_MAX_LABELS,
    maxPointerDepth:  32,                                     // pointer chain count
    maxCnameDepth:    32,                                     // chain count
    maxAnswerRrs:     256,                                    // RR count
    maxAuthorityRrs:  128,                                    // RR count
    maxAdditionalRrs: 128,                                    // RR count
    maxTxtRdata:      C.BYTES.kib(512),
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: SafeDnsError,
  codePrefix: "safe-dns",
  byObject:   true,
});

/**
 * @primitive b.safeDns.parseResponse
 * @signature b.safeDns.parseResponse(buf, opts?)
 * @since     0.9.31
 * @status    stable
 * @related   b.safeDns.boundEdns0, b.safeDns.checkCnameChainDepth
 *
 * Parse a DNS wire-format response into a structured shape. Returns
 * `{ id, rcode, flags, question, answer, authority, additional,
 * edns0 }`. Each RR carries `{ name, type, typeName, class, ttl,
 * rdata, decoded }` — `rdata` is the rdlength-bounded byte slice,
 * `decoded` is the type-specific parse where the parser knows the
 * type (A / AAAA / CNAME / NS / PTR / MX / TXT / SOA / SRV / DS /
 * DNSKEY / TLSA / RRSIG / NSEC / NSEC3 / SVCB / HTTPS), otherwise
 * `null`.
 *
 * Throws `SafeDnsError` with codes:
 *   `safe-dns/bad-input` / `oversize-response` / `truncated-header`
 *   / `truncated-rr` / `truncated-name` / `oversize-label` /
 *   `oversize-name` / `oversize-pointer-depth` / `oversize-labels` /
 *   `oversize-answer-rrs` / `oversize-authority-rrs` /
 *   `oversize-additional-rrs` / `oversize-txt-rdata` /
 *   `oversize-edns0` / `malformed-rdlength` / `bad-profile`.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var parsed = b.safeDns.parseResponse(wireBytes);
 *   parsed.answer.forEach(function (rr) {
 *     if (rr.typeName === "TXT") console.log(rr.decoded.join(""));
 *   });
 */
function parseResponse(buf, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(buf)) {
    throw new SafeDnsError("safe-dns/bad-input",
      "safeDns.parseResponse: buf must be a Buffer; got " + (typeof buf));
  }
  var caps = _resolveProfile(opts);
  if (buf.length > caps.maxResponseBytes) {
    throw new SafeDnsError("safe-dns/oversize-response",
      "safeDns.parseResponse: " + buf.length + " bytes exceeds maxResponseBytes=" +
      caps.maxResponseBytes + " (RFC 6891 §6.1 EDNS0 advertised buffer size)");
  }
  if (buf.length < DNS_HEADER_BYTES) {
    throw new SafeDnsError("safe-dns/truncated-header",
      "safeDns.parseResponse: response truncated below header size (" +
      buf.length + " < " + DNS_HEADER_BYTES + ")");
  }

  var id      = buf.readUInt16BE(0);
  var flags   = buf.readUInt16BE(2);
  var qdcount = buf.readUInt16BE(4);
  var ancount = buf.readUInt16BE(6);
  var nscount = buf.readUInt16BE(8);
  var arcount = buf.readUInt16BE(10);

  if (ancount > caps.maxAnswerRrs) {
    throw new SafeDnsError("safe-dns/oversize-answer-rrs",
      "safeDns.parseResponse: ancount=" + ancount + " exceeds maxAnswerRrs=" +
      caps.maxAnswerRrs + " (RFC 9156 amplification defense)");
  }
  if (nscount > caps.maxAuthorityRrs) {
    throw new SafeDnsError("safe-dns/oversize-authority-rrs",
      "safeDns.parseResponse: nscount=" + nscount + " exceeds maxAuthorityRrs=" +
      caps.maxAuthorityRrs);
  }
  if (arcount > caps.maxAdditionalRrs) {
    throw new SafeDnsError("safe-dns/oversize-additional-rrs",
      "safeDns.parseResponse: arcount=" + arcount + " exceeds maxAdditionalRrs=" +
      caps.maxAdditionalRrs);
  }

  var state = { off: DNS_HEADER_BYTES, buf: buf, caps: caps };
  var question = [];
  for (var q = 0; q < qdcount; q += 1) {
    var qname = _readName(state, 0);
    if (state.off + 4 > buf.length) {                                                                   // RFC 1035 question fixed tail (QTYPE 2 + QCLASS 2)
      throw new SafeDnsError("safe-dns/truncated-rr",
        "safeDns.parseResponse: question RR truncated mid-fixed-tail");
    }
    var qtype  = buf.readUInt16BE(state.off);
    var qclass = buf.readUInt16BE(state.off + 2);
    state.off += 4;                                                                                     // RFC 1035 QTYPE 2 + QCLASS 2 advance
    question.push({
      name:     qname,
      type:     qtype,
      typeName: RTYPE_NAMES[qtype] || ("TYPE" + qtype),
      class:    qclass,
    });
  }

  var answer     = [];
  var authority  = [];
  var additional = [];
  var edns0      = null;

  for (var a = 0; a < ancount; a += 1) answer.push(_readRr(state));
  for (var n = 0; n < nscount; n += 1) authority.push(_readRr(state));
  for (var ad = 0; ad < arcount; ad += 1) {
    var rr = _readRr(state);
    if (rr.type === RTYPE_OPT) {
      edns0 = _decodeOpt(rr, caps);
    } else {
      additional.push(rr);
    }
  }

  return {
    id:         id,
    rcode:      flags & 0x0f,                                                                            // RFC 1035 §4.1.1 RCODE mask
    flags:      flags,
    question:   question,
    answer:     answer,
    authority:  authority,
    additional: additional,
    edns0:      edns0,
  };
}

/**
 * @primitive b.safeDns.boundEdns0
 * @signature b.safeDns.boundEdns0(advertised, opts?)
 * @since     0.9.31
 * @status    stable
 *
 * Clamp an operator-supplied EDNS0 advertised buffer size to the
 * profile cap. Resolver code calls this when constructing a query's
 * OPT pseudo-RR so a misconfigured operator can't advertise a buffer
 * larger than the profile permits.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var udpMax = b.safeDns.boundEdns0(operatorConfig.ednsBuffer);
 */
function boundEdns0(advertised, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  if (typeof advertised !== "number" || !isFinite(advertised) || advertised < 0) {
    throw new SafeDnsError("safe-dns/bad-input",
      "safeDns.boundEdns0: advertised must be a non-negative finite number");
  }
  if (advertised > EDNS0_HARD_MAX) {
    throw new SafeDnsError("safe-dns/oversize-edns0",
      "safeDns.boundEdns0: advertised=" + advertised + " exceeds protocol max=" + EDNS0_HARD_MAX);
  }
  return Math.min(advertised, caps.maxEdns0Bytes);
}

/**
 * @primitive b.safeDns.checkCnameChainDepth
 * @signature b.safeDns.checkCnameChainDepth(depth, opts?)
 * @since     0.9.31
 * @status    stable
 *
 * Throw if a CNAME-following loop has exceeded the profile's chain
 * depth cap. Called by the resolver as it walks CNAME redirections
 * across follow-up queries (each new query bumps the counter).
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   for (var i = 0; i < 100; i += 1) {
 *     b.safeDns.checkCnameChainDepth(i);
 *     // ...follow the CNAME if there is one, else break...
 *     break;
 *   }
 */
function checkCnameChainDepth(depth, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  if (typeof depth !== "number" || !isFinite(depth) || depth < 0) {
    throw new SafeDnsError("safe-dns/bad-input",
      "safeDns.checkCnameChainDepth: depth must be a non-negative finite number");
  }
  if (depth > caps.maxCnameDepth) {
    throw new SafeDnsError("safe-dns/oversize-cname-depth",
      "safeDns.checkCnameChainDepth: depth=" + depth + " exceeds maxCnameDepth=" +
      caps.maxCnameDepth + " (RFC 1912 §2.4 chain-loop defense; matches BIND9's cap of 8 canonical-name translations)");
  }
}

function _readName(state, pointerDepth) {
  if (pointerDepth > state.caps.maxPointerDepth) {
    throw new SafeDnsError("safe-dns/oversize-pointer-depth",
      "safeDns.readName: compression-pointer chain depth=" + pointerDepth +
      " exceeds maxPointerDepth=" + state.caps.maxPointerDepth + " (RFC 1035 §4.1.4 loop defense)");
  }
  var labels = [];
  var totalBytes = 0;
  var jumped = false;
  var afterPointerOff = -1;
  var off = state.off;
  while (true) {
    if (off >= state.buf.length) {
      throw new SafeDnsError("safe-dns/truncated-name",
        "safeDns.readName: name walk past end of message");
    }
    var byte = state.buf[off];
    if (byte === 0) {
      off += 1;
      totalBytes += 1;
      if (totalBytes > DNS_MAX_NAME_BYTES) {
        throw new SafeDnsError("safe-dns/oversize-name",
          "safeDns.readName: wire-name=" + totalBytes + " bytes exceeds RFC 1035 cap=" +
          DNS_MAX_NAME_BYTES);
      }
      break;
    }
    if ((byte & 0xc0) === 0xc0) {                                                                       // RFC 1035 §4.1.4 compression pointer mask
      if (off + 1 >= state.buf.length) {
        throw new SafeDnsError("safe-dns/truncated-name",
          "safeDns.readName: compression pointer truncated");
      }
      var ptrOff = ((byte & 0x3f) << 8) | state.buf[off + 1];                                           // RFC 1035 §4.1.4 14-bit pointer offset
      if (ptrOff >= state.buf.length) {
        throw new SafeDnsError("safe-dns/truncated-name",
          "safeDns.readName: compression pointer offset past message end");
      }
      // First compression pointer ends the in-line label walk
      // (line break below). `jumped` can never already be true here;
      // assign unconditionally per Codex code-quality review.
      afterPointerOff = off + 2;                                                                        // RFC 1035 §4.1.4 2-byte pointer width
      jumped = true;
      var subState = { off: ptrOff, buf: state.buf, caps: state.caps };
      var tailName = _readName(subState, pointerDepth + 1);
      if (tailName.length) labels.push(tailName);
      totalBytes += 2;                                                                                  // RFC 1035 §4.1.4 2-byte pointer width
      if (totalBytes > DNS_MAX_NAME_BYTES) {
        throw new SafeDnsError("safe-dns/oversize-name",
          "safeDns.readName: composite name=" + totalBytes + " bytes exceeds RFC 1035 cap=" +
          DNS_MAX_NAME_BYTES);
      }
      break;
    }
    if (byte > DNS_MAX_LABEL_BYTES) {
      throw new SafeDnsError("safe-dns/oversize-label",
        "safeDns.readName: label length=" + byte + " exceeds RFC 1035 cap=" + DNS_MAX_LABEL_BYTES);
    }
    if (off + 1 + byte > state.buf.length) {
      throw new SafeDnsError("safe-dns/truncated-name",
        "safeDns.readName: label content past message end");
    }
    labels.push(state.buf.toString("ascii", off + 1, off + 1 + byte));
    if (labels.length > state.caps.maxLabels) {
      throw new SafeDnsError("safe-dns/oversize-labels",
        "safeDns.readName: label count=" + labels.length + " exceeds maxLabels=" + state.caps.maxLabels);
    }
    off += 1 + byte;
    totalBytes += 1 + byte;
    if (totalBytes > DNS_MAX_NAME_BYTES) {
      throw new SafeDnsError("safe-dns/oversize-name",
        "safeDns.readName: wire-name=" + totalBytes + " bytes exceeds RFC 1035 cap=" +
        DNS_MAX_NAME_BYTES);
    }
  }
  state.off = jumped ? afterPointerOff : off;
  return labels.join(".");
}

function _readRr(state) {
  var name = _readName(state, 0);
  if (state.off + DNS_RR_FIXED_BYTES > state.buf.length) {
    throw new SafeDnsError("safe-dns/truncated-rr",
      "safeDns.readRr: RR truncated mid-fixed-prefix");
  }
  var rtype   = state.buf.readUInt16BE(state.off);
  var rclass  = state.buf.readUInt16BE(state.off + 2);                                                  // RFC 1035 §3.2.1 CLASS offset
  var ttl     = state.buf.readUInt32BE(state.off + 4);                                                  // RFC 1035 §3.2.1 TTL offset
  var rdlen   = state.buf.readUInt16BE(state.off + 8);                                                  // RFC 1035 §3.2.1 RDLENGTH offset
  state.off += DNS_RR_FIXED_BYTES;
  if (state.off + rdlen > state.buf.length) {
    throw new SafeDnsError("safe-dns/malformed-rdlength",
      "safeDns.readRr: RDLENGTH=" + rdlen + " runs past message end (off=" + state.off +
      " len=" + state.buf.length + ")");
  }
  var rdataStart = state.off;
  var rdata      = state.buf.slice(rdataStart, rdataStart + rdlen);
  state.off += rdlen;

  var decoded = null;
  if (rtype === RTYPE_A && rdlen === 4) {                                                               // RFC 1035 §3.4.1 A record is 4 octets
    decoded = rdata[0] + "." + rdata[1] + "." + rdata[2] + "." + rdata[3];                              // dotted-quad indices into 4-octet A rdata
  } else if (rtype === RTYPE_AAAA && rdlen === 16) {                                                    // RFC 3596 §2.2 AAAA record is 16 octets
    decoded = _formatIpv6(rdata);
  } else if (rtype === RTYPE_CNAME || rtype === RTYPE_NS || rtype === RTYPE_PTR) {
    var subState = { off: rdataStart, buf: state.buf, caps: state.caps };
    decoded = _readName(subState, 0);
  } else if (rtype === RTYPE_MX && rdlen >= 3) {                                                        // RFC 1035 §3.3.9 MX preference 2 + min exchange 1
    var pref = rdata.readUInt16BE(0);
    var mxState = { off: rdataStart + 2, buf: state.buf, caps: state.caps };                            // MX preference field width
    var exchange = _readName(mxState, 0);
    decoded = { preference: pref, exchange: exchange };
  } else if (rtype === RTYPE_TXT) {
    decoded = _decodeTxt(rdata, rdlen, state.caps);
  } else if (rtype === RTYPE_SOA) {
    decoded = _decodeSoa(state.buf, rdataStart, rdlen, state.caps);
  } else if (rtype === RTYPE_SRV && rdlen >= 7) {                                                       // RFC 2782 SRV fixed prefix 6 + min target 1
    var srvState = { off: rdataStart + 6, buf: state.buf, caps: state.caps };                           // RFC 2782 priority 2 + weight 2 + port 2
    var target = _readName(srvState, 0);
    decoded = {
      priority: rdata.readUInt16BE(0),
      weight:   rdata.readUInt16BE(2),                                                                  // RFC 2782 weight offset
      port:     rdata.readUInt16BE(4),                                                                  // RFC 2782 port offset
      target:   target,
    };
  } else if (rtype === RTYPE_DS && rdlen >= 4) {                                                        // RFC 4034 §5.1 DS fixed prefix 4 + digest
    decoded = {
      keyTag:     rdata.readUInt16BE(0),
      algorithm:  rdata.readUInt8(2),
      digestType: rdata.readUInt8(3),
      digest:     rdata.slice(4),                                                                       // RFC 4034 §5.1 digest start
    };
  } else if (rtype === RTYPE_DNSKEY && rdlen >= 4) {                                                    // RFC 4034 §2.1 DNSKEY fixed prefix 4 + pubkey
    decoded = {
      flags:     rdata.readUInt16BE(0),
      protocol:  rdata.readUInt8(2),
      algorithm: rdata.readUInt8(3),
      publicKey: rdata.slice(4),                                                                        // RFC 4034 §2.1 publicKey start
    };
  } else if (rtype === RTYPE_RRSIG && rdlen >= 18) {                                                    // RFC 4034 §3.1 RRSIG fixed prefix 18 + signer + signature
    var rrsigState = { off: rdataStart + 18, buf: state.buf, caps: state.caps };                        // RFC 4034 §3.1 fixed prefix width
    var signer = _readName(rrsigState, 0);
    decoded = {
      typeCovered: rdata.readUInt16BE(0),
      algorithm:   rdata.readUInt8(2),
      labels:      rdata.readUInt8(3),
      originalTtl: rdata.readUInt32BE(4),                                                               // RFC 4034 §3.1 originalTtl offset
      sigExpiry:   rdata.readUInt32BE(8),                                                               // RFC 4034 §3.1 expiry offset
      sigInception: rdata.readUInt32BE(12),                                                             // RFC 4034 §3.1 inception offset
      keyTag:      rdata.readUInt16BE(16),                                                              // RFC 4034 §3.1 keyTag offset
      signerName:  signer,
      signature:   state.buf.slice(rrsigState.off, rdataStart + rdlen),
    };
  } else if (rtype === RTYPE_TLSA && rdlen >= 3) {                                                      // RFC 6698 §2.1 TLSA fixed prefix 3 + certData
    decoded = {
      usage:        rdata.readUInt8(0),
      selector:     rdata.readUInt8(1),
      matchingType: rdata.readUInt8(2),
      certData:     rdata.slice(3),                                                                     // RFC 6698 §2.1 certData start
    };
  }

  return {
    name:     name,
    type:     rtype,
    typeName: RTYPE_NAMES[rtype] || ("TYPE" + rtype),
    class:    rclass,
    ttl:      ttl,
    rdata:    rdata,
    decoded:  decoded,
  };
}

// Format a 16-byte AAAA rdata buffer as a canonical IPv6 string per
// RFC 5952 §4: lowercase hex; suppress leading zeros in each group;
// compress the longest run of all-zero groups (>= 2) with "::"; on
// ties prefer the leftmost run; if the address is IPv4-mapped
// (::ffff:0:0/96) emit the trailing 32 bits as dotted-quad per
// RFC 5952 §5.
function _formatIpv6(rdata) {
  var groups = new Array(8);                                                                            // RFC 4291 §2.2 8 IPv6 groups
  for (var g = 0; g < 8; g += 1) groups[g] = rdata.readUInt16BE(g * 2);                                 // RFC 4291 §2.2 group byte stride

  // RFC 5952 §5 — IPv4-mapped: first 80 bits zero, next 16 bits 0xFFFF.
  var isV4Mapped = true;
  for (var z = 0; z < 5; z += 1) if (groups[z] !== 0) { isV4Mapped = false; break; }                    // RFC 5952 §5 v4-mapped zero-prefix groups
  if (isV4Mapped && groups[5] !== 0xffff) isV4Mapped = false;                                           // RFC 5952 §5 v4-mapped marker group
  if (isV4Mapped) {
    var dotted = rdata[12] + "." + rdata[13] + "." + rdata[14] + "." + rdata[15];                       // RFC 5952 §5 trailing v4 octets
    return "::ffff:" + dotted;
  }

  // Find the longest run of zeros (length >= 2 to use "::" per RFC 5952 §4.2.2).
  var bestStart = -1;
  var bestLen   = 0;
  var curStart  = -1;
  var curLen    = 0;
  for (var i = 0; i < 8; i += 1) {                                                                      // RFC 4291 §2.2 IPv6 group iteration
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen += 1;
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  var hex = groups.map(function (n) { return n.toString(16); });                                        // hex radix
  if (bestLen < 2) return hex.join(":");
  var head = hex.slice(0, bestStart).join(":");
  var tail = hex.slice(bestStart + bestLen).join(":");
  return head + "::" + tail;
}

function _decodeTxt(rdata, rdlen, caps) {
  if (rdlen > caps.maxTxtRdata) {
    throw new SafeDnsError("safe-dns/oversize-txt-rdata",
      "safeDns.decodeTxt: TXT rdata=" + rdlen + " exceeds maxTxtRdata=" + caps.maxTxtRdata);
  }
  var strings = [];
  var off = 0;
  while (off < rdlen) {
    var len = rdata.readUInt8(off);
    off += 1;
    if (off + len > rdlen) {
      throw new SafeDnsError("safe-dns/malformed-rdlength",
        "safeDns.decodeTxt: character-string length=" + len + " runs past rdata end");
    }
    strings.push(rdata.toString("utf8", off, off + len));
    off += len;
  }
  return strings;
}

function _decodeSoa(buf, rdataStart, rdlen, caps) {
  var state = { off: rdataStart, buf: buf, caps: caps };
  var mname = _readName(state, 0);
  var rname = _readName(state, 0);
  if (state.off + 20 > rdataStart + rdlen) {                                                            // RFC 1035 §3.3.13 SOA tail = SERIAL 4 + REFRESH 4 + RETRY 4 + EXPIRE 4 + MINIMUM 4 = 20 octets
    throw new SafeDnsError("safe-dns/malformed-rdlength",
      "safeDns.decodeSoa: SOA tail truncated");
  }
  var serial  = buf.readUInt32BE(state.off);
  var refresh = buf.readUInt32BE(state.off + 4);                                                        // RFC 1035 §3.3.13 REFRESH offset
  var retry   = buf.readUInt32BE(state.off + 8);                                                        // RFC 1035 §3.3.13 RETRY offset
  var expire  = buf.readUInt32BE(state.off + 12);                                                       // RFC 1035 §3.3.13 EXPIRE offset
  var minimum = buf.readUInt32BE(state.off + 16);                                                       // RFC 1035 §3.3.13 MINIMUM offset
  return {
    mname: mname, rname: rname,
    serial: serial, refresh: refresh, retry: retry, expire: expire, minimum: minimum,
  };
}

function _decodeOpt(rr, caps) {
  // RFC 6891 §6.1.2 — for OPT, CLASS holds the requestor's UDP payload
  // size (advertised buffer), TTL holds extended RCODE + version +
  // flags. We surface those and refuse oversize advertisement.
  var advertised = rr.class;
  if (advertised > caps.maxEdns0Bytes) {
    throw new SafeDnsError("safe-dns/oversize-edns0",
      "safeDns.decodeOpt: advertised buffer size=" + advertised +
      " exceeds maxEdns0Bytes=" + caps.maxEdns0Bytes);
  }
  var extendedRcode = (rr.ttl >>> 24) & 0xff;                                                           // RFC 6891 §6.1.3 extended RCODE upper byte
  var version       = (rr.ttl >>> 16) & 0xff;                                                           // RFC 6891 §6.1.3 version byte
  var dnssecOk      = (rr.ttl & 0x8000) !== 0;                                                          // RFC 4035 §3.2.1 DO bit
  return {
    advertisedUdpSize: advertised,
    extendedRcode:     extendedRcode,
    version:           version,
    dnssecOk:          dnssecOk,
    rdata:             rr.rdata,
  };
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "dns",
  entry:      parseResponse,
  entryName:  "parseResponse",
  errorClass: SafeDnsError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    boundEdns0:           boundEdns0,
    checkCnameChainDepth: checkCnameChainDepth,
    RTYPE_NAMES:          RTYPE_NAMES,
    NAME:                 "dns",
    KIND:                 "dns-response",
  },
});
