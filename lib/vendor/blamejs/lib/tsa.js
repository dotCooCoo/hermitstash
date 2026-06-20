"use strict";
/**
 * @module b.tsa
 * @nav    Crypto
 * @title  Timestamping (RFC 3161)
 *
 * @intro
 *   An RFC 3161 Time-Stamp Protocol client — the requester / verifier
 *   side, not a TSA. A timestamp authority binds a hash of your data to
 *   a trusted time, producing a timestamp token that proves the data
 *   existed at that instant: timestamp a release artifact, an audit-log
 *   checkpoint, a <code>b.scitt</code> signed statement, a contract.
 *
 *   <code>b.tsa.buildRequest(data, opts)</code> produces the DER
 *   TimeStampReq (a message imprint = the hash of your data, plus an
 *   optional nonce and a request for the TSA's certificate);
 *   <code>b.tsa.parseResponse(der)</code> reads the TimeStampResp,
 *   surfacing the PKIStatus (and any failure-info bits) and the token;
 *   <code>b.tsa.verifyToken(token, opts)</code> verifies the token
 *   against your data and returns the asserted time. The transport (an
 *   HTTP POST of <code>application/timestamp-query</code> to the TSA's
 *   URL) is the operator's to make — the framework builds the request
 *   and verifies the response.
 *
 *   <strong>Verification</strong> (RFC 3161 §2.4.2 / §2.3) is the
 *   security-bearing part and is done in full: the token is a CMS
 *   SignedData (<code>b.cms</code>) whose eContentType must be
 *   <code>id-ct-TSTInfo</code>; the message imprint inside the TSTInfo
 *   must equal the hash of your data (constant-time compare); a sent
 *   nonce must round-trip; the signer's certificate must carry the
 *   <code>id-kp-timeStamping</code> extended key usage, marked critical
 *   and as the <em>only</em> EKU; and the CMS signature over the signed
 *   attributes must verify (the <code>messageDigest</code> attribute is
 *   checked against the recomputed eContent digest first). An optional
 *   trust-anchor set verifies the certificate chain and validity at the
 *   asserted time.
 *
 *   <strong>Algorithms.</strong> Timestamp tokens are third-party
 *   artifacts: public TSAs sign with classical RSA (PKCS#1 v1.5 or PSS)
 *   or ECDSA over SHA-2, so verification accepts those — the same
 *   consume-what-exists stance as <code>b.cose</code> verification. This
 *   is not a signing default (the framework is not the TSA); it is
 *   verification of externally-produced tokens. The message-imprint
 *   hash you request defaults to SHA-512 and may be any of SHA-256 /
 *   384 / 512 or SHA3-256 / 512 the TSA supports.
 *
 * @card
 *   RFC 3161 timestamp client — build a TimeStampReq, parse the
 *   response, and verify a timestamp token in full (imprint match,
 *   nonce, id-kp-timeStamping EKU critical+sole, CMS signature, optional
 *   chain). Composes b.cms + the in-tree ASN.1 DER codec.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var safeBuffer = require("./safe-buffer");
var asn1 = require("./asn1-der");
var cms = require("./cms-codec");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var TsaError = defineClass("TsaError", { alwaysPermanent: true });

// id-ct-TSTInfo (RFC 3161 §2.4.2) — the eContentType of a timestamp token.
var OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
// id-kp-timeStamping (RFC 3161 §2.3) — the required, critical, sole EKU.
var OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
var OID_EXT_EKU = "2.5.29.37";                       // certificate extendedKeyUsage extension
var OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";     // RFC 5652 messageDigest signed attribute
var OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";       // RFC 5652 contentType signed attribute

// Message-imprint hash algorithms: name to { oid, nodeHash }.
var IMPRINT_HASHES = {
  "SHA-256":  { oid: "2.16.840.1.101.3.4.2.1",  nodeHash: "sha256" },
  "SHA-384":  { oid: "2.16.840.1.101.3.4.2.2",  nodeHash: "sha384" },
  "SHA-512":  { oid: "2.16.840.1.101.3.4.2.3",  nodeHash: "sha512" },
  "SHA3-256": { oid: "2.16.840.1.101.3.4.2.8",  nodeHash: "sha3-256" },
  "SHA3-512": { oid: "2.16.840.1.101.3.4.2.10", nodeHash: "sha3-512" },
};
var OID_TO_IMPRINT_HASH = {};
Object.keys(IMPRINT_HASHES).forEach(function (n) { OID_TO_IMPRINT_HASH[IMPRINT_HASHES[n].oid] = n; });

// Signer signature algorithms a real TSA emits to node verify parameters.
// scheme "rsa" = PKCS#1 v1.5, "pss" = RSASSA-PSS, "ecdsa" = ECDSA(DER).
var SIG_ALGS = {
  // Bare rsaEncryption — RFC 8933 / common CMS producers (incl. OpenSSL
  // ts) put this in SignerInfo.signatureAlgorithm and take the hash from
  // the separate digestAlgorithm field.
  "1.2.840.113549.1.1.1":  { hash: null,     scheme: "rsa" },   // rsaEncryption (hash from digestAlg)
  "1.2.840.113549.1.1.11": { hash: "sha256", scheme: "rsa" },   // sha256WithRSAEncryption
  "1.2.840.113549.1.1.12": { hash: "sha384", scheme: "rsa" },   // sha384WithRSAEncryption
  "1.2.840.113549.1.1.13": { hash: "sha512", scheme: "rsa" },   // sha512WithRSAEncryption
  "1.2.840.113549.1.1.10": { hash: null,     scheme: "pss" },   // RSASSA-PSS (hash from signerInfo digestAlg)
  // Bare id-ecPublicKey appears in some producers' SignerInfo too.
  "1.2.840.10045.2.1":     { hash: null,     scheme: "ecdsa" }, // id-ecPublicKey (hash from digestAlg)
  "1.2.840.10045.4.3.2":   { hash: "sha256", scheme: "ecdsa" }, // ecdsa-with-SHA256
  "1.2.840.10045.4.3.3":   { hash: "sha384", scheme: "ecdsa" }, // ecdsa-with-SHA384
  "1.2.840.10045.4.3.4":   { hash: "sha512", scheme: "ecdsa" }, // ecdsa-with-SHA512
};
var DIGEST_OID_TO_NODE = {
  "2.16.840.1.101.3.4.2.1":  "sha256",
  "2.16.840.1.101.3.4.2.2":  "sha384",
  "2.16.840.1.101.3.4.2.3":  "sha512",
  "2.16.840.1.101.3.4.2.8":  "sha3-256",
  "2.16.840.1.101.3.4.2.10": "sha3-512",
};

var _bytes = safeBuffer.makeByteCoercer({
  errorClass:    TsaError,
  typeCode:      "tsa/bad-bytes",
  messagePrefix: "tsa: ",
  messageSuffix: " must be Buffer / Uint8Array / string",
});

function _normHex(h) {
  return String(h).replace(/[^0-9a-fA-F]/g, "").replace(/^0+(?=.)/, "").toUpperCase();
}

// Resolve the message imprint: hash the data, or use a pre-computed hash.
function _imprint(data, opts, fnName) {
  var hashName = opts.hashAlg || "SHA-512";
  var h = IMPRINT_HASHES[hashName];
  if (!h) {
    throw new TsaError("tsa/bad-hash-alg",
      fnName + ": hashAlg must be one of " + Object.keys(IMPRINT_HASHES).join(" / "));
  }
  var digest;
  if (opts.hashed) {
    digest = _bytes(data, "hash");
    var expectLen = nodeCrypto.createHash(h.nodeHash).update(Buffer.alloc(0)).digest().length;
    if (digest.length !== expectLen) {
      throw new TsaError("tsa/bad-hash-length",
        fnName + ": pre-hashed input is " + digest.length + " bytes, expected " +
        expectLen + " for " + hashName);
    }
  } else {
    digest = nodeCrypto.createHash(h.nodeHash).update(_bytes(data, "data")).digest();
  }
  return { hashName: hashName, hashOid: h.oid, digest: digest };
}

/**
 * @primitive b.tsa.buildRequest
 * @signature b.tsa.buildRequest(data, opts?)
 * @since     0.12.38
 * @status    experimental
 * @compliance soc2
 * @related   b.tsa.parseResponse, b.tsa.verifyToken
 *
 * Build a DER-encoded RFC 3161 TimeStampReq for <code>data</code>. POST
 * the returned bytes to the TSA as <code>application/timestamp-query</code>;
 * keep the returned <code>nonce</code> to pass to
 * <code>verifyToken</code>. By default a random 64-bit nonce is included
 * and the TSA is asked to return its certificate.
 *
 * @opts
 *   {
 *     hashAlg:    string,   // "SHA-512" (default) | "SHA-256" | "SHA-384" | "SHA3-256" | "SHA3-512"
 *     hashed:     boolean,  // true means `data` is already the digest (must match hashAlg length)
 *     reqPolicy:  string,   // request a specific TSA policy OID (dotted)
 *     nonce:      Buffer,   // explicit nonce bytes, or false to omit (default: random 8 bytes)
 *     certReq:    boolean,  // ask the TSA to include its cert (default true)
 *   }
 *
 * @example
 *   var req = b.tsa.buildRequest(releaseTarball, { hashAlg: "SHA-512" });
 *   // POST req.der to the TSA; keep req.nonce for verifyToken
 *   // → { der, nonce, hashAlg, messageImprint }
 */
function buildRequest(data, opts) {
  opts = opts || {};
  validateOpts.requireObject(opts, "tsa.buildRequest", TsaError);
  validateOpts(opts, ["hashAlg", "hashed", "reqPolicy", "nonce", "certReq"], "tsa.buildRequest");
  var imp = _imprint(data, opts, "tsa.buildRequest");

  var algId = asn1.writeSequence([asn1.writeOid(imp.hashOid), asn1.writeNull()]);
  var messageImprint = asn1.writeSequence([algId, asn1.writeOctetString(imp.digest)]);

  var children = [asn1.writeInteger(Buffer.from([1])), messageImprint];          // version 1
  if (typeof opts.reqPolicy === "string") children.push(asn1.writeOid(opts.reqPolicy));

  var nonce = null;
  if (opts.nonce !== false) {
    nonce = Buffer.isBuffer(opts.nonce) ? opts.nonce : nodeCrypto.randomBytes(8);  // RFC 3161 nonce: 64-bit random
    children.push(asn1.writeInteger(nonce));
  }
  // certReq DEFAULTS TRUE (RFC 3161 §2.4.1) — encode the boolean unless
  // the caller explicitly opts out with certReq:false.
  var certReq = opts.certReq !== false;
  if (certReq) children.push(asn1.writeBoolean(true));

  return {
    der:            asn1.writeSequence(children),
    nonce:          nonce,
    hashAlg:        imp.hashName,
    messageImprint: imp.digest,
  };
}

/**
 * @primitive b.tsa.parseResponse
 * @signature b.tsa.parseResponse(der)
 * @since     0.12.38
 * @status    experimental
 * @compliance soc2
 * @related   b.tsa.buildRequest, b.tsa.verifyToken
 *
 * Parse a DER RFC 3161 TimeStampResp. Returns the PKIStatus and, when
 * the request was granted, the timestamp token (the DER ContentInfo to
 * pass to <code>verifyToken</code>). A non-granted status surfaces the
 * status integer, any free-text, and the decoded failure-info flags
 * rather than throwing — the caller decides how to react.
 *
 * @example
 *   var resp = b.tsa.parseResponse(httpBodyBytes);
 *   if (resp.granted) { var out = b.tsa.verifyToken(resp.token, { data: tarball, nonce: req.nonce }); }
 *   // → { granted: true, status: 0, token, statusString: null, failInfo: [] }
 */
function parseResponse(der) {
  var buf = _bytes(der, "der");
  var root;
  try { root = asn1.readNode(buf, 0); } catch (e) {
    throw new TsaError("tsa/malformed", "tsa.parseResponse: not DER: " + ((e && e.message) || e));
  }
  if (root.tag !== asn1.TAG.SEQUENCE || root.tagClass !== asn1.TAG_CLASS.UNIVERSAL) {
    throw new TsaError("tsa/malformed", "tsa.parseResponse: TimeStampResp must be a SEQUENCE");
  }
  var children = asn1.readSequence(root.value);
  if (children.length < 1 || children[0].tag !== asn1.TAG.SEQUENCE) {
    throw new TsaError("tsa/malformed", "tsa.parseResponse: missing PKIStatusInfo");
  }
  var statusInfo = asn1.readSequence(children[0].value);
  if (statusInfo.length < 1 || statusInfo[0].tag !== asn1.TAG.INTEGER) {
    throw new TsaError("tsa/malformed", "tsa.parseResponse: PKIStatusInfo missing status INTEGER");
  }
  var status = asn1.readUnsignedInt(statusInfo[0]);
  if (typeof status !== "number") {
    throw new TsaError("tsa/malformed", "tsa.parseResponse: status integer out of range");
  }

  var statusString = null;
  var failInfo = [];
  for (var i = 1; i < statusInfo.length; i += 1) {
    var n = statusInfo[i];
    if (n.tag === asn1.TAG.SEQUENCE && statusString === null) {
      var texts = asn1.readSequence(n.value).map(function (t) { return t.value.toString("utf8"); });
      statusString = texts.join("; ");
    } else if (n.tag === asn1.TAG.BIT_STRING) {
      failInfo = _decodeFailInfo(n);
    }
  }

  // granted(0) / grantedWithMods(1) carry a token; 2..5 are failures.
  var granted = status === 0 || status === 1;
  var token = null;
  if (granted) {
    var tokNode = children[1];
    if (!tokNode) {
      throw new TsaError("tsa/no-token",
        "tsa.parseResponse: status granted but no timeStampToken present");
    }
    token = tokNode.raw;
  }
  return { granted: granted, status: status, statusString: statusString, failInfo: failInfo, token: token };
}

// PKIFailureInfo bit names (RFC 3161 §2.4.2 / RFC 2510).
var FAIL_INFO_BITS = {                                                                 // RFC 3161 PKIFailureInfo bit positions
  0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable",
  15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure",
};
function _decodeFailInfo(bitStringNode) {
  var out = [];
  var v = bitStringNode.value;
  if (v.length <= 1) return out;                      // first byte = unused-bit count
  var bits = v.slice(1);
  for (var byteIdx = 0; byteIdx < bits.length; byteIdx += 1) {
    for (var b = 0; b < 8; b += 1) {                    // 8 bits per byte
      if (bits[byteIdx] & (0x80 >> b)) {
        var pos = byteIdx * 8 + b;                      // 8 bits per byte
        out.push(FAIL_INFO_BITS[pos] || ("bit" + pos));
      }
    }
  }
  return out;
}

// Parse GeneralizedTime "YYYYMMDDHHMMSS[.fff]Z" to Date (UTC).
function _parseGeneralizedTime(node) {
  var s = node.value.toString("ascii");
  var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  if (!m) {
    throw new TsaError("tsa/bad-gentime", "tsa: genTime is not a 'Z'-terminated GeneralizedTime: " + s);
  }
  // Fractional seconds (rare in timestamps) → milliseconds from the
  // first three fractional digits, zero-padded; no float arithmetic.
  var frac = m[7] ? m[7].slice(1) : "";
  var ms = frac ? parseInt((frac + "000").slice(0, 3), 10) : 0;
  var t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms);
  return new Date(t);
}

// TSTInfo (RFC 3161 §2.4.2) to fields. messageImprint stays raw so
// verifyToken can compare hash-alg OID + hashed bytes.
function _parseTstInfo(eContent) {
  var root = asn1.readNode(eContent, 0);
  if (root.tag !== asn1.TAG.SEQUENCE) {
    throw new TsaError("tsa/malformed", "tsa: TSTInfo must be a SEQUENCE");
  }
  var c = asn1.readSequence(root.value);
  if (c.length < 5) throw new TsaError("tsa/malformed", "tsa: TSTInfo too short");
  var idx = 0;
  idx += 1;                                           // version
  var policy = asn1.readOid(c[idx]); idx += 1;
  var miNode = c[idx]; idx += 1;
  var serialNode = c[idx]; idx += 1;
  var genTime = _parseGeneralizedTime(c[idx]); idx += 1;

  // Parse messageImprint { hashAlgorithm AlgId, hashedMessage OCTET STRING }.
  var mi = asn1.readSequence(miNode.value);
  var miAlg = asn1.readSequence(mi[0].value);
  var miHashOid = asn1.readOid(miAlg[0]);
  var miHash = asn1.readOctetString(mi[1]);

  var accuracy = null;
  var nonce = null;
  for (; idx < c.length; idx += 1) {
    var n = c[idx];
    if (n.tagClass === asn1.TAG_CLASS.UNIVERSAL && n.tag === asn1.TAG.SEQUENCE && accuracy === null) {
      accuracy = _parseAccuracy(n);
    } else if (n.tagClass === asn1.TAG_CLASS.UNIVERSAL && n.tag === asn1.TAG.INTEGER) {
      nonce = n.value;                                // raw INTEGER bytes
    }
    // ordering BOOLEAN, [0] tsa, [1] extensions are read but not surfaced in v1.
  }

  var serialHex = Buffer.isBuffer(serialNode.value) ? serialNode.value.toString("hex") : null;
  return {
    policy:       policy,
    genTime:      genTime,
    accuracy:     accuracy,
    nonce:        nonce,
    serialHex:    serialHex,
    imprintHashOid: miHashOid,
    imprintHash:  miHash,
  };
}

function _parseAccuracy(node) {
  var c = asn1.readSequence(node.value);
  var out = { seconds: 0, millis: 0, micros: 0 };
  for (var i = 0; i < c.length; i += 1) {
    var n = c[i];
    if (n.tagClass === asn1.TAG_CLASS.UNIVERSAL && n.tag === asn1.TAG.INTEGER) {
      out.seconds = asn1.readUnsignedInt(n);
    } else if (n.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && n.tag === 0) {
      out.millis = _ctxInt(n);
    } else if (n.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && n.tag === 1) {
      out.micros = _ctxInt(n);
    }
  }
  return out;
}
function _ctxInt(node) {
  // [n] IMPLICIT INTEGER — value bytes are the integer content directly.
  var v = node.value, n = 0;
  for (var i = 0; i < v.length; i += 1) n = (n * 256) + v[i];  // base-256 integer accumulation
  return n;
}

// Walk a certificate's extensions for one OID to { critical, valueBytes } or null.
function _certExtension(certDer, wantOid) {
  var cert = asn1.readNode(certDer, 0);
  var top = asn1.readSequence(cert.value);            // [ tbs, sigAlg, sigValue ]
  var tbs = asn1.readSequence(top[0].value);
  // Find the [3] EXPLICIT extensions wrapper.
  var extsWrapper = asn1.findChild(tbs, function (n) {
    return n.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && n.tag === 3;
  });
  if (!extsWrapper) return null;
  var extsSeq = asn1.unwrapExplicit(extsWrapper, 3);
  var exts = asn1.readSequence(extsSeq.value);
  for (var i = 0; i < exts.length; i += 1) {
    var ec = asn1.readSequence(exts[i].value);
    var oid = asn1.readOid(ec[0]);
    if (oid !== wantOid) continue;
    var critical = false;
    var valueNode = null;
    for (var j = 1; j < ec.length; j += 1) {
      if (ec[j].tag === asn1.TAG.BOOLEAN) critical = ec[j].value[0] !== 0;
      else if (ec[j].tag === asn1.TAG.OCTET_STRING) valueNode = ec[j];
    }
    if (!valueNode) return null;
    return { critical: critical, valueBytes: asn1.readOctetString(valueNode) };
  }
  return null;
}

// RFC 3161 §2.3: the signing cert's EKU MUST contain id-kp-timeStamping,
// MUST be critical, and MUST be the only key purpose.
function _checkTimestampingEku(certDer) {
  var ext = _certExtension(certDer, OID_EXT_EKU);
  if (!ext) {
    throw new TsaError("tsa/bad-eku",
      "tsa.verifyToken: signer certificate has no extendedKeyUsage (RFC 3161 §2.3 requires id-kp-timeStamping)");
  }
  if (!ext.critical) {
    throw new TsaError("tsa/bad-eku",
      "tsa.verifyToken: extendedKeyUsage is not marked critical (RFC 3161 §2.3)");
  }
  var purposes = asn1.readSequence(asn1.readNode(ext.valueBytes, 0).value).map(asn1.readOid);
  if (purposes.length !== 1 || purposes[0] !== OID_KP_TIMESTAMPING) {
    throw new TsaError("tsa/bad-eku",
      "tsa.verifyToken: extendedKeyUsage must be exactly { id-kp-timeStamping } (got " +
      purposes.join(", ") + ")");
  }
}

// Pick the signing cert from the token: prefer the one whose serial
// matches the SignerInfo sid (IssuerAndSerialNumber); else fall through
// to all certs (the EKU + signature checks remain authoritative).
function _candidateSigners(sidRaw, certs) {
  var wantSerial = null;
  try {
    var sid = asn1.readNode(sidRaw, 0);
    if (sid.tag === asn1.TAG.SEQUENCE && sid.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
      var parts = asn1.readSequence(sid.value);       // IssuerAndSerialNumber { issuer, serial }
      var serialNode = parts[parts.length - 1];
      if (serialNode && serialNode.tag === asn1.TAG.INTEGER) {
        wantSerial = _normHex(serialNode.value.toString("hex"));
      }
    }
  } catch (_e) { wantSerial = null; }
  if (wantSerial === null) return certs.slice();
  var matched = certs.filter(function (d) {
    try { return _normHex(new nodeCrypto.X509Certificate(d).serialNumber) === wantSerial; }
    catch (_e) { return false; }
  });
  return matched.length ? matched : certs.slice();
}

function _verifyCmsSignature(si, eContent, signerCertDer) {
  var alg = SIG_ALGS[si.sigAlgOid];
  if (!alg) {
    throw new TsaError("tsa/bad-sig-alg",
      "tsa.verifyToken: signer signature algorithm " + si.sigAlgOid +
      " is not a supported RSA / ECDSA timestamp algorithm");
  }
  if (!si.signedAttrsRaw) {
    throw new TsaError("tsa/no-signed-attrs",
      "tsa.verifyToken: SignerInfo has no signed attributes (RFC 3161 tokens always sign attributes)");
  }
  var digestNode = DIGEST_OID_TO_NODE[si.digestAlgOid];
  if (!digestNode) {
    throw new TsaError("tsa/bad-digest",
      "tsa.verifyToken: SignerInfo digest algorithm " + si.digestAlgOid + " unsupported");
  }
  // The eContent digest must equal the messageDigest signed attribute,
  // and the contentType attribute must be id-ct-TSTInfo.
  var attrs = _parseSignedAttrs(si.signedAttrsRaw);
  if (!attrs.messageDigest) {
    throw new TsaError("tsa/no-message-digest", "tsa.verifyToken: signed attrs missing messageDigest");
  }
  var actual = nodeCrypto.createHash(digestNode).update(eContent).digest();
  if (!bCrypto.timingSafeEqual(actual, attrs.messageDigest)) {
    throw new TsaError("tsa/message-digest-mismatch",
      "tsa.verifyToken: recomputed eContent digest does not match the messageDigest attribute");
  }
  if (attrs.contentType && attrs.contentType !== OID_TST_INFO) {
    throw new TsaError("tsa/bad-content-type-attr",
      "tsa.verifyToken: signed contentType attribute is " + attrs.contentType + ", expected id-ct-TSTInfo");
  }

  var pubKey = new nodeCrypto.X509Certificate(signerCertDer).publicKey;
  // For algorithm ids that don't name the hash (bare rsaEncryption /
  // id-ecPublicKey / RSASSA-PSS), the hash comes from the digestAlgorithm.
  var hashName = alg.hash || digestNode;
  var keyParam = pubKey;
  if (alg.scheme === "pss") {
    keyParam = { key: pubKey, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_AUTO };
  }
  var ok;
  try { ok = nodeCrypto.verify(hashName, si.signedAttrsRaw, keyParam, si.signature); }
  catch (e) {
    throw new TsaError("tsa/verify-threw",
      "tsa.verifyToken: signature verification threw: " + ((e && e.message) || e));
  }
  if (!ok) {
    throw new TsaError("tsa/bad-signature",
      "tsa.verifyToken: CMS signature over the signed attributes did not verify");
  }
}

// Parse the universal-SET signedAttrs bytes for contentType + messageDigest.
function _parseSignedAttrs(signedAttrsRaw) {
  var set = asn1.readNode(signedAttrsRaw, 0);
  var attrs = asn1.readSequence(set.value);
  var out = { contentType: null, messageDigest: null };
  for (var i = 0; i < attrs.length; i += 1) {
    var a = asn1.readSequence(attrs[i].value);        // Attribute { type OID, values SET }
    var type = asn1.readOid(a[0]);
    var valueSet = asn1.readSequence(a[1].value);
    if (!valueSet.length) continue;
    if (type === OID_MESSAGE_DIGEST) out.messageDigest = asn1.readOctetString(valueSet[0]);
    else if (type === OID_CONTENT_TYPE) out.contentType = asn1.readOid(valueSet[0]);
  }
  return out;
}

// Optional: verify the signer chains to a trust anchor and is valid at `at`.
function _verifyChain(signerCertDer, tokenCerts, trustAnchorsPem, at) {
  var anchors = trustAnchorsPem.map(function (p) { return new nodeCrypto.X509Certificate(p); });
  var pool = tokenCerts.map(function (d) { return new nodeCrypto.X509Certificate(d); });
  var current = new nodeCrypto.X509Certificate(signerCertDer);
  var seen = 0;
  var atTime = at.getTime();
  while (seen <= pool.length + 1) {
    _assertValidAt(current, atTime);
    // Anchor reached?
    for (var a = 0; a < anchors.length; a += 1) {
      if (_issued(anchors[a], current)) { _assertValidAt(anchors[a], atTime); return; }
      if (current.fingerprint256 === anchors[a].fingerprint256) return;
    }
    // Walk up through the token's intermediates.
    var parent = null;
    for (var p = 0; p < pool.length; p += 1) {
      if (pool[p].fingerprint256 !== current.fingerprint256 && _issued(pool[p], current)) {
        parent = pool[p]; break;
      }
    }
    if (!parent) {
      throw new TsaError("tsa/untrusted-chain",
        "tsa.verifyToken: signer certificate does not chain to any supplied trust anchor");
    }
    current = parent;
    seen += 1;
  }
  throw new TsaError("tsa/chain-loop", "tsa.verifyToken: certificate chain did not terminate");
}
function _issued(issuer, subject) {
  try { return subject.checkIssued(issuer) && subject.verify(issuer.publicKey); }
  catch (_e) { return false; }
}
function _assertValidAt(cert, atMs) {
  if (atMs < cert.validFromDate.getTime() || atMs > cert.validToDate.getTime()) {
    throw new TsaError("tsa/cert-expired",
      "tsa.verifyToken: certificate '" + cert.subject + "' is not valid at the asserted time");
  }
}

/**
 * @primitive b.tsa.verifyToken
 * @signature b.tsa.verifyToken(token, opts)
 * @since     0.12.38
 * @status    experimental
 * @compliance soc2
 * @related   b.tsa.buildRequest, b.cms.parseSignedData
 *
 * Verify an RFC 3161 timestamp token against your data and return the
 * asserted time. Performs the full §2.4.2 / §2.3 check: eContentType is
 * <code>id-ct-TSTInfo</code>, the message imprint equals the hash of
 * <code>opts.data</code> (or <code>opts.hash</code>), a sent nonce
 * round-trips, the signer cert's extendedKeyUsage is a critical, sole
 * <code>id-kp-timeStamping</code>, and the CMS signature verifies. Pass
 * <code>opts.trustAnchorsPem</code> to also verify the certificate
 * chain and validity at the asserted time.
 *
 * @opts
 *   {
 *     data:            Buffer,    // the timestamped data (hashed with hashAlg)
 *     hash:            Buffer,    // OR a pre-computed digest (with hashAlg)
 *     hashAlg:         string,    // default "SHA-512" — must match the imprint
 *     nonce:           Buffer,    // require the token nonce to match (from buildRequest)
 *     trustAnchorsPem: string|string[], // PEM root(s) — enables chain + validity verification
 *     at:              Date,      // validity instant for chain check (default: genTime); must be a valid Date
 *   }
 *
 * @example
 *   var out = b.tsa.verifyToken(resp.token, { data: tarball, hashAlg: "SHA-512", nonce: req.nonce });
 *   // → { genTime, policy, serialHex, accuracy, hashAlg, signerCertPem }
 */
function verifyToken(token, opts) {
  validateOpts.requireObject(opts, "tsa.verifyToken", TsaError);
  validateOpts(opts, ["data", "hash", "hashAlg", "nonce", "trustAnchorsPem", "at"], "tsa.verifyToken");
  if (opts.data == null && opts.hash == null) {
    throw new TsaError("tsa/no-data", "tsa.verifyToken: pass opts.data or opts.hash to bind the token");
  }
  var imp = _imprint(opts.hash != null ? opts.hash : opts.data,
    { hashAlg: opts.hashAlg, hashed: opts.hash != null }, "tsa.verifyToken");

  var sd;
  try { sd = cms.parseSignedData(_bytes(token, "token")); }
  catch (e) {
    throw new TsaError("tsa/not-cms", "tsa.verifyToken: token is not CMS SignedData: " + ((e && e.message) || e));
  }
  if (sd.encapContent.eContentType !== OID_TST_INFO) {
    throw new TsaError("tsa/not-tst",
      "tsa.verifyToken: eContentType is " + sd.encapContent.eContentType + ", expected id-ct-TSTInfo");
  }
  if (!sd.encapContent.eContent) {
    throw new TsaError("tsa/detached", "tsa.verifyToken: timestamp token has no embedded TSTInfo (detached not allowed)");
  }
  if (!sd.signerInfos.length) {
    throw new TsaError("tsa/no-signer", "tsa.verifyToken: token has no SignerInfo");
  }
  if (!sd.certificates.length) {
    throw new TsaError("tsa/no-cert",
      "tsa.verifyToken: token carries no certificate — request one with certReq (the default)");
  }

  var tst = _parseTstInfo(sd.encapContent.eContent);

  // (3) message imprint must match the data.
  if (OID_TO_IMPRINT_HASH[tst.imprintHashOid] !== imp.hashName) {
    throw new TsaError("tsa/imprint-alg-mismatch",
      "tsa.verifyToken: token imprint hash (" + tst.imprintHashOid + ") differs from " + imp.hashName);
  }
  if (!bCrypto.timingSafeEqual(tst.imprintHash, imp.digest)) {
    throw new TsaError("tsa/imprint-mismatch",
      "tsa.verifyToken: token message imprint does not match the supplied data");
  }

  // (4) nonce round-trip.
  if (opts.nonce != null) {
    var want = _bytes(opts.nonce, "nonce");
    var got = tst.nonce == null ? Buffer.alloc(0) : Buffer.from(tst.nonce);
    // Compare as unsigned integers (ignore a DER sign-pad byte difference).
    if (_normHex(want.toString("hex")) !== _normHex(got.toString("hex"))) {
      throw new TsaError("tsa/nonce-mismatch", "tsa.verifyToken: token nonce does not match the request nonce");
    }
  }

  // (5)+(6) signer cert + EKU + CMS signature.
  var si = sd.signerInfos[0];
  var candidates = _candidateSigners(si.sid, sd.certificates);
  var signerCertDer = null;
  var lastErr = null;
  for (var i = 0; i < candidates.length; i += 1) {
    try {
      _checkTimestampingEku(candidates[i]);
      _verifyCmsSignature(si, sd.encapContent.eContent, candidates[i]);
      signerCertDer = candidates[i];
      break;
    } catch (e) { lastErr = e; }
  }
  if (!signerCertDer) {
    throw lastErr || new TsaError("tsa/no-valid-signer",
      "tsa.verifyToken: no certificate in the token both carries the timestamping EKU and verifies the signature");
  }

  // (7) optional chain + validity. Accept a single PEM string or an
  // array — never silently skip chain verification when the caller
  // supplied an anchor in an unexpected shape (a fail-open).
  if (opts.trustAnchorsPem !== undefined && opts.trustAnchorsPem !== null) {
    var anchors = typeof opts.trustAnchorsPem === "string" ? [opts.trustAnchorsPem] : opts.trustAnchorsPem;
    if (!Array.isArray(anchors) || anchors.length === 0 ||
        !anchors.every(function (a) { return typeof a === "string" && a.length > 0; })) {
      throw new TsaError("tsa/bad-trust-anchors",
        "tsa.verifyToken: trustAnchorsPem must be a non-empty PEM string or array of PEM strings");
    }
    // A supplied opts.at must be a valid Date — an Invalid Date would make
    // every validity-window comparison NaN (silently disabling it).
    validateOpts.optionalDate(opts.at, "tsa.verifyToken: opts.at", TsaError, "tsa/bad-at");
    var at = (opts.at !== undefined && opts.at !== null) ? opts.at : tst.genTime;
    _verifyChain(signerCertDer, sd.certificates, anchors, at);
  }

  return {
    genTime:       tst.genTime,
    policy:        tst.policy,
    serialHex:     tst.serialHex,
    accuracy:      tst.accuracy,
    hashAlg:       imp.hashName,
    signerCertPem: new nodeCrypto.X509Certificate(signerCertDer).toString(),
  };
}

module.exports = {
  buildRequest:   buildRequest,
  parseResponse:  parseResponse,
  verifyToken:    verifyToken,
  IMPRINT_HASHES: IMPRINT_HASHES,
  TsaError:       TsaError,
};
