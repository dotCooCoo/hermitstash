// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mail-dkim — DKIM-Signature header generation for outbound mail.
 *
 * RFC 6376 (rsa-sha256) is the default; RFC 8463 (ed25519-sha256) is
 * available as opt-in. The two share the same signer surface so
 * operators flip algorithms by changing the `algorithm` opt and the
 * private key — no code change.
 *
 * Forward-looking: the DKIM-Signature `a=` tag carries an algorithm
 * identifier. When the IETF standardizes a post-quantum DKIM algorithm
 * (an SLH-DSA or ML-DSA variant), this module gains a third allowed
 * value alongside `rsa-sha256` and `ed25519-sha256`. The signer's
 * outer surface stays the same.
 *
 * Public API:
 *
 *   var signer = b.mail.dkim.create({
 *     domain:          "example.com",
 *     selector:        "s1",
 *     privateKey:      pemString | crypto.KeyObject,
 *     algorithm:       "rsa-sha256" (default) | "ed25519-sha256"
 *     headersToSign:   ["from","to","subject","date","message-id"]
 *                       (default — order matters in the signed string)
 *     canonicalization:"relaxed/relaxed" (default) | "simple/simple"
 *                      | "relaxed/simple" | "simple/relaxed"
 *     bodyLength:      number (optional `l=` cap; off by default)
 *     audit:           false (default true)
 *   });
 *
 *   var signedRfc822 = signer.sign(rfc822String);
 *
 * The signer never mutates the message object — it consumes the final
 * RFC 822 wire format produced by `mail._buildRfc822` and returns a
 * new string with the DKIM-Signature header prepended.
 *
 * Validation surface uses DkimError (FrameworkError subclass) with a
 * permanent flag — every problem here is a configuration / shape
 * problem, not a transient one.
 */
var lazyRequire = require("./lazy-require");
var audit       = lazyRequire(function () { return require("./audit"); });
var structuredFields = require("./structured-fields");
var nodeCrypto  = require("node:crypto");
var safeBuffer  = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var ARC_AMS_REUSE = require("./mail-arc-reuse-token");
var C           = require("./constants");
var networkDnsResolver = lazyRequire(function () { return require("./network-dns-resolver"); });
var { FrameworkError } = require("./framework-error");

class DkimError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "DkimError";
    this.permanent = true;
    this.isDkimError = true;
  }
}

var ALLOWED_ALGORITHMS = ["rsa-sha256", "ed25519-sha256"];
var ALLOWED_CANON = [
  "relaxed/relaxed",
  "simple/simple",
  "relaxed/simple",
  "simple/relaxed",
];
var DEFAULT_HEADERS = ["from", "to", "subject", "date", "message-id"];

var RSA_MIN_BITS  = 2048;
var RSA_WEAK_BITS = 2048;
var RSA_LEGACY_MIN_BITS = 1024;

function _canonHeaderRelaxed(name, value) {
  var unfolded = structuredFields.unfoldHeaderContinuations(value);
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");
  return name.toLowerCase() + ":" + trimmed + "\r\n";
}

function _canonHeaderSimple(name, value) {
  return name + ":" + value + "\r\n";
}

function _canonBodyRelaxed(body) {
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  var lines = normalized.split("\r\n");
  for (var i = 0; i < lines.length; i++) {
    lines[i] = safeBuffer.stripTrailingHspace(lines[i].replace(/[ \t]+/g, " "));
  }
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return "\r\n";
  return lines.join("\r\n") + "\r\n";
}

function _canonBodySimple(body) {
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  while (normalized.endsWith("\r\n\r\n")) {
    normalized = normalized.slice(0, -2);
  }
  if (!normalized.endsWith("\r\n")) normalized += "\r\n";
  return normalized;
}

function _splitHeadersBody(rfc822) {
  rfc822 = rfc822.replace(/\r?\n/g, "\r\n");
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) {
    throw new DkimError("dkim/missing-body-separator",
      "rfc822 input has no header/body separator (CRLF CRLF)");
  }
  return {
    headers: rfc822.slice(0, sep + 2),
    body:    rfc822.slice(sep + 4),
  };
}

function _parseHeaders(rawHeaders) {
  var lines = rawHeaders.split("\r\n");
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    if (line[0] === " " || line[0] === "\t") {
      if (out.length > 0) out[out.length - 1].value += "\r\n" + line;
      continue;
    }
    var colon = line.indexOf(":");
    if (colon === -1) continue;
    out.push({
      name:  line.slice(0, colon),
      value: line.slice(colon + 1),
    });
  }
  return out;
}

function _toWire(rfc822) {
  if (Buffer.isBuffer(rfc822)) return rfc822.toString("latin1");
  if (typeof rfc822 !== "string") {
    throw new DkimError("dkim/bad-input",
      "message must be a Buffer or a string — got " +
      (rfc822 === null ? "null" : typeof rfc822));
  }
  return Buffer.from(rfc822, "utf8").toString("latin1");
}

function _wireBytes(wire) {
  return Buffer.from(wire, "latin1");
}

function _bodyHashB64(body, algorithm, canonBody, lcap) {
  var canonicalized = canonBody === "simple"
    ? _canonBodySimple(body)
    : _canonBodyRelaxed(body);
  var hashName = "sha256";
  var hash = nodeCrypto.createHash(hashName);
  var buf = _wireBytes(canonicalized);
  if (typeof lcap === "number" && isFinite(lcap) && lcap >= 0) {
    hash.update(lcap < buf.length ? buf.subarray(0, lcap) : buf);
  } else {
    hash.update(buf);
  }
  return hash.digest("base64");
}

function _signString(strToSign, privateKey, algorithm) {
  var toSign = _wireBytes(strToSign);
  if (algorithm === "rsa-sha256") {
    return nodeCrypto.createSign("RSA-SHA256")
      .update(toSign).sign(privateKey).toString("base64");
  }
  if (algorithm === "ed25519-sha256") {
    return nodeCrypto.sign(null, toSign, privateKey)
      .toString("base64");
  }
  throw new DkimError("dkim/bad-algorithm",
    "unknown algorithm: " + algorithm);
}

function _foldSignatureHeader(unfolded) {
  var maxLine = 76;
  var name = "DKIM-Signature: ";
  var rest = unfolded;
  if ((name + rest).length <= maxLine) return name + rest;
  var parts = rest.split("; ");
  var lines = [name + parts[0] + (parts.length > 1 ? ";" : "")];
  for (var i = 1; i < parts.length; i++) {
    lines.push("\t" + parts[i] + (i < parts.length - 1 ? ";" : ""));
  }
  return lines.join("\r\n");
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "domain", "selector", "privateKey", "algorithm",
    "headersToSign", "canonicalization", "bodyLength", "audit",
  ], "mail.dkim.create");

  if (typeof opts.domain !== "string" || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(opts.domain)) {
    throw new DkimError("dkim/bad-domain",
      "domain must be a valid DNS name (e.g. 'example.com')");
  }
  if (typeof opts.selector !== "string" ||
      opts.selector.length === 0 || opts.selector.length > 253 ||
      !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/i.test(opts.selector)) {
    throw new DkimError("dkim/bad-selector",
      "selector must be a non-empty LDH token, optionally dot-separated (e.g. 's1', '2024.s1') (RFC 6376 §3.1)");
  }
  if (!opts.privateKey || (typeof opts.privateKey !== "string" &&
      typeof opts.privateKey !== "object")) {
    throw new DkimError("dkim/missing-private-key",
      "privateKey is required (PEM string or crypto.KeyObject)");
  }
  var algorithm = opts.algorithm || "rsa-sha256";
  if (ALLOWED_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new DkimError("dkim/bad-algorithm",
      "algorithm must be one of: " + ALLOWED_ALGORITHMS.join(", "));
  }
  var canonicalization = opts.canonicalization || "relaxed/relaxed";
  if (ALLOWED_CANON.indexOf(canonicalization) === -1) {
    throw new DkimError("dkim/bad-canonicalization",
      "canonicalization must be one of: " + ALLOWED_CANON.join(", "));
  }
  var canonHeader = canonicalization.split("/")[0];
  var canonBody   = canonicalization.split("/")[1];

  var headersToSign = opts.headersToSign || DEFAULT_HEADERS;
  if (!Array.isArray(headersToSign) || headersToSign.length === 0) {
    throw new DkimError("dkim/bad-headers",
      "headersToSign must be a non-empty array of header names");
  }
  for (var i = 0; i < headersToSign.length; i++) {
    if (typeof headersToSign[i] !== "string" || headersToSign[i].length === 0) {
      throw new DkimError("dkim/bad-headers",
        "headersToSign[" + i + "] must be a non-empty string");
    }
  }
  if (opts.bodyLength !== undefined) {
    throw new DkimError("dkim/l-tag-forbidden",
      "DKIM `l=` body-length tag is forbidden — append-after-signature " +
      "attack vector. Remove opts.bodyLength.");
  }

  var auditOn = opts.audit !== false;
  var keyObject;
  try {
    keyObject = typeof opts.privateKey === "string" || Buffer.isBuffer(opts.privateKey)
      ? nodeCrypto.createPrivateKey({ key: opts.privateKey, format: "pem" })
      : opts.privateKey;
  } catch (e) {
    throw new DkimError("dkim/bad-private-key",
      "privateKey could not be parsed: " + ((e && e.message) || String(e)));
  }

  function _emit(action, info) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  info.outcome || "success",
      actor:    info.actor || {},
      metadata: {
        domain:     opts.domain,
        selector:   opts.selector,
        algorithm:  algorithm,
        bodyLength: info.bodyLength,
        durationMs: info.durationMs,
      },
      reason: info.reason || null,
    });
  }

  function sign(rfc822) {
    var gaveBuffer = Buffer.isBuffer(rfc822);
    if ((!gaveBuffer && typeof rfc822 !== "string") || rfc822.length === 0) {
      throw new DkimError("dkim/bad-input",
        "sign() requires the rfc822 wire format as a non-empty Buffer or string");
    }
    var t0 = Date.now();
    rfc822 = _toWire(rfc822);
    var split = _splitHeadersBody(rfc822);
    var parsedHeaders = _parseHeaders(split.headers);

    var body = split.body;
    var bh = _bodyHashB64(body, algorithm, canonBody);

    var sigTags = [
      "v=1",
      "a=" + algorithm,
      "c=" + canonicalization,
      "d=" + opts.domain,
      "s=" + opts.selector,
      "h=" + headersToSign.join(":"),
      "bh=" + bh,
    ];
    sigTags.push("b=");
    var unsignedSigValue = sigTags.join("; ");

    var headerNamesLc = parsedHeaders.map(function (h) { return h.name.toLowerCase(); });
    var missingHeaders = [];
    var canonicalizedHeaders = "";
    for (var j = 0; j < headersToSign.length; j++) {
      var wantLc = headersToSign[j].toLowerCase();
      var idx = -1;
      for (var k = 0; k < headerNamesLc.length; k++) {
        if (headerNamesLc[k] === wantLc) idx = k;
      }
      if (idx === -1) {
        missingHeaders.push(headersToSign[j]);
        continue;
      }
      var h = parsedHeaders[idx];
      canonicalizedHeaders += canonHeader === "simple"
        ? _canonHeaderSimple(h.name, h.value)
        : _canonHeaderRelaxed(h.name, h.value);
    }
    if (missingHeaders.length > 0 && auditOn) {
      try {
        audit().safeEmit({
          action:  "dkim.sign.headers_missing",
          outcome: "success",
          actor:   null,
          metadata: {
            domain:           opts.domain,
            selector:         opts.selector,
            missingHeaders:   missingHeaders,
            headersConfigured: headersToSign.length,
            severity:         "warning",
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    var foldedEmptyB = _foldSignatureHeader(unsignedSigValue);
    var dkimHeaderForSigning;
    if (canonHeader === "simple") {
      dkimHeaderForSigning = foldedEmptyB;
    } else {
      dkimHeaderForSigning = _canonHeaderRelaxed("DKIM-Signature", unsignedSigValue);
    }
    canonicalizedHeaders += dkimHeaderForSigning.replace(/\r\n$/, "");

    var signature = _signString(canonicalizedHeaders, keyObject, algorithm);

    var dkimHeaderLine;
    if (canonHeader === "simple") {
      dkimHeaderLine = foldedEmptyB + signature + "\r\n";
    } else {
      var finalSigValue = sigTags.slice(0, -1).concat(["b=" + signature]).join("; ");
      dkimHeaderLine = _foldSignatureHeader(finalSigValue) + "\r\n";
    }

    _emit("dkim.sign.success", {
      bodyLength: body.length,
      durationMs: Date.now() - t0,
    });

    var out = dkimHeaderLine + rfc822;
    return gaveBuffer ? _wireBytes(out) : _wireBytes(out).toString("utf8");
  }

  return {
    sign: sign,
    domain:    opts.domain,
    selector:  opts.selector,
    algorithm: algorithm,
  };
}

function _parseDkimTagList(value) {
  var pairs = structuredFields.parseTagList(value,
    { unfold: true, stripValueWs: true, lowerKey: false });
  var tags = {};
  for (var i = 0; i < pairs.length; i += 1) tags[pairs[i][0]] = pairs[i][1];
  return tags;
}

function _parseDkimUnsignedInt(raw, maxDigits) {
  if (typeof raw !== "string") return null;
  var len = raw.length;
  if (len === 0 || (maxDigits && len > maxDigits)) return null;
  for (var i = 0; i < len; i++) {
    var c = raw.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return null;
  }
  var n = parseInt(raw, 10);
  if (!isFinite(n)) return null;
  return n;
}

function _parseDkimNumericDate(raw) {
  return _parseDkimUnsignedInt(raw, 12);
}

function _selectorTxtToKeyTags(txtRecords) {
  var joined = "";
  if (Array.isArray(txtRecords)) {
    for (var i = 0; i < txtRecords.length; i += 1) {
      var rec = txtRecords[i];
      joined = Array.isArray(rec) ? rec.join("") : String(rec);
      if (joined.indexOf("v=DKIM1") === 0 || joined.indexOf("p=") !== -1) break;
    }
  } else {
    joined = String(txtRecords || "");
  }
  if (joined.length === 0) {
    throw new DkimError("dkim/key-not-found", "DKIM key record is empty");
  }
  return _parseDkimTagList(joined);
}

var DKIM_KEY_CACHE = new Map();
var DKIM_KEY_CACHE_TTL_MS = C.TIME.minutes(5);
var DKIM_KEY_CACHE_MAX_ENTRIES = 1024;

var DKIM_MAX_SIGNATURES_PER_MESSAGE = 8;
var DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING = 16;

function _cacheGet(qname) {
  var ent = DKIM_KEY_CACHE.get(qname);
  if (!ent) return null;
  if (ent.expires <= Date.now()) {
    DKIM_KEY_CACHE.delete(qname);
    return null;
  }
  DKIM_KEY_CACHE.delete(qname);
  DKIM_KEY_CACHE.set(qname, ent);
  return ent.tags;
}

function _cachePut(qname, tags) {
  if (DKIM_KEY_CACHE.size >= DKIM_KEY_CACHE_MAX_ENTRIES) {
    var oldest = DKIM_KEY_CACHE.keys().next().value;
    if (oldest !== undefined) DKIM_KEY_CACHE.delete(oldest);
  }
  DKIM_KEY_CACHE.set(qname, { tags: tags, expires: Date.now() + DKIM_KEY_CACHE_TTL_MS });
}

var _defaultResolver = null;
function _getDefaultResolver() {
  if (_defaultResolver) return _defaultResolver;
  _defaultResolver = networkDnsResolver().create();
  return _defaultResolver;
}

async function _safeResolveTxt(qname, operatorLookup) {
  return networkDnsResolver().resolveTxt(qname, operatorLookup, _getDefaultResolver());
}

function _resetDkimKeyCacheForTest() { DKIM_KEY_CACHE.clear(); }

var ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function _pemFromB64KeyMaterial(b64) {
  var raw = null;
  try { raw = Buffer.from(b64, "base64"); } catch (_e) { raw = null; }
  if (raw && raw.length === 32) {
    b64 = Buffer.concat([ED25519_SPKI_PREFIX, raw]).toString("base64");
  }
  var pem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < b64.length; i += 64) {
    pem += b64.slice(i, i + 64) + "\n";
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

async function _fetchDkimKey(domain, selector, dnsLookup) {
  var qname = selector + "._domainkey." + domain;
  var cached = _cacheGet(qname);
  if (cached) return cached;
  var records;
  try {
    records = await _safeResolveTxt(qname, dnsLookup);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) {
      throw new DkimError("dkim/key-not-found",
        "no DKIM TXT record at " + qname);
    }
    throw new DkimError("dkim/key-lookup-temperror",
      "DKIM TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  var tags = _selectorTxtToKeyTags(records);
  _cachePut(qname, tags);
  return tags;
}

function _findDkimSignatureHeaders(parsedHeaders) {
  var out = [];
  for (var i = 0; i < parsedHeaders.length; i += 1) {
    if (parsedHeaders[i].name.toLowerCase() === "dkim-signature") {
      out.push({ index: i, name: parsedHeaders[i].name, value: parsedHeaders[i].value });
    }
  }
  return out;
}

function _stripBTagValue(value) {
  var parts = String(value).split(";");
  var out = [];
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    var m = /^(\s*)([A-Za-z][A-Za-z0-9_-]*)(\s*=)/.exec(p);
    if (m && m[2].toLowerCase() === "b") {
      out.push(m[1] + m[2] + m[3]);
      continue;
    }
    out.push(p);
  }
  return out.join(";");
}

function _verifySingleSignature(rfc822, parsedHeaders, sigHeader, keyTags, sigTags, verifyOpts) {
  verifyOpts = verifyOpts || {};
  var canonicalization = sigTags.c || "simple/simple";
  var canonHeader = canonicalization.split("/")[0];
  var canonBody   = canonicalization.split("/")[1];
  var algorithm   = sigTags.a;

  if (!verifyOpts.arcAmsReuse && typeof sigTags.i === "string" && sigTags.i.length > 0) {
    var iDomain = sigTags.i.indexOf("@") === -1
                    ? sigTags.i
                    : sigTags.i.slice(sigTags.i.indexOf("@") + 1);
    var d = String(sigTags.d || "").toLowerCase();
    var iDl = iDomain.toLowerCase();
    if (d.length === 0 || (iDl !== d && iDl.slice(-d.length - 1) !== "." + d)) {
      return { result: "permerror",
               errors: ["DKIM-Signature i=" + sigTags.i + " is not d= or a subdomain of d=" + sigTags.d + " (RFC 6376 §3.5)"] };
    }
  }

  if (typeof keyTags.h === "string" && keyTags.h.length > 0) {
    var sigHash = String(algorithm || "").toLowerCase().split("-").slice(-1)[0];
    var allowedHashes = keyTags.h.toLowerCase().split(":").map(function (s) { return s.trim(); });
    if (sigHash.length === 0 || allowedHashes.indexOf(sigHash) === -1) {
      return { result: "permerror",
               errors: ["DKIM-Signature a=" + algorithm + " hash '" + sigHash +
                        "' not in key h=" + keyTags.h + " (RFC 6376 §3.6.1)"] };
    }
  }

  var split = _splitHeadersBody(rfc822);
  var body = split.body;
  var lcap;
  if (sigTags.l !== undefined) {
    var parsedL = _parseDkimUnsignedInt(sigTags.l, 18);
    if (parsedL === null) {
      return { result: "permerror",
               errors: ["DKIM-Signature l= present but unparseable (RFC 6376 §3.5 — unsigned integer required)"] };
    }
    lcap = parsedL;
  }

  var expectedBh = sigTags.bh;
  if (typeof expectedBh !== "string") {
    return { result: "permerror", errors: ["DKIM-Signature missing bh="] };
  }
  var actualBh = _bodyHashB64(body, algorithm, canonBody, lcap);
  if (actualBh !== expectedBh) {
    return { result: "fail", errors: ["body hash mismatch"] };
  }
  if (lcap !== undefined && !verifyOpts.acceptBodyLengthLimit) {
    var fullCanon = canonBody === "simple" ? _canonBodySimple(body) : _canonBodyRelaxed(body);
    if (lcap < Buffer.byteLength(fullCanon, "latin1")) {
      return { result: "fail",
               errors: ["DKIM-Signature l= leaves appended body content unsigned " +
                        "(RFC 6376 §8.2 append-after-signature)"] };
    }
  }

  var headerNames = (sigTags.h || "").split(":").map(function (s) {
    return s.trim().toLowerCase();
  });
  if (headerNames.indexOf("from") === -1) {
    return { result: "permerror",
             errors: ["DKIM-Signature h= tag does not include 'from' (RFC 6376 §3.5)"] };
  }
  var lcNames = parsedHeaders.map(function (h) { return h.name.toLowerCase(); });
  var canonicalizedHeaders = "";
  for (var j = 0; j < headerNames.length; j += 1) {
    var want = headerNames[j];
    if (want.length === 0) continue;
    var idx = lcNames.lastIndexOf(want);
    if (idx === -1) continue;
    var h = parsedHeaders[idx];
    canonicalizedHeaders += canonHeader === "simple"
      ? _canonHeaderSimple(h.name, h.value)
      : _canonHeaderRelaxed(h.name, h.value);
  }
  var unsignedSigValue = _stripBTagValue(sigHeader.value);
  var sigCanonName = verifyOpts.arcAmsReuse ? "ARC-Message-Signature" : sigHeader.name;
  canonicalizedHeaders += canonHeader === "simple"
    ? _canonHeaderSimple(sigCanonName, unsignedSigValue).replace(/\r\n$/, "")
    : _canonHeaderRelaxed(sigCanonName, unsignedSigValue).replace(/\r\n$/, "");

  var sigB64 = sigTags.b;
  if (typeof sigB64 !== "string") {
    return { result: "permerror", errors: ["DKIM-Signature missing b="] };
  }
  var sigBuf = Buffer.from(sigB64, "base64");
  var pem = _pemFromB64KeyMaterial(keyTags.p);
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey(pem); }
  catch (e) {
    return { result: "permerror",
             errors: ["DKIM key parse failed: " + ((e && e.message) || String(e))] };
  }

  var nodeAlgo = algorithm === "rsa-sha256"     ? "sha256" :
                 algorithm === "ed25519-sha256" ? null     : null;
  if (algorithm !== "rsa-sha256" && algorithm !== "ed25519-sha256") {
    return { result: "permerror",
             errors: ["unsupported DKIM algorithm '" + algorithm + "'"] };
  }

  var operatorMinBits = (typeof verifyOpts.minRsaBits === "number" &&
                          isFinite(verifyOpts.minRsaBits) &&
                          verifyOpts.minRsaBits >= RSA_LEGACY_MIN_BITS)
                         ? Math.floor(verifyOpts.minRsaBits)
                         : RSA_MIN_BITS;
  var warnings = [];
  if (algorithm === "rsa-sha256" && keyObj.asymmetricKeyType === "rsa") {
    var modBits = (keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.modulusLength) || 0;
    if (modBits > 0 && modBits < operatorMinBits) {
      return { result: "fail",
               errors: ["RSA key too small: " + modBits + " bits (minimum " + operatorMinBits +
                        " — RFC 8301bis + 2024 bulk-sender)"] };
    }
    if (modBits > 0 && modBits < RSA_WEAK_BITS) {
      warnings.push("rsa-key-weak: " + modBits + " bits (< " + RSA_WEAK_BITS + ")");
    }
  }
  if (sigTags.l !== undefined) {
    warnings.push("l-tag-present: append-after-signature exposure (RFC 6376 §8.2)");
  }

  var verified;
  try {
    verified = nodeCrypto.verify(nodeAlgo,
      _wireBytes(canonicalizedHeaders), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: ["DKIM verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [], warnings: warnings }
    : { result: "fail", errors: ["signature verification failed"], warnings: warnings };
}

var DKIM_CLOCK_SKEW_MS_MAX = C.TIME.hours(24);
var DKIM_CLOCK_SKEW_MS_DEFAULT = C.TIME.minutes(5);

async function verify(rfc822, opts) {
  if ((!Buffer.isBuffer(rfc822) && typeof rfc822 !== "string") || rfc822.length === 0) {
    throw new DkimError("dkim/bad-input",
      "verify(): rfc822 must be a non-empty Buffer or string");
  }
  rfc822 = _toWire(rfc822);
  opts = opts || {};
  validateOpts(opts, ["dnsLookup", "audit", "clockSkewMs", "maxSignatures",
                       "minRsaBits", "acceptBodyLengthLimit"], "mail.dkim.verify");
  var auditOn = opts.audit !== false;

  var clockSkewMs;
  if (opts.clockSkewMs === undefined || opts.clockSkewMs === null) {
    clockSkewMs = DKIM_CLOCK_SKEW_MS_DEFAULT;
  } else if (typeof opts.clockSkewMs !== "number" || !isFinite(opts.clockSkewMs) ||
             opts.clockSkewMs < 0) {
    throw new DkimError("dkim/bad-clock-skew",
      "verify(): clockSkewMs must be a finite non-negative number");
  } else if (opts.clockSkewMs > DKIM_CLOCK_SKEW_MS_MAX) {
    throw new DkimError("dkim/bad-clock-skew",
      "verify(): clockSkewMs " + opts.clockSkewMs + " exceeds framework ceiling " +
      DKIM_CLOCK_SKEW_MS_MAX + " (RFC 6376 §3.5 — back-dating replay defense)");
  } else {
    clockSkewMs = Math.floor(opts.clockSkewMs);
  }

  var maxSignatures = DKIM_MAX_SIGNATURES_PER_MESSAGE;
  if (opts.maxSignatures !== undefined) {
    if (typeof opts.maxSignatures !== "number" ||
        !isFinite(opts.maxSignatures) ||
        opts.maxSignatures < 1 ||
        opts.maxSignatures > DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING) {
      throw new DkimError("dkim/bad-max-signatures",
        "verify: maxSignatures must be an integer in [1, " +
        DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING + "] (got " + opts.maxSignatures + ")");
    }
    maxSignatures = Math.floor(opts.maxSignatures);
  }
  var verifyOpts = { minRsaBits: opts.minRsaBits,
                     acceptBodyLengthLimit: opts.acceptBodyLengthLimit === true };
  if (opts[ARC_AMS_REUSE] === true) verifyOpts.arcAmsReuse = true;

  var split = _splitHeadersBody(rfc822);
  var parsedHeaders = _parseHeaders(split.headers);
  var sigHeaders = _findDkimSignatureHeaders(parsedHeaders);
  if (sigHeaders.length === 0) {
    return [{ result: "none", errors: ["no DKIM-Signature headers"] }];
  }
  if (sigHeaders.length > maxSignatures) {
    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "dkim.verify.signature_count_cap",
          outcome: "denied",
          actor:   null,
          metadata: {
            sigCount:      sigHeaders.length,
            maxSignatures: maxSignatures,
            severity:      "warning",
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    return [{ result: "policy",
              errors: ["DKIM-Signature count " + sigHeaders.length +
                       " exceeds maxSignatures=" + maxSignatures +
                       " (RFC 6376 §6.1; verifier DoS cap)"] }];
  }

  var results = [];
  for (var i = 0; i < sigHeaders.length; i += 1) {
    var sigTags = _parseDkimTagList(sigHeaders[i].value);
    var d = sigTags.d;
    var s = sigTags.s;
    var alg = sigTags.a;
    if (sigTags.v !== undefined && sigTags.v !== "1") {
      results.push({ d: d || null, s: s || null, alg: alg || null,
        result: "permerror", errors: ["DKIM-Signature v=" + sigTags.v + " unsupported (RFC 6376 §3.5 — only v=1)"] });
      continue;
    }
    var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
    var clockSkewSec = Math.floor(clockSkewMs / C.TIME.seconds(1));
    var xSec = null;
    if (sigTags.x !== undefined) {
      xSec = _parseDkimNumericDate(sigTags.x);
      if (xSec === null) {
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature x= present but unparseable (RFC 6376 §3.5 — NumericDate required)"] });
        continue;
      }
      if (xSec + clockSkewSec < nowSec) {
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature x=" + xSec + " has expired (RFC 6376 §3.5)"] });
        continue;
      }
    }
    if (sigTags.t !== undefined) {
      var tSec = _parseDkimNumericDate(sigTags.t);
      if (tSec === null) {
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature t= present but unparseable (RFC 6376 §3.5 — NumericDate required)"] });
        continue;
      }
      if (tSec - (24 * 60 * 60) > nowSec) {                                                    // allow:raw-time-literal — 24h future-date sanity ceiling
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature t=" + tSec + " is more than 24h in the future (RFC 6376 §3.5 sanity)"] });
        continue;
      }
      if (xSec !== null && xSec < tSec) {
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature x= must be after t= (RFC 6376 §3.5)"] });
        continue;
      }
    }
    if (!d || !s) {
      results.push({ d: d || null, s: s || null, alg: alg || null,
        result: "permerror", errors: ["DKIM-Signature missing d= or s="] });
      continue;
    }
    var keyTags;
    try { keyTags = await _fetchDkimKey(d, s, opts.dnsLookup); }
    catch (e) {
      var verdict = e.code === "dkim/key-lookup-temperror" ? "temperror" : "permerror";
      results.push({ d: d, s: s, alg: alg, result: verdict, errors: [e.message] });
      continue;
    }
    if (keyTags.p === "") {
      results.push({ d: d, s: s, alg: alg, result: "fail",
        errors: ["DKIM key revoked (empty p= per RFC 6376 §3.6.1)"] });
      continue;
    }
    if (!keyTags.p) {
      results.push({ d: d, s: s, alg: alg, result: "permerror",
        errors: ["DKIM key record missing p="] });
      continue;
    }
    var kFamily   = keyTags.k !== undefined ? String(keyTags.k).toLowerCase() : "rsa";
    var sigFamily = String(alg || "").toLowerCase().split("-")[0];
    if (kFamily !== sigFamily) {
      results.push({ d: d, s: s, alg: alg, result: "permerror",
        errors: ["DKIM key k=" + kFamily + " does not match signature a=" + alg + " (RFC 6376 §3.6.1)"] });
      continue;
    }
    var rv = _verifySingleSignature(rfc822, parsedHeaders, sigHeaders[i], keyTags, sigTags, verifyOpts);
    results.push(Object.assign({ d: d, s: s, alg: alg }, rv));
  }
  return results;
}

function dualSigner(opts) {
  if (!opts || !opts.rsa || !opts.eddsa) {
    throw new DkimError("dkim/dual-signer-missing",
      "dualSigner requires both opts.rsa and opts.eddsa");
  }
  if (!opts.domain) {
    throw new DkimError("dkim/dual-signer-missing-domain",
      "dualSigner requires opts.domain");
  }
  function _merge(base, alg, override) {
    return Object.assign({}, base, { algorithm: alg }, override);
  }
  var sharedBase = {};
  var commonKeys = ["domain", "headersToSign", "canonicalization", "audit"];
  for (var i = 0; i < commonKeys.length; i += 1) {
    if (opts[commonKeys[i]] !== undefined) sharedBase[commonKeys[i]] = opts[commonKeys[i]];
  }
  var rsaSigner   = create(_merge(sharedBase, "rsa-sha256",     opts.rsa));
  var eddsaSigner = create(_merge(sharedBase, "ed25519-sha256", opts.eddsa));
  return {
    sign: function (rfc822) {
      var afterRsa = rsaSigner.sign(rfc822);
      return eddsaSigner.sign(afterRsa);
    },
    rsa:   rsaSigner,
    eddsa: eddsaSigner,
  };
}

/**
 * @primitive b.mail.dkim.bootstrap
 * @signature b.mail.dkim.bootstrap(opts)
 * @since     0.9.48
 * @status    stable
 * @related   b.vault.sealPemFile
 *
 * Bootstrap a DKIM keypair + DNS TXT record + ready-to-use signer.
 * Operators deploying outbound mail (b.mail.send, b.mail.server.submission)
 * need three things in place: (1) a private signing key, (2) the matching
 * public key published as a DNS TXT record under
 * `<selector>._domainkey.<domain>`, (3) a `b.mail.dkim.create(...)` handle
 * wired into the outbound agent. Pre-this-primitive every consumer
 * reinvented the keypair-mint + DNS-record-serialize plumbing; this
 * primitive owns it.
 *
 * Default algorithm is `ed25519-sha256` (RFC 8463): smaller DNS record,
 * faster signing, modern crypto. Operators with receivers that don't yet
 * support Ed25519 pass `algorithm: "rsa-sha256"` for RFC 6376 (defaults
 * to 2048-bit RSA per RFC 8301 §3.1 guidance — opt up with `rsaBits`).
 * Passing `algorithm: "dual"` mints BOTH keypairs and returns a
 * `b.mail.dkim.dualSigner`-shaped signer that emits two DKIM-Signature
 * headers (one per alg) for max receiver compat per RFC 8463 §3 dual-
 * signing pattern.
 *
 * @opts
 *   domain:     string,           // required — RFC 5321 domain
 *   selector:   string,           // required — RFC 6376 §3.1 selector (the `s1` in s1._domainkey.example.com)
 *   algorithm:  "ed25519-sha256" | "rsa-sha256" | "dual",
 *                                  // default: "ed25519-sha256"
 *   rsaBits:    number,           // RSA-only; default 2048; refused below 1024 (RFC 8301 §3.1)
 *   rsaSelector: string,          // dual-only; selector for the RSA key (defaults to selector + "-rsa")
 *
 * @example
 *   var dkim = b.mail.dkim.bootstrap({ domain: "example.com", selector: "s1" });
 *   // → {
 *   //     algorithm:    "ed25519-sha256",
 *   //     domain:       "example.com",
 *   //     selector:     "s1",
 *   //     privateKeyPem,
 *   //     publicKeyPem,
 *   //     dnsName:      "s1._domainkey.example.com",
 *   //     dnsTxtValue:  "v=DKIM1; k=ed25519; p=MCowBQYDK2Vw...",
 *   //     dnsRecord:    's1._domainkey.example.com. IN TXT ("v=DKIM1; k=ed25519; p=MCo...")',
 *   //     signer:       fn(headersToSign?, canonicalization?) → signer,
 *   //   }
 *
 *   // Operator seals the private key via the vault then wires the signer:
 *   var sealedPath = b.vault.sealPemFile({ source: "/var/lib/blamejs/dkim.key", destination: "/var/lib/blamejs/dkim.key.sealed" });
 *   var signer = dkim.signer();      // uses dkim.privateKeyPem in-memory
 *
 *   // Dual signing — RSA + Ed25519 for max receiver compatibility:
 *   var dkim2 = b.mail.dkim.bootstrap({ domain: "example.com", selector: "s1", algorithm: "dual" });
 *   // dkim2.signer() returns a dualSigner emitting both DKIM-Signature headers.
 */
function bootstrap(opts) {
  validateOpts.requireObject(opts, "b.mail.dkim.bootstrap", DkimError, "dkim/bad-opts");
  validateOpts.requireNonEmptyString(opts.domain, "b.mail.dkim.bootstrap: opts.domain",
    DkimError, "dkim/bad-domain");
  validateOpts.requireNonEmptyString(opts.selector, "b.mail.dkim.bootstrap: opts.selector",
    DkimError, "dkim/bad-selector");
  var alg = opts.algorithm || "ed25519-sha256";
  if (alg !== "ed25519-sha256" && alg !== "rsa-sha256" && alg !== "dual") {
    throw new DkimError("dkim/bad-algorithm",
      "b.mail.dkim.bootstrap: opts.algorithm must be 'ed25519-sha256' | 'rsa-sha256' | 'dual'");
  }
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/.test(opts.selector)) {                  // allow:regex-no-length-cap — anchored + bounded repeat
    throw new DkimError("dkim/bad-selector",
      "b.mail.dkim.bootstrap: opts.selector must match RFC 6376 §3.1 selector shape");
  }
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$/.test(opts.domain)) {                    // allow:regex-no-length-cap — anchored + bounded repeat
    throw new DkimError("dkim/bad-domain",
      "b.mail.dkim.bootstrap: opts.domain must be a DNS-hostname-shaped string");
  }

  if (alg === "ed25519-sha256") {
    return _bootstrapSingle("ed25519-sha256", opts.domain, opts.selector);
  }
  if (alg === "rsa-sha256") {
    var bits = opts.rsaBits === undefined ? RSA_MIN_BITS : opts.rsaBits;
    if (typeof bits !== "number" || !isFinite(bits) || bits < RSA_LEGACY_MIN_BITS || (bits % 1) !== 0) {
      throw new DkimError("dkim/bad-rsa-bits",
        "b.mail.dkim.bootstrap: opts.rsaBits must be an integer >= " + RSA_LEGACY_MIN_BITS +
        " (RFC 8301 §3.1 floor; default " + RSA_MIN_BITS +
        " per RFC 8301bis + 2024 bulk-sender)");
    }
    return _bootstrapSingle("rsa-sha256", opts.domain, opts.selector, bits);
  }
  var rsaSelector = opts.rsaSelector || (opts.selector + "-rsa");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/.test(rsaSelector)) {                    // allow:regex-no-length-cap — anchored + bounded repeat
    throw new DkimError("dkim/bad-selector",
      "b.mail.dkim.bootstrap: opts.rsaSelector must match RFC 6376 §3.1 selector shape");
  }
  var rsaBits = opts.rsaBits === undefined ? RSA_MIN_BITS : opts.rsaBits;
  if (typeof rsaBits !== "number" || !isFinite(rsaBits) || rsaBits < RSA_LEGACY_MIN_BITS || (rsaBits % 1) !== 0) {
    throw new DkimError("dkim/bad-rsa-bits",
      "b.mail.dkim.bootstrap: opts.rsaBits must be an integer >= " + RSA_LEGACY_MIN_BITS);
  }
  var ed = _bootstrapSingle("ed25519-sha256", opts.domain, opts.selector);
  var rsa = _bootstrapSingle("rsa-sha256",   opts.domain, rsaSelector, rsaBits);
  return {
    algorithm:    "dual",
    domain:       opts.domain,
    ed25519:      ed,
    rsa:          rsa,
    signer: function (signOpts) {
      signOpts = signOpts || {};
      return dualSigner({
        domain:           opts.domain,
        headersToSign:    signOpts.headersToSign,
        canonicalization: signOpts.canonicalization,
        eddsa: {
          selector:   opts.selector,
          privateKey: ed.privateKeyPem,
        },
        rsa: {
          selector:   rsaSelector,
          privateKey: rsa.privateKeyPem,
        },
      });
    },
  };
}

function _bootstrapSingle(algorithm, domain, selector, rsaBits) {
  var keyPair;
  var k;
  if (algorithm === "ed25519-sha256") {
    keyPair = nodeCrypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding:  { type: "spki",  format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    k = "ed25519";
  } else {
    keyPair = nodeCrypto.generateKeyPairSync("rsa", {
      modulusLength:      rsaBits,
      publicKeyEncoding:  { type: "spki",  format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    k = "rsa";
  }
  var publicKeyPemObj = nodeCrypto.createPublicKey({ key: keyPair.publicKey, type: "spki", format: "der" });
  var publicKeyPem    = publicKeyPemObj.export({ type: "spki", format: "pem" });
  var pBase64;
  if (k === "ed25519") {
    var spkiDer = Buffer.from(keyPair.publicKey);
    pBase64 = spkiDer.subarray(spkiDer.length - 32).toString("base64");
  } else {
    pBase64 = Buffer.from(keyPair.publicKey).toString("base64");
  }
  var dnsName         = selector + "._domainkey." + domain;
  var dnsTxtValue = "v=DKIM1; k=" + k + "; p=" + pBase64;
  var dnsRecord = dnsName + ". IN TXT (" + _wrapDnsTxt(dnsTxtValue) + ")";

  return {
    algorithm:    algorithm,
    domain:       domain,
    selector:     selector,
    privateKeyPem: keyPair.privateKey,
    publicKeyPem:  publicKeyPem,
    dnsName:       dnsName,
    dnsTxtValue:   dnsTxtValue,
    dnsRecord:     dnsRecord,
    signer: function (signOpts) {
      signOpts = signOpts || {};
      return create({
        domain:           domain,
        selector:         selector,
        privateKey:       keyPair.privateKey,
        algorithm:        algorithm,
        headersToSign:    signOpts.headersToSign,
        canonicalization: signOpts.canonicalization,
      });
    },
  };
}

function _wrapDnsTxt(value) {
  if (value.length <= 255) return '"' + value + '"';
  var parts = [];
  for (var i = 0; i < value.length; i += 255) parts.push('"' + value.slice(i, i + 255) + '"');
  return parts.join(" ");
}

module.exports = {
  create:      create,
  bootstrap:   bootstrap,
  verify:      verify,
  _resetDkimKeyCacheForTest: _resetDkimKeyCacheForTest,
  dualSigner:  dualSigner,
  DkimError:   DkimError,
  RSA_MIN_BITS:               RSA_MIN_BITS,
  RSA_LEGACY_MIN_BITS:        RSA_LEGACY_MIN_BITS,
  DKIM_MAX_SIGNATURES_PER_MESSAGE: DKIM_MAX_SIGNATURES_PER_MESSAGE,
  DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING: DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING,
  DKIM_CLOCK_SKEW_MS_MAX:     DKIM_CLOCK_SKEW_MS_MAX,
  canonHeaderRelaxed:         _canonHeaderRelaxed,
  _canonHeaderRelaxedForTest: _canonHeaderRelaxed,
  _canonBodyRelaxedForTest:   _canonBodyRelaxed,
  _canonBodySimpleForTest:    _canonBodySimple,
  _stripBTagValue:            _stripBTagValue,
  _toWire:                    _toWire,
  _wireBytes:                 _wireBytes,
  _stripBTagValueForTest:     _stripBTagValue,
  _parseHeadersForTest:       _parseHeaders,
};
