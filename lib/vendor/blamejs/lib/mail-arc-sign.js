// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var dkim = require("./mail-dkim");
var { defineClass } = require("./framework-error");

var MailAuthError = defineClass("MailAuthError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

var ALLOWED_ALGORITHMS = ["rsa-sha256", "ed25519-sha256"];
var ALLOWED_CV         = ["none", "pass", "fail"];
var DEFAULT_HEADERS    = ["From", "To", "Subject", "Date", "Message-ID",
                          "MIME-Version", "Content-Type"];

function _splitHeadersBody(rfc822) {
  var idx = rfc822.indexOf("\r\n\r\n");
  if (idx === -1) {
    var lfIdx = rfc822.indexOf("\n\n");
    if (lfIdx === -1) {
      throw new MailAuthError("arc-sign/bad-rfc822",
        "rfc822 body has no header/body separator (CRLF-CRLF or LF-LF)");
    }
    return { headers: rfc822.substring(0, lfIdx), body: rfc822.substring(lfIdx + 2) };
  }
  return { headers: rfc822.substring(0, idx), body: rfc822.substring(idx + 4) };
}

function _parseHeaderBlock(headerBlock) {
  var lines = headerBlock.split(/\r?\n/);
  var headers = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) continue;
    if (line.charAt(0) === " " || line.charAt(0) === "\t") {
      if (current) current.value += "\r\n" + line;
      continue;
    }
    var colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    if (current) headers.push(current);
    current = {
      name:  line.slice(0, colonIdx),
      value: line.slice(colonIdx + 1).replace(/^[ \t]+/, ""),    // allow:duplicate-regex — RFC 5322 leading-WSP strip; identical to mail-auth/mail-dkim by spec
    };
  }
  if (current) headers.push(current);
  return headers;
}

function _canonRelaxedHeader(name, value) {
  return dkim.canonHeaderRelaxed(name, value);
}

function _canonRelaxedBody(body) {
  return dkim._canonBodyRelaxedForTest(body || "");
}

function _bodyHashB64(body, algorithm) {
  var hashAlgo = algorithm.indexOf("sha256") !== -1 ? "sha256" : "sha512";
  var canonical = _canonRelaxedBody(body);
  return nodeCrypto.createHash(hashAlgo).update(canonical, "latin1").digest("base64");
}

var ARC_MAX_HOPS_FOR_EXTRACT = 50;

function _arcExtractPriorHops(parsedHeaders) {
  var hopMap = {};
  for (var i = 0; i < parsedHeaders.length; i += 1) {
    var h = parsedHeaders[i];
    var lcName = h.name.toLowerCase();
    if (lcName !== "arc-authentication-results" &&
        lcName !== "arc-message-signature" &&
        lcName !== "arc-seal") continue;
    var iMatch = h.value.match(/(?:^|[;,\s])i=(\d+)/);                                  // allow:regex-no-length-cap — ARC header bounded by RFC 5322 §2.1.1
    if (!iMatch) continue;
    var instance = parseInt(iMatch[1], 10);
    if (!isFinite(instance) || instance < 1 || instance > ARC_MAX_HOPS_FOR_EXTRACT) {
      continue;
    }
    if (!hopMap[instance]) hopMap[instance] = { instance: instance };
    hopMap[instance][lcName] = h.value;
  }
  var hops = [];
  var keys = Object.keys(hopMap).sort(function (a, b) { return Number(a) - Number(b); });
  if (keys.length > ARC_MAX_HOPS_FOR_EXTRACT) {
    throw new MailAuthError("arc-sign/chain-too-long",
      "_arcExtractPriorHops: chain has " + keys.length +
      " hops, exceeds RFC 8617 §5 ceiling of " + ARC_MAX_HOPS_FOR_EXTRACT);
  }
  for (var k = 0; k < keys.length; k += 1) hops.push(hopMap[keys[k]]);
  return hops;
}

function sign(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "rfc822", "instance", "authservId", "domain", "selector",
    "privateKey", "algorithm", "cv", "authResults",
    "headersToSign", "timestamp", "audit", "excludeAarFromAms",
  ], "mail.arc.sign");

  var gaveBuffer = Buffer.isBuffer(opts.rfc822);
  if (gaveBuffer) {
    if (opts.rfc822.length === 0) {
      throw new MailAuthError("arc-sign/bad-input",
        "sign: rfc822 must be a non-empty Buffer or string");
    }
  } else {
    validateOpts.requireNonEmptyString(opts.rfc822, "sign: rfc822",
      MailAuthError, "arc-sign/bad-input");
  }
  opts = Object.assign({}, opts, { rfc822: dkim._toWire(opts.rfc822) });
  if (typeof opts.instance !== "number" || !isFinite(opts.instance) ||
      opts.instance < 1 || opts.instance > 50 ||
      Math.floor(opts.instance) !== opts.instance) {
    throw new MailAuthError("arc-sign/bad-instance",
      "sign: instance must be an integer in [1, 50] — got " + JSON.stringify(opts.instance));
  }
  var arcHeaderFields = [
    ["authservId",  opts.authservId,  "arc-sign/bad-authserv"],
    ["domain",      opts.domain,      "arc-sign/bad-domain"],
    ["selector",    opts.selector,    "arc-sign/bad-selector"],
    ["authResults", opts.authResults, "arc-sign/bad-auth-results"],
  ];
  for (var fi = 0; fi < arcHeaderFields.length; fi += 1) {
    var af = arcHeaderFields[fi];
    validateOpts.requireNonEmptyString(af[1], "sign: " + af[0], MailAuthError, af[2]);
    safeBuffer.assertHeaderSafe(af[1], af[0], MailAuthError, af[2]);
  }
  if (!opts.privateKey || (typeof opts.privateKey !== "string" &&
      typeof opts.privateKey !== "object")) {
    throw new MailAuthError("arc-sign/missing-private-key",
      "sign: privateKey is required (PEM string or crypto.KeyObject)");
  }
  var algorithm = opts.algorithm || "rsa-sha256";
  if (ALLOWED_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new MailAuthError("arc-sign/bad-algorithm",
      "sign: algorithm must be one of " + ALLOWED_ALGORITHMS.join(", "));
  }
  if (ALLOWED_CV.indexOf(opts.cv) === -1) {
    throw new MailAuthError("arc-sign/bad-cv",
      "sign: cv must be one of " + ALLOWED_CV.join(", ") + " — got " + JSON.stringify(opts.cv));
  }
  if (opts.instance === 1 && opts.cv !== "none") {
    throw new MailAuthError("arc-sign/cv-rule",
      "sign: i=1 requires cv=none (per RFC 8617 §5.1.1)");
  }
  if (opts.instance >= 2 && opts.cv === "none") {
    throw new MailAuthError("arc-sign/cv-rule",
      "sign: i>=2 disallows cv=none — must be cv=pass or cv=fail (per RFC 8617 §5.1.1)");
  }
  var headersToSign = opts.headersToSign || DEFAULT_HEADERS;
  if (!Array.isArray(headersToSign) || headersToSign.length === 0) {
    throw new MailAuthError("arc-sign/bad-headers",
      "sign: headersToSign must be a non-empty array of header names");
  }
  var hasAar = headersToSign.some(function (n) {
    return String(n).toLowerCase() === "arc-authentication-results";
  });
  if (!hasAar && opts.excludeAarFromAms !== true) {
    headersToSign = headersToSign.slice();
    headersToSign.unshift("ARC-Authentication-Results");
  }
  for (var hi = 0; hi < headersToSign.length; hi += 1) {
    if (typeof headersToSign[hi] !== "string" || headersToSign[hi].length === 0) {
      throw new MailAuthError("arc-sign/bad-headers",
        "sign: headersToSign[" + hi + "] must be a non-empty string");
    }
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.timestamp, "arc.sign: opts.timestamp", MailAuthError, "arc-sign/bad-timestamp");
  var timestamp = (typeof opts.timestamp === "number")
    ? opts.timestamp : Math.floor(Date.now() / 1000);
  var auditOn = opts.audit !== false;

  var keyObject;
  try {
    keyObject = (typeof opts.privateKey === "string" || Buffer.isBuffer(opts.privateKey))
      ? nodeCrypto.createPrivateKey({ key: opts.privateKey, format: "pem" })
      : opts.privateKey;
  } catch (e) {
    throw new MailAuthError("arc-sign/bad-private-key",
      "sign: privateKey could not be parsed: " + ((e && e.message) || String(e)));
  }

  var split = _splitHeadersBody(opts.rfc822);
  var parsedHeaders = _parseHeaderBlock(split.headers);
  var priorHops = _arcExtractPriorHops(parsedHeaders);

  for (var ph = 0; ph < priorHops.length; ph += 1) {
    if (priorHops[ph].instance !== ph + 1) {
      throw new MailAuthError("arc-sign/chain-broken",
        "sign: prior chain has gap or mismatch — expected i=" + (ph + 1) +
        " at slot " + ph + ", got i=" + priorHops[ph].instance);
    }
  }
  if (priorHops.length !== opts.instance - 1) {
    throw new MailAuthError("arc-sign/chain-broken",
      "sign: prior chain has " + priorHops.length + " hops but instance=" +
      opts.instance + " requires " + (opts.instance - 1) + " prior hops");
  }

  var bh = _bodyHashB64(split.body, algorithm);

  var aarValue = "i=" + opts.instance + "; " + opts.authservId + "; " + opts.authResults;

  var amsTags = [
    "i=" + opts.instance,
    "a=" + algorithm,
    "c=relaxed/relaxed",
    "d=" + opts.domain,
    "s=" + opts.selector,
    "t=" + timestamp,
    "h=" + headersToSign.join(":"),
    "bh=" + bh,
  ];
  amsTags.push("b=");
  var amsUnsigned = amsTags.join("; ");

  var priorArcStripped = parsedHeaders.filter(function (ph2) {
    var lc = ph2.name.toLowerCase();
    return lc !== "arc-authentication-results" &&
           lc !== "arc-message-signature" &&
           lc !== "arc-seal";
  });
  var amsParsedHeaders = [{
    name:  "ARC-Authentication-Results",
    value: " " + aarValue,
  }].concat(priorArcStripped);
  var canonHeaders = "";
  var headerNamesLc = amsParsedHeaders.map(function (h) { return h.name.toLowerCase(); });
  for (var j = 0; j < headersToSign.length; j += 1) {
    var wantLc = headersToSign[j].toLowerCase();
    var idx = -1;
    for (var k = 0; k < headerNamesLc.length; k += 1) {
      if (headerNamesLc[k] === wantLc) idx = k;
    }
    if (idx === -1) continue;
    var h = amsParsedHeaders[idx];
    canonHeaders += _canonRelaxedHeader(h.name, h.value);
  }
  var amsCanonInput = canonHeaders +
    _canonRelaxedHeader("ARC-Message-Signature", amsUnsigned).replace(/\r\n$/, "");

  var amsSignatureB64 = _signOne(amsCanonInput, keyObject, algorithm);
  var amsValue = amsUnsigned.replace(/\bb=$/, "b=" + amsSignatureB64);

  var asTags = [
    "i=" + opts.instance,
    "a=" + algorithm,
    "t=" + timestamp,
    "cv=" + opts.cv,
    "d=" + opts.domain,
    "s=" + opts.selector,
  ];
  asTags.push("b=");
  var asUnsigned = asTags.join("; ");

  var asCanonInput = "";
  for (var p = 0; p < priorHops.length; p += 1) {
    var hop = priorHops[p];
    asCanonInput += _canonRelaxedHeader("ARC-Authentication-Results", hop["arc-authentication-results"]);
    asCanonInput += _canonRelaxedHeader("ARC-Message-Signature",      hop["arc-message-signature"]);
    asCanonInput += _canonRelaxedHeader("ARC-Seal",                   hop["arc-seal"]);
  }
  asCanonInput += _canonRelaxedHeader("ARC-Authentication-Results", aarValue);
  asCanonInput += _canonRelaxedHeader("ARC-Message-Signature",      amsValue);
  asCanonInput += _canonRelaxedHeader("ARC-Seal", asUnsigned).replace(/\r\n$/, "");

  var asSignatureB64 = _signOne(asCanonInput, keyObject, algorithm);
  var asValue = asUnsigned.replace(/\bb=$/, "b=" + asSignatureB64);

  var prependedHeaders =
    "ARC-Seal: " + asValue + "\r\n" +
    "ARC-Message-Signature: " + amsValue + "\r\n" +
    "ARC-Authentication-Results: " + aarValue + "\r\n";
  var sealedWire = prependedHeaders + opts.rfc822;
  var sealedRfc822 = gaveBuffer
    ? Buffer.from(sealedWire, "latin1")
    : Buffer.from(sealedWire, "latin1").toString("utf8");

  if (auditOn) {
    try {
      audit().safeEmit({
        action:   "dkim.arc.signed",
        outcome:  "success",
        actor:    null,
        metadata: {
          instance:   opts.instance,
          domain:     opts.domain,
          selector:   opts.selector,
          algorithm:  algorithm,
          cv:         opts.cv,
          priorHops:  priorHops.length,
        },
      });
    } catch (_e) { /* drop-silent */ }
  }

  return {
    aar:    aarValue,
    ams:    amsValue,
    as:     asValue,
    rfc822: sealedRfc822,
    instance: opts.instance,
    cv:     opts.cv,
  };
}

function _signOne(canonInput, keyObject, algorithm) {
  var toSign = Buffer.from(canonInput, "latin1");
  if (algorithm === "ed25519-sha256") {
    return nodeCrypto.sign(null, toSign, keyObject).toString("base64");
  }
  var signer = nodeCrypto.createSign("RSA-SHA256");
  signer.update(toSign);
  return signer.sign(keyObject).toString("base64");
}

module.exports = {
  sign:           sign,
  ALLOWED_CV:     ALLOWED_CV,
  ALLOWED_ALGORITHMS: ALLOWED_ALGORITHMS,
  DEFAULT_HEADERS: DEFAULT_HEADERS,
  MailAuthError:  MailAuthError,
  _parseHeaderBlockForTest: _parseHeaderBlock,
};
