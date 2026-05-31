"use strict";
/**
 * b.mail.arc.sign — RFC 8617 ARC chain construction.
 *
 * Companion to b.mail.arc.verify (relay-side ARC chain validation).
 * When a relay receives a message with optional prior ARC headers
 * and is about to forward it, it signs and prepends three new
 * headers per RFC 8617 §5.1:
 *
 *   - ARC-Authentication-Results (AAR) — relay's verification verdict
 *     for SPF / DKIM / DMARC at this hop, formatted per RFC 8601.
 *   - ARC-Message-Signature (AMS) — DKIM-style signature over the
 *     message body + selected headers + the AAR.
 *   - ARC-Seal (AS) — signature over the catenation of every prior
 *     hop's three headers plus the current AAR + AMS, with cv= tag
 *     reporting the upstream chain validation outcome.
 *
 * The operator's verification result lives in opts.authResults; the
 * cv= self-attestation comes from opts.cv (typically the result.cv
 * of a prior arc.verify() call: "none" at i=1, "pass" / "fail" at
 * i>=2).
 *
 *   var signed = b.mail.arc.sign({
 *     rfc822:        message,
 *     instance:      i,                          // 1, 2, 3, ...
 *     authservId:    "relay.example.com",
 *     domain:        "relay.example.com",
 *     selector:      "arc",
 *     privateKey:    pem,
 *     algorithm:     "rsa-sha256",
 *     cv:            "none",                     // i=1: none; i>=2: pass / fail
 *     authResults:   "spf=pass smtp.mailfrom=...",
 *     headersToSign: ["From", "To", "Subject", "Date", "Message-ID"],
 *     timestamp:     Math.floor(Date.now() / 1000),
 *   });
 *   // signed.aar, signed.ams, signed.as → strings
 *   // signed.rfc822 → message with all three headers prepended
 *
 * Per RFC 8617:
 *   - i=1: cv=none REQUIRED.
 *   - i>=2: cv=pass | cv=fail; cv=none is invalid at i>=2.
 *   - Once any hop's AS reports cv=fail, no downstream hop may sign
 *     a cv=pass — the chain is permanently broken. Signers MUST
 *     report cv=fail when forwarding such a chain.
 *
 * Per the framework's validation-tier policy: sign() throws on bad
 * input (config-time entry-point). Audit emissions on every signed
 * hop: `dkim.arc.signed`.
 */

var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
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
  // Returns array of { name, value } in source order. Folds CRLF+WSP
  // continuations.
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
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");                // allow:duplicate-regex — DKIM/ARC RFC 6376 §3.4.2 unfolding
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");  // allow:duplicate-regex — DKIM/ARC RFC 6376 §3.4.2 WSP collapse
  return name.toLowerCase() + ":" + trimmed + "\r\n";
}

// RFC 8617 §5.1.1 references RFC 6376 §3.4.4 for body canonicalization.
// The DKIM verifier and signer share `_canonBodyRelaxed`; ARC MUST
// produce a byte-identical canon so a downstream ARC-verifier (which
// composes the DKIM verifier per §5.1.1) reaches the same body hash.
// Earlier inline shape collapsed `[ \t]+` across newlines (the regex
// is global and not bound per-line), which diverged from DKIM's
// per-line `safeBuffer.stripTrailingHspace` on a line whose only WSP
// run sat at the end. Compose the DKIM canon directly.
function _canonRelaxedBody(body) {
  return dkim._canonBodyRelaxedForTest(body || "");
}

function _bodyHashB64(body, algorithm) {
  var hashAlgo = algorithm.indexOf("sha256") !== -1 ? "sha256" : "sha512";
  var canonical = _canonRelaxedBody(body);
  // RFC 6376 §3.4.4 — empty body canon is `\r\n` (one CRLF). Hash
  // includes that CRLF.
  return nodeCrypto.createHash(hashAlgo).update(canonical).digest("base64");
}

// RFC 8617 §5 — ARC chains MUST NOT exceed 50 hops. The verifier
// caps in `mail-auth.js` (`ARC_MAX_HOPS`); the signer's prior-hop
// extractor needs the same ceiling so a message arriving with a
// hostile chain (51+ instances) doesn't expand the per-hop walk to
// unbounded work before the signer's own validation catches up.
var ARC_MAX_HOPS_FOR_EXTRACT = 50;                                                      // RFC 8617 §5 chain bound

function _arcExtractPriorHops(parsedHeaders) {
  // Walk parsedHeaders; for each ARC-Authentication-Results /
  // ARC-Message-Signature / ARC-Seal entry, extract instance via i=N
  // and group by hop. The `i=` value is bounded against the RFC's
  // 50-hop ceiling before being used as a map key, so an attacker-
  // chosen `i=999999` can't allocate a sparse map.
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
      // Out-of-spec instance number — refuse to consider it. Upstream
      // `sign` will see `priorHops.length !== opts.instance - 1` and
      // refuse the message.
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
    "headersToSign", "timestamp", "audit",
  ], "mail.arc.sign");

  validateOpts.requireNonEmptyString(opts.rfc822, "sign: rfc822",
    MailAuthError, "arc-sign/bad-input");
  if (typeof opts.instance !== "number" || !isFinite(opts.instance) ||
      opts.instance < 1 || opts.instance > 50 ||                                        // RFC 8617 §5 chain bound
      Math.floor(opts.instance) !== opts.instance) {
    throw new MailAuthError("arc-sign/bad-instance",
      "sign: instance must be an integer in [1, 50] — got " + JSON.stringify(opts.instance));
  }
  validateOpts.requireNonEmptyString(opts.authservId,
    "sign: authservId", MailAuthError, "arc-sign/bad-authserv");
  validateOpts.requireNonEmptyString(opts.domain,
    "sign: domain", MailAuthError, "arc-sign/bad-domain");
  validateOpts.requireNonEmptyString(opts.selector,
    "sign: selector", MailAuthError, "arc-sign/bad-selector");
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
  if (opts.instance >= 2 && opts.cv === "none") {                                       // RFC 8617 chain rule
    throw new MailAuthError("arc-sign/cv-rule",
      "sign: i>=2 disallows cv=none — must be cv=pass or cv=fail (per RFC 8617 §5.1.1)");
  }
  validateOpts.requireNonEmptyString(opts.authResults, "sign: authResults",
    MailAuthError, "arc-sign/bad-auth-results");
  if (safeBuffer.hasCrlf(opts.authResults)) {
    throw new MailAuthError("arc-sign/bad-auth-results",
      "sign: authResults contains CR/LF (header injection refused)");
  }
  var headersToSign = opts.headersToSign || DEFAULT_HEADERS;
  if (!Array.isArray(headersToSign) || headersToSign.length === 0) {
    throw new MailAuthError("arc-sign/bad-headers",
      "sign: headersToSign must be a non-empty array of header names");
  }
  // RFC 8617 §5.1.1 + Microsoft + Google receiver interop — the
  // current hop's ARC-Authentication-Results MUST appear in the AMS
  // h= list. Pre-v0.8.17 the framework default omitted it; receivers
  // that include AAR in their canonicalization (M365, Gmail) failed
  // to verify framework-signed chains. Auto-prepend if absent.
  // Operators that explicitly want to opt out (deprecated, do not)
  // pass `excludeAarFromAms: true`.
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
  var timestamp = (typeof opts.timestamp === "number" && opts.timestamp > 0)            // allow:numeric-opt-Infinity
    ? Math.floor(opts.timestamp) : Math.floor(Date.now() / 1000);                       // Unix epoch seconds divisor
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

  // Validate prior chain's instance numbering: hops must be 1..N-1
  // contiguous, where N is opts.instance.
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

  // ----- AAR (ARC-Authentication-Results) -----
  // RFC 8617 §4.1.1 — `i=N; <auth-result-string>`.
  var aarValue = "i=" + opts.instance + "; " + opts.authservId + "; " + opts.authResults;

  // ----- AMS (ARC-Message-Signature) -----
  // Looks like DKIM-Signature with `i=N` tag added.
  // Tags in canonical order: i, a, c, d, s, t, h, bh, b
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

  // RFC 8617 §5.1.1 — the current hop's ARC-Authentication-Results
  // is part of the AMS canonicalization input when h= covers it.
  // Synthesize a virtual entry at the top of parsedHeaders so the
  // header-name lookup below sees it; the canonicalizer reads
  // parsedHeaders[idx] like any other header.
  var amsParsedHeaders = [{
    name:  "ARC-Authentication-Results",
    value: " " + aarValue,
  }].concat(parsedHeaders);
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
  // RFC 8617 §5.1 — current-hop AAR is included via h= (prepended
  // above); canonical input is (h-listed headers) + (AMS with empty
  // b=).
  var amsCanonInput = canonHeaders +
    _canonRelaxedHeader("ARC-Message-Signature", amsUnsigned).replace(/\r\n$/, "");

  var amsSignatureB64 = _signOne(amsCanonInput, keyObject, algorithm);
  var amsValue = amsUnsigned.replace(/\bb=$/, "b=" + amsSignatureB64);

  // ----- AS (ARC-Seal) -----
  // Tags: i, a, t, cv, d, s, b
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

  // AS canonical input: every prior hop's AAR + AMS + AS in instance
  // order, then current AAR + AMS, then current AS with empty b=.
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

  // Prepend headers in the RFC-recommended order: AS, AMS, AAR.
  var prependedHeaders =
    "ARC-Seal: " + asValue + "\r\n" +
    "ARC-Message-Signature: " + amsValue + "\r\n" +
    "ARC-Authentication-Results: " + aarValue + "\r\n";
  var sealedRfc822 = prependedHeaders + opts.rfc822;

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
  if (algorithm === "ed25519-sha256") {
    // Ed25519 prehash variant — Node's `crypto.sign(null, msg, key)`
    // accepts the message directly.
    return nodeCrypto.sign(null, Buffer.from(canonInput, "utf8"), keyObject)
      .toString("base64");
  }
  // RSA-SHA256 / default — createSign + update + sign.
  var signer = nodeCrypto.createSign("RSA-SHA256");
  signer.update(canonInput);
  return signer.sign(keyObject).toString("base64");
}

module.exports = {
  sign:           sign,
  ALLOWED_CV:     ALLOWED_CV,
  ALLOWED_ALGORITHMS: ALLOWED_ALGORITHMS,
  DEFAULT_HEADERS: DEFAULT_HEADERS,
  MailAuthError:  MailAuthError,
};
