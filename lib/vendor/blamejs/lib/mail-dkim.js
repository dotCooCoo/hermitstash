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
var nodeCrypto  = require("node:crypto");
var safeBuffer  = require("./safe-buffer");
var validateOpts = require("./validate-opts");
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

// RSA modulus bit-size thresholds per RFC 8301 §3.1 + M³AAWG hardening
// guidance. Anything below MIN must be considered failure; below WEAK
// emits a warning so operators can quarantine while transitioning.
var RSA_MIN_BITS  = 1024;                                                        // allow:raw-byte-literal — RFC 8301 RSA bit floor
var RSA_WEAK_BITS = 2048;                                                        // allow:raw-byte-literal — RFC 8301 RSA bit weak threshold

// ---- Canonicalization (RFC 6376 §3.4) ----

function _canonHeaderRelaxed(name, value) {
  // Lowercase name, unfold continuations, collapse internal WSP runs to
  // single SP, strip leading/trailing WSP from value.
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");
  return name.toLowerCase() + ":" + trimmed + "\r\n";
}

function _canonHeaderSimple(name, value) {
  // Preserve as-is. Used rarely in practice but spec-compliant.
  return name + ":" + value + "\r\n";
}

function _canonBodyRelaxed(body) {
  // 1) Reduce internal WSP runs in each line to a single SP, strip
  //    trailing WSP. 2) Strip empty lines at end of body. 3) Ensure
  //    a single trailing CRLF. Empty body → just "\r\n".
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  var lines = normalized.split("\r\n");
  for (var i = 0; i < lines.length; i++) {
    lines[i] = safeBuffer.stripTrailingHspace(lines[i].replace(/[ \t]+/g, " "));
  }
  // Drop trailing empty lines.
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return "\r\n";
  return lines.join("\r\n") + "\r\n";
}

function _canonBodySimple(body) {
  // Strip trailing empty lines but otherwise preserve the body. Empty
  // body → "\r\n".
  if (!body) return "\r\n";
  var normalized = body.replace(/\r?\n/g, "\r\n");
  // Strip trailing empty lines.
  while (normalized.endsWith("\r\n\r\n")) {
    normalized = normalized.slice(0, -2);
  }
  if (!normalized.endsWith("\r\n")) normalized += "\r\n";
  return normalized;
}

// ---- RFC 822 split ----

function _splitHeadersBody(rfc822) {
  // Headers terminated by the first empty line. Headers may use folded
  // continuation lines (CRLF + WSP); we keep them folded and let the
  // canonicalizer unfold relaxed-mode.
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) {
    throw new DkimError("dkim/missing-body-separator",
      "rfc822 input has no header/body separator (CRLF CRLF)");
  }
  return {
    headers: rfc822.slice(0, sep + 2),  // include trailing CRLF after last header
    body:    rfc822.slice(sep + 4),
  };
}

function _parseHeaders(rawHeaders) {
  // Parse into [{ name, value }, ...] preserving order. Folded
  // continuation lines (start with WSP) are appended to the prior
  // header's value verbatim.
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
      value: line.slice(colon + 1),  // preserve leading SP for simple canon
    });
  }
  return out;
}

// ---- Hashing + signing ----

function _bodyHashB64(body, algorithm, canonBody) {
  var canonicalized = canonBody === "simple"
    ? _canonBodySimple(body)
    : _canonBodyRelaxed(body);
  var hashName = "sha256";  // both rsa-sha256 and ed25519-sha256 hash with sha256
  return nodeCrypto.createHash(hashName)
    .update(canonicalized).digest("base64");
}

function _signString(strToSign, privateKey, algorithm) {
  if (algorithm === "rsa-sha256") {
    return nodeCrypto.createSign("RSA-SHA256")
      .update(strToSign).sign(privateKey).toString("base64");
  }
  if (algorithm === "ed25519-sha256") {
    // Ed25519 in node:crypto signs the raw message (it hashes
    // internally as part of EdDSA). Per RFC 8463 the verifier still
    // sees `a=ed25519-sha256` because the body hash is sha256.
    return nodeCrypto.sign(null, Buffer.from(strToSign, "utf8"), privateKey)
      .toString("base64");
  }
  throw new DkimError("dkim/bad-algorithm",
    "unknown algorithm: " + algorithm);
}

// ---- Signature header construction ----

function _foldSignatureHeader(unfolded) {
  // RFC 5322 §2.2.3 line length: 78 preferred, 998 max. The b= value
  // is long enough that folding helps readability and stays well clear
  // of the limit.
  var maxLine = 76;
  var name = "DKIM-Signature: ";
  var rest = unfolded;
  if ((name + rest).length <= maxLine) return name + rest;
  // Fold on tag boundaries (`; tag=value`). Each non-last chunk keeps
  // its trailing `;` (RFC 6376 §3.2 — `;` is the tag-list separator,
  // not a tag-end terminator; receivers' parsers expect it on the
  // PRIOR line at fold points). Earlier shape ("v=1\r\n\ta=...;")
  // missed the first separator and tripped strict parsers.
  var parts = rest.split("; ");
  var lines = [name + parts[0] + (parts.length > 1 ? ";" : "")];
  for (var i = 1; i < parts.length; i++) {
    lines.push("\t" + parts[i] + (i < parts.length - 1 ? ";" : ""));
  }
  return lines.join("\r\n");
}

// ---- Public surface ----

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
  // RFC 6376 §3.1 ABNF: selector = sub-domain *("." sub-domain). Multi-
  // label selectors like "2024.s1" are valid (and common for time-rotated
  // keys). Each label is the LDH set; refuse leading/trailing dots and
  // empty labels.
  if (typeof opts.selector !== "string" ||
      opts.selector.length === 0 || opts.selector.length > 253 ||                            // allow:raw-byte-literal — DNS label length cap (RFC 1035)
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
  // The DKIM `l=` body-length tag is intentionally NOT supported.
  // M³AAWG, Gmail, and Microsoft 365 guidance is "never use l=" — it
  // enables append-after-signature attacks where an attacker appends
  // arbitrary content past the signed length and the DKIM signature
  // still validates against the original prefix. Throw at create-time
  // so the misconfiguration surfaces at boot, not at first send().
  if (opts.bodyLength !== undefined) {
    throw new DkimError("dkim/l-tag-forbidden",
      "DKIM `l=` body-length tag is forbidden — append-after-signature " +
      "attack vector. Remove opts.bodyLength.");
  }

  var auditOn = opts.audit !== false;
  // Try to parse the private key once at create time so misconfigured
  // operators see the failure at boot rather than at first send().
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
    if (typeof rfc822 !== "string" || rfc822.length === 0) {
      throw new DkimError("dkim/bad-input",
        "sign() requires the rfc822 wire format as a non-empty string");
    }
    var t0 = Date.now();
    var split = _splitHeadersBody(rfc822);
    var parsedHeaders = _parseHeaders(split.headers);

    // Body hash. The `l=` body-length tag is forbidden at create-time
    // (above), so the body is always hashed in full.
    var body = split.body;
    var bh = _bodyHashB64(body, algorithm, canonBody);

    // Build the unsigned DKIM-Signature header (b= empty).
    // Tag order follows RFC 6376 examples: v, a, c, d, s, h, bh, b.
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

    // Canonicalize the header set: each header in headersToSign (in
    // order, picking the LAST occurrence per RFC 6376 §5.4.2), then
    // the DKIM-Signature header itself with empty b=. The result is
    // what gets signed.
    var headerNamesLc = parsedHeaders.map(function (h) { return h.name.toLowerCase(); });
    var canonicalizedHeaders = "";
    for (var j = 0; j < headersToSign.length; j++) {
      var wantLc = headersToSign[j].toLowerCase();
      var idx = -1;
      for (var k = 0; k < headerNamesLc.length; k++) {
        if (headerNamesLc[k] === wantLc) idx = k;
      }
      if (idx === -1) continue;  // missing headers are skipped (signer's choice)
      var h = parsedHeaders[idx];
      canonicalizedHeaders += canonHeader === "simple"
        ? _canonHeaderSimple(h.name, h.value)
        : _canonHeaderRelaxed(h.name, h.value);
    }
    // Append the unsigned DKIM-Signature header without trailing CRLF
    // per RFC 6376 §3.7.
    var dkimHeaderForSigning = canonHeader === "simple"
      ? _canonHeaderSimple("DKIM-Signature", " " + unsignedSigValue)
      : _canonHeaderRelaxed("DKIM-Signature", unsignedSigValue);
    canonicalizedHeaders += dkimHeaderForSigning.replace(/\r\n$/, "");

    var signature = _signString(canonicalizedHeaders, keyObject, algorithm);
    // Replace the empty `b=` placeholder with the actual base64 signature.
    var finalSigValue = sigTags.slice(0, -1).concat(["b=" + signature]).join("; ");

    var dkimHeaderLine = _foldSignatureHeader(finalSigValue) + "\r\n";

    _emit("dkim.sign.success", {
      bodyLength: body.length,
      durationMs: Date.now() - t0,
    });

    return dkimHeaderLine + rfc822;
  }

  return {
    sign: sign,
    domain:    opts.domain,
    selector:  opts.selector,
    algorithm: algorithm,
  };
}

// dualSigner — RFC 8463 §3 transition signer. Produces messages with
// BOTH a legacy RSA-SHA-256 DKIM-Signature AND an Ed25519-SHA-256
// DKIM-Signature header. Receivers that don't yet support Ed25519
// validate the RSA signature; receivers that prefer Ed25519 validate
// the post-quantum-friendlier signature. The transition pattern is
// the recommended path for moving the operator's domain off RSA-SHA-
// 256 without breaking older verifiers.
//
//   var dual = b.mail.dkim.dualSigner({
//     domain: "example.com",
//     rsa:    { selector: "rsa1",   privateKey: rsaPemKey },
//     eddsa:  { selector: "eddsa1", privateKey: ed25519PemKey },
//     // every other create() opt is shared (canonicalization,
//     // headersToSign, audit) but can be overridden per algorithm.
//   });
//   var signed = dual.sign(rfc822Wire);
//   // → wire with two DKIM-Signature: headers (RSA first, Ed25519 second)
//
// Both signers are constructed eagerly at create-time (configuration
// errors surface at boot, not at first send). The combined sign()
// applies the RSA signer first, then the Ed25519 signer on top.
// ---- DKIM-Signature verification (RFC 6376 §6) ----
//
// Counterpart to the signer. Walks every DKIM-Signature header in
// the message, parses the tag list, fetches the signing public key
// from DNS TXT at <selector>._domainkey.<domain>, canonicalizes the
// body + headers per the c= tag, and runs nodeCrypto.verify.
//
// Surface:
//
//   var rv = await b.mail.dkim.verify(rfc822, {
//     dnsLookup: async function (qname, type) { return [["v=DKIM1; k=rsa; p=BASE64..."]]; },
//   });
//   // → [{ d, s, alg, result, errors }, ...]
//
// One result per DKIM-Signature header (operators expect multiple
// when senders dual-sign with RSA + Ed25519). Each result's `result`
// is one of: "pass" / "fail" / "permerror" / "temperror" / "neutral".
//
// dnsLookup is operator-supplied so verify() composes with the
// framework's b.network.dns (DoH / DoT / system) without taking a
// hard dependency on it. When omitted, falls back to node:dns.

function _parseDkimTagList(value) {
  // RFC 6376 §3.2 — tags are `key=value` separated by `;`. Whitespace
  // around `=` and `;` is allowed and stripped. The signer folds the
  // DKIM-Signature header across CRLF + WSP; unfold first so tag
  // boundaries land in the right place.
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");
  var tags = {};
  var parts = unfolded.split(";");
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var key = p.slice(0, eq).trim().toLowerCase();
    var val = p.slice(eq + 1).trim();
    // Whitespace inside values is unfolded — RFC 6376 §3.2 says FWS
    // (folding whitespace) is ignored within a tag value. Strip
    // newlines + tabs while preserving the meaningful tokens.
    val = val.replace(/\s+/g, "");
    tags[key] = val;
  }
  return tags;
}

function _selectorTxtToKeyTags(txtRecords) {
  // DKIM key record is a TXT record at <selector>._domainkey.<domain>.
  // Format: "v=DKIM1; k=rsa; p=<base64>" (chunks may be split across
  // multi-string TXT). Returns { v, k, p, t, h } or throws.
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

// Process-local cache for fetched DKIM key TXT records. Mailing-list
// fan-out and bulk-replay scenarios frequently re-fetch the same
// selector; without a cache the verifier hammers DNS. TTL bounded so
// rotated keys propagate within minutes, not hours.
var DKIM_KEY_CACHE = new Map();
var DKIM_KEY_CACHE_TTL_MS = 5 * 60 * 1000;                                       // allow:raw-time-literal — TTL ms expression
var DKIM_KEY_CACHE_MAX_ENTRIES = 1024;

function _cacheGet(qname) {
  var ent = DKIM_KEY_CACHE.get(qname);
  if (!ent) return null;
  if (ent.expires <= Date.now()) {
    DKIM_KEY_CACHE.delete(qname);
    return null;
  }
  return ent.tags;
}

function _cachePut(qname, tags) {
  if (DKIM_KEY_CACHE.size >= DKIM_KEY_CACHE_MAX_ENTRIES) {
    // Drop oldest (Map preserves insertion order). Cheap LRU-ish.
    var oldest = DKIM_KEY_CACHE.keys().next().value;
    if (oldest !== undefined) DKIM_KEY_CACHE.delete(oldest);
  }
  DKIM_KEY_CACHE.set(qname, { tags: tags, expires: Date.now() + DKIM_KEY_CACHE_TTL_MS });
}

function _resetDkimKeyCacheForTest() { DKIM_KEY_CACHE.clear(); }

function _pemFromB64KeyMaterial(b64) {
  // RSA: SubjectPublicKeyInfo DER in base64. Ed25519: raw 32-byte key
  // OR SPKI DER. Wrap in PEM markers so node:crypto.createPublicKey
  // accepts it.
  var pem = "-----BEGIN PUBLIC KEY-----\n";
  // 64-char wrap (PEM convention).
  for (var i = 0; i < b64.length; i += 64) {                                     // allow:raw-byte-literal — PEM wrap width
    pem += b64.slice(i, i + 64) + "\n";                                          // allow:raw-byte-literal — PEM wrap width
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
    if (dnsLookup) {
      records = await dnsLookup(qname, "TXT");
    } else {
      var dnsModule = require("node:dns/promises");
      records = await dnsModule.resolveTxt(qname);
    }
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

function _verifySingleSignature(rfc822, parsedHeaders, sigHeader, keyTags, sigTags) {
  // Reconstruct what the signer canonicalized, per RFC 6376 §3.7.
  var canonicalization = sigTags.c || "simple/simple";
  var canonHeader = canonicalization.split("/")[0];
  var canonBody   = canonicalization.split("/")[1];
  var algorithm   = sigTags.a;

  var split = _splitHeadersBody(rfc822);
  var body = split.body;
  if (sigTags.l !== undefined) {
    // The framework refuses l= at SIGN-time per the M3AAWG / Gmail /
    // Microsoft 365 guidance (v0.7.18). On VERIFY, an `l=` tag on an
    // inbound signature signals append-after-signature exposure —
    // operators decide acceptance. Honor the cap for the body hash so
    // the signature still validates against legitimate senders that
    // use l=, but flag in the result.
    var lcap = parseInt(sigTags.l, 10);
    if (isFinite(lcap) && lcap >= 0) body = body.slice(0, lcap);
  }

  // 1. Body-hash check.
  var expectedBh = sigTags.bh;
  if (typeof expectedBh !== "string") {
    return { result: "permerror", errors: ["DKIM-Signature missing bh="] };
  }
  var actualBh = _bodyHashB64(body, algorithm, canonBody);
  if (actualBh !== expectedBh) {
    return { result: "fail", errors: ["body hash mismatch"] };
  }

  // 2. Canonicalize the headers in h= order, then the DKIM-Signature
  //    header itself with the b= value emptied (per §3.7).
  var headerNames = (sigTags.h || "").split(":").map(function (s) {
    return s.trim().toLowerCase();
  });
  // RFC 6376 §3.5 — "from" MUST be in h=. Without From-coverage the
  // signature does not bind to the visible sender, and the receiver's
  // "this domain signed for that From" claim is meaningless. Cornerstone
  // bypass class — refuse the signature outright.
  if (headerNames.indexOf("from") === -1) {
    return { result: "permerror",
             errors: ["DKIM-Signature h= tag does not include 'from' (RFC 6376 §3.5)"] };
  }
  var lcNames = parsedHeaders.map(function (h) { return h.name.toLowerCase(); });
  var canonicalizedHeaders = "";
  for (var j = 0; j < headerNames.length; j += 1) {
    var want = headerNames[j];
    if (want.length === 0) continue;
    var idx = lcNames.lastIndexOf(want);                                         // last-occurrence per the DKIM spec
    if (idx === -1) continue;
    var h = parsedHeaders[idx];
    canonicalizedHeaders += canonHeader === "simple"
      ? _canonHeaderSimple(h.name, h.value)
      : _canonHeaderRelaxed(h.name, h.value);
  }
  // Strip the b= value from the DKIM-Signature header for the canonical
  // form per §3.7.
  var unsignedSigValue = sigHeader.value.replace(/(\bb=)[^;]*/i, "$1");
  canonicalizedHeaders += canonHeader === "simple"
    ? _canonHeaderSimple("DKIM-Signature", " " + unsignedSigValue).replace(/\r\n$/, "")
    : _canonHeaderRelaxed("DKIM-Signature", unsignedSigValue).replace(/\r\n$/, "");

  // 3. Verify the signature.
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

  // Key-size enforcement (RFC 8301 §3.1, M³AAWG hardening guidance):
  // RSA keys < 1024 bits MUST be considered failure; < 2048 is weak.
  // The framework rejects < 1024 as a security baseline; < 2048 emits
  // a warning in the result so operators can quarantine.
  var warnings = [];
  if (algorithm === "rsa-sha256" && keyObj.asymmetricKeyType === "rsa") {
    var modBits = (keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.modulusLength) || 0;
    if (modBits > 0 && modBits < RSA_MIN_BITS) {
      return { result: "fail",
               errors: ["RSA key too small: " + modBits + " bits (RFC 8301 §3.1 minimum " + RSA_MIN_BITS + ")"] };
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
      Buffer.from(canonicalizedHeaders, "utf8"), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: ["DKIM verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [], warnings: warnings }
    : { result: "fail", errors: ["signature verification failed"], warnings: warnings };
}

async function verify(rfc822, opts) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new DkimError("dkim/bad-input",
      "verify(): rfc822 must be a non-empty string");
  }
  opts = opts || {};
  validateOpts(opts, ["dnsLookup", "audit"], "mail.dkim.verify");

  var split = _splitHeadersBody(rfc822);
  var parsedHeaders = _parseHeaders(split.headers);
  var sigHeaders = _findDkimSignatureHeaders(parsedHeaders);
  if (sigHeaders.length === 0) {
    return [{ result: "none", errors: ["no DKIM-Signature headers"] }];
  }

  var results = [];
  for (var i = 0; i < sigHeaders.length; i += 1) {
    var sigTags = _parseDkimTagList(sigHeaders[i].value);
    var d = sigTags.d;
    var s = sigTags.s;
    var alg = sigTags.a;
    // RFC 6376 §3.5 — v= tag is REQUIRED and MUST be "1". Unrecognized
    // version → permerror per spec; refuse rather than guess at intent.
    if (sigTags.v !== undefined && sigTags.v !== "1") {
      results.push({ d: d || null, s: s || null, alg: alg || null,
        result: "permerror", errors: ["DKIM-Signature v=" + sigTags.v + " unsupported (RFC 6376 §3.5 — only v=1)"] });
      continue;
    }
    // RFC 6376 §3.5 — x= signature expiration, t= signature timestamp.
    // x= MUST be after t= and MUST NOT be in the past. t= sanity:
    // refuse if more than 24h in the future (clock drift between
    // signer + verifier of more than a day is a near-certain bug or
    // attack). Both are in seconds-since-epoch per ABNF.
    var nowSec = Math.floor(Date.now() / 1000);                                                // allow:raw-byte-literal — Unix-epoch seconds divisor
    var clockSkewSec = Math.floor((opts.clockSkewMs || (5 * 60 * 1000)) / 1000);              // allow:raw-time-literal — default 5-minute skew
    if (sigTags.x !== undefined) {
      var expSec = parseInt(sigTags.x, 10);
      if (isFinite(expSec) && expSec + clockSkewSec < nowSec) {
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature x=" + expSec + " has expired (RFC 6376 §3.5)"] });
        continue;
      }
    }
    if (sigTags.t !== undefined) {
      var tSec = parseInt(sigTags.t, 10);
      // Allow up to 24h future-skew; beyond that, refuse — neither
      // operator clock drift nor delivery latency explains a future-
      // dated signing time of more than a day.
      if (isFinite(tSec) && tSec - (24 * 60 * 60) > nowSec) {                                  // allow:raw-byte-literal — Unix-seconds offset, not bytes / allow:raw-time-literal — 24h future-date sanity ceiling
        results.push({ d: d || null, s: s || null, alg: alg || null,
          result: "permerror",
          errors: ["DKIM-Signature t=" + tSec + " is more than 24h in the future (RFC 6376 §3.5 sanity)"] });
        continue;
      }
      if (sigTags.x !== undefined) {
        var xSec = parseInt(sigTags.x, 10);
        if (isFinite(xSec) && isFinite(tSec) && xSec < tSec) {
          results.push({ d: d || null, s: s || null, alg: alg || null,
            result: "permerror",
            errors: ["DKIM-Signature x= must be after t= (RFC 6376 §3.5)"] });
          continue;
        }
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
      // RFC 6376 §3.6.1 — empty p= explicitly revokes the key. Verdict
      // is "fail" (not "permerror") — the signature is well-formed but
      // the key authority intentionally withdrew it.
      results.push({ d: d, s: s, alg: alg, result: "fail",
        errors: ["DKIM key revoked (empty p= per RFC 6376 §3.6.1)"] });
      continue;
    }
    if (!keyTags.p) {
      results.push({ d: d, s: s, alg: alg, result: "permerror",
        errors: ["DKIM key record missing p="] });
      continue;
    }
    // RFC 6376 §3.6.1 — k= tag declares the key's algorithm family.
    // Default is "rsa" when absent. If the key's k= disagrees with the
    // signature's a= family, the operator who published the key intends
    // a different algorithm; refuse rather than guess.
    if (keyTags.k !== undefined) {
      var kFamily   = String(keyTags.k).toLowerCase();
      var sigFamily = String(alg || "").toLowerCase().split("-")[0];
      if (kFamily !== sigFamily) {
        results.push({ d: d, s: s, alg: alg, result: "permerror",
          errors: ["DKIM key k=" + kFamily + " does not match signature a=" + alg + " (RFC 6376 §3.6.1)"] });
        continue;
      }
    }
    var rv = _verifySingleSignature(rfc822, parsedHeaders, sigHeaders[i], keyTags, sigTags);
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

// Test-only exports for unit testing the canonicalization primitives
// directly without going through a full sign() round.
module.exports = {
  create:      create,
  verify:      verify,
  _resetDkimKeyCacheForTest: _resetDkimKeyCacheForTest,
  dualSigner:  dualSigner,
  DkimError:   DkimError,
  _canonHeaderRelaxedForTest: _canonHeaderRelaxed,
  _canonBodyRelaxedForTest:   _canonBodyRelaxed,
  _canonBodySimpleForTest:    _canonBodySimple,
};
