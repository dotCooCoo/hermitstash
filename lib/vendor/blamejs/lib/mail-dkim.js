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

// RSA modulus bit-size thresholds per RFC 8301bis (draft-ietf-dmarc-rfc8301bis)
// + Google + Yahoo February 2024 bulk-sender policy + M³AAWG hardening.
// RFC 8301 §3.1 historic floor was 1024; bulk-sender enforcement at the
// two largest mailbox providers raised the operational floor to 2048
// (messages signed with <2048-bit keys are rejected or quarantined).
// Anything below MIN must be considered failure on verify; below WEAK
// emits a warning so operators can quarantine while transitioning.
// Operators stuck with legacy 1024-bit signers (deprecated; remediate
// before bulk-sending) opt down via verify({ minRsaBits: 1024 }) per-call
// — the historical floor stays available for migration but the
// framework default refuses sub-2048 inbound.
var RSA_MIN_BITS  = 2048;                                                        // allow:raw-byte-literal — RFC 8301bis + 2024 bulk-sender floor
var RSA_WEAK_BITS = 2048;                                                        // allow:raw-byte-literal — RFC 8301bis weak threshold (same as floor)
var RSA_LEGACY_MIN_BITS = 1024;                                                  // allow:raw-byte-literal — RFC 8301 historical floor, opt-in only

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
    //
    // Missing-header policy (RFC 6376 §3.4.2 + §5.4): the signer is
    // permitted to list a header in h= that isn't present in the
    // message — the verifier will compute the canonicalized form as
    // empty and the signature still validates IF both sides agree the
    // header is absent. The risk is silent drift: an operator
    // configures `headersToSign: [..., "List-Unsubscribe-Post", ...]`
    // for a campaign mailer, the per-message builder forgets to add
    // the header, and the signature ships without binding to the
    // intended commitment. Emit an audit event so operators see the
    // skip rather than only noticing when a recipient rejects.
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
        // Operator configured h= entry that isn't in the message —
        // surface via audit; sign continues per RFC 6376 §3.4.2.
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
//
// Eviction is LRU (not FIFO): on hit, the entry is removed and
// re-inserted so the Map's insertion-order ordering tracks recency.
// FIFO would evict the most-recently-fetched key of an
// active-domain mix under cache pressure — exactly the wrong shape
// for repeated-sender workloads.
var DKIM_KEY_CACHE = new Map();
var DKIM_KEY_CACHE_TTL_MS = C.TIME.minutes(5);
var DKIM_KEY_CACHE_MAX_ENTRIES = 1024;

// Per-message signature-count cap (DoS bound). A single message with
// many DKIM-Signature headers forces the verifier to fetch a key and
// run cryptographic verify for each — without a cap, an attacker
// inflates verifier work linearly in header count. RFC 6376 §6.1
// permits multiple signatures but doesn't bound them; mainstream
// receivers cap at 5–8. Operators that legitimately accept more
// override via verify({ maxSignatures }).
var DKIM_MAX_SIGNATURES_PER_MESSAGE = 8;                                         // allow:raw-byte-literal — receiver-fan-out DoS bound
// Operator-supplied `maxSignatures` opt is range-checked against this
// ceiling. RFC 6376 §6.1 sets no upper bound; 16 is generous headroom
// for legitimate relay chains with hop signatures while keeping the
// verify-fan-out within a CPU-DoS envelope.
var DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING = 16;                                // allow:raw-byte-literal — operator-opt range ceiling

function _cacheGet(qname) {
  var ent = DKIM_KEY_CACHE.get(qname);
  if (!ent) return null;
  if (ent.expires <= Date.now()) {
    DKIM_KEY_CACHE.delete(qname);
    return null;
  }
  // LRU: remove + re-insert so this entry becomes the most-recent in
  // Map insertion order. Evictions below pop the oldest via keys().
  DKIM_KEY_CACHE.delete(qname);
  DKIM_KEY_CACHE.set(qname, ent);
  return ent.tags;
}

function _cachePut(qname, tags) {
  if (DKIM_KEY_CACHE.size >= DKIM_KEY_CACHE_MAX_ENTRIES) {
    // Drop oldest by insertion-order (LRU since _cacheGet rotates).
    var oldest = DKIM_KEY_CACHE.keys().next().value;
    if (oldest !== undefined) DKIM_KEY_CACHE.delete(oldest);
  }
  DKIM_KEY_CACHE.set(qname, { tags: tags, expires: Date.now() + DKIM_KEY_CACHE_TTL_MS });
}

// Shared safe-DNS TXT lookup. Operator-supplied `dnsLookup` (legacy
// `[[strings]]` shape) takes precedence; otherwise routes through
// `b.network.dns.resolver` which uses DoH by default (per v0.7.23),
// so the framework default never falls back to plaintext node:dns
// resolution against an operator-untrusted upstream. CVE-2008-1447
// (Kaminsky) + CVE-2022-3204 (NRDelegationAttack) class — the
// transport-encrypted DoH path plus `b.safeDns` parse caps defend
// both transport and parse-side. Operators that need plaintext
// upstream wire it explicitly via `dnsLookup`.
var _defaultResolver = null;
function _getDefaultResolver() {
  if (_defaultResolver) return _defaultResolver;
  _defaultResolver = networkDnsResolver().create();
  return _defaultResolver;
}

async function _safeResolveTxt(qname, operatorLookup) {
  if (operatorLookup) return operatorLookup(qname, "TXT");
  var r = await _getDefaultResolver().queryTxt(qname);
  // Resolver returns parsed RRs; reshape to the legacy
  // `[[chunk1, chunk2], ...]` shape so callers downstream don't care
  // which path produced the bytes.
  var out = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    if (rr && rr.type === 16) {                                                  // allow:raw-byte-literal — IANA DNS qtype TXT
      out.push(Array.isArray(rr.decoded) ? rr.decoded : [String(rr.decoded)]);
    }
  }
  if (out.length === 0) {
    var err = new Error("no TXT records for " + qname);
    err.code = "ENODATA";
    throw err;
  }
  return out;
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

// Strip the value of the `b=` tag from a DKIM-Signature tag list per
// RFC 6376 §3.7. Walks tag-spec boundaries (`;` separator) and only
// matches the exact `b` tag name — not any tag whose name happens
// to end in `b`. Returns the value with the b= tag's content removed
// (leaving `b=` in place).
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
  // Reconstruct what the signer canonicalized, per RFC 6376 §3.7.
  var canonicalization = sigTags.c || "simple/simple";
  var canonHeader = canonicalization.split("/")[0];
  var canonBody   = canonicalization.split("/")[1];
  var algorithm   = sigTags.a;

  // RFC 6376 §3.5 — the optional i= tag (Agent or User Identifier),
  // when present, MUST have a domain part identical to or a subdomain
  // of d=. A signature whose i= claims `@evil.example.com` while d=
  // is `example.org` is malformed and binds the signer's claim to a
  // domain the verifier wouldn't otherwise associate. Refuse.
  if (typeof sigTags.i === "string" && sigTags.i.length > 0) {
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

  // RFC 6376 §3.6.1 — the key record's optional h= tag declares the
  // hash algorithms the key MAY be used with (`sha256` is canonical).
  // The signature's a= names the hash via its suffix (`rsa-sha256`,
  // `ed25519-sha256`). If h= is present on the key, the signature's
  // hash MUST appear in the colon-separated list; otherwise the key
  // owner intends the key for a different hash family and the
  // signature is unauthorized.
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
  // form per RFC 6376 §3.7. The strip must locate the `b=` tag within
  // the tag-list grammar (`tag-spec *( ";" tag-spec )` per §3.2) and
  // zero its value through the next `;` OR end-of-string. The earlier
  // shape `/(\bb=)[^;]*/i` matched on the first `b=` substring anywhere
  // in the value — fine for current DKIM tag vocabulary (no tag-name
  // ends in `b`) but brittle against any hypothetical future tag whose
  // name ends in `b` (`ab=`, `pub=`, `cb=` …). Anchor on the tag-list
  // structure instead.
  var unsignedSigValue = _stripBTagValue(sigHeader.value);
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

  // Key-size enforcement (RFC 8301bis §3.1 + Google + Yahoo Feb 2024
  // bulk-sender + M³AAWG hardening):
  //   - Default floor: 2048 bits (bulk-sender enforced floor).
  //   - Operator opt-down: verify({ minRsaBits: 1024 }) re-enables the
  //     historical RFC 8301 floor for legacy migration windows. Sub-
  //     1024 is refused regardless of opt-down — no operator policy
  //     can accept genuinely-too-small RSA per §3.1.
  //   - Below opt-down-honored floor → fail; below WEAK threshold →
  //     warning so operators can quarantine while transitioning.
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
      Buffer.from(canonicalizedHeaders, "utf8"), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: ["DKIM verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [], warnings: warnings }
    : { result: "fail", errors: ["signature verification failed"], warnings: warnings };
}

// RFC 6376 §3.5 — `t=` / `x=` clock-skew bound. Operator-tunable, but
// must be a finite non-negative number and must NOT exceed the
// FRAMEWORK absolute ceiling. An unbounded skew lets an attacker
// re-play a long-expired signed message indefinitely; the ceiling
// bounds the maximum back-dating tolerance.
var DKIM_CLOCK_SKEW_MS_MAX = C.TIME.hours(24);
var DKIM_CLOCK_SKEW_MS_DEFAULT = C.TIME.minutes(5);

async function verify(rfc822, opts) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new DkimError("dkim/bad-input",
      "verify(): rfc822 must be a non-empty string");
  }
  opts = opts || {};
  validateOpts(opts, ["dnsLookup", "audit", "clockSkewMs", "maxSignatures",
                       "minRsaBits"], "mail.dkim.verify");
  var auditOn = opts.audit !== false;

  // Bounded clock skew: refuse non-numeric / negative / infinite /
  // beyond-ceiling. Throwing on bad config-time input per the
  // framework's three-tier validation policy.
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

  // RFC 6376 §6.1 — verifier MUST handle multiple signatures but the
  // RFC sets no count cap. An unbounded count is a CPU-DoS surface
  // (each sig forces a DNS fetch + cryptographic verify). Range 1-16
  // — mainstream receivers (Gmail/Yahoo/MS 2024 bulk-sender guidance)
  // cite 2-3 valid signatures per message as the operational ceiling;
  // 16 is generous headroom for relay chains with hop signatures. The
  // operator opt is range-checked at config time — values < 1 or > 16
  // throw rather than silently clamp so an over-large config doesn't
  // re-introduce the DoS surface.
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
  var verifyOpts = { minRsaBits: opts.minRsaBits };

  var split = _splitHeadersBody(rfc822);
  var parsedHeaders = _parseHeaders(split.headers);
  var sigHeaders = _findDkimSignatureHeaders(parsedHeaders);
  if (sigHeaders.length === 0) {
    return [{ result: "none", errors: ["no DKIM-Signature headers"] }];
  }
  // When the message carries more signatures than the cap allows,
  // surface a `policy` verdict before any cryptographic work runs.
  // The prior `slice(0, maxSignatures)` shape silently truncated; an
  // operator-visible refusal lets postmasters see DoS attempts in
  // their authentication-results stream.
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
    var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
    var clockSkewSec = Math.floor(clockSkewMs / C.TIME.seconds(1));
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

// Test-only exports for unit testing the canonicalization primitives
// directly without going through a full sign() round.
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
  // DKIM selector + domain shape: RFC 6376 §3.1 — selector is a
  // sub-domain label (no leading/trailing dot; no whitespace; no
  // wildcards). domain is a normal DNS hostname.
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
  // dual
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
  var k;     // DNS TXT `k=` tag value
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
  var pBase64         = Buffer.from(keyPair.publicKey).toString("base64");
  var dnsName         = selector + "._domainkey." + domain;
  // RFC 6376 §3.6.1 record syntax: v=DKIM1; k=<alg>; p=<base64>
  // The optional t/s/g/n/h/k tags omitted (operator can re-edit
  // the dnsTxtValue before publishing if they need policy flags).
  var dnsTxtValue = "v=DKIM1; k=" + k + "; p=" + pBase64;
  // BIND/Unbound zone-file shape: name TTL? IN TXT ("...").
  // TXT values > 255 octets must be split into multiple quoted
  // strings per RFC 1035 §3.3.14 — long RSA records will trip this.
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

// RFC 1035 §3.3.14 — TXT records carry one or more <character-string>s
// each capped at 255 octets. Long RSA p= values are split into multiple
// quoted strings so the zone file is valid.
function _wrapDnsTxt(value) {
  if (value.length <= 255) return '"' + value + '"';                                                // allow:raw-byte-literal — RFC 1035 character-string cap
  var parts = [];
  for (var i = 0; i < value.length; i += 255) parts.push('"' + value.slice(i, i + 255) + '"');     // allow:raw-byte-literal — RFC 1035 character-string cap
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
  DKIM_CLOCK_SKEW_MS_MAX:     DKIM_CLOCK_SKEW_MS_MAX,
  _canonHeaderRelaxedForTest: _canonHeaderRelaxed,
  _canonBodyRelaxedForTest:   _canonBodyRelaxed,
  _canonBodySimpleForTest:    _canonBodySimple,
  _stripBTagValueForTest:     _stripBTagValue,
};
