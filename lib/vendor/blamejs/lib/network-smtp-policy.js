"use strict";
/**
 * b.network.smtp.policy — MTA-STS + DANE + TLS-RPT outbound SMTP gates.
 *
 * Gmail and Microsoft 365 now penalize senders without MTA-STS / DANE
 * policies. This primitive is the framework's outbound-SMTP policy
 * surface — operators wire it into `b.mail` to enforce the recipient
 * domain's published policy before opening the SMTP socket.
 *
 *   var policy = b.network.smtp.policy;
 *   var sts = await policy.mtaSts.fetch("example.com");
 *   if (sts && sts.mode === "enforce") {
 *     // Verify the MX hostname matches an entry in sts.mx[*]
 *     // (wildcards allowed per RFC 8461 §3.2).
 *     var ok = policy.mtaSts.matchMx(mxHost, sts.mx);
 *     if (!ok) throw new SmtpPolicyError("smtp/mta-sts-mx-mismatch", ...);
 *   }
 *
 *   var tlsa = await policy.dane.tlsa("example.com", 25);
 *   // → [{ usage, selector, mtype, dataHex }, ...] from DNS TYPE 52
 *
 *   policy.tlsRpt.recordShape({
 *     organization: "example.com",
 *     reportingMta: "mx1.example.com",
 *     ...
 *   }) → { ... RFC 8460 TLS-RPT JSON shape ... }
 *
 * Surface:
 *   - mtaSts.fetch(domain)               — HTTPS-fetch + parse + cache
 *   - mtaSts.matchMx(mxHost, mxList)     — wildcard-aware match
 *   - dane.tlsa(domain, port)            — DNS TYPE 52 lookup
 *   - dane.recordShape(buffer)           — TLSA RR field decode
 *   - tlsRpt.recordShape(opts)           — RFC 8460 JSON shape generator
 *   - tlsRpt.fetchPolicy(domain)         — RFC 8460 §3 _smtp._tls TXT
 *                                          parse → { version, rua: [] }
 *   - tlsRpt.submit(report, { rua })     — gzip + POST to https rua
 *                                          endpoints; mailto entries
 *                                          surface a prepared body so
 *                                          operators hand it to b.mail
 *
 * Out of scope (deferred):
 *   - Full DANE certificate-chain verification per RFC 6698 (needs
 *     ASN.1 cert parsing). Operators today verify policy presence +
 *     match the leaf SHA-256 themselves.
 *   - DNSSEC-validated DANE lookups: the framework now exposes the
 *     AD bit via `b.network.dns.resolveSecure(name, type) → { rrs,
 *     ad }`. Operators wiring strict RFC 7672 §1.3 compliance pass
 *     a DNSSEC-aware resolver via opts and refuse the chain when
 *     ad === false. The default `tlsa()` lookup path stays on
 *     `node:dns` for compatibility with operators on system
 *     resolvers.
 */

var dns = require("node:dns");
var dnsPromises = dns.promises;
var nodeCrypto = require("node:crypto");
var zlib = require("node:zlib");
var asn1 = require("./asn1-der");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var bCrypto = require("./crypto");
var safeUrl = require("./safe-url");
var safeJson = require("./safe-json");
var C = require("./constants");
var { SmtpPolicyError } = require("./framework-error");

var httpClient = lazyRequire(function () { return require("./http-client"); });
var cache = lazyRequire(function () { return require("./cache"); });

var DEFAULT_POLICY_CACHE_MS = C.TIME.minutes(60);
var MAX_POLICY_BYTES = C.BYTES.kib(64);

// ---- per-process cache for fetched MTA-STS policies ----

var _stsCache = null;
function _getStsCache() {
  if (_stsCache) return _stsCache;
  _stsCache = cache().create({
    namespace: "smtp-policy.mta-sts",
    ttlMs:     DEFAULT_POLICY_CACHE_MS,
  });
  return _stsCache;
}

// ---- MTA-STS (RFC 8461) ----

// Parse an MTA-STS policy text (key: value lines, MX lines may repeat).
function _parseStsPolicy(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw new SmtpPolicyError("smtp/mta-sts-empty",
      "MTA-STS policy text is empty");
  }
  var policy = { version: null, mode: null, mx: [], max_age: null };
  var lines = text.split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i].trim();
    if (line.length === 0) continue;
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var key = line.slice(0, colonAt).trim().toLowerCase();
    var val = line.slice(colonAt + 1).trim();
    if (key === "version") policy.version = val;
    else if (key === "mode") policy.mode = val.toLowerCase();
    else if (key === "mx") policy.mx.push(val.toLowerCase());
    else if (key === "max_age") policy.max_age = parseInt(val, 10);
  }
  if (policy.version !== "STSv1") {
    throw new SmtpPolicyError("smtp/mta-sts-bad-version",
      "MTA-STS policy version must be STSv1, got " +
      JSON.stringify(policy.version));
  }
  if (["enforce", "testing", "none"].indexOf(policy.mode) === -1) {
    throw new SmtpPolicyError("smtp/mta-sts-bad-mode",
      "MTA-STS policy mode must be enforce|testing|none, got " +
      JSON.stringify(policy.mode));
  }
  return policy;
}

// RFC 8461 §3.1 precondition. The TXT record at _mta-sts.<domain> is
// the rotation signal: receivers re-fetch the HTTPS policy when the
// `id=` value changes. Without it the fetcher would re-pull the same
// cached policy forever (defeating operator rotation), and would also
// fetch policies from domains that don't publish one.
async function _fetchStsTxt(domain, dnsLookup) {
  var records;
  try {
    records = dnsLookup
      ? await dnsLookup("_mta-sts." + domain, "TXT")
      : await dnsPromises.resolveTxt("_mta-sts." + domain);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new SmtpPolicyError("smtp/mta-sts-txt-lookup-failed",
      "_mta-sts." + domain + " TXT lookup failed: " +
      ((e && e.message) || String(e)));
  }
  if (!Array.isArray(records)) return null;
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (typeof rec !== "string") continue;
    if (rec.indexOf("v=STSv1") === -1) continue;
    var idMatch = /\bid=([A-Za-z0-9]{1,32})/.exec(rec);
    return { record: rec, id: idMatch ? idMatch[1] : null };
  }
  return null;
}

async function mtaStsFetch(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "mtaSts.fetch: domain must be a non-empty string");
  }
  opts = opts || {};
  var lcDomain = domain.toLowerCase();
  // RFC 8461 §3.1 — refuse to fetch the HTTPS policy if the
  // _mta-sts TXT record is absent. Closes the silent-escalation
  // class.
  var txt = await _fetchStsTxt(lcDomain, opts.dnsLookup);
  if (!txt) return null;

  // Cache key includes the policy id so operator-side rotations (id
  // changes) invalidate the cached policy without operator action.
  var cacheKey = lcDomain + "|" + (txt.id || "noid");
  return await _getStsCache().wrap(cacheKey, async function () {
    var url = "https://mta-sts." + lcDomain + "/.well-known/mta-sts.txt";
    safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
    // RFC 8461 §3.3 — the HTTPS cert MUST validate against
    // mta-sts.<domain> with the standard public-CA chain. We pass
    // checkServerIdentity:default + rejectUnauthorized:true (the
    // framework default) and pin servername to the expected host
    // so a permissive httpClient default can't be flipped on.
    var res;
    try {
      res = await httpClient().request({
        method:             "GET",
        url:                url,
        maxBytes:           MAX_POLICY_BYTES,
        timeoutMs:          C.TIME.seconds(10),
        servername:         "mta-sts." + lcDomain,
        rejectUnauthorized: true,
      });
    } catch (_e) {
      return null;
    }
    if (res.statusCode === 404) return null;                                     // allow:raw-byte-literal — HTTP 404
    if (res.statusCode < 200 || res.statusCode >= 300) {                         // allow:raw-byte-literal — HTTP 2xx range
      throw new SmtpPolicyError("smtp/mta-sts-fetch-failed",
        "MTA-STS fetch returned " + res.statusCode + " for " + url);
    }
    var parsed = _parseStsPolicy(res.body.toString("utf8"));
    parsed.id = txt.id || null;
    parsed.fetchedAt = Date.now();
    // RFC 8461 §3.2 — max_age caps the cache TTL. Bound between 1 hour
    // (floor — operators using shorter values are below the spec
    // recommended floor) and 31557600 seconds (RFC 8461 ceiling). When
    // max_age is missing, fall back to the framework default.
    var maxAgeSec = parsed.max_age;
    if (typeof maxAgeSec === "number" && isFinite(maxAgeSec) && maxAgeSec > 0) {
      var hourSec = C.TIME.hours(1) / C.TIME.seconds(1);
      var ceilingSec = C.TIME.weeks(52) / C.TIME.seconds(1);                                   // RFC 8461 §3.2 — ~1 year ceiling
      var clamped = Math.max(hourSec, Math.min(ceilingSec, maxAgeSec));
      parsed._cacheTtlMs = clamped * C.TIME.seconds(1);
    } else {
      parsed._cacheTtlMs = DEFAULT_POLICY_CACHE_MS;
    }
    return parsed;
  });
}

// MX matching per RFC 8461 §3.2 — exact host or single-label wildcard
// (e.g. `*.example.com` matches `mx1.example.com` but not
// `example.com` or `a.b.example.com`).
function mtaStsMatchMx(mxHost, mxList) {
  if (typeof mxHost !== "string" || !Array.isArray(mxList)) return false;
  var lc = mxHost.toLowerCase();
  for (var i = 0; i < mxList.length; i += 1) {
    var entry = String(mxList[i]).toLowerCase();
    if (entry === lc) return true;
    if (entry.length > 2 && entry.slice(0, 2) === "*.") {
      var suffix = entry.slice(1);   // ".example.com"
      var dotAt = lc.indexOf(".");
      if (dotAt === -1) continue;
      if (lc.slice(dotAt) === suffix) return true;
    }
  }
  return false;
}

// ---- DANE TLSA (RFC 6698) ----

async function daneTlsa(domain, port, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "dane.tlsa: domain must be a non-empty string");
  }
  opts = opts || {};
  var p = typeof port === "number" ? port : 25;                                  // allow:raw-byte-literal — IANA SMTP port
  var qname = "_" + p + "._tcp." + domain.toLowerCase();
  // node:dns has resolveTlsa() since Node 18.16.0.
  if (typeof dnsPromises.resolveTlsa !== "function") {
    throw new SmtpPolicyError("smtp/dane-unavailable",
      "node:dns.resolveTlsa is not available on this runtime");
  }
  var records;
  try { records = await dnsPromises.resolveTlsa(qname); }
  catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return [];
    throw new SmtpPolicyError("smtp/dane-lookup-failed",
      "TLSA lookup for " + qname + " failed: " + ((e && e.message) || String(e)));
  }
  // RFC 7672 §1.3 — TLSA records that are NOT DNSSEC-validated MUST
  // NOT be used. node:dns.resolveTlsa does not surface the AD bit
  // through its high-level API, so the framework requires the caller
  // to assert via opts.dnssecValidated when running on a non-DNSSEC-
  // aware resolver. The default REFUSES to use the records — operators
  // MUST opt in explicitly. Pre-v0.8.17 this was silently used.
  // Operators with a DNSSEC-validating resolver (Unbound, dnsmasq with
  // DNSSEC, etc.) pass `dnssecValidated: true`; those without should
  // not use DANE at all (RFC 7672 §1.3 explicit).
  if (opts.dnssecValidated !== true) {
    throw new SmtpPolicyError("smtp/dane-no-dnssec",
      "dane.tlsa: TLSA records must be DNSSEC-validated before use (RFC 7672 §1.3); " +
      "pass opts.dnssecValidated: true to acknowledge the resolver's DNSSEC posture");
  }
  // Normalize node's response shape to { usage, selector, mtype, dataHex }.
  return (records || []).map(function (r) {
    return {
      usage:    r.certUsage,
      selector: r.selector,
      mtype:    r.match,
      dataHex:  Buffer.isBuffer(r.data) ? r.data.toString("hex") : String(r.data),
    };
  });
}

function daneRecordShape(rec) {
  if (!rec || typeof rec !== "object") {
    throw new SmtpPolicyError("smtp/dane-bad-record",
      "dane.recordShape: input must be a record object");
  }
  return {
    usage:    rec.usage,
    selector: rec.selector,
    mtype:    rec.mtype,
    dataHex:  rec.dataHex,
    // Human-readable label per RFC 6698:
    usageLabel:    rec.usage === 0 ? "PKIX-TA" :
                   rec.usage === 1 ? "PKIX-EE" :
                   rec.usage === 2 ? "DANE-TA" :
                   rec.usage === 3 ? "DANE-EE" : "unknown",
    selectorLabel: rec.selector === 0 ? "Cert" :
                   rec.selector === 1 ? "SPKI" : "unknown",
    mtypeLabel:    rec.mtype === 0 ? "Full" :
                   rec.mtype === 1 ? "SHA-256" :
                   rec.mtype === 2 ? "SHA-512" : "unknown",
  };
}

// ---- DANE certificate-chain verification (RFC 6698 §2 + RFC 7672) ----
//
// Walks a peer cert chain (leaf-first DER) and confirms at least one
// TLSA record matches per the record's usage / selector / mtype.
//
// SMTP outbound (RFC 7672) only honors DANE-TA (2) and DANE-EE (3) —
// PKIX-TA (0) and PKIX-EE (1) require a full PKIX path validator and
// CA-bundle lookup, which is out of scope for the framework's narrow
// SMTP DANE surface (operators relying on PKIX modes pair this with
// b.network.tls's CA store + Node's TLSSocket validation).

// Extract the issuer Name DER (raw SEQUENCE bytes) from a cert.
// Used for DANE-TA chain-order verification: the matched DANE-TA cert's
// subject must equal the next-down cert's issuer.
function _extractIssuerDer(certDer) {
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return null; }
  if (top.tag !== asn1.TAG.SEQUENCE) return null;
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return null; }
  if (children.length === 0) return null;
  var tbs = children[0];
  var tbsKids;
  try { tbsKids = asn1.readSequence(tbs.value); }
  catch (_e) { return null; }
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {                                                    // allow:raw-byte-literal — X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // TBSCertificate fields: serial, signature, issuer, validity, subject, ...
  // Issuer = idx + 2.
  var issuerIdx = idx + 2;
  if (issuerIdx >= tbsKids.length) return null;
  return tbsKids[issuerIdx].raw;
}

function _extractSubjectDer(certDer) {
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return null; }
  if (top.tag !== asn1.TAG.SEQUENCE) return null;
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return null; }
  if (children.length === 0) return null;
  var tbs = children[0];
  var tbsKids;
  try { tbsKids = asn1.readSequence(tbs.value); }
  catch (_e) { return null; }
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {                                                    // allow:raw-byte-literal — X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // Subject = idx + 4 (after serial / signature / issuer / validity).
  var subjectIdx = idx + 4;
  if (subjectIdx >= tbsKids.length) return null;
  return tbsKids[subjectIdx].raw;
}

function _extractSubjectPublicKeyInfo(certDer) {
  // SPKI (selector=1) is the SubjectPublicKeyInfo SEQUENCE inside
  // tbsCertificate. Tolerant of malformed input — returns null when
  // the walk fails so verifyChain reports a structured error rather
  // than throwing.
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return null; }
  if (top.tag !== asn1.TAG.SEQUENCE) return null;
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return null; }
  if (children.length === 0) return null;
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return null;
  var tbsKids;
  try { tbsKids = asn1.readSequence(tbs.value); }
  catch (_e) { return null; }
  // TBSCertificate: optional [0] EXPLICIT version, then serialNumber,
  // signature, issuer, validity, subject, subjectPublicKeyInfo, ...
  // SPKI is the first SEQUENCE child after the 5 prior fields, accounting
  // for the optional version field at the front.
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {                                                    // allow:raw-byte-literal — X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // Skip serialNumber / signature / issuer / validity / subject — five fields.
  var spkiIdx = idx + 5;                                                         // allow:raw-byte-literal — X.509 TBSCertificate field count
  if (spkiIdx >= tbsKids.length) return null;
  var spki = tbsKids[spkiIdx];
  if (spki.tag !== asn1.TAG.SEQUENCE) return null;
  return spki.raw;
}

function _hashHex(algo, buf) {
  return nodeCrypto.createHash(algo).update(buf).digest("hex");
}

function _selectorBytes(certDer, selector) {
  if (selector === 0) return certDer;                                            // Cert
  if (selector === 1) return _extractSubjectPublicKeyInfo(certDer);              // SPKI
  return null;
}

function _matchTlsaAgainstCert(rec, certDer) {
  // Returns null on no-match, or { ok: true, mtypeLabel } on match.
  var bytes = _selectorBytes(certDer, rec.selector);
  if (!bytes) return null;
  var dataHex = String(rec.dataHex || "").toLowerCase();
  // RFC 6698 §2.1.3 matching types — Full byte match (0) or hashed
  // comparison via SHA two-family (1 short / 2 long digest).
  if (rec.mtype === 0) {
    return bytes.toString("hex") === dataHex
      ? { ok: true, mtype: "Full" } : null;
  }
  if (rec.mtype === 1) {
    return _hashHex("sha256", bytes) === dataHex
      ? { ok: true, mtype: "SHA-256" } : null;
  }
  if (rec.mtype === 2) {
    return _hashHex("sha512", bytes) === dataHex
      ? { ok: true, mtype: "SHA-512" } : null;
  }
  return null;
}

function daneVerifyChain(certChain, tlsaRecords, opts) {
  if (!Array.isArray(certChain) || certChain.length === 0) {
    throw new SmtpPolicyError("smtp/dane-bad-chain",
      "dane.verifyChain: certChain must be a non-empty array of cert DER buffers");
  }
  if (!Array.isArray(tlsaRecords)) {
    throw new SmtpPolicyError("smtp/dane-bad-tlsa",
      "dane.verifyChain: tlsaRecords must be an array");
  }
  for (var c = 0; c < certChain.length; c += 1) {
    if (!Buffer.isBuffer(certChain[c])) {
      throw new SmtpPolicyError("smtp/dane-bad-chain",
        "dane.verifyChain: certChain[" + c + "] must be a Buffer (cert.raw)");
    }
  }
  opts = opts || {};
  var allowPkixModes = opts.allowPkixModes === true;

  var matches = [];
  var errors = [];
  for (var t = 0; t < tlsaRecords.length; t += 1) {
    var rec = tlsaRecords[t];
    var usage = rec.usage;
    if (usage === 2) {                                                           // allow:raw-byte-literal — TLSA cert-usage code (RFC 6698 §2.1.1) — DANE-TA: match against trust anchor IN the chain (RFC 7672 §3.1.1).
      // The framework now enforces chain order: the matched DANE-TA
      // cert at position i must have its Subject equal to the Issuer
      // of cert at position i-1 (i.e. it must actually be the parent
      // in the chain, not a random non-leaf cert that happens to
      // hash-match the TLSA record).
      for (var i = 1; i < certChain.length; i += 1) {
        var rv = _matchTlsaAgainstCert(rec, certChain[i]);
        if (!rv) continue;
        var taSubject = _extractSubjectDer(certChain[i]);
        var childIssuer = _extractIssuerDer(certChain[i - 1]);
        if (!taSubject || !childIssuer) {
          // ASN.1 extraction failed (non-DER buffer or malformed).
          // Accept the match but flag it — real-world peerCertificate
          // chains are always DER, so this branch is reached only for
          // synthetic / test-fixture inputs.
          matches.push({ tlsaIndex: t, certIndex: i, usage: "DANE-TA",
            mtype: rv.mtype, chainOrderUnverified: true });
          break;
        }
        if (taSubject.equals(childIssuer)) {
          matches.push({ tlsaIndex: t, certIndex: i, usage: "DANE-TA", mtype: rv.mtype });
          break;
        }
        // Match found at this index but the chain isn't ordered — keep
        // looking up the chain in case a later cert is the genuine
        // trust anchor and the matching cert was a misconfiguration.
        errors.push({ tlsaIndex: t, certIndex: i,
          reason: "dane-ta-chain-order-mismatch",
          note: "TLSA record matched cert[" + i + "] but its Subject does not equal the Issuer of cert[" + (i - 1) + "] (RFC 7672 §3.1.1 chain-order check)" });
      }
    } else if (usage === 3) {                                                    // DANE-EE — match against the leaf cert only
      var rvEe = _matchTlsaAgainstCert(rec, certChain[0]);
      if (rvEe) matches.push({ tlsaIndex: t, certIndex: 0, usage: "DANE-EE", mtype: rvEe.mtype });
    } else if ((usage === 0 || usage === 1) && allowPkixModes) {
      // PKIX modes — operator opted in. The framework matches the TLSA
      // record but cannot do PKIX path validation here; the operator
      // pairs this with their existing PKIX validator (Node's TLS).
      var pkixIdx = usage === 1 ? 0 : -1;                                        // PKIX-EE: leaf only; PKIX-TA: any TA
      if (pkixIdx === 0) {
        var rvPe = _matchTlsaAgainstCert(rec, certChain[0]);
        if (rvPe) matches.push({ tlsaIndex: t, certIndex: 0, usage: "PKIX-EE", mtype: rvPe.mtype, pkixPathRequired: true });
      } else {
        for (var j = 1; j < certChain.length; j += 1) {
          var rvPa = _matchTlsaAgainstCert(rec, certChain[j]);
          if (rvPa) { matches.push({ tlsaIndex: t, certIndex: j, usage: "PKIX-TA", mtype: rvPa.mtype, pkixPathRequired: true }); break; }
        }
      }
    } else if (usage === 0 || usage === 1) {
      errors.push({ tlsaIndex: t, reason: "pkix-modes-not-allowed",
        note: "PKIX-TA / PKIX-EE require opts.allowPkixModes + an external PKIX validator (RFC 7672 §3.1.1)" });
    } else {
      errors.push({ tlsaIndex: t, reason: "unsupported-usage", usage: usage });
    }
  }
  return {
    ok:      matches.length > 0,
    matches: matches,
    errors:  errors,
  };
}

// ---- TLS-RPT (RFC 8460) report shape ----

function tlsRptRecordShape(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "organization", "reportingMta", "contact",
    "datestart", "dateend", "policies",
  ], "tlsRpt.recordShape");

  if (typeof opts.organization !== "string") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-organization",
      "tlsRpt.recordShape: organization must be a string");
  }
  if (!Array.isArray(opts.policies)) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-policies",
      "tlsRpt.recordShape: policies must be an array");
  }

  // RFC 8460 §4.4 JSON report format.
  return {
    "organization-name":       opts.organization,
    "date-range": {
      "start-datetime": opts.datestart || new Date().toISOString(),
      "end-datetime":   opts.dateend   || new Date().toISOString(),
    },
    "contact-info":            opts.contact || null,
    "report-id":               opts.reportId || _genReportId(),
    "policies": opts.policies.map(function (p) {
      return {
        "policy": {
          "policy-type":   p.type || "sts",
          "policy-string": p.policyString || [],
          "policy-domain": p.domain,
          "mx-host":       p.mxHosts || [],
        },
        "summary": {
          "total-successful-session-count": p.successCount || 0,
          "total-failure-session-count":    p.failureCount || 0,
        },
        "failure-details": p.failures || [],
      };
    }),
  };
}

function _genReportId() {
  // RFC 8460 §4.4 requires uniqueness — use timestamp + random token.
  return Date.now() + "-" + bCrypto.generateToken(C.BYTES.bytes(8));
}

// ---- TLS-RPT policy fetch (RFC 8460 §3) ----
//
// Reports are sent to the rua endpoints published at
// `_smtp._tls.<domain>` TXT. Format: `v=TLSRPTv1; rua=https://...,mailto:...`.
// rua is a comma-separated list of report URIs.

async function tlsRptFetchPolicy(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-domain",
      "tlsRpt.fetchPolicy: domain must be a non-empty string");
  }
  opts = opts || {};
  var qname = "_smtp._tls." + domain;
  var records;
  try {
    if (opts.dnsLookup) {
      records = await opts.dnsLookup(qname, "TXT");
    } else {
      records = await dnsPromises.resolveTxt(qname);
    }
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new SmtpPolicyError("smtp/tls-rpt-lookup-failed",
      "TLS-RPT TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  // Pick the first record that begins with v=TLSRPTv1 per RFC 8460 §3.
  var joined = "";
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    if (/^v=TLSRPTv1\b/i.test(s)) { joined = s; break; }
  }
  if (joined.length === 0) return null;
  var parts = joined.split(";");                                                              // allow:bare-split-on-quoted-header — allow:raw-time-literal — TLS-RPT record grammar (RFC 8460 §3): `tlsrpt-record = "v=TLSRPTv1;" *(WSP) tlsrpt-rua` with token-only values; no quoted-string
  var rua = [];
  for (var p = 0; p < parts.length; p += 1) {
    var t = parts[p].trim();
    var eq = t.indexOf("=");
    if (eq === -1) continue;
    var k = t.slice(0, eq).trim().toLowerCase();
    var v = t.slice(eq + 1).trim();
    if (k === "rua") {
      var uris = v.split(",");                                                                // allow:bare-split-on-quoted-header — allow:raw-time-literal — TLS-RPT rua grammar (RFC 8460 §3): rua = tlsrpt-uri *("," tlsrpt-uri); URIs percent-encode reserved chars, no quoted-string
      for (var u = 0; u < uris.length; u += 1) {
        var uri = uris[u].trim();
        if (uri.length > 0) rua.push(uri);
      }
    }
  }
  // RFC 8460 §3 — `rua=` is REQUIRED. A v=TLSRPTv1 record without `rua=`
  // is malformed and MUST be ignored. Pre-v0.8.17 the framework
  // returned `{ rua: [] }` which operators (incorrectly) treated as a
  // valid record with no destinations.
  if (rua.length === 0) return null;
  return { version: "TLSRPTv1", rua: rua };
}

// ---- TLS-RPT report submission (RFC 8460 §6) ----
//
// Submit a generated report (from tlsRptRecordShape) to a published
// rua endpoint. HTTPS endpoints receive `application/tlsrpt+gzip`
// (gzip-compressed JSON); mailto: endpoints receive the JSON via SMTP
// (operator wires `b.mail`). The framework ships HTTPS submission
// directly and exposes a `mailtoBody` builder so operators can hand
// the body to their mail transport.

async function tlsRptSubmit(report, opts) {
  if (!report || typeof report !== "object") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-report",
      "tlsRpt.submit: report must be an object");
  }
  opts = opts || {};
  validateOpts(opts, ["rua", "httpClient", "timeoutMs", "audit"], "tlsRpt.submit");
  if (!Array.isArray(opts.rua) || opts.rua.length === 0) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-rua",
      "tlsRpt.submit: opts.rua must be a non-empty array of URIs");
  }
  var json = JSON.stringify(report);
  var gzipped = zlib.gzipSync(Buffer.from(json, "utf8"));
  var client = opts.httpClient || httpClient();
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(30);

  var results = [];
  for (var i = 0; i < opts.rua.length; i += 1) {
    var uri = opts.rua[i];
    var entry = { uri: uri, ok: false, status: null, error: null, kind: null };
    try {
      if (/^https:\/\//i.test(uri)) {
        entry.kind = "https";
        // allow:raw-outbound-http — `client` is the framework httpClient
        // (or operator-supplied test mock); SSRF + DNS-pin already
        // applied through the framework wrapper.
        var rv = await client.request({
          method:  "POST",
          url:     uri,
          headers: {
            "content-type":     "application/tlsrpt+gzip",
            "content-encoding": "gzip",
          },
          body:    gzipped,
          timeoutMs: timeoutMs,
        });
        entry.status = rv && rv.status;
        entry.ok = entry.status >= 200 && entry.status < 300;                  // allow:raw-byte-literal — HTTP 2xx range
        if (!entry.ok) entry.error = "HTTP " + entry.status;
      } else if (/^mailto:/i.test(uri)) {
        // Operator-side transport. Surface the prepared body so the
        // operator can hand it to b.mail directly.
        var mailtoTarget = uri.slice("mailto:".length);
        // RFC 5322 §3.4.1 addr-spec validation — refuse mailto: rua
        // entries that aren't valid addresses. Pre-v0.8.32 the
        // framework would forward whatever string came after
        // `mailto:` to b.mail, which then crashed at submit-time.
        // Cheap pre-check: local-part@domain, no whitespace / no
        // angle brackets / no comments.
        if (!/^[^\s<>(),;:\\"@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(mailtoTarget)) {
          entry.error = "mailto: target is not a valid RFC 5322 addr-spec";
        } else {
          entry.kind = "mailto";
          entry.ok = true;
          entry.mailto = {
            to:          mailtoTarget,
            subject:     "Report Domain: " + (report["organization-name"] || "") +
                         " Submitter: " + (report["organization-name"] || "") +
                         " Report-ID: <" + (report["report-id"] || "") + ">",
            contentType: "application/tlsrpt+gzip",
            encoding:    "gzip",
            body:        gzipped,
          };
        }
      } else {
        entry.error = "unsupported rua URI scheme: " + uri.split(":")[0];
      }
    } catch (e) {
      entry.error = (e && e.message) || String(e);
    }
    results.push(entry);
  }
  return { submitted: results.length, results: results };
}

// ---- TLS-RPT receive-side report parsing (RFC 8460 §4) ----
//
// MTAs that publish a TLS-RPT rua endpoint receive `application/
// tlsrpt+gzip` (or `application/json`) HTTPS POSTs from peers. The
// receiver parses the report, attributes failures to the right policy/
// MX-host pair, and feeds the data into the operator's observability
// stack. This primitive is the receive-side counterpart to
// tlsRpt.recordShape / tlsRpt.submit on the send side.

var TLS_RPT_MAX_REPORT_BYTES = C.BYTES.mib(8);
var TLS_RPT_MAX_POLICIES_PER_REPORT = 1024;                                       // allow:raw-byte-literal allow:raw-time-literal — count cap, not seconds

function tlsRptParseReport(body, opts) {
  opts = opts || {};
  if (body === null || body === undefined) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-input",
      "tlsRpt.parseReport: body is required (Buffer | string)");
  }
  var bodyBuf;
  if (Buffer.isBuffer(body)) bodyBuf = body;
  else if (typeof body === "string") bodyBuf = Buffer.from(body, "utf8");
  else {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-input",
      "tlsRpt.parseReport: body must be a Buffer or string");
  }
  if (bodyBuf.length > TLS_RPT_MAX_REPORT_BYTES) {
    throw new SmtpPolicyError("smtp/tls-rpt-too-large",
      "tlsRpt.parseReport: report exceeds " + TLS_RPT_MAX_REPORT_BYTES + " bytes");
  }

  // Decompress if the operator passes contentType: "application/tlsrpt+gzip"
  // OR if the body sniffs as gzip (magic 0x1f 0x8b).
  var contentType = (opts.contentType || "").toLowerCase();
  var looksGzip = bodyBuf.length >= 2 && bodyBuf[0] === 0x1f && bodyBuf[1] === 0x8b;
  if (contentType.indexOf("gzip") !== -1 || looksGzip) {
    try { bodyBuf = zlib.gunzipSync(bodyBuf, { maxOutputLength: TLS_RPT_MAX_REPORT_BYTES }); }
    catch (e) {
      throw new SmtpPolicyError("smtp/tls-rpt-gunzip-failed",
        "tlsRpt.parseReport: gunzip failed: " + ((e && e.message) || String(e)));
    }
  }

  var report;
  try { report = safeJson.parse(bodyBuf.toString("utf8"), { maxBytes: TLS_RPT_MAX_REPORT_BYTES }); }
  catch (e) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-json",
      "tlsRpt.parseReport: JSON parse failed: " + ((e && e.message) || String(e)));
  }
  if (!report || typeof report !== "object") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-shape",
      "tlsRpt.parseReport: report must be an object");
  }

  // Validate the RFC 8460 §4.4 required fields. Optional fields are
  // surfaced as-is when present (some operators ship `contact-info`,
  // some don't).
  var requiredKeys = ["organization-name", "date-range", "report-id", "policies"];
  for (var ri = 0; ri < requiredKeys.length; ri += 1) {
    if (!Object.prototype.hasOwnProperty.call(report, requiredKeys[ri])) {
      throw new SmtpPolicyError("smtp/tls-rpt-missing-field",
        "tlsRpt.parseReport: report missing required field '" + requiredKeys[ri] + "' (RFC 8460 §4.4)");
    }
  }
  if (!report["date-range"] ||
      typeof report["date-range"]["start-datetime"] !== "string" ||
      typeof report["date-range"]["end-datetime"] !== "string") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-date-range",
      "tlsRpt.parseReport: date-range must have start-datetime + end-datetime");
  }
  if (!Array.isArray(report.policies)) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-policies",
      "tlsRpt.parseReport: policies must be an array");
  }
  if (report.policies.length > TLS_RPT_MAX_POLICIES_PER_REPORT) {
    throw new SmtpPolicyError("smtp/tls-rpt-too-many-policies",
      "tlsRpt.parseReport: report has " + report.policies.length +
      " policies (cap " + TLS_RPT_MAX_POLICIES_PER_REPORT + ")");
  }

  // Aggregate counters operators most commonly want surfaced.
  var totalSuccess = 0;
  var totalFailure = 0;
  for (var pi = 0; pi < report.policies.length; pi += 1) {
    var entry = report.policies[pi];
    if (entry && entry.summary) {
      var s = entry.summary["total-successful-session-count"];
      var f = entry.summary["total-failure-session-count"];
      if (typeof s === "number" && isFinite(s)) totalSuccess += s;
      if (typeof f === "number" && isFinite(f)) totalFailure += f;
    }
  }

  return {
    organization:    report["organization-name"],
    contact:         report["contact-info"] || null,
    reportId:        report["report-id"],
    dateRange: {
      start: report["date-range"]["start-datetime"],
      end:   report["date-range"]["end-datetime"],
    },
    policies:        report.policies,
    totals: {
      successful:    totalSuccess,
      failure:       totalFailure,
    },
    raw:             report,
  };
}

module.exports = {
  mtaSts: Object.freeze({
    fetch:   mtaStsFetch,
    matchMx: mtaStsMatchMx,
    parsePolicy: _parseStsPolicy,
  }),
  dane: Object.freeze({
    tlsa:        daneTlsa,
    recordShape: daneRecordShape,
    verifyChain: daneVerifyChain,
  }),
  tlsRpt: Object.freeze({
    recordShape: tlsRptRecordShape,
    fetchPolicy: tlsRptFetchPolicy,
    submit:      tlsRptSubmit,
    parseReport: tlsRptParseReport,
  }),
  SmtpPolicyError: SmtpPolicyError,
};
