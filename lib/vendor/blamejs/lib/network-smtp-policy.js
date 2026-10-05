// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var dns = require("node:dns");
var dnsPromises = dns.promises;
var nodeCrypto = require("node:crypto");
var zlib = require("node:zlib");
var asn1 = require("./asn1-der");
var x509Chain = require("./x509-chain");
var lazyRequire = require("./lazy-require");
var networkDnsResolver = lazyRequire(function () { return require("./network-dns-resolver"); });
var validateOpts = require("./validate-opts");
var structuredFields = require("./structured-fields");
var bCrypto = require("./crypto");
var safeUrl = require("./safe-url");
var safeJson = require("./safe-json");
var C = require("./constants");
var { SmtpPolicyError } = require("./framework-error");

var httpClient = lazyRequire(function () { return require("./http-client"); });
var cache = lazyRequire(function () { return require("./cache"); });

var DEFAULT_POLICY_CACHE_MS = C.TIME.minutes(60);
var MAX_POLICY_BYTES = C.BYTES.kib(64);
var STS_VERSION_GRAMMAR = Object.freeze({ requireNextField: true, nameIgnoresCase: true });
var TLSRPT_VERSION_GRAMMAR = Object.freeze({ requireNextField: true });
var STS_ID_RE = /^[A-Za-z0-9]{1,32}$/;

var _stsCache = null;
function _getStsCache() {
  if (_stsCache) return _stsCache;
  _stsCache = cache().create({
    namespace: "smtp-policy.mta-sts",
    ttlMs:     DEFAULT_POLICY_CACHE_MS,
  });
  return _stsCache;
}

function _parseStsPolicy(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw new SmtpPolicyError("smtp/mta-sts-empty",
      "MTA-STS policy text is empty");
  }
  var policy = { version: null, mode: null, mx: [], max_age: null };
  var pairs = structuredFields.parseTagList(text, { sep: /\r?\n/, kvSep: ":" });
  for (var i = 0; i < pairs.length; i += 1) {
    var key = pairs[i][0];
    var val = pairs[i][1];
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

async function _fetchStsTxt(domain, dnsLookup, resolver) {
  var records = await networkDnsResolver().safeResolveTxt("_mta-sts." + domain, {
    dnsLookup:    dnsLookup,
    resolver:     resolver,
    errorFactory: function (code, msg) { return new SmtpPolicyError(code, msg); },
    code:         "smtp/mta-sts-txt-lookup-failed",
  });
  if (!Array.isArray(records)) return null;
  var matches = [];
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (structuredFields.recordVersionMatches(rec, "v", "STSv1", STS_VERSION_GRAMMAR)) matches.push(rec);
  }
  if (matches.length !== 1) return null;
  var pairs = structuredFields.parseTagList(matches[0], { lowerKey: false });
  for (var p = 0; p < pairs.length; p += 1) {
    if (pairs[p][0] !== "id") continue;
    var id = pairs[p][1];
    if (typeof id !== "string" || id.length > 32 || !STS_ID_RE.test(id)) return null;
    return { record: matches[0], id: id };
  }
  return null;
}

function _policyTtlMs(maxAgeSec) {
  if (typeof maxAgeSec !== "number" || !isFinite(maxAgeSec) || maxAgeSec <= 0) {
    return DEFAULT_POLICY_CACHE_MS;
  }
  var hourSec = C.TIME.hours(1) / C.TIME.seconds(1);
  var ceilingSec = C.TIME.weeks(52) / C.TIME.seconds(1);
  return Math.max(hourSec, Math.min(ceilingSec, maxAgeSec)) * C.TIME.seconds(1);
}

function _policyUnexpired(policy) {
  if (!policy || typeof policy.fetchedAt !== "number" || !isFinite(policy.fetchedAt)) return false;
  var maxAgeSec = policy.max_age;
  var lifetimeMs = (typeof maxAgeSec === "number" && isFinite(maxAgeSec) && maxAgeSec >= 0)
    ? Math.min(maxAgeSec * C.TIME.seconds(1), C.TIME.weeks(52))
    : DEFAULT_POLICY_CACHE_MS;
  return Date.now() < policy.fetchedAt + lifetimeMs;
}

async function _fetchStsPolicy(lcDomain, id, client) {
  var url = "https://mta-sts." + lcDomain + "/.well-known/mta-sts.txt";
  safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  var res;
  try {
    res = await (client || httpClient()).request({                                                   // allow:raw-outbound-http-framework-internal — the framework httpClient or an operator-supplied client, with SSRF and DNS-pin checks applied by the framework wrapper
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
  if (res.statusCode === C.HTTP.STATUS.NOT_FOUND) return null;
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new SmtpPolicyError("smtp/mta-sts-fetch-failed",
      "MTA-STS fetch returned " + res.statusCode + " for " + url);
  }
  var parsed = _parseStsPolicy(res.body.toString("utf8"));
  parsed.id = id;
  parsed.fetchedAt = Date.now();
  return parsed;
}

async function mtaStsFetch(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "mtaSts.fetch: domain must be a non-empty string");
  }
  opts = opts || {};
  validateOpts(opts, ["dnsLookup", "resolver", "httpClient"], "mtaSts.fetch");
  var lcDomain = domain.toLowerCase();
  var store = _getStsCache();
  var policyKey = "policy|" + lcDomain;
  var cached = await store.get(policyKey);
  if (cached === undefined || !_policyUnexpired(cached)) cached = null;

  var txt;
  try { txt = await _fetchStsTxt(lcDomain, opts.dnsLookup, opts.resolver); }
  catch (e) {
    if (cached) return cached;
    throw e;
  }
  if (!txt) return cached;
  if (cached && cached.id === txt.id) return cached;

  var missKey = "miss|" + lcDomain + "|" + txt.id;
  if (await store.get(missKey) !== undefined) return cached;
  var fresh;
  try {
    fresh = await store.wrap("fetch|" + lcDomain + "|" + txt.id, function () {
      return _fetchStsPolicy(lcDomain, txt.id, opts.httpClient);
    }, { ttlMs: 0 });
  } catch (e2) {
    if (cached) return cached;
    throw e2;
  }
  if (fresh === null) {
    await store.set(missKey, true, { ttlMs: DEFAULT_POLICY_CACHE_MS });
    return cached;
  }
  await store.set(policyKey, fresh, { ttlMs: _policyTtlMs(fresh.max_age) });
  return fresh;
}

function mtaStsMatchMx(mxHost, mxList) {
  if (typeof mxHost !== "string" || !Array.isArray(mxList)) return false;
  var lc = mxHost.toLowerCase();
  for (var i = 0; i < mxList.length; i += 1) {
    var entry = String(mxList[i]).toLowerCase();
    if (entry === lc) return true;
    if (entry.length > 2 && entry.slice(0, 2) === "*.") {
      var suffix = entry.slice(1);
      var dotAt = lc.indexOf(".");
      if (dotAt === -1) continue;
      if (lc.slice(dotAt) === suffix) return true;
    }
  }
  return false;
}

async function daneTlsa(domain, port, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/bad-domain",
      "dane.tlsa: domain must be a non-empty string");
  }
  opts = opts || {};
  var p = typeof port === "number" ? port : 25;
  var qname = "_" + p + "._tcp." + domain.toLowerCase();

  var records;
  if (opts.resolver) {
    if (typeof opts.resolver.queryTlsa !== "function") {
      throw new SmtpPolicyError("smtp/dane-resolver-no-tlsa",
        "dane.tlsa: opts.resolver was supplied but has no queryTlsa(name); the " +
        "records must come from the resolver whose DNSSEC posture was asserted, " +
        "so falling back to the system resolver is refused");
    }
    var rv;
    try { rv = await opts.resolver.queryTlsa(qname); }
    catch (e0) {
      if (e0 && e0.code === "resolver/nxdomain") return [];
      throw new SmtpPolicyError("smtp/dane-lookup-failed",
        "TLSA lookup for " + qname + " failed: " + ((e0 && e0.message) || String(e0)));
    }
    records = ((rv && rv.rrs) || []).filter(function (r) {
      return r && r.decoded && typeof r.decoded.usage === "number";
    }).map(function (r) {
      return { certUsage: r.decoded.usage, selector: r.decoded.selector,
               match: r.decoded.matchingType, data: r.decoded.certData };
    });
  } else {
    if (typeof dnsPromises.resolveTlsa !== "function") {
      throw new SmtpPolicyError("smtp/dane-unavailable",
        "node:dns.resolveTlsa is not available on this runtime");
    }
    try { records = await dnsPromises.resolveTlsa(qname); }
    catch (e) {
      if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return [];
      throw new SmtpPolicyError("smtp/dane-lookup-failed",
        "TLSA lookup for " + qname + " failed: " + ((e && e.message) || String(e)));
    }
  }
  if (opts.dnssecValidated !== true) {
    throw new SmtpPolicyError("smtp/dane-no-dnssec",
      "dane.tlsa: TLSA records must be DNSSEC-validated before use (RFC 7672 §1.3); " +
      "pass opts.dnssecValidated: true to acknowledge the resolver's DNSSEC posture");
  }
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

function _extractSubjectPublicKeyInfo(certDer) {
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
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {
    idx = 1;
  }
  var spkiIdx = idx + 5;
  if (spkiIdx >= tbsKids.length) return null;
  var spki = tbsKids[spkiIdx];
  if (spki.tag !== asn1.TAG.SEQUENCE) return null;
  return spki.raw;
}

function _selectorBytes(certDer, selector) {
  if (selector === 0) return certDer;
  if (selector === 1) return _extractSubjectPublicKeyInfo(certDer);
  return null;
}

function _constEqBytes(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && bCrypto.timingSafeEqual(a, b);
}

function _matchTlsaAgainstCert(rec, certDer) {
  var bytes = _selectorBytes(certDer, rec.selector);
  if (!bytes) return null;
  var dataHex = (typeof rec.dataHex === "string" ? rec.dataHex : "").toLowerCase();
  var want = Buffer.from(dataHex, "hex");
  if (rec.mtype === 0) {
    return _constEqBytes(bytes, want) ? { ok: true, mtype: "Full" } : null;
  }
  if (rec.mtype === 1) {
    return _constEqBytes(nodeCrypto.createHash("sha256").update(bytes).digest(), want)
      ? { ok: true, mtype: "SHA-256" } : null;
  }
  if (rec.mtype === 2) {
    return _constEqBytes(nodeCrypto.createHash("sha512").update(bytes).digest(), want)
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

  var parsedCerts = certChain.map(function (der) {
    try { return new nodeCrypto.X509Certificate(der); }
    catch (_e) { return null; }
  });

  var matches = [];
  var errors = [];
  for (var t = 0; t < tlsaRecords.length; t += 1) {
    var rec = tlsaRecords[t];
    var usage = rec.usage;
    if (usage === 2) {
      var leafCert = parsedCerts[0];
      if (!leafCert) {
        errors.push({ tlsaIndex: t, reason: "dane-ta-unparseable-leaf",
          note: "DANE-TA (RFC 7672 §3.1.1) requires a validated path from the leaf, but cert[0] is not parseable X.509" });
      } else {
        for (var i = 1; i < certChain.length; i += 1) {
          var rv = _matchTlsaAgainstCert(rec, certChain[i]);
          if (!rv) continue;
          var taCert = parsedCerts[i];
          if (!taCert) {
            errors.push({ tlsaIndex: t, certIndex: i, reason: "dane-ta-unparseable-anchor",
              note: "TLSA matched cert[" + i + "] as a DANE-TA anchor but it is not parseable X.509 — cannot validate the path (RFC 7672 §3.1.1)" });
            continue;
          }
          var pool = [];
          for (var m = 1; m < parsedCerts.length; m += 1) {
            if (m !== i && parsedCerts[m]) pool.push(parsedCerts[m]);
          }
          var res = x509Chain.resolveChain(leafCert, pool, [taCert]);
          if (res.ok) {
            matches.push({ tlsaIndex: t, certIndex: i, usage: "DANE-TA", mtype: rv.mtype });
            break;
          }
          errors.push({ tlsaIndex: t, certIndex: i, reason: "dane-ta-path-not-validated",
            note: "TLSA matched cert[" + i + "] but no cryptographically validated path runs from the leaf to it (RFC 7672 §3.1.1; resolveChain reason=" + res.reason + ")" });
        }
      }
    } else if (usage === 3) {
      var rvEe = _matchTlsaAgainstCert(rec, certChain[0]);
      if (rvEe) matches.push({ tlsaIndex: t, certIndex: 0, usage: "DANE-EE", mtype: rvEe.mtype });
    } else if ((usage === 0 || usage === 1) && allowPkixModes) {
      var pkixIdx = usage === 1 ? 0 : -1;
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

function tlsRptRecordShape(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "organization", "contact",
    "datestart", "dateend", "policies", "reportId",
  ], "tlsRpt.recordShape");

  if (typeof opts.organization !== "string") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-organization",
      "tlsRpt.recordShape: organization must be a string");
  }
  if (!Array.isArray(opts.policies)) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-policies",
      "tlsRpt.recordShape: policies must be an array");
  }

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
  return Date.now() + "-" + bCrypto.generateToken(C.BYTES.bytes(8));
}

async function tlsRptFetchPolicy(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-domain",
      "tlsRpt.fetchPolicy: domain must be a non-empty string");
  }
  opts = opts || {};
  var qname = "_smtp._tls." + domain;
  var records = await networkDnsResolver().safeResolveTxt(qname, {
    dnsLookup:    opts.dnsLookup,
    resolver:     opts.resolver,
    errorFactory: function (code, msg) { return new SmtpPolicyError(code, msg); },
    code:         "smtp/tls-rpt-lookup-failed",
  });
  if (records === null) return null;
  var matches = [];
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    if (structuredFields.recordVersionMatches(s, "v", "TLSRPTv1", TLSRPT_VERSION_GRAMMAR)) matches.push(s);
  }
  if (matches.length !== 1) return null;
  var pairs = structuredFields.parseTagList(matches[0]);
  var rua = [];
  for (var p = 0; p < pairs.length; p += 1) {
    if (pairs[p][0] === "rua") {
      var uris = pairs[p][1].split(",");                                                      // allow:bare-split-on-quoted-header-token-grammar — allow:raw-time-literal — TLS-RPT rua grammar (RFC 8460 §3): rua = tlsrpt-uri *("," tlsrpt-uri); URIs percent-encode reserved chars, no quoted-string
      for (var u = 0; u < uris.length; u += 1) {
        var uri = uris[u].trim();
        if (uri.length > 0) rua.push(uri);
      }
    }
  }
  if (rua.length === 0) return null;
  return { version: "TLSRPTv1", rua: rua };
}

async function tlsRptSubmit(report, opts) {
  if (!report || typeof report !== "object") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-report",
      "tlsRpt.submit: report must be an object");
  }
  opts = opts || {};
  validateOpts(opts, ["rua", "httpClient", "timeoutMs"], "tlsRpt.submit");
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
        // allow:raw-outbound-http-framework-internal — `client` is the framework httpClient or an operator-supplied test mock, with SSRF and DNS-pin checks already applied through the framework wrapper
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
        entry.status = rv && rv.statusCode;
        entry.ok = entry.status >= 200 && entry.status < 300;
        if (!entry.ok) entry.error = "HTTP " + entry.status;
      } else if (/^mailto:/i.test(uri)) {
        var publishedTarget = uri.slice("mailto:".length);
        var mailtoTarget = publishedTarget.replace(/\.$/, "");
        if (!/^[^\s<>(),;:\\"@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(mailtoTarget)) {
          entry.error = "mailto: target is not a valid RFC 5322 addr-spec";
        } else {
          entry.kind = "mailto";
          entry.ok = true;
          entry.mailto = {
            to:          mailtoTarget,
            published:   publishedTarget,
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

var TLS_RPT_MAX_REPORT_BYTES = C.BYTES.mib(8);
var TLS_RPT_MAX_POLICIES_PER_REPORT = 1024;

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

  var contentType = (opts.contentType || "").toLowerCase();
  var looksGzip = bodyBuf.length >= 2 && bodyBuf[0] === 0x1f && bodyBuf[1] === 0x8b;
  if (contentType.indexOf("gzip") !== -1 || looksGzip) {
    try { bodyBuf = zlib.gunzipSync(bodyBuf, { maxOutputLength: TLS_RPT_MAX_REPORT_BYTES }); }
    catch (e) {
      throw new SmtpPolicyError("smtp/tls-rpt-gunzip-failed",
        "tlsRpt.parseReport: gunzip failed: " + ((e && e.message) || String(e)));
    }
  }

  var report = safeJson.parseTyped(bodyBuf.toString("utf8"), {
    maxBytes:   TLS_RPT_MAX_REPORT_BYTES,
    errorClass: SmtpPolicyError,
    code:       "smtp/tls-rpt-bad-json",
    label:      "tlsRpt.parseReport: JSON parse failed",
  });
  if (!report || typeof report !== "object") {
    throw new SmtpPolicyError("smtp/tls-rpt-bad-shape",
      "tlsRpt.parseReport: report must be an object");
  }

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
