// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.smtp.policy — coverage for the input-validation, option-default,
 * error-handling, and pure-logic branches that smtp-policy.test.js leaves
 * uncovered.
 *
 * Everything here is in-memory: DNS is driven through the `dnsLookup` opt,
 * HTTPS submission through an operator-supplied `httpClient` fake, and the
 * receive-side `parseReport` runs on Buffers built in-process. No branch
 * needs a live network or DNS backend (those belong to the integration
 * suite). The uncovered surface is: MTA-STS parse rejects (empty / bad-mode /
 * non-string), matchMx defensive returns, mtaSts.fetch precondition + domain
 * guard, dane.tlsa / recordShape guards + every RFC 6698 label, verifyChain
 * PKIX-opt-in + unsupported-usage + SHA-512 + SPKI-no-bytes paths, tlsRpt
 * recordShape type guards + policy defaults, fetchPolicy rua-required +
 * no-record returns, submit scheme dispatch + failure branches, and the
 * entire tlsRpt.parseReport receive-side parser.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("crypto");
var zlib       = require("zlib");
var nodeDns    = require("node:dns");
var C          = require("../../lib/constants");
var asn1       = require("../../lib/asn1-der");
var httpClientMod = require("../../lib/http-client");

// ---- small local helpers -------------------------------------------------

function throwsWithCode(fn, codeRe) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  return threw !== null && codeRe.test(threw.code || "");
}

async function asyncThrowsWithCode(fn, codeRe) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  return threw !== null && codeRe.test(threw.code || "");
}

// mtaSts.fetch uses the framework httpClient() singleton directly (no
// opts.httpClient seam like tlsRpt.submit has), so the successful-fetch
// path is driven by swapping the singleton's `.request` for a responder
// and restoring it in finally. The layer-0 runner forks one process per
// file, so this patch never leaks across test files. `dnsLookup` still
// drives the _mta-sts TXT precondition lookup as the operator seam.
async function withFakeHttpRequest(responder, fn) {
  var orig = httpClientMod.request;
  httpClientMod.request = responder;
  try { return await fn(); }
  finally { httpClientMod.request = orig; }
}

// dane.tlsa reads node:dns.promises.resolveTlsa (captured once at module
// load as a stable object reference). Swapping the method on that same
// object injects the TLSA answer without a live DNS TYPE-52 query.
async function withFakeResolveTlsa(impl, fn) {
  var orig = nodeDns.promises.resolveTlsa;
  nodeDns.promises.resolveTlsa = impl;
  try { return await fn(); }
  finally { nodeDns.promises.resolveTlsa = orig; }
}

// Minimal-but-parseable X.509 DER for the DANE-TA chain-order checks.
// verifyChain extracts the TA cert's Subject and the child cert's Issuer
// via asn1-der and requires TA.subject === child.issuer (RFC 7672
// §3.1.1). A real peerCertificate chain is always DER; these fixtures let
// the ASN.1 walk succeed so the ordered-match and mismatch branches run.
function _derName(label) {
  return asn1.writeSequence([ asn1.writeNode(asn1.TAG.PRINTABLE_STRING, Buffer.from(label, "ascii")) ]);
}
// Shared SubjectPublicKeyInfo fixture — embedded verbatim in every
// _derCert, so a selector=1 (SPKI) TLSA match can be built against its
// exact bytes (readNode's .raw slices these back out byte-identically).
var _SPKI_DER = asn1.writeSequence([
  asn1.writeSequence([ asn1.writeOid("1.2.840.10045.2.1"), asn1.writeOid("1.2.840.10045.3.1.7") ]),
  asn1.writeNode(asn1.TAG.BIT_STRING, Buffer.from([0x00, 0x04, 0x01, 0x02, 0x03, 0x04])),
]);
function _derCert(issuerName, subjectName) {
  var sigAlg = asn1.writeSequence([ asn1.writeOid("1.2.840.113549.1.1.11"), asn1.writeNull() ]);
  var validity = asn1.writeSequence([
    asn1.writeNode(asn1.TAG.UTC_TIME, Buffer.from("260101000000Z")),
    asn1.writeNode(asn1.TAG.UTC_TIME, Buffer.from("270101000000Z")),
  ]);
  var spki = _SPKI_DER;
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([0x02]))),        // [0] version
    asn1.writeInteger(Buffer.from([0x01])),                                       // serialNumber
    sigAlg,                                                                        // signature
    issuerName,                                                                    // issuer
    validity,                                                                      // validity
    subjectName,                                                                   // subject
    spki,                                                                          // subjectPublicKeyInfo
  ]);
  return asn1.writeSequence([ tbs, sigAlg, asn1.writeNode(asn1.TAG.BIT_STRING, Buffer.from([0x00, 0xaa])) ]);
}

// ---- MTA-STS parse (mtaSts.parsePolicy) ----------------------------------

function testParseStsEmptyAndNonString() {
  check("parsePolicy: empty text → mta-sts-empty",
        throwsWithCode(function () { b.network.smtp.mtaSts.parsePolicy(""); }, /mta-sts-empty/));
  check("parsePolicy: non-string → mta-sts-empty",
        throwsWithCode(function () { b.network.smtp.mtaSts.parsePolicy(null); }, /mta-sts-empty/));
  check("parsePolicy: number → mta-sts-empty",
        throwsWithCode(function () { b.network.smtp.mtaSts.parsePolicy(42); }, /mta-sts-empty/));
}

function testParseStsBadMode() {
  check("parsePolicy: unknown mode → mta-sts-bad-mode",
        throwsWithCode(function () {
          b.network.smtp.mtaSts.parsePolicy("version: STSv1\nmode: bogus\n");
        }, /mta-sts-bad-mode/));
  // A version-only policy (no mode line) leaves mode null → bad-mode.
  check("parsePolicy: missing mode → mta-sts-bad-mode",
        throwsWithCode(function () {
          b.network.smtp.mtaSts.parsePolicy("version: STSv1\nmax_age: 100\n");
        }, /mta-sts-bad-mode/));
}

function testParseStsBadVersion() {
  // A syntactically valid policy whose version token is not STSv1 is
  // refused before the mode check (RFC 8461 §3.1 — version MUST be STSv1).
  check("parsePolicy: version STSv2 → mta-sts-bad-version",
        throwsWithCode(function () {
          b.network.smtp.mtaSts.parsePolicy("version: STSv2\nmode: enforce\n");
        }, /mta-sts-bad-version/));
  // Absent version line leaves version null → bad-version (not bad-mode).
  check("parsePolicy: missing version → mta-sts-bad-version",
        throwsWithCode(function () {
          b.network.smtp.mtaSts.parsePolicy("mode: enforce\nmax_age: 100\n");
        }, /mta-sts-bad-version/));
}

function testParseStsModeVariantsAndMaxAge() {
  var testing = b.network.smtp.mtaSts.parsePolicy("version: STSv1\nmode: testing\n");
  check("parsePolicy: testing mode accepted", testing.mode === "testing");

  var none = b.network.smtp.mtaSts.parsePolicy("version: STSv1\nmode: none\n");
  check("parsePolicy: none mode accepted", none.mode === "none");

  // mode is lowercased on parse.
  var upper = b.network.smtp.mtaSts.parsePolicy("version: STSv1\nmode: ENFORCE\n");
  check("parsePolicy: mode is case-normalized to lowercase", upper.mode === "enforce");

  // mx hosts are lowercased and collected in order (repeats preserved).
  var multi = b.network.smtp.mtaSts.parsePolicy(
    "version: STSv1\nmode: enforce\nmx: MX1.Example.COM\nmx: mx2.example.com\n");
  check("parsePolicy: mx hosts lowercased + ordered",
        multi.mx.length === 2 && multi.mx[0] === "mx1.example.com" && multi.mx[1] === "mx2.example.com");

  // With no max_age line the field stays null (falls back to the default TTL
  // inside fetch; parse itself just records absence).
  check("parsePolicy: absent max_age stays null", multi.max_age === null);
}

// ---- MTA-STS MX match (mtaSts.matchMx) — defensive returns ----------------

function testMatchMxDefensiveReturns() {
  check("matchMx: non-string mxHost → false",
        b.network.smtp.mtaSts.matchMx(123, ["mx.example.com"]) === false);
  check("matchMx: non-array mxList → false",
        b.network.smtp.mtaSts.matchMx("mx.example.com", "mx.example.com") === false);
  check("matchMx: null mxList → false",
        b.network.smtp.mtaSts.matchMx("mx.example.com", null) === false);
}

function testMatchMxCaseAndDotEdges() {
  // Case-insensitive exact match.
  check("matchMx: exact match is case-insensitive",
        b.network.smtp.mtaSts.matchMx("MX1.EXAMPLE.COM", ["mx1.example.com"]) === true);
  // A single-label host (no dot) cannot satisfy a wildcard entry.
  check("matchMx: dotless host vs wildcard → false",
        b.network.smtp.mtaSts.matchMx("localhost", ["*.example.com"]) === false);
  // A bare "*." entry is too short to be a wildcard and never matches.
  check("matchMx: bare '*.' entry never matches",
        b.network.smtp.mtaSts.matchMx("a.example.com", ["*."]) === false);
  // A non-matching-suffix wildcard → false.
  check("matchMx: wildcard suffix must match",
        b.network.smtp.mtaSts.matchMx("mx1.other.com", ["*.example.com"]) === false);
  // A single-label wildcard that DOES match the host's suffix → true.
  check("matchMx: single-label wildcard matches a subdomain",
        b.network.smtp.mtaSts.matchMx("mx1.example.com", ["*.example.com"]) === true);
  // A wildcard entry preceding an exact entry: the exact host still matches.
  check("matchMx: exact host matches even when a wildcard precedes it",
        b.network.smtp.mtaSts.matchMx("mail.example.com", ["*.other.com", "mail.example.com"]) === true);
}

// ---- MTA-STS fetch (mtaSts.fetch) — precondition + domain guard -----------

async function testMtaStsFetchDomainGuard() {
  check("mtaSts.fetch: non-string domain → bad-domain",
        await asyncThrowsWithCode(function () { return b.network.smtp.mtaSts.fetch(123); }, /bad-domain/));
  check("mtaSts.fetch: empty domain → bad-domain",
        await asyncThrowsWithCode(function () { return b.network.smtp.mtaSts.fetch(""); }, /bad-domain/));
}

async function testMtaStsFetchNoTxtRecord() {
  // A domain whose _mta-sts TXT does not carry v=STSv1 has no rotation
  // signal → fetch refuses to pull the HTTPS policy (RFC 8461 §3.1) and
  // returns null WITHOUT touching the network.
  var dnsLookup = async function () { return [["some-unrelated-txt-value"]]; };
  var rv = await b.network.smtp.mtaSts.fetch("example.com", { dnsLookup: dnsLookup });
  check("mtaSts.fetch: TXT without v=STSv1 → null", rv === null);
}

async function testMtaStsFetchTxtAbsent() {
  // ENOTFOUND from the resolver → safeResolveTxt returns null → fetch null.
  var dnsLookup = async function () { var e = new Error("nx"); e.code = "ENOTFOUND"; throw e; };
  var rv = await b.network.smtp.mtaSts.fetch("no-such.example.com", { dnsLookup: dnsLookup });
  check("mtaSts.fetch: absent _mta-sts TXT → null", rv === null);
}

async function testMtaStsFetchTxtHardLookupFailure() {
  // A hard resolver failure (not ENOTFOUND/ENODATA) on the _mta-sts TXT
  // lookup surfaces a structured SmtpPolicyError — a spoofable/absent TXT
  // is null, but a genuine resolver fault is an error, not silent success.
  var dnsLookup = async function () { var e = new Error("servfail"); e.code = "ESERVFAIL"; throw e; };
  check("mtaSts.fetch: hard TXT resolver failure → mta-sts-txt-lookup-failed",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.mtaSts.fetch("servfail.example.com", { dnsLookup: dnsLookup });
        }, /mta-sts-txt-lookup-failed/));
}

// ---- DANE tlsa (dane.tlsa) — domain guard ---------------------------------

async function testDaneTlsaDomainGuard() {
  check("dane.tlsa: non-string domain → bad-domain",
        await asyncThrowsWithCode(function () { return b.network.smtp.dane.tlsa(42); }, /bad-domain/));
  check("dane.tlsa: empty domain → bad-domain",
        await asyncThrowsWithCode(function () { return b.network.smtp.dane.tlsa(""); }, /bad-domain/));
}

// ---- DANE recordShape (dane.recordShape) — guard + every label -----------

function testDaneRecordShapeGuard() {
  check("dane.recordShape: non-object → dane-bad-record",
        throwsWithCode(function () { b.network.smtp.dane.recordShape(null); }, /dane-bad-record/));
  check("dane.recordShape: string → dane-bad-record",
        throwsWithCode(function () { b.network.smtp.dane.recordShape("x"); }, /dane-bad-record/));
}

function testDaneRecordShapeAllLabels() {
  var pkixTa = b.network.smtp.dane.recordShape({ usage: 0, selector: 0, mtype: 0, dataHex: "aa" });
  check("recordShape: usage 0 / selector 0 / mtype 0 → PKIX-TA / Cert / Full",
        pkixTa.usageLabel === "PKIX-TA" && pkixTa.selectorLabel === "Cert" && pkixTa.mtypeLabel === "Full");

  var pkixEe = b.network.smtp.dane.recordShape({ usage: 1, selector: 1, mtype: 2, dataHex: "bb" });
  check("recordShape: usage 1 / selector 1 / mtype 2 → PKIX-EE / SPKI / SHA-512",
        pkixEe.usageLabel === "PKIX-EE" && pkixEe.selectorLabel === "SPKI" && pkixEe.mtypeLabel === "SHA-512");

  var daneTa = b.network.smtp.dane.recordShape({ usage: 2, selector: 0, mtype: 1, dataHex: "cc" });
  check("recordShape: usage 2 → DANE-TA", daneTa.usageLabel === "DANE-TA");

  var unknown = b.network.smtp.dane.recordShape({ usage: 9, selector: 5, mtype: 7, dataHex: "dd" });
  check("recordShape: out-of-range codes → unknown labels",
        unknown.usageLabel === "unknown" && unknown.selectorLabel === "unknown" && unknown.mtypeLabel === "unknown");

  // The raw fields pass through unchanged.
  check("recordShape: raw fields pass through",
        daneTa.usage === 2 && daneTa.selector === 0 && daneTa.mtype === 1 && daneTa.dataHex === "cc");

  // usage 3 → DANE-EE (the last labeled arm before "unknown").
  var daneEe = b.network.smtp.dane.recordShape({ usage: 3, selector: 1, mtype: 1, dataHex: "ee" });
  check("recordShape: usage 3 → DANE-EE", daneEe.usageLabel === "DANE-EE");
}

// ---- DANE verifyChain (dane.verifyChain) — uncovered branches ------------

function testVerifyChainPkixOptIn() {
  var leaf = Buffer.from("leaf-der-bytes", "utf8");
  var ca   = Buffer.from("ca-der-bytes", "utf8");

  // PKIX-EE (usage 1) with allowPkixModes → matches leaf, flags pkixPathRequired.
  var eeRec = { usage: 1, selector: 0, mtype: 0, dataHex: leaf.toString("hex") };
  var eeRv = b.network.smtp.dane.verifyChain([leaf, ca], [eeRec], { allowPkixModes: true });
  check("verifyChain: PKIX-EE opt-in matches leaf with pkixPathRequired",
        eeRv.ok === true && eeRv.matches[0].usage === "PKIX-EE" &&
        eeRv.matches[0].certIndex === 0 && eeRv.matches[0].pkixPathRequired === true);

  // PKIX-TA (usage 0) with allowPkixModes → matches a non-leaf cert.
  var taRec = { usage: 0, selector: 0, mtype: 0, dataHex: ca.toString("hex") };
  var taRv = b.network.smtp.dane.verifyChain([leaf, ca], [taRec], { allowPkixModes: true });
  check("verifyChain: PKIX-TA opt-in matches trust-anchor cert with pkixPathRequired",
        taRv.ok === true && taRv.matches[0].usage === "PKIX-TA" &&
        taRv.matches[0].certIndex === 1 && taRv.matches[0].pkixPathRequired === true);
}

function testVerifyChainUnsupportedUsage() {
  var leaf = Buffer.from("leaf", "utf8");
  var rec = { usage: 7, selector: 0, mtype: 0, dataHex: "00" };                  // out-of-range usage
  var rv = b.network.smtp.dane.verifyChain([leaf], [rec]);
  check("verifyChain: unsupported usage → ok=false + unsupported-usage error",
        rv.ok === false && rv.matches.length === 0 &&
        rv.errors[0] && rv.errors[0].reason === "unsupported-usage" && rv.errors[0].usage === 7);
}

function testVerifyChainDaneEeSha512() {
  var leaf = Buffer.from("leaf-bytes-for-sha512", "utf8");
  var sha512Hex = nodeCrypto.createHash("sha512").update(leaf).digest("hex");
  var rec = { usage: 3, selector: 0, mtype: 2, dataHex: sha512Hex };
  var rv = b.network.smtp.dane.verifyChain([leaf], [rec]);
  check("verifyChain: DANE-EE / Cert / SHA-512 matches via hash",
        rv.ok === true && rv.matches[0].usage === "DANE-EE" && rv.matches[0].mtype === "SHA-512");
}

function testVerifyChainSpkiSelectorNoBytes() {
  // selector=1 (SPKI) on a non-DER buffer → SPKI extraction returns null →
  // no match (the `if (!bytes) return null` branch in _matchTlsaAgainstCert).
  var fake = Buffer.from("definitely not DER", "utf8");
  var rec = { usage: 3, selector: 1, mtype: 0, dataHex: fake.toString("hex") };
  var rv = b.network.smtp.dane.verifyChain([fake], [rec]);
  check("verifyChain: SPKI selector on non-DER cert → no match",
        rv.ok === false && rv.matches.length === 0);
}

// ---- TLS-RPT recordShape (tlsRpt.recordShape) — type guards + defaults ----

function testRecordShapeTypeGuards() {
  // Called with no opts at all → defaults to {} → the organization guard
  // fires (proving the opts-default path, not a TypeError on undefined).
  check("recordShape: no opts → tls-rpt-bad-organization",
        throwsWithCode(function () { b.network.smtp.tlsRpt.recordShape(); }, /tls-rpt-bad-organization/));
  check("recordShape: non-string organization → tls-rpt-bad-organization",
        throwsWithCode(function () {
          b.network.smtp.tlsRpt.recordShape({ organization: 123, policies: [] });
        }, /tls-rpt-bad-organization/));
  check("recordShape: non-array policies → tls-rpt-bad-policies",
        throwsWithCode(function () {
          b.network.smtp.tlsRpt.recordShape({ organization: "example.com", policies: "nope" });
        }, /tls-rpt-bad-policies/));
}

function testRecordShapePolicyDefaults() {
  var rpt = b.network.smtp.tlsRpt.recordShape({
    organization: "example.com",
    policies:     [{ domain: "example.com" }],                                   // everything else defaulted
  });
  var pol = rpt.policies[0];
  check("recordShape: policy-type defaults to 'sts'", pol.policy["policy-type"] === "sts");
  check("recordShape: policy-string defaults to []",
        Array.isArray(pol.policy["policy-string"]) && pol.policy["policy-string"].length === 0);
  check("recordShape: mx-host defaults to []",
        Array.isArray(pol.policy["mx-host"]) && pol.policy["mx-host"].length === 0);
  check("recordShape: session counts default to 0",
        pol.summary["total-successful-session-count"] === 0 &&
        pol.summary["total-failure-session-count"] === 0);
  check("recordShape: failure-details defaults to []",
        Array.isArray(pol["failure-details"]) && pol["failure-details"].length === 0);
  // A generated report-id + a default date-range are always present.
  check("recordShape: auto report-id present",
        typeof rpt["report-id"] === "string" && rpt["report-id"].length > 0);
  check("recordShape: default date-range present",
        typeof rpt["date-range"]["start-datetime"] === "string" &&
        typeof rpt["date-range"]["end-datetime"] === "string");
  check("recordShape: contact-info defaults to null", rpt["contact-info"] === null);
}

// ---- TLS-RPT fetchPolicy (tlsRpt.fetchPolicy) — guard + no-record returns --

async function testFetchPolicyDomainGuard() {
  check("fetchPolicy: non-string domain → tls-rpt-bad-domain",
        await asyncThrowsWithCode(function () { return b.network.smtp.tlsRpt.fetchPolicy(42); }, /tls-rpt-bad-domain/));
}

async function testFetchPolicyRuaRequired() {
  // A v=TLSRPTv1 record with no rua= is malformed and MUST be ignored.
  var dnsLookup = async function () { return [["v=TLSRPTv1;"]]; };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy: v=TLSRPTv1 without rua → null", rv === null);
}

async function testFetchPolicyNoMatchingRecord() {
  // No record begins with v=TLSRPTv1 → null.
  var dnsLookup = async function () { return [["v=spf1 -all"]]; };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy: no v=TLSRPTv1 record → null", rv === null);
}

async function testFetchPolicyHardLookupFailure() {
  // A hard resolver failure on the _smtp._tls TXT lookup surfaces a
  // structured SmtpPolicyError (absence is null; a fault is an error).
  var dnsLookup = async function () { var e = new Error("servfail"); e.code = "ESERVFAIL"; throw e; };
  check("fetchPolicy: hard TXT resolver failure → tls-rpt-lookup-failed",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.tlsRpt.fetchPolicy("servfail.example.com", { dnsLookup: dnsLookup });
        }, /tls-rpt-lookup-failed/));
}

async function testFetchPolicyNoTxtAtAll() {
  // safeResolveTxt returns null on ENODATA → fetchPolicy null.
  var dnsLookup = async function () { var e = new Error("nodata"); e.code = "ENODATA"; throw e; };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("bare.example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy: no TXT record at all → null", rv === null);
}

async function testFetchPolicyTrimsAndSplitsRua() {
  var dnsLookup = async function () {
    return [["v=TLSRPTv1; rua=https://a.example.com/r , mailto:tls@example.com "]];
  };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy: comma-split rua entries are trimmed",
        rv && rv.rua.length === 2 &&
        rv.rua[0] === "https://a.example.com/r" && rv.rua[1] === "mailto:tls@example.com");
}

async function testFetchPolicyStringRecordAmongNonMatching() {
  // A plain-string TXT record (not the array-of-chunks shape) is read
  // directly, and a preceding non-TLSRPT record is skipped before the
  // matching one is chosen.
  var dnsLookup = async function () {
    return ["v=spf1 -all", "v=TLSRPTv1; rua=https://reports.example.com/r"];
  };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy: string record chosen past a non-matching record",
        rv && rv.rua.length === 1 && rv.rua[0] === "https://reports.example.com/r");
}

// ---- TLS-RPT submit (tlsRpt.submit) — dispatch + failure branches ----------

async function testSubmitRejectsNonObjectReport() {
  check("submit: non-object report → tls-rpt-bad-report",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.tlsRpt.submit("not-a-report", { rua: ["https://x.example/r"] });
        }, /tls-rpt-bad-report/));
}

async function testSubmitHttpsNon2xx() {
  // The framework httpClient resolves { statusCode, headers, body } — the
  // fake mirrors that real contract so this branch exercises the shape the
  // production path actually returns.
  var fakeHttp = { request: async function () { return { statusCode: 500, body: Buffer.from("") }; } };
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com", "report-id": "r1" },
    { rua: ["https://reports.example.com/submit"], httpClient: fakeHttp });
  var e = rv.results[0];
  check("submit: https non-2xx → ok=false with HTTP-status error",
        e.kind === "https" && e.ok === false && e.error === "HTTP 500");
}

async function testSubmitHttpsSuccess2xx() {
  // A successful submission MUST be reported ok=true. The framework
  // httpClient resolves { statusCode, headers, body } (see mtaSts.fetch,
  // which reads res.statusCode); a submit path that reads a non-existent
  // `status` field would mark every real 2xx POST as a failure.
  var fakeHttp = { request: async function () { return { statusCode: 200, headers: {}, body: Buffer.from("") }; } };
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com", "report-id": "r1" },
    { rua: ["https://reports.example.com/submit"], httpClient: fakeHttp });
  var e = rv.results[0];
  check("submit: https 2xx → ok=true, status=200, no error",
        e.kind === "https" && e.ok === true && e.status === 200 && e.error === null);
}

async function testSubmitHttpsThrows() {
  var fakeHttp = { request: async function () { throw new Error("connreset"); } };
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com" },
    { rua: ["https://reports.example.com/submit"], httpClient: fakeHttp });
  var e = rv.results[0];
  check("submit: https request throw is caught into entry.error",
        e.ok === false && /connreset/.test(e.error || ""));
}

async function testSubmitHttpsThrowsNonError() {
  // An error with an empty (falsy) message is still captured into
  // entry.error via the String(e) fallback rather than surfacing as
  // "undefined".
  var fakeHttp = { request: async function () { throw new Error(""); } };
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com" },
    { rua: ["https://reports.example.com/submit"], httpClient: fakeHttp });
  var e = rv.results[0];
  check("submit: message-less throw captured via String(e)",
        e.ok === false && e.error === "Error");
}

async function testSubmitInvalidMailtoAddr() {
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com" },
    { rua: ["mailto:not a valid address"] });
  var e = rv.results[0];
  check("submit: invalid mailto addr-spec → refused, not forwarded",
        e.ok === false && /not a valid RFC 5322 addr-spec/.test(e.error || "") && !e.mailto);
}

async function testSubmitUnsupportedScheme() {
  var rv = await b.network.smtp.tlsRpt.submit(
    { "organization-name": "example.com" },
    { rua: ["ftp://reports.example.com/r"] });
  var e = rv.results[0];
  check("submit: unsupported rua scheme → error names the scheme",
        e.ok === false && /unsupported rua URI scheme: ftp/.test(e.error || ""));
}

async function testSubmitValidMailtoBody() {
  var report = b.network.smtp.tlsRpt.recordShape({
    organization: "example.com",
    reportId:     "rpt-777",
    policies:     [{ type: "sts", domain: "example.com" }],
  });
  var rv = await b.network.smtp.tlsRpt.submit(report, { rua: ["mailto:tls@example.com"] });
  var e = rv.results[0];
  check("submit: valid mailto → prepared gzip body + subject with Report-ID",
        e.kind === "mailto" && e.ok === true &&
        Buffer.isBuffer(e.mailto.body) && e.mailto.body[0] === 0x1f && e.mailto.body[1] === 0x8b &&
        e.mailto.to === "tls@example.com" &&
        e.mailto.subject.indexOf("rpt-777") !== -1);
}

// ---- TLS-RPT parseReport (tlsRpt.parseReport) — receive-side parser -------

function _validReport() {
  return {
    "organization-name": "reporter.example",
    "date-range": { "start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-02T00:00:00Z" },
    "report-id":  "report-abc-123",
    "contact-info": "tls-reports@reporter.example",
    "policies": [
      { summary: { "total-successful-session-count": 10, "total-failure-session-count": 3 } },
      { summary: { "total-successful-session-count": 5,  "total-failure-session-count": 1 } },
    ],
  };
}

function testParseReportBadInput() {
  check("parseReport: null body → tls-rpt-bad-input",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(null); }, /tls-rpt-bad-input/));
  check("parseReport: undefined body → tls-rpt-bad-input",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(undefined); }, /tls-rpt-bad-input/));
  check("parseReport: number body → tls-rpt-bad-input",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(12345); }, /tls-rpt-bad-input/));
}

function testParseReportBadJsonAndShape() {
  check("parseReport: malformed JSON → tls-rpt-bad-json",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport("{not json"); }, /tls-rpt-bad-json/));
  check("parseReport: scalar JSON (number) → tls-rpt-bad-shape",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport("123"); }, /tls-rpt-bad-shape/));
  check("parseReport: JSON null → tls-rpt-bad-shape",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport("null"); }, /tls-rpt-bad-shape/));
}

function testParseReportMissingRequiredField() {
  var r = _validReport();
  delete r["report-id"];
  check("parseReport: missing required field → tls-rpt-missing-field",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(JSON.stringify(r)); }, /tls-rpt-missing-field/));
}

function testParseReportBadDateRange() {
  var r = _validReport();
  r["date-range"] = { "start-datetime": 1234, "end-datetime": "2026-01-02T00:00:00Z" };
  check("parseReport: non-string date-range field → tls-rpt-bad-date-range",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(JSON.stringify(r)); }, /tls-rpt-bad-date-range/));
}

function testParseReportPoliciesNotArray() {
  var r = _validReport();
  r.policies = { "0": {} };
  check("parseReport: policies not an array → tls-rpt-bad-policies",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(JSON.stringify(r)); }, /tls-rpt-bad-policies/));
}

function testParseReportTooManyPolicies() {
  var r = _validReport();
  r.policies = [];
  for (var i = 0; i < 1025; i += 1) r.policies.push({ summary: {} });             // cap is 1024
  check("parseReport: > 1024 policies → tls-rpt-too-many-policies",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(JSON.stringify(r)); }, /tls-rpt-too-many-policies/));
}

function testParseReportTooLarge() {
  // A body larger than the 8 MiB cap is refused before any parse/decompress.
  var big = Buffer.alloc(C.BYTES.mib(8) + 1, 0x20);                              // spaces, not gzip magic
  check("parseReport: over-cap body → tls-rpt-too-large",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(big); }, /tls-rpt-too-large/));
}

function testParseReportHappyPathAggregates() {
  var parsed = b.network.smtp.tlsRpt.parseReport(JSON.stringify(_validReport()));
  check("parseReport: organization surfaced", parsed.organization === "reporter.example");
  check("parseReport: report-id surfaced", parsed.reportId === "report-abc-123");
  check("parseReport: contact surfaced", parsed.contact === "tls-reports@reporter.example");
  check("parseReport: date-range surfaced",
        parsed.dateRange.start === "2026-01-01T00:00:00Z" && parsed.dateRange.end === "2026-01-02T00:00:00Z");
  check("parseReport: success/failure counts aggregated across policies",
        parsed.totals.successful === 15 && parsed.totals.failure === 4);
  check("parseReport: raw report echoed", parsed.raw && parsed.raw["report-id"] === "report-abc-123");
}

function testParseReportContactOptional() {
  var r = _validReport();
  delete r["contact-info"];
  var parsed = b.network.smtp.tlsRpt.parseReport(JSON.stringify(r));
  check("parseReport: absent contact-info → null", parsed.contact === null);
}

function testParseReportNonFiniteCountsSkipped() {
  var r = _validReport();
  r.policies = [
    { summary: { "total-successful-session-count": "not-a-number", "total-failure-session-count": 2 } },
    { summary: { "total-successful-session-count": 4, "total-failure-session-count": null } },
    { /* no summary at all */ },
  ];
  var parsed = b.network.smtp.tlsRpt.parseReport(JSON.stringify(r));
  check("parseReport: non-numeric counts ignored in aggregation",
        parsed.totals.successful === 4 && parsed.totals.failure === 2);
}

function testParseReportGzipMagicSniff() {
  var gz = zlib.gzipSync(Buffer.from(JSON.stringify(_validReport()), "utf8"));
  var parsed = b.network.smtp.tlsRpt.parseReport(gz);                             // no contentType — sniffed by magic
  check("parseReport: gzip body auto-detected by magic bytes",
        parsed.organization === "reporter.example" && parsed.totals.successful === 15);
}

function testParseReportGzipViaContentType() {
  var gz = zlib.gzipSync(Buffer.from(JSON.stringify(_validReport()), "utf8"));
  var parsed = b.network.smtp.tlsRpt.parseReport(gz, { contentType: "application/tlsrpt+gzip" });
  check("parseReport: gzip body decompressed via contentType hint",
        parsed.reportId === "report-abc-123");
}

function testParseReportGunzipFailure() {
  // gzip magic bytes but a truncated/garbage deflate stream → gunzip throws.
  var bad = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);
  check("parseReport: corrupt gzip → tls-rpt-gunzip-failed",
        throwsWithCode(function () { b.network.smtp.tlsRpt.parseReport(bad); }, /tls-rpt-gunzip-failed/));
}

// ---- MTA-STS fetch (mtaSts.fetch) — HTTPS-fetch success + cache-TTL clamp -

var _STS_ENFORCE = "version: STSv1\nmode: enforce\nmx: MX1.Example.COM\nmx: mx2.example.com\n";

async function testMtaStsFetchSuccessAndMaxAgeClamp() {
  // A published _mta-sts TXT (v=STSv1 with an id) satisfies the RFC 8461
  // §3.1 precondition, so fetch pulls + parses the HTTPS policy and caches
  // it. max_age within the [1h, ~1y] window is honored verbatim as the
  // cache TTL.
  var body = _STS_ENFORCE + "max_age: 604800\n";                                 // 7 days, in-window
  var rv = await withFakeHttpRequest(
    async function () { return { statusCode: 200, headers: {}, body: Buffer.from(body, "utf8") }; },
    function () {
      return b.network.smtp.mtaSts.fetch("within.example", {
        dnsLookup: async function () { return [["v=STSv1; id=WITHIN01"]]; },
      });
    });
  check("mtaSts.fetch: enforce policy fetched + parsed",
        rv && rv.mode === "enforce" && rv.version === "STSv1");
  check("mtaSts.fetch: mx hosts lowercased from HTTPS body",
        rv.mx.length === 2 && rv.mx[0] === "mx1.example.com");
  check("mtaSts.fetch: policy id carried from the _mta-sts TXT", rv.id === "WITHIN01");
  check("mtaSts.fetch: fetchedAt stamped", typeof rv.fetchedAt === "number" && rv.fetchedAt > 0);
  check("mtaSts.fetch: in-window max_age honored as cache TTL",
        rv._cacheTtlMs === 604800 * C.TIME.seconds(1));
}

async function testMtaStsFetchMaxAgeCeilingClamp() {
  // max_age above the RFC 8461 §3.2 ceiling (~1 year) clamps to the ceiling.
  var body = _STS_ENFORCE + "max_age: 999999999\n";
  var rv = await withFakeHttpRequest(
    async function () { return { statusCode: 200, headers: {}, body: Buffer.from(body, "utf8") }; },
    function () {
      return b.network.smtp.mtaSts.fetch("ceil.example", {
        dnsLookup: async function () { return [["v=STSv1; id=CEIL01"]]; },
      });
    });
  check("mtaSts.fetch: over-ceiling max_age clamps to ~1y", rv._cacheTtlMs === C.TIME.weeks(52));
}

async function testMtaStsFetchMaxAgeAbsentUsesDefault() {
  // No max_age line → parsed.max_age null → default framework TTL (60 min).
  var rv = await withFakeHttpRequest(
    async function () { return { statusCode: 200, headers: {}, body: Buffer.from(_STS_ENFORCE, "utf8") }; },
    function () {
      return b.network.smtp.mtaSts.fetch("noage.example", {
        dnsLookup: async function () { return [["v=STSv1;"]]; },                 // no id= → policy id null
      });
    });
  check("mtaSts.fetch: absent max_age → default cache TTL", rv._cacheTtlMs === C.TIME.minutes(60));
  check("mtaSts.fetch: TXT without id= → policy id null", rv.id === null);
}

async function testMtaStsFetchTxtRecordShapes() {
  // _fetchStsTxt tolerates a mixed TXT answer: a non-string chunk is
  // skipped, and a plain-string record (not the array-of-chunks shape) is
  // read directly. The id= token is extracted from whichever record
  // carries v=STSv1.
  var rv = await withFakeHttpRequest(
    async function () { return { statusCode: 200, headers: {}, body: Buffer.from(_STS_ENFORCE + "max_age: 86400\n", "utf8") }; },
    function () {
      return b.network.smtp.mtaSts.fetch("mixed.example", {
        dnsLookup: async function () { return [12345, "v=STSv1; id=MIXED42"]; }, // non-string then plain string
      });
    });
  check("mtaSts.fetch: mixed TXT (non-string skipped, string record read) → id extracted",
        rv && rv.id === "MIXED42" && rv.mode === "enforce");
}

async function testMtaStsFetch404ReturnsNull() {
  // A 404 at the well-known path means "no policy published" → null,
  // NOT an error (RFC 8461 opportunistic behavior).
  var rv = await withFakeHttpRequest(
    async function () { return { statusCode: 404, headers: {}, body: Buffer.from("") }; },
    function () {
      return b.network.smtp.mtaSts.fetch("gone.example", {
        dnsLookup: async function () { return [["v=STSv1; id=GONE01"]]; },
      });
    });
  check("mtaSts.fetch: HTTPS 404 → null (no policy)", rv === null);
}

async function testMtaStsFetchNon2xxThrows() {
  // A non-404 non-2xx (e.g. 500) is a hard fetch failure and surfaces a
  // structured SmtpPolicyError.
  var threw = await asyncThrowsWithCode(function () {
    return withFakeHttpRequest(
      async function () { return { statusCode: 500, headers: {}, body: Buffer.from("") }; },
      function () {
        return b.network.smtp.mtaSts.fetch("err5.example", {
          dnsLookup: async function () { return [["v=STSv1; id=ERR501"]]; },
        });
      });
  }, /mta-sts-fetch-failed/);
  check("mtaSts.fetch: 5xx → mta-sts-fetch-failed", threw);
}

async function testMtaStsFetchHttpThrowIsOpportunisticNull() {
  // A network / TLS error from the httpClient on an un-cached first fetch
  // yields "no enforceable policy" → null (documented TOFU fallback).
  var rv = await withFakeHttpRequest(
    async function () { throw new Error("ECONNRESET at policy endpoint"); },
    function () {
      return b.network.smtp.mtaSts.fetch("reset.example", {
        dnsLookup: async function () { return [["v=STSv1; id=RESET01"]]; },
      });
    });
  check("mtaSts.fetch: httpClient throw → opportunistic null", rv === null);
}

// ---- DANE tlsa (dane.tlsa) — resolveTlsa dispatch + DNSSEC gate -----------

function _tlsaRec(usage, selector, match, data) {
  return { certUsage: usage, selector: selector, match: match, data: data };
}

async function testDaneTlsaMapsRecordsWhenDnssecAsserted() {
  // With opts.dnssecValidated:true the raw node:dns TLSA rows are
  // normalized to { usage, selector, mtype, dataHex }. Buffer data is
  // hex-encoded; a non-Buffer data field is stringified.
  var rv = await withFakeResolveTlsa(
    async function () {
      return [
        _tlsaRec(3, 1, 1, Buffer.from([0xab, 0xcd])),
        _tlsaRec(2, 0, 1, "deadbeef"),
      ];
    },
    function () { return b.network.smtp.dane.tlsa("example.com", 25, { dnssecValidated: true }); });
  check("dane.tlsa: DNSSEC-asserted → records normalized",
        rv.length === 2 && rv[0].usage === 3 && rv[0].selector === 1 && rv[0].mtype === 1);
  check("dane.tlsa: Buffer data hex-encoded", rv[0].dataHex === "abcd");
  check("dane.tlsa: non-Buffer data stringified", rv[1].dataHex === "deadbeef");
}

async function testDaneTlsaDefaultPortWhenOmitted() {
  // Port omitted → defaults to 25 (the qname is _25._tcp.<domain>); the
  // lookup still succeeds through the same DNSSEC-asserted path.
  var seenQname = null;
  var rv = await withFakeResolveTlsa(
    async function (qname) { seenQname = qname; return [_tlsaRec(3, 0, 1, Buffer.from([0x01]))]; },
    function () { return b.network.smtp.dane.tlsa("mail.example.com", undefined, { dnssecValidated: true }); });
  check("dane.tlsa: omitted port defaults to 25 in the qname",
        seenQname === "_25._tcp.mail.example.com" && rv.length === 1);
}

async function testDaneTlsaRefusesWithoutDnssec() {
  // The default (no opts.dnssecValidated) REFUSES to use TLSA records —
  // RFC 7672 §1.3 fail-closed: unvalidated records MUST NOT be used.
  var threw = await asyncThrowsWithCode(function () {
    return withFakeResolveTlsa(
      async function () { return [_tlsaRec(3, 0, 1, Buffer.from([0x01]))]; },
      function () { return b.network.smtp.dane.tlsa("example.com", 25); });
  }, /dane-no-dnssec/);
  check("dane.tlsa: no dnssecValidated → dane-no-dnssec (fail-closed)", threw);
}

async function testDaneTlsaEmptyOnNxAndNoData() {
  // ENOTFOUND / ENODATA are "domain publishes no TLSA" → empty array, not
  // an error (and the DNSSEC gate is never reached because there are no
  // records to use).
  var nx = await withFakeResolveTlsa(
    async function () { var e = new Error("nx"); e.code = "ENOTFOUND"; throw e; },
    function () { return b.network.smtp.dane.tlsa("nx.example.com", 25, { dnssecValidated: true }); });
  check("dane.tlsa: ENOTFOUND → []", Array.isArray(nx) && nx.length === 0);

  var nd = await withFakeResolveTlsa(
    async function () { var e = new Error("nodata"); e.code = "ENODATA"; throw e; },
    function () { return b.network.smtp.dane.tlsa("nd.example.com", 25, { dnssecValidated: true }); });
  check("dane.tlsa: ENODATA → []", Array.isArray(nd) && nd.length === 0);
}

async function testDaneTlsaLookupFailure() {
  // A non-NX resolver error (SERVFAIL, timeout) is surfaced as a
  // structured lookup failure.
  var threw = await asyncThrowsWithCode(function () {
    return withFakeResolveTlsa(
      async function () { var e = new Error("SERVFAIL"); e.code = "ESERVFAIL"; throw e; },
      function () { return b.network.smtp.dane.tlsa("srvfail.example.com", 25, { dnssecValidated: true }); });
  }, /dane-lookup-failed/);
  check("dane.tlsa: resolver SERVFAIL → dane-lookup-failed", threw);

  // A resolver error with an empty (falsy) message still yields a
  // structured failure — the detail falls back to String(e).
  var threwNoMsg = await asyncThrowsWithCode(function () {
    return withFakeResolveTlsa(
      async function () { var e = new Error(""); e.code = "EWEIRD"; throw e; },   // falsy .message
      function () { return b.network.smtp.dane.tlsa("weird.example.com", 25, { dnssecValidated: true }); });
  }, /dane-lookup-failed/);
  check("dane.tlsa: message-less resolver error → dane-lookup-failed", threwNoMsg);
}

async function testDaneTlsaNullRecordsYieldEmpty() {
  // A resolver that resolves null (rather than an array) still produces a
  // safe empty result after the DNSSEC gate.
  var rv = await withFakeResolveTlsa(
    async function () { return null; },
    function () { return b.network.smtp.dane.tlsa("nullrecs.example.com", 25, { dnssecValidated: true }); });
  check("dane.tlsa: null resolver result → []", Array.isArray(rv) && rv.length === 0);
}

async function testDaneTlsaUnavailableRuntime() {
  // On a runtime without node:dns.resolveTlsa the primitive refuses
  // rather than silently degrading.
  var threw = await asyncThrowsWithCode(function () {
    return withFakeResolveTlsa(undefined, function () {
      return b.network.smtp.dane.tlsa("example.com", 25, { dnssecValidated: true });
    });
  }, /dane-unavailable/);
  check("dane.tlsa: resolveTlsa missing → dane-unavailable", threw);
}

// ---- DANE verifyChain (dane.verifyChain) — input guards + DANE-TA chain ---

function testVerifyChainInputGuards() {
  check("verifyChain: empty chain → dane-bad-chain",
        throwsWithCode(function () { b.network.smtp.dane.verifyChain([], []); }, /dane-bad-chain/));
  check("verifyChain: non-array chain → dane-bad-chain",
        throwsWithCode(function () { b.network.smtp.dane.verifyChain("nope", []); }, /dane-bad-chain/));
  check("verifyChain: non-Buffer chain entry → dane-bad-chain",
        throwsWithCode(function () { b.network.smtp.dane.verifyChain(["not-a-buffer"], []); }, /dane-bad-chain/));
  check("verifyChain: non-array tlsaRecords → dane-bad-tlsa",
        throwsWithCode(function () { b.network.smtp.dane.verifyChain([Buffer.from("x")], "nope"); }, /dane-bad-tlsa/));
}

function testVerifyChainDaneEeSha256() {
  // DANE-EE / Cert / SHA-256 — the mtype=1 hash branch against the leaf.
  var leaf = Buffer.from("leaf-bytes-for-sha256", "utf8");
  var sha256Hex = nodeCrypto.createHash("sha256").update(leaf).digest("hex");
  var rv = b.network.smtp.dane.verifyChain([leaf], [{ usage: 3, selector: 0, mtype: 1, dataHex: sha256Hex }]);
  check("verifyChain: DANE-EE / Cert / SHA-256 matches via hash",
        rv.ok === true && rv.matches[0].usage === "DANE-EE" && rv.matches[0].mtype === "SHA-256");
}

function testVerifyChainDaneEeFullNoMatchAndBadDataHex() {
  var leaf = Buffer.from("leaf", "utf8");
  // mtype=0 (Full) with the wrong bytes → no match, ok=false.
  var wrong = b.network.smtp.dane.verifyChain([leaf], [{ usage: 3, selector: 0, mtype: 0, dataHex: "00" }]);
  check("verifyChain: DANE-EE Full wrong bytes → no match", wrong.ok === false && wrong.matches.length === 0);
  // Non-string dataHex is coerced to empty → cannot match.
  var noHex = b.network.smtp.dane.verifyChain([leaf], [{ usage: 3, selector: 0, mtype: 0, dataHex: null }]);
  check("verifyChain: non-string dataHex → no match", noHex.ok === false && noHex.matches.length === 0);
}

function testVerifyChainPkixModesRejectedByDefault() {
  // usage 0/1 WITHOUT opts.allowPkixModes → structured pkix-modes-not-allowed
  // error, ok=false (RFC 7672 §3.1.1 — SMTP DANE honors only DANE-TA/EE).
  var fake = Buffer.from("anything", "utf8");
  var rvEe = b.network.smtp.dane.verifyChain([fake], [{ usage: 1, selector: 0, mtype: 1, dataHex: "abc" }]);
  check("verifyChain: PKIX-EE without opt-in → pkix-modes-not-allowed",
        rvEe.ok === false && rvEe.errors[0] && rvEe.errors[0].reason === "pkix-modes-not-allowed");
  var rvTa = b.network.smtp.dane.verifyChain([fake], [{ usage: 0, selector: 0, mtype: 1, dataHex: "abc" }]);
  check("verifyChain: PKIX-TA without opt-in → pkix-modes-not-allowed",
        rvTa.ok === false && rvTa.errors[0] && rvTa.errors[0].reason === "pkix-modes-not-allowed");
}

function testVerifyChainDaneTaSyntheticUnverified() {
  // usage=2 against non-DER buffers: the TLSA hash-matches the non-leaf
  // cert, but the ASN.1 chain-order extraction fails, so the match is
  // accepted-but-flagged chainOrderUnverified (synthetic/test inputs only).
  var leaf = Buffer.from("leaf-synthetic", "utf8");
  var ca   = Buffer.from("ca-synthetic", "utf8");
  var caSha = nodeCrypto.createHash("sha256").update(ca).digest("hex");
  var rv = b.network.smtp.dane.verifyChain([leaf, ca], [{ usage: 2, selector: 0, mtype: 1, dataHex: caSha }]);
  check("verifyChain: DANE-TA on non-DER buffers → match flagged chainOrderUnverified",
        rv.ok === true && rv.matches[0].usage === "DANE-TA" &&
        rv.matches[0].certIndex === 1 && rv.matches[0].chainOrderUnverified === true);
}

function testVerifyChainDaneTaChainOrderVerified() {
  // Real DER: the matched DANE-TA cert's Subject equals the leaf's Issuer,
  // so the RFC 7672 §3.1.1 chain-order check passes and the match is NOT
  // flagged unverified.
  var caName   = _derName("Test Root CA");
  var leafName = _derName("leaf.example.com");
  var leaf = _derCert(caName, leafName);                                          // issuer=CA, subject=leaf
  var ta   = _derCert(caName, caName);                                            // self-issued root
  var taSha = nodeCrypto.createHash("sha256").update(ta).digest("hex");
  var rv = b.network.smtp.dane.verifyChain([leaf, ta], [{ usage: 2, selector: 0, mtype: 1, dataHex: taSha }]);
  check("verifyChain: DANE-TA ordered chain → verified match",
        rv.ok === true && rv.matches.length === 1 &&
        rv.matches[0].usage === "DANE-TA" && rv.matches[0].certIndex === 1 &&
        rv.matches[0].chainOrderUnverified === undefined);
}

function testVerifyChainDaneTaChainOrderMismatch() {
  // Real DER where the hash-matching cert's Subject does NOT equal the
  // leaf's Issuer: the match is refused and a chain-order-mismatch error
  // is recorded (a cert that merely hash-matches is not accepted as the
  // trust anchor unless it is actually the parent).
  var caName    = _derName("Real Issuer CA");
  var leafName  = _derName("leaf.example.com");
  var otherName = _derName("Unrelated Subject");
  var leaf = _derCert(caName, leafName);                                          // leaf.issuer = caName
  var rogue = _derCert(caName, otherName);                                        // subject != caName
  var rogueSha = nodeCrypto.createHash("sha256").update(rogue).digest("hex");
  var rv = b.network.smtp.dane.verifyChain([leaf, rogue], [{ usage: 2, selector: 0, mtype: 1, dataHex: rogueSha }]);
  check("verifyChain: DANE-TA out-of-order chain → refused with chain-order-mismatch",
        rv.ok === false && rv.matches.length === 0 &&
        rv.errors[0] && rv.errors[0].reason === "dane-ta-chain-order-mismatch");
}

function testVerifyChainDaneTaSkipsNonMatchingCert() {
  // A three-cert chain where the TLSA record matches only the last cert:
  // the non-matching intermediate is skipped and the loop continues up the
  // chain until the trust anchor matches.
  var leaf  = Buffer.from("leaf-3chain", "utf8");
  var inter = Buffer.from("intermediate-3chain", "utf8");
  var ta    = Buffer.from("trust-anchor-3chain", "utf8");
  var taSha = nodeCrypto.createHash("sha256").update(ta).digest("hex");
  var rv = b.network.smtp.dane.verifyChain([leaf, inter, ta], [{ usage: 2, selector: 0, mtype: 1, dataHex: taSha }]);
  check("verifyChain: DANE-TA skips non-matching intermediate, matches anchor",
        rv.ok === true && rv.matches[0].usage === "DANE-TA" && rv.matches[0].certIndex === 2);
}

function testVerifyChainSpkiSelectorRealDer() {
  // selector=1 (SPKI) against a REAL DER leaf: the SubjectPublicKeyInfo is
  // extracted from tbsCertificate and matched. Full (mtype 0) compares the
  // SPKI bytes verbatim; the DER embeds _SPKI_DER, so its hex is the
  // association data.
  var leaf = _derCert(_derName("Issuer"), _derName("leaf.example.com"));
  var full = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 1, mtype: 0, dataHex: _SPKI_DER.toString("hex") }]);
  check("verifyChain: DANE-EE / SPKI / Full matches extracted SubjectPublicKeyInfo",
        full.ok === true && full.matches[0].usage === "DANE-EE" && full.matches[0].mtype === "Full");

  // SHA-256 over the same SPKI bytes → hash match.
  var spkiSha = nodeCrypto.createHash("sha256").update(_SPKI_DER).digest("hex");
  var hashed = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 1, mtype: 1, dataHex: spkiSha }]);
  check("verifyChain: DANE-EE / SPKI / SHA-256 matches SPKI digest",
        hashed.ok === true && hashed.matches[0].mtype === "SHA-256");
}

function testVerifyChainSelectorAndMtypeFallthroughs() {
  var leaf = _derCert(_derName("Issuer"), _derName("leaf.example.com"));
  // selector=1 mtype=1 with the WRONG digest → SPKI extracted but no match.
  var wrongSha = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 1, mtype: 1, dataHex: "00".repeat(32) }]);
  check("verifyChain: SPKI SHA-256 wrong digest → no match",
        wrongSha.ok === false && wrongSha.matches.length === 0);
  // selector=1 mtype=2 (SHA-512) wrong digest → no match (exercises the
  // SHA-512 branch's non-match arm).
  var wrong512 = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 1, mtype: 2, dataHex: "00".repeat(64) }]);
  check("verifyChain: SPKI SHA-512 wrong digest → no match",
        wrong512.ok === false && wrong512.matches.length === 0);
  // selector=2 is neither Cert(0) nor SPKI(1) → _selectorBytes returns
  // null → the record cannot match.
  var badSelector = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 2, mtype: 0, dataHex: "aa" }]);
  check("verifyChain: unknown selector → no bytes → no match",
        badSelector.ok === false && badSelector.matches.length === 0);
  // mtype=9 is not a defined matching type → falls through to no match.
  var badMtype = b.network.smtp.dane.verifyChain([leaf],
    [{ usage: 3, selector: 0, mtype: 9, dataHex: "aa" }]);
  check("verifyChain: unknown mtype → no match", badMtype.ok === false && badMtype.matches.length === 0);
}

function testVerifyChainMalformedDerFailsClosed() {
  // A hostile / malformed peer cert must never crash the DANE verifier and
  // must never yield a spuriously-verified match from unparseable ASN.1.
  // These fixtures drive the structural guard arms in the cert-field
  // extractors (non-SEQUENCE top, short TBSCertificate, non-SEQUENCE tbs,
  // wrong-typed SubjectPublicKeyInfo slot) — every one returns null so the
  // verdict stays fail-closed.
  var sigAlg = asn1.writeSequence([ asn1.writeOid("1.2.840.113549.1.1.11"), asn1.writeNull() ]);
  var bit    = asn1.writeNode(asn1.TAG.BIT_STRING, Buffer.from([0x00, 0xaa]));
  var name   = _derName("x");
  var validity = asn1.writeSequence([
    asn1.writeNode(asn1.TAG.UTC_TIME, Buffer.from("260101000000Z")),
    asn1.writeNode(asn1.TAG.UTC_TIME, Buffer.from("270101000000Z")),
  ]);

  // (a) valid DER whose top node is an INTEGER, not a SEQUENCE.
  var intCert = asn1.writeInteger(Buffer.from([0x2a]));
  // (b) SEQUENCE whose tbsCertificate SEQUENCE holds too few fields.
  var shortTbs = asn1.writeSequence([
    asn1.writeSequence([ asn1.writeInteger(Buffer.from([1])), asn1.writeInteger(Buffer.from([2])) ]),
    sigAlg, bit,
  ]);
  // (c) SEQUENCE whose first child (the tbs slot) is an INTEGER.
  var nonSeqTbs = asn1.writeSequence([ asn1.writeInteger(Buffer.from([1])), sigAlg, bit ]);
  // (d) well-formed field layout but the SubjectPublicKeyInfo slot is an
  //     INTEGER instead of a SEQUENCE.
  var wrongSpki = asn1.writeSequence([
    asn1.writeSequence([
      asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
      asn1.writeInteger(Buffer.from([1])), sigAlg, name, validity, name,
      asn1.writeInteger(Buffer.from([7])),                                        // SPKI slot: INTEGER, not SEQUENCE
    ]),
    sigAlg, bit,
  ]);

  // (e) SEQUENCE with an empty value → zero children.
  var emptySeq = asn1.writeSequence([]);
  // (f) SEQUENCE whose value is a truncated inner tag → readSequence throws.
  var truncatedSeq = asn1.writeNode(asn1.TAG.SEQUENCE | 0x20, Buffer.from([0x30]));
  // (g) SEQUENCE whose tbs child is itself a SEQUENCE with a truncated
  //     value → the inner readSequence(tbs.value) throws.
  var truncatedTbs = asn1.writeSequence([
    asn1.writeNode(asn1.TAG.SEQUENCE | 0x20, Buffer.from([0x30])), sigAlg, bit,
  ]);

  var mangled = [intCert, shortTbs, nonSeqTbs, wrongSpki, emptySeq, truncatedSeq, truncatedTbs];
  for (var i = 0; i < mangled.length; i += 1) {
    var cert = mangled[i];
    var sha = nodeCrypto.createHash("sha256").update(cert).digest("hex");
    var noThrowTa = true, taRv = null;
    try { taRv = b.network.smtp.dane.verifyChain([cert, cert], [{ usage: 2, selector: 0, mtype: 1, dataHex: sha }]); }
    catch (_e) { noThrowTa = false; }
    check("verifyChain: malformed cert #" + i + " DANE-TA does not throw", noThrowTa && taRv !== null);

    var noThrowEe = true, eeRv = null;
    try { eeRv = b.network.smtp.dane.verifyChain([cert], [{ usage: 3, selector: 1, mtype: 0, dataHex: "aa" }]); }
    catch (_e) { noThrowEe = false; }
    check("verifyChain: malformed cert #" + i + " SPKI selector fails closed (no match, no throw)",
          noThrowEe && eeRv !== null && eeRv.ok === false && eeRv.matches.length === 0);
  }
}

// ---- TLS-RPT submit (tlsRpt.submit) — rua guard ---------------------------

async function testSubmitRuaGuard() {
  check("submit: empty rua array → tls-rpt-bad-rua",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.tlsRpt.submit({ "organization-name": "example.com" }, { rua: [] });
        }, /tls-rpt-bad-rua/));
  check("submit: missing rua (non-array) → tls-rpt-bad-rua",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.tlsRpt.submit({ "organization-name": "example.com" }, {});
        }, /tls-rpt-bad-rua/));
  // Called with no opts at all → defaults to {} → the same rua guard fires.
  check("submit: no opts → tls-rpt-bad-rua",
        await asyncThrowsWithCode(function () {
          return b.network.smtp.tlsRpt.submit({ "organization-name": "example.com" });
        }, /tls-rpt-bad-rua/));
}

async function testSubmitMailtoSubjectFallbacks() {
  // A mailto submission for a report missing organization-name / report-id
  // still produces a subject; the missing fields fall back to empty
  // strings rather than "undefined".
  var rv = await b.network.smtp.tlsRpt.submit({}, { rua: ["mailto:tls@example.com"] });
  var e = rv.results[0];
  check("submit: mailto with bare report → prepared body, empty-string subject fields",
        e.kind === "mailto" && e.ok === true && Buffer.isBuffer(e.mailto.body) &&
        e.mailto.subject.indexOf("undefined") === -1 &&
        e.mailto.subject.indexOf("Report-ID: <>") !== -1);
}

// ---- runner --------------------------------------------------------------

async function run() {
  testParseStsEmptyAndNonString();
  testParseStsBadMode();
  testParseStsBadVersion();
  testParseStsModeVariantsAndMaxAge();

  testMatchMxDefensiveReturns();
  testMatchMxCaseAndDotEdges();

  await testMtaStsFetchDomainGuard();
  await testMtaStsFetchNoTxtRecord();
  await testMtaStsFetchTxtAbsent();
  await testMtaStsFetchSuccessAndMaxAgeClamp();
  await testMtaStsFetchMaxAgeCeilingClamp();
  await testMtaStsFetchMaxAgeAbsentUsesDefault();
  await testMtaStsFetchTxtRecordShapes();
  await testMtaStsFetch404ReturnsNull();
  await testMtaStsFetchNon2xxThrows();
  await testMtaStsFetchHttpThrowIsOpportunisticNull();
  await testMtaStsFetchTxtHardLookupFailure();

  await testDaneTlsaDomainGuard();
  await testDaneTlsaMapsRecordsWhenDnssecAsserted();
  await testDaneTlsaDefaultPortWhenOmitted();
  await testDaneTlsaRefusesWithoutDnssec();
  await testDaneTlsaEmptyOnNxAndNoData();
  await testDaneTlsaLookupFailure();
  await testDaneTlsaNullRecordsYieldEmpty();
  await testDaneTlsaUnavailableRuntime();

  testDaneRecordShapeGuard();
  testDaneRecordShapeAllLabels();

  testVerifyChainInputGuards();
  testVerifyChainPkixOptIn();
  testVerifyChainPkixModesRejectedByDefault();
  testVerifyChainUnsupportedUsage();
  testVerifyChainDaneEeSha256();
  testVerifyChainDaneEeSha512();
  testVerifyChainDaneEeFullNoMatchAndBadDataHex();
  testVerifyChainSpkiSelectorNoBytes();
  testVerifyChainDaneTaSyntheticUnverified();
  testVerifyChainDaneTaChainOrderVerified();
  testVerifyChainDaneTaChainOrderMismatch();
  testVerifyChainDaneTaSkipsNonMatchingCert();
  testVerifyChainSpkiSelectorRealDer();
  testVerifyChainSelectorAndMtypeFallthroughs();
  testVerifyChainMalformedDerFailsClosed();

  testRecordShapeTypeGuards();
  testRecordShapePolicyDefaults();

  await testFetchPolicyDomainGuard();
  await testFetchPolicyRuaRequired();
  await testFetchPolicyNoMatchingRecord();
  await testFetchPolicyHardLookupFailure();
  await testFetchPolicyNoTxtAtAll();
  await testFetchPolicyTrimsAndSplitsRua();
  await testFetchPolicyStringRecordAmongNonMatching();

  await testSubmitRejectsNonObjectReport();
  await testSubmitHttpsNon2xx();
  await testSubmitHttpsSuccess2xx();
  await testSubmitHttpsThrows();
  await testSubmitHttpsThrowsNonError();
  await testSubmitInvalidMailtoAddr();
  await testSubmitUnsupportedScheme();
  await testSubmitValidMailtoBody();
  await testSubmitRuaGuard();
  await testSubmitMailtoSubjectFallbacks();

  testParseReportBadInput();
  testParseReportBadJsonAndShape();
  testParseReportMissingRequiredField();
  testParseReportBadDateRange();
  testParseReportPoliciesNotArray();
  testParseReportTooManyPolicies();
  testParseReportTooLarge();
  testParseReportHappyPathAggregates();
  testParseReportContactOptional();
  testParseReportNonFiniteCountsSkipped();
  testParseReportGzipMagicSniff();
  testParseReportGzipViaContentType();
  testParseReportGunzipFailure();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
