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
var C          = require("../../lib/constants");

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

// ---- runner --------------------------------------------------------------

async function run() {
  testParseStsEmptyAndNonString();
  testParseStsBadMode();
  testParseStsModeVariantsAndMaxAge();

  testMatchMxDefensiveReturns();
  testMatchMxCaseAndDotEdges();

  await testMtaStsFetchDomainGuard();
  await testMtaStsFetchNoTxtRecord();
  await testMtaStsFetchTxtAbsent();

  await testDaneTlsaDomainGuard();

  testDaneRecordShapeGuard();
  testDaneRecordShapeAllLabels();

  testVerifyChainPkixOptIn();
  testVerifyChainUnsupportedUsage();
  testVerifyChainDaneEeSha512();
  testVerifyChainSpkiSelectorNoBytes();

  testRecordShapeTypeGuards();
  testRecordShapePolicyDefaults();

  await testFetchPolicyDomainGuard();
  await testFetchPolicyRuaRequired();
  await testFetchPolicyNoMatchingRecord();
  await testFetchPolicyNoTxtAtAll();
  await testFetchPolicyTrimsAndSplitsRua();

  await testSubmitRejectsNonObjectReport();
  await testSubmitHttpsNon2xx();
  await testSubmitHttpsSuccess2xx();
  await testSubmitHttpsThrows();
  await testSubmitInvalidMailtoAddr();
  await testSubmitUnsupportedScheme();
  await testSubmitValidMailtoBody();

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
