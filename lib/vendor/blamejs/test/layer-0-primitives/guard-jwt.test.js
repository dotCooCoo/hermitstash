// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// base64url encode (no padding) — the JWT compact-serialization segment
// encoding. Kept local so every fixture token is built in-process from a
// plain object; no network, no vendored codec dependency.
function b64url(str) {
  return Buffer.from(str, "utf8").toString("base64")
    .replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// Assemble a compact-serialization token from a header object, a payload
// (object OR a pre-encoded segment string — passing a string lets a test
// smuggle a non-object / undecodable payload past JSON.stringify), and an
// optional signature segment.
function mkTok(header, payload, sig) {
  var h = b64url(JSON.stringify(header));
  var p = typeof payload === "string" ? payload : b64url(JSON.stringify(payload));
  return h + "." + p + "." + (sig === undefined ? "sig" : sig);
}

var OK_HEADER  = { alg: "ES256", typ: "JWT" };
var OK_PAYLOAD = { iss: "example", exp: 9999999999, iat: 1700000000 };

// Minimal ES256 token — valid JSON header/payload, required claims
// present, far-future exp. The "sig" segment is a placeholder; the
// guard is the shape/header/claims contract, not a signature verifier.
var BENIGN_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9." +
  "sig";

// alg=none — RFC 7518 §3.6 explicit-no-signature; the canonical
// CVE-2015-9235 / CVE-2018-0114 algorithm-confusion refuse class.
var ALG_NONE_JWT =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
  "eyJzdWIiOiJhdHRhY2tlciJ9.";

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function hasIssue(rv, ruleId) {
  return rv.issues.some(function (i) { return i.ruleId === ruleId; });
}

function testKidSafe() {
  // Benign: a plain keystore identifier survives unchanged.
  var ok = b.guardJwt.kidSafe("tenant-1-2026-05");
  check("guardJwt.kidSafe benign passthrough",   ok === "tenant-1-2026-05");

  // Hostile: dot-dot path traversal — the operator keyResolver could
  // otherwise read outside the keystore directory.
  var trav = expectThrows("guardJwt.kidSafe rejects ../ traversal",
    function () { b.guardJwt.kidSafe("../../etc/passwd"); },
    "jwt.kid-traversal");
  check("guardJwt.kidSafe traversal GuardJwtError",
    trav instanceof b.guardJwt.GuardJwtError);

  // Hostile: forward slash / backslash separators and percent-encoded
  // variants are each refused as traversal indicators.
  expectThrows("guardJwt.kidSafe rejects embedded ../",
    function () { b.guardJwt.kidSafe("keys/../secret"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects backslash separator",
    function () { b.guardJwt.kidSafe("keys\\secret"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects percent-encoded dot-dot",
    function () { b.guardJwt.kidSafe("%2e%2e/keys"); },
    "jwt.kid-traversal");
  expectThrows("guardJwt.kidSafe rejects percent-encoded slash",
    function () { b.guardJwt.kidSafe("id%2fx"); },
    "jwt.kid-traversal");

  // Empty / non-string kid is a config-time refusal.
  expectThrows("guardJwt.kidSafe rejects empty string",
    function () { b.guardJwt.kidSafe(""); },
    "jwt.kid-empty");
  expectThrows("guardJwt.kidSafe rejects non-string",
    function () { b.guardJwt.kidSafe(1234); },
    "jwt.kid-empty");

  // Control byte in the kid — non-printable smuggling refuse.
  expectThrows("guardJwt.kidSafe rejects control byte",
    function () { b.guardJwt.kidSafe("bad\x00ctl"); },
    "jwt.kid-control");
}

function testSanitize() {
  // Benign: a well-formed ES256 token with required claims passes
  // through unchanged (compact serialization can't be repaired).
  var safe = b.guardJwt.sanitize(BENIGN_JWT, { profile: "strict" });
  check("guardJwt.sanitize benign passthrough",  safe === BENIGN_JWT);

  // Hostile: alg=none — critical, refused at every profile. sanitize
  // throws rather than returning a "cleaned" token.
  var noneErr = expectThrows("guardJwt.sanitize rejects alg=none",
    function () { b.guardJwt.sanitize(ALG_NONE_JWT, { profile: "strict" }); },
    "jwt.alg-none");
  check("guardJwt.sanitize alg-none GuardJwtError",
    noneErr instanceof b.guardJwt.GuardJwtError);

  // alg=none is universal — even permissive, which loosens the alg
  // allowlist entirely, still refuses the explicit-no-signature class.
  expectThrows("guardJwt.sanitize rejects alg=none at permissive too",
    function () { b.guardJwt.sanitize(ALG_NONE_JWT, { profile: "permissive" }); },
    "jwt.alg-none");

  // Hostile: not JWT compact-serialization shape — refused as jwt-shape.
  expectThrows("guardJwt.sanitize rejects non-JWT shape",
    function () { b.guardJwt.sanitize("not-a-jwt", { profile: "strict" }); },
    "jwt.jwt-shape");
}

function testValidateAlgNone() {
  // validate is the non-throwing sibling — confirm the alg=none refuse
  // surfaces in the issue list with ok=false, matching sanitize's throw.
  var rv = b.guardJwt.validate(ALG_NONE_JWT, { profile: "strict" });
  check("guardJwt.validate alg=none ok=false", rv.ok === false);
  check("guardJwt.validate alg-none kind present",
    rv.issues.some(function (i) { return i.kind === "alg-none"; }));
}

// ---- payload-decode fail-open (root: an undecodable / non-object payload
//      silently skipped the required-claims + exp/nbf/iat sanity checks,
//      so a token missing every required claim passed at strict — the
//      asymmetric sibling of the header-decode path, which DOES refuse) ----

function testValidatePayloadDecode() {
  // Sibling that IS handled: an undecodable HEADER surfaces header-decode
  // and fails the token. The payload path below must behave the same.
  var badHdr = b.guardJwt.validate("qqqq." + b64url(JSON.stringify(OK_PAYLOAD)) +
    ".sig", { profile: "strict" });
  check("validate: undecodable header -> header-decode (control)",
    badHdr.ok === false && hasIssue(badHdr, "jwt.header-decode"));

  // A JSON-STRING payload is not a claims object — required-claims and
  // exp/nbf/iat sanity have nothing to check. It must refuse, not pass.
  var strPay = mkTok(OK_HEADER, b64url(JSON.stringify("attacker")));
  var rStr = b.guardJwt.validate(strPay, { profile: "strict" });
  check("validate: json-string payload -> ok=false", rStr.ok === false);
  check("validate: json-string payload -> payload-decode",
    hasIssue(rStr, "jwt.payload-decode"));

  // A JSON-NUMBER payload — same non-object class.
  var numPay = mkTok(OK_HEADER, b64url("12345"));
  var rNum = b.guardJwt.validate(numPay, { profile: "strict" });
  check("validate: json-number payload -> ok=false + payload-decode",
    rNum.ok === false && hasIssue(rNum, "jwt.payload-decode"));

  // An UNDECODABLE payload (valid base64url, non-JSON bytes) — the required
  // claims definitionally can't be present, so it must fail fast.
  var undec = mkTok(OK_HEADER, "qqqq");
  var rUn = b.guardJwt.validate(undec, { profile: "strict" });
  check("validate: undecodable payload -> ok=false + payload-decode",
    rUn.ok === false && hasIssue(rUn, "jwt.payload-decode"));

  // A JSON-ARRAY payload is not a valid claims set (RFC 7519 §7.2 requires
  // a JSON object). Refused at EVERY profile, including permissive where
  // requiredClaims is empty — otherwise an array payload passes untouched.
  var arrPay = mkTok(OK_HEADER, b64url("[1,2,3]"));
  var rArrStrict = b.guardJwt.validate(arrPay, { profile: "strict" });
  check("validate: array payload strict -> ok=false + payload-decode",
    rArrStrict.ok === false && hasIssue(rArrStrict, "jwt.payload-decode"));
  var rArrPerm = b.guardJwt.validate(arrPay, { profile: "permissive" });
  check("validate: array payload permissive -> ok=false + payload-decode",
    rArrPerm.ok === false && hasIssue(rArrPerm, "jwt.payload-decode"));

  // Regression floor: a real object payload with required claims still
  // passes — the fix must not over-reject a well-formed claims set.
  var okObj = b.guardJwt.validate(mkTok(OK_HEADER, OK_PAYLOAD), { profile: "strict" });
  check("validate: object payload with claims still passes",
    okObj.ok === true && okObj.issues.length === 0);
}

function testSanitizePayloadDecode() {
  // sanitize is the throwing sibling — a non-object payload throws
  // jwt.payload-decode rather than returning the token as "clean".
  var strPay = mkTok(OK_HEADER, b64url(JSON.stringify("attacker")));
  var err = expectThrows("sanitize: json-string payload throws payload-decode",
    function () { b.guardJwt.sanitize(strPay, { profile: "strict" }); },
    "jwt.payload-decode");
  check("sanitize payload-decode GuardJwtError",
    err instanceof b.guardJwt.GuardJwtError);
}

async function testGatePayloadDecode() {
  // The shipped consumer path: b.guardJwt.gate().check(ctx). A token whose
  // payload is a JSON string (missing every required claim at strict) must
  // NOT be served.
  var g = b.guardJwt.gate({ profile: "strict" });
  try {
    var strPay = mkTok(OK_HEADER, b64url(JSON.stringify("attacker")));
    var d = await g.check({ jwt: strPay });
    check("gate: non-object payload -> action !== serve", d.action !== "serve");
    check("gate: non-object payload -> ok=false", d.ok === false);
  } finally {
    await g.close();
  }
}

// ---- broad branch coverage for the detector ----

function testValidateAlgAllowlist() {
  var hs = mkTok({ alg: "HS256", typ: "JWT" }, OK_PAYLOAD);

  // strict: alg-not-allowed is high -> ok=false. This is the HS256-against-
  // RSA-public-key forgery class blocked before the verifier.
  var rStrict = b.guardJwt.validate(hs, { profile: "strict" });
  check("alg-not-allowed strict -> ok=false high",
    rStrict.ok === false &&
    rStrict.issues.some(function (i) {
      return i.ruleId === "jwt.alg-not-allowed" && i.severity === "high";
    }));

  // balanced: audit -> warn severity, ok stays true (surfaced, not refused).
  var rBal = b.guardJwt.validate(hs, { profile: "balanced" });
  check("alg-not-allowed balanced -> ok=true warn",
    rBal.ok === true &&
    rBal.issues.some(function (i) {
      return i.ruleId === "jwt.alg-not-allowed" && i.severity === "warn";
    }));

  // permissive: allowlist off -> no alg-not-allowed issue at all.
  var rPerm = b.guardJwt.validate(hs, { profile: "permissive" });
  check("alg-not-allowed permissive -> not flagged",
    rPerm.ok === true && !hasIssue(rPerm, "jwt.alg-not-allowed"));

  // Operator allowlist override — add HS256 and it passes strict.
  var rOverride = b.guardJwt.validate(hs, {
    profile: "strict", allowedAlgs: ["HS256"],
  });
  check("alg allowlist override admits HS256",
    !hasIssue(rOverride, "jwt.alg-not-allowed"));
}

function testValidateTypConfusion() {
  var tok = mkTok({ alg: "ES256", typ: "evil" }, OK_PAYLOAD);
  var rStrict = b.guardJwt.validate(tok, { profile: "strict" });
  check("typ-confusion strict -> ok=false high",
    rStrict.ok === false && hasIssue(rStrict, "jwt.typ-confusion"));
  var rBal = b.guardJwt.validate(tok, { profile: "balanced" });
  check("typ-confusion balanced -> audit warn, ok=true",
    rBal.ok === true &&
    rBal.issues.some(function (i) {
      return i.ruleId === "jwt.typ-confusion" && i.severity === "warn";
    }));
  // Known JWT media-type is not flagged.
  var okTyp = b.guardJwt.validate(mkTok({ alg: "ES256", typ: "at+jwt" }, OK_PAYLOAD),
    { profile: "strict" });
  check("typ at+jwt not flagged", !hasIssue(okTyp, "jwt.typ-confusion"));
}

function testValidateCritUnknown() {
  var tok = mkTok({ alg: "ES256", typ: "JWT", crit: ["b64"] }, OK_PAYLOAD);
  // Unknown crit is refused at every profile (RFC 7515 §4.1.11).
  var rStrict = b.guardJwt.validate(tok, { profile: "strict" });
  check("crit-unknown strict -> ok=false",
    rStrict.ok === false && hasIssue(rStrict, "jwt.crit-unknown"));
  var rPerm = b.guardJwt.validate(tok, { profile: "permissive" });
  check("crit-unknown permissive -> ok=false (refused every profile)",
    rPerm.ok === false && hasIssue(rPerm, "jwt.crit-unknown"));
  // Opt a crit name into knownCrit and it is accepted.
  var rKnown = b.guardJwt.validate(tok, { profile: "strict", knownCrit: ["b64"] });
  check("crit in knownCrit allowlist -> not flagged",
    !hasIssue(rKnown, "jwt.crit-unknown"));
}

function testValidateClaimSanity() {
  var now = Math.floor(Date.now() / 1000);

  // exp in the past — replay / expired-token detection.
  var expPast = b.guardJwt.validate(
    mkTok(OK_HEADER, { iss: "ex", exp: 1, iat: 1 }), { profile: "strict" });
  check("exp-past -> ok=false", expPast.ok === false && hasIssue(expPast, "jwt.exp-past"));

  // nbf far in the future (> strict 5-min slack) — clock-skew / not-yet-valid.
  var nbfFar = b.guardJwt.validate(
    mkTok(OK_HEADER, { iss: "ex", exp: 9999999999, iat: now, nbf: now + 86400 }),
    { profile: "strict" });
  check("nbf-far-future -> ok=false",
    nbfFar.ok === false && hasIssue(nbfFar, "jwt.nbf-far-future"));

  // iat far in the future — issued-in-the-future is suspect.
  var iatFar = b.guardJwt.validate(
    mkTok(OK_HEADER, { iss: "ex", exp: 9999999999, iat: now + 86400 }),
    { profile: "strict" });
  check("iat-far-future -> ok=false",
    iatFar.ok === false && hasIssue(iatFar, "jwt.iat-far-future"));

  // nbf within slack is NOT flagged.
  var nbfOk = b.guardJwt.validate(
    mkTok(OK_HEADER, { iss: "ex", exp: 9999999999, iat: now, nbf: now + 60 }),
    { profile: "strict" });
  check("nbf within slack not flagged", !hasIssue(nbfOk, "jwt.nbf-far-future"));

  // Missing required claim — strict requires iss/exp/iat; an empty object
  // payload flags every one.
  var missing = b.guardJwt.validate(mkTok(OK_HEADER, {}), { profile: "strict" });
  check("claim-missing -> ok=false", missing.ok === false && hasIssue(missing, "jwt.claim-missing"));
  var missingCount = missing.issues.filter(function (i) {
    return i.ruleId === "jwt.claim-missing";
  }).length;
  check("claim-missing flags all three strict required claims", missingCount === 3);
}

function testValidateKidTraversalHeader() {
  var tok = mkTok({ alg: "ES256", typ: "JWT", kid: "../../etc/passwd" }, OK_PAYLOAD);
  var rv = b.guardJwt.validate(tok, { profile: "strict" });
  check("header kid traversal -> critical, ok=false",
    rv.ok === false &&
    rv.issues.some(function (i) {
      return i.ruleId === "jwt.kid-traversal" && i.severity === "critical";
    }));
}

function testValidateSegmentCaps() {
  // header segment over maxHeaderBytes (strict 2 KiB).
  var bigHdr = mkTok({ alg: "ES256", typ: "JWT", kid: "A".repeat(3000) }, OK_PAYLOAD);
  var rHc = b.guardJwt.validate(bigHdr, { profile: "strict" });
  check("header-cap -> ok=false", rHc.ok === false && hasIssue(rHc, "jwt.header-cap"));

  // signature segment over maxSignatureBytes (strict 4 KiB).
  var rSc = b.guardJwt.validate(
    mkTok(OK_HEADER, OK_PAYLOAD, "s".repeat(5000)), { profile: "strict" });
  check("signature-cap -> ok=false", rSc.ok === false && hasIssue(rSc, "jwt.signature-cap"));

  // total token over maxBytes (strict 16 KiB) — refused before segment parse.
  var rTc = b.guardJwt.validate(
    mkTok(OK_HEADER, OK_PAYLOAD, "s".repeat(17000)), { profile: "strict" });
  check("jwt-cap (total) -> ok=false", rTc.ok === false && hasIssue(rTc, "jwt.jwt-cap"));
}

function testValidateInputContract() {
  // Non-string input is bad-input, not a thrown TypeError.
  var rNon = b.guardJwt.validate(12345, { profile: "strict" });
  check("non-string input -> bad-input high",
    rNon.ok === false && hasIssue(rNon, "jwt.bad-input"));
  // Empty string is refused.
  var rEmpty = b.guardJwt.validate("", { profile: "strict" });
  check("empty input -> empty issue",
    rEmpty.ok === false && hasIssue(rEmpty, "jwt.empty"));
  // Not JWT compact shape.
  var rShape = b.guardJwt.validate("not-a-jwt", { profile: "strict" });
  check("non-JWT shape -> jwt-shape",
    rShape.ok === false && hasIssue(rShape, "jwt.jwt-shape"));
}

function testValidateCharThreats() {
  // A raw NUL byte in the compact string is a universal-refuse codepoint
  // class BEFORE any base64url decode — trojan-source can't ride inside.
  var tok = mkTok(OK_HEADER, OK_PAYLOAD);
  var withNul = tok.slice(0, 5) + "\x00" + tok.slice(5);
  var rv = b.guardJwt.validate(withNul, { profile: "strict" });
  check("raw NUL byte -> ok=false null-byte",
    rv.ok === false && hasIssue(rv, "jwt.null-byte"));
}

function testValidateBadOpts() {
  // A negative maxBytes is a config-time throw (entry-point tier).
  expectThrows("negative maxBytes throws jwt.bad-opt",
    function () { b.guardJwt.validate(BENIGN_JWT, { profile: "strict", maxBytes: -5 }); },
    "jwt.bad-opt");
  // Non-integer slack window is a config-time throw.
  expectThrows("non-int nbfFutureSlackMs throws jwt.bad-opt",
    function () { b.guardJwt.validate(BENIGN_JWT, { profile: "strict", nbfFutureSlackMs: 1.5 }); },
    "jwt.bad-opt");
  // Unknown profile / posture are config-time throws.
  expectThrows("unknown profile throws jwt.bad-profile",
    function () { b.guardJwt.validate(BENIGN_JWT, { profile: "nope" }); },
    "jwt.bad-profile");
  expectThrows("unknown compliancePosture throws jwt.bad-posture",
    function () { b.guardJwt.validate(BENIGN_JWT, { compliancePosture: "nope" }); },
    "jwt.bad-posture");
}

function testCompliancePosture() {
  // A benign token passes under a mapped posture (hipaa) — the posture
  // overlay tightens caps/policies but does not reject a well-formed token.
  var rv = b.guardJwt.validate(BENIGN_JWT, { profile: "strict", compliancePosture: "hipaa" });
  check("hipaa posture admits benign token", rv.ok === true);
  // The guard advertises the four postures via compliancePosture().
  var hipaa = b.guardJwt.compliancePosture("hipaa");
  check("compliancePosture(hipaa) resolves", !!hipaa && typeof hipaa === "object");
}

async function testGate() {
  var g = b.guardJwt.gate({ profile: "strict" });
  try {
    var clean = await g.check({ identifier: BENIGN_JWT });
    check("gate: benign token -> serve", clean.ok === true && clean.action === "serve");

    var none = await g.check({ token: ALG_NONE_JWT });
    check("gate: alg=none -> action !== serve", none.action !== "serve");

    // No token in ctx -> nothing to guard -> serve.
    var empty = await g.check({});
    check("gate: no identifier field -> serve", empty.action === "serve");
  } finally {
    await g.close();
  }
}

async function run() {
  testKidSafe();
  testSanitize();
  testValidateAlgNone();
  testValidatePayloadDecode();
  testSanitizePayloadDecode();
  await testGatePayloadDecode();
  testValidateAlgAllowlist();
  testValidateTypConfusion();
  testValidateCritUnknown();
  testValidateClaimSanity();
  testValidateKidTraversalHeader();
  testValidateSegmentCaps();
  testValidateInputContract();
  testValidateCharThreats();
  testValidateBadOpts();
  testCompliancePosture();
  await testGate();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
