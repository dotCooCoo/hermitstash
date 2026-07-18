// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.password — Argon2id hashing + verify + needsRehash + the
 * b.auth.password.policy() presentation-time gate (length / common /
 * dictionary / context / complexity / HIBP breach check).
 *
 * This file exercises the ERROR, ADVERSARIAL, DEFENSIVE and
 * OPTION-DEFAULT branches: config-time throws (bad params / bad
 * policy), fail-closed request-shape readers (verify tolerates garbage
 * by returning false), the concurrency semaphore's queue path, and the
 * HIBP breach-check response handling — network error, non-200,
 * poisoned-mirror, match and no-match — driven through an injected
 * http-client stub (NEVER real network). Sibling
 * auth-password-audit.test.js covers b.auth.password.params().
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The password policy's HIBP breach check calls httpClient.request.
// password.js captures `require("../http-client")` (the shared module
// object) once at load; requiring the same resolved path here hands
// back that identical object, so replacing `.request` injects a stub
// into the live consumer path with no real network. Each test restores
// the original in a finally. Layer-0 files fork into their own process
// (smoke isolation), so this patch never bleeds into a sibling file.
var httpClient = require("../../lib/http-client");
// The framework's own SHA-1 (the only in-process SHA-1, HIBP-only) —
// used here to build a REALISTIC k-anonymity response body whose suffix
// matches the plaintext under test, not to mock anything.
var hibpSha1 = require("../../lib/framework-sha1-hibp");

// Fast Argon2 params for round-trip tests — the framework default of
// 64 MiB / t=3 / p=4 is ~250-500ms per call; 1 MiB / t=1 / p=1 keeps
// the suite quick while still driving the real vendor hash + verify.
var FAST = { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1 };

// ---- hash / verify happy path + defensive readers ------------------

async function testHashVerifyRoundtrip() {
  var h = await b.auth.password.hash("hunter2", FAST);
  check("hash produces argon2id PHC string", h.indexOf("$argon2id$") === 0);
  check("verify matches the original plaintext",
        (await b.auth.password.verify(h, "hunter2")) === true);
  check("verify rejects a wrong plaintext (returns false, not throw)",
        (await b.auth.password.verify(h, "wrong")) === false);
}

async function testHashRejectsBadPlain() {
  var threwEmpty, threwType, threwBig;
  try { await b.auth.password.hash(""); } catch (e) { threwEmpty = e; }
  check("hash: empty plaintext throws invalid-plain",
        threwEmpty && threwEmpty.code === "auth-password/invalid-plain");
  try { await b.auth.password.hash(12345); } catch (e) { threwType = e; }
  check("hash: non-string plaintext throws invalid-plain",
        threwType && threwType.code === "auth-password/invalid-plain");
  // 4 KiB is the plaintext cap; one byte over must be refused.
  var oversize = "a".repeat(b.constants.BYTES.kib(4) + 1);
  try { await b.auth.password.hash(oversize, FAST); } catch (e) { threwBig = e; }
  check("hash: oversize plaintext throws plain-too-large",
        threwBig && threwBig.code === "auth-password/plain-too-large");
}

async function testHashRejectsBadParams() {
  var threwMem, threwTime, threwPar;
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1) - 1, timeCost: 1, parallelism: 1 });
  } catch (e) { threwMem = e; }
  check("hash: memoryCost below 1 MiB floor throws bad-params",
        threwMem && threwMem.code === "auth-password/bad-params");
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1), timeCost: 0, parallelism: 1 });
  } catch (e) { threwTime = e; }
  check("hash: timeCost below 1 throws bad-params",
        threwTime && threwTime.code === "auth-password/bad-params");
  try {
    await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 0 });
  } catch (e) { threwPar = e; }
  check("hash: parallelism below 1 throws bad-params",
        threwPar && threwPar.code === "auth-password/bad-params");
}

async function testVerifyDefensiveReturnsFalse() {
  // verify() never throws on garbage — login flows treat false as
  // "credentials didn't match" and shouldn't wrap each call in try/catch.
  check("verify: non-string stored → false",
        (await b.auth.password.verify(null, "pw")) === false);
  check("verify: empty stored → false",
        (await b.auth.password.verify("", "pw")) === false);
  check("verify: non-string plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", 42)) === false);
  check("verify: empty plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", "")) === false);
  // Other Argon2 variants are out of spec — verify() refuses without
  // even attempting to validate them.
  check("verify: argon2i variant (wrong prefix) → false",
        (await b.auth.password.verify("$argon2i$v=19$m=1024,t=1,p=1$x$y", "pw")) === false);
  // Oversize plaintext is rejected before touching the vendor.
  var oversize = "a".repeat(b.constants.BYTES.kib(4) + 1);
  check("verify: oversize plain → false",
        (await b.auth.password.verify("$argon2id$v=19$m=1024,t=1,p=1$x$y", oversize)) === false);
  // A corrupted PHC string surfaces as a vendor throw; verify() must
  // swallow it and return false rather than break the login flow.
  check("verify: corrupted argon2id PHC (vendor throws) → false",
        (await b.auth.password.verify("$argon2id$this-is-not-a-valid-phc-body", "pw")) === false);
}

async function testNeedsRehash() {
  var strong = await b.auth.password.hash("pw", { memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 4 });
  check("needsRehash: hash at current defaults → false",
        b.auth.password.needsRehash(strong) === false);
  // A hash weaker than the requested target must be flagged for rehash.
  var weak = await b.auth.password.hash("pw", FAST);
  check("needsRehash: weaker-than-target hash → true",
        b.auth.password.needsRehash(weak, { memoryCost: b.constants.BYTES.kib(64), timeCost: 3, parallelism: 4 }) === true);
  // Non-argon2id / malformed stored value forces a rehash on next login.
  check("needsRehash: non-argon2id variant → true",
        b.auth.password.needsRehash("$argon2i$v=19$m=1024,t=1,p=1$x$y") === true);
  check("needsRehash: non-string stored → true",
        b.auth.password.needsRehash(null) === true);
  // Unparseable argon2id body → vendor throws → forced rehash.
  check("needsRehash: unparseable argon2id PHC → true",
        b.auth.password.needsRehash("$argon2id$broken") === true);
}

async function testGate() {
  var threw;
  try { b.auth.password.gate(1.5); } catch (e) { threw = e; }
  check("gate: non-integer rejected with bad-gate",
        threw && threw.code === "auth-password/bad-gate");
  var threwNeg;
  try { b.auth.password.gate(0); } catch (e) { threwNeg = e; }
  check("gate: zero rejected with bad-gate",
        threwNeg && threwNeg.code === "auth-password/bad-gate");
}

async function testConcurrencySemaphoreQueue() {
  // gate(1) shrinks the semaphore to a single slot; two concurrent
  // hashes force the second to queue on _waiters, then be released when
  // the first finishes — exercising the queue push + release-to-waiter
  // path that a single-call test never reaches.
  b.auth.password.gate(1);
  try {
    var order = [];
    var p1 = b.auth.password.hash("first", FAST).then(function () { order.push("first"); });
    var p2 = b.auth.password.hash("second", FAST).then(function () { order.push("second"); });
    await Promise.all([p1, p2]);
    check("concurrency gate: both queued hashes complete", order.length === 2);
  } finally {
    // Restore a sane default so no later work runs single-slot.
    b.auth.password.gate(8);
  }
}

// ---- policy() config-time throws -----------------------------------

function _expectPolicyThrow(label, opts) {
  var threw;
  try { b.auth.password.policy(opts); } catch (e) { threw = e; }
  check(label, threw && threw.code === "auth-password/bad-policy");
}

function testPolicyConstructionRejects() {
  _expectPolicyThrow("policy: unknown profile rejected", { profile: "totally-made-up" });
  _expectPolicyThrow("policy: minLength below 1 rejected", { minLength: 0 });
  _expectPolicyThrow("policy: minLength above cap rejected", { minLength: b.constants.BYTES.kib(4) + 1 });
  _expectPolicyThrow("policy: maxLength below minLength rejected", { minLength: 10, maxLength: 5 });
  _expectPolicyThrow("policy: unsupported breachCheck rejected", { breachCheck: "some-other-service" });
  _expectPolicyThrow("policy: non-positive mustRotateAfterMs rejected", { mustRotateAfterMs: -1 });
  _expectPolicyThrow("policy: non-finite mustRotateAfterMs rejected", { mustRotateAfterMs: Infinity });
  _expectPolicyThrow("policy: fractional historyMinDistance rejected", { historyMinDistance: 2.5 });
  _expectPolicyThrow("policy: negative historyMinDistance rejected", { historyMinDistance: -1 });
  _expectPolicyThrow("policy: non-object complexity rejected", { complexity: "yes" });
  _expectPolicyThrow("policy: complexity.minCategories out of range rejected",
    { complexity: { minCategories: 9, categories: ["lower", "upper"] } });
  _expectPolicyThrow("policy: complexity.categories bad token rejected",
    { complexity: { minCategories: 1, categories: ["lower", "emoji"] } });
  // hibpEndpoint must be a valid https URL (safeUrl ALLOW_HTTP_TLS).
  var threwUrl;
  try { b.auth.password.policy({ hibpEndpoint: "ftp://evil.example/range" }); } catch (e) { threwUrl = e; }
  check("policy: non-https hibpEndpoint rejected", threwUrl !== undefined);
}

function testPolicyProfilesApply() {
  var nist = b.auth.password.policy({ profile: "nist-aal2" });
  var d1 = nist.describe();
  check("policy profile nist-aal2: 8-byte floor + breach check",
        d1.minLength === b.constants.BYTES.bytes(8) && d1.breachCheck === "haveibeenpwned");
  var pci = b.auth.password.policy({ profile: "pci-4.0" });
  var d2 = pci.describe();
  check("policy profile pci-4.0: 12 min, rotation + history",
        d2.minLength === 12 && d2.mustRotateAfterMs === b.constants.TIME.days(90) && d2.historyMinDistance === 4);
  var hipaa = b.auth.password.policy({ profile: "hipaa-aal2" });
  var d3 = hipaa.describe();
  check("policy profile hipaa-aal2: complexity enabled",
        d3.complexity && d3.complexity.minCategories === 3);
  // Operator field override wins over the named profile.
  var overridden = b.auth.password.policy({ profile: "pci-4.0", minLength: 20 });
  check("policy: operator opt overrides profile default",
        overridden.describe().minLength === 20);
  // POLICY_PROFILES constant surface (verbatim dotted form for the gate).
  check("b.auth.password.POLICY_PROFILES exposes the three profiles",
        b.auth.password.POLICY_PROFILES["nist-aal2"] &&
        b.auth.password.POLICY_PROFILES["pci-4.0"] &&
        b.auth.password.POLICY_PROFILES["hipaa-aal2"]);
  check("b.auth.password.DEFAULT_POLICY minLength is the NIST 8 floor",
        b.auth.password.DEFAULT_POLICY.minLength === 8);
  check("b.auth.password.DEFAULT_PARAMS memoryCost is 64 MiB in KiB",
        b.auth.password.DEFAULT_PARAMS.memoryCost === b.constants.BYTES.kib(64));
}

// ---- policy.check() gates (no breach check) ------------------------

async function testCheckLengthAndTypeGates() {
  var pol = b.auth.password.policy({ minLength: 8, maxLength: 20, useBundledCommon: false });
  var r1 = await pol.check(1234);
  check("check: non-string plaintext → bad-input", r1.ok === false && r1.code === "policy/bad-input");
  var r2 = await pol.check("short");
  check("check: below minLength → too-short", r2.ok === false && r2.code === "policy/too-short");
  var r3 = await pol.check("x".repeat(21));
  check("check: above maxLength → too-long", r3.ok === false && r3.code === "policy/too-long");
  var r4 = await pol.check("a-perfectly-fine-pw");
  check("check: in-range unique pw passes (no breach check) → ok", r4.ok === true);
}

async function testCheckCommonAndDictionary() {
  // Bundled top-10000 set is on by default — "password" is in it.
  var pol = b.auth.password.policy({ minLength: 4 });
  var r1 = await pol.check("password");
  check("check: bundled common password → forbidden-common",
        r1.ok === false && r1.code === "policy/forbidden-common");
  // Operator-supplied forbidCommon (bundled off to isolate the branch).
  var pol2 = b.auth.password.policy({ minLength: 4, useBundledCommon: false, forbidCommon: ["s3cr3t-corp-pw"] });
  var r2 = await pol2.check("s3cr3t-corp-pw");
  check("check: operator forbidCommon match → forbidden-common",
        r2.ok === false && r2.code === "policy/forbidden-common");
  // Dictionary substring (brand names) — case-insensitive substring.
  var pol3 = b.auth.password.policy({ minLength: 4, useBundledCommon: false, dictionary: ["acmecorp"] });
  var r3 = await pol3.check("myAcmeCorpLogin");
  check("check: dictionary substring → forbidden-dictionary",
        r3.ok === false && r3.code === "policy/forbidden-dictionary");
}

async function testCheckContextSubstrings() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  var r1 = await pol.check("alice-and-friends", { email: "alice@example.com" });
  check("check: password containing email local-part → contains-context",
        r1.ok === false && r1.code === "policy/contains-context");
  var r2 = await pol.check("mybobbypassword", { username: "bob" });
  check("check: password containing username → contains-context",
        r2.ok === false && r2.code === "policy/contains-context");
  var r3 = await pol.check("secret-widgets-99", { deny: ["widgets"] });
  check("check: password containing operator deny string → contains-context",
        r3.ok === false && r3.code === "policy/contains-context");
}

async function testCheckComplexity() {
  var pol = b.auth.password.policy({
    minLength: 4, useBundledCommon: false,
    complexity: { minCategories: 3, minRunRepeat: 3, minSequenceLength: 3 },
  });
  var r1 = await pol.check("alllowercaseonly");
  check("check: too few character categories → complexity-categories",
        r1.ok === false && r1.code === "policy/complexity-categories");
  var r2 = await pol.check("Aaaa1!wxqz");
  check("check: N-identical-run → complexity-run",
        r2.ok === false && r2.code === "policy/complexity-run");
  var r3 = await pol.check("Xabcdef1!q");
  check("check: ascending sequence → complexity-sequence",
        r3.ok === false && r3.code === "policy/complexity-sequence");
  // A password that clears every complexity gate (4 categories, no
  // 3-run, no 3-char sequence) drives the run/sequence scanners through
  // their "not found" return arms and yields ok.
  var r4 = await pol.check("Xk9!mQ2w");
  check("check: complexity all-clear → ok", r4.ok === true);
}

function testParamsAudit() {
  var p = b.auth.password.params();
  check("params: algorithm is argon2id + meets OWASP floor",
        p.algorithm === "argon2id" && p.meetsFloor === true);
  check("params: active memoryCost matches the 64 MiB default (in KiB)",
        p.active.memoryCostKib === b.constants.BYTES.kib(64));
  check("b.auth.password.OWASP_FLOOR_2026 is the 19 MiB / t2 / p1 floor",
        b.auth.password.OWASP_FLOOR_2026.memoryCostKib === b.constants.BYTES.kib(19) &&
        b.auth.password.OWASP_FLOOR_2026.timeCost === 2 &&
        b.auth.password.OWASP_FLOOR_2026.parallelism === 1);
}

// ---- HIBP breach check via injected stub ---------------------------

// Build a k-anonymity response body: for the target plaintext, place
// its real SHA-1 suffix into the returned list with `count` sightings,
// plus a couple of decoy lines. This is exactly the shape HIBP returns.
function _hibpBodyFor(plaintext, count, extraLines) {
  var full = hibpSha1.sha1Hex(plaintext).toUpperCase();
  var suffix = full.slice(5);
  var lines = ["00000000000000000000000000000000000:3",
               suffix + ":" + count,
               "11111111111111111111111111111111111:9"];
  if (extraLines) lines = lines.concat(extraLines);
  return lines.join("\r\n");
}

// Run `fn` with httpClient.request replaced by `stub`; always restore.
async function _withStub(stub, fn) {
  var orig = httpClient.request;
  httpClient.request = stub;
  try { return await fn(); }
  finally { httpClient.request = orig; }
}

async function testBreachCheckMatch() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () {
    return { statusCode: 200, body: _hibpBodyFor("breached-pw-xyz", 42) };
  }, async function () {
    var r = await pol.check("breached-pw-xyz");
    check("check: plaintext found in HIBP → breached",
          r.ok === false && r.code === "policy/breached");
  });
}

async function testBreachCheckNoMatchAndThreshold() {
  // No matching suffix in the body → ok, breachCheckCount 0.
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () {
    return { statusCode: 200, body: "00000000000000000000000000000000000:3\r\n11111111111111111111111111111111111:9" };
  }, async function () {
    var r = await pol.check("unbreached-unique-pw");
    check("check: no HIBP match → ok with breachCheckCount 0",
          r.ok === true && r.breachCheckCount === 0);
  });
  // Suffix present but below breachThreshold → not flagged.
  var polHi = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", breachThreshold: 100 });
  await _withStub(async function () {
    return { statusCode: 200, body: _hibpBodyFor("rare-pw", 5) };
  }, async function () {
    var r = await polHi.check("rare-pw");
    check("check: HIBP count below threshold → ok (not breached)", r.ok === true);
  });
}

async function testBreachCheckNetworkError() {
  // Default (fail-open): a request throw → skip the check, allow.
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { throw new Error("ECONNREFUSED simulated"); }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP request error, fail-open → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
  // fail-closed: a request throw → reject.
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { throw new Error("ECONNREFUSED simulated"); }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: HIBP request error, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
}

async function testBreachCheckBadStatus() {
  // Non-200 (rate limited): fail-open skips, fail-closed rejects.
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { return { statusCode: 429, body: "" }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP non-200, fail-open → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { return { statusCode: 503, body: null }; }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: HIBP non-200, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
  // 200 with an empty body isolates the `!resp.body` arm (status is
  // fine but there's nothing to scan) — fail-open skips.
  await _withStub(async function () { return { statusCode: 200, body: null }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: HIBP 200 with empty body → breachCheckSkipped",
          r.ok === true && r.breachCheckSkipped === true);
  });
}

async function testBreachCheckPoisonedMirror() {
  // A body shaped like HIBP but mostly-unparseable (missing colons /
  // non-numeric counts) must not read as "looks fine". fail-open skips
  // with a reason; fail-closed rejects.
  var poisoned = ["no-colon-line-one", "another-bad-line", "third-bad-line",
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:notanumber",
                  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:7"].join("\r\n");
  var polOpen = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned" });
  await _withStub(async function () { return { statusCode: 200, body: poisoned }; }, async function () {
    var r = await polOpen.check("some-pw");
    check("check: poisoned HIBP mirror, fail-open → skipped w/ reason",
          r.ok === true && r.breachCheckSkipped === true &&
          r.breachCheckSkipReason === "hibp-response-mostly-unparseable");
  });
  var polClosed = b.auth.password.policy({ minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned", failClosed: true });
  await _withStub(async function () { return { statusCode: 200, body: poisoned }; }, async function () {
    var r = await polClosed.check("some-pw");
    check("check: poisoned HIBP mirror, fail-closed → breach-check-failed",
          r.ok === false && r.code === "policy/breach-check-failed");
  });
}

async function testBreachCheckEndpointTrailingSlash() {
  // A custom endpoint with trailing slashes must be normalized (the
  // linear backward slash-strip) before "/range/<prefix>" is appended.
  var seenUrl = null;
  var pol = b.auth.password.policy({
    minLength: 4, useBundledCommon: false, breachCheck: "haveibeenpwned",
    hibpEndpoint: "https://api.pwnedpasswords.com///",
  });
  await _withStub(async function (reqOpts) {
    seenUrl = reqOpts.url;
    return { statusCode: 200, body: "00000000000000000000000000000000000:3" };
  }, async function () {
    await pol.check("some-pw");
    check("check: trailing slashes stripped before /range/ appended",
          seenUrl === "https://api.pwnedpasswords.com/range/" + hibpSha1.sha1Hex("some-pw").toUpperCase().slice(0, 5));
  });
}

// ---- shouldRotate + reuseProhibited --------------------------------

function testShouldRotate() {
  var noRotate = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  check("shouldRotate: no rotation policy → false",
        noRotate.shouldRotate(Date.now()) === false);
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, mustRotateAfterMs: b.constants.TIME.days(90) });
  var longAgo = Date.now() - b.constants.TIME.days(200);
  check("shouldRotate: password older than window → true",
        pol.shouldRotate(longAgo) === true);
  check("shouldRotate: fresh password → false",
        pol.shouldRotate(Date.now()) === false);
  // Explicit `now` argument path.
  check("shouldRotate: explicit now arg respected",
        pol.shouldRotate(0, b.constants.TIME.days(91)) === true);
  var threw;
  try { pol.shouldRotate("not-a-timestamp"); } catch (e) { threw = e; }
  check("shouldRotate: non-numeric passwordSetAt throws bad-input",
        threw && threw.code === "auth-password/bad-input");
}

async function testReuseProhibited() {
  var pol = b.auth.password.policy({ minLength: 4, useBundledCommon: false, historyMinDistance: 4 });
  var stored = await b.auth.password.hash("old-password-1", FAST);
  check("reuseProhibited: candidate matches a stored history hash → true",
        (await pol.reuseProhibited("old-password-1", [stored])) === true);
  check("reuseProhibited: candidate absent from history → false",
        (await pol.reuseProhibited("brand-new-pw", [stored])) === false);
  // Non-argon2id history entry is skipped safely (returns false there).
  check("reuseProhibited: non-argon2id history entry ignored → false",
        (await pol.reuseProhibited("whatever", ["$argon2i$garbage"])) === false);
  // Empty plaintext short-circuits false.
  check("reuseProhibited: empty candidate → false",
        (await pol.reuseProhibited("", [stored])) === false);
  // Empty / non-array history short-circuits false.
  check("reuseProhibited: empty history → false",
        (await pol.reuseProhibited("old-password-1", [])) === false);
  // history-distance disabled short-circuits false regardless of match.
  var polOff = b.auth.password.policy({ minLength: 4, useBundledCommon: false });
  check("reuseProhibited: history disabled → false",
        (await polOff.reuseProhibited("old-password-1", [stored])) === false);
}

async function run() {
  await testHashVerifyRoundtrip();
  await testHashRejectsBadPlain();
  await testHashRejectsBadParams();
  await testVerifyDefensiveReturnsFalse();
  await testNeedsRehash();
  await testGate();
  await testConcurrencySemaphoreQueue();
  testPolicyConstructionRejects();
  testPolicyProfilesApply();
  await testCheckLengthAndTypeGates();
  await testCheckCommonAndDictionary();
  await testCheckContextSubstrings();
  await testCheckComplexity();
  testParamsAudit();
  await testBreachCheckMatch();
  await testBreachCheckNoMatchAndThreshold();
  await testBreachCheckNetworkError();
  await testBreachCheckBadStatus();
  await testBreachCheckPoisonedMirror();
  await testBreachCheckEndpointTrailingSlash();
  testShouldRotate();
  await testReuseProhibited();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
