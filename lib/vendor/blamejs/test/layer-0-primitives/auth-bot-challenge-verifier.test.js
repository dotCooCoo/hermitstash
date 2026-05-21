"use strict";
/**
 * b.auth.botChallenge — server-side Turnstile / hCaptcha / reCAPTCHA-v3
 * widget-token verifier.
 *
 * Run standalone:
 *   node test/layer-0-primitives/auth-bot-challenge-verifier.test.js
 * Or via smoke:
 *   node test/smoke.js
 *
 * Coverage:
 *   - Public surface (create, PROVIDERS, BotChallengeError, DEFAULTS)
 *   - Factory rejects malformed opts (missing/empty secret, unknown
 *     provider, timeoutMs floor, allowlist shape, http-client shape)
 *   - verify resolves on provider success
 *   - verify throws bot-challenge/invalid-token on provider success=false,
 *     surfacing the error-codes array
 *   - verify throws bot-challenge/hostname-mismatch when the embedded
 *     hostname is outside the allowlist / does not match the per-call
 *     expectedHostname
 *   - verify throws bot-challenge/action-mismatch on action allowlist /
 *     expectedAction mismatch
 *   - verify throws bot-challenge/timeout on transport timeout
 *   - reCAPTCHA-v3 provider surfaces the `score` field on success
 *   - empty + oversize tokens refused at the boundary (no outbound call)
 *   - audit emission verified via spy
 *   - secret NEVER appears in any audit-event metadata (whole-object
 *     traversal, no string contains)
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

var botChallenge = b.auth.botChallenge;

var TEST_SECRET = "secret-DO_NOT_LEAK_3xampleSecretBytes-AAAA";

// ---- shared fixtures ----

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (e) { captured.push(e); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (ev) { return ev.action === action; });
    },
  };
}

// In-memory httpClient stub matching the b.httpClient.request shape.
// Each call records the request opts (so we can assert the secret +
// token shape) and returns the configured response. `nextResponse` is
// a function so timing-shape errors (timeout) can be expressed.
function _mockHttp(behaviour) {
  var calls = [];
  return {
    calls: calls,
    request: function (opts) {
      calls.push(opts);
      if (typeof behaviour === "function") return behaviour(opts);
      return Promise.resolve(behaviour);
    },
  };
}

function _jsonResponse(obj, statusCode) {
  return {
    statusCode: typeof statusCode === "number" ? statusCode : 200,
    headers:    { "content-type": "application/json; charset=utf-8" },
    body:       Buffer.from(JSON.stringify(obj), "utf8"),
  };
}

function _deepContainsString(value, needle) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.indexOf(needle) !== -1;
  if (typeof value === "number" || typeof value === "boolean") return false;
  if (Buffer.isBuffer(value)) return value.toString("utf8").indexOf(needle) !== -1;
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      if (_deepContainsString(value[i], needle)) return true;
    }
    return false;
  }
  if (typeof value === "object") {
    var keys = Object.keys(value);
    for (var k = 0; k < keys.length; k++) {
      if (_deepContainsString(value[keys[k]], needle)) return true;
    }
    return false;
  }
  return false;
}

// ---- tests ----

function testSurface() {
  check("botChallenge.create is a function", typeof botChallenge.create === "function");
  check("PROVIDERS frozen", Object.isFrozen(botChallenge.PROVIDERS));
  check("PROVIDERS includes turnstile",    !!botChallenge.PROVIDERS.turnstile);
  check("PROVIDERS includes hcaptcha",     !!botChallenge.PROVIDERS.hcaptcha);
  check("PROVIDERS includes recaptcha-v3", !!botChallenge.PROVIDERS["recaptcha-v3"]);
  check("turnstile endpoint correct",
    botChallenge.PROVIDERS.turnstile.endpoint ===
      "https://challenges.cloudflare.com/turnstile/v0/siteverify");
  check("hcaptcha endpoint correct",
    botChallenge.PROVIDERS.hcaptcha.endpoint ===
      "https://api.hcaptcha.com/siteverify");
  check("recaptcha-v3 endpoint correct",
    botChallenge.PROVIDERS["recaptcha-v3"].endpoint ===
      "https://www.google.com/recaptcha/api/siteverify");
  check("BotChallengeError exported",
    typeof botChallenge.BotChallengeError === "function");
  check("DEFAULTS.provider is turnstile",
    botChallenge.DEFAULTS.provider === "turnstile");
  check("DEFAULTS.timeoutMs is 5_000", botChallenge.DEFAULTS.timeoutMs === 5000);
  check("DEFAULTS.minTimeoutMs is 500", botChallenge.DEFAULTS.minTimeoutMs === 500);
  check("DEFAULTS.maxTokenBytes is 4 KiB",
    botChallenge.DEFAULTS.maxTokenBytes === 4096);
}

function _expectThrow(fn, label) {
  var threw = false;
  try { fn(); } catch (_e) { threw = true; }
  check("create() throws — " + label, threw);
}

function testCreateRejectsBadOpts() {
  _expectThrow(function () { botChallenge.create({}); }, "missing secret");
  _expectThrow(function () { botChallenge.create({ secret: "" }); }, "empty secret");
  _expectThrow(function () { botChallenge.create({ secret: 123 }); }, "non-string secret");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, provider: "unknown" });
  }, "unknown provider");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, timeoutMs: 100 });
  }, "timeoutMs below floor");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, timeoutMs: "5000" });
  }, "timeoutMs non-number");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, allowedHostnames: [] });
  }, "empty hostname allowlist");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, allowedHostnames: ["", "x"] });
  }, "empty-string in hostname allowlist");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, allowedActions: "login" });
  }, "non-array action allowlist");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, httpClient: { request: "nope" } });
  }, "httpClient missing request fn");
  _expectThrow(function () {
    botChallenge.create({ secret: TEST_SECRET, audit: {} });
  }, "audit missing safeEmit");
}

async function testVerifySuccessTurnstile() {
  var http = _mockHttp(_jsonResponse({
    success:      true,
    hostname:     "app.example.com",
    action:       "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var auditSpy = _captureAudit();
  var verifier = botChallenge.create({
    secret:     TEST_SECRET,
    httpClient: http,
    audit:      auditSpy,
  });
  var verdict = await verifier.verify("turnstile-token-OK-XYZ", { remoteIp: "203.0.113.4" });

  check("verify resolves with ok=true", verdict.ok === true);
  check("verify returns provider key",  verdict.provider === "turnstile");
  check("verify returns hostname",      verdict.hostname === "app.example.com");
  check("verify returns action",        verdict.action === "login");
  check("verify returns challengeTs",   verdict.challengeTs === "2026-05-20T12:00:00Z");
  check("verify returns raw response",  verdict.raw && verdict.raw.success === true);
  check("turnstile success result has no score field", verdict.score === undefined);

  check("http.calls length is 1", http.calls.length === 1);
  var call = http.calls[0];
  check("POST method", call.method === "POST");
  check("turnstile endpoint", call.url ===
    "https://challenges.cloudflare.com/turnstile/v0/siteverify");
  check("application/x-www-form-urlencoded Content-Type",
    call.headers["Content-Type"] === "application/x-www-form-urlencoded");
  check("body carries secret",  call.body.indexOf("secret=" + encodeURIComponent(TEST_SECRET)) !== -1);
  check("body carries response token",
    call.body.indexOf("response=turnstile-token-OK-XYZ") !== -1);
  check("body carries remoteip",  call.body.indexOf("remoteip=203.0.113.4") !== -1);
  check("body is not on URL",   call.url.indexOf("secret=") === -1);
  check("timeoutMs honoured (default)", call.timeoutMs === 5000);

  var audited = auditSpy.byAction("auth.bot_challenge.verify");
  check("audit emitted exactly once", audited.length === 1);
  check("audit outcome success", audited[0].outcome === "success");
  check("audit metadata carries provider", audited[0].metadata.provider === "turnstile");
  check("audit metadata ok=true",          audited[0].metadata.ok === true);
}

async function testVerifyProviderFailureSurfaces() {
  var http = _mockHttp(_jsonResponse({
    success:      false,
    "error-codes": ["invalid-input-response", "timeout-or-duplicate"],
  }));
  var auditSpy = _captureAudit();
  var verifier = botChallenge.create({
    secret:     TEST_SECRET,
    httpClient: http,
    audit:      auditSpy,
  });
  var threw  = null;
  try { await verifier.verify("bad-token"); }
  catch (e) { threw = e; }

  check("provider-rejected throws BotChallengeError",
    threw && threw.name === "BotChallengeError");
  check("provider-rejected code is invalid-token",
    threw && threw.code === "bot-challenge/invalid-token");
  check("error.errorCodes mirrors provider error-codes",
    Array.isArray(threw.errorCodes) &&
    threw.errorCodes[0] === "invalid-input-response" &&
    threw.errorCodes[1] === "timeout-or-duplicate");

  var audited = auditSpy.byAction("auth.bot_challenge.verify");
  check("provider-rejected audit emitted", audited.length === 1);
  check("provider-rejected audit outcome failure",
    audited[0].outcome === "failure");
  check("provider-rejected audit metadata includes errorCodes",
    Array.isArray(audited[0].metadata.errorCodes) &&
    audited[0].metadata.errorCodes.length === 2);
}

async function testHostnameAllowlistMismatch() {
  var http = _mockHttp(_jsonResponse({
    success: true, hostname: "evil.example.org", action: "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var verifier = botChallenge.create({
    secret:           TEST_SECRET,
    httpClient:       http,
    allowedHostnames: ["app.example.com", "console.example.com"],
  });
  var threw = null;
  try { await verifier.verify("token"); }
  catch (e) { threw = e; }
  check("hostname-mismatch throws BotChallengeError",
    threw && threw.name === "BotChallengeError");
  check("hostname-mismatch code", threw &&
    threw.code === "bot-challenge/hostname-mismatch");
}

async function testExpectedHostnameMismatch() {
  var http = _mockHttp(_jsonResponse({
    success: true, hostname: "app.example.com", action: "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var verifier = botChallenge.create({ secret: TEST_SECRET, httpClient: http });
  var threw = null;
  try { await verifier.verify("token", { expectedHostname: "billing.example.com" }); }
  catch (e) { threw = e; }
  check("expectedHostname mismatch throws hostname-mismatch", threw &&
    threw.code === "bot-challenge/hostname-mismatch");
}

async function testActionAllowlistMismatch() {
  var http = _mockHttp(_jsonResponse({
    success: true, hostname: "app.example.com", action: "delete-account",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var verifier = botChallenge.create({
    secret:         TEST_SECRET,
    httpClient:     http,
    allowedActions: ["login", "signup"],
  });
  var threw = null;
  try { await verifier.verify("token"); }
  catch (e) { threw = e; }
  check("action-mismatch throws BotChallengeError",
    threw && threw.name === "BotChallengeError");
  check("action-mismatch code", threw &&
    threw.code === "bot-challenge/action-mismatch");
}

async function testExpectedActionMismatch() {
  var http = _mockHttp(_jsonResponse({
    success: true, hostname: "app.example.com", action: "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var verifier = botChallenge.create({ secret: TEST_SECRET, httpClient: http });
  var threw = null;
  try { await verifier.verify("token", { expectedAction: "signup" }); }
  catch (e) { threw = e; }
  check("expectedAction mismatch throws action-mismatch", threw &&
    threw.code === "bot-challenge/action-mismatch");
}

async function testTimeout() {
  var http = _mockHttp(function () {
    var err = new Error("operation timed out");
    err.code = "TIMEOUT";
    return Promise.reject(err);
  });
  var auditSpy = _captureAudit();
  var verifier = botChallenge.create({
    secret:     TEST_SECRET,
    httpClient: http,
    timeoutMs:  500,
    audit:      auditSpy,
  });
  var threw = null;
  try { await verifier.verify("token"); }
  catch (e) { threw = e; }
  check("timeout throws BotChallengeError", threw && threw.name === "BotChallengeError");
  check("timeout code", threw && threw.code === "bot-challenge/timeout");
  var audited = auditSpy.byAction("auth.bot_challenge.verify");
  check("timeout audited", audited.length === 1 && audited[0].outcome === "failure");
  check("timeout audit reason", audited[0].metadata.reason === "timeout");
}

async function testRecaptchaV3Score() {
  var http = _mockHttp(_jsonResponse({
    success:      true,
    hostname:     "app.example.com",
    action:       "login",
    score:        0.85,
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var verifier = botChallenge.create({
    secret:     TEST_SECRET,
    provider:   "recaptcha-v3",
    httpClient: http,
  });
  var verdict = await verifier.verify("recaptcha-token");
  check("recaptcha-v3 success ok=true", verdict.ok === true);
  check("recaptcha-v3 score surfaced", verdict.score === 0.85);
  check("recaptcha-v3 provider key set",
    verdict.provider === "recaptcha-v3");
  check("recaptcha-v3 endpoint hit",
    http.calls[0].url === "https://www.google.com/recaptcha/api/siteverify");
}

async function testEmptyAndOversizeTokenRefused() {
  var http = _mockHttp(_jsonResponse({ success: true }));
  var verifier = botChallenge.create({ secret: TEST_SECRET, httpClient: http });

  var threw1 = null;
  try { await verifier.verify(""); }
  catch (e) { threw1 = e; }
  check("empty token refused", threw1 &&
    threw1.code === "bot-challenge/invalid-token");
  check("empty token did not call siteverify", http.calls.length === 0);

  var threw2 = null;
  try { await verifier.verify(null); }
  catch (e) { threw2 = e; }
  check("null token refused", threw2 &&
    threw2.code === "bot-challenge/invalid-token");

  var oversize = new Array(5000).join("A") + "Z"; // > 4 KiB
  var threw3 = null;
  try { await verifier.verify(oversize); }
  catch (e) { threw3 = e; }
  check("oversize token refused", threw3 &&
    threw3.code === "bot-challenge/invalid-token");
  check("oversize token did not call siteverify", http.calls.length === 0);
}

async function testNon2xxRefused() {
  var http = _mockHttp(_jsonResponse({ success: true }, 503));
  var verifier = botChallenge.create({ secret: TEST_SECRET, httpClient: http });
  var threw = null;
  try { await verifier.verify("token"); }
  catch (e) { threw = e; }
  check("non-2xx throws provider-error", threw &&
    threw.code === "bot-challenge/provider-error");
}

async function testBadContentTypeRefused() {
  var http = _mockHttp({
    statusCode: 200,
    headers:    { "content-type": "text/html" },
    body:       Buffer.from("<html>nope</html>", "utf8"),
  });
  var verifier = botChallenge.create({ secret: TEST_SECRET, httpClient: http });
  var threw = null;
  try { await verifier.verify("token"); }
  catch (e) { threw = e; }
  check("bad Content-Type throws provider-error", threw &&
    threw.code === "bot-challenge/provider-error");
}

async function testSecretNeverInAuditMetadata() {
  // Drive every code path that emits audit and confirm the secret
  // bytes never surface in any captured event.
  var auditSpy = _captureAudit();
  var sharedSecret = TEST_SECRET;

  // Success path.
  var httpOk = _mockHttp(_jsonResponse({
    success: true, hostname: "app.example.com", action: "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var vOk = botChallenge.create({
    secret: sharedSecret, httpClient: httpOk, audit: auditSpy,
  });
  await vOk.verify("token-OK");

  // Provider-rejected path.
  var httpBad = _mockHttp(_jsonResponse({
    success: false, "error-codes": ["invalid-input-response"],
  }));
  var vBad = botChallenge.create({
    secret: sharedSecret, httpClient: httpBad, audit: auditSpy,
  });
  try { await vBad.verify("token-BAD"); } catch (_e) { /* expected */ }

  // Timeout path.
  var httpTo = _mockHttp(function () {
    var err = new Error("timed out");
    err.code = "TIMEOUT";
    return Promise.reject(err);
  });
  var vTo = botChallenge.create({
    secret: sharedSecret, httpClient: httpTo, audit: auditSpy,
  });
  try { await vTo.verify("token-TO"); } catch (_e) { /* expected */ }

  // Hostname mismatch path.
  var httpHn = _mockHttp(_jsonResponse({
    success: true, hostname: "evil.example.org", action: "login",
    challenge_ts: "2026-05-20T12:00:00Z",
  }));
  var vHn = botChallenge.create({
    secret: sharedSecret, httpClient: httpHn, audit: auditSpy,
    allowedHostnames: ["app.example.com"],
  });
  try { await vHn.verify("token-HN"); } catch (_e) { /* expected */ }

  check("audit captured multiple events", auditSpy.captured.length >= 4);
  var anyLeak = false;
  var leakingEvent = null;
  for (var i = 0; i < auditSpy.captured.length; i++) {
    if (_deepContainsString(auditSpy.captured[i], sharedSecret)) {
      anyLeak = true;
      leakingEvent = auditSpy.captured[i];
      break;
    }
  }
  check("secret bytes never appear in any audit metadata", !anyLeak);
  if (anyLeak) {
    console.error("LEAKING AUDIT EVENT:", JSON.stringify(leakingEvent));
  }
}

async function run() {
  testSurface();
  testCreateRejectsBadOpts();
  await testVerifySuccessTurnstile();
  await testVerifyProviderFailureSurfaces();
  await testHostnameAllowlistMismatch();
  await testExpectedHostnameMismatch();
  await testActionAllowlistMismatch();
  await testExpectedActionMismatch();
  await testTimeout();
  await testRecaptchaV3Score();
  await testEmptyAndOversizeTokenRefused();
  await testNon2xxRefused();
  await testBadContentTypeRefused();
  await testSecretNeverInAuditMetadata();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK auth-bot-challenge-verifier — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };
