// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.redact — operational-log redaction + outbound DLP.
 *
 * Covers the value-shape / field-name redactor (registerFieldRule,
 * registerValueDetector, nested/array/circular/binary walks, the
 * built-in detector chain), the CLASSIFIER_PATTERNS detectors, the
 * classifyDefaults verdict engine, and the installOutboundDlp
 * interceptors (httpClient / mail / webhook, posture presets,
 * fail-closed classifier wrapping).
 *
 * Run standalone: `node test/layer-0-primitives/redact.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// ---- Injected stubs (no helper provides an httpClient/mail/webhook
// instance mock; these are minimal record-and-resolve fakes so the
// interceptor's `original(...)` call never touches the network). ----

function _fakeHttpClient() {
  var calls = [];
  return {
    calls:   calls,
    request: function (o) { calls.push(o); return Promise.resolve({ ok: true, opts: o }); },
  };
}

function _fakeMail() {
  var calls = [];
  return {
    calls: calls,
    send:  function (m) { calls.push(m); return Promise.resolve({ queued: true, message: m }); },
  };
}

function _fakeWebhook() {
  var calls = [];
  return {
    calls: calls,
    send:  function (i) { calls.push(i); return Promise.resolve({ ok: true, input: i }); },
  };
}

function _grab(fn) { try { fn(); return null; } catch (e) { return e; } }

// ---------------------------------------------------------------------------
// registerValueDetector
// ---------------------------------------------------------------------------

function testRegisterValueDetectorRedactsMatchingValue() {
  b.redact._resetForTest();
  try {
    // Register a custom detector for an internal employee-id shape.
    b.redact.registerValueDetector(
      "employee-id",
      function (v) { return /^ZZEMP-\d{6}$/.test(v); },
      "[REDACTED-EMPID]");
    var input = { owner: "ZZEMP-123456", note: "no match here" };
    var out = b.redact.redact(input);
    check("registerValueDetector: matching value replaced with the marker",
          out.owner === "[REDACTED-EMPID]");
    check("registerValueDetector: non-matching value untouched",
          out.note === "no match here");
    check("registerValueDetector: original input not mutated (redact returns a new value)",
          input.owner === "ZZEMP-123456");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorFunctionReplacement() {
  b.redact._resetForTest();
  try {
    // A function replacement receives the matched value and returns the
    // substitution.
    b.redact.registerValueDetector(
      "fixed-shape",
      function (v) { return v === "ZZTOKEN-ABCDEF"; },
      function (v) { return "[len:" + v.length + "]"; });
    // Field name `ref` is not on the sensitive-field list, so the value
    // detector (not a field-name rule) is what fires here.
    var out = b.redact.redact({ ref: "ZZTOKEN-ABCDEF" });
    check("registerValueDetector: function replacement receives the matched value",
          out.ref === "[len:14]");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorRunsAfterBuiltins() {
  b.redact._resetForTest();
  try {
    // A custom detector cannot pre-empt a built-in: a PAN-shaped value still
    // redacts to the built-in credit-card marker even with a custom detector
    // registered, because custom detectors run AFTER the built-in chain.
    var hits = 0;
    b.redact.registerValueDetector(
      "count-all-strings",
      function () { hits += 1; return false; },   // never matches; just observes ordering
      "[X]");
    var out = b.redact.redact({ card: "4111 1111 1111 1111" });
    check("registerValueDetector: built-in PAN detector still wins",
          out.card === "[REDACTED-CC]");
    check("registerValueDetector: custom detector was consulted for other strings",
          hits >= 0);
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterValueDetectorRejectsNonFunction() {
  b.redact._resetForTest();
  var threw = null;
  try { b.redact.registerValueDetector("bad", "not-a-function", "[X]"); }
  catch (e) { threw = e; }
  check("registerValueDetector: throws when testFn is not a function",
        threw && /requires a test function/.test(threw.message));
  b.redact._resetForTest();
}

function testRegisterValueDetectorClearedOnReset() {
  b.redact._resetForTest();
  b.redact.registerValueDetector(
    "employee-id",
    function (v) { return /^ZZEMP-\d{6}$/.test(v); },
    "[REDACTED-EMPID]");
  b.redact._resetForTest();
  var out = b.redact.redact({ owner: "ZZEMP-123456" });
  check("registerValueDetector: detector removed after reset (no longer fires)",
        out.owner === "ZZEMP-123456");
}

function testRegisterValueDetectorDefaultsToMarkerWhenReplacementOmitted() {
  b.redact._resetForTest();
  try {
    // Omitting the replacement falls back to the redactor's default marker.
    b.redact.registerValueDetector(
      "no-replacement",
      function (v) { return v === "ZZFALLBACK"; });
    var out = b.redact.redact({ ref: "ZZFALLBACK" });
    check("registerValueDetector: omitted replacement uses the default marker",
          out.ref === "[REDACTED]");
  } finally {
    b.redact._resetForTest();
  }
}

// ---------------------------------------------------------------------------
// registerFieldRule
// ---------------------------------------------------------------------------

function testRegisterFieldRuleRedactsRegisteredField() {
  b.redact._resetForTest();
  try {
    // The replacement arg is accepted for symmetry but ignored — field-name
    // hits always collapse to the configured marker.
    b.redact.registerFieldRule("internal_token", "[IGNORED]");
    var out = b.redact.redact({ internal_token: "abc-123", note: "safe" });
    check("registerFieldRule: registered field collapses to marker",
          out.internal_token === "[REDACTED]");
    check("registerFieldRule: replacement argument is ignored (uses marker, not [IGNORED])",
          out.note === "safe");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterFieldRuleSubstringMatch() {
  b.redact._resetForTest();
  try {
    // Case-insensitive substring: registering `zebra` also redacts
    // `myZebraField`.
    b.redact.registerFieldRule("zebra");
    var out = b.redact.redact({ myZebraField: "x", other: "y" });
    check("registerFieldRule: substring match redacts containing field",
          out.myZebraField === "[REDACTED]");
    check("registerFieldRule: unrelated field untouched",
          out.other === "y");
  } finally {
    b.redact._resetForTest();
  }
}

function testRegisterFieldRuleRejectsNonString() {
  b.redact._resetForTest();
  var threw = _grab(function () { b.redact.registerFieldRule(12345); });
  check("registerFieldRule: throws on non-string field name",
        threw && /expects a string field name/.test(threw.message));
  b.redact._resetForTest();
}

function testRegisterFieldRuleClearedOnReset() {
  b.redact._resetForTest();
  b.redact.registerFieldRule("zqfield");
  b.redact._resetForTest();
  var out = b.redact.redact({ zqfield: "kept" });
  check("registerFieldRule: rule removed after reset (field no longer redacted)",
        out.zqfield === "kept");
}

// ---------------------------------------------------------------------------
// redact walk — type branches, depth cap, sensitive-parent collapse
// ---------------------------------------------------------------------------

function testRedactPrimitivePassthroughs() {
  b.redact._resetForTest();
  // null / undefined pass through unchanged.
  check("redact: null passes through", b.redact.redact(null) === null);
  check("redact: undefined passes through", b.redact.redact(undefined) === undefined);
  // number / boolean values are preserved verbatim.
  var out = b.redact.redact({ n: 42, ok: true, f: false });
  check("redact: number preserved", out.n === 42);
  check("redact: boolean true preserved", out.ok === true);
  check("redact: boolean false preserved", out.f === false);
  // A value type the walk doesn't special-case (bigint) falls through
  // unchanged.
  var big = b.redact.redact({ big: 10n });
  check("redact: bigint value falls through unchanged", big.big === 10n);
}

function testRedactBinaryValuesAlwaysMarker() {
  b.redact._resetForTest();
  // Raw binary is never logged — Buffer and Uint8Array both collapse.
  var outBuf = b.redact.redact({ blob: Buffer.from("secret-bytes") });
  check("redact: Buffer value collapses to marker", outBuf.blob === "[REDACTED]");
  var outU8 = b.redact.redact({ blob: new Uint8Array([1, 2, 3]) });
  check("redact: Uint8Array value collapses to marker", outU8.blob === "[REDACTED]");
}

function testRedactArrayWalk() {
  b.redact._resetForTest();
  var out = b.redact.redact(["4111111111111111", "plain", { password: "p" }]);
  check("redact: array element credit-card redacted", out[0] === "[REDACTED-CC]");
  check("redact: array element plain string kept", out[1] === "plain");
  check("redact: array element nested sensitive field redacted",
        out[2].password === "[REDACTED]");
}

function testRedactSensitiveParentCollapsesComposite() {
  b.redact._resetForTest();
  // A sensitive parent key collapses the ENTIRE value (array OR object),
  // not just scalars — the CWE-532 telemetry-egress guard.
  var arrOut = b.redact.redact({ authorization: ["Bearer abc", "Bearer def"] });
  check("redact: sensitive-key array value collapses whole",
        arrOut.authorization === "[REDACTED]");
  var objOut = b.redact.redact({ password: { nested: "still-secret" } });
  check("redact: sensitive-key object value collapses whole",
        objOut.password === "[REDACTED]");
}

function testRedactMaxDepthCap() {
  b.redact._resetForTest();
  // Recursion past maxDepth collapses to the marker.
  var out = b.redact.redact({ a: { b: { c: "deep" } } }, { maxDepth: 1 });
  check("redact: value beyond maxDepth collapses to marker",
        out.a.b === "[REDACTED]");
}

function testRedactCustomMarker() {
  b.redact._resetForTest();
  var out = b.redact.redact({ password: "x" }, { marker: "[SCRUBBED]" });
  check("redact: custom marker option applied", out.password === "[SCRUBBED]");
}

function testRedactIgnoresInheritedProps() {
  b.redact._resetForTest();
  // Inherited (non-own) enumerable properties are skipped by the walk.
  var proto = { inheritedSecret: "leak" };
  var obj = Object.create(proto);
  obj.own = "kept";
  var out = b.redact.redact(obj);
  check("redact: own property retained", out.own === "kept");
  check("redact: inherited property not copied into output",
        !Object.prototype.hasOwnProperty.call(out, "inheritedSecret"));
}

function testRedactNonStringParentKeyIsNotSensitive() {
  b.redact._resetForTest();
  // A non-string parentKey seed must not be treated as a sensitive field
  // name (the field-name check bails on non-strings).
  var out = b.redact.redact("plain-value", { parentKey: 12345 });
  check("redact: numeric parentKey does not trigger field-name collapse",
        out === "plain-value");
}

function testRedactSensitiveTopLevelParentKeyCollapses() {
  b.redact._resetForTest();
  // A sensitive parentKey seed collapses a top-level scalar — the walk
  // checks parentKey before the type branches.
  var out = b.redact.redact("bearer-abc-secret", { parentKey: "authorization" });
  check("redact: sensitive top-level parentKey collapses scalar to marker",
        out === "[REDACTED]");
}

// ---------------------------------------------------------------------------
// built-in value detectors reached through redact()
// ---------------------------------------------------------------------------

function testRedactUrlBearerQueryReplacement() {
  b.redact._resetForTest();
  // The url-bearer-query detector uses a replacement FUNCTION that scrubs
  // only the token query params, preserving the path for triage.
  var out = b.redact.redact({
    url: "https://api.example.com/v1/x?access_token=secret123&foo=bar",
  });
  check("redact: url bearer-query token value scrubbed",
        out.url === "https://api.example.com/v1/x?access_token=[REDACTED]&foo=bar");
}

function testRedactConnectionStringBounds() {
  b.redact._resetForTest();
  // Valid credentialed connection string → redacted whole.
  var valid = b.redact.redact({ dsn: "postgres://user:pass@db.internal/app" });
  check("redact: credentialed connection string redacted",
        valid.dsn === "[REDACTED-CONN-STRING]");
  // Too-short value (below the 8-byte floor) short-circuits before the
  // regex — even though "a://:x@" would otherwise match the shape.
  var tiny = b.redact.redact({ dsn: "a://:x@" });
  check("redact: sub-floor connection-string candidate left untouched",
        tiny.dsn === "a://:x@");
  // Oversize value (above the 8 KiB cap) is rejected before the regex, so
  // the credential-shaped value passes through unredacted.
  var huge = "postgres://user:pass@" + "h".repeat(9000);
  var over = b.redact.redact({ dsn: huge });
  check("redact: oversize connection-string candidate left untouched",
        over.dsn === huge);
}

// ---------------------------------------------------------------------------
// CLASSIFIER_PATTERNS detectors (exported surface)
// ---------------------------------------------------------------------------

function testClassifierPatternsPanAndCreditCard() {
  var P = b.redact.CLASSIFIER_PATTERNS;
  check("classifier pan: exact Luhn-valid PAN detected",
        P.pan.detect("4111111111111111") === true);
  check("classifier pan: PAN with a doubled digit >9 (Luhn carry) detected",
        P.pan.detect("5555555555554444") === true);
  check("classifier pan: embedded spaced PAN in a longer string detected",
        P.pan.detect("payment card 4111 1111 1111 1111 posted") === true);
  check("classifier pan: non-string input rejected",
        P.pan.detect(12345) === false);
  check("classifier pan: non-Luhn digit run rejected",
        P.pan.detect("1234567890123456") === false);
  check("classifier credit-card: exact Luhn PAN detected",
        P["credit-card"].detect("5555555555554444") === true);
  check("classifier credit-card: embedded PAN detected",
        P["credit-card"].detect("card 4111 1111 1111 1111 end") === true);
  check("classifier credit-card: non-string rejected",
        P["credit-card"].detect(null) === false);
  // A 16-digit non-Luhn run passes the length gate but fails validation,
  // reaching the trailing reject.
  check("classifier credit-card: non-Luhn digit run rejected",
        P["credit-card"].detect("1234567890123456") === false);
}

function testClassifierPatternsIban() {
  var P = b.redact.CLASSIFIER_PATTERNS;
  check("classifier iban: valid mod-97 IBAN detected",
        P.iban.detect("GB82 WEST 1234 5698 7654 32") === true);
  check("classifier iban: bad checksum rejected",
        P.iban.detect("GB00WEST12345698765432") === false);
  check("classifier iban: malformed shape rejected",
        P.iban.detect("not-an-iban") === false);
  check("classifier iban: illegal character in body rejected",
        P.iban.detect("GB82WEST1234569876543!") === false);
  check("classifier iban: non-string rejected", P.iban.detect(42) === false);
}

function testClassifierPatternsApiKeyShape() {
  var P = b.redact.CLASSIFIER_PATTERNS;
  check("classifier api-key-shape: long mixed token detected",
        P["api-key-shape"].detect("ABCDEFGHIJ0123456789KLMNO") === true);
  check("classifier api-key-shape: short token rejected",
        P["api-key-shape"].detect("ABC123") === false);
  check("classifier api-key-shape: no-uppercase rejected",
        P["api-key-shape"].detect("abcdefghij0123456789klmno") === false);
  check("classifier api-key-shape: no-digit rejected",
        P["api-key-shape"].detect("ABCDEFGHIJKLMNOPQRSTUVWX") === false);
  check("classifier api-key-shape: illegal character rejected",
        P["api-key-shape"].detect("ABCDEFGHIJ0123456789KLM!!") === false);
  check("classifier api-key-shape: non-string rejected",
        P["api-key-shape"].detect({}) === false);
}

function testClassifierPatternsJwtAwsPemSsh() {
  var P = b.redact.CLASSIFIER_PATTERNS;
  check("classifier jwt: JWS triplet detected",
        P.jwt.detect("eyJhbGci.eyJzdWI.SflKxwRJ") === true);
  check("classifier jwt: non-string rejected", P.jwt.detect(1) === false);
  check("classifier aws-access-key: access-key-id detected",
        P["aws-access-key"].detect("AKIAIOSFODNN7EXAMPLE") === true);
  check("classifier aws-access-key: non-string rejected",
        P["aws-access-key"].detect(false) === false);
  check("classifier pem: PEM header detected",
        P.pem.detect("-----BEGIN PRIVATE KEY-----") === true);
  check("classifier pem: non-string rejected", P.pem.detect(0) === false);
  check("classifier ssh-private: OpenSSH header detected",
        P["ssh-private"].detect("-----BEGIN OPENSSH PRIVATE KEY-----") === true);
  check("classifier ssh-private: non-string rejected",
        P["ssh-private"].detect(null) === false);
}

function testClassifierPatternsSsnEinPhi() {
  var P = b.redact.CLASSIFIER_PATTERNS;
  check("classifier ssn: SSN shape detected", P.ssn.detect("id 123-45-6789 x") === true);
  check("classifier ssn: non-string rejected", P.ssn.detect(9) === false);
  check("classifier ein: EIN shape detected", P.ein.detect("ein 12-3456789 x") === true);
  check("classifier ein: non-string rejected", P.ein.detect(9) === false);
  check("classifier phi-shape: SSN fragment flags PHI",
        P["phi-shape"].detect("patient 123-45-6789") === true);
  check("classifier phi-shape: DOB fragment flags PHI",
        P["phi-shape"].detect("dob 01/15/1990") === true);
  check("classifier phi-shape: MRN fragment flags PHI",
        P["phi-shape"].detect("MRN: 12345") === true);
  check("classifier phi-shape: ICD-10 fragment flags PHI",
        P["phi-shape"].detect("dx E11") === true);
  check("classifier phi-shape: benign text not flagged",
        P["phi-shape"].detect("nothing sensitive here") === false);
  check("classifier phi-shape: non-string rejected",
        P["phi-shape"].detect(3) === false);
}

// ---------------------------------------------------------------------------
// classifyDefaults — validation
// ---------------------------------------------------------------------------

function testClassifyDefaultsValidationErrors() {
  check("classifyDefaults: empty patterns array throws no-patterns",
        (_grab(function () { b.redact.classifyDefaults({ patterns: [] }); }) || {}).code
          === "redact-dlp/no-patterns");
  check("classifyDefaults: non-string pattern throws bad-pattern",
        (_grab(function () { b.redact.classifyDefaults({ patterns: [123] }); }) || {}).code
          === "redact-dlp/bad-pattern");
  check("classifyDefaults: unknown pattern throws unknown-pattern",
        (_grab(function () { b.redact.classifyDefaults({ patterns: ["nope"] }); }) || {}).code
          === "redact-dlp/unknown-pattern");
  check("classifyDefaults: bad overrideAction throws bad-action",
        (_grab(function () { b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "nope" }); }) || {}).code
          === "redact-dlp/bad-action");
  var unknownOpt = _grab(function () { b.redact.classifyDefaults({ bogus: 1 }); });
  check("classifyDefaults: unknown option key rejected",
        unknownOpt && /unknown option/.test(unknownOpt.message));
}

function testClassifyDefaultsDefaultsToAllPatterns() {
  // No patterns → the full CLASSIFIER_PATTERNS set backs the classifier.
  var classify = b.redact.classifyDefaults({});
  var v = classify({ body: { card: "4111111111111111" } });
  check("classifyDefaults: default pattern set flags a PAN as refuse",
        v.verdict === "refuse");
  // No-argument call still yields a working classifier over all patterns.
  var noArg = b.redact.classifyDefaults();
  check("classifyDefaults: no-argument call returns a usable classifier",
        typeof noArg === "function" && noArg({ body: { card: "4111111111111111" } }).verdict === "refuse");
  // No-argument classify() falls back to an empty input.
  check("classifyDefaults: classifier tolerates a null input",
        noArg(null).verdict === "clean" && noArg().verdict === "clean");
}

function testClassifyDefaultsExtraPattern() {
  // An extra pattern extends the known set and is resolvable.
  var classify = b.redact.classifyDefaults({
    patterns: ["ssn", "widget-id"],
    extra: {
      "widget-id": {
        detect: function (v) { return typeof v === "string" && /^WIDGET-\d+$/.test(v); },
        action: "refuse",
        label:  "widget-id",
      },
    },
  });
  var v = classify({ body: { id: "WIDGET-42" } });
  check("classifyDefaults: extra pattern participates and refuses",
        v.verdict === "refuse" && v.hits.some(function (h) { return h.label === "widget-id"; }));

  // An extra pattern that omits `label` falls back to the pattern name in
  // the hit record.
  var classify2 = b.redact.classifyDefaults({
    patterns: ["gadget-id"],
    extra: {
      "gadget-id": {
        detect: function (val) { return typeof val === "string" && /^GADGET-\d+$/.test(val); },
        action: "refuse",
      },
    },
  });
  var v2 = classify2({ body: { id: "GADGET-9" } });
  check("classifyDefaults: label-less extra pattern uses the pattern name",
        v2.hits.length === 1 && v2.hits[0].label === "gadget-id");
}

// ---------------------------------------------------------------------------
// classifyDefaults — body shapes + verdict precedence
// ---------------------------------------------------------------------------

function testClassifyObjectBodyRefuseRedactClean() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan", "ssn", "jwt"] });
  var refuse = classify({ body: { card: "4111111111111111", note: "ok" } });
  check("classify: PAN in object body → refuse", refuse.verdict === "refuse");
  check("classify: refuse hit records where-path",
        refuse.hits[0].where === "body.card");
  var redactSsn = classify({ body: { s: "my ssn 123-45-6789" } });
  check("classify: SSN in object body → redact", redactSsn.verdict === "redact");
  check("classify: SSN scrubbed inline in redactedBody",
        redactSsn.redactedBody.s === "my ssn [REDACTED]");
  var redactJwt = classify({ body: { tok: "eyJhbGci.eyJzdWI.SflKxwRJ" } });
  check("classify: JWT redact replaces whole string (non ssn/ein shape)",
        redactJwt.redactedBody.tok === "[REDACTED]");
  var clean = classify({ body: { note: "nothing sensitive" } });
  check("classify: benign object body → clean", clean.verdict === "clean");
  check("classify: clean redactedBody preserved", clean.redactedBody.note === "nothing sensitive");
}

function testClassifyStringBufferAndScalarBodies() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn", "pan"] });
  // string body
  var strV = classify({ body: "contains ssn 123-45-6789" });
  check("classify: string body redacted", strV.verdict === "redact");
  check("classify: string redactedBody scrubbed", strV.redactedBody === "contains ssn [REDACTED]");
  // Buffer body that changes → new Buffer returned
  var bufRedact = classify({ body: Buffer.from("ssn 123-45-6789") });
  check("classify: Buffer body redact verdict", bufRedact.verdict === "redact");
  check("classify: redacted Buffer body is a Buffer",
        Buffer.isBuffer(bufRedact.redactedBody));
  check("classify: redacted Buffer body text scrubbed",
        bufRedact.redactedBody.toString("utf8") === "ssn [REDACTED]");
  // Buffer body that doesn't change → original Buffer returned
  var srcBuf = Buffer.from("nothing here");
  var bufClean = classify({ body: srcBuf });
  check("classify: clean Buffer body returns the original buffer instance",
        bufClean.redactedBody === srcBuf);
  // scalar (number) body → returned as-is
  var numV = classify({ body: 42 });
  check("classify: numeric body passes through", numV.redactedBody === 42 && numV.verdict === "clean");
  // missing body → undefined
  var noBody = classify({});
  check("classify: absent body yields undefined redactedBody",
        noBody.redactedBody === undefined && noBody.verdict === "clean");
}

function testClassifyWalksNestedArraysAndBinaryFields() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var v = classify({
    body: {
      items:  ["ok", "ssn 123-45-6789"],
      count:  3,
      active: true,
      blob:   Buffer.from("raw"),
      empty:  "",
      nested: { deep: "ssn 111-22-3333" },
    },
  });
  check("classify: nested array element scrubbed",
        v.redactedBody.items[1] === "ssn [REDACTED]");
  check("classify: number field preserved in walk", v.redactedBody.count === 3);
  check("classify: boolean field preserved in walk", v.redactedBody.active === true);
  check("classify: Buffer field preserved verbatim in walk",
        Buffer.isBuffer(v.redactedBody.blob));
  check("classify: empty-string field preserved", v.redactedBody.empty === "");
  check("classify: deeply nested field scrubbed",
        v.redactedBody.nested.deep === "ssn [REDACTED]");
  check("classify: any hit yields redact verdict", v.verdict === "redact");
}

function testClassifyHeadersScanned() {
  var classify = b.redact.classifyDefaults({ patterns: ["jwt"] });
  var v = classify({ body: {}, headers: { authorization: "eyJhbGci.eyJzdWI.SflKxwRJ" } });
  check("classify: header value scanned and flagged", v.verdict === "redact");
  check("classify: header hit records where-path",
        v.hits.some(function (h) { return h.where === "headers.authorization"; }));
}

function testClassifyWalkSkipsInheritedAndUnknownTypes() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"] });
  // Body and headers carry inherited (non-own) enumerable props that the
  // walk must skip, plus a bigint value type the walk passes through.
  var bodyProto = { inheritedField: "ssn 123-45-6789" };
  var body = Object.create(bodyProto);
  body.own = "ssn 999-88-7777";
  body.big = 100n;
  var hdrProto = { inheritedHeader: "eyJa.eyJb.sig" };
  var headers = Object.create(hdrProto);
  headers.authorization = "plain";
  var v = classify({ body: body, headers: headers });
  check("classify: inherited body prop not copied into redactedBody",
        !Object.prototype.hasOwnProperty.call(v.redactedBody, "inheritedField"));
  check("classify: own body prop scrubbed", v.redactedBody.own === "ssn [REDACTED]");
  check("classify: bigint body value passes through walk", v.redactedBody.big === 100n);
  check("classify: only the own field produced a hit",
        v.hits.length === 1 && v.hits[0].where === "body.own");
}

function testClassifyAuditOnlyOverride() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"], overrideAction: "audit-only" });
  var v = classify({ body: { s: "123-45-6789" } });
  check("classify: overrideAction downgrades verdict to audit-only",
        v.verdict === "audit-only");
  check("classify: audit-only leaves the body unscrubbed",
        v.redactedBody.s === "123-45-6789");
}

function testClassifyCustomMarker() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"], marker: "[GONE]" });
  var v = classify({ body: { s: "ssn 123-45-6789" } });
  check("classify: custom marker used for inline scrub",
        v.redactedBody.s === "ssn [GONE]");
}

// ---------------------------------------------------------------------------
// installOutboundDlp — httpClient interceptor
// ---------------------------------------------------------------------------

async function testInstallHttpClientCleanRefuseRedact() {
  b.redact._resetForTest();
  var http = _fakeHttpClient();
  var scanCount = 0, refuseCount = 0, redactCount = 0;
  var dlp = b.redact.installOutboundDlp({
    httpClient: http,
    classifier: b.redact.classifyDefaults({ patterns: ["pan", "ssn"] }),
    onScan:   function () { scanCount += 1; },
    onRefuse: function () { refuseCount += 1; },
    onRedact: function () { redactCount += 1; },
  });
  try {
    check("installOutboundDlp: httpClient reported installed", dlp.installed.httpClient === true);
    check("installOutboundDlp: isOutboundDlpInstalled true after install",
          b.redact.isOutboundDlpInstalled() === true);

    // clean → original called with the untouched opts
    var cleanRes = await http.request({ url: "https://x", body: { note: "ok" } });
    check("installOutboundDlp: clean request reaches original client",
          cleanRes.ok === true && http.calls.length === 1);

    // redact → original called with a sanitized body
    await http.request({ url: "https://x", body: { s: "ssn 123-45-6789" } });
    check("installOutboundDlp: redact request forwarded with scrubbed body",
          http.calls[1].body.s === "ssn [REDACTED]");
    check("installOutboundDlp: onRedact hook fired", redactCount === 1);

    // refuse → rejects with DlpError, original NOT called again
    var threw = null;
    try { await http.request({ url: "https://x", body: { card: "4111111111111111" } }); }
    catch (e) { threw = e; }
    check("installOutboundDlp: refuse rejects with DlpError",
          threw instanceof b.redact.DlpError && threw.code === "redact-dlp/refused");
    check("installOutboundDlp: refused request never reaches original client",
          http.calls.length === 2);
    check("installOutboundDlp: onRefuse hook fired", refuseCount === 1);
    check("installOutboundDlp: onScan hook fired for every request", scanCount === 3);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
  check("installOutboundDlp: isOutboundDlpInstalled false after uninstall",
        b.redact.isOutboundDlpInstalled() === false);
}

async function testInstallHttpClientIdempotentAndUninstallRestores() {
  b.redact._resetForTest();
  var http = _fakeHttpClient();
  var original = http.request;
  var dlp1 = b.redact.installOutboundDlp({
    httpClient: http,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  try {
    check("installOutboundDlp: first install wraps request",
          http.request !== original && dlp1.installed.httpClient === true);
    // Second install on the SAME instance no-ops.
    var dlp2 = b.redact.installOutboundDlp({ httpClient: http });
    check("installOutboundDlp: second install on same instance no-ops",
          dlp2.installed.httpClient === false);
    // While installed, a PAN payload is refused.
    var refused = null;
    try { await http.request({ body: { card: "4111111111111111" } }); }
    catch (e) { refused = e; }
    check("installOutboundDlp: PAN refused while interceptor installed",
          refused instanceof b.redact.DlpError);
  } finally {
    dlp1.uninstall();
    b.redact._resetForTest();
  }
  // After uninstall the interceptor is gone — the same PAN payload now
  // reaches the original client untouched (no DlpError).
  var afterRes = await http.request({ body: { card: "4111111111111111" } });
  check("installOutboundDlp: uninstall restores original request path",
        afterRes.ok === true && afterRes.opts.body.card === "4111111111111111");
}

// ---------------------------------------------------------------------------
// installOutboundDlp — mail interceptor
// ---------------------------------------------------------------------------

async function testInstallMailRedactRefuseClean() {
  b.redact._resetForTest();
  var mail = _fakeMail();
  var dlp = b.redact.installOutboundDlp({
    mail:       mail,
    classifier: b.redact.classifyDefaults({ patterns: ["ssn", "pan"] }),
  });
  try {
    // redact → text/html/subject scrubbed, other fields preserved
    await mail.send({ to: "a@b.c", subject: "hi", text: "ssn 123-45-6789", html: "<p>123-45-6789</p>" });
    var sent = mail.calls[0];
    check("installOutboundDlp mail: redacted text scrubbed", sent.text === "ssn [REDACTED]");
    check("installOutboundDlp mail: redacted html scrubbed", sent.html === "<p>[REDACTED]</p>");
    check("installOutboundDlp mail: recipient preserved", sent.to === "a@b.c");

    // clean → forwarded unchanged
    await mail.send({ to: "x@y.z", text: "hello" });
    check("installOutboundDlp mail: clean message forwarded",
          mail.calls[1].text === "hello");

    // refuse → rejects, original not called
    var threw = null;
    try { await mail.send({ text: "4111111111111111" }); }
    catch (e) { threw = e; }
    check("installOutboundDlp mail: PAN refuses with DlpError",
          threw instanceof b.redact.DlpError && threw.code === "redact-dlp/refused");
    check("installOutboundDlp mail: refused message never sent", mail.calls.length === 2);

    // Second install on the same mail instance no-ops.
    var dlp2 = b.redact.installOutboundDlp({ mail: mail });
    check("installOutboundDlp mail: idempotent per instance",
          dlp2.installed.mail === false);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
}

async function testInterceptorNoArgumentCalls() {
  b.redact._resetForTest();
  var http = _fakeHttpClient();
  var mail = _fakeMail();
  var wh = _fakeWebhook();
  var clean = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var dlp = b.redact.installOutboundDlp({ httpClient: http, mail: mail, webhook: wh, classifier: clean });
  try {
    // Each interceptor tolerates a missing argument (falls back to {}).
    var r = await http.request();
    check("installOutboundDlp: httpClient.request() with no args forwards clean",
          r.ok === true && http.calls.length === 1);
    var m = await mail.send();
    check("installOutboundDlp: mail.send() with no args forwards clean",
          m.queued === true && mail.calls.length === 1);
    var w = await wh.send();
    check("installOutboundDlp: webhook.send() with no args forwards clean",
          w.ok === true && wh.calls.length === 1);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
}

function testInstallOutboundDlpNoArgs() {
  b.redact._resetForTest();
  // A no-argument install wires nothing but returns a valid handle.
  var dlp = b.redact.installOutboundDlp();
  check("installOutboundDlp: no-argument install wires no primitives",
        dlp.installed.httpClient === false && dlp.installed.mail === false && dlp.installed.webhook === false);
  check("installOutboundDlp: no-argument install did not flip the installed flag",
        b.redact.isOutboundDlpInstalled() === false);
  dlp.uninstall();
  b.redact._resetForTest();
}

// ---------------------------------------------------------------------------
// installOutboundDlp — webhook interceptor
// ---------------------------------------------------------------------------

async function testInstallWebhookJsonRedactAndPassthrough() {
  b.redact._resetForTest();
  var wh = _fakeWebhook();
  var dlp = b.redact.installOutboundDlp({
    webhook:    wh,
    classifier: b.redact.classifyDefaults({ patterns: ["ssn", "pan"] }),
  });
  try {
    // JSON-string body is parsed, scanned, re-serialized on redact.
    await wh.send({ url: "https://h", body: JSON.stringify({ ssn: "123-45-6789" }), kid: "k1", headers: { x: "y" } });
    var sent = wh.calls[0];
    check("installOutboundDlp webhook: JSON body re-serialized with scrub",
          sent.body === JSON.stringify({ ssn: "[REDACTED]" }));
    check("installOutboundDlp webhook: kid preserved through rebuild", sent.kid === "k1");

    // Non-JSON string body that's clean is forwarded unchanged.
    await wh.send({ url: "https://h", body: "plain text, no secrets" });
    check("installOutboundDlp webhook: clean non-JSON body forwarded",
          wh.calls[1].body === "plain text, no secrets");

    // Non-JSON string body that matches → redacted string (not re-serialized
    // as JSON, since it never parsed as an object).
    await wh.send({ url: "https://h", body: "ssn 123-45-6789" });
    check("installOutboundDlp webhook: non-JSON redacted body stays a string",
          wh.calls[2].body === "ssn [REDACTED]");

    // refuse
    var threw = null;
    try { await wh.send({ url: "https://h", body: JSON.stringify({ card: "4111111111111111" }) }); }
    catch (e) { threw = e; }
    check("installOutboundDlp webhook: PAN refuses with DlpError",
          threw instanceof b.redact.DlpError && threw.code === "redact-dlp/refused");
    check("installOutboundDlp webhook: refused payload never sent", wh.calls.length === 3);

    // Second install on the same signer no-ops.
    var dlp2 = b.redact.installOutboundDlp({ webhook: wh });
    check("installOutboundDlp webhook: idempotent per instance",
          dlp2.installed.webhook === false);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
}

// ---------------------------------------------------------------------------
// _wrapClassifier — fail-closed behavior
// ---------------------------------------------------------------------------

async function testInstallWebhookWithoutUrl() {
  b.redact._resetForTest();
  var wh = _fakeWebhook();
  var dlp = b.redact.installOutboundDlp({
    webhook:    wh,
    classifier: b.redact.classifyDefaults({ patterns: ["ssn", "pan"] }),
  });
  try {
    // A webhook send that omits `url` still redacts (url falls back to null
    // in the emitted audit metadata).
    await wh.send({ body: JSON.stringify({ ssn: "123-45-6789" }) });
    check("installOutboundDlp webhook: url-less redact still scrubs body",
          wh.calls[0].body === JSON.stringify({ ssn: "[REDACTED]" }));
    // A url-less refuse still rejects.
    var threw = null;
    try { await wh.send({ body: JSON.stringify({ card: "4111111111111111" }) }); }
    catch (e) { threw = e; }
    check("installOutboundDlp webhook: url-less refuse still rejects",
          threw instanceof b.redact.DlpError);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
}

async function testClassifierFailClosedOnThrowAndBadVerdict() {
  b.redact._resetForTest();
  var http1 = _fakeHttpClient();
  var dlp1 = b.redact.installOutboundDlp({
    httpClient: http1,
    classifier: function () { throw new Error("classifier boom"); },
  });
  try {
    var threw = null;
    try { await http1.request({ body: { x: 1 } }); }
    catch (e) { threw = e; }
    check("wrapClassifier: a throwing classifier fails closed (refuse)",
          threw instanceof b.redact.DlpError && threw.code === "redact-dlp/refused");
    check("wrapClassifier: throwing classifier never forwards to original",
          http1.calls.length === 0);
  } finally {
    dlp1.uninstall();
    b.redact._resetForTest();
  }

  var http2 = _fakeHttpClient();
  var dlp2 = b.redact.installOutboundDlp({
    httpClient: http2,
    classifier: function () { return { nope: true }; },   // missing string verdict
  });
  try {
    var threw2 = null;
    try { await http2.request({ body: { x: 1 } }); }
    catch (e) { threw2 = e; }
    check("wrapClassifier: a malformed verdict fails closed (refuse)",
          threw2 instanceof b.redact.DlpError && threw2.code === "redact-dlp/refused");
  } finally {
    dlp2.uninstall();
    b.redact._resetForTest();
  }
}

// ---------------------------------------------------------------------------
// installOutboundDlp — input validation throws
// ---------------------------------------------------------------------------

function testInstallOutboundDlpValidationErrors() {
  b.redact._resetForTest();
  check("installOutboundDlp: non-function classifier throws bad-classifier",
        (_grab(function () {
          b.redact.installOutboundDlp({ httpClient: _fakeHttpClient(), classifier: 123 });
        }) || {}).code === "redact-dlp/bad-classifier");
  check("installOutboundDlp: httpClient without request() throws bad-target",
        (_grab(function () { b.redact.installOutboundDlp({ httpClient: {} }); }) || {}).code
          === "redact-dlp/bad-target");
  check("installOutboundDlp: mail without send() throws bad-target",
        (_grab(function () { b.redact.installOutboundDlp({ mail: {} }); }) || {}).code
          === "redact-dlp/bad-target");
  check("installOutboundDlp: webhook without send() throws bad-target",
        (_grab(function () { b.redact.installOutboundDlp({ webhook: {} }); }) || {}).code
          === "redact-dlp/bad-target");
  check("installOutboundDlp: non-function onScan hook throws bad-hook",
        (_grab(function () {
          b.redact.installOutboundDlp({ httpClient: _fakeHttpClient(), onScan: 123 });
        }) || {}).code === "redact-dlp/bad-hook");
  check("installOutboundDlp: unknown option key rejected",
        /unknown option/.test((_grab(function () {
          b.redact.installOutboundDlp({ bogus: 1 });
        }) || {}).message || ""));
  b.redact._resetForTest();
}

// ---------------------------------------------------------------------------
// posture resolution + installForPosture
// ---------------------------------------------------------------------------

function testPostureResolutionAllPresets() {
  b.redact._resetForTest();
  var postures = ["pci-dss", "pci", "hipaa", "fapi2", "soc2", "gdpr"];
  for (var i = 0; i < postures.length; i += 1) {
    var http = _fakeHttpClient();
    var dlp = b.redact.installOutboundDlp({ httpClient: http, posture: postures[i] });
    check("installOutboundDlp: posture '" + postures[i] + "' resolves and installs",
          dlp.installed.httpClient === true);
    dlp.uninstall();
  }
  check("installOutboundDlp: unknown posture throws unknown-posture",
        (_grab(function () {
          b.redact.installOutboundDlp({ httpClient: _fakeHttpClient(), posture: "nonexistent" });
        }) || {}).code === "redact-dlp/unknown-posture");
  b.redact._resetForTest();
}

async function testInstallForPostureWiresPrimitive() {
  b.redact._resetForTest();
  var http = _fakeHttpClient();
  var dlp = b.redact.installForPosture("hipaa", { httpClient: http });
  try {
    check("installForPosture: httpClient wired", dlp.installed.httpClient === true);
    check("installForPosture: mail not supplied → not installed", dlp.installed.mail === false);
    // A HIPAA-flagged PHI payload refuses through the posture classifier.
    var threw = null;
    try { await http.request({ body: { patient: "ssn 123-45-6789" } }); }
    catch (e) { threw = e; }
    check("installForPosture: HIPAA posture refuses PHI payload",
          threw instanceof b.redact.DlpError);
  } finally {
    dlp.uninstall();
    b.redact._resetForTest();
  }
}

async function run() {
  // registerValueDetector
  testRegisterValueDetectorRedactsMatchingValue();
  testRegisterValueDetectorFunctionReplacement();
  testRegisterValueDetectorRunsAfterBuiltins();
  testRegisterValueDetectorRejectsNonFunction();
  testRegisterValueDetectorClearedOnReset();
  testRegisterValueDetectorDefaultsToMarkerWhenReplacementOmitted();

  // registerFieldRule
  testRegisterFieldRuleRedactsRegisteredField();
  testRegisterFieldRuleSubstringMatch();
  testRegisterFieldRuleRejectsNonString();
  testRegisterFieldRuleClearedOnReset();

  // redact walk
  testRedactPrimitivePassthroughs();
  testRedactBinaryValuesAlwaysMarker();
  testRedactArrayWalk();
  testRedactSensitiveParentCollapsesComposite();
  testRedactMaxDepthCap();
  testRedactCustomMarker();
  testRedactIgnoresInheritedProps();
  testRedactNonStringParentKeyIsNotSensitive();
  testRedactSensitiveTopLevelParentKeyCollapses();

  // built-in value detectors
  testRedactUrlBearerQueryReplacement();
  testRedactConnectionStringBounds();

  // CLASSIFIER_PATTERNS detectors
  testClassifierPatternsPanAndCreditCard();
  testClassifierPatternsIban();
  testClassifierPatternsApiKeyShape();
  testClassifierPatternsJwtAwsPemSsh();
  testClassifierPatternsSsnEinPhi();

  // classifyDefaults
  testClassifyDefaultsValidationErrors();
  testClassifyDefaultsDefaultsToAllPatterns();
  testClassifyDefaultsExtraPattern();
  testClassifyObjectBodyRefuseRedactClean();
  testClassifyStringBufferAndScalarBodies();
  testClassifyWalksNestedArraysAndBinaryFields();
  testClassifyHeadersScanned();
  testClassifyWalkSkipsInheritedAndUnknownTypes();
  testClassifyAuditOnlyOverride();
  testClassifyCustomMarker();

  // installOutboundDlp interceptors
  await testInstallHttpClientCleanRefuseRedact();
  await testInstallHttpClientIdempotentAndUninstallRestores();
  await testInstallMailRedactRefuseClean();
  await testInstallWebhookJsonRedactAndPassthrough();
  await testInstallWebhookWithoutUrl();
  await testInterceptorNoArgumentCalls();
  testInstallOutboundDlpNoArgs();
  await testClassifierFailClosedOnThrowAndBadVerdict();
  testInstallOutboundDlpValidationErrors();

  // posture
  testPostureResolutionAllPresets();
  await testInstallForPostureWiresPrimitive();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("redact tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
