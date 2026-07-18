// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

var asn1 = require("../../lib/asn1-der");

// Inject resolvers so the posture tests aren't sensitive to whatever
// framework state happens to be initialized in the fork.
function _resolvers(vaultMode, dbAtRest, auditMode) {
  return {
    vault:        function () { return vaultMode; },
    dbAtRest:     function () { return dbAtRest; },
    auditSigning: function () { return auditMode; },
  };
}

// A fully production-clean opts base. Each targeted branch test layers a
// single failing condition on top so the resulting `failures` set stays
// deterministic:
//   - clean resolvers (vault/db/audit all pass)
//   - ntpStrict off  (no BLAMEJS_NTP_STRICT env dependence)
//   - forbidNodeEnv off (no NODE_ENV env dependence)
//   - allowDpiTrust on  (skip the global trust-store read)
function _cleanBase(overrides) {
  var base = {
    resolvers:     _resolvers("wrapped", "encrypted", "wrapped"),
    ntpStrict:     false,
    forbidNodeEnv: false,
    allowDpiTrust: true,
  };
  if (overrides) {
    Object.keys(overrides).forEach(function (k) { base[k] = overrides[k]; });
  }
  return base;
}

function _hasCode(err, code) {
  return !!(err && Array.isArray(err.failures) &&
    err.failures.some(function (f) { return f.code === code; }));
}

// Minimal structurally-valid self-signed X.509 for exercising the
// DPI-trust-installed assertion. Not a mock of a shared helper — the
// framework ships no cert-synth fixture; this builds one DER cert so
// b.network.tls.addCa populates the real trust store.
function _synthCaPem(cn) {
  var algId    = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cnrdn    = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, Buffer.from(cn, "ascii"))]);
  var name     = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("260101000000Z", "ascii")),
    asn1.writeNode(0x17, Buffer.from("270101000000Z", "ascii")),
  ]);
  var spki     = asn1.writeSequence([algId,
    asn1.writeNode(0x03, Buffer.concat([Buffer.from([0]), Buffer.from("k-bytes-aaaaaaaaaaaaaaaaaaaaaaaa")]))]);
  var version  = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbs      = asn1.writeSequence([version, asn1.writeInteger(Buffer.from([0x12, 0x34])),
    algId, name, validity, name, spki]);
  var der      = asn1.writeSequence([tbs, algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
  return "-----BEGIN CERTIFICATE-----\n" +
    der.toString("base64").replace(/(.{64})/g, "$1\n") +
    "\n-----END CERTIFICATE-----\n";
}

// ---- Core verdicts: clean pass, single/aggregate fail, opt-out ----
async function _testCoreVerdicts() {
  check("security namespace present",        typeof b.security === "object");
  check("security.assertProduction is fn",   typeof b.security.assertProduction === "function");
  check("b.security.SecurityAssertError is a class",  typeof b.security.SecurityAssertError === "function");
  check("b.security.DEFAULT_RESOLVERS is frozen obj",
        b.security.DEFAULT_RESOLVERS && Object.isFrozen(b.security.DEFAULT_RESOLVERS));

  var prevNtp = process.env.BLAMEJS_NTP_STRICT;
  delete process.env.BLAMEJS_NTP_STRICT;
  try {
    // Production-clean posture passes.
    var passThrew = null;
    try {
      await b.security.assertProduction({ resolvers: _resolvers("wrapped", "encrypted", "wrapped") });
    } catch (e) { passThrew = e; }
    check("clean production posture: no throw", passThrew === null);

    // Dev posture (plaintext vault) fails on the first assertion.
    var devThrew = null;
    try {
      await b.security.assertProduction({ resolvers: _resolvers("plaintext", "encrypted", "wrapped") });
    } catch (e) { devThrew = e; }
    check("plaintext vault: throws SecurityAssertError",
          devThrew && devThrew.isSecurityAssertError === true);
    check("plaintext vault: is instanceof SecurityAssertError",
          devThrew instanceof b.security.SecurityAssertError);
    check("plaintext vault: failures array", Array.isArray(devThrew.failures) && devThrew.failures.length === 1);
    check("plaintext vault: code mentions vault", /vault/.test(devThrew.failures[0].code));
    // The thrown error's operator-facing .message carries the full
    // multi-line diagnostic; .code is the short stable token.
    check("aggregated throw: .code is ASSERT_FAILED", devThrew.code === "ASSERT_FAILED");
    check("aggregated throw: .message carries the diagnostic",
          /production security policy failed/.test(devThrew.message));
    check("aggregated throw: .message lists the failing code",
          /security\/vault-mismatch/.test(devThrew.message));
    check("aggregated throw: permanent flag set", devThrew.permanent === true);

    // Multiple failures aggregate.
    var multiThrew = null;
    try {
      await b.security.assertProduction({ resolvers: _resolvers("plaintext", "plain", "plaintext") });
    } catch (e) { multiThrew = e; }
    check("triple failure: 3 failures aggregated", multiThrew && multiThrew.failures.length === 3);

    // BLAMEJS_NTP_STRICT=0 fails when ntpStrict assertion is on (default).
    process.env.BLAMEJS_NTP_STRICT = "0";
    var ntpThrew = null;
    try {
      await b.security.assertProduction({ resolvers: _resolvers("wrapped", "encrypted", "wrapped") });
    } catch (e) { ntpThrew = e; }
    check("BLAMEJS_NTP_STRICT=0: throws", ntpThrew !== null);
    check("BLAMEJS_NTP_STRICT=0: code references ntp", _hasCode(ntpThrew, "security/ntp-strict-disabled"));

    // BLAMEJS_NTP_STRICT="false" also trips the same assertion.
    process.env.BLAMEJS_NTP_STRICT = "false";
    var ntpFalseThrew = null;
    try {
      await b.security.assertProduction({ resolvers: _resolvers("wrapped", "encrypted", "wrapped") });
    } catch (e) { ntpFalseThrew = e; }
    check("BLAMEJS_NTP_STRICT=false: also trips ntp assertion", _hasCode(ntpFalseThrew, "security/ntp-strict-disabled"));

    // Clear the ntp env before the remaining opt-out checks so it doesn't
    // leak a spurious ntp failure into them.
    delete process.env.BLAMEJS_NTP_STRICT;

    // Operator extra: passes / fails.
    var extraOk = null;
    try {
      await b.security.assertProduction(_cleanBase({ extra: [function () { return { ok: true }; }] }));
    } catch (e) { extraOk = e; }
    check("extra:[ok] does not throw", extraOk === null);

    var extraFail = null;
    try {
      await b.security.assertProduction(_cleanBase({
        extra: [function () { return { ok: false, code: "wiki/x", message: "missing" }; }],
      }));
    } catch (e) { extraFail = e; }
    check("extra:[fail] throws aggregated", extraFail && extraFail.failures.length === 1);
    check("extra:[fail] preserves code", extraFail.failures[0].code === "wiki/x");

    // Operator can opt out of an assertion (vault: false).
    var optOut = null;
    try {
      await b.security.assertProduction({ vault: false, resolvers: _resolvers("plaintext", "encrypted", "wrapped") });
    } catch (e) { optOut = e; }
    check("vault:false opts out of plaintext check", optOut === null);

    // Operator explicitly restates each posture target (exercises the
    // opts-supplied side of every posture-default ternary).
    var explicitTargets = null;
    try {
      await b.security.assertProduction({
        resolvers:    _resolvers("wrapped", "encrypted", "wrapped"),
        vault:        "wrapped",
        dbAtRest:     "encrypted",
        auditSigning: "wrapped",
        ntpStrict:    false, forbidNodeEnv: false, allowDpiTrust: true,
      });
    } catch (e) { explicitTargets = e; }
    check("explicit posture targets matching resolvers: no throw", explicitTargets === null);

    // Operator restates a target the resolver does NOT meet → mismatch.
    var explicitMismatch = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "plain", "wrapped"),
        dbAtRest:  "encrypted",
        ntpStrict: false, forbidNodeEnv: false, allowDpiTrust: true,
      });
    } catch (e) { explicitMismatch = e; }
    check("explicit dbAtRest target vs plain resolver: dbAtRest-mismatch",
          _hasCode(explicitMismatch, "security/dbAtRest-mismatch"));
  } finally {
    if (prevNtp === undefined) delete process.env.BLAMEJS_NTP_STRICT;
    else process.env.BLAMEJS_NTP_STRICT = prevNtp;
  }
}

// ---- DEFAULT_RESOLVERS: exercise the built-in resolver dispatch ----
async function _testDefaultResolvers() {
  var prevNtp = process.env.BLAMEJS_NTP_STRICT;
  delete process.env.BLAMEJS_NTP_STRICT;
  try {
    // No `resolvers` override → the frozen DEFAULT_RESOLVERS fire against
    // the real framework instance (vault().getMode(), db().getAtRestMode(),
    // auditSign().getMode()). We don't assert the outcome — a fresh fork's
    // default posture may be plaintext (→ throws) or wrapped (→ passes) —
    // only that the built-in resolver dispatch runs to completion.
    var threw = null;
    try {
      await b.security.assertProduction({ allowDpiTrust: true });
    } catch (e) { threw = e; }
    check("DEFAULT_RESOLVERS dispatch completes (pass or SecurityAssertError)",
          threw === null || threw instanceof b.security.SecurityAssertError);

    // Called with NO opts at all → opts defaults to {} and the full
    // default posture runs against the live framework. Outcome is
    // environment-dependent; we only assert the call is well-formed.
    var noArgThrew = null;
    try { await b.security.assertProduction(); } catch (e) { noArgThrew = e; }
    check("assertProduction() with no opts: runs to a defined verdict",
          noArgThrew === null || noArgThrew instanceof b.security.SecurityAssertError);

    // Partial override: only vault is injected → dbAtRest + auditSigning
    // still resolve via DEFAULT_RESOLVERS.
    var partialThrew = null;
    try {
      await b.security.assertProduction({
        allowDpiTrust: true,
        ntpStrict:     false,
        vault:         false,
        auditSigning:  false,
        resolvers:     { dbAtRest: function () { return "encrypted"; } },
      });
    } catch (e) { partialThrew = e; }
    check("partial resolver override: dbAtRest default replaced, still runs",
          partialThrew === null || partialThrew instanceof b.security.SecurityAssertError);
  } finally {
    if (prevNtp === undefined) delete process.env.BLAMEJS_NTP_STRICT;
    else process.env.BLAMEJS_NTP_STRICT = prevNtp;
  }
}

// ---- Resolver that throws → resolver-failed verdict (_check catch) ----
async function _testResolverThrows() {
  var threw = null;
  try {
    await b.security.assertProduction(_cleanBase({
      resolvers: {
        vault:        function () { throw new Error("kaboom"); },
        dbAtRest:     function () { return "encrypted"; },
        auditSigning: function () { return "wrapped"; },
      },
    }));
  } catch (e) { threw = e; }
  check("resolver throw: raises SecurityAssertError", threw instanceof b.security.SecurityAssertError);
  check("resolver throw: code is vault-resolver-failed", _hasCode(threw, "security/vault-resolver-failed"));
  check("resolver throw: message carries the thrown text",
        threw && threw.failures.some(function (f) { return /kaboom/.test(f.message); }));

  // A resolver that throws a non-Error (no .message) still produces a
  // clean resolver-failed verdict via String(e).
  var stringThrew = null;
  try {
    await b.security.assertProduction(_cleanBase({
      resolvers: {
        vault:        function () { throw "plain-string-fault"; },  // eslint-disable-line no-throw-literal
        dbAtRest:     function () { return "encrypted"; },
        auditSigning: function () { return "wrapped"; },
      },
    }));
  } catch (e) { stringThrew = e; }
  check("resolver throws non-Error: still resolver-failed", _hasCode(stringThrew, "security/vault-resolver-failed"));
  check("resolver throws non-Error: String(e) captured in message",
        stringThrew && stringThrew.failures.some(function (f) { return /plain-string-fault/.test(f.message); }));
}

// ---- requireTLS opt-in tightening ----
async function _testRequireTls() {
  // No protocol / non-https → fail.
  var noProto = null;
  try { await b.security.assertProduction(_cleanBase({ requireTLS: true })); }
  catch (e) { noProto = e; }
  check("requireTLS + no protocol: fails tls-required", _hasCode(noProto, "security/tls-required"));

  var httpProto = null;
  try { await b.security.assertProduction(_cleanBase({ requireTLS: true, protocol: "http" })); }
  catch (e) { httpProto = e; }
  check("requireTLS + http: fails tls-required", _hasCode(httpProto, "security/tls-required"));

  // protocol https → passes.
  var httpsOk = null;
  try { await b.security.assertProduction(_cleanBase({ requireTLS: true, protocol: "https" })); }
  catch (e) { httpsOk = e; }
  check("requireTLS + https: no throw", httpsOk === null);
}

// ---- require* middleware introspection ----
async function _testRequireMiddleware() {
  // No router but a require* flag set → router-introspection-missing.
  var noRouter = null;
  try { await b.security.assertProduction(_cleanBase({ requireCSRF: true })); }
  catch (e) { noRouter = e; }
  check("requireCSRF + no router: router-introspection-missing",
        _hasCode(noRouter, "security/router-introspection-missing"));

  // Router present but nothing mounted → one middleware-missing per flag.
  var emptyRouter = { _mounted: [] };
  var missing = null;
  try {
    await b.security.assertProduction(_cleanBase({
      requireCSPNonce: true, requireCSRF: true, requireRateLimit: true, router: emptyRouter,
    }));
  } catch (e) { missing = e; }
  check("empty router: three middleware-missing failures",
        missing && missing.failures.filter(function (f) { return f.code === "security/middleware-missing"; }).length === 3);
  check("empty router: message names b.middleware.cspNonce",
        missing && missing.failures.some(function (f) { return /b\.middleware\.cspNonce/.test(f.message); }));

  // Router with all three mounted (case-insensitive match) → passes.
  // A nameless mounted entry is tolerated (name coalesces to "").
  var fullRouter = { _mounted: [{ name: "CSPNonce" }, {}, { name: "csrfProtect" }, { name: "RateLimit" }] };
  var allMounted = null;
  try {
    await b.security.assertProduction(_cleanBase({
      requireCSPNonce: true, requireCSRF: true, requireRateLimit: true, router: fullRouter,
    }));
  } catch (e) { allMounted = e; }
  check("router with all middleware mounted: no throw", allMounted === null);
}

// ---- CORS allow-all detection (independent of require* flags) ----
async function _testCorsAllowAll() {
  var wildcard = { _mounted: [{ name: "cors", opts: { origins: "*" } }] };
  var wildThrew = null;
  try { await b.security.assertProduction(_cleanBase({ router: wildcard })); }
  catch (e) { wildThrew = e; }
  check("cors origins:'*' : fails cors-allow-all", _hasCode(wildThrew, "security/cors-allow-all"));

  // CORS mounted with a concrete origin → no cors failure. A nameless
  // sibling entry must not break the scan (name coalesces to "").
  var scoped = { _mounted: [{}, { name: "cors", opts: { origins: "https://app.example" } }] };
  var scopedThrew = null;
  try { await b.security.assertProduction(_cleanBase({ router: scoped })); }
  catch (e) { scopedThrew = e; }
  check("cors scoped origin: no cors-allow-all", scopedThrew === null);

  // Router without cors mounted → no cors failure.
  var noCors = { _mounted: [{ name: "logger" }] };
  var noCorsThrew = null;
  try { await b.security.assertProduction(_cleanBase({ router: noCors })); }
  catch (e) { noCorsThrew = e; }
  check("router without cors: no cors-allow-all", noCorsThrew === null);
}

// ---- minNodeMajor floor ----
async function _testMinNodeMajor() {
  // Impossibly-high floor → node-version failure.
  var tooLow = null;
  try { await b.security.assertProduction(_cleanBase({ minNodeMajor: 9999 })); }
  catch (e) { tooLow = e; }
  check("minNodeMajor:9999 : fails node-version", _hasCode(tooLow, "security/node-version"));

  // Explicit low floor the running node satisfies → passes.
  var okFloor = null;
  try { await b.security.assertProduction(_cleanBase({ minNodeMajor: 4 })); }
  catch (e) { okFloor = e; }
  check("minNodeMajor:4 : no throw on current node", okFloor === null);

  // Opt out with false → check skipped entirely.
  var optOut = null;
  try { await b.security.assertProduction(_cleanBase({ minNodeMajor: false })); }
  catch (e) { optOut = e; }
  check("minNodeMajor:false : opts out, no throw", optOut === null);
}

// ---- minTlsVersion vocabulary + rank compare ----
async function _testMinTlsVersion() {
  var nodeTls = require("node:tls");

  // Typo'd required version → config-time TypeError (not an aggregated failure).
  var typoErr = null;
  try { await b.security.assertProduction(_cleanBase({ minTlsVersion: "TLSv1.4" })); }
  catch (e) { typoErr = e; }
  check("minTlsVersion typo: throws TypeError", typoErr instanceof TypeError);
  check("minTlsVersion typo: message names the bad value",
        typoErr && /TLSv1\.4/.test(typoErr.message));

  // Require exactly the active floor → passes.
  var got = nodeTls.DEFAULT_MIN_VERSION;
  var atFloor = null;
  try { await b.security.assertProduction(_cleanBase({ minTlsVersion: got })); }
  catch (e) { atFloor = e; }
  check("minTlsVersion == active floor: no throw", atFloor === null);

  // Require a version ABOVE the active floor → tls-min-version failure.
  // The framework boots TLS 1.3-only, so the live floor is already the
  // maximum; temporarily lower the shared floor to a recognized value so
  // the rank compare (active < required) fires deterministically. This is
  // exactly the posture the assertion guards: a runtime whose TLS floor
  // sits below the operator's production requirement.
  var origFloor = nodeTls.DEFAULT_MIN_VERSION;
  try {
    nodeTls.DEFAULT_MIN_VERSION = "TLSv1.2";
    var belowThrew = null;
    try { await b.security.assertProduction(_cleanBase({ minTlsVersion: "TLSv1.3" })); }
    catch (e) { belowThrew = e; }
    check("minTlsVersion above active floor: fails tls-min-version", _hasCode(belowThrew, "security/tls-min-version"));
    check("minTlsVersion above active floor: message names both versions",
          belowThrew && belowThrew.failures.some(function (f) {
            return /is 'TLSv1\.2', required 'TLSv1\.3'/.test(f.message);
          }));
  } finally {
    nodeTls.DEFAULT_MIN_VERSION = origFloor;
  }

  // Defensive branch: Node's DEFAULT_MIN_VERSION drifts outside the known
  // vocabulary (future node / monkeypatched runtime) → surfaced, not
  // silently treated as "below". Temporarily perturb the shared tls object.
  var orig = nodeTls.DEFAULT_MIN_VERSION;
  try {
    nodeTls.DEFAULT_MIN_VERSION = "TLSbogus";
    var driftThrew = null;
    try { await b.security.assertProduction(_cleanBase({ minTlsVersion: "TLSv1.2" })); }
    catch (e) { driftThrew = e; }
    check("unrecognized node tls floor: surfaced as tls-min-version",
          _hasCode(driftThrew, "security/tls-min-version"));
    check("unrecognized node tls floor: message flags the bad value",
          driftThrew && driftThrew.failures.some(function (f) { return /unrecognized value 'TLSbogus'/.test(f.message); }));
  } finally {
    nodeTls.DEFAULT_MIN_VERSION = orig;
  }
}

// ---- requireEnv presence ----
async function _testRequireEnv() {
  var missingKey = "BLAMEJS_ASSERT_TEST_MISSING_XYZ";
  var prev = process.env[missingKey];
  delete process.env[missingKey];
  try {
    var threw = null;
    try {
      // Mix an empty string and a non-string to exercise the skip path,
      // plus the genuinely-missing key that must fail.
      await b.security.assertProduction(_cleanBase({ requireEnv: ["", 123, missingKey] }));
    } catch (e) { threw = e; }
    check("requireEnv missing var: fails env-missing", _hasCode(threw, "security/env-missing"));
    check("requireEnv: exactly one failure (empty + non-string skipped)",
          threw && threw.failures.length === 1);

    // Now set it → passes.
    process.env[missingKey] = "present";
    var okThrew = null;
    try { await b.security.assertProduction(_cleanBase({ requireEnv: [missingKey] })); }
    catch (e) { okThrew = e; }
    check("requireEnv set var: no throw", okThrew === null);
  } finally {
    if (prev === undefined) delete process.env[missingKey];
    else process.env[missingKey] = prev;
  }
}

// ---- forbidEnv (string form + {key,value} form) ----
async function _testForbidEnv() {
  var sKey = "BLAMEJS_ASSERT_TEST_FORBIDDEN";
  var kvKey = "BLAMEJS_ASSERT_TEST_KV";
  var prevS = process.env[sKey];
  var prevKv = process.env[kvKey];
  try {
    // String form: var present at all → forbidden.
    process.env[sKey] = "anything";
    var sThrew = null;
    try { await b.security.assertProduction(_cleanBase({ forbidEnv: [sKey] })); }
    catch (e) { sThrew = e; }
    check("forbidEnv string form: fails env-forbidden", _hasCode(sThrew, "security/env-forbidden"));

    // String form: var absent → passes.
    delete process.env[sKey];
    var sAbsent = null;
    try { await b.security.assertProduction(_cleanBase({ forbidEnv: [sKey] })); }
    catch (e) { sAbsent = e; }
    check("forbidEnv string form, var absent: no throw", sAbsent === null);

    // Object form: forbid only when value matches.
    process.env[kvKey] = "bad";
    var kvMatch = null;
    try { await b.security.assertProduction(_cleanBase({ forbidEnv: [{ key: kvKey, value: "bad" }] })); }
    catch (e) { kvMatch = e; }
    check("forbidEnv {key,value} match: fails env-forbidden-value", _hasCode(kvMatch, "security/env-forbidden-value"));

    // Object form: value does NOT match → passes.
    process.env[kvKey] = "fine";
    var kvNoMatch = null;
    try { await b.security.assertProduction(_cleanBase({ forbidEnv: [{ key: kvKey, value: "bad" }] })); }
    catch (e) { kvNoMatch = e; }
    check("forbidEnv {key,value} non-match: no throw", kvNoMatch === null);
  } finally {
    if (prevS === undefined) delete process.env[sKey]; else process.env[sKey] = prevS;
    if (prevKv === undefined) delete process.env[kvKey]; else process.env[kvKey] = prevKv;
  }
}

// ---- forbidNodeEnv pinning ----
async function _testForbidNodeEnv() {
  var prev = process.env.NODE_ENV;
  try {
    // Default forbidden list ["development","dev","test"].
    process.env.NODE_ENV = "test";
    var defThrew = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, allowDpiTrust: true,
      });
    } catch (e) { defThrew = e; }
    check("NODE_ENV=test with default forbid list: fails node-env-forbidden",
          _hasCode(defThrew, "security/node-env-forbidden"));

    // Custom forbid list — value not in the operator's list → passes.
    process.env.NODE_ENV = "staging";
    var customOk = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, allowDpiTrust: true,
        forbidNodeEnv: ["development", "dev"],
      });
    } catch (e) { customOk = e; }
    check("NODE_ENV=staging with custom list: no throw", customOk === null);

    // Custom list that DOES contain the value → fails.
    var customThrew = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, allowDpiTrust: true,
        forbidNodeEnv: ["staging"],
      });
    } catch (e) { customThrew = e; }
    check("NODE_ENV=staging in custom list: fails node-env-forbidden",
          _hasCode(customThrew, "security/node-env-forbidden"));

    // Opt out entirely with forbidNodeEnv:false → skipped even with a
    // forbidden NODE_ENV present.
    process.env.NODE_ENV = "test";
    var optOut = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, allowDpiTrust: true, forbidNodeEnv: false,
      });
    } catch (e) { optOut = e; }
    check("forbidNodeEnv:false : opts out, no throw", optOut === null);
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev;
  }
}

// ---- extra validation + async execution ----
async function _testExtraValidation() {
  // Non-array extra → config-time throw.
  var notArray = null;
  try { await b.security.assertProduction(_cleanBase({ extra: "nope" })); }
  catch (e) { notArray = e; }
  check("extra not an array: throws SecurityAssertError", notArray instanceof b.security.SecurityAssertError);
  check("extra not an array: BAD_OPT code", notArray && notArray.code === "BAD_OPT");
  check("extra not an array: message describes the fault",
        notArray && /opts\.extra must be an array/.test(notArray.message));

  // Non-function element → config-time throw.
  var notFn = null;
  try { await b.security.assertProduction(_cleanBase({ extra: [123] })); }
  catch (e) { notFn = e; }
  check("extra[0] not a function: throws SecurityAssertError", notFn instanceof b.security.SecurityAssertError);
  check("extra[0] not a function: BAD_OPT code", notFn && notFn.code === "BAD_OPT");
  check("extra[0] not a function: message names index", notFn && /extra\[0\]/.test(notFn.message));

  // Extra that throws → aggregated as extra-threw (not a hard throw).
  var extraThrew = null;
  try {
    await b.security.assertProduction(_cleanBase({
      extra: [function () { throw new Error("assert-boom"); }],
    }));
  } catch (e) { extraThrew = e; }
  check("extra throws: aggregated as extra-threw", _hasCode(extraThrew, "security/extra-threw"));
  check("extra throws: message carries thrown text",
        extraThrew && extraThrew.failures.some(function (f) { return /assert-boom/.test(f.message); }));

  // Extra that throws a non-Error (no .message) → String(e) fallback.
  var extraThrewStr = null;
  try {
    await b.security.assertProduction(_cleanBase({
      extra: [function () { throw "raw-extra-fault"; }],  // eslint-disable-line no-throw-literal
    }));
  } catch (e) { extraThrewStr = e; }
  check("extra throws non-Error: String(e) captured",
        extraThrewStr && extraThrewStr.failures.some(function (f) { return /raw-extra-fault/.test(f.message); }));

  // Async extra returning not-ok WITHOUT a code → default extra-failed code.
  var noCode = null;
  try {
    await b.security.assertProduction(_cleanBase({
      extra: [async function () { return { ok: false }; }],
    }));
  } catch (e) { noCode = e; }
  check("extra async not-ok without code: default extra-failed", _hasCode(noCode, "security/extra-failed"));

  // Extra returning a non-object falsy verdict → treated as failed.
  var falsy = null;
  try {
    await b.security.assertProduction(_cleanBase({ extra: [function () { return undefined; }] }));
  } catch (e) { falsy = e; }
  check("extra returns undefined: treated as extra-failed", _hasCode(falsy, "security/extra-failed"));
}

// ---- audit emission (pass + fail outcomes, injected + default sink) ----
async function _testAuditEmit() {
  // Injected sink, clean posture → success event, no throw.
  var captured = [];
  var fakeSink = { safeEmit: function (rec) { captured.push(rec); } };
  var okThrew = null;
  try { await b.security.assertProduction(_cleanBase({ audit: fakeSink })); }
  catch (e) { okThrew = e; }
  check("audit sink + clean posture: no throw", okThrew === null);
  check("audit sink: success event emitted",
        captured.length === 1 && captured[0].action === "system.security.assert.success");
  check("audit sink: success outcome", captured.length === 1 && captured[0].outcome === "success");
  check("audit sink: metadata.failureCount is 0",
        captured.length === 1 && captured[0].metadata && captured[0].metadata.failureCount === 0);

  // Injected sink, failing posture → failure event emitted THEN throws.
  var captured2 = [];
  var fakeSink2 = { safeEmit: function (rec) { captured2.push(rec); } };
  var failThrew = null;
  try {
    await b.security.assertProduction(_cleanBase({
      audit: fakeSink2,
      extra: [function () { return { ok: false, code: "wiki/x", message: "m" }; }],
    }));
  } catch (e) { failThrew = e; }
  check("audit sink + failing posture: throws", failThrew instanceof b.security.SecurityAssertError);
  check("audit sink: failure event emitted",
        captured2.length === 1 && captured2[0].action === "system.security.assert.failure");
  check("audit sink: failedCodes lists the failure",
        captured2.length === 1 && captured2[0].metadata.failedCodes.indexOf("wiki/x") !== -1);

  // A sink whose safeEmit throws must not break the assert (best-effort).
  var throwingSink = { safeEmit: function () { throw new Error("sink down"); } };
  var sinkThrewSwallowed = null;
  try { await b.security.assertProduction(_cleanBase({ audit: throwingSink })); }
  catch (e) { sinkThrewSwallowed = e; }
  check("audit sink that throws is swallowed: no throw", sinkThrewSwallowed === null);

  // audit:true → default framework sink (audit()) path (drop-silent).
  var defaultSink = null;
  try { await b.security.assertProduction(_cleanBase({ audit: true })); }
  catch (e) { defaultSink = e; }
  check("audit:true default sink path: no throw", defaultSink === null);

  // audit:false → auditing skipped entirely (auditOn short-circuits).
  var offThrew = null;
  try { await b.security.assertProduction(_cleanBase({ audit: false })); }
  catch (e) { offThrew = e; }
  check("audit:false : auditing skipped, no throw", offThrew === null);

  // audit omitted (undefined) on a failing posture → no emit, still throws.
  var noAuditThrew = null;
  try {
    await b.security.assertProduction(_cleanBase({
      extra: [function () { return { ok: false, code: "x/y", message: "m" }; }],
    }));
  } catch (e) { noAuditThrew = e; }
  check("audit omitted + failing posture: throws without an audit sink",
        noAuditThrew instanceof b.security.SecurityAssertError);
}

// ---- forbidProxy: refuse outbound proxy in production ----
async function _testForbidProxy() {
  var proxy = b.network.proxy;
  proxy._resetForTest();
  try {
    // No proxy configured + forbidProxy:true → passes.
    var noProxyThrew = null;
    try { await b.security.assertProduction(_cleanBase({ forbidProxy: true })); }
    catch (e) { noProxyThrew = e; }
    check("forbidProxy + no proxy set: no throw", noProxyThrew === null);

    // Proxy configured + forbidProxy:true → outbound-proxy-set failure.
    proxy.set({ http: "http://127.0.0.1:8080", https: "http://127.0.0.1:8443" });
    var proxyThrew = null;
    try { await b.security.assertProduction(_cleanBase({ forbidProxy: true })); }
    catch (e) { proxyThrew = e; }
    check("forbidProxy + proxy set: fails outbound-proxy-set", _hasCode(proxyThrew, "security/outbound-proxy-set"));

    // Same proxy state but forbidProxy NOT set → block skipped, no failure.
    var noFlagThrew = null;
    try { await b.security.assertProduction(_cleanBase({})); }
    catch (e) { noFlagThrew = e; }
    check("proxy set but forbidProxy off: no outbound-proxy-set", noFlagThrew === null);
  } finally {
    proxy._resetForTest();
  }
}

// ---- allowDpiTrust: refuse runtime-installed CAs in production ----
async function _testDpiTrust() {
  var tls = b.network.tls;
  tls._resetForTest();
  try {
    // Empty trust store, default (allowDpiTrust off) → no dpi failure.
    var emptyThrew = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, forbidNodeEnv: false,
      });
    } catch (e) { emptyThrew = e; }
    check("empty trust store: no dpi-trust-installed", emptyThrew === null);

    // Install a CA at runtime → the default policy refuses boot.
    tls.addCa(_synthCaPem("Prod Posture Test CA"), { label: "dpi-test" });
    check("precondition: trust store has the installed CA", tls.getTrustStore().length === 1);

    var dpiThrew = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, forbidNodeEnv: false,
      });
    } catch (e) { dpiThrew = e; }
    check("runtime CA + default policy: fails dpi-trust-installed", _hasCode(dpiThrew, "security/dpi-trust-installed"));

    // Same state but allowDpiTrust:true → operator opt-in bypasses the check.
    var allowThrew = null;
    try {
      await b.security.assertProduction({
        resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
        ntpStrict: false, forbidNodeEnv: false, allowDpiTrust: true,
      });
    } catch (e) { allowThrew = e; }
    check("runtime CA + allowDpiTrust:true : no dpi failure", allowThrew === null);
  } finally {
    tls._resetForTest();
  }
}

// ---- dataDir mode check (POSIX-only; win32 skips silently) ----
async function _testDataDir() {
  if (process.platform === "win32") {
    // The dataDir permission block short-circuits on win32 — passing a
    // dataDir here must be a silent no-op, never a stat/permission failure.
    var winThrew = null;
    try { await b.security.assertProduction(_cleanBase({ dataDir: "C:/some/data/dir", maxDataDirMode: 0o750 })); }
    catch (e) { winThrew = e; }
    check("dataDir on win32: skipped silently (no throw)", winThrew === null);
    return;
  }
  // POSIX: a non-existent dataDir cannot be stat'd → datadir-stat-failed.
  var statThrew = null;
  try { await b.security.assertProduction(_cleanBase({ dataDir: "/no/such/blamejs/datadir/xyz" })); }
  catch (e) { statThrew = e; }
  check("dataDir stat failure: fails datadir-stat-failed", _hasCode(statThrew, "security/datadir-stat-failed"));
}

async function run() {
  await _testCoreVerdicts();
  await _testDefaultResolvers();
  await _testResolverThrows();
  await _testRequireTls();
  await _testRequireMiddleware();
  await _testCorsAllowAll();
  await _testMinNodeMajor();
  await _testMinTlsVersion();
  await _testRequireEnv();
  await _testForbidEnv();
  await _testForbidNodeEnv();
  await _testExtraValidation();
  await _testAuditEmit();
  await _testForbidProxy();
  await _testDpiTrust();
  await _testDataDir();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[security-assert] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
