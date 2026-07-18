// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Case-insensitive security-token bypass class.
//
// A browser / HTTP stack / URL parser matches a whole family of security-
// relevant tokens ASCII case-INSENSITIVELY: CSP source keywords
// ('unsafe-inline' / 'unsafe-eval' / 'unsafe-hashes'), CSP scheme sources
// (https: / data:), cookie name prefixes (__Secure- / __Host-), the https
// scheme of a report-collector URL, and origin/host allowlist entries. A
// framework guard that compares such a token case-SENSITIVELY lets a
// case-variant slip past — the bypass direction leaks an unsafe value the
// browser still honors (b.csp.build emitting an unsafe keyword, b.cookies /
// csrf-protect accepting a prefix-violating cookie the browser then drops),
// and the over-strict direction silently refuses a spec-compliant value
// (b.middleware.nel rejecting HTTPS://, b.safeRedirect never matching a
// mixed-case operator allowlist). Every root is the same: normalize the token
// to ASCII lowercase before the membership / equality / prefix test.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function _code(fn) { try { fn(); return null; } catch (e) { return e.code || e.message; } }

// ---- CSP: unsafe keyword case variants must be refused ----
function testCspUnsafeKeywordCaseVariants() {
  // Baseline: exact-case guard already fires.
  check("csp.build refuses exact 'unsafe-inline'",
    _code(function () { b.csp.build({ "script-src": ["'self'", "'unsafe-inline'"] }); }) === "csp/unsafe-keyword");

  // Case variants a browser treats identically must ALSO be refused.
  check("csp.build refuses 'Unsafe-Inline' (mixed case)",
    _code(function () { b.csp.build({ "script-src": ["'self'", "'Unsafe-Inline'"] }); }) === "csp/unsafe-keyword");
  check("csp.build refuses 'UNSAFE-INLINE' (upper case)",
    _code(function () { b.csp.build({ "script-src": ["'self'", "'UNSAFE-INLINE'"] }); }) === "csp/unsafe-keyword");
  check("csp.build refuses 'UNSAFE-EVAL' (upper case)",
    _code(function () { b.csp.build({ "script-src": ["'self'", "'UNSAFE-EVAL'"] }); }) === "csp/unsafe-keyword");
  check("csp.build refuses 'Unsafe-Hashes' (mixed case)",
    _code(function () { b.csp.build({ "script-src": ["'self'", "'Unsafe-Hashes'"] }); }) === "csp/unsafe-keyword");

  // The emitted policy must NEVER carry an unsafe keyword in any case when the
  // caller didn't acknowledge it (direct proof the value isn't reaching the wire).
  var leaked = null;
  try { leaked = b.csp.build({ "script-src": ["'self'", "'Unsafe-Inline'"] }); }
  catch (_e) { leaked = null; }
  check("csp.build does not emit a case-variant unsafe keyword",
    leaked === null || !/unsafe-inline/i.test(leaked));
}

// ---- CSP: catch-all scheme case variants must be refused ----
function testCspCatchAllSchemeCaseVariants() {
  check("csp.build refuses exact 'https:' catch-all",
    _code(function () { b.csp.build({ "img-src": ["https:"] }); }) === "csp/catch-all-source");
  check("csp.build refuses 'HTTPS:' catch-all (upper)",
    _code(function () { b.csp.build({ "img-src": ["HTTPS:"] }); }) === "csp/catch-all-source");
  check("csp.build refuses 'Https:' catch-all (mixed)",
    _code(function () { b.csp.build({ "connect-src": ["Https:"] }); }) === "csp/catch-all-source");

  // A real host that merely starts with HTTPS must still be accepted (no
  // over-broad false positive from the lowercase compare).
  var ok = _code(function () { b.csp.build({ "img-src": ["https://Example.com/Path"] }); });
  check("csp.build still accepts a real https host with mixed-case authority", ok === null);
}

// ---- CSP: data: scheme case variants must be refused in img/media/font ----
function testCspDataSchemeCaseVariants() {
  check("csp.build refuses exact 'data:' in img-src",
    _code(function () { b.csp.build({ "img-src": ["'self'", "data:"] }); }) === "csp/data-source");
  check("csp.build refuses 'DATA:' in img-src (upper)",
    _code(function () { b.csp.build({ "img-src": ["'self'", "DATA:"] }); }) === "csp/data-source");
  check("csp.build refuses 'Data:' in font-src (mixed)",
    _code(function () { b.csp.build({ "font-src": ["Data:"] }); }) === "csp/data-source");

  // Opt-in still works for a case variant.
  var policy = b.csp.build({ "img-src": ["'self'", "DATA:"] }, { allowDataImages: true });
  check("csp.build accepts case-variant data: with allowDataImages",
    /img-src 'self' DATA:/.test(policy));
}

// ---- CSP: mergeDirectives routes added sources through the same guard ----
function testCspMergeCaseVariants() {
  check("mergeDirectives refuses a case-variant unsafe keyword in an added source",
    _code(function () { b.csp.mergeDirectives(undefined, { "script-src": ["'UNSAFE-INLINE'"] }); }) === "csp/unsafe-keyword");
  check("mergeDirectives refuses a case-variant catch-all scheme in an added source",
    _code(function () { b.csp.mergeDirectives(undefined, { "img-src": ["HTTPS:"] }); }) === "csp/catch-all-source");
}

// ---- Cookies: __Host- / __Secure- prefix invariants are case-insensitive ----
function testCookieHostPrefixCaseVariants() {
  // Baseline: exact-case guard fires.
  check("serialize refuses __Host- without Secure (exact)",
    _code(function () { b.cookies.serialize("__Host-sid", "x", { secure: false, path: "/" }); }) === "cookies/prefix-host-secure-required");

  // A browser enforces __host- (any case) as the Host prefix. A cookie without
  // Secure / with Domain / without Path=/ must be refused for EVERY case.
  check("serialize refuses __host- without Secure (lower)",
    _code(function () { b.cookies.serialize("__host-sid", "x", { secure: false, path: "/" }); }) === "cookies/prefix-host-secure-required");
  check("serialize refuses __HOST- with Domain (upper)",
    _code(function () { b.cookies.serialize("__HOST-sid", "x", { secure: true, path: "/", domain: "example.com" }); }) === "cookies/prefix-host-no-domain");
  check("serialize refuses __Host- (mixed) without Path=/",
    _code(function () { b.cookies.serialize("__hOsT-sid", "x", { secure: true, path: "/app" }); }) === "cookies/prefix-host-path-required");

  // Direct proof: no case-variant __host- cookie is ever emitted without Secure.
  var leaked = null;
  try { leaked = b.cookies.serialize("__host-sid", "x", { secure: false, path: "/" }); }
  catch (_e) { leaked = null; }
  check("serialize never emits a Secure-less __host- cookie",
    leaked === null || /;\s*Secure/i.test(leaked));
}

function testCookieSecurePrefixCaseVariants() {
  check("serialize refuses __Secure- without Secure (exact)",
    _code(function () { b.cookies.serialize("__Secure-x", "x", { secure: false }); }) === "cookies/prefix-secure-required");
  check("serialize refuses __SECURE- without Secure (upper)",
    _code(function () { b.cookies.serialize("__SECURE-x", "x", { secure: false }); }) === "cookies/prefix-secure-required");
  check("serialize refuses __secure- without Secure (lower)",
    _code(function () { b.cookies.serialize("__secure-x", "x", { secure: false }); }) === "cookies/prefix-secure-required");

  // A correctly-formed case-variant __secure- cookie still serializes.
  var ok = _code(function () { b.cookies.serialize("__secure-x", "x", { secure: true }); });
  check("serialize accepts a well-formed case-variant __secure- cookie", ok === null);
}

// ---- csrf-protect: cookie name-prefix invariants are case-insensitive ----
// csrf-protect builds its OWN Set-Cookie header (not via b.cookies.serialize),
// so this boot check is the only enforcement point for its cookie name.
function testCsrfProtectPrefixCaseVariants() {
  // Baseline: exact-case __Host- fires on a bad path.
  check("csrfProtect refuses __Host- with a non-root path (exact)",
    /path='\/'/.test(String(_code(function () {
      b.middleware.csrfProtect({ cookie: { name: "__Host-csrf", path: "/app" } });
    }))));

  // A browser enforces __host-/__secure- (any case). A case-variant name with a
  // path/Secure violation must be refused, not silently emitted then dropped.
  check("csrfProtect refuses __host- (lower) with a non-root path",
    /path='\/'/.test(String(_code(function () {
      b.middleware.csrfProtect({ cookie: { name: "__host-csrf", path: "/app" } });
    }))));
  check("csrfProtect refuses __HOST- (upper) with explicit secure:false",
    /requires secure/.test(String(_code(function () {
      b.middleware.csrfProtect({ cookie: { name: "__HOST-csrf", path: "/", secure: false } });
    }))));
  check("csrfProtect refuses __secure- (lower) with explicit secure:false",
    /__Secure-\* cookie name requires secure/.test(String(_code(function () {
      b.middleware.csrfProtect({ cookie: { name: "__secure-csrf", secure: false } });
    }))));
  check("csrfProtect refuses __Secure- (exact) with explicit secure:false",
    /__Secure-\* cookie name requires secure/.test(String(_code(function () {
      b.middleware.csrfProtect({ cookie: { name: "__Secure-csrf", secure: false } });
    }))));

  // A well-formed case-variant name still builds (no over-strict false positive).
  check("csrfProtect accepts a well-formed __host- name (lower, path=/, secure)",
    _code(function () { b.middleware.csrfProtect({ cookie: { name: "__host-csrf", path: "/", secure: true } }); }) === null);
}

// ---- nel: the collector-URL https scheme is matched case-insensitively ----
function testNelCollectorSchemeCaseVariants() {
  // A compliant HTTPS:// (RFC 3986 scheme is case-insensitive) must be accepted.
  check("nel accepts HTTPS:// collector (upper scheme)",
    _code(function () { b.middleware.nel({ collectorUrl: "HTTPS://collector.example/r" }); }) === null);
  check("nel accepts HttpS:// collector (mixed scheme)",
    _code(function () { b.middleware.nel({ collectorUrl: "HttpS://collector.example/r" }); }) === null);

  // A genuine non-secure scheme is still refused in every case.
  check("nel refuses http:// collector (insecure, lower)",
    /must be https/.test(String(_code(function () { b.middleware.nel({ collectorUrl: "http://collector.example/r" }); }))));
  check("nel refuses HTTP:// collector (insecure, upper)",
    /must be https/.test(String(_code(function () { b.middleware.nel({ collectorUrl: "HTTP://collector.example/r" }); }))));
}

// ---- safe-redirect: operator origin/host allowlist is case-insensitive ----
function testSafeRedirectAllowlistCaseVariants() {
  var FB = "/fallback";

  // A mixed-case operator allowlist entry must match the (lowercased)
  // parsed origin/host, not silently fall through to the fallback.
  check("safeRedirect matches a mixed-case allowedHosts entry",
    b.safeRedirect.resolve("https://example.com/next", { allowedHosts: ["Example.COM"], fallback: FB }) === "https://example.com/next");
  check("safeRedirect matches a mixed-case allowedOrigins entry",
    b.safeRedirect.resolve("https://example.com/next", { allowedOrigins: ["HTTPS://Example.com"], fallback: FB }) === "https://example.com/next");

  // Baseline exact-case entry still matches.
  check("safeRedirect matches an exact-case allowedHosts entry",
    b.safeRedirect.resolve("https://example.com/next", { allowedHosts: ["example.com"], fallback: FB }) === "https://example.com/next");

  // An unlisted host is still refused (the lowercase compare does not widen
  // the allowlist — attacker rawTarget is already normalized by the parser).
  check("safeRedirect still refuses an unlisted host",
    b.safeRedirect.resolve("https://evil.example/x", { allowedHosts: ["example.com"], fallback: FB }) === FB);
  check("safeRedirect still refuses a host that is not in a mixed-case allowlist",
    b.safeRedirect.resolve("https://evil.example/x", { allowedHosts: ["Example.COM"], fallback: FB }) === FB);
}

function run() {
  testCspUnsafeKeywordCaseVariants();
  testCspCatchAllSchemeCaseVariants();
  testCspDataSchemeCaseVariants();
  testCspMergeCaseVariants();
  testCookieHostPrefixCaseVariants();
  testCookieSecurePrefixCaseVariants();
  testCsrfProtectPrefixCaseVariants();
  testNelCollectorSchemeCaseVariants();
  testSafeRedirectAllowlistCaseVariants();
}

if (require.main === module) {
  var before = helpers.getChecks();
  try { run(); console.log("OK — case-insensitive security-token guard — " + (helpers.getChecks() - before) + " checks"); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
