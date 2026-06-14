"use strict";
/**
 * b.safeRedirect — open-redirect (CWE-601) defense for operator-supplied
 * post-login redirect targets.
 *
 * Run standalone: `node test/layer-0-primitives/safe-redirect.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function testSurface() {
  check("b.safeRedirect is object",            typeof b.safeRedirect === "object");
  check("b.safeRedirect.resolve is fn",        typeof b.safeRedirect.resolve === "function");
  check("b.safeRedirect.DEFAULT_FALLBACK",     b.safeRedirect.DEFAULT_FALLBACK === "/");
}

function testRelativeAndFragmentTargets() {
  check("relative path is same-origin safe",
        b.safeRedirect.resolve("/dashboard", { fallback: "/x" }) === "/dashboard");
  check("query-only target is safe",
        b.safeRedirect.resolve("?q=1", { fallback: "/x" }) === "?q=1");
  check("fragment target is safe",
        b.safeRedirect.resolve("#section", { fallback: "/x" }) === "#section");
}

function testHostileTargetsFallBack() {
  check("protocol-relative // → fallback",
        b.safeRedirect.resolve("//attacker.example.com", { fallback: "/safe" }) === "/safe");
  check("backslash-relative \\\\ → fallback",
        b.safeRedirect.resolve("\\\\attacker.example.com", { fallback: "/safe" }) === "/safe");
  check("control char → fallback",
        b.safeRedirect.resolve("/a\nb", { fallback: "/safe" }) === "/safe");
  check("empty target → fallback",
        b.safeRedirect.resolve("", { fallback: "/safe" }) === "/safe");
  check("full URL with no allowlist → fallback",
        b.safeRedirect.resolve("https://attacker.example.com/x", { fallback: "/safe" }) === "/safe");
}

function testAllowedOriginsAndHosts() {
  check("full URL matching allowedOrigins passes",
        b.safeRedirect.resolve("https://app.example.com/next",
          { allowedOrigins: ["https://app.example.com"], fallback: "/safe" })
        === "https://app.example.com/next");
  check("full URL not in allowedOrigins → fallback",
        b.safeRedirect.resolve("https://evil.example.com/x",
          { allowedOrigins: ["https://app.example.com"], fallback: "/safe" })
        === "/safe");
  check("full URL matching allowedHosts passes",
        b.safeRedirect.resolve("https://app.example.com/next",
          { allowedHosts: ["app.example.com"], fallback: "/safe" })
        === "https://app.example.com/next");
}

// ---- base wiring (opts.base is the app's own origin) ----

function testBaseOriginImplicitlyAllowed() {
  // A full URL on the same origin as base is same-origin by definition,
  // so it passes even without an explicit allowedOrigins / allowedHosts.
  check("full URL on base origin allowed via base alone",
        b.safeRedirect.resolve("https://app.example.com/dashboard",
          { base: "https://app.example.com", fallback: "/safe" })
        === "https://app.example.com/dashboard");

  // A cross-origin full URL is still refused when only base is supplied.
  check("cross-origin full URL refused with base only",
        b.safeRedirect.resolve("https://attacker.example.com/x",
          { base: "https://app.example.com", fallback: "/safe" })
        === "/safe");

  // base combines with allowedOrigins (both are accepted).
  check("base origin allowed alongside allowedOrigins",
        b.safeRedirect.resolve("https://app.example.com/y",
          { base: "https://app.example.com",
            allowedOrigins: ["https://other.example.com"], fallback: "/safe" })
        === "https://app.example.com/y");

  // A different port is a different origin → refused.
  check("base origin port mismatch refused",
        b.safeRedirect.resolve("https://app.example.com:8443/x",
          { base: "https://app.example.com", fallback: "/safe" })
        === "/safe");
}

function testBaseDefaultBehaviorUnchanged() {
  // No base + no allowlist → full URLs still refused (default safe).
  check("no base, no allowlist → full URL fallback",
        b.safeRedirect.resolve("https://app.example.com/x", { fallback: "/safe" }) === "/safe");

  // Relative paths are unaffected by base.
  check("relative path safe regardless of base",
        b.safeRedirect.resolve("/home", { base: "https://app.example.com", fallback: "/safe" })
        === "/home");

  // A malformed / non-http(s) base is ignored (no crash, falls through
  // to refuse the full URL with no other allowlist).
  check("malformed base ignored → full URL fallback",
        b.safeRedirect.resolve("https://app.example.com/x",
          { base: "not a url", fallback: "/safe" })
        === "/safe");
}

function run() {
  testSurface();
  testRelativeAndFragmentTargets();
  testHostileTargetsFallBack();
  testAllowedOriginsAndHosts();
  testBaseOriginImplicitlyAllowed();
  testBaseDefaultBehaviorUnchanged();
  console.log("OK — safe-redirect tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
