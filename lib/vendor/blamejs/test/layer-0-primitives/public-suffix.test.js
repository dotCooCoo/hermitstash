"use strict";
/**
 * b.publicSuffix — Mozilla PSL substrate.
 *
 * Covers the lookup algorithm against the vendored
 * lib/vendor/public-suffix-list.dat: exact match, wildcard rules,
 * exception rules, IDN normalization, organizational-domain
 * derivation across registry depths, and input-shape rejects.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testExactMatch() {
  check("publicSuffix('example.com') = 'com'",
        b.publicSuffix.publicSuffix("example.com") === "com");
  check("publicSuffix('foo.example.com') = 'com'",
        b.publicSuffix.publicSuffix("foo.example.com") === "com");
  check("publicSuffix('example.co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("example.co.uk") === "co.uk");
  check("publicSuffix('a.b.example.co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("a.b.example.co.uk") === "co.uk");
  // Multi-label rules from the PSL private section.
  check("publicSuffix('example.s3.amazonaws.com') = 's3.amazonaws.com'",
        b.publicSuffix.publicSuffix("example.s3.amazonaws.com") === "s3.amazonaws.com");
}

function testInputItselfIsPublicSuffix() {
  // Input that IS a public suffix returns itself for publicSuffix().
  check("publicSuffix('co.uk') = 'co.uk'",
        b.publicSuffix.publicSuffix("co.uk") === "co.uk");
  check("publicSuffix('com') = 'com'",
        b.publicSuffix.publicSuffix("com") === "com");
}

function testWildcardRule() {
  // The PSL has `*.ck` — every `<label>.ck` is a public suffix.
  // For `foo.bar.ck`, suffix is `bar.ck` (wildcard ate one extra label).
  check("publicSuffix('foo.bar.ck') = 'bar.ck' (wildcard)",
        b.publicSuffix.publicSuffix("foo.bar.ck") === "bar.ck");
}

function testExceptionRule() {
  // `!www.ck` overrides the `*.ck` wildcard — `www.ck` itself is
  // registrable. The public suffix is `ck`.
  check("publicSuffix('www.ck') = 'ck' (exception)",
        b.publicSuffix.publicSuffix("www.ck") === "ck");
  check("publicSuffix('foo.www.ck') = 'ck' (exception parent)",
        b.publicSuffix.publicSuffix("foo.www.ck") === "ck");
}

function testIdn() {
  // Non-ASCII input punycodes via UTS #46 before lookup. `münchen.de`
  // — `de` is the public suffix (registrable below it).
  check("publicSuffix('münchen.de') = 'de'",
        b.publicSuffix.publicSuffix("münchen.de") === "de");
  // Punycode form of the same input — same answer.
  check("publicSuffix('xn--mnchen-3ya.de') = 'de'",
        b.publicSuffix.publicSuffix("xn--mnchen-3ya.de") === "de");
}

function testTrailingDot() {
  // A single trailing dot (FQDN form) is stripped before lookup.
  check("publicSuffix('example.com.') = 'com'",
        b.publicSuffix.publicSuffix("example.com.") === "com");
}

function testOrganizationalDomain() {
  check("orgDomain('foo.bar.example.co.uk') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("foo.bar.example.co.uk") === "example.co.uk");
  check("orgDomain('example.co.uk') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("example.co.uk") === "example.co.uk");
  check("orgDomain('example.com') = 'example.com'",
        b.publicSuffix.organizationalDomain("example.com") === "example.com");
  check("orgDomain('foo.bar.example.com') = 'example.com'",
        b.publicSuffix.organizationalDomain("foo.bar.example.com") === "example.com");
  // Input IS a public suffix → no organizational domain exists.
  check("orgDomain('co.uk') = null",
        b.publicSuffix.organizationalDomain("co.uk") === null);
  check("orgDomain('com') = null",
        b.publicSuffix.organizationalDomain("com") === null);
  // Wildcard depth: `bar.ck` is the suffix, `example.bar.ck` is the orgdomain.
  check("orgDomain('foo.example.bar.ck') = 'example.bar.ck'",
        b.publicSuffix.organizationalDomain("foo.example.bar.ck") === "example.bar.ck");
}

function testIsPublicSuffix() {
  check("isPublicSuffix('com') = true",
        b.publicSuffix.isPublicSuffix("com") === true);
  check("isPublicSuffix('co.uk') = true",
        b.publicSuffix.isPublicSuffix("co.uk") === true);
  check("isPublicSuffix('example.com') = false",
        b.publicSuffix.isPublicSuffix("example.com") === false);
  check("isPublicSuffix('example.co.uk') = false",
        b.publicSuffix.isPublicSuffix("example.co.uk") === false);
  // Multi-label private-section rule.
  check("isPublicSuffix('s3.amazonaws.com') = true",
        b.publicSuffix.isPublicSuffix("s3.amazonaws.com") === true);
}

function testInvalidInput() {
  var threw, err;

  threw = false;
  try { b.publicSuffix.publicSuffix(null); }
  catch (e) { threw = true; err = e; }
  check("null input throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix(""); }
  catch (e) { threw = true; err = e; }
  check("empty string throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix(123); }
  catch (e) { threw = true; err = e; }
  check("non-string throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo..bar"); }
  catch (e) { threw = true; err = e; }
  check("empty label throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo\x00.com"); }
  catch (e) { threw = true; err = e; }
  check("null byte throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  threw = false;
  try { b.publicSuffix.publicSuffix("foo bar.com"); }
  catch (e) { threw = true; err = e; }
  check("whitespace byte throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");

  // 254-char input exceeds RFC 1035 cap.
  var tooLong = new Array(252).join("a") + ".co";
  threw = false;
  try { b.publicSuffix.publicSuffix(tooLong); }
  catch (e) { threw = true; err = e; }
  check("253-octet overflow throws invalid-domain",
        threw && err.code === "public-suffix/invalid-domain");
}

function testLookupSource() {
  var src = b.publicSuffix.lookupSource();
  check("lookupSource returns object",
        src && typeof src === "object");
  check("lookupSource.entries > 1000",
        typeof src.entries === "number" && src.entries > 1000);
  check("lookupSource.sha256 is 64-hex",
        typeof src.sha256 === "string" && /^[0-9a-f]{64}$/.test(src.sha256));
  check("lookupSource.vendoredAt is a string",
        typeof src.vendoredAt === "string" && src.vendoredAt.length > 0);
  // Frozen so callers can't mutate the framework-internal cache.
  // Either a throw (strict-mode + frozen) or a no-op (non-strict
  // ignore) is acceptable; the invariant is "the cached value didn't
  // change". We swallow the throw and re-fetch.
  try { src.entries = 0; }
  catch (_e) { /* frozen-mutation rejection is the success path */ }
  check("lookupSource is frozen (mutation no-op)",
        b.publicSuffix.lookupSource().entries === src.entries &&
        b.publicSuffix.lookupSource().entries > 1000);
}

function testCaseInsensitive() {
  check("publicSuffix('EXAMPLE.CO.UK') = 'co.uk'",
        b.publicSuffix.publicSuffix("EXAMPLE.CO.UK") === "co.uk");
  check("orgDomain('EXAMPLE.CO.UK') = 'example.co.uk'",
        b.publicSuffix.organizationalDomain("EXAMPLE.CO.UK") === "example.co.uk");
}

async function run() {
  testExactMatch();
  testInputItselfIsPublicSuffix();
  testWildcardRule();
  testExceptionRule();
  testIdn();
  testTrailingDot();
  testOrganizationalDomain();
  testIsPublicSuffix();
  testInvalidInput();
  testLookupSource();
  testCaseInsensitive();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
