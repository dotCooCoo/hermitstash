// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cdnCacheControl — RFC 9213 Targeted Cache-Control helper.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("cdnCacheControl.build is fn",  typeof b.cdnCacheControl.build === "function");
  check("cdnCacheControl.parse is fn",  typeof b.cdnCacheControl.parse === "function");
  check("cdnCacheControl.isTargetedHeader is fn",
        typeof b.cdnCacheControl.isTargetedHeader === "function");
  check("TARGETED_HEADERS is array",
        Array.isArray(b.cdnCacheControl.TARGETED_HEADERS) && b.cdnCacheControl.TARGETED_HEADERS.length > 0);
  check("BOOLEAN_DIRECTIVES is array",
        Array.isArray(b.cdnCacheControl.BOOLEAN_DIRECTIVES));
  check("NUMERIC_DIRECTIVES is array",
        Array.isArray(b.cdnCacheControl.NUMERIC_DIRECTIVES));
  check("CdnCacheControlError is a constructor",
        typeof b.cdnCacheControl.CdnCacheControlError === "function");
  // Exercise the error class directly so it round-trips a thrown
  // instance through `instanceof` for operators catching specific
  // shapes.
  var err;
  try { b.cdnCacheControl.build({}); } catch (e) { err = e; }
  check("CdnCacheControlError thrown shape",
        err instanceof b.cdnCacheControl.CdnCacheControlError);
}

function testBuild() {
  check("build: public + s-maxage + swr",
        b.cdnCacheControl.build({ public: true, sMaxAge: 3600, staleWhileRevalidate: 60 }) ===
          "public, s-maxage=3600, stale-while-revalidate=60");
  check("build: private + max-age=0 + no-store",
        b.cdnCacheControl.build({ private: true, maxAge: 0, noStore: true }) ===
          "private, max-age=0, no-store");
  check("build: kebab-case keys also accepted",
        b.cdnCacheControl.build({ "max-age": 60, "no-cache": true }) ===
          "max-age=60, no-cache");
  check("build: stale-if-error and immutable",
        b.cdnCacheControl.build({ maxAge: 3600, staleIfError: 86400, immutable: true }) ===
          "max-age=3600, stale-if-error=86400, immutable");

  // Extensions: bare token, token=token, token=number
  check("build: extensions bare token",
        b.cdnCacheControl.build({ maxAge: 60, extensions: { "x-foo": true } }) ===
          "max-age=60, x-foo");
  check("build: extensions token=value",
        b.cdnCacheControl.build({ maxAge: 60, extensions: { "x-foo": "bar" } }) ===
          "max-age=60, x-foo=bar");
}

function testBuildRefusals() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("build: null opts",
             function () { b.cdnCacheControl.build(null); }, "cdn-cache-control/bad-opts");
  expectCode("build: array opts",
             function () { b.cdnCacheControl.build([]); }, "cdn-cache-control/bad-opts");
  expectCode("build: empty opts",
             function () { b.cdnCacheControl.build({}); }, "cdn-cache-control/empty");
  expectCode("build: public + private conflict",
             function () { b.cdnCacheControl.build({ public: true, private: true }); }, "cdn-cache-control/conflicting-visibility");
  expectCode("build: negative max-age refused",
             function () { b.cdnCacheControl.build({ maxAge: -1 }); }, "cdn-cache-control/bad-numeric");
  expectCode("build: Infinity max-age refused",
             function () { b.cdnCacheControl.build({ maxAge: Infinity }); }, "cdn-cache-control/bad-numeric");
  expectCode("build: NaN max-age refused",
             function () { b.cdnCacheControl.build({ maxAge: NaN }); }, "cdn-cache-control/bad-numeric");
  expectCode("build: float max-age refused",
             function () { b.cdnCacheControl.build({ maxAge: 1.5 }); }, "cdn-cache-control/bad-numeric");
  expectCode("build: string boolean refused",
             function () { b.cdnCacheControl.build({ noStore: "yes" }); }, "cdn-cache-control/bad-boolean");
  expectCode("build: extension key with delimiter refused",
             function () { b.cdnCacheControl.build({ maxAge: 60, extensions: { "x;y": true } }); }, "cdn-cache-control/bad-extension-key");
  expectCode("build: extension value with delimiter refused",
             function () { b.cdnCacheControl.build({ maxAge: 60, extensions: { "x-foo": "ba,r" } }); }, "cdn-cache-control/bad-extension-value");
}

function testParse() {
  var r = b.cdnCacheControl.parse("public, s-maxage=3600, stale-while-revalidate=60");
  check("parse: public flag",   r.public === true);
  check("parse: sMaxAge number", r.sMaxAge === 3600);
  check("parse: swr number",    r.staleWhileRevalidate === 60);

  var r2 = b.cdnCacheControl.parse("private, no-store, x-foo=bar, x-flag");
  check("parse: private flag",  r2.private === true);
  check("parse: noStore flag",  r2.noStore === true);
  check("parse: extension value", r2.directives["x-foo"] === "bar");
  check("parse: extension flag",  r2.directives["x-flag"] === true);

  // Quoted-value tolerance (RFC 8941 §3.3.3 sf-string)
  var r3 = b.cdnCacheControl.parse('max-age="60"');
  check("parse: quoted numeric tolerated", r3.maxAge === 60);

  // Empty / null / non-string → null
  check("parse: empty → null",        b.cdnCacheControl.parse("") === null);
  check("parse: undefined → null",    b.cdnCacheControl.parse(undefined) === null);
  check("parse: non-string → null",   b.cdnCacheControl.parse(5) === null);
  check("parse: whitespace → null",   b.cdnCacheControl.parse("   ") === null);

  // Trailing semicolons / extra whitespace tolerance
  var r4 = b.cdnCacheControl.parse("  public ,  max-age=60  ");
  check("parse: tolerates surrounding whitespace",
        r4.public === true && r4.maxAge === 60);
}

function testParseQualifiedDirectives() {
  // RFC 9111 §5.2.2.6 — `private="Authorization"` is qualified-form:
  // the private directive is STILL enabled and applies ONLY to the
  // listed field-name list. A previous parse() implementation flipped
  // the flag to false when val was a non-empty string.
  var r = b.cdnCacheControl.parse('private="Authorization"');
  check("parse: private with field-name list still flagged true",
        r.private === true);
  check("parse: private surfaces field list under .fields.private",
        r.fields && Array.isArray(r.fields.private) && r.fields.private[0] === "authorization");

  // RFC 9111 §5.2.2.4 — `no-cache="Set-Cookie"` is qualified-form
  // too; the no-cache directive STAYS enabled, scoped to the listed
  // header field.
  var r2 = b.cdnCacheControl.parse('no-cache="Set-Cookie"');
  check("parse: no-cache with field-name list still flagged true",
        r2.noCache === true);
  check("parse: no-cache field list",
        r2.fields && r2.fields.noCache && r2.fields.noCache[0] === "set-cookie");

  // Quoted-value with INTERNAL comma must NOT split the directive.
  // `private="Authorization, Cookie", max-age=60` is two top-level
  // directives, with `private` carrying a 2-element field-name list.
  var r3 = b.cdnCacheControl.parse('private="Authorization, Cookie", max-age=60');
  check("parse: quoted comma preserved (top-level split count)",
        r3.private === true && r3.maxAge === 60);
  check("parse: quoted comma preserved (field-list count)",
        r3.fields.private.length === 2 &&
        r3.fields.private[0] === "authorization" &&
        r3.fields.private[1] === "cookie");

  // Extension directive carrying a quoted comma value: the comma is
  // value-internal, the directive remains a single piece.
  var r4 = b.cdnCacheControl.parse('foo="a,b", public');
  check("parse: extension quoted comma preserved",
        r4.public === true && r4.directives.foo === "a,b");
}

function testParseBareMaxStale() {
  // RFC 9111 §5.2.1.2 — `max-stale` without an argument means
  // "accept a stale response of ANY age". A previous parse()
  // implementation set val=true on the bare form and then ran
  // Number(true)===1, coercing the directive to "accept stale by up
  // to 1 second" which would reject otherwise-acceptable cached
  // responses.
  var r = b.cdnCacheControl.parse("max-stale");
  check("parse: bare max-stale → Infinity (RFC 9111 §5.2.1.2 any age)",
        r.maxStale === Infinity);
  check("parse: bare max-stale isFinite false",
        isFinite(r.maxStale) === false);

  // Sanity: max-stale=60 still parses normally.
  var r2 = b.cdnCacheControl.parse("max-stale=60");
  check("parse: max-stale=60 surfaces as 60",
        r2.maxStale === 60);
}

function testParseUnterminatedQuote() {
  // The quote-aware top-level splitter must drop the trailing piece
  // when the input ends mid-quoted-string (malformed header). Verifies
  // the inQuote-state-machine drops the unterminated tail implicitly
  // (the dead `if (!inQuote)` guard was removed in v0.9.0 — the
  // unterminated case never reaches the end-of-string branch because
  // the in-quote `continue` absorbs the sentinel).
  var r = b.cdnCacheControl.parse('public, foo="abc');
  check("parse: unterminated quote keeps only the well-formed top-level pieces",
        r.public === true);
  // No 'foo' directive should land in `.directives` since the trailing
  // piece was dropped without ever reaching the equals-split path.
  check("parse: unterminated quote — trailing piece dropped",
        r.directives && r.directives.foo === undefined);
}

function testParseControlByteRefusal() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("parse: CR/LF refused",
             function () { b.cdnCacheControl.parse("public\r\nattacker: x"); }, "cdn-cache-control/bad-header-value");
  expectCode("parse: leading \\n refused (pre-trim scan)",
             function () { b.cdnCacheControl.parse("\npublic"); }, "cdn-cache-control/bad-header-value");
  expectCode("parse: trailing \\r refused (pre-trim scan)",
             function () { b.cdnCacheControl.parse("public\r"); }, "cdn-cache-control/bad-header-value");
  expectCode("parse: NUL refused",
             function () { b.cdnCacheControl.parse("\x00public"); }, "cdn-cache-control/bad-header-value");
  expectCode("parse: DEL refused",
             function () { b.cdnCacheControl.parse("public\x7F"); }, "cdn-cache-control/bad-header-value");
  // HT permitted as folding whitespace
  check("parse: HT-wrapped tolerated",
        b.cdnCacheControl.parse("\tpublic\t").public === true);
}

function testIsTargetedHeader() {
  check("isTargetedHeader: CDN-Cache-Control",
        b.cdnCacheControl.isTargetedHeader("CDN-Cache-Control") === true);
  check("isTargetedHeader: lower-case",
        b.cdnCacheControl.isTargetedHeader("cdn-cache-control") === true);
  check("isTargetedHeader: Cloudflare-CDN-Cache-Control",
        b.cdnCacheControl.isTargetedHeader("Cloudflare-CDN-Cache-Control") === true);
  check("isTargetedHeader: Surrogate-Control",
        b.cdnCacheControl.isTargetedHeader("Surrogate-Control") === true);
  check("isTargetedHeader: Cache-Control",
        b.cdnCacheControl.isTargetedHeader("Cache-Control") === true);
  check("isTargetedHeader: unknown returns false",
        b.cdnCacheControl.isTargetedHeader("Cache") === false);
  check("isTargetedHeader: non-string returns false",
        b.cdnCacheControl.isTargetedHeader(null) === false);
  check("isTargetedHeader: empty returns false",
        b.cdnCacheControl.isTargetedHeader("") === false);
}

async function run() {
  testSurface();
  testBuild();
  testBuildRefusals();
  testParse();
  testParseQualifiedDirectives();
  testParseBareMaxStale();
  testParseUnterminatedQuote();
  testParseControlByteRefusal();
  testIsTargetedHeader();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
