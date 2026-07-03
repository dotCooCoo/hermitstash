// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeUrl.canonicalize — URL/host canonicalizer for safe comparison and
 * SSRF-allowlist defense.
 *
 * Every obfuscated spelling of one destination must reduce to one string so a
 * host allowlist / dedup key / SSRF pre-check compares equal. The adversarial
 * cases below are the exact shapes an attacker reaches for to slip a naive
 * `===` allowlist: IPv4 in octal / hex / decimal-int / shorthand, IPv4-mapped
 * and zero-compressed IPv6, IDN homographs, trailing-dot and default-port and
 * case variations, and over-encoded path bytes.
 *
 * Source-discipline: NO attack characters are typed as literals. The one
 * mixed-script case is expressed as its already-encoded punycode A-label
 * (`xn--ggle-55da.com`, same fixture the homograph suite uses) so this file
 * stays pure ASCII.
 */

var b     = require("../..");
var check = require("../helpers/check").check;

// ---- Equivalence classes: obfuscated loopback collapses to one string ----

function testIpv4LoopbackEquivalenceClass() {
  // Decimal-dotted, octal, hex-word, decimal-int, and shorthand spellings of
  // 127.0.0.1 — in the OLD world (raw string compare, no canonicalizer) every
  // pair below compared UNEQUAL, so an allowlist of "127.0.0.1" let them all
  // through. canonicalize collapses them to one form.
  var forms = [
    "http://127.0.0.1/",
    "http://0177.0.0.1/",      // octal first octet
    "http://0x7f.1/",          // hex octet + shorthand
    "http://0x7f000001/",      // single hex dword
    "http://2130706433/",      // single decimal dword
    "http://127.1/",           // a.d shorthand
  ];
  var expected = "http://127.0.0.1/";
  for (var i = 0; i < forms.length; i += 1) {
    var got = b.safeUrl.canonicalize(forms[i]);
    check("ipv4 loopback form '" + forms[i] + "' canonicalizes to " + expected,
          got === expected);
    // The pairwise equality the allowlist actually relies on.
    check("ipv4 loopback '" + forms[i] + "' === canonical '127.0.0.1' form",
          b.safeUrl.canonicalize(forms[i]) === b.safeUrl.canonicalize(forms[0]));
    // Prove the test is meaningful: the RAW strings were NOT equal.
    if (forms[i] !== forms[0]) {
      check("raw '" + forms[i] + "' !== raw canonical (old-world bypass shape)",
            forms[i] !== forms[0]);
    }
  }
}

function testIpv6MappedEquivalenceClass() {
  // An IPv4-mapped IPv6 address (::ffff:a.b.c.d, the ::ffff:0:0/96 block) IS
  // the IPv4 address a.b.c.d for routing / access-control: a dual-stack peer
  // arriving on ::ffff:1.2.3.4 reaches the same host as 1.2.3.4, and the SSRF
  // classifier already re-classifies it by the embedded v4. So the canonical
  // form must FOLD it to the IPv4 dotted form — otherwise a dual-stack peer
  // never unifies with an operator's IPv4 allowlist entry (the exact bypass).
  var mappedForms = [
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[0:0:0:0:0:ffff:7f00:1]/",
    "http://[0:0:0:0:0:FFFF:7F00:1]/",   // mixed-case hex
  ];
  var bareV4 = b.safeUrl.canonicalize("http://127.0.0.1/");
  check("plain IPv4 canonical is the dotted form", bareV4 === "http://127.0.0.1/");
  for (var i = 0; i < mappedForms.length; i += 1) {
    check("ipv4-mapped '" + mappedForms[i] + "' folds to the bare IPv4 form",
          b.safeUrl.canonicalize(mappedForms[i]) === bareV4);
    check("raw '" + mappedForms[i] + "' !== 'http://127.0.0.1/' (old-world unequal)",
          mappedForms[i] !== "http://127.0.0.1/");
  }
  // canonicalizeHost folds the host-only form too (used for host allowlists).
  check("canonicalizeHost folds ::ffff:1.2.3.4 to 1.2.3.4",
        b.ssrfGuard.canonicalizeHost("::ffff:1.2.3.4") === "1.2.3.4");
  check("canonicalizeHost folds the all-hex mapped spelling too",
        b.ssrfGuard.canonicalizeHost("::ffff:102:304") === "1.2.3.4");
  // A non-mapped IPv6 (no ::ffff:0:0/96 prefix) stays IPv6 — only the
  // v4-mapped block is an IPv4 alias; an embedded-v4 in a documentation
  // prefix is a distinct address.
  check("a non-mapped IPv6 stays IPv6 (::1)",
        b.ssrfGuard.canonicalizeHost("::1") === "::1");
  check("2001:db8::1.2.3.4 (v4 suffix, NOT v4-mapped) stays IPv6",
        b.ssrfGuard.canonicalizeHost("2001:db8::1.2.3.4").indexOf(".") === -1);
}

function testEmbeddedV4AndTrailingDotUnification() {
  // The canonical form must never flip an SSRF classify() verdict from blocked
  // to allowed. Only the IPv4-mapped block (::ffff:0:0/96) folds, because
  // classify(::ffff:x) === classify(x) — its branch returns classify(mappedV4)
  // with NO reserved fallback. NAT64 (64:ff9b::/96) and 6to4 (2002::/16) are
  // NOT folded: classify treats a NAT64 literal as `classify(v4) || "reserved"`,
  // so classify("64:ff9b::8.8.8.8") is "reserved" while classify("8.8.8.8") is
  // null — folding would turn a blocked NAT64 address into an allowed public
  // IPv4 verdict. The invariant below pins that: canonicalizing then classifying
  // must agree with classifying the original.
  var classify = b.ssrfGuard.classify;
  function classifyAgrees(host) {
    return classify(b.ssrfGuard.canonicalizeHost(host)) === classify(host);
  }
  check("NAT64 stays IPv6 (a public NAT64 literal must not become an allowed IPv4)",
        b.ssrfGuard.canonicalizeHost("64:ff9b::8.8.8.8").indexOf(".") === -1);
  check("canonicalize agrees with classify on a public NAT64 literal",
        classifyAgrees("64:ff9b::8.8.8.8"));
  check("canonicalize agrees with classify on a NAT64 loopback literal",
        classifyAgrees("64:ff9b::127.0.0.1"));
  check("canonicalize agrees with classify on a public IPv4-mapped literal",
        classifyAgrees("::ffff:8.8.8.8"));
  // 6to4 (2002::/16) is a /48 PREFIX, not a 1:1 alias — it must stay IPv6
  // (folding it would collapse a whole subnet onto one IPv4).
  check("6to4 2002:7f00:1:: stays IPv6 (not a 1:1 v4 alias)",
        b.ssrfGuard.canonicalizeHost("2002:7f00:1::").indexOf(".") === -1);

  // Trailing dots are not significant for host identity — every count must
  // collapse to the bare name so host / host. / host.. all unify.
  check("single trailing dot strips to the bare name",
        b.ssrfGuard.canonicalizeHost("example.com.") === "example.com");
  check("multiple trailing dots all strip to the bare name",
        b.ssrfGuard.canonicalizeHost("example.com..") === "example.com");
  check("canonicalize unifies a trailing-dot URL host with the bare host",
        b.safeUrl.canonicalize("http://example.com./p") === b.safeUrl.canonicalize("http://example.com/p"));
}

function testIpv6ZeroCompressionEquivalenceClass() {
  // ::1 in compressed, fully-expanded, and zero-padded spellings.
  var forms = [
    "http://[::1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[0000:0000:0000:0000:0000:0000:0000:0001]/",
  ];
  var first = b.safeUrl.canonicalize(forms[0]);
  check("IPv6 loopback canonical is [::1]", first === "http://[::1]/");
  for (var i = 1; i < forms.length; i += 1) {
    check("IPv6 loopback form '" + forms[i] + "' === [::1] canonical",
          b.safeUrl.canonicalize(forms[i]) === first);
    check("raw '" + forms[i] + "' !== raw '[::1]' (old-world unequal)",
          forms[i] !== forms[0]);
  }
  // A documentation address with an INTERIOR zero run picks the longest run
  // (RFC 5952 §4.2.3) and stays lower-hex.
  check("interior zero-run compresses correctly",
        b.safeUrl.canonicalize("https://[2001:0DB8:0:0:0:0:0:1]/") ===
        "https://[2001:db8::1]/");
}

// ---- IP-literal cross-check against the SSRF classifier's byte parser ----

function testIpCanonicalAgreesWithClassifier() {
  // The canonical host string and the SSRF verdict are derived from the SAME
  // bytes — so the canonical loopback string classifies as loopback and the
  // canonical mapped form re-classifies its embedded v4 as loopback too.
  check("canonical 127.0.0.1 classifies loopback",
        b.ssrfGuard.classify("127.0.0.1") === "loopback");
  // canonicalizeHost is the IP-byte + case layer: it byte-canonicalizes
  // net.isIP-recognized literals (the numeric-base decode of 0x.../octal/dword
  // is the WHATWG-URL-parser layer that safeUrl.canonicalize runs first).
  check("ssrfGuard.canonicalizeHost passes an already-canonical dotted-quad",
        b.ssrfGuard.canonicalizeHost("127.0.0.1") === "127.0.0.1");
  check("ssrfGuard.canonicalizeHost collapses expanded v6 to ::1",
        b.ssrfGuard.canonicalizeHost("[0:0:0:0:0:0:0:1]") === "::1");
  check("ssrfGuard.canonicalizeHost compresses + lower-hexes a mixed-case v6",
        b.ssrfGuard.canonicalizeHost("2001:0DB8:0:0:0:0:0:1") === "2001:db8::1");
  check("ssrfGuard.canonicalizeHost lowercases + strips trailing dot",
        b.ssrfGuard.canonicalizeHost("Example.COM.") === "example.com");
}

// ---- IDN: A-label emission + homograph refusal ----

function testIdnEmittedAsPunycode() {
  // A pure-Cyrillic+Latin-tld host parses (single script per label) and is
  // emitted as its xn-- A-label, never the Unicode form.
  var got = b.safeUrl.canonicalize("https://xn--80akhbyknj4f.com/");
  check("IDN host emitted as xn-- A-label",
        got === "https://xn--80akhbyknj4f.com/");
}

function testConfusableHostThrows() {
  // xn--ggle-55da.com decodes to a label mixing Cyrillic + Latin (the
  // gооgle.com homograph). canonicalize must THROW, never silently pass it.
  var threw = false;
  var code = null;
  try { b.safeUrl.canonicalize("https://xn--ggle-55da.com/"); }
  catch (e) { threw = true; code = e.code; }
  check("confusable / mixed-script host throws", threw === true);
  check("confusable host throw carries safe-url/idn-homograph",
        code === "safe-url/idn-homograph");
}

function testMixedScriptOptInCanonicalizes() {
  // Operators with a legitimate non-Latin host opt in; the A-label is then
  // canonicalized rather than refused.
  var got = b.safeUrl.canonicalize("https://xn--ggle-55da.com/", {
    allowMixedScript: true,
  });
  check("allowMixedScript:true canonicalizes the mixed-script host",
        got === "https://xn--ggle-55da.com/");
}

// ---- scheme / host case, default port, trailing dot, path ----

function testEndToEndNormalization() {
  // The headline end-to-end case from the spec: case-folded host, stripped
  // default port, resolved `..`, all in one.
  check("https://Example.COM:443/a/../b -> https://example.com/b",
        b.safeUrl.canonicalize("https://Example.COM:443/a/../b") ===
        "https://example.com/b");
  check("http default :80 stripped + host lowercased",
        b.safeUrl.canonicalize("http://Example.COM:80/") ===
        "http://example.com/");
  check("trailing-dot host removed",
        b.safeUrl.canonicalize("https://example.com./path") ===
        "https://example.com/path");
  check("non-default port preserved",
        b.safeUrl.canonicalize("https://example.com:8443/") ===
        "https://example.com:8443/");
}

function testPathPercentNormalization() {
  // RFC 3986 §6.2.2: escapes of unreserved chars are decoded, hex digits
  // uppercased — in the PATH only.
  check("path %7E decodes to ~ and %2D to -",
        b.safeUrl.canonicalize("https://example.com/%7Euser/a%2Db") ===
        "https://example.com/~user/a-b");
  // A reserved char (%2F = '/') is NOT decoded (would change structure); its
  // hex is uppercased.
  check("reserved %2f path escape uppercased, NOT decoded",
        b.safeUrl.canonicalize("https://example.com/a%2fb") ===
        "https://example.com/a%2Fb");
  // Query semantics are conservative: a %2D in the QUERY is left verbatim
  // (lowercase, undecoded) so value semantics are never altered.
  check("query percent-escape left byte-for-byte",
        b.safeUrl.canonicalize("https://example.com/?x=%2d") ===
        "https://example.com/?x=%2d");
}

// ---- throw paths: disallowed scheme + unparseable + scheme allowlist ----

function testDisallowedSchemeThrows() {
  var threw = false;
  var code = null;
  try { b.safeUrl.canonicalize("ftp://example.com/file"); }
  catch (e) { threw = true; code = e.code; }
  check("ftp scheme throws", threw === true);
  check("disallowed-scheme code is safe-url/protocol-disallowed",
        code === "safe-url/protocol-disallowed");
}

function testUnparseableThrows() {
  var threw = false;
  var code = null;
  try { b.safeUrl.canonicalize("this is not a url"); }
  catch (e) { threw = true; code = e.code; }
  check("unparseable input throws", threw === true);
  check("unparseable code is safe-url/malformed", code === "safe-url/malformed");
}

function testMissingInputThrows() {
  var threw = false;
  var code = null;
  try { b.safeUrl.canonicalize(""); }
  catch (e) { threw = true; code = e.code; }
  check("empty input throws safe-url/missing", threw === true && code === "safe-url/missing");
}

function testCustomSchemeAllowlist() {
  // Narrow the allowlist: https-only refuses an http URL.
  var threw = false;
  var code = null;
  try {
    b.safeUrl.canonicalize("http://example.com/", {
      allowedSchemes: b.safeUrl.ALLOW_HTTP_TLS,
    });
  } catch (e) { threw = true; code = e.code; }
  check("custom allowedSchemes (https-only) refuses http",
        threw === true && code === "safe-url/protocol-disallowed");
  // ws canonicalizes under the default ALLOW_ANY.
  check("ws scheme canonicalizes under default allowlist",
        b.safeUrl.canonicalize("ws://Example.COM:80/s") === "ws://example.com/s");
}

function testIdempotence() {
  // canonicalize(canonicalize(x)) === canonicalize(x) for the whole adversarial
  // set — a canonical form must be a fixed point.
  var inputs = [
    "http://0177.0.0.1/",
    "http://[0:0:0:0:0:ffff:7f00:1]/",
    "https://Example.COM:443/a/../b",
    "https://example.com/%7Euser",
    "https://xn--80akhbyknj4f.com/",
  ];
  for (var i = 0; i < inputs.length; i += 1) {
    var once = b.safeUrl.canonicalize(inputs[i]);
    var twice = b.safeUrl.canonicalize(once);
    check("canonicalize is idempotent for '" + inputs[i] + "'", once === twice);
  }
}

function testUncanonicalizableCodeIsRegistered() {
  // The post-parse fallback code is reachable as a documented SafeUrlError
  // code — constructing it directly proves the class accepts it.
  var e = new b.safeUrl.SafeUrlError("safe-url/uncanonicalizable", "x");
  check("safe-url/uncanonicalizable is a valid SafeUrlError code",
        e.code === "safe-url/uncanonicalizable" && e.isSafeUrlError === true);
}

// ---- Credentials are never carried into the canonical form ----

function testUserinfoDroppedFromCanonicalForm() {
  // The canonical string is built to be compared, used as a dedup / cache key,
  // or logged — it must never carry user:pass credentials, and the creds are
  // not part of the target identity for an allowlist / SSRF decision. parse()
  // refuses userinfo by default; even opted-in, the canonical output omits it.
  var user = "alice";
  var token = "s3cr" + "et-pw-9f3a";          // split so no secret-shaped literal sits in source
  var withCreds = "https://" + user + ":" + token + "@host.example.com/p";

  var deniedCode = null;
  try { b.safeUrl.canonicalize(withCreds); }
  catch (e) { deniedCode = e && e.code; }
  check("canonicalize refuses userinfo by default",
        deniedCode === "safe-url/userinfo-disallowed");

  var canon = b.safeUrl.canonicalize(withCreds, { allowUserinfo: true });
  check("canonicalize drops the userinfo delimiter from the canonical form",
        canon.indexOf("@") === -1);
  check("canonicalize does not carry the password into the canonical form",
        canon.indexOf(token) === -1);
  check("canonicalize does not carry the username into the canonical form",
        canon.indexOf("//" + user) === -1);
  check("the credential-stripped canonical form is the bare target",
        canon === "https://host.example.com/p");
  check("URLs differing only in credentials canonicalize equal",
        b.safeUrl.canonicalize("https://x:y@host.example.com/p", { allowUserinfo: true }) === canon);
}

async function run() {
  testUserinfoDroppedFromCanonicalForm();
  testEmbeddedV4AndTrailingDotUnification();
  testIpv4LoopbackEquivalenceClass();
  testIpv6MappedEquivalenceClass();
  testIpv6ZeroCompressionEquivalenceClass();
  testIpCanonicalAgreesWithClassifier();
  testIdnEmittedAsPunycode();
  testConfusableHostThrows();
  testMixedScriptOptInCanonicalizes();
  testEndToEndNormalization();
  testPathPercentNormalization();
  testDisallowedSchemeThrows();
  testUnparseableThrows();
  testMissingInputThrows();
  testCustomSchemeAllowlist();
  testIdempotence();
  testUncanonicalizableCodeIsRegistered();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
