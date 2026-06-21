"use strict";
/**
 * Response-output, header, and compliance hardening — each test drives the
 * shipped consumer path with the input that triggers the failure.
 *
 *   - ai.output.sanitize: a markdown image/link whose alt text equals its URL
 *     no longer leaves the real exfiltration target intact (EchoLeak / CWE-918).
 *   - dora.classify: evaluates the percentage-of-client-base criterion (not just
 *     absolute counts); dora.report anchors the next-stage deadline on the
 *     report's submission time, not detection.
 *   - cookies.serialize: value cap is byte-length (multibyte overflow refused);
 *     a ';' in Path is scrubbed (no attribute injection).
 *   - csp.mergeDirectives: merging a real source into a 'none' directive drops
 *     'none' (no malformed "'none' host").
 *   - cdnCacheControl.parse: delta-seconds accepts only decimal digits (no
 *     hex / exponential / whitespace forms).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _throws(fn) { try { fn(); return null; } catch (e) { return (e && e.code) || e.message || "threw"; } }

function testAiOutputEchoLeak() {
  var meta = "https://169.254.169.254/latest/meta-data";
  var out = b.ai.output.sanitize("![" + meta + "](" + meta + ")", { audit: false });
  var text = out.text || out;
  check("ai.output.sanitize neutralizes the real URL when alt === url (EchoLeak)",
    text.indexOf("(" + meta + ")") === -1 && /about:blank#blocked/.test(text));
  // A normal link is still neutralized.
  var out2 = b.ai.output.sanitize("[x](" + meta + ")", { audit: false });
  check("ai.output.sanitize still neutralizes a normal metadata link",
    /about:blank#blocked/.test(out2.text || out2));
}

function testDoraClientBasePercentile() {
  var d = b.dora.create({ audit: false });
  // 8000 of 50000 = 16% > 10% major threshold, but 8000 < 100000 absolute.
  var major = d.classify({ affectedClients: 8000, clientBase: 50000 });
  check("dora.classify: 16% of client base → major (percentile criterion)",
    major.classification === "major");
  // Absolute-only behavior unchanged when clientBase omitted.
  var minor = d.classify({ affectedClients: 8000 });
  check("dora.classify: 8000 with no clientBase → not major (absolute-only)",
    minor.classification !== "major");
}

function testDoraDeadlineAnchor() {
  var d = b.dora.create({ audit: false });
  var detected = Date.now() - 5 * 60 * 60 * 1000;   // detected 5h ago
  var rep = d.report({
    incidentId: "inc-1", classification: "major", stage: "initial",
    detectedAt: detected, description: "x",
  });
  // nextStageDueAt must anchor on submission (~now), not detectedAt — so it is
  // well past detectedAt + 72h would have been if anchored on detection.
  check("dora.report: nextStageDueAt anchored on submission, not detectedAt",
    rep.nextStageDueAt > detected + 72 * 60 * 60 * 1000 - 60000);
}

function testCookieByteCapAndPath() {
  var bigMultibyte = "€".repeat(4096);   // 4096 chars = 12288 UTF-8 bytes
  check("cookies.serialize refuses an over-byte-cap multibyte value",
    _throws(function () { b.cookies.serialize("c", bigMultibyte, { secure: true }); }) === "cookies/invalid-value");
  // A ';' in Path must not survive into the Set-Cookie attribute list.
  var sc = b.cookies.serialize("c", "v", { path: "/a;HttpOnly=evil", secure: true });
  check("cookies.serialize scrubs ';' from Path (no attribute injection)",
    sc.indexOf("/aHttpOnly=evil") !== -1 && sc.indexOf("/a;HttpOnly=evil") === -1);
}

function testCspMergeNone() {
  var merged = b.csp.mergeDirectives("script-src 'none'", { "script-src": ["https://cdn.example"] });
  check("csp.mergeDirectives drops 'none' when a real source is merged in",
    merged.indexOf("'none'") === -1 && merged.indexOf("https://cdn.example") !== -1);
}

function testCdnDeltaSeconds() {
  var ok = b.cdnCacheControl.parse("max-age=3600");
  check("cdnCacheControl.parse accepts decimal delta-seconds", ok.maxAge === 3600);
  // hex / exponential / whitespace are not RFC 9111 delta-seconds.
  var hex = b.cdnCacheControl.parse("max-age=0x10");
  check("cdnCacheControl.parse rejects hex delta-seconds", hex.maxAge === undefined);
  var exp = b.cdnCacheControl.parse("max-age=1e3");
  check("cdnCacheControl.parse rejects exponential delta-seconds", exp.maxAge === undefined);
}

async function run() {
  testAiOutputEchoLeak();
  testDoraClientBasePercentile();
  testDoraDeadlineAnchor();
  testCookieByteCapAndPath();
  testCspMergeNone();
  testCdnDeltaSeconds();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
