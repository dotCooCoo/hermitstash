// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-svg — SVG content-safety primitive (b.guardSvg).
 *
 * Covers: surface; registry parity; dangerous-tag detection (script /
 * foreignObject / handler / iframe / animate-family); on* event-handler
 * strip; href + xlink:href dangerous URL schemes (javascript / vbscript
 * / file / mhtml + entity-encoded form); animation-element
 * attributeName allowlist (animate attributeName="href"
 * to="javascript:" hijack); cross-origin <use> external-ref refusal;
 * DOCTYPE rejection (billion laughs / XXE); <!ENTITY> declaration
 * detection; CDATA + processing-instruction policy; SVGZ magic-byte
 * detection; CSS injection in style attribute; bidi / control / null
 * detection; element-count + use-depth + attr-count caps; sanitize
 * round-trip; gate decision shapes (clean / refuse / sanitize); profile
 * + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardSvgSurface() {
  check("guardSvg is an object",                     typeof b.guardSvg === "object");
  check("guardSvg.NAME === 'svg'",                   b.guardSvg.NAME === "svg");
  check("guardSvg.MIME_TYPES has image/svg+xml",     b.guardSvg.MIME_TYPES.indexOf("image/svg+xml") !== -1);
  check("guardSvg.EXTENSIONS includes .svg",         b.guardSvg.EXTENSIONS.indexOf(".svg") !== -1);
  check("guardSvg.PROFILES has strict",              !!b.guardSvg.PROFILES["strict"]);
  check("guardSvg.PROFILES has balanced",            !!b.guardSvg.PROFILES["balanced"]);
  check("guardSvg.PROFILES has permissive",          !!b.guardSvg.PROFILES["permissive"]);
  check("guardSvg.COMPLIANCE_POSTURES has hipaa",    !!b.guardSvg.COMPLIANCE_POSTURES["hipaa"]);
  check("guardSvg.validate is a function",           typeof b.guardSvg.validate === "function");
  check("guardSvg.sanitize is a function",           typeof b.guardSvg.sanitize === "function");
  check("guardSvg.gate is a function",               typeof b.guardSvg.gate === "function");
  check("guardSvg.GuardSvgError is a function",      typeof b.guardSvg.GuardSvgError === "function");
  check("frameworkError.GuardSvgError exposed",      typeof b.frameworkError.GuardSvgError === "function");
}

function testGuardSvgRegistryParity() {
  check("guardSvg registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "svg"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "svg"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: svg supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: svg supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardSvgDangerousTags() {
  var tags = ["script", "foreignObject", "handler", "listener",
              "iframe", "embed", "object", "audio", "video"];
  for (var i = 0; i < tags.length; i++) {
    var rv = b.guardSvg.validate("<svg><" + tags[i] + ">x</" + tags[i] + "></svg>",
                                 { profile: "strict" });
    check("dangerous tag <" + tags[i] + "> detected",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

function testGuardSvgEventHandlers() {
  var handlers = ["onclick", "onerror", "onload", "onbegin", "onend",
                  "onrepeat", "onfocusin", "onfocusout"];
  for (var i = 0; i < handlers.length; i++) {
    var rv = b.guardSvg.validate('<svg><circle ' + handlers[i] + '="x"/></svg>',
                                 { profile: "balanced" });
    check("event handler " + handlers[i] + " detected",
          rv.issues.some(function (issue) { return issue.kind === "event-handler"; }));
  }
}

function testGuardSvgUrlSchemes() {
  var dangerous = ["javascript:", "vbscript:", "livescript:", "data:text/html,",
                   "file:///", "mhtml:", "view-source:", "jar:"];
  for (var i = 0; i < dangerous.length; i++) {
    var rv = b.guardSvg.validate(
      '<svg><a xlink:href="' + dangerous[i] + 'x">y</a></svg>',
      { profile: "balanced" });
    check("dangerous scheme " + JSON.stringify(dangerous[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
  }

  var rvEnc = b.guardSvg.validate(
    '<svg><a xlink:href="&#x6A;avascript:alert(1)">x</a></svg>',
    { profile: "balanced" });
  check("entity-encoded javascript: scheme detected",
        rvEnc.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // Fragment-only references allowed.
  var rvFrag = b.guardSvg.validate(
    '<svg><use xlink:href="#icon"/></svg>',
    { profile: "balanced" });
  check("fragment-only #ref allowed (not flagged as scheme)",
        !rvFrag.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgAnimationHrefHijack() {
  var rv = b.guardSvg.validate(
    '<svg><animate attributeName="href" to="javascript:alert(1)"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=href hijack detected",
        rv.issues.some(function (issue) { return issue.kind === "animation-target"; }));

  var rv2 = b.guardSvg.validate(
    '<svg><animate attributeName="xlink:href" to="evil"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=xlink:href hijack detected",
        rv2.issues.some(function (issue) { return issue.kind === "animation-target"; }));

  // attributeName="cx" — safe target, not flagged.
  var rvSafe = b.guardSvg.validate(
    '<svg><animate attributeName="cx" to="100"/></svg>',
    { profile: "permissive" });
  check("animation attributeName=cx (safe target) NOT flagged",
        !rvSafe.issues.some(function (issue) { return issue.kind === "animation-target"; }));
}

function testGuardSvgUseExternalRef() {
  var rv = b.guardSvg.validate(
    '<svg><use xlink:href="https://evil.example/icons.svg#x"/></svg>',
    { profile: "strict" });
  check("strict: cross-origin <use> external-ref detected",
        rv.issues.some(function (issue) { return issue.kind === "external-ref" ||
                                                 issue.kind === "non-allowlisted-url-scheme" ||
                                                 issue.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgDoctype() {
  var rv = b.guardSvg.validate(
    '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x.dtd"><svg/>',
    { profile: "strict" });
  check("DOCTYPE detected",
        rv.issues.some(function (issue) { return issue.kind === "doctype"; }));

  var rvEntity = b.guardSvg.validate(
    '<!DOCTYPE svg [<!ENTITY xx "yy">]><svg/>',
    { profile: "strict" });
  check("<!ENTITY> declaration detected",
        rvEntity.issues.some(function (issue) { return issue.kind === "entity-declaration"; }));
}

function testGuardSvgCdataAndPi() {
  var rvCdata = b.guardSvg.validate(
    '<svg><![CDATA[x]]><circle/></svg>',
    { profile: "strict" });
  check("CDATA detected under strict",
        rvCdata.issues.some(function (issue) { return issue.kind === "cdata"; }));

  var rvPi = b.guardSvg.validate(
    '<?xml-stylesheet type="text/css" href="x.css"?><svg/>',
    { profile: "strict" });
  check("processing-instruction detected under strict",
        rvPi.issues.some(function (issue) { return issue.kind === "processing-instruction"; }));
}

function testGuardSvgSvgz() {
  var rv = b.guardSvg.validate(
    Buffer.from([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]),
    { profile: "strict" });
  check("SVGZ magic-byte detected",
        rv.issues.some(function (issue) { return issue.kind === "svgz-compressed"; }));
}

function testGuardSvgCssInjection() {
  var rv = b.guardSvg.validate(
    '<svg><circle style="background:url(javascript:alert(1))"/></svg>',
    { profile: "balanced" });
  check("CSS injection in style attribute detected",
        rv.issues.some(function (issue) { return issue.kind === "css-injection"; }));
}

function testGuardSvgBidiNullControl() {
  var bidi = "‮";
  var rvBidi = b.guardSvg.validate("<svg><title>x" + bidi + "y</title></svg>",
                                   { profile: "strict" });
  check("bidi override detected",
        rvBidi.issues.some(function (issue) { return issue.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardSvg.validate("<svg><title>x" + nb + "y</title></svg>",
                                   { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardSvgCaps() {
  var threwSize = null;
  try { b.guardSvg.sanitize("<svg>" + "<g/>".repeat(100), { profile: "strict", maxBytes: 50 }); }
  catch (e) { threwSize = e; }
  check("maxBytes cap throws on sanitize",
        threwSize && /exceeds maxBytes/.test(threwSize.message));

  // <use> nesting depth.
  var deep = "";
  for (var i = 0; i < 20; i++) deep += "<use>";
  var rv = b.guardSvg.validate("<svg>" + deep + "</svg>",
                               { profile: "balanced", maxUseDepth: 5 });
  check("maxUseDepth cap detected",
        rv.issues.some(function (issue) { return issue.kind === "use-depth-cap"; }));
}

function testGuardSvgByteCapsMeasureBytes() {
  // Caps named in *Bytes must measure UTF-8 bytes, not UTF-16 code units.
  // "é" is one code unit (.length 1) but two UTF-8 bytes. A 50-char run is
  // 50 code units / 100 bytes — under a 60 char-count but over a 60-byte cap.
  var multibyte = "é".repeat(50);
  check("multibyte fixture: 50 code units, 100 UTF-8 bytes",
        multibyte.length === 50 && Buffer.byteLength(multibyte, "utf8") === 100);

  // Top-level maxBytes (validate path → tokenizer cap).
  var rvSize = b.guardSvg.validate(multibyte, { profile: "strict", maxBytes: 60 });
  check("validate: multibyte over byte cap reports too-large",
        rvSize.issues.some(function (issue) {
          return /exceeds maxBytes/.test(issue.snippet || "");
        }));
  check("validate: too-large snippet reports the BYTE count, not char count",
        rvSize.issues.some(function (issue) {
          return /input 100 bytes exceeds maxBytes 60/.test(issue.snippet || "");
        }));

  // Top-level maxBytes (sanitize path → throws).
  var threwMb = null;
  try { b.guardSvg.sanitize(multibyte, { profile: "strict", maxBytes: 60 }); }
  catch (e) { threwMb = e; }
  check("sanitize: multibyte over byte cap throws too-large with byte count",
        threwMb && /input 100 bytes exceeds maxBytes 60/.test(threwMb.message));

  // ASCII under the same cap stays unchanged (no false positive).
  var rvAscii = b.guardSvg.validate("a".repeat(50), { profile: "strict", maxBytes: 60 });
  check("validate: 50-byte ASCII under 60-byte cap is NOT flagged too-large",
        !rvAscii.issues.some(function (issue) {
          return /exceeds maxBytes/.test(issue.snippet || "");
        }));

  // Per-attribute maxAttrValueBytes measures bytes too.
  var attrMb = "<svg><circle foo=\"" + "é".repeat(50) + "\"/></svg>";
  var rvAttr = b.guardSvg.validate(attrMb,
    { profile: "balanced", maxAttrValueBytes: 60, maxBytes: 1000000 });
  check("validate: multibyte attr value over byte cap reports attr-value-too-large",
        rvAttr.issues.some(function (issue) { return issue.ruleId === "svg.attr-size"; }));

  var attrAscii = "<svg><circle foo=\"" + "a".repeat(50) + "\"/></svg>";
  var rvAttrAscii = b.guardSvg.validate(attrAscii,
    { profile: "balanced", maxAttrValueBytes: 60, maxBytes: 1000000 });
  check("validate: 50-byte ASCII attr value under 60-byte cap NOT flagged",
        !rvAttrAscii.issues.some(function (issue) { return issue.ruleId === "svg.attr-size"; }));
}

function testGuardSvgSanitize() {
  var clean = b.guardSvg.sanitize("<svg><script>alert(1)</script><circle/></svg>",
                                  { profile: "strict" });
  check("sanitize: script + body dropped",
        /<svg><circle\/?>(<\/svg>)?/.test(clean) && clean.indexOf("script") === -1);

  var clean2 = b.guardSvg.sanitize(
    '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
    { profile: "balanced" });
  check("sanitize: javascript: href stripped",
        clean2.indexOf("javascript") === -1);

  var clean3 = b.guardSvg.sanitize(
    '<svg><circle onclick="x"/></svg>', { profile: "strict" });
  check("sanitize: onclick stripped",
        clean3.indexOf("onclick") === -1);
}

async function testGuardSvgGate() {
  var g = b.guardSvg.gate({ profile: "strict" });
  var rv = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from("<svg><circle r=\"10\"/></svg>"),
  });
  check("gate clean → action=serve", rv.ok === true && rv.action === "serve");

  var rvHostile = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><script>alert(1)</script></svg>'),
  });
  check("gate hostile under strict → not serve",
        rvHostile.action !== "serve");

  var rvSvgz = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from([0x1F, 0x8B, 0x08, 0x00]),
  });
  check("gate svgz → refuse (never sanitize-eligible)",
        rvSvgz.action === "refuse");
}

function testGuardSvgCompliancePosture() {
  var hipaa = b.guardSvg.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.bidiPolicy === "reject" &&
        hipaa.cssPolicy === "reject" &&
        hipaa.doctypePolicy === "reject");
  var threw = null;
  try { b.guardSvg.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGdprPostureMatchesBalancedTier() {
  // gdpr is the balanced-tier posture for content guards (data-minimization
  // strips rather than rejects, but structural threats stay rejected). svg's
  // balanced profile allows cross-origin external refs (allowExternalRefs:
  // true) while strict refuses them. A partial gdpr posture object that omits
  // allowExternalRefs silently backfills the strict value, turning gdpr into
  // an incoherent strict/balanced hybrid that rejects an external <use> the
  // balanced tier accepts. Assert the gdpr verdict matches the balanced
  // verdict for that exact input.
  var external = '<svg><use xlink:href="https://cdn.example/icons.svg#x"/></svg>';
  var gdpr     = b.guardSvg.validate(external, { compliancePosture: "gdpr" });
  var balanced = b.guardSvg.validate(external, { profile: "balanced" });

  check("gdpr posture allows the same external <use> the balanced tier allows",
        gdpr.ok === balanced.ok);
  check("gdpr posture raises no external-ref the balanced tier does not",
        !gdpr.issues.some(function (issue) { return issue.kind === "external-ref"; }));

  // Structural identity: the gdpr posture is the balanced profile plus the
  // data-minimization forensic budget (base 256 / 2 = 128), nothing
  // strict-derived backfilled.
  var expected = Object.assign({}, b.guardSvg.PROFILES.balanced,
                               { forensicSnippetBytes: 128 });
  check("COMPLIANCE_POSTURES.gdpr deep-equals balanced + forensicSnippetBytes:128",
        JSON.stringify(b.guardSvg.COMPLIANCE_POSTURES.gdpr) === JSON.stringify(expected));
}

function testGuardSvgBadProfile() {
  var threw = null;
  try { b.guardSvg.validate("<svg/>", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

function testGuardSvgSchemeWhitespaceBypass() {
  // Browsers remove ASCII tab (U+0009) / LF (U+000A) / CR (U+000D) from a URL
  // before resolving its scheme (WHATWG URL parser "remove ASCII tab or
  // newline"), so `java<TAB>script:` / `java<LF>script:` navigate as
  // `javascript:`. The guard's scheme decoder even maps the NAMED entities
  // `&Tab;`/`&NewLine;` to those characters (its own comment names
  // `java&Tab;script:` as the threat), but decoding is defeated unless the
  // resulting whitespace is stripped before the scheme match. A miss here is
  // a fail-open: validate returns ok and the gate serves the hostile bytes.
  //
  // The same URL parser also trims a leading/trailing C0-control-OR-SPACE run
  // (U+0000..U+0020) before parsing, so an ENTITY-encoded leading space
  // (`&#32;javascript:` / `&#x20;javascript:`) decodes to " javascript:" and
  // navigates as `javascript:`. A literal leading space is caught by the raw
  // .trim(), but the entity-encoded space survives the decode (space is not a
  // C0 control, not tab/lf/cr), so it must be trimmed after decoding.
  var vectors = [
    ["literal tab",   '<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>'],
    ["literal lf",    '<svg><a xlink:href="java\nscript:alert(1)">x</a></svg>'],
    ["literal cr",    '<svg><a xlink:href="java\rscript:alert(1)">x</a></svg>'],
    ["&Tab; named",   '<svg><a xlink:href="java&Tab;script:alert(1)">x</a></svg>'],
    ["&NewLine; named", '<svg><a xlink:href="java&NewLine;script:alert(1)">x</a></svg>'],
    ["&#9; numeric",  '<svg><a xlink:href="java&#9;script:alert(1)">x</a></svg>'],
    ["&#32; entity leading space",  '<svg><a xlink:href="&#32;javascript:alert(1)">x</a></svg>'],
    ["&#x20; entity leading space", '<svg><a xlink:href="&#x20;javascript:alert(1)">x</a></svg>'],
  ];
  for (var i = 0; i < vectors.length; i++) {
    var rv = b.guardSvg.validate(vectors[i][1], { profile: "balanced" });
    check("scheme bypass (" + vectors[i][0] + ") flagged dangerous-url-scheme",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
  }

  // A control char the strip set DOES cover (U+0001) must still be caught.
  var rvCtrl = b.guardSvg.validate(
    '<svg><a xlink:href="&#1;javascript:alert(1)">x</a></svg>', { profile: "balanced" });
  check("control-char-prefixed javascript: still flagged (no regression)",
        rvCtrl.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // A legitimate https URL is NOT flagged (no false positive from stripping).
  var rvOk = b.guardSvg.validate(
    '<svg><a xlink:href="https://example.com/a">x</a></svg>', { profile: "balanced" });
  check("plain https href not flagged as dangerous scheme",
        !rvOk.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // sanitize must strip the tab-obfuscated scheme, not re-emit it.
  var san = b.guardSvg.sanitize('<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>',
                                { profile: "balanced" });
  check("sanitize: tab-obfuscated javascript scheme stripped",
        san.indexOf("script:") === -1);
}

function testGuardSvgCssEntityBypass() {
  // A style attribute is HTML/XML character-reference-decoded before the CSS
  // parser sees it, so `ex&#x70;ression(` reaches CSS as `expression(` and
  // `behavior&colon;` as `behavior:`. The css-danger check must decode the
  // same references the URL-scheme check already decodes, or an entity-encoded
  // style payload is served verbatim and executes (stored XSS).
  var vectors = [
    ["numeric &#x70; -> p (expression()",
     '<svg><rect style="width:ex&#x70;ression(alert(1))"/></svg>'],
    ["numeric &#x6A; -> j (url(javascript:))",
     '<svg><rect style="background:url(&#x6A;avascript:alert(1))"/></svg>'],
    ["decimal &#106; -> j (url(javascript:))",
     '<svg><rect style="background:url(&#106;avascript:alert(1))"/></svg>'],
    ["named &colon; -> : (behavior:)",
     '<svg><rect style="behavior&colon;url(evil.htc)"/></svg>'],
    // Whitespace-hidden scheme inside url(): a browser strips tab/lf/cr from a URL
    // before resolving its scheme, so url(java<TAB>script:) navigates as
    // javascript:. The decoded CSS value must also fold that URL whitespace.
    ["named &Tab; -> tab (url(java<TAB>script:))",
     '<svg><rect style="background:url(java&Tab;script:alert(1))"/></svg>'],
    ["numeric &#9; -> tab (url(java<TAB>script:))",
     '<svg><rect style="background:url(java&#9;script:alert(1))"/></svg>'],
  ];
  for (var i = 0; i < vectors.length; i++) {
    var rv = b.guardSvg.validate(vectors[i][1], { profile: "balanced" });
    check("CSS entity bypass (" + vectors[i][0] + ") flagged css-injection",
          rv.issues.some(function (issue) { return issue.kind === "css-injection"; }));
  }

  // Plain (unencoded) dangerous CSS still flagged (regression guard).
  var plain = b.guardSvg.validate('<svg><rect style="width:expression(alert(1))"/></svg>',
                                  { profile: "balanced" });
  check("CSS: plain expression( still flagged",
        plain.issues.some(function (issue) { return issue.kind === "css-injection"; }));

  // No false positive: a benign style value is untouched.
  var benign = b.guardSvg.validate('<svg><rect style="fill:red;stroke-width:2"/></svg>',
                                   { profile: "balanced" });
  check("CSS: benign style not flagged as css-injection",
        !benign.issues.some(function (issue) { return issue.kind === "css-injection"; }));
}

function testGuardSvgSanitizeAnimationPreserved() {
  // permissive permits animation; a safe-target <animate> must SURVIVE
  // sanitize. Every animation tag is in DANGEROUS_TAGS, so the sanitizer must
  // affirmatively re-permit the safe case — otherwise the open tag is dropped
  // while its (still allowlisted) close tag is emitted, leaving an orphan.
  var safe = '<svg><animate attributeName="cx" to="100"/></svg>';
  var out = b.guardSvg.sanitize(safe, { profile: "permissive" });
  check("sanitize permissive: safe <animate> open tag preserved",
        /<animate\b/i.test(out));

  var motion = '<svg><animateMotion dur="1s"><mpath xlink:href="#p"/></animateMotion></svg>';
  var outM = b.guardSvg.sanitize(motion, { profile: "permissive" });
  var opens  = (outM.match(/<animatemotion\b/gi) || []).length;
  var closes = (outM.match(/<\/animatemotion\b/gi) || []).length;
  check("sanitize permissive: animateMotion open/close balanced (no orphan close)",
        opens === 1 && closes === 1);

  // Unsafe attributeName animation is still neutralized under permissive.
  var unsafe = '<svg><animate attributeName="href" to="javascript:alert(1)"/></svg>';
  var outU = b.guardSvg.sanitize(unsafe, { profile: "permissive" });
  check("sanitize permissive: unsafe-target <animate> payload dropped",
        outU.indexOf("javascript") === -1);
}

async function testGuardSvgGateFailOpen() {
  var g = b.guardSvg.gate({ profile: "balanced" });

  var rvScheme = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><a xlink:href="java\tscript:alert(1)">x</a></svg>', "utf8"),
  });
  check("gate: tab-obfuscated javascript scheme not served as-is",
        rvScheme.action !== "serve");

  var rvCss = await g.check({
    contentType: "image/svg+xml",
    bytes: Buffer.from('<svg><rect style="width:ex&#x70;ression(alert(1))"/></svg>', "utf8"),
  });
  check("gate: entity-encoded CSS expression not served as-is",
        rvCss.action !== "serve");
}

function testGuardSvgBadInput() {
  // Non-string / non-Buffer input → a single bad-input issue; validate never
  // throws on hostile input (callers inspect the issue list themselves).
  [123, null, undefined, {}, ["<svg/>"], true].forEach(function (bad, idx) {
    var rv = b.guardSvg.validate(bad, { profile: "strict" });
    check("validate(bad-input #" + idx + ") → ok=false + single bad-input issue",
          rv.ok === false &&
          rv.issues.length === 1 &&
          rv.issues[0].kind === "bad-input" &&
          rv.issues[0].severity === "high");
  });
  // sanitize refuses non-string/non-Buffer at the entry point (throws, since a
  // sanitizer has nothing to serialize back).
  var threw = null;
  try { b.guardSvg.sanitize(123, { profile: "strict" }); }
  catch (e) { threw = e; }
  check("sanitize(number) throws svg.bad-input",
        threw && /string or Buffer/.test(threw.message));
}

function testGuardSvgShortInput() {
  // A sub-2-byte input can't be SVGZ (the gzip signature is 2 bytes) — the
  // length<2 guard must return false, not read past the buffer.
  var rv = b.guardSvg.validate("x", { profile: "strict" });
  check("1-char input NOT mis-detected as SVGZ",
        !rv.issues.some(function (i) { return i.kind === "svgz-compressed"; }));
  var rvBuf = b.guardSvg.validate(Buffer.from([0x1F]), { profile: "strict" });
  check("1-byte 0x1F Buffer NOT mis-detected as SVGZ (needs both magic bytes)",
        !rvBuf.issues.some(function (i) { return i.kind === "svgz-compressed"; }));
}

function testGuardSvgImageDataUrl() {
  // allowImageData (balanced / permissive): a data:image/<raster>; URL on
  // <image> is the ONE permitted use of the otherwise-denylisted data: scheme.
  var okData = '<svg><image href="data:image/png;base64,iVBORw0KGgo="/></svg>';
  var rv = b.guardSvg.validate(okData, { profile: "balanced" });
  check("balanced: data:image/png on <image> allowed (no dangerous-url-scheme)",
        rv.ok === true &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
  var san = b.guardSvg.sanitize(okData, { profile: "balanced" });
  check("balanced sanitize: data:image/png survives on <image>",
        san.indexOf("data:image/png") !== -1);

  // The exact same data URL on a NON-image element stays denied — the
  // exception is <image>-scoped, not a blanket data:-image allow.
  var rvA = b.guardSvg.validate(
    '<svg><a xlink:href="data:image/png;base64,iVBORw0KGgo=">x</a></svg>',
    { profile: "balanced" });
  check("balanced: data:image/png on <a> still flagged dangerous-url-scheme",
        rvA.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // A non-raster data: MIME on <image> (text/html) is NOT the image exception.
  var rvHtml = b.guardSvg.validate(
    '<svg><image href="data:text/html;base64,PHNjcmlwdD4="/></svg>',
    { profile: "balanced" });
  check("balanced: data:text/html on <image> flagged dangerous-url-scheme",
        rvHtml.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // strict has allowImageData:false — even a raster data URL on <image> is
  // refused there.
  var rvStrict = b.guardSvg.validate(okData, { profile: "strict" });
  check("strict: data:image/png on <image> refused (allowImageData false)",
        rvStrict.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgNonAllowlistedScheme() {
  // A scheme that is neither dangerous NOR in the profile's urlSchemes
  // allowlist (ftp under strict) → non-allowlisted-url-scheme (sanitize-class),
  // distinct from the dangerous-scheme denylist hit.
  var svg = '<svg><path href="ftp://host/x" d="M0 0"/></svg>';
  var rv = b.guardSvg.validate(svg, { profile: "strict" });
  check("strict: ftp scheme flagged non-allowlisted-url-scheme (not dangerous)",
        rv.issues.some(function (i) { return i.kind === "non-allowlisted-url-scheme"; }) &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));
  var san = b.guardSvg.sanitize(svg, { profile: "strict" });
  check("strict sanitize: ftp href dropped, benign d preserved",
        san.indexOf("ftp") === -1 && san.indexOf('d="M0 0"') !== -1);

  // ftp IS in the balanced profile's urlSchemes → not flagged there.
  var rvBal = b.guardSvg.validate('<svg><a xlink:href="ftp://host/x">y</a></svg>',
                                  { profile: "balanced" });
  check("balanced: ftp scheme allowed (in profile urlSchemes)",
        !rvBal.issues.some(function (i) { return i.kind === "non-allowlisted-url-scheme" ||
                                                 i.kind === "dangerous-url-scheme"; }));
}

function testGuardSvgStructuralCaps() {
  // element-count-cap: total token count over maxElementCount → high issue.
  var manyTokens = "<g></g>".repeat(20);
  var rvEl = b.guardSvg.validate(manyTokens, { profile: "strict", maxElementCount: 5 });
  check("element-count-cap fires when token count exceeds maxElementCount",
        rvEl.issues.some(function (i) { return i.kind === "element-count-cap"; }));

  // attr-count-cap: attribute count on one tag over maxAttrsPerTag → high issue.
  var manyAttrs = "<circle";
  for (var i = 0; i < 10; i += 1) manyAttrs += ' a' + i + '="1"';
  manyAttrs += "/>";
  var rvAttr = b.guardSvg.validate("<svg>" + manyAttrs + "</svg>",
                                   { profile: "balanced", maxAttrsPerTag: 3 });
  check("attr-count-cap fires when attribute count exceeds maxAttrsPerTag",
        rvAttr.issues.some(function (i) { return i.kind === "attr-count-cap"; }));
}

function testGuardSvgStandaloneEntityDeclaration() {
  // A bare <!ENTITY ...> OUTSIDE a DOCTYPE (tokenized as a declaration, not a
  // doctype) is still an entity-expansion / XXE vector and must be flagged.
  var rv = b.guardSvg.validate('<!ENTITY xxe "payload"><svg><circle r="1"/></svg>',
                               { profile: "strict" });
  check("standalone <!ENTITY> declaration flagged entity-declaration",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "entity-declaration"; }));

  // A benign non-ENTITY declaration (<!ATTLIST>) is dropped, no entity flag.
  var rvAttlist = b.guardSvg.validate('<!ATTLIST x y CDATA><svg><circle r="1"/></svg>',
                                      { profile: "strict" });
  check("non-ENTITY <!ATTLIST> declaration raises no entity-declaration",
        !rvAttlist.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardSvgCdataPiAuditSeverity() {
  // Under balanced, cdataPolicy is "audit" → warn severity (not critical), and
  // ok stays true (warn does not flip ok).
  var rvCdata = b.guardSvg.validate('<svg><![CDATA[x]]><circle r="1"/></svg>',
                                    { profile: "balanced" });
  check("balanced CDATA → warn severity (audit policy), ok stays true",
        rvCdata.ok === true &&
        rvCdata.issues.some(function (i) {
          return i.kind === "cdata" && i.severity === "warn";
        }));

  // Under permissive, processingInstrPolicy is "audit" → warn severity.
  var rvPi = b.guardSvg.validate('<?xml-stylesheet href="x"?><svg/>',
                                 { profile: "permissive" });
  check("permissive processing-instruction → warn severity (audit policy)",
        rvPi.issues.some(function (i) {
          return i.kind === "processing-instruction" && i.severity === "warn";
        }));
}

function testGuardSvgTruncatedTokens() {
  // Truncated / unterminated markup must not silently smuggle content: the
  // tokenizer treats each open-without-close as a token running to EOF.
  var rvCdata = b.guardSvg.validate('<svg><![CDATA[unterminated payload',
                                    { profile: "strict" });
  check("unterminated CDATA still flagged (scans to EOF)",
        rvCdata.issues.some(function (i) { return i.kind === "cdata"; }));

  var rvPi = b.guardSvg.validate('<svg><?xml-stylesheet type="text/css"',
                                 { profile: "strict" });
  check("unterminated processing-instruction still flagged",
        rvPi.issues.some(function (i) { return i.kind === "processing-instruction"; }));

  // Unterminated DOCTYPE with an internal-subset '[' and no closing ']' / '>'
  // — still detected as a doctype plus its embedded <!ENTITY>.
  var rvDoc = b.guardSvg.validate('<!DOCTYPE svg [<!ENTITY x "y"',
                                  { profile: "strict" });
  check("unterminated DOCTYPE-with-subset still flags doctype + entity",
        rvDoc.issues.some(function (i) { return i.kind === "doctype"; }) &&
        rvDoc.issues.some(function (i) { return i.kind === "entity-declaration"; }));

  // Unterminated (no closing '>') start tag for a DANGEROUS element is still
  // caught — the tokenizer scans to EOF and names the tag.
  var rvTag = b.guardSvg.validate('<svg><script', { profile: "strict" });
  check("unterminated <script (no >) still flagged dangerous-tag",
        rvTag.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  // Unterminated benign start tag validates clean (no spurious issue) — covers
  // the raw-without-trailing-'>' reconstruction path.
  var rvBenign = b.guardSvg.validate('<svg><circle r="1"', { profile: "strict" });
  check("unterminated benign <circle validates clean", rvBenign.ok === true);

  // Unterminated quoted attribute value (no closing quote, EOF) — parser must
  // clamp to EOF without crashing.
  var rvQuote = b.guardSvg.validate('<svg><circle r="unterminated', { profile: "strict" });
  check("unterminated quoted attr value handled without error",
        rvQuote && Array.isArray(rvQuote.issues));

  // Unterminated end tag (no '>') is dropped without error.
  var rvEnd = b.guardSvg.validate('<svg><circle r="1"/></circle', { profile: "strict" });
  check("unterminated end tag handled without error", rvEnd.ok === true);

  // Unterminated comment (no terminator, runs to EOF) — the hidden text stays
  // inert (not smuggled as a live element).
  var rvComment = b.guardSvg.validate('<svg><circle r="1"/><!-- <script>alert(1)',
                                      { profile: "strict" });
  check("unterminated comment swallows trailing markup (no dangerous-tag)",
        !rvComment.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  // Unterminated DOCTYPE WITHOUT an internal subset '[' and no closing '>' —
  // still flagged as a doctype.
  var rvDocPlain = b.guardSvg.validate('<!DOCTYPE svg PUBLIC "id"', { profile: "strict" });
  check("unterminated bracket-less DOCTYPE still flagged doctype",
        rvDocPlain.issues.some(function (i) { return i.kind === "doctype"; }));

  // Unterminated generic declaration (no '>') — dropped without error, no
  // spurious entity flag.
  var rvDecl = b.guardSvg.validate('<svg><circle r="1"/></svg><!ATTLIST foo',
                                   { profile: "strict" });
  check("unterminated <!ATTLIST declaration handled without error",
        rvDecl && Array.isArray(rvDecl.issues) &&
        !rvDecl.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardSvgComment() {
  // A comment's contents are NOT parsed as markup — a <script> hidden inside a
  // comment is inert and must be dropped, not tokenized as a live element.
  var withComment = '<svg><!-- <script>alert(1)</script> --><circle r="1"/></svg>';
  var rv = b.guardSvg.validate(withComment, { profile: "strict" });
  check("comment-wrapped <script> not flagged (comment content inert)",
        rv.ok === true &&
        !rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
  var san = b.guardSvg.sanitize(withComment, { profile: "strict" });
  check("sanitize strips the comment entirely (no smuggled script)",
        san.indexOf("<!--") === -1 && san.indexOf("script") === -1);
}

function testGuardSvgSanitizeStructural() {
  // Structural noise (DOCTYPE / declaration / CDATA / PI / comment) is dropped
  // by sanitize, leaving only the allowlisted element.
  var noisy = '<!DOCTYPE svg><!ENTITY z "z"><svg><![CDATA[x]]>' +
              '<?xml-stylesheet href="x"?><!--c--><circle r="1"/></svg>';
  var san = b.guardSvg.sanitize(noisy, { profile: "strict" });
  check("sanitize drops doctype/declaration/cdata/pi/comment structural tokens",
        san.indexOf("DOCTYPE") === -1 && san.indexOf("ENTITY") === -1 &&
        san.indexOf("CDATA") === -1 && san.indexOf("xml-stylesheet") === -1 &&
        san.indexOf("<!--") === -1 && /<circle r="1"\/?>/.test(san));

  // Nested same-name dangerous element: the body-drop scan must balance the
  // inner <script> against the outer so ALL nested content is removed.
  var nested = '<svg><script>a<script>b</script>c</script><circle r="1"/></svg>';
  var sanNest = b.guardSvg.sanitize(nested, { profile: "strict" });
  check("sanitize body-drop balances nested <script> (no leaked payload)",
        sanNest.indexOf("script") === -1 &&
        sanNest.indexOf(">a") === -1 && sanNest.indexOf("b<") === -1 &&
        sanNest.indexOf("c<") === -1);

  // Over-cap attribute value is dropped while its element is kept.
  var bigAttr = '<svg><circle foo="' + "a".repeat(100) + '" r="1"/></svg>';
  var sanBig = b.guardSvg.sanitize(bigAttr, { profile: "balanced", maxAttrValueBytes: 20 });
  check("sanitize drops an over-cap attribute value but keeps the element",
        sanBig.indexOf("foo") === -1 && /<circle[^>]*r="1"/.test(sanBig));

  // External-ref on <use> under allowExternalRefs:false → href stripped, the
  // <use> element itself kept.
  var extUse = '<svg><use xlink:href="icons.svg#x"/></svg>';
  var sanUse = b.guardSvg.sanitize(extUse, { profile: "balanced", allowExternalRefs: false });
  check("sanitize strips external <use> href when allowExternalRefs:false",
        sanUse.indexOf("icons.svg") === -1 && /<use\/?>/.test(sanUse));

  // Single-quoted + unquoted attribute values are parsed and re-emitted
  // double-quoted (re-serialization normalizes quoting).
  var mixed = "<svg><rect fill='red' width=10 height=10/></svg>";
  var sanMixed = b.guardSvg.sanitize(mixed, { profile: "balanced" });
  check("sanitize normalizes single-quoted + unquoted attrs to double-quoted",
        sanMixed.indexOf('fill="red"') !== -1 &&
        sanMixed.indexOf('width="10"') !== -1 &&
        sanMixed.indexOf('height="10"') !== -1);
}

function testGuardSvgSvgzSanitizeThrows() {
  // sanitize refuses gzipped SVGZ bytes — a text sanitizer must never run on
  // compressed input (operator ungzips + re-sanitizes the inner SVG).
  var threw = null;
  try {
    b.guardSvg.sanitize(Buffer.from([0x1F, 0x8B, 0x08, 0x00, 0x00]), { profile: "strict" });
  } catch (e) { threw = e; }
  check("sanitize(SVGZ magic bytes) throws svg.svgz",
        threw && /SVGZ|ungzip/i.test(threw.message));
}

function testGuardSvgAttrEdgeCases() {
  // Empty URL-bearing attribute value → treated as a fragment (no scheme),
  // never flagged. Exercises the empty-string extraction / fragment paths.
  var rvEmpty = b.guardSvg.validate('<svg><a xlink:href="">x</a></svg>',
                                    { profile: "balanced" });
  check("empty xlink:href value not flagged as a dangerous scheme",
        !rvEmpty.issues.some(function (i) { return i.kind === "dangerous-url-scheme"; }));

  // Spaced attribute (name = value) — whitespace around the '=' is skipped.
  var rvSpaced = b.guardSvg.validate('<svg><circle r = "1" /></svg>', { profile: "strict" });
  check("spaced attribute (name = value) parsed cleanly", rvSpaced.ok === true);

  // Malformed attribute source (leading '=' with no name) must not crash — the
  // scanner breaks out cleanly.
  var rvMal = b.guardSvg.validate('<svg><circle  = r="1" /></svg>', { profile: "strict" });
  check("malformed attribute source (leading =) parsed without error",
        rvMal && Array.isArray(rvMal.issues));

  // Trailing intra-tag whitespace before '>' exercises the whitespace-run break.
  var rvWs = b.guardSvg.validate('<svg><circle r="1"   ></circle></svg>', { profile: "strict" });
  check("trailing intra-tag whitespace parsed cleanly", rvWs.ok === true);
}

async function testGuardSvgGateDispositions() {
  // Each disposition class the gate maps, exercised through the real
  // gate().check() consumer path (verdict.action is the observable contract).
  var bidi  = String.fromCharCode(0x202E);
  var gStrict = b.guardSvg.gate({ profile: "strict" });
  var gBal    = b.guardSvg.gate({ profile: "balanced" });
  var gPerm   = b.guardSvg.gate({ profile: "permissive" });

  // char-threat (bidi) under permissive (bidiPolicy "audit") → audit-only.
  var rvBidi = await gPerm.check({
    bytes: Buffer.from("<svg><title>x" + bidi + "y</title></svg>", "utf8"),
  });
  check("gate: permissive bidi (audit policy) → audit-only",
        rvBidi.action === "audit-only");

  // doctype (reject policy in every profile) → refuse.
  var rvDoc = await gStrict.check({ bytes: Buffer.from('<!DOCTYPE svg><svg/>', "utf8") });
  check("gate: doctype → refuse", rvDoc.action === "refuse");

  // cdata under balanced (audit policy) → audit-only.
  var rvCdata = await gBal.check({ bytes: Buffer.from('<svg><![CDATA[x]]></svg>', "utf8") });
  check("gate: balanced cdata (audit policy) → audit-only",
        rvCdata.action === "audit-only");

  // processing-instruction under permissive (audit policy) → audit-only.
  var rvPi = await gPerm.check({ bytes: Buffer.from('<?xml-stylesheet href="x"?><svg/>', "utf8") });
  check("gate: permissive processing-instruction (audit policy) → audit-only",
        rvPi.action === "audit-only");

  // non-allowlisted (benign) tag → sanitize.
  var rvNal = await gBal.check({ bytes: Buffer.from('<svg><foobar/></svg>', "utf8") });
  check("gate: non-allowlisted benign tag → sanitize", rvNal.action === "sanitize");

  // tokenize-failed (input over maxBytes) → refuse.
  var rvTok = await b.guardSvg.gate({ profile: "strict", maxBytes: 10 }).check({
    bytes: Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
  });
  check("gate: tokenize-failed (over maxBytes) → refuse", rvTok.action === "refuse");

  // element-count-cap → refuse.
  var rvEl = await b.guardSvg.gate({ profile: "strict", maxElementCount: 3 }).check({
    bytes: Buffer.from("<g></g>".repeat(10), "utf8"),
  });
  check("gate: element-count-cap → refuse", rvEl.action === "refuse");

  // attr-count-cap → refuse.
  var manyAttrs = "<circle";
  for (var i = 0; i < 10; i += 1) manyAttrs += ' a' + i + '="1"';
  manyAttrs += "/>";
  var rvAttrCap = await b.guardSvg.gate({ profile: "balanced", maxAttrsPerTag: 3 }).check({
    bytes: Buffer.from("<svg>" + manyAttrs + "</svg>", "utf8"),
  });
  check("gate: attr-count-cap → refuse", rvAttrCap.action === "refuse");

  // use-depth-cap → refuse.
  var deep = "";
  for (var j = 0; j < 10; j += 1) deep += "<use>";
  var rvUse = await b.guardSvg.gate({ profile: "balanced", maxUseDepth: 3 }).check({
    bytes: Buffer.from("<svg>" + deep + "</svg>", "utf8"),
  });
  check("gate: use-depth-cap → refuse", rvUse.action === "refuse");

  // attr-value-too-large → refuse.
  var rvBig = await b.guardSvg.gate({ profile: "balanced", maxAttrValueBytes: 10 }).check({
    bytes: Buffer.from('<svg><circle foo="' + "a".repeat(50) + '"/></svg>', "utf8"),
  });
  check("gate: attr-value-too-large → refuse", rvBig.action === "refuse");

  // bad-input (ctx.bytes is neither Buffer nor string) → refuse.
  var rvBad = await gStrict.check({ bytes: 12345 });
  check("gate: non-Buffer bytes (bad-input) → refuse", rvBad.action === "refuse");
}

async function run() {
  testGuardSvgSurface();
  testGuardSvgRegistryParity();
  testGuardSvgDangerousTags();
  testGuardSvgEventHandlers();
  testGuardSvgUrlSchemes();
  testGuardSvgAnimationHrefHijack();
  testGuardSvgUseExternalRef();
  testGuardSvgDoctype();
  testGuardSvgCdataAndPi();
  testGuardSvgSvgz();
  testGuardSvgCssInjection();
  testGuardSvgBidiNullControl();
  testGuardSvgCaps();
  testGuardSvgByteCapsMeasureBytes();
  testGuardSvgSanitize();
  testGuardSvgCompliancePosture();
  testGdprPostureMatchesBalancedTier();
  testGuardSvgBadProfile();
  testGuardSvgSchemeWhitespaceBypass();
  testGuardSvgCssEntityBypass();
  testGuardSvgSanitizeAnimationPreserved();
  testGuardSvgBadInput();
  testGuardSvgShortInput();
  testGuardSvgImageDataUrl();
  testGuardSvgNonAllowlistedScheme();
  testGuardSvgStructuralCaps();
  testGuardSvgStandaloneEntityDeclaration();
  testGuardSvgCdataPiAuditSeverity();
  testGuardSvgTruncatedTokens();
  testGuardSvgComment();
  testGuardSvgSanitizeStructural();
  testGuardSvgSvgzSanitizeThrows();
  testGuardSvgAttrEdgeCases();
  await testGuardSvgGate();
  await testGuardSvgGateFailOpen();
  await testGuardSvgGateDispositions();
}

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}

module.exports = { run: run };
