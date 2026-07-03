// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-html — HTML content-safety primitive (b.guardHtml).
 *
 * Covers: surface; registry parity (NAME / MIME_TYPES / EXTENSIONS /
 * shared profiles + postures); dangerous-tag detection (script / style /
 * iframe / object / form / etc.); on* event-handler attribute strip;
 * dangerous-attribute strip (formaction / srcdoc / is / nonce);
 * URL-scheme allowlist (javascript / vbscript / data outside image /
 * file / mhtml denied); image-context data: opt-in; CSS dangerous
 * tokens (expression / behavior / -moz-binding / @import / javascript:
 * inside url()); DOM-clobbering id/name=document on form / input;
 * mXSS hint (<svg> / <math> namespace shift); IE conditional comments;
 * bidi / control / null-byte / zero-width handling; tag-depth +
 * attr-count + attr-value-size caps; sanitize round-trip preserves
 * allowed tags, drops dangerous + their body content; escapeText /
 * escapeAttr correctness; gate decision shapes (serve / refuse /
 * sanitize); profile + posture vocabulary.
 *
 * Run standalone: node test/layer-0-primitives/guard-html.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Surface ----

function testGuardHtmlSurface() {
  check("guardHtml is an object",                    typeof b.guardHtml === "object");
  check("guardHtml.NAME === 'html'",                 b.guardHtml.NAME === "html");
  check("guardHtml.MIME_TYPES includes text/html",   b.guardHtml.MIME_TYPES.indexOf("text/html") !== -1);
  check("guardHtml.EXTENSIONS includes .html",       b.guardHtml.EXTENSIONS.indexOf(".html") !== -1);
  check("guardHtml.PROFILES has strict",             !!b.guardHtml.PROFILES["strict"]);
  check("guardHtml.PROFILES has balanced",           !!b.guardHtml.PROFILES["balanced"]);
  check("guardHtml.PROFILES has permissive",         !!b.guardHtml.PROFILES["permissive"]);
  check("guardHtml.COMPLIANCE_POSTURES has hipaa",   !!b.guardHtml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardHtml.validate is a function",          typeof b.guardHtml.validate === "function");
  check("guardHtml.sanitize is a function",          typeof b.guardHtml.sanitize === "function");
  check("guardHtml.escapeText is a function",        typeof b.guardHtml.escapeText === "function");
  check("guardHtml.escapeAttr is a function",        typeof b.guardHtml.escapeAttr === "function");
  check("guardHtml.gate is a function",              typeof b.guardHtml.gate === "function");
  check("guardHtml.GuardHtmlError is a function",    typeof b.guardHtml.GuardHtmlError === "function");
  check("frameworkError.GuardHtmlError exposed",     typeof b.frameworkError.GuardHtmlError === "function");
}

// ---- Registry parity ----

function testGuardHtmlRegistryParity() {
  check("guardHtml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "html"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "html"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: html supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: html supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

// ---- Dangerous tag detection ----

function testGuardHtmlDangerousTags() {
  var tags = ["script", "style", "iframe", "object", "embed", "applet",
              "form", "input", "button", "meta", "base", "link",
              "frame", "frameset", "marquee", "blink", "plaintext",
              "math", "svg", "template", "noscript", "portal", "dialog"];
  for (var i = 0; i < tags.length; i++) {
    var rv = b.guardHtml.validate("<" + tags[i] + ">x</" + tags[i] + ">",
                                  { profile: "strict" });
    check("dangerous tag <" + tags[i] + "> detected",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

// ---- on* handler family ----

function testGuardHtmlEventHandlers() {
  var handlers = ["onclick", "onerror", "onload", "onmouseover",
                  "onfocus", "onblur", "onsubmit", "onkeydown",
                  "onbeforeunload", "onpaste", "onwheel", "onpointerdown",
                  "ontoggle", "onanimationend", "ontransitionstart"];
  for (var i = 0; i < handlers.length; i++) {
    var rv = b.guardHtml.validate("<div " + handlers[i] + "=foo>x</div>",
                                  { profile: "balanced" });
    check("event handler " + handlers[i] + " detected",
          rv.issues.some(function (issue) { return issue.kind === "event-handler"; }));
  }
}

// ---- Dangerous attributes ----

function testGuardHtmlDangerousAttrs() {
  var attrs = ["formaction", "formmethod", "srcdoc", "is", "integrity",
               "nonce", "crossorigin", "http-equiv", "manifest"];
  for (var i = 0; i < attrs.length; i++) {
    var rv = b.guardHtml.validate("<a " + attrs[i] + "=foo>x</a>",
                                  { profile: "balanced" });
    check("dangerous attr " + attrs[i] + " detected",
          rv.issues.some(function (issue) { return issue.kind === "dangerous-attr"; }));
  }
}

// ---- URL scheme allowlist ----

function testGuardHtmlUrlSchemes() {
  var dangerous = ["javascript:", "vbscript:", "livescript:", "mocha:",
                   "data:text/html,", "file:///", "mhtml:", "view-source:",
                   "jar:", "intent:"];
  for (var i = 0; i < dangerous.length; i++) {
    var rv = b.guardHtml.validate('<a href="' + dangerous[i] + 'x">x</a>',
                                  { profile: "balanced" });
    check("dangerous URL scheme " + JSON.stringify(dangerous[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));
  }

  // Entity-encoded scheme — `&#x6A;avascript:` decodes to javascript:
  var rvEnc = b.guardHtml.validate(
    '<a href="&#x6A;avascript:alert(1)">x</a>', { profile: "balanced" });
  check("entity-encoded javascript: detected after entity decode",
        rvEnc.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // #B7 — NO-semicolon decimal entity `&#106avascript:` (106='j', terminates at
  // the non-digit 'a') is browser-decoded to javascript:. A semicolon-required
  // decoder let this bypass the scheme allowlist as clean.
  var rvNoSemi = b.guardHtml.validate(
    '<a href="&#106avascript:alert(1)">x</a>', { profile: "balanced" });
  check("no-semicolon entity javascript: detected",
        rvNoSemi.issues.some(function (issue) { return issue.kind === "dangerous-url-scheme"; }));

  // Image-context data URL allowed under balanced when allowImageData true.
  var rvImg = b.guardHtml.validate(
    '<img src="data:image/png;base64,iVBORw0KG" alt="x">',
    { profile: "balanced" });
  check("image-context data:image/* allowed under balanced",
        rvImg.ok === true || rvImg.issues.every(function (issue) {
          return issue.kind !== "dangerous-url-scheme" &&
                 issue.kind !== "non-allowlisted-url-scheme";
        }));
}

// ---- CSS injection ----

function testGuardHtmlCssInjection() {
  var payloads = [
    'style="expression(alert(1))"',
    'style="behavior:url(x.htc)"',
    'style="-moz-binding:url(x.xml)"',
    'style="background:url(javascript:alert(1))"',
    'style="@import url(evil.css)"',
  ];
  for (var i = 0; i < payloads.length; i++) {
    var rv = b.guardHtml.validate("<div " + payloads[i] + ">x</div>",
                                  { profile: "balanced" });
    check("CSS injection detected: " + payloads[i].slice(0, 40) + "...",
          rv.issues.some(function (issue) { return issue.kind === "css-injection"; }));
  }
}

// ---- DOM clobbering ----

function testGuardHtmlDomClobbering() {
  var globals = ["document", "window", "cookie", "__proto__",
                 "constructor", "innerHTML", "src", "href"];
  for (var i = 0; i < globals.length; i++) {
    var rv = b.guardHtml.validate(
      '<form id="' + globals[i] + '">x</form>',
      { profile: "balanced" });
    check("DOM clobber id=" + JSON.stringify(globals[i]) + " on form detected",
          rv.issues.some(function (issue) { return issue.kind === "dom-clobber"; }));
  }
  // Same value but on a non-clobber-prone tag (paragraph) → not flagged.
  var rvP = b.guardHtml.validate('<p id="document">x</p>', { profile: "balanced" });
  check("DOM clobber on <p> NOT flagged (not clobber-prone)",
        !rvP.issues.some(function (issue) { return issue.kind === "dom-clobber"; }));
}

// ---- mXSS hint ----

function testGuardHtmlMxssHint() {
  var rvSvg = b.guardHtml.validate("<svg><p>nested</p></svg>",
                                   { profile: "balanced" });
  check("mXSS hint: <svg> namespace shift detected",
        rvSvg.issues.some(function (issue) { return issue.kind === "mxss-hint"; }));
  var rvMath = b.guardHtml.validate("<math><p>nested</p></math>",
                                    { profile: "balanced" });
  check("mXSS hint: <math> namespace shift detected",
        rvMath.issues.some(function (issue) { return issue.kind === "mxss-hint"; }));
}

// ---- IE conditional comments ----

function testGuardHtmlIeConditional() {
  var rv = b.guardHtml.validate("<!--[if IE]><script>alert(1)</script><![endif]-->",
                                { profile: "balanced" });
  check("IE conditional comment detected",
        rv.issues.some(function (issue) { return issue.kind === "ie-conditional-comment"; }));
}

// ---- Bidi / control / null-byte / zero-width ----

function testGuardHtmlBidi() {
  var bidi = "‮";    // RLO
  var rv = b.guardHtml.validate("<p>x" + bidi + "y</p>", { profile: "strict" });
  check("bidi override detected",
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));
}

function testGuardHtmlNullByte() {
  var nb = String.fromCharCode(0);
  var rv = b.guardHtml.validate("<p>x" + nb + "y</p>", { profile: "strict" });
  check("null byte detected",
        rv.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardHtmlControlChar() {
  var ctrl = String.fromCharCode(7);   // BEL
  var rv = b.guardHtml.validate("<p>x" + ctrl + "y</p>", { profile: "strict" });
  check("C0 control char detected",
        rv.issues.some(function (issue) { return issue.kind === "control-char"; }));
}

// ---- Caps ----

function testGuardHtmlSizeCaps() {
  var threwSize = null;
  try { b.guardHtml.sanitize("<p>" + "x".repeat(100), { profile: "strict", maxBytes: 10 }); }
  catch (e) { threwSize = e; }
  check("maxBytes cap throws on sanitize",
        threwSize && /exceeds maxBytes/.test(threwSize.message));

  // maxTagDepth — deeply nested.
  var deep = "";
  for (var i = 0; i < 150; i++) deep += "<div>";
  var rv = b.guardHtml.validate(deep, { profile: "strict", maxTagDepth: 100 });
  check("maxTagDepth cap detected",
        rv.issues.some(function (issue) { return issue.kind === "depth-cap"; }));
}

// Byte caps measure UTF-8 bytes, not UTF-16 code units — a multibyte
// payload under the .length cap but over the byte cap must still be
// refused. "é" is 1 code unit but 2 UTF-8 bytes.
function testGuardHtmlByteCaps() {
  var multi = "é".repeat(8);                 // .length 8, 16 UTF-8 bytes
  check("fixture: multibyte byteLength exceeds .length",
        multi.length === 8 && Buffer.byteLength(multi, "utf8") === 16);

  // Top-level maxBytes — validate path (tokenizer refusal surfaces as an issue).
  var rvSize = b.guardHtml.validate(multi, { profile: "strict", maxBytes: 10 });
  check("maxBytes caps multibyte input over the byte limit (validate)",
        rvSize.issues.some(function (issue) {
          return issue.kind === "tokenize-failed" ||
                 /exceeds maxBytes/.test(issue.snippet || "");
        }));

  // Top-level maxBytes — sanitize path throws.
  var threwBytes = null;
  try { b.guardHtml.sanitize(multi, { profile: "strict", maxBytes: 10 }); }
  catch (e) { threwBytes = e; }
  check("maxBytes caps multibyte input over the byte limit (sanitize)",
        threwBytes && /exceeds maxBytes/.test(threwBytes.message));

  // Multibyte under BOTH the byte cap and .length stays accepted.
  var smallMulti = "é".repeat(3);            // .length 3, 6 bytes
  var rvOk = b.guardHtml.validate(smallMulti, { profile: "strict", maxBytes: 10 });
  check("maxBytes accepts multibyte input under the byte limit",
        !rvOk.issues.some(function (issue) {
          return issue.kind === "tokenize-failed" ||
                 /exceeds maxBytes/.test(issue.snippet || "");
        }));

  // Per-attribute maxAttrValueBytes measures bytes.
  var attrVal = "é".repeat(8);               // .length 8, 16 bytes
  var rvAttr = b.guardHtml.validate('<a title="' + attrVal + '">x</a>',
                                    { profile: "strict", maxAttrValueBytes: 10 });
  check("maxAttrValueBytes caps multibyte attribute value over the byte limit",
        rvAttr.issues.some(function (issue) { return issue.kind === "attr-value-too-large"; }));

  // ASCII attribute value under the byte cap stays accepted.
  var rvAttrOk = b.guardHtml.validate('<a title="short">x</a>',
                                      { profile: "strict", maxAttrValueBytes: 10 });
  check("maxAttrValueBytes accepts attribute value under the byte limit",
        !rvAttrOk.issues.some(function (issue) { return issue.kind === "attr-value-too-large"; }));
}

// ---- Sanitize round-trip ----

function testGuardHtmlCommentEndDifferential() {
  // mXSS comment-parser differential: the WHATWG HTML parser closes a comment
  // at "--!>" (comment-end-bang) and ABRUPTLY at "<!-->" / "<!--->". A
  // tokenizer honouring only "-->" treats the trailing <img onerror> as part
  // of an inert comment; the browser parses it as a LIVE element. With the
  // comment boundary fixed, the <img> is a real token the sanitizer disarms
  // and validate flags — even in the permissive (allowComments) profile.
  var payloads = [
    "<!-- a --!><img src=x onerror=alert(1)>",
    "<!--><img src=x onerror=alert(1)>-->",
    "<!---><img src=x onerror=alert(1)>",
  ];
  for (var i = 0; i < payloads.length; i += 1) {
    var p = payloads[i];
    var s = b.guardHtml.sanitize(p, { profile: "permissive" });
    check("comment-differential: sanitize strips smuggled onerror (" + i + ")",
          s.indexOf("onerror=alert") === -1);
    check("comment-differential: sanitize is not a verbatim pass-through (" + i + ")",
          s !== p);
    var v = b.guardHtml.validate(p, { profile: "permissive" });
    check("comment-differential: validate flags the smuggled element (" + i + ")",
          v.ok === false);
  }
}

function testGuardHtmlSanitizeBasic() {
  var clean = b.guardHtml.sanitize("<p>hello <b>world</b></p>",
                                   { profile: "strict" });
  check("sanitize: allowlisted tags survive",
        /<p>hello <b>world<\/b><\/p>/.test(clean));

  var clean2 = b.guardHtml.sanitize("<script>alert(1)</script><p>hi</p>",
                                    { profile: "strict" });
  check("sanitize: script tag + body dropped",
        clean2 === "<p>hi</p>");

  var clean3 = b.guardHtml.sanitize('<div onclick="x()">hi</div>',
                                    { profile: "strict" });
  check("sanitize: on* attribute stripped",
        clean3.indexOf("onclick") === -1);

  var clean4 = b.guardHtml.sanitize('<a href="javascript:alert(1)">x</a>',
                                    { profile: "balanced" });
  check("sanitize: javascript: href stripped",
        clean4.indexOf("javascript") === -1);

  var clean5 = b.guardHtml.sanitize("<style>body{x:y}</style><p>hi</p>",
                                    { profile: "strict" });
  check("sanitize: style tag + body dropped",
        clean5 === "<p>hi</p>");
}

// ---- escapeText / escapeAttr ----

function testGuardHtmlEscape() {
  check("escapeText: < > &",
        b.guardHtml.escapeText("<a>&b</a>") === "&lt;a&gt;&amp;b&lt;/a&gt;");
  check("escapeText: \"  '",
        b.guardHtml.escapeText('"x\'y') === "&quot;x&#39;y");
  check("escapeAttr: backtick + equals",
        b.guardHtml.escapeAttr("a`b=c") === "a&#96;b&#61;c");
  check("escapeText: null safe",        b.guardHtml.escapeText(null) === "");
  check("escapeAttr: undefined safe",   b.guardHtml.escapeAttr(undefined) === "");
}

// ---- Gate decision shapes ----

async function testGuardHtmlGateClean() {
  var g = b.guardHtml.gate({ profile: "strict" });
  var rv = await g.check({
    contentType: "text/html",
    bytes: Buffer.from("<p>hello</p>"),
  });
  check("gate clean → action=serve", rv.ok === true && rv.action === "serve");
}

async function testGuardHtmlGateRefuse() {
  var g = b.guardHtml.gate({ profile: "strict" });
  var rv = await g.check({
    contentType: "text/html",
    bytes: Buffer.from('<a href="javascript:alert(1)">x</a>'),
  });
  check("gate hostile under strict → action !== serve",
        rv.action !== "serve");
}

async function testGuardHtmlGateSanitize() {
  var g = b.guardHtml.gate({ profile: "balanced" });
  var rv = await g.check({
    contentType: "text/html",
    bytes: Buffer.from('<div onclick="x()">hello</div>'),
  });
  check("gate sanitize-eligible under balanced → action=sanitize or refuse",
        rv.action === "sanitize" || rv.action === "refuse");
}

// ---- Profile + posture vocabulary ----

function testGuardHtmlBadProfile() {
  var threw = null;
  try { b.guardHtml.validate("<p>x</p>", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

function testGuardHtmlCompliancePosture() {
  var hipaa = b.guardHtml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.bidiPolicy === "reject" &&
        hipaa.cssPolicy === "reject");
  var threw = null;
  try { b.guardHtml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

// The gdpr posture is the balanced tier (data-minimization strips bytes
// rather than rejecting the whole value), so it must carry the balanced
// profile's attribute allowlist — which keeps `href`. The strict tier's
// 4-attribute allowlist (class/title/lang/dir) drops href; gdpr must not
// inherit it.
function testGdprPostureMatchesBalancedTier() {
  var sanitized = b.guardHtml.sanitize(
    '<a href="http://x.com/p">L</a>', { compliancePosture: "gdpr" });
  check("gdpr posture keeps href on <a> (balanced tier, not strict backfill)",
        sanitized === '<a href="http://x.com/p">L</a>');
}

// ---- Run all ----

async function run() {
  testGuardHtmlSurface();
  testGuardHtmlRegistryParity();
  testGuardHtmlDangerousTags();
  testGuardHtmlEventHandlers();
  testGuardHtmlDangerousAttrs();
  testGuardHtmlUrlSchemes();
  testGuardHtmlCssInjection();
  testGuardHtmlDomClobbering();
  testGuardHtmlMxssHint();
  testGuardHtmlIeConditional();
  testGuardHtmlBidi();
  testGuardHtmlNullByte();
  testGuardHtmlControlChar();
  testGuardHtmlSizeCaps();
  testGuardHtmlByteCaps();
  testGuardHtmlCommentEndDifferential();
  testGuardHtmlSanitizeBasic();
  testGuardHtmlEscape();
  testGuardHtmlBadProfile();
  testGuardHtmlCompliancePosture();
  testGdprPostureMatchesBalancedTier();
  await testGuardHtmlGateClean();
  await testGuardHtmlGateRefuse();
  await testGuardHtmlGateSanitize();
}

module.exports = { run: run };
