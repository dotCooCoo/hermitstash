"use strict";
/**
 * Tests for b.guardHtml.wcag.audit (WCAG 2.2 audit-only scanner).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var wcag = b.guardHtml.wcag;

function _hasFinding(report, sc) {
  return report.findings.some(function (f) { return f.sc === sc; });
}

// ---- Page-level checks ----

function testHtmlLangMissing() {
  var html = "<html><head><title>X</title></head><body><h1>Hi</h1></body></html>";
  var r = wcag.audit(html);
  check("html missing lang flagged", _hasFinding(r, "3.1.1"));
}

function testHtmlLangPresent() {
  var html = '<html lang="en"><head><title>Hello world</title></head><body><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  check("html lang=en passes", !_hasFinding(r, "3.1.1"));
}

function testPageTitleMissing() {
  var html = '<html lang="en"><head></head><body><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  check("missing title flagged", _hasFinding(r, "2.4.2"));
}

function testPageTitleEmpty() {
  var html = '<html lang="en"><head><title></title></head><body><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  check("empty title flagged", _hasFinding(r, "2.4.2"));
}

function testPageTitleTooShort() {
  var html = '<html lang="en"><head><title>Hi</title></head><body><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  var sc242 = r.findings.filter(function (f) { return f.sc === "2.4.2"; });
  check("short title is warning",
        sc242.length > 0 && sc242[0].severity === "warning");
}

function testPageTitleUntitled() {
  var html = '<html lang="en"><head><title>Untitled Page</title></head><body><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  var sc242 = r.findings.filter(function (f) { return f.sc === "2.4.2"; });
  check("\"Untitled\" title is warning",
        sc242.length > 0 && sc242[0].severity === "warning");
}

function testSkipLinkMissing() {
  var html = '<html lang="en"><head><title>Real page title</title></head><body><h1>Hi</h1><p>x</p></body></html>';
  var r = wcag.audit(html);
  check("missing skip link is info-level",
        _hasFinding(r, "2.4.1"));
}

function testSkipLinkPresent() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><a href="#main">Skip to content</a><h1>Hi</h1></body></html>';
  var r = wcag.audit(html);
  check("skip link found",
        !_hasFinding(r, "2.4.1"));
}

// ---- img alt ----

function testImgWithoutAlt() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="cat.png"></body></html>';
  var r = wcag.audit(html);
  check("img without alt flagged", _hasFinding(r, "1.1.1"));
}

function testImgWithEmptyAlt() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="cat.png" alt=""></body></html>';
  var r = wcag.audit(html);
  check("img with alt=\"\" passes (decorative)",
        !_hasFinding(r, "1.1.1"));
}

function testImgWithDescriptiveAlt() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="cat.png" alt="A black cat"></body></html>';
  var r = wcag.audit(html);
  check("img with alt passes",
        !_hasFinding(r, "1.1.1"));
}

// ---- input labels ----

function testInputWithoutLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><input type="text" name="q"></body></html>';
  var r = wcag.audit(html);
  check("input without label flagged", _hasFinding(r, "3.3.2"));
}

function testInputWithLabelFor() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<label for="q">Search</label>' +
             '<input id="q" type="text" name="q"></body></html>';
  var r = wcag.audit(html);
  check("input with <label for=...> passes",
        !_hasFinding(r, "3.3.2"));
}

function testInputWithAriaLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="text" name="q" aria-label="Search"></body></html>';
  var r = wcag.audit(html);
  check("input with aria-label passes",
        !_hasFinding(r, "3.3.2"));
}

function testInputHiddenSkipped() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="hidden" name="csrf" value="x"></body></html>';
  var r = wcag.audit(html);
  check("hidden input not flagged",
        !_hasFinding(r, "3.3.2"));
}

function testInputWithoutName() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="text" aria-label="Search"></body></html>';
  var r = wcag.audit(html);
  var sc412 = r.findings.filter(function (f) { return f.sc === "4.1.2"; });
  check("input without name is warning",
        sc412.length > 0 && sc412[0].severity === "warning");
}

// ---- buttons ----

function testButtonNoText() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><button></button></body></html>';
  var r = wcag.audit(html);
  check("empty button flagged", _hasFinding(r, "4.1.2"));
}

function testButtonWithText() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><button>Submit</button></body></html>';
  var r = wcag.audit(html);
  check("button with text passes",
        !r.findings.some(function (f) { return f.sc === "4.1.2" && f.element === "button"; }));
}

function testButtonWithAriaLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><button aria-label="Close"><svg></svg></button></body></html>';
  var r = wcag.audit(html);
  check("button with aria-label passes (icon button)",
        !r.findings.some(function (f) { return f.sc === "4.1.2" && f.element === "button"; }));
}

// ---- anchors ----

function testAnchorNoText() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><a href="/foo"></a></body></html>';
  var r = wcag.audit(html);
  check("empty anchor flagged", _hasFinding(r, "2.4.4"));
}

function testAnchorWithText() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><a href="/foo">Foo</a></body></html>';
  var r = wcag.audit(html);
  check("anchor with text passes",
        !_hasFinding(r, "2.4.4"));
}

function testAnchorIconWithAriaLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><a href="/twitter" aria-label="Twitter"><img src="x.png" alt=""></a></body></html>';
  var r = wcag.audit(html);
  check("icon anchor with aria-label passes",
        !_hasFinding(r, "2.4.4"));
}

// ---- heading order ----

function testHeadingFirstNotH1() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h2>Sub</h2></body></html>';
  var r = wcag.audit(html);
  var sc131 = r.findings.filter(function (f) { return f.sc === "1.3.1"; });
  check("first heading not h1 flagged",
        sc131.some(function (f) { return f.message.indexOf("h1") !== -1; }));
}

function testHeadingSkippedLevel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Top</h1><h3>Sub-sub</h3></body></html>';
  var r = wcag.audit(html);
  var sc131 = r.findings.filter(function (f) { return f.sc === "1.3.1"; });
  check("skipped heading level flagged",
        sc131.some(function (f) { return f.message.indexOf("skip") !== -1; }));
}

function testHeadingProperOrder() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Top</h1><h2>Sub</h2><h3>Sub-sub</h3></body></html>';
  var r = wcag.audit(html);
  // No 1.3.1 ordering warning
  var orderings = r.findings.filter(function (f) {
    return f.sc === "1.3.1" && (f.message.indexOf("skip") !== -1 ||
                                f.message.indexOf("first") !== -1);
  });
  check("proper heading order passes",
        orderings.length === 0);
}

function testEmptyHeading() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1></h1></body></html>';
  var r = wcag.audit(html);
  var sc131 = r.findings.filter(function (f) { return f.sc === "1.3.1"; });
  check("empty heading flagged",
        sc131.some(function (f) { return f.message.indexOf("Empty") !== -1; }));
}

// ---- Conformance level filter ----

function testLevelAOnly() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1></body></html>';
  var rA = wcag.audit(html, { level: "A" });
  var rAA = wcag.audit(html, { level: "AA" });
  // Skip-link is info-level (info doesn't depend on conformance level
  // strictly; the SC 2.4.1 is level A so both audits should report it)
  check("level A audit captures level-A SCs", _hasFinding(rA, "2.4.1"));
  check("level AA audit captures level-A SCs too", _hasFinding(rAA, "2.4.1"));
}

// ---- Ignore list ----

function testIgnoreSc() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="x.png"></body></html>';
  var rNoIgnore = wcag.audit(html);
  var rWithIgnore = wcag.audit(html, { ignore: ["1.1.1"] });
  check("ignored SC removed",
        _hasFinding(rNoIgnore, "1.1.1") && !_hasFinding(rWithIgnore, "1.1.1"));
}

// ---- Score ----

function testScoreFullClean() {
  var html = '<html lang="en">' +
             '<head><title>A descriptive page title</title></head>' +
             '<body><a href="#main">Skip to content</a>' +
             '<h1>Hi</h1>' +
             '<p>Body content here.</p>' +
             '</body></html>';
  var r = wcag.audit(html);
  check("clean page score >= 0.8",
        typeof r.score === "number" && r.score >= 0.8);
}

function testScoreManyErrors() {
  var html = '<html><head></head><body><img><img><img></body></html>';
  var r = wcag.audit(html);
  check("messy page score < 0.7",
        r.score < 0.7);
}

// ---- Validation ----

function testAuditValidation() {
  var threwBadHtml = false;
  try { wcag.audit(123); } catch (_e) { threwBadHtml = true; }
  check("audit: non-string html throws", threwBadHtml);

  var threwBadLevel = false;
  try { wcag.audit("<html></html>", { level: "X" }); }
  catch (_e) { threwBadLevel = true; }
  check("audit: invalid level throws", threwBadLevel);

  var threwBadIgnore = false;
  try { wcag.audit("<html></html>", { ignore: [123] }); }
  catch (_e) { threwBadIgnore = true; }
  check("audit: non-string ignore entry throws", threwBadIgnore);
}

// ---- Report shape ----

function testReportShape() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="x"></body></html>';
  var r = wcag.audit(html, { scopeUrl: "https://example.com/p" });
  check("report.scopeUrl preserved",
        r.scopeUrl === "https://example.com/p");
  check("report has summary",
        r.summary && typeof r.summary.error === "number");
  check("report has scannedAt",
        typeof r.scannedAt === "number");
  check("report findings have line/column",
        r.findings.every(function (f) {
          return typeof f.line === "number" && typeof f.column === "number";
        }));
  check("report findings have remediation",
        r.findings.every(function (f) { return typeof f.remediation === "string"; }));
}

function testFindingFields() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1><img src="x"></body></html>';
  var r = wcag.audit(html);
  var imgFinding = r.findings.find(function (f) { return f.sc === "1.1.1"; });
  check("img finding has element=img",
        imgFinding && imgFinding.element === "img");
  check("img finding has severity",
        imgFinding && imgFinding.severity === "error");
  check("img finding references SC 1.1.1",
        imgFinding && imgFinding.sc === "1.1.1");
  check("img finding has level=A",
        imgFinding && imgFinding.level === "A");
}

// ---- de-advertised opts ----

function testAuditRejectsCheckAll() {
  // checkAll was an accepted-but-never-read knob; it is no longer in the
  // validateOpts allowlist, so passing it is now a config-time error.
  var threw = false;
  try { wcag.audit("<html lang=\"en\"><head><title>Real page title</title></head><body></body></html>",
                   { checkAll: true }); }
  catch (_e) { threw = true; }
  check("audit: unknown checkAll opt throws", threw);
}

// ---- scopeUrl stamped onto sub-scanner findings ----

function testSubScannerScopeUrlStamped() {
  var url = "https://example.com/page";

  var ariaFindings = wcag.aria.audit('<div role="invalidrole"></div>', { scopeUrl: url });
  check("aria sub-scanner: scopeUrl stamped on finding",
        ariaFindings.length >= 1 &&
        ariaFindings.every(function (f) { return f.scopeUrl === url; }));

  var tableFindings = wcag.tables.audit('<table><tbody><tr><td>1</td></tr></tbody></table>', { scopeUrl: url });
  check("tables sub-scanner: scopeUrl stamped on finding",
        tableFindings.length >= 1 &&
        tableFindings.every(function (f) { return f.scopeUrl === url; }));

  var formFindings = wcag.forms.audit('<textarea></textarea>', { scopeUrl: url });
  check("forms sub-scanner: scopeUrl stamped on finding",
        formFindings.length >= 1 &&
        formFindings.every(function (f) { return f.scopeUrl === url; }));
}

function testSubScannerScopeUrlDefaultUnchanged() {
  // No scopeUrl → findings carry no scopeUrl field (default behavior).
  var ariaFindings = wcag.aria.audit('<div role="invalidrole"></div>');
  check("aria sub-scanner: no scopeUrl field by default",
        ariaFindings.length >= 1 &&
        ariaFindings.every(function (f) { return f.scopeUrl === undefined; }));

  var tableFindings = wcag.tables.audit('<table><tbody><tr><td>1</td></tr></tbody></table>');
  check("tables sub-scanner: no scopeUrl field by default",
        tableFindings.length >= 1 &&
        tableFindings.every(function (f) { return f.scopeUrl === undefined; }));

  var formFindings = wcag.forms.audit('<textarea></textarea>');
  check("forms sub-scanner: no scopeUrl field by default",
        formFindings.length >= 1 &&
        formFindings.every(function (f) { return f.scopeUrl === undefined; }));

  // Empty-string scopeUrl is treated as absent (no stamp).
  var emptyScope = wcag.aria.audit('<div role="invalidrole"></div>', { scopeUrl: "" });
  check("aria sub-scanner: empty scopeUrl not stamped",
        emptyScope.every(function (f) { return f.scopeUrl === undefined; }));
}

// ---- SC registry ----

function testRegistryShape() {
  check("SC_REGISTRY has 1.1.1",
        wcag.SC_REGISTRY["1.1.1"] && wcag.SC_REGISTRY["1.1.1"].level === "A");
  check("SC_REGISTRY has 2.5.8 (target size)",
        wcag.SC_REGISTRY["2.5.8"] && wcag.SC_REGISTRY["2.5.8"].level === "AA");
  check("SC_REGISTRY has 3.3.7 (redundant entry, 2.2 addition)",
        wcag.SC_REGISTRY["3.3.7"] !== undefined);
  check("SC_REGISTRY frozen",
        Object.isFrozen(wcag.SC_REGISTRY));
}

// ---- ARIA validation ----

function testAriaUnknownRole() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="invalidrole">x</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var unknown = r.findings.filter(function (f) {
    return f.message.indexOf("Unknown ARIA role") !== -1;
  });
  check("aria: unknown role flagged",
        unknown.length === 1 && unknown[0].severity === "warning");
}

function testAriaKnownRole() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<nav role="navigation">x</nav>' +
             '</body></html>';
  var r = wcag.audit(html);
  var unknown = r.findings.filter(function (f) {
    return f.message.indexOf("Unknown ARIA role") !== -1;
  });
  check("aria: known role passes", unknown.length === 0);
}

function testAriaMissingRequiredProp() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="checkbox">x</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var missing = r.findings.filter(function (f) {
    return f.message.indexOf("requires attribute") !== -1;
  });
  check("aria: role=checkbox missing aria-checked flagged",
        missing.length === 1 && missing[0].message.indexOf("aria-checked") !== -1);
}

function testAriaWithRequiredProp() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="checkbox" aria-checked="true">x</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var missing = r.findings.filter(function (f) {
    return f.message.indexOf("requires attribute") !== -1;
  });
  check("aria: required prop satisfied", missing.length === 0);
}

function testAriaInvalidValue() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="checkbox" aria-checked="maybe">x</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var bad = r.findings.filter(function (f) {
    return f.message.indexOf("not in the allowed value set") !== -1;
  });
  check("aria: invalid aria-checked value flagged",
        bad.length === 1);
}

function testAriaValidValue() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="checkbox" aria-checked="mixed">x</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var bad = r.findings.filter(function (f) {
    return f.message.indexOf("not in the allowed value set") !== -1;
  });
  check("aria: valid aria-checked value passes", bad.length === 0);
}

function testAriaUnresolvedReference() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<button aria-labelledby="missing-id">x</button>' +
             '</body></html>';
  var r = wcag.audit(html);
  var unresolved = r.findings.filter(function (f) {
    return f.message.indexOf("references id that is not declared") !== -1;
  });
  check("aria: unresolved aria-labelledby flagged",
        unresolved.length === 1);
}

function testAriaResolvedReference() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<span id="lbl">Save</span>' +
             '<button aria-labelledby="lbl"></button>' +
             '</body></html>';
  var r = wcag.audit(html);
  var unresolved = r.findings.filter(function (f) {
    return f.message.indexOf("references id that is not declared") !== -1;
  });
  check("aria: resolved aria-labelledby passes",
        unresolved.length === 0);
}

function testAriaHiddenInteractive() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<button aria-hidden="true">Click</button>' +
             '</body></html>';
  var r = wcag.audit(html);
  var conflict = r.findings.filter(function (f) {
    return f.message.indexOf("aria-hidden") !== -1;
  });
  check("aria: aria-hidden on interactive flagged",
        conflict.length === 1);
}

function testAriaHiddenStaticElement() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div aria-hidden="true">decorative</div>' +
             '</body></html>';
  var r = wcag.audit(html);
  var conflict = r.findings.filter(function (f) {
    return f.message.indexOf("aria-hidden") !== -1;
  });
  check("aria: aria-hidden on static div passes",
        conflict.length === 0);
}

function testAriaCustomAllowedRole() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="custom-design-system-widget">x</div>' +
             '</body></html>';
  var rNoAllow = wcag.audit(html);
  var unknownNoAllow = rNoAllow.findings.filter(function (f) {
    return f.message.indexOf("Unknown ARIA role") !== -1;
  });
  check("aria: custom role flagged by default",
        unknownNoAllow.length === 1);

  var rAllow = wcag.audit(html, { allowedRoles: ["custom-design-system-widget"] });
  var unknownAllow = rAllow.findings.filter(function (f) {
    return f.message.indexOf("Unknown ARIA role") !== -1;
  });
  check("aria: allowedRoles override accepts custom role",
        unknownAllow.length === 0);
}

function testAriaSkipAria() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<div role="invalidrole">x</div>' +
             '</body></html>';
  var rNoAria = wcag.audit(html, { skipAria: true });
  var unknown = rNoAria.findings.filter(function (f) {
    return f.message.indexOf("Unknown ARIA role") !== -1;
  });
  check("aria: skipAria removes ARIA findings", unknown.length === 0);
}

// ---- ARIA standalone module ----

function testAriaStandalone() {
  var aria = wcag.aria;
  check("aria.KNOWN_ROLES exposed",
        Array.isArray(aria.KNOWN_ROLES) && aria.KNOWN_ROLES.indexOf("button") !== -1);
  check("aria.ROLE_REQUIRED_PROPS exposed",
        aria.ROLE_REQUIRED_PROPS && Array.isArray(aria.ROLE_REQUIRED_PROPS["checkbox"]));
  check("aria.ARIA_VALUE_SETS exposed",
        Array.isArray(aria.ARIA_VALUE_SETS["aria-checked"]));

  var findings = aria.audit('<div role="invalidrole"></div>');
  check("aria.audit standalone returns array",
        Array.isArray(findings) && findings.length === 1);
}

// ---- Table semantics ----

function testTableNoCaption() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><thead><tr><th>A</th></tr></thead><tbody><tr><td>1</td></tr></tbody></table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var captionWarn = r.findings.filter(function (f) {
    return f.element === "table" && f.message.indexOf("caption") !== -1;
  });
  check("table without caption flagged", captionWarn.length === 1);
}

function testTableWithCaption() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><caption>Quarterly results</caption>' +
             '<thead><tr><th scope="col">Q1</th></tr></thead></table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var captionWarn = r.findings.filter(function (f) {
    return f.element === "table" && f.message.indexOf("caption") !== -1;
  });
  check("table with caption passes", captionWarn.length === 0);
}

function testTablePresentationRoleSkipsCaption() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table role="presentation"><tr><td>x</td></tr></table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var captionWarn = r.findings.filter(function (f) {
    return f.element === "table" && f.message.indexOf("caption") !== -1;
  });
  check("layout table (role=presentation) doesn't need caption",
        captionWarn.length === 0);
}

function testThWithoutScope() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><caption>x</caption><thead><tr><th>A</th></tr></thead></table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var thWarn = r.findings.filter(function (f) {
    return f.element === "th" && f.message.indexOf("scope") !== -1;
  });
  check("th without scope flagged", thWarn.length === 1);
}

function testThWithValidScope() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><caption>x</caption>' +
             '<thead><tr><th scope="col">A</th></tr></thead>' +
             '<tbody><tr><th scope="row">B</th><td>1</td></tr></tbody>' +
             '</table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var thWarn = r.findings.filter(function (f) {
    return f.element === "th";
  });
  check("th with valid scope passes", thWarn.length === 0);
}

function testThWithInvalidScope() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><caption>x</caption>' +
             '<thead><tr><th scope="diagonal">A</th></tr></thead>' +
             '</table>' +
             '</body></html>';
  var r = wcag.audit(html);
  var thBad = r.findings.filter(function (f) {
    return f.element === "th" && f.message.indexOf("not in the allowed") !== -1;
  });
  check("th with invalid scope value flagged",
        thBad.length === 1 && thBad[0].severity === "error");
}

function testTrOutsideTable() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<tr><td>orphan</td></tr>' +
             '</body></html>';
  var r = wcag.audit(html);
  var trWarn = r.findings.filter(function (f) {
    return f.element === "tr" && f.message.indexOf("outside") !== -1;
  });
  check("tr outside table context flagged",
        trWarn.length === 1);
}

function testSkipTables() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<table><tr><th>A</th></tr></table>' +
             '</body></html>';
  var rNoTables = wcag.audit(html, { skipTables: true });
  var tableFindings = rNoTables.findings.filter(function (f) {
    return f.element === "table" || f.element === "th" || f.element === "tr";
  });
  check("skipTables removes table findings",
        tableFindings.length === 0);
}

function testTablesStandalone() {
  var t = wcag.tables;
  check("tables.VALID_SCOPE_VALUES exposed",
        Array.isArray(t.VALID_SCOPE_VALUES) &&
        t.VALID_SCOPE_VALUES.indexOf("col") !== -1);
  var findings = t.audit("<table><tr><th>X</th></tr></table>");
  check("tables.audit standalone returns array",
        Array.isArray(findings));
}

// ---- Forms validation ----

function testFieldsetWithoutLegend() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<form><fieldset>' +
             '<input type="text" name="x" aria-label="X">' +
             '</fieldset></form>' +
             '</body></html>';
  var r = wcag.audit(html);
  var fsetFindings = r.findings.filter(function (f) {
    return f.element === "fieldset" && f.message.indexOf("legend") !== -1;
  });
  check("forms: fieldset without legend flagged",
        fsetFindings.length === 1);
}

function testFieldsetWithLegend() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<form><fieldset><legend>Group</legend>' +
             '<input type="text" name="x" aria-label="X">' +
             '</fieldset></form>' +
             '</body></html>';
  var r = wcag.audit(html);
  var fsetFindings = r.findings.filter(function (f) {
    return f.element === "fieldset" && f.message.indexOf("legend") !== -1;
  });
  check("forms: fieldset with legend passes",
        fsetFindings.length === 0);
}

function testAutocompleteUnknownToken() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="text" name="x" aria-label="X" autocomplete="customtoken">' +
             '</body></html>';
  var r = wcag.audit(html);
  var acFindings = r.findings.filter(function (f) {
    return f.message.indexOf("autocomplete=") !== -1;
  });
  check("forms: unknown autocomplete token flagged",
        acFindings.length === 1);
}

function testAutocompleteKnownToken() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="email" name="email" aria-label="Email" autocomplete="email">' +
             '</body></html>';
  var r = wcag.audit(html);
  var acFindings = r.findings.filter(function (f) {
    return f.message.indexOf("autocomplete=") !== -1;
  });
  check("forms: known autocomplete token passes",
        acFindings.length === 0);
}

function testAutocompleteCompoundToken() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="text" name="x" aria-label="X" autocomplete="section-billing tel">' +
             '</body></html>';
  var r = wcag.audit(html);
  var acFindings = r.findings.filter(function (f) {
    return f.message.indexOf("autocomplete=") !== -1;
  });
  check("forms: compound autocomplete (canonical token last) passes",
        acFindings.length === 0);
}

function testPasswordAutocompleteOff() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="password" name="p" aria-label="Password" autocomplete="off">' +
             '</body></html>';
  var r = wcag.audit(html);
  var pwFindings = r.findings.filter(function (f) {
    return f.sc === "3.3.8";
  });
  check("forms: password+autocomplete=off flagged",
        pwFindings.length === 1);
}

function testTextareaWithoutLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<textarea name="msg"></textarea>' +
             '</body></html>';
  var r = wcag.audit(html);
  var taFindings = r.findings.filter(function (f) {
    return f.element === "textarea";
  });
  check("forms: textarea without label flagged",
        taFindings.length === 1);
}

function testTextareaWithLabel() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<textarea name="msg" aria-label="Your message"></textarea>' +
             '</body></html>';
  var r = wcag.audit(html);
  var taFindings = r.findings.filter(function (f) {
    return f.element === "textarea";
  });
  check("forms: textarea with aria-label passes",
        taFindings.length === 0);
}

function testInputEmailNoAutocomplete() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<input type="email" name="e" aria-label="Email">' +
             '</body></html>';
  var r = wcag.audit(html);
  var redundant = r.findings.filter(function (f) {
    return f.sc === "3.3.7";
  });
  check("forms: email input without autocomplete is info",
        redundant.length === 1 && redundant[0].severity === "info");
}

function testSkipForms() {
  var html = '<html lang="en"><head><title>Real page title</title></head>' +
             '<body><h1>Hi</h1>' +
             '<fieldset><input type="text" name="x" aria-label="X"></fieldset>' +
             '</body></html>';
  var rNoForms = wcag.audit(html, { skipForms: true });
  var formFindings = rNoForms.findings.filter(function (f) {
    return f.element === "fieldset" || f.element === "textarea";
  });
  check("skipForms removes form findings",
        formFindings.length === 0);
}

function testFormsStandalone() {
  var fr = wcag.forms;
  check("forms.AUTOCOMPLETE_TOKENS exposed",
        Array.isArray(fr.AUTOCOMPLETE_TOKENS) &&
        fr.AUTOCOMPLETE_TOKENS.indexOf("email") !== -1);
  var findings = fr.audit('<input autocomplete="bogus">');
  check("forms.audit standalone returns array",
        Array.isArray(findings));
}

// ---- Run all ----

(function run() {
  testHtmlLangMissing();
  testHtmlLangPresent();
  testPageTitleMissing();
  testPageTitleEmpty();
  testPageTitleTooShort();
  testPageTitleUntitled();
  testSkipLinkMissing();
  testSkipLinkPresent();
  testImgWithoutAlt();
  testImgWithEmptyAlt();
  testImgWithDescriptiveAlt();
  testInputWithoutLabel();
  testInputWithLabelFor();
  testInputWithAriaLabel();
  testInputHiddenSkipped();
  testInputWithoutName();
  testButtonNoText();
  testButtonWithText();
  testButtonWithAriaLabel();
  testAnchorNoText();
  testAnchorWithText();
  testAnchorIconWithAriaLabel();
  testHeadingFirstNotH1();
  testHeadingSkippedLevel();
  testHeadingProperOrder();
  testEmptyHeading();
  testLevelAOnly();
  testIgnoreSc();
  testScoreFullClean();
  testScoreManyErrors();
  testAuditValidation();
  testAuditRejectsCheckAll();
  testSubScannerScopeUrlStamped();
  testSubScannerScopeUrlDefaultUnchanged();
  testReportShape();
  testFindingFields();
  testRegistryShape();
  testAriaUnknownRole();
  testAriaKnownRole();
  testAriaMissingRequiredProp();
  testAriaWithRequiredProp();
  testAriaInvalidValue();
  testAriaValidValue();
  testAriaUnresolvedReference();
  testAriaResolvedReference();
  testAriaHiddenInteractive();
  testAriaHiddenStaticElement();
  testAriaCustomAllowedRole();
  testAriaSkipAria();
  testAriaStandalone();
  testTableNoCaption();
  testTableWithCaption();
  testTablePresentationRoleSkipsCaption();
  testThWithoutScope();
  testThWithValidScope();
  testThWithInvalidScope();
  testTrOutsideTable();
  testSkipTables();
  testTablesStandalone();
  testFieldsetWithoutLegend();
  testFieldsetWithLegend();
  testAutocompleteUnknownToken();
  testAutocompleteKnownToken();
  testAutocompleteCompoundToken();
  testPasswordAutocompleteOff();
  testTextareaWithoutLabel();
  testTextareaWithLabel();
  testInputEmailNoAutocomplete();
  testSkipForms();
  testFormsStandalone();
})();
