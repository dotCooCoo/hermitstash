// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-pdf — PDF content-safety primitive (b.guardPdf).
 *
 * Covers: surface; registry parity; magic-byte / declared-MIME mismatch;
 * polyglot; JavaScript / Launch / OpenAction active-content detection;
 * embedded files; encryption; inspectMagic; and the disarm-by-refusal
 * sanitize — PDF active content lives in a cross-referenced object graph
 * that cannot be excised without a vendored parser, so sanitize forces every
 * active-content / exfil / encryption policy to reject and refuses anything
 * it cannot disarm rather than passing a live action through.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var _PDF = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]);                           // %PDF-
function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testGuardPdfSurface() {
  check("guardPdf is an object",                typeof b.guardPdf === "object");
  check("guardPdf.NAME === 'pdf'",              b.guardPdf.NAME === "pdf");
  check("guardPdf.PROFILES has strict",         !!b.guardPdf.PROFILES["strict"]);
  check("guardPdf.COMPLIANCE_POSTURES hipaa",   !!b.guardPdf.COMPLIANCE_POSTURES["hipaa"]);
  check("guardPdf.validate is a function",      typeof b.guardPdf.validate === "function");
  check("guardPdf.sanitize is a function",      typeof b.guardPdf.sanitize === "function");
  check("guardPdf.gate is a function",          typeof b.guardPdf.gate === "function");
  check("frameworkError.GuardPdfError exposed", typeof b.frameworkError.GuardPdfError === "function");
}

function testGuardPdfRegistryParity() {
  check("guardPdf registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "pdf"; }));
}

function testValidateActiveContent() {
  var rv = b.guardPdf.validate({ bytes: _PDF, hasJavaScript: true }, { profile: "strict" });
  check("javascript: validate ok:false", rv.ok === false);
  check("javascript: kind reported", rv.issues.some(function (i) { return i.kind === "javascript-action"; }));
}

// ---- disarm-by-refusal sanitize ----

function testSanitizeInertPassthrough() {
  var inert = { bytes: _PDF };
  var out = b.guardPdf.sanitize(inert, { profile: "balanced" });
  check("inert PDF passes through unchanged", out === inert);
}

function testSanitizeRefusesJavaScript() {
  check("javascript refused",
    _code(function () { b.guardPdf.sanitize({ bytes: _PDF, hasJavaScript: true }, { profile: "balanced" }); }) === "pdf.javascript-action");
}

function testSanitizeRefusesLaunch() {
  check("launch refused",
    _code(function () { b.guardPdf.sanitize({ bytes: _PDF, hasLaunchAction: true }, { profile: "balanced" }); }) === "pdf.launch-action");
}

function testSanitizeForcesOpenActionReject() {
  // open-action is warn-level under permissive at the gate, but sanitize forces
  // reject (it cannot strip the action) → refuse, never a silent passthrough.
  check("open-action refused under sanitize even at permissive",
    _code(function () { b.guardPdf.sanitize({ bytes: _PDF, hasOpenAction: true }, { profile: "permissive" }); }) === "pdf.open-action");
}

function testSanitizeForcesEmbeddedFileReject() {
  check("embedded-file refused under sanitize even at permissive",
    _code(function () { b.guardPdf.sanitize({ bytes: _PDF, hasEmbeddedFiles: true }, { profile: "permissive" }); }) === "pdf.embedded-file");
}

function testSanitizeForcesEncryptedReject() {
  check("encrypted refused under sanitize even at permissive",
    _code(function () { b.guardPdf.sanitize({ bytes: _PDF, isEncrypted: true }, { profile: "permissive" }); }) === "pdf.encrypted");
}

// An operator-supplied permissive policy opt must NOT let sanitize hand back a
// PDF that still carries an RCE-class action. sanitize is disarm-by-refusal and
// forces the active-content policies to reject; the forced set previously
// covered open-action / embedded-file / encrypted but OMITTED the three classes
// the guard "refuses to negotiate" on — JavaScript, Launch, and polyglot — so
// `sanitize(bag, { javascriptPolicy: "allow" })` returned the live PDF. Each of
// these drives the same override object and must refuse regardless of the opt.
function testSanitizeForcesJavaScriptRejectOverOperatorAllow() {
  check("javascript refused under sanitize even when javascriptPolicy:allow",
    _code(function () {
      b.guardPdf.sanitize({ bytes: _PDF, hasJavaScript: true },
        { profile: "strict", javascriptPolicy: "allow" });
    }) === "pdf.javascript-action");
  check("javascript refused under sanitize even when javascriptPolicy:audit",
    _code(function () {
      b.guardPdf.sanitize({ bytes: _PDF, hasJavaScript: true },
        { profile: "permissive", javascriptPolicy: "audit" });
    }) === "pdf.javascript-action");
}

function testSanitizeForcesLaunchRejectOverOperatorAllow() {
  check("launch refused under sanitize even when launchActionPolicy:allow",
    _code(function () {
      b.guardPdf.sanitize({ bytes: _PDF, hasLaunchAction: true },
        { profile: "strict", launchActionPolicy: "allow" });
    }) === "pdf.launch-action");
}

function testSanitizeForcesPolyglotRejectOverOperatorAllow() {
  check("polyglot refused under sanitize even when polyglotPolicy:allow",
    _code(function () {
      b.guardPdf.sanitize({ bytes: _PDF, polyglotDetected: true },
        { profile: "strict", polyglotPolicy: "allow" });
    }) === "pdf.polyglot");
}

function testSanitizeBadInput() {
  check("bad input refused",
    _code(function () { b.guardPdf.sanitize(null, { profile: "balanced" }); }) === "pdf.bad-input");
}

// ---- magic-byte inspection ----

function testInspectMagic() {
  // %PDF-1.7 header (25 50 44 46 2D 31 2E 37) — real PDF prefix.
  var pdfBytes = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]);
  check("inspectMagic: %PDF- prefix → true",
    b.guardPdf.inspectMagic(pdfBytes) === true);
  // Exactly the 5-byte magic is enough.
  check("inspectMagic: bare %PDF- (5 bytes) → true",
    b.guardPdf.inspectMagic(_PDF) === true);
  // Non-PDF bytes — the operator fed the wrong gate.
  check("inspectMagic: mismatching bytes → false",
    b.guardPdf.inspectMagic(Buffer.from([0x00, 0x01, 0x02])) === false);
  // A buffer shorter than the 5-byte magic can't match.
  check("inspectMagic: too-short buffer → false",
    b.guardPdf.inspectMagic(Buffer.from([0x25, 0x50])) === false);
  // Near-miss: right length, one byte off (0x2E vs 0x2D at index 4).
  check("inspectMagic: one-byte-off prefix → false",
    b.guardPdf.inspectMagic(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2E])) === false);
  // Pure inspection — never throws on non-Buffer input.
  check("inspectMagic: null input → false (no throw)",
    b.guardPdf.inspectMagic(null) === false);
}

function run() {
  testGuardPdfSurface();
  testGuardPdfRegistryParity();
  testValidateActiveContent();
  testSanitizeInertPassthrough();
  testSanitizeRefusesJavaScript();
  testSanitizeRefusesLaunch();
  testSanitizeForcesOpenActionReject();
  testSanitizeForcesEmbeddedFileReject();
  testSanitizeForcesEncryptedReject();
  testSanitizeForcesJavaScriptRejectOverOperatorAllow();
  testSanitizeForcesLaunchRejectOverOperatorAllow();
  testSanitizeForcesPolyglotRejectOverOperatorAllow();
  testSanitizeBadInput();
  testInspectMagic();
  testValidateNeverThrowsOnArrayLikeBytes();
}

// ---- validate must never throw on hostile metadata (sibling of the guard-image
// array-like crash: byteLengthOf was called for any numeric-.length value, but
// it only accepts string/Buffer/Uint8Array and threw TypeError on a plain Array
// / array-like bag, crashing a direct validate/sanitize caller). ----
function testValidateNeverThrowsOnArrayLikeBytes() {
  check("validate does not throw on Array-typed bytes",
    _code(function () { b.guardPdf.validate({ bytes: [0x25, 0x50, 0x44, 0x46] }, { profile: "balanced" }); }) === null);
  check("validate does not throw on array-like-object bytes",
    _code(function () { b.guardPdf.validate({ bytes: { length: 1e9 } }, { profile: "strict" }); }) === null);
  // The unrecognized array-like content is still refused (unknown-magic under
  // strict), not served — never-throw does not mean fail-open.
  var rv = b.guardPdf.validate({ bytes: [1, 2, 3] }, { profile: "strict" });
  check("array-like bytes → refused (ok:false), not a crash", rv.ok === false);
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-pdf] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
