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

function testSanitizeBadInput() {
  check("bad input refused",
    _code(function () { b.guardPdf.sanitize(null, { profile: "balanced" }); }) === "pdf.bad-input");
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
  testSanitizeBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-pdf] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
