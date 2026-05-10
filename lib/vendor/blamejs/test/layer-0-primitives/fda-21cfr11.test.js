"use strict";
/**
 * b.fda21cfr11 — 21 CFR Part 11 §11.10(e) audit-content + §11.50(b)
 * electronic-signature shape primitives.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAudit() {
  var emitted = [];
  return {
    safeEmit: function (event) { emitted.push(event); },
    query:    function () { return Promise.resolve([]); },
    _emitted: emitted,
  };
}

function testSurface() {
  check("fda21cfr11.posture is a function", typeof b.fda21cfr11.posture === "function");
  check("fda21cfr11.electronicSignature.create exposed",
        typeof b.fda21cfr11.electronicSignature.create === "function");
  check("fda21cfr11.assertGxpAudit exposed",
        typeof b.fda21cfr11.assertGxpAudit === "function");
  check("fda21cfr11.checkGxpAudit is fn",
        typeof b.fda21cfr11.checkGxpAudit === "function");
  check("fda21cfr11.Fda21Cfr11Error is fn",
        typeof b.fda21cfr11.Fda21Cfr11Error === "function");
  check("frameworkError.Fda21Cfr11Error exposed",
        typeof b.frameworkError.Fda21Cfr11Error === "function");
  check("DEFAULT_SIGNATURE_MEANINGS includes 'approval'",
        b.fda21cfr11.DEFAULT_SIGNATURE_MEANINGS.indexOf("approval") !== -1);
}

function testSignatureCreate() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var rec = fda.electronicSignature.create({
    printedName:      "Jane Doe, M.D.",
    signatureMeaning: "approval",
    predicateRule:    "21 CFR 312.62 — investigator records",
    boundRecord:      Buffer.from("trial-data"),
  });
  check("signature has printedName",       rec.printedName === "Jane Doe, M.D.");
  check("signature has dateTimeUtc ISO",   /^\d{4}-\d{2}-\d{2}T/.test(rec.dateTimeUtc));
  check("signature has signatureMeaning",  rec.signatureMeaning === "approval");
  check("signature has predicateRule",     rec.predicateRule.indexOf("21 CFR 312.62") === 0);
  check("signature has recordHash hex",    typeof rec.recordHash === "string" && rec.recordHash.length > 0);
  check("signature has signatureRecord",   typeof rec.signatureRecord === "string");
}

function testSignatureBadMeaning() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.electronicSignature.create({
      printedName: "X", signatureMeaning: "bogus",
      predicateRule: "21 CFR x",
    });
  } catch (e) { threw = e; }
  check("bad signatureMeaning throws Fda21Cfr11Error",
        threw && /bad-signature-meaning/.test(threw.code || ""));
}

function testSignatureMissingPredicate() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.electronicSignature.create({
      printedName: "X", signatureMeaning: "approval",
    });
  } catch (e) { threw = e; }
  check("missing predicateRule throws",
        threw && /missing-predicate-rule/.test(threw.code || ""));
}

function testAssertGxpAuditOk() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "user-1",
    action: "subject.update",
    reason: "operator request",
    metadata: { before: { x: 1 }, after: { x: 2 } },
  });
  check("assertGxpAudit returns true on valid row", ok === true);
}

function testAssertGxpAuditMissingBefore() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var threw = null;
  try {
    fda.assertGxpAudit({
      recordedAt: Date.now(),
      actorUserId: "user-1",
      action: "subject.updated",
      reason: "operator request",
      metadata: { after: { x: 2 } },
    });
  } catch (e) { threw = e; }
  check("assertGxpAudit throws on missing before",
        threw && /gxp-shape-violation/.test(threw.code || ""));
}

function testAssertGxpAuditMetadataAsString() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  // Audit chain rows have metadata as a JSON string. Accept that form.
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "u",
    action: "subject.update",
    reason: "r",
    metadata: JSON.stringify({ before: 1, after: 2 }),
  });
  check("assertGxpAudit accepts JSON-string metadata", ok === true);
}

function testCheckGxpAuditMissingActor() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  var rv = fda.checkGxpAudit({
    recordedAt: Date.now(),
    action: "subject.update",
  });
  check("checkGxpAudit returns ok=false missing-actor",
        rv.ok === false && /actor/.test(rv.reason));
}

function testNonModificationBypassesShape() {
  var fda = b.fda21cfr11.posture({ audit: _fakeAudit(), interceptAudit: false });
  // Read-shaped events don't need before/after.
  var ok = fda.assertGxpAudit({
    recordedAt: Date.now(),
    actorUserId: "u",
    action: "subject.read",
  });
  check("read-shape audit bypasses before/after requirement", ok === true);
}

async function run() {
  testSurface();
  testSignatureCreate();
  testSignatureBadMeaning();
  testSignatureMissingPredicate();
  testAssertGxpAuditOk();
  testAssertGxpAuditMissingBefore();
  testAssertGxpAuditMetadataAsString();
  testCheckGxpAuditMissingActor();
  testNonModificationBypassesShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
