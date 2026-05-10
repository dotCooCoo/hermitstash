"use strict";

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers = require("../helpers");
var dbHelper = require("../helpers/db");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  check("legalHold namespace present",     typeof b.legalHold === "object");
  check("legalHold.create is fn",          typeof b.legalHold.create === "function");
  check("legalHold.KNOWN_CITATIONS list",  Array.isArray(b.legalHold.KNOWN_CITATIONS) &&
                                            b.legalHold.KNOWN_CITATIONS.indexOf("FRCP-26") !== -1);

  // Hermetic db — fresh dataDir per run so the framework schema
  // (which includes _blamejs_legal_hold) is created clean.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-legal-hold-"));
  await dbHelper.setupTestDb(tmpDir);

  var holds = b.legalHold.create({
    db:    b.db,
    audit: b.audit,
  });

  check("place rejects empty subjectId throws", (function () {
    try { holds.place("", { reason: "test" }); return false; }
    catch (_e) { return true; }
  })());

  check("place rejects missing reason throws", (function () {
    try { holds.place("user-1", {}); return false; }
    catch (_e) { return true; }
  })());

  var placeRes = holds.place("user-1", {
    reason:    "SEC subpoena 24-cv-01933",
    custodian: "legal@example.com",
    citation:  "SEC-Rule-17a-4",
  });
  check("place: success",        placeRes.placed === true);

  check("isHeld returns true after placement",  holds.isHeld("user-1") === true);
  check("isHeld returns false on unrelated",    holds.isHeld("user-2") === false);

  var dup = holds.place("user-1", { reason: "duplicate placement test" });
  check("place: duplicate returns already-held", dup.error === "already-held");

  var info = holds.get("user-1");
  check("get returns reason",      info && info.reason === "SEC subpoena 24-cv-01933");
  check("get returns citation",    info && info.citation === "SEC-Rule-17a-4");

  // subject.erase must refuse while held — gated path goes via the
  // singleton registry. The default schema doesn't carry a
  // subjectField so erase() iterates an empty list, but the legal-
  // hold check still fires before any iteration.
  var refused = false;
  try {
    b.subject.erase("user-1", {
      reason: "test erase under hold",
      acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
      legalHold: holds,
    });
  } catch (e) {
    refused = /legal hold/i.test(e.message);
  }
  check("subject.erase refuses while held", refused);

  var release = holds.release("user-1", {
    reason:   "case dismissed",
    approver: "legal@example.com",
  });
  check("release: success",            release.released === true);
  check("isHeld returns false after release", holds.isHeld("user-1") === false);

  // retainUntil sunset
  holds.place("user-2", {
    reason:      "short hold",
    retainUntil: Date.now() - 1000,  // already lapsed
  });
  check("isHeld returns false on lapsed retainUntil", holds.isHeld("user-2") === false);
  var lapsedInfo = holds.get("user-2");
  check("get marks lapsed:true on expired",  lapsedInfo && lapsedInfo.lapsed === true);

  // list returns rows
  var listed = holds.list();
  check("list returns array",          Array.isArray(listed));
  check("list includes placed entry",  listed.length >= 1);

  // Surface assertions — direct b.* references for the coverage gate.
  // legal-hold owns the column-residency table schema, so the
  // cryptoField residency / per-row-key surface lives next to it.
  check("legalHold.LegalHoldError is fn",
        typeof b.legalHold.LegalHoldError === "function");
  check("subject.eraseHard is fn",
        typeof b.subject.eraseHard === "function");
  check("cryptoField.declareColumnResidency is fn",
        typeof b.cryptoField.declareColumnResidency === "function");
  check("cryptoField.getColumnResidency is fn",
        typeof b.cryptoField.getColumnResidency === "function");
  check("cryptoField.assertColumnResidency is fn",
        typeof b.cryptoField.assertColumnResidency === "function");
  check("cryptoField.declarePerRowKey is fn",
        typeof b.cryptoField.declarePerRowKey === "function");
  check("cryptoField.hasPerRowKey is fn",
        typeof b.cryptoField.hasPerRowKey === "function");
  check("cryptoField.materializePerRowKey is fn",
        typeof b.cryptoField.materializePerRowKey === "function");
  check("cryptoField.destroyPerRowKey is fn",
        typeof b.cryptoField.destroyPerRowKey === "function");
  check("cryptoField.clearResidencyForTest is fn",
        typeof b.cryptoField.clearResidencyForTest === "function");

  await dbHelper.teardownTestDb(tmpDir);
}

module.exports = { run: run };
