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

  runPerRowResidencyUnit();

  // ---- #114: legal-hold + subject-restriction PII must be SEALED at rest ----
  // These local tables hold legal-basis / custodian / ticket-reference free
  // text that links a data subject to a legal matter — PII at rest. The raw
  // write path (sql.insert + db.prepare().run()) bypassed the structured
  // builder's auto-seal, so the values landed in clear despite the schema.
  var LH_SECRET    = "TOPSECRET-legal-reason-9f3a";
  var LH_CUSTODIAN = "custodian-secret-7b2c@example.com";
  holds.place("seal-subj-1", { reason: LH_SECRET, custodian: LH_CUSTODIAN, citation: "SEC-Rule-17a-4" });
  var lhRaw = JSON.stringify(b.db.prepare("SELECT reason, custodian, citation FROM \"_blamejs_legal_hold\"").all());
  check("#114 legal-hold reason is sealed at rest (not plaintext)",    lhRaw.indexOf(LH_SECRET) === -1);
  check("#114 legal-hold custodian is sealed at rest (not plaintext)", lhRaw.indexOf(LH_CUSTODIAN) === -1);
  var lhGet = holds.get("seal-subj-1");
  check("#114 legal-hold get() unseals on the consumer path",
        !!(lhGet && lhGet.reason === LH_SECRET && lhGet.custodian === LH_CUSTODIAN));
  var lhList = holds.list();
  check("#114 legal-hold list() unseals on the consumer path",
        lhList.some(function (h) { return h.reason === LH_SECRET; }));

  var RES_SECRET = "TOPSECRET-restrict-reason-4e1d";
  b.subject.restrict("seal-subj-2", { on: true, reason: RES_SECRET });
  var resRaw = JSON.stringify(b.db.prepare("SELECT reason FROM \"_blamejs_subject_restrictions\"").all());
  check("#114 subject-restriction reason is sealed at rest (not plaintext)", resRaw.indexOf(RES_SECRET) === -1);

  // ---- B8b: a LAPSED hold must be renewable via place() ----
  // place() rejected "already-held" whenever ANY row existed — including a hold
  // whose retainUntil sunset had passed (isHeld already false). That left a
  // subject both unprotected (isHeld false) AND unable to receive a fresh hold
  // when new litigation arose. A lapsed hold must be replaceable; an ACTIVE one
  // still rejects.
  var lapsedPlace = holds.place("lapse-user", {
    reason: "original matter (sunset already passed)",
    retainUntil: Date.now() - b.constants.TIME.days(1),   // born lapsed
  });
  check("B8b: placing a hold with a past retainUntil succeeds", lapsedPlace.placed === true);
  check("B8b: a lapsed hold reads as NOT held", holds.isHeld("lapse-user") === false);

  var renew = holds.place("lapse-user", {
    reason:    "fresh litigation — renewed hold",
    citation:  "FRCP-26",
  });
  check("B8b: place() RENEWS a lapsed hold (not rejected already-held)", renew.placed === true);
  check("B8b: renewal is flagged renewedFromLapsed", renew.renewedFromLapsed === true);
  check("B8b: subject is held again after renewal", holds.isHeld("lapse-user") === true);
  check("B8b: the renewed hold carries the new reason",
        holds.get("lapse-user").reason === "fresh litigation — renewed hold");

  // Control: an ACTIVE (non-lapsed) hold still rejects a second place().
  var activeReplace = holds.place("lapse-user", { reason: "duplicate attempt" });
  check("B8b: re-placing an ACTIVE hold is still rejected already-held",
        activeReplace.error === "already-held");

  await dbHelper.teardownTestDb(tmpDir);
}

// Returns the thrown error's .code when fn() throws, else null. Mirrors
// the threw-matching pattern used elsewhere in the layer-0 suite.
function codeFromThrow(fn) {
  try { fn(); } catch (e) { return e && e.code; }
  return null;
}

// Per-row residency unit surface (declare/get/clear). The cryptoField
// residency registry is in-process global state, so the block restores
// it via clearResidencyForTest in a finally so a parallel smoke file
// running another residency case isn't poisoned.
function runPerRowResidencyUnit() {
  b.cryptoField.clearResidencyForTest();
  try {
    // ---- valid declare → return shape + getPerRowResidency round-trip ----
    var decl = b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "global"],
    });
    check("declarePerRowResidency returns table",
          decl.table === "residents");
    check("declarePerRowResidency returns residencyColumn",
          decl.residencyColumn === "dataRegion");
    check("declarePerRowResidency returns allowedTags copy",
          Array.isArray(decl.allowedTags) && decl.allowedTags.length === 3 &&
          decl.allowedTags.indexOf("eu-west-1") !== -1);

    var got = b.cryptoField.getPerRowResidency("residents");
    check("getPerRowResidency round-trips residencyColumn",
          got && got.residencyColumn === "dataRegion");
    check("getPerRowResidency round-trips allowedTags",
          got && got.allowedTags.join(",") === "eu-west-1,us-east-1,global");
    check("getPerRowResidency returns a defensive allowedTags copy",
          got.allowedTags !== decl.allowedTags);
    check("getPerRowResidency on undeclared table → null",
          b.cryptoField.getPerRowResidency("never-declared") === null);

    // ---- refusals: each asserts the thrown e.code ----
    check("declarePerRowResidency empty table → table-empty code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("", {
              residencyColumn: "dataRegion", allowedTags: ["eu-west-1"],
            });
          }) === "crypto-field/per-row-residency-table-empty");

    check("declarePerRowResidency null opts → opts-not-object code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("residents", null);
          }) === "crypto-field/per-row-residency-opts-not-object");

    check("declarePerRowResidency bad residencyColumn → column-invalid code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("residents", {
              residencyColumn: "", allowedTags: ["eu-west-1"],
            });
          }) === "crypto-field/per-row-residency-column-invalid");

    check("declarePerRowResidency empty allowedTags → tags-invalid code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("residents", {
              residencyColumn: "dataRegion", allowedTags: [],
            });
          }) === "crypto-field/per-row-residency-tags-invalid");

    check("declarePerRowResidency non-array allowedTags → tags-invalid code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("residents", {
              residencyColumn: "dataRegion", allowedTags: "eu-west-1",
            });
          }) === "crypto-field/per-row-residency-tags-invalid");

    check("declarePerRowResidency non-string tag → tag-empty code",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("residents", {
              residencyColumn: "dataRegion", allowedTags: ["eu-west-1", 42],
            });
          }) === "crypto-field/per-row-residency-tag-empty");

    // Unknown opt key throws via validateOpts (plain Error, no .code) —
    // assert the message names the unknown key + the primitive.
    var unknownKeyErr = null;
    try {
      b.cryptoField.declarePerRowResidency("residents", {
        residencyColumn: "dataRegion", allowedTags: ["eu-west-1"], bogusKey: 1,
      });
    } catch (e) { unknownKeyErr = e; }
    check("declarePerRowResidency unknown opt key throws",
          unknownKeyErr !== null);
    check("declarePerRowResidency unknown opt key message names the key",
          unknownKeyErr && /unknown option 'bogusKey'/.test(unknownKeyErr.message) &&
          /declarePerRowResidency/.test(unknownKeyErr.message));

    // A sealed column can't be the residency tag column — the gate
    // reads the tag as plaintext before sealRow, and reads return it
    // verbatim. Declaring a sealed column refuses at declaration time.
    b.cryptoField.registerTable("sealed_residents", { sealedFields: ["dataRegion"] });
    check("declarePerRowResidency rejects a sealed column as the tag column",
          codeFromThrow(function () {
            b.cryptoField.declarePerRowResidency("sealed_residents", {
              residencyColumn: "dataRegion", allowedTags: ["eu-west-1"],
            });
          }) === "crypto-field/per-row-residency-sealed-conflict");
    check("declarePerRowResidency accepts a non-sealed column on the same table",
          b.cryptoField.declarePerRowResidency("sealed_residents", {
            residencyColumn: "region_tag", allowedTags: ["eu-west-1"],
          }).residencyColumn === "region_tag");

    // ---- clearResidencyForTest clears the per-row registry too ----
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion", allowedTags: ["eu-west-1"],
    });
    check("per-row residency present before clear",
          b.cryptoField.getPerRowResidency("residents") !== null);
    b.cryptoField.clearResidencyForTest();
    check("clearResidencyForTest drops the per-row residency registry",
          b.cryptoField.getPerRowResidency("residents") === null);
  } finally {
    b.cryptoField.clearResidencyForTest();
  }
}

module.exports = { run: run };
