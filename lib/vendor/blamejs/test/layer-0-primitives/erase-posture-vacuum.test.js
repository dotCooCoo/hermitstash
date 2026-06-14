"use strict";
/**
 * b.cryptoField.eraseRow posture-driven VACUUM cascade.
 *
 * The advertised guarantee (crypto-field.js eraseRow docstring +
 * compliance.js POSTURE_DEFAULTS): under a regulatory posture whose
 * requireVacuumAfterErase floor is true, calling eraseRow on a sealed-
 * column table automatically runs b.db.vacuumAfterErase({ mode:"full" })
 * so SQLite's freed B-tree pages don't keep sealed-column ciphertext
 * recoverable from a forensic disk image — the residual that would
 * defeat the right-to-erasure the regime guarantees.
 *
 * This drives that guarantee end-to-end on a REAL encrypted-at-rest DB
 * (wrapped vault, sealed db.enc, signed audit chain — the production
 * path via setupTestDb). The vacuum entry point is wrapped with a
 * call-through spy: the real VACUUM still executes against the real
 * tmpfs SQLite, AND the framework's own `db.vacuum_after_erase` row is
 * read back out of the signed audit chain as the observable side
 * effect.
 *
 * gdpr / hipaa MUST trigger the vacuum (positive control).
 *
 * uk-gdpr / appi-jp / pdpa-sg are all in
 * b.compliance.CROSS_BORDER_REGULATED_POSTURES — the same cross-border
 * privacy regimes whose Art. 17-equivalent right-to-erasure applies
 * identically (uk-gdpr is literally "retained EU GDPR"), so they MUST
 * trigger the same mandatory residue VACUUM. An invariant below asserts
 * that EVERY cross-border regulated posture carries the
 * requireVacuumAfterErase floor, so a newly-added regime can never
 * silently drop the residue cleanup the right-to-erasure depends on.
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var setupTestDb    = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;

var SEALED_SCHEMA = [
  {
    name: "patients",
    columns: {
      _id:     "TEXT PRIMARY KEY",
      ssn:     "TEXT",
      ssnHash: "TEXT",
      name:    "TEXT",
    },
    indexes: ["ssnHash"],
    sealedFields:  ["ssn", "name"],
    derivedHashes: { ssnHash: { from: "ssn" } },
    // AAD-bound envelope so the table satisfies the HIPAA
    // sealEnvelopeFloor:"aad" gate as well as the no-floor postures.
    aad:        true,
    rowIdField: "_id",
  },
];

// Drive the full erase under one posture against a real encrypted DB
// and report whether the posture-cascade actually fired the VACUUM.
// Returns { vacuumCalled, modeFull, auditRowSeen }.
async function eraseUnderPosture(posture) {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-erasevac-"));
  await setupTestDb(dataDir, SEALED_SCHEMA);

  // Pin the posture. The cascade calls cryptoField.applyPosture(posture)
  // (records _activePosture) + db.applyPosture(posture). This is the
  // exact boot wiring an operator running under `posture` gets.
  b.compliance._resetForTest();
  b.compliance.set(posture);
  check("compliance.current cascaded -> " + posture,
        b.compliance.current() === posture);
  check("cryptoField active posture cascaded -> " + posture,
        b.cryptoField.getActivePosture() === posture);

  // The sealed table is already in the field-crypto registry —
  // setupTestDb's db.init registered it from the schema (sealedFields /
  // derivedHashes / aad) — so eraseRow has a schema to tombstone against.

  // Persist a real row through the real field-crypto + db path
  // (insertOne seals the sealed columns itself), then delete it so the
  // upcoming erase + vacuum has freed B-tree pages to reclaim. The
  // residue the VACUUM clears is exactly those freed pages — they still
  // hold the sealed-column ciphertext until a full rewrite.
  var inserted = b.db.from("patients").insertOne({
    ssn:  "123-45-6789",
    name: "Alice Patient",
  });
  b.db.from("patients").where({ _id: inserted._id }).deleteOne();

  // A sealed-shaped in-memory row for eraseRow to tombstone (eraseRow
  // operates on a row object, NULLing its sealed + derived columns).
  var sealed = b.cryptoField.sealRow("patients", {
    _id:  inserted._id,
    ssn:  "123-45-6789",
    name: "Alice Patient",
  });

  // Wrap the real vacuum entry point with a call-through spy. eraseRow
  // reaches it via require("./db").vacuumAfterErase, which is the same
  // object as b.db — so the wrapper is what eraseRow invokes, and the
  // real VACUUM still runs against the encrypted tmpfs SQLite.
  var realVacuum = b.db.vacuumAfterErase;
  var spy = { called: false, mode: null, threw: null };
  b.db.vacuumAfterErase = function (opts) {
    spy.called = true;
    spy.mode   = opts && opts.mode;
    try {
      return realVacuum.call(b.db, opts);   // real VACUUM executes
    } catch (e) {
      spy.threw = e;
      throw e;
    }
  };

  var auditRowSeen = false;
  try {
    var sinceMs = Date.now();
    // The advertised cascade: erasing a sealed row under a vacuum-floor
    // posture auto-runs b.db.vacuumAfterErase({ mode:"full" }).
    var erased = b.cryptoField.eraseRow("patients", sealed);
    check("eraseRow NULLed the sealed ssn (" + posture + ")", erased.ssn === null);
    check("eraseRow NULLed the derived ssnHash (" + posture + ")", erased.ssnHash === null);

    // Real side effect: the framework's own audit row for the vacuum
    // must be present in the signed chain when (and only when) the
    // posture actually triggered it.
    await b.audit.flush();
    var rows = await b.audit.query({
      action: "db.vacuum_after_erase",
      from:   sinceMs - 1000,
      limit:  50,
    });
    // The audit chain stores metadata as a JSON string column; parse
    // it back to confirm the vacuum row carried mode:"full".
    auditRowSeen = Array.isArray(rows) && rows.some(function (r) {
      if (!r || r.metadata == null) return false;
      var md = r.metadata;
      if (typeof md === "string") { try { md = JSON.parse(md); } catch (_e) { return false; } }
      return md && md.mode === "full";
    });
  } finally {
    b.db.vacuumAfterErase = realVacuum;
    await teardownTestDb(dataDir);
    b.compliance._resetForTest();
  }

  return {
    vacuumCalled: spy.called,
    modeFull:     spy.mode === "full",
    vacuumThrew:  spy.threw,
    auditRowSeen: auditRowSeen,
  };
}

async function run() {
  // ---- Positive control: gdpr + hipaa MUST trigger the full VACUUM,
  // the real VACUUM must execute, and the audit row must land. This is
  // the genuine end-to-end proof of the advertised guarantee.
  var gdpr = await eraseUnderPosture("gdpr");
  check("gdpr eraseRow TRIGGERED vacuumAfterErase", gdpr.vacuumCalled === true);
  check("gdpr vacuum ran with mode:'full'", gdpr.modeFull === true);
  check("gdpr real VACUUM executed without throwing", gdpr.vacuumThrew === null);
  check("gdpr db.vacuum_after_erase landed in the signed audit chain",
        gdpr.auditRowSeen === true);

  var hipaa = await eraseUnderPosture("hipaa");
  check("hipaa eraseRow TRIGGERED vacuumAfterErase", hipaa.vacuumCalled === true);
  check("hipaa vacuum ran with mode:'full'", hipaa.modeFull === true);
  check("hipaa real VACUUM executed without throwing", hipaa.vacuumThrew === null);
  check("hipaa db.vacuum_after_erase landed in the signed audit chain",
        hipaa.auditRowSeen === true);

  // ---- Invariant (recurrence guard): EVERY cross-border regulated posture
  // must carry the requireVacuumAfterErase floor. A regime added to
  // CROSS_BORDER_REGULATED_POSTURES without a POSTURE_DEFAULTS entry would
  // silently skip the mandatory residue cleanup — this catches that drift.
  var crossBorder = b.compliance.CROSS_BORDER_REGULATED_POSTURES.slice();
  check("there is at least one cross-border regulated posture to check",
        crossBorder.length > 0);
  for (var k = 0; k < crossBorder.length; k += 1) {
    check(crossBorder[k] + " carries the requireVacuumAfterErase floor",
          b.compliance.postureDefault(crossBorder[k], "requireVacuumAfterErase") === true);
  }

  // ---- End-to-end: erasing under each cross-border posture triggers the
  // same mandatory residue VACUUM the positive controls (gdpr/hipaa) do.
  var sample = ["uk-gdpr", "appi-jp", "pdpa-sg"];
  for (var i = 0; i < sample.length; i += 1) {
    var p = sample[i];
    var r = await eraseUnderPosture(p);
    check(p + " eraseRow TRIGGERED the mandatory residue VACUUM",
          r.vacuumCalled === true);
    check(p + " vacuum ran with mode:'full'", r.modeFull === true);
    check(p + " db.vacuum_after_erase landed in the signed audit chain",
          r.auditRowSeen === true);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[erase-posture-vacuum] OK"); },
    function (e) { console.error(e.stack || e); process.exit(1); }
  );
}
