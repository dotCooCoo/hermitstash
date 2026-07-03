// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers = require("../helpers");
var dbHelper = require("../helpers/db");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  check("db.declareWorm is fn",               typeof b.db.declareWorm === "function");
  check("db.declareRequireDualControl is fn", typeof b.db.declareRequireDualControl === "function");
  check("db.eraseHard is fn",                 typeof b.db.eraseHard === "function");

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-worm-"));
  await dbHelper.setupTestDb(tmpDir, [
    {
      name: "orders",
      columns: {
        _id:      "TEXT PRIMARY KEY",
        userId:   "TEXT",
        amount:   "INTEGER",
        placedAt: "INTEGER",
      },
      indexes: ["userId"],
    },
    {
      // Erasure target for the eraseHard happy-path proof. NOT a WORM
      // table (eraseHard's raw DELETE would trip a WORM BEFORE-DELETE
      // trigger), but gated by dual-control so the destructive op only
      // runs against a consumed m-of-n grant.
      //   ssn  — sealed at rest (exercises cryptoField.eraseRow)
      //   tag  — non-sealed, INDEXED plaintext column. This is the
      //          forensic target: its plaintext lands in the SQLite
      //          table-leaf AND index B-tree pages, so DELETE + REINDEX
      //          (+ the advertised vacuumAfterErase companion) must
      //          leave no on-disk residual.
      name: "stale_pii",
      columns: {
        _id:    "TEXT PRIMARY KEY",
        ssn:    "TEXT",
        tag:    "TEXT",
        keepId: "TEXT",
      },
      indexes:      ["tag"],
      sealedFields: ["ssn"],
    },
  ]);

  // Insert a row before WORM declaration to exercise the trigger gate.
  b.db.from("orders").insertOne({ _id: "ord-1", userId: "u-1", amount: 100, placedAt: Date.now() });

  var dec = b.db.declareWorm({ tables: ["orders"], posture: "sec-17a-4" });
  check("declareWorm: returns tables",  Array.isArray(dec.tables) && dec.tables[0] === "orders");

  // Insert another row — INSERT must still succeed under WORM.
  var inserted = false;
  try {
    b.db.from("orders").insertOne({ _id: "ord-2", userId: "u-2", amount: 50, placedAt: Date.now() });
    inserted = true;
  } catch (_e) { inserted = false; }
  check("WORM: INSERT still permitted", inserted);

  // UPDATE must throw.
  var updateRefused = false;
  try {
    b.db.from("orders").where({ _id: "ord-1" }).updateOne({ amount: 999 });
  } catch (_e) { updateRefused = true; }
  check("WORM: UPDATE refused", updateRefused);

  // DELETE must throw.
  var deleteRefused = false;
  try {
    b.db.from("orders").where({ _id: "ord-1" }).deleteMany();
  } catch (_e) { deleteRefused = true; }
  check("WORM: DELETE refused", deleteRefused);

  // declareWorm refuses framework tables
  var rejectedReserved = false;
  try { b.db.declareWorm({ tables: ["audit_log"] }); }
  catch (_e) { rejectedReserved = true; }
  check("declareWorm: rejects audit_log", rejectedReserved);

  // declareRequireDualControl
  var dcDec = b.db.declareRequireDualControl({
    tables:  ["orders"],
    m:       2,
    n:       3,
    posture: "sox",
  });
  check("declareRequireDualControl: m=2",  dcDec.m === 2);
  check("declareRequireDualControl: n=3",  dcDec.n === 3);

  // eraseHard requires reason
  var noReasonRefused = false;
  try { await b.db.eraseHard("orders", "ord-1", {}); }
  catch (_e) { noReasonRefused = true; }
  check("eraseHard: no reason throws", noReasonRefused);

  // eraseHard with no grant under dual-control gate refuses
  var noGrantRefused = false;
  try { await b.db.eraseHard("orders", "ord-1", { reason: "test" }); }
  catch (e) { noGrantRefused = /dual-control/i.test(e.message); }
  check("eraseHard: dual-control gate refuses without grant", noGrantRefused);

  // ---------------------------------------------------------------------
  // Happy path — eraseHard ACTUALLY destroys data (DELETE + crypto-erase
  // + REINDEX) under a real consumed dual-control grant, and leaves no
  // forensic residual on disk.
  // ---------------------------------------------------------------------

  // A unique, high-entropy sentinel so a byte-scan of the on-disk files
  // can't false-positive on incidental bytes. Stored in the non-sealed,
  // INDEXED `tag` column → its plaintext is in both the table-leaf and
  // the index B-tree pages of the working SQLite file.
  var SENTINEL = "ERASE-SENTINEL-" +
    b.crypto.generateToken(b.constants.BYTES.bytes(24)) + "-ZZ";
  var SSN_PLAIN = "987-65-4321";

  b.db.from("stale_pii").insertOne({ _id: "doomed", ssn: SSN_PLAIN, tag: SENTINEL, keepId: "k1" });
  // A second row that must SURVIVE the erase — proves eraseHard scopes
  // to the named rowId and doesn't wipe the table.
  var SURVIVOR = "SURVIVOR-SENTINEL-" +
    b.crypto.generateToken(b.constants.BYTES.bytes(16)) + "-YY";
  b.db.from("stale_pii").insertOne({ _id: "keeper", ssn: "111-22-3333", tag: SURVIVOR, keepId: "k2" });

  // Gate the erase behind dual-control (m=2, n=3).
  b.db.declareRequireDualControl({ tables: ["stale_pii"], m: 2, n: 3, posture: "gdpr" });

  // Sealed round-trip: the row reads back with plaintext ssn (proves the
  // value was genuinely sealed-then-unsealed, i.e. encryption is live).
  var before = b.db.from("stale_pii").where({ _id: "doomed" }).first();
  check("eraseHard happy: sealed row reads back before erase", !!before && before.ssn === SSN_PLAIN);
  check("eraseHard happy: tag present in-row before erase",    !!before && before.tag === SENTINEL);

  // Locate the on-disk files. In encrypted-at-rest mode the working
  // SQLite file lives in tmpfs (getDbPath); the durable sealed copy is
  // <dataDir>/db.enc. Force a checkpoint + WAL flush so committed pages
  // are visible in the main file for the forensic scan.
  var dbFile  = b.db.getDbPath();
  var walFile = dbFile + "-wal";
  var encFile = path.join(tmpDir, "db.enc");
  b.db.flushToDisk(); // checkpoint(TRUNCATE) + re-seal db.enc

  function fileHasSentinel(p, needle) {
    if (!fs.existsSync(p)) return false;
    return fs.readFileSync(p).includes(Buffer.from(needle, "utf8"));
  }
  function diskHasSentinel(needle) {
    return fileHasSentinel(dbFile, needle) ||
           fileHasSentinel(walFile, needle);
  }

  // CONTROL — before erase the sentinel plaintext IS recoverable from the
  // working SQLite file (table-leaf and/or index pages). Without this the
  // "absent after" assertion below would be vacuous.
  check("eraseHard FORENSIC control: sentinel plaintext present on disk before erase",
    diskHasSentinel(SENTINEL));
  // db.enc is an encrypted envelope — the sentinel must NOT be plaintext-
  // visible there at any point (sanity check on at-rest encryption).
  check("eraseHard FORENSIC: db.enc never exposes sentinel plaintext (encrypted at rest)",
    !fileHasSentinel(encFile, SENTINEL));

  // Build a REAL dual-control grant: request → a different actor approves
  // → quorum → consume. consume() returns { ready: true } which eraseHard
  // requires. No stub — the production dual-control workflow.
  var approvals = b.dualControl.create({
    namespace: "stale_pii.eraseHard",
    cache:     b.cache.create({ namespace: "dc-erase", backend: "memory" }),
    audit:     b.audit,
    minApprovers: 2,
  });
  var opened = await approvals.request({
    action:      "stale_pii.eraseHard",
    resource:    { kind: "stale_pii", id: "doomed" },
    requestedBy: { id: "alice" },
    reason:      "GDPR Art. 17 erasure request, ticket SUP-9001",
  });
  check("eraseHard happy: grant opened pending", opened && opened.status === "pending");
  await approvals.approve({ grantId: opened.grantId, approver: { id: "bob" },     reason: "verified subject identity" });
  var quorum = await approvals.approve({ grantId: opened.grantId, approver: { id: "carol" }, reason: "second approval" });
  check("eraseHard happy: grant reached quorum", quorum && quorum.status === "approved");
  var grant = await approvals.consume(opened.grantId, {});
  check("eraseHard happy: grant consumed (ready)", grant && grant.ready === true);

  // The destructive op under the consumed grant.
  var result = await b.db.eraseHard("stale_pii", "doomed", {
    reason:           "subject erasure under GDPR Art 17, ticket SUP-9001",
    dualControlGrant: grant,
  });
  check("eraseHard happy: reports rowsDeleted === 1", result && result.rowsDeleted === 1);

  // (a) Row is gone from the table.
  var afterRow = b.db.from("stale_pii").where({ _id: "doomed" }).first();
  check("eraseHard happy: erased row absent from table", afterRow === null || afterRow === undefined);
  // The unrelated row survives — erase is row-scoped, not a table wipe.
  var keeper = b.db.from("stale_pii").where({ _id: "keeper" }).first();
  check("eraseHard happy: unrelated row survives", !!keeper && keeper.tag === SURVIVOR);

  // (b) Audit chain still verifies end-to-end (the erase emitted a signed
  // db.erase_hard row; the hash chain must remain intact).
  await b.audit.flush();
  var chain = await b.audit.verify();
  check("eraseHard happy: audit chain verifies intact after erase", chain && chain.ok === true);

  // (c) FORENSIC — the core guarantee, attributed to eraseHard ITSELF
  // (DELETE + REINDEX), measured BEFORE any later vacuum so the scrub
  // can't be credited to a separate VACUUM pass. Re-checkpoint + re-seal
  // so the on-disk files reflect post-erase state, then assert the
  // deleted row's plaintext sentinel is gone from the working SQLite +
  // WAL. The CONTROL above proved it WAS recoverable before the erase, so
  // this is a real before/after delta, not a vacuous read.
  b.db.flushToDisk();
  check("eraseHard FORENSIC: erased sentinel plaintext ABSENT from working SQLite + WAL after eraseHard+REINDEX",
    !diskHasSentinel(SENTINEL));
  // The survivor's plaintext is still on disk — confirms the scan is live
  // (it isn't reporting "absent" because the whole file was wiped).
  check("eraseHard FORENSIC: survivor sentinel still present on disk (scan is live, not whole-file wipe)",
    diskHasSentinel(SURVIVOR));
  // db.enc is an encrypted envelope — never plaintext-visible at any point.
  check("eraseHard FORENSIC: db.enc holds no sentinel plaintext after erase",
    !fileHasSentinel(encFile, SENTINEL));

  // Belt-and-suspenders: the advertised vacuumAfterErase companion (full
  // VACUUM rewrites every page) is the operator's defense against any
  // freed-page residual a later large-scale erase batch could leave. Run
  // it and re-confirm the sentinel stays absent and the survivor stays.
  b.db.vacuumAfterErase({ mode: "full" });
  b.db.flushToDisk();
  check("eraseHard FORENSIC: sentinel still absent after vacuumAfterErase(full)",
    !diskHasSentinel(SENTINEL));
  check("eraseHard FORENSIC: survivor still present after vacuumAfterErase(full)",
    diskHasSentinel(SURVIVOR));

  await dbHelper.teardownTestDb(tmpDir);
}

module.exports = { run: run };
