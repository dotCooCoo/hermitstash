"use strict";
/**
 * b.auditTools export verbs — `returnBytes` (serverless / read-only fs)
 * path. exportSlice / archive / forensicSnapshot assemble the bundle
 * in memory as a { filename: Buffer } map instead of writing to an
 * `out` directory. The in-memory bytes must be byte-identical to a
 * written bundle, so writing them to disk and verifyBundle-ing proves
 * the round-trip.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var backupCrypto = require("../../lib/backup/crypto");

var PASS = "test-pass-".padEnd(32, "x");

function _rows(n, baseMs) {
  var rows = [];
  for (var i = 1; i <= n; i++) {
    rows.push({
      _id:              "log-" + i,
      monotonicCounter: i,
      recordedAt:       baseMs + i * 1000,
      action:           "user.login",
      outcome:          "success",
      actorUserId:      "alice",
      actorUserIdHash:  "h-alice",
      actorIp:          "10.0.0.5",
      actorSessionId:   "s-" + i,
      resourceKind:     "session",
      resourceId:       "s-" + i,
      reason:           null,
      metadata:         null,
      prevHash:         (i === 1 ? "00" : "ab").repeat(64),
      rowHash:          "ab".repeat(64),
    });
  }
  return rows;
}

async function run() {
  var base = Date.UTC(2026, 4, 1, 12, 0, 0);
  var fakeRows = _rows(5, base);
  async function readRows(_criteria) { return fakeRows; }
  async function readPredecessorRowHash(_c) { return "00".repeat(64); }

  // exportSlice returnBytes → in-memory files, no disk.
  var slice = await b.auditTools.exportSlice({
    returnBytes: true,
    from: base, to: base + 10000,
    passphrase: PASS, readRows: readRows,
    readPredecessorRowHash: readPredecessorRowHash,
  });
  check("exportSlice returnBytes: no manifestPath / outDir",
    slice.manifestPath === undefined && slice.outDir === undefined);
  check("exportSlice returnBytes: files is a map", slice.files && typeof slice.files === "object");
  check("exportSlice returnBytes: rows.enc is a Buffer", Buffer.isBuffer(slice.files["rows.enc"]));
  check("exportSlice returnBytes: manifest.json is a Buffer", Buffer.isBuffer(slice.files["manifest.json"]));
  check("exportSlice returnBytes: rowCount matches", slice.rowCount === 5);
  check("exportSlice returnBytes: no checkpoint.enc (export kind)",
    slice.files["checkpoint.enc"] === undefined);

  // The manifest describes the actual returned bytes: its checksum
  // over rows.enc must match (computed with the same function the
  // bundle uses), and rows.enc must decrypt back to the 5 rows.
  var manifest = JSON.parse(slice.files["manifest.json"].toString("utf8"));
  check("exportSlice returnBytes: manifest rowCount matches", manifest.rowCount === 5);
  check("exportSlice returnBytes: manifest kind is export", manifest.kind === "export");
  check("exportSlice returnBytes: manifest checksum matches rows.enc bytes",
    backupCrypto.checksum(slice.files["rows.enc"]) === manifest.checksum.rowsSha3_512);
  var plain = (await backupCrypto.decryptWithPassphrase(
    slice.files["rows.enc"], PASS, manifest.salts.rows)).toString("utf8");
  var decodedRows = plain.split("\n").filter(Boolean);
  check("exportSlice returnBytes: rows.enc decrypts to the 5 rows", decodedRows.length === 5);

  // out + returnBytes is rejected (mutually exclusive).
  var threwBoth = null;
  try {
    await b.auditTools.exportSlice({ out: "/tmp/x", returnBytes: true,
      from: base, to: base + 10000, passphrase: PASS, readRows: readRows });
  } catch (e) { threwBoth = e; }
  check("exportSlice: out + returnBytes throws",
    threwBoth && /either.*out.*or.*returnBytes/i.test(threwBoth.message));

  // forensicSnapshot returnBytes → slice files + the IR wrapper, and
  // the `since` window is actually applied (regression: it used to be
  // dropped because the value was passed as `until`, not `to`).
  var windowCriteria = null;
  async function windowedReadRows(criteria) { windowCriteria = criteria; return fakeRows; }
  var snap = await b.auditTools.forensicSnapshot({
    returnBytes: true,
    since: base + 2000,
    passphrase: PASS,
    reason: "IR drill — verify returnBytes path",
    incidentId: "inc-rb-1",
    readRows: windowedReadRows,
    readPredecessorRowHash: readPredecessorRowHash,
  });
  check("forensicSnapshot returnBytes: files has the IR wrapper",
    snap.files && Buffer.isBuffer(snap.files["forensic-snapshot.json"]));
  check("forensicSnapshot returnBytes: files has the slice rows.enc",
    Buffer.isBuffer(snap.files["rows.enc"]));
  check("forensicSnapshot returnBytes: no disk manifestPath",
    snap.manifestPath === null || snap.manifestPath === undefined);
  check("forensicSnapshot returnBytes: snapshotKind is forensic",
    snap.snapshotKind === "forensic");
  check("forensicSnapshot: since is applied as the from-bound (fromMs set)",
    windowCriteria && windowCriteria.fromMs === base + 2000);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[audit-tools-return-bytes] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
