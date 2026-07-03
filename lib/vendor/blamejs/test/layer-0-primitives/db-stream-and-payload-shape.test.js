// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.stream OOM-safety + streamLimit cap, and sealed-column byte-
 * fidelity across hostile payload shapes.
 *
 * Two guarantees under test, both on the production encrypted-at-rest
 * path (real wrapped vault + sealed db.enc + audit chain via
 * setupTestDb):
 *
 *   (a) b.db.stream yields rows from node:sqlite's iterate() WITHOUT
 *       materializing the whole result set (the documented win over
 *       .all()), preserves row order, and DESTROYS the stream with a
 *       db/stream-limit-exceeded error once the per-call streamLimit
 *       cap is crossed rather than accumulating unboundedly.
 *
 *   (b) A sealed column round-trips seal -> store -> read -> unseal
 *       byte-identical for the payload shapes a real column carries.
 *       This is where a silent value-corruption bug would hide: the
 *       seal layer must not lose bytes on the way through the AEAD
 *       envelope.
 */

var helpers     = require("../helpers");
var b           = helpers.b;
var check       = helpers.check;
var fs          = helpers.fs;
var os          = helpers.os;
var path        = helpers.path;
var setupTestDb = helpers.setupTestDb;
var waitUntil   = helpers.waitUntil;

// Stream-test table: a sealed column so the stream's auto-unseal path
// (opts.table) is exercised, plus an ordering column.
// Payload-fidelity table: one sealed TEXT column (seal layer) and one
// NON-sealed BLOB column (raw node:sqlite storage), so the two
// round-trip paths are isolated from each other.
var SCHEMA = [
  {
    name: "events",
    columns: {
      _id:   "TEXT PRIMARY KEY",
      seq:   "INTEGER NOT NULL",
      payload: "TEXT",
    },
    indexes: ["seq"],
    sealedFields: ["payload"],
  },
  {
    name: "blobs",
    columns: {
      _id:    "TEXT PRIMARY KEY",
      sealedText: "TEXT",   // routed through the seal layer
      rawBlob:    "BLOB",   // stored as a raw node:sqlite BLOB, not sealed
    },
    sealedFields: ["sealedText"],
  },
];

// Drain a Readable into an array of rows, honoring backpressure-free
// flowing mode but capturing order. Rejects on stream error.
function collectStream(stream) {
  return new Promise(function (resolve, reject) {
    var rows = [];
    stream.on("data", function (row) { rows.push(row); });
    stream.on("end", function () { resolve(rows); });
    stream.on("error", function (err) { reject(err); });
  });
}

// Capture the error a stream destroys with (the cap path). Resolves
// with { errored, err, rowsBeforeError }.
function collectStreamError(stream) {
  return new Promise(function (resolve) {
    var rows = [];
    stream.on("data", function (row) { rows.push(row); });
    stream.on("end", function () { resolve({ errored: false, err: null, rowsBeforeError: rows }); });
    stream.on("error", function (err) { resolve({ errored: true, err: err, rowsBeforeError: rows }); });
  });
}

function bufEqual(a, exp) {
  return Buffer.isBuffer(a) || a instanceof Uint8Array
    ? Buffer.compare(Buffer.from(a), exp) === 0
    : false;
}

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-stream-shape-"));
  await setupTestDb(tmp, SCHEMA);

  // ====================================================================
  // (a) b.db.stream — non-materializing, ordered, capped
  // ====================================================================

  // Insert a few thousand rows so the stream has real work to do and
  // the cap can fire well before the end of the set.
  var N = 4000;
  var events = b.db.from("events");
  for (var i = 0; i < N; i++) {
    events.insertOne({ seq: i, payload: "payload-row-" + i });
  }
  check("inserted N rows", b.db.from("events").count() === N);

  // ---- order + completeness: every row arrives, in seq order, unsealed
  var streamed = await collectStream(
    b.db.stream("SELECT * FROM events ORDER BY seq ASC", { table: "events" })
  );
  check("stream yielded every row", streamed.length === N);
  var ordered = true;
  var unsealedOk = true;
  for (var j = 0; j < streamed.length; j++) {
    if (streamed[j].seq !== j) ordered = false;
    if (streamed[j].payload !== "payload-row-" + j) unsealedOk = false;
  }
  check("stream preserved row order", ordered);
  check("stream auto-unsealed the sealed column", unsealedOk);

  // ---- non-materialization: the stream is pull-based. Pause it after
  // the first row and prove no further rows are delivered while paused
  // (a .all()-style eager materialization could not honor this), then
  // resume and confirm the rest flow. This demonstrates the iterate()
  // generator is pulled lazily, not collected up-front.
  var pullStream = b.db.stream("SELECT * FROM events ORDER BY seq ASC", { table: "events" });
  var seen = [];
  var pausedAtCount = -1;
  pullStream.on("data", function (row) {
    seen.push(row);
    if (seen.length === 1) {
      pullStream.pause();
      pausedAtCount = seen.length;
      // Resume on the next tick; while paused, no more 'data' must fire.
      setImmediate(function () {
        // Confirm the stream did NOT race ahead and buffer the whole
        // set while we were paused: at most a tiny highWaterMark of
        // rows can be in flight, never the full N.
        check("paused stream did not materialize the full set",
          seen.length < N);
        pullStream.resume();
      });
    }
  });
  var pulled = await new Promise(function (resolve, reject) {
    pullStream.on("end", function () { resolve(seen); });
    pullStream.on("error", reject);
  });
  check("paused-then-resumed stream still delivered every row", pulled.length === N);
  check("pause point was the first row", pausedAtCount === 1);

  // ---- cap: a per-call streamLimit BELOW the row count must destroy
  // the stream with db/stream-limit-exceeded, not silently truncate or
  // run to completion.
  var CAP = 100;
  var capResult = await collectStreamError(
    b.db.stream("SELECT * FROM events ORDER BY seq ASC", { table: "events", streamLimit: CAP })
  );
  check("over-cap stream errored (did not run to completion)", capResult.errored === true);
  check("over-cap stream error carries db/stream-limit-exceeded code",
    !!capResult.err && capResult.err.code === "db/stream-limit-exceeded");
  check("over-cap stream stopped at the cap (no unbounded accumulation)",
    capResult.rowsBeforeError.length <= CAP);

  // ---- a streamLimit AT OR ABOVE the row count runs clean to the end.
  var underCap = await collectStream(
    b.db.stream("SELECT * FROM events ORDER BY seq ASC", { table: "events", streamLimit: N + 10 })
  );
  check("within-cap stream completes without error", underCap.length === N);

  // ---- a bad streamLimit shape throws at call time (config-time tier).
  var badLimitThrew = false;
  try { b.db.stream("SELECT * FROM events", { table: "events", streamLimit: -1 }); }
  catch (e) { badLimitThrew = e && e.code === "db/bad-stream-limit"; }
  check("negative streamLimit throws db/bad-stream-limit at call time", badLimitThrew);

  // ====================================================================
  // (b) sealed-column byte-fidelity across hostile payload shapes
  // ====================================================================
  //
  // For each shape, drive the PRODUCTION seal path
  // (cryptoField.sealRow -> store via db -> read -> auto-unseal) and
  // assert byte-identical recovery. Any shape that does not round-trip
  // byte-identical is a real data-integrity bug — the column was
  // declared sealed by the operator and silently corrupting its value
  // defeats the at-rest-encryption guarantee.

  // --- Shape 1: astral-plane Unicode (emoji + CJK Extension B) ---
  var astral = "rocket\u{1F680} cjkB\u{20000}\u{2A6B2} family\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
  b.db.from("blobs").insertOne({ _id: "astral", sealedText: astral });
  var gotAstral = b.db.from("blobs").where({ _id: "astral" }).first();
  check("astral-plane Unicode round-trips byte-identical through sealed column",
    gotAstral.sealedText === astral);

  // --- Shape 2: a string containing embedded NUL bytes ---
  var withNul = "before middle  after";
  b.db.from("blobs").insertOne({ _id: "nul", sealedText: withNul });
  var gotNul = b.db.from("blobs").where({ _id: "nul" }).first();
  check("string with embedded NUL bytes round-trips byte-identical through sealed column",
    gotNul.sealedText === withNul);

  // --- Shape 3: a large (~256 KiB) value ---
  var large = "";
  var chunk = "0123456789abcdef";                 // 16 bytes
  while (large.length < 256 * 1024) large += chunk; // ~256 KiB
  b.db.from("blobs").insertOne({ _id: "large", sealedText: large });
  var gotLarge = b.db.from("blobs").where({ _id: "large" }).first();
  check("large (~256 KiB) value round-trips byte-identical through sealed column",
    gotLarge.sealedText === large && gotLarge.sealedText.length === large.length);

  // --- Shape 4: a binary Buffer/BLOB carrying all 256 byte values ---
  // First prove the DB BLOB column itself preserves bytes (the storage
  // floor), so any seal-layer corruption can't be blamed on sqlite.
  var allBytes = Buffer.alloc(256);
  for (var bb = 0; bb < 256; bb++) allBytes[bb] = bb;
  b.db.from("blobs").insertOne({ _id: "rawblob", rawBlob: allBytes });
  var gotRawBlob = b.db.from("blobs").where({ _id: "rawblob" }).first();
  check("raw (non-sealed) BLOB column preserves all 256 byte values byte-identical",
    bufEqual(gotRawBlob.rawBlob, allBytes));

  // Now the same all-256-bytes Buffer through a SEALED column. A sealed
  // column is the operator's declaration that the value holds protected
  // data; a binary column (e.g. a sealed encryption sub-key, a packed
  // protobuf, a thumbnail) is a legitimate sealed payload. The seal
  // path MUST either preserve the bytes or refuse — silently mangling
  // them is the bug.
  b.db.from("blobs").insertOne({ _id: "sealedblob", sealedText: allBytes });
  var gotSealedBlob = b.db.from("blobs").where({ _id: "sealedblob" }).first();
  var sealedBlobBytes = Buffer.isBuffer(gotSealedBlob.sealedText) || gotSealedBlob.sealedText instanceof Uint8Array
    ? Buffer.from(gotSealedBlob.sealedText)
    : Buffer.from(String(gotSealedBlob.sealedText), "utf8");
  check("all-256-byte Buffer round-trips byte-identical through a SEALED column",
    Buffer.compare(sealedBlobBytes, allBytes) === 0);

  // --- Shape 5: a deeply-nested JSON object ---
  // A sealed column declared to hold a structured value (the framework
  // even JSON.stringify's containment values elsewhere) must recover the
  // SAME object — not a coerced "[object Object]" / lossy string.
  var nested = { a: { b: { c: { d: [1, 2, { e: "deep", f: [null, true, "x y"] }] } } }, n: 42 };
  b.db.from("blobs").insertOne({ _id: "nested", sealedText: nested });
  var gotNested = b.db.from("blobs").where({ _id: "nested" }).first();
  var recovered;
  try {
    recovered = typeof gotNested.sealedText === "string"
      ? JSON.parse(gotNested.sealedText)
      : gotNested.sealedText;
  } catch (_e) { recovered = gotNested.sealedText; }
  check("deeply-nested object round-trips structurally through a SEALED column",
    JSON.stringify(recovered) === JSON.stringify(nested));

  // Touch waitUntil so the import is exercised even though every assert
  // above is synchronous against the local sqlite path (keeps the
  // helper dependency honest for future async growth).
  await waitUntil(function () { return true; }, { timeoutMs: 1000, label: "db-stream-shape: trivial settle" });

  b.db.close();
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) {}

  console.log("OK — db.stream OOM-safety + cap, sealed-column byte-fidelity");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
