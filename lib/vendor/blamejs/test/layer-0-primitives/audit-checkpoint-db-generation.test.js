// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * audit.checkpoint() launched fire-and-forget must not fail when the database
 * it was reading closes underneath it.
 *
 * db.close() is synchronous by design and anchors a best-effort final
 * checkpoint without awaiting it. That checkpoint spans async boundaries
 * (tip read -> sign -> insert), so a caller that closes and then replaces the
 * database — orderly shutdown followed by a fresh init, which every test
 * teardown does — can have the checkpoint resume against a database that is
 * gone.
 *
 * The write side already refuses to anchor a tip that belongs to a database
 * that no longer exists. The tip READ is the same hazard one await earlier:
 * left unguarded it rejects, and because close() only logs the rejection the
 * failure surfaces as a stray error line that no runner can attribute to a
 * test. The checkpoint must instead resolve to null — there is nothing to
 * anchor — while a genuine failure against a LIVE database still rejects.
 */

var nodeFs = require("node:fs");
var nodeOs = require("node:os");
var nodePath = require("node:path");
var helpers = require("../helpers");
var dbHelper = require("../helpers/db");

var b = helpers.b;
var check = helpers.check;

async function testCheckpointResolvesNullWhenDbClosesUnderIt() {
  var tmpDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "ckpt-gen-"));
  var settled = null;
  try {
    // setupTestDb boots the signing keypair too, so a checkpoint here can sign
    // for real and the ONLY thing that can stop it is the database going away.
    // The live-database case below proves that precondition holds.
    await dbHelper.setupTestDb(tmpDir);

    // A non-empty audit chain, so checkpoint() has a real tip to read and
    // cannot short-circuit on the empty-log path.
    await b.audit.emit({ event: "checkpoint.generation.fixture", outcome: "success" });
    await b.audit.flush();

    // Launch WITHOUT awaiting — the shape db.close() uses — then take the
    // database away before the tip read can resume. checkpoint() runs
    // synchronously up to its first await, so the reset always lands mid-flight.
    var pending = b.audit.checkpoint({});
    b.db._resetForTest();

    try {
      var result = await pending;
      settled = { ok: true, value: result };
    } catch (e) {
      settled = { ok: false, error: e };
    }

    check("a checkpoint whose database closed under it resolves instead of rejecting",
      settled.ok === true);
    check("it anchors nothing — there is no database left to anchor into",
      settled.ok === true && settled.value === null);
  } finally {
    // The db is already reset; drop the remaining module state and the dir.
    try { b.audit._resetForTest(); } catch (_e) { /* best effort */ }
    try { b.auditSign._resetForTest(); } catch (_e) { /* best effort */ }
    try { b.vault._resetForTest(); } catch (_e) { /* best effort */ }
    try { b.cluster._resetForTest(); } catch (_e) { /* best effort */ }
    try { nodeFs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

async function testCheckpointStillAnchorsAgainstALiveDatabase() {
  // The guard must not swallow real work: with the database untouched, the
  // same call anchors a checkpoint normally.
  var tmpDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "ckpt-live-"));
  try {
    await dbHelper.setupTestDb(tmpDir);
    await b.audit.emit({ event: "checkpoint.generation.live", outcome: "success" });
    await b.audit.flush();

    var ckpt = await b.audit.checkpoint({});
    check("against a live database the checkpoint still anchors", !!ckpt);

    // And the skip path still reports "already anchored" rather than erroring.
    var again = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("an unchanged tip skips rather than double-anchoring", again === null);
  } finally {
    await dbHelper.teardownTestDb(tmpDir);
    try { b.auditSign._resetForTest(); } catch (_e) { /* best effort */ }
  }
}

async function run() {
  await testCheckpointResolvesNullWhenDbClosesUnderIt();
  await testCheckpointStillAnchorsAgainstALiveDatabase();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[audit-checkpoint-db-generation] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
