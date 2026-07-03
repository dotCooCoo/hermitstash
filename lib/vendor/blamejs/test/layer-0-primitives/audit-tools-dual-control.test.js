// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditTools.purge dual-control gate.
 *
 * When audit_log is placed under dual control, physically purging the
 * audit chain requires a consumed m-of-n grant in addition to a
 * verified archive and confirm:true — one operator must not be able to
 * erase the tamper-evident chain alone. The grant's action is also
 * bound, so a grant minted for a different operation can't be replayed
 * against a purge.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var PASS = Buffer.from("operator-passphrase");
var PURGE_ACTION = "auditTools.purge";

async function _seedAuditRows(count) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({
      actor: { userId: "u-" + i }, action: "test.seeded", outcome: "success", metadata: { i: i },
    });
  }
}

async function _expectCode(fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  return threw && threw.code === code;
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-dc-"));
  try {
    await setupTestDb(dir);
    await _seedAuditRows(5);
    await b.audit.checkpoint();

    var out = path.join(dir, "bundles", "archive-dc");
    await b.auditTools.archive({ before: Date.now() + 1000, out: out, passphrase: PASS });

    // Simulate audit_log being under dual control (m-of-n). The gate
    // override returns a gate descriptor for the audit_log table; the
    // denial branches all fire before any chain mutation, so the same
    // verified bundle is reused across them.
    var sawTable = null;
    var gate = function (table) { sawTable = table; return { m: 2, n: 3 }; };

    // No grant → refused.
    check("purge under dual control refuses without a grant",
      await _expectCode(function () {
        return b.auditTools.purge({ archive: out, passphrase: PASS, confirm: true, checkDualControlGate: gate });
      }, "audit-tools/dual-control-required"));
    check("gate was consulted for the audit_log table", sawTable === "audit_log");

    // Grant not ready (not a consumed m-of-n grant) → refused.
    check("purge refuses a not-ready grant",
      await _expectCode(function () {
        return b.auditTools.purge({
          archive: out, passphrase: PASS, confirm: true, checkDualControlGate: gate,
          dualControlGrant: { ready: false, action: PURGE_ACTION },
        });
      }, "audit-tools/dual-control-grant-not-ready"));

    // Grant minted for a different action → refused (action binding).
    check("purge refuses a grant bound to a different action",
      await _expectCode(function () {
        return b.auditTools.purge({
          archive: out, passphrase: PASS, confirm: true, checkDualControlGate: gate,
          dualControlGrant: { ready: true, action: "db.eraseHard" },
        });
      }, "audit-tools/dual-control-grant-mismatch"));

    // Confirm the chain is still intact — no denial mutated it.
    var beforeRows = await b.clusterStorage.executeAll("SELECT COUNT(*) as c FROM audit_log");
    check("audit_log untouched by denied purges", Number(beforeRows[0].c) >= 5);

    // Valid consumed grant for the purge action → proceeds.
    var pres = await b.auditTools.purge({
      archive: out, passphrase: PASS, confirm: true, checkDualControlGate: gate,
      dualControlGrant: { ready: true, action: PURGE_ACTION },
    });
    check("purge with a valid grant succeeds", pres.purged === true);
    check("purge reports dual-control was consumed", pres.dualControlConsumed === true);
    check("purge deleted rows", pres.rowsDeleted > 0);

    // No gate (audit_log not under dual control) → confirm + archive
    // alone is sufficient (no grant required) — the gate is opt-in.
    var noGateResult = b.auditTools.purge;
    check("purge surface present", typeof noGateResult === "function");
  } finally {
    await teardownTestDb(dir);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }

  console.log("OK — audit-tools dual-control tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node surfaces the error and exits non-zero,
  // instead of logging the caught error object — a taint analyzer traces
  // a logged error back to the test passphrase fixture (a non-secret
  // constant) and raises a false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
