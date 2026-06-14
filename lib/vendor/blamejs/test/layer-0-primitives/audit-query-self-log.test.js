"use strict";
/**
 * b.audit.query self-logging (PCI DSS 10.2.3) — every read of audit_log
 * is itself recorded as an `audit.read` event.
 *
 * The self-log suppression is decided per-invocation from the call's own
 * `criteria.action`, never from shared module state. A prior design used a
 * module-global `_selfLogging` boolean toggled across record()'s await
 * (chain mutex + SQL yield); a CONCURRENT query() racing a mid-flight
 * self-log observed the flag set and silently skipped emitting its own
 * audit.read — under-logging reads exactly when load is highest. These
 * tests pin: two concurrent reads BOTH log, a single read logs exactly
 * once (no double/recursive log), and a query targeting `audit.read`
 * itself does not auto-log.
 *
 * Run standalone: `node test/layer-0-primitives/audit-query-self-log.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var waitUntil      = helpers.waitUntil;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-self-")); }

// Count audit.read rows directly via the query path that does NOT auto-log
// (criteria.action === "audit.read"), so counting never perturbs the count.
async function _readCount() {
  var rows = await b.audit.query({ action: "audit.read" });
  return rows.length;
}

// ---- Concurrent reads each emit their own audit.read ----

async function testConcurrentReadsBothLog() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Seed a non-read row so the concurrent queries return something and,
    // more importantly, so each emits its own self-log.
    await b.audit.record({ action: "consent.granted", outcome: "success" });

    var before = await _readCount();

    // Fire two concurrent reads. Pre-fix, the second to enter would see the
    // module-global flag set by the first (mid-record) and skip its self-log,
    // so only ONE audit.read would land. Post-fix, BOTH land.
    var qA = b.audit.query({ action: "consent.granted", actorUserId: "reader-a" });
    var qB = b.audit.query({ action: "consent.granted", actorUserId: "reader-b" });
    await Promise.all([qA, qB]);

    await waitUntil(async function () {
      return (await _readCount()) >= before + 2;
    }, { timeoutMs: 5000, label: "M3: both concurrent reads emit audit.read" });

    var after = await _readCount();
    check("two concurrent reads emit two audit.read rows (no under-logging)",
          after === before + 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- A single read emits exactly one audit.read (no double/recursion) ----

async function testSingleReadLogsExactlyOnce() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    await b.audit.record({ action: "consent.granted", outcome: "success" });

    var before = await _readCount();
    await b.audit.query({ action: "consent.granted" });
    var after = await _readCount();

    check("a single read emits exactly one audit.read (no double/recursive log)",
          after === before + 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Querying audit.read itself does not auto-log (no Russell spiral) ----

async function testAuditReadQueryDoesNotSelfLog() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Generate at least one audit.read so the table is non-empty.
    await b.audit.query({ action: "consent.granted" });

    var before = await _readCount();
    // Querying for audit.read must NOT emit another audit.read.
    await b.audit.query({ action: "audit.read" });
    var after = await _readCount();

    check("querying action='audit.read' does not auto-log a new audit.read",
          after === before);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testConcurrentReadsBothLog();
  await testSingleReadLogsExactlyOnce();
  await testAuditReadQueryDoesNotSelfLog();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       // Re-throw rather than console.error the error object: a DB-setup
       // failure can carry passphrase-derived material on the error, and
       // logging it would be clear-text logging of sensitive data
       // (CWE-312). The non-zero exit + thrown stack still surface the
       // failure to the runner.
       .catch(function (e) { process.exitCode = 1; throw e; });
}
