"use strict";
/**
 * b.pqcAgent — ecdhCurve negotiation surface.
 *
 * Covers the framework-default PQC-hybrid preference (now a 3-entry
 * list including SecP256r1MLKEM768), the narrowing path (subset of
 * the default), and the operator-supplied-group escape hatch
 * (allowOperatorGroups: true) including the audit emit on accepted
 * non-default groups.
 *
 * Run standalone: `node test/layer-0-primitives/pqc-agent-curve.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

async function testDefaultGroupList() {
  var agent = b.pqcAgent.create();
  // The agent is built with options.ecdhCurve set to the framework
  // PQC-hybrid preference. Read it via agent.options.
  var ec = agent.options.ecdhCurve;
  check("default ecdhCurve includes SecP384r1MLKEM1024",
        ec.indexOf("SecP384r1MLKEM1024") !== -1);
  check("default ecdhCurve includes X25519MLKEM768",
        ec.indexOf("X25519MLKEM768") !== -1);
  check("default ecdhCurve includes SecP256r1MLKEM768",
        ec.indexOf("SecP256r1MLKEM768") !== -1);
  check("default ecdhCurve preserves preference order",
        ec.indexOf("SecP384r1MLKEM1024") < ec.indexOf("X25519MLKEM768") &&
        ec.indexOf("X25519MLKEM768") < ec.indexOf("SecP256r1MLKEM768"));
  agent.destroy();
}

function testNarrowToFrameworkSubset() {
  // Narrowing within the framework preference list is allowed without
  // allowOperatorGroups.
  var agent = b.pqcAgent.create({ ecdhCurve: "SecP256r1MLKEM768" });
  check("narrowed ecdhCurve = SecP256r1MLKEM768",
        agent.options.ecdhCurve === "SecP256r1MLKEM768");
  agent.destroy();

  var two = b.pqcAgent.create({ ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768" });
  check("two-group narrowing accepted",
        two.options.ecdhCurve === "X25519MLKEM768:SecP256r1MLKEM768");
  two.destroy();
}

function testRefuseUnknownGroupByDefault() {
  var threw = false;
  try {
    b.pqcAgent.create({ ecdhCurve: "X25519" });
  } catch (e) {
    threw = e instanceof TypeError &&
            e.message.indexOf("not in the framework PQC-hybrid") !== -1 &&
            e.message.indexOf("allowOperatorGroups") !== -1;
  }
  check("default refuses non-framework group with helpful error", threw);

  var threwUnknown = false;
  try {
    b.pqcAgent.create({ ecdhCurve: "NotARealGroup", allowOperatorGroups: true });
  } catch (e) {
    threwUnknown = e instanceof TypeError &&
                   e.message.indexOf("not a known IANA TLS Supported Group") !== -1;
  }
  check("allowOperatorGroups still refuses unknown group names", threwUnknown);

  var threwBadShape = false;
  try {
    b.pqcAgent.create({ ecdhCurve: "X25519:bad name", allowOperatorGroups: true });
  } catch (e) {
    threwBadShape = e instanceof TypeError &&
                    e.message.indexOf("illegal characters") !== -1;
  }
  check("operator-group entries reject illegal characters", threwBadShape);
}

async function testAllowOperatorGroupsAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pqcagent-"));
  try {
    await setupTestDb(tmpDir);
    var agent = b.pqcAgent.create({
      ecdhCurve:           "X25519",
      allowOperatorGroups: true,
    });
    check("X25519 accepted under allowOperatorGroups",
          agent.options.ecdhCurve === "X25519");
    agent.destroy();

    await b.audit.flush();
    var rows = await b.audit.query({ action: "pqcagent.operator_group.accepted" });
    check("audit row written for operator-group acceptance", rows.length >= 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit metadata carries group=X25519", meta.group === "X25519");
    check("audit metadata carries ecdhCurve",    meta.ecdhCurve === "X25519");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testKnownTlsGroupsExposed() {
  check("KNOWN_TLS_GROUPS exposed as array",
        Array.isArray(b.pqcAgent.KNOWN_TLS_GROUPS));
  check("KNOWN_TLS_GROUPS includes SecP256r1MLKEM768",
        b.pqcAgent.KNOWN_TLS_GROUPS.indexOf("SecP256r1MLKEM768") !== -1);
  check("KNOWN_TLS_GROUPS includes X25519",
        b.pqcAgent.KNOWN_TLS_GROUPS.indexOf("X25519") !== -1);
}

function testReloadSurface() {
  check("b.pqcAgent.reload is fn", typeof b.pqcAgent.reload === "function");
}

function testReloadAfterBuild() {
  // Touch b.pqcAgent.agent so it lazy-builds; then b.pqcAgent.reload()
  // tears it down. Subsequent agent access rebuilds.
  var first = b.pqcAgent.agent;
  check("agent: lazy-built on first access",
        first !== null && typeof first.destroy === "function");
  var res = b.pqcAgent.reload();
  check("reload: returns object", res && typeof res.destroyed === "boolean");
  var second = b.pqcAgent.agent;
  check("agent: rebuilt after reload", second !== null);
  // Reload is idempotent (no-op when nothing built).
  b.pqcAgent.reload();   // destroys second
  var res2 = b.pqcAgent.reload();
  check("reload: idempotent — second consecutive call returns destroyed=false",
        res2.destroyed === false);
}

async function run() {
  await testDefaultGroupList();
  testNarrowToFrameworkSubset();
  testRefuseUnknownGroupByDefault();
  await testAllowOperatorGroupsAuditEmit();
  testKnownTlsGroupsExposed();
  testReloadSurface();
  testReloadAfterBuild();
}

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}

module.exports = { run: run };
