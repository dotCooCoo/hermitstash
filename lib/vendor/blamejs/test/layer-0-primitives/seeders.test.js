"use strict";
/**
 * b.seeders — DB seeders.
 *
 * Run standalone: `node test/layer-0-primitives/seeders.test.js`
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

// Build a test fixture directory under /tmp/blamejs-seeders-XXXX/seeders/<env>/...
// with the supplied seed-source map (env-name → { filename → moduleSource }).
function _buildSeedTree(map) {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seeders-"));
  var seedsDir = path.join(rootDir, "seeders");
  fs.mkdirSync(seedsDir);
  for (var env in map) {
    if (!Object.prototype.hasOwnProperty.call(map, env)) continue;
    var envDir = path.join(seedsDir, env);
    fs.mkdirSync(envDir, { recursive: true });
    var files = map[env];
    for (var fname in files) {
      if (!Object.prototype.hasOwnProperty.call(files, fname)) continue;
      fs.writeFileSync(path.join(envDir, fname), files[fname]);
    }
  }
  return { rootDir: rootDir, seedsDir: seedsDir };
}

function _cleanupTree(t) {
  try { fs.rmSync(t.rootDir, { recursive: true, force: true }); }
  catch (_e) { /* tmpdir cleanup best-effort */ }
}

// Each seed file uses a side-effect log (`global.__seedLog__`) so we can
// observe execution order without owning a test DB schema.
function _resetSeedLog() {
  global.__seedLog__ = [];
}

function _seedSource(name, opts) {
  opts = opts || {};
  var pieces = [];
  if (opts.description) pieces.push("  description: " + JSON.stringify(opts.description) + ",");
  if (opts.envs) pieces.push("  envs: " + JSON.stringify(opts.envs) + ",");
  if (opts.rerunnable !== undefined) pieces.push("  rerunnable: " + JSON.stringify(opts.rerunnable) + ",");
  if (opts.dependsOn) pieces.push("  dependsOn: " + JSON.stringify(opts.dependsOn) + ",");
  var body = opts.body || ("global.__seedLog__.push(" + JSON.stringify(name) + ");");
  if (opts.throws) {
    body = "throw new Error(" + JSON.stringify(opts.throws) + ");";
  }
  // Some seeds also write to a sentinel table to verify txn semantics.
  pieces.push("  run: async function (db, ctx) {\n" +
              "    void ctx;\n" +
              "    " + body + "\n" +
              "  },");
  return "module.exports = {\n" + pieces.join("\n") + "\n};\n";
}

// ---- Surface ----

async function testSurface() {
  check("b.seeders namespace present",      typeof b.seeders === "object");
  check("b.seeders.create is a function",   typeof b.seeders.create === "function");
  check("b.seeders.SeederError class",      typeof b.seeders.SeederError === "function");
  check("b.seeders.DEFAULTS frozen",        Object.isFrozen(b.seeders.DEFAULTS));
  check("DEFAULTS.auditApplied true (operator action)",
        b.seeders.DEFAULTS.auditApplied === true);
  check("DEFAULTS.auditFailures true (signal)",
        b.seeders.DEFAULTS.auditFailures === true);
  check("DEFAULTS.lockStaleAfterMs 0 (no auto-replace)",
        b.seeders.DEFAULTS.lockStaleAfterMs === 0);
  check("SEEDERS_TABLE constant",           b.seeders.SEEDERS_TABLE === "_blamejs_seeders");
  check("LOCK_TABLE constant",              b.seeders.LOCK_TABLE === "_blamejs_seeders_lock");
  check("FILE_RE matches NNNN-slug.js",     b.seeders.FILE_RE.test("0001-init.js"));
  check("FILE_RE rejects no-prefix",        !b.seeders.FILE_RE.test("init.js"));
}

// ---- Input validation (rejects bad opts at create time) ----

async function testValidation() {
  var threwNoOpts = false;
  try { b.seeders.create(); } catch (_e) { threwNoOpts = true; }
  check("create() with no opts throws",     threwNoOpts);

  var threwNoDir = false;
  try { b.seeders.create({}); } catch (_e) { threwNoDir = true; }
  check("create() without dir throws",      threwNoDir);

  var threwBadDb = false;
  try { b.seeders.create({ dir: "/x", db: 42 }); } catch (_e) { threwBadDb = true; }
  check("create() with non-handle db throws", threwBadDb);

  var threwBadAudit = false;
  try { b.seeders.create({ dir: "/x", audit: { /* no safeEmit */ } }); }
  catch (_e) { threwBadAudit = true; }
  check("create() with non-conforming audit throws", threwBadAudit);

  var threwBadLockMs = false;
  try { b.seeders.create({ dir: "/x", lockStaleAfterMs: -1 }); }
  catch (_e) { threwBadLockMs = true; }
  check("create() with negative lockStaleAfterMs throws", threwBadLockMs);
}

async function testRunRequiresEnv() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({ dev: {} });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threwNoEnv = false;
      try { await runner.run({}); } catch (_e) { threwNoEnv = true; }
      check("run() without env throws",          threwNoEnv);
      var threwBadEnv = false;
      try { await runner.run({ env: "BAD ENV" }); } catch (_e) { threwBadEnv = true; }
      check("run() with bad-format env throws",  threwBadEnv);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Basic apply + idempotency ----

async function testBasicApplyAndIdempotent() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-alpha.js": _seedSource("alpha"),
        "0002-bravo.js": _seedSource("bravo"),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var r1 = await runner.run({ env: "dev" });
      check("first run applies all seeds",       r1.applied.length === 2);
      check("first run skipped is empty",        r1.skipped.length === 0);
      check("first run failed is null",          r1.failed === null);
      check("seeds executed in filename order",
            global.__seedLog__.length === 2 &&
            global.__seedLog__[0] === "alpha" &&
            global.__seedLog__[1] === "bravo");

      // Registry rows recorded
      var rows = b.db.prepare(
        "SELECT name, env, rerunnable FROM _blamejs_seeders WHERE env = ? ORDER BY name"
      ).all("dev");
      check("registry has 2 rows for env=dev",   rows.length === 2);
      check("registry rerunnable=0 for default",  rows[0].rerunnable === 0);

      _resetSeedLog();
      var r2 = await runner.run({ env: "dev" });
      check("second run applies 0 (idempotent)", r2.applied.length === 0);
      check("second run skips both",             r2.skipped.length === 2);
      check("seeds did NOT re-execute",          global.__seedLog__.length === 0);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Env scoping ----

async function testEnvScoping() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev:  { "0001-dev-only.js":  _seedSource("dev-only") },
      prod: { "0001-prod-only.js": _seedSource("prod-only") },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      await runner.run({ env: "dev" });
      check("dev run applies only dev/0001-dev-only.js",
            global.__seedLog__.length === 1 &&
            global.__seedLog__[0] === "dev-only");
      _resetSeedLog();
      await runner.run({ env: "prod" });
      check("prod run applies only prod/0001-prod-only.js",
            global.__seedLog__.length === 1 &&
            global.__seedLog__[0] === "prod-only");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Explicit envs declaration overrides path ----

async function testExplicitEnvsList() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        // envs: ["dev","test"] — applies under both
        "0001-shared.js": _seedSource("shared", { envs: ["dev", "test"] }),
        // envs: ["test"] — declared as test-only even though placed in dev/
        "0002-test-only.js": _seedSource("test-only", { envs: ["test"] }),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      await runner.run({ env: "dev" });
      check("explicit envs=['dev','test'] applies under dev",
            global.__seedLog__.indexOf("shared") !== -1);
      check("explicit envs=['test'] does NOT apply under dev",
            global.__seedLog__.indexOf("test-only") === -1);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- only filter ----

async function testOnlyFilter() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-alpha.js":   _seedSource("alpha"),
        "0002-bravo.js":   _seedSource("bravo"),
        "0003-charlie.js": _seedSource("charlie"),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var r = await runner.run({ env: "dev", only: "0002-bravo.js" });
      check("only filter applies single seed", r.applied.length === 1);
      check("only filter ran the named seed",
            global.__seedLog__.length === 1 &&
            global.__seedLog__[0] === "bravo");

      var threwNotFound = false;
      try { await runner.run({ env: "dev", only: "0042-missing.js" }); }
      catch (_e) { threwNotFound = true; }
      check("only with unknown filename throws", threwNotFound);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Rerunnable seeds ----

async function testRerunnable() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-once.js":      _seedSource("once"),
        "0002-recurring.js": _seedSource("recurring", { rerunnable: true }),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var r1 = await runner.run({ env: "dev" });
      check("first run applies both",            r1.applied.length === 2);

      _resetSeedLog();
      var r2 = await runner.run({ env: "dev" });
      check("second run skips once-seed",
            r2.skipped.indexOf("0001-once.js") !== -1);
      check("second run RE-applies rerunnable seed",
            r2.applied.indexOf("0002-recurring.js") !== -1);
      check("rerunnable seed body invoked again",
            global.__seedLog__.length === 1 &&
            global.__seedLog__[0] === "recurring");

      var rerunnableRow = b.db.prepare(
        "SELECT rerunnable FROM _blamejs_seeders WHERE env = ? AND name = ?"
      ).get("dev", "0002-recurring.js");
      check("rerunnable=1 in registry",          rerunnableRow.rerunnable === 1);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- force flag ----

async function testForceFlag() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-once.js": _seedSource("once") },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      await runner.run({ env: "dev" });
      check("baseline first run applies",        global.__seedLog__.length === 1);

      _resetSeedLog();
      var r2 = await runner.run({ env: "dev" });
      check("default re-run skips",              r2.applied.length === 0);

      _resetSeedLog();
      var r3 = await runner.run({ env: "dev", force: true });
      check("force re-applies non-rerunnable",   r3.applied.length === 1);
      check("force seed body invoked again",     global.__seedLog__.length === 1);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Dependencies ----

async function testDependencies() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        // Even though 0010-z is sorted last by name, B depends on it,
        // so topo sort must put 0010-z before 0020-b.
        "0010-z.js": _seedSource("z"),
        "0020-b.js": _seedSource("b", { dependsOn: ["0010-z.js"] }),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      await runner.run({ env: "dev" });
      check("topo-sorted: z before b (dependsOn honored)",
            global.__seedLog__.length === 2 &&
            global.__seedLog__[0] === "z" &&
            global.__seedLog__[1] === "b");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMissingDependency() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-orphan.js": _seedSource("orphan", { dependsOn: ["0099-missing.js"] }) },
    });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threwMissing = false;
      try { await runner.run({ env: "dev" }); } catch (e) {
        threwMissing = (e && /MISSING_DEP/.test(e.code || ""));
      }
      check("missing dep throws MISSING_DEP",    threwMissing);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCycleDetection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-a.js": _seedSource("a", { dependsOn: ["0002-b.js"] }),
        "0002-b.js": _seedSource("b", { dependsOn: ["0001-a.js"] }),
      },
    });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threwCycle = false;
      try { await runner.run({ env: "dev" }); } catch (e) {
        threwCycle = (e && /CYCLE/.test(e.code || ""));
      }
      check("dependency cycle throws CYCLE",     threwCycle);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Bad seed shape rejected at load ----

async function testBadSeedShape() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    // Seed missing run() — caught at load
    var tree = _buildSeedTree({
      dev: {
        "0001-no-run.js": "module.exports = { description: 'oops' };\n",
      },
    });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threw = false;
      try { await runner.run({ env: "dev" }); } catch (e) {
        threw = (e && /BAD_SEED/.test(e.code || ""));
      }
      check("seed without run() throws BAD_SEED at load", threw);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Per-seed txn rollback on failure ----

async function testPerSeedTxnRollback() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    // Build a fixture table (operator's app schema), and have each seed
    // INSERT into it. Failure mid-seed should leave the table empty
    // for that seed's rows.
    b.db.prepare("CREATE TABLE IF NOT EXISTS _seed_test (val TEXT NOT NULL)").run();
    var tree = _buildSeedTree({
      dev: {
        "0001-good.js":      _seedSource("good", {
          body: "db.prepare('INSERT INTO _seed_test (val) VALUES (?)').run('one');" +
                "global.__seedLog__.push('good');"
        }),
        "0002-explodes.js":  _seedSource("explodes", {
          body: "db.prepare('INSERT INTO _seed_test (val) VALUES (?)').run('two-then-throw');" +
                "global.__seedLog__.push('partial-write');" +
                "throw new Error('bang');"
        }),
        "0003-skipped.js":   _seedSource("skipped"),
      },
    });
    try {
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threwRunFailed = false;
      var resultErr = null;
      try { await runner.run({ env: "dev" }); }
      catch (e) {
        threwRunFailed = (e && /RUN_FAILED/.test(e.code || ""));
        resultErr = e;
      }
      check("run throws RUN_FAILED when a seed errors", threwRunFailed);
      check("error carries partial result with applied/failed",
            !!resultErr && !!resultErr.result &&
            resultErr.result.applied[0] === "0001-good.js" &&
            resultErr.result.failed === "0002-explodes.js");

      var rows = b.db.prepare("SELECT val FROM _seed_test ORDER BY val").all();
      check("good seed wrote its row (committed)",
            rows.length === 1 && rows[0].val === "one");
      check("failed seed's partial write rolled back",
            rows.findIndex(function (r) { return r.val === "two-then-throw"; }) === -1);
      check("subsequent seeds in batch did NOT run",
            global.__seedLog__.indexOf("skipped") === -1);

      var registry = b.db.prepare(
        "SELECT name FROM _blamejs_seeders WHERE env = ?"
      ).all("dev");
      check("registry has only the good seed",
            registry.length === 1 && registry[0].name === "0001-good.js");
    } finally {
      try { b.db.prepare("DROP TABLE IF EXISTS _seed_test").run(); } catch (_e) {}
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Lock ----

async function testLockHeld() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({ dev: {} });
    try {
      // Pre-occupy the lock with a fake holder.
      b.db.prepare(
        "INSERT INTO _blamejs_seeders_lock (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
      ).run(Date.now(), "other-process@host");
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var threwLock = false;
      try { await runner.run({ env: "dev" }); }
      catch (e) { threwLock = (e && /LOCK_HELD/.test(e.code || "")); }
      check("concurrent run sees LOCK_HELD",     threwLock);
      // Cleanup
      b.db.prepare("DELETE FROM _blamejs_seeders_lock").run();
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLockStaleReplace() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-x.js": _seedSource("x") },
    });
    try {
      // Pre-occupy lock with an "old" timestamp 10s ago.
      var staleAt = Date.now() - 10000;
      b.db.prepare(
        "INSERT INTO _blamejs_seeders_lock (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
      ).run(staleAt, "abandoned@host");
      _resetSeedLog();
      var runner = b.seeders.create({ dir: tree.seedsDir, lockStaleAfterMs: 1000 });
      var r = await runner.run({ env: "dev" });
      check("stale lock replaced + run succeeded",
            r.applied.length === 1 && global.__seedLog__[0] === "x");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- status() ----

async function testStatus() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-a.js": _seedSource("a"),
        "0002-b.js": _seedSource("b", { rerunnable: true }),
        "0003-c.js": _seedSource("c"),
      },
    });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var s0 = await runner.status({ env: "dev" });
      check("status before run: 3 pending",      s0.pending.length === 3);
      check("status before run: 0 applied",      s0.applied.length === 0);
      check("status: total=3",                   s0.total === 3);
      check("status: 1 rerunnable identified",   s0.rerunnable.length === 1);

      await runner.run({ env: "dev" });
      var s1 = await runner.status({ env: "dev" });
      check("status after run: 3 applied",       s1.applied.length === 3);
      // rerunnable seeds remain "pending" (always run on next invocation)
      check("status after run: rerunnable still in pending",
            s1.pending.length === 1 && s1.pending[0] === "0002-b.js");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Audit emission ----

async function testAuditAppliedOn() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-a.js": _seedSource("a", { description: "test seed" }) },
    });
    try {
      var audit = b.testing.captureAudit();
      var runner = b.seeders.create({
        dir:   tree.seedsDir,
        audit: audit,
      });
      var fakeReq = b.testing.mockReq({
        ip:        "10.0.0.5",
        userAgent: "tester/1.0",
        requestId: "req-42",
        method:    "POST",
        url:       "/admin/seed/run",
      });
      await runner.run({ env: "dev", req: fakeReq });
      var ev = audit.byAction("seeders.applied")[0];
      check("default: seeders.applied audited",  !!ev);
      check("audit carries 5 W's via extractActorContext",
            !!ev &&
            ev.actor.ip === "10.0.0.5" &&
            ev.actor.userAgent === "tester/1.0" &&
            ev.actor.requestId === "req-42" &&
            ev.actor.method === "POST" &&
            ev.actor.route === "/admin/seed/run");
      check("audit metadata includes description",
            !!ev && ev.metadata && ev.metadata.description === "test seed");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditAppliedOptOut() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-a.js": _seedSource("a") },
    });
    try {
      var audit = b.testing.captureAudit();
      var runner = b.seeders.create({
        dir:           tree.seedsDir,
        audit:         audit,
        auditApplied:  false,
      });
      await runner.run({ env: "dev" });
      check("opt-out: seeders.applied NOT emitted when auditApplied=false",
            audit.byAction("seeders.applied").length === 0);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditFailedOn() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-bad.js": _seedSource("bad", { throws: "boom" }) },
    });
    try {
      var audit = b.testing.captureAudit();
      var runner = b.seeders.create({
        dir:   tree.seedsDir,
        audit: audit,
      });
      try { await runner.run({ env: "dev" }); } catch (_e) {}
      var ev = audit.byAction("seeders.failed")[0];
      check("default: seeders.failed audited on error",  !!ev);
      check("failed audit outcome=failure",
            !!ev && ev.outcome === "failure");
      check("failed audit metadata carries cause message",
            !!ev && ev.metadata && /boom/.test(ev.metadata.message || ""));
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditForceApplied() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: { "0001-x.js": _seedSource("x") },
    });
    try {
      var audit = b.testing.captureAudit();
      var runner = b.seeders.create({
        dir:   tree.seedsDir,
        audit: audit,
      });
      await runner.run({ env: "dev" });
      audit.clear();
      await runner.run({ env: "dev", force: true });
      check("force re-apply emits seeders.force_applied (distinct from applied)",
            audit.byAction("seeders.force_applied").length > 0 &&
            audit.byAction("seeders.applied").length === 0);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Observability ----

async function testObservabilityEmission() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0001-a.js": _seedSource("a"),
        "0002-b.js": _seedSource("b"),
      },
    });
    try {
      var cap = b.testing.captureMetricsTap();
      try {
        var runner = b.seeders.create({ dir: tree.seedsDir });
        await runner.run({ env: "dev" });
      } finally {
        cap.restore();
      }
      check("emits seeders.run.start",          cap.byName("seeders.run.start").length > 0);
      check("emits seeders.applied",            cap.byName("seeders.applied").length > 0);
      check("emits seeders.run.completed",      cap.byName("seeders.run.completed").length > 0);
      var startEvt = cap.byName("seeders.run.start")[0];
      check("seeders.run.start labels carry env + count",
            !!startEvt && startEvt.labels.env === "dev" && startEvt.labels.count === 2);
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- list() ----

async function testListSorted() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-seedersdb-"));
  try {
    await setupTestDb(tmpDir);
    var tree = _buildSeedTree({
      dev: {
        "0003-c.js": _seedSource("c"),
        "0001-a.js": _seedSource("a"),
        "0002-b.js": _seedSource("b"),
      },
    });
    try {
      var runner = b.seeders.create({ dir: tree.seedsDir });
      var files = await runner.list({ env: "dev" });
      check("list returns filename-sorted array",
            files.length === 3 &&
            files[0] === "0001-a.js" &&
            files[1] === "0002-b.js" &&
            files[2] === "0003-c.js");
    } finally {
      _cleanupTree(tree);
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- run ----

async function run() {
  await testSurface();
  await testValidation();
  await testRunRequiresEnv();
  await testBasicApplyAndIdempotent();
  await testEnvScoping();
  await testExplicitEnvsList();
  await testOnlyFilter();
  await testRerunnable();
  await testForceFlag();
  await testDependencies();
  await testMissingDependency();
  await testCycleDetection();
  await testBadSeedShape();
  await testPerSeedTxnRollback();
  await testLockHeld();
  await testLockStaleReplace();
  await testStatus();
  await testAuditAppliedOn();
  await testAuditAppliedOptOut();
  await testAuditFailedOn();
  await testAuditForceApplied();
  await testObservabilityEmission();
  await testListSorted();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
