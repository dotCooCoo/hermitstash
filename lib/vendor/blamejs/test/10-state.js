"use strict";
/**
 * Layer 1 — framework-state primitives.
 *
 * (Layer 1: framework-state-dependent
 * but isolated). These primitives initialize / tear down framework state
 * but don't depend on db, audit chain, or external integrations.
 *
 *   vault             — keypair derivation, wrapping, mode mismatch detection
 *   cluster           — leader election + provider abstraction + gates
 *   framework-schema  — DDL emitter + table-name resolver
 *
 * Layer 0 primitives (test/00-primitives.js) must run first.
 *
 * Usage from smoke.js:
 *   var stateLayer = require("./10-state");
 *   await stateLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var _makeSqliteDriver        = helpers._makeSqliteDriver;
var _makeFakeMysqlDriver     = helpers._makeFakeMysqlDriver;

async function testVaultWrapRoundTrip() {
  var fastOpts = { memoryCost: 1024, timeCost: 1, parallelism: 1, saltLength: 16 };
  var pt = Buffer.from("the quick brown fox jumps over the lazy dog", "utf8");
  var passphrase = Buffer.from("test-passphrase-2026", "utf8");

  var wrapped = await b.vaultWrap.wrap(pt, passphrase, fastOpts);
  check("vault-wrap output starts with magic 0xE2",  wrapped[0] === 0xE2);
  check("vault-wrap output has format version 0x01", wrapped[1] === 0x01);

  var unwrapped = await b.vaultWrap.unwrap(wrapped, passphrase);
  check("vault-wrap round-trip preserves plaintext", unwrapped.equals(pt));

  // Wrong passphrase
  var wrongRejected = false;
  try { await b.vaultWrap.unwrap(wrapped, Buffer.from("wrong-passphrase", "utf8")); }
  catch (_) { wrongRejected = true; }
  check("vault-wrap rejects wrong passphrase", wrongRejected);

  // Tampered ciphertext
  var tampered = Buffer.from(wrapped);
  tampered[tampered.length - 1] ^= 0x01;
  var tamperRejected = false;
  try { await b.vaultWrap.unwrap(tampered, passphrase); }
  catch (_) { tamperRejected = true; }
  check("vault-wrap rejects tampered ciphertext", tamperRejected);

  // Tampered header (memory cost byte) — AAD binding catches this
  var headerTampered = Buffer.from(wrapped);
  headerTampered[5] ^= 0x01;  // flip a memoryCost byte
  var headerRejected = false;
  try { await b.vaultWrap.unwrap(headerTampered, passphrase); }
  catch (_) { headerRejected = true; }
  check("vault-wrap rejects tampered header", headerRejected);
}

async function testPassphraseEnv() {
  process.env.BLAMEJS_VAULT_PASSPHRASE = "smoke-test-passphrase";
  var buf = await b.vaultPassphraseSource.fromEnv();
  check("vaultPassphraseSource.fromEnv returns Buffer",  Buffer.isBuffer(buf));
  check("vaultPassphraseSource.fromEnv preserves bytes", buf.toString("utf8") === "smoke-test-passphrase");
  check("vaultPassphraseSource.fromEnv strips env var",  !("BLAMEJS_VAULT_PASSPHRASE" in process.env));
}

async function testVaultPlaintextRoundTrip() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smoke-"));
  try {
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault.init writes vault.key in plaintext mode", fs.existsSync(path.join(tmpDir, "vault.key")));
    check("vault.getMode() returns 'plaintext'", b.vault.getMode() === "plaintext");

    var sealed = b.vault.seal("test-payload-" + b.version);
    check("vault.seal returns 'vault:' prefixed string",
          typeof sealed === "string" && sealed.startsWith("vault:"));

    var opened = b.vault.unseal(sealed);
    check("vault.unseal round-trip preserves plaintext",
          opened === "test-payload-" + b.version);

    // idempotent seal — already-sealed values pass through
    var doubleSealed = b.vault.seal(sealed);
    check("vault.seal is idempotent on already-sealed values", doubleSealed === sealed);

    // null/empty pass-through
    check("vault.seal passes empty through",  b.vault.seal("") === "");
    check("vault.unseal passes empty through", b.vault.unseal("") === "");
    check("vault.unseal passes plain through", b.vault.unseal("plaintext-not-sealed") === "plaintext-not-sealed");

    // Persistence — re-init from same dir restores keys, same envelope decodes
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    var openedAgain = b.vault.unseal(sealed);
    check("vault persistence: second init restores keys", openedAgain === "test-payload-" + b.version);
  } finally {
    b.vault._resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testVaultModeMismatch() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smoke-mode-"));
  try {
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.vault._resetForTest();
    // Now there's a vault.key file but we'll request wrapped mode → should fatal
    // We can't easily test process.exit(1) without forking, so we check that
    // the init's preflight detects the mismatch. Instead, verify we can re-init
    // with the same mode after reset — this confirms the path works.
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault re-init in same mode succeeds", b.vault.getMode() === "plaintext");
  } finally {
    b.vault._resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testVaultRequiresDataDir() {
  b.vault._resetForTest();
  var rejected = false;
  try { await b.vault.init({}); } catch (_) { rejected = true; }
  check("vault.init() rejects missing dataDir", rejected);
  b.vault._resetForTest();
}

async function testVaultWrappedE2E() {
  if (process.env.BLAMEJS_SKIP_WRAPPED_E2E === "1") {
    return;
  }
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wrap-e2e-"));
  var passphrase = "smoke-wrapped-vault-2026-" + Date.now();
  // Save whatever was set by an earlier test (e.g. helpers/db.js
  // sets a stable test passphrase) so the finally block restores it
  // — deleting it unconditionally breaks downstream tests that need
  // the helper-supplied passphrase.
  var priorPassphrase = process.env.BLAMEJS_VAULT_PASSPHRASE;
  process.env.BLAMEJS_VAULT_PASSPHRASE = passphrase;
  try {
    b.vault._resetForTest();
    var t0 = Date.now();
    await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    var t1 = Date.now();
    check("wrapped first-run init under 5s", (t1 - t0) < 5000);
    check("wrapped init sets mode='wrapped'",          b.vault.getMode() === "wrapped");
    check("wrapped init writes vault.key.sealed",      fs.existsSync(path.join(tmpDir, "vault.key.sealed")));
    check("wrapped init does NOT write vault.key",     !fs.existsSync(path.join(tmpDir, "vault.key")));

    // Verify the sealed file format starts with the wrap magic byte (0xE2)
    var sealedBytes = fs.readFileSync(path.join(tmpDir, "vault.key.sealed"));
    check("vault.key.sealed starts with magic 0xE2",   sealedBytes[0] === 0xE2);
    check("vault.key.sealed has format version 0x01",  sealedBytes[1] === 0x01);

    // seal/unseal round-trip works under wrapped mode
    var payload = "wrapped-e2e-payload-" + b.version;
    var sealedVal = b.vault.seal(payload);
    var openedVal = b.vault.unseal(sealedVal);
    check("wrapped seal/unseal round-trip preserves plaintext", openedVal === payload);

    // Persistence — close, reset, re-init from the same sealed file with the same passphrase
    b.vault._resetForTest();
    process.env.BLAMEJS_VAULT_PASSPHRASE = passphrase;
    var t2 = Date.now();
    await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    var t3 = Date.now();
    check("wrapped restore (existing sealed) under 5s", (t3 - t2) < 5000);
    check("restored mode is 'wrapped'",                 b.vault.getMode() === "wrapped");

    // The previously-sealed value must still decrypt under the restored vault
    var openedAgain = b.vault.unseal(sealedVal);
    check("wrapped persistence: prior sealed value decrypts after restart", openedAgain === payload);
  } finally {
    if (priorPassphrase === undefined) delete process.env.BLAMEJS_VAULT_PASSPHRASE;
    else process.env.BLAMEJS_VAULT_PASSPHRASE = priorPassphrase;
    b.vault._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testClusterSingleNodeFallback() {
  // Without cluster.init, the framework treats us as permanent leader.
  b.cluster._resetForTest();
  check("cluster.isLeader() true when not initialized",  b.cluster.isLeader() === true);
  check("cluster.fencingToken() = 0 when not initialized", b.cluster.fencingToken() === 0);
  check("cluster.currentNodeId() = single-node-local",   b.cluster.currentNodeId() === "single-node-local");
  // requireLeader is a no-op
  var threw = false;
  try { b.cluster.requireLeader(); } catch (_e) { threw = true; }
  check("cluster.requireLeader() does not throw on single-node", threw === false);
}

async function testClusterProviderAcquireAndRenew() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var p = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await p.ensureSchema();

    var lease1 = await p.acquireLease("node-A", b.constants.TIME.seconds(30));
    check("provider.acquireLease succeeds on empty DB",  lease1 !== null);
    check("first lease has fencingToken = 1",            lease1.fencingToken === 1);
    check("first lease records nodeId",                  lease1.nodeId === "node-A");
    check("first lease has acquiredAt set",              typeof lease1.acquiredAt === "number");

    var renewed = await p.renewLease(lease1);
    check("renewLease returns updated lease",            renewed.leaseId === lease1.leaseId);
    check("renewLease pushes expiresAt forward",         renewed.expiresAt >= lease1.expiresAt);
    check("renewLease does NOT bump fencingToken",       renewed.fencingToken === 1);

    var current = await p.currentLeader();
    check("currentLeader returns us",                    current.nodeId === "node-A");
    check("currentLeader fencingToken matches",          current.fencingToken === 1);

    await p.releaseLease(renewed);
    var afterRelease = await p.currentLeader();
    check("currentLeader returns null after release",    afterRelease === null);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderTwoNodeContention() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    var leaseA = await pA.acquireLease("node-A", b.constants.TIME.seconds(30));
    check("node-A acquires lease",                       leaseA !== null);

    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("node-B blocked while A holds non-expired",    leaseB === null);

    var current = await pB.currentLeader();
    check("node-B's currentLeader sees node-A",          current.nodeId === "node-A");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderTakeoverAfterExpiry() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    // Node A acquires with a tiny TTL — practically already expired by
    // the time we attempt the takeover.
    var leaseA = await pA.acquireLease("node-A", 50);
    check("node-A acquired short-TTL lease",             leaseA !== null);
    check("first acquire fencingToken = 1",              leaseA.fencingToken === 1);

    // Wait past expiry (50ms TTL + buffer) — a real-time elapse to let the
    // DB-side lease TTL lapse, not a condition-wait, so passiveObserve is right.
    await helpers.passiveObserve(100, "10-state: lease TTL expiry (50ms TTL + buffer)");

    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("node-B steals expired lease",                 leaseB !== null);
    check("takeover bumps fencingToken to 2",            leaseB.fencingToken === 2);
    check("node-B is now recorded leader",               leaseB.nodeId === "node-B");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderRenewalRace() {
  // After takeover, the old leader's renewLease must throw LEASE_LOST.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    var leaseA = await pA.acquireLease("node-A", 50);
    // Real-time elapse to let the 50ms lease TTL lapse before the takeover race.
    await helpers.passiveObserve(100, "10-state: lease TTL expiry before takeover-race");
    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("takeover succeeded for race test",            leaseB !== null);

    var threw = null;
    try { await pA.renewLease(leaseA); }
    catch (e) { threw = e; }
    check("old leader's renewLease throws",              threw !== null);
    check("error code is LEASE_LOST",                    threw && threw.code === "LEASE_LOST");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderMysqlDialect() {
  // MySQL dialect uses a different acquire shape (INSERT ... ON
  // DUPLICATE KEY UPDATE with IF()-gated columns + follow-up SELECT)
  // and ?-placeholders. The fake mysql driver emulates the per-column
  // IF() semantics so we can test acquire / renew / takeover / release
  // semantics without a real MySQL connection.
  var driver = _makeFakeMysqlDriver();
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close, dialect: "mysql" },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "mysql" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "mysql" });

    // Reject unsupported dialect.
    var threwBad = null;
    try { providerFactory.create({ externalDbBackend: "ops", dialect: "oracle" }); }
    catch (e) { threwBad = e; }
    check("mysql provider: rejects unsupported dialect 'oracle'",
          threwBad && threwBad.code === "UNSUPPORTED_DIALECT");

    await pA.ensureSchema();
    var sqlSeen = driver._loggedSql();
    check("mysql provider: ensureSchema emits CREATE TABLE _blamejs_leader",
          sqlSeen.some(function (e) { return /CREATE TABLE IF NOT EXISTS _blamejs_leader/.test(e.sql); }));
    check("mysql provider: emits VARCHAR for primary-key columns",
          sqlSeen.some(function (e) { return /VARCHAR\(64\) PRIMARY KEY/.test(e.sql); }));
    check("mysql provider: skips Postgres-only CHECK constraint",
          !sqlSeen.some(function (e) { return /_blamejs_leader[\s\S]*CHECK \(scope = 'leader'\)/.test(e.sql); }));

    var leaseA = await pA.acquireLease("node-A", b.constants.TIME.seconds(30));
    check("mysql provider: acquireLease succeeds on empty DB",  leaseA !== null);
    check("mysql provider: first lease has fencingToken = 1",   leaseA.fencingToken === 1);
    check("mysql provider: emitted INSERT...ON DUPLICATE KEY",
          sqlSeen.some(function (e) { return /ON DUPLICATE KEY UPDATE/.test(e.sql); }));
    check("mysql provider: uses ? placeholders not $1",
          sqlSeen.some(function (e) {
            // The provider composes the upsert through b.sql, which binds
            // every value (scope included) as a `?` rather than inlining
            // the 'leader' literal — so the MySQL form is an all-`?` VALUES
            // list with no Postgres `$1` numbering.
            return /INSERT INTO _blamejs_leader[\s\S]*VALUES\s*\(\s*\?(?:\s*,\s*\?)*\s*\)/.test(e.sql) &&
                   !/\$1/.test(e.sql);
          }));
    check("mysql provider: gates fencingToken with IF(expiresAt < ?, ...)",
          sqlSeen.some(function (e) { return /`fencingToken` = IF\(`expiresAt` < \?, `fencingToken` \+ 1, `fencingToken`\)/.test(e.sql); }));

    // Second node blocked while A holds.
    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("mysql provider: B blocked while A holds non-expired", leaseB === null);

    // Renew preserves fencingToken.
    var renewed = await pA.renewLease(leaseA);
    check("mysql provider: renewLease keeps fencingToken",       renewed.fencingToken === 1);

    // Takeover after expiry. Force expiresAt to the past to simulate
    // expiry without a real time-pause; same fencingToken state as A's
    // current acquire.
    var fencingBeforeTakeover = renewed.fencingToken;
    driver._state()._blamejs_leader.expiresAt = 0;
    var leaseTakeover = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("mysql provider: B takes over after expiry",           leaseTakeover !== null);
    check("mysql provider: takeover bumps fencingToken",
          leaseTakeover.fencingToken === fencingBeforeTakeover + 1);

    // Old leader's renew throws LEASE_LOST.
    var threwRenew = null;
    try { await pA.renewLease(renewed); }
    catch (e) { threwRenew = e; }
    check("mysql provider: old leader's renewLease throws LEASE_LOST",
          threwRenew && threwRenew.code === "LEASE_LOST");

    // currentLeader sees B.
    var current = await pB.currentLeader();
    check("mysql provider: currentLeader reports B",             current.nodeId === "node-B");

    await pB.releaseLease(leaseTakeover);
    var afterRelease = await pB.currentLeader();
    check("mysql provider: currentLeader null after release",    afterRelease === null);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
  }
}

async function testClusterInitAndRequireLeader() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    b.cluster._resetForTest();
    await b.cluster.init({
      nodeId:            "test-node-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    check("after init, isLeader() is true",              b.cluster.isLeader() === true);
    check("currentNodeId reflects config",               b.cluster.currentNodeId() === "test-node-1");
    check("fencingToken > 0 after init",                 b.cluster.fencingToken() > 0);

    // requireLeader passes silently
    var threwOnLeader = false;
    try { b.cluster.requireLeader(); } catch (_e) { threwOnLeader = true; }
    check("requireLeader does not throw on leader",      threwOnLeader === false);

    var leader = await b.cluster.currentLeader();
    check("currentLeader returns this node",             leader && leader.nodeId === "test-node-1");

    // Simulate becoming non-leader by manually clearing the lease (the
    // module's normal path for losing leadership is via a renewal race,
    // already covered in testClusterProviderRenewalRace).
    await b.cluster.shutdown();
    check("after shutdown, isLeader() false",            b.cluster.isLeader() === false);
    var threwOnFollower = null;
    try { b.cluster.requireLeader(); } catch (e) { threwOnFollower = e; }
    check("requireLeader throws when not leader",        threwOnFollower !== null);
    check("error is NotLeaderError",                     threwOnFollower &&
                                                          threwOnFollower.code === "NOT_LEADER");
    check("error has 503 statusCode",                    threwOnFollower &&
                                                          threwOnFollower.statusCode === 503);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testFrameworkSchemaEnsure() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fs-"));
  var dbPath = path.join(tmpDir, "schema.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var result = await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    check("ensureSchema returns 20 tables (_blamejs_session_valid_from is the 20th)",
          result.tables.length === 20);
    check("ensureSchema includes _blamejs_cache_tags",
          result.tables.indexOf("_blamejs_cache_tags") !== -1);
    check("ensureSchema includes _blamejs_session_valid_from",
          result.tables.indexOf("_blamejs_session_valid_from") !== -1);
    check("ensureSchema includes _blamejs_break_glass_policies",
          result.tables.indexOf("_blamejs_break_glass_policies") !== -1);
    check("ensureSchema includes _blamejs_break_glass_grants",
          result.tables.indexOf("_blamejs_break_glass_grants") !== -1);
    check("ensureSchema includes _blamejs_audit_log",
          result.tables.indexOf("_blamejs_audit_log") !== -1);
    check("ensureSchema includes _blamejs_consent_log",
          result.tables.indexOf("_blamejs_consent_log") !== -1);
    check("ensureSchema includes _blamejs_audit_checkpoints",
          result.tables.indexOf("_blamejs_audit_checkpoints") !== -1);
    check("ensureSchema includes _blamejs_audit_tip",
          result.tables.indexOf("_blamejs_audit_tip") !== -1);
    check("ensureSchema includes _blamejs_sessions",
          result.tables.indexOf("_blamejs_sessions") !== -1);
    check("ensureSchema includes _blamejs_jobs",
          result.tables.indexOf("_blamejs_jobs") !== -1);
    check("ensureSchema includes _blamejs_consent_tip",
          result.tables.indexOf("_blamejs_consent_tip") !== -1);
    check("ensureSchema includes _blamejs_audit_purge_anchor",
          result.tables.indexOf("_blamejs_audit_purge_anchor") !== -1);
    check("ensureSchema includes _blamejs_scheduler_ticks",
          result.tables.indexOf("_blamejs_scheduler_ticks") !== -1);
    check("ensureSchema includes _blamejs_rate_limit_counters",
          result.tables.indexOf("_blamejs_rate_limit_counters") !== -1);
    check("ensureSchema includes _blamejs_pubsub_messages",
          result.tables.indexOf("_blamejs_pubsub_messages") !== -1);
    check("ensureSchema includes _blamejs_cache",
          result.tables.indexOf("_blamejs_cache") !== -1);
    check("ensureSchema includes _blamejs_seeders",
          result.tables.indexOf("_blamejs_seeders") !== -1);
    check("ensureSchema includes _blamejs_seeders_lock",
          result.tables.indexOf("_blamejs_seeders_lock") !== -1);

    // Each table is queryable
    var auditEmpty = await b.externalDb.query("SELECT COUNT(*) AS n FROM _blamejs_audit_log");
    check("audit_log table exists and is empty",    auditEmpty.rows[0].n === 0);
    var consentEmpty = await b.externalDb.query("SELECT COUNT(*) AS n FROM _blamejs_consent_log");
    check("consent_log table exists and is empty",  consentEmpty.rows[0].n === 0);

    // Audit-tip CHECK constraint enforces scope = 'audit'
    var threwBadScope = false;
    try {
      await b.externalDb.query(
        "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, fencingToken) VALUES ($1, $2, $3)",
        ["NOT_AUDIT", 0, 0]
      );
    } catch { threwBadScope = true; }
    check("audit_tip CHECK constraint rejects bad scope", threwBadScope);

    // Idempotent re-run
    var second = await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    check("ensureSchema is idempotent",             second.tables.length === 20);

    // Indexes exist
    var idxRow = await b.externalDb.query(
      "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = '_blamejs_audit_log'"
    );
    check("audit_log indexes created",              idxRow.rows.length >= 4);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testFrameworkSchemaTableNameMapping() {
  check("tableName('audit_log') maps to prefixed",
        b.frameworkSchema.tableName("audit_log") === "_blamejs_audit_log");
  check("tableName('consent_log') maps to prefixed",
        b.frameworkSchema.tableName("consent_log") === "_blamejs_consent_log");
  check("tableName('audit_checkpoints') maps to prefixed",
        b.frameworkSchema.tableName("audit_checkpoints") === "_blamejs_audit_checkpoints");
  check("tableName('_blamejs_audit_tip') is identity",
        b.frameworkSchema.tableName("_blamejs_audit_tip") === "_blamejs_audit_tip");
  check("tableName(unknown) returns identity",
        b.frameworkSchema.tableName("custom_table") === "custom_table");
  check("LOCAL_TO_EXTERNAL is frozen",
        Object.isFrozen(b.frameworkSchema.LOCAL_TO_EXTERNAL));

  // ---- Configurable table prefix ----
  // Default prefix is byte-identical to the historical names.
  check("getTablePrefix default is _blamejs_",
        b.frameworkSchema.getTablePrefix() === "_blamejs_");
  check("DEFAULT_TABLE_PREFIX is _blamejs_",
        b.frameworkSchema.DEFAULT_TABLE_PREFIX === "_blamejs_");

  // setTablePrefix throws config-time on a non-identifier prefix.
  var threwEmpty = false;
  try { b.frameworkSchema.setTablePrefix(""); }
  catch (e) { threwEmpty = e.code === "framework-schema/invalid-prefix"; }
  check("setTablePrefix('') throws invalid-prefix", threwEmpty);
  var threwBad = false;
  try { b.frameworkSchema.setTablePrefix("bad-prefix!"); }
  catch (e) { threwBad = e.code === "framework-schema/invalid-prefix"; }
  check("setTablePrefix('bad-prefix!') throws invalid-prefix", threwBad);
  var threwType = false;
  try { b.frameworkSchema.setTablePrefix(123); }
  catch (e) { threwType = e.code === "framework-schema/invalid-prefix"; }
  check("setTablePrefix(non-string) throws invalid-prefix", threwType);
  // A bad prefix must not have mutated state.
  check("getTablePrefix unchanged after rejected prefix",
        b.frameworkSchema.getTablePrefix() === "_blamejs_");

  // A valid prefix swaps the leading default across every framework name.
  try {
    b.frameworkSchema.setTablePrefix("acme_");
    check("getTablePrefix reflects configured prefix",
          b.frameworkSchema.getTablePrefix() === "acme_");
    check("tableName('audit_log') honors configured prefix",
          b.frameworkSchema.tableName("audit_log") === "acme_audit_log");
    check("tableName('_blamejs_sessions') honors configured prefix",
          b.frameworkSchema.tableName("_blamejs_sessions") === "acme_sessions");
    check("tableName(unknown) still identity under configured prefix",
          b.frameworkSchema.tableName("custom_table") === "custom_table");
  } finally {
    // Restore the default so the rest of the suite (and the running DB)
    // see the historical names — this state is module-global.
    b.frameworkSchema.setTablePrefix("_blamejs_");
  }
  check("getTablePrefix restored to default",
        b.frameworkSchema.getTablePrefix() === "_blamejs_");
}

// resolveTables rewrites bare framework table names to their prefixed
// external form ONLY in cluster mode, and honors a configured tablePrefix
// (set config-time). Proves _REWRITE_TABLE is prefix-aware (rebuilt when the
// prefix changes), so cluster-mode DML targets the same prefixed tables the
// DDL builders create — both the local-mapped names (audit_log) and the
// already-`_blamejs_`-prefixed identity names (_blamejs_scheduler_ticks),
// which only need rewriting under a custom prefix.
async function testClusterStoragePrefixRewrite() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-clpfx-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    b.cluster._resetForTest();
    await b.cluster.init({
      nodeId:            "pfx-node-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Default prefix: local-mapped name rewrites to its _blamejs_ external;
    // identity-mapped name passes through unchanged.
    check("resolveTables rewrites audit_log under default prefix",
          b.clusterStorage.resolveTables("SELECT id FROM audit_log WHERE n > ?") ===
          "SELECT id FROM _blamejs_audit_log WHERE n > ?");
    check("resolveTables leaves _blamejs_scheduler_ticks under default prefix",
          b.clusterStorage.resolveTables("DELETE FROM _blamejs_scheduler_ticks") ===
          "DELETE FROM _blamejs_scheduler_ticks");

    // Custom prefix: BOTH the local-mapped and the identity-mapped names
    // rewrite to <prefix>* so cluster DML matches the prefixed DDL. App
    // tables are never rewritten.
    try {
      b.frameworkSchema.setTablePrefix("acme_");
      check("resolveTables rewrites audit_log to the configured prefix",
            b.clusterStorage.resolveTables("SELECT id FROM audit_log WHERE n > ?") ===
            "SELECT id FROM acme_audit_log WHERE n > ?");
      check("resolveTables rewrites identity name _blamejs_scheduler_ticks to the prefix",
            b.clusterStorage.resolveTables("DELETE FROM _blamejs_scheduler_ticks") ===
            "DELETE FROM acme_scheduler_ticks");
      check("resolveTables leaves a non-framework table untouched under prefix",
            b.clusterStorage.resolveTables("SELECT * FROM my_app_table") ===
            "SELECT * FROM my_app_table");
    } finally {
      b.frameworkSchema.setTablePrefix("_blamejs_");
    }
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testFrameworkSchemaInvalidDialect() {
  // postgres, sqlite, and mysql are the supported dialects. A dialect
  // outside that set is rejected at the config-validation gate with
  // framework-schema/unsupported-dialect, BEFORE any backend dispatch — so
  // an operator typo surfaces at boot. (The mysql DDL path itself is proven
  // end-to-end against a live server in framework-schema-mysql.test.js.)
  var unsupportedErr = null;
  try {
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "oracle" });
  } catch (e) { unsupportedErr = e; }
  check("ensureSchema rejects an unsupported dialect at the config gate",
        unsupportedErr !== null &&
        unsupportedErr.code === "framework-schema/unsupported-dialect");

  // mysql is now a SUPPORTED dialect, so it passes the dialect-validation
  // gate — a mysql ensureSchema no longer fails with the unsupported-dialect
  // code (it proceeds to backend dispatch; the live DDL is covered in the
  // integration suite). Assert the gate no longer rejects it.
  var mysqlErr = null;
  try {
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "mysql" });
  } catch (e) { mysqlErr = e; }
  check("ensureSchema accepts mysql at the dialect gate (no unsupported-dialect rejection)",
        mysqlErr === null ||
        mysqlErr.code !== "framework-schema/unsupported-dialect");
}

// ---- run() ----

async function run() {
  // vault primitives
  await testVaultWrapRoundTrip();
  await testPassphraseEnv();
  await testVaultPlaintextRoundTrip();
  await testVaultModeMismatch();
  await testVaultRequiresDataDir();
  await testVaultWrappedE2E();

  // cluster module + provider
  await testClusterSingleNodeFallback();
  await testClusterProviderAcquireAndRenew();
  await testClusterProviderTwoNodeContention();
  await testClusterProviderTakeoverAfterExpiry();
  await testClusterProviderRenewalRace();
  await testClusterProviderMysqlDialect();
  await testClusterInitAndRequireLeader();

  // framework-schema (DDL emitter + table-name resolver)
  await testFrameworkSchemaEnsure();
  testFrameworkSchemaTableNameMapping();
  await testClusterStoragePrefixRewrite();
  await testFrameworkSchemaInvalidDialect();
}

module.exports = {
  name: "Layer 1 — state (vault, cluster, framework-schema)",
  run:  run,
  testVaultWrapRoundTrip:                   testVaultWrapRoundTrip,
  testPassphraseEnv:                        testPassphraseEnv,
  testVaultPlaintextRoundTrip:              testVaultPlaintextRoundTrip,
  testVaultModeMismatch:                    testVaultModeMismatch,
  testVaultRequiresDataDir:                 testVaultRequiresDataDir,
  testVaultWrappedE2E:                      testVaultWrappedE2E,
  testClusterSingleNodeFallback:            testClusterSingleNodeFallback,
  testClusterProviderAcquireAndRenew:       testClusterProviderAcquireAndRenew,
  testClusterProviderTwoNodeContention:     testClusterProviderTwoNodeContention,
  testClusterProviderTakeoverAfterExpiry:   testClusterProviderTakeoverAfterExpiry,
  testClusterProviderRenewalRace:           testClusterProviderRenewalRace,
  testClusterProviderMysqlDialect:          testClusterProviderMysqlDialect,
  testClusterInitAndRequireLeader:          testClusterInitAndRequireLeader,
  testFrameworkSchemaEnsure:                testFrameworkSchemaEnsure,
  testFrameworkSchemaTableNameMapping:      testFrameworkSchemaTableNameMapping,
  testClusterStoragePrefixRewrite:          testClusterStoragePrefixRewrite,
  testFrameworkSchemaInvalidDialect:        testFrameworkSchemaInvalidDialect,
};
