require("../helpers/isolate-db");
var { describe, it, before, beforeEach, after, mock } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var nodePath = require("path");
var { DatabaseSync } = require("node:sqlite");

// lib/session.js opens its store when it is required. Each test file uses its
// own store name.
process.env.HERMITSTASH_SESSION_DB = "test-session-purge-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";

var b = require("../../lib/vendor/blamejs");
var TIME = b.constants.TIME;
var BYTES = b.constants.BYTES;

// lib/session.js reads this when it is required.
process.env.SESSION_ABSOLUTE_TIMEOUT_MS = String(TIME.hours(12));

var session = require("../../lib/session");
var config = require("../../lib/config");
var vault = require("../../lib/vault");
var sessionPurgeJob = require("../../app/jobs/session-purge.job");

var TABLE = b.frameworkSchema.tableName("_blamejs_sessions");
var STORE = nodePath.join(process.env.HERMITSTASH_TMPDIR, process.env.HERMITSTASH_SESSION_DB);
var FLOORS_OFF = { idleTimeoutMs: 0, absoluteTimeoutMs: 0 };
var writer;

function storedRows() {
  var q = b.sql.select(TABLE, { dialect: "sqlite" }).count("*", "c").toSql();
  return writer.prepare(q.sql).get().c;
}

// createAt creates a session with the clock set offsetMs from now.
async function createAt(offsetMs, userId) {
  var realNow = Date.now();
  var clock = mock.method(Date, "now", function () { return realNow + offsetMs; });
  try {
    return await b.session.create({ userId: userId, ttlMs: TIME.days(7), data: {} });
  } finally {
    clock.mock.restore();
  }
}

// insertIdleRows writes count unsealed rows that have been idle for two hours,
// each with a payload of payloadBytes random bytes.
function insertIdleRows(count, payloadBytes) {
  var idleSince = Date.now() - TIME.hours(2);
  var q = b.sql.insert(TABLE, { dialect: "sqlite" })
    .columns(["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"])
    .values({ sidHash: "", userId: "", userIdHash: "", data: "", createdAt: 0, expiresAt: 0, lastActivity: 0 })
    .toSql();
  var stmt = writer.prepare(q.sql);
  for (var i = 0; i < count; i++) {
    stmt.run(b.crypto.generateToken(32), "anon:raw", "raw",
      b.crypto.generateBytes(payloadBytes).toString("base64"),
      idleSince, Date.now() + TIME.days(1), idleSince);
  }
}

before(async function () {
  await vault.init();
  writer = new DatabaseSync(STORE);
  writer.exec("PRAGMA busy_timeout=5000");
});

beforeEach(function () {
  var q = b.sql.delete(TABLE, { dialect: "sqlite" }).where("createdAt", ">=", 0).toSql();
  var stmt = writer.prepare(q.sql);
  stmt.run.apply(stmt, q.params);
});

after(function () { writer.close(); });

describe("purgeStaleSessions", function () {
  it("deletes sessions past their expiry, idle timeout or absolute timeout and keeps a live one", async function () {
    await createAt(-TIME.days(8), "anon:expired");
    var idle = await createAt(-TIME.hours(2), "anon:idle");
    var aged = await createAt(-TIME.hours(13), "anon:aged");
    await b.session.touch(aged.token, { extendBy: TIME.days(7), idleTimeoutMs: 0, absoluteTimeoutMs: 0 });
    var live = await createAt(0, "anon:live");
    assert.strictEqual(storedRows(), 4);

    var removed = await session.purgeStaleSessions();

    assert.strictEqual(removed, 3);
    assert.strictEqual(storedRows(), 1);
    assert.ok(await b.session.verify(live.token, FLOORS_OFF), "the live session must survive");
    assert.strictEqual(await b.session.verify(idle.token, FLOORS_OFF), null);
    assert.strictEqual(await b.session.verify(aged.token, FLOORS_OFF), null);
  });

  it("measures idleness against the configured idle timeout", async function () {
    var saved = config.sessionIdleTimeout;
    config.sessionIdleTimeout = TIME.hours(3);
    try {
      var idle = await createAt(-TIME.hours(2), "anon:within");
      assert.strictEqual(await session.purgeStaleSessions(), 0);
      assert.ok(await b.session.verify(idle.token, FLOORS_OFF));
    } finally {
      config.sessionIdleTimeout = saved;
    }
  });

  it("deletes more stale rows than one batch holds", async function () {
    insertIdleRows(600, 16);
    assert.strictEqual(await session.purgeStaleSessions(), 600);
    assert.strictEqual(storedRows(), 0);
  });

  it("returns 0 when nothing is stale", async function () {
    await createAt(0, "anon:fresh");
    assert.strictEqual(await session.purgeStaleSessions(), 0);
  });

  it("passes the configured timeouts and batch size to b.session.purgeStale", async function () {
    var saved = config.sessionIdleTimeout;
    config.sessionIdleTimeout = TIME.hours(3);
    var purge = mock.method(b.session, "purgeStale");
    try {
      await createAt(-TIME.hours(4), "anon:spied");
      await createAt(-TIME.hours(2), "anon:kept");
      assert.strictEqual(await session.purgeStaleSessions(), 1);
      assert.strictEqual(purge.mock.callCount(), 1);
      assert.deepStrictEqual(purge.mock.calls[0].arguments, [{
        idleTimeoutMs:     TIME.hours(3),
        absoluteTimeoutMs: TIME.hours(12),
        batchSize:         256,
      }]);
    } finally {
      purge.mock.restore();
      config.sessionIdleTimeout = saved;
    }
  });
});

describe("compactSessionStore", function () {
  it("leaves a small store alone", async function () {
    await createAt(0, "anon:small");
    assert.strictEqual(await session.compactSessionStore(), false);
  });

  it("returns the space a purge freed and keeps live sessions readable", async function () {
    var live = await createAt(0, "anon:kept");
    insertIdleRows(2500, BYTES.kib(6));
    writer.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    assert.ok(fs.statSync(STORE).size >= BYTES.mib(16), "the fixture must exceed the compaction floor");

    await session.purgeStaleSessions();
    assert.strictEqual(await session.compactSessionStore(), true);

    assert.ok(fs.statSync(STORE).size < BYTES.mib(1), "size after compaction: " + fs.statSync(STORE).size);
    assert.ok(await b.session.verify(live.token, FLOORS_OFF), "a live session must survive compaction");
  });
});

describe("clearAllSessions", function () {
  it("deletes every stored session", async function () {
    await createAt(0, "anon:first");
    await createAt(-TIME.hours(2), "anon:second");
    await session.clearAllSessions();
    assert.strictEqual(storedRows(), 0);
  });
});

describe("the session purge job", function () {
  it("reports how many sessions it deleted", async function () {
    await createAt(-TIME.hours(2), "anon:job");
    var result = await sessionPurgeJob.run();
    assert.strictEqual(result.removed, 1);
  });
});

describe("server-main.js schedules the session purge", function () {
  var source = fs.readFileSync(nodePath.join(__dirname, "..", "..", "server-main.js"), "utf8");

  it("registers session_purge to run hourly before the scheduler starts", function () {
    var registered = source.search(/scheduler\.register\("session_purge", C\.TIME\.hours\(1\), function \(\) \{\s*return sessionPurgeJob\.run\(\)/);
    var started = source.search(/^scheduler\.start\(\);/m);
    assert.notStrictEqual(registered, -1, "server-main.js does not register session_purge hourly");
    assert.ok(started > registered, "session_purge must be registered before scheduler.start()");
  });

  it("runs the purge once at boot", function () {
    assert.match(source, /^sessionPurgeJob\.run\(\)\.catch\(/m);
  });
});
