const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { DatabaseSync } = require("node:sqlite");
const b = require("../../lib/vendor/blamejs");

const migrationRunner = require("../../app/data/db/migration-runner");

function cols(db) { return db.prepare("PRAGMA table_info(users)").all().map((c) => c.name); }
function applied(db) { return db.prepare("SELECT name FROM _blamejs_migrations").all().map((r) => r.name); }

function freshDb() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
  return db;
}

// A database upgraded from the prior hand-rolled runner: lockout columns
// already added by 001, and an old _migrations table recording it.
function upgradedDb() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, failedLoginAttempts INTEGER DEFAULT 0, lockedUntil TEXT)");
  db.exec("CREATE TABLE _migrations (_id TEXT PRIMARY KEY, name TEXT NOT NULL, appliedAt TEXT NOT NULL)");
  db.prepare("INSERT INTO _migrations (_id,name,appliedAt) VALUES (?,?,?)").run("x", "001-add-lockout-columns.js", new Date().toISOString());
  return db;
}

describe("migration-runner — b.migrations delegation", function () {
  it("runs pending migrations synchronously on a fresh database (adds lockout columns)", function () {
    const db = freshDb();
    const result = migrationRunner.run(db);
    assert.strictEqual(typeof (result && result.then), "undefined"); // sync, not a promise
    assert.ok(applied(db).includes("001-add-lockout-columns.js"));
    assert.ok(cols(db).includes("failedLoginAttempts") && cols(db).includes("lockedUntil"));
    db.close();
  });

  it("cutover: re-runs idempotently on a DB upgraded from the prior runner (no throw, schema intact)", function () {
    const db = upgradedDb();
    assert.doesNotThrow(function () { migrationRunner.run(db); });
    assert.ok(applied(db).includes("001-add-lockout-columns.js"));
    assert.strictEqual(cols(db).filter((c) => c === "failedLoginAttempts").length, 1); // not duplicated
    assert.ok(cols(db).includes("lockedUntil"));
    db.close();
  });

  it("is a no-op on a second run (already recorded in _blamejs_migrations)", function () {
    const db = freshDb();
    migrationRunner.run(db);
    const r2 = migrationRunner.run(db);
    assert.deepStrictEqual(r2.applied, []);
    db.close();
  });
});

describe("migration-runner — crash-leftover lock recovery (staleAfterMs)", function () {
  it("reclaims a stale coordination lock left by a hard-killed boot (no permanent brick)", function () {
    const db = freshDb();
    migrationRunner.run(db); // creates _blamejs_migrations_lock (row released in finally)
    db.exec("DELETE FROM _blamejs_migrations_lock");
    const twoMinAgo = Date.now() - 2 * 60 * 1000; // older than the 1-minute stale window
    db.prepare("INSERT INTO _blamejs_migrations_lock (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)").run(twoMinAgo, "crashed-boot@host");
    assert.doesNotThrow(function () { migrationRunner.run(db); });
    db.close();
  });

  it("still refuses a fresh lock from a genuinely concurrent run", function () {
    const db = freshDb();
    migrationRunner.run(db);
    db.exec("DELETE FROM _blamejs_migrations_lock");
    db.prepare("INSERT INTO _blamejs_migrations_lock (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)").run(Date.now(), "concurrent@host");
    assert.throws(function () { migrationRunner.run(db); }, /lock.held|lock is held/i);
    db.close();
  });
});

describe("migration-runner — b.migrations contract (fail-fast on a throwing migration)", function () {
  it("b.migrations throws when a migration up() throws (no longer swallowed)", function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-mig-"));
    fs.writeFileSync(path.join(dir, "001-boom.js"), "module.exports={up:function(){throw new Error('boom');}};");
    const db = new DatabaseSync(":memory:");
    try {
      assert.throws(function () { b.migrations.create({ dir: dir, db: db }).up(); }, /boom|migration|up-failed/i);
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
