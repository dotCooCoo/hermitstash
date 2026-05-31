/**
 * Database migration runner.
 *
 * Delegates to b.migrations, which reads NNN-name.js files from
 * app/data/db/migrations/, runs each pending migration's `up(db)` in order
 * under a coordination lock (so two processes booting at once can't race),
 * and records applied migrations in its own `_blamejs_migrations` table.
 *
 * Each migration file exports `{ up: function(db) {} }` (a `down` is only
 * needed for rollback, which HermitStash does not use).
 *
 * Unlike the prior hand-rolled runner, a migration whose `up()` throws now
 * fails the boot (b.migrations throws MigrationError) rather than being
 * logged and skipped — a half-applied schema should stop, not continue.
 *
 * Cutover note: on a database upgraded from the prior runner the old
 * `_migrations` table is left untouched (and unused). b.migrations starts
 * from an empty `_blamejs_migrations` and re-runs every migration once; this
 * is safe because each shipped migration is idempotent (its `ALTER TABLE ADD
 * COLUMN`s are wrapped in try/catch), so a re-run on an already-migrated
 * database is a no-op.
 *
 * Note: db is a node:sqlite DatabaseSync instance; b.migrations uses it
 * synchronously (up() returns a value, not a promise), so the synchronous
 * boot call site in lib/db.js is unchanged.
 *
 * staleAfterMs: b.migrations writes a coordination-lock row before running and
 * removes it in a finally. If the process is hard-killed mid-run (OOM, a
 * `docker stop` grace-period timeout escalating to SIGKILL, power loss) the
 * lock row survives on disk; with the default staleAfterMs (0 = never replace)
 * every later boot would refuse with `migrations/lock-held` and the server
 * could never start again without hand-editing the encrypted database. A
 * one-minute staleness window lets a later boot reclaim such a crash-leftover
 * lock — comfortably longer than any real migration here yet bounded for
 * recovery. HermitStash is single-instance, so a genuinely concurrent run
 * (the case the lock guards) does not occur.
 */
var b = require("../../../lib/vendor/blamejs");
var C = require("../../../lib/constants");
var nodePath = require("node:path");

var migrationsDir = nodePath.join(__dirname, "migrations");

function run(db) {
  return b.migrations.create({ dir: migrationsDir, db: db, staleAfterMs: C.TIME.minutes(1) }).up();
}

module.exports = { run: run };
