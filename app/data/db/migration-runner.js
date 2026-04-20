/**
 * Database migration runner.
 *
 * Maintains a _migrations table that tracks which migration files have been
 * applied.  On startup, reads .js files from app/data/db/migrations/ sorted
 * alphabetically, skips already-applied ones, and executes the rest in order.
 *
 * Each migration file exports { up: function(db) {} }.
 *
 * Note: db.exec() below is SQLite DatabaseSync.exec(), NOT child_process.exec().
 */

var fs = require("fs");
var path = require("path");

var migrationsDir = path.join(__dirname, "migrations");

/**
 * Ensure the _migrations tracking table exists.
 */
function ensureTable(db) {
  // SQLite DatabaseSync.exec — not child_process
  db.exec(
    "CREATE TABLE IF NOT EXISTS _migrations (" +
      "_id TEXT PRIMARY KEY, " +
      "name TEXT NOT NULL, " +
      "appliedAt TEXT NOT NULL" +
    ")"
  );
}

/**
 * Return a Set of migration filenames already applied.
 */
function getApplied(db) {
  var rows = db.prepare("SELECT name FROM _migrations").all();
  var set = new Set();
  for (var i = 0; i < rows.length; i++) {
    set.add(rows[i].name);
  }
  return set;
}

/**
 * Read migration files from the migrations directory, sorted alphabetically.
 */
function getMigrationFiles() {
  if (!fs.existsSync(migrationsDir)) return [];
  return fs
    .readdirSync(migrationsDir)
    .filter(function (f) { return f.endsWith(".js") && f !== ".gitkeep"; })
    .sort();
}

/**
 * Run all pending migrations against the given database instance.
 */
function run(db) {
  ensureTable(db);

  var applied = getApplied(db);
  var files = getMigrationFiles();
  var pending = files.filter(function (f) { return !applied.has(f); });

  if (pending.length === 0) return;

  var { generateToken } = require("../../../lib/crypto");
  var insertStmt = db.prepare(
    "INSERT INTO _migrations (_id, name, appliedAt) VALUES (?, ?, ?)"
  );

  for (var i = 0; i < pending.length; i++) {
    var filename = pending[i];
    var filePath = path.join(migrationsDir, filename);
    try {
      var migration = require(filePath);
      if (typeof migration.up !== "function") {
        console.log("  [migration] Skipping " + filename + " (no up function)");
        continue;
      }
      migration.up(db);
      var id = generateToken(32);
      insertStmt.run(id, filename, new Date().toISOString());
      console.log("  [migration] Applied: " + filename);
    } catch (e) {
      console.error("  [migration] Failed: " + filename + " — " + e.message);
    }
  }
}

module.exports = { run: run };
