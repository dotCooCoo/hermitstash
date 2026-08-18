/**
 * Give this test process a private scratch directory and point the database at it,
 * before any HermitStash module is loaded.
 *
 * `require("../helpers/isolate-db");` on the FIRST line of a test file, above
 * every other require.
 *
 * Two separate reasons, both of which cost something real.
 *
 * The database. lib/db.js resolves its paths once, at load. With
 * HERMITSTASH_DB_PATH unset it takes the real ones — and its encrypted path is
 * non-null only in that case, so the exit hook re-encrypts
 * data/hermitstash.db.enc on the way out. A test file never has to mention the
 * database for this to happen: lib/config reads settings from it, so requiring
 * lib/client-ip, lib/audit-siem, middleware/security-headers or
 * middleware/sync-guards is enough. Seven files reached it that way. Each one
 * decrypted the operator's live database, ran its assertions against whatever
 * real settings it found there, and wrote the file back out at exit.
 *
 * The directory. lib/db.js also sweeps its working directory at load, deleting
 * every hermitstash-*.db in it except its own (cleanupStaleDbFiles) — that is
 * how a crashed process's plaintext database gets reclaimed. The directory is
 * HERMITSTASH_TMPDIR, or /dev/shm, or the data directory. So a process that
 * leaves it at the default sweeps the repository's data/, where a running
 * development server keeps its own working database; and every process that
 * points it at the shared OS temp root sweeps every OTHER test's database out
 * from under it. A private directory per process is the only arrangement where
 * the sweep can only ever reach this process's own files.
 *
 * Requiring this module is also what tests/lint/codebase-patterns.test.js looks
 * for — a file that reaches lib/db and neither requires this nor redirects the
 * path itself fails the gate.
 */
var os = require("os");
var path = require("path");
var fs = require("fs");

// Private to this process. mkdtemp, not a name built from a random token: the
// directory has to be known-unique before anything is written into it.
var scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermitstash-test-"));

// Never override a path the caller has already chosen — test-server sets its
// own, and a file may load this after it.
var weChosePath = !process.env.HERMITSTASH_DB_PATH;
if (weChosePath) process.env.HERMITSTASH_DB_PATH = path.join(scratchDir, "test.db");

// Confines the stale-database sweep to scratchDir. Also where lib/session puts
// its store: HERMITSTASH_SESSION_DB is a filename rather than a path, and it is
// joined onto this directory wherever /dev/shm is absent.
//
// Unconditionally, unlike the database path above. An inherited value — from a
// developer's shell, or from the CI environment — is exactly the shared
// directory this exists to get out of, and every caller of this helper is taken
// to be isolated on the strength of having required it. So it always wins.
process.env.HERMITSTASH_TMPDIR = scratchDir;

var dbPath = process.env.HERMITSTASH_DB_PATH;

// Remove the directory this module made. A database path the caller already had
// is theirs — it may be another helper's scratch, or one from a developer's
// shell — so it is left alone even though it sits outside scratchDir.
//
// The close comes first because Windows refuses to remove a file another handle
// still has open, and nothing else closes it: lib/db's own exit handler
// re-encrypts and unlinks, but its encrypted path is null here (the database is
// redirected) so it returns before touching the handle. Without this the removal
// failed silently on every run and left one directory behind each time — 1,049
// had collected, which is the accumulation this helper exists to stop. Reached
// through require.cache rather than by requiring lib/db, which would load it in
// processes that never used it.
function loadedExports(relative) {
  var entry = require.cache[path.join(__dirname, "..", "..", relative)];
  return entry && entry.exports ? entry.exports : null;
}

function closeDatabase() {
  var db = loadedExports(path.join("lib", "db.js"));
  if (db) {
    try {
      if (typeof db.suppressExitEncrypt === "function") db.suppressExitEncrypt();
      var handle = typeof db.getDb === "function" ? db.getDb() : null;
      if (handle && typeof handle.close === "function") handle.close();
    } catch (_e) { /* best effort — a failure here only restores the old littering */ }
  }
  // The session store is a SECOND database, opened by lib/session at load, and
  // it holds this directory just as firmly as the first one.
  var session = loadedExports(path.join("lib", "session.js"));
  if (session && typeof session.closeStore === "function") {
    try { session.closeStore(); } catch (_e) { /* best effort */ }
  }
}

function cleanup() {
  closeDatabase();
  try { fs.rmSync(scratchDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); }
  catch (_e) { /* still held — the OS sweeps its temp directory */ }
  if (!weChosePath) return;
  [dbPath, dbPath + "-shm", dbPath + "-wal", dbPath + ".enc"].forEach(function (p) {
    try { fs.unlinkSync(p); } catch (_e) { /* already gone with the directory */ }
  });
}
process.on("exit", cleanup);

module.exports = { dbPath: dbPath, dir: scratchDir, cleanup: cleanup, isOurs: weChosePath };
