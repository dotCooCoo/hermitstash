/**
 * Lightweight DB isolation for unit tests that need a database but no HTTP server.
 * Sets HERMITSTASH_DB_PATH, clears module cache, and provides cleanup.
 */
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

const projectRoot = path.join(__dirname, "..", "..");
const testId = b.crypto.generateToken(4);

// Scratch goes to a directory private to this process, never to data/ and never
// to the shared OS temp root.
//
// data/ holds the live database and the vault keys, and on a development machine
// it is inside a synced folder — so every abandoned scratch database was
// replicated to cloud storage alongside them. They abandon easily: a test file
// that forgets cleanup() leaves one, and on Windows the exit hook cannot remove a
// file SQLite still holds open. 670 had collected.
//
// The shared temp root is no good either: lib/db.js sweeps its working directory
// at load, deleting every other hermitstash-*.db in it, so pointing several
// concurrent test processes at one directory has them deleting each other's
// databases. isolate-db makes the private directory and confines the sweep to it.
const scratch = require("./isolate-db");
const testDbPath = scratch.dbPath;

process.env.HERMITSTASH_SESSION_DB = "test-session-" + testId + ".db";

function clearCache() {
  var keys = Object.keys(require.cache);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].includes("hermitstash") && !keys[i].includes("node_modules") && !keys[i].includes("test")) {
      delete require.cache[keys[i]];
    }
  }
}

clearCache();

function cleanup() {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
}

// cleanup() stays exported for a test that wants to drop the file mid-run.
// Removal at exit is isolate-db's — it owns the directory all of this sits in,
// and takes the whole thing rather than the three files named here. Relying on
// every caller to remember did not work: of the files using this helper, three
// never called it, and data/ had accumulated 670 abandoned test databases beside
// the real vault keys and the live database.

module.exports = { projectRoot, testDbPath, clearCache, cleanup };
