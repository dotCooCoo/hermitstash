/**
 * Lightweight DB isolation for unit tests that need a database but no HTTP server.
 * Sets HERMITSTASH_DB_PATH, clears module cache, and provides cleanup.
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

const projectRoot = path.join(__dirname, "..", "..");
const testId = b.crypto.generateToken(4);
const testDbPath = path.join(projectRoot, "data", "test-env-" + testId + ".db");

process.env.HERMITSTASH_DB_PATH = testDbPath;
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

module.exports = { projectRoot, testDbPath, clearCache, cleanup };
