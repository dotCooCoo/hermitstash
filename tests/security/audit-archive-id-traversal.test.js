"use strict";

/**
 * An archive id names a file, and it arrives from a request.
 *
 * /admin/audit/archives/verify takes it from a JSON body and /export from the
 * query string, and both hand it to lib/audit-archive, which joins it onto the
 * archive directory to pick a file to read. That is a filename built from
 * request input, so the confinement to the archive directory is the control
 * that matters, and it had no test.
 *
 * The routes are admin-only. That bounds who can try, not what a successful
 * try would read — the process runs with access to the vault key, the sealed
 * database and the TLS material, and any of it would come back through the
 * export endpoint as an audit download.
 *
 * Rejection happens before the passphrase is used: verifyArchive resolves the
 * envelope's path as its first act, so a bad id is refused whatever else is
 * supplied.
 */

var { describe, it, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

// Both of these must happen before lib/audit-archive is loaded, because it
// resolves its paths at require time.
//
// test-env points the database somewhere disposable. It does not touch the data
// directory, and the archive directory hangs off that — so without the second
// line the "accepts" cases below would look for their id among the real
// archives, and find one if it happened to exist.
var testEnv = require("../helpers/test-env");
var tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-archive-id-"));
process.env.HERMITSTASH_DATA_DIR = tmpDataDir;

var auditArchive = require("../../lib/audit-archive");

after(function () {
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

// Names that must never resolve to a file. Each is a different way of asking
// for somewhere other than the archive directory.
var HOSTILE = [
  "../../../etc/passwd",
  "../../data/vault.key",
  "audit-x/../../../etc/passwd",
  "/etc/passwd",
  "C:\\Windows\\win.ini",
  "audit-x\\..\\..\\vault.key",
  "audit-..",
  "audit-../../secret",
  "....//....//vault.key",
  "audit-\u0000.json",
  "audit-x.json.bak",
  "vault.key",
  "",
  ".",
  "..",
];

describe("audit archive ids cannot escape the archive directory", function () {
  HOSTILE.forEach(function (id) {
    it("refuses " + JSON.stringify(id), async function () {
      // The passphrase is deliberately wrong: a bad id must be refused on the
      // id alone, not by failing to decrypt whatever it managed to open.
      await assert.rejects(
        function () { return auditArchive.verifyArchive(id, "not-the-passphrase"); },
        function (err) {
          // Specifically "Invalid archive id", not merely some failure. Drop the
          // shape check and basename() alone still strips the directory parts,
          // so "../../data/vault.key" becomes "vault.key" and fails later with
          // "Archive not found" — an accepted name that simply was not there.
          // Asserting either message would pass with the guard removed.
          assert.match(err.message, /Invalid archive id\./,
            "must be refused on the id itself, got: " + err.message);
          assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY|ecPrivateKey|\[fonts\]/.test(err.message),
            "the failure must not carry another file's contents: " + err.message);
          return true;
        });
    });
  });

  it("accepts the shape a real archive id has", async function () {
    // The guard is worthless if it also refuses genuine ids. This one is
    // well-formed and simply does not exist, which is a different refusal —
    // proving the name passed validation and was looked for in the right place.
    await assert.rejects(
      function () { return auditArchive.verifyArchive("audit-2026-08-15T00-00-00-000Z-c42", "pw"); },
      function (err) {
        assert.match(err.message, /Archive not found/,
          "a well-formed id must reach the lookup, not be rejected as invalid: " + err.message);
        return true;
      });
  });

  it("accepts the same id written with its .json suffix", async function () {
    await assert.rejects(
      function () { return auditArchive.verifyArchive("audit-2026-08-15T00-00-00-000Z-c42.json", "pw"); },
      function (err) {
        assert.match(err.message, /Archive not found/, err.message);
        return true;
      });
  });
});
