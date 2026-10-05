require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, after, mock } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var nodeCrypto = require("node:crypto");

// Wrapped audit signing, with the passphrase in the environment.
var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-audit-sign-env-"));
process.env.HERMITSTASH_DATA_DIR = dataDir;
process.env.AUDIT_SIGNING_MODE = "wrapped";
process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "audit-signing-passphrase-1";
delete process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE;
delete process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE;

var archive = require("../../lib/audit-archive");

after(function () {
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
});

describe("lib/audit-archive signing key load, passphrase in the environment", function () {
  it("returns the first error instead of prompting on a terminal once the variable is gone", async function () {
    var calls = 0;
    var argon2 = mock.method(nodeCrypto, "argon2", function (algorithm, params, callback) {
      calls += 1;
      process.nextTick(callback, new Error("injected Argon2id failure"));
    });
    var hadTty = Object.prototype.hasOwnProperty.call(process.stdin, "isTTY");
    var savedTty = process.stdin.isTTY;
    try {
      await assert.rejects(archive.ensureSigning(), /injected Argon2id failure/);
      assert.strictEqual(process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE, undefined, "the framework removed the variable");
      process.stdin.isTTY = true;
      await assert.rejects(archive.ensureSigning(), /injected Argon2id failure/);
      assert.strictEqual(calls, 1, "the second call did not load the key again");
    } finally {
      if (hadTty) process.stdin.isTTY = savedTty;
      else delete process.stdin.isTTY;
      argon2.mock.restore();
    }
  });
});
