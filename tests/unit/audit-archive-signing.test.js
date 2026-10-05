require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, after, mock } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var nodeCrypto = require("node:crypto");

// Wrapped audit signing, with the passphrase read from a file.
var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-audit-sign-"));
var passphraseFile = path.join(dataDir, "audit-sign-passphrase");
fs.writeFileSync(passphraseFile, "audit-signing-passphrase-1", { mode: 0o600 });
process.env.HERMITSTASH_DATA_DIR = dataDir;
process.env.AUDIT_SIGNING_MODE = "wrapped";
process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE = passphraseFile;

var b = require("../../lib/vendor/blamejs");
var archive = require("../../lib/audit-archive");

after(function () {
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
});

describe("lib/audit-archive signing key load", function () {
  it("loads the key on the next call after a load failed", async function () {
    // The first Argon2id derivation is the one that seals the new key. It fails.
    var realArgon2 = nodeCrypto.argon2;
    var calls = 0;
    var argon2 = mock.method(nodeCrypto, "argon2", function (algorithm, params, callback) {
      calls += 1;
      if (calls === 1) {
        process.nextTick(callback, new Error("injected Argon2id failure"));
        return;
      }
      realArgon2.call(nodeCrypto, algorithm, params, callback);
    });
    try {
      await assert.rejects(archive.ensureSigning(), /injected Argon2id failure/);
      await archive.ensureSigning();
    } finally {
      argon2.mock.restore();
    }

    assert.ok(calls >= 2, "the second call ran a new derivation");
    assert.strictEqual(b.auditSign.getMode(), "wrapped");
    assert.ok(fs.existsSync(path.join(dataDir, "audit-sign.key.sealed")), "the sealed key was written");
  });
});
