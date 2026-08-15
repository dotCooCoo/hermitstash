"use strict";

/**
 * A damaged vault key must be told apart from an old one — and must not echo
 * key material while doing it.
 *
 * The vault key decrypts everything this server stores, so what boot says about
 * a bad one is the instruction an operator follows at the worst moment.
 * Unparseable means restore, because the bytes are gone. Readable but missing
 * the hybrid fields means run the migration tool. Answering the first with the
 * second sends someone to a converter that cannot repair the file.
 *
 * lib/vault.js owns this. app/bootstrap/startup-checks.js used to carry a second
 * copy that could never reach the operator — it queued its error for a summary
 * printed at the end of the run, while the vault exits the process partway
 * through — and that copy got the distinction wrong, because it parsed with a
 * helper that returns {} for anything malformed. These tests pin the live
 * behaviour and the fact that the duplicate is gone.
 *
 * Boot runs in a child process because the check exits, which cannot be caught
 * in-process — the same reason db-key-fail-closed.test.js does it that way.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var { spawnSync } = require("node:child_process");

var projectRoot = path.join(__dirname, "..", "..");

// Load the vault against a data directory we control. Requiring the module is
// enough: loadKeys runs on the way to any key operation, and a bad key file
// ends the process there.
function bootVault(dataDir) {
  var script = [
    "var vault = require(" + JSON.stringify(path.join(projectRoot, "lib", "vault.js")) + ");",
    "vault.seal('probe');",
    "process.stdout.write('BOOTED');",
  ].join("\n");

  var res = spawnSync(process.execPath, ["-e", script], {
    cwd: projectRoot,
    encoding: "utf8",
    env: Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dataDir,
      HERMITSTASH_ALLOW_DISK_DB: "true",
    }),
  });
  return {
    status: res.status,
    said: String(res.stderr || "") + String(res.stdout || ""),
    booted: String(res.stdout || "").indexOf("BOOTED") !== -1,
  };
}

describe("a damaged vault key is diagnosed distinctly from an old one", function () {
  var tmp;

  before(function () { tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hs-vaultkey-")); });
  after(function () {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  });

  function withVaultKey(contents) {
    var dir = fs.mkdtempSync(path.join(tmp, "case-"));
    fs.writeFileSync(path.join(dir, "vault.key"), contents);
    return bootVault(dir);
  }

  it("calls a truncated key corrupt and sends the operator to a restore", function () {
    var out = withVaultKey('{"ecPublicKey":"abc');
    assert.equal(out.booted, false, "boot must not continue on an unreadable vault key");
    assert.match(out.said, /corrupted or not valid JSON/i, out.said.slice(0, 300));
    assert.match(out.said, /Restore data\/vault\.key from backup/i,
      "the instruction for a corrupt key is a restore");
    assert.ok(!/migration tool/i.test(out.said),
      "and must not point at the migration tool, which cannot repair it: " + out.said.slice(0, 300));
  });

  it("says the same for an empty key file", function () {
    var out = withVaultKey("");
    assert.equal(out.booted, false);
    assert.match(out.said, /corrupted or not valid JSON/i);
  });

  it("does not echo the file's bytes while reporting the failure", function () {
    // The reason the message is deliberately vague. A SyntaxError quotes a
    // window of the input, and a vault key is mostly private key material, so
    // an interpolated parser message writes secrets to stderr.
    var secret = "SUPERSECRETPRIVATEKEYMATERIAL0123456789";
    var out = withVaultKey('{"ecPrivateKey":"' + secret + '" TRUNCATED');
    assert.equal(out.booted, false);
    assert.ok(out.said.indexOf(secret) === -1,
      "key material must never reach the log: " + out.said.slice(0, 400));
    assert.ok(!/SyntaxError|position \d+|Unexpected token/i.test(out.said),
      "and neither must the parser's own message: " + out.said.slice(0, 400));
  });

  it("still tells a genuinely old-format key to migrate", function () {
    // Valid JSON, no hybrid fields — the one case the migration tool is for.
    var out = withVaultKey(JSON.stringify({ publicKey: "x", privateKey: "y" }));
    assert.equal(out.booted, false);
    assert.match(out.said, /missing required ML-KEM-1024 \+ P-384 fields/i, out.said.slice(0, 300));
    assert.match(out.said, /migration tool/i, "this is the case that migrates");
    assert.ok(!/corrupted or not valid JSON/i.test(out.said),
      "and must not be called corrupt: " + out.said.slice(0, 300));
  });

  it("the duplicate check is gone from the boot module", function () {
    // It could never print, and it answered the corrupt case with the migration
    // instruction. Pinned so it does not come back as a well-meaning addition.
    var src = fs.readFileSync(path.join(projectRoot, "app", "bootstrap", "startup-checks.js"), "utf8");
    assert.ok(!/is not in the ML-KEM-1024 \+ P-384 hybrid format/.test(src),
      "startup-checks must not re-implement the vault key shape check");
    assert.ok(!/Vault key file is corrupted/.test(src),
      "nor its corruption message");
  });
});
