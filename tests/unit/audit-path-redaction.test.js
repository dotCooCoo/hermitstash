// F-4 regression: single-use tokens embedded in the request PATH
// (/auth/reset-password/:token, /auth/verify/:token, /auth/invite/:token) must be
// templated to the route pattern before the path is stored in an audit row or
// forwarded to a SIEM — the concrete token value must never land in either.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var scratch = require("../helpers/isolate-db");
var testDbPath = path.join(scratch.dir, "test-audit-path-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db = require("../../lib/db");
var audit = require("../../lib/audit");

before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

// Log an event carrying the given request path and return the stored (unsealed) path.
function storedPathFor(pathname) {
  audit.log(audit.ACTIONS.PASSWORD_RESET_REQUESTED, {
    req: { pathname: pathname, method: "POST", headers: {}, socket: { remoteAddress: "203.0.113.9" } },
    performedBy: "system",
  });
  var rows = db.auditLog.raw().find({});
  return audit.unsealEntry(rows[rows.length - 1]).path;
}

describe("audit path token redaction (F-4)", function () {
  it("templates a reset-password token to :token", function () {
    var secret = "RESETTOKEN_" + b.crypto.generateToken(16);
    var stored = storedPathFor("/auth/reset-password/" + secret);
    assert.strictEqual(stored, "/auth/reset-password/:token");
    assert.ok(stored.indexOf(secret) === -1, "the concrete reset token must not survive in the stored path");
  });

  it("templates an email-verify token to :token", function () {
    var secret = "VERIFYTOKEN_" + b.crypto.generateToken(16);
    var stored = storedPathFor("/auth/verify/" + secret);
    assert.strictEqual(stored, "/auth/verify/:token");
    assert.ok(stored.indexOf(secret) === -1, "the concrete verify token must not survive in the stored path");
  });

  it("templates an invite token to :token", function () {
    var secret = "INVITETOKEN_" + b.crypto.generateToken(16);
    var stored = storedPathFor("/auth/invite/" + secret);
    assert.strictEqual(stored, "/auth/invite/:token");
    assert.ok(stored.indexOf(secret) === -1, "the concrete invite token must not survive in the stored path");
  });

  it("leaves ordinary paths untouched", function () {
    assert.strictEqual(storedPathFor("/admin/dashboard"), "/admin/dashboard");
    assert.strictEqual(storedPathFor("/b/abc123/download"), "/b/abc123/download");
  });

  it("leaves the token-less request form of a secret route untouched", function () {
    // GET /auth/reset-password (the request form, no token segment) is not templated.
    assert.strictEqual(storedPathFor("/auth/reset-password"), "/auth/reset-password");
  });
});
