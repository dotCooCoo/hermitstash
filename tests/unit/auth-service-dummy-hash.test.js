var scratch = require("../helpers/isolate-db"); // must precede every HermitStash require
process.env.HERMITSTASH_DATA_DIR = scratch.dir;
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var argon2Probe = require("../helpers/argon2-probe");

argon2Probe.install();

var b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var vault = require("../../lib/vault");
var passwordGate = require("../../lib/password-gate");
var authService = require("../../app/domain/auth/auth.service");

before(async function () { await vault.init(); });
after(function () { argon2Probe.uninstall(); });

describe("auth.service with a full password-check queue", function () {
  it("drops a refused dummy hash, so a later unknown-account login gets the normal 401", async function () {
    var fillerHash = await b.auth.password.hash("filler-password-1", { memoryCost: C.BYTES.kib(1), timeCost: 1, parallelism: 1 });
    argon2Probe.hold();
    var fillers = [];
    for (var i = 0; i < C.PASSWORD_HASH.MAX_CONCURRENT + C.PASSWORD_HASH.MAX_QUEUED; i++) {
      fillers.push(passwordGate.verify(fillerHash, "filler-password-1"));
    }
    try {
      await assert.rejects(authService.authenticateLocal("nobody@example.test", "any-password-1"),
        function (e) { return e.statusCode === 503 && e.code === "SERVICE_UNAVAILABLE"; });
    } finally {
      argon2Probe.release();
      await Promise.all(fillers);
    }
    await assert.rejects(authService.authenticateLocal("nobody@example.test", "any-password-1"),
      function (e) { return e.statusCode === 401 && e.code === "AUTH_REQUIRED"; });
  });
});
