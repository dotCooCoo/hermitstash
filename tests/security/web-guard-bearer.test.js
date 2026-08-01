/**
 * D-2 — web-guard soft-mTLS bearer bypass.
 *
 * Under config.enforceMtls (soft mode) middleware/web-guard.js let ANY request
 * carrying an "Authorization: Bearer ..." header past the gate without a client
 * cert — the old isBearerAuth() checked only the header prefix, never the token.
 * A bogus bearer therefore bypassed the soft mTLS gate. web-guard now validates
 * the token the same way middleware/api-auth.js does (format check + api-key
 * hash lookup + active-user check), so only a real API key satisfies the gate.
 *
 * web-guard is invoked directly here (it is a plain (req,res,next) middleware);
 * a mock socket records whether the connection was dropped.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");

var b, config, webGuard, db;
var validToken;

before(async function () {
  await testServer.start();
  // Resolve AFTER start() so these reference the same post-cache-clear module
  // instances the running server (and web-guard's own requires) use.
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  config = require(path.join(testServer.projectRoot, "lib", "config"));
  webGuard = require(path.join(testServer.projectRoot, "middleware", "web-guard"));
  db = require(path.join(testServer.projectRoot, "lib", "db"));

  // Seed an active user + a live API key whose keyHash is sha3(validToken).
  db.users.insert({
    email: "webguard-bearer@test.com",
    displayName: "WebGuard Bearer",
    role: "user",
    status: "active",
    authType: "local",
    createdAt: new Date().toISOString(),
  });
  var user = db.users.findOne({ email: "webguard-bearer@test.com" });
  validToken = "hs_" + b.crypto.generateToken(24);
  db.apiKeys.insert({
    keyHash: b.crypto.sha3Hash(validToken),
    userId: user._id,
    name: "webguard-test-key",
    prefix: "hs_test",
    permissions: "[]",
    createdAt: new Date().toISOString(),
  });
});

after(function () { return testServer.stop(); });

// Drive web-guard once with a given Authorization header and a non-authorized
// socket (no client cert). Returns whether the connection was dropped and
// whether next() was called (i.e. the request was let through the gate).
function runGuard(authHeader) {
  var state = { destroyed: false, nextCalled: false };
  var req = {
    headers: authHeader ? { authorization: authHeader } : {},
    pathname: "/dashboard",
    socket: { authorized: false, destroy: function () { state.destroyed = true; } },
  };
  webGuard(req, {}, function () { state.nextCalled = true; });
  return state;
}

describe("web-guard soft-mTLS bearer validation (D-2)", function () {
  it("a bogus bearer does NOT pass the soft mTLS gate", function () {
    config.enforceMtls = true;
    try {
      // Malformed token (too short) — rejected before any DB hit.
      var malformed = runGuard("Bearer x");
      assert.strictEqual(malformed.nextCalled, false, "malformed bearer must not pass the gate");
      assert.strictEqual(malformed.destroyed, true, "connection must be dropped");

      // Well-formed but unknown token — no matching API key.
      var unknown = runGuard("Bearer hs_" + b.crypto.generateToken(24));
      assert.strictEqual(unknown.nextCalled, false, "unknown API key must not pass the gate");
      assert.strictEqual(unknown.destroyed, true, "connection must be dropped");
    } finally {
      config.enforceMtls = false;
    }
  });

  it("a valid API-key bearer passes the soft mTLS gate", function () {
    config.enforceMtls = true;
    try {
      var valid = runGuard("Bearer " + validToken);
      assert.strictEqual(valid.nextCalled, true, "a valid API key must pass the gate");
      assert.strictEqual(valid.destroyed, false, "a valid API key must not be dropped");
    } finally {
      config.enforceMtls = false;
    }
  });

  it("is a no-op when enforceMtls is off (default)", function () {
    config.enforceMtls = false;
    var r = runGuard("Bearer x");
    assert.strictEqual(r.nextCalled, true, "gate disabled → everything passes");
    assert.strictEqual(r.destroyed, false);
  });
});
