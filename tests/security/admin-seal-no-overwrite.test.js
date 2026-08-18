"use strict";

/**
 * Sealing a private key must never overwrite one that is already sealed.
 *
 * Two admin actions seal a PEM in place: the mTLS CA's private key and the TLS
 * server key. Each refuses when a sealed file is already there, and neither
 * refusal had a test.
 *
 * The consequence of losing that guard is not recoverable. The sealed file is
 * the only copy readable through the vault; writing over it with a seal of a
 * different plaintext — a regenerated CA, a renewed TLS key — destroys the
 * original. For the CA that also invalidates every client certificate it ever
 * issued, so every enrolled sync client stops connecting at once.
 *
 * Asserted on the BYTES of the existing file, not on the status code. A handler
 * that sealed first and checked afterwards returns the same 409 while the
 * damage is already done, and that is the shape worth catching.
 */

var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var PATHS;

before(async function () {
  // Both key paths honour an environment override — MTLS_CA_KEY decides
  // PATHS.CA_KEY and its .sealed sibling, TLS_KEY decides the TLS plaintext —
  // so a machine with either set would have this test writing over, and then
  // deleting, the real private keys it exists to protect. Pinned inside the
  // harness's own directory before anything resolves them.
  await testServer.start({
    env: {
      MTLS_CA_KEY: path.join(testServer.testDataDir, "ca.key"),
      TLS_KEY: path.join(testServer.testDataDir, "tls", "privkey.pem"),
    },
  });
  client = new TestClient(testServer.baseUrl());
  PATHS = require(path.join(testServer.projectRoot, "lib", "constants")).PATHS;
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: "Seal Admin", email: "sealadmin@test.com", password: "password123" },
  });
});
after(function () { return testServer.stop(); });

function tlsPlainPath() {
  return process.env.TLS_KEY || path.join(PATHS.TLS_DIR, "privkey.pem");
}

// Each case owns its files; nothing here should survive into the next.
var made = [];
function put(p, contents) {
  // Fail closed rather than write. The pinning above is what keeps these paths
  // inside the harness, and this refuses to act if that ever stops being true —
  // a test that deletes a real private key is a worse outcome than a red test.
  var root = path.resolve(testServer.testDataDir);
  var target = path.resolve(p);
  if (target !== root && target.indexOf(root + path.sep) !== 0) {
    throw new Error("refusing to write a key fixture outside the test data directory: " + target);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  made.push(target);
  return target;
}
beforeEach(function () {
  made.splice(0).forEach(function (p) {
    try { fs.unlinkSync(p); } catch (_e) { /* already gone */ }
  });
});
after(function () {
  made.forEach(function (p) { try { fs.unlinkSync(p); } catch (_e) { /* already gone */ } });
});

var TARGETS = [
  {
    name: "the mTLS CA key",
    route: "/admin/security/seal/ca-key",
    plain: function () { return PATHS.CA_KEY; },
    sealed: function () { return PATHS.CA_KEY_SEALED; },
  },
  {
    name: "the TLS server key",
    route: "/admin/security/seal/tls-key",
    plain: tlsPlainPath,
    sealed: function () { return tlsPlainPath() + ".sealed"; },
  },
];

TARGETS.forEach(function (t) {
  describe("sealing " + t.name, function () {
    it("refuses when a sealed file is already there, and leaves it byte-for-byte", async function () {
      put(t.plain(), "-----BEGIN PRIVATE KEY-----\nplaintext\n-----END PRIVATE KEY-----\n");
      var sealedPath = put(t.sealed(), "SEALED-ORIGINAL-DO-NOT-TOUCH");
      var before_ = fs.readFileSync(sealedPath);

      var res = await client.post(t.route, { json: {} });

      assert.strictEqual(res.status, 409, "an existing sealed file is a conflict");
      assert.match(String(res.json.detail || res.json.error || ""), /refusing to overwrite/i,
        "and the refusal must say why");
      assert.deepStrictEqual(fs.readFileSync(sealedPath), before_,
        "the sealed key that was already there must be untouched");
    });

    it("refuses when there is no plaintext key to seal", async function () {
      // Nothing is created. Sealing an absent file would otherwise write a seal
      // of nothing over whatever name it was given.
      var res = await client.post(t.route, { json: {} });
      assert.strictEqual(res.status, 409);
      assert.match(String(res.json.detail || res.json.error || ""), /nothing to seal/i);
      assert.strictEqual(fs.existsSync(t.sealed()), false,
        "and no sealed file may be left behind by the refusal");
    });

    it("is refused for a signed-in non-admin", async function () {
      put(t.plain(), "-----BEGIN PRIVATE KEY-----\nplaintext\n-----END PRIVATE KEY-----\n");
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "Ordinary", email: "ordinary-seal-" + t.route.replace(/\W/g, "") + "@test.com", password: "password123" },
      });

      var res = await client.post(t.route, { json: {} });
      assert.strictEqual(res.status, 403);
      assert.strictEqual(fs.existsSync(t.sealed()), false,
        "a refused caller must not have sealed anything");

      // Back to the admin for the next case.
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", { json: { email: "sealadmin@test.com", password: "password123" } });
    });
  });
});
