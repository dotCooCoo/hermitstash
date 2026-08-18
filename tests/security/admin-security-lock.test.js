"use strict";

/**
 * One security operation at a time, and the lock has to come back.
 *
 * Sealing, unsealing and regenerating keys all run under a single-flight lock:
 * two of them overlapping would interleave writes to the same key files. The
 * "already in progress" branch had never run.
 *
 * The half that matters more is the release. The lock is taken before the
 * operation and dropped in a `finally`, so an operation that FAILS still has to
 * give it back — and every one of these routes has failure paths that are
 * ordinary rather than exceptional (nothing to seal, already sealed, wrong
 * passphrase). If the lock leaked on those, the first mistake an operator made
 * would wedge the entire security surface until the process restarted, and the
 * only symptom would be "another security operation is in progress" forever.
 *
 * The race is not timed. The lock is taken synchronously, before the handler
 * awaits anything, so issuing the second call without awaiting the first puts it
 * squarely inside the window every time.
 */

// The data directory is pinned before anything resolves it. isolate-db moves the
// database and the swept directory but not this one, and these routes derive the
// CA and TLS key paths from it — so without pinning they inspect the operator's
// real data directory. Nothing here writes, but a route that starts to would.
var nodeOs = require("node:os");
var nodePath = require("node:path");
var nodeFs = require("node:fs");
var DATA_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "hs-seclock-"));
process.env.HERMITSTASH_DATA_DIR = DATA_DIR;

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var vault = require("../../lib/vault");
var routes = {};

after(function () {
  try { nodeFs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

before(async function () {
  await vault.init();
  var app = {
    get: function () {},
    post: function (routePath) { routes["POST " + routePath] = arguments[arguments.length - 1]; },
    put: function () {}, delete: function () {},
    getReservedSlugs: function () { return new Set(); },
  };
  require("../../routes/admin")(app);
});

function adminReq() {
  return {
    user: { _id: "admin-1", role: "admin" },
    params: {}, headers: {}, method: "POST", pathname: "/admin/security/seal/ca-key",
    session: {}, socket: { remoteAddress: "203.0.113.5" },
  };
}
function mockRes() {
  return {
    statusCalled: null, body: null,
    status: function (c) { this.statusCalled = c; return this; },
    json: function (o) { this.body = o; return this; },
  };
}

// No plaintext key exists in this scratch directory, so the operation refuses
// with "nothing to seal" — an ordinary failure, which is exactly the path the
// lock has to survive.
var ROUTE = "POST /admin/security/seal/ca-key";

async function settled(p) {
  try { await p; return null; } catch (e) { return e; }
}

describe("the security operation lock", function () {
  it("refuses a second operation while the first is in flight", async function () {
    var handler = routes[ROUTE];
    assert.ok(handler, "the seal route must be registered");

    var first = handler(adminReq(), mockRes());     // takes the lock synchronously
    var second = await settled(handler(adminReq(), mockRes()));

    assert.ok(second, "the second operation must be refused while the first holds the lock");
    assert.match(second.message, /Another security operation is in progress/);
    assert.strictEqual(second.statusCode, 409);

    await settled(first);
  });

  it("gives the lock back after an operation that failed", async function () {
    // The first call refuses with "nothing to seal". If the lock leaked on that
    // path, this second call would report the lock instead — every security
    // operation blocked until restart, from one ordinary refusal.
    var handler = routes[ROUTE];

    var firstErr = await settled(handler(adminReq(), mockRes()));
    assert.ok(firstErr, "precondition: with no key present the operation refuses");
    assert.match(firstErr.message, /nothing to seal/i,
      "and it refuses for that reason, not because of the lock");

    var secondErr = await settled(handler(adminReq(), mockRes()));
    assert.ok(secondErr, "still nothing to seal");
    assert.strictEqual(/Another security operation is in progress/.test(secondErr.message), false,
      "the lock must have been released by the failed operation: " + secondErr.message);
    assert.match(secondErr.message, /nothing to seal/i);
  });

  it("stays released across many failed operations", async function () {
    // A leak that only shows after N attempts is the same outage, later.
    var handler = routes[ROUTE];
    for (var i = 0; i < 5; i++) {
      var e = await settled(handler(adminReq(), mockRes()));
      assert.strictEqual(/Another security operation is in progress/.test(e.message), false,
        "attempt " + (i + 1) + " hit the lock: " + e.message);
    }
  });

  it("covers every route that shares the lock", async function () {
    // The lock is one flag across all of them, so holding it on one route must
    // refuse the others — that is the property, not "this route is serialised".
    //
    // All six, and each asserted to be registered. The list was four, with the
    // two vault-passphrase routes missing and a filter that quietly dropped any
    // name that no longer resolved: a route could have lost its lock, or its
    // registration, and this would still have reported covering every one.
    var SHARED = [
      "POST /admin/security/seal/vault-passphrase",
      "POST /admin/security/unseal/vault-passphrase",
      "POST /admin/security/seal/ca-key",
      "POST /admin/security/unseal/ca-key",
      "POST /admin/security/seal/tls-key",
      "POST /admin/security/unseal/tls-key",
    ];
    SHARED.forEach(function (r) {
      assert.ok(routes[r], r + " must be registered — a route that vanished cannot be checked");
    });

    // Every call is issued before any of them is awaited. Awaiting between them
    // lets the holder settle and drop the lock, so the later routes would be
    // measured against a lock nobody holds — which is how this first read as the
    // routes not sharing it.
    var holder = routes[SHARED[0]](adminReq(), mockRes());
    var contenders = SHARED.slice(1).map(function (r) {
      return { route: r, promise: routes[r](adminReq(), mockRes()) };
    });

    for (var i = 0; i < contenders.length; i++) {
      var e = await settled(contenders[i].promise);
      assert.ok(e, contenders[i].route + " must be refused while another operation holds the lock");
      assert.match(e.message, /Another security operation is in progress/,
        contenders[i].route + " shares the lock");
    }
    await settled(holder);
  });
});
