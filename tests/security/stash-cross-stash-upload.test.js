"use strict";

/**
 * A visitor to one stash cannot upload into another stash's bundle.
 *
 * POST /stash/:slug/file/:bundleId takes the stash from the path and the bundle
 * from the path, and they are supplied independently by whoever is calling. The
 * route resolves the stash, checks that visitor is allowed through its gate, and
 * then has to confirm the bundle actually belongs to THAT stash — otherwise
 * clearing the lock on an open stash is enough to write into a locked one, by
 * naming its bundle id.
 *
 * That check had no test. The two either side of it did, which is the shape that
 * makes a gap easy to miss: the sync-bundle guard below it is covered, and the
 * completed-bundle guard above it is covered.
 *
 * The route is driven directly against a captured router with the repositories
 * stubbed, matching tests/unit/stash-sync-access.test.js — no server, no
 * network, and the guard is reached before any upload machinery.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var vault = require("../../lib/vault");
var stashRepo, bundlesRepo, blamejs;
var routes = {};
var orig = {};

// Two stashes. The open one is the foothold; the private one owns the target.
var OPEN_STASH = {
  _id: "stash-open", slug: "openstash", enabled: "true",
  accessMode: "open", passwordHash: null, allowedEmails: null,
  syncEnabled: "false", syncBundleId: null,
  name: "Open", title: "Open", teamId: null, defaultExpiry: 0,
};
var OTHER_STASH = {
  _id: "stash-other", slug: "otherstash", enabled: "true",
  accessMode: "open", passwordHash: null, allowedEmails: null,
  syncEnabled: "false", syncBundleId: null,
  name: "Other", title: "Other", teamId: null, defaultExpiry: 0,
};
var OTHER_BUNDLE = {
  _id: "bundle-of-other", shareId: "share-of-other",
  bundleType: "snapshot", stashId: OTHER_STASH._id, status: "uploading",
};
var OWN_BUNDLE = {
  _id: "bundle-of-open", shareId: "share-of-open",
  bundleType: "snapshot", stashId: OPEN_STASH._id, status: "uploading",
};

before(async function () {
  await vault.init();
  stashRepo = require("../../app/data/repositories/stash.repo");
  bundlesRepo = require("../../app/data/repositories/bundles.repo");
  blamejs = require("../../lib/vendor/blamejs");

  var app = {
    get: function () {},
    post: function (routePath) { routes["POST " + routePath] = arguments[arguments.length - 1]; },
    getReservedSlugs: function () { return new Set(); },
  };
  require("../../routes/stash")(app);

  orig.findBySlug = stashRepo.findBySlug;
  stashRepo.findBySlug = function (slug) {
    if (slug === OPEN_STASH.slug) return OPEN_STASH;
    if (slug === OTHER_STASH.slug) return OTHER_STASH;
    return null;
  };
  orig.findById = bundlesRepo.findById;
  bundlesRepo.findById = function (id) {
    if (id === OTHER_BUNDLE._id) return OTHER_BUNDLE;
    if (id === OWN_BUNDLE._id) return OWN_BUNDLE;
    return null;
  };
  orig.parsersJson = blamejs.parsers.json;
  blamejs.parsers.json = async function () { return {}; };
});

after(function () {
  if (stashRepo) stashRepo.findBySlug = orig.findBySlug;
  if (bundlesRepo) bundlesRepo.findById = orig.findById;
  if (blamejs) blamejs.parsers.json = orig.parsersJson;
});

function mockRes() {
  return {
    statusCalled: null, body: null,
    status: function (c) { this.statusCalled = c; return this; },
    json: function (o) { this.body = o; return this; },
  };
}

function uploadReq(slug, bundleId) {
  return {
    params: { slug: slug, bundleId: bundleId },
    session: {}, headers: {}, method: "POST",
    socket: { remoteAddress: "203.0.113.7" },
  };
}

async function thrownBy(route, slug, bundleId) {
  var handler = routes[route];
  assert.ok(handler, route + " must be registered");
  try {
    await handler(uploadReq(slug, bundleId), mockRes());
    return null;
  } catch (e) { return e; }
}

// All three routes that take a stash and a bundle from the path independently.
// The guard is written out once per route, so covering one proves nothing about
// the others — and the chunked path is the one an uploader of any size uses.
var ROUTES = [
  ["uploading a single file", "POST /stash/:slug/file/:bundleId"],
  ["uploading a chunk", "POST /stash/:slug/chunk/:bundleId"],
  ["finalizing an upload", "POST /stash/:slug/finalize/:bundleId"],
];

ROUTES.forEach(function (pair) {
  var label = pair[0], route = pair[1];

  describe(label + " into a stash bundle", function () {
    it("refuses a bundle belonging to a different stash", async function () {
      var e = await thrownBy(route, OPEN_STASH.slug, OTHER_BUNDLE._id);
      assert.ok(e, "naming another stash's bundle must not be allowed to proceed");
      assert.strictEqual(e.statusCode, 403, "it is a forbidden write, not a not-found: " + e.message);
      assert.match(e.message, /does not belong to this stash/);
    });

    it("refuses it in the other direction too", async function () {
      // Symmetric, so the check cannot be satisfied by one stash happening to be
      // the first the resolver returns.
      //
      // The message is asserted, not just the status. Checking for 403 alone let
      // this pass on the finalize route with the guard removed, because what it
      // reaches next refuses with a 403 of its own — a different reason arriving
      // at the same status reads as the check still working.
      var e = await thrownBy(route, OTHER_STASH.slug, OWN_BUNDLE._id);
      assert.ok(e);
      assert.strictEqual(e.statusCode, 403);
      assert.match(e.message, /does not belong to this stash/);
    });

    it("refuses a bundle that does not exist", async function () {
      var e = await thrownBy(route, OPEN_STASH.slug, "no-such-bundle");
      assert.ok(e);
      assert.strictEqual(e.statusCode, 404, "an unknown bundle is not found");
    });

    it("refuses an unknown stash before it ever looks at the bundle", async function () {
      var e = await thrownBy(route, "no-such-stash", OWN_BUNDLE._id);
      assert.ok(e);
      assert.strictEqual(e.statusCode, 404);
    });

    it("gets past the ownership check for its own bundle", async function () {
      // The refusals above are worth nothing if everything is refused. This one
      // clears ownership and fails further along, which is proof it reached past
      // the guard rather than being stopped by it.
      var e = await thrownBy(route, OPEN_STASH.slug, OWN_BUNDLE._id);
      assert.strictEqual(e && /does not belong to this stash/.test(e.message), false,
        "it must not have been stopped by the ownership check: " + (e && e.message));
    });
  });
});
