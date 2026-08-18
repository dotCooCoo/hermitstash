"use strict";

/**
 * The anonymous upload budget is keyed per /64, not per address.
 *
 * An end site is allocated a whole IPv6 /64 (RFC 4291 §2.5.4, RFC 6177) and can
 * pick any of the 2^64 addresses inside it at will. A rolling byte budget keyed
 * on the full /128 therefore caps nothing at all: the client changes the low 64
 * bits, gets a fresh bucket, and uploads again. The cap looks enforced from
 * every angle except the one that matters.
 *
 * IPv4 stays exact, because there is no equivalent freedom — an address is a
 * host, and collapsing to a prefix would make one customer's uploads eat a
 * neighbour's budget.
 *
 * Both directions are asserted here: a second address inside a spent /64 is
 * refused, and the first address of a different /64 is not. Testing only the
 * refusal would pass just as well if everything were refused.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, beforeEach, after } = require("node:test");
var assert = require("node:assert");

var config = require("../../lib/config");
var vault = require("../../lib/vault");
var uploads = require("../../app/domain/uploads/upload.handler");

before(async function () { await vault.init(); });

var saved = {};
before(function () {
  ["publicIpQuotaBytes", "storageQuotaBytes", "perUserQuotaBytes"].forEach(function (k) {
    saved[k] = config[k];
  });
});
after(function () { Object.keys(saved).forEach(function (k) { config[k] = saved[k]; }); });

// An anonymous bundle: no owner, so the per-user cap is skipped and the per-IP
// budget is the one under test.
var ANON = { ownerId: null, _id: "bundle-anon", shareId: "share-anon" };

function reqFrom(ip) {
  return { socket: { remoteAddress: ip }, headers: {}, connection: { remoteAddress: ip } };
}

var capCounter = 0;
beforeEach(function () {
  config.storageQuotaBytes = 0;      // global cap off; the per-IP budget is the subject
  config.perUserQuotaBytes = 0;
  // A distinct cap each time rebuilds the quota object, so buckets do not carry
  // between cases. The handler rebuilds whenever the configured value changes.
  capCounter += 1;
  config.publicIpQuotaBytes = 1000 + capCounter;
});

describe("an IPv6 client cannot mint a fresh budget by changing its address", function () {
  it("a second address in the same /64 shares the spent budget", async function () {
    var cap = config.publicIpQuotaBytes;
    var first = await uploads.checkAllQuotas(cap, ANON, reqFrom("2001:db8:1:1::1"));
    assert.strictEqual(first.allowed, true, "the first upload fits the budget");

    // Same /64, different interface identifier — the part a client rotates freely.
    var second = await uploads.checkAllQuotas(cap, ANON, reqFrom("2001:db8:1:1::dead:beef"));
    assert.strictEqual(second.allowed, false,
      "rotating the low 64 bits must not buy a fresh budget");
    assert.match(second.error, /quota exceeded/i);
  });

  it("a different /64 has its own budget", async function () {
    // The other half of the property. Without this, a check that refused
    // everything would look identical to a correct one.
    var cap = config.publicIpQuotaBytes;
    assert.strictEqual((await uploads.checkAllQuotas(cap, ANON, reqFrom("2001:db8:1:1::1"))).allowed,
      true);
    assert.strictEqual((await uploads.checkAllQuotas(cap, ANON, reqFrom("2001:db8:1:2::1"))).allowed,
      true, "a different end site must not inherit its neighbour's spend");
  });
});

describe("an IPv4 client is budgeted by its own address", function () {
  it("one address's spend does not touch another's", async function () {
    var cap = config.publicIpQuotaBytes;
    assert.strictEqual((await uploads.checkAllQuotas(cap, ANON, reqFrom("203.0.113.10"))).allowed, true);
    assert.strictEqual((await uploads.checkAllQuotas(cap, ANON, reqFrom("203.0.113.11"))).allowed, true,
      "IPv4 is keyed exactly — a neighbour must keep its own budget");
  });

  it("the same address is held to the budget it already spent", async function () {
    var cap = config.publicIpQuotaBytes;
    assert.strictEqual((await uploads.checkAllQuotas(cap, ANON, reqFrom("203.0.113.20"))).allowed, true);
    var again = await uploads.checkAllQuotas(cap, ANON, reqFrom("203.0.113.20"));
    assert.strictEqual(again.allowed, false);
    assert.strictEqual(again.reason, "per-IP quota exceeded");
  });
});

describe("the budget applies to anonymous uploads only", function () {
  it("a bundle with an owner is not charged to the address", async function () {
    // Signed-in uploads are bounded by the per-user cap instead; charging them
    // to the address as well would have one user's uploads exhaust the budget
    // for every anonymous visitor behind the same network.
    var cap = config.publicIpQuotaBytes;
    var owned = { ownerId: "user-1", _id: "bundle-owned", shareId: "share-owned" };
    var ip = reqFrom("203.0.113.30");
    assert.strictEqual((await uploads.checkAllQuotas(cap, owned, ip)).allowed, true);
    assert.strictEqual((await uploads.checkAllQuotas(cap, owned, ip)).allowed, true);
    assert.strictEqual((await uploads.checkAllQuotas(cap, owned, ip)).ipReserved, 0,
      "an owned upload reserves nothing against the address");
  });

  it("a cap of zero disables the budget entirely", async function () {
    // 0 means "no limit" throughout this codebase, and the quota primitive
    // refuses to be built with a non-positive budget — so the call has to be
    // skipped, not made with zero.
    config.publicIpQuotaBytes = 0;
    var ip = reqFrom("203.0.113.40");
    for (var i = 0; i < 3; i++) {
      var r = await uploads.checkAllQuotas(1024 * 1024, ANON, ip);
      assert.strictEqual(r.allowed, true, "no cap means no refusal");
      assert.strictEqual(r.ipReserved, 0, "and nothing is reserved");
    }
  });
});

describe("what an allowed check reserves", function () {
  it("reports the bytes it debited, so a rollback can return them", async function () {
    // The debit happens before the save, so concurrent uploads see the
    // in-flight bytes. The caller needs to know how much to give back if the
    // write then fails.
    var r = await uploads.checkAllQuotas(512, ANON, reqFrom("203.0.113.50"));
    assert.strictEqual(r.allowed, true);
    assert.strictEqual(r.ipReserved, 512);
  });

  it("an unparseable address still gets a bucket rather than throwing", async function () {
    // The quota primitive refuses an empty key, so a degenerate address falls
    // back to its canonical form instead of taking the upload path down.
    var r = await uploads.checkAllQuotas(16, ANON, reqFrom("not-an-address"));
    assert.strictEqual(typeof r.allowed, "boolean");
  });
});
