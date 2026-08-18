"use strict";

/**
 * Redeeming an email-verification token is rate limited, like every sibling flow.
 *
 * Not because the token can be guessed — it is 256 bits, and the route rejects
 * anything that is not 64 hex characters before it hashes or looks anything up.
 * The cost is what an attacker gets for free otherwise: every rejected token
 * writes an EMAIL_VERIFICATION_FAILED row, and an unauthenticated caller could
 * write those without bound, filling the audit table and burying the events it
 * exists to record.
 *
 * The password-reset flow — the same shape, a token redeemed from a link in an
 * email — has always been limited, and so has resend-verification in this very
 * file. These two routes were the gap.
 *
 * The assertion is on the audit rows, not only on the status code. A limiter
 * that returned 429 while still doing the work would leave the flooding intact.
 */

var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var db;
var audit;

// 64 hex characters, so the shape check passes and the request reaches the
// lookup — which is where the audit row is written.
function bogusToken(n) {
  return String(n).padStart(4, "0").repeat(16);
}

function failedVerificationRows() {
  return db.auditLog.raw().find({}).filter(function (r) {
    var e = audit.unsealEntry(r);
    return e && e.action === audit.ACTIONS.EMAIL_VERIFICATION_FAILED;
  }).length;
}

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  audit = require(path.join(testServer.projectRoot, "lib", "audit"));
});
after(function () { return testServer.stop(); });

beforeEach(function () { testServer.resetAllRateLimits(); });

describe("redeeming a verification token", function () {
  it("stops answering once the ceiling is reached, on POST", async function () {
    var statuses = [];
    for (var i = 0; i < 14; i++) {
      statuses.push((await client.post("/auth/verify/" + bogusToken(i), { json: {} })).status);
    }
    assert.ok(statuses.includes(429),
      "an unauthenticated caller must not get unlimited attempts: " + statuses.join(","));
    assert.strictEqual(statuses[statuses.length - 1], 429, "and the ceiling must hold");
  });

  it("stops answering once the ceiling is reached, on GET", async function () {
    // The link in the email is a GET, and it reaches the same lookup — limiting
    // only the POST would leave the cost open.
    var statuses = [];
    for (var i = 0; i < 14; i++) {
      statuses.push((await client.get("/auth/verify/" + bogusToken(100 + i))).status);
    }
    assert.ok(statuses.includes(429),
      "the GET path must be limited too: " + statuses.join(","));
  });

  it("bounds the audit rows a refused caller can write", async function () {
    // The property the limit exists for. Without it, every one of these writes
    // a row; with it, the writes stop when the answers do.
    var before_ = failedVerificationRows();
    for (var i = 0; i < 30; i++) {
      await client.post("/auth/verify/" + bogusToken(200 + i), { json: {} });
    }
    var written = failedVerificationRows() - before_;
    assert.ok(written > 0, "precondition: a rejected token is audited at all");
    assert.ok(written <= 12,
      "30 attempts must not write 30 audit rows — wrote " + written);
  });

  it("serves a caller again once the window is reset", async function () {
    // A limiter that never released would lock legitimate users out of their own
    // verification link.
    for (var i = 0; i < 14; i++) {
      await client.post("/auth/verify/" + bogusToken(300 + i), { json: {} });
    }
    assert.strictEqual((await client.post("/auth/verify/" + bogusToken(399), { json: {} })).status, 429);

    testServer.resetAllRateLimits();
    var after_ = await client.post("/auth/verify/" + bogusToken(398), { json: {} });
    assert.notStrictEqual(after_.status, 429,
      "the window must release rather than locking the address out for good");
  });
});
