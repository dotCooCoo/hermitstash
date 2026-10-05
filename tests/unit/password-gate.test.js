require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var argon2Probe = require("../helpers/argon2-probe");

argon2Probe.install();

var b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var { ServiceUnavailableError } = require("../../app/shared/errors");
var passwordGate = require("../../lib/password-gate");

var PW = "gate-test-password-1";
var BUSY = "Too many password checks are in progress. Try again in a few seconds.";
var ADMITTED = C.PASSWORD_HASH.MAX_CONCURRENT + C.PASSWORD_HASH.MAX_QUEUED;
var fastHash;

before(async function () {
  // A 1 MiB stored hash keeps each verify short; verify reads its cost from
  // the stored hash.
  fastHash = await b.auth.password.hash(PW, { memoryCost: C.BYTES.kib(1), timeCost: 1, parallelism: 1 });
});

after(function () { argon2Probe.uninstall(); });

describe("lib/password-gate", function () {
  it("b.promisePool.create refuses past queueLimit with promise-pool/queue-full", async function () {
    var pool = b.promisePool.create({ concurrency: 1, queueLimit: 1 });
    var first = pool.run(function () { return new Promise(function (resolve) { setImmediate(resolve); }); });
    var second = pool.run(function () { return 2; });
    assert.strictEqual(pool.inFlight(), 1);
    assert.strictEqual(pool.queued(), 1);
    assert.throws(function () { pool.run(function () { return 3; }); },
      function (e) { return e.code === "promise-pool/queue-full"; });
    await first;
    assert.strictEqual(await second, 2);
  });

  it("sets b.auth.password.gate when it loads", async function () {
    argon2Probe.reset();
    var jobs = [];
    for (var i = 0; i < 6; i++) jobs.push(b.auth.password.verify(fastHash, PW));
    assert.deepStrictEqual(await Promise.all(jobs), [true, true, true, true, true, true]);
    assert.strictEqual(argon2Probe.stats().maxRunning, C.PASSWORD_HASH.MAX_CONCURRENT);
  });

  it("isVerifiable compares a stored hash's cost with b.auth.password.costCeiling()", function () {
    var c = b.auth.password.costCeiling();
    var tail = "$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    function phc(m, t, p) { return "$argon2id$v=19$m=" + m + ",t=" + t + ",p=" + p + tail; }
    assert.strictEqual(passwordGate.isVerifiable(phc(c.memoryCost, c.timeCost, c.parallelism)), true);
    assert.strictEqual(passwordGate.isVerifiable(phc(c.memoryCost + 1, 3, 4)), false);
    assert.strictEqual(passwordGate.isVerifiable(phc(65536, c.timeCost + 1, 4)), false);
    assert.strictEqual(passwordGate.isVerifiable(phc(65536, 3, c.parallelism + 1)), false);
    assert.strictEqual(passwordGate.isVerifiable(phc(512, 2, 1)), true, "a memory cost under 1 MiB is below the ceiling");
    assert.strictEqual(passwordGate.isVerifiable("$2b$12$abcdefghijklmnopqrstuuWJ1Pp0SUYYMp8zSrkkyIa2Wq4JHgB."), false);
    assert.strictEqual(passwordGate.isVerifiable(""), false);
  });

  // With no queue bound and no wait timeout, the framework gate never raises
  // argon2/busy or argon2/queue-timeout. scripts/release.js lists the
  // a-catch-around-a-gated-argon2-call-swallows-the-capacity-refusal detector as
  // not applicable on that basis.
  it("leaves the framework gate without a queue bound or a wait timeout", function () {
    var s = b.auth.password.stats();
    assert.strictEqual(s.limit, C.PASSWORD_HASH.MAX_CONCURRENT);
    assert.strictEqual(s.maxQueued, Infinity);
    assert.strictEqual(s.waitTimeoutMs, 0);
  });

  it("runs MAX_CONCURRENT checks at once and completes every queued check", async function () {
    argon2Probe.reset();
    var jobs = [];
    for (var i = 0; i < ADMITTED; i++) jobs.push(passwordGate.verify(fastHash, PW));
    var s = passwordGate.stats();
    assert.strictEqual(s.running, C.PASSWORD_HASH.MAX_CONCURRENT);
    assert.strictEqual(s.queued, C.PASSWORD_HASH.MAX_QUEUED);
    var results = await Promise.all(jobs);
    assert.strictEqual(results.filter(function (r) { return r === true; }).length, ADMITTED);
    assert.strictEqual(argon2Probe.stats().maxRunning, C.PASSWORD_HASH.MAX_CONCURRENT);
    assert.strictEqual(argon2Probe.stats().calls, ADMITTED);
  });

  it("refuses a check with a 503 once MAX_QUEUED checks are waiting", async function () {
    argon2Probe.reset();
    var jobs = [];
    for (var i = 0; i < ADMITTED + 2; i++) jobs.push(passwordGate.verify(fastHash, PW));
    var settled = await Promise.allSettled(jobs);
    assert.deepStrictEqual(settled.map(function (s) { return s.status; }),
      new Array(ADMITTED).fill("fulfilled").concat(["rejected", "rejected"]));
    [settled[ADMITTED].reason, settled[ADMITTED + 1].reason].forEach(function (err) {
      assert.ok(err instanceof ServiceUnavailableError);
      assert.strictEqual(err.statusCode, 503);
      assert.strictEqual(err.code, "SERVICE_UNAVAILABLE");
      assert.strictEqual(err.message, BUSY);
      assert.strictEqual(err.retryAfter, C.PASSWORD_HASH.RETRY_AFTER_SECONDS);
      assert.strictEqual(err.exposeDetail, true);
    });
    assert.strictEqual(argon2Probe.stats().calls, ADMITTED, "a refused check starts no Argon2id run");
  });

  it("frees its slots after a refusal and after a failed check", async function () {
    await assert.rejects(passwordGate.hash(""), function (e) { return e.code === "auth-password/invalid-plain"; });
    var s = passwordGate.stats();
    assert.strictEqual(s.running, 0);
    assert.strictEqual(s.queued, 0);
    assert.strictEqual(await passwordGate.verify(fastHash, PW), true);
  });

  it("hashes under the same limit, and the hashes verify", async function () {
    argon2Probe.reset();
    var hashes = await Promise.all([passwordGate.hash("pw-one-1"), passwordGate.hash("pw-two-2"), passwordGate.hash("pw-three-3")]);
    assert.strictEqual(argon2Probe.stats().maxRunning, C.PASSWORD_HASH.MAX_CONCURRENT);
    hashes.forEach(function (h) { assert.strictEqual(h.indexOf("$argon2id$v=19$m=65536,t=3,p=4$"), 0); });
    assert.strictEqual(await passwordGate.verify(hashes[1], "pw-two-2"), true);
  });
});
