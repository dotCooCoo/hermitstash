/**
 * Argon2id password hashing and verification, limited across the process.
 *
 * Every HermitStash call to b.auth.password.hash or b.auth.password.verify
 * goes through hash() and verify() here. A b.promisePool runs at most
 * C.PASSWORD_HASH.MAX_CONCURRENT checks at once and holds at most
 * C.PASSWORD_HASH.MAX_QUEUED more. A check that arrives while the queue is
 * full is refused with a ServiceUnavailableError (HTTP 503 with Retry-After),
 * and no Argon2id work starts for it.
 *
 * Loading this module calls b.auth.password.gate() with
 * C.PASSWORD_HASH.MAX_CONCURRENT, no queue bound and a shared handle. The
 * framework gate counts every Argon2id derivation on the main thread. The vault
 * passphrase and audit-archive derivations wait there for a free slot and are
 * never refused. The backup and restore workers are started with
 * shareArgon2Gate and adopt the same gate, so their derivations count against
 * the same limit. tests/lint/codebase-patterns.test.js fails on a reference to
 * b.auth.password anywhere else in the server code except those two workers.
 */
"use strict";

var b = require("./vendor/blamejs");
var C = require("./constants");
var logger = require("../app/shared/logger");
var { ServiceUnavailableError } = require("../app/shared/errors");

var BUSY_MESSAGE = "Too many password checks are in progress. Try again in a few seconds.";

b.auth.password.gate(C.PASSWORD_HASH.MAX_CONCURRENT, { shared: true });

var pool = b.promisePool.create({
  concurrency: C.PASSWORD_HASH.MAX_CONCURRENT,
  queueLimit:  C.PASSWORD_HASH.MAX_QUEUED,
});

// Refusals are logged at most once a minute, with the number refused since the
// previous log line.
var refusedSinceLog = 0;
var lastRefusalLogAt = 0;

function _refuse() {
  refusedSinceLog += 1;
  var now = Date.now();
  if (now - lastRefusalLogAt >= C.TIME.minutes(1)) {
    logger.warn("Password checks refused: queue full", {
      refused: refusedSinceLog,
      running: pool.inFlight(),
      queued:  pool.queued(),
    });
    lastRefusalLogAt = now;
    refusedSinceLog = 0;
  }
  return new ServiceUnavailableError(BUSY_MESSAGE, C.PASSWORD_HASH.RETRY_AFTER_SECONDS);
}

// pool.run() throws promise-pool/queue-full synchronously when the queue is
// full. Any other error from the pool or the task is passed through.
function _submit(task) {
  try {
    return pool.run(task);
  } catch (e) {
    if (e && e.code === "promise-pool/queue-full") throw _refuse();
    throw e;
  }
}

async function hash(plain) {
  return _submit(function () { return b.auth.password.hash(plain); });
}

async function verify(stored, plain) {
  return _submit(function () { return b.auth.password.verify(stored, plain); });
}

function stats() {
  return {
    running:       pool.inFlight(),
    queued:        pool.queued(),
    maxConcurrent: C.PASSWORD_HASH.MAX_CONCURRENT,
    maxQueued:     C.PASSWORD_HASH.MAX_QUEUED,
  };
}

// isVerifiable returns false for a stored value that verify() rejects whatever
// the password: one that is not an Argon2id PHC string, and one whose memory,
// time or parallelism cost b.auth.password.exceedsCostCeiling() reports as above
// b.auth.password.costCeiling(). It returns true for any other Argon2id string,
// including one the framework cannot decode, and verify() rejects that one.
function isVerifiable(stored) {
  if (typeof stored !== "string" || stored.indexOf("$argon2id$") !== 0) return false;
  return !b.auth.password.exceedsCostCeiling(stored);
}

module.exports = { hash: hash, verify: verify, stats: stats, isVerifiable: isVerifiable };
