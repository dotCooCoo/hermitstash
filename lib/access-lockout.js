/**
 * Persistent, subnet-keyed exponential-backoff lockout for public unlock routes.
 *
 * Both the bundle-password unlock (/b/:shareId/unlock) and the stash-password
 * unlock (/stash/:slug/unlock) gate an operator-set password on an
 * unauthenticated public route. A per-IP fixed-window rate limiter caps attempts
 * while the process is up, but it is in-memory (cleared on restart / worker
 * rotation) and keys on the exact client IP (an attacker rotating addresses
 * within a /24 or /64 gets a fresh budget per address). This module is the
 * second, stronger layer: a DB-backed counter (bundle_access_lockouts table)
 * that survives restart and keys on the routing subnet, so the escalating
 * backoff can't be reset by a restart or by subnet IP rotation.
 *
 * The counter is keyed on a caller-supplied namespace (e.g. "bundle" / "stash")
 * + the resource id + the masked client subnet. Distinct namespaces never
 * collide, so the two routes share one implementation and one table without
 * sharing counters.
 *
 * THRESHOLD failures arm the lockout; each failure past it doubles a 30s
 * backoff window. Stale rows (> 24h idle) are swept by the scheduled
 * bundle_lockout_cleanup job in server.js (it DELETEs the whole table by
 * lastAttempt, so namespaced rows are reclaimed by the same sweep).
 */
"use strict";

var b = require("./vendor/blamejs");
var C = require("./constants");
var db = require("./db");

var THRESHOLD = 5;
var BACKOFF_BASE_SECONDS = 30;

// Mask the client IP to its /24 (v4) / /64 (v6) routing subnet, then derive a
// namespaced blind index. ipPrefix collapses the rotatable low bits so an
// attacker rotating addresses within a subnet can't reset the counter; the
// namespace partitions bundle vs. stash counters into disjoint key spaces.
function _key(namespace, resourceId, ip) {
  var masked = (ip && b.requestHelpers.ipPrefix(ip)) || ip || "unknown";
  return b.crypto.namespaceHash(C.HASH_PREFIX.SHARE_ID, namespace + "|" + resourceId + "|" + masked);
}

// Returns the current lockout row ({ failures, lastAttempt }) or null.
function getLockout(namespace, resourceId, ip) {
  return db.bundleAccessLockouts.findOne({ shareIdHash: _key(namespace, resourceId, ip) });
}

// Returns the seconds the caller must wait before another attempt is allowed,
// or 0 when not currently locked out. A single source of truth so both routes
// compute the backoff identically.
function lockedFor(lockout) {
  if (!lockout || lockout.failures < THRESHOLD) return 0;
  var backoffSeconds = Math.pow(2, lockout.failures - THRESHOLD) * BACKOFF_BASE_SECONDS;
  // Fail closed: an absent or unparseable last-attempt timestamp can't prove the
  // backoff window elapsed. A bare Date.parse(NaN) propagates through the elapsed
  // math (Date.now() - NaN = NaN), and `NaN >= backoffSeconds` is false, so the
  // gate returned NaN and the caller's `retryAfter > 0` silently skipped the
  // lockout. Keep the lockout armed for the full window instead.
  var lastMs = lockout.lastAttempt ? Date.parse(lockout.lastAttempt) : NaN;
  if (!Number.isFinite(lastMs)) return Math.ceil(backoffSeconds);
  var elapsed = (Date.now() - lastMs) / C.TIME.seconds(1); // ms elapsed → seconds
  if (elapsed >= backoffSeconds) return 0;
  return Math.ceil(backoffSeconds - elapsed);
}

// Records one failed attempt; returns { failures, retryAfter } where retryAfter
// is the backoff window the new failure count implies (>0 once armed).
function recordFailure(namespace, resourceId, ip) {
  var hash = _key(namespace, resourceId, ip);
  var existing = db.bundleAccessLockouts.findOne({ shareIdHash: hash });
  var now = new Date().toISOString();
  var failures;
  if (existing) {
    failures = (existing.failures || 0) + 1;
    db.bundleAccessLockouts.update({ _id: existing._id }, { $set: { failures: failures, lastAttempt: now } });
  } else {
    failures = 1;
    db.bundleAccessLockouts.insert({ shareIdHash: hash, failures: failures, lastAttempt: now });
  }
  var retryAfter = failures >= THRESHOLD
    ? Math.pow(2, failures - THRESHOLD) * BACKOFF_BASE_SECONDS
    : 0;
  return { failures: failures, retryAfter: retryAfter };
}

function clearLockout(namespace, resourceId, ip) {
  db.bundleAccessLockouts.remove({ shareIdHash: _key(namespace, resourceId, ip) });
}

module.exports = {
  THRESHOLD: THRESHOLD,
  getLockout: getLockout,
  lockedFor: lockedFor,
  recordFailure: recordFailure,
  clearLockout: clearLockout,
};
