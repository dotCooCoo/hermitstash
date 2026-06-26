/**
 * Per-user serialization for vault mutations.
 *
 * Vault rotation snapshots the user's file set, re-encrypts each file under a
 * new key, then swaps the user's vault key. A concurrent upload or a second
 * rotation that interleaves with that sequence can leave a file encrypted
 * under the discarded old seed — permanently undecryptable. Every mutating
 * vault route (rotate / upload / delete) takes the same per-user lock so those
 * sequences run one-at-a-time for a given user.
 *
 * HermitStash is a single-process server, so an in-process keyed mutex is the
 * correct scope. Each user-id maps to its own b.safeAsync.Mutex (FIFO,
 * release-on-finally even when fn throws); the mutex is dropped from the map
 * once nothing is queued so the map can't grow unbounded across many users.
 */
var b = require("./vendor/blamejs");

var _mutexes = new Map(); // userId -> b.safeAsync.Mutex

function _mutexFor(userId) {
  var key = String(userId);
  var m = _mutexes.get(key);
  if (!m) {
    m = new b.safeAsync.Mutex();
    _mutexes.set(key, m);
  }
  return m;
}

function _maybeDrop(userId, mutex) {
  // Drop the mutex once it's idle so the map doesn't accumulate one entry per
  // user seen. A queued waiter keeps pendingCount > 0; isHeld() guards against
  // dropping a mutex another caller is mid-runExclusive on.
  if (!mutex.isHeld() && mutex.pendingCount() === 0) {
    _mutexes.delete(String(userId));
  }
}

/**
 * Run fn while holding the per-user vault lock. fn may be async; the lock is
 * released on its resolution or rejection.
 * @param {string} userId
 * @param {function(): (any|Promise<any>)} fn
 * @returns {Promise<any>} fn's result
 */
async function withUserLock(userId, fn) {
  var mutex = _mutexFor(userId);
  try {
    return await mutex.runExclusive(fn);
  } finally {
    _maybeDrop(userId, mutex);
  }
}

/**
 * True when a vault mutation is currently in flight for this user (lock held
 * or a waiter queued).
 */
function isLocked(userId) {
  var m = _mutexes.get(String(userId));
  return !!(m && (m.isHeld() || m.pendingCount() > 0));
}

/**
 * Acquire-or-reject. If a mutation is already in flight for this user, returns
 * { acquired: false } WITHOUT running fn — the caller turns that into a 409.
 * Otherwise runs fn under the lock and returns { acquired: true, value }.
 *
 * The held-check and the acquire happen synchronously (single-threaded JS, no
 * await between them), so two concurrent rotations can't both observe an idle
 * lock and queue — the second sees the first's held lock and is rejected
 * rather than running after the first discarded its old key.
 */
async function tryWithUserLock(userId, fn) {
  if (isLocked(userId)) return { acquired: false };
  // No await between isLocked() above and runExclusive() below: the mutex is
  // marked held synchronously when an idle mutex is acquired, so any second
  // caller reaching isLocked() before fn yields will see it held.
  var value = await withUserLock(userId, fn);
  return { acquired: true, value: value };
}

module.exports = {
  withUserLock: withUserLock,
  isLocked: isLocked,
  tryWithUserLock: tryWithUserLock,
};
