/**
 * Shared single-use replay-claim store.
 *
 * b.nonceStore.checkAndInsert(nonce, expireAt) atomically records a nonce and
 * returns false if it was already present — the primitive for "claim this
 * exactly once". It serializes concurrent single-use operations (a 2FA TOTP
 * step / backup code) so two simultaneous requests presenting the same value
 * can't both succeed across an intervening `await` (CWE-367 TOCTOU). The
 * backend fails CLOSED at capacity (reports a nonce as seen rather than admit
 * an unproven-first-seen request).
 *
 * Memory backend: coordinates within a process, which covers the dominant
 * concurrent-replay window (two simultaneous requests landing on one worker).
 * A multi-replica deployment that needs cross-worker coordination should swap
 * the backend to "cluster".
 */
var b = require("./vendor/blamejs");

var store = b.nonceStore.create({ backend: "memory" });

/**
 * Claim `key` exactly once within `ttlMs`. Returns true on the first claim,
 * false if it was already claimed (a concurrent or recent replay).
 */
function claimOnce(key, ttlMs) {
  var nonce = b.crypto.sha3Hash(String(key));
  return store.checkAndInsert(nonce, Date.now() + ttlMs);
}

// Test-only: drop every recorded claim so a deliberately reused single-use
// value (the 2FA suite reuses one TOTP code across cases within a single time
// window) isn't rejected as a replay. Production never calls this — a real
// client never replays a code, which is exactly what the live claim defends.
function _resetForTests() {
  try { store.close(); } catch (_e) { /* close also stops the sweep timer */ }
  store = b.nonceStore.create({ backend: "memory" });
}

module.exports = { claimOnce: claimOnce, _store: store, _resetForTests: _resetForTests };
