/**
 * DB-backed idempotency-key store for b.middleware.idempotencyKey.
 *
 * Implements the { get, set, delete } contract the middleware expects.
 * Backed by the `idempotency_keys` table (see lib/db.js). Rows are
 * sealed via field-crypto on the way in and unsealed on the way out.
 *
 * Why DB-backed and not memoryStore: a retry crossing a server
 * restart needs to replay the original response, not double-execute
 * the handler. Memory store loses entries on restart, defeating the
 * whole point on multi-day TTL. The DB path also makes this safe
 * for any future multi-replica deployment.
 *
 * GC: lazy on read (TTL check), periodic via
 * app/jobs/expiry-cleanup.job.cleanupExpiredIdempotencyKeys (hourly).
 */
var b = require("./vendor/blamejs");
var { idempotencyKeys } = require("./db");
var { HASH_PREFIX } = require("./constants");

// Hash the raw header value to keep the operator's idempotency key
// out of the DB (the key is unguessable per-client; storing the raw
// value would let a DB read replay any client's retried response).
function _keyHash(rawKey) {
  return b.crypto.namespaceHash(HASH_PREFIX.IDEMPOTENCY_KEY, String(rawKey));
}

function get(rawKey) {
  var keyHash = _keyHash(rawKey);
  var row = idempotencyKeys.findOne({ keyHash: keyHash });
  if (!row) return null;
  if (row.expiresAt < Date.now()) {
    idempotencyKeys.remove({ _id: row._id });
    return null;
  }
  // field-crypto unseals on read. Headers come back as a JSON string
  // we serialized on insert.
  var headers = null;
  try { headers = row.headers ? JSON.parse(row.headers) : null; } // allow:bare-json-parse — round-trip of our own JSON.stringify in set(), field-crypto unsealed it
  catch (_e) { headers = null; }
  return {
    fingerprint: row.fingerprint,
    statusCode:  row.statusCode,
    headers:     headers,
    body:        row.body,
  };
}

function set(rawKey, value, ttlMs) {
  if (!value || typeof value !== "object") return;
  var now = Date.now();
  idempotencyKeys.insert({
    _id:         b.crypto.generateBytes(b.constants.BYTES.bytes(16)).toString("hex"), // allow:raw-byte-literal — 128-bit random row ID
    keyHash:     _keyHash(rawKey),
    fingerprint: String(value.fingerprint || ""),
    statusCode:  Number(value.statusCode) || 0,
    headers:     value.headers ? JSON.stringify(value.headers) : null,
    body:        value.body != null ? String(value.body) : "",
    createdAt:   now,
    expiresAt:   now + (Number(ttlMs) || b.constants.TIME.hours(24)), // allow:raw-byte-literal — 24 here is hours, not bytes; draft-ietf-httpapi-idempotency-key default TTL window
  });
}

function del(rawKey) {
  idempotencyKeys.remove({ keyHash: _keyHash(rawKey) });
}

module.exports = { get: get, set: set, delete: del };
