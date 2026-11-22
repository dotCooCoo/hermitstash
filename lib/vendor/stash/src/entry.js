// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. Operators receive entries from
// show()/list(); this module is where their one canonical shape lives.
//
// entry -- the canonical Entry structure (SPEC.md 4), defined ONCE.
//
// One structure, both directions: a push, the disk backend's meta read, and
// store()'s replication input all compose this module, so the writer's shape and
// a reader's validation can never diverge. A second Entry construction site is
// the bug class this file exists to prevent.

import { isValidDigest } from "./digest.js";
import { isValid } from "./ref.js";

// The sidecar codec derives its accept-list from THIS array, not a second copy.
export const FIELDS = Object.freeze([
  "id",
  "size",
  "digest",
  "createdAt",
  "expiresAt",
  "reads",
  "readsLeft",
  "meta",
]);

function _isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function _isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

// The read direction: stored bytes are untrusted (CWE-20; the sidecar is RFC
// 8259 JSON), so a stored entry must carry exactly FIELDS with every field
// well-typed. Messages name the failing FIELD, never a value: field names are
// contract, values are capabilities.
// @enforced-by behavioral -- the hostile-sidecar battery drives every
//   rejection branch through the shipped read path; the shape itself has
//   no rename-proof code signature apart from entry.make's, which the
//   guard detector already owns.
export function assertShape(value, ErrorClass) {
  if (!_isPlainObject(value)) throw new ErrorClass("stored entry rejected: not an object");
  const keys = Object.keys(value);
  if (keys.length !== FIELDS.length) throw new ErrorClass("stored entry rejected: field set");
  for (const field of FIELDS) {
    if (!(field in value)) throw new ErrorClass("stored entry rejected: field set");
  }
  if (!isValid(value.id)) throw new ErrorClass("stored entry rejected: id");
  if (!_isCount(value.size)) throw new ErrorClass("stored entry rejected: size");
  if (!isValidDigest(value.digest)) {
    throw new ErrorClass("stored entry rejected: digest");
  }
  if (!_isCount(value.createdAt)) throw new ErrorClass("stored entry rejected: createdAt");
  if (value.expiresAt !== null && !_isCount(value.expiresAt)) {
    throw new ErrorClass("stored entry rejected: expiresAt");
  }
  const budgeted = value.reads !== null;
  if (budgeted && !(Number.isSafeInteger(value.reads) && value.reads > 0)) {
    throw new ErrorClass("stored entry rejected: reads");
  }
  if (budgeted !== (value.readsLeft !== null)) {
    throw new ErrorClass("stored entry rejected: read budget coherence");
  }
  // A LIVE budgeted entry has readsLeft in [1, reads]: the read spending the last
  // credit destroys the entry, so 0 never persists. An entry carrying it is
  // exhausted-but-undestroyed, which a replica must not be able to smuggle in.
  if (
    budgeted &&
    (!(Number.isSafeInteger(value.readsLeft) && value.readsLeft > 0) ||
      value.readsLeft > value.reads)
  ) {
    throw new ErrorClass("stored entry rejected: readsLeft");
  }
  if (!_isPlainObject(value.meta)) throw new ErrorClass("stored entry rejected: meta");
  return value;
}

// The ONE expiry comparator. The boundary is `<=`, not `<`: an entry whose
// deadline is the current instant IS expired, which is what makes a `ttl: 0`
// push deterministic rather than a clock race.
// @enforced-by guard-shape-reinlined
// @guard-shape \.expiresAt\s*[<>]
export function isExpired(entry, nowMs) {
  return entry.expiresAt !== null && entry.expiresAt <= nowMs;
}

// Size and digest are the backend's to fill during the write stream. `expiresAt`
// is stamped from the SAME `createdAt` clock read, so the two can never come
// from different reads, and the sum must land on a safe integer: an expiresAt
// past 2^53-1 serializes as a lie (JSON turns a non-finite into null, meaning
// "never expires"). `reads` and `readsLeft` travel together, so a reader can
// never see one without the other.
// @enforced-by guard-shape-reinlined
// @guard-shape readsLeft\s*:
export function make(id, meta, ttlMs = null, reads = null) {
  const createdAt = Date.now();
  let expiresAt = null;
  if (ttlMs !== null) {
    expiresAt = createdAt + ttlMs;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new TypeError("push: ttl places expiresAt beyond the safe integer range");
    }
  }
  if (reads !== null && !(Number.isSafeInteger(reads) && reads > 0)) {
    throw new TypeError("push: reads must be a positive integer or null");
  }
  return {
    id,
    size: 0,
    digest: null,
    createdAt,
    expiresAt,
    reads,
    readsLeft: reads,
    meta,
  };
}

// A grave's canonical shape (SPEC.md 4.4). It says only "never accept this id
// again": id, when, how, and NOTHING describing the body, because recording what
// the entry was would leak the content the destruction removed. `CAUSES` is the
// frozen set of early-destruction paths; expiry writes no grave.
export const TOMBSTONE_FIELDS = Object.freeze(["id", "destroyedAt", "cause"]);
export const CAUSES = Object.freeze(["pop", "drop", "clear", "spent"]);

// The write direction. No other module hand-rolls a
// `{ id, destroyedAt, cause }` literal.
// @enforced-by guard-shape-reinlined
// @guard-shape destroyedAt\s*:
export function makeTombstone(id, cause) {
  return { id, destroyedAt: Date.now(), cause };
}

// The read direction: a stored grave is untrusted bytes. Messages name the
// failing FIELD, never a value, since the id especially is a capability.
// @enforced-by behavioral -- the hostile-tombstone battery drives every rejection
//   branch through the shipped tombstones()/store() path; the shape has no
//   rename-proof code signature apart from makeTombstone's, which the guard owns.
export function assertTombstoneShape(value, ErrorClass) {
  if (!_isPlainObject(value)) throw new ErrorClass("stored tombstone rejected: not an object");
  const keys = Object.keys(value);
  if (keys.length !== TOMBSTONE_FIELDS.length)
    throw new ErrorClass("stored tombstone rejected: field set");
  for (const field of TOMBSTONE_FIELDS) {
    if (!(field in value)) throw new ErrorClass("stored tombstone rejected: field set");
  }
  if (!isValid(value.id)) throw new ErrorClass("stored tombstone rejected: id");
  if (!_isCount(value.destroyedAt)) throw new ErrorClass("stored tombstone rejected: destroyedAt");
  if (typeof value.cause !== "string" || !CAUSES.includes(value.cause)) {
    throw new ErrorClass("stored tombstone rejected: cause");
  }
  return value;
}

// The monotone read-budget debit (SPEC.md 4.1, 4.2), returning a COPY so no
// backend hand-rolls `readsLeft` arithmetic. Spending an unbudgeted or exhausted
// entry is a TypeError, never a silent no-op that would let a budgeted entry
// outlive its budget. Applied only while the caller holds the entry's claim,
// which is the cross-process mutex.
// @enforced-by guard-shape-reinlined
// @guard-shape readsLeft\s*:
export function spend(entry) {
  if (entry.readsLeft === null) throw new TypeError("spend: entry has no read budget");
  if (entry.readsLeft === 0) throw new TypeError("spend: read budget already exhausted");
  return { ...entry, readsLeft: entry.readsLeft - 1 };
}
