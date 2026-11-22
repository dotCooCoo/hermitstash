// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash
 * @nav        Core
 * @title      Stash
 * @order      10
 * @slug       stash
 *
 * @intro
 *   The policy layer of the store. `Stash` owns identity (refs), lifecycle,
 *   and integrity; the backend it wraps owns bytes. You put bytes in with
 *   `push` and get a ref back -- a 256-bit random capability, not a content
 *   address. You read them back with `apply`, inspect with `show` / `list`,
 *   and destroy with `drop` / `clear`.
 *
 *   The verb set is `git stash`'s, and the correspondence is the contract:
 *   lifecycle verbs the git command doesn't have don't get added, and the
 *   ones it has don't get renamed. Entries are write-once and their
 *   lifecycle is monotone -- every state change moves an entry closer to
 *   destruction, never further.
 *
 *   The store is crypto-agnostic by architecture: there is no key parameter
 *   on any method and no cipher import anywhere in the tree. Encryption
 *   belongs to the consumer; StashJS is a shelf.
 *
 *   A `Stash` is an `EventEmitter`. It emits `'pushed'` (Entry) after a push
 *   commits, `'popped'` (Entry) after a pop's delete lands, `'dropped'` (Entry)
 *   on `drop` / `clear` / a budget-exhausting read, `'expired'` (Entry) exactly
 *   once per reaped entry, and `'sweepError'` (Error) -- never `'error'`, which
 *   would crash the process -- when a background sweep throws. Payloads are full,
 *   defensive-copy Entry objects emitted after the change commits, so a throwing
 *   listener cannot unwind the committed operation.
 *
 * @card
 *   The policy layer -- push bytes in for a random-capability ref, stream
 *   them back out, destroy on demand; write-once entries, fail-closed
 *   verdicts.
 */

import { EventEmitter } from "node:events";
import { Transform, pipeline } from "node:stream";
import { isUint8Array } from "node:util/types";

import { C } from "./constants.js";
import {
  DEFAULT_DIGEST,
  algoOf,
  assertDigestAlgo,
  digestHash,
  digestMarker,
  finalize,
  isValidDigest,
} from "./digest.js";
import { parse } from "./duration.js";
import { assertShape, isExpired, make, makeTombstone } from "./entry.js";
import { IntegrityError, RefClaimed, RefNotFound, SizeExceeded, StashFull } from "./errors.js";
import { assertValid, constantTimeEqual, generate } from "./ref.js";
import { parse as parseSize } from "./size.js";
import { oneOf, options, plainObject } from "./validate.js";

// The fail-loud placeholder hook: a spec'd-but-unshipped push option listed here
// throws at config time rather than sitting accepted-but-unenforced. Empty
// today, since every spec'd option is implemented.
const UNIMPLEMENTED_PUSH_OPTIONS = [];

const DEFAULT_TOMBSTONE_TTL = "30d";

// Validated at construction so a misassembled backend fails at boot.
const REQUIRED_BACKEND_METHODS = [
  "write",
  "read",
  "remove",
  "stat",
  "list",
  "listReconcilable",
  "stats",
  "verify",
  "claim",
  "restore",
  "commit",
  "listClaims",
  "consumeRead",
  "isClaimed",
  "writeTombstone",
  "hasTombstone",
  "listTombstones",
  "removeTombstone",
];

const ON_POP_FAILURE = ["restore", "burn"];

const DEFAULT_CLAIM_TIMEOUT = "10m";

// Normalize a push source to an async-iterable of byte chunks. Never buffers.
//
// Three deliberate choices, each guarding a distinct bug class:
//   - isUint8Array, not `instanceof`: a typed array from another realm is a
//     genuine Uint8Array whose prototype is that realm's, so `instanceof` would
//     refuse a value the documented source set promises to take.
//   - NOT ArrayBuffer.isView: that admits a Uint16Array, whose elements copy
//     mod 256, storing bytes the caller never handed over.
//   - copyBytesFrom, not Buffer.from: `.length` is an ordinary property a
//     subclass may override, so Buffer.from on a view reporting 512 but holding
//     2 allocates 512 from the shared pool and pads the entry with whatever it
//     last held. copyBytesFrom reads the internal byteLength slot, which no
//     property can forge, and honours byteOffset.
function _toChunkSource(source) {
  if (typeof source === "string") return [Buffer.from(source, "utf8")];
  if (isUint8Array(source)) return [Buffer.copyBytesFrom(source)];
  if (source !== null && typeof source === "object" && Symbol.asyncIterator in source) {
    return source;
  }
  // No verb in the message: push() and store() both reach this line, so it cannot
  // know which one the caller invoked.
  throw new TypeError("source must be a Buffer, Uint8Array, string, Readable, or AsyncIterable");
}

// Wrap a backend read stream in a digest-verifying passthrough; nothing is
// buffered, and a mismatch errors the stream with IntegrityError rather than
// delivering silently bad bytes.
//
// `verdict` (optional) drives the claimed-read lifecycle for pop and budgeted
// apply. `onCommit()` runs in flush BEFORE the transform signals end, so a
// consumer that has seen 'end' knows the commit landed. `onFail()` runs on the
// other outcomes. Both flush and the pipeline callback can reach the verdict,
// so the `resolved` latch is what makes it fire exactly once.
function _verifiedStream(entry, source, verdict) {
  // Self-describing: verify with the algorithm the entry was WRITTEN with, never
  // a global assumption, since a store may mix digests (SPEC.md 5).
  const algo = algoOf(entry.digest);
  const hash = digestHash(algo);
  let resolved = false;
  const verify = new Transform({
    transform(chunk, _encoding, callback) {
      hash.update(chunk);
      callback(null, chunk);
    },
    async flush(callback) {
      const got = finalize(hash, algo);
      if (!constantTimeEqual(got, entry.digest)) {
        resolved = true;
        if (verdict && verdict.onFail) await _settle(verdict.onFail);
        callback(new IntegrityError());
        return;
      }
      if (verdict && verdict.onCommit) {
        resolved = true;
        // `.then(ok, fail)`, never a catch that would read as fail-open. A
        // commit fault surfaces on the stream; recovery resolves the
        // still-standing claim later.
        callback(
          await verdict.onCommit().then(
            () => null,
            (err) => err,
          ),
        );
        return;
      }
      callback();
    },
  });
  // A failure reaching here without flush having resolved (a source error, a
  // premature destroy at N%) still owes the claim its verdict.
  pipeline(source, verify, (err) => {
    if (err && !resolved && verdict && verdict.onFail) {
      resolved = true;
      void _settle(verdict.onFail);
    }
  });
  return verify;
}

// store()'s write-side digest+size gate. The backend recomputes the digest and
// OVERWRITES stored.digest, so an unverified store would self-certify whatever
// bytes arrive, recording transfer corruption as truth (CWE-345). Checking
// in-stream puts the throw after the last chunk but BEFORE the backend's
// post-loop rename/sidecar, so a mismatch leaves nothing on disk; a post-hoc
// check would leave the corrupt entry live and listed in between.
async function* _verifiedInbound(source, entry) {
  const algo = algoOf(entry.digest);
  const hash = digestHash(algo);
  let size = 0;
  for await (const chunk of source) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    hash.update(buf);
    size += buf.length;
    yield buf;
  }
  // Size FIRST: a lying `size` with a matching digest diverges the sidecars
  // across replicas even though the bytes are identical.
  if (size !== entry.size) throw new IntegrityError();
  if (!constantTimeEqual(finalize(hash, algo), entry.digest)) throw new IntegrityError();
}

// Run a claim-resolution hook. Drop-silent -- by design: a restore/burn that
// cannot land must not throw into a stream teardown. A claim it leaves standing
// is what the lazy recovery scan resolves on the next construction.
async function _settle(hook) {
  await hook().catch(() => {});
}

// Best-effort teardown of an opened read source we are abandoning. It must NOT
// wait for 'close': a Readable with `emitClose: false`, which the SPEC.md 9
// backend contract permits, emits neither 'close' nor 'error' on destroy, so
// waiting would hang apply forever.
function _dispose(source) {
  if (!source || typeof source.destroy !== "function" || source.destroyed) return;
  source.once("error", () => {}); // abandoning it -- a teardown error is not ours to surface
  source.destroy();
}

// True for a raw ArrayBuffer or SharedArrayBuffer from ANY realm. `instanceof`
// misses both SharedArrayBuffer and a cross-realm buffer, which would then fall
// through to `.length` (undefined, so every size comparison is false) while
// Buffer.from still writes every byte. The brand check trips no get/index trap.
function _isArrayBuffer(value) {
  if (value === null || typeof value !== "object") return false;
  const tag = Object.prototype.toString.call(value);
  return tag === "[object ArrayBuffer]" || tag === "[object SharedArrayBuffer]";
}

// Enforce the size limits DURING the stream, in the policy layer, never in a
// backend: the verdict is thrown before the crossing chunk reaches the backend's
// tmp file, so an unbounded source is abandoned at the boundary rather than
// drained. `residual` is the remaining stash-wide headroom. SizeExceeded is
// reported before StashFull when one chunk crosses both, because a per-entry
// overflow is permanent while a full stash may later clear.
async function* _boundedSource(source, maxSize, residual) {
  let total = 0;
  for await (const chunk of source) {
    // Measure WITHOUT copying, so a hostile oversized chunk is rejected before it
    // is duplicated in memory: the advertised limit has to bound this allocation
    // too. Measure by byteLength, never `.length`, which is undefined on a raw
    // buffer (so every comparison goes false) and an element count on a
    // multi-byte view. Measurement and the copy below classify identically.
    let len;
    if (typeof chunk === "string") len = Buffer.byteLength(chunk);
    else if (ArrayBuffer.isView(chunk)) len = chunk.byteLength;
    else if (_isArrayBuffer(chunk)) len = chunk.byteLength;
    else len = chunk.length;
    total += len;
    if (maxSize !== null && total > maxSize) throw new SizeExceeded();
    if (residual !== null && total > residual) throw new StashFull();
    // Materialize only now that it is known to fit, over its EXACT bytes: a view
    // is normalized through its backing buffer, since Buffer.from(uint16array)
    // would copy each element mod 256.
    if (typeof chunk === "string") yield Buffer.from(chunk, "utf8");
    else if (ArrayBuffer.isView(chunk))
      yield Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    else yield Buffer.from(chunk);
  }
}

// A byte bound resolved through size.parse, then required POSITIVE: zero would
// reject every push. null means no bound.
function _positiveBytes(value, label) {
  const bytes = parseSize(value, label);
  if (bytes !== null && bytes <= 0) {
    throw new TypeError(label + ": must be a positive size; 0 would reject every push");
  }
  return bytes;
}

// A count bound (maxEntries): no string form, since it is a count rather than a
// size or duration. null means no bound.
function _positiveCount(value, label) {
  if (value === null || value === undefined) return null;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(label + ": expected a positive integer count");
  }
  return value;
}

/**
 * @primitive  stash.Stash
 * @signature  new Stash(opts) -> Stash
 * @since      0.1.0
 * @status     stable
 * @spec       SPEC.md 4, SPEC.md 7, SPEC.md 7.1
 * @defends    CWE-1188
 * @related    stash.backends.MemoryBackend
 *
 * Construct a store over a backend. `opts.backend` is required and must
 * implement the backend contract (SPEC.md 9).
 *
 * `opts.ttl` (`'30m'`, `'24h'`, `'7d'`, a number of ms, or `null` for no
 * expiry) is the construct-time default expiry for every push, overridable per
 * call. `opts.sweepInterval` (same duration forms) arms a background `prune()`
 * timer. The timer is `.unref()`'d, so an open `Stash` never holds the process
 * open on exit, but still call `close()` or `await using` on shutdown, since an
 * unref'd timer keeps the `Stash` reachable. A `sweepInterval` of zero, or above
 * Node's ~24.8-day timer ceiling, is a config-time TypeError rather than a
 * silent busy loop.
 *
 * `opts.maxSize` bounds each entry (a size string like `'100mb'`, or a byte
 * count). A push that exceeds it aborts mid-stream with `SizeExceeded`, leaving
 * no partial behind. `opts.maxEntries` and `opts.maxTotal` bound the whole
 * store; a push that would exceed either is refused with `StashFull`, and
 * nothing existing is evicted to make room. Expired-but-unswept entries are
 * pruned before the store is judged full, so they never block a live push.
 *
 * A stats read and the write are not atomic, so concurrent pushes can overshoot
 * a stash-wide bound by the number in flight: the bound stops unbounded growth,
 * not that exact byte. `maxTotal` counts the stored footprint, each blob plus
 * its metadata, so many tiny blobs carrying large `meta` cannot slip past it. It
 * is a ceiling you set rather than one the disk enforces, so size it below the
 * backing partition's free space, and keep `maxSize` at or below it, or the
 * filesystem fills before the limit fires.
 *
 * `opts.onPopFailure` decides what happens to an entry whose `pop`, or budgeted
 * `apply`, fails to fully drain, whether through a stream destroyed early, a
 * source error, or a digest mismatch. `'restore'` (the default) returns the
 * entry so the read can be retried; `'burn'` destroys it anyway.
 *
 * `opts.claimTimeout` (a duration string or a number of ms, default `'10m'`,
 * strictly POSITIVE) is how long a claim left by a crashed process is treated as
 * still live before recovery reclaims it on the next construction. A claim
 * younger than this is left untouched. Recovery NEVER reclaims a claim a live
 * reader in THIS process is still draining: single-writer-per-root means the
 * process tracks its own live claims, so the age test, and the wall clock behind
 * it that a forward step can jump, is consulted only for an ORPHAN with no live
 * holder, meaning a crashed prior run's. Set it to comfortably exceed the
 * longest `pop` or budgeted read, and keep a disk root to a single writing
 * process. A non-positive `claimTimeout` is refused at construction.
 *
 * `opts.tombstoneTtl` (a duration string, a number of ms, or `null` to never
 * prune; default `'30d'`) is how long a destruction's grave is kept before
 * pruning. Size it above the longest gap between replica reconciliations, or a
 * forgotten grave lets an id come back.
 *
 * `opts.digest` picks the integrity hash for new pushes: `'sha3-512'` (the
 * default), `'sha256'`, `'sha512'`, `'sha3-256'`, or `'shake256'`. The stored
 * digest is self-describing, so a read verifies with the entry's OWN algorithm
 * and one store may mix them. SHA-3 is not hardware-accelerated where SHA-2 is,
 * so the default trades throughput for its algorithm choice; `'sha256'` buys the
 * throughput back.
 *
 * Every option this constructor accepts is enforced; an unknown one is a
 * config-time TypeError.
 *
 * @example
 *   import { Stash } from "@blamejs/stash";
 *   import { MemoryBackend } from "@blamejs/stash/backends/memory";
 *
 *   const stash = new Stash({ backend: new MemoryBackend(), ttl: "24h" });
 */
// Process-wide live-claim guards, keyed by backend identity (SPEC.md 6,
// single-writer-per-root). Two Stash over the SAME store share ONE guard map, so one
// instance's crash recovery never age-reclaims a claim another instance's live reader
// still holds, which would restore or burn a once-only read out from under it. A backend
// declaring no identity keys by the backend OBJECT instead. The entry survives close(),
// which leaves the store usable, and is released only when the last holder is
// garbage-collected (GUARD_REAP).
const CLAIM_GUARDS = new Map(); // key -> { guard: Map<id, count>, holders: number }
const GUARD_REAP = new FinalizationRegistry((key) => {
  const shared = CLAIM_GUARDS.get(key);
  // The whole entry goes with the last holder, INCLUDING any claims still in the map:
  // with the holder gone those claims are stale, and keeping them would make a subsequent
  // Stash treat an abandoned backend claim as live and never reclaim it (stuck ECLAIMED).
  // A concurrent binder that raced this collection has already re-incremented `holders`.
  if (shared !== undefined && (shared.holders -= 1) <= 0) CLAIM_GUARDS.delete(key);
});

export class Stash extends EventEmitter {
  #backend;
  #ttlMs = null;
  #sweepTimer = null;
  #sweepInFlight = null;
  #maxSize = null;
  #maxTotal = null;
  #maxEntries = null;
  #onPopFailure = "restore";
  #claimTimeoutMs = 0;
  #tombstoneTtlMs = null;
  // The integrity hash for NEW writes only; reads are self-describing, verifying with
  // the entry's own stored algorithm.
  #digestAlgo = DEFAULT_DIGEST;
  // The lazy crash-recovery scan, memoized: resolved on the first public verb, never in
  // the constructor (no I/O there). It re-runs once a claim a prior scan skipped for being
  // younger than the lease would have aged past it; #nextRecoverAt is that deadline.
  #recovered = null;
  #nextRecoverAt = 0;
  // Bumped by every scan start and every forced reschedule: a scan publishes its computed
  // deadline only if the counter is unchanged, so a racing #scheduleRecover is not lost.
  #recoverGen = 0;
  // In-flight store() chains by id: serializing same-id inserts stops two replicas both
  // passing the reconcile and racing the write (SPEC.md 4.4 write-once).
  #storeChains = new Map();
  // The claims held over THIS store by a live pop / budgeted-read drain, by id. #recover NEVER
  // age-reclaims one: the wall clock, which a forward step can jump, is meaningful only for an
  // ORPHAN with no live holder. SHARED per store (the CLAIM_GUARDS registry), so two Stash over
  // one root see each other's live reads. An id is guarded from the instant acquisition BEGINS,
  // before backend.claim writes the on-disk record, until the claim resolves. A crash starts the
  // next process with an EMPTY map, so a genuine prior-run orphan is still reclaimed by age.
  // REFCOUNTED: two readers can both begin acquisition, and the loser's release must not clear
  // the winner's guard.
  #liveClaims; // id -> live-holder count; bound LAZILY (#ensureGuardBound) from the shared registry

  // Bind to the store's shared guard once, on the first #recover: a backend's canonical
  // identity (the disk root's realpath, a memory instance tag) is stable only after its
  // lazy init has run. A backend declaring none keys by the backend OBJECT, so two Stash
  // over one instance still coordinate. GUARD_REAP releases the entry when this instance
  // is garbage-collected, never on close(), which leaves the store usable.
  #ensureGuardBound() {
    if (this.#liveClaims !== undefined) return;
    const key = this.#backend.identity !== undefined ? this.#backend.identity : this.#backend;
    let shared = CLAIM_GUARDS.get(key);
    if (shared === undefined) {
      shared = { guard: new Map(), doomed: new Set(), removals: new Map(), holders: 0 };
      CLAIM_GUARDS.set(key, shared);
    }
    shared.holders += 1;
    this.#liveClaims = shared.guard;
    this.#doomed = shared.doomed;
    this.#removals = shared.removals;
    // GUARD_REAP holds `key`, so the reaper needs no field on this instance.
    GUARD_REAP.register(this, key);
  }
  #guardClaim(ref) {
    this.#liveClaims.set(ref, (this.#liveClaims.get(ref) ?? 0) + 1);
  }
  #unguardClaim(ref) {
    const n = (this.#liveClaims.get(ref) ?? 0) - 1;
    if (n > 0) this.#liveClaims.set(ref, n);
    else {
      this.#liveClaims.delete(ref);
      this.#doomed.delete(ref);
    }
  }
  // The live-claimed ids a drop or clear destroyed mid-claim, SHARED like #liveClaims. That
  // destroyer writes the grave and emits the one event; the claim's terminal step then only
  // finishes the physical cleanup (#unlessDoomed). Cleared when the last holder releases.
  // Like #liveClaims, it is in-process state: a drop in one process does not see a claim
  // held by a Stash in another process over the same disk root, and that claim resolves on
  // its own terms, so both processes can emit for the entry.
  #doomed;
  // A drop / clear's remove of `ref`. A true result is the single destruction witness: the
  // id is marked doomed as soon as that result settles, before the destroyer emits, when a
  // Stash in this process holds a live claim on it. A failed or false-returning remove marks
  // nothing, so the claim resolves on its own terms.
  // While the remove runs, `#removals` holds a promise that settles once its result has
  // been recorded, so a claim's terminal step can wait for every in-flight remove of the id.
  async #removeWitnessed(ref) {
    const removal = this.#backend.remove(ref);
    const witnessed = removal.then(
      (removed) => {
        if (removed && this.#liveClaims.has(ref)) this.#doomed.add(ref);
      },
      () => {},
    );
    const prior = this.#removals.get(ref);
    const tracked = prior === undefined ? witnessed : Promise.all([prior, witnessed]);
    this.#removals.set(ref, tracked);
    await tracked;
    if (this.#removals.get(ref) === tracked) this.#removals.delete(ref);
    return removal;
  }
  // The removal shared state, keyed alongside #doomed.
  #removals;
  // True when a drop / clear's remove destroyed `ref` while it was claimed. It first waits
  // for every remove of `ref` already in flight. A remove that starts after the caller's
  // commit or restore returned finds the entry gone and reports false.
  async #destroyedElsewhere(ref) {
    const pending = this.#removals.get(ref);
    if (pending !== undefined) await pending;
    return this.#doomed.has(ref);
  }
  // Force the next public verb to re-run #recover, after a claim resolution FAULTS
  // (restore / commit / burn threw): the on-disk claim may still stand as an orphan with
  // no scan scheduled to reclaim it, stranding it ECLAIMED until restart. A due deadline
  // is harmless when nothing orphaned.
  #scheduleRecover() {
    this.#nextRecoverAt = 0;
    this.#recoverGen++;
  }

  constructor(opts) {
    super();
    options(opts, "new Stash", {
      allowed: [
        "backend",
        "ttl",
        "sweepInterval",
        "maxSize",
        "maxEntries",
        "maxTotal",
        "onPopFailure",
        "claimTimeout",
        "tombstoneTtl",
        "digest",
      ],
    });
    const backend = opts.backend;
    if (backend === null || typeof backend !== "object") {
      throw new TypeError("new Stash: a backend is required");
    }
    for (const method of REQUIRED_BACKEND_METHODS) {
      if (typeof backend[method] !== "function") {
        throw new TypeError("new Stash: backend is missing '" + method + "'");
      }
    }
    this.#backend = backend;
    // The live-claim guard binds lazily on the first #recover; see #ensureGuardBound.
    this.#ttlMs = parse(opts.ttl, "new Stash: ttl");
    // A valid duration can still place expiresAt past the safe integer range, which make()
    // refuses at push: catch an unusable DEFAULT at construction instead.
    if (this.#ttlMs !== null && !Number.isSafeInteger(Date.now() + this.#ttlMs)) {
      throw new TypeError("new Stash: ttl places expiresAt beyond the safe integer range");
    }
    // Bounds resolve before the sweep timer is armed, so a malformed one leaves no timer.
    this.#maxSize = _positiveBytes(opts.maxSize, "new Stash: maxSize");
    this.#maxTotal = _positiveBytes(opts.maxTotal, "new Stash: maxTotal");
    this.#maxEntries = _positiveCount(opts.maxEntries, "new Stash: maxEntries");
    // A maxSize above maxTotal can never bind (an empty store admits at most maxTotal
    // bytes), so it is dead configuration: refuse it at boot rather than accept a check
    // that never fires (SPEC.md 8.2).
    if (this.#maxSize !== null && this.#maxTotal !== null && this.#maxSize > this.#maxTotal) {
      throw new TypeError(
        "new Stash: maxSize must not exceed maxTotal -- a per-entry cap above the whole-store cap can never bind",
      );
    }
    // Both validated at config time: an unrecognized onPopFailure or a NaN claimTimeout
    // is a silently disabled recovery scan.
    this.#onPopFailure =
      opts.onPopFailure === undefined
        ? "restore"
        : oneOf(opts.onPopFailure, "new Stash: onPopFailure", ON_POP_FAILURE);
    const claimTimeout =
      opts.claimTimeout === undefined ? DEFAULT_CLAIM_TIMEOUT : opts.claimTimeout;
    this.#claimTimeoutMs = parse(claimTimeout, "new Stash: claimTimeout");
    // Strictly POSITIVE: at zero or below, staleAt == claimedAt, so recovery would treat
    // EVERY orphan as abandoned the instant it appears, collapsing the grace to nothing.
    if (this.#claimTimeoutMs === null || this.#claimTimeoutMs <= 0) {
      throw new TypeError("new Stash: claimTimeout must be a positive duration");
    }
    // A grave is pruned once older than this (SPEC.md 4.4), riding the same sweeper as
    // expiry. An explicit null never prunes; an absent option inherits '30d'.
    const tombstoneTtl =
      opts.tombstoneTtl === undefined ? DEFAULT_TOMBSTONE_TTL : opts.tombstoneTtl;
    this.#tombstoneTtlMs = parse(tombstoneTtl, "new Stash: tombstoneTtl");
    // The integrity hash for new writes: a registry algorithm (DEFAULT_DIGEST).
    this.#digestAlgo = assertDigestAlgo(
      opts.digest === undefined ? DEFAULT_DIGEST : opts.digest,
      "new Stash: digest",
    );
    const sweepMs = parse(opts.sweepInterval, "new Stash: sweepInterval");
    if (sweepMs !== null) {
      if (sweepMs <= 0 || sweepMs > C.TIME.MAX_TIMER_MS) {
        throw new TypeError(
          "new Stash: sweepInterval must be a positive duration no larger than " +
            C.TIME.MAX_TIMER_MS +
            "ms (Node's timer ceiling); for anything rarer, call prune() on your own schedule",
        );
      }
      // Arming a timer is not I/O (the sweep callback is); unref() so it never pins the loop.
      this.#sweepTimer = setInterval(() => {
        void this.#sweep();
      }, sweepMs);
      this.#sweepTimer.unref();
    }
  }

  // The background tick. #sweepInFlight is BOTH the overlap guard (a non-null value means
  // a prune is still running, so a slow backend and a short interval cannot stack sweeps)
  // AND the promise close() awaits, so no sweep-side deletion lands after close() resolves.
  // It is a settled-tracker, resolving on success or failure and never rejecting, so
  // close() cannot inherit a sweep failure.
  async #sweep() {
    if (this.#sweepInFlight !== null) return;
    const work = this.prune();
    this.#sweepInFlight = work.then(
      () => {},
      () => {},
    );
    // A rejected background sweep must never become an unhandledRejection, fatal on Node:
    // it surfaces as 'sweepError', never 'error', which crashes the process unhandled, and
    // #emitSweepError contains a listener's own failure. #emitSweepError returns
    // synchronously, so the guard below always clears; a stuck guard would silently disable
    // the janitor for the process's life.
    await work.catch((err) => this.#emitSweepError(err));
    this.#sweepInFlight = null;
  }

  // Emit 'sweepError' such that NO listener can crash the janitor. EventEmitter.emit does
  // not await listeners, so an ASYNC listener's rejection would escape as an
  // unhandledRejection and a SYNCHRONOUS throw would propagate out of the emit: each
  // listener runs in its own promise chain, whose one trailing `.catch` contains both. A
  // handler's own failure is dropped here, the one sanctioned drop-silent sink.
  // rawListeners preserves `once` semantics (its wrapper self-removes when called).
  #emitSweepError(err) {
    for (const listener of this.rawListeners("sweepError")) {
      Promise.resolve()
        .then(() => listener.call(this, err))
        .catch(() => {});
    }
  }

  // The shared lazy-expiry gate for apply, show, and pop: an expired entry is dropped in
  // passing (remove BEFORE the throw) and reported RefNotFound, so it is never served even
  // if no sweep ever runs. A failing remove (a read-only grant, a vanished dir) propagates
  // LOUDLY, never swallowed into the not-found verdict (SPEC.md 2.1).
  async #statLive(ref) {
    const entry = await this.#backend.stat(ref);
    if (isExpired(entry, Date.now())) {
      // A live claim holds it: hidden from every surface, but left for the claim's own
      // resolution, which restores, spends, or destroys it under one event (SPEC.md 6).
      // Only claims held in this process are seen here; an entry claimed by another
      // process over the same disk root goes through the remove below like any other.
      if (this.#liveClaims.has(ref)) throw new RefNotFound();
      // The remove returning true is the single 'I destroyed it' witness, so a lazy reap
      // racing the sweeper emits 'expired' exactly once (SPEC.md 4.3).
      if (await this.#backend.remove(ref)) this.#emit("expired", entry);
      throw new RefNotFound();
    }
    return entry;
  }

  // Emit a lifecycle event with a DEFENSIVE COPY of the Entry (SPEC.md 4.3): a listener
  // that mutates its payload must never reach a later show()/list(). The single copy site,
  // called at the verb layer AFTER the change commits, so store() stays silent by
  // construction.
  #emit(event, entry) {
    this.emit(event, structuredClone(entry));
  }

  // A live claim means a pop or budgeted read holds the entry, so a concurrent reader
  // rejects RefClaimed HERE, before the advisory stat opens the sidecar the holder is
  // rewriting: on Windows an open reader blocks that rewrite's rename and livelocks the
  // holder. Advisory only, since the claim's own link is the authoritative mutex, so a
  // claim taken after this probe still serializes, rejecting at the link instead.
  async #rejectIfClaimed(ref) {
    if (await this.#backend.isClaimed(ref)) throw new RefClaimed();
  }

  // The lazy crash-recovery scan (SPEC.md 6). Memoized: it runs on the first public verb, never
  // in the constructor (no I/O there), and re-runs only once a claim it skipped for being too
  // young would have aged past the lease. It resolves every STALE ORPHAN, a claim no live
  // in-process reader holds (#liveClaims) and older than claimTimeout; a claim a live drain
  // holds is skipped, since the wall clock a forward step can jump says nothing about it. A
  // sidecar-less claim is an interrupted commit, so recovery FINISHES the deletion; otherwise
  // the entry is resolved per onPopFailure. It drives backend methods only, so it cannot recurse
  // into a public verb, and a failed scan clears the memo so the next verb retries.
  #recover() {
    // Memoizing forever would strand a claim that looked live at the first op (a crash
    // within claimTimeout) as ECLAIMED until restart. The memo stays shared until
    // #nextRecoverAt, so concurrent ops still run one scan.
    if (this.#recovered !== null && Date.now() < this.#nextRecoverAt) return this.#recovered;
    this.#nextRecoverAt = Infinity; // claim this re-scan for concurrent ops to share
    const gen = ++this.#recoverGen; // this scan's generation; a forced reschedule during it bumps this
    this.#recovered = (async () => {
      const claims = await this.#backend.listClaims();
      this.#ensureGuardBound(); // listClaims has run the backend's lazy init -> its identity is now stable
      const now = Date.now();
      let nextAt = Infinity;
      for (const { id, claimedAt } of claims) {
        const staleAt = claimedAt + this.#claimTimeoutMs;
        // A claim a LIVE in-process reader holds is NEVER reclaimed by age: consulting the
        // wall clock for a held claim is what a forward clock step corrupts, aging a young
        // claim past the lease so recovery burns or restores a once-only read mid-drain.
        // STILL schedule a re-scan for when it would age out: a drain that drops its guard
        // WITHOUT resolving the on-disk claim (a faulted commit or restore) leaves an orphan,
        // and that pending scan is what reclaims it. A claim already past its lease re-checks
        // one lease out, never on every verb. A prior process's orphans are absent from THIS
        // set and still age-reclaimed below.
        if (this.#liveClaims.has(id)) {
          nextAt = Math.min(nextAt, staleAt > now ? staleAt : now + this.#claimTimeoutMs);
          continue;
        }
        if (now < staleAt) {
          // still within the lease (maybe a live pop); leave it,
          nextAt = Math.min(nextAt, staleAt); // but re-scan once it would age past the lease
          continue;
        }
        let hasSidecar = true;
        let corruptSidecar = false;
        try {
          await this.#backend.stat(id);
        } catch (err) {
          if (err instanceof RefNotFound) hasSidecar = false;
          // A corrupt sidecar on a stale orphan claim (a crash mid consumeRead rewrite) is
          // a DAMAGED entry recovery must RESOLVE, never rethrow: every verb runs #recover
          // first, so a rethrow poisons the memo and one corrupt claimed entry becomes a
          // permanent store-wide EINTEGRITY denial. The entry is unreadable, so restore is
          // meaningless; recovery finishes the destruction, writing no grave, since damage
          // repair is not a lifecycle destruction and a healthy replica may still reconcile
          // the id back. Genuine fs damage stays loud: the commit(id) / isClaimed(id) below
          // re-drive the backend's containment.
          else if (err instanceof IntegrityError) corruptSidecar = true;
          else throw err;
        }
        // A grave already standing means a terminal #destroy wrote it and crashed BEFORE
        // its commit: the destruction was decided, so recovery FINISHES it and never
        // restores, which would resurrect an entry a grave says is gone (SPEC.md 4.2, 4.4).
        // A sidecar-less claim is the same interrupted commit to finish.
        const graved = await this.#backend.hasTombstone(id);
        // Resolve the stale claim, tolerating one another process's recovery over the same root
        // already resolved between our listClaims and here. Recovery's contract is only that no
        // stale claim REMAINS, so the verdict is the claim's presence: gone means the work is
        // done, while a claim still standing after a failed restore/commit is a real fault,
        // propagated to clear the memo for a retry.
        try {
          if (graved || !hasSidecar || corruptSidecar) {
            await this.#backend.commit(id); // finish a decided/interrupted destruction, or reap an unreadable one
          } else {
            // Restore a stale orphan carrying NO durable destruction intent. This drops no burn:
            // a live 'burn' writes its grave DURABLY BEFORE committing, so it lands in the
            // `graved` branch above and its verdict survives a faulted commit. What reaches HERE
            // is a crash orphan, whose outcome is unknowable, or a burn whose grave write
            // PERMANENTLY faulted, and a burn cannot be completed without a grave: committing
            // without one would let a replica store() the id back (SPEC.md 4.4). Across a crash
            // the store cannot tell a read that observed bytes from one that read nothing, so
            // restoring beats silently destroying possibly-unread bytes.
            await this.#backend.restore(id);
          }
        } catch (err) {
          if (await this.#backend.isClaimed(id)) throw err;
        }
      }
      // Publish this scan's deadline ONLY if no forced reschedule raced it: a
      // #scheduleRecover during the scan set the deadline due for an orphan this scan could
      // not have seen, and this stale nextAt must not overwrite that forced re-scan.
      if (gen === this.#recoverGen) this.#nextRecoverAt = nextAt;
    })().catch((err) => {
      this.#recovered = null;
      this.#nextRecoverAt = 0;
      throw err;
    });
    return this.#recovered;
  }

  // The ONE claimed-read path, shared by pop and budgeted apply (SPEC.md 4.1 "same commit path").
  // The claim serializes concurrent readers (the loser gets RefClaimed), expiry is re-checked on
  // the CLAIMED entry, authoritative because a TTL can lapse between the advisory pre-check and
  // winning the claim, and the stream is digest-verified. A full drain with a matching digest runs
  // `onCommit(claimedEntry)`; any other outcome restores the claim, or burns it under
  // onPopFailure: 'burn'. pop and budgeted apply differ only in onCommit.
  async #claimedRead(ref, onCommit, destruction) {
    // Guard BEFORE acquisition: backend.claim writes the on-disk claim during its own awaits, so
    // a concurrent #recover would see a fresh claim with no live holder and, on a forward
    // wall-clock step aging it past claimTimeout, restore or burn it out from under the reader,
    // handing the same once-only bytes to a second reader. A failed claim releases the guard.
    this.#guardClaim(ref);
    let entry, source;
    try {
      ({ entry, source } = await this.#backend.claim(ref));
    } catch (err) {
      this.#unguardClaim(ref);
      throw err;
    }
    if (isExpired(entry, Date.now())) {
      _dispose(source);
      try {
        await this.#backend.restore(ref);
        if (await this.#backend.remove(ref)) this.#emit("expired", entry); // lazy-drop, witnessed; expiry writes NO grave
      } catch (err) {
        this.#scheduleRecover(); // a faulted restore leaves the claim an orphan -- ensure a re-scan reclaims it
        throw err;
      } finally {
        // Drop the guard whether the restore/remove resolved OR faulted: a faulted restore
        // leaves the claim standing as an ORPHAN, and #recover can reclaim it only once
        // this process is no longer flagged as its live holder.
        this.#unguardClaim(ref);
      }
      throw new RefNotFound();
    }
    return _verifiedStream(entry, source, {
      // Drop the live-holder guard once the verdict RESOLVES the claim, never before, and
      // in a `finally` so a resolution fault still releases it: a claim a faulted commit
      // left standing is the orphan #recover resolves later. The verdict fires exactly once
      // (the `resolved` latch), so exactly one branch runs and drops the id.
      onCommit: async () => {
        try {
          await this.#unlessDoomed(ref, () => onCommit(entry));
        } catch (err) {
          this.#scheduleRecover();
          throw err;
        } finally {
          // a faulted commit leaves an interrupted destruction orphan
          this.#unguardClaim(ref);
        }
      },
      // 'burn' destroys the entry the read could not consume through the SAME
      // grave-then-commit-then-emit terminal a successful drain runs, so a burned entry
      // leaves a grave (SPEC.md 4.4) and is never destroyed silently (SPEC.md 4.3).
      // 'restore' returns the entry, which survives, so it writes no grave and emits nothing.
      onFail: async () => {
        try {
          await this.#unlessDoomed(ref, () =>
            this.#onPopFailure === "burn"
              ? this.#destroy(ref, entry, destruction.cause, destruction.event)
              : this.#backend.restore(ref),
          );
        } catch (err) {
          this.#scheduleRecover();
          throw err;
        } finally {
          // a faulted burn/restore leaves the claim an orphan
          this.#unguardClaim(ref);
        }
      },
    });
  }

  // The shared terminal destruction of a claimed read (pop, a budget-exhausting apply, or
  // either one burned): write the grave FIRST (SPEC.md 4.4), then commit the deletion. A
  // crash between grave and commit leaves a tombstoned-but-present entry, which store()
  // already refuses; the reverse order would resurrect (CWE-459). It resolves to the
  // emission, which #unlessDoomed runs only when no drop / clear's remove destroyed the
  // entry first.
  async #destroy(ref, entry, cause, event) {
    await this.#backend.writeTombstone(ref, makeTombstone(ref, cause));
    await this.#backend.commit(ref);
    return () => this.#emit(event, entry);
  }

  // Resolve a claim through `settle`, unless a drop / clear's remove destroyed the claimed
  // entry mid-claim. That remove's true result is the destruction witness: its destroyer
  // wrote the grave and emits, so the claim then resolves without a second event, grave,
  // debit, or restore, and only commits away what the backend still holds for it (a
  // RefNotFound there means nothing is left). A settle that loses the race to that remove
  // fails with RefNotFound and takes the same path, and so does a settle that succeeds
  // while that remove is still in flight. A settle that ran #destroy resolves to its
  // emission: this method runs it when no remove won, and issues no further commit when
  // one did, since #destroy's own commit already succeeded.
  async #unlessDoomed(ref, settle) {
    if (!this.#doomed.has(ref)) {
      let emit;
      try {
        emit = await settle();
      } catch (err) {
        if (!(err instanceof RefNotFound) || !(await this.#destroyedElsewhere(ref))) throw err;
      }
      if (!(await this.#destroyedElsewhere(ref))) {
        if (typeof emit === "function") emit();
        return;
      }
      if (typeof emit === "function") return;
    }
    try {
      await this.#backend.commit(ref);
    } catch (err) {
      if (!(err instanceof RefNotFound)) throw err;
    }
  }

  // The stash-wide capacity gate, and the ONE place maxEntries / maxTotal are enforced. Both
  // a local push and store()'s replication insert charge through it, so a replica is never
  // admitted on terms a push would be refused on. It resolves the maxTotal residual the write
  // streams against, or null when no byte bound applies, and throws StashFull otherwise.
  //
  // The two scans do not collapse. prune() MUST run first, because the residual is charged
  // against the LIVE footprint: a total still counting an expired entry rejects an entry that
  // fits once the dead one is reaped. stats() then totals the PHYSICAL footprint, blob plus
  // sidecar PLUS the orphan and sidecar-less claim blobs list() never sees, the maxTotal-bypass
  // accounting only a layout walk can do. Across DIFFERENT ids the stats read and the write
  // are not atomic, so concurrent inserts can overshoot by the in-flight count.
  async #chargeCapacity(entry) {
    if (this.#maxEntries === null && this.#maxTotal === null) return null;
    await this.prune();
    const stats = await this.#backend.stats();
    if (this.#maxEntries !== null && stats.entries >= this.#maxEntries) {
      throw new StashFull();
    }
    if (this.#maxTotal === null) return null;
    // maxTotal bounds the stored footprint, blob plus sidecar, so this entry's own metadata is
    // charged before the blob streams: otherwise unbounded `meta` (or an endless run of
    // zero-byte blobs, each still costing a sidecar) slips past the limit.
    //
    // The DIGEST is measured at the width it will be stored at, not the `null` a fresh push
    // still carries. The backend finalizes it after the blob streams, so measuring the entry
    // as-is under-counts the sidecar by the whole hex string: 69 bytes while the default was
    // sha256, and 135 under a 512-bit default. That is how a longer digest would quietly widen
    // a bound this comment promises. Charging the finalized width makes the bound a property
    // of the arithmetic rather than of whichever algorithm happens to be the default.
    //
    // The width comes from hashing nothing with the entry's own algorithm, so it tracks the
    // registry rather than restating a hex length the registry already owns.
    //
    // `size` is deliberately left at its pre-write 0. It grows by at most the digits of the
    // final byte count, so the charge still under-counts a stored entry by under twenty bytes
    // and NEVER over-counts one, which is what stops this check rejecting an entry that would
    // have fit. Trading that guarantee away to close a sixteen-byte gap would be the wrong way
    // round.
    const algo = algoOf(entry.digest) ?? this.#digestAlgo;
    const measured = isValidDigest(entry.digest)
      ? entry
      : { ...entry, digest: finalize(digestHash(algo), algo) };
    const sidecarBytes = Buffer.byteLength(JSON.stringify(measured));
    const residual = this.#maxTotal - stats.bytes - sidecarBytes;
    if (residual < 0) throw new StashFull();
    return residual;
  }

  /**
   * @primitive  stash.push
   * @signature  stash.push(source, opts) -> Promise<string>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 5, FIPS 180-4, FIPS 202, RFC 4648, RFC 8259
   * @defends    CWE-330
   * @related    stash.apply, stash.show, stash.drop
   *
   * Store bytes; resolve to the entry's ref. The source may be a Buffer, a
   * Uint8Array, a UTF-8 string, a Readable, or any AsyncIterable of chunks; it
   * streams through to the backend, which computes size and the digest as the bytes
   * pass, using the algorithm chosen at construction (`sha3-512` by default).
   *
   * `opts.meta` is a caller-owned plain object, round-tripped verbatim as JSON and
   * never interpreted. `opts.ttl` overrides the constructor default for this entry
   * (`null` overrides a default back to no expiry); an absent `ttl` inherits it.
   * `opts.reads` is a read budget: a positive integer count of successful `apply`
   * drains after which the entry self-destructs (`null`, the default, is unlimited).
   * A budgeted `apply` spends one credit only on a full, digest-verified drain, so an
   * abandoned or corrupted read costs nothing, and the read that takes the budget to
   * zero destroys the entry. Terms are fixed at push and only move the entry toward
   * destruction: there is no touch or extend.
   *
   * The ref is random, a capability rather than a content address. Construct-time
   * `maxSize` bounds this entry (`SizeExceeded`, thrown mid-stream), and `maxEntries`
   * / `maxTotal` bound the whole store (`StashFull`); a rejected push leaves nothing
   * behind.
   *
   * @example
   *   const ref = await stash.push(ciphertext, { meta: { kind: "drop" }, ttl: "1h" });
   */
  async push(source, opts = {}) {
    options(opts, "push", {
      allowed: ["meta", "ttl", "reads"],
      unimplemented: UNIMPLEMENTED_PUSH_OPTIONS,
    });
    let meta = {};
    if (opts.meta !== undefined) {
      plainObject(opts.meta, "push: meta");
      // meta is stored as its JSON round-trip, and serialization hooks (a Date's
      // toJSON, a caller's own) can change the type between the check above and the
      // bytes stored, landing an entry the read path refuses.
      const serialized = JSON.stringify(opts.meta);
      meta = plainObject(serialized === undefined ? null : JSON.parse(serialized), "push: meta");
    }
    // Presence-keyed: an explicit ttl (including null) overrides the constructor default,
    // an absent key inherits it; a malformed one throws before anything is stored.
    const ttlMs = opts.ttl !== undefined ? parse(opts.ttl, "push: ttl") : this.#ttlMs;
    // make() validates reads: a positive integer, or null for unlimited.
    const reads = opts.reads === undefined ? null : opts.reads;
    const chunks = _toChunkSource(source);
    await this.#recover();
    // Stash-wide bounds are enforced in the policy layer before the backend stores a byte:
    // maxEntries as a hard pre-check, maxTotal mid-stream against the residual headroom
    // (see _boundedSource). #chargeCapacity owns the expiry-aware reasoning and the
    // arithmetic.
    const id = generate();
    const entry = make(id, meta, ttlMs, reads);
    const residual = await this.#chargeCapacity(entry);
    // Stamp the chosen algorithm's pending marker ("<algo>:") so the selection travels
    // INSIDE the documented write(id, source, entry) contract, which the backend reads back
    // (algoOf). An out-of-band write() argument would let a custom backend built to the
    // 3-arg contract silently drop the selection back to the default.
    entry.digest = digestMarker(this.#digestAlgo);
    const bounded = _boundedSource(chunks, this.#maxSize, residual);
    const stored = await this.#backend.write(id, bounded, entry);
    this.#emit("pushed", stored); // after the write commits (SPEC.md 4.3)
    return stored.id;
  }

  /**
   * @primitive  stash.apply
   * @signature  stash.apply(ref) -> Promise<Readable>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4, FIPS 180-4, FIPS 202
   * @defends    CWE-354, CWE-208
   * @related    stash.push, stash.show
   *
   * Stream an entry's bytes without destroying it. The stream is
   * digest-verified as it drains: a corrupted blob errors the stream with
   * `IntegrityError` rather than delivering silently bad bytes. An unknown OR
   * expired ref rejects with `RefNotFound` -- an expired entry is dropped in
   * passing and never streamed, even if the sweeper has not run; a malformed
   * ref dies at the whitelist with `InvalidRef` before any storage access.
   *
   * An entry pushed with a read budget (`reads`) is instead claimed for the
   * read: concurrent readers serialize through the claim (the loser rejects
   * `RefClaimed`), one credit is spent only on a full, digest-verified drain,
   * and the read that exhausts the budget destroys the entry through the same
   * path as `pop`. An unbudgeted entry stays lock-free and pays nothing for the
   * feature.
   *
   * @example
   *   const readable = await stash.apply(ref);
   *   for await (const chunk of readable) sink.write(chunk);
   */
  async apply(ref) {
    assertValid(ref);
    await this.#recover();
    await this.#rejectIfClaimed(ref); // a contended reader bails before opening the sidecar
    const entry = await this.#statLive(ref);
    // A budgeted entry serializes through the claim mechanism, so two concurrent reads
    // cannot both spend the last credit. An unbudgeted entry stays lock-free.
    if (entry.reads !== null) {
      return this.#claimedRead(
        ref,
        async (claimed) => {
          if (claimed.readsLeft === 1) {
            return this.#destroy(ref, claimed, "spent", "dropped"); // the last credit: grave + commit, then 'dropped'
          }
          await this.#backend.consumeRead(ref); // persist the debit BEFORE restoring
          await this.#backend.restore(ref); // a non-terminal read destroys nothing -- no grave, no event
        },
        { cause: "spent", event: "dropped" },
      ); // a burned budgeted read destroys the entry -> 'dropped'
    }
    const source = await this.#backend.read(ref);
    // The gate above and this open are two awaits apart, so a short TTL can lapse in
    // between: re-check at serve time, and drop an entry expired NOW rather than serve it.
    // The verdict is fixed here, synchronously before the return, so an entry that lapses
    // mid-drain afterward is not killed mid-stream.
    if (isExpired(entry, Date.now())) {
      _dispose(source);
      // The same remove-witness the lazy gate uses, so an entry lapsing in the stat/read
      // window is still audited exactly once and never reaped silently (SPEC.md 4.3).
      if (await this.#backend.remove(ref)) this.#emit("expired", entry);
      throw new RefNotFound();
    }
    return _verifiedStream(entry, source);
  }

  /**
   * @primitive  stash.pop
   * @signature  stash.pop(ref) -> Promise<Readable>
   * @since      0.1.7
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 6, FIPS 180-4, FIPS 202
   * @defends    CWE-362, CWE-367, CWE-354
   * @related    stash.apply, stash.drop
   *
   * Read an entry's bytes and destroy it: the stream is digest-verified as it
   * drains, and the entry is deleted the instant it drains cleanly -- bytes out
   * once, then gone. Pop ignores any read budget; it is terminal by definition.
   *
   * The claim is atomic at the filesystem: two concurrent `pop(ref)` race on the
   * claim, exactly one wins and drains, the other rejects `RefClaimed`
   * (`ECLAIMED`). A stream that errors, is destroyed early, or fails its digest
   * is resolved by `onPopFailure` -- `'restore'` (default) returns the entry so
   * the read can be retried, `'burn'` destroys it anyway. An unknown, expired, or
   * already-claimed ref rejects (`RefNotFound` / `RefClaimed`); a malformed ref
   * dies at the whitelist with `InvalidRef` before any storage access.
   *
   * @example
   *   const readable = await stash.pop(ref); // drains, then the entry is gone
   *   for await (const chunk of readable) sink.write(chunk);
   */
  async pop(ref) {
    assertValid(ref);
    await this.#recover();
    await this.#rejectIfClaimed(ref); // a concurrent pop's loser bails before the advisory stat
    await this.#statLive(ref); // advisory: reject an expired entry with zero claim taken
    return this.#claimedRead(
      ref,
      (entry) => this.#destroy(ref, entry, "pop", "popped"), // grave + commit + 'popped'
      { cause: "pop", event: "popped" },
    ); // a burned pop's delete also lands -> a 'pop' grave, 'popped'
  }

  /**
   * @primitive  stash.store
   * @signature  stash.store(entry, source) -> Promise<boolean>
   * @since      0.1.9
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 4.4, FIPS 180-4, FIPS 202, RFC 8259
   * @defends    CWE-345, CWE-354, CWE-20
   * @related    stash.push, stash.tombstones, stash.drop
   *
   * The replication-grade insert (SPEC.md 4.4): file an already-created entry,
   * preserving its identity where `push` mints a new one. The caller supplies the
   * COMPLETE `Entry` -- `id`, `createdAt`, `expiresAt`, `reads`, `readsLeft`,
   * `digest`, `meta` -- and it lands verbatim; the bytes are verified against the
   * supplied `digest` and `size` as they stream, so transfer corruption is caught
   * on the way in and nothing lands. It proceeds in a normative order:
   *
   *   1. a malformed id is `InvalidRef`, before any storage access;
   *   2. a tombstoned id returns `false`, writing nothing -- a destroyed id never
   *      comes back;
   *   3. an entry already past its `expiresAt` is a no-op `false` (the dead travel
   *      as dead, and get no grave);
   *   4. an identical live entry (same id, same digest) is an idempotent no-op
   *      `false`, so a retry-based sync is free;
   *   5. same id, different digest is an `IntegrityError` -- corruption, not a
   *      merge; the existing entry is untouched;
   *   6. otherwise it writes exactly like `push`, every field the caller's, and
   *      returns `true`.
   *
   * A genuinely new entry (past step 5) is charged against the stash bounds exactly
   * as a `push` is: a replica larger than `maxSize` aborts `SizeExceeded`, and one
   * past `maxEntries` / `maxTotal` is refused `StashFull` -- replication input does
   * not get to slip the configured capacity. Concurrent stores of the SAME id are
   * serialized so two conflicting replicas cannot both land (the loser sees the
   * winner and reconciles: idempotent-`false` or an `IntegrityError`).
   *
   * `store` emits NO event: a sync daemon that heard its own writes would echo them
   * back forever, so the silence removes that bug class here rather than in every
   * caller. The replicated entry is untrusted input -- a shape violation, a digest
   * that is not a well-formed `<algo>:<hex>` for a registry algorithm, an incoherent
   * read budget, or a non-plain `meta` is an `IntegrityError`, never a partial write.
   *
   * A read budget is enforced per store, so two replicas of a `reads: 1` entry can
   * each serve one full read before their tombstones converge -- exactly-once
   * becomes eventually-once. Serve reads from a single node (cold standby) unless
   * that weaker guarantee is a deliberate choice.
   *
   * @example
   *   for (const e of await primary.list()) await replica.store(e, bytesFor(e.id));
   */
  async store(rawEntry, source) {
    // The replicated entry and its bytes are BOTH untrusted. Argument shape is a
    // config-time TypeError; every verdict on the entry's CONTENT past that is a typed
    // IntegrityError, since replicated bytes are stored input, not a caller argument.
    plainObject(rawEntry, "store: entry");
    // Step 1: a malformed id dies at the whitelist BEFORE any backend access, so this MUST
    // precede the store chain and #recover(), which touch the backend.
    assertValid(rawEntry.id);
    const chunks = _toChunkSource(source);
    const ref = rawEntry.id;
    // Serialize concurrent store()s of the SAME id: unserialized, memory would
    // last-writer-win and disk would raw-EEXIST on the shared blob tmp, neither honoring
    // write-once or the digest-conflict verdict (SPEC.md 4.4). Chaining makes the loser run
    // AFTER the winner lands and reconcile against it (idempotent false, or an
    // IntegrityError on a different digest).
    const prior = this.#storeChains.get(ref);
    const mine = (async () => {
      if (prior) await prior; // await my turn; prior is the never-rejecting chain tail
      return this.#storeOne(rawEntry, chunks, ref);
    })();
    const tail = mine.catch(() => {}); // the tail never rejects, so a failed store still releases the next in line
    this.#storeChains.set(ref, tail);
    try {
      return await mine;
    } finally {
      if (this.#storeChains.get(ref) === tail) this.#storeChains.delete(ref); // last in line -- bound the map
    }
  }

  // store()'s serialized body: the SPEC.md 4.4 reconcile order (tombstoned -> expired ->
  // identical -> digest-conflict), then the same capacity gate push() applies, since a
  // replicated entry is untrusted, then the verified, bounded write.
  async #storeOne(rawEntry, chunks, ref) {
    await this.#recover();
    // Normalize meta to its STORED form BEFORE validating: the backend persists via
    // JSON.stringify, so a meta whose toJSON() returns a scalar would serialize to one and
    // then be rejected by every later show()/list(), a store() that "succeeds" into an
    // unreadable entry. Validating the round-tripped value judges what actually lands; a
    // meta that does not survive it is an IntegrityError, never a bad write.
    const metaJson = JSON.stringify(rawEntry.meta);
    const entry = { ...rawEntry, meta: metaJson === undefined ? undefined : JSON.parse(metaJson) };
    // Full shape of the replicated entry (id re-checked, meta in its stored form).
    assertShape(entry, IntegrityError);

    // Step 2: a tombstoned id never comes back.
    if (await this.#backend.hasTombstone(ref)) return false;
    // Step 3: an entry already past its deadline is dead on arrival: no-op, no grave.
    if (isExpired(entry, Date.now())) return false;
    // Steps 4/5: reconcile against an existing entry. The stat probe swallows ONLY
    // RefNotFound (absent); corruption or an fs fault propagates, never a false.
    let existing = null;
    try {
      existing = await this.#backend.stat(ref);
    } catch (err) {
      if (!(err instanceof RefNotFound)) throw err;
    }
    // Steps 4/5 reconcile on BYTE IDENTITY, not on the algo-tagged digest STRING: in a
    // mixed-algorithm store (first-class per SPEC.md 5) identical bytes carry different
    // digest strings, so the strings cannot decide it.
    if (existing !== null) return this.#reconcileExisting(existing, entry, chunks);

    // Capacity gate: a genuinely new entry is charged exactly as a push is, through the
    // same #chargeCapacity, or a replica past maxSize / maxEntries / maxTotal slips the
    // configured safeguards. Across DIFFERENT ids the stats read and the write are not
    // atomic; the per-id chain makes the SAME id exact.
    const residual = await this.#chargeCapacity(entry);

    // Step 6: write like push, but every field is the caller's. The bytes are bounded
    // mid-stream (_boundedSource) AND verified against the supplied digest and size
    // (_verifiedInbound), since the backend would otherwise self-certify whatever arrives.
    // An over-bound abort or a mismatch throws before the backend's rename, leaving nothing
    // on disk (SPEC.md 8). store emits nothing.
    const bounded = _verifiedInbound(_boundedSource(chunks, this.#maxSize, residual), entry);
    // The replicated entry carries its full self-describing digest, so the backend re-hashes
    // with the entry's own algorithm (algoOf): the selection rides in the entry, never an
    // extra argument.
    await this.#backend.write(ref, bounded, entry);
    // TOCTOU (CWE-367): a concurrent pop/drop could dig the grave between the step-2 check
    // and this write landing, and the grave must ALWAYS win, since a store onto a
    // tombstoned id would resurrect it. Re-check AFTER the write; if a grave appeared,
    // remove what was just stored and refuse.
    if (await this.#backend.hasTombstone(ref)) {
      await this.#backend.remove(ref);
      return false;
    }
    return true;
  }

  // store()'s SPEC.md 4.4 step-4/step-5 verdict against an entry already holding this id,
  // keyed on BYTE IDENTITY: same bytes is an idempotent false, different bytes an
  // IntegrityError (corruption, not a merge). BOTH outcomes write NOTHING and leave the
  // existing entry, and its algorithm, untouched.
  async #reconcileExisting(existing, entry, chunks) {
    const existingAlgo = algoOf(existing.digest);
    if (existingAlgo === algoOf(entry.digest)) {
      // Same algorithm: the hex is directly comparable, so a constant-time string compare
      // settles identity without touching the bytes. Same string is step 4, different is
      // step 5.
      if (constantTimeEqual(existing.digest, entry.digest)) return false;
      throw new IntegrityError();
    }
    // Different algorithm (a mixed-algorithm store, SPEC.md 5): the digest STRINGS are
    // incomparable, so re-hash the incoming source under the existing algorithm to decide on the
    // bytes. _verifiedInbound catches a replica that lies about its own manifest, and the
    // existing-algorithm hash then proves byte identity against the stored content. A reconcile
    // writes nothing and charges no maxTotal residual, so it must not reject on a WRITE-path
    // limit: a same-bytes duplicate no-ops even when the current maxSize sits BELOW the stored
    // entry. A differing declared size is a conflict with no re-read; otherwise the EXISTING
    // entry's own trusted size bounds the re-hash, holding a hostile replica without maxSize.
    if (entry.size !== existing.size) throw new IntegrityError();
    const hash = digestHash(existingAlgo);
    let seen = 0;
    for await (const buf of _verifiedInbound(chunks, entry)) {
      seen += buf.length;
      // A stream longer than the stored bytes cannot be identical: bound the drain so a
      // hostile replica cannot stream unboundedly, and treat the overflow as a byte
      // CONFLICT, IntegrityError rather than SizeExceeded, since a reconcile enforces no
      // write limit.
      if (seen > existing.size) throw new IntegrityError();
      hash.update(buf);
    }
    // Self-consistent incoming bytes that reproduce the stored digest under its OWN
    // algorithm ARE the stored content (step 4). Anything else is genuinely different bytes
    // under the same id (step 5).
    if (constantTimeEqual(finalize(hash, existingAlgo), existing.digest)) {
      return false;
    }
    throw new IntegrityError();
  }

  /**
   * @primitive  stash.show
   * @signature  stash.show(ref) -> Promise<Entry>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4
   * @related    stash.list, stash.apply
   *
   * Resolve a ref to its Entry -- metadata only, never contents. The Entry
   * is a defensive copy; entries are write-once and nothing a caller does
   * to the returned object changes the store. An expired ref is dropped in
   * passing and rejects with `RefNotFound`, the same as an unknown one.
   *
   * @example
   *   const entry = await stash.show(ref);
   *   entry.size; // bytes
   */
  async show(ref) {
    assertValid(ref);
    await this.#recover();
    return this.#statLive(ref);
  }

  /**
   * @primitive  stash.has
   * @signature  stash.has(ref) -> Promise<boolean>
   * @since      0.1.8
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 5, SPEC.md 7
   * @related    stash.show, stash.list
   *
   * Existence check without the try/catch `show` needs. `true` for a live entry,
   * `false` for an unknown OR expired ref -- an expired entry is reaped in passing,
   * exactly as `show`/`apply` treat it. A malformed ref still dies at the whitelist
   * with `InvalidRef` BEFORE any backend access -- a boolean query is not a licence
   * to fail open on hostile input -- and a corrupt entry throws `IntegrityError`
   * rather than answering `false`: a clean boolean must never hide corruption.
   *
   * @example
   *   if (await stash.has(ref)) console.log("still present");
   */
  async has(ref) {
    assertValid(ref);
    await this.#recover();
    try {
      await this.#statLive(ref);
      return true;
    } catch (err) {
      if (err instanceof RefNotFound) return false;
      throw err; // IntegrityError / fs faults propagate -- never absorbed into false
    }
  }

  /**
   * @primitive  stash.stats
   * @signature  stash.stats() -> Promise<{ entries, bytes, claimed }>
   * @since      0.1.8
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 9
   * @related    stash.list, stash.verify
   *
   * Aggregate counts, never refs: `entries` (live plus expired-but-unswept),
   * `bytes` (the stored footprint -- each blob plus its metadata), and `claimed`
   * (in-flight pop / budgeted-read claims). The object carries exactly those three
   * keys. Aggregates are the physical truth of the shelf: an expired entry still
   * counts until a read or `prune()` reaps it, so it is a fast lstat walk. A
   * foreign file in the layout fails the aggregate loudly with `IntegrityError`,
   * never a silently smaller number; content integrity (a corrupt sidecar, a
   * bit-flipped blob) is `verify()`'s job, not this count's.
   *
   * @example
   *   const { entries, bytes, claimed } = await stash.stats();
   */
  async stats() {
    await this.#recover();
    return this.#backend.stats();
  }

  /**
   * @primitive  stash.tombstones
   * @signature  stash.tombstones() -> Promise<Tombstone[]>
   * @since      0.1.9
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 4.4
   * @related    stash.store, stash.drop
   *
   * The graves, for reconciliation: `{ id, destroyedAt, cause }[]` -- an id that
   * was destroyed, when (ms since the epoch), and how (`'pop'` / `'drop'` /
   * `'clear'` / `'spent'`), and NOTHING that describes the body (no digest, size,
   * or meta -- recording those would leak the content the destruction removed).
   * Expiry leaves no grave (terms travel with the entry). A query: it inspects the
   * shelf, never moves bytes, and is loud over a corrupt grave, the same as
   * `list()`. Feed each id to a replica's `drop()` to converge the two stores.
   *
   * @example
   *   for (const grave of await primary.tombstones()) await replica.drop(grave.id);
   */
  async tombstones() {
    await this.#recover();
    return this.#backend.listTombstones();
  }

  /**
   * @primitive  stash.verify
   * @signature  stash.verify(opts?) -> Promise<Report>
   * @since      0.1.8
   * @status     stable
   * @spec       SPEC.md 4, FIPS 180-4, FIPS 202
   * @related    stash.stats, stash.prune
   *
   * Audit the store's physical integrity. Dry-run by default: it digest-checks
   * every blob (streamed, never a full-blob read) and reports damage --
   * `digest-mismatch`, `size-mismatch`, `corrupt-sidecar`, `missing-blob`,
   * `orphan-blob`, `orphan-tmp`, `foreign-file`, `stale-claim`, `corrupt-tombstone`
   * -- without touching anything. `{ repair: true }` removes ONLY what it condemns (a
   * damaged entry's blob and sidecar together, or a corrupt grave whose contents fail
   * the parser); healthy entries survive byte-identical, a fresh push's in-flight
   * `.tmp` is spared, and a stale claim is reported but never deleted (resolving it is
   * crash recovery's job -- deleting a restorable claim would be data loss). The Report
   * is `{ scanned, findings: [{ kind, id }], repaired: [{ kind, id }] }`; `id` is the
   * ref for ref-shaped damage (the store is the embedder's) and `null` for a foreign
   * name -- verify never echoes an on-disk path. Damage is a FINDING; an I/O fault (a
   * permission denial, a vanished layout dir) THROWS -- a walk error absorbed into a
   * clean report would be fail-open. A condemnation is physical cleanup of already-
   * broken data, not a lifecycle destruction, so it writes no grave (the SPEC.md 4.4
   * causes are pop/drop/clear/spent); a corrupt grave is simply removed.
   *
   * @example
   *   const report = await stash.verify();      // dry run: report only
   *   await stash.verify({ repair: true });     // remove the condemned
   */
  async verify(opts = {}) {
    options(opts, "verify", { allowed: ["repair"] });
    if (opts.repair !== undefined && typeof opts.repair !== "boolean") {
      throw new TypeError("verify: repair must be a boolean");
    }
    // verify does NOT run #recover: it audits the store as-is and REPORTS stale claims
    // (SPEC.md 6). Recovering here would make a dry run MUTATE and would hide the very
    // stale-claim finding verify exists to surface, so a fresh auditor process whose first
    // call is verify() sees the crash residue rather than silently cleaning it. claimTimeout
    // is policy, passed down so the backend can age a stale claim without owning the
    // threshold; the tmp grace is C.AUDIT.
    return this.#backend.verify({
      repair: opts.repair === true,
      claimTimeoutMs: this.#claimTimeoutMs,
    });
  }

  // `for await (const entry of stash)` is sugar over list(): live entries, expired ones
  // filtered, contents never yielded. Documented on the list() primitive, since a Symbol
  // method has no dotted name for its own wiki page.
  async *[Symbol.asyncIterator]() {
    for (const entry of await this.list()) yield entry;
  }

  /**
   * @primitive  stash.list
   * @signature  stash.list(opts) -> Promise<Entry[]>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4
   * @related    stash.show, stash.clear
   *
   * List every entry's metadata. Contents never appear; a listing that
   * leaked blob bytes would defeat the point of refs as capabilities. Expired
   * entries are filtered out by default; `list({ includeExpired: true })`
   * includes them. `list` only filters -- it never drops, so an expired entry
   * still appears under `includeExpired` until a read verb or `prune()` reaps
   * it.
   *
   * @example
   *   const entries = await stash.list();
   *   entries.length;
   */
  async list(opts = {}) {
    options(opts, "list", { allowed: ["includeExpired"] });
    // A truthy non-boolean (the string "false" from a config parse) must not silently
    // expose the expired entries the default hides. Fail loud, never fail open.
    if (opts.includeExpired !== undefined && typeof opts.includeExpired !== "boolean") {
      throw new TypeError("list: includeExpired must be a boolean");
    }
    await this.#recover();
    const entries = await this.#backend.list();
    if (opts.includeExpired) return entries;
    const now = Date.now();
    return entries.filter((entry) => !isExpired(entry, now));
  }

  /**
   * @primitive  stash.reconcilable
   * @signature  stash.reconcilable() -> Promise<{ entries: Entry[], corrupt: string[] }>
   * @since      0.1.15
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 4.4
   * @related    stash.list, stash.tombstones, stash.store, stash.verify
   *
   * The reconciliation-grade listing for anti-entropy (SPEC.md 4.4). `list()` is
   * loud over a corrupt sidecar -- it fails the whole listing so damage is never
   * silently dropped -- which is right for an audit but wrong for a sync loop: a
   * single unreadable entry would abort enumeration and stall replication of every
   * healthy one. `reconcilable()` returns `{ entries, corrupt }` instead. `entries`
   * is the healthy metadata a full-scan pass replicates (expired entries filtered,
   * exactly as `list()`), and `corrupt` is the ref ids whose sidecars are too damaged
   * to read. One rotten sidecar no longer blocks the sync of sound entries, and the
   * damage is SURFACED, never swallowed -- route `corrupt` to `verify({ repair: true })`
   * to reap it. Structural layout damage (a foreign file in the store) and I/O faults
   * still throw, as in `list()`: neither is a per-entry corruption with a ref to
   * report. Contents never appear; a listing that leaked blob bytes would defeat the
   * point of refs as capabilities.
   *
   * @example
   *   const { entries, corrupt } = await from.reconcilable();
   *   for (const entry of entries) await to.store(entry, bytesFor(entry.id));
   *   if (corrupt.length) console.warn("corrupt sidecars, run verify({ repair: true }):", corrupt.length);
   */
  async reconcilable() {
    await this.#recover();
    const { entries, corrupt } = await this.#backend.listReconcilable();
    const now = Date.now();
    // Filter expired entries exactly as list() does: an expired entry is nonexistent on
    // every read surface (SPEC.md 7), and every replica reaches the same deadline on its own
    // clock, so store() no-ops one anyway. `corrupt` passes through untouched, since a
    // damaged sidecar's terms are unreadable and cannot be judged expired.
    return { entries: entries.filter((entry) => !isExpired(entry, now)), corrupt };
  }

  /**
   * @primitive  stash.drop
   * @signature  stash.drop(ref) -> Promise<boolean>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4
   * @related    stash.clear, stash.list
   *
   * Delete an entry without reading it, and tombstone the id. Resolves `false`
   * when the ref names nothing LIVE -- an absent entry is a fact, not a failure --
   * and `true` when a live entry was destroyed. A malformed ref still throws
   * `InvalidRef`; replication input and typos both die at the whitelist. A corrupt
   * entry is still removed -- drop deletes without reading, so a sidecar too
   * damaged to parse never blocks cleanup; it carries no lifecycle event (there is
   * no whole Entry to hand a listener). `verify` is the audit path that classifies
   * the damage. Dropping an id the store never held still leaves a grave: that is
   * how a tombstone propagates across replicas (SPEC.md 4.4) -- reconciliation
   * `drop`s each of the other node's grave ids, so a destroyed id is refused even
   * on a node that never held it. Expiry is the one exception that leaves no grave
   * (its terms travel with the entry, and every replica reaches the same deadline).
   *
   * @example
   *   await stash.drop(ref); // true -- gone
   */
  async drop(ref) {
    assertValid(ref);
    await this.#recover();
    // stat BEFORE remove for the Entry payload; the remove-returns-false witness covers the
    // vanish race. An expired entry is nonexistent on every public surface (SPEC.md 7), so
    // dropping one reaps it as 'expired' and returns false; only a LIVE removal is true.
    let entry;
    try {
      entry = await this.#backend.stat(ref);
    } catch (err) {
      if (err instanceof RefNotFound) {
        // The ref names no live entry here, but drop STILL writes a grave: that is how a
        // tombstone PROPAGATES across replicas (SPEC.md 4.4). A node that never held the id
        // must adopt the grave, or a later sync from a stale node resurrects the entry the
        // destruction removed. Grave BEFORE the remove (the #destroy ordering); remove()
        // also cleans an orphaned blob a crash mid-remove may have stranded. It returns
        // false, since no LIVE entry was destroyed, but the id is now tombstoned.
        await this.#backend.writeTombstone(ref, makeTombstone(ref, "drop"));
        await this.#backend.remove(ref);
        return false;
      }
      // A sidecar too corrupt to parse must not make the entry un-droppable: drop deletes
      // without reading, unlike show/has, which surface the corruption. It existed and is
      // destroyed, so it leaves a grave; there is no whole Entry to carry, so no event fires.
      if (err instanceof IntegrityError) {
        await this.#backend.writeTombstone(ref, makeTombstone(ref, "drop"));
        return this.#removeWitnessed(ref);
      }
      throw err;
    }
    const expired = isExpired(entry, Date.now());
    // A live drop leaves a grave (SPEC.md 4.4), written BEFORE the remove; an expired
    // entry's terms travel with it, so expiry writes none. A grave already standing (a
    // concurrent pop won the race) is kept first-write-wins, so its cause is not clobbered.
    if (!expired) await this.#backend.writeTombstone(ref, makeTombstone(ref, "drop"));
    if (!(await this.#removeWitnessed(ref))) return false; // vanished between stat and remove
    this.#emit(expired ? "expired" : "dropped", entry);
    return !expired;
  }

  /**
   * @primitive  stash.clear
   * @signature  stash.clear() -> Promise<number>
   * @since      0.1.0
   * @status     stable
   * @spec       SPEC.md 4
   * @related    stash.drop, stash.list
   *
   * Drop everything; resolve to the number of LIVE entries destroyed. Entries
   * that had already expired are reaped too, but they are not counted -- an
   * expired entry is already nonexistent on every read surface, so the number
   * answers "how many live entries did this destroy", not "how many files went
   * away". Each live destruction leaves a `'clear'` grave, visible through
   * `tombstones()`, which blocks a later `store()` of that same ref.
   *
   * @example
   *   const destroyed = await stash.clear();
   */
  async clear() {
    await this.#recover();
    const entries = await this.#backend.list();
    const now = Date.now();
    // Destroy EVERYTHING first, recording each removal and its cause, and emit only once
    // the whole clear has committed: a listener that throws must not abort the loop and
    // strand the un-visited entries (SPEC.md 4.3). A live entry is 'dropped' and counts; an
    // expired one is 'expired' and does not, being already nonexistent (SPEC.md 4.3, 7).
    const reaped = [];
    let destroyed = 0;
    for (const entry of entries) {
      const expired = isExpired(entry, now);
      // A grave per LIVE entry destroyed (cause 'clear'), written before its remove; an
      // expired entry writes none. clear removes no existing tombstone: destruction is
      // monotone across replicas.
      if (!expired) await this.#backend.writeTombstone(entry.id, makeTombstone(entry.id, "clear"));
      if (await this.#removeWitnessed(entry.id)) {
        reaped.push([expired ? "expired" : "dropped", entry]);
        if (!expired) destroyed += 1;
      }
    }
    for (const [event, entry] of reaped) this.#emit(event, entry);
    return destroyed;
  }

  /**
   * @primitive  stash.prune
   * @signature  stash.prune() -> Promise<number>
   * @since      0.1.5
   * @status     stable
   * @spec       SPEC.md 4, SPEC.md 7
   * @related    stash.clear, stash.list
   *
   * Destroy expired entries on demand; resolve to the count actually
   * destroyed. Live entries are untouched. The count is real destructions, not
   * the number of expired entries seen -- an entry that a concurrent drop
   * removes first is not double-counted. Loud over corruption: it lists through
   * the backend, whose verdict on a rotten stored entry surfaces rather than
   * being skipped. `sweepInterval` calls this on a timer; without it, a store
   * relies on the lazy read-path gate and whatever `prune()` its owner runs.
   *
   * @example
   *   const reaped = await stash.prune(); // number of expired entries destroyed
   */
  async prune() {
    // prune is a public verb AND the background sweep's operation, so it carries the same
    // first-operation recovery every other verb does: a sweep-only deployment must still
    // resolve a prior run's stale claims, not leave claimed bytes occupying the store.
    // #recover drives backend methods only, so this cannot recurse into prune.
    await this.#recover();
    const entries = await this.#backend.list();
    const now = Date.now();
    // Reap every expired entry FIRST, emit only after: a throwing 'expired' listener must
    // not abort the reap and strand the rest, which on the sweep timer would linger until a
    // lazy read finds them. An entry a concurrent drop removed first fails the
    // remove-witness and is never double-counted (SPEC.md 4.3). An expired entry a live claim
    // holds is left for that claim to resolve, the same rule #statLive follows. That check
    // sees only claims held in this process, not a claim another process holds.
    const reaped = [];
    for (const entry of entries) {
      if (
        isExpired(entry, now) &&
        !this.#liveClaims.has(entry.id) &&
        (await this.#backend.remove(entry.id))
      )
        reaped.push(entry);
    }
    for (const entry of reaped) this.#emit("expired", entry);
    // Prune stale graves (SPEC.md 4.4) on THIS sweep, so a single sweep owns both entry
    // expiry and grave pruning and no second timer exists. A null tombstoneTtl never prunes;
    // listTombstones is loud over a corrupt grave, exactly as the entry scan is.
    if (this.#tombstoneTtlMs !== null) {
      for (const grave of await this.#backend.listTombstones()) {
        if (now - grave.destroyedAt >= this.#tombstoneTtlMs)
          await this.#backend.removeTombstone(grave.id);
      }
    }
    return reaped.length;
  }

  /**
   * @primitive  stash.close
   * @signature  stash.close() -> Promise<void>
   * @since      0.1.5
   * @status     stable
   * @spec       SPEC.md 7, SPEC.md 7.1
   * @related    stash.prune
   *
   * Stop the background sweep timer. Idempotent -- calling it again, or on a
   * store that never armed a timer, is a no-op, never an error. It stops the
   * janitor and only the janitor: a closed store still serves push, apply, and
   * the rest. `Stash` also implements `Symbol.asyncDispose` as an alias, so
   * `await using stash = new Stash(...)` clears the timer when the block exits,
   * even on throw. Disposal is a real boundary: `close()` also awaits a sweep
   * already in flight, so no background deletion lands after it resolves.
   * Disposal is the real shutdown path -- the sweep timer is `unref()`'d so it
   * never blocks process exit, but it keeps the `Stash` reachable until closed.
   *
   * @example
   *   import { Stash } from "@blamejs/stash";
   *
   *   const stash = new Stash({ backend, sweepInterval: "5m" });
   *   try {
   *     await stash.push(data);
   *   } finally {
   *     await stash.close();
   *   }
   */
  async close() {
    // close() does NOT release the shared guard: it stops only the janitor and leaves the
    // store fully usable, so a claim taken after close, or a second Stash opened later over
    // the same store, must still find the guard registered. GUARD_REAP releases it on GC.
    if (this.#sweepTimer !== null) {
      clearInterval(this.#sweepTimer);
      this.#sweepTimer = null;
    }
    // Await a sweep already running so no sweep-side mutation lands after close() resolves.
    // Captured first, since the sweep nulls it when it ends; the tracker never rejects.
    const inFlight = this.#sweepInFlight;
    if (inFlight !== null) await inFlight;
  }

  // The `await using` alias for close() (SPEC.md 7.1), idempotent because close() is:
  // disposal running twice is normal, not an error. It does not replace the unref() rule.
  async [Symbol.asyncDispose]() {
    await this.close();
  }
}
