// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash.backends
 * @nav        Backends
 * @title      Backends
 * @order      20
 * @slug       backends
 *
 * @intro
 *   The storage layer, behind one contract (SPEC.md 9): the backend holds
 *   bytes, `Stash` holds policy. A backend never validates lifecycle, never
 *   interprets `meta`, and never decides destruction. It stores what it is
 *   handed under the id it is handed, computes size and the digest as the
 *   bytes stream through (with the algorithm named by the entry's
 *   self-describing digest), and reports what it holds. The same conformance
 *   suite runs against every backend, unmodified.
 *
 *   Two implementations ship. The memory backend is Map-backed, for tests and
 *   process-lifetime stashes. The disk backend is sidecar-file storage: one
 *   blob and one JSON sidecar per entry, no central index to corrupt, atomic
 *   tmp-write-rename writes opened with O_DSYNC, 0700/0600 modes, and realpath containment that
 *   refuses a planted symlink instead of following it.
 *
 * @card
 *   The storage contract and both shipped backends: Map-backed memory, and
 *   sidecar-file disk with atomic writes and realpath containment.
 */

import { Readable } from "node:stream";
import { isUint8Array } from "node:util/types";

import { DEFAULT_DIGEST, algoOf, digestHash, finalize } from "../digest.js";
import { spend } from "../entry.js";
import { IntegrityError, RefClaimed, RefNotFound } from "../errors.js";
import { assertValid, constantTimeEqual } from "../ref.js";

/**
 * @primitive  stash.backends.MemoryBackend
 * @signature  new MemoryBackend() -> MemoryBackend
 * @since      0.1.0
 * @status     stable
 * @spec       SPEC.md 9
 * @related    stash.Stash
 *
 * Construct the in-memory backend. Pass it as `backend` to `new Stash()`.
 * Storage is a private Map from id to `{ entry, chunks }`; nothing touches
 * the filesystem.
 *
 * A `claim` (the pop cycle, SPEC.md 6) moves the entry into a separate claims
 * Map with no `await` between the "already claimed?" check and the move, so
 * on the single-threaded event loop that move ITSELF is the atomicity two
 * concurrent pops race on: the first wins, the second gets `RefClaimed`.
 * `restore` returns a claim to the live map, `commit` destroys it, and
 * `verify` reports a claim older than `claimTimeout` as stale without
 * repairing it.
 *
 * The claims Map lives only in this process's heap, so a claim dies with the
 * process and nothing persists for a later run to reclaim: there is NO
 * cross-process crash recovery here. Reach for the disk backend when a claim,
 * or the data, must survive a restart.
 *
 * @example
 *   import { Stash } from "@blamejs/stash";
 *   import { MemoryBackend } from "@blamejs/stash/backends/memory";
 *
 *   const stash = new Stash({ backend: new MemoryBackend() });
 *   const ref = await stash.push("hello");
 */
// Per-process counter: each instance is its OWN store, and the policy layer keys its
// single-writer guard (SPEC.md 6) on this identity, so it need only be unique in-process.
let MEMORY_INSTANCE_SEQ = 0;

// Re-hash with the entry's OWN stored algorithm (digests are self-describing) and compare
// timing-safe. One site, so verify()'s unclaimed and claimed walks cannot drift.
function _digestMatches(held) {
  const algo = algoOf(held.entry.digest);
  const hash = digestHash(algo);
  for (const buf of held.chunks) hash.update(buf);
  return constantTimeEqual(finalize(hash, algo), held.entry.digest);
}

export class MemoryBackend {
  #entries = new Map();
  // `id` sits inside the value because listTombstones returns these verbatim and
  // consumers read `.id` off them. First-write-wins (SPEC.md 4.4).
  #tombstones = new Map();
  // id -> { entry, chunks, claimedAt }. A claim moves an entry OUT of #entries with no
  // await in between, and that synchronous move IS the atomicity two pops race on.
  #claims = new Map();

  // The policy layer keys its single-writer-per-root guard on this identity (SPEC.md 6)
  // so two Stash over one store never age-reclaim each other's live reads.
  #identity = "mem:" + (MEMORY_INSTANCE_SEQ += 1);
  get identity() {
    return this.#identity;
  }

  // The digest algorithm rides IN the entry (digests are self-describing); a markerless
  // entry takes DEFAULT_DIGEST. Every retained chunk is an OWNED COPY: the store outlives
  // the push, so a caller reusing its buffer must not rewrite stored bytes.
  async write(id, source, entry) {
    const algo = algoOf(entry.digest) ?? DEFAULT_DIGEST;
    const hash = digestHash(algo);
    const chunks = [];
    let size = 0;
    for await (const chunk of source) {
      // isUint8Array, not `instanceof`: a chunk from another realm is still a Uint8Array
      // and must take the copyBytesFrom path that snapshots bytes the caller may reuse.
      const buf = isUint8Array(chunk) ? Buffer.copyBytesFrom(chunk) : Buffer.from(chunk);
      hash.update(buf);
      size += buf.length;
      chunks.push(buf);
    }
    const stored = structuredClone(entry);
    stored.size = size;
    stored.digest = finalize(hash, algo);
    this.#entries.set(id, { entry: stored, chunks });
    return structuredClone(stored);
  }

  // A claimed entry's bytes moved to #claims: a reader gets RefClaimed, not RefNotFound.
  async read(id) {
    if (this.#claims.has(id)) throw new RefClaimed();
    const held = this.#entries.get(id);
    if (held === undefined) throw new RefNotFound();
    return Readable.from(held.chunks.map((buf) => Buffer.from(buf)));
  }

  // Monotone destruction (SPEC.md 4.2): a drop removes live OR claimed, so a later
  // restore of that claim finds nothing and cannot resurrect it.
  async remove(id) {
    const wasLive = this.#entries.delete(id);
    const wasClaimed = this.#claims.delete(id);
    return wasLive || wasClaimed;
  }

  // A claimed entry still exists with its metadata intact, so it resolves from either map.
  async stat(id) {
    const held = this.#entries.get(id) || this.#claims.get(id);
    if (held === undefined) throw new RefNotFound();
    return structuredClone(held.entry);
  }

  // A claimed entry is mid-pop, not gone: it stays listed until its claim commits.
  async list() {
    const out = [];
    for (const held of this.#entries.values()) out.push(structuredClone(held.entry));
    for (const held of this.#claims.values()) out.push(structuredClone(held.entry));
    return out;
  }

  // Reconciliation-grade listing (SPEC.md 4.4): healthy entries plus unreadable ids, so
  // one corrupt sidecar cannot stall replication of the rest. A Map has none, so
  // `corrupt` is always empty here.
  async listReconcilable() {
    return { entries: await this.list(), corrupt: [] };
  }

  // No await precedes the move, so two concurrent claims cannot both win. The source
  // reads the SNAPSHOT taken here, so restore or commit never disturbs an in-flight read.
  async claim(id) {
    if (this.#claims.has(id)) throw new RefClaimed();
    const held = this.#entries.get(id);
    if (held === undefined) throw new RefNotFound();
    this.#entries.delete(id);
    this.#claims.set(id, { entry: held.entry, chunks: held.chunks, claimedAt: Date.now() });
    return {
      entry: structuredClone(held.entry),
      source: Readable.from(held.chunks.map((buf) => Buffer.from(buf))),
    };
  }

  // An occupied live slot is impossible for a unique-minted id and would mean a
  // drop/claim interleaving resurrecting destroyed data (SPEC.md 4.2), so it is refused.
  async restore(id) {
    const held = this.#claims.get(id);
    if (held === undefined) throw new RefNotFound();
    if (this.#entries.has(id)) throw new IntegrityError("restore target is occupied");
    this.#claims.delete(id);
    this.#entries.set(id, { entry: held.entry, chunks: held.chunks });
  }

  // Destroys a claimed entry; only ever called while holding the claim.
  async commit(id) {
    if (!this.#claims.delete(id)) throw new RefNotFound();
  }

  // A recovery input (the scan resolves claims a prior run abandoned), not an operator API.
  async listClaims() {
    const out = [];
    for (const [id, held] of this.#claims) out.push({ id, claimedAt: held.claimedAt });
    return out;
  }

  // apply/pop probe this before their stat, so a contended reader rejects RefClaimed
  // without touching the sidecar the claim-holder rewrites (an open reader blocks it).
  async isClaimed(id) {
    return this.#claims.has(id);
  }

  // Routed through entry.spend so the decrement lives at the schema home, never
  // hand-rolled here (the guard-shape tripwire). It rides on the claim, which is the
  // cross-reader mutex, so it survives a later restore.
  async consumeRead(id) {
    const held = this.#claims.get(id);
    if (held === undefined) throw new RefNotFound();
    held.entry = spend(held.entry);
    return held.entry.readsLeft;
  }

  // `bytes` sums blob size AND metadata, so a caller cannot slip past `maxTotal` with
  // tiny blobs and huge `meta`. Claimed and expired entries still count: a backend never
  // interprets expiry, and the policy layer prunes before it rejects.
  async stats() {
    let bytes = 0;
    let entries = 0;
    for (const held of this.#entries.values()) {
      bytes += held.entry.size + Buffer.byteLength(JSON.stringify(held.entry));
      entries += 1;
    }
    for (const held of this.#claims.values()) {
      bytes += held.entry.size + Buffer.byteLength(JSON.stringify(held.entry));
      entries += 1;
    }
    return { entries, bytes, claimed: this.#claims.size };
  }

  // A Map has no orphan halves, corrupt sidecars, or in-flight .tmp, so those finding
  // kinds are structurally empty while the report SHAPE still matches disk's. Repair
  // removes only a digest-mismatched UNCLAIMED entry: a claimed one is mid-pop, so its
  // mismatch, like a stale claim, is reported for recovery to resolve.
  async verify(opts) {
    const findings = [];
    const repaired = [];
    let scanned = 0;
    for (const [id, held] of this.#entries) {
      scanned += 1;
      if (!_digestMatches(held)) {
        findings.push({ kind: "digest-mismatch", id });
        if (opts.repair) {
          this.#entries.delete(id);
          repaired.push({ kind: "digest-mismatch", id });
        }
      }
    }
    const now = Date.now();
    for (const [id, held] of this.#claims) {
      scanned += 1; // a claimed blob still occupies the store; disk counts its meta/ sidecar, so match
      // Unreachable through the public API here (the claimed chunks are the object the
      // digest was taken over), but it keeps the backends parallel.
      if (!_digestMatches(held)) findings.push({ kind: "digest-mismatch", id });
      if (now - held.claimedAt >= opts.claimTimeoutMs) findings.push({ kind: "stale-claim", id });
    }
    return { scanned, findings, repaired };
  }

  // FIRST-WRITE-WINS: rewriting an existing grave's destroyedAt would extend its own ttl
  // life (SPEC.md 4.2, 4.4). The id is revalidated where a ref becomes a storage key.
  async writeTombstone(id, tombstone) {
    assertValid(id);
    if (this.#tombstones.has(id)) return;
    this.#tombstones.set(id, structuredClone(tombstone)); // a copy -- the grave outlives the caller's object
  }

  async hasTombstone(id) {
    assertValid(id);
    return this.#tombstones.has(id);
  }

  // Each grave is a fresh object, so a caller mutating one cannot reach the next reader.
  async listTombstones() {
    const out = [];
    for (const t of this.#tombstones.values()) out.push(structuredClone(t)); // defensive copies, never a live reference
    return out;
  }

  async removeTombstone(id) {
    assertValid(id);
    return this.#tombstones.delete(id);
  }
}
