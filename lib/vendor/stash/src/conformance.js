// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash.conformance
 * @nav        Conformance
 * @title      Backend conformance
 * @order      30
 * @slug       conformance
 *
 * @intro
 *   The backend interface (SPEC.md 9) is a stable contract, and this module
 *   is its executable form. A backend holds bytes, `Stash` holds policy. Any
 *   object implementing the SPEC.md 9 method set can be handed to
 *   `new Stash({ backend })`, so a store on a filesystem this library does
 *   not ship (an object store, a remote block device, whatever a deployment
 *   already trusts) is a first-class backend the moment it passes the same
 *   behavioral cases the in-tree memory and disk backends pass.
 *
 *   `runBackendConformance` registers that behavioral suite against a
 *   backend factory, driving the shipped consumer path (`stash.push(...)`,
 *   `stash.pop(ref)`, `stash.store(entry, bytes)`) and asserting the frozen
 *   verdicts (`ENOREF` on absence, `ECLAIMED` on claim contention, `E2BIG`
 *   over `maxSize`, `EFULL` over `maxEntries`). It is test-runner-agnostic:
 *   the caller wires their own runner's `test` (and, optionally, an assert),
 *   so it never imports one at module load. The in-tree suite runs the
 *   identical cases against memory and disk.
 *
 * @card
 *   The SPEC.md 9 backend contract as a runnable suite: point it at your own
 *   backend factory and your runner's `test`, and it certifies the store
 *   behaves like the ones that ship.
 */

import { strict as defaultAssert } from "node:assert";
import { Readable } from "node:stream";

import { Stash } from "./stash.js";
import { RefClaimed, RefNotFound, SizeExceeded, StashFull } from "./errors.js";
import { algoOf, digestHash, finalize } from "./digest.js";
import { makeTombstone } from "./entry.js";

// Collect a Readable to one Buffer. Only the small fixtures here are ever buffered.
async function drain(readable) {
  const chunks = [];
  for await (const chunk of readable) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// Retry `fn` while it loses the claim race, until it wins or the entry is exhausted. The
// retry yields to the MACROTASK queue (setImmediate): a microtask spin would starve the
// claim holder's stream drain, which advances on IO and macrotasks, and livelock.
async function retryOnClaimed(fn) {
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof RefClaimed) {
        await new Promise((resolve) => setImmediate(resolve));
        continue;
      }
      throw err;
    }
  }
}

/**
 * @primitive  stash.conformance.runBackendConformance
 * @signature  runBackendConformance(factory, options) -> void
 * @since      0.1.16
 * @status     stable
 * @spec       SPEC.md 9, SPEC.md 13
 * @related    stash.Stash, stash.backends.MemoryBackend
 *
 * Register the SPEC.md 9 backend conformance suite against a backend
 * `factory` of `{ name, create() }`, where `create()` returns a fresh backend
 * per case and `name` is a required non-empty string labelling every case
 * (`"<name>: <case>"`), so two backends certified in one run produce two
 * distinguishable suites. A factory missing either member is a `TypeError`.
 * `options.test` is your runner's test function (`(title, fn) => void`);
 * `options.assert` is a `node:assert/strict`-shaped assertion object,
 * defaulting to the built-in when omitted. Every case drives the shipped
 * `Stash` consumer path against a `Stash` wrapping the factory's backend, so
 * passing the suite is proof the backend is interchangeable with the ones
 * that ship. The cases cover round-trip fidelity for every source type and
 * for a payload over 4 MiB, identity, expiry, limits, `stats()` byte
 * accounting under `maxTotal`, claim atomicity, read budgets, the
 * `verify()` and `reconcilable()` reports, tombstone first-write-wins, and
 * grave pruning past `tombstoneTtl`. No test runner is imported here; the caller owns that choice.
 *
 * @example
 *   import { test } from "node:test";
 *   import { runBackendConformance } from "@blamejs/stash/conformance";
 *   import { MemoryBackend } from "@blamejs/stash/backends/memory";
 *
 *   runBackendConformance(
 *     { name: "my-backend", create: () => new MemoryBackend() },
 *     { test },
 *   );
 */
export function runBackendConformance(factory, options) {
  const opts = options || {};
  const register = opts.test;
  const assert = opts.assert || defaultAssert;
  if (typeof register !== "function") {
    throw new TypeError(
      "runBackendConformance(factory, { test }): `test` must be your test runner's registration function",
    );
  }
  if (
    factory === null ||
    typeof factory !== "object" ||
    typeof factory.create !== "function" ||
    typeof factory.name !== "string" ||
    factory.name.length === 0
  ) {
    throw new TypeError("runBackendConformance(factory, ...): factory must be { name, create() }");
  }
  // Without the label, two backends certified in one run produce byte-identical title
  // sets and a failure that names no backend.
  const test = (title, fn) => register(factory.name + ": " + title, fn);
  // Called AS A METHOD, never a bare extracted reference: the contract is
  // `{ name, create() }`, so an author may read config through `this`, and extracting
  // the function would hand create() a `this` of undefined.
  const create = () => factory.create();

  // ---- Round-trip fidelity: every source type in, identical bytes out ----

  test("round-trips a Buffer; apply is non-destructive", async () => {
    const stash = new Stash({ backend: create() });
    const payload = Buffer.from([0, 1, 2, 250, 251, 252]);
    const ref = await stash.push(payload);
    assert.equal(typeof ref, "string");
    assert.ok(ref.length > 0);
    assert.deepEqual(await drain(await stash.apply(ref)), payload);
    // apply is non-destructive: the bytes are still there
    assert.deepEqual(await drain(await stash.apply(ref)), payload);
  });

  test("round-trips a bare Uint8Array without aliasing the caller's buffer", async () => {
    const stash = new Stash({ backend: create() });
    const payload = new Uint8Array([9, 8, 7, 6]);
    const ref = await stash.push(payload);
    payload.fill(0); // caller mutation after push must not reach the store
    assert.deepEqual(await drain(await stash.apply(ref)), Buffer.from([9, 8, 7, 6]));
  });

  test("round-trips a UTF-8 string", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push("hello stash");
    assert.equal((await drain(await stash.apply(ref))).toString("utf8"), "hello stash");
  });

  test("round-trips a Readable without mutating the payload", async () => {
    const stash = new Stash({ backend: create() });
    const payload = Buffer.from("streamed bytes, chunk by chunk");
    const ref = await stash.push(Readable.from([payload.subarray(0, 9), payload.subarray(9)]));
    assert.deepEqual(await drain(await stash.apply(ref)), payload);
  });

  test("round-trips an AsyncIterable", async () => {
    const stash = new Stash({ backend: create() });
    async function* chunks() {
      yield Buffer.from("alpha ");
      yield Buffer.from("beta");
    }
    const ref = await stash.push(chunks());
    assert.equal((await drain(await stash.apply(ref))).toString("utf8"), "alpha beta");
  });

  test("round-trips mixed chunk types: a streamed string chunk and a typed-array chunk encode as bytes", async () => {
    // A streamed string chunk is the ONLY way to reach per-chunk UTF-8 encoding (a
    // top-level string becomes a Buffer first), and it is measured in bytes, not chars.
    const stash = new Stash({ backend: create() });
    async function* chunks() {
      yield "text chunk ";
      yield new Uint8Array([0x62, 0x79, 0x74, 0x65, 0x73]);
    }
    const ref = await stash.push(chunks());
    const got = await drain(await stash.apply(ref));
    assert.equal(got.toString("utf8"), "text chunk bytes");
    assert.equal((await stash.show(ref)).size, got.length);
  });

  test("stream chunks are copied at write: caller buffer reuse cannot rewrite stored bytes", async () => {
    // The pooled-slab pattern. The store outlives the push, so a backend retaining the
    // caller's buffer instead of an owned copy lets a later mutation rewrite stored
    // bytes out from under the digest.
    const stash = new Stash({ backend: create() });
    const scratch = Buffer.from("aaaa");
    async function* reusing() {
      yield scratch;
      scratch.fill(0x62); // runs after the store consumed the first chunk
      yield Buffer.from("cccc");
    }
    const ref = await stash.push(reusing());
    assert.equal((await drain(await stash.apply(ref))).toString("utf8"), "aaaacccc");
  });

  test("a zero-byte source round-trips: size 0, a self-describing digest, bytes empty", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push(Buffer.alloc(0));
    const entry = await stash.show(ref);
    assert.equal(entry.size, 0);
    assert.equal(typeof entry.digest, "string");
    assert.ok(entry.digest.includes(":"), "the digest is self-describing (<algo>:<hex>)");
    assert.equal((await drain(await stash.apply(ref))).length, 0);
    const fromString = await stash.push("");
    assert.equal((await stash.show(fromString)).size, 0);
    assert.equal(await stash.drop(ref), true);
  });

  test("an abandoned apply leaves the entry intact and releases its handle", async () => {
    // Destroying the stream after the first chunk must leave the entry readable and
    // droppable: a read handle left open by the abort would block the delete on some
    // filesystems.
    const stash = new Stash({ backend: create() });
    const payload = Buffer.alloc(262144, 7);
    const ref = await stash.push(payload);
    const readable = await stash.apply(ref);
    readable.once("data", () => readable.destroy());
    await new Promise((resolve) => readable.once("close", resolve));
    assert.deepEqual(await drain(await stash.apply(ref)), payload);
    assert.equal(await stash.drop(ref), true);
  });

  // ---- Identity and metadata: refs are capabilities, not addresses ----

  test("push mints a fresh ref per entry, even for identical bytes", async () => {
    const stash = new Stash({ backend: create() });
    const first = await stash.push("same bytes");
    const second = await stash.push("same bytes");
    assert.notEqual(first, second);
    assert.equal((await stash.list()).length, 2);
  });

  test("show returns metadata only, with size and a self-describing digest, never contents", async () => {
    const stash = new Stash({ backend: create() });
    const payload = Buffer.from("metadata subject");
    const before = Date.now();
    const ref = await stash.push(payload, { meta: { label: "opaque" } });
    const entry = await stash.show(ref);
    assert.equal(entry.id, ref);
    assert.equal(entry.size, payload.length);
    assert.equal(typeof entry.digest, "string");
    assert.ok(entry.digest.includes(":"));
    assert.ok(entry.createdAt >= before && entry.createdAt <= Date.now());
    assert.equal(entry.expiresAt, null);
    assert.equal(entry.reads, null);
    assert.equal(entry.readsLeft, null);
    assert.deepEqual(entry.meta, { label: "opaque" });
    assert.equal("contents" in entry, false);
    assert.equal("chunks" in entry, false);
  });

  test("meta round-trips verbatim as JSON and stays caller-isolated", async () => {
    const stash = new Stash({ backend: create() });
    const meta = { nested: { deep: [1, 2, 3] }, text: "x" };
    const ref = await stash.push("payload", { meta });
    meta.nested.deep.push(4); // caller mutation after push must not leak in
    const entry = await stash.show(ref);
    assert.deepEqual(entry.meta, { nested: { deep: [1, 2, 3] }, text: "x" });
    entry.meta.nested.deep = []; // returned-copy mutation must not leak back
    assert.deepEqual((await stash.show(ref)).meta.nested.deep, [1, 2, 3]);
  });

  // ---- Enumeration and destruction ----

  test("list enumerates entries; drop removes exactly one; an absent drop is false", async () => {
    const stash = new Stash({ backend: create() });
    const keep = await stash.push("keep");
    const gone = await stash.push("gone");
    assert.deepEqual((await stash.list()).map((e) => e.id).sort(), [keep, gone].sort());
    assert.equal(await stash.drop(gone), true);
    assert.equal(await stash.drop(gone), false); // absent is a fact, not a failure
    assert.deepEqual(
      (await stash.list()).map((e) => e.id),
      [keep],
    );
  });

  test("clear destroys everything and counts it", async () => {
    const stash = new Stash({ backend: create() });
    await stash.push("one");
    await stash.push("two");
    await stash.push("three");
    assert.equal(await stash.clear(), 3);
    assert.deepEqual(await stash.list(), []);
    assert.equal(await stash.clear(), 0);
  });

  test("an unknown well-formed ref is RefNotFound from apply and show", async () => {
    const stash = new Stash({ backend: create() });
    const absent = await stash.push("transient");
    assert.equal(await stash.drop(absent), true); // well-formed, now absent
    await assert.rejects(
      stash.apply(absent),
      (err) => err instanceof RefNotFound && err.code === "ENOREF",
    );
    await assert.rejects(
      stash.show(absent),
      (err) => err instanceof RefNotFound && err.code === "ENOREF",
    );
  });

  test("a dropped entry is gone from every read path", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push("ephemeral");
    assert.equal(await stash.drop(ref), true);
    await assert.rejects(stash.apply(ref), RefNotFound);
    await assert.rejects(stash.show(ref), RefNotFound);
    assert.deepEqual(await stash.list(), []);
  });

  // ---- Expiry: deterministic via ttl 0 (expired at birth) ----

  test("an expired entry is RefNotFound from apply and show, before any sweep runs", async () => {
    const stash = new Stash({ backend: create() }); // no sweepInterval
    const ref = await stash.push("gone at birth", { ttl: 0 });
    await assert.rejects(
      stash.apply(ref),
      (err) => err instanceof RefNotFound && err.code === "ENOREF",
    );
    const other = await stash.push("also gone", { ttl: 0 });
    await assert.rejects(
      stash.show(other),
      (err) => err instanceof RefNotFound && err.code === "ENOREF",
    );
  });

  // ---- Limits: bounded mid-stream, refused before eviction ----

  test("maxSize: exactly the limit round-trips; one byte over is SizeExceeded (E2BIG)", async () => {
    const stash = new Stash({ backend: create(), maxSize: 16 });
    const ref = await stash.push(Buffer.alloc(16, 7));
    assert.equal((await drain(await stash.apply(ref))).length, 16);
    await assert.rejects(
      stash.push(Buffer.alloc(17, 7)),
      (e) => e instanceof SizeExceeded && e.code === "E2BIG",
    );
  });

  test("maxEntries: a full store is StashFull (EFULL) before the stream starts; drop frees a slot", async () => {
    const stash = new Stash({ backend: create(), maxEntries: 1 });
    const first = await stash.push("a");
    let pulled = false;
    async function* watched() {
      pulled = true;
      yield Buffer.from("b");
    }
    await assert.rejects(
      stash.push(watched()),
      (e) => e instanceof StashFull && e.code === "EFULL",
    );
    assert.equal(
      pulled,
      false,
      "rejected before the source was pulled -- no eviction, no wasted read",
    );
    await stash.drop(first);
    assert.equal(typeof (await stash.push("b")), "string");
  });

  // ---- Pop and claim atomicity ----

  test("pop round-trips and destroys: the payload streams once, then the entry is gone", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push("bytes at rest");
    assert.deepEqual(await drain(await stash.pop(ref)), Buffer.from("bytes at rest"));
    await assert.rejects(stash.show(ref), (e) => e instanceof RefNotFound && e.code === "ENOREF");
    await assert.rejects(stash.apply(ref), RefNotFound);
    await assert.rejects(stash.pop(ref), RefNotFound);
    assert.deepEqual(await stash.list(), []);
  });

  test("concurrent pop: exactly one drains the payload, the other is RefClaimed (ECLAIMED)", async () => {
    const stash = new Stash({ backend: create() });
    // Above the stream highWaterMark, so backpressure holds the winner's claim until it
    // is drained and the loser races a live claim, not one that already auto-committed.
    const payload = Buffer.alloc(65536, 7);
    const ref = await stash.push(payload);
    const settled = await Promise.allSettled([stash.pop(ref), stash.pop(ref)]);
    const winners = settled.filter((r) => r.status === "fulfilled");
    const losers = settled.filter((r) => r.status === "rejected");
    assert.equal(winners.length, 1, "exactly one pop won the claim");
    assert.equal(losers.length, 1);
    assert.equal(losers[0].reason.code, "ECLAIMED");
    assert.deepEqual(await drain(winners[0].value), payload);
    await assert.rejects(stash.show(ref), RefNotFound);
  });

  test("a claimed entry is RefClaimed to a concurrent reader, not IntegrityError", async () => {
    const stash = new Stash({ backend: create() });
    const payload = Buffer.alloc(65536, 3); // above the highWaterMark: the claim stays held
    const ref = await stash.push(payload);
    const inflight = await stash.pop(ref); // claimed, not yet drained
    await assert.rejects(stash.apply(ref), (e) => e instanceof RefClaimed && e.code === "ECLAIMED");
    await assert.rejects(stash.pop(ref), RefClaimed);
    await drain(inflight); // finish the pop
    await assert.rejects(stash.show(ref), RefNotFound);
  });

  // ---- Read budgets: consumeRead is atomic and never over-spends ----

  test("reads:2 sequential: two full drains, one credit left between them, then RefNotFound", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push("twice", { reads: 2 });
    assert.deepEqual(await drain(await stash.apply(ref)), Buffer.from("twice"));
    assert.equal((await stash.show(ref)).readsLeft, 1);
    assert.deepEqual(await drain(await stash.apply(ref)), Buffer.from("twice"));
    await assert.rejects(stash.show(ref), RefNotFound);
    await assert.rejects(stash.apply(ref), RefNotFound);
  });

  test("reads:2 concurrent: exactly two drained successes ever, then RefNotFound", async () => {
    const stash = new Stash({ backend: create() });
    const ref = await stash.push("shared", { reads: 2 });
    let drained = 0;
    // race more readers than credits; losers retry the claim until exhausted
    await Promise.all(
      Array.from({ length: 6 }, () =>
        (async () => {
          try {
            const bytes = await retryOnClaimed(async () => drain(await stash.apply(ref)));
            assert.deepEqual(bytes, Buffer.from("shared"));
            drained += 1;
          } catch (err) {
            if (!(err instanceof RefNotFound)) throw err; // the budget is spent -- expected
          }
        })(),
      ),
    );
    assert.equal(drained, 2, "a reads:2 entry served exactly twice under contention");
    await assert.rejects(stash.show(ref), RefNotFound);
  });

  // ---- Replication: store() and tombstone first-write-wins ----

  test("store() replicates an entry to a fresh backend and round-trips", async () => {
    const donor = new Stash({ backend: create() });
    const bytes = Buffer.from("replicated bytes");
    const ref = await donor.push(bytes, { meta: { label: "opaque" } });
    const entry = await donor.show(ref);
    const target = new Stash({ backend: create() });
    assert.equal(await target.store(entry, bytes), true, "a fresh store lands");
    const shown = await target.show(ref);
    assert.equal(shown.id, ref, "identity is preserved across replication");
    assert.deepEqual(shown.meta, { label: "opaque" });
    assert.deepEqual(await drain(await target.apply(ref)), bytes);
  });

  test("a destroyed id never resurrects through store() (tombstone first-write-wins)", async () => {
    const stash = new Stash({ backend: create() });
    const bytes = Buffer.from("burn me");
    const ref = await stash.push(bytes);
    const entry = await stash.show(ref);
    assert.equal(await stash.drop(ref), true); // destruction writes a tombstone
    assert.equal(
      await stash.store(entry, bytes),
      false,
      "a tombstoned id is refused, writing nothing",
    );
    await assert.rejects(stash.apply(ref), (e) => e instanceof RefNotFound && e.code === "ENOREF");
  });

  // ---- Large payloads: no per-value cap below the stream ----

  test("a 4 MiB + 1 byte payload streams in and out byte-exact", async () => {
    const stash = new Stash({ backend: create() });
    const total = 4 * 1048576 + 1;
    const chunk = 65536;
    // Each chunk carries its own offset pattern, so a backend that drops or repeats a
    // chunk changes the bytes and the length together. The source is never buffered whole.
    async function* source() {
      for (let at = 0; at < total; at += chunk) {
        const piece = Buffer.alloc(Math.min(chunk, total - at));
        for (let i = 0; i < piece.length; i++) piece[i] = (at + i) % 251;
        yield piece;
      }
    }
    const ref = await stash.push(source());
    const entry = await stash.show(ref);
    assert.equal(entry.size, total);
    const algo = algoOf(entry.digest);
    assert.ok(algo !== null, "the stored digest names a known algorithm");
    const hash = digestHash(algo);
    let length = 0;
    let mismatch = -1;
    for await (const piece of await stash.apply(ref)) {
      for (let i = 0; i < piece.length && mismatch === -1; i++) {
        if (piece[i] !== (length + i) % 251) mismatch = length + i;
      }
      hash.update(piece);
      length += piece.length;
    }
    // The length and content checks are both needed: a backend that truncates and
    // re-hashes what it kept produces a digest consistent with the truncated bytes.
    assert.equal(length, total, "every pushed byte comes back");
    assert.equal(mismatch, -1, "every byte comes back in its pushed position");
    assert.equal(finalize(hash, algo), entry.digest);
  });

  // ---- Accounting: stats() feeds the maxTotal bound ----

  test("stats() counts every stored byte, and maxTotal binds on that count", async () => {
    const plain = new Stash({ backend: create() });
    await plain.push(Buffer.alloc(100000, 1));
    const stats = await plain.stats();
    assert.equal(stats.entries, 1);
    assert.ok(stats.bytes >= 100000, "stats().bytes includes the blob");

    const bounded = new Stash({ backend: create(), maxTotal: 250000 });
    await bounded.push(Buffer.alloc(100000, 2));
    await bounded.push(Buffer.alloc(100000, 3));
    await assert.rejects(
      bounded.push(Buffer.alloc(100000, 4)),
      (e) => e instanceof StashFull && e.code === "EFULL",
    );
  });

  // ---- Audit and reconciliation listings ----

  test("verify() scans every live entry and reports a clean store as clean", async () => {
    const stash = new Stash({ backend: create() });
    const refs = [await stash.push("one"), await stash.push("two"), await stash.push("three")];
    const report = await stash.verify();
    assert.ok(report.scanned >= 3, "verify scanned each of the three entries");
    assert.deepEqual(report.findings, []);
    assert.deepEqual(report.repaired, []);
    for (const ref of refs) assert.equal(await stash.drop(ref), true);
    const after = await stash.verify();
    assert.deepEqual(after.findings, []);
    assert.ok(after.scanned < report.scanned, "dropped entries are no longer scanned");
  });

  test("reconcilable() lists every live entry and no dropped one", async () => {
    const stash = new Stash({ backend: create() });
    const keep = await stash.push("keep");
    const gone = await stash.push("gone");
    const before = await stash.reconcilable();
    assert.deepEqual(before.entries.map((e) => e.id).sort(), [keep, gone].sort());
    assert.deepEqual(before.corrupt, []);
    assert.equal(await stash.drop(gone), true);
    const after = await stash.reconcilable();
    assert.deepEqual(
      after.entries.map((e) => e.id),
      [keep],
    );
    assert.deepEqual(after.corrupt, []);
  });

  // ---- Grave pruning: tombstoneTtl reaps a grave through removeTombstone ----

  test("prune() past tombstoneTtl removes the grave, so store() accepts the id again", async () => {
    const source = new Stash({ backend: create() });
    const bytes = Buffer.from("buried, then forgotten");
    const ref = await source.push(bytes);
    const entry = await source.show(ref);
    // A grave stamped at the epoch is already older than any tombstoneTtl.
    const backend = create();
    const grave = makeTombstone(ref, "drop");
    grave.destroyedAt = 0;
    await backend.writeTombstone(ref, grave);
    const stash = new Stash({ backend, tombstoneTtl: "1h" });
    assert.equal((await stash.tombstones()).length, 1);
    assert.equal(await stash.store(entry, bytes), false, "the standing grave refuses the id");
    await stash.prune();
    assert.deepEqual(await stash.tombstones(), []);
    assert.equal(await stash.store(entry, bytes), true, "the pruned grave no longer refuses the id");
    assert.deepEqual(await drain(await stash.apply(ref)), bytes);
  });

  // ---- Destruction witness: one destroyer per entry ----

  test("remove() after commit() reports false: a committed entry has no second destroyer", async () => {
    const backend = create();
    const ref = await new Stash({ backend }).push("destroyed once");
    const { source } = await backend.claim(ref);
    await drain(source);
    await backend.commit(ref);
    assert.equal(await backend.remove(ref), false, "the committed entry is already gone");
  });
}
