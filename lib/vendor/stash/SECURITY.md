# Security Policy

`@blamejs/stash` is an ephemeral content store whose security posture is
architectural. There is nowhere in it to put a decryption key, refs are 256-bit
random capabilities rather than content addresses, ref validation is a strict
whitelist that doubles as path-traversal defense, and every failure is a typed
error that never echoes a ref, a `meta` value, or a filesystem path.

This document describes how to report a vulnerability, which versions are
supported, and how an operator hardens a deployment that embeds the store.

---

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Report privately through GitHub's **["Report a vulnerability"](https://github.com/blamejs/stash/security/advisories/new)**
private advisory form on the repository's Security tab. This opens a private
channel with the maintainers.

Please include:

- The affected version. `npm ls @blamejs/stash` prints it; if you tested against
  `main`, give the `<sha>` instead.
- A description of the issue and the impact you observed.
- A minimal reproducer: the smallest sequence of calls, hostile ref string, or
  corrupted store layout that triggers the behavior.
- Whether you have discussed this with anyone else, and any coordinated
  disclosure timeline you are working to.

The store's dominant attack surfaces are **hostile ref strings** (path
traversal), **hostile push sources** (resource exhaustion), and **a hostile store
directory** (symlinks, planted corruption). Reproducers in those shapes are
especially valuable.

### Response targets

| Severity | First response | Triage / acknowledgment | Fix released |
|---|---|---|---|
| Critical (ref whitelist bypass, containment escape, bytes served for a foreign ref) | within 72 h | within 7 d | next patch |
| High (fail-closed guarantee broken, capability leaked into an error or log surface, integrity check bypassed) | within 7 d | within 14 d | next patch |
| Medium (unbounded work or DoS on adversarial input) | within 14 d | within 30 d | next patch |
| Low (defense-in-depth gaps) | within 30 d | as scheduled | next release |

## Supported versions

Only the current major, `v2.x`, receives fixes. `v1.x` and `v0.x` are superseded
and not serviced. [LTS-CALENDAR.md](LTS-CALENDAR.md) records that the `v1.x`
window `v1.0` announced is not being honored, and why. Upgrading from `v1.x` is
two edits with no on-disk format change
([MIGRATING.md](MIGRATING.md#upgrading-to-20)).

## Known issues in unserviced lines

Fixed in `v2.0.0`, present in every `v1.x` and `v0.1.x` release, and not
backported:

- **A push or store source that misreports its own length made the store record
  bytes the caller never supplied.** `length` on a typed array is an ordinary
  property, so a `Uint8Array` subclass holding two bytes but reporting 512 caused
  the copy to allocate 512 bytes from Node's shared buffer pool and write only
  the two real ones. The remainder was whatever that pool last held, and the
  entry's `size` and digest were computed over it, so the store certified content
  it was never given and charged `maxSize` and `maxTotal` for it. In a process
  handling more than one tenant's bytes, the padding could carry another entry's
  plaintext.

  Reaching it requires the embedding application to pass an object it does not
  control as a push or store source. An application passing its own `Buffer`,
  string, `Readable`, or ordinary `Uint8Array` was never affected. `v2.0.0`
  copies by the view's real byte length, which no property can forge.

  If you are on `v1.x` and cannot upgrade, report it through the process above
  and a backport will be reconsidered.

## Continuous fuzzing

The store's untrusted-input surfaces are fuzzed continuously with jazzer.js:
hostile ref strings, the disk backend's entry-sidecar bytes, its tombstone-grave
bytes, and the self-describing digest parser (`"<algo>:<hex>"`). Pull requests
that touch `src/` get a short burst against every target, and a scheduled run
each night fuzzes for longer.

The targets treat a typed `StashError` as the correct fail-closed verdict on
hostile input. Anything else that escapes, an untyped exception or a hang, is
reported as a crash, and its reproducer is kept as a run artifact. The harness
lives in `.clusterfuzzlite/`, with a plain-node seed-corpus check at
`node .clusterfuzzlite/local-smoke.js` that runs in the smoke pipeline and needs
no engine, and it never ships in the npm tarball.

The engine is installed only inside the fuzzing job, outside the checkout, so the
library keeps zero dependencies including dev. ClusterFuzzLite drove these same
targets previously and its workflows remain in the tree on manual dispatch; it
cannot currently build a JavaScript project, which the note at the top of
`.github/workflows/cflite_pr.yml` records in full.

## Hardening a deployment

### Run under the Node permission model

The store is designed to run with the WRITE grant scoped to its root. The read
grant must also cover the app's own source, since Node loads its module graph
(your code and `node_modules`) from disk, so it spans the app directory; only the
store's directory is writable. Create that directory first, because under the
sandbox the backend fills it but cannot create it, which would need write on its
parent:

```
mkdir -p .stash
node --permission --allow-fs-read=. --allow-fs-write=./.stash app.js
```

`--permission` does not gate the network on Node 24.x; StashJS opens no sockets
regardless. This is a process-level filesystem allowlist, not per-module
isolation. It bounds what the whole process can touch, StashJS and every
dependency loaded in it, so a compromised dependency cannot escape to the wider
filesystem. Code sharing the process can still read the stash root, so run the
store in its own process to isolate it from other in-process code.

Use `v2.2.1` or later under `--permission`. On Node 24.22.0 and later the
permission model refuses `FileHandle.sync()`, and the disk backend in `v2.2.0`
and earlier calls it on every write, so every disk push fails with
`ERR_ACCESS_DENIED`.

### Let the store own its directory

The disk backend creates its layout `0700` and `0600` and enforces realpath
containment itself: a symlink planted inside the root is refused rather than
followed, which the permission model alone does not stop. Point `root` at a
dedicated directory and let the backend create it rather than pre-seeding it.

### Never log refs or `meta` values

A ref is a capability, so a ref in a log file is a leaked capability. Log counts
and error codes.

### Treat `StashError` codes as the branch surface

Messages may change between patches. Codes are frozen (see SPEC.md section 10).

### Size the store's limits before exposing `push` to any network path

`maxSize` bounds each entry mid-stream and `maxEntries` and `maxTotal` bound the
whole store, so a request flood, or a single unbounded upload, becomes a loud
`SizeExceeded` or `StashFull` instead of a full disk. An oversized source is cut
off at the limit rather than written and then measured, and a rejected push
leaves no partial behind. `maxTotal` counts the stored footprint, each blob plus
its metadata, so a caller cannot slip past it with many tiny blobs carrying large
`meta`.

### Set `maxTotal` against the real endpoint

The limit is a ceiling you choose; it does not read the disk. A `maxTotal` above
the partition's free space never fires: the filesystem fills first, and the write
dies with an I/O error instead of a clean `StashFull`.

Keep it below the free capacity of the backing partition, leave slack for the
one-entry sidecar overshoot and for block-granularity rounding on many small
entries, and keep `maxSize` at or below `maxTotal`. On the memory backend the
ceiling is the process heap rather than a partition. SPEC.md section 8.2 has the
full sizing guidance.

### A pop or budgeted read is claimed, not locked in memory

Concurrent `pop(ref)`, and concurrent budgeted `apply`, race on an atomic
filesystem claim, a hard link on disk. Exactly one reader drains and the rest
reject `RefClaimed`. The last read credit cannot be double-spent, and a credit is
charged only on a full, digest-verified drain, so an abandoned or corrupted read
never consumes budget.

A process killed mid-pop leaves a claim rather than a lost entry. The next
construction reclaims it on its first operation, resolving it per `onPopFailure`.

Recovery reclaims a claim purely by age, so this is a single-writer-per-root
model. Keep one process on a disk root, and set `claimTimeout` **above** the
longest `pop` or budgeted read that process can run. Otherwise a legitimately
slow reader's claim looks abandoned and gets reclaimed out from under it, and the
once-only read is gone. A non-positive `claimTimeout` is refused at construction,
since it would reclaim an active pop instantly. A claim survives a crash on disk
only; the memory backend is process-lifetime by definition.

The `stashjs` CLI is a second process opening a disk root, so the same rule binds
it. Point it only at a stash whose owning process is stopped, or at a
cold-standby replica: every command except `verify` runs the crash-recovery scan
and can reclaim a claim a live app is mid-read on. The CLI exposes only the query
and maintenance verbs, so it never moves bytes, hands out no capability, and
keeps its errors capability-free, and it runs under the same `--permission` grant
as the library.

### Only choose `onPopFailure: 'burn'` when a partial read must never be retried

The default `'restore'` is the safe choice for irreplaceable bytes. A pop that
fails or is aborted mid-stream, through a dropped connection or a digest
mismatch, leaves the entry intact, so the read is simply retried and nothing is
lost.

`'burn'` destroys the entry on that same failed drain, with no second chance,
deliberately reinstating the data loss the claim/stream/commit cycle exists to
prevent. It is sound only when the loss is acceptable: a genuinely one-shot token
whose bytes must not be served again even after a broken read, or bytes the
caller can re-obtain elsewhere. If losing the entry to a dropped connection would
be a bug for the caller, the bytes are irreplaceable and `'burn'` is the wrong
policy. The choice is store-wide and fixed at construction; there is no
per-`pop` override.

### Replication cannot resurrect a destroyed entry, if `tombstoneTtl` is set right

Every early destruction leaves a tombstone, and `store()` refuses a tombstoned
id, so a `store` racing a `drop`, or a sync replaying an old copy, never brings a
burned entry back within the tombstone window.

That window is the one setting the deployment owns. `tombstoneTtl` (default
`'30d'`) must comfortably exceed the longest gap between reconciliations, or a
grave is pruned before a lagging replica has seen it and the id can return.
StashJS cannot know the sync schedule, so it documents this floor rather than
enforcing it. Size it against your slowest replica, not an arbitrary number.

A tombstone records only `{ id, destroyedAt, cause }`. It never carries the
destroyed entry's digest, size, or `meta`, so a grave cannot leak the content the
destruction removed.

Replicating a `reads: 1` entry to more than one node weakens exactly-once to
eventually-once, since each node serves one read before the graves converge.
Serve reads from a single node, a cold standby, unless that tradeoff is a
deliberate choice.

## What StashJS deliberately does not do

StashJS cannot decrypt anything. No method takes a key, and no cipher primitive
is imported anywhere in the tree, a CI-enforced invariant (SPEC.md section 13.1).
It does not deduplicate, compress, inspect, or index contents. The threat model
behind each refusal is in [THREAT-MODEL.md](THREAT-MODEL.md) and SPEC.md section
3.
