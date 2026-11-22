# @blamejs/stash architecture

A contributor's guide to where things live and why the pieces are shaped the way
they are. This doc is the orientation map. The authoritative contract is
[SPEC.md](SPEC.md), and the contributor disciplines are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Top-level layout

```
stashjs/
|-- src/
|   |-- index.js          # Single export surface: Stash, the typed errors, version
|   |-- stash.js          # Policy layer: TTL, limits, read budgets, claim lifecycle, events
|   |-- ref.js            # Ref generation, whitelist validation, timing-safe comparison
|   |-- entry.js          # The canonical Entry schema (one shape, both directions) + tombstones
|   |-- digest.js         # The integrity-hash registry: algorithm set, stored digest shape
|   |-- validate.js       # Config-time input-shape validation (option + plain-object whitelists)
|   |-- constants.js      # C.TIME / C.BYTES / C.REF: every scale literal, deep-frozen
|   |-- duration.js       # '24h' to milliseconds (composes C.TIME)
|   |-- size.js           # '100mb' to bytes (a sibling to duration, its own scale table)
|   |-- errors.js         # StashError base + the typed subclasses with stable codes
|   |-- cli.js            # The `stashjs` command: query and maintenance verbs only
|   |-- conformance.js    # runBackendConformance: the backend contract, executable
|   `-- backends/
|       |-- memory.js     # Map-backed backend
|       `-- disk.js       # Sidecar-file backend: atomic writes, realpath containment
|-- test/                 # node:test suites; one conformance suite shared across backends
|-- examples/
|-- SPEC.md               # The contract
`-- package.json
```

Consumers use one import:

```js
import { Stash } from '@blamejs/stash';
import { MemoryBackend } from '@blamejs/stash/backends/memory';

const stash = new Stash({ backend: new MemoryBackend() });
const ref = await stash.push(bytes);
const entry = await stash.show(ref);
```

## The two layers: policy and backend

The load-bearing split is SPEC.md section 9: **`Stash` holds the policy; the
backend holds the bytes.** The backend is the only thing that touches storage.

- **`Stash` (src/stash.js)** owns everything that is a decision: TTL and expiry,
  size and count limits, read-budget accounting, the claim lifecycle for
  destructive reads, the `onPopFailure` policy, event emission, and ref
  validation at every public entry point.
- **A backend** implements a fixed async storage interface, and nothing else:
  `write`, `read`, `claim`, `restore`, `commit`, `consumeRead`, `isClaimed`,
  `remove`, `stat`, `list`, `listReconcilable`, `listClaims`, `stats`, `verify`,
  `writeTombstone`, `hasTombstone`, `listTombstones`, `removeTombstone`. It
  stores and retrieves; it does not decide.

Because the policy layer never touches storage directly, both backends run the
same conformance suite, and a behavior implemented once in `Stash` (lazy expiry,
budget accounting, the claim cycle) cannot diverge between them.

Two backends ship, per the spec's "no cloud backends" rule. **MemoryBackend** is
Map-backed with no persistence and no pretense; it exists so tests and consumers
can exercise the full contract without a filesystem. **DiskBackend** uses sidecar
metadata files rather than a central index, so there is no index to corrupt and
no lock contention, and it is crash-safe by construction. It writes to a tmp file
opened with `O_DSYNC` and renames it into place, so a reader never sees a partial
blob. It enforces realpath
containment that refuses planted symlinks, validates sidecars under a strict size
bound, and uses `0700` and `0600` modes throughout.

The interface is a public extension point, not an internal detail. A backend this
library does not ship certifies against the same cases through
`@blamejs/stash/conformance`; see SPEC.md section 9.1.

## Refs are capabilities, not addresses

SPEC.md section 5 is the identity design, and it is deliberate:

- A ref is `'v1_' + randomBytes(32).toString('base64url')`, 256 bits,
  unguessable. Refs are **not** content hashes. A content hash is guessable by
  anyone holding the content, which turns the store into an enumeration oracle,
  and dedup, the usual payoff, buys nothing when the payload is ciphertext.
- The `digest` on each entry is integrity-only. It is never a lookup key and
  never appears on an API surface that accepts it as input.
- Ref comparison uses `timingSafeEqual`.
- **Refs become filenames, so ref validation is path-traversal defense.** Every
  ref entering a public method must match `/^v1_[A-Za-z0-9_-]{43}$/` exactly
  before it touches anything, or it is `InvalidRef`. No normalization, no
  `path.resolve` rescue. A whitelist, and it stays a whitelist.

## `pop`: the claim, stream, commit cycle

Destructive reads are the hard part (SPEC.md section 6). A naive
delete-then-stream loses data the moment a connection drops mid-read, so `pop` is
a three-phase cycle with a defined failure path:

1. **Claim.** Atomically move the entry to a claimed state (`fs.rename` on disk,
   atomic within a filesystem). Two concurrent `pop(ref)` calls race on the
   rename; exactly one wins, and the loser gets `RefClaimed`. Once-only is
   enforced at the filesystem, not with an in-process lock.
2. **Stream.** Read from the claimed location, verifying the digest
   incrementally.
3. **Commit.** On full drain with a matching digest, delete.
4. **Fail.** On stream error, premature destroy, or digest mismatch, apply
   `onPopFailure`. The default `'restore'` keeps the entry so the read can be
   retried. The opt-in `'burn'` treats any read attempt as observation, so the
   entry must not survive.

Crash recovery rides the same machinery. Claims older than `claimTimeout` are
resolved on the first operation after construction, lazily, because constructors
do no I/O. Read budgets (SPEC.md section 4.1) reuse the claim path too: the read
that spends the last credit destroys the entry through the same commit path as
`pop`, so there is nothing new to get wrong.

## The monotone lifecycle

SPEC.md section 4.2: **every state change moves an entry closer to destruction,
never further.** `readsLeft` only decrements, claims only resolve, expiry only
arrives. There is no `touch()`, no TTL extension, and no metadata mutation,
because an entry that can be argued back from the brink is a retention liability
rather than a stash. New terms mean a new push.

This rule is also the acceptance filter for future features. Anything that would
let an entry outlive its terms at push time is rejected on sight.

## Typed errors

Every failure is a typed class extending `StashError` with a stable `.code`
(SPEC.md section 10): `RefNotFound` and `ENOREF`, `RefClaimed` and `ECLAIMED`,
`IntegrityError` and `EINTEGRITY`, `SizeExceeded` and `E2BIG`, `StashFull` and
`EFULL`, `InvalidRef` and `EBADREF`.

Consumers branch on the code, never on message text. No message ever contains a
ref, a `meta` value, or a path, because refs are capabilities and error text ends
up in logs.

## The permission-model posture

The library is designed to run cleanly under Node's stable permission model
(SPEC.md section 2.1):

```
mkdir -p .stash
node --permission --allow-fs-read=. --allow-fs-write=./.stash app.js
```

This is the crypto-agnosticism argument enforced by the runtime instead of by
discipline. The whole process is confined to the app directory and its store:
read spans the app's own module graph, since Node loads it from disk, and write
is scoped to the store. Nothing wider is reachable. It is a process-level
filesystem allowlist, not per-module isolation.

The design implications are mandatory. No child processes, no worker threads, no
native addons, no WASI, since each would need its own grant. Paths only, never
file descriptors, because fds bypass the model. No `process.permission.has()`
branching: if the grant is wrong, the `ERR_ACCESS_DENIED` surfaces loudly.

The permission model follows symlinks out of granted paths, so symlink
containment is the DiskBackend's own job. It realpaths the root at construction,
asserts every resolved path stays under it, and uses `lstat` rather than `stat`
so a planted symlink reads as corruption rather than as a blob.

`--permission` does not gate the network on this Node line. The store opens no
sockets regardless, which is the actual guarantee.

## Constraints the layout encodes

1. **Zero dependencies, including dev dependencies.** Node builtins only; tests
   are `node:test` and `node:assert/strict` run with plain `node --test`.
2. **Crypto-agnostic.** `node:crypto` is imported for `createHash`,
   `randomBytes`, and `timingSafeEqual` only. There is no key parameter on any
   method and nowhere for one to live, so the store cannot decrypt what it holds,
   by construction.
3. **ESM, plain JavaScript, no build step.** What ships is what runs, on Node
   26.13.1 as a floor.
4. **Streaming-first.** No method buffers an entire blob; limits are enforced
   mid-stream, and a rejected write cleans up its partial.
5. **Fail loud.** When full, `push` throws `StashFull`. There is no eviction,
   because stash entries are promises rather than cache hints, and silently
   destroying the oldest entry would turn a push flood into an attack on other
   people's data.

## Explicit non-goals

SPEC.md section 3 is load-bearing, and it binds contributors and maintainer
alike. The store will not grow any of the following:

- Encryption.
- Content addressing or dedup.
- Compression.
- A `node:sqlite` index. It is still experimental, it loses to sidecar files on
  crash-safety, and, decisively, its filesystem access bypasses the permission
  model.
- Mimetype sniffing, or any content inspection.
- An HTTP server.
- Cloud backends.
- Eviction.
- `touch()`, TTL extension, or metadata mutation.
- Namespaces.
- A sync transport or oplog.
- Logging of refs or `meta` values.
- Telemetry.

Each entry has its reasoning in the spec. Read it before proposing the
improvement.

## Implementation status

Everything this document describes is shipped code. The SPEC.md section 12
delivery plan is complete, and the public surface is stable;
[ROADMAP.md](ROADMAP.md) records what landed when.

- **Typed errors and refs.** The frozen `StashError` code set, and refs generated
  as 256-bit random capabilities validated against a whitelist before any storage
  access.
- **Two backends.** `MemoryBackend` and `DiskBackend`, both driven through one
  conformance suite.
- **The verb set.** `push`, `apply`, `show`, `list`, `drop`, `clear`, plus `pop`
  and `store`.
- **Expiry.** Per-entry `ttl`, lazy expiry on read, `prune()`, the `unref()`'d
  sweep timer, and `close()` with `Symbol.asyncDispose`.
- **Size and count limits.** `maxSize` enforced mid-stream, `maxEntries` and
  `maxTotal`, `StashFull`, and `stats()`.
- **Pop and read budgets.** The claim lifecycle, `reads` budgets, `onPopFailure`,
  and crash recovery of orphaned claims.
- **Audit and lifecycle events.** `has` and `verify`, the event set (`pushed`,
  `popped`, `dropped`, `expired`, `sweepError`), and async iteration.
- **Replication.** Tombstones, `store()`, `tombstones()`, `reconcilable()`, and
  `tombstoneTtl`.
- **Digest agility.** A selectable integrity hash (`sha3-512` by default, plus
  `sha256`, `sha512`, `sha3-256`, `shake256`) with a self-describing stored
  digest, so a single store can mix algorithms.
- **The `stashjs` CLI.** Inspect and maintain a disk-backed stash from the shell
  with `verify`, `stats`, `prune`, `list`, `tombstones`, and `has`.
- **A consumable backend conformance contract.** The same cases run against every
  backend, unmodified.

## Where to read first

If you're new to the codebase, read in this order:

1. [SPEC.md](SPEC.md), the contract, including the "do not build these" list and
   the reasoning behind it.
2. `src/index.js`, the export surface.
3. `src/errors.js`, the typed-failure shape everything uses.
4. `src/ref.js`, capability generation and the traversal-defense whitelist.
5. `src/stash.js`, the policy layer.
6. `src/backends/memory.js`, the backend interface in its simplest
   implementation.
7. `test/`, the shared conformance suite. The SPEC.md section 13 list is the test
   plan.

This is enough orientation to start contributing without spelunking every module.
