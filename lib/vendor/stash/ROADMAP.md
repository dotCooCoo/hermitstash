# Roadmap

`SPEC.md` is the contract, and its section 12 defines the milestones. This file
records what landed in which release.

The section 12 delivery plan is complete and the public surface is stable. There
are no unshipped milestones; later releases are hardening, fixes, and capability
work on top of the finished plan.

## M1, Skeleton. SHIPPED (0.1.0)

`errors.js`, `ref.js` (generation and the whitelist), `duration.js`,
`MemoryBackend`, and `push` / `apply` / `show` / `list` / `drop` / `clear`.
Round-trips a Buffer and a Readable through memory, all errors typed, traversal
refs rejected before any storage access, digest-verified reads.

## M2, Disk. SHIPPED (0.1.1)

`DiskBackend`: sidecar metadata, atomic tmp+fsync+rename writes, `0700` and
`0600` permissions, realpath containment that refuses a planted symlink rather
than following it, strict size-bounded sidecar validation, and streaming both
directions. The M1 conformance suite passes unmodified against both backends,
and the library suite passes under `--permission` scoped to the test root.

## M3, Expiry. SHIPPED (0.1.5)

A construct-time `ttl` default, overridable per push (`null` clears it), with
`expiresAt` stamped once at push and never extended.

Lazy expiry runs on every read verb: an expired entry is `RefNotFound` and is
dropped in passing, before any sweep. `list()` filters expired entries by
default, and `includeExpired` reveals them. `prune()` reaps on demand and
returns the real destruction count. A `sweepInterval` arms an `unref()`'d
background sweep that never blocks process exit, skips overlapping ticks, and
cannot crash the process on failure. `close()`, and `Symbol.asyncDispose` for
`await using`, stops the timer.

## M4, Limits. SHIPPED (0.1.6)

`maxSize` bounds each entry and is enforced as the bytes stream: the count is
checked before each chunk reaches the backend, so an oversized or unbounded
source aborts with `SizeExceeded` at the limit instead of filling the disk.

`maxEntries` and `maxTotal` bound the whole store. A push that would exceed
either is refused with `StashFull`, and nothing already stored is evicted.
Expired-but-unswept entries are pruned before the store is judged full, so a
dead entry never blocks a live push, and every rejected push leaves no partial
behind. The backend contract gains `stats()` for the aggregate the checks read.

## M5, Pop and budgets. SHIPPED (0.1.7)

`pop(ref)` reads an entry and destroys it the instant the stream drains cleanly.
Two concurrent pops race on an atomic claim, so exactly one drains and the other
rejects `RefClaimed`.

`push(source, { reads: N })` gives an entry a finite read budget on the same
claim machinery. A credit is spent only on a full, digest-verified `apply`
drain, concurrent budgeted readers serialize so the last credit is never
double-spent, and the read that exhausts the budget destroys the entry. A read
that fails to drain is resolved by `onPopFailure`, restored by default or
burned.

On the disk backend, a claim abandoned by a process killed mid-pop is reclaimed
on the next construction, on the first operation, with `claimTimeout` setting
the grace window before a stale claim is resolved. An interrupted commit is
finished, never resurrected, and a drop during a live claim is monotone. The
backend contract gains the claim lifecycle: `claim`, `restore`, `commit`,
`listClaims`, `consumeRead`, `isClaimed`.

## M6, Audit. SHIPPED (0.1.8)

`verify(opts?)` audits physical integrity. It re-hashes every blob with the
entry's own algorithm and reports damage as `{ scanned, findings, repaired }`,
covering `digest-mismatch`, `size-mismatch`, `corrupt-sidecar`, `missing-blob`,
`orphan-blob`, `orphan-tmp`, `foreign-file`, and `stale-claim`. It is a dry run
by default; `{ repair: true }` removes only what it condemns, sparing healthy
entries, a live push's in-flight `.tmp`, and a claim recovery owns. Damage is a
finding; an I/O fault throws.

A `Stash` becomes an `EventEmitter`, emitting `'pushed'`, `'popped'`,
`'dropped'`, `'expired'` once per reaped entry, and `'sweepError'`, never
`'error'`, with full defensive-copy Entry payloads emitted after commit. It is
also async-iterable. `has(ref)` is a boolean existence check, and `stats()`
returns `{ entries, bytes, claimed }`. The backend contract gains `verify`.

## M7, Replication. SHIPPED (0.1.9)

Every early destruction (`pop`, `drop`, `clear`, a spent read budget) writes a
tombstone of `{ id, destroyedAt, cause }` and nothing more, so a destroyed id
never comes back. Expiry writes none, because terms travel with the entry.

`store(entry, source)` is the replication-grade insert. It files an
already-created entry with its identity preserved, proceeds through the section
4.4 order of checks (malformed id, tombstoned id, expired, identical, digest
conflict, else write), verifies the bytes against the supplied digest and size
as they stream, and emits nothing, so a sync daemon never hears its own writes.

`tombstones()` returns the graves for reconciliation; feeding each id to a
replica's `drop()` converges two stores with no resurrection. `tombstoneTtl`
(default `'30d'`, `null` never prunes) reaps a grave once older than the window,
riding the existing sweep. The backend contract gains `writeTombstone`,
`hasTombstone`, `listTombstones`, and `removeTombstone`.

## M8, Docs. SHIPPED (0.1.10)

Three runnable, self-asserting examples under `examples/`: a lifecycle
walkthrough, a cold-standby replication sketch, and a permission-model grant
demonstration that re-execs itself under `--permission` and proves an
out-of-scope write is denied. All run in CI, so a broken example fails the
build.

The README gains a verb table mapped to the git-stash mental model and an
error-code table generated from `src/errors.js`, with a drift check keeping it
in sync. The public surface is documented in full through the source comment
blocks the wiki renders. No library surface changed: the `SPEC.md` section 12
delivery plan is complete.

## M9, Digest agility. SHIPPED (0.1.12)

The integrity hash becomes a construct-time choice.
`new Stash({ backend, digest })` selects `sha256` (the default, unchanged),
`sha512`, `sha3-256`, `sha3-512`, or `shake256`, all `node:crypto` builtins, so
the zero-dependency rule holds. There is still no key and no cipher: this is
integrity, not confidentiality.

The stored digest is self-describing (`"algo:hex"`), so `apply`, `pop`, and
`verify()` hash each entry with its OWN algorithm and one store may mix them.
`store()` replicates an entry with its algorithm intact. Omitting the option
keeps `sha256`, so every existing store is byte-identical.

## Hardening, disk file identity. SHIPPED (0.1.13)

On a filesystem without `O_NOFOLLOW`, the disk backend cross-checks an open
descriptor's identity against a no-follow lookup of the name, to catch a symlink
traversed at open or a name swapped after it.

That check keyed on device and inode alone. Windows can transiently report inode
`0` for a file under heavy parallel I/O, so two distinct files could be mistaken
for one, a fail-open in the swap guard. The identity comparison now also
requires size and creation time to agree. The terms are ANDed, so the check is
strictly more selective and an untampered read still matches. It is the single
choke point behind both the read-path swap guard and the crash-recovery
interrupted-claim check.

## Operational CLI. SHIPPED (0.1.14)

The store gains its first executable entry point. The `stashjs` command
(`npx @blamejs/stash <command>`) inspects and maintains a disk-backed stash from
the shell, with `verify` (and `--repair`), `stats`, `prune`, `list` (and
`--include-expired`), `tombstones`, and `has <ref>`, printing a human table by
default and `--json` for scripting.

It composes only the already-shipped query and maintenance verbs: it never moves
bytes and never destroys by ref, so it hands out no capability and streams no
blob. The root is taken from `--root`, `$STASH_ROOT`, or `./.stash`, and must
already exist. It fails closed with stable exit codes, keeps every error
capability-free, and runs under `--permission` exactly as the library does.
Being a second process on a disk root, it is single-writer: point it at a
quiesced store or a cold-standby replica.

## Replication and recovery hardening. SHIPPED (0.1.15)

`reconcilable()` is a resilient anti-entropy source read. It returns the healthy
entries to replicate plus the ids of entries whose sidecars are too damaged to
read, so one corrupt entry no longer halts the sync of every sound one, while
`list()` stays loud over corruption for an audit.

`store()` reconciles on byte identity rather than the algorithm-tagged digest
string, so two stores holding the same bytes under different digest algorithms
reconcile idempotently instead of throwing a spurious conflict. It is verified
byte-for-byte, bounded by the stored entry's size, so a lying or oversized
replica still fails closed. The disk backend's blob rename now rides out a
transient filesystem fault, as its sidecar and claim renames already did.

Crash recovery and the claimed-read path are hardened throughout. A live
reader's claim is guarded from the moment acquisition begins, so a forward
wall-clock step can never hand a once-only entry to a second reader nor destroy
a read mid-drain. A claim orphaned by a faulted resolution is always reclaimed
rather than stranded, a crash-corrupted sidecar on a claimed entry no longer
wedges every operation, and a replicated entry with an exhausted read budget is
rejected.

## Backend contract and conformance harness. SHIPPED (0.1.16)

The SPEC.md 9 backend interface becomes a declared stable contract with an
executable form. The `@blamejs/stash/conformance` subpath exports
`runBackendConformance(factory, { test })`, the behavioral suite the in-tree
memory and disk backends pass, so a store this library does not bundle certifies
interchangeability against the same cases without cloning the repository. It
imports no test runner, so a backend author wires their own.

A prototype-key-confusion class (CWE-1321) is closed in the two lookups keyed by
untrusted strings, a stored digest's algorithm prefix and a CLI subcommand
token, either of which could resolve an inherited `Object.prototype` member as a
phantom. Both now gate membership on `Object.hasOwn`, guarded by a source-wide
detector.

Documentation gains a CommonJS consumption guarantee, a soundness criterion for
the `'burn'` pop-failure trade, the Node-floor rationale, and the memory
backend's claim semantics without a filesystem.

## Crash recovery never burns, and clock posture. SHIPPED (0.1.17)

`onPopFailure: 'burn'` destroys a read entry on the assumption that a read
attempt may have observed its bytes, but crash recovery applied it even to a
claim whose process died before any byte was read, turning a crash into silent
data destruction.

`onPopFailure` now governs only the LIVE read path, a mid-drain failure resolved
in-process. Crash recovery of a stale orphan ALWAYS restores it and never burns,
since a crashed process observed nothing recovery can confirm, and a crashed
once-only read is safer to hand back than to destroy.

The store's wall-clock posture is now documented (SPEC.md 7.2): what each
time-based decision reads, and how the store behaves under a clock step in
either direction. The README shows materializing an entry to a file in a single,
digest-verified copy; there is no `materializeTo`, because piping the verified
stream is already single-copy and backend-agnostic.

## Documentation and comment clarity. SHIPPED (0.1.18)

A sweep of the tarball's prose, covering source comments, the threat model, and
the architecture and spec docs, so every shipped explanation describes what the
store does and how to use it, readable with no prior context.

Comments that named internal build artifacts a reader cannot resolve, narrated
when a feature was added rather than what it does, or described not-yet-shipped
work now state the current, shipped behavior directly. No API, behavior,
on-disk format, or documented guarantee changed. Prose only.

## v1.0, Stable. SHIPPED (1.0.0)

The `SPEC.md` section 12 delivery plan is complete and the public surface is
declared stable. Every verb, option, error code, and on-disk format now carries
a semantic-versioning commitment: a breaking change ships a new major, preceded
by a deprecation warning at least one minor ahead
([MIGRATING.md](MIGRATING.md)) and covered by the support window in
[LTS-CALENDAR.md](LTS-CALENDAR.md).

`v1.0` is the final `v0.1.x` store unchanged, with no API, behavior, or format
change, and that commitment attached, so consumers upgrade with
`npm install @blamejs/stash@1` and no code changes.

## v2.0. SHIPPED (2.0.0)

Two error verdicts change class so a caller can branch on them, and nothing else
does. An oversized `meta` is rejected as `IntegrityError` (`EINTEGRITY`) rather
than a bare `TypeError`, matching the read side of the same bound. The shared
source check no longer names a verb it cannot know, and `runBackendConformance`
enforces the `name` its `{ name, create() }` contract always specified, labelling
every case with it. A `Uint8Array` from another realm is accepted as a source,
and a source that misreports its own length is copied by its real byte length
rather than its claimed one.

There is no on-disk format change, so a `v1.x` store opens under `v2.0`
unmodified. This major shipped without a preceding deprecation minor, an
exception to the commitment above, recorded in
[MIGRATING.md](MIGRATING.md#policy) alongside the reason.

## v2.0.1. SHIPPED (2.0.1)

Every example in the API documentation now runs on each build. The one that had
quietly stopped working, the snippet for `close()`, which used `Stash` without
importing it, is corrected.

## v2.0.2. SHIPPED (2.0.2)

The package now contains the documents it tells you to read. README and
SECURITY.md pointed at `ARCHITECTURE.md` and `THREAT-MODEL.md`, neither of which
shipped in the tarball, so a reader following the README's own reading list found
nothing. Six documents were added to the published file list, and the packaging
gate was widened to catch a filename named in prose rather than only one behind a
markdown link.

The contributor setup instructions documented a test command that fails on
current Node and silently skips a chaos vector. Every document was rewritten for
clarity, and the source comments, which ship in the tarball and generate the API
reference, are considerably shorter.

## v2.1.0. SHIPPED (2.1.0)

New entries are hashed with `sha3-512` instead of `sha256`. Entries written
before this release keep their own algorithm and keep verifying, because a stored
digest has always been self-describing, and a store may hold both. Replication
reconciles on byte identity rather than on the digest string, so stores on either
side of the change still converge. `digest: 'sha256'` pins the previous
behaviour and has existed since 0.1.12.

Two costs come with it. SHA-3 has no hardware acceleration where SHA-2 does, so
the new default hashes at roughly a sixth of the old rate, and the store hashes
every byte on the way in and again on every verified read. A `sha3-512` digest is
also 64 more hex characters, so each entry's metadata grows by about that much.

`maxTotal` no longer under-charges the digest. The capacity check runs before the
backend finalizes an entry, and it measured the sidecar while `digest` was still
`null`, so a store could finish 69 bytes over the limit under `sha256` and would
have gone to 135 under the new default. The charge now uses the width the digest
will be stored at, taken from the algorithm registry, and the overshoot is about
three bytes regardless of algorithm.

This release is a minor carrying a consumer-visible change, which the policy in
[MIGRATING.md](MIGRATING.md#policy) makes a major. The deviation and its
reasoning are recorded there rather than the policy being rewritten.

## v2.2.0. SHIPPED (2.2.0)

The Node floor moves from 24.19.0 to 24.21.0. It stays a floor rather than a
ceiling, and nothing the store does depends on a capability that first shipped in
24.21. The move lands inside the window the LTS calendar freezes a major's Node
minimum for; that is a commitment this release does not meet, and it is recorded
in `MIGRATING.md` under "Exceptions taken" rather than left to be discovered. On
Node 24.19.0 or 24.20.0, `npm` warns and installs while Yarn 1 and any
`engine-strict` setting refuse.

Node 24.21.0 also added `crypto.createPrivateKey()` backed by an OpenSSL STORE
loader, reached through a new `--allow-openssl-store` grant. A loader may reach
files, devices, tokens, or the network, and its access is not bounded by the
`fs.read` and `fs.write` scopes, so the grant opens a path the filesystem
allowlist does not cover. The store needs no key, so the flag is never passed and
the sandboxed suite runs with it denied.

The check enforcing that guarantee matched cipher calls only, which reads it as
"does not encrypt" when it is "holds no key". A key arrives through
`createPrivateKey`, `createSecretKey`, a `generateKeyPair`, a WebCrypto
`importKey`, or a KDF long before any cipher names it, so all of those are now
refused in `src/` too.

Three drift fixes ride along. The lockfile check compares `engines.node`, which
it had never read, so a raised floor no longer ships with the two files
disagreeing. The release container was pinned to an image carrying Node 24.18.0,
below the floor the package declares. The container reproducing the CI runtime
locally tracked a rolling tag and drifted away from the pinned CI version in
either direction.

## v2.2.1. SHIPPED (2.2.1)

The Node floor moves from 24.21.0 to 24.22.1, the current security release of the
Node 24 line. It stays a floor rather than a ceiling, and nothing the store does
depends on a capability that first shipped in 24.22. Like the `v2.2.0` move, it
lands inside the window the LTS calendar freezes, and it is recorded in
`MIGRATING.md` under "Exceptions taken".

Node 24.22.0 added two crypto APIs that take key material: `createMac(algorithm,
key)` and `parsePKCS12(bundle)`, which returns the private keys a PKCS#12 bundle
carries. The import allowlist already refused both, because neither is one of the
three `node:crypto` names `src/` may import. The forbidden-token check now names
them too, so a commented-out sketch that names either one is refused as well.

Node 24.22.0 also made the permission model refuse `FileHandle.sync()` and
`.datasync()`. The disk backend called `sync()` after every blob, sidecar,
tombstone and read debit, so on Node 24.22.0 and later every disk write under
`--permission` failed with `ERR_ACCESS_DENIED`, `v2.2.0` included. The backend
now opens those files with `O_DSYNC`, a path operation the write grant covers,
and issues blob writes in 1 MiB units. Measured on Linux, per-chunk `O_DSYNC`
at 64 KiB wrote about 33 MiB/s, while 1 MiB units wrote about 370 MiB/s, close
to the `sha3-512` hash rate the push already runs at.

## v2.2.4. SHIPPED (2.2.4)

`engines.node` is now `>=24.22.1 <25 || >=26.12.1`. The previous `>=24.22.1`
admitted Node 26 releases before 26.12.1, which lack the security fixes 24.22.1
carries. The docs-site container's base image moves from Node 26.5.0 to
26.12.1. A new gate, `scripts/check-node-pins.js`, checks every Node runtime
pinned in the tree against `engines.node`; in CI it also runs the docs-site base
image to read its Node version.

## v2.3.0. SHIPPED (2.3.0)

`engines.node` is now `>=26.13.1`, and Node 24 is out of range. The floor moves
inside the `v2.x` window in a minor release; the deviation is recorded in
`MIGRATING.md` under "Exceptions taken".

A `pop` or budgeted `apply` whose entry is dropped, cleared or reaped by expiry
during the read now completes on both backends with exactly one lifecycle event.
Expiry leaves an entry alone while an in-process claim holds it. The disk
backend counts `*.tmp` files in `stats().bytes`, so `maxTotal` bounds partial
writes. `runBackendConformance` gains cases for large payloads, byte
accounting, `verify()`, `reconcilable()` and grave pruning.

## Standing constraints

Every release honors the one rule (no decrypt capability), zero dependencies,
ESM-only, streaming-first, and the do-not-build list (`SPEC.md` sections 1
through 3).

The constructor refuses any option it does not implement, so nothing is ever
accepted-but-unenforced. The mechanism stays in place for a future spec'd
option; today every option `SPEC.md` defines is implemented and enforced.
