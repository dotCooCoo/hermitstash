# Threat model

`@blamejs/stash` holds bytes other systems consider sensitive. Its first consumer
stores encrypted uploads for scenarios up to and including a whistleblower drop.
The store itself never sees plaintext and never holds a key, but it does hold the
capabilities that gate access, the promise that a popped entry is gone, and, with
the disk backend, a directory an attacker would love to escape.

This document states what the library defends, where the trust boundaries are,
the threat classes it is designed against, and what is explicitly out of scope.
Every defense below is implemented in the shipped store.

## Assets

- **Ref confidentiality.** A ref is a capability. Whoever holds it can read and
  destroy the entry; nobody without it can. The ref must be unguessable,
  unenumerable, and must not leak through errors or logs.
- **The destruction guarantee.** A popped, dropped, expired, or budget-spent
  entry must actually be gone, and must stay gone, including across replicas.
- **Entry integrity and survival.** Bytes read out are the bytes pushed in. A
  failed read must not silently destroy data, and a full store must not silently
  destroy other entries to make room.
- **Containment.** The store's filesystem footprint is its root directory and
  nothing else, even against hostile refs and planted symlinks.

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Refs arriving at any public method | **Untrusted** | Whitelist regex (`/^v1_[A-Za-z0-9_-]{43}$/`) before anything else; `InvalidRef` otherwise |
| Blob bytes (`push` sources) | **Untrusted, opaque** | Never interpreted, sniffed, or inspected; size-limited mid-stream |
| `meta` values | **Untrusted, opaque** | Round-tripped verbatim; never read, validated, indexed, or logged |
| Replication input (`store()` entries) | **Untrusted** | Full check order of SPEC.md section 4.4: ref whitelist, tombstone refusal, expiry no-op, idempotency, digest-conflict rejection |
| The filesystem under the stash root | **Semi-trusted** | Realpath containment, `lstat` symlink rejection, digest verification |
| Constructor options (backend, TTL, limits, policies) | **Operator-provided (trusted)** | Taken as configuration |

## Threat classes and design response

### 1. Compelled-operator disclosure

Someone with legal or physical leverage over the operator demands the contents.

**Response.** The store cannot decrypt anything. There is no key parameter on any
method, no cipher import anywhere in the source tree, and no `decrypt` option. A
store that *chooses* not to decrypt is a promise; a store with nowhere for a key
to live is an architecture, and only the second survives compulsion. Encryption
belongs to the consumer, which is the thing with the key.

This is architectural, and enforced by an executable invariant: the source greps
clean of `createCipheriv` and `createDecipheriv` (SPEC.md section 13.1).

### 2. Ref guessing and enumeration (CWE-330, CWE-340; timing side CWE-208)

An attacker probes for entries they suspect exist.

**Response.** Refs are 256-bit random values, not content hashes. A content hash
is guessable by anyone holding the content, which would make the store an
enumeration oracle for "did someone stash this document." The digest is
integrity-only and is never accepted as a lookup key. Ref comparison uses
`timingSafeEqual`, so a comparison cannot leak prefix matches.

### 3. Path traversal via refs (CWE-22, CWE-23, the Zip-Slip class)

Refs become filenames, so a hostile ref is a hostile path.

**Response.** Every ref entering a public method must match the whitelist regex
character-for-character before it touches the filesystem. `../../etc/shadow` dies
at the regex, not at the syscall. No normalization, no `path.resolve` rescue, no
clean-it-up-and-continue. The whitelist runs at every public method, and the disk
backend revalidates at its own public boundary.

### 4. Symlink escape from the stash root (CWE-59, CWE-61)

Something plants a symlink inside the root pointing outside it.

**Response.** Node's permission model follows symlinks out of granted paths, so
containment is the library's job rather than the sandbox's. The DiskBackend
realpaths its root at construction, asserts every resolved blob, meta, and claim
path is still under that root (refusing with `InvalidRef` otherwise), and uses
`lstat` rather than `stat`, so a symlink where a blob should be reads as
corruption rather than as a blob. Planted-symlink and swapped-directory cases are
covered. The sidecar is also size-bounded before parse (CWE-770) and strictly
shape-validated (CWE-20).

### 5. Push flood and disk fill (CWE-400, CWE-770)

An attacker, or a `curl` loop, pushes until the disk is full.

**Response.** `maxSize` is enforced mid-stream: the write is destroyed and the
partial cleaned up the moment the limit is crossed, never written and then
checked. `maxEntries` and `maxTotal` reject with `StashFull`.

There is **no eviction**. Silently destroying the oldest entry to make room would
turn a push flood into an attack on other people's data, and for a whistleblower
drop, into a denial-of-evidence primitive. The loud rejection is the feature, and
no-eviction is a standing design rule (SPEC.md section 3).

### 6. Partial-read data loss

A destructive read's connection drops at 60%, and the bytes are gone while the
reader got half a file.

**Response.** `pop` is a claim, stream, commit cycle. The delete happens only
after a full drain with a matching digest, and a failed read applies the
`onPopFailure` policy: `'restore'` by default, since losing data by default is
hostile and the entry survives for retry, or `'burn'` as an explicit opt-in for
stores that treat any read attempt as observation. Claims orphaned by a crash are
recovered per the same policy.

### 7. Capability leakage through errors, logs, and telemetry (CWE-209, CWE-532)

A ref in a log file is a leaked capability.

**Response.** No error message ever contains a ref, a `meta` value, or a path;
errors carry stable `.code` values instead. The library itself logs nothing and
phones nothing home, and the `stats()` surface returns aggregates only, never
refs. Event payloads carry full entries by design, because the embedder owns the
store, and the no-refs-in-logs rule binds what the embedder writes out. Typed
errors carry no identifier, and the logging and telemetry prohibitions are
standing design rules (SPEC.md sections 3 and 10).

### 8. Replication resurrection

Naive sync copies a popped entry straight back from a replica that still holds
it, and the dead walk.

**Response.** Every early destruction (`pop`, `drop`, `clear`, a spent read
budget) writes a tombstone recording only `{ id, destroyedAt, cause }`. It
carries no digest, no size, and no `meta`, because a tombstone that describes the
body defeats the burial. `store()` refuses a tombstoned id outright and no-ops an
entry whose expiry has already passed, so destruction is monotone across
replicas.

The residual risk is documented rather than hidden. Tombstones are pruned after
`tombstoneTtl`, and that TTL must exceed the longest gap between reconciliations,
a knob only the deployment can set. A read budget is enforced per store, so
multi-replica serving degrades exactly-once to eventually-once; the spec directs
consumers to a cold-standby topology if they need the stronger guarantee.

### 9. Silent corruption (the CWE-354 class, validated rather than skipped)

Bit rot, or a tampered blob served as good bytes.

**Response.** A digest is computed during the write stream and verified
incrementally on read, and a mismatch is a loud `IntegrityError`, never silent
bad bytes. `verify()` audits the whole store for corrupt blobs, orphaned halves,
and stale claims, and removes nothing without an explicit `repair: true`.

### Defense in depth around all of the above

The library is designed to run under Node's permission model with filesystem
grants scoped to the stash root (SPEC.md section 2.1): no child processes, worker
threads, native addons, or WASI; paths only, never file descriptors; fail loud on
`ERR_ACCESS_DENIED` rather than silently degrading. The suite passes under
`--permission` scoped to the test root, enforced as a CI gate.

Note that `--permission` does not gate the network on this Node line. The store
opens no sockets regardless, which is the actual guarantee.

## Out of scope

- **Plaintext confidentiality.** The store holds opaque bytes and cannot decrypt
  them, but it also cannot encrypt them. If the bytes arrive as plaintext, they
  sit on disk as plaintext. Encryption is the consumer's layer, by design.
- **An attacker with the operator's privileges.** File modes (`0600`, `0700`) and
  the permission-model posture raise the bar, but an attacker running as root or
  as the stash-owning user reads the blobs. This is precisely why the payload
  should arrive encrypted.
- **Access control beyond ref possession.** A ref is the authorization. There are
  no users, ACLs, or scopes; anyone holding a ref can read and destroy that
  entry.
- **Durability.** The store is ephemeral by design. TTLs, read budgets, and `pop`
  destroy data on purpose, and there is no backup mechanism. It is not an
  archive.
- **Transport security.** The library opens no sockets. Protecting bytes and refs
  in flight, including the replication transport, is the consumer's
  responsibility.
- **Memory forensics and swap.** Bytes stream through process memory. Defending a
  compromised or memory-captured host is out of scope.

## Reporting

Security issues are reported privately via GitHub's
["Report a vulnerability"](https://github.com/blamejs/stash/security/advisories/new)
advisory form, never through a public issue.
