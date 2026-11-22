# Changelog

All notable changes to `@blamejs/stash` are documented here, newest first.

## 2.3.0 — 2026-11-20

`engines.node` is now `>=26.13.1`, so Node 24 and Node 26 releases before
26.13.1 are out of range. Moving the floor inside the `v2.x` window is
recorded in MIGRATING.md under "Exceptions taken". No verb, option, error
class or error code changed. If you run on Node 24, upgrade Node before you
upgrade to `v2.3`; see MIGRATING.md, "Upgrading to 2.3". If you publish a
third-party backend, run `runBackendConformance` again: it now covers large
payloads, byte accounting, `verify()`, `reconcilable()` and grave pruning, so
a backend that passed before can fail.

### Changed

- The supported Node range is `>=26.13.1`. CI, the fuzz and publish
  workflows, the release container and the docs-site image run Node 26.13.1.
- `runBackendConformance` adds five cases: a payload over 4 MiB checked by
  position, length and digest; `stats().bytes` accounting and the `maxTotal`
  bound it feeds; `verify()` and `reconcilable()` over every live entry;
  grave removal by `prune()` past `tombstoneTtl`; and `remove()` returning
  false after a claim commits.
- SPEC.md 9 states that `remove(id)` on a claimed id must destroy the entry,
  and that a later `commit(id)` for that claim must resolve or throw
  `RefNotFound`.

### Fixed

- A `pop` or budgeted `apply` that drained every byte with a matching digest
  rejected with `ENOREF` when expiry reaped the entry during the read
  (through `has`, `show`, `prune`, the sweep timer or a capacity check).
  Expiry now leaves an entry alone while an in-process claim holds it, and
  the read completes with one lifecycle event (#84).
- A `drop()` or `clear()` inside a live `pop` or budgeted `apply` claim
  failed the read with `ENOREF` on the memory backend, while on the disk
  backend the read completed and both `'dropped'` and `'popped'` were emitted
  for one entry. Both backends now complete the read, the destroyer writes
  the one grave and emits the one event, and the disk backend removes the
  claimed bytes when the read ends instead of after `claimTimeout` (#86).
- The disk backend's `stats().bytes` skipped `*.tmp` files, so partial files
  left by an interrupted write never counted against `maxTotal` and a store
  could hold several times its ceiling. Temporary files in `meta/`, `blobs/`
  and `claims/` now count until `verify({ repair: true })` removes them
  (#87).
- `runBackendConformance` certified backends that truncated large values,
  reported `bytes: 0`, returned a hollow `verify()` report, listed nothing
  from `listReconcilable()`, or reported a grave removed without removing it
  (#85).

## 2.2.5 — 2026-10-30

No release from `v2.2.0` through `v2.2.4` published
`ghcr.io/blamejs/stash-wiki`, because the release-container workflow failed
before the build. This release publishes the image again, on the Node 26.12.1
base `v2.2.4` pinned. The library code is identical to `v2.2.4`, so an npm
install does not need to move to `v2.2.5`. If you deploy the docs site with
`examples/wiki/docker-compose.prod.yml`, it now pulls `stash-wiki:2.2.5`.

### Fixed

- The release-container workflow installs git before it checks out the
  repository. The suite job runs in `node:24.22.1-alpine`, which has no git,
  so the checkout had no `.git` directory and the pack gate's `git ls-files`
  failed. The build, scan and publish jobs never ran.

## 2.2.4 — 2026-10-30

`engines.node` is now `>=24.22.1 <25 || >=26.12.1`. Node 24.22.1 and 26.12.1
fix CVE-2026-111497, an out-of-bounds write in the Brotli decoder Node
bundles. The previous range, `>=24.22.1`, also admitted Node 25 and every
Node 26 release before 26.12.1, none of which carry the fix. The Node 24
minimum is unchanged. On Node 25, or on Node 26 before 26.12.1, `npm` warns
and installs while Yarn 1 and any `engine-strict` setting refuse, so upgrade
Node. The narrowing lands inside the window the LTS calendar freezes a
major's Node minimum for, and it ships as a patch; both are recorded in
MIGRATING.md under "Exceptions taken". No verb, option, error code or on-disk
layout changed.

### Added

- `scripts/check-node-pins.js` checks every Node version pinned in the
  repository against `engines.node`: `.node-version`, `.nvmrc`, the CI,
  fuzzing, publish and release-container workflows, and
  `docker-compose.test.yml`. It also requires `examples/wiki/package.json` to
  declare the same range. It runs in `npm run gates` and `npm run smoke`. In
  CI, `--image` also runs the docs-site base image with `--version` and
  checks the result, since that image is pinned by digest.

### Changed

- `engines.node` is `>=24.22.1 <25 || >=26.12.1`, in `package.json` and in
  `examples/wiki/package.json`.

### Security

- The docs-site container (`examples/wiki/Dockerfile`) pins a base image that
  runs Node 26.12.1. The previous pin ran Node 26.5.0, and a build of the
  Dockerfile with no build-args used it. If you deploy the docs site from
  that Dockerfile, rebuild it.

## 2.2.3 — 2026-10-27

`v2.2.1` and `v2.2.2` were tagged but never published to npm, because the
registry refused the publish credential. This release carries the same
library code as both and publishes it. If you install from npm, upgrade from
`v2.2.0` to `v2.2.3`; the `v2.2.1` notes and the `Upgrading to 2.2.1` section
of MIGRATING.md apply unchanged.

### Changed

- The package is published with an npm token held in the publish environment,
  not with trusted publishing as the `v2.2.2` notes describe. Provenance is
  attached as before; check it on the package's npm page or with `npm audit
  signatures`. The publish order and the rerun check that `v2.2.2` introduced
  are unchanged.

## 2.2.2 — 2026-10-27

`v2.2.1` was tagged and has a GitHub release, but it was never published to
npm, because the registry refused the publish credential. This release
carries the same library code as `v2.2.1` and publishes it. If you install
from npm, upgrade from `v2.2.0` to `v2.2.2`; the `v2.2.1` notes and the
`Upgrading to 2.2.1` section of MIGRATING.md apply unchanged.

### Changed

- The package is published with npm trusted publishing. The registry
  exchanges the publish job's GitHub OIDC token for a short-lived credential,
  so no npm token is stored in the repository. Provenance is attached as
  before; check it on the package's npm page or with `npm audit signatures`.
- The publish workflow publishes to npm before it creates the GitHub release,
  so a refused publish no longer leaves a GitHub release for a version the
  registry does not serve. A rerun after a successful publish compares the
  registry's `dist.integrity` with the validated tarball and, when they
  match, skips the publish and creates the release.

## 2.2.1 — 2026-10-27

Node 24.22.0 made the permission model refuse `FileHandle.sync()`. The disk
backend called it after every blob, sidecar, tombstone and read debit, so
with `v2.2.0` on Node 24.22.0 or later every disk write under `--permission`
failed with `ERR_ACCESS_DENIED`. The backend now opens those files with
`O_DSYNC`, which the write grant covers, so each write still reaches stable
storage before it returns. If you run the disk backend under `--permission`,
upgrade. The package now requires Node 24.22.1, the current security release
of the Node 24 line. On Node 24.21.0 or 24.22.0, `npm` warns and installs
while Yarn 1 and any `engine-strict` setting refuse, so upgrade Node. The
move lands inside the window the LTS calendar freezes a major's Node minimum
for, and it ships as a patch; both are recorded in MIGRATING.md under
"Exceptions taken". No verb, option, error code or on-disk layout changed.

### Changed

- The Node floor moves from 24.21.0 to **24.22.1**, and `.node-version`,
  `.nvmrc`, the CI runtime, the fuzzing and publish workflows, the release
  container and the local CI-runtime container move with it. It remains a
  floor and not a ceiling: any newer 24.x, and later majors per the LTS
  calendar, are supported. Nothing the store does depends on a capability
  that first shipped in 24.22. On Node 24.21.0 or 24.22.0, upgrade Node;
  nothing else changes.
- The disk backend writes a blob in 1 MiB units. Each write is synchronous,
  and a source that yields small chunks would otherwise wait on one device
  flush per chunk: on Linux, 64 KiB synchronous writes measured about 33
  MiB/s and 1 MiB writes about 370 MiB/s. Each chunk is copied into the unit
  before the next is read, so a source that reuses its buffer after yielding
  stores what it yielded.

### Fixed

- The disk backend no longer calls `FileHandle.sync()`, which the permission
  model refuses on Node 24.22.0 and later. Every file it writes (blob,
  sidecar, tombstone, and the in-place read debit) is opened with `O_DSYNC`
  instead, so a write is durable when it returns. A pattern check refuses any
  descriptor-based `sync`, `datasync`, `fsync`, `fdatasync`, `fchmod` or
  `fchown` call in `src/`.
- The forbidden-token check refuses `createMac` and `parsePKCS12` in `src/`.
  Node 24.22.0 added both: `createMac(algorithm, key)` takes a key directly,
  and `parsePKCS12(bundle)` returns the private keys a PKCS#12 bundle
  carries. The import allowlist already refused importing either one, since
  neither is among the three `node:crypto` names `src/` may import, but the
  token check is the layer that also reads comments, and it did not name
  them.

## 2.2.0 — 2026-09-10

Node 24.21.0 added `crypto.createPrivateKey()` backed by an OpenSSL STORE
loader, reached through a new `--allow-openssl-store` grant whose access is
not bounded by the `fs.read` and `fs.write` permission scopes. The store
holds no key and never asks for that grant, but the check that enforces it
matched cipher calls only, so a key-ingestion API could be added to the
source with every gate green. It now matches key ingestion, generation,
derivation and agreement, and the sandboxed suite records that the grant is
denied. The floor move is the part that can affect you. It lands inside the
window the LTS calendar freezes a major's Node minimum for, which is a
commitment this release does not meet; it is written down in MIGRATING.md
rather than left to be found. Nothing in the library's surface changed, and a
process already running on 24.19.0 is unaffected until it reinstalls.

### Changed

- The Node floor moves from 24.19.0 to **24.21.0**, and `.node-version`,
  `.nvmrc` and the CI runtime move with it. It remains a floor and not a
  ceiling: any newer 24.x, and later majors per the LTS calendar, are
  supported. Nothing the store does depends on a capability that first
  shipped in 24.21. On Node 24.19.0 or 24.20.0, `npm` warns and installs
  while Yarn 1 and any `engine-strict` setting refuse, so upgrade Node;
  nothing else changes. The LTS calendar freezes a major's Node minimum for
  its security-patch window and this move is inside that window, which is
  recorded in MIGRATING.md under "Exceptions taken".
- The no-key guarantee is enforced by two allowlists rather than a list of
  forbidden calls. `src/` may import only the builtins it is granted, so a
  module that accepts key material is refused by not appearing on the list:
  `node:tls`, `node:https` and `node:http2` take a private key through their
  secure-context options, and `node:module` hands back a loader that reaches
  any builtin under any alias. From `node:crypto` it may import only the
  three names `SPEC.md` section 1 grants -- `createHash`, `randomBytes` and
  `timingSafeEqual`. A default, namespace or wildcard binding is refused
  because it hides which names are reached, a re-export is held to the same
  list, and a specifier carrying a backslash is refused whatever it would
  decode to, since escapes are resolved before the module is.
- The forbidden-token check that backs it covers key ingestion, generation,
  derivation and agreement, not only the cipher calls that consume a key.
  `createPrivateKey`, `createSecretKey`, `createPublicKey`, `createHmac`,
  `generateKey*`, WebCrypto `importKey` / `deriveKey` / `deriveBits`,
  Diffie-Hellman and ECDH, `createSign` / `createVerify`, the `hkdf` /
  `pbkdf2` / `scrypt` derivations, and `passphrase` are all refused in
  `src/`, alongside the ciphers already covered. It reaches what an import
  check cannot: a commented-out sketch, a `node:sqlite` index, a password
  surface.
- The permission-model posture names OpenSSL STORE loaders. A STORE loader
  may reach files, devices, tokens, or the network, and its access is not
  constrained by the filesystem grants, so `--allow-openssl-store` is never
  passed and the sandboxed suite runs with it denied.

### Fixed

- The lockfile check compares `engines.node` between `package.json` and
  `package-lock.json`. Raising the Node floor edits `package.json` alone, so
  the two shipped disagreeing until an unrelated install rewrote the
  lockfile, and no other gate read the field.
- The release container builds on the Node the package supports. It was
  pinned to an image carrying Node 24.18.0, below the floor the package
  declares.
- The container that reproduces the CI runtime locally is pinned to an exact
  Node tag. It tracked the rolling `node:24-alpine` tag, which moves whenever
  the Node line does and drifted away from the version CI pins, in either
  direction and without notice.

## 2.1.0 — 2026-08-22

The default integrity hash changes and nothing else does: same verbs, same
options, same error codes, same on-disk layout, no migration step and no data
to convert. A stored digest has always carried its own algorithm, so an entry
written before this release is still read, verified, and audited with the
algorithm it was written with, and a store may hold both without complaint.
Replication reconciles on byte identity rather than on the digest string, so
a 2.0 store and a 2.1 store still converge. What changes is what a new push
records: `sha3-512:<128 hex>` where it used to be `sha256:<64 hex>`. That is
consumer-visible, which under the policy this project published at 1.0 would
make it a major; it ships as a minor by maintainer decision, and the
deviation is recorded in MIGRATING.md rather than the promise being quietly
rewritten. Two costs are worth knowing before you upgrade. SHA-3 has no
hardware acceleration where SHA-2 does, so the new default hashes at roughly
a sixth of the old rate, and the store hashes every byte on the way in and
again on every verified read. And a `sha3-512` digest is 64 more hex
characters than a `sha256` one, so each entry's stored metadata grows by
about that much, which counts against `maxTotal`. Both are bought back by
naming `digest: 'sha256'` explicitly.

### Changed

- The `digest` constructor option now defaults to `sha3-512`. It previously
  defaulted to `sha256`. The set of accepted values is unchanged: `sha3-512`,
  `sha256`, `sha512`, `sha3-256`, `shake256`, all `node:crypto` builtins.
  This is integrity, not confidentiality; there is still no key and no cipher
  anywhere in the store.
- The published API surface is otherwise identical. No verb, option, error
  code, event, or on-disk format changed, and the primitive count in the API
  snapshot is unchanged.

### Fixed

- `maxTotal` now charges an entry's digest at the width it will be stored at,
  so a push that fills the store no longer overshoots the limit by the length
  of a hash. The capacity check runs before the backend finalizes the entry,
  and it used to measure the sidecar while `digest` was still `null`, which
  under-counted by the whole hex string: a store could end up 69 bytes over
  `maxTotal` under `sha256` and would have gone to 135 under the new default.
  The overshoot is now about three bytes and no longer depends on which
  algorithm you choose. The check still never over-counts, so it cannot
  refuse an entry that would have fit.
- The architecture, specification, and README all described `sha256` as the
  default in prose. They now describe the shipped default, and each states
  the throughput trade so the choice is visible at the point a reader picks
  an algorithm.

## 2.0.2 — 2026-08-21

A documentation and packaging release. No API, behavior, error, or on-disk
format changes: a 2.0.1 store opens under 2.0.2 unchanged and every verb does
exactly what it did. What changes is what arrives when you install the
package, and whether the prose in it is accurate. Four documents that shipped
docs referred to were missing from the tarball, so a reader who followed the
README's own reading list found nothing; they now ship, and the packaging
gate was widened so it catches a filename named in prose, not only one behind
a markdown link. Widening it immediately found two more instances of the same
defect. Separately, the contributor setup instructions documented a test
command that fails on current Node and silently skips a chaos vector, several
documents still described the store as pre-1.0 more than a year of releases
later, and the architecture document's module map omitted three modules that
have shipped since it was written. Every document has been rewritten for
clarity, and the source comments, which ship inside the tarball and generate
the API reference, are substantially shorter.

### Added

- `ARCHITECTURE.md`, `THREAT-MODEL.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, and `SUPPORT.md` now ship in the
  published package. Installing `@blamejs/stash` gives you the full document
  set, and every cross-reference between shipped documents resolves to a file
  that is actually there.

### Changed

- Every operator-facing document has been rewritten: the README's feature
  list is now a set of scannable sections rather than one unbroken block,
  long explanatory paragraphs are split at their topic boundaries, and dash
  punctuation has been restructured into ordinary sentences throughout. No
  documented guarantee, option, error code, or default changed wording that
  alters its meaning; the specification's section numbering is
  byte-identical, so every reference to it still resolves.
- The source comments are considerably shorter. They ship inside the tarball
  and generate the API reference, so they are text a reader encounters.
  Signature restatements, repeated rationale, and narrative about how a piece
  of code came to be are gone; the reasoning behind each non-obvious
  defensive construct is kept, in shorter form.
- The documentation site's sitemap no longer reports a `lastmod` date. The
  pages are generated when the server boots, so the only date it could
  compute was the current one, which restamped every URL as freshly modified
  on each restart. `changefreq` and `priority` are gone with it, for the same
  reason: they were self-reported hints with nothing behind them.

### Fixed

- The packaging check now verifies a document reference written as a bare
  filename in prose, not only one written as a markdown link. The narrower
  check is why the README could tell a tarball reader to open two files the
  tarball did not contain while the gate stayed green. Widening it found two
  further references to a document that was not shipping.
- The contributor setup instructions documented `node --test test/` as the
  way to run the suite. That command fails outright on current Node versions,
  and where it does run it silently skips the vector that needs a forced
  garbage collection. The documented command is now `npm test`, which passes
  the flag the suite requires.
- `ARCHITECTURE.md`, `THREAT-MODEL.md`, and `GOVERNANCE.md` described the
  store as feature-complete pre-1.0, and `SUPPORT.md` said the supported
  version was whatever was published most recently because the project was
  pre-1.0. All four now describe the shipped support policy, which is that
  only the current major receives fixes.
- The module map in `ARCHITECTURE.md` omitted `digest.js`, `cli.js`, and
  `conformance.js`, three modules the same document described further down.
- `LTS-CALENDAR.md` told consumers still on a `v0.x` release to upgrade to
  `v1.x`, a line the same document records as unserviced two sections later.
  It now points them at the current major.
- `SECURITY.md` and `SUPPORT.md` asked reporters for a `v0.X.Y` version tag,
  a version series that has not been current since 1.0.
- Six threat-class headings in `THREAT-MODEL.md` rendered a bold full stop
  after the CWE reference, and two documents broke a hyphenated word across a
  line so it rendered with a space after the hyphen.
- The documentation site invited crawlers to index its search page, which
  renders a different result set for every query string and duplicates pages
  already in the sitemap. Search results now carry `noindex,follow`, and the
  page stays crawlable on purpose so that tag can be read: a `robots.txt`
  disallow would stop the fetch, leaving an already-indexed URL with no way
  to observe the removal request. The health probe answers JSON and carries
  no tag, so it is the one path `robots.txt` holds back. The link preview
  card also declared a wide image while the only image on the site is the
  square logo, so a share preview letterboxed it; the card type now matches
  the asset, and its dimensions are declared so a scraper need not fetch the
  file to lay the card out.

## 2.0.1 — 2026-08-11

A documentation-correctness release. No API, behavior, error, or on-disk
format changes: a 2.0.0 store opens under 2.0.1 unchanged and every verb does
exactly what it did. What changes is the standard the documented examples are
held to. The `@example` blocks in the source comments generate the API
reference and ship inside the tarball, so they are code a reader copies --
but nothing had ever run them. They were compiled and the result discarded,
which catches a syntax error and nothing else: an example calling a method
that has been renamed, or passing an option the code stopped accepting,
parses perfectly and is still wrong. All of them now execute on every build,
each in its own process, and the build fails if one does not. Turning that on
found a broken example on the first run, fixed here. Examples are also now
resolved through the package's published `exports` map, so a snippet
importing a subpath the package does not publish fails the build rather than
the reader's terminal.

### Added

- The build executes every `@example` in the published documentation and
  fails if one of them does not run. Each example runs as a real module in
  its own process and counts as verified only when that process exits cleanly
  -- an example that hands its work to a test runner, as the
  backend-conformance snippet does, is judged on the assertions rather than
  on the import returning. Import specifiers resolve through this package's
  own `exports` map, so an example naming `@blamejs/stash/backends/disk` is
  checked against what the package actually publishes, and an example whose
  body is only prose or only imports is rejected for showing no call. There
  is no way to opt an example out. CONTRIBUTING.md describes what an example
  may assume.

### Fixed

- The example for `close()` constructed a `Stash` without importing it, so
  copying it produced a `ReferenceError`. It now carries the import the other
  constructor examples do. This was the only documented example that did not
  run; the rest were confirmed correct by executing them.

## 2.0.0 — 2026-08-07

A small, sharp-edged major, and one memory-disclosure fix. This release ships
WITHOUT a preceding deprecation minor -- an exception to the post-1.0
commitment, recorded with its reason in MIGRATING.md, so read the recipe
rather than relying on having been warned at runtime. Everything the store
does is otherwise unchanged: the verb set, the on-disk format, the ref
format, expiry and read budgets, replication, digest agility, and the CLI all
behave exactly as they did in 1.x. What changes is how a few failures report
themselves. Rejecting an entry whose metadata is too large for a sidecar is a
judgement about stored content, not about a caller's argument -- so it now
throws `IntegrityError` with code `EINTEGRITY`, the same verdict the read
side of that identical bound has always used, and the same class every other
content rejection uses. Previously it threw a bare `TypeError` with no code
at all, labelled `push:` even when `store()` was the caller, which left a
replication path reporting a verb the caller never invoked and an error the
documented `err.code` contract could not describe. Separately,
`runBackendConformance` now requires the `name` its published `{ name,
create() }` contract has always specified and labels every registered case
with it; certifying two backends in one run previously produced two identical
sets of test titles with nothing to distinguish a failure. Upgrading is two
mechanical edits at most, both listed in MIGRATING.md, and neither touches
stored data: no migration, no re-write, no format change. A 1.x store opens
under 2.0 unchanged.

### Changed

- The Node floor moves from 24.18.0 to **24.19.0**. It remains a floor and
  not a ceiling -- any newer 24.x, and later majors per the LTS calendar, are
  supported -- and nothing the store does depends on a capability that first
  shipped in 24.19; the patch level is a security-currency floor, kept
  current at the major boundary where raising it is not a surprise. Consumers
  pinned below 24.19.0 upgrade Node; nothing else changes.
- Fuzzing runs the same targets under jazzer.js directly instead of through
  ClusterFuzzLite, whose action cannot build a JavaScript project at any
  sanitizer setting. Pull requests touching `src/` get a burst against every
  target and a scheduled run fuzzes longer each night, with a crash's
  reproducer kept as a run artifact. The seed-corpus verdict check still runs
  with plain Node and no engine. The engine is installed only inside the
  fuzzing job and outside the checkout, so the zero-dependency posture --
  runtime and dev -- is unchanged.
- An entry whose `meta` is too large for a sidecar is now rejected with
  `IntegrityError` (code `EINTEGRITY`) instead of `TypeError`. The bound is
  enforced by the backend write that serves both `push()` and `store()`, and
  a replicated entry is untrusted stored input, so the rejection is a content
  verdict carrying a code you can branch on -- matching how the read side of
  that same bound has always reported an over-large sidecar. If you catch
  this case, catch `IntegrityError` (or branch on `err.code ===
  'EINTEGRITY'`) rather than `TypeError`. The message no longer names a verb,
  because the line cannot tell which one called it.
- `runBackendConformance(factory, ...)` now requires `factory.name` to be a
  non-empty string, and prefixes every case it registers with it. The `{
  name, create() }` contract already specified `name`, and the type check
  already named it, but nothing enforced or used it -- so a third-party
  author certifying two backends in one run got two byte-identical sets of
  test titles and a failure that named no backend. If you were passing only
  `{ create }`, add a `name`.
- `v1.x` is superseded and will NOT receive security patches, withdrawing the
  24-month window `v1.0` announced would open when its successor shipped.
  `v1.x` had no known consumers and `v2.0` is a two-edit upgrade with no
  on-disk format change, so the line is retired rather than serviced. The
  memory-disclosure fix below therefore ships only in `v2.x`; LTS-CALENDAR.md
  and SECURITY.md record both facts. If you are on `v1.x` and cannot upgrade,
  open a security advisory and the position will be revisited.
- A `Uint8Array` created in another realm -- a `vm` context, a second module
  loader -- is now accepted as a `push()` or `store()` source. It was already
  accepted when yielded as a chunk, so the two paths disagreed about the same
  value, and the documented source set names `Uint8Array` with no realm
  qualifier. An 8-bit unsigned view remains the only typed array that may
  pass: a `Uint16Array` is still refused, because copying one would silently
  store a single byte per element.

### Fixed

- A source that misreported its own length could make the store record bytes
  the caller never supplied. `length` on a typed array is an ordinary
  property, so a `Uint8Array` subclass holding two bytes but reporting 512
  caused the copy to allocate 512 bytes from Node's shared pool and write
  only the two real ones -- padding the entry with whatever the pool last
  held, and certifying a size and digest over content that was never handed
  over. Sources are now copied by their real byte length, which no property
  can forge. A store embedded alongside other tenants was the exposure; the
  affected copy also charged `maxSize` and `maxTotal` for the phantom bytes.
- The shared source check no longer names a verb. `push()` and `store()` both
  reach it, so its message said `push:` even when `store()` was the caller --
  the same defect the sidecar-size verdict fixes, one function above it.
- The temp-file grace period was documented as making `verify` report an
  in-flight `.tmp` without repairing it. It reports neither, and it does
  discard one aged past the grace under `{ repair: true }`.
- `consumeRead`'s sidecar rewrite was described as atomic. It is deliberately
  an in-place rewrite through a single descriptor -- which is what prevents a
  concurrent `drop()` from being undone -- and a crash mid-write is caught by
  the next read, which rejects the short sidecar.
- `clear()` resolves to the number of live entries destroyed. Entries that
  had already expired are reaped as well but are not counted, and each live
  destruction leaves a `'clear'` grave visible through `tombstones()`. None
  of this was stated.
- The memory backend's tombstone map stores `id` alongside `destroyedAt` and
  `cause`, and consumers read that `id`; the field comment omitted it,
  inviting an edit that would have broken replication.
- Constructor option errors now all carry the `new Stash:` prefix. Seven of
  nine were missing it, so the same option could report two
  differently-shaped messages depending on which check rejected it.

## 1.0.0 — 2026-07-23

The store is feature-complete and the surface it presents is now a contract.
Bytes in, a random-capability ref out, bytes out once and they're gone: the
git-stash verb set, per-entry expiry and read budgets, streaming size and
store-wide limits, integrity verification and audit, tombstone-based
replication, digest agility, and the operational CLI are all shipped and
frozen against breaking change. From 1.0, a breaking change ships a new major
preceded by a deprecation warning at least one minor ahead, and each major
carries a 24-month security-patch window after its successor ships. Nothing
about the code, the API, the on-disk format, or any documented guarantee
changed in this release -- 1.0 is the final 0.1.x store with a commitment
attached, so consumers upgrade with `npm install @blamejs/stash@1` and no
code changes. The one load-bearing property is unchanged and now permanent:
there is nowhere in the store to put a key, so it can never decrypt, and no
operator can be compelled to.

### Changed

- The public API surface is declared stable under semantic versioning. Every
  verb (`push`, `apply`, `pop`, `show`, `has`, `list`, `reconcilable`,
  `stats`, `tombstones`, `store`, `drop`, `clear`, `verify`, `prune`,
  `close`), every constructor option, every typed error code, the ref format,
  and the on-disk sidecar format are covered: a breaking change ships a new
  major, preceded by a deprecation warning at least one minor ahead and a
  migration recipe. See MIGRATING.md and LTS-CALENDAR.md.
- The support policy takes effect: each major receives 24 months of
  security-only patches beginning when its successor ships, on the
  zero-dependency posture (no third-party CVE lane -- a vulnerability is in
  this library's code or in Node itself). The Node floor is 24.18.0.
- The published package now includes the support-window calendar
  (LTS-CALENDAR.md), the vulnerability-disclosure policy (SECURITY.md), and
  the roadmap (ROADMAP.md) alongside the changelog, migration guide, and
  spec, so every cross-reference in the packaged README resolves for a
  consumer reading the extracted tarball rather than pointing at a file the
  package omits.

## 0.1.18 — 2026-07-23

A sweep of the tarball's prose -- the source comments, the threat model, the
architecture and spec docs -- to remove development-process voice in favor of
plain descriptions of the store's behavior. Comments that named internal
build artifacts a reader cannot resolve (numbered internal-rule and
fragile-area references), narrated when a feature was added rather than what
it does (milestone and version tags like `(M4)` or `implemented in M2`), or
described planned-but-not-yet work now state the current, shipped behavior
directly. The code, the API surface, the on-disk format, and every documented
guarantee are unchanged -- this release only makes the shipped explanations
read for someone encountering the store for the first time.

### Changed

- Source comments and the operator-facing docs (SPEC.md, THREAT-MODEL.md,
  ARCHITECTURE.md, README.md, CONTRIBUTING.md) now describe the store's
  behavior and how to use it rather than how it was built: internal
  build-order and milestone tags, references to internal development
  conventions a reader cannot resolve, and phrasing that narrated
  version-to-version change were replaced with plain statements of the
  current shipped behavior. The threat model states each defense as
  implemented fact without per-defense build-provenance tags; the
  architecture doc presents the shipped surface as a capability list. No API,
  behavior, format, or guarantee changed -- prose only.

## 0.1.17 — 2026-07-23

The default `'restore'` policy has always kept a failed read's entry for
retry. `'burn'` is the opt-in that destroys a read entry on the assumption
that a read attempt may have observed its bytes -- but crash recovery applied
it even to a claim whose process died before any byte was read, turning a
crash into silent data destruction that burn's own rationale does not
justify. `onPopFailure` now governs only the LIVE read path -- a read that
fails mid-drain, resolved in-process by its own handler. Crash recovery of a
stale orphan always RESTORES it and never burns, since a crashed process
observed nothing recovery can confirm and handing a once-only read back for a
retry is safer than destroying it. The store's wall-clock posture -- and its
behavior under a clock step in either direction -- is now written down.

### Changed

- The store's clock posture is now documented (SPEC.md 7.2): every time-based
  decision -- expiry, claim-lease freshness, tombstone pruning -- reads the
  wall clock, because each must survive a restart and, for expiry and
  pruning, agree across replicas. Expiry and pruning are deterministic (an
  absolute `expiresAt` / `destroyedAt`, not skew-sensitive); a live reader's
  claim is immune to a clock step; and a backward step only defers a
  destruction the push-time terms already permit -- it never destroys an
  entry early nor lets one outlive its terms.
- The README documents materializing an entry to a file in a single,
  digest-verified copy (`pipeline(await stash.apply(ref),
  createWriteStream(dest))`). The store deliberately offers no
  `materializeTo` method: a store-side copy would give up the digest-verified
  read, cross the store's write-scope boundary, and work only on a filesystem
  backend, where piping the verified stream is already single-copy and
  backend-agnostic.

### Fixed

- Under `onPopFailure: 'burn'`, crash recovery destroyed a stale claim left
  by a crashed process even when no byte had been read, turning a crash
  before any read into silent data destruction. `onPopFailure` now applies
  only to a LIVE read that fails mid-drain (resolved in-process); crash
  recovery of a stale orphan always RESTORES it and never burns, even under
  `'burn'`. The entry comes back for a retry and no tombstone is written. The
  default `'restore'` policy is unchanged.

## 0.1.16 — 2026-07-22

The SPEC.md 9 backend interface is now a public extension point with a stated
stability discipline, not an undocumented internal seam: any object
implementing its method set is a first-class backend for `new Stash({ backend
})`, and the contract is executable. The new `@blamejs/stash/conformance`
subpath exports `runBackendConformance(factory, { test })` -- the behavioral
suite the in-tree memory and disk backends pass -- so a store on a filesystem
this library does not ship certifies interchangeability against the same
cases without cloning the repository. It imports no test runner, so a backend
author wires their own. Alongside it, a prototype-key-confusion hole
(CWE-1321) is closed in two lookups keyed by untrusted strings: a stored
digest's algorithm prefix and a CLI subcommand token could name an inherited
Object.prototype member and resolve to a phantom the registry never defined
-- both now gate membership on Object.hasOwn, and a source-wide detector
keeps the class from reappearing. Documentation gains a CommonJS consumption
guarantee (pinned by a fixture), a soundness criterion for the `onPopFailure:
'burn'` trade, the rationale behind the Node floor, and the memory backend's
claim semantics without a filesystem.

### Added

- `@blamejs/stash/conformance` -- a shippable, zero-dependency,
  test-runner-agnostic backend conformance harness.
  `runBackendConformance(factory, { test, assert? })` registers the SPEC.md 9
  behavioral suite against your backend factory, driving the shipped `Stash`
  consumer path (push / apply / pop / store) and asserting the frozen error
  verdicts (ENOREF, ECLAIMED, E2BIG, EFULL), so a third-party backend
  certifies itself against the same cases the in-tree backends pass without
  cloning this repository. It imports no test runner -- you wire your own
  (`node:test` or otherwise) -- and the in-tree conformance run composes the
  identical harness against both backends, so there is one definition of the
  shared cases.
- SPEC.md section 9 now declares the backend interface a stable, spec-first
  contract: its method surface, its semantics (claim atomicity, consumeRead
  atomicity, tombstone first-write-wins, digest verification on read), and
  its error expectations change only with a spec change. Pre-1.0 that
  contract is stable within a version line.

### Changed

- CommonJS consumers can `require()` the main entry and both backend subpaths
  on the Node floor -- the module graph has no top-level await and imports
  only a synchronous JSON module -- now documented in the README and pinned
  by a spawned .cjs fixture against a future regression.
- The `onPopFailure: 'burn'` trade has a stated soundness criterion (SPEC.md
  6, SECURITY.md): `'restore'` (the default) keeps a failed pop's entry
  intact for retry and is safe for irreplaceable bytes, while `'burn'`
  reinstates partial-delivery data loss and is sound only when a partial read
  must never be retried and the loss is acceptable.
- The `>=24.18.0` Node floor's rationale is recorded (SPEC.md 2,
  LTS-CALENDAR.md): the capabilities the store relies on -- the stable
  permission model, explicit resource management, require(esm) -- arrived at
  the Node 24 major; the patch level is a security-currency floor, not a
  feature dependency.
- The MemoryBackend `@module` block documents its claim semantics without a
  filesystem -- the synchronous Map move as the atomicity two concurrent pops
  race on, a `claimedAt` stamp as the disk mtime analogue, and
  process-lifetime claims with no cross-process crash recovery -- and the
  bounded-insert capacity gate records its two-pass (prune then stats) design
  as an irreducible invariant.

### Security

- CWE-1321 (prototype-key confusion): a stored digest whose algorithm prefix,
  or a CLI subcommand token, named an inherited Object.prototype member
  (`constructor`, `__proto__`, `toString`, `valueOf`) resolved to that member
  instead of a registry miss. The phantom defeated the digest read's
  `algoOf(digest) ?? default` fallback -- turning a self-describing read into
  a crash on an algorithm the store cannot construct -- and slipped past the
  CLI's unknown-command guard so an inherited name was dispatched as a known
  command. Both lookups now gate membership on `Object.hasOwn`, so only a
  defined algorithm or command ever resolves and a non-registry key is always
  a clean miss; a source-wide detector fails the build on any reintroduction
  of the inline membership shape.

## 0.1.15 — 2026-07-18

A batch of replication- and recovery-correctness fixes. `reconcilable()` is a
new resilient query for the anti-entropy loop: `list()` stays loud on a
corrupt sidecar (right for an audit), but one damaged entry no longer halts
the replication of every healthy one -- `reconcilable()` returns the healthy
entries and reports the corrupt ids separately, so a sync keeps flowing and
surfaces the damage instead of stopping. `store()` now reconciles on byte
identity rather than the algorithm-tagged digest string, so two stores
holding the same bytes under different digest algorithms (a mixed-algorithm
topology, first-class since digest agility) reconcile idempotently instead of
throwing a spurious integrity conflict -- verified byte-for-byte, so
genuinely different bytes and a lying replica still fail closed, and the
reconcile no longer rejects an already-present entry just because the
receiving store's limit is now smaller. The disk backend's blob rename -- the
one mutation rename that was not retried -- now rides out a transient
filesystem fault (a briefly-held handle on Windows) exactly as the sidecar
and claim renames already do, so a legitimate push is not lost. And crash
recovery and the claimed-read path are hardened throughout: a live reader's
claim is guarded from the moment acquisition begins (so a forward wall-clock
step can never hand a once-only entry to a second reader, nor destroy a read
mid-drain), a claim orphaned by a faulted resolution is always reclaimed
rather than stranded, a crash-corrupted sidecar on a claimed entry no longer
wedges every operation, and a replicated entry with an exhausted read budget
is rejected. Documentation was also swept for stale single-algorithm digest
references left over from digest agility.

### Added

- `reconcilable()` -- a resilient reconciliation query returning `{ entries,
  corrupt }`: the healthy entries to replicate plus the ids of entries whose
  sidecars are too damaged to read. It is the source read for the documented
  anti-entropy loop, so one corrupt sidecar can no longer halt replication of
  the healthy entries; `list()` remains loud over corruption (an audit must
  be), and the corrupt ids are surfaced for `verify({ repair: true })`, never
  silently skipped.

### Fixed

- `store()` reconciles a replicated entry on BYTE IDENTITY, not the
  algorithm-tagged digest string. Two stores holding the same bytes under
  different digest algorithms carried different `"<algo>:<hex>"` strings, so
  an identical-bytes replica was rejected as a digest conflict and could
  never reconcile. It now settles the idempotent/conflict verdict on the
  bytes -- identical bytes reconcile as a no-op, genuinely different bytes
  still fail closed with `IntegrityError`, and a lying replica is caught --
  nothing is written and no id is resurrected.
- A same-bytes duplicate under a different digest algorithm now reconciles
  idempotently even when the receiving store's `maxSize` is smaller than the
  entry -- a lowered limit, or a replica with a tighter limit, no longer
  wedges mixed-algorithm anti-entropy on a spurious `SizeExceeded`. A
  reconcile writes nothing, so it bounds its byte-identity re-hash by the
  already-stored entry's own size; an oversized replica under an existing id
  is reported as an `IntegrityError` byte conflict, never a limit error.
- The claimed-read path (`pop` and budgeted `apply`) is hardened around crash
  recovery, which never age-reclaims a claim a live reader holds -- only
  orphan claims from a crashed prior run. The live-holder guard now protects
  a claim across its whole life: from the moment acquisition begins, through
  the drain, until it resolves. So a forward wall-clock step past
  `claimTimeout` can neither resurrect a once-only entry for a second reader
  during acquisition nor reclaim/burn the read a consumer is still mid-drain
  on; and a claim orphaned by a faulted resolution (a restore, commit, or
  burn that throws) is always reclaimed by recovery on the next operation,
  rather than stranded `ECLAIMED` until the process restarts. The guard is
  shared per store (keyed by backend identity), so even two `Stash` instances
  constructed over one store -- single-writer-per-root is the contract, but
  the guard holds regardless -- never age-reclaim each other's live reads.
- A crash during a budgeted read that leaves a claimed entry with a corrupt
  sidecar no longer wedges the entire store. Because crash recovery runs
  before every operation, one such entry previously made every call --
  `push`, `apply`, `pop`, `drop`, `list`, `stats` -- fail with an integrity
  error, with no way back. Recovery now reaps the unreadable entry; a genuine
  layout fault still fails loudly.
- `store()` rejects a replicated budgeted entry whose read budget is already
  exhausted (`readsLeft` 0) as malformed, instead of accepting it and then
  throwing on the first read: a live budgeted entry always has at least one
  read remaining, since the read that spends the last credit destroys the
  entry.
- Disk backend: the blob `.tmp`->final rename now retries a transient
  filesystem fault (a briefly-lingering handle, e.g. on Windows under
  contention) instead of failing an otherwise-valid push and destroying the
  already-streamed bytes -- the one mutation rename that was not yet wrapped
  in the transient-fault retry every sibling rename uses.
- Documentation and code comments no longer describe the integrity digest as
  fixed to sha256: prose and `@spec` references now reflect the
  construct-time algorithm choice (sha256 by default) and the full FIPS
  coverage (180-4 for sha2, 202 for sha3/shake).

## 0.1.14 — 2026-07-18

The store gains its first executable entry point. `npx @blamejs/stash
<command>` (or the `stashjs` command from a global install) exposes the query
and maintenance verbs: `verify` (audit for damage, `--repair` to remove
condemned entries, orphans, and corrupt graves), `stats`, `prune`, `list`
(`--include-expired` to reveal lapsed entries), `tombstones`, and `has
<ref>`. Add `--json` to any command for a machine-readable document, for cron
and scripting. The root comes from `--root <dir>`, else `$STASH_ROOT`, else
`./.stash`; a missing root is refused rather than conjured into an empty
store from a typo. The CLI composes only already-shipped verbs -- it never
moves bytes (no push/apply/pop/store) and never destroys by ref (no
drop/clear), so it hands out no capability and streams no blob. It runs under
`node --permission` with read/write scoped to the root exactly as the library
does, fails closed with stable exit codes, and never echoes a ref, a metadata
value, or a filesystem path in an error. Point it at a stash whose owning
process is stopped, or a cold-standby replica: like every access to a disk
root, it is single-writer, and every command except `verify` runs the
crash-recovery scan first.

### Added

- The `stashjs` CLI (`npx @blamejs/stash <command>`): `verify [--repair]`,
  `stats`, `prune`, `list [--include-expired]`, `tombstones`, and `has
  <ref>`, each a thin adapter over the matching Stash verb. `--json` on any
  command emits the raw object for scripting; the default is a human table
  (which omits opaque per-entry metadata). The root is taken from `--root`,
  `$STASH_ROOT`, or `./.stash`, and must already exist. Exit codes are stable
  and distinct: clean, damage-found, usage error, malformed ref, integrity
  fault, or I/O fault. It exposes only the query and maintenance verbs --
  never the bytes-moving or destroy-by-ref verbs -- and holds the library's
  permission-model and capability-free-error posture.

## 0.1.13 — 2026-07-17

On a platform without O_NOFOLLOW (Windows), the disk backend cannot refuse a
symlink at the open itself, so after opening a blob or sidecar it
cross-checks the descriptor's identity against a no-follow lookup of the name
-- catching a symlink traversed at open or a name swapped for a different
object afterward. That check keyed on device + inode alone. Windows
synthesizes the inode from the NTFS file index and can transiently report 0
for a file under heavy parallel I/O, so two distinct in-root files could both
read as inode 0 and be mistaken for the same object -- a fail-open in the
swap guard. The identity comparison now also requires size and creation time
to match. Because the new terms are ANDed on, the check only ever becomes
more selective: it never accepts a swap it rejected before, and an untampered
read (whose open descriptor and name resolve to the same inode) still
matches, since size and creation time agree for one object. This is
defense-in-depth -- planting a symlink in the store root already requires a
privilege the recommended permission sandbox denies -- but a security guard
that silently passes on an identity collision is a real gap, now closed. No
API change.

### Fixed

- Disk backend, platforms without `O_NOFOLLOW` (Windows): the post-open
  symlink-swap guard compared only device + inode, so two distinct files that
  transiently reported inode 0 (an NTFS-file-index quirk under heavy parallel
  I/O) could be mistaken for one object -- a fail-open. The file-identity
  comparison now also requires size and creation time to agree. The terms are
  ANDed, so the check is strictly more selective and cannot vouch for a
  swapped object it previously rejected; an untampered read still matches.
  The same identity check is now the single choke point behind both the
  read-path swap guard and the crash-recovery interrupted-claim check.

## 0.1.12 — 2026-07-17

The integrity hash is now a construct-time choice: new Stash({ backend,
digest }) selects sha256 (the default, unchanged), sha512, sha3-256,
sha3-512, or shake256 -- all node:crypto builtins, so the zero-dependency
rule holds. This is crypto-agnosticism for INTEGRITY, not confidentiality:
there is still no key and no cipher anywhere in the tree. The stored digest
is self-describing ("algo:hex"), so a read -- and verify() -- hashes with the
algorithm the entry was WRITTEN with, never a global assumption. A store may
therefore hold entries under different algorithms (the option changed over
the store's life, or store() replicated an entry that carried its own) and
each still verifies. The construct-time option sets the algorithm for new
pushes only; omitting it keeps sha256, so every existing store is
byte-identical. An unknown algorithm is a config-time TypeError; a stored
digest with an unknown algorithm or the wrong hex length is an
IntegrityError.

### Added

- `digest` constructor option -- the integrity-hash algorithm for new writes:
  `sha256` (default), `sha512`, `sha3-256`, `sha3-512`, or `shake256`. sha2
  is FIPS 180-4; sha3 and shake are FIPS 202; `shake256`'s output is pinned
  to 64 bytes. The stored digest is self-describing (`"<algo>:<hex>"`), so
  `apply`, `pop`, and `verify()` hash each entry with its own algorithm -- a
  store may mix algorithms and every entry still verifies, and `store()`
  replicates an entry with its algorithm intact. The default is unchanged, so
  an omitted option leaves every existing store byte-identical. This stays
  inside SPEC.md section 1: still no key, no cipher -- the digest verifies
  integrity, never confidentiality.

## 0.1.11 — 2026-07-17

A correctness sweep of the documentation against the actual code. No library
surface changes. The SPEC.md permission-model command granted read only to
the store directory, so an app launched under --permission could not read its
own module graph and died with ERR_ACCESS_DENIED before the store started; it
now reads the app directory (write still scoped to the store, which is
pre-created). The SPEC.md method table said verify({ repair: true }) removes
what it finds, which overstated it: repair removes damaged blob/sidecar
pairs, orphans, foreign files, and corrupt tombstones, but leaves a stale
claim for crash recovery to resolve. THREAT-MODEL.md and ARCHITECTURE.md
still described the store as mid-build with most milestones unshipped; they
now reflect that the SPEC.md section 12 plan (M1-M8) is complete.
MIGRATING.md's 'no releases have shipped yet' and CONTRIBUTING.md's
milestone-build guidance were likewise brought up to date.

### Fixed

- The `--permission` sandbox command in `SPEC.md` (and the architecture doc
  and generated docs site) was unrunnable: it granted `--allow-fs-read` only
  on the store directory, but Node must read the application's own module
  graph from disk to launch, so the process failed `ERR_ACCESS_DENIED` before
  the store initialized. The command now reads the app directory and writes
  only the pre-created store, matching the shipped `permission-flags`
  example. The accompanying prose is corrected too: the permission model is a
  process-level filesystem allowlist, not per-module isolation.
- `SPEC.md`'s `verify()` description said `{ repair: true }` 'removes what it
  finds'; it now states repair removes damaged blob/sidecar pairs, orphaned
  `.tmp` files, foreign files, and corrupt tombstones, and reports -- but
  never deletes -- a stale claim, which crash recovery owns (deleting a
  restorable claim would be data loss).
- `THREAT-MODEL.md` and `ARCHITECTURE.md` described the store as mid-build
  with milestones M3-M8 'not yet built'; every defense is implemented, and
  both docs now reflect that the `SPEC.md` section 12 delivery plan (M1-M8)
  is complete and the store is feature-complete pre-1.0. The architecture
  module map and backend-interface list are corrected to the full shipped
  set.
- `MIGRATING.md` said 'no releases have shipped yet' (eleven have); it now
  reads 'no breaking-change migrations have shipped yet'. `CONTRIBUTING.md`
  no longer presents the fully-shipped M2-M8 milestones as open build work.

## 0.1.10 — 2026-07-17

This release is documentation; the library surface does not change. Three
runnable examples land under examples/, each a zero-dependency plain-node
script that asserts every step so it cannot rot: lifecycle.js walks an entry
from push through show, apply, pop, read budgets, and expiry; cold-standby.js
replicates a store to a standby with store()/tombstones()/drop() and proves a
stale node cannot resurrect a destroyed entry; permission-flags.js re-execs
itself under the Node permission model and shows a stash write to the granted
root succeeding while a write outside it is denied by the runtime. The README
gains a verb table mapped to the git-stash mental model, an error-code table
generated from src/errors.js so it cannot drift, and a runnable-examples
section. All three examples run in CI, so a broken one fails the build.

### Added

- Runnable examples under `examples/`, each a zero-dependency plain-node
  script that self-asserts: `lifecycle.js` (push -> show -> apply -> pop ->
  gone, read budgets, expiry, prune/clear), `cold-standby.js` (replicate a
  store to a standby and prove no resurrection), and `permission-flags.js`
  (run under `--permission` and prove the filesystem grant is scoped to the
  store root -- an out-of-scope write is denied). All three run in CI and the
  pre-release checks, so a broken example fails the build.
- README verb table mapping every method to the git-stash mental model, and
  an error-code table generated from `src/errors.js` (a drift check keeps it
  in sync with the shipped typed-error set, SPEC.md section 10).

## 0.1.9 — 2026-07-17

store(entry, source) is the replication-grade insert. The caller supplies the
complete Entry -- id, createdAt, expiresAt, reads, readsLeft, digest, meta --
and it lands verbatim, with the bytes verified against the supplied digest
and size as they stream so transfer corruption is caught on the way in and
nothing lands. It proceeds in a fixed order: a malformed id is InvalidRef, a
tombstoned id returns false and writes nothing, an already-expired entry is a
no-op, an identical live entry is an idempotent no-op (retrying a sync is
free), a same-id-different-digest is an IntegrityError, and otherwise it
writes. store() emits no event, so a sync daemon never echoes its own writes.
Every early destruction -- pop, drop, clear, a spent read budget -- now
writes a tombstone of { id, destroyedAt, cause } and nothing that describes
the body; expiry writes none, because an entry's terms travel with it.
tombstones() returns the graves for reconciliation: feed each id to a
replica's drop() and two stores converge with no resurrection. tombstoneTtl
(default '30d', null never prunes) reaps a grave once older than the window,
riding the existing sweep -- with the floor rule the deployment owns: keep it
comfortably above the longest gap between reconciliations.

### Added

- `store(entry, source)` -- the replication-grade insert (a git `stash
  store`). It preserves an existing identity where `push` mints a new one:
  the caller supplies the complete `Entry` and it lands verbatim, honoring
  the REMAINING read budget rather than resetting it. The bytes are verified
  against the supplied `digest` AND `size` as they stream (in-stream, never
  write-then-check), so a transfer that corrupted the bytes throws
  `IntegrityError` and leaves nothing behind. Six checks, in a normative
  order: `1` malformed id -> `InvalidRef` (before any storage access); `2`
  tombstoned id -> `false`, writes nothing; `3` already-expired -> `false`;
  `4` identical live entry (same id, same digest) -> `false` (a retry-based
  sync is free); `5` same id, different digest -> `IntegrityError`
  (corruption, not a merge; the existing entry is untouched); `6` otherwise
  write. The replicated entry is untrusted input -- a shape violation, a
  non-hex digest, an incoherent read budget, or a non-plain `meta` is a typed
  `IntegrityError`, never a partial write. `store` emits NO event, so a sync
  daemon never hears its own writes back.
- Tombstones: every early destruction -- `pop`, `drop`, `clear`, or a read
  that spends the last of a budget -- writes a grave of `{ id, destroyedAt,
  cause }` (cause is `'pop'` / `'drop'` / `'clear'` / `'spent'`) and nothing
  that describes the destroyed entry -- no digest, size, or meta -- so a
  grave can never leak the content the destruction removed. A destroyed id
  never comes back within the tombstone window: `store()` refuses a
  tombstoned id, and two replicas converge because their graves propagate.
  EXPIRY writes no tombstone -- an entry's terms travel with it, and every
  replica reaches the same deadline on its own clock.
- `tombstones()` -> `{ id, destroyedAt, cause }[]` -- the graves, for
  reconciliation. A query: it inspects the shelf, never moves bytes, and is
  loud over a corrupt grave. The done-when it enables: for each grave on one
  store, `drop()` the id on the other; then `store()` each live entry across;
  the two stores converge -- pops don't resurrect, read budgets converge, and
  a repeated `store` is a no-op.
- `tombstoneTtl` constructor option (default `'30d'`; a duration string, a
  number of ms, or `null` to never prune) -- a grave is pruned once older
  than this, riding the existing `prune()` / `sweepInterval` sweep, no second
  timer. The one setting a deployment must get right: it must comfortably
  exceed the longest gap between reconciliations, or a forgotten tombstone
  lets an id come back. StashJS cannot know the sync schedule, so it
  documents this floor rather than enforcing it.
- The `backends/*` storage contract gains `writeTombstone` (first-write-wins
  -- an existing grave is never overwritten, even under concurrent
  destruction of one id), `hasTombstone`, `listTombstones`, and
  `removeTombstone`; both shipped backends implement them, and all four are
  now required backend methods. On disk a grave is one `tombstones/<id>.json`
  sidecar -- atomic, `0600`, realpath-contained, size-bounded before parse,
  and refused if a symlink is planted where it belongs.
- `verify()` now audits grave CONTENTS, not just names: a corrupt tombstone
  (bit rot, tampering, an id that mismatches its filename) is a
  `corrupt-tombstone` finding, and `verify({ repair: true })` removes it --
  so a rotten grave that would otherwise wedge `tombstones()` and `prune()`
  has a recovery path, the same one a corrupt entry sidecar already had.

### Changed

- The `tombstoneTtl` constructor option -- the last spec'd option a shipped
  milestone had not yet implemented -- is now enforced rather than refused.
  Every option `SPEC.md` defines is now accepted and applied; an unknown
  option is still a config-time `TypeError`.

## 0.1.8 — 2026-07-17

verify() walks the store and reports physical damage -- a bit-flipped blob, a
corrupt sidecar, a size mismatch, an orphaned blob or half-written .tmp, a
foreign file, a stale claim -- digest-checking every blob as a stream. It is
a dry run by default; verify({ repair: true }) removes only what it condemns,
sparing healthy entries, a live push's in-flight .tmp, and a claim recovery
still owns. A Stash is now an EventEmitter: 'pushed' when a push commits,
'popped' when a pop's delete lands, 'dropped' on drop / clear / a spent read
budget, 'expired' exactly once per reaped entry, and 'sweepError' -- never
'error' -- when a background sweep throws, so a janitor can never crash the
app. has(ref) is a boolean existence check, stats() returns { entries, bytes,
claimed }, and a Stash is async-iterable.

### Added

- `verify(opts?)` audits the store's physical integrity. Dry-run by default:
  it streams a `sha256` over every blob and reports damage --
  `digest-mismatch`, `size-mismatch`, `corrupt-sidecar`, `missing-blob`,
  `orphan-blob`, `orphan-tmp`, `foreign-file`, `stale-claim` -- as `{
  scanned, findings: [{ kind, id }], repaired: [] }`, touching nothing. `{
  repair: true }` removes ONLY what it condemns (a damaged entry's blob and
  sidecar together); a healthy entry survives byte-identical, a live push's
  in-flight `.tmp` is spared, and a stale claim is reported but never deleted
  (resolving it is crash recovery's job). Damage is a finding; an I/O fault
  (a permission denial, a vanished layout dir) throws rather than resolving a
  falsely clean report. Finding `id`s are refs; a foreign or `.tmp` name
  reports `id: null`, so verify never echoes an on-disk path.
- A `Stash` is now an `EventEmitter` (`node:events`). It emits `'pushed'`
  (Entry) after a push commits, `'popped'` (Entry) after a pop's delete
  lands, `'dropped'` (Entry) on `drop`, `clear`, or a budget-exhausting read,
  `'expired'` (Entry) exactly once per reaped entry (whichever of the lazy
  read path or the sweeper wins), and `'sweepError'` (Error) when a
  background sweep throws. The failure channel is `'sweepError'`, NEVER
  `'error'` -- an unhandled `'error'` crashes a Node process, and a
  background janitor must not be able to take the app down; with no listener
  it is a no-op. Every payload is a full, defensive-copy Entry emitted after
  the state change commits, so a throwing listener cannot unwind the
  committed operation.
- `has(ref)` is an existence check without the try/catch `show` needs: `true`
  for a live entry, `false` for an unknown or expired ref (reaped in
  passing), `InvalidRef` for a malformed ref before any backend access, and
  `IntegrityError` for a corrupt entry rather than a `false` that would hide
  corruption.
- `stats()` returns `{ entries, bytes, claimed }` -- aggregate counts, never
  refs -- over a fast physical walk; an expired-but-unswept entry still
  counts until a read or `prune()` reaps it, and a foreign file in the layout
  fails the count loudly.
- A `Stash` is async-iterable: `for await (const entry of stash)` yields the
  live entries, sugar over `list()`.
- The `backends/*` storage contract gains `verify(opts)`; both shipped
  backends implement it, and it is now a required backend method.

### Changed

- `drop(ref)` on an expired entry now returns `false` and emits `'expired'`
  (not `'dropped'`): an expired entry is already nonexistent on every public
  surface, so dropping one reaps it rather than reporting a live removal.
  `clear()` likewise counts only the live entries it destroys.
- The disk backend's `remove` deletes the sidecar with `unlink` rather than
  `rm`, so the boolean it returns is a true single-writer witness -- exactly
  one of two concurrent reapers reports the removal, which is what makes an
  `'expired'`/`'dropped'` event fire exactly once under a lazy-read / sweep
  race.

## 0.1.7 — 2026-07-16

pop(ref) streams an entry and deletes it the instant the stream drains
cleanly -- bytes out once, then gone -- with two concurrent pops racing on an
atomic claim so exactly one drains and the other is refused. push(source, {
reads: N }) gives an entry a finite read budget: a credit is spent only on a
full, digest-verified drain, and the read that exhausts it destroys the
entry, with concurrent budgeted readers serialized so the last credit can
never be double-spent. A read that fails or is abandoned costs nothing and is
resolved by onPopFailure -- restored for a retry by default, or burned. On
the disk backend, a claim abandoned by a process killed mid-pop is reclaimed
on the next construction rather than stranding the entry, and destruction
stays monotone across the crash: a dropped entry never comes back.

### Added

- `pop(ref)` reads an entry's bytes and destroys it: the stream is
  digest-verified as it drains, and the entry is deleted the instant it
  drains cleanly -- bytes out once, then gone. Two concurrent `pop(ref)` race
  on an atomic claim: exactly one wins and drains, the other rejects
  `RefClaimed` (code `ECLAIMED`). `pop` ignores any read budget -- it is
  terminal by definition.
- `push(source, { reads: N })` gives an entry a read budget: a positive
  integer count of successful `apply` drains after which the entry
  self-destructs (`null`, the default, is unlimited). A budgeted `apply`
  spends one credit only on a full, digest-verified drain -- an abandoned or
  corrupted read costs nothing -- concurrent budgeted readers serialize
  through the claim so the last credit can never be double-spent, and the
  read that takes the budget to zero destroys the entry through the same path
  as `pop`. An unbudgeted `apply` stays lock-free and pays nothing for the
  feature.
- `onPopFailure` (constructor option) decides what happens to an entry whose
  `pop` or budgeted `apply` fails to fully drain -- a stream destroyed early,
  a source error, a digest mismatch: `'restore'` (the default) returns the
  entry so the read can be retried, `'burn'` destroys it anyway.
- Crash recovery (disk backend): a claim left behind by a process killed
  mid-`pop` is reclaimed on the next construction, on the first operation --
  never in the constructor, which does no I/O. `claimTimeout` (constructor
  option, default `'10m'`) is how long such a claim is treated as another
  live reader's before recovery resolves it per `onPopFailure`; a younger
  claim is left untouched. A claim whose entry was already deleted is
  completed -- the interrupted deletion finishes -- never resurrected, and a
  drop during a live claim destroys the entry for good: an abandoned read
  cannot bring it back.
- The `backends/*` storage contract gains `claim`, `restore`, `commit`,
  `listClaims`, `consumeRead`, and `isClaimed` -- the claim lifecycle the pop
  and budget paths drive. Both shipped backends implement them, and they are
  now required backend methods.

### Changed

- `onPopFailure` and `claimTimeout` are now live constructor options; they
  previously threw at construction as not-yet-shipped. `onPopFailure` must be
  `'restore'` or `'burn'`, and `claimTimeout` a POSITIVE duration -- a
  non-positive lease would let recovery reclaim an active pop instantly, so
  it is a config-time `TypeError`. Recovery reclaims a claim by age alone, so
  a disk root is single-writer and `claimTimeout` must exceed the longest
  read a deployment runs.
- A custom backend must now implement the claim lifecycle -- `claim`,
  `restore`, `commit`, `listClaims`, `consumeRead`, and `isClaimed` --
  alongside the existing methods, or the `Stash` constructor rejects it.

## 0.1.6 — 2026-07-16

A store can now be bounded. maxSize caps each entry and is enforced as the
bytes stream, so an oversized or unbounded source is cut off at the limit
rather than written and then measured. maxEntries and maxTotal bound the
whole store; a push that would exceed either is refused with StashFull, and
nothing already stored is evicted to make room. Expired-but-unswept entries
are reaped before the store is judged full, so a dead entry never blocks a
live push. Every rejected push leaves nothing behind.

### Added

- `maxSize` (constructor option) bounds each entry -- a size string like
  `'100mb'` or a byte count. It is enforced during the write stream: the
  running byte count is checked before each chunk is handed to the backend,
  so a push that crosses the limit aborts with `SizeExceeded` (code `E2BIG`)
  and an unbounded or hostile source is cut off at the boundary instead of
  filling the disk. Every chunk is counted by its real byte length -- a
  multibyte string by its encoded size, a typed array or ArrayBuffer by its
  byte count rather than its element count -- so no chunk shape slips past
  the limit, and each is stored by its exact bytes.
- `maxEntries` and `maxTotal` (constructor options) bound the whole store. A
  push that would exceed the entry count or the total byte size is refused
  with `StashFull` (code `EFULL`), and no existing entry is evicted to make
  room -- a flood of pushes cannot delete other people's data. `maxEntries`
  is checked before the stream starts; `maxTotal` is enforced against the
  remaining headroom as the bytes stream.
- `maxTotal` counts the stored footprint -- each blob plus the metadata
  stored beside it -- not the blob bytes alone. The entry's own metadata is
  charged against the headroom before the blob streams, so a caller cannot
  slip past the limit with a flood of tiny (or zero-byte) blobs carrying
  large `meta`.
- Expired-but-unswept entries are pruned before the store is judged full, so
  an entry past its deadline that no read or sweep has reaped yet never
  blocks a live push against `maxEntries` or `maxTotal`.
- The `backends/*` storage contract gains `stats()` -> `{ entries, bytes,
  claimed }`, the aggregate the limit checks read instead of parsing every
  entry. Both shipped backends implement it, and it is now a required backend
  method.

### Changed

- A malformed limit value fails at construction: `maxSize` / `maxTotal` must
  be a positive size, and `maxEntries` a positive integer count -- zero, a
  negative, a fraction, or a non-size string is a config-time `TypeError`,
  never a silently disabled check.
- A `maxSize` larger than `maxTotal` is refused at construction: a per-entry
  cap above the whole-store cap can never bind, since even an empty store
  admits at most `maxTotal` bytes. The contradiction surfaces as a
  `TypeError` at boot rather than as dead configuration.
- Because the store's size is read but not locked, concurrent pushes can
  overshoot a stash-wide bound by the number in flight; the bound stops
  unbounded growth rather than pinning the store to an exact byte. A custom
  backend must now provide `stats()`.

## 0.1.5 — 2026-07-16

Push an entry with a TTL and it reads back as gone once the deadline passes
-- lazily on the next read, before any sweep has run, and optionally on a
background timer that never holds your process open. A construct-time default
applies to every push and is overridable per call; expiry is fixed at push
and only ever moves an entry toward destruction, never further. prune() reaps
on demand, list() hides expired entries by default, and close() (or await
using) stops the sweeper.

### Added

- A construct-time `ttl` default -- `'30m'`, `'24h'`, `'7d'`, a number of
  milliseconds, or `null` for no expiry -- applied to every push and
  overridable per call with `push(source, { ttl })`. An explicit `ttl: null`
  on a push clears a construct-time default back to no expiry; an absent
  option inherits it. A ttl whose deadline would exceed the safe integer
  range is refused at config time rather than serialized as a false 'never
  expires'.
- Lazy expiry on every read: `apply` and `show` treat an expired entry as
  `RefNotFound` and drop it in passing, so an expired entry is never served
  even if the sweeper has not run. `list()` filters expired entries out by
  default; `list({ includeExpired: true })` includes them, and `list` only
  filters -- it never drops.
- `prune()` destroys expired entries on demand and resolves to the count
  actually destroyed (an entry a concurrent drop removes first is not
  double-counted).
- `sweepInterval` arms a background `prune()` on a timer that is
  `.unref()`'d, so an open `Stash` never holds the process open on exit; it
  skips overlapping sweeps and cannot crash the process if a sweep fails. A
  `sweepInterval` above Node's timer ceiling, or of zero, is a config-time
  error rather than a silent busy loop.
- `close()` stops the sweep timer and is idempotent; `Symbol.asyncDispose`
  aliases it, so `await using stash = new Stash(...)` clears the timer when
  the block exits, even on throw.

### Changed

- `apply` and `show` may now delete: reaping an expired entry in passing
  calls the backend's remove. Under `--permission`, the read verbs therefore
  need the same write grant on the stash root the rest of the store already
  uses; a denied delete surfaces loudly rather than degrading into a silent
  not-found.

## 0.1.4 — 2026-07-16

The disk backend closes a family of filesystem-race and denial-of-service
vectors: reads bind to a verified descriptor, the containment check moves to
the moment of the write, and a planted named pipe can no longer hang a read.
The memory backend copies caller-owned bytes, and the documentation site now
ships as a hardened container alongside a continuous fuzzing harness over the
store's untrusted-input surfaces.

### Added

- The documentation site ships as a stateless, hardened container (nonroot,
  all capabilities dropped) with a single-container local deploy and a
  production overlay that fronts it with automatic TLS; a runbook covers
  both.
- Continuous fuzzing of the store's untrusted-input surfaces -- the
  capability-ref validator and the sidecar-metadata parser -- runs on every
  pull request and on a schedule.

### Fixed

- DiskBackend reads a blob or sidecar through a descriptor whose identity is
  verified against the name it was opened through, so a symlink or file
  swapped in after the check can no longer redirect the read outside the
  storage root (CWE-367). On platforms without O_NOFOLLOW the descriptor's
  device and inode are checked against a no-follow lookup of the name,
  closing the swap window there too.
- A blob or sidecar replaced with a named pipe can no longer hang a read:
  stored files open non-blocking, so a pipe with no writer is refused as
  corruption instead of parking show, list, or apply forever (CWE-410).
- DiskBackend re-checks storage-root containment at the moment it writes the
  sidecar rather than before streaming the blob, so a directory swapped in
  during a long write can no longer land metadata outside the root.
- The sidecar's stored identity is compared to the addressed identity in
  constant time, matching the timing-safe comparison the rest of the store
  already uses (CWE-208).
- MemoryBackend copies each caller-owned chunk it retains, so a caller that
  reuses its buffer after yielding no longer corrupts the stored bytes.
- A push whose sidecar write fails now cleans up the blob on every path,
  including the final rename, leaving no orphaned bytes behind.

## 0.1.3 — 2026-07-16

Every documented primitive now names the external standards it implements and
the weakness classes it defends, and the npm publish pipeline ships its first
working end-to-end run.

### Added

- Conformance tags across the documented surface: primitives cite the
  standards they implement (FIPS 180-4 digests, RFC 4648 base64url refs, RFC
  8259 sidecar JSON) alongside their SPEC.md sections, and name the CWE
  classes they defend (CWE-22/23 path traversal at the ref whitelist, CWE-59
  link following at the containment check, CWE-208 timing at the
  constant-time compare, CWE-330/340 ref predictability, CWE-354 silent
  corruption, CWE-377 temp-file exposure, CWE-770 sidecar allocation bounds,
  CWE-209/532 capability leakage, CWE-1188 refused-not-ignored options). The
  documentation site renders both on every primitive.
- THREAT-MODEL.md maps each threat class to its CWE identifiers.

### Changed

- ARCHITECTURE.md and THREAT-MODEL.md implementation statuses reflect the
  shipped disk backend.

### Fixed

- The publish workflow extracts release notes with the changelog's actual
  header grammar (the previous matcher expected a v-prefixed header with an
  ASCII suffix and could never match the generated file).
- An explicit workflow dispatch may publish when the built commit is exactly
  the commit the version's pushed tag points at -- a fix to the publish path
  itself can now ship a release without minting a new tag for it, while a
  dispatch can never publish bytes no tag vouches for.

## 0.1.2 — 2026-07-16

The documentation site's accent surfaces move to the logo's own measured blue
family, the README fronts the logo, and two continuous-integration gates are
hardened.

### Changed

- Documentation site: links, active navigation, focus borders, badges, search
  highlights, code inks, the hero glow, and the browser theme color now come
  from the logo's measured blue ramp; syntax-highlighting keyword and
  operator tokens are re-inked to match through site-owned overrides (the
  vendored highlighter file is untouched). Every introduced color pair is
  contrast-checked; one pre-existing text-contrast failure is fixed,
  unfocused search fields gain a visible boundary, keyboard-selected search
  results are conveyed by color rather than background alone, and printed
  pages force code and highlights to legible ink on white.
- README: the logo now heads the page, served from assets/.
- Documentation server: the default port moves to 3011 (WIKI_PORT still
  overrides).
- actions/setup-node moves to the v7.0.0 pin; the diff between the pinned
  commits was reviewed (two new cache outputs, toolchain migration, no new
  execution surface).

### Fixed

- The forbidden-token gates in both CI workflows now fail on a hit in ANY
  pattern: under errexit a non-final negated command's failure was silently
  skipped, which left the first pattern advisory.
- The CI checkout no longer persists credentials into the workspace.

## 0.1.1 — 2026-07-15

The M2 milestone: `DiskBackend` (`@blamejs/stash/backends/disk`) brings
persistent storage under the same contract the memory backend implements --
the whole conformance suite runs against both, unmodified.

### Added

- `DiskBackend`: one blob plus one JSON sidecar per entry (`blobs/<id>`,
  `meta/<id>.json`), no central index to corrupt -- a listing is a readdir
  plus sidecar reads. Directories are created `0700` and files `0600`, lazily
  on first use; the constructor does no I/O.
- Atomic writes: bytes stream to `blobs/<id>.tmp` with size and `sha256`
  digest computed as they pass, then fsync and rename -- a reader never sees
  a partial blob, and a failed push leaves nothing behind.
- Realpath containment: the root is pinned at first use and every operation
  re-asserts that its directory still resolves inside it. A subdirectory
  swapped for a link out of the root is refused with `InvalidRef`; a symlink
  where a blob should be is refused as `IntegrityError`, never followed. The
  Node permission model follows symlinks out of granted paths, so this check
  is the store's own wall.
- Strict sidecar validation: a sidecar is size-bounded before it is read,
  parsed under a corruption verdict, and shape-checked field by field against
  the one canonical Entry structure -- wrong types, missing or extra fields,
  an identity mismatch, or a malformed digest are `IntegrityError`, and
  `list()` fails loud over a corrupt sidecar rather than silently skipping
  it. Entries carrying valid future terms (an expiry, a read budget) are
  accepted, so a store written by a newer release stays readable.
- A crash mid-write leaves an invisible orphan, never a served half-entry: a
  blob without its sidecar does not exist to `list`/`show`/`apply`, and a
  sidecar whose blob is missing is a loud `IntegrityError`.

### Changed

- The documentation site's Backends page now covers the storage contract and
  both shipped backends.

## 0.1.0 — 2026-07-15

Initial release: the M1 surface of the specification.

### Added

- `Stash` with `push` / `apply` / `show` / `list` / `drop` / `clear` over a
  backend, plus the `MemoryBackend` (`@blamejs/stash/backends/memory`).
- Refs as capabilities: `v1_` + 32 random bytes (base64url), validated
  against a strict whitelist before any storage access -- ref validation is
  the path-traversal defense.
- Digest-verified reads: `apply` streams through a `sha256` check and errors
  with `IntegrityError` instead of delivering silently corrupted bytes.
- The typed error set with frozen codes: `RefNotFound` (`ENOREF`),
  `RefClaimed` (`ECLAIMED`), `IntegrityError` (`EINTEGRITY`), `SizeExceeded`
  (`E2BIG`), `StashFull` (`EFULL`), `InvalidRef` (`EBADREF`), all extending
  `StashError`. No error message contains a ref, a `meta` value, or a path.
- Fail-loud configuration: spec options whose milestone has not shipped
  (`ttl`, `maxSize`, `maxEntries`, `maxTotal`, `onPopFailure`,
  `tombstoneTtl`, `sweepInterval`, `claimTimeout`, per-push `ttl`/`reads`)
  throw a `TypeError` at the call site instead of being accepted and ignored.
- The source-generated documentation site under `examples/wiki`.
