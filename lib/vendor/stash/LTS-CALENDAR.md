# LTS calendar

`@blamejs/stash` ships on a published major cadence. Each major receives **24
months of security-only patches** starting the day the next major is published.
Feature backports are not promised.

| Version          | First release | Security patches through   | Node minimum | Dependency posture |
|------------------|---------------|----------------------------|--------------|--------------------|
| `v0.x` (pre-1.0) | 2026          | superseded by v1.0 (2026-07-23) | 24.18.0 | Zero dependencies, runtime and dev |
| `v1.x`           | 2026-07-23    | **not serviced**; superseded by v2.0 (2026-08-07), upgrade to `v2.x` | 24.18.0 | Zero dependencies, runtime and dev |
| `v2.x`           | 2026-08-07    | current major; 24 months after v3.0 ships | 26.13.1 (since `v2.3.0`; 24.22.1 on 24.x and 26.12.1 on 26.x before it, from `v2.2.4`; 24.22.1 and later before `v2.2.4`, 24.21.0 before `v2.2.1`, 24.19.0 before `v2.2.0`) | Zero dependencies, runtime and dev |

> **`v1.x` is not receiving security patches.** `v1.0` shipped on 2026-07-23
> stating that a 24-month window would open when its successor shipped. `v2.0`
> shipped 15 days later, and that window is not being serviced: `v1.x` had no
> known consumers, and `v2.0` is a two-edit upgrade with no on-disk format
> change ([MIGRATING.md](MIGRATING.md#upgrading-to-20)). This is a withdrawal of
> a commitment `v1.0` made, stated here rather than left to be discovered. A fix
> that exists only in `v2.x` is listed in
> [SECURITY.md](SECURITY.md#known-issues-in-unserviced-lines). If you are on
> `v1.x` and cannot upgrade, open a security advisory and the position will be
> revisited.

## What "security patches" means

- Critical and high-severity vulnerabilities in the library's own code: a
  ref-validation or containment escape, a capability leak through an error or an
  API surface, a destruction guarantee that fails to hold, resource exhaustion
  in the streaming paths.
- **Not** included: feature backports, performance improvements, or non-security
  bug fixes. Consumers who want those upgrade to the current major.
- There are no dependencies, runtime or dev or vendored, so there is no
  third-party-CVE patch lane. A vulnerability is either in this library's code or
  in Node itself, and the latter is fixed by upgrading Node within the supported
  floor.

## Node minimum policy

The "Node minimum" column is the lowest Node version the library supports for
that line. `v0.x` and `v1.x` shipped against a 24.18.0 floor; `v2.x` shipped
against 24.19.0, moved to 24.21.0 in `v2.2.0`, moved to 24.22.1 in
`v2.2.1`, and moved to 26.13.1 in `v2.3.0`. Either way it is a floor
rather than a ceiling: no polyfills, no compat shims, no version branches for
older runtimes.

The capabilities the library relies on all arrived at the Node 24 major level,
not in any one patch (see [SPEC.md](SPEC.md) section 2). A consumer on any
release at or above the floor is fully supported.

A new major adopts whatever Node major is the active LTS at release. Once on the
LTS line, the Node minimum is frozen for that major's security-patch window, so
consumers are not forced onto a newer Node mid-window. Nothing is transpiled, so
the supported Node version is exactly the version the source runs on.

> **`v2.2.0` moved the `v2.x` minimum from 24.19.0 to 24.21.0, inside the
> window the paragraph above freezes.** The commitment stands as written and
> this release did not meet it. If you are on Node 24.19.0 or 24.20.0, `npm`
> warns and installs, and Yarn 1 or any `engine-strict` setting refuses;
> upgrading Node is the only step. The reasoning is recorded in
> [MIGRATING.md](MIGRATING.md#policy) under "Exceptions taken".
>
> **`v2.2.1` moved it again, from 24.21.0 to 24.22.1, inside the same
> window.** If you are on any Node from 24.21.0 through 24.22.0, the same
> install-time behavior applies and upgrading Node is the only step. This move
> is also recorded under "Exceptions taken".
>
> **`v2.2.4` narrowed the range on later release lines.** 24.22.1 is unchanged
> as the Node 24 minimum. On Node 26 the minimum is now 26.12.1, the release
> carrying the same security fixes as 24.22.1, and Node 25 is excluded. If you
> are on Node 25 or on Node 26 before 26.12.1, the same install-time behavior
> applies and upgrading Node is the only step. This move is also recorded under
> "Exceptions taken".
>
> **`v2.3.0` moved the minimum to Node 26.13.1, inside the same window.** Node 24
> and Node 25 are no longer supported. If you are on Node 24, Node 25, or Node 26
> before 26.13.1, the same install-time behavior applies and upgrading Node is
> the only step. This move is also recorded under "Exceptions taken".

## The v0.x line

`v0.x` had no LTS commitment. Every pre-1.0 release could change something
consumers depended on, with no backwards-compatibility shims, because the surface
was still evolving toward the contract in [SPEC.md](SPEC.md). That contract
became stable at `v1.0`, and this calendar and the deprecation policy in
[MIGRATING.md](MIGRATING.md) took effect with it.

Consumers still on a `v0.x` release should upgrade to `v2.x`, the current major.
Going only as far as `v1.x` lands on a line that is no longer serviced. Read
[CHANGELOG.md](CHANGELOG.md) before upgrading across more than a few releases at
a time.

## The v1.x line

`v1.x` is superseded and not serviced. `v2.0` is a two-edit upgrade with no
on-disk format change, so a `v1.x` store opens under `v2.0` unmodified; the
recipe is in [MIGRATING.md](MIGRATING.md#upgrading-to-20). At least one fix ships
only in `v2.x`, listed in
[SECURITY.md](SECURITY.md#known-issues-in-unserviced-lines).
