# Governance

`@blamejs/stash` is a zero-dependency, ephemeral content store with a published LTS calendar and a documented threat model. This document captures how decisions get made, who makes them, and what happens if the maintainer becomes unavailable.

It exists so a consumer betting their stack on the library can answer three questions before they commit:

1. Who decides what changes in the library?
2. What happens to the project if the maintainer disappears?
3. How are consumer-impacting changes (deprecations, removals, behavior shifts) communicated?

## Current governance model

Solo maintainer.

- **Maintainer:** dotCooCoo (Robert Lee), via GitHub user [dotCooCoo](https://github.com/dotCooCoo).
- **Organization:** github.com/blamejs.
- **npm package:** `@blamejs/stash`. Sibling packages under the `@blamejs/*` scope are documented per-package.

The project transitions to a multi-maintainer model when an aligned co-maintainer with sustained core-area commit cadence joins. Until then, the maintainer is final on technical direction.

## How decisions get made

- **Technical direction.** Maintainer-final, within the boundaries [SPEC.md](SPEC.md) draws. The spec is the contract: a behavior change requires a spec change first, and the spec's "do not build these" list (section 3) is binding on the maintainer too. Consumer input arrives via GitHub Issues + Discussions; the maintainer weighs it but the final call rests with them. There is no formal vote. The delivery plan is public in SPEC.md section 12.
- **Security-vulnerability triage.** Coordinated disclosure via [GitHub Security Advisories](https://github.com/blamejs/stash/security/advisories/new), a fix target for High / Critical vulnerabilities in the library's own code, and a public advisory on remediation. There are no dependencies, vendored or otherwise, so there is no third-party-CVE triage lane.
- **Consumer-impacting changes.** Breaking changes ship deprecation warnings at least one minor before removal, with a 24-month LTS window per [LTS-CALENDAR.md](LTS-CALENDAR.md) and the upgrade recipe recorded in [MIGRATING.md](MIGRATING.md). Where a release has not met that commitment, it is named in MIGRATING.md rather than left to be discovered.
- **Releases.** Patch is the default; minor requires an explicit decision the maintainer documents in the release notes; major requires a deprecation cycle.
- **Governance change process.** Edits to this file require a consumer-facing 30-day RFC period via GitHub Discussions. RFCs open at the proposal stage and close with a maintainer decision + rationale in the discussion thread.

## Succession plan

Bus-factor-1 is the largest non-technical risk the project carries. This section documents the recovery path so a consumer depending on the library has a defensible plan if the maintainer becomes unavailable.

### Designated successor

**Status:** TBD with documented re-open trigger.

A named successor requires:

- An aligned contributor with sustained commit cadence to a core area (the policy layer, the backend interface, the ref/capability machinery, or the release workflow).
- Demonstrated familiarity with the design decisions recorded in [SPEC.md](SPEC.md) and [ARCHITECTURE.md](ARCHITECTURE.md), in particular why the "do not build these" list rejects what it rejects.
- A documented commitment to the project's stated discipline: zero dependencies, crypto-agnosticism (no key ever lives in the store), fail-loud typed errors, and the monotone lifecycle.

The maintainer reviews successor candidacy whenever a contributor crosses the sustained-core-area-commit threshold. Until a successor is named, the sections below describe the fallback path.

### Repository ownership

The GitHub Organization (`blamejs`) is currently single-owner. The maintainer commits to adding a second organization owner within 30 days of naming a designated successor. Until then, the maintainer-incapacitation path goes through GitHub Support's account-recovery flow (2FA recovery codes).

### npm publish credentials

The npm publishing identity owns the `@blamejs` scope. Publish authority for releases lives in:

1. **Primary:** OIDC trusted-publisher binding (GitHub Actions environment-scoped, npm `--provenance` flow).
2. **Backup automation token:** 2FA-protected, recovery codes stored offline, scoped to publish-only on the `@blamejs` scope.

If the maintainer becomes incapacitated, recovery is via npm Support's account-recovery flow and 2FA recovery codes.

### Signing key (commit + tag signatures)

Every release commit and tag is signed.

**Rotation procedure** (planned; runs when needed):

1. Generate a new keypair.
2. Sign a key-rotation announcement with the **old** key during an overlap window where both keys are valid.
3. Update the published fingerprint in the repository's security policy.
4. Push the rotation announcement to [LTS-CALENDAR.md](LTS-CALENDAR.md) so consumers running automated tag-signature verification can update their pinned fingerprint.
5. Revoke the old key 30 days after the announcement.

### Critical knowledge

Design decisions land in **public, repo-resident artifacts**:

- [SPEC.md](SPEC.md), the authoritative specification, including the reasoning behind every deliberate rejection.
- [ARCHITECTURE.md](ARCHITECTURE.md), the layer shape and the design principles behind it.
- [CHANGELOG.md](CHANGELOG.md), consumer-facing surface evolution.

A successor inheriting the project relies on these artifacts plus the source code itself; there is no private decision record a successor would be missing.

## Key-loss recovery

| Asset | Recovery path |
|---|---|
| npm publish | npm Support account-recovery flow with 2FA recovery codes; backup automation token sealed offline. |
| GitHub org ownership | GitHub Support account-recovery flow with 2FA recovery codes. |
| Signing key | Key-rotation procedure above; 30-day consumer-notification window via LTS-CALENDAR.md. |

## Dependent-notification protocol

If the maintainer becomes unavailable, the project enters a documented recovery process rather than silent decay.

- **Contact channel:** [GitHub Security Advisories](https://github.com/blamejs/stash/security/advisories/new) for security matters; GitHub Issues / Discussions otherwise.
- **Escalation trigger:** if no maintainer activity for 30 days **and** no scheduled hiatus pre-announced in LTS-CALENDAR.md, the designated-successor process activates. If no successor is named, the project enters maintenance-hibernation status with a public announcement on the GitHub README.
- **Public announcement format:** README banner + a pinned issue + a CHANGELOG entry documenting the status change. Consumers on the published npm versions see no surface change (the published versions stay reachable); consumers bumping a pinned dependency see the hibernation banner before they upgrade.

## Open: items the maintainer commits to address

These are documented gaps in the current governance posture. The re-open trigger for each is consumer-visible so a consumer can evaluate the project's posture against their own risk tolerance.

1. **Named successor.** TBD; re-opens when a contributor crosses the sustained-core-area-commit threshold described above.
2. **Second GitHub org owner.** Adds within 30 days of naming a successor (no separate trigger; tracks succession).

## References

- OpenSSF Best Practices Badge governance criterion.
- bus-factor risk class for solo-maintainer projects.
- npm Support account-recovery flow.
- GitHub Support account-recovery flow.
