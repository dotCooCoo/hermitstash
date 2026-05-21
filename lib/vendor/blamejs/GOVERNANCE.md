# Governance

blamejs is a server-side Node framework with a published LTS calendar
and a documented threat model. This document captures how decisions
get made, who makes them, and what happens if the maintainer becomes
unavailable.

It exists so an operator betting their stack on blamejs can answer
three questions before they commit:

1. Who decides what changes in the framework?
2. What happens to the project if the maintainer disappears?
3. How are operator-impacting changes (deprecations, removals,
   security defaults) communicated?

## Current governance model

Solo maintainer, pre-1.0.

- **Maintainer:** dotCooCoo (Robert Lee), via GitHub user [dotCooCoo](https://github.com/dotCooCoo).
- **Organization:** github.com/blamejs.
- **npm scope:** `@blamejs/*` (`@blamejs/core` is the framework; sibling
  packages enumerated in [SECURITY.md → Namespace reservations](SECURITY.md#namespace-reservations)).

The project transitions to a multi-maintainer model when an aligned
co-maintainer with sustained core-area commit cadence joins. Until
then, the maintainer is final on technical direction.

## How decisions get made

- **Technical direction.** Maintainer-final. Operator input arrives
  via GitHub Issues + Discussions; the maintainer weighs it but the
  final call rests with them. There is no formal vote.
- **Security-vulnerability triage.** Per
  [SECURITY.md](SECURITY.md#reporting-cves-in-vendored-dependencies)
  — coordinated disclosure via GitHub Security Advisories, 7-day
  fix target for High / Critical vendored CVEs, public advisory on
  remediation.
- **Operator-impacting changes.** Pre-1.0 the framework reserves the
  right to break operator-facing surface in any minor version; major
  versions ship deprecation warnings at least one minor before
  removal (per project rule §6 in `CLAUDE.md`). Post-1.0 the same
  contract applies across majors with a 24-month LTS window per
  [LTS-CALENDAR.md](LTS-CALENDAR.md).
- **Releases.** Patch (`0.0.x`) is the default; minor (`0.x.0`)
  requires an explicit decision the maintainer documents in the
  release notes; major (`x.0.0`) requires a deprecation cycle. The
  full release workflow is documented in the project's local
  contributor guide.
- **Governance change process.** Edits to this file require an
  operator-facing 30-day RFC period via GitHub Discussions. RFCs
  open at the proposal stage and close with a maintainer decision
  + rationale in the discussion thread.

## Succession plan

Bus-factor-1 is the largest non-technical risk the project carries.
This section documents the recovery path so an operator depending on
blamejs has a defensible plan if the maintainer becomes unavailable.

### Designated successor

**Status:** TBD with documented re-open trigger.

A named successor requires:

- An aligned contributor with sustained commit cadence to a core
  area (auth / crypto / DB / mail-stack / release workflow).
- Demonstrated familiarity with the architectural decisions
  recorded in `docs/adr/`, `ARCHITECTURE.md`, and
  `memory/specs/` (the latter is maintainer-local but the public
  ADRs + ARCHITECTURE.md should let a successor reconstruct the
  decision context).
- A documented commitment to the project's stated discipline:
  zero npm runtime deps, PQC-first defaults, security-on-by-default,
  no AI/Anthropic attribution in shipped artifacts, no internal-process
  narrative in operator-facing surface.

The maintainer reviews successor candidacy whenever a contributor
crosses the sustained-core-area-commit threshold. Until a successor
is named, sections below describe the fallback path.

### Repository ownership

GitHub Organization (`blamejs`) is currently single-owner. The
maintainer commits to adding a second organization owner within
30 days of naming a designated successor.

Until a second owner is named, the maintainer-incapacitation path
goes through GitHub Support's account-recovery flow (DNS + 2FA
recovery codes; see below).

### npm publish credentials

The npm publishing identity owns the `@blamejs` scope. Publish
authority for releases lives in:

1. **Primary:** OIDC trusted-publisher binding (GitHub Actions
   environment-scoped, npm `--provenance` flow). Already in place.
2. **Backup automation token:** 2FA-protected, recovery codes
   stored offline. The token is scoped to publish-only on the
   `@blamejs` scope.

If the maintainer becomes incapacitated, recovery is via npm
Support's account-recovery flow keyed off the registered domain
(blamejs.com) and 2FA recovery codes.

### SSH signing key (commit + tag signatures)

Every release commit and tag is SSH-signed. The public key
fingerprint is published in
[SECURITY.md → Verifying release authenticity](SECURITY.md#verifying-release-authenticity).

**Rotation procedure** (planned; runs when needed):

1. Generate a new keypair.
2. Sign a key-rotation announcement with the **old** key (during
   an overlap window where both keys are valid).
3. Update `~/.ssh/allowed_signers` (operator-side verification
   files) + SECURITY.md fingerprint.
4. Push the rotation announcement to LTS-CALENDAR.md so operators
   running automated tag-signature verification can update their
   pinned fingerprint.
5. Revoke the old key 30 days after the announcement.

### Sigstore / cosign keyless

Identity-based; rotation is automatic when GitHub Organization
ownership rotates. No standalone key material to manage.

### Critical knowledge

Architectural decisions land in **public, repo-resident artifacts**:

- `docs/adr/` — Architecture Decision Records (rationale captured
  at decision-time, not reconstructed after the fact).
- `ARCHITECTURE.md` — high-level system shape.
- `CHANGELOG.md` (derived from `release-notes/*.json`) —
  operator-facing surface evolution.

Maintainer-local notes under `memory/specs/` are NOT
operator-facing and are not durable — a successor inheriting the
project relies on the public artifacts above plus the source code
itself.

## Key-loss recovery

| Asset | Recovery path |
|---|---|
| npm publish | npm Support account-recovery flow (registered domain + 2FA recovery codes); backup automation token sealed offline. |
| GitHub org ownership | GitHub Support account-recovery flow with 2FA recovery codes. |
| SSH signing key | Key-rotation procedure above; 30-day operator-notification window via LTS-CALENDAR.md. |
| Sigstore / cosign | Identity-based — rotates with GH org ownership. |
| Domain (blamejs.com) | Registrar account-recovery flow; DNS held with 2FA + recovery email. |

## Dependent-notification protocol

If the maintainer becomes unavailable, the project enters a
documented recovery process rather than silent decay.

- **Contact channel:** `security@blamejs.com` per SECURITY.md.
  The mailbox is dual-controlled at the email + DNS level (DNS
  held by the registrar with 2FA + recovery email; mail routed
  through the registrar's MX records).
- **Escalation trigger:** if no maintainer activity for 30 days
  **and** no scheduled hiatus pre-announced in LTS-CALENDAR.md,
  the designated-successor process activates. If no successor is
  named, the project enters maintenance-hibernation status with
  a public announcement on the GitHub README.
- **Public announcement format:** README banner + a pinned issue
  + a CHANGELOG entry documenting the status change. Operators
  on the npm package see no surface change (the published
  versions stay reachable); operators bumping a pinned dependency
  see the hibernation banner before they upgrade.

## Open: items the maintainer commits to address

These are documented gaps in the current governance posture. The
re-open trigger for each is operator-visible so the operator can
evaluate the project's posture against their own risk tolerance.

1. **Named successor.** TBD; re-opens when a contributor crosses
   the sustained-core-area-commit threshold described above.
2. **Second GitHub org owner.** Adds within 30 days of naming a
   successor (no separate trigger; tracks succession).
3. **OpenSSF Best Practices Badge — Silver tier.** Structurally
   addressable once the multi-maintainer model is live. Gold tier
   requires several additional discipline items beyond governance.
4. **`docs/adr/` first ADRs.** The directory exists in spirit
   (architectural decisions are recorded in commits, release
   notes, and `memory/specs/`); promoting the high-value
   decisions to repo-resident ADRs is a backlog item the
   maintainer tracks.

## References

- OpenSSF Best Practices Badge governance criterion.
- bus-factor risk class (opensauced.pizza research on solo-maintainer
  popular GH projects).
- npm Support account-recovery flow.
- GitHub Support account-recovery flow.
