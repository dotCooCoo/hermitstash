# Support

Thanks for using `@blamejs/stash`. This page points you at the right channel for
whatever you need.

## Where to go

| I want to... | Go here |
|---|---|
| Understand the API and its guarantees | [SPEC.md](SPEC.md), the authoritative specification |
| See what the store does today | [ROADMAP.md](ROADMAP.md) for shipped capabilities, [ARCHITECTURE.md](ARCHITECTURE.md) for how they fit together |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Ask a usage question or propose a feature | [GitHub Discussions](https://github.com/blamejs/stash/discussions) |
| Report a reproducible bug | [GitHub Issues](https://github.com/blamejs/stash/issues) |
| Report a security vulnerability | **Privately**, through GitHub's ["Report a vulnerability"](https://github.com/blamejs/stash/security/advisories/new) form. Do not open a public issue. |

## Before you open an issue

A tight report gets a fast answer. Please include:

- The version you are on. `npm ls @blamejs/stash` prints it; if you are testing
  against `main`, give the `<sha>` instead.
- Your Node.js version (`node -v`). The library targets Node 26.13.1 or later,
  and runs on the shipped runtime with no build
  step.
- A **minimal reproducer**, ideally a short script against the `MemoryBackend`,
  which needs no filesystem setup. If the behavior is specific to the disk
  backend or to the permission model, say so and include the flags you launched
  with.
- What you expected, and what actually happened. If a call threw, include the
  error's class name and its `.code`, for example `RefNotFound` and `ENOREF`.
  Those codes are stable, so they make triage fast.
- **Never paste a live ref, a `meta` value, or a stash path from a production
  store into an issue.** A ref is a capability, so a ref in a public issue is a
  leaked capability. Reproduce with throwaway data.

A method that throws a typed error on malformed or expired input is usually the
library working as designed. It fails loudly on purpose: the rejection is the
feature. If you believe an input *should* be accepted and is not, or *should* be
rejected and is not, that is exactly the kind of report we want.

## Versions and upgrades

Only the current major receives fixes. Superseded lines are not serviced and
get no backports; [LTS-CALENDAR.md](LTS-CALENDAR.md) records which line is
current and what the support window covers. Breaking-change policy and upgrade
recipes live in [MIGRATING.md](MIGRATING.md).

## Security

Security reports do not go through Issues or Discussions. Report privately via
GitHub's ["Report a vulnerability"](https://github.com/blamejs/stash/security/advisories/new)
advisory form. [THREAT-MODEL.md](THREAT-MODEL.md) documents what the library
defends and what is out of scope.

## License

`@blamejs/stash` is [Apache-2.0](LICENSE) licensed.
