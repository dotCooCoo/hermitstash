<!--
Thanks for the PR! Fill in the sections below. The Lint summary CI
check is required to pass before merge — local pre-flight:

  node test/smoke.js
  cd examples/wiki && rm -rf data data-e2e && node test/e2e.js
  npx eslint@latest --max-warnings 0 .

See CONTRIBUTING.md for the full PR loop + house rules. Security-
sensitive patches: don't open here, see SECURITY.md.
-->

## Summary

<!-- One or two sentences. What does this change and why. -->

## Type of change

<!-- Check all that apply -->

- [ ] Bug fix (no API change)
- [ ] New framework primitive
- [ ] New CLI subcommand
- [ ] Wiki / docs / DEPLOY.md update
- [ ] Vendored dep refresh
- [ ] Test coverage / CI improvement
- [ ] Refactor (no behavior change)
- [ ] Other:

## Linked issue

<!-- Required for non-trivial changes. See CONTRIBUTING.md → "The PR loop" → step 1. -->

Closes #

## House rules checklist

<!-- See CONTRIBUTING.md → "House rules". -->

- [ ] No new npm runtime dependencies (vendored via `scripts/vendor-update.sh` if a new external library was needed)
- [ ] All crypto operations use the framework's PQC stack (no SHA-256 / AES-GCM / P-256-only / Ed25519-outside-hybrid)
- [ ] New audit-emitting code registers its namespace via `audit.registerNamespace`
- [ ] CommonJS / `var` / no TypeScript / no transpilation
- [ ] Used framework primitives (`C.TIME.*`, `C.BYTES.*`, `timingSafeEqual`, `b.validateOpts`, etc.) instead of raw literals or hand-rolled helpers
- [ ] New `create()` factory uses `validateOpts` for opts allow-list (boot-time validation)
- [ ] No "future patch" deferrals — sweep across all existing call sites in this same PR if introducing a shared helper

## Tests

- [ ] `node test/smoke.js` passes — count: `____`
- [ ] `examples/wiki/test/e2e.js` passes — count: `____`
- [ ] `npx eslint@latest --max-warnings 0 .` exits 0
- [ ] New tests added for the new behavior:
  - [ ] Layer 0 (primitive)
  - [ ] Layer 1 (state-touching)
  - [ ] Layer 2 (middleware composition)
  - [ ] Layer 3 (end-to-end framework boot)
  - [ ] Wiki e2e (operator-facing route)

## Documentation

<!-- Check the ones that apply to this PR -->

- [ ] Wiki seeded pages updated (`examples/wiki/seeders/prod/0001-default-pages.js`) for new operator-facing surfaces
- [ ] DEPLOY.md updated for new env vars / GitHub settings / cosign / verification
- [ ] SECURITY.md updated for new threat model entries / supported versions
- [ ] README.md updated if the new feature appears in the high-level pitch
- [ ] Commit message explains *why* and *what tradeoff*, not just *what*

## Behavior changes

<!-- If this PR changes existing behavior (output channel, exit code, default value, ...),
     call it out here so the next release notes can flag it. -->

## Open questions / reviewer focus

<!-- Anything you want the reviewer to look at specifically. -->
