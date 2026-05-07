# Migrating

Operator-facing migration recipes per breaking change. Each entry below is a `deprecate()`-marked surface in the framework — the running app will warn about it (with `BLAMEJS_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.

## No active deprecations

The framework has no `deprecate()`-marked surface awaiting removal.
