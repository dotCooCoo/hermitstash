# Migrating

Operator-facing migration recipes per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the framework — the running app warns about each (with `BLAMEJS_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.

**Out-of-band breaking changes** (schema breaks, config-shape changes, on-disk format breaks) cannot be expressed as `deprecate()` calls because there's no in-process runtime to warn from. They're hardcoded in the OUT_OF_BAND_BREAKS table inside `scripts/gen-migrating.js` so the operator sees the full upgrade path here without needing to grep CHANGELOG.

## No active deprecations

The framework has no `deprecate()`-marked surface awaiting removal.

---

## Out-of-band breaking changes

Listed newest-first.

### v0.9.15 — `b.middleware.idempotencyKey.dbStore — table schema`

Single `v` JSON-envelope column split into discrete `fingerprint` / `status_code` / `headers` / `body` / `expires_at` columns; `headers` + `body` are sealed via `b.cryptoField.sealRow` when vault is initialized; `k` column carries the sha3-512 namespace-hash of the operator-supplied key.

Operators with a v0.9.14 (or earlier) idempotency table on disk:

```sql
DROP TABLE <tableName>;   -- default: blamejs_idempotency_keys
```

Or pick a fresh `tableName` in v0.9.15+ `dbStore({ tableName: "..." })`. The init step (`init: true`, default) creates the new split-column schema. `CREATE TABLE IF NOT EXISTS` does NOT migrate column layout on an existing table, so the drop-and-recreate is required.

Cached records in the existing table are not recoverable across the schema break — operators who care about replay continuity warm the new table by retrying the in-flight requests under the new dbStore.
