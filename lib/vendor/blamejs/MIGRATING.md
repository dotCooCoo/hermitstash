# Migrating

Operator-facing migration recipes per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the framework — the running app warns about each (with `BLAMEJS_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.

**Out-of-band breaking changes** (schema breaks, config-shape changes, on-disk format breaks) cannot be expressed as `deprecate()` calls because there's no in-process runtime to warn from. They're hardcoded in the OUT_OF_BAND_BREAKS table inside `scripts/gen-migrating.js` so the operator sees the full upgrade path here without needing to grep CHANGELOG.

## No active deprecations

The framework has no `deprecate()`-marked surface awaiting removal.

---

## Out-of-band breaking changes

Listed newest-first.

### v0.15.7 — `b.auth.oauth verifyIdToken — azp (authorized party) is now enforced`

verifyIdToken now applies OIDC Core 3.1.3.7: a multi-audience ID token (aud is an array with more than one entry) MUST carry an azp claim, and a present azp MUST equal the configured client_id. A token whose azp is a different client, or a multi-audience token with no azp, now throws (auth-oauth/azp-mismatch / auth-oauth/azp-required). Previously only `aud contains client_id` was checked, so a token authorized for a different party but also listing this RP verified clean.

No change for the common single-audience ID token with no azp. If your IdP issues multi-audience ID tokens, ensure it sets azp to your client_id (it should, per the spec) — otherwise verifyIdToken will now reject them. This is a security fix; a token that fails the new check was authorized for a different client.

### v0.15.7 — `b.safeUrl.canonicalize — IPv4-mapped hosts fold to IPv4`

b.safeUrl.canonicalize / b.ssrfGuard.canonicalizeHost now fold an IPv4-mapped IPv6 host (::ffff:1.2.3.4) to its embedded IPv4 dotted form, and strip every trailing dot from a host. In 0.15.6 it canonicalized to an IPv6 string and only one trailing dot was stripped. NAT64 / 6to4 hosts stay IPv6.

No code change is needed — this makes a dual-stack / NAT64 peer unify with a dotted-IPv4 allow/deny entry as intended. If you persisted canonical host strings produced by 0.15.6 (e.g. as cache or dedup keys) and compare them against freshly-canonicalized hosts, recompute them: an IPv4-mapped host now yields the dotted IPv4 instead of the bracketed IPv6, and a multi-trailing-dot host yields the bare name.

### v0.15.6 — `b.auth.sdJwtVc — ES256 / ES384 signatures are now JOSE raw r||s, not DER`

`b.auth.sdJwtVc` now signs and verifies ES256 / ES384 with `dsaEncoding: "ieee-p1363"` (raw r||s), the encoding JOSE / JWS and EUDI wallets require. Previously it used node:crypto's default DER ECDSA encoding, so a credential this issuer signed was rejected by conformant verifiers and the library rejected conformant holders' key-binding JWTs. The signature bytes change shape (64 bytes for ES256, 96 for ES384, no leading `0x30` SEQUENCE tag).

No code change is needed — interop with conformant JOSE / wallet verifiers now works where it previously failed. Two things to re-check if you integrated with the OLD output:

- A previously-issued ES256 / ES384 SD-JWT-VC signed by an earlier version is DER-encoded; re-issue it (signatures are not portable across the encodings). Tokens are short-lived, so this clears on the next issuance cycle.
- If you pinned, cached, or asserted on the raw signature bytes of this library's ES256 / ES384 output, update the fixture — the bytes are now `ieee-p1363`. EdDSA / ML-DSA signatures are unchanged.

### v0.15.6 — `b.auth.oauth verifyIdToken — skipExpCheck is restricted to logout tokens`

`verifyIdToken`'s `skipExpCheck` option now throws (`auth-oauth/skip-exp-check-not-allowed`) on any token that is not an OIDC Back-Channel-Logout token (no `http://schemas.openid.net/event/backchannel-logout` event claim), and enforces an `iat` freshness floor on logout tokens (`auth-oauth/logout-token-stale`). Previously any caller could pass `skipExpCheck: true` to verify an expired — or replayed — ID token. The option was undocumented and only used internally by the back-channel-logout path, which is unaffected.

No change for normal ID-token verification or for the framework's back-channel-logout handling. If you called `verifyIdToken(token, { skipExpCheck: true })` directly on a non-logout token (an undocumented use), it now throws: drop the option so expiry is validated, or verify the token through the back-channel-logout path if it really is a logout token.

### v0.15.4 — `b.middleware.dpop — replayStore now required at mount`

`b.middleware.dpop` now REQUIRES a `replayStore` at mount time and throws (`auth-dpop/replay-store-required`) if it is omitted or lacks `checkAndInsert`. Previously the jti-replay check was gated behind store presence, so omitting it silently mounted a DPoP gate with NO replay defense — a captured proof could be replayed indefinitely (RFC 9449 §11.1).

Operators mounting `b.middleware.dpop` without a `replayStore`:

```js
b.middleware.dpop({
  replayStore: b.nonceStore.create({ backend: "memory" }), // shared backend on multi-process
  // ...other opts
});
```

Use a process-shared `replayStore` backend (not `"memory"`) on a multi-process / multi-node deployment so a proof replayed against a different worker is still caught. The low-level `b.auth.dpop.verify` primitive keeps `replayStore` optional for advanced callers that track `jti` themselves.

### v0.15.4 — `b.session.rotate — { req } required for a fingerprint-bound session`

Rotating a session created with a device fingerprint (`{ req, fingerprintFields }`) now requires the same `{ req, fingerprintFields }` at `b.session.rotate()`; a bound session rotated without `req` throws (`ROTATE_FINGERPRINT_REQ_REQUIRED`). The fingerprint is keyed to the session id, so rotation must re-key it to the new id from the live request — previously rotation left the old-id-keyed hash in place, which made the next `verify` false-drift (logging the user out under strict operators) or silently break the binding. Unbound sessions are unaffected.

Operators who rotate fingerprint-bound sessions (login / MFA / role-change transitions):

```js
// Pass the same { req, fingerprintFields } used at create():
await b.session.rotate(oldToken, { req, fingerprintFields: ["clientIp", "userAgent"], reason: "mfa" });
```

If you rotate a bound session from a context without the request, you must supply `req` so the binding can follow to the new session id. Sessions created WITHOUT a fingerprint need no change.

### v0.9.15 — `b.middleware.idempotencyKey.dbStore — table schema`

Single `v` JSON-envelope column split into discrete `fingerprint` / `status_code` / `headers` / `body` / `expires_at` columns; `headers` + `body` are sealed via `b.cryptoField.sealRow` when vault is initialized; `k` column carries the sha3-512 namespace-hash of the operator-supplied key.

Operators with a v0.9.14 (or earlier) idempotency table on disk:

```sql
DROP TABLE <tableName>;   -- default: blamejs_idempotency_keys
```

Or pick a fresh `tableName` in v0.9.15+ `dbStore({ tableName: "..." })`. The init step (`init: true`, default) creates the new split-column schema. `CREATE TABLE IF NOT EXISTS` does NOT migrate column layout on an existing table, so the drop-and-recreate is required.

Cached records in the existing table are not recoverable across the schema break — operators who care about replay continuity warm the new table by retrying the in-flight requests under the new dbStore.
