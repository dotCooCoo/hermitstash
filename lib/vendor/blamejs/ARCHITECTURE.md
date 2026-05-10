# blamejs architecture

A new contributor's guide to where things live and why. The repository tree at `git ls-tree -r HEAD --name-only | wc -l` is north of 800 files; this doc is the orientation map.

## Top-level layout

```
blamejs/
├── bin/              # `blamejs` CLI entry shim → lib/cli.js
├── index.js          # Single npm export — `var b = require("@blamejs/core")`
├── lib/              # Framework source (the SHIPPED code)
│   ├── vendor/       # Vendored crypto + utility libraries (no npm runtime deps)
│   ├── middleware/   # HTTP middleware primitives
│   ├── auth/         # Auth-flow primitives (password, passkey, OAuth, JWT, TOTP)
│   ├── parsers/      # Safe-by-default config parsers (yaml, toml, json, schema)
│   ├── object-store/ # S3/Azure/local object-store backends
│   ├── vault/        # Vault keypair management + passphrase ops
│   ├── backup/       # Backup bundle creation
│   └── *.js          # Top-level primitives (one .js per primitive)
├── examples/wiki/    # Reference operator-built app (lives at blamejs.com)
├── test/             # Layered tests (smoke runner walks every layer)
│   ├── layer-0-primitives/
│   ├── layer-1-state/
│   ├── 30-chain.js etc.  # Layer 2/3 integration tests
│   └── helpers/      # Shared test fixtures + capture helpers
├── scripts/          # Vendor-update + sync-to-public + audit-history tooling
├── .github/          # CI + release-container workflows + issue templates
└── *.md              # README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ARCHITECTURE
```

## Single export, named primitives

Operators consume the framework via one `require()`:

```js
var b = require("@blamejs/core");

await b.createApp({...});       // app boot
b.audit.safeEmit({...});         // audit chain
var keys = b.apiKey.create({...}); // primitive instances
```

Every primitive is namespaced under `b.X`. `index.js` is the canonical export list — when adding a new primitive, register it there in alphabetical order (within its group: Crypto / Storage / Audit / HTTP / Observability / Auth / etc.). The grep is `git grep "var X =" index.js` to find similar entries.

## Where each concern lives

| Concern | Primary file(s) | Tests |
|---|---|---|
| App boot orchestration | `lib/app.js` | `test/layer-3-*` |
| HTTP router | `lib/router.js` | `test/30-chain.js`, `test/00-primitives.js` |
| Middleware (CORS, CSRF, rate-limit, body parsing, etc.) | `lib/middleware/*.js` | `test/layer-0-primitives/*.test.js` |
| Vault (PQC keypair, sealed/wrapped) | `lib/vault/index.js` + `lib/vault/wrap.js` + `lib/vault/passphrase-ops.js` | `test/layer-1-state/vault*.test.js` |
| Sealed-column DB | `lib/db.js` + `lib/crypto-field.js` | `test/layer-1-state/sealed-fields*.test.js` |
| Audit chain | `lib/audit.js` + `lib/audit-chain.js` + `lib/audit-sign.js` + `lib/chain-writer.js` | `test/30-chain.js` |
| API keys | `lib/api-key.js` | `test/layer-0-primitives/api-key*.test.js` |
| Permissions (RBAC) | `lib/permissions.js` | `test/00-primitives.js` |
| Sessions | `lib/session.js` + `lib/middleware/attach-user.js` | `test/layer-1-state/session*.test.js` |
| Mail / notify / webhook | `lib/mail.js` + `lib/notify.js` + `lib/webhook.js` | `test/00-primitives.js` |
| i18n | `lib/i18n.js` + `lib/middleware/i18n-mw.js` (folded into i18n.js) | `test/00-primitives.js` |
| Cluster mode + external DB | `lib/cluster.js` + `lib/external-db.js` + `lib/cluster-storage.js` | `test/30-chain.js` |
| Backup / restore | `lib/backup/index.js` + `lib/restore.js` + `lib/restore-bundle.js` | `test/00-primitives.js` |
| Templates | `lib/template.js` (eval-free interpreter) | `test/00-primitives.js` |
| Logging / metrics / tracing | `lib/log.js` + `lib/metrics.js` + `lib/tracing.js` + `lib/observability.js` | `test/00-primitives.js` |
| CLI | `lib/cli.js` (dispatch) + `lib/cli-helpers.js` (shared headless-app + reporter) | `test/layer-0-primitives/cli-*.test.js` |
| Wiki example app | `examples/wiki/server.js` + `examples/wiki/lib/build-app.js` + `examples/wiki/routes/*.js` + `examples/wiki/views/*.html` | `examples/wiki/test/e2e.js` |
| Outbound HTTP + SSRF gate | `lib/http-client.js` + `lib/ssrf-guard.js` + `lib/safe-url.js` | `test/layer-0-primitives/http-client-*.test.js` + `test/layer-0-primitives/ssrf-guard*.test.js` |
| Outbound WebSocket client | `lib/ws-client.js` | `test/layer-0-primitives/ws-client*.test.js` |
| Network configurability (NTP/NTS/DNS/proxy/CA) | `lib/network/*.js` | `test/layer-0-primitives/network-*.test.js` |
| Object store + bucket-ops + Object Lock | `lib/object-store/*.js` | `test/layer-1-state/object-store*.test.js` |
| Outbox / inbox (exactly-once) | `lib/outbox.js` + `lib/inbox.js` | `test/layer-1-state/outbox-inbox*.test.js` |
| Content-safety guards (`b.guard*`) | `lib/guard-*.js` + `lib/gate-contract.js` + `lib/codepoint-class.js` | `test/layer-0-primitives/guard-*.test.js` + `test/layer-5-integration/guard-host-integration.test.js` |
| Compliance regimes | `lib/compliance.js` + `lib/dora.js` + `lib/dsr.js` + `lib/cra-report.js` + `lib/nis2-report.js` + `lib/sec-cyber.js` + `lib/fapi2.js` + `lib/fdx.js` + `lib/tcpa-10dlc.js` + `lib/iab-tcf.js` + `lib/iab-mspa.js` + `lib/incident-report.js` | per-regime tests under `test/layer-0-primitives/` |
| MCP / GraphQL Federation / A2A guards | `lib/mcp.js` + `lib/graphql-federation.js` + `lib/a2a.js` | `test/layer-0-primitives/mcp*.test.js` + similar |
| Honeytoken / forensic snapshot / config drift | `lib/honeytoken.js` + `lib/audit-tools.js` (`forensicSnapshot`) + `lib/config-drift.js` (`verifyVendorIntegrity`) | `test/layer-0-primitives/honeytoken*.test.js` + `test/layer-0-primitives/config-drift*.test.js` |
| Account-takeover kill-switch | `lib/auth/ato-kill-switch.js` | `test/layer-0-primitives/ato-kill-switch*.test.js` |
| Content credentials (C2PA / SB-942) | `lib/content-credentials.js` | `test/layer-0-primitives/content-credentials*.test.js` |
| Events bus + CloudEvents | `lib/events.js` + `lib/cloud-events.js` | `test/layer-0-primitives/events*.test.js` |
| Feature flags (OpenFeature) | `lib/flag.js` + `lib/middleware/flag-context.js` | `test/layer-0-primitives/flag*.test.js` |
| File-upload chunking + filename safety | `lib/file-upload.js` + `lib/guard-filename.js` | `test/layer-1-state/file-upload*.test.js` |

## Boot order

`b.createApp({...})` orchestrates a strict dependency-ordered boot. Skipping or reordering breaks invariants downstream.

1. **Vault** — keypair loaded (or generated on first run). Sealed columns + audit chain + signed checkpoints all depend on the vault key being available.
2. **External DB** (cluster mode only) — if `opts.externalDb` is set, init the cluster's durable backend.
3. **Cluster lease** — if `opts.cluster` is set, acquire the leader lease before touching any framework schema.
4. **Framework schema** — `_blamejs_audit_log`, `_blamejs_audit_checkpoints`, `_blamejs_sessions`, `_blamejs_api_keys`, `_blamejs_consent_log`, etc. created if absent (idempotent).
5. **Local DB** — open the sqlite file (or in-memory tmpfs handle in encrypted-at-rest mode).
6. **Router + middleware stack** — request-id → securityHeaders → botGuard → cors → fetchMetadata → networkAllowlist (when wired) → rateLimit → dailyByteQuota → cspNonce → cookies → bodyParser → compression → attachUser → dbRoleFor (when wired) → csrfProtect → traceLogCorrelation → spanHttpServer → cspReport (route-mounted) → health. Operator-mounted variants: `requireAuth` / `requireAal` / `requireMtls` / `requireStepUp` / `requireBoundKey` / `bearerAuth` / `dpop` / `hostAllowlist` / `requireMethods` / `requireContentType` / `gpc` / `errorHandler`.
7. **Operator routes** — the `routes: function (router) {...}` callback runs. Operator wires their own routes on top of the middleware stack.
8. **Error handler** — last so it catches everything from operator routes and middleware.

`app.shutdown()` reverses the order.

## Audit-everything posture

Every operator action emits to the audit chain. The framework primitives self-emit (e.g., `apiKey.issue` → `apikey.issue`); operators emit their own via `audit.safeEmit({ action: "wiki.page.edited", ... })`. The shape is the 5 W's (WHO/WHAT/WHEN/WHERE/HOW) — the framework derives most of it from the request via `b.requestHelpers.extractActorContext(req)`.

A new namespace must be registered before first emission:

```js
b.audit.registerNamespace("myapp"); // call once at app bootstrap
```

The framework's own namespaces are pre-registered in `lib/audit.js` — read `FRAMEWORK_NAMESPACES` for the live set with per-name sub-event documentation. The smoke test `test/layer-0-primitives/audit-framework-namespaces.test.js` walks `lib/` for emission patterns and fails CI on any missing registration.

## Crypto envelope versioning

Every encrypted blob starts with a 4-byte header identifying KEM / cipher / KDF. `b.crypto.decrypt` dispatches on the header bytes, not on a guess at the active default — old blobs continue reading after the active algorithm rolls forward.

To add a new algorithm (HQC when standardized, etc.):

1. Assign the next ID in `lib/crypto.js`'s `KEM` / `CIPHER` / `KDF` constants
2. Implement the encrypt/decrypt path in `lib/crypto.js`
3. Set the `ACTIVE_*` constant for new writes
4. Keep the old ID's decrypt case in place — back-compat is mandatory
5. Vendor the upstream library via `scripts/vendor-update.sh`

The same pattern works for new ciphers and KDFs.

## Vendoring policy

Zero npm runtime dependencies. `lib/vendor/` holds bundled third-party libraries with their license + version + provenance manifest at `lib/vendor/MANIFEST.json`. The vendor-update script (`scripts/vendor-update.sh`) does:

1. `npm install <pkg> [@version]` (in a scratch dir)
2. esbuild bundle to `lib/vendor/<name>.cjs` (server) and `public/js/<name>.js` (browser, where applicable)
3. Copy + update MANIFEST.json
4. Remove the npm install (no `node_modules` dep persists)

For the noble-* libraries (ESM-only upstream), there's a manual ESM→CJS conversion step in the script — see `scripts/vendor-update.sh` for the exact handling.

## Tests

The smoke target (`node test/smoke.js`) is the single entry point that walks all four layers in order:

- **Layer 0 — Primitives** (`test/layer-0-primitives/`): pure-function primitives. No DB, no network, no vault.
- **Layer 1 — State** (`test/layer-1-state/`): primitives that touch the DB or vault. Spin up an isolated data dir per test.
- **Layer 2 — Composition** (`test/00-primitives.js` + others): middleware composition + framework integration.
- **Layer 3 — End-to-end** (`test/30-chain.js`, `test/50-integration.js`): full framework boot scenarios including cluster mode + external DB.

A new framework primitive lands with at least Layer 0 tests. New middleware lands with Layer 2. New CLI subcommand lands with `test/layer-0-primitives/cli-X.test.js` (see `cli-vault.test.js`, `cli-backup.test.js`, `cli-api-key.test.js` for the established shape — they boot a real headless app instance via `b.cliHelpers.bootApp` and round-trip operations through the CLI dispatcher).

The wiki example app has its own e2e at `examples/wiki/test/e2e.js` — boots the wiki on an ephemeral port, hits every authenticated and public route via `node:http`, asserts the rendered output. Operators forking the framework should keep their own equivalent.

## Where to read first

If you're new to the codebase and want to understand how it fits together, read in this order:

1. `index.js` — the single export surface
2. `lib/app.js` `createApp()` — the boot orchestration
3. `lib/audit.js` — the audit chain shape (most other primitives emit through this)
4. `lib/crypto.js` — envelope versioning + active algorithms
5. `lib/middleware/csrf-protect.js` — a representative middleware (cookie-mode + boot-time validation + `req.X` exposure)
6. `lib/cli.js` + `lib/cli-helpers.js` — the CLI dispatch + headless-app pattern
7. `examples/wiki/lib/build-app.js` — what an operator-built app looks like

This isn't a complete tour — it's enough orientation to start contributing meaningfully without spelunking every primitive.
