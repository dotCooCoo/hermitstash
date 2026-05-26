# blamejs wiki — reference app + docs site

The blamejs wiki is the framework's documentation site, built as a working blamejs app. It is a working reference operators can study to see every primitive wired up in an opinionated baseline configuration.

## Boot

```bash
cd examples/wiki
npm install
WIKI_ADMIN_PASSWORD="some-strong-password" npm start
```

Server listens on `http://localhost:3008` by default. Override with `WIKI_PORT`. Admin credentials via `WIKI_ADMIN_EMAIL` (default `admin@blamejs.com`) and `WIKI_ADMIN_PASSWORD` (required ≥ 8 chars; a random dev password is generated and printed if unset).

## Run with Docker Compose

```bash
cd examples/wiki
docker compose up --build
```

The compose file mounts a named volume (`wiki-data`) at `/data` so the vault key, sqlite database, and audit chain persist across container restarts. Set `WIKI_ADMIN_PASSWORD` (and any other `WIKI_*` envs from `server.js`) in a `.env` file alongside `docker-compose.yml`, or in the host environment, to pin a stable admin credential. Healthcheck hits `/healthz` every 30 seconds.

The `Dockerfile` is multi-stage (deps build + slim runtime), runs as the unprivileged `node` user, and uses a `node:24-slim` base (24.14+ — the engine pin in `package.json` requires `>=24.14.1` for CVE-2026-21713 fix). Argon2id routes through Node's built-in `crypto.argon2*` API, so the image carries no native-module prebuild.

For production deploys with TLS terminator + auto Let's Encrypt, see [DEPLOY.md](./DEPLOY.md) — it documents the `docker-compose.prod.yml` overlay that fronts the wiki with Caddy and pulls the published `ghcr.io/blamejs/blamejs-wiki` image instead of building from source.

## Run the e2e test

```bash
cd examples/wiki
npm test
```

Boots the server in-process on an ephemeral port, hits each route with browser-shaped headers (CORS-on path included so the compression backpressure path is exercised), validates response codes and body content, walks every internal link, and verifies every code-block language is loadable by the Prism bundle. **102/102 checks** at present.

## What's wired (baseline-all-features stance)

The wiki is a reference, not a one-off — every in-process primitive the framework ships is wired with operator-safe defaults. Operators copying this app inherit the right baseline.

### Security middleware (all ON)

- `b.middleware.requestId` — every response carries `X-Request-Id`
- `b.middleware.securityHeaders` — HSTS, X-Frame-Options, COOP, COEP, etc.
- `b.middleware.botGuard` — rejects requests missing real-browser headers
- `b.middleware.cors` — same-origin only (`allowedOrigins: []`)
- `b.middleware.rateLimit` — 120 req/min memory token-bucket; `/healthz` skipped
- `b.middleware.cspNonce` — per-request nonce for inline styles/scripts
- `b.middleware.bodyParser` — form-URL-encoded + JSON
- `b.middleware.compression` — Brotli + gzip negotiation
- `b.middleware.attachUser` — session cookie → `req.user`
- `b.middleware.csrfProtect` — POST forms include hidden CSRF token
- `b.middleware.health` — `/healthz` (liveness), `/readyz` (readiness with DB check), `/startupz` (startup)

### State + storage

- `b.db` — SQLite with sealed columns + audit chain + audit signing
- `b.migrations` — `migrations/0001-pages-schema.js` creates pages table + FTS5 mirror + sync triggers
- `b.seeders` — `seeders/prod/0001-default-pages.js` seeds the concern-group nav (rerunnable: true)
- `b.cache` — page-render cache, namespace `wiki.page`, 5-minute TTL, audit-emitting

### Auth

- `b.auth.password` (Argon2id) — admin login
- `b.session` — sealed cookie token, 24h expiry
- `b.permissions` — `admin` and `viewer` roles, `admin` scope gates `/admin/*`

### Rendering

- `b.template` — eval-free template engine, views in `views/`
- `b.render.html` / `b.render.htmlString` / `b.render.json` / `b.render.redirect`
- `b.staticServe` — assets in `public/` (favicon.ico, robots.txt, etc.)

### Localization

- `b.i18n` — wired with English by default. Operators add locales by extending the `translations` object or pointing `dir` at a JSON tree.

### Validation + observability + audit

- `b.slug` — admin save uses `b.slug(value, { fallback })` for URL slug normalization
- `b.audit` — every login / page edit / cache clear / etc. emits with the 5 W's (WHO/WHAT/WHEN/WHERE/HOW) via `b.requestHelpers.extractActorContext`
- `b.observability` — every primitive's events (cache hit/miss, audit emit, etc.) route through here; pluggable to OTel
- `b.metrics` + `b.tracing` — pass-through unless operator wires a real backend

## What's documented but not wired (operator-specific)

These primitives are intentionally NOT wired in the wiki because they require operator-supplied infrastructure (TLS certs, SMTP servers, external DB, etc.). The docs pages explain how operators integrate them:

- `b.cluster` — opt-in HA (active/active leader election)
- `b.externalDb` — Postgres / SQLite-cluster operator-side
- `b.mtlsCa` — operator-managed certificate authority
- `b.pqcGate` — TLS layer for production deploy
- `b.mail` + `b.mailBounce` — SMTP / SES operator setup
- `b.websocket` + `b.websocketChannels` — operator-opt-in for live features
- `b.objectStore` + `b.storage` — S3 / GCS / Azure Blob (operator backend)
- `b.backup` + `b.restore` — CLI workflow
- `b.bundler` — frontend asset bundling (no client JS in the wiki yet)

## Production deploy

The wiki ships with development-friendly defaults (`vault: { mode: "plaintext" }`, `db: { atRest: "plain", auditSigning: { mode: "plaintext" } }`). For production:

1. Set `BLAMEJS_VAULT_PASSPHRASE` (or wire a `vault.passphraseSource`)
2. Change `vault.mode` to `"wrapped"` (default)
3. Change `db.atRest` to `"encrypted"` (default; requires tmpfs at `/dev/shm` or `BLAMEJS_TMPDIR`)
4. Change `db.auditSigning.mode` to `"wrapped"`
5. Deploy behind a TLS-terminating reverse proxy OR enable `b.pqcGate`
6. Set `WIKI_TRUST_PROXY=1` if (and only if) the wiki sits behind a reverse proxy that injects `x-forwarded-proto`. With trustProxy off (the default), the wiki ignores `x-forwarded-proto` for cookie Secure-flag detection, so a misconfigured deployment can't accept attacker-supplied `x-forwarded-proto: https` as proof a request was over TLS.
7. Set `WIKI_ADMIN_PASSWORD` to a strong value managed by your secret-store

## Trust model for editable page bodies

Page bodies are stored verbatim and rendered as raw HTML (the template uses `{{{ body }}}`, not `{{ body }}`). This is **intentional**, but it means:

- **Anyone with admin credentials can ship arbitrary HTML / `<script>` / `<style>` to every page reader.** The `wiki:admin` scope is fully equivalent to "operator-trusted to author the rendered output."
- The framework's strict CSP (no `'unsafe-inline'`) blocks inline `<script>` even from admin-authored bodies — an XSS payload pasted into a page would not execute. This is the framework's defense-in-depth, not a license to lower CSP.
- The save-time `b.htmlBalance.check()` is for shape correctness (unclosed tags would otherwise eat surrounding layout), **not** for sanitization.

Adopters who plan to expand the editor surface beyond a single trusted admin should swap `{{{ body }}}` for sanitized rendering. The framework does not ship an HTML sanitizer primitive; the recommended pattern is to vendor a maintained sanitizer (DOMPurify-equivalent) and wrap it in a small `b.sanitize`-shape helper module — same vendoring discipline as `lib/vendor/MANIFEST.json`. Run sanitization at **save** time so the stored body is already safe; running it at render time means an XSS payload sits in the database in case the sanitizer ever regresses.

## File layout

```
examples/wiki/
├── package.json                  # depends on @blamejs/core via file:../..
├── server.js                     # createApp boot, all primitives wired
├── routes/
│   ├── pages.js                  # public routes (split: registerSpecific + registerCatchAll)
│   └── admin.js                  # login / logout / dashboard / edit / save (admin-gated)
├── views/
│   ├── _layout.html              # base layout (locale, dir, csp-nonce, csrf-token, user)
│   ├── partials/
│   │   └── nav.html              # concern-group navigation
│   ├── home.html
│   ├── page.html                 # renders DB-stored page bodies
│   ├── login.html
│   ├── search.html
│   └── admin/
│       ├── dashboard.html
│       └── edit.html
├── migrations/
│   └── 0001-pages-schema.js      # pages + FTS5 + sync triggers
├── seeders/
│   └── prod/
│       └── 0001-default-pages.js # nav landing pages
├── public/                       # static assets (favicon etc.)
├── test/
│   └── e2e.js                    # boot-and-probe via node:http with browser headers
└── data/                         # local SQLite + vault key (gitignored)
```

## Known gaps

- **Search**: `/search?q=...` works against the FTS5 index, but most concern-group pages are still stubs so there isn't much to find yet.
- **Concern-group pages are stubs**: most landing pages (Auth, Storage, HTTP, etc.) currently have a "Coming soon" body. Full primitive walkthroughs land as each group is written.
- **Editor is plain HTML**: the admin edit screen is a `<textarea>`. A small client-side enhancement (autosave, slug-from-title preview) is on the list.
- **Recipe pages**: cluster mode, mail, websocket, FTS5 schema walkthrough — stubbed for now.
