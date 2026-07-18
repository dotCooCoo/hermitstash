# Deploying the wiki

The wiki ships with two compose configurations:

- `docker-compose.yml` — local dev. Builds from source, exposes 3008.
- `docker-compose.prod.yml` — production overlay. Pulls the published GHCR image, fronts it with Caddy for automatic TLS, exposes 80/443.

## Quick deploy to a VPS for `blamejs.com`

Prerequisites:

- A host with Docker + Docker Compose installed
- Inbound 80/443 open
- DNS `A` (and `AAAA` if IPv6) for `blamejs.com` and `www.blamejs.com` pointing at the host
- A stable strong admin password (see `.env` below)

Steps:

```bash
# 1. Get the deploy artifacts onto the host
git clone https://github.com/blamejs/blamejs.git
cd blamejs/examples/wiki

# 2. Configure the .env (every value below is optional except the
#    one explicitly marked REQUIRED — see "Environment variables"
#    section for the full matrix).
cat > .env <<'EOF'
# REQUIRED
WIKI_ADMIN_PASSWORD=<a strong passphrase>

# Recommended once you flip the wiki to wrapped vault mode
BLAMEJS_VAULT_PASSPHRASE=<a different strong passphrase>

# Optional — defaults shown
WIKI_ADMIN_EMAIL=admin@blamejs.com
WIKI_PORT=3008
LOG_LEVEL=info

# Optional — outbound page-edit webhook
WIKI_WEBHOOK_URL=
WIKI_WEBHOOK_SECRET=
EOF
chmod 600 .env

# 3. Start the stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 4. Watch the first boot — Caddy will request the cert from
#    Let's Encrypt and the wiki will seed its admin user.
docker compose logs -f
```

When the Caddy logs show `certificate obtained successfully`, the site is live at `https://blamejs.com`.

## Environment variables

The wiki container reads its configuration from environment. `docker-compose.prod.yml` wires every variable below from your `.env`; the Dockerfile sets non-secret defaults so an operator who just wants the basics can leave most blank.

### Wiki app

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `WIKI_ADMIN_PASSWORD` | **yes (production)** | random + printed to stdout once | Seeded admin login. Setting it explicitly avoids the random-on-each-restart pattern. |
| `WIKI_ADMIN_EMAIL` | no | `admin@blamejs.com` | Seeded admin login email. |
| `WIKI_PORT` | no | `3008` | HTTP listen port inside the container. Caddy proxies to this; rarely overridden. |
| `WIKI_DATA_DIR` | no | `/data` | On-disk path the wiki writes vault key + sqlite + audit chain to. Bound to a Docker volume in the compose. |
| `WIKI_WEBHOOK_URL` | no | unset | Outbound HTTPS endpoint that receives one POST per `wiki.page.edited` event. |
| `WIKI_WEBHOOK_SECRET` | required if URL set | unset | HMAC secret the webhook receiver uses to verify the request signature. |

### Framework (`BLAMEJS_*`)

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `BLAMEJS_VAULT_PASSPHRASE` | required for production posture | unset | Argon2id-stretched into the vault-key wrapping key. **Setting this auto-flips the wiki to wrapped vault + encrypted-at-rest DB at boot** (the wiki's `lib/build-app.js` reads the env var as the production-posture signal). Without it the wiki boots in plaintext mode for dev ergonomics. |
| `BLAMEJS_AUDIT_SIGNING_PASSPHRASE` | required for production posture | unset | Argon2id-stretched into the audit-signing key wrap. **Setting this auto-flips audit-sign to wrapped at boot** (`audit-sign.key.sealed` on disk, never plaintext). Different from `BLAMEJS_AUDIT_PASSPHRASE` below — that's for the archive CLI, not boot-time signing. |
| `BLAMEJS_AUDIT_PASSPHRASE` | only when running `blamejs audit` CLI | unset | Used by `blamejs audit archive / export / verify / purge` for the chain-export bundle wrap. Not read at app boot. |
| `WIKI_VAULT_MODE` | no | auto-detect | `wrapped` \| `plaintext`. Explicit override for the auto-detect logic above. |
| `WIKI_DB_AT_REST` | no | auto-detect | `encrypted` \| `plain`. Explicit override. |
| `WIKI_AUDIT_SIGNING_MODE` | no | auto-detect | `wrapped` \| `plaintext`. Explicit override. |
| `BLAMEJS_BACKUP_PASSPHRASE` | only when running `blamejs backup` CLI | unset | Used by `blamejs backup verify / extract` against an existing bundle on disk. Not read at app boot. |
| `BLAMEJS_DEPRECATIONS` | no | `warn` | `warn` (default) emits a structured log line; `throw` makes deprecated calls fail loud (recommended pre-v1); `silent` suppresses. |

### Standard Node

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `NODE_ENV` | no | `production` | Standard `production`/`development` flag. |
| `LOG_LEVEL` | no | `info` | Structured-log filter. `debug` / `info` / `warn` / `error`. |

### Secrets handling

Every passphrase / webhook secret in the table above is **never** ENV-baked into the image — they're injected at runtime via the `.env` file (compose), Docker secrets, or a secret-manager mount. The `.env` file should be `chmod 600` and excluded from version control. The `Dockerfile` only sets non-secret defaults (`NODE_ENV`, `WIKI_DATA_DIR`, `WIKI_PORT`).

## What's where

- The wiki container persists state in the `wiki-data` named volume — vault key, sealed audit-signing key, sqlite database, audit chain. **Back this up.** Losing it loses the audit chain and admin credentials.
- Caddy persists ACME state in the `caddy-data` named volume. Deleting it forces a re-issuance from scratch — Let's Encrypt rate limits apply, so don't.
- All TLS is Caddy's. The wiki container only speaks HTTP on the compose network.
- Prefer nginx? [`nginx.conf`](./nginx.conf) is an equivalent reference config — same TLS 1.3 floor, `www.`→apex 308 redirect, `X-Forwarded-Proto https` / `X-Forwarded-For`, and HSTS `max-age=63072000; includeSubDomains; preload`. nginx does not issue certificates itself; pair it with certbot for the cert paths it references, and set `WIKI_ADMIN_TRUSTED_PROXIES` to the proxy's CIDR so the wiki trusts the forwarded headers.

## Updating to a new version

```bash
# Pin the new version in docker-compose.prod.yml (image: ghcr.io/...:vX.Y.Z)
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

The wiki container's healthcheck on `/healthz` ensures Caddy only routes once the new container is ready.

## Rolling back

```bash
# Edit docker-compose.prod.yml back to the previous image tag.
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d wiki
```

The on-disk schema is forward-compatible within a minor; downgrading across a minor isn't supported.

## Troubleshooting

- **Caddy can't issue cert** — check that ports 80 and 443 are reachable from the public internet (Let's Encrypt's HTTP-01 challenge needs port 80). Run `docker compose logs caddy` for the specific ACME error.
- **Wiki returns 502** — the wiki container's healthcheck is failing. `docker compose logs wiki` shows the cause; usually missing `WIKI_ADMIN_PASSWORD` or a corrupt vault key.
- **Cookies / sessions don't stick** — the wiki sets `Secure` cookies in production. If you're testing on `http://` for some reason, sessions will drop; either add `WIKI_INSECURE_COOKIES=1` (dev only) or use the proper TLS path.

## GitHub repository + Actions setup (publishing your own image)

If you're forking `blamejs` (or running this wiki as your own deployment that ships its own GHCR image), the workflows have prerequisites on the GitHub side that aren't visible in the code. Configure these once per org / per fork.

### Org-level Actions billing

The release-container workflow runs five jobs per tag push: 3 lint jobs, the build/scan/sign/publish job, and a post-publish smoke-test. The build job does a multi-arch build (linux/amd64 + linux/arm64 via QEMU) which consumes more runner-minutes than a single-arch build. Make sure the **organization's** Actions spending limit (not personal) is non-zero — public-repo Linux runner-minutes are free on most plans, but a `Stop usage: Yes` setting with a $0 limit blocks all jobs.

- **Org settings**: `https://github.com/organizations/<your-org>/settings/billing`
- **Spending limit**: `https://github.com/organizations/<your-org>/settings/billing/spending_limit`
- Symptom of a billing block: a job fails in seconds with no steps, no runner allocated, and an annotation containing `"recent account payments have failed or your spending limit needs to be increased"`. The fix has to propagate from GitHub's billing system after you change the limit; allow a few minutes.

### Workflow permissions (already set in the YAML, but worth knowing)

`.github/workflows/release-container.yml` declares the minimum permissions the workflow needs. Each one is required for a specific step:

| Permission | Used by | Why |
|---|---|---|
| `contents: read` | `actions/checkout@v6` | Read the repo source |
| `packages: write` | `docker/login-action@v4` + `docker/build-push-action@v7` | Push the built image to `ghcr.io/<owner>/blamejs-wiki` |
| `id-token: write` | `sigstore/cosign-installer@v3` + `cosign sign --yes` | Mint a short-lived OIDC token GitHub Actions exchanges with Sigstore's Fulcio for a keyless signing certificate |

CI (`ci.yml`) declares `contents: read` + `pull-requests: write` (the latter so the lint-summary job can post / update the sticky PR comment).

These are scoped per workflow; the org-level **default permissions** at `https://github.com/organizations/<your-org>/settings/actions` should be set to `Read repository contents and packages permissions` (the most-restrictive default) so workflows that don't declare explicit permissions can't accidentally write.

### GHCR package visibility

GitHub Container Registry packages default to **private** when a workflow first publishes them. For an open-source framework, you'll want public so operators can `docker pull` without authenticating:

- `https://github.com/orgs/<your-org>/packages/container/blamejs-wiki/settings`
- "Change visibility" → Public

Even with a public package, the post-publish smoke-test job logs in via `docker/login-action@v4` (using the auto-provided `GITHUB_TOKEN`) — login is a no-op for public packages and required for private, so the same workflow shape works either way.

### Cosign signature verification (downstream operators)

The publish job signs the multi-arch manifest with Sigstore's keyless flow — there's no long-lived key to manage. The signing identity is the workflow itself, attested by GitHub's OIDC issuer. Downstream operators verify before pulling:

```bash
cosign verify ghcr.io/<your-org>/blamejs-wiki:<tag> \
  --certificate-identity-regexp "https://github.com/<your-org>/<repo>/.github/workflows/release-container.yml@refs/tags/v.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful verification proves the image was built by the actual release-container workflow on a tag push, and not pushed by anyone with `packages: write` directly. Combine with the SBOM + provenance attestations the workflow attaches (`provenance: true` + `sbom: true` on `docker/build-push-action`) for full supply-chain confidence.

### Branch protection (recommended)

For `main`, require the CI workflow's lint-summary job to pass before merge. The lint-summary aggregates ESLint + Hadolint + ShellCheck and is the single check name to add to "Required status checks":

- `https://github.com/<your-org>/<repo>/settings/branches`
- Add rule for `main`
- "Require status checks to pass before merging" → "Lint summary"
- Optionally also require: "Framework smoke (ubuntu-latest)" + "Wiki e2e (ubuntu-latest)"

### Tag-driven releases

The release-container workflow triggers on `push: tags: ["v*"]`. The canonical release flow runs through `node scripts/release.js`, which orchestrates everything from version bump through publish:

```bash
# One-shot — patch bump, runs every gate in sequence, opens PR, watches CI, tags, watches publish
node scripts/release.js all

# Or individual phases:
node scripts/release.js prepare    # bump + regen CHANGELOG + api-snapshot + static gates
node scripts/release.js regen      # re-regen artifacts after release-notes edits (mid-flow)
node scripts/release.js smoke      # SMOKE_PARALLEL=64 + (auto) wiki e2e if examples/wiki touched
node scripts/release.js commit     # release/v<next> branch + signed commit (resumable)
node scripts/release.js push       # gitleaks + push + open PR
node scripts/release.js watch      # gh pr checks --watch + flag unresolved Codex threads
node scripts/release.js merge      # squash-merge after re-checking threads
node scripts/release.js tag        # signed annotated tag + push tag
node scripts/release.js publish    # watch npm-publish + release-container workflows

# Minor bump (rolls up prior minor's release-notes automatically):
node scripts/release.js all --minor

# Read-only state report:
node scripts/release.js status
```

Pre-requisites the script enforces:
- Operator wrote `release-notes/v<next>.json` (the only manual content step). The script refuses with a stub template if missing.
- SSH signing config in place (the script refuses if `git log -1 --pretty='%G?'` doesn't report `G`).

After the tag push, the release-container workflow runs all 5 jobs; on success, image is at `ghcr.io/<your-org>/blamejs-wiki:<tag>` (signed, scanned, smoke-tested). Operators pin the new tag in `docker-compose.prod.yml`'s `image:` line on the deploy host, then `docker compose pull && docker compose up -d`.

Hot-fixes / dry-runs use the `workflow_dispatch` trigger with the `dry_run` input — run the build + scan path without pushing or signing, useful for verifying a Dockerfile change before tagging:

```bash
gh workflow run release-container.yml --repo <your-org>/<repo> --ref <branch> -F dry_run=true
```
