# syntax=docker/dockerfile:1.7
#
# Wolfi-based image (Chainguard's distro) for the wiki reference app.
#
# Build context = repo root, not examples/wiki/. The wiki package.json
# declares "@blamejs/core": "file:../..", so the framework source has
# to be reachable from the wiki directory at install time. Compose
# in this directory sets context: ../.. accordingly.
#
# Two stages:
#   - builder uses cgr.dev/chainguard/node:latest-dev (shell + npm
#     for the install-links resolve)
#   - runtime uses cgr.dev/chainguard/node:latest (no shell, drops
#     to the nonroot user, minimal attack surface)
#
# The vendored Argon2id native module ships glibc prebuilds; Wolfi is
# glibc-based so the existing prebuilds load without rebuild.

# Chainguard's :latest-dev runs as the `node` user by default with HOME
# at /home/node. Anchor the build there with matching --chown=node:node
# so npm install can create node_modules without any USER root step.
# The :latest runtime image runs as `nonroot` (different user, lower
# privilege); --chown=nonroot:nonroot on the COPY --from=deps rewrites
# ownership at copy time into the runtime image.
# Base images are digest-pinned in source (tag@sha256) for reproducible local
# builds and supply-chain provenance. Dependabot's docker updater bumps these
# digests weekly so they track Chainguard's continuous CVE rebuilds instead of
# freezing — the historical objection to a committed pin (it goes stale and the
# Trivy CRITICAL/HIGH gate rejects the build) does not apply here, because the
# committed digest never reaches that gate: release-container.yml resolves the
# rolling tag to a FRESH digest at build time and passes it via the BASE_DEPS /
# BASE_RUNTIME build-args below, overriding these defaults, so the scanned image
# always carries current patches and scan == publish. A local `docker build`
# with no build-args uses the pinned (Dependabot-current) digest; the
# human-readable tag is retained alongside the digest for readability and as the
# rolling source the release workflow resolves.
ARG BASE_DEPS=cgr.dev/chainguard/node:latest-dev@sha256:b165c3da2bc85bb4d7a4749854a087996bf51f540bc0655689ab5c43409bb741
ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@sha256:05d2ed6a0b3e6d3b9ca1d7f0b76e88dd06b91fa95c4f1e849f99bba7bd5a21b8

FROM ${BASE_DEPS} AS deps
WORKDIR /home/node
COPY --chown=node:node package.json index.js NOTICE LICENSE README.md ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node lib ./lib
COPY --chown=node:node examples/wiki ./examples/wiki
WORKDIR /home/node/examples/wiki
# Install deps + pre-build the public/dist bundle here in the build
# stage so the runtime image ships with bundles already on disk. The
# runtime container never needs to write to public/dist (which under
# --cap-drop ALL + nonroot-only invocations would EACCES even on a
# correctly-chowned dir). Bundle output is operator-deterministic
# given a pinned source tree, so building at image-build time is a
# reproducibility win as well.
RUN rm -rf node_modules data data-e2e public/dist \
 && npm ci --omit=dev --install-links \
 && node -e "var b = require('@blamejs/core'); var path = require('node:path'); (async function () { var bundler = b.bundler.create({ entries: { wiki: path.join(process.cwd(), 'src', 'wiki.js'), editor: path.join(process.cwd(), 'src', 'editor.js') }, outdir: path.join(process.cwd(), 'public', 'dist'), manifest: 'manifest.json', hashLen: 16 }); await bundler.build(); console.log('[Dockerfile] bundle pre-built into public/dist'); })().catch(function (e) { console.error('bundle build failed:', e.stack || e); process.exit(1); });" \
 && mkdir -p /home/node/data-skeleton

# See the deps stage above: rolling base, resolved to a digest at build time by
# release-container.yml (build-arg) so the scanned and published images match.
FROM ${BASE_RUNTIME} AS runtime
# Explicit USER directive — Chainguard's :latest image already runs as
# `nonroot` (UID 65532) by default, but Trivy's static Dockerfile
# checker (DS-0002) flags any image without an explicit USER line
# regardless of the base image's default. Restate it here.
USER 65532:65532
# Non-secret defaults baked into the image. Secrets (passphrases,
# webhook secrets, admin password) are NEVER ENV-baked — they're
# injected at runtime via env / docker secrets / mounted files.
#
# Available environment variables (operator-set at runtime):
#
#   NODE_ENV               production | development                 (default: production)
#   WIKI_DATA_DIR          on-disk path for vault.key + sqlite +
#                          audit chain                              (default: /data)
#   WIKI_PORT              listen port                              (default: 3008)
#
#   WIKI_ADMIN_EMAIL       seeded admin login email                 (default: admin@blamejs.com)
#   WIKI_ADMIN_PASSWORD    seeded admin password                    (REQUIRED — generated
#                                                                    if absent, printed to
#                                                                    stdout on first boot;
#                                                                    set explicitly in prod)
#   WIKI_WEBHOOK_URL       outbound page-edit webhook target        (optional)
#   WIKI_WEBHOOK_SECRET    HMAC secret for the webhook              (required if URL set)
#
#   BLAMEJS_VAULT_PASSPHRASE
#                          when set, the wiki auto-flips to vault:
#                          wrapped + DB encrypted-at-rest at boot —
#                          Argon2id-stretched into the wrapping key
#                          for vault.key.sealed. Without it the wiki
#                          boots in plaintext mode for dev ergonomics.
#
#   BLAMEJS_AUDIT_SIGNING_PASSPHRASE
#                          when set, the audit-chain signing key is
#                          sealed at boot (audit-sign.key.sealed on
#                          disk) — Argon2id-stretched. Read at boot.
#                          Different from BLAMEJS_AUDIT_PASSPHRASE.
#
#   BLAMEJS_AUDIT_PASSPHRASE
#                          used by `blamejs audit archive/export/
#                          verify/purge` CLI commands invoked
#                          inside the container; not read at boot
#
#   WIKI_VAULT_MODE / WIKI_DB_AT_REST / WIKI_AUDIT_SIGNING_MODE
#                          explicit overrides for the auto-detect
#                          above ("wrapped" / "encrypted" / etc.)
#
#   BLAMEJS_DEPRECATIONS   "verbose" | "throw" | "silent"           (default: warn)
#                          framework deprecation reporting mode
#
#   LOG_LEVEL              "debug" | "info" | "warn" | "error"      (default: info)
#                          structured-log filter level
ENV NODE_ENV=production \
    WIKI_DATA_DIR=/data \
    WIKI_PORT=3008
WORKDIR /app
COPY --from=deps --chown=65532:65532 /home/node/package.json /home/node/index.js /home/node/NOTICE /home/node/LICENSE /home/node/README.md ./
COPY --from=deps --chown=65532:65532 /home/node/bin ./bin
COPY --from=deps --chown=65532:65532 /home/node/lib ./lib
COPY --from=deps --chown=65532:65532 /home/node/examples/wiki ./examples/wiki
# Pre-create WIKI_DATA_DIR (default /data) with nonroot ownership so
# the runtime user can populate it with vault.key + sqlite + audit
# chain on first boot. The framework's createApp does
# fs.mkdirSync(dataDir, {recursive:true}); without this, that mkdir
# fails because nonroot (UID 65532) doesn't have write permission on
# /. Production deployments bind-mount a named volume on top of
# /data — see examples/wiki/docker-compose.prod.yml. This empty
# pre-created dir is the fallback for a `docker run` with no volume
# (the post-publish smoke-test job's invocation).
COPY --from=deps --chown=65532:65532 /home/node/data-skeleton /data
WORKDIR /app/examples/wiki
EXPOSE 3008
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3008/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
# The Chainguard node image has ENTRYPOINT ["/usr/bin/node"], so CMD
# is just the script path the operator wants Node to run.
CMD ["server.js"]
