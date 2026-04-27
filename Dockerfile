# check=skip=SecretsUsedInArgOrEnv
# The CA_KEY_SEALED / TLS_KEY_SEALED ENV values below are a single-word
# mode string ("auto" | "required" | "disabled"), not a secret. The buildx
# Dockerfile linter flags any ENV whose name contains "_KEY" or "_SEALED"
# on a heuristic; this directive suppresses that false positive. Real
# secrets (vault passphrase, SMTP credentials, OAuth secrets) continue to
# be delivered at runtime via env / Docker secrets / mounted files — never
# baked into the image.
FROM cgr.dev/chainguard/node:latest-dev
# Chainguard wolfi-based Node image — glibc-dynamic (not musl), continuously
# rebuilt when upstream CVE fixes land. CVE count at any given digest is
# typically near-zero; chosen over debian-slim to eliminate the unfixed
# systemd/ncurses/util-linux/glibc base-image noise previously flagged by
# Trivy (debian:trixie-slim surfaced ~100 findings of which almost none were
# fixable).
#
# Wolfi uses apk-tools (like Alpine) but stays on glibc, so the vendored
# argon2 prebuilds under lib/vendor/argon2/prebuilds/linux-{x64,arm64}
# (glibc-linked) work unmodified — the Alpine musl trap doesn't apply here.
#
# Requires Node 24.8+ for PQC: ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87
# (OpenSSL 3.5). `:latest-dev` tracks the current Node major and includes
# apk-tools + shell needed by docker-entrypoint.sh.

# Chainguard images default to a non-root USER; override for the build so
# we can install packages and create the hermit user. Runtime privilege drop
# happens in docker-entrypoint.sh via setpriv — the entrypoint NEEDS to start
# as root so it can remap hermit's UID/GID to the user's PUID/PGID before
# dropping privs. Hadolint DL3002 ("last USER should not be root") flags this
# because it can't see the runtime privilege drop; the `docker-entrypoint.sh`
# execution ends with `setpriv --reuid=hermit --regid=hermit` so the node
# process never runs as root.
# hadolint ignore=DL3002
USER root

# Build-time args for OCI labels (injected by CI)
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown

# OCI image metadata
LABEL org.opencontainers.image.title="HermitStash" \
      org.opencontainers.image.description="Post-quantum encrypted, self-hosted file upload server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/dotCooCoo/hermitstash" \
      org.opencontainers.image.url="https://hermitstash.com" \
      org.opencontainers.image.documentation="https://github.com/dotCooCoo/hermitstash#readme" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="dotCooCoo"

# Runtime tooling required by docker-entrypoint.sh:
#   - su-exec: drops privileges to hermit and direct-execs node — node
#     becomes PID 1's successor, signals reach it natively. We originally
#     used util-linux's setpriv, but wolfi ships BusyBox which provides
#     its own stripped setpriv applet (no --reuid/--regid/--init-groups),
#     and `apk add util-linux` didn't override the BusyBox PATH priority.
#     su-exec is tiny (~10KB), purpose-built, and standard in wolfi/Alpine
#     images for this exact workflow.
#   - shadow: groupmod / usermod / groupadd / useradd for PUID/PGID remap
#     at container start (Unraid/Synology integration — see entrypoint)
# --no-cache keeps the layer small. Intentionally NOT pinning package
# versions (hadolint DL3018): Chainguard's value proposition is that each
# rebuild of :latest-dev carries the latest patched wolfi packages. Pinning
# defeats the continuous-rebuild CVE posture we switched bases to get.
# hadolint ignore=DL3018
RUN apk add --no-cache shadow su-exec

# Security: non-root user for runtime. PUID/PGID env vars remap UID/GID at
# runtime via groupmod/usermod (installed above); setpriv then drops privs.
RUN groupadd -r hermit && useradd -r -g hermit -s /bin/sh hermit

WORKDIR /app

# Single COPY — .dockerignore excludes data/, uploads/, tests/, node_modules/, etc.
# No separate layer for vendor/public: with zero npm deps there's nothing to `npm ci`
# between copies, and those dirs already travel with the rest of the source.
COPY . .

# Create persistent directories
RUN mkdir -p data uploads public/img/custom && \
    chown -R hermit:hermit /app && \
    chmod +x docker-entrypoint.sh

ENV NODE_ENV=production
ENV HERMITSTASH_TMPDIR=/dev/shm

# v1.9.4+ opt-in PEM at-rest sealing — tristate: auto (default) |
# required | disabled. "auto" = load whichever plain/sealed file exists.
# Operators flip to "required" after sealing via admin UI (v1.9.6+) or
# scripts/ca-key-seal.js / scripts/tls-key-seal.js. Compose-level env
# setting overrides this default.
ENV CA_KEY_SEALED=auto
ENV TLS_KEY_SEALED=auto

# Persistent volumes — mount these in Coolify/Docker
VOLUME ["/app/data", "/app/uploads"]

EXPOSE 3000

# Graceful shutdown — Node.js handles SIGTERM in server.js
STOPSIGNAL SIGTERM

# Health check for orchestrators (Docker, Kubernetes, Coolify).
# Uses node (already in the image as the runtime) so we don't need curl/wget.
# Coolify accepts any healthcheck tool — see docker-compose.coolify.yml for the
# matching compose-level form.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',function(r){process.exit(r.statusCode===200?0:1)}).on('error',function(){process.exit(1)})"

# Start as root, entrypoint fixes volume permissions then drops to hermit
ENTRYPOINT ["./docker-entrypoint.sh"]
