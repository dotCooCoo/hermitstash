FROM node:24-slim
# Requires Node 24.8+ for PQC: ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f (OpenSSL 3.5)

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

# Security: non-root user. setpriv (from util-linux, pre-installed in node:24-slim)
# drops privileges in the entrypoint with direct exec semantics — node becomes the
# PID, signals reach it natively. No apt-get install at all → no DL3008, no version
# drift, no apt cache layer. PUID/PGID env vars remap UID/GID at runtime (see
# docker-entrypoint.sh).
RUN groupadd -r hermit && useradd -r -g hermit -s /bin/sh hermit

WORKDIR /app

# Copy vendored dependencies first (changes less often → better layer cache)
COPY lib/vendor/ lib/vendor/
COPY public/ public/

# Copy application code
COPY . .

# Create persistent directories
RUN mkdir -p data uploads public/img/custom && \
    chown -R hermit:hermit /app && \
    chmod +x docker-entrypoint.sh

ENV NODE_ENV=production
ENV HERMITSTASH_TMPDIR=/dev/shm

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
