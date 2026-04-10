FROM node:24-slim AS base
# Requires Node 24.8+ for PQC: ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f (OpenSSL 3.5)

# Security: non-root user + gosu for entrypoint
RUN groupadd -r hermit && useradd -r -g hermit hermit && \
    apt-get update && apt-get install -y --no-install-recommends gosu && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application — all dependencies vendored, no npm install needed
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

# Health check for orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', r => { let d=''; r.on('data', c => d+=c); r.on('end', () => { try { process.exit(JSON.parse(d).status === 'ok' ? 0 : 1) } catch(e) { process.exit(1) } }) }).on('error', () => process.exit(1))"

# Start as root, entrypoint fixes volume permissions then drops to hermit
ENTRYPOINT ["./docker-entrypoint.sh"]
