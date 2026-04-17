<p align="center"><img src="https://raw.githubusercontent.com/dotCooCoo/hermitstash/main/public/img/logos/purple.svg" width="120" alt="HermitStash"></p>
<h1 align="center">HermitStash</h1>
<p align="center"><strong>Stash it quietly. Share it instantly.</strong><br>Post-quantum encrypted, self-hosted file upload server.</p>
<p align="center"><a href="https://github.com/dotCooCoo/hermitstash-sync">HermitStash Sync</a> — companion desktop sync client</p>

---

> **A note before you dive in.**
>
> HermitStash is my first public repo. It started as a weekend project to solve my own problem — sharing files with clients without trusting third-party cloud storage — and grew from there. I use it daily and it works for me, but I'm sharing it publicly knowing that "works for me" and "is fit for your use case" are different things.
>
> A few things I want to be honest about:
>
> - **I'm not a cryptographer.** I've used well-reviewed primitives and tried to assemble them carefully, but I haven't had this audited, and there are almost certainly things I don't know that I don't know.
> - **This is a personal project.** I maintain it solo, in my spare time, and I can't promise fast response times or backwards compatibility.
> - **I'm not currently accepting code contributions** (more on that below), but bug reports, security findings, and feedback are genuinely welcome — they're how I learn.
>
> If HermitStash is useful to you, that's wonderful. If you're considering it for anything where the consequences of a security flaw matter, please weigh that against the fact that no professional has reviewed this code.
>
> — .CooCoo ([@dotCooCoo](https://github.com/dotCooCoo))

> **Status:** Personal project · Not audited · API may change · Use at your own risk

---

## Quick Start

```bash
git clone https://github.com/dotCooCoo/hermitstash.git
cd hermitstash
node server.js
```

No config files. No build step. No `npm install` — all dependencies are vendored in the repo with zero npm runtime packages. First run generates the vault keypair and creates default accounts. Configure everything from the admin panel.

**Default admin:** `admin@hermitstash.com` / `admin` — change immediately via the setup wizard. The wizard walks you through changing the admin email and password, setting your site name, configuring the passkey relying party (rpOrigin/rpId), and generating a session secret. Once completed, password reset is available via the login page.

## Why HermitStash?

- **Post-quantum encryption** — your files are protected against both today's computers and tomorrow's quantum computers
- **Zero plaintext** — every database field, every file, every audit log entry is encrypted or hashed before touching disk
- **Self-hosted** — your server, your keys, your data. No third-party cloud
- **Zero dependencies at runtime** — `node server.js` is the entire setup. All crypto libraries are vendored and committed
- **One-command deploy** — Docker or bare metal, no build step, no config files needed

## Crypto Suite

All cryptographic operations use NIST-standardized post-quantum algorithms:

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| **KEM** | ML-KEM-1024 + P-384 ECDH hybrid | FIPS 203 + NIST P-384 | Key encapsulation (PQC + classical) |
| **Symmetric** | XChaCha20-Poly1305 | RFC 8439 extended | Data encryption (192-bit nonce, constant-time) |
| **KDF** | SHAKE256 | FIPS 202 (XOF) | Key derivation from KEM shared secrets |
| **Hash** | SHA3-512 | FIPS 202 | Integrity, email/IP hashing, checksums |
| **HMAC** | HMAC-SHA3-512 | FIPS 202 | Webhook signing, token verification |
| **Password** | Argon2id | RFC 9106 | Memory-hard password hashing |
| **Signatures** | ML-DSA-87 / SLH-DSA-SHAKE-256f | FIPS 204 / 205 | Digital signatures (auto-detected from key) |
| **Random** | SHA3-512(entropy) | FIPS 202 | All random generation via centralized KDF |

### Envelope versioning

Every encrypted blob starts with a 4-byte header encoding the algorithms used:

```
byte 0: 0xE1  (envelope magic)
byte 1: KEM   (0x02 ML-KEM-1024 / 0x03 ML-KEM-1024+P-384)
byte 2: Cipher(0x02 XChaCha20-Poly1305)
byte 3: KDF   (0x02 SHAKE256)
```

Any component can be swapped independently without re-encrypting existing data. When HQC or future algorithms are standardized, assign a new ID and existing blobs remain readable.

API payload encryption (ECIES key exchange) has its own protocol version byte — the `_ek` field is prefixed with `0x01` identifying ML-KEM-1024 + P-384 + HKDF-SHA3-512 + XChaCha20-Poly1305. Future KEMs get a new version byte; clients reject unknown versions.

### Hybrid KEM

```
ML-KEM-1024 encapsulate  -->  shared_secret_1 (32 bytes)
P-384 ephemeral ECDH     -->  shared_secret_2 (48 bytes)
                               |
                     SHAKE256(ss1 || ss2, 32)
                               |
                     XChaCha20-Poly1305(key, nonce=24)  -->  ciphertext
```

Protects against both quantum (ML-KEM) and classical (P-384) attacks. If either is broken, the other still holds.

## Encryption Architecture

Zero plaintext anywhere. Every piece of data is encrypted or hashed before touching disk:

```
ML-KEM-1024 + P-384 (vault.key)
  |
  +-- vault.seal() = hybrid KEM --> SHAKE256 KDF --> XChaCha20-Poly1305
  |
  +-- Wraps per-file XChaCha20-Poly1305 keys (file encryption at rest)
  +-- Wraps per-session XChaCha20-Poly1305 keys (API payload encryption)
  +-- Hybrid ECIES key exchange for API clients (ML-KEM-1024 + ECDH P-384 + HKDF-SHA3-512)
  +-- Wraps database file XChaCha20-Poly1305 key (DB encryption at rest)
  +-- Directly seals ALL database fields (not just PII)
  +-- Directly seals session cookie values
```

### Automatic field-level encryption

Routes never touch `vault.seal()` directly. A centralized **field-crypto middleware** (`lib/field-crypto.js`) intercepts all database operations:

```
Routes pass PLAINTEXT
       |
  Collection.insert() / update() / find()
       |
  field-crypto.js (automatic middleware)
       |
  +-- sealDoc() on write ---> vault.seal() per field ---> DB stores ciphertext
  +-- unsealDoc() on read ---> vault.unseal() per field ---> routes get plaintext
  +-- derived hashes --------> emailHash, shareIdHash auto-computed
  +-- _translateQuery() -----> { email: "x" } becomes { emailHash: sha3("hs-email:x") }
```

Every field in every table is classified as `seal` (encrypted), `hash` (one-way lookup), `derived` (auto-computed from another field), or `raw` (IDs, timestamps, counters). The schema is defined once in `FIELD_SCHEMA` and enforced on every database operation.

### What gets encrypted and how

| Data | Encryption | Key Protection |
|------|-----------|----------------|
| **File contents** | XChaCha20-Poly1305 (random key per file) | Key sealed with hybrid ML-KEM-1024 + P-384 vault |
| **Vault files** | ML-KEM-1024 + SHAKE256 + XChaCha20-Poly1305 (client-side) | Key derived from passkey (never leaves browser) |
| **API request/response bodies** | XChaCha20-Poly1305 (random key per session) | Key sealed with hybrid vault |
| **Database file on disk** | XChaCha20-Poly1305 (random key) | Key sealed with hybrid vault |
| **Session cookies** | Hybrid KEM + XChaCha20-Poly1305 | Direct vault.seal() per cookie |
| **All user fields** (email, name, avatar, googleId) | Hybrid KEM + XChaCha20-Poly1305 | Auto vault.seal() per field |
| **All file metadata** (names, paths, MIME, storage) | Hybrid KEM + XChaCha20-Poly1305 | Auto vault.seal() per field |
| **Audit log fields** (action, emails, details) | Hybrid KEM + XChaCha20-Poly1305 | Auto vault.seal() per field |
| **Audit log IPs** | SHA3-512 hash then vault-sealed | One-way hashed, then auto-sealed |
| **Passwords** | Argon2id | One-way hash (no key needed) |
| **Email/IP lookups** | SHA3-512 | One-way hash for indexed queries |

### Anti-attack protections

| Attack | Protection |
|--------|-----------|
| Quantum computer key recovery | Hybrid ML-KEM-1024 + P-384 ECDH (dual protection) |
| Harvest-now-decrypt-later | ML-KEM-1024 post-quantum KEM + envelope versioning for algorithm agility |
| Classical-only TLS downgrade | ClientHello PQC gate rejects connections without hybrid key exchange groups |
| Brute-force passwords | Argon2id (64MB memory, 3 iterations) |
| Brute-force login | Rate limiting (5 attempts / 15 min per IP) |
| Brute-force share IDs | 256-bit SHA3-derived IDs (2^256 search space) |
| Session hijacking | Hybrid KEM encrypted cookies, per-session keys |
| API replay attacks | Timestamp validation (30-second window) |
| API payload tampering | XChaCha20-Poly1305 authentication (Poly1305 MAC) |
| Database file theft | XChaCha20-Poly1305 encrypted at rest, key requires vault.key |
| PII exposure from DB dump | Every field vault-sealed, IPs one-way hashed |
| Nonce collision | XChaCha20 192-bit nonce eliminates birthday-bound risk |
| AES-NI side channels | XChaCha20 is constant-time in software, no hardware dependency |
| Brute-force bundle passwords | Exponential backoff lockout after 5 failed attempts |
| Email enumeration on bundles | Identical response regardless of whether email is in allow list |
| Brute-force access codes | 5 attempt limit per code, rate limiting, 10-minute expiry |
| CSRF on API endpoints | Per-session XChaCha20-Poly1305 key binds JSON requests to session; form POSTs validated with constant-time CSRF token |
| Logout CSRF | Logout is POST-only with CSRF token validation — cross-site `<img>` or `<a>` tags cannot force logout |
| WebSocket credential leakage | API keys accepted only via Authorization header — query string tokens rejected to prevent proxy/log/Referer leaks |
| Session key interception | Hybrid ECIES key exchange — session key encrypted via ML-KEM-1024 + ECDH P-384, never plaintext in HTTP |
| CSV formula injection | Export values sanitized to prevent spreadsheet code execution |
| DNS rebinding via webhooks | Pre-validated IP pinned to outbound connection |
| SSRF via webhooks | Blocks localhost, RFC 1918, RFC 6598 CGNAT, link-local, IPv6 private ranges |
| Disguised file uploads | Magic byte validation rejects files whose content doesn't match extension |
| Malicious filenames | Backend sanitization strips control chars, path traversal, dot attacks, HTML injection |
| ZIP path traversal (Zip Slip) | Entry names sanitized to remove `..` segments; paths normalized on both upload and archive |
| Anonymous storage abuse | Per-IP upload quota with 24-hour rolling window |
| Stored XSS via uploads | User-controlled names auto-escaped in templates; raw output reserved for admin-set values only |
| Weak bundle/stash passwords | Minimum 4-character requirement enforced server-side |
| Automated scanners and bots | Request fingerprinting (accept-language, sec-fetch-dest, sec-fetch-mode) blocks non-browser clients on public routes — survives PQC TLS adoption |
| NPM supply chain | All dependencies vendored as committed bundles — zero npm runtime packages |
| Admin settings injection | Type-safe settings schema (lib/settings-schema.js) sanitizes on save (strip control chars, trim, type-specific normalization) and validates (format, range, enum) — bad data rejected at the gate with clear error messages |
| Stale config after admin change | Config reset registry (config.onReset) invalidates cached clients (S3, etc.) when dependent settings change at runtime |

Built on Node.js 24.8+ (LTS) with ML-KEM-1024, ML-DSA-87, and SLH-DSA-SHAKE-256f via OpenSSL 3.5, XChaCha20-Poly1305 and SHAKE256 via vendored @noble/ciphers and @noble/hashes, Argon2id via vendored native prebuilds, WebAuthn via vendored @simplewebauthn/server, and built-in SQLite via `node:sqlite`. Zero npm runtime dependencies.

## Features

**Authentication**
- Argon2id local auth, Google OAuth, WebAuthn passkeys -- all simultaneous
- TOTP 2FA with single-use backup codes
- Email verification with SHA3-hashed tokens
- Hybrid KEM encrypted session cookies
- Per-session XChaCha20-Poly1305 encrypted API payloads with anti-replay and anti-tamper
- Hybrid ECIES key exchange for API clients -- ML-KEM-1024 + ECDH P-384 + HKDF-SHA3-512 + XChaCha20-Poly1305 (no plaintext keys in responses)
- Rate limiting on login (5/15min), registration (10/15min), 2FA verify (5/5min), passkey login (10/min)
- Account lockout after 10 consecutive failed password attempts (30-minute cooldown)
- Password reset flow with single-use, 1-hour-expiry tokens and anti-enumeration (always returns success)
- User invitation system -- admin invites by email with role assignment, 48-hour expiry
- Configurable session idle timeout (default 30 minutes, server-side enforcement)
- OAuth CSRF state validation on Google callback
- Password change automatically revokes all other sessions

**File Management**
- Public folder drops -- drag entire trees, no login required
- Per-file XChaCha20-Poly1305 encryption, keys sealed with hybrid ML-KEM-1024 + P-384
- Chunked uploads for large files (>10MB auto-split, server reassembly)
- Pause/resume/cancel uploads, per-file progress bars
- Password-protected share links with exponential backoff lockout (2^n × 30s after 5 failed attempts)
- Email-gated access -- restrict bundles to specific recipient emails, verified by one-time code (anti-enumeration, rate limited, SHA3-hashed codes)
- Dual protection mode -- require both email verification and password for maximum security
- Custom expiry per bundle (1d, 7d, 30d, 90d, never)
- Bundle messages, multiple recipient emails
- Bundle naming -- name bundles during upload, rename inline from dashboard
- Inline rename for files and bundles with backend-enforced sanitization (dot attack protection, path traversal prevention, extension preservation)
- Magic byte content validation -- uploaded files verified against claimed extension (15 format signatures)
- File preview with SVG sanitization, HTML/JS forced download
- Shareable links -- browse folders or download as ZIP
- Subfolder ZIP download -- download individual subdirectories from a bundle
- Safe Content-Disposition headers with RFC 5987 encoding for non-ASCII filenames

**Zero-Knowledge Vault**
- Client-side ML-KEM-1024 + SHAKE256 KDF + XChaCha20-Poly1305 encryption in the browser
- Passkey-gated access (Touch ID, Face ID, YubiKey, FIDO2)
- PRF mode for true zero-knowledge (no seed touches the server)
- Stealth mode hides vault operations from audit logs
- Self-access links for direct vault file download with passkey auth
- Vault key rotation with atomic re-encryption of all files
- Batch upload and batch delete with client-generated batch IDs
- Folder structure preserved in vault uploads and batch ZIP downloads
- Inline rename for vault batches and individual vault files
- Force-reset recovery mode for vault lockout (deletes all vault files, clears vault state)
- ML-KEM-1024 only (ML-KEM-768 fully removed — server rejects 768 keys at startup)

**Customer Stash — Branded Upload Portals**
- Create custom-branded upload pages at `/stash/:slug` for clients and partners
- Per-page branding -- custom title, instructions, accent color, and logo
- Per-page upload constraints -- max file size, max files, default expiry, allowed extensions
- Password-protected stash pages with Argon2 hashing and rate-limited unlock
- Email/domain-gated stash access -- restrict by specific emails or entire domains (@acme.com), verified by one-time code
- Dual protection mode -- require both email verification and password on stash pages
- Simplified upload form -- message and files only (no name/email fields)
- Bundle naming during stash upload
- Dynamic slug validation with automatic reserved-word detection from registered routes
- Upload stats tracked per stash page (bundle count, total bytes)
- Custom logo upload per stash page with magic-byte validation
- Dedicated admin page with bundle drill-down -- view bundles, browse files, inline rename, delete, purge all
- Admin management -- create, edit, toggle, copy link, delete stash pages

**Teams**
- Create teams, add/remove members with role-based access
- Team-scoped file visibility -- cross-team isolation enforced
- Team admin and member roles

**Profile**
- Self-service email change with password re-authentication
- Self-service account deletion (files reassigned, sessions revoked, last admin protected)

**Admin Dashboard**
- Stats with computed totals (size, downloads), activity feed
- Row-based bundle lists with file drill-down (My Stash + Personal Vault)
- Paginated file/bundle browser with search
- User management -- create, suspend, delete, role toggle
- Audit log -- searchable, filterable, date range
- Settings panel -- 9 tabs (Branding, General, Auth, Uploads, Storage, Theme, Email, Environment, Backup)
- API keys with scoped permissions (upload, read, admin, webhook) validated against canonical enum
- Webhooks with HMAC-SHA3-512 signed payloads, per-hook delivery log, enable/disable toggle
- IP blocklist
- Database backup (serves encrypted-at-rest copy), CSV exports (with formula injection protection)
- Automated off-site backup to S3-compatible storage (AWS, R2, MinIO, B2, DO Spaces) with passphrase-encrypted vault key, incremental file manifests, configurable retention, and manual trigger from admin UI
- Scheduled tasks -- file expiry, audit retention, stale upload cleanup, token cleanup, invite cleanup, daily SQLite vacuum, automated backup
- Danger Zone -- factory reset, purge all sessions, purge all users, purge all files (typed confirmation required)
- Custom logo upload with magic-byte validation and SVG sanitization
- Reverse proxy auto-detection with config snippet generator (nginx, Caddy, Apache)
- Per-user storage quotas (separate from global quota) and per-IP public upload quota (24h rolling window)
- Configurable upload concurrency, retry count, timeout, and file extension allowlist
- Admin email list for auto-promoting OAuth users to admin role
- Maintenance mode -- blocks non-admin access with 503 page
- Announcement banner -- site-wide text displayed on all pages

**Email**
- SMTP or Resend API backend (switchable from admin)
- Dual-mode failover -- SMTP-primary/Resend-fallback or Resend-primary/SMTP-fallback
- Resend quota enforcement (daily/monthly limits per plan tier)
- Email template customization -- subject, header, footer with named placeholders ({siteName}, {uploaderName}, {fileCount}, {totalSize})
- Upload confirmations, admin notifications, verification emails
- All email send/fail/quota events audit-logged

**Sync and API**
- Mutable sync bundles -- `bundleType: "sync"` creates persistent, mutable bundles that accept file additions, replacements, and deletions after creation
- File replace -- uploading to a sync bundle with an existing `relativePath` overwrites the file with a new encryption key (old key and blob fully removed)
- File rename/move -- `POST /sync/rename` updates relativePath without re-uploading the file (metadata-only, emits `file_renamed` WebSocket event). Sync client detects local renames by checksum matching within the debounce window
- File delete -- individual files can be removed from sync bundles with tombstone-based soft delete (30-day cleanup)
- Per-file change tracking -- `seq` monotonic counter and `updatedAt` timestamp on files and bundles for sync change feeds
- JSON content negotiation on bundle view -- `Accept: application/json` returns file list with checksums and metadata
- Structured audit log events for file mutations (JSON details with action, bundleId, checksum, size)
- Shared access control middleware (`require-access.js`) -- centralized lock checks for bundles and stash
- JSON-aware auth -- API/sync clients receive 401 JSON, browsers get login redirect
- WebSocket sync channel -- `GET /sync/ws` with auth during upgrade handshake, scoped to single bundle
- Real-time file change events over WebSocket (file_added, file_replaced, file_removed, heartbeat)
- Catch-up on reconnect via seq cursor (`?since=N` on WebSocket upgrade)
- PQC TLS enforcement -- ClientHello inspection rejects connections without PQC hybrid key exchange groups
- PQC gate architecture -- TCP proxy inspects `supported_groups` extension before TLS handshake completes
- Localhost bypass for Docker health probes (127.0.0.1/::1 skip PQC check)
- `PQC_ENFORCE=false` disables gate for transition periods (PQC preferred but not required)
- PQC TLS -- conditional HTTPS with SecP384r1MLKEM1024 + X25519MLKEM768 + SecP256r1MLKEM768 hybrid key exchange (TLS 1.3 only, Level 5 preferred)
- Certificate auto-reload on Let's Encrypt renewal (hourly file poll)
- PQC outbound HTTPS agent -- all S3, SMTP, Resend, webhook, OAuth calls use PQC hybrid TLS groups
- `PQC_OUTBOUND_ENFORCE=false` allows classical fallback for outbound connections
- mTLS for sync clients -- server acts as its own Certificate Authority (ECDSA P-384)
- Client certificate generation on sync token creation with one-click PEM bundle download
- Certificate revocation table with SHA3-512 hashed fingerprint lookups
- WebSocket upgrade validates mTLS cert + API key (dual auth, neither alone sufficient)
- `MTLS_REQUIRED=true` to enforce client certificates on all sync connections
- New `sync` API key scope for WebSocket connections and sync bundle operations
- Resource-scoped API keys -- `boundStashId` and `boundBundleId` columns restrict keys to specific resources
- Stash-scoped sync tokens -- admin generates tokens that grant sync access to a single stash only
- One-time enrollment codes -- admin generates a short code (e.g. `HSTASH-A4K9-XMWP-7RB2`), client redeems it to get API key + mTLS certs automatically (no file transfer needed, 1-hour expiry)
- Stash sync mode -- persistent mutable bundle per stash for desktop sync clients
- Admin UI: sync toggle per stash, one-click sync token generation with copy button
- Desktop sync client: [hermitstash-sync](https://github.com/dotCooCoo/hermitstash-sync) — watches a local folder and syncs via WebSocket + PQC TLS

**Security Hardening**
- Security headers on all responses (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP)
- HSTS with preload auto-enabled when rpOrigin uses HTTPS
- Content Security Policy with no external domains -- fonts vendored locally, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`
- 256-bit SHA3-derived share IDs (no brute-force, no collisions)
- CSRF protection: JSON requests bound by per-session encryption key; form POSTs validated with constant-time CSRF token; non-JSON/non-exempt POSTs rejected
- Logout is POST-only with CSRF token validation (no GET logout CSRF)
- Bot guard middleware -- request fingerprinting (accept-language, sec-fetch-dest, sec-fetch-mode) blocks automated scanners on public routes without relying on user-agent strings
- WebSocket API keys accepted only via Authorization header -- query string tokens rejected to prevent proxy/log/Referer leaks
- CSV formula injection protection on all exports
- CORS configurable via admin (wildcard disallowed with credentials)
- Health endpoint CORS configurable from admin for PQC gateway status checks
- Canonical origin policy -- all URLs generated from rpOrigin, never from Host header
- Webhook DNS pinning -- resolved IP reused for outbound connection, preventing TOCTOU rebinding
- Input length limits on all free-text fields
- Pagination capped at 200 results
- X-Forwarded-For only trusted from configured proxies
- Safe redirects (relative paths only)
- SSRF protection covers all RFC 1918, RFC 6598 CGNAT, link-local, metadata, and IPv6 ranges
- All crypto and font dependencies vendored from npm -- zero external CDN requests, zero runtime packages
- Restrictive CSP on user-uploaded logo directory (defense-in-depth against SVG XSS)

**Storage**
- Local disk, NAS mount, or any S3-compatible bucket (MinIO, Cloudflare R2, DigitalOcean Spaces, Backblaze B2)
- S3 direct downloads with pre-signed URLs (configurable expiry, AWS Signature V4)
- Per-file XChaCha20-Poly1305 encryption at rest, keys sealed with hybrid vault

**SEO and Legal**
- Open Graph and Twitter card meta tags with dynamic site name and origin
- Canonical URL tag derived from rpOrigin
- robots.txt blocks admin, dashboard, vault, and auth pages from search engines
- Dynamic sitemap.xml (`GET /sitemap.xml`) with public pages
- noindex/nofollow meta tag on all authenticated pages
- Configurable Privacy Policy, Terms of Service, and Cookie Policy pages
- Default legal page templates with sensible content for self-hosted deployments
- Footer links to all legal pages
- Configurable analytics script injection -- paste any provider's `<script>` tag (Plausible, Umami, Matomo, Fathom, PostHog, Google Analytics)
- Analytics injected on public pages only (admin/dashboard excluded)
- API encryption scoped to same-origin -- external analytics and third-party fetches pass through unmodified
- Auto-detected CSP domains from analytics script with manual override

**Accessibility**
- Skip-to-content link for keyboard navigation
- ARIA labels on interactive controls (theme toggle, icon buttons)
- Alt text on all logo and avatar images
- Semantic HTML with `<main>` landmark on all pages

**Zero Configuration**
- No `.env` file -- settings stored in encrypted database
- No build step -- vanilla Node.js
- `node server.js` is the entire setup -- no npm install needed
- `process.env` overrides available for Docker/containers
- Health check endpoint (`GET /health`) for load balancers, container probes, and PQC gateway status checks (CORS configurable)
- Zero external CDN dependencies -- fonts vendored locally, no requests to Google, Cloudflare, or any third-party on page load
- PWA web app manifest with dynamic site name and theme colors
- Automatic database schema migrations on startup
- Startup invariant checks -- validates vault key, warns on default credentials/secrets, checks directory permissions

## Docker Deployment

### Quick start

```bash
docker compose up -d
```

Uses `node:24-slim` (OpenSSL 3.5+ for PQC support). No config files needed — all dependencies vendored, no `npm install`. Starts with defaults and generates the vault keypair on first run. Configure everything from the admin panel at `/admin` once running.

### Image details

| | |
|---|---|
| **Base image** | `node:24-slim` (Debian Bookworm) |
| **Node.js** | 24.8+ (required for ML-KEM-1024, ML-DSA-87, SLH-DSA via OpenSSL 3.5) |
| **User** | Runs as `hermit` (non-root) via `gosu` — entrypoint fixes volume permissions then drops privileges |
| **Tmpfs** | `HERMITSTASH_TMPDIR=/dev/shm` — plaintext DB held in memory, never on disk. Set `shm_size: 256m` in compose. |
| **Volumes** | `/app/data` (encrypted DB, vault keys, TLS certs), `/app/uploads` (files if using local storage) |
| **Port** | 3000 (configurable via `PORT` env var) |
| **Health check** | Built-in: `GET /health` every 30s, 5s timeout, 3 retries, 10s start period |
| **Entrypoint** | `docker-entrypoint.sh` — chowns volumes to `hermit:hermit`, then `exec gosu hermit node server.js` |

### docker-compose.yml

The included `docker-compose.yml` provides a production-ready starting point:

```yaml
services:
  hermitstash:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data       # encrypted DB, vault keys, TLS certs
      - ./uploads:/app/uploads  # files (local storage only)
    shm_size: 256m              # /dev/shm for plaintext DB in memory
    environment:
      NODE_ENV: production
      HERMITSTASH_TMPDIR: /dev/shm
      PORT: 3000
      TRUST_PROXY: "true"       # set if behind nginx/Cloudflare/Coolify
      RP_ORIGIN: ""             # https://your-domain.com (required for passkeys + HSTS)
    restart: unless-stopped
```

All other settings (auth, email, S3, branding) are best configured via the admin panel at `/admin` so credentials are vault-sealed in the encrypted database. Environment variables override DB settings and are visible in Admin > Settings > Environment tab.

### Coolify / managed Docker hosts

Works out of the box with Coolify, Portainer, CapRover, and similar platforms:

1. Point the platform at the git repo (or Dockerfile)
2. Set the `RP_ORIGIN` env var to your domain's full URL (e.g., `https://app.hermitstash.com`)
3. Mount persistent volumes for `/app/data` and `/app/uploads`
4. Set `shm_size: 256m` (or equivalent in the platform's container config)
5. The built-in health check works with any orchestrator that supports `HEALTHCHECK`

### TLS / HTTPS

The server can terminate TLS itself (for PQC enforcement) or sit behind a reverse proxy:

- **Behind Cloudflare/nginx (recommended):** Set `TRUST_PROXY=true`. The proxy terminates TLS; the server runs HTTP internally. PQC TLS between browser and Cloudflare is handled by Cloudflare's edge. Set `PQC_ENFORCE=false` if the proxy→server leg is plain HTTP.
- **Direct TLS (PQC enforced):** Mount TLS certs at `/app/data/tls/fullchain.pem` and `/app/data/tls/privkey.pem` (or set `TLS_CERT` and `TLS_KEY` env vars). The PQC gate inspects ClientHello and rejects non-PQC connections. The server negotiates `SecP384r1MLKEM1024 > X25519MLKEM768 > SecP256r1MLKEM768` (strongest available hybrid group). Certificate auto-reload on Let's Encrypt renewal (hourly file poll via `fs.watchFile`).

### Persistent data

| Path | Contents | Backup? |
|------|----------|---------|
| `/app/data/hermitstash.db.enc` | Vault-encrypted SQLite database (users, files, settings, audit log) | Yes — automated S3 backup available |
| `/app/data/vault.key` | ML-KEM-1024 + P-384 hybrid keypair (encrypts all DB fields) | **Critical** — lose this and all sealed data is unrecoverable |
| `/app/data/tls/` | TLS certificates (if using direct TLS) | Regenerated by Let's Encrypt |
| `/app/uploads/` | Uploaded files (if using local storage; not needed with S3) | Optional — files are re-uploadable |

### Health check

`GET /health` returns `{ status, uptime, timestamp }` — works with Docker HEALTHCHECK, Kubernetes liveness probes, load balancers, and the [PQC gateway](https://github.com/dotCooCoo/hermitstash-web) status check.

### Reverse proxy

Need nginx, Caddy, or Apache in front? The admin panel (Settings > Uploads) auto-detects your proxy and generates a ready-to-paste config snippet with the correct body size limits.

### S3 storage

Configure S3-compatible storage (AWS, MinIO, Cloudflare R2, DigitalOcean Spaces, Backblaze B2) from Admin > Settings > Storage tab. All credentials are vault-sealed and validated by the settings schema on save. For R2, set the endpoint to `https://<account-id>.r2.cloudflarestorage.com` and region to `auto`.

### Maintenance mode

Toggle from Admin > Settings > Branding. Blocks all non-admin access and serves a 503 page. Admin routes, auth routes, and API keys with admin scope still work during maintenance.

## API Keys

API keys enable programmatic access. Manage them in the admin panel under the **API Keys** collapsible section.

### Creating a key

Generate a key from the admin panel or via the API:

```bash
curl -X POST https://your-domain/admin/apikeys/create \
  -H "Authorization: Bearer <admin-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI Pipeline", "permissions": "upload"}'
```

Response (key shown once, then SHA3-hashed -- never retrievable):
```json
{ "success": true, "key": "hs_a1b2c3d4e5f6...", "prefix": "hs_a1b2" }
```

### Authentication

Include the key as a Bearer token:

```
Authorization: Bearer hs_a1b2c3d4e5f6...
```

### Permission scopes

| Scope | Access |
|-------|--------|
| `upload` | Create bundles, upload files via `/drop` endpoints |
| `read` | List and download files, view bundles |
| `admin` | Full admin access (settings, users, webhooks, keys) |
| `webhook` | Manage webhooks |

### Upload endpoints

Public upload endpoints accept API key authentication. When authenticated, uploads are assigned to the key owner's account.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /drop/init` | Initialize a bundle. Returns `bundleId`, `shareId`, `finalizeToken` |
| `POST /drop/file/:bundleId` | Upload a file (multipart/form-data, field: `file`) |
| `POST /drop/chunk/:bundleId` | Upload a chunk for large files (multipart, fields: `chunk`, `filename`, `chunkIndex`, `totalChunks`) |
| `POST /drop/finalize/:bundleId` | Finalize the bundle. Body: `{ "finalizeToken": "..." }` |

### Example: programmatic upload

```bash
# 1. Init bundle
INIT=$(curl -s -X POST https://your-domain/drop/init \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"password": "", "message": "Automated upload", "expiryDays": 7}')

BUNDLE_ID=$(echo $INIT | jq -r '.bundleId')
TOKEN=$(echo $INIT | jq -r '.finalizeToken')
SHARE_ID=$(echo $INIT | jq -r '.shareId')

# 2. Upload file
curl -X POST "https://your-domain/drop/file/$BUNDLE_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -F "file=@report.pdf"

# 3. Finalize
curl -X POST "https://your-domain/drop/finalize/$BUNDLE_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"finalizeToken\": \"$TOKEN\"}"

echo "Share link: https://your-domain/b/$SHARE_ID"
```

### Admin endpoints

All require `admin` scope:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /admin/apikeys/api` | List all API keys (hashes hidden) |
| `POST /admin/apikeys/create` | Generate new key. Body: `{ "name": "...", "permissions": "upload" }` |
| `POST /admin/apikeys/:id/revoke` | Revoke a key permanently |
| `GET /admin/settings` | Get all settings (sensitive values masked) |
| `POST /admin/settings` | Update settings. Body: `{ "siteName": "...", ... }` |
| `GET /admin/environment` | Runtime info (Node.js, OpenSSL, Docker, env overrides) |

## Webhooks

Webhooks send signed HTTP POST requests when events occur. Manage them in the admin panel under the **Webhooks** collapsible section.

### Creating a webhook

```bash
curl -X POST https://your-domain/admin/webhooks/create \
  -H "Authorization: Bearer <admin-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/hook", "events": "*"}'
```

Response (secret shown once):
```json
{ "success": true, "secret": "a1b2c3d4..." }
```

### Events

| Event | Trigger | Payload |
|-------|---------|---------|
| `bundle_finalized` | Bundle upload completed and finalized | `{ shareId, uploaderName, files, size }` |

Event filter: set to `*` for all events, or a specific event name. Additional events may be added in future releases.

### Payload format

```json
{
  "event": "bundle_finalized",
  "data": {
    "shareId": "a1b2c3d4e5f6...",
    "uploaderName": "Anonymous",
    "files": 3,
    "size": 1048576
  },
  "timestamp": "2026-04-09T12:00:00.000Z"
}
```

### Signature verification

Every webhook request includes an `X-Webhook-Signature` header containing an HMAC-SHA3-512 hex digest of the raw JSON body, signed with the webhook secret:

```
X-Webhook-Signature: a1b2c3d4e5f6...
```

Verify in your handler:

```javascript
const crypto = require("crypto");

function verifyWebhook(body, signature, secret) {
  const expected = crypto
    .createHmac("sha3-512", secret)
    .update(body)
    .digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expected, "hex")
  );
}
```

```python
import hmac, hashlib

def verify_webhook(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha3_512).hexdigest()
    return hmac.compare_digest(signature, expected)
```

### SSRF protection

Webhook URLs are validated against:
- Private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local addresses (169.254.0.0/16, fe80::/10)
- IPv6 private ranges (fc00::/7, ::1)
- Cloud metadata endpoints (169.254.169.254)
- Non-HTTPS schemes are rejected in production

## Critical Files

All in the `data/` directory (gitignored):

| File | What it is | Lose it? |
|------|-----------|----------|
| `data/vault.key` | ML-KEM-1024 + P-384 hybrid keypair | **All encrypted data permanently unrecoverable** |
| `data/db.key.enc` | DB file encryption key (vault-sealed) | Database file unreadable |
| `data/hermitstash.db.enc` | Encrypted database at rest | All settings, users, audit logs lost |

**Back up `data/vault.key`.** This is the root of the entire encryption chain. Every sealed value, every encrypted file, every protected key traces back to this keypair. It cannot be regenerated.

## Vendored Dependencies

All runtime dependencies are committed to the repo -- no `npm install` needed. Managed via `scripts/vendor-update.sh`:

```bash
./scripts/vendor-update.sh --check        # see what's outdated
./scripts/vendor-update.sh --diff @noble/ciphers  # see changelog
./scripts/vendor-update.sh @noble/ciphers 2.2.0   # update a package
```

| Package | Version | Author | Purpose |
|---------|---------|--------|---------|
| [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) | 2.1.1 | [Paul Miller](https://github.com/paulmillr) | XChaCha20-Poly1305 (server + browser) |
| [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) | 2.0.1 | [Paul Miller](https://github.com/paulmillr) | SHAKE256 KDF (browser) |
| [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) | 0.6.0 | [Paul Miller](https://github.com/paulmillr) | ML-KEM-1024 (browser vault + server ECIES) |
| [`@simplewebauthn/server`](https://github.com/MasterKale/SimpleWebAuthn) | 13.3.0 | [Matthew Miller](https://github.com/MasterKale) | WebAuthn/passkey verification |
| [`argon2`](https://github.com/ranisalt/node-argon2) | 0.44.0 | [Ranieri Althoff](https://github.com/ranisalt) | Password hashing (native prebuilds, 8 platforms) |

These libraries are exceptional work. HermitStash wouldn't exist without them. All are MIT licensed.

## Architecture

100+ JS files, 26 HTML templates, 20 database tables. Small files, one job each.

```
server.js             Bootstrap, middleware, scheduled tasks, default accounts
lib/
  crypto.js           PQC crypto: ML-KEM-1024+P-384, XChaCha20, SHAKE256,
                      ML-DSA-87, SLH-DSA-SHAKE-256f, envelope versioning
  vault.js            Hybrid keypair management, seal/unseal, auto key upgrade
  field-crypto.js     FIELD_SCHEMA: auto seal/unseal/hash for all DB fields
  db.js               SQLite + auto field crypto + DB file encryption
  api-crypto.js       API payload XChaCha20-Poly1305 encrypt/decrypt
  session.js          Hybrid KEM encrypted cookies, LRU eviction
  storage.js          Local/S3 + XChaCha20-Poly1305 file encryption + pre-signed URLs
  config.js           Settings from encrypted DB, env fallback, onReset registry
  settings-schema.js  Type-safe settings sanitization + validation (74 settings)
  audit.js            Audit logging with auto-sealed entries
  rate-limit.js       Per-IP rate limiting with proxy validation
  ip-quota.js         Per-IP storage quota for anonymous uploads
  email.js            SMTP + Resend API with dual failover + quota tracking
  router.js           HTTP server, routing, pre-compiled patterns
  multipart.js        Multipart + JSON body parser (shared accumulator)
  template.js         Custom template engine with caching
  sanitize.js         Filename sanitization + HTML escaping
  sanitize-svg.js     SVG sanitizer (strips scripts, events, dangerous tags)
  totp.js             TOTP generation/verification, backup codes
  google-auth.js      Google OAuth2 (OpenID Connect, CSRF state)
  constants.js        Paths, versions, theme, hash prefixes, time constants
  zip.js              ZIP writer with Deflate compression
  expiry.js           File expiry cleanup
  scheduler.js        Task scheduler
  webhook.js          Webhook dispatch queue
  pqc-gate.js         ClientHello PQC group inspection at TCP level
  pqc-agent.js        PQC-only outbound HTTPS agent
  vendor/             Vendored dependencies (argon2, noble-*, simplewebauthn)

app/
  bootstrap/          Startup invariant checks
  data/               Repositories + migration runner
  domain/             Services (auth, uploads, teams, admin, webhooks, email)
  http/               Request validators (upload magic bytes, auth, admin)
  security/           CSRF, CORS, SSRF, scope, origin policies
  domain/uploads/     Shared upload handler, bundle service, chunk service
  jobs/               Background jobs (expiry, audit retention, webhook dispatch)
  shared/             Errors, logger, validation helpers, filename sanitization

scripts/              vendor-update.sh, vendor-font.js, sync-to-public.sh
routes/               18 route files (includes stash.js for Customer Stash)
middleware/           12 files (auth, CORS, CSRF, API encryption, security headers, bot guard)
views/                25 templates
public/               CSS, JS, logos, icons, vendored fonts
```

## Contributing

I want to be straightforward about this: **I'm not currently accepting code contributions**, and I want to explain why rather than just saying no.

HermitStash is a security-focused project maintained by one person. Reviewing external code contributions to a cryptographic system is something I don't feel I can do responsibly right now — I'm still learning, and I'd rather not merge code I can't fully evaluate myself. Accepting PRs would mean either rubber-stamping changes I don't understand (bad) or asking contributors to wait indefinitely while I figure it out (also bad). The honest answer is that I'm not set up for it yet.

That said, there are a lot of ways to help that I genuinely welcome:

- **Bug reports.** If something doesn't work, or works in a way that surprises you, please open an issue. Steps to reproduce help a lot.
- **Security findings.** If you spot a cryptographic issue, a misuse of a primitive, or anything that contradicts a security claim in the README, please report it privately — see [SECURITY.md](SECURITY.md) for how.
- **Feature requests.** Open an issue describing the use case. I can't promise I'll build it, but I want to hear what people would find useful.
- **Documentation feedback.** If something in the README is unclear, wrong, or missing, an issue is great. Documentation issues are some of the most useful kinds of feedback I get.
- **Questions.** If you're trying to use HermitStash and something isn't clear, asking is welcome.

If you've built something on top of HermitStash, or you're running it somewhere interesting, I'd love to hear about that too — feel free to open an issue just to say hi.

This may change in the future. If HermitStash grows to a point where I can responsibly review external code, I'll update this section. Until then: thank you for understanding, and thank you for being interested enough to consider contributing in the first place.

## License

MIT

## A final note

If you've read this far — thank you. Building and sharing HermitStash has been one of the most rewarding things I've worked on, and the fact that you took the time to look at it means a lot.

If HermitStash has been useful to you and you'd like to buy me a coffee, you can do so at [ko-fi.com/dotcoocoo](https://ko-fi.com/dotcoocoo). It's never expected, always appreciated.
