<div align="center">

<img src="assets/BlameJS_Logo.png" alt="blamejs" width="220" />

# blamejs

**The Node framework that owns its stack.**

One install. One upgrade path. One place to look when something breaks — no blame to pass between forty transitive dependencies you didn't choose.

[![npm version](https://img.shields.io/npm/v/@blamejs/core.svg?label=%40blamejs%2Fcore&color=d946ef)](https://www.npmjs.com/package/@blamejs/core)
[![npm downloads](https://img.shields.io/npm/dm/@blamejs/core.svg?color=d946ef)](https://www.npmjs.com/package/@blamejs/core)
[![CI](https://img.shields.io/github/actions/workflow/status/blamejs/blamejs/ci.yml?branch=main&label=CI)](https://github.com/blamejs/blamejs/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/blamejs/blamejs?include_prereleases&sort=semver)](https://github.com/blamejs/blamejs/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/blamejs/blamejs/badge)](https://scorecard.dev/viewer/?uri=github.com/blamejs/blamejs)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![node](https://img.shields.io/node/v/@blamejs/core.svg)](https://nodejs.org)
[![Zero runtime deps](https://img.shields.io/badge/runtime%20deps-0-2ea043)](#why-blamejs)
[![PQC-first](https://img.shields.io/badge/crypto-PQC--first-d946ef)](#why-blamejs)

</div>

---

## Why blamejs

The modern Node app is a 1,200-package supply-chain liability with no LTS calendar, no curator, and no accountability. Frameworks peer-depend their internals onto you and call it modularity. blamejs takes the opposite stance:

- **Vendored standard library.** Auth, sessions, jobs, mail, storage, crypto, ORM, templating — bundled with the framework, not hunted on npm. Your `package.json` has one entry.
- **Security as a default, not a config flag.** Post-quantum-aware crypto envelopes, sealed-by-default storage, server-rendered output, CSRF/origin/bot defenses, per-account brute-force lockout, all wired in from line zero.
- **Server-rendering first.** HTML out of the box; client JS is opt-in islands, not the foundation.
- **A real LTS calendar.** Major versions on a published cadence with documented deprecation windows. No silent semver-major surprises in transitive deps.

## Status

Pre-1.0. Usable end-to-end — operators can build production apps on it today; the surface is still subject to change before 1.0. The latest release lives on [GitHub](https://github.com/blamejs/blamejs/releases), [npm](https://www.npmjs.com/package/@blamejs/core), and the [container registry](https://github.com/blamejs/blamejs/pkgs/container/blamejs-wiki).

```js
var b = require("@blamejs/core");

(async function () {
  var app = await b.createApp({
    dataDir: "./data",
    routes: function (router) {
      router.get("/", function (req, res) {
        b.render.htmlString(res, "<h1>Hello from blamejs</h1>");
      });
    },
  });
  await app.listen({ port: 3000 });
})();
```

**Requirements:** Node.js 24.14+ (current active LTS, fixes CVE-2026-21713 non-constant-time HMAC compare).

## What ships in the box

The framework bundles the surface a typical Node app reaches for. Every primitive listed is callable today; nothing is a stub.

### Data layer

- **SQLite with sealed-by-default columns** — `b.db`, migrations, seeders, atomic-file writes
- **Chainable query builder** — atomic `.increment(col, delta)`, closure-form `.whereGroup` / top-level `.orWhere` OR composition, `.search(fields, term)` LIKE-OR with safe `%`/`_` ESCAPE handling, `.paginate(opts)` returning `{ items, total, page, totalPages }`
- **Mongo-style document-store facade** — `b.db.collection(name, opts?)` with `$set` / `$inc` / `$unset` / `$eq` / `$ne` / `$gt` / `$gte` / `$lt` / `$lte` / `$in` / `$like`; schemaless-document opts via `overflow: "<col>"` (folds unknown fields into a JSON-text column; rewrites `WHERE` on virtual fields to `JSON_EXTRACT`), `jsonColumns: [...]` (auto-stringify on write + parse via `b.safeJson` on read), `sealedFields: { email: "emailHash" }` (co-locates a `b.cryptoField` sealed-column / derived-hash declaration so plaintext lookups auto-rewrite to hash-column lookups)
- **DB lifecycle** — in-memory encrypted snapshot via `b.db.snapshot()`; standalone encrypted-DB-file lifecycle (`b.db.fileLifecycle({ dataDir, vault })` — decrypt-to-tmpfs, periodic re-encrypt flush, graceful shutdown — same envelope as `b.db`, no schema/audit-chain coupling); `db.init` opt-outs `frameworkTables: false` / `auditSigning: false` and path overrides `encryptedDbPath` / `encryptedDbName` / `dbKeyPath`
- **External RDBMS** — bring-your-own Postgres / MySQL with pool tuning + role-aware connect + read-replica routing (`b.externalDb`); declarative role-narrowed views and Postgres row-level-security migrations (`b.db.declareView`, `b.db.declareRowPolicy`)
- **Object store** — S3 / R2 / B2 / GCS / Azure with multipart upload + SSE + bucket-ops (create / delete / list / lifecycle / CORS); S3 Object Lock + per-object retention + legal hold for write-once-read-many compliance workloads (`b.storage`, `b.objectStore`)
- **Queues + cache** — durable queue with priority + cron + flows on local SQLite, shared Redis, OR AWS SQS via SigV4 + AWSJsonProtocol_1.0 (`b.queue`, `b.jobs`); cluster-shared cache (`b.cache`)
### Identity & access

- **Passwords** — Argon2id + policy primitive (`b.auth.password`); NIST 800-63B / PCI-DSS 4.0 / HIPAA-AAL2 profiles; HaveIBeenPwned k-anonymity breach check; length / context / dictionary / complexity rules; rotation + history
- **Multi-factor + WebAuthn** — passkeys (WebAuthn), TOTP, JWT (PQ-default)
- **OAuth / OIDC RP** — `b.auth.oauth`
  - RP-Initiated / Front-Channel / Back-Channel Logout 1.0 (`parseFrontchannelLogoutRequest` + `verifyBackchannelLogoutToken` with jti-replay defense)
  - RFC 9207 AS Issuer Identifier validation on callbacks (`parseCallback` — refuses iss mismatch + OP `error=` redirect)
  - OAuth 2.0 JARM signed-response decode (`parseJarmResponse`)
  - One-time-use refresh-token rotation with operator-supplied replay-defense callback (RFC 9700 §4.13 / OAuth 2.1 §6.1 — `refreshAccessToken({ seen })`)
- **Federation / VC** — CIBA Core 1.0 (`b.auth.ciba`, poll/ping/push); OpenID Federation 1.0 trust chain + metadata_policy (`b.auth.openidFederation`); SAML 2.0 SP with XMLDSig signature-wrapping defense + RFC 9525 server-identity (`b.auth.saml`); OpenID4VCI 1.0 issuer (`b.auth.oid4vci`); OpenID4VP 1.0 verifier with DCQL (`b.auth.oid4vp`); SD-JWT VC with `key_attestation` extension (`b.auth.sdJwtVc`)
- **Sessions** — `b.session`
  - PQC-sealed sid cookie (ML-KEM-1024 + P-384 hybrid + XChaCha20-Poly1305 wire envelope)
  - `/24` IPv4 + `/64` IPv6 subnet binding via `fingerprintFields: ["clientIpPrefix"]` (carrier-roaming-safe)
  - Pluggable storage via `b.session.useStore` + first-party `b.session.stores.localDbThin` (tmpfs-fast)
  - Opaque-userId anonymous sessions via `create({ anonymous: true })`
  - Idle / absolute timeouts, fingerprint drift detection + anomaly scoring, brute-force lockout
- **Authorization** — RBAC + per-role DB binding + role-spec `requireMfa` + per-route MFA freshness window + ABAC predicate registry (`b.permissions`); API keys with rotation (`b.apiKey`)
- **Workflow gates** — break-glass column gates with second-factor + audit (`b.breakGlass`); two-person-rule m-of-n approval with cooling-off lock + cancellation (`b.dualControl`)
- **Financial / Open Banking** — FAPI 2.0 Final composite posture (PAR + PKCE-S256 + DPoP-or-mTLS + RFC 9207); runtime enforcement helpers `b.fapi2.assertCallback` (refuses missing iss + bare-param under message-signing) and `b.fapi2.assertAuthzRequest` (refuses non-JAR); CFPB §1033 / FDX 6.0 consumer-financial-data-sharing wrapper (`b.fdx`)
- **Data-subject coordination** — cross-table export / rectify / erase / restrict / objection (`b.subject`, `b.subject.eraseHard`); subject-level legal-hold registry consulted by erase + retention paths (FRCP Rule 26/37(e), GDPR Art 17(3)(e), SEC Rule 17a-4, HIPAA §164.530(j)(2)) (`b.legalHold`)
- **Account safety** — adaptive bot-challenge staircase (`b.authBotChallenge`); session-to-device-posture binding with fail-closed verify (`b.sessionDeviceBinding`)
### Crypto

- **At-rest envelope** — envelope-versioned PQC (ML-KEM-1024 + P-384 hybrid, XChaCha20-Poly1305, SHAKE256); vault sealing (`b.crypto`, `b.vault`)
- **Field-level + crypto-shred** — `b.cryptoField.eraseRow`; per-column data residency tagging + per-row keys (`K_row = HKDF(K_table, rowId)`) so erasing the per-row key makes WAL / replica residuals undecryptable (`b.cryptoField.declareColumnResidency`, `b.cryptoField.declarePerRowKey`)
- **AAD-bound sealed columns** — AEAD tag tied to `(table, rowId, column, schemaVersion)`; copy-paste between rows or schema-version replay surfaces as refused decrypt (`b.vault.aad`)
- **Signed webhooks + API encryption** — SLH-DSA-SHAKE-256f default; ML-DSA-65 opt-in; ECIES API encryption (`b.webhook`, `b.crypto`)
- **HPKE / HTTP signatures** — RFC 9180 HPKE with ML-KEM-1024 + HKDF-SHA3-512 + ChaCha20-Poly1305 (`b.crypto.hpke`); RFC 9421 HTTP Message Signatures with derived components and ed25519 / ML-DSA-65 (`b.crypto.httpSig`)
- **CMS codec** — RFC 5652 Cryptographic Message Syntax encoder + decoder with PQC signers (ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f; RFC 9909 + 9881) and KEMRecipientInfo recipients (ML-KEM-1024; RFC 9629 + 9936); ChaCha20-Poly1305 content encryption (RFC 8103) so Efail-class malleability cannot apply (`b.cms`)
- **Stream throttle** — shared token-bucket bandwidth limiter (RFC 2697 srTCM shape); N concurrent `node:stream` pipelines draw from one operator-configured `bytesPerSec` budget (`b.streamThrottle`)
- **TLS-RPT receiver** — RFC 8460 inbound aggregate-report ingest; HTTPS POST handler + §4.4 schema parser with gzip-bomb / ratio-bomb / depth-bomb defenses (`b.mail.deploy.parseTlsRptReport` / `b.mail.deploy.tlsRptIngestHttp`)
- **TLS / channel binding** — RFC 9266 TLS-Exporter token-to-session pinning (`b.tlsExporter`); RFC 9162 CT v2 inclusion-proof verification (`b.network.tls.ct.verifyInclusion`); RFC 8555 ACME + RFC 9773 ARI for 47-day certs with `{ jitter: true }` fleet-scheduling (`b.acme.renewIfDue`); draft-aaron-acme-profiles (`acme.listProfiles()` + `newOrder({ profile })`); draft-ietf-acme-dns-account-label (`acme.dnsAccount01ChallengeRecord(token, { identifier })`); RFC 8470 0-RTT inbound posture refuse / replay-cache (`b.router.create({tls0Rtt})`); RFC 9794 SecP256r1MLKEM768 in preferred-group order (`b.network.tls.preferredGroups`)
- **mTLS CA** — pure-JS, issues clientAuth / serverAuth / dual-EKU certs with SAN; auto-detects highest-PQC signature alg (today ECDSA-P384-SHA384; self-upgrades to SLH-DSA / ML-DSA when X.509 ecosystem catches up); PQC TLS gates inbound + outbound (`b.mtlsCa`, `b.pqcGate`, `b.pqcAgent`)
### HTTP

- **Router + API specs** — schema-validated routes; OpenAPI publication (`b.openapi`) + AsyncAPI publication for event/streaming (`b.asyncapi`)
- **Middleware stack (wired by `createApp`)**
  - CSRF protection
  - CORS with W3C Private Network Access preflight refusal default + `allowPrivateNetwork` opt
  - Rate-limit
  - Security headers with `Permissions-Policy` defaults denying storage-access / browsing-topics / private-aggregation / controlled-frame
  - CSP nonce
  - Body parser
  - Compression
  - SSE
  - Request log
  - Threat-aware cookie parser (`b.middleware.cookies`)
  - Request-time DB role binding (`b.middleware.dbRoleFor`)
  - In-process CIDR fence (`b.middleware.networkAllowlist`)
  - `Cache-Control: no-store` on every 401 from `requireAuth` / `requireAal` / `requireStepUp` per RFC 9111 §5.2.2.5
- **Outbound HTTP client** — HTTP/1.1 + HTTP/2 with SSRF gate (cloud-metadata IPs hard-denied; private / loopback / link-local overridable per call); scheme + userinfo + per-host destination allowlist; redirects, multipart, interceptors, progress, encrypted cookie jar (`b.httpClient`, `b.ssrfGuard`, `b.safeUrl`)
- **Network configurability (`b.network`)** — env-driven NTP / NTS (RFC 8915), IPv4/IPv6 NTP, DNS with IPv6 / DoH / DoT (private-CA pinning) / cache / lookup timeout; outbound HTTP proxy (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`); runtime DPI trust-store CA additions; application-level heartbeats; TCP socket defaults
- **Error pages** — operator-rendered, no app-frame leakage (`b.errorPage`)
### Defensive parsers

- **JSON / SQL / schema** — `b.safeJson` (with `maxKeys` cap defending CVE-2026-21717 V8 HashDoS), `b.safeBuffer`, `b.safeSql`, `b.safeSchema`
- **URL + path** — `b.safeUrl` (IDN mixed-script / homograph refuse); `b.safeJsonPath` (refuses filter `?(...)`, deep-scan `$..`, script-shape `(@.x)` for safe Postgres JSONB ops)
- **Document parsers** — `b.parsers` (XML / TOML / YAML / .env); `b.config` (schema-validated env)
- **File-type detection** — `b.fileType` magic-byte content classification with deny-on-upload categories (image / document / archive / executable / etc.)
### Content-safety gates

- **Composition contract** — `b.gateContract` uniform mode posture / hooks / forensic snapshot / decision cache / runtime cap
- **Document guards** — `b.guardCsv` (formula injection, dangerous-function denylist, bidi / homoglyph / dialect ambiguity, CSV-bombs); `b.guardHtml` (XSS / mXSS / DOM-clobbering, dangerous-tag + event-handler family, URL-scheme with entity-decode bypass, CSS-injection in style); `b.guardSvg` (script / foreignObject / animation href hijack / DOCTYPE / XXE / SVGZ / cross-origin `<use>` SSRF); `b.guardMarkdown` (URL schemes pre-render, CVE-2026-30838 dangerous-tag, ReDoS emphasis runs)
- **Structured data** — `b.guardJson` (prototype-pollution, dup keys, JSON5, depth/breadth caps); `b.guardYaml` (deserialization-tag RCE, billion-laughs aliases, Norway-problem); `b.guardXml` (XXE / billion-laughs / xi:include / signature wrapping; DOCTYPE refused at all profile levels)
- **Archive + filename** — `b.guardArchive` (zip-slip, symlink + hardlink escape, decompression bombs, duplicate-entry); `b.guardFilename` (path traversal raw + percent-encoded + overlong-UTF-8, null-byte, Windows reserved, NTFS ADS, RTLO bidi)
- **Email** — `b.guardEmail` (SMTP smuggling per CVE-2023-51764 / 51765 / 51766 class, CRLF header injection, IDN homograph, IP-literals, RFC 5321 length caps)
- **Profiles + postures** — every member ships strict / balanced / permissive plus hipaa / pci-dss / gdpr / soc2
- **Aggregator** — `b.guardAll` registry; every shipped guard ON by default; opt-out per guard with audited reason via `exceptFor: { name: { reason } }`. `b.fileUpload` and `b.staticServe` wire `b.guardAll.byExtension({ profile: "strict" })` + `b.guardFilename.gate({ profile: "strict" })` automatically — operator opts out via `contentSafety: null` / `filenameSafety: null` (audited)
### Communication

- **WebSockets (server)** — channel/room fan-out across cluster replicas; RFC 6455 §5.5 control-frame size + FIN enforcement on inbound (defends 1 MiB-PING-as-PONG amplification) (`b.websocket`, `b.websocketChannels`)
- **WebSockets (client)** — `b.wsClient` with PQC-TLS handshake, permessage-deflate negotiation with decompression-bomb cap, fatal UTF-8 validation, permanent-error classifier (skips reconnect on 4xx / accept mismatch / bad-subprotocol), exponential-backoff with full jitter
- **Pub/sub + events** — distributed pub/sub with cluster-table / Redis PUB/SUB / custom backends (`b.pubsub`); framework-emitted signal bus for breach / integrity events (`b.events`)
- **CloudEvents + SSE** — CloudEvents 1.0 envelope for AWS EventBridge / Knative / Azure Event Grid / Google Eventarc / CNCF (`b.cloudEvents`); Server-Sent Events with newline-injection refusal in `event:` / `id:` / `data:` / `Last-Event-ID` (CVE-2026-33128 / 29085 / 44217 class) (`b.sse`, `b.middleware.sse`)
- **Mail (outbound)** — multipart + attachments + DKIM + calendar invites; bounce intake (`b.mail`, `b.mailBounce`)
- **Mail (inbound auth)** — SPF / DMARC / ARC verify + ARC chain signing for relays (`b.mail.spf`, `b.mail.dmarc`, `b.mail.arc`)
- **Notifications** — generic dispatcher with operator-supplied transports (`b.notify`); TCPA / FCC 1:1 prior-express-written-consent + 10DLC carrier-shaped consent snapshot for SMS marketing (`b.tcpa10dlc`)
- **File uploads** — chunked with per-chunk SHA3-512 verification + atomic finalize + tombstone cleanup (`b.fileUpload`)
### AI / agentic

- **MCP (Model Context Protocol)** — `b.mcp.serverGuard` with bearer auth + redirect_uri allowlist + dynamic-register refusal + tool/resource allowlists (CVE-2026-33032 / CVE-2025-6514 / confused-deputy class)
- **MCP safety primitives**
  - `b.mcp.toolResult.sanitize` — prompt-injection / dangerous-HTML / off-allowlist-URL detection (OWASP LLM07)
  - `b.mcp.capability.create` — least-privilege capability scopes (OWASP LLM08)
  - `b.mcp.validateToolInput` — JSON Schema 2020-12 input enforcement
- **GraphQL Federation** — `_service.sdl` trust-boundary with router-token + nonce store (`b.graphqlFederation`)
- **Prompt-injection classification** — OWASP LLM01:2025 / NIST COSAIS RFI (`b.ai.input.classify`)
- **Agent identity** — A2A signed agent-card primitive (Linux Foundation Agentic AI Foundation v1.x, ML-DSA-87) (`b.a2a`)
- **Content provenance** — C2PA 2.1 + California SB-942 / AB-853 manifest builder for AI-generated media (provider, model id + version, timestamp, content ID, signed) (`b.contentCredentials`)
### Compliance regimes

- **Posture coordinator** — `b.compliance` cascades operator-declared regime into retention / audit / db / cryptoField via POSTURE_DEFAULTS:
  - **US** — `hipaa` / `hipaa-2026` / `hhs-repro-24` / `hitech` / `pci-dss` / `glba-safeguards` / `sox-404` / `soc2` / `soc2-cc1.3` / `sec-cyber` / `sec-17a-4` / `finra-4511` / `fda-21cfr11` / `fda-annex-11` / `modpa` / `nydfs-500` / `staterramp` / `ferpa` / `fl-fdbr` / `coppa` / `coppa-2025` / `gina` / `vppa` / `can-spam` / `il-gipa` / `nist-pf-1.1`
  - **EU / UK** — `gdpr` / `dora` / `nis2` / `cra` / `eu-data-act` / `eaa` / `uk-g-cloud` / `uk-duaa` / `dsa` / `dga` / `eu-cer` / `eu-cyber-sol` / `eidas-2`
  - **APAC + LATAM** — `dpdp` / `pipl-cn` / `lgpd-br` / `appi-jp` / `pdpa-sg` / `quebec-25` / `irap` / `kr-ai-basic` / `pipa-kr` / `au-privacy` / `th-pdpa` / `vn-pdp` / `id-pdp` / `my-pdpa` / `cl-pdpa` / `mx-lfpdppp` / `ar-pdpa`
  - **Child privacy / age-appropriate design** — `ca-aadc` / `ny-safe-kids` / `ny-saffe` / `md-kids-code` / `vt-aadc`
  - **Financial / data-portability** — `fapi2` / `fapi-2.0-message-signing` / `fdx` / `dsr`
  - **AI governance** — `co-ai` / `il-hb3773` / `tx-traiga` / `ut-aipa` / `nyc-ll144` / `ca-tfaia` / `ca-sb942` / `ca-ab853` / `cn-ai-label` / `iso-42001` / `iso-23894`
  - **Accessibility** — `wcag-2-2`
  - **Other** — `bsi-c5` / `ens-es` / etc.
- **AI Act ⇄ ISO cross-walk** — `b.compliance.aiAct.crossWalkIso42001()` + `crossWalkIso23894()` map every AI Act article (Art. 9 risk management → Art. 73 incident reporting) to the matching ISO/IEC 42001:2023 Annex A controls and ISO/IEC 23894:2023 risk-management clauses for ISO-certification audit packs
- **EU Data Act** — Regulation 2023/2854 connected-product data access workflow with DMA-gatekeeper share refusal (Art 32 §1) and 30-day switch-request notice cap (Art 28 §3) (`b.dataAct`)
- **Audit + segregation** — 21 CFR Part 11 §11.10(e) audit-content gate + §11.50(b) electronicSignature (`b.fda21cfr11`); PCI DSS 4.0 Req 10.4.1.1 daily-review automation (`b.auditDailyReview`); SOX §404 + SOC 2 CC1.3 segregation-of-duties via Postgres trigger DDL (`b.audit.bindActor`, `b.audit.assertSegregation`)
- **Change control + WORM** — m-of-n approver DDL change-control with maintenance-window + ML-DSA-87 signed proposals (`b.ddlChangeControl`); row-level WORM triggers boot-asserted under `sec-17a-4` / `finra-4511` / `fda-21cfr11` (`b.db.declareWorm`); dual-control physical delete + crypto-erase + REINDEX in one transaction (`b.db.declareRequireDualControl`, `b.db.eraseHard`)
- **Consumer-protection** — FTC click-to-cancel UX-parity attestation (`ftc-2024` / `ca-sb942` / `strict`) (`b.darkPatterns`)
- **Privacy / DSR** — GDPR Articles 15–22 / CCPA / CPRA / LGPD / PIPEDA data-subject-rights workflow (`b.dsr`); IAB TCF v2.3 consent-string parser + `disclosedVendors` validator (`b.iabTcf`); IAB MSPA / GPP universal-opt-out (USNAT / USCA / USVA / USCO / USCT / USUT) + GPC mirror (`b.iabMspa`); generic consent capture + withdrawal (`b.consent`)
- **Incident reporters** — EU DORA Article 17 ICT-incident workflow per Commission Delegated Regulation 2024/1772 (`b.dora`); EU NIS2 (`b.nis2`); EU Cyber Resilience Act SBOM + secure-software-attestation (`b.cra`); SEC Form 8-K Item 1.05 cybersecurity-incident materiality-disclosure (`b.secCyber`); incident lifecycle coordinator (`b.incident`)
- **Outbound DLP** — interceptor-installed on httpClient + mail + webhook with built-in detectors for PAN (Luhn), SSN, EIN, IBAN (mod-97), api-key shapes, PEM, SSH private keys, JWTs, AWS access keys, PHI composite; refuse / redact / audit-only verdicts under pci-dss / hipaa / fapi2 / soc2 / gdpr presets (`b.redact.installOutboundDlp`)
### Observability

- **Audit chain** — tamper-evident, SLH-DSA-signed checkpoints; CADF (ISO/IEC 19395:2017) envelope export for federated SIEM (`b.audit`, `b.audit.export({ format: "cadf" })`)
- **Metrics + tracing** — `b.metrics`, `b.tracing` (OTel pass-through); OTLP/HTTP-JSON exporter for traces + metrics (`b.otelExport`)
- **Log-stream sinks** — local file rotation, generic webhook, OTLP/HTTP-JSON OR OTLP/gRPC, AWS CloudWatch Logs via SigV4 with optional autoCreate, RFC 5424 syslog over UDP/TCP/TLS (`b.logStream`)
- **PII redaction** — `b.redact`
- **Decoy detection** — canary-credential / decoy-record framework auditing every positive lookup as `honeytoken.tripped` (`b.honeytoken`)
- **Boot assertions** — operator-callable security policy assertions (`b.security.assertProduction`); tamper-evident config-baseline drift detection signed with audit-signing key + at-boot vendor-bundle SHA-256 integrity verification across `lib/vendor/*` (`b.configDrift`, `b.configDrift.verifyVendorIntegrity`)
- **CSP reports + forensic export** — `b.middleware.cspReport`; post-incident audit-bundle composer (`b.auditTools.forensicSnapshot`)

### i18n + format helpers

- **i18n** — CLDR plural rules, Accept-Language negotiation, Intl formatters, RTL (`b.i18n`)
- **CSV** — RFC 4180 with Excel formula-injection prevention (`b.csv`)
- **IDs + slugs** — RFC 9562 UUID v4 + v7 (`b.uuid`); URL-safe slugs (`b.slug`)
- **Time + archive** — TZ-aware datetime (`b.time`); ZIP creation (`b.archive`)
- **Pagination + forms** — HMAC-signed cursor pagination (`b.pagination`); HTML form rendering + validation + CSRF (`b.forms`)

### Production

- **Cluster + scheduling** — cluster leader election with fenced leases over Postgres/SQLite (`b.cluster`); cron + interval scheduler that runs exactly-once globally (`b.scheduler`)
- **Reliability** — retry with full-jitter backoff + circuit breaker (`b.retry`); graceful shutdown (`b.appShutdown`); NTP boot check (`b.ntpCheck`)
- **Transactional integration** — outbox + dedupe-on-receive inbox; exactly-once semantics across Postgres / SQLite (`b.outbox`, `b.inbox`); Debezium-shape change-event envelope on the outbox (`b.outbox.create({ envelope: "debezium" })`)
- **Backup + restore** — end-to-end-encrypted bundles with pre-flush fail-closed mode + ML-DSA-87 signed manifests + scheduled backup-restore drills (`b.backup`, `b.backup.scheduleTest`, `b.backupBundle.verifyManifestSignature`); restore with pulled-bundle footprint preflight (`b.restore`); disaster-recovery runbook generator (HIPAA / PCI-DSS / GDPR / SOC 2 / DORA postures) (`b.drRunbook`)
- **Multi-tenant** — per-tenant DB storage caps, query budgets, tenant-isolation breach detection (`b.tenantQuota`); per-Postgres-role hardening with `pg_roles` enumeration guard (`b.externalDb.assertRoleHardening`)
- **Data export** — RFC 4180 strict CSV table export with SHA3-512 manifest + ML-DSA-87 signature + JSON Schema 2020-12 reflective metadata (`b.db.exportCsv`, `b.db.getTableMetadata`)
- **Retention** — GDPR / PCI / HIPAA-shaped rules with multi-stage warn → archive → erase, legal-hold exemptions, dry-run preview, cross-table cascade (`b.retention`)
- **Feature flags** — OpenFeature-spec client with pluggable providers + evaluation-context targeting + per-request `req.flag` accessor (`b.flag`)
- **Concurrency + kill-switches** — per-resource lock with cooperative-cancel + audit (`b.resourceAccessLock`); composite account-takeover kill-switch (`b.atoKillSwitch`)
- **Sandbox + spawn** — `worker_threads` sandbox with strict resource limits (`b.sandbox`, composable into `b.template.create({ sandbox: true })`); hardened `processSpawn` refusing shell-string invocation (`b.processSpawn`)
- **Egress allowlist** — per-host outbound destination allowlist (wildcard / per-method) via `b.httpClient.request({ allowedHosts: [...] })`

## Documentation

Full primitive-by-primitive docs live at [blamejs.com](https://blamejs.com), which is itself the `examples/wiki/` app running in production. The wiki is organized by concern:

- **Data** — [Database](https://blamejs.com/database) · [Object Store](https://blamejs.com/object-store) · [Queue & Cache](https://blamejs.com/queue-cache)
- **Identity** — [Authentication](https://blamejs.com/auth) · [Access Control](https://blamejs.com/access-control)
- **Crypto** — [Crypto & Vault](https://blamejs.com/crypto-vault) · [Network Crypto](https://blamejs.com/network-crypto)
- **HTTP** — [Routing](https://blamejs.com/routing) · [Middleware](https://blamejs.com/middleware) · [Outbound HTTP](https://blamejs.com/outbound-http) · [Network Configurability](https://blamejs.com/network-config)
- **Validation** — [Safe Parsers](https://blamejs.com/safe-parsers)
- **Communication** — [WebSockets](https://blamejs.com/websockets) · [Mail](https://blamejs.com/mail) · [Notifications](https://blamejs.com/notifications) · [File Upload](https://blamejs.com/file-upload)
- **Tools** — [Observability](https://blamejs.com/observability) · [Testing](https://blamejs.com/testing) · [i18n & Locale](https://blamejs.com/i18n-locale) · [Format Helpers](https://blamejs.com/format-helpers)
- **Compliance** — [Compliance Patterns](https://blamejs.com/compliance-patterns)
- **Production** — [Cluster Mode](https://blamejs.com/cluster) · [Reliability](https://blamejs.com/reliability) · [Backup & Restore](https://blamejs.com/backup-restore) · [Quality Contract](https://blamejs.com/quality-contract)

## CLI

`blamejs` ships an operator-facing CLI for the recurring ops work. Each subcommand boots a headless app instance from `--data-dir` (no HTTP listener), runs the operation, and shuts down. Same vault + DB + audit chain the running app uses.

```
blamejs migrate       up | down | status                          --db <path> [--dir <path>]
blamejs seed          run | status                                --db <path> --env <name> [--dir <path>]
blamejs dev           --command <cmd> [--watch <dir>...]
blamejs api-snapshot  capture | compare                           --file <path>
blamejs api-key       issue | revoke | list | rotate | verify     --data-dir <path> --namespace <ns>
blamejs audit         archive | export | verify-bundle | verify-chain | purge   --data-dir <path>
blamejs backup        inspect | verify | extract                  --bundle <path>
blamejs restore       list | inspect | apply | rollback | list-rollbacks         --data-dir <path> --bundle <dir>
blamejs mtls          status | show-cert | init | issue | issue-p12  --data-dir <path>
blamejs vault         status | seal | unseal | rotate             --data-dir <path>
blamejs security      assert                                      --data-dir <path>
blamejs config-drift  inspect | verify                            --data-dir <path>
blamejs file-type     detect <file>                               [--allowlist image,pdf,...]
blamejs password      check                                       --plaintext "..." [--profile pci-4.0|nist-aal2|hipaa-aal2] [--breach-check] [--email <e>] [--username <u>]
blamejs erase         --table <t> --row-id <id> --confirm         --data-dir <path>
blamejs retention     preview | run                               --data-dir <path> --table <t> --age-field <col> --ttl-ms <n> [--action soft-delete|delete|erase] [--soft-delete-field <col>]
blamejs version
blamejs help [<command>]
```

Pass `--help` to any subcommand for the full flag list (`blamejs api-key --help` etc.). Passphrases for crypto-backed operations resolve from the appropriate env var (`BLAMEJS_VAULT_PASSPHRASE`, `BLAMEJS_BACKUP_PASSPHRASE`, `BLAMEJS_AUDIT_PASSPHRASE`) so they don't end up in shell history.

## Reference app + deployment

`examples/wiki/` is a complete production-ready operator-built blamejs app — the wiki you're looking at when you visit `blamejs.com`. It demonstrates every framework primitive in real usage and ships with `Dockerfile`, `docker-compose.yml` (dev), `docker-compose.prod.yml` (Caddy + GHCR image), and a published OCI image at `ghcr.io/blamejs/blamejs-wiki:<tag>` (multi-arch amd64/arm64, cosign-signed via GitHub OIDC, Trivy-scanned, SHA3-512 digest).

See [`examples/wiki/DEPLOY.md`](examples/wiki/DEPLOY.md) for the full deployment walkthrough, including the operator-facing environment-variable matrix (`WIKI_*` and `BLAMEJS_*` keys) and the pin-to-version workflow for production updates.

## Vendored dependencies

All runtime dependencies are committed to the repo — no transitive npm install at runtime, no `node_modules` lookup path for production. Server-side deps are bundled via `scripts/vendor-update.sh`:

```bash
./scripts/vendor-update.sh --check                  # see what's outdated
./scripts/vendor-update.sh --diff @noble/ciphers    # see changelog before bumping
./scripts/vendor-update.sh @noble/ciphers 2.2.0     # bundle + commit a new version
```

| Package | Version | Author | Purpose |
|---|---|---|---|
| [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) | 2.2.0 | [Paul Miller](https://github.com/paulmillr) | XChaCha20-Poly1305 AEAD |
| [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) | 0.6.1 | [Paul Miller](https://github.com/paulmillr) | Pure-JS FIPS 203 ML-KEM (`ml_kem_512` / `ml_kem_768` / `ml_kem_1024`), FIPS 204 ML-DSA (`ml_dsa_44/65/87`), FIPS 205 SLH-DSA (`slh_dsa_*`). First-class on both server-side and client-side via `b.pqcSoftware` — security-first defaults pin to the highest cat-5 levels (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f); interoperable with Node's built-in WebCrypto ML-KEM that `b.crypto.encrypt` / `b.middleware.apiEncrypt` use. |
| [`@simplewebauthn/server`](https://github.com/MasterKale/SimpleWebAuthn) | 13.3.0 | [Matthew Miller](https://github.com/MasterKale) | WebAuthn / passkey verification |
| [`@peculiar/x509`](https://github.com/PeculiarVentures/x509) + [`pkijs`](https://github.com/PeculiarVentures/PKI.js) | 2.0.0 + 3.4.0 | [Peculiar Ventures](https://github.com/PeculiarVentures) | Pure-JS mTLS CA — ECDSA P-384 cert signing, PKCS#12 packaging (no openssl CLI) |
| [`SecLists` 10k-most-common.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt) | master snapshot | [Daniel Miessler / SecLists contributors](https://github.com/danielmiessler/SecLists) (CC-BY-3.0) | Top-10000 common-password dictionary read by `b.auth.password.policy()` for the NIST 800-63B §5.1.1.2 "previously breached" check |
| [`prismjs`](https://prismjs.com/) | 1.30.0 | [Lea Verou + contributors](https://github.com/PrismJS/prism) | Syntax highlighting in the example wiki's code blocks (browser-side) |

These libraries are exceptional work — blamejs wouldn't exist without them. All are MIT licensed (the SecLists password list is CC-BY-3.0). Per-package version, license, and provenance live in two manifests: [`lib/vendor/MANIFEST.json`](lib/vendor/MANIFEST.json) for the framework's server-side bundles and [`examples/wiki/public/vendor/MANIFEST.json`](examples/wiki/public/vendor/MANIFEST.json) for the wiki app's browser-side bundle. The framework's [`NOTICE`](NOTICE) file carries the upstream attributions.

## Why "blamejs"

Because when something breaks, `blame` should know exactly where it lives. We own the stack so you don't have to chase the fault across an ecosystem.

## Quality contract

Every release passes a layered gate at `test/layer-0-primitives/codebase-patterns.test.js` that operates on lib/ source:

- **Bug-class detectors** — raw byte / time literals, `JSON.parse` on operator input without size cap, numeric opts that silently accept `Infinity` / `NaN`, ReDoS-risky regex without length cap, hash / token compares without `timingSafeEqual`, raw `new URL` skipping the SSRF gate, `Math.random()` in security-sensitive paths, and a couple dozen others — each a bug class the framework already swept once and won't re-introduce.
- **Inline-shape catalog (n=1)** — every primitive that's been extracted (`validateOpts.requireNonEmptyString`, `safeAsync.makeScheduledFlush`, `dbSchema.runInTransaction`, etc.) registers the inline shape it replaced; new code that re-implements the shape fails the gate even if it's the only file matching.
- **Cluster allowlist (n>=3)** — duplicate-block detection across files. Genuine new clusters get extracted; clusters that resist extraction (parser error class signature mismatches, framework-convention shapes, cross-domain coincidences) get an entry with a documented structural reason. No silent allowlisting.

The gate is part of `node test/smoke.js`; the framework refuses to release without it green.

## Contributing

Patches welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, house rules (zero npm runtime deps, PQC-only crypto, audit-on-every-action, ship-complete-not-incremental), and the PR loop. New to the codebase? Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the orientation map.

Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Be excellent.

## Security

Threat model, supported versions, vulnerability disclosure: [SECURITY.md](SECURITY.md). Do **not** file public issues for security bugs — email `security@blamejs.com`.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution of vendored components.
