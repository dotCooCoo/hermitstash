# blamejs

**The Node framework that owns its stack.**

One install. One upgrade path. One place to look when something breaks — no blame to pass between forty transitive dependencies you didn't choose.

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

**Requirements:** Node.js 24+ (current active LTS).

## What ships in the box

The framework bundles the surface a typical Node app reaches for. Every primitive listed is callable today; nothing is a stub.

- **Data layer** — SQLite with sealed-by-default columns (`b.db`), migrations, seeders, atomic-file writes; bring-your-own external Postgres / MySQL / etc. with pool tuning + role-aware connect + read-replica routing (`b.externalDb`); declarative role-narrowed views and Postgres row-level-security migrations (`b.db.declareView`, `b.db.declareRowPolicy`); S3 / R2 / B2 / GCS / Azure object store with multipart upload + SSE + bucket-ops (create / delete / list / lifecycle / CORS) across all three clouds, plus S3 Object Lock + per-object retention + legal hold for write-once-read-many compliance workloads (`b.storage`, `b.objectStore`); durable queue with priority + cron + flows on the local SQLite backend, a shared Redis backend, OR AWS SQS via SigV4 + AWSJsonProtocol_1.0 for fully-managed multi-replica deploys (`b.queue`, `b.jobs`); cluster-shared cache (`b.cache`).
- **Identity & access** — passwords (Argon2id) + policy primitive (NIST 800-63B / PCI-DSS 4.0 / HIPAA-AAL2 profiles, HaveIBeenPwned k-anonymity breach check, length / context / dictionary / complexity rules, rotation + history) (`b.auth.password`); passkeys (WebAuthn), TOTP, JWT (PQ-default), OAuth, sessions with optional IP / UA fingerprint drift detection + anomaly scoring, brute-force lockout (`b.auth.*`, `b.session`); RBAC + optional per-role DB binding + role-spec `requireMfa` + per-route MFA freshness window + ABAC predicate registry (`b.permissions`); API keys with rotation (`b.apiKey`); break-glass column gates with second-factor + audit (`b.breakGlass`); two-person-rule approval workflow with m-of-n quorum + cooling-off lock + approver-role gate + cancellation (`b.dualControl`).
- **Crypto** — envelope-versioned PQC at rest (ML-KEM-1024 + P-384 hybrid, XChaCha20-Poly1305, SHAKE256), vault sealing, field-level crypto + cryptographic erasure (`b.cryptoField.eraseRow`), AAD-bound sealed columns whose AEAD tag is tied to a `(table, rowId, column, schemaVersion)` tuple so a copy-paste between rows or a schema-version replay surfaces as a refused decrypt (`b.vault.aad`), signed webhooks (SLH-DSA-SHAKE-256f), ECIES API encryption (`b.crypto`, `b.vault`, `b.webhook`); pure-JS mTLS CA that issues clientAuth / serverAuth / dual-EKU certs with SAN entries and auto-detects the highest-PQC signature algorithm the vendored x509 library accepts (today: ECDSA-P384-SHA384 bridge; self-upgrades to SLH-DSA / ML-DSA when the X.509 ecosystem catches up), PQC TLS gates inbound + outbound (`b.mtlsCa`, `b.pqcGate`, `b.pqcAgent`).
- **HTTP** — router with schema-validated routes + OpenAPI publication; full middleware stack (CSRF, CORS, rate-limit, security headers, CSP nonce, body parser, compression, SSE, request log, request-time DB role binding via `b.middleware.dbRoleFor`, in-process CIDR fence via `b.middleware.networkAllowlist`) wired by `createApp`; HTTP/1.1 + HTTP/2 outbound client with SSRF gate (cloud-metadata IPs hard-denied unconditionally; private / loopback / link-local overridable per call), scheme + userinfo + per-host (wildcard / per-method) destination allowlist, redirects, multipart, interceptors, progress, encrypted cookie jar (`b.httpClient`, `b.ssrfGuard`, `b.safeUrl`); operator-tunable network configurability — env-driven NTP / NTS (RFC 8915 authenticated time), IPv4-or-IPv6 NTP servers, DNS with IPv6 / DoH / DoT (private-CA trust pinning via `opts.ca`) / cache / lookup timeout, outbound HTTP proxy (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`), runtime DPI trust-store CA additions, application-level heartbeats, TCP socket defaults (`b.network`).
- **Defensive parsers** — `b.safeJson`, `b.safeBuffer`, `b.safeSql`, `b.safeSchema`, `b.parsers` (XML / TOML / YAML / .env), `b.config` (schema-validated env), `b.fileType` magic-byte content classification with deny-on-upload categories (image / document / archive / executable / etc.).
- **Content-safety gates** — `b.gateContract` uniform composition contract (mode posture / hooks / forensic snapshot / decision cache / runtime cap). Family members: `b.guardCsv` (formula injection ASCII + full-width prefixes, dangerous-function denylist, bidi / homoglyph / control / null / BOM / zero-width detection, dialect ambiguity, CSV-bombs, numeric precision, schema-bound serializer); `b.guardHtml` (XSS / mXSS / DOM-clobbering / dangerous-tag / event-handler-family / dangerous-URL-scheme with entity-decode / CSS-injection in style attribute / IE conditional comments + token-level sanitize + always-correct `escapeText` / `escapeAttr` entity encoders); `b.guardSvg` (script / foreignObject / animation-element href hijack / DOCTYPE billion-laughs / XXE / SVGZ / cross-origin `<use>` SSRF / event-handlers + token-level sanitize). `b.guardArchive` (zip-slip / symlink + hardlink escape / decompression-ratio bombs (per-entry + aggregate) / nested-archive depth / duplicate-entry / case-insensitive collision / encryption-claim mismatch / format-claim mismatch via magic-byte detection — composes `b.guardFilename` for per-entry-name validation); `b.guardJson` (source-level prototype-pollution detection, duplicate-key, NaN/Infinity, JSON5 syntax, BOM, bidi, numeric-precision-loss, top-level-key allowlist, depth/breadth/array/string/node-count caps); `b.guardYaml` (deserialization-tag RCE via language-specific tag prefixes, billion-laughs alias recursion, Norway-problem implicit booleans, leading-zero octals, multi-document streams, duplicate keys, merge-key chains, depth+anchor+node caps); `b.guardXml` (XXE / billion-laughs / external-entity / parameter-entity / XInclude / xsi:schemaLocation / processing-instruction / CDATA / XML-signature-wrapping detection — DOCTYPE refused at all profile levels); `b.guardMarkdown` (source-level scan run BEFORE any markdown renderer sees the input — dangerous URL schemes in inline links + images + autolinks + reference-link definitions with HTML-entity decode bypass; whitespace-tolerant dangerous-tag matching per CVE-2026-30838; front-matter; HTML comments; code-fence language injection; catastrophic emphasis-run ReDoS per CVE-2025-6493 class; inline DOCTYPE; depth + link + image + autolink + ref-def caps); `b.guardEmail` (single-address + full RFC 822/5322 message validation — SMTP smuggling per CVE-2023-51764 / 51765 / 51766 / CVE-2026-32178 class via bare-CR + bare-LF + smuggled SMTP verbs; CRLF header injection; IDN homograph mixed-script domains with operator-opt-in `allowedScripts`; Punycode flag; display-name spoofing; IP-literal addresses; RFC 5322 comment syntax; multi-@; RFC 5321 length caps + RFC 5322 line cap; BOM injection). Filename safety: `b.guardFilename` (path traversal raw + percent-encoded + overlong-UTF-8 + null-byte truncation + Windows reserved names + NTFS ADS + RTLO bidi spoofing + shell-exec / double-extension detection — standalone, wires into `b.fileUpload` via `filenameSafety`). All members ship strict / balanced / permissive profiles plus hipaa / pci-dss / gdpr / soc2 compliance postures. `b.guardAll` is the registry + aggregator: every shipped guard ON by default; opt-out per guard with audited reason via `exceptFor: { name: { reason } }`. **As of v0.7.12, `b.fileUpload` and `b.staticServe` wire `b.guardAll.byExtension({ profile: "strict" })` automatically + `b.fileUpload` also wires `b.guardFilename.gate({ profile: "strict" })` as `filenameSafety`** — defense-in-depth applied without any explicit operator wiring. Operators opt out per host-primitive via `contentSafety: null` / `filenameSafety: null` (audited at create() with operator-supplied reason).
- **Communication** — WebSockets with channel/room fan-out across cluster replicas + RFC 6455 §5.5 control-frame size + FIN enforcement on inbound (defends 1 MiB-PING-echoed-as-PONG 2× amplification class) (`b.websocket`, `b.websocketChannels`); outbound WebSocket client (RFC 6455) with PQC-TLS handshake, permessage-deflate negotiation with decompression-bomb cap, fatal UTF-8 validation, control-frame size + FIN enforcement, permanent-error classifier that skips reconnect on 4xx handshake / accept mismatch / bad-subprotocol, exponential-backoff with full jitter (`b.wsClient`); generic distributed pub/sub with cluster-table / Redis PUB/SUB / custom backends (`b.pubsub`); Server-Sent Events with newline-injection refusal in `event:` / `id:` / `data:` / `Last-Event-ID` per CVE-2026-33128 / 29085 / 44217 class (`b.sse`, `b.middleware.sse`); mail with multipart + attachments + DKIM + calendar invites + bounce intake (`b.mail`, `b.mailBounce`); inbound mail authentication — SPF / DMARC / ARC verify + ARC chain signing for relays (`b.mail.spf`, `b.mail.dmarc`, `b.mail.arc`); generic notification dispatcher with operator-supplied transports (`b.notify`); chunked file uploads with per-chunk SHA3-512 verification + atomic finalize + tombstone cleanup (`b.fileUpload`).
- **AI / agentic** — Model Context Protocol server-guard with bearer auth + redirect_uri allowlist + dynamic-register refusal + tool/resource allowlists (CVE-2026-33032 / CVE-2025-6514 / confused-deputy class) (`b.mcp.serverGuard`); GraphQL Federation `_service.sdl` trust-boundary with router-token + nonce store (`b.graphqlFederation`); prompt-injection input classifier (OWASP LLM01:2025 / NIST COSAIS RFI) (`b.ai.input.classify`); A2A signed agent-card primitive (Linux Foundation Agentic AI Foundation v1.x, ML-DSA-87) (`b.a2a`).
- **FTC compliance** — click-to-cancel UX-parity attestation with `ftc-2024` / `ca-sb942` / `strict` postures (`b.darkPatterns`).
- **Observability** — tamper-evident audit chain with SLH-DSA-signed checkpoints, metrics, tracing (OTel pass-through when wired), PII redaction, log-stream sinks (local file rotation, generic webhook, OTLP/HTTP-JSON OR OTLP/gRPC to an OTel collector, AWS CloudWatch Logs via SigV4 with optional autoCreate, RFC 5424 syslog over UDP/TCP/TLS), OTLP/HTTP-JSON exporter for traces + metrics (`b.audit`, `b.metrics`, `b.tracing`, `b.redact`, `b.logStream`, `b.otelExport`); operator-callable boot-time security policy assertions (`b.security.assertProduction`) and tamper-evident config-baseline drift detection signed with the audit-signing key (`b.configDrift`).
- **i18n** — CLDR plural rules, Accept-Language negotiation, Intl formatters, RTL (`b.i18n`).
- **Format helpers** — RFC 4180 CSV with Excel formula-injection prevention (`b.csv`), RFC 9562 UUID v4 + v7 (`b.uuid`), URL-safe slugs (`b.slug`), TZ-aware datetime (`b.time`), ZIP creation (`b.archive`), HMAC-signed cursor pagination (`b.pagination`), HTML form rendering + validation + CSRF (`b.forms`).
- **Production** — cluster leader election with fenced leases over Postgres/SQLite (`b.cluster`); cron + interval scheduler that runs exactly-once globally (`b.scheduler`); retry with full-jitter backoff + circuit breaker (`b.retry`); graceful shutdown (`b.appShutdown`); NTP boot check (`b.ntpCheck`); transactional outbox + dedupe-on-receive inbox so the business-state change and the outbound publish (or the inbound mark-handled) live in the same DB transaction — exactly-once semantics across Postgres / SQLite (`b.outbox`, `b.inbox`); end-to-end-encrypted backup bundles with pre-flush fail-closed mode (`b.backup`); restore with pulled-bundle footprint preflight (`b.restore`); GDPR / PCI / HIPAA-shaped retention rules with multi-stage warn → archive → erase, legal-hold exemptions, dry-run preview, cross-table cascade (`b.retention`).

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
