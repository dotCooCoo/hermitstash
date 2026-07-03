// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// wiki-concepts — narrative-shaped framework topics that don't belong
// to any single primitive. Each @concept block becomes one wiki page,
// driven by the entries in examples/wiki/wiki.config.js.
//
// This file exports nothing. It exists purely as the source of truth
// for cross-cutting docs. The same JSDoc-comment convention as
// @primitive blocks: single-line tags first, prose body, multi-line
// @section blocks last (each becomes an <h2> on the rendered page).

/**
 * @concept welcome
 * @title   Welcome
 * @nav     Welcome
 * @related b.createApp, b.audit, b.crypto, b.session
 *
 * blamejs is a Node framework for operators who care more about what
 * the wire actually does than how loudly the README claims to do it.
 * Zero npm runtime dependencies. Post-quantum crypto from line zero.
 * Sealed-by-default storage. Audit chain on every operator action.
 *
 * Every primitive on this site is documented from its source file —
 * the `@primitive` JSDoc block above each function IS the wiki page
 * section. Drift between code and docs is structurally impossible:
 * the same diff that changes the function changes the documentation.
 *
 * @section Install
 *   The framework targets Node Active LTS (24+). No transpilation
 *   step, no Babel, no build pipeline. CommonJS, `var`, `node:`
 *   builtins, no shipped TypeScript.
 *
 *   ```bash
 *   npm install @blamejs/core
 *   ```
 *
 *   Then in any `.js` file:
 *
 *   ```javascript
 *   var b = require("@blamejs/core");
 *   ```
 *
 *   Every public primitive is accessible from the `b` namespace —
 *   `b.crypto`, `b.audit`, `b.session`, `b.uuid`, etc. Browse the
 *   API index for the full list, or jump to a concern group from the
 *   sidebar.
 *
 * @section First server
 *   `b.createApp({ dataDir, routes })` boots the framework with
 *   strict CSP, CSRF, origin verification, bot-guard, encrypted
 *   sessions, sealed storage, and the audit chain wired into the
 *   request lifecycle. Operators who do nothing get the same posture
 *   as operators who carefully read every config option.
 *
 *   ```javascript
 *   var b = require("@blamejs/core");
 *
 *   var app = await b.createApp({
 *     dataDir: "./data",
 *     routes: function (router) {
 *       router.get("/", function (req, res) {
 *         b.render.htmlString(res, "<h1>Hello from blamejs</h1>");
 *       });
 *     },
 *   });
 *
 *   await app.listen({ port: 3000 });
 *   // → server listening on :3000 with CSP / CSRF / origin / audit / sealed storage all on.
 *   ```
 *
 *   That snippet is a production-posture server. Every default that
 *   matters is already on. Read the Concepts pages for the details.
 *
 * @section Sealed storage example
 *   Every database column except IDs / timestamps / FK references is
 *   sealed at rest by default. The framework's vault wraps each
 *   value in a versioned envelope with AAD bound to the row context.
 *
 *   ```javascript
 *   var b = require("@blamejs/core");
 *
 *   await b.db.declareTable({
 *     name: "users",
 *     columns: { id: "TEXT PRIMARY KEY", email: "TEXT NOT NULL", note: "TEXT" },
 *     sealedFields: ["note"],
 *   });
 *
 *   await b.db.insert("users", { id: b.uuid.v7(), email: "a@b.com", note: "PHI here" });
 *   // The `note` column lands as a versioned ciphertext on disk; reads
 *   // through b.db transparently decrypt for application code.
 *   ```
 *
 * @section Audit chain example
 *   Every operator action emits a tamper-evident audit row. The chain
 *   is hash-linked and periodically signed with SLH-DSA-SHAKE-256f
 *   (FIPS 205 stateless hash signature).
 *
 *   ```javascript
 *   b.audit.emit({
 *     event:    "wiki.page.edited",
 *     actor:    req.user.id,
 *     subject:  page.slug,
 *     outcome:  "success",
 *     metadata: { from: prev.updatedAt, to: now },
 *   });
 *   // Returns immediately; the row lands on the audit chain
 *   // synchronously, prev_hash linked, before the request response.
 *   ```
 *
 * @section How to read this site
 *   - **Concepts** — the framework's posture and patterns: security
 *     defaults, envelope versioning, validation discipline,
 *     compliance postures, modernity posture.
 *   - **Reference** — auto-generated tables: every error class, every
 *     env var, every CLI command, every vendored dep, the full API
 *     index.
 *   - **Tools / Validation / etc.** — per-namespace primitive guides,
 *     each rendered straight from `@primitive` source comments. The
 *     code↔docs link is structural, not aspirational.
 *
 * @section What's next
 *   The wiki is in active migration. New namespaces appear in the
 *   sidebar as their `@primitive` blocks land in the source. The
 *   API index lists every primitive currently documented;
 *   undocumented surface still works in code but isn't yet wiki-
 *   visible.
 *
 *   For framework rules + design decisions read the **Concepts**
 *   pages. For runtime configuration read **Reference / Environment
 *   variables**. For day-to-day operator tasks read **Reference /
 *   CLI commands**.
 */

/**
 * @concept security-defaults
 * @title   Security defaults
 * @nav     Concepts
 * @related b.middleware, b.audit, b.session, b.csrf
 *
 * Every blamejs primitive ships with hostile-input handling,
 * transport hardening, and audit emission already wired into the
 * request lifecycle. Operators who do nothing get the same posture
 * as operators who carefully read every config option.
 *
 * Defaults are *not* opt-in. CSRF, origin verification, bot-guard,
 * sealed storage, encrypted sessions, fetch-metadata enforcement,
 * cookie prefixes (`__Host-` / `__Secure-`), DNS-over-HTTPS, and
 * Trusted Types are wired into `b.createApp()` — not behind config
 * flags an operator might forget to set.
 *
 * @section Why defaults, not config?
 *   Frameworks that ship insecure defaults rely on operators reading
 *   docs, copying the right snippet, and never breaking that snippet
 *   during refactors. Real codebases drift. A bot-guard that ships
 *   disabled in the example app gets copied disabled into production.
 *
 *   blamejs inverts this: every defense ships ON, and the operator
 *   must explicitly disable each with an audited reason. The audit
 *   chain captures every disable so a future reviewer can see exactly
 *   what was loosened and why.
 *
 * @section If a default trips a test, fix the test
 *   The temptation to disable a security default to make a test pass
 *   is the single largest source of long-term drift. blamejs's
 *   example apps and integration tests run with the production
 *   default chain enabled. When CSRF / origin / bot-guard / rate-
 *   limit blocks a fixture: send realistic browser headers (Origin,
 *   Sec-Fetch-Site, User-Agent) instead of disabling the middleware.
 *
 * @section Strict CSP, no `unsafe-inline`
 *   The default Content-Security-Policy drops `'unsafe-inline'` from
 *   `style-src` and `script-src`. Inline elements opt in via
 *   `cspNonce`; pages with no inline elements need no nonce at all.
 *   The default applies to every example app the framework ships.
 */

/**
 * @concept envelope-versioning
 * @title   Envelope versioning
 * @nav     Concepts
 * @related b.crypto, b.vault, b.audit, b.session
 *
 * Every ciphertext, every signed audit row, every persisted session
 * ships inside a versioned envelope. The version byte is the
 * framework's lever for rolling crypto algorithms forward without
 * breaking a single piece of legacy data on disk.
 *
 * Every primitive that emits crypto bytes (`b.crypto.encryptEnvelope`,
 * `b.vault.seal`, `b.audit.sign`, `b.session.encrypt`, …) writes the
 * same envelope shape: `{ v, alg, kid, fixedInfo, ct, aad }`. Decrypt
 * paths route on `v` + `alg` — old envelopes keep working when the
 * framework rolls forward.
 *
 * @section Key rotation without re-encryption
 *   The `kid` field references the key by id, not by value. Operators
 *   add a new key (`vault-2026-06`); new envelopes get the new `kid`;
 *   old envelopes keep their old `kid` and decrypt against the
 *   historical key in the keyring. Background re-encryption is a
 *   deliberate operator action, not a hidden migration.
 *
 * @section Algorithm rollover
 *   When a new KEM/cipher pair is added (e.g. `x-wing+xchacha`
 *   alongside `ml-kem-1024+xchacha`), the new pair becomes the
 *   default for fresh envelopes. Decrypt paths still route on `alg`
 *   — old envelopes resolve to the old pair via the keyring. The
 *   framework refuses to drop a registered algorithm until every
 *   on-disk envelope has been re-encrypted to a newer version.
 *
 * @section Why AAD matters
 *   Every envelope binds AAD (additional authenticated data) to the
 *   ciphertext. The AAD is the row id, the user id, the table name,
 *   the request method — whatever context determines whether this
 *   ciphertext was meant to be read here. An attacker who copies a
 *   ciphertext from row A to row B can't decrypt at row B because
 *   the AAD doesn't match. This defends the entire class of replay-
 *   style attacks where one user's ciphertext is reused as another's.
 */

/**
 * @concept validation-discipline
 * @title   Validation discipline
 * @nav     Concepts
 * @related b.audit, b.observability, b.requestHelpers, b.frameworkError
 *
 * Different layers of the framework treat bad input differently — on
 * purpose. A boot-time misconfiguration must crash the process; a
 * hot-path observability sink must drop silent rather than crash the
 * request that triggered it; a defensive request-shape reader must
 * return a sensible default. blamejs picks one of three behaviors per
 * primitive and documents the choice.
 *
 * @section Config-time / entry-point: throw
 *   Primitives that receive operator input at boot or app
 *   construction throw a `TypeError` on bad input. The operator
 *   catches the typo at deploy time, never at request time. Examples:
 *   `b.constants.TIME.minutes(n)`, `b.protocolDispatcher.create(opts)`,
 *   `b.frameworkError.defineClass(opts)`.
 *
 * @section Hot-path observability sinks: drop silent
 *   Primitives that emit on every request — audit, observability,
 *   metrics — must never crash the request that triggered them. They
 *   wrap their internal validation in `try/catch` and drop the bad
 *   call silently. Each is marked "drop-silent — by design" in its
 *   docstring. Operators who need to surface drops set
 *   `BLAMEJS_OBSERVABILITY_STRICT=1` to promote drops to errors.
 *
 * @section Request-shape readers: return defaults
 *   Primitives that read per-request shape (route, headers, query)
 *   return a defaulted sensible value rather than throwing on missing
 *   or garbage input. A request with no `Origin` header must still
 *   resolve *some* answer; throwing here means a request crash for a
 *   header the client legitimately omitted.
 *
 * @section Picking consciously
 *   Every new primitive picks one tier and documents it. The choice
 *   surfaces in the source comment + the JSDoc + the wiki page.
 *   Default-by-accident is the bug class this discipline closes.
 */

/**
 * @concept compliance-postures
 * @title   Compliance postures
 * @nav     Concepts
 * @related b.compliance, b.dora, b.retention, b.audit
 *
 * Compliance regimes (HIPAA, PCI-DSS, GDPR, SOC 2, DORA, NIS 2, CRA,
 * etc.) overlap heavily — they share retention floors, encryption
 * floors, audit floors, breach-notification windows. blamejs collapses
 * the overlap into a **union-of-bars** strategy: pick every regime
 * that applies, and the framework computes the strictest setting
 * that satisfies all of them.
 *
 * @section Setting a posture
 *   `b.compliance.set({ postures: ["hipaa", "pci-dss", "gdpr",
 *   "soc2"] })`. The call cascades into every framework primitive
 *   that exposes a posture-aware default: retention floors, audit
 *   signing requirements, password complexity, session lifetimes,
 *   log redaction, mTLS profiles, TLS minimums.
 *
 * @section Conflict resolution
 *   When two postures disagree, the strictest setting wins. SOC 2's
 *   1-year audit-retention floor is shorter than HIPAA's 6-year, so
 *   joint posture takes 6 years. Documented exceptions list the
 *   specific cases where strictest-wins doesn't apply.
 *
 * @section Reading the resolved posture
 *   `b.compliance.current()` returns the resolved bundle:
 *   `{ active: ["hipaa","pci-dss"], retentionFloorDays: 2190,
 *   auditSigningRequired: true, … }`. Every primitive reads this at
 *   boot to compute its tightened defaults. Operators inspect the
 *   resolved bundle to confirm the cascade matches expectations.
 */

/**
 * @concept modernity-posture
 * @title   Modernity posture
 * @nav     Concepts
 * @related b.crypto, b.network, b.auth, b.middleware
 *
 * blamejs anchors its defaults to the *current* bar — the active
 * LTS, the current TLS minimum, the post-quantum primitives
 * standardized today — not the broadest-compatible older option.
 * Frameworks that pin to "what most people support" entrench
 * yesterday's posture as tomorrow's default.
 *
 * @section Node.js: Active LTS, no transpilation
 *   The framework runs on Node Active LTS as shipped — currently
 *   Node 24+. No Babel, no TypeScript build, no transpilation step.
 *   Every transpilation hop is a supply-chain hop and a debug-loss
 *   hop. CommonJS, `var`, `node:`-prefixed builtins.
 *
 * @section TLS 1.3 minimum, no fallbacks
 *   Inbound and outbound TLS both refuse anything below 1.3. ALPN
 *   announces `h2` first; HTTP/1.1 only on opt-in. ECH is enabled
 *   when the OS / Node version supports it; SVCB / HTTPS records
 *   are honored on outbound DNS. OCSP stapling is required on
 *   inbound listeners; CT SCTs are validated on outbound dialing.
 *
 * @section Post-quantum first
 *   Default symmetric: **XChaCha20-Poly1305** (extended-nonce, 256-
 *   bit key). Default KEM: **ML-KEM-1024 hybridized with X25519**
 *   (FIPS 203 + classical safety net). Default KDF: **SHAKE256**.
 *   Default signature: **SLH-DSA-SHAKE-256f** for audit; **ML-DSA**
 *   for outbound where size matters. No AES-GCM, SHA-256, P-256,
 *   or classical-only ECDH as defaults.
 *
 * @section Passwords: Argon2id only
 *   The framework refuses to verify a hash that doesn't start with
 *   `$argon2id$`. No PBKDF2 or bcrypt fallback. Operators with
 *   legacy hashes migrate at first login (the verify path detects +
 *   re-hashes).
 *
 * @section LTS calendar
 *   Every major version ships with a 24-month security-only patch
 *   calendar. The calendar is published at blamejs.com/lts with the
 *   next-major's breaking-change list visible during the deprecation
 *   window. Deprecation warnings ship at least one minor before
 *   removal. No silent breaking changes in minor versions.
 */
