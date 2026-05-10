"use strict";
/**
 * @module b.compliance
 * @featured true
 * @nav    Compliance
 * @title  Compliance
 *
 * @intro
 *   Top-level compliance-posture coordinator — single source of truth
 *   for "what regulatory regime is this deployment running under?".
 *
 *   `b.compliance.set("hipaa")` cascades the posture into every
 *   framework primitive that owns a posture-conditioned default:
 *   `b.retention` (TTL floors), `b.audit` (ML-DSA-87 chain-signing),
 *   `b.db` (column-policy enforcement), `b.cryptoField` (vacuum-after-
 *   erase). Each primitive merges the matching `POSTURE_DEFAULTS`
 *   entry into its own state and emits a
 *   `compliance.posture.cascade.applied` audit row so operators can
 *   confirm the cascade landed.
 *
 *   Posture overlays follow a union-of-bars rule: when a primitive
 *   knob has different floors per regime (TLS minimum, retention
 *   ceiling, hash-algorithm minimum), the strictest applicable bar
 *   wins. Operators running under a single posture get that posture's
 *   floor; operators running multi-tenant deployments compose
 *   per-tenant by reading `postureDefault(posture, key)` per request
 *   instead of pinning a single global.
 *
 *   Boot-time only — `set()` MUST run before the primitives it
 *   coordinates are first used. Runtime switches throw
 *   `compliance/already-set` because partial cascades produce
 *   half-set state across already-initialized primitives.
 *
 *   Audit emissions: `compliance.posture.set` on success,
 *   `compliance.posture.set_rejected` on unknown / already-set,
 *   `compliance.posture.cascade.applied` / `.skipped` per primitive,
 *   `compliance.posture.cleared` on `clear()`. Grep audit chain to
 *   reconstruct posture history per deployment.
 *
 * @card
 *   Top-level compliance-posture coordinator — single source of truth for "what regulatory regime is this deployment running under?".
 */

var lazyRequire = require("./lazy-require");
var sanctions = require("./compliance-sanctions");
var aiAct     = require("./compliance-ai-act");
var { ComplianceError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var retentionMod  = lazyRequire(function () { return require("./retention"); });
var auditFwk      = lazyRequire(function () { return require("./audit"); });
var dbMod         = lazyRequire(function () { return require("./db"); });
var cryptoFieldMod = lazyRequire(function () { return require("./crypto-field"); });

// Recognised posture names. Aligns with the compliance-posture
// vocabulary every guard / retention floor / etc. accepts. Operators
// passing an unknown name get a typo-surfacing throw at set-time, not
// silent fall-through to no-op.
var KNOWN_POSTURES = Object.freeze([
  // ---- US Federal / Sectoral ----
  "hipaa",       // Health Insurance Portability and Accountability Act
  "pci-dss",     // Payment Card Industry Data Security Standard
  "soc2",        // System and Organization Controls 2
  "sox",         // Sarbanes-Oxley
  "sox-404",     // Sarbanes-Oxley §404 ICFR (DDL change-control + segregation of duties)
  "soc2-cc1.3",  // SOC 2 Trust Services Criterion CC1.3 (segregation of duties)
  "wmhmda",      // Washington My Health My Data Act (added 2026)
  "bipa",        // Illinois Biometric Information Privacy Act (added 2026)
  // ---- US State Privacy ----
  "ccpa",        // California Consumer Privacy Act / CPRA (added 2026)
  // ---- EU / EEA ----
  "gdpr",        // General Data Protection Regulation
  "dora",        // EU Digital Operational Resilience Act
  "nis2",        // EU Network and Information Security Directive 2 (added 2026)
  "cra",         // EU Cyber Resilience Act (added 2026)
  "ai-act",      // EU AI Act (added 2026)
  // ---- Latin America / APAC ----
  "lgpd-br",     // Brazil Lei Geral de Proteção de Dados (added 2026)
  "pipl-cn",     // China Personal Information Protection Law (added 2026)
  "appi-jp",     // Japan Act on Protection of Personal Information (added 2026)
  "pdpa-sg",     // Singapore Personal Data Protection Act (added 2026)
  // ---- Canada / UK ----
  "pipeda-ca",   // Canada Personal Information Protection and Electronic Documents Act (added 2026)
  "uk-gdpr",     // UK General Data Protection Regulation (added 2026)
  // ---- Sectoral expansions (added 2026 — v0.8.24) ----
  "fapi-2.0",        // Financial-grade API 2.0 Final (composes PAR + DPoP + OAuth 2.1 + mTLS)
  "cfpb-1033",       // CFPB §1033 / FDX consumer-financial-data sharing (deadline past for $250B+ banks 2026-04-01)
  "iab-tcf-v2.3",    // IAB Transparency & Consent Framework v2.3 with disclosedVendors (deadline past 2026-02-28)
  "iab-mspa",        // IAB Multi-State Privacy Agreement / Global Privacy Platform universal opt-out
  "tcpa-10dlc",      // TCPA 10DLC carrier-shaped consent + FCC 1:1 disclosure
  "fda-21cfr11",     // FDA 21 CFR Part 11 — audit-trail + electronic signatures (general-purpose subset)
  "fda-annex-11",    // EU GMP Annex 11 — computerized systems (Part-11 equivalent)
  "sec-1.05",        // SEC Cybersecurity Disclosure Item 1.05 — material-incident 8-K filing                                  // allow:raw-byte-literal — regulatory identifier, not bytes
  // ---- US state student-data privacy (F5.1 posture group) ----
  "ny-2-d",          // NY Education Law §2-d
  "il-soppa",        // Illinois Student Online Personal Protection Act
  "ca-sopipa",       // California Student Online Personal Information Protection Act
  "ct-pa-5-2",       // Connecticut Public Act 5-2
  "tx-hb-4504",      // Texas HB 4504                                                                                            // allow:raw-byte-literal — statute identifier, not bytes
  "va-sb-1376",      // Virginia SB 1376                                                                                         // allow:raw-byte-literal — statute identifier, not bytes
  // ---- EU government / cloud-region ----
  "staterramp",      // StateRAMP / TX-RAMP / AZ-RAMP / GovRAMP family (FedRAMP-Moderate cross-walks)
  "irap",            // Australia IRAP / Essential Eight / ISM
  "bsi-c5",          // Germany BSI C5
  "ens-es",          // Spain Esquema Nacional de Seguridad
  "uk-g-cloud",      // UK G-Cloud
]);

var STATE = { posture: null, setAt: null };

function _emitAudit(action, metadata, outcome) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata,
    });
  } catch (_e) { /* audit best-effort */ }
}

/**
 * @primitive b.compliance.set
 * @signature b.compliance.set(posture)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.current, b.compliance.assert, b.compliance.clear, b.compliance.postureDefault
 *
 * Pin the deployment's compliance posture and cascade the matching
 * defaults into every primitive that owns posture-conditioned state
 * (`b.retention`, `b.audit`, `b.db`, `b.cryptoField`). Throws
 * `compliance/unknown-posture` for names outside `KNOWN_POSTURES`,
 * `compliance/already-set` if a different posture is already pinned
 * (runtime switches are forbidden — they create half-set state across
 * already-initialized primitives). Idempotent for the same posture:
 * calling `set("hipaa")` a second time after `set("hipaa")` is a
 * no-op, no audit row, no cascade.
 *
 * Operators wiring multiple regimes pick the strictest single posture
 * here and read per-regime knobs via `postureDefault(posture, key)`
 * for tenant-level overrides — see the @intro union-of-bars note.
 *
 * Emits `compliance.posture.set` (success), `compliance.posture.set_rejected`
 * (unknown/already-set), `compliance.posture.cascade.applied`/`.skipped`
 * per primitive, `compliance.posture.tz_warning` when `process.env.TZ`
 * is set to a non-UTC value under a regulated posture (HIPAA / PCI-DSS /
 * SOX / GDPR / SOC2 / FDA 21 CFR 11).
 *
 * @example
 *   b.compliance.set("hipaa");
 *   b.compliance.current();   // → "hipaa"
 *
 *   // Calling again with the same posture is idempotent:
 *   b.compliance.set("hipaa");   // no-op, no audit row
 *
 *   // Switching to a different posture throws:
 *   try {
 *     b.compliance.set("pci-dss");
 *   } catch (e) {
 *     e.code;   // → "compliance/already-set"
 *   }
 */
function set(posture) {
  if (typeof posture !== "string" || posture.length === 0) {
    throw new ComplianceError("compliance/bad-posture",
      "compliance.set: posture must be a non-empty string, got " +
      JSON.stringify(posture));
  }
  if (KNOWN_POSTURES.indexOf(posture) === -1) {
    _emitAudit("compliance.posture.set_rejected",
      { reason: "unknown-posture", posture: posture }, "denied");
    throw new ComplianceError("compliance/unknown-posture",
      "compliance.set: unknown posture '" + posture + "'; expected one of " +
      KNOWN_POSTURES.join(", "));
  }
  if (STATE.posture && STATE.posture !== posture) {
    // Audit the rejection so an attacker (or operator misconfig) trying
    // to downgrade an already-set posture produces a chain row
    // operators can alert on.
    _emitAudit("compliance.posture.set_rejected",
      { reason: "already-set", current: STATE.posture, attempted: posture },
      "denied");
    throw new ComplianceError("compliance/already-set",
      "compliance.set: posture is already '" + STATE.posture + "' (set at " +
      new Date(STATE.setAt).toISOString() + "). Runtime switches are " +
      "forbidden — they create half-set state across already-initialized " +
      "primitives. Set once at boot.");
  }
  STATE.posture = posture;
  STATE.setAt   = Date.now();
  _emitAudit("compliance.posture.set", { posture: posture });

  // F-POSTURE-1 — cascade the posture into every primitive that owns a
  // posture-conditioned default. Each primitive exposes an
  // `applyPosture(name)` that merges the POSTURE_DEFAULTS entry for the
  // posture into its own state and emits
  // `compliance.posture.cascade.applied` with { primitive, posture }
  // metadata. Cascade is ATOMIC at the chain-emission level — every
  // primitive emits success/skipped, and a single primitive's failure
  // (DB not initialized, retention not wired) emits skipped without
  // failing the cascade. Operators wire DB/retention before set();
  // skipped rows surface in the audit chain so a forensic review can
  // reconstruct the boot order.
  _applyPostureCascade(posture);
  // F-AUD-5 — TZ awareness. Auditors expect timestamps in UTC.
  // process.env.TZ controls Node's local-time conversion for any
  // operator code that uses non-UTC formatters; under regulated
  // postures (hipaa / pci-dss / sox / gdpr / soc2) emit a boot
  // warning if it's set to a non-UTC value or unset (which means
  // host-default which on most cloud images IS UTC but isn't
  // guaranteed). Pure signal — no behavior change.
  var REGULATED = ["hipaa", "pci-dss", "sox", "gdpr", "soc2", "fda-21cfr11"];
  if (REGULATED.indexOf(posture) !== -1) {
    var tz = process.env.TZ;                                                                  // allow:raw-process-env — bootstrap signal, no operator-supplied default needed
    if (typeof tz === "string" && tz !== "UTC" && tz !== "Etc/UTC") {
      _emitAudit("compliance.posture.tz_warning",
        { posture: posture, tz: tz, recommendation: "Set TZ=UTC under regulated postures so audit timestamps align with regulator expectations." },
        "warning");
    }
  }
}

// _applyPostureCascade — F-POSTURE-1. Walks every primitive that
// participates in posture-conditioned defaults and asks it to merge
// the named posture into its state. Each step is best-effort at the
// audit-emission level (a primitive that isn't loaded yet emits
// 'skipped'); each step's success/skipped emits its own audit row so
// operators can confirm the cascade landed without re-reading
// state.posture per primitive.
function _applyPostureCascade(posture) {
  var steps = [
    { primitive: "retention",   resolver: function () { return retentionMod(); } },
    { primitive: "audit",       resolver: function () { return auditFwk();    } },
    { primitive: "db",          resolver: function () { return dbMod();        } },
    { primitive: "cryptoField", resolver: function () { return cryptoFieldMod(); } },
  ];
  for (var i = 0; i < steps.length; i += 1) {
    var step = steps[i];
    var mod;
    try { mod = step.resolver(); }
    catch (_loadErr) { mod = null; }
    if (!mod || typeof mod.applyPosture !== "function") {
      _emitAudit("compliance.posture.cascade.skipped",
        { primitive: step.primitive, posture: posture, reason: "not-loaded-or-no-applyPosture" });
      continue;
    }
    var result;
    try { result = mod.applyPosture(posture); }
    catch (e) {
      _emitAudit("compliance.posture.cascade.skipped",
        { primitive: step.primitive, posture: posture,
          reason: (e && e.message) ? e.message : String(e) },
        "warning");
      continue;
    }
    _emitAudit("compliance.posture.cascade.applied",
      { primitive: step.primitive, posture: posture, applied: result || null });
  }
}

/**
 * @primitive b.compliance.current
 * @signature b.compliance.current()
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.set, b.compliance.assert, b.compliance.describe
 *
 * Read the currently-pinned posture, or `null` if `set()` has not yet
 * run. Cheap; pure read of internal state. Operators rendering an
 * admin-UI banner ("running under HIPAA posture") call this once per
 * page render — no caching needed.
 *
 * @example
 *   b.compliance.current();   // → null
 *   b.compliance.set("hipaa");
 *   b.compliance.current();   // → "hipaa"
 */
function current() {
  return STATE.posture;
}

/**
 * @primitive b.compliance.assert
 * @signature b.compliance.assert(posture)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.current, b.compliance.set
 *
 * Throw `compliance/assertion-failed` if the currently-pinned posture
 * differs from `posture`. Use at the top of a request handler that is
 * only safe to run under a specific regime — fails closed with a
 * stack trace that names the mismatch instead of silently serving
 * under the wrong posture.
 *
 * @example
 *   b.compliance.set("hipaa");
 *   b.compliance.assert("hipaa");   // → no throw
 *
 *   try {
 *     b.compliance.assert("pci-dss");
 *   } catch (e) {
 *     e.code;   // → "compliance/assertion-failed"
 *   }
 */
function assert(posture) {
  if (STATE.posture !== posture) {
    throw new ComplianceError("compliance/assertion-failed",
      "compliance.assert('" + posture + "'): current posture is " +
      JSON.stringify(STATE.posture));
  }
}

/**
 * @primitive b.compliance.clear
 * @signature b.compliance.clear()
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.set, b.compliance.current
 *
 * Reset the pinned posture to `null` and emit a
 * `compliance.posture.cleared` audit row carrying the previous
 * posture. Reserved for tests + operator-controlled tear-down — the
 * primitives that were cascaded into do not roll back their merged
 * defaults, so production code that called `set()` should not call
 * `clear()` mid-life.
 *
 * @example
 *   b.compliance.set("hipaa");
 *   b.compliance.clear();
 *   b.compliance.current();   // → null
 */
function clear() {
  // Reserved for tests + operator-controlled tear-down. Emits an audit
  // row so the chain shows the posture was intentionally cleared.
  if (STATE.posture) {
    _emitAudit("compliance.posture.cleared", { previous: STATE.posture });
  }
  STATE.posture = null;
  STATE.setAt   = null;
}

function _resetForTest() {
  STATE.posture = null;
  STATE.setAt   = null;
}

// Posture → human-readable name + statutory citation + jurisdiction.
// Operators rendering the deployment posture in admin UI / audit logs
// reach for REGIME_MAP[posture] instead of hand-rolling a lookup
// table. The values track the regulatory text and update with the
// framework rather than going stale in operator code.
var REGIME_MAP = Object.freeze({
  "hipaa": {
    name:       "Health Insurance Portability and Accountability Act",
    citation:   "Pub. L. 104-191; 45 CFR Parts 160, 162, 164",
    jurisdiction: "US",
    domain:     "health",
  },
  "pci-dss": {
    name:       "Payment Card Industry Data Security Standard",
    citation:   "PCI Security Standards Council v4.0.1",
    jurisdiction: "international",
    domain:     "payment",
  },
  "soc2": {
    name:       "System and Organization Controls 2",
    citation:   "AICPA Trust Services Criteria",
    jurisdiction: "US",
    domain:     "audit-attestation",
  },
  "sox": {
    name:       "Sarbanes-Oxley Act",
    citation:   "Pub. L. 107-204; 15 U.S.C. §§7201-7266",
    jurisdiction: "US",
    domain:     "financial-reporting",
  },
  "wmhmda": {
    name:       "Washington My Health My Data Act",
    citation:   "RCW 19.373",
    jurisdiction: "US-WA",
    domain:     "health",
  },
  "bipa": {
    name:       "Illinois Biometric Information Privacy Act",
    citation:   "740 ILCS 14",
    jurisdiction: "US-IL",
    domain:     "biometrics",
  },
  "ccpa": {
    name:       "California Consumer Privacy Act / California Privacy Rights Act",
    citation:   "Cal. Civ. Code §§1798.100-1798.199",
    jurisdiction: "US-CA",
    domain:     "privacy",
  },
  "gdpr": {
    name:       "General Data Protection Regulation",
    citation:   "Regulation (EU) 2016/679",
    jurisdiction: "EU",
    domain:     "privacy",
  },
  "dora": {
    name:       "Digital Operational Resilience Act",
    citation:   "Regulation (EU) 2022/2554",
    jurisdiction: "EU",
    domain:     "financial-resilience",
  },
  "nis2": {
    name:       "Network and Information Security Directive 2",
    citation:   "Directive (EU) 2022/2555",
    jurisdiction: "EU",
    domain:     "cybersecurity",
  },
  "cra": {
    name:       "Cyber Resilience Act",
    citation:   "Regulation (EU) 2024/2847",
    jurisdiction: "EU",
    domain:     "product-cybersecurity",
  },
  "ai-act": {
    name:       "Artificial Intelligence Act",
    citation:   "Regulation (EU) 2024/1689",
    jurisdiction: "EU",
    domain:     "ai-governance",
  },
  "lgpd-br": {
    name:       "Lei Geral de Proteção de Dados",
    citation:   "Lei nº 13.709/2018",
    jurisdiction: "BR",
    domain:     "privacy",
  },
  "pipl-cn": {
    name:       "Personal Information Protection Law",
    citation:   "Adopted Aug 20, 2021; effective Nov 1, 2021",
    jurisdiction: "CN",
    domain:     "privacy",
  },
  "appi-jp": {
    name:       "Act on Protection of Personal Information",
    citation:   "Act No. 57 of 2003 (most recent amendment 2022)",
    jurisdiction: "JP",
    domain:     "privacy",
  },
  "pdpa-sg": {
    name:       "Personal Data Protection Act",
    citation:   "Act 26 of 2012",
    jurisdiction: "SG",
    domain:     "privacy",
  },
  "pipeda-ca": {
    name:       "Personal Information Protection and Electronic Documents Act",
    citation:   "S.C. 2000, c. 5",
    jurisdiction: "CA",
    domain:     "privacy",
  },
  "uk-gdpr": {
    name:       "UK General Data Protection Regulation",
    citation:   "Data Protection Act 2018 + retained EU GDPR",
    jurisdiction: "UK",
    domain:     "privacy",
  },
});

/**
 * @primitive b.compliance.describe
 * @signature b.compliance.describe(posture)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.list, b.compliance.posturesByJurisdiction, b.compliance.posturesByDomain
 *
 * Resolve a posture name to its human-readable record:
 * `{ name, citation, jurisdiction, domain }`. Returns `null` for
 * unknown postures. Operators rendering "we run under {name}
 * ({citation})" in admin UI / generated audit reports reach for this
 * instead of hand-rolling a lookup; the values track the regulatory
 * text and update with the framework rather than going stale in
 * operator code.
 *
 * @example
 *   var meta = b.compliance.describe("hipaa");
 *   meta.name;           // → "Health Insurance Portability and Accountability Act"
 *   meta.citation;       // → "Pub. L. 104-191; 45 CFR Parts 160, 162, 164"
 *   meta.jurisdiction;   // → "US"
 *   meta.domain;         // → "health"
 *
 *   b.compliance.describe("not-a-real-posture");   // → null
 */
function describe(posture) {
  return REGIME_MAP[posture] || null;
}

// POSTURE_DEFAULTS — per-posture configuration knobs that primitives
// (b.backup, b.retention, b.audit, b.cryptoField, b.db, etc.) consult
// when the operator hasn't passed an explicit value. Not user-facing
// config — primitives look up here at boot to enforce regulatory
// floors.
//
// Keys per posture:
//   backupEncryptionRequired  — backup.create refuses encrypt:false (F-BUDR-4)
//   auditChainSignedRequired  — audit emissions MUST be ML-DSA-87 chain-signed
//   tlsMinVersion             — minimum TLS version (string e.g. "TLSv1.3")
//   sessionAbsoluteTimeoutMs  — hard session expiry ceiling
//   requireVacuumAfterErase   — F-RTBF-2: cryptoField.eraseRow must call
//                               b.db.vacuumAfterErase({ mode: "full" })
//                               so freed B-tree index pages don't linger
//                               with sealed-column ciphertext readable
//                               from a forensic disk image. GDPR Art. 17
//                               + DPDP §12 + LGPD-BR Art. 18 + PIPL-CN
//                               Art. 47 all require effective erasure;
//                               leftover index residue defeats it.
//
// This table is the single source-of-truth — duplicating values into
// per-primitive defaults would drift the moment a regulator updates.
var POSTURE_DEFAULTS = Object.freeze({
  "hipaa": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "pci-dss": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  false,
  }),
  "gdpr": Object.freeze({
    backupEncryptionRequired: false,           // GDPR Art. 32 says "appropriate" — not mandatory floor // allow:protocol-constant — regulatory article number in prose
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    // GDPR Art. 17 — "right to erasure" includes residual indexes; B-tree
    // pages holding sealed-column ciphertext after a row-erase defeat
    // the right unless followed by a full vacuum.
    requireVacuumAfterErase:  true,
  }),
  "soc2": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  false,
  }),
  "dora": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  false,
  }),
  // LGPD-BR Art. 18 — equivalent right to deletion + residue cleanup.
  "lgpd-br": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // PIPL-CN Art. 47 — deletion right; cross-border residue concerns.
  "pipl-cn": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // India DPDP Act 2023 §12 — right to erasure with effectiveness floor.
  "dpdp": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
});

/**
 * @primitive b.compliance.postureDefault
 * @signature b.compliance.postureDefault(posture, key)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.set, b.compliance.list
 *
 * Look up a single posture-conditioned default without pinning the
 * posture globally. Returns `null` for unknown postures, unknown
 * keys, or empty/non-string inputs. Used by primitives that need to
 * read a regime's floor per-tenant in a multi-tenant deployment
 * where `set()` would over-pin the process.
 *
 * Recognised keys per posture include `backupEncryptionRequired`,
 * `auditChainSignedRequired`, `tlsMinVersion`, and
 * `requireVacuumAfterErase` — the floors enforced by `b.backup`,
 * `b.audit`, the TLS minimum-version gate, and `b.cryptoField`'s
 * residual-erasure pass.
 *
 * @example
 *   b.compliance.postureDefault("hipaa", "tlsMinVersion");
 *   // → "TLSv1.3"
 *
 *   b.compliance.postureDefault("hipaa", "backupEncryptionRequired");
 *   // → true
 *
 *   b.compliance.postureDefault("soc2", "requireVacuumAfterErase");
 *   // → false
 *
 *   b.compliance.postureDefault("hipaa", "no-such-key");
 *   // → null
 *
 *   b.compliance.postureDefault("not-a-real-posture", "tlsMinVersion");
 *   // → null
 */
function postureDefault(posture, key) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  var d = POSTURE_DEFAULTS[posture];
  if (!d) return null;
  return Object.prototype.hasOwnProperty.call(d, key) ? d[key] : null;
}

// posturesByDomain — list every posture that maps to the named
// domain (privacy / health / payment / cybersecurity / etc.).
// Operators rendering compliance dashboards grouped by domain pull
// the per-domain posture list with this; admin UIs that show "we
// satisfy the privacy regimes for {users.country}" use it to pick
// the right posture name without hand-rolling the lookup.
/**
 * @primitive b.compliance.posturesByDomain
 * @signature b.compliance.posturesByDomain(domain)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.posturesByJurisdiction, b.compliance.list, b.compliance.describe
 *
 * Return every posture name whose `REGIME_MAP[p].domain` equals
 * `domain`, in canonical `KNOWN_POSTURES` order. Returns `[]` for
 * empty/non-string inputs and for domains with no matches.
 * Operators rendering compliance dashboards grouped by domain
 * (privacy / health / payment / cybersecurity / etc.) iterate the
 * domain list once and read posture sets from here.
 *
 * @example
 *   b.compliance.posturesByDomain("privacy");
 *   // → ["ccpa", "gdpr", "lgpd-br", "pipl-cn", "appi-jp",
 *   //    "pdpa-sg", "pipeda-ca", "uk-gdpr"]
 *
 *   b.compliance.posturesByDomain("health");
 *   // → ["hipaa", "wmhmda"]
 *
 *   b.compliance.posturesByDomain("payment");
 *   // → ["pci-dss"]
 *
 *   b.compliance.posturesByDomain("not-a-domain");
 *   // → []
 */
function posturesByDomain(domain) {
  if (typeof domain !== "string" || domain.length === 0) return [];
  var out = [];
  var keys = Object.keys(REGIME_MAP);
  for (var i = 0; i < keys.length; i++) {
    if (REGIME_MAP[keys[i]].domain === domain) out.push(keys[i]);
  }
  return out;
}

// posturesByJurisdiction — same shape, keyed off the ISO 3166 alpha-2
// code or `EU` / `international`. Operators handling a multi-region
// deployment (e.g. one that serves users in EU + CA + JP) iterate
// over jurisdiction codes and resolve to per-jurisdiction posture
// configs without hand-rolling the lookup table.
/**
 * @primitive b.compliance.posturesByJurisdiction
 * @signature b.compliance.posturesByJurisdiction(jurisdiction)
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.posturesByDomain, b.compliance.list, b.compliance.describe
 *
 * Return every posture whose `REGIME_MAP[p].jurisdiction` equals
 * `jurisdiction`, in canonical `KNOWN_POSTURES` order. Jurisdiction
 * values are ISO 3166 alpha-2 codes (`US`, `BR`, `CA`, `JP`, `CN`,
 * `SG`, `UK`) plus `EU` and `international`, and `US-`-prefixed
 * state codes (`US-CA`, `US-IL`, `US-WA`). Returns `[]` for
 * empty/non-string inputs and unknown jurisdictions.
 *
 * @example
 *   b.compliance.posturesByJurisdiction("EU");
 *   // → ["gdpr", "dora", "nis2", "cra", "ai-act"]
 *
 *   b.compliance.posturesByJurisdiction("US");
 *   // → ["hipaa", "soc2", "sox"]
 *
 *   b.compliance.posturesByJurisdiction("US-CA");
 *   // → ["ccpa"]
 *
 *   b.compliance.posturesByJurisdiction("XX");
 *   // → []
 */
function posturesByJurisdiction(jurisdiction) {
  if (typeof jurisdiction !== "string" || jurisdiction.length === 0) return [];
  var out = [];
  var keys = Object.keys(REGIME_MAP);
  for (var i = 0; i < keys.length; i++) {
    if (REGIME_MAP[keys[i]].jurisdiction === jurisdiction) out.push(keys[i]);
  }
  return out;
}

// list — returns every posture as a { name, ...regime-map-fields }
// object array, in canonical KNOWN_POSTURES order. Useful for admin
// UIs that render the full set as a dropdown / table.
/**
 * @primitive b.compliance.list
 * @signature b.compliance.list()
 * @since     0.7.27
 * @status    stable
 * @related   b.compliance.describe, b.compliance.posturesByDomain, b.compliance.posturesByJurisdiction
 *
 * Return every documented posture as a
 * `{ posture, name, citation, jurisdiction, domain }` record array,
 * in canonical `KNOWN_POSTURES` order. Postures present in
 * `KNOWN_POSTURES` but missing from `REGIME_MAP` (sectoral identifiers
 * such as `fapi-2.0` or `ny-2-d`) are skipped — `list()` is the
 * "regimes with full metadata" view; full naming awaits the regime
 * map gaining those rows. Useful for admin UIs that render the full
 * set as a dropdown / table without hand-rolling iteration over
 * `REGIME_MAP`.
 *
 * @example
 *   var rows = b.compliance.list();
 *   rows[0].posture;        // → "hipaa"
 *   rows[0].jurisdiction;   // → "US"
 *   rows[0].domain;         // → "health"
 *
 *   // Render as a dropdown:
 *   var options = rows.map(function (r) {
 *     return { value: r.posture, label: r.name + " (" + r.jurisdiction + ")" };
 *   });
 */
function list() {
  var out = [];
  for (var i = 0; i < KNOWN_POSTURES.length; i++) {
    var p = KNOWN_POSTURES[i];
    var meta = REGIME_MAP[p];
    if (!meta) continue;
    out.push({
      posture:      p,
      name:         meta.name,
      citation:     meta.citation,
      jurisdiction: meta.jurisdiction,
      domain:       meta.domain,
    });
  }
  return out;
}

module.exports = {
  set:                    set,
  current:                current,
  assert:                 assert,
  clear:                  clear,
  describe:               describe,
  posturesByDomain:       posturesByDomain,
  posturesByJurisdiction: posturesByJurisdiction,
  list:                   list,
  postureDefault:         postureDefault,
  sanctions:              sanctions,
  aiAct:                  aiAct,
  KNOWN_POSTURES:         KNOWN_POSTURES,
  POSTURE_DEFAULTS:       POSTURE_DEFAULTS,
  REGIME_MAP:             REGIME_MAP,
  ComplianceError:        ComplianceError,
  _resetForTest:          _resetForTest,
};
