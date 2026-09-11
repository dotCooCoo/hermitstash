// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var audit         = lazyRequire(function () { return require("./audit"); });
var auditEmit     = require("./audit-emit");
var retentionMod  = lazyRequire(function () { return require("./retention"); });
var db            = lazyRequire(function () { return require("./db"); });
var cryptoField   = lazyRequire(function () { return require("./crypto-field"); });
var redact        = lazyRequire(function () { return require("./redact"); });

var OUTBOUND_DLP_FLOOR_POSTURES = Object.freeze([
  "hipaa", "pci-dss", "gdpr", "soc2", "fapi-2.0", "fapi-2.0-message-signing",
]);

var KNOWN_POSTURES = Object.freeze([
  "hipaa",
  "pci-dss",
  "soc2",
  "sox",
  "sox-404",
  "soc2-cc1.3",
  "wmhmda",
  "bipa",
  "ccpa",
  "gdpr",
  "dora",
  "nis2",
  "cra",
  "ai-act",
  "eu-ai-act",
  "ca-ab-853",
  "cac-genai-label",
  "lgpd-br",
  "pipl-cn",
  "appi-jp",
  "pdpa-sg",
  "pipeda-ca",
  "uk-gdpr",
  "fapi-2.0",
  "fapi-2.0-message-signing",
  "cfpb-1033",
  "iab-tcf-v2.3",
  "iab-mspa",
  "tcpa-10dlc",
  "fda-21cfr11",
  "fda-annex-11",
  "sec-17a-4",
  "finra-4511",
  "sec-1.05",
  "ny-2-d",
  "il-soppa",
  "ca-sopipa",
  "ct-pa-5-2",
  "tx-hb-4504",
  "va-sb-1376",
  "staterramp",
  "irap",
  "bsi-c5",
  "ens-es",
  "uk-g-cloud",
  "modpa",
  "nydfs-500",
  "hipaa-2026",
  "quebec-25",
  "vcdpa",
  "co-cpa",
  "ctdpa",
  "ucpa",
  "tdpsa",
  "or-cpa",
  "mt-cdpa",
  "ia-icdpa",
  "in-indpa",
  "de-dpdpa",
  "nh-nhpa",
  "nj-njdpa",
  "ky-kcdpa",
  "tn-tipa",
  "mn-mncdpa",
  "ri-ricpa",
  "ne-dpa",
  "nv-sb370",
  "ca-aadc",
  "ct-sb3",
  "tx-cubi",
  "fl-fdbr",
  "co-ai",
  "il-hb3773",
  "tx-traiga",
  "ut-aipa",
  "nyc-ll144",
  "ca-tfaia",
  "kr-ai-basic",
  "cn-ai-label",
  "iso-42001",
  "iso-23894",
  "ca-sb942",
  "ca-ab853",
  "eaa",
  "wcag-2-2",
  "eu-data-act",
  "hitech",
  "ferpa",
  "dpdp",
  "coppa",
  "coppa-2025",
  "glba-safeguards",
  "uk-duaa",
  "cl-pdpa",
  "mx-lfpdppp",
  "ar-pdpa",
  "pipa-kr",
  "au-privacy",
  "th-pdpa",
  "vn-pdp",
  "id-pdp",
  "my-pdpa",
  "ny-safe-kids",
  "ny-saffe",
  "md-kids-code",
  "vt-aadc",
  "gina",
  "vppa",
  "can-spam",
  "il-gipa",
  "hhs-repro-24",
  "nist-pf-1.1",
  "dsa",
  "dga",
  "eu-cer",
  "eu-cyber-sol",
  "eidas-2",
  "cmmc-2.0",
  "cjis-v6",
  "iso-27001-2022",
  "iso-27002-2022",
  "iso-27017",
  "iso-27018",
  "iso-27701",
  "nist-800-66-r2",
  "ehds",
  "circia",
  "nist-800-53",
  "nist-ai-rmf-1.0",
  "iso-42001-2023",
  "iso-23894-2023",
  "owasp-llm-top-10-2025",
  "owasp-asvs-v5.0",
  "nist-800-218-ssdf",
  "nist-800-82-r3",
  "nist-800-63b-rev4",
  "iec-62443-3-3",
  "fedramp-rev5-moderate",
  "hipaa-security-rule",
  "hitrust-csf-v11.4",
  "nerc-cip-007-6",
  "psd2-rts-sca",
  "swift-cscf-v2026",
  "slsa-v1.0-build-l3",
  "vex-csaf-2.1",
  "cyclonedx-v1.6",
  "spdx-v3.0",
  "owasp-wstg-v5",
  "ptes",
  "nist-800-115",
  "cwe-top-25-2024",
  "cis-controls-v8",
  "cmmc-2.0-level-2",
  "cmmc-2.0-level-1",
  "cmmc-2.0-level-3",
  "42-cfr-part-2",
  "hti-1",
  "uscdi-v4",
  "irs-1075",
  "nist-800-172-r3",
  "tlp-2.0",
  "soci-au",
  "ffiec-cat-2",
  "cri-profile-v2.0",
  "m-22-09",
  "m-22-18",
  "nist-800-53-r5-privacy",
  "nist-ai-600-1-genai",
  "nist-csf-2.0",
  "sb-53",
  "nyc-ll144-2024",
]);

var ARTIFACT_STANDARDS = Object.freeze([
  "cyclonedx-v1.6",
  "spdx-v3.0",
  "vex-csaf-2.1",
]);

var STATE = { posture: null, setAt: null, fipsMode: false };

var _emitAudit = auditEmit.emit;

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

  if (ARTIFACT_STANDARDS.indexOf(posture) !== -1) {
    _emitAudit("compliance.posture.format_as_regime",
      { posture: posture, artifactStandards: ARTIFACT_STANDARDS,
        recommendation: "Artifact standards describe what SBOM/VEX format the deployment emits — not the regulatory floor. Pin the underlying regime (e.g. 'nist-800-218-ssdf', 'fedramp-rev5-moderate') and surface emitted formats via b.compliance.artifactStandards()." },
      "warning");
  }

  var FIPS_BOUNDARY_POSTURES = ["fedramp-rev5-moderate", "cmmc-2.0-level-3"];
  if (FIPS_BOUNDARY_POSTURES.indexOf(posture) !== -1 && !STATE.fipsMode) {
    _emitAudit("compliance.posture.fips_conflict",
      { posture: posture,
        cryptoDefaults: "PQC-first (ML-KEM-1024 / SLH-DSA-SHAKE-256f / XChaCha20-Poly1305 / SHA3-512)",
        fipsMode: false,
        recommendation: "Call b.compliance.fipsMode(true) BEFORE b.compliance.set() to switch b.audit.sign to FIPS-140-3 validated AES-GCM + SHA-384, or document the PQC-first deviation in the SSP." },
      "warning");
  }

  _applyPostureCascade(posture);
  var REGULATED = ["hipaa", "pci-dss", "sox", "gdpr", "soc2", "fda-21cfr11"];
  if (REGULATED.indexOf(posture) !== -1) {
    var tz = process.env.TZ;                                                                  // allow:raw-process-env-bootstrap — bootstrap signal, no operator-supplied default needed
    if (typeof tz === "string" && tz !== "UTC" && tz !== "Etc/UTC") {
      _emitAudit("compliance.posture.tz_warning",
        { posture: posture, tz: tz, recommendation: "Set TZ=UTC under regulated postures so audit timestamps align with regulator expectations." },
        "warning");
    }
  }

  if (OUTBOUND_DLP_FLOOR_POSTURES.indexOf(posture) !== -1) {
    var dlpInstalled = false;
    try { dlpInstalled = redact().isOutboundDlpInstalled() === true; }
    catch (_e) { dlpInstalled = false; }
    if (!dlpInstalled) {
      _emitAudit("compliance.posture.outbound_dlp_unwired",
        { posture: posture,
          recommendation: "compliance.set does not auto-install outbound DLP — it holds no httpClient / mail / webhook handles. Call b.redact.installForPosture('" + posture + "', { httpClient, mail, webhook }) with your primitive instances so outbound payloads are classified (CWE-200 / CWE-201)." },
        "warning");
    }
  }
}

function _applyPostureCascade(posture) {
  var steps = [
    { primitive: "retention",   resolver: function () { return retentionMod(); } },
    { primitive: "audit",       resolver: function () { return audit();       } },
    { primitive: "db",          resolver: function () { return db();        } },
    { primitive: "cryptoField", resolver: function () { return cryptoField(); } },
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
  if (STATE.posture) {
    _emitAudit("compliance.posture.cleared", { previous: STATE.posture });
  }
  STATE.posture = null;
  STATE.setAt   = null;
  _applyPostureCascade(null);
}

function _resetForTest() {
  STATE.posture  = null;
  STATE.setAt    = null;
  STATE.fipsMode = false;
}

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
  "eu-ai-act": {
    name:       "Artificial Intelligence Act",
    citation:   "Regulation (EU) 2024/1689",
    jurisdiction: "EU",
    domain:     "ai-governance",
  },
  "ca-ab-853": {
    name:       "Model-Generated Content Disclosure Act",
    citation:   "California AB-853 (effective 2026)",
    jurisdiction: "US-CA",
    domain:     "ai-governance",
  },
  "cac-genai-label": {
    name:       "Generative AI Service Measures (synthetic-content labelling)",
    citation:   "China CAC Order; effective 2023-08, 2024 labelling amendment",
    jurisdiction: "CN",
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
  "fapi-2.0-message-signing": {
    name:        "FAPI 2.0 Message Signing Profile",
    citation:    "OpenID Foundation FAPI 2.0 Message Signing — Final",
    jurisdiction: "INTL",
    domain:      "financial",
  },
  "modpa": {
    name:        "Maryland Online Data Privacy Act",
    citation:    "Md. Code Ann., Com. Law §§14-4601 et seq. (effective 2025-10-01)",
    jurisdiction: "US-MD",
    domain:      "privacy",
  },
  "nydfs-500": {
    name:        "NYDFS 23 NYCRR 500 Amendment 2",
    citation:    "23 NYCRR Part 500 (Second Amendment, effective 2024-11-01 with rolling phase-in)",
    jurisdiction: "US-NY",
    domain:      "financial",
  },
  "hipaa-2026": {
    name:        "HIPAA Security Rule (2026 Final)",
    citation:    "45 CFR Parts 160, 162, 164 — HHS Final Rule (effective 2026-Q4)",
    jurisdiction: "US",
    domain:      "health",
  },
  "quebec-25": {
    name:        "Loi 25 (Quebec — final phase)",
    citation:    "An Act to modernize legislative provisions as regards the protection of personal information (Final phase 2026-09-22)",
    jurisdiction: "CA-QC",
    domain:      "privacy",
  },
  "vcdpa":     { name: "Virginia Consumer Data Protection Act",       citation: "Va. Code §59.1-575 et seq. (effective 2023-01-01)", jurisdiction: "US-VA", domain: "privacy" },
  "co-cpa":    { name: "Colorado Privacy Act",                         citation: "C.R.S. §6-1-1301 et seq. (effective 2023-07-01)", jurisdiction: "US-CO", domain: "privacy" },
  "ctdpa":     { name: "Connecticut Data Privacy Act",                 citation: "Conn. Gen. Stat. §42-515 et seq. (effective 2023-07-01)", jurisdiction: "US-CT", domain: "privacy" },
  "ucpa":      { name: "Utah Consumer Privacy Act",                    citation: "Utah Code §13-61-101 et seq. (effective 2023-12-31)", jurisdiction: "US-UT", domain: "privacy" },
  "tdpsa":     { name: "Texas Data Privacy and Security Act",          citation: "Tex. Bus. & Com. Code §541.001 et seq. (effective 2024-07-01)", jurisdiction: "US-TX", domain: "privacy" },
  "or-cpa":    { name: "Oregon Consumer Privacy Act",                  citation: "Or. Rev. Stat. §646A.570 et seq. (effective 2024-07-01)", jurisdiction: "US-OR", domain: "privacy" },
  "mt-cdpa":   { name: "Montana Consumer Data Privacy Act",            citation: "Mont. Code §30-14-2801 et seq. (effective 2024-10-01)", jurisdiction: "US-MT", domain: "privacy" },
  "ia-icdpa":  { name: "Iowa Consumer Data Protection Act",            citation: "Iowa Code §715D (effective 2025-01-01)", jurisdiction: "US-IA", domain: "privacy" },
  "in-indpa":  { name: "Indiana Consumer Data Protection Act",         citation: "Ind. Code §24-15 (effective 2026-01-01)", jurisdiction: "US-IN", domain: "privacy" },
  "de-dpdpa":  { name: "Delaware Personal Data Privacy Act",           citation: "6 Del. Code Ch. 12D (effective 2026-01-01)", jurisdiction: "US-DE", domain: "privacy" },
  "nh-nhpa":   { name: "New Hampshire SB 255 Consumer Privacy Act",    citation: "NH RSA Chapter 507-H (effective 2025-01-01)", jurisdiction: "US-NH", domain: "privacy" },
  "nj-njdpa":  { name: "New Jersey Data Privacy Act",                  citation: "N.J. Rev. Stat. §56:8-166.4 et seq. (effective 2025-01-15)", jurisdiction: "US-NJ", domain: "privacy" },
  "ky-kcdpa":  { name: "Kentucky Consumer Data Protection Act",        citation: "Ky. Rev. Stat. §367.3611 et seq. (effective 2026-01-01)", jurisdiction: "US-KY", domain: "privacy" },
  "tn-tipa":   { name: "Tennessee Information Protection Act",         citation: "Tenn. Code §47-18-3201 et seq. (effective 2025-07-01)", jurisdiction: "US-TN", domain: "privacy" },
  "mn-mncdpa": { name: "Minnesota Consumer Data Privacy Act",          citation: "Minn. Stat. §325O (effective 2025-07-31)", jurisdiction: "US-MN", domain: "privacy" },
  "ri-ricpa":  { name: "Rhode Island Consumer Privacy Act",            citation: "R.I. Gen. Laws §6-48.1 (effective 2026-01-01)", jurisdiction: "US-RI", domain: "privacy" },
  "ne-dpa":    { name: "Nebraska Data Privacy Act",                    citation: "Neb. Rev. Stat. §87-1101 et seq. (effective 2025-01-01)", jurisdiction: "US-NE", domain: "privacy" },
  "nv-sb370":  { name: "Nevada SB 370 Consumer Health Data Privacy",   citation: "Nev. Rev. Stat. §603A (consumer-health amendments, effective 2024-03-31)", jurisdiction: "US-NV", domain: "health" },
  "ca-aadc":   { name: "California Age-Appropriate Design Code Act",   citation: "Cal. Civ. Code §1798.99.28 et seq. (partial preliminary injunction NetChoice v. Bonta)", jurisdiction: "US-CA", domain: "privacy" },
  "ct-sb3":    { name: "Connecticut SB 3 Consumer Health Data",        citation: "Conn. P.A. 23-56 (effective 2023-07-01)", jurisdiction: "US-CT", domain: "health" },
  "tx-cubi":   { name: "Texas Capture or Use of Biometric Identifier", citation: "Tex. Bus. & Com. Code §503.001 (effective 2009-09-01)", jurisdiction: "US-TX", domain: "biometric" },
  "fl-fdbr":   { name: "Florida Digital Bill of Rights",              citation: "Fla. Stat. §501.701 et seq. SB 262 (effective 2024-07-01)", jurisdiction: "US-FL", domain: "privacy" },
  "co-ai":       { name: "Colorado AI Act",                            citation: "C.R.S. §6-1-1701 et seq. SB24-205 (postponed to 2026-06-30; enforcement stayed)", jurisdiction: "US-CO", domain: "ai-governance" },
  "il-hb3773":   { name: "Illinois HB 3773 — AI in Employment",        citation: "775 ILCS 5 IHRA AI amendment (effective 2026-01-01)", jurisdiction: "US-IL", domain: "ai-governance" },
  "tx-traiga":   { name: "Texas Responsible AI Governance Act",        citation: "Tex. Bus. & Com. Code Ch. 552 HB 149 (effective 2026-01-01)", jurisdiction: "US-TX", domain: "ai-governance" },
  "ut-aipa":     { name: "Utah AI Disclosure Act (UAIPA)",             citation: "Utah Code §13-2-12 SB149 + 2025 amendments (sunset 2027-07-01)", jurisdiction: "US-UT", domain: "ai-governance" },
  "nyc-ll144":   { name: "NYC Automated Employment Decision Tools Law", citation: "NYC Admin. Code §20-870 et seq. Local Law 144 (in force 2023-07-05)", jurisdiction: "US-NY-NYC", domain: "ai-governance" },
  "ca-tfaia":    { name: "California Transparency in Frontier AI Act",  citation: "Cal. Bus. & Prof. Code §22757.10 et seq. SB 53 (effective 2026-01-01)", jurisdiction: "US-CA", domain: "ai-governance" },
  "kr-ai-basic": { name: "South Korea AI Basic Act",                    citation: "Framework Act on Development of AI (effective 2026-01-22)", jurisdiction: "KR", domain: "ai-governance" },
  "cn-ai-label": { name: "China — Measures for Labelling AI-Generated Content", citation: "CAC + MIIT + Ministry of Public Security + NRTA Order (effective 2025-09-01)", jurisdiction: "CN", domain: "ai-governance" },
  "iso-42001":   { name: "ISO/IEC 42001 — AI Management System",        citation: "ISO/IEC 42001:2023", jurisdiction: "international", domain: "ai-governance" },
  "iso-23894":   { name: "ISO/IEC 23894 — AI Risk Management",          citation: "ISO/IEC 23894:2023", jurisdiction: "international", domain: "ai-governance" },
  "ca-sb942":    { name: "California Gen-AI Provenance Disclosure",     citation: "Cal. Bus. & Prof. Code §22757 SB-942 (effective 2026-08-02)", jurisdiction: "US-CA", domain: "content-credentials" },
  "ca-ab853":    { name: "California Platform Gen-AI Detection",        citation: "Cal. Bus. & Prof. Code §22757 AB-853 (effective 2026-08-02)", jurisdiction: "US-CA", domain: "content-credentials" },
  "eaa":         { name: "EU Accessibility Act",                        citation: "Directive (EU) 2019/882 (effective 2025-06-28)", jurisdiction: "EU", domain: "accessibility" },
  "wcag-2-2":    { name: "W3C Web Content Accessibility Guidelines 2.2", citation: "W3C Recommendation (Oct 2023)", jurisdiction: "international", domain: "accessibility" },
  "eu-data-act": { name: "EU Data Act",                                 citation: "Regulation (EU) 2023/2854 (effective 2025-09-12)", jurisdiction: "EU", domain: "data-sharing" },
  "hitech":      { name: "Health Information Technology for Economic and Clinical Health Act", citation: "Pub. L. 111-5, Title XIII, Subtitle D (2009)", jurisdiction: "US", domain: "health" },
  "ferpa":       { name: "Family Educational Rights and Privacy Act",   citation: "20 U.S.C. §1232g; 34 CFR Part 99", jurisdiction: "US", domain: "student-records" },
  "dpdp":        { name: "Digital Personal Data Protection Act 2023",   citation: "Act 22 of 2023 (India; rules pending)", jurisdiction: "IN", domain: "privacy" },
  "coppa":           { name: "Children's Online Privacy Protection Act",         citation: "15 U.S.C. §§6501-6506; 16 CFR Part 312 (effective 2000-04-21)", jurisdiction: "US", domain: "child-privacy" },
  "coppa-2025":      { name: "COPPA 2025 Amendment",                              citation: "FTC final rule (2025-04-22; effective 2026-06-23) — biometric expansion + knowing-collection-13-and-under disclosure", jurisdiction: "US", domain: "child-privacy" },
  "glba-safeguards": { name: "GLBA Safeguards Rule 2024 Amendment",               citation: "16 CFR Part 314 (effective 2024-05-13)", jurisdiction: "US", domain: "financial-privacy" },
  "gina":            { name: "Genetic Information Nondiscrimination Act",        citation: "Pub. L. 110-233; 42 U.S.C. §2000ff et seq. (effective 2009-11-21)", jurisdiction: "US", domain: "genetic-privacy" },
  "vppa":            { name: "Video Privacy Protection Act",                     citation: "18 U.S.C. §2710 (effective 1988-11-05)", jurisdiction: "US", domain: "consumer-privacy" },
  "can-spam":        { name: "CAN-SPAM Act",                                     citation: "15 U.S.C. §§7701-7713; 16 CFR Part 316 (effective 2004-01-01)", jurisdiction: "US", domain: "consumer-privacy" },
  "il-gipa":         { name: "Illinois Genetic Information Privacy Act",         citation: "410 ILCS 513 (private right of action post-2024 amendment)", jurisdiction: "US-IL", domain: "genetic-privacy" },
  "hhs-repro-24":    { name: "HHS Reproductive Health HIPAA Amendment 2024",     citation: "45 CFR Parts 160, 164 — Final Rule (effective 2024-12-23)", jurisdiction: "US", domain: "health" },
  "nist-pf-1.1":     { name: "NIST Privacy Framework 1.1",                       citation: "NIST PF 1.1 (final 2025-04-14)", jurisdiction: "US", domain: "privacy" },
  "uk-duaa":         { name: "UK Data (Use and Access) Act 2025",                citation: "DUAA c. 26 (Royal Assent 2025-06-19; replaces DPDI Bill)", jurisdiction: "UK", domain: "privacy" },
  "cl-pdpa":         { name: "Chile Ley 21.719 Protección de Datos Personales",  citation: "Ley 21.719 (enacted 2024-12-13; effective 2026-12-01)", jurisdiction: "CL", domain: "privacy" },
  "mx-lfpdppp":      { name: "Mexico LFPDPPP + 2025 reform",                     citation: "Ley Federal de Protección de Datos Personales en Posesión de los Particulares (2010 + 2025 secondary reform)", jurisdiction: "MX", domain: "privacy" },
  "ar-pdpa":         { name: "Argentina Personal Data Protection Act",            citation: "Ley 25.326 + 2024 modernization bill (pending)", jurisdiction: "AR", domain: "privacy" },
  "pipa-kr":         { name: "South Korea Personal Information Protection Act",   citation: "PIPA 2011 + 2023 major amendment (phased 2023-09-15 / 2024-03-15)", jurisdiction: "KR", domain: "privacy" },
  "au-privacy":      { name: "Australia Privacy Act + 2024 Amendment Act",        citation: "Privacy Act 1988 + Privacy and Other Legislation Amendment Act 2024 (first tranche 2024-12-10; statutory tort 2025-06-10)", jurisdiction: "AU", domain: "privacy" },
  "th-pdpa":         { name: "Thailand Personal Data Protection Act",             citation: "PDPA B.E. 2562 (2019; full effect 2022-06-01)", jurisdiction: "TH", domain: "privacy" },
  "vn-pdp":          { name: "Vietnam Personal Data Protection Law",              citation: "Decree 13/2023 + PDP Law (effective 2026-01-01)", jurisdiction: "VN", domain: "privacy" },
  "id-pdp":          { name: "Indonesia Personal Data Protection Law",            citation: "Law 27 of 2022 (effective 2024-10-17)", jurisdiction: "ID", domain: "privacy" },
  "my-pdpa":         { name: "Malaysia Personal Data Protection Act",             citation: "PDPA 2010 + 2024 amendments (effective 2025-04-30)", jurisdiction: "MY", domain: "privacy" },
  "ny-safe-kids":    { name: "NY Child Data Protection Act / SAFE for Kids Act",  citation: "N.Y. Gen. Bus. Law §899-ff et seq. (effective 2025-06-20)", jurisdiction: "US-NY", domain: "child-privacy" },
  "ny-saffe":        { name: "NY Stop Addictive Feeds Exploitation for Kids Act", citation: "N.Y. Gen. Bus. Law §1500 et seq. (effective 2025-06-20)", jurisdiction: "US-NY", domain: "child-privacy" },
  "md-kids-code":    { name: "Maryland Age-Appropriate Design Code",              citation: "Md. Code Ann., Com. Law §14-4901 et seq. (enacted 2024)", jurisdiction: "US-MD", domain: "child-privacy" },
  "vt-aadc":         { name: "Vermont Age-Appropriate Design Code",               citation: "Vt. Stat. Ann. tit. 9 §2447 et seq. (enacted 2024)", jurisdiction: "US-VT", domain: "child-privacy" },
  "dsa":             { name: "EU Digital Services Act",                          citation: "Regulation (EU) 2022/2065 (fully applicable 2024-02-17)", jurisdiction: "EU", domain: "platform-governance" },
  "dga":             { name: "EU Data Governance Act",                           citation: "Regulation (EU) 2022/868 (applicable 2023-09-24)", jurisdiction: "EU", domain: "data-sharing" },
  "eu-cer":          { name: "EU Critical Entities Resilience Directive",        citation: "Directive (EU) 2022/2557 (transposition 2024-10-17)", jurisdiction: "EU", domain: "cybersecurity" },
  "eu-cyber-sol":    { name: "EU Cyber Solidarity Act",                          citation: "Regulation (EU) 2025/38 (effective 2025-02-04)", jurisdiction: "EU", domain: "cybersecurity" },
  "eidas-2":         { name: "eIDAS 2 / EUDI Wallet",                            citation: "Regulation (EU) 2024/1183 (rollout 2026-2027)", jurisdiction: "EU", domain: "identity" },
  "cmmc-2.0":        { name: "Cybersecurity Maturity Model Certification 2.0",   citation: "32 CFR Part 170 (DFARS rule effective 2025-Q1)", jurisdiction: "US", domain: "cybersecurity" },
  "cjis-v6":         { name: "FBI CJIS Security Policy v6.0",                    citation: "CJIS Security Policy v6.0 (effective 2024-12)", jurisdiction: "US", domain: "law-enforcement" },
  "iso-27001-2022":  { name: "ISO/IEC 27001:2022 Information Security Management System", citation: "ISO/IEC 27001:2022", jurisdiction: "international", domain: "cybersecurity" },
  "iso-27002-2022":  { name: "ISO/IEC 27002:2022 Information Security Controls",  citation: "ISO/IEC 27002:2022", jurisdiction: "international", domain: "cybersecurity" },
  "iso-27017":       { name: "ISO/IEC 27017 Cloud Services Security Controls",   citation: "ISO/IEC 27017:2015", jurisdiction: "international", domain: "cybersecurity" },
  "iso-27018":       { name: "ISO/IEC 27018 PII Protection in Public Cloud",     citation: "ISO/IEC 27018:2019", jurisdiction: "international", domain: "privacy" },
  "iso-27701":       { name: "ISO/IEC 27701 Privacy Information Management System", citation: "ISO/IEC 27701:2019", jurisdiction: "international", domain: "privacy" },
  "nist-800-66-r2":  { name: "NIST SP 800-66 Rev 2 — HIPAA Security Rule Guidance", citation: "NIST SP 800-66 Rev 2 (Feb 2024)", jurisdiction: "US", domain: "health" },
  "ehds":            { name: "European Health Data Space",                        citation: "Regulation (EU) 2025/327 (phased 2027-2029)", jurisdiction: "EU", domain: "health" },
  "circia":          { name: "Cyber Incident Reporting for Critical Infrastructure Act", citation: "6 U.S.C. §681 et seq. (final rule pending)", jurisdiction: "US", domain: "cybersecurity" },
  "42-cfr-part-2":   { name: "Confidentiality of Substance Use Disorder Patient Records", citation: "42 CFR Part 2 (HHS final rule effective 2024-02-08)", jurisdiction: "US", domain: "health" },
  "hti-1":           { name: "ONC HTI-1 Final Rule — Health IT Certification + Algorithm Transparency", citation: "45 CFR Part 170 / 89 FR 1192 (effective 2024-12-31)", jurisdiction: "US", domain: "health" },
  "uscdi-v4":        { name: "US Core Data for Interoperability v4",            citation: "ONC USCDI v4 (Jan 2024)",                          jurisdiction: "US", domain: "health" },
  "irs-1075":        { name: "IRS Publication 1075 — Tax Information Security Guidelines", citation: "IRS Pub 1075 (Rev. 11-2023)",        jurisdiction: "US", domain: "tax" },
  "nist-800-172-r3": { name: "NIST SP 800-172 Rev 3 — Enhanced CUI Security Requirements", citation: "NIST SP 800-172 Rev 3",                jurisdiction: "US", domain: "cybersecurity" },
  "tlp-2.0":         { name: "FIRST Traffic Light Protocol 2.0",                citation: "FIRST TLP v2.0 (Aug 2022)",                       jurisdiction: "international", domain: "information-sharing" },
  "soci-au":         { name: "Australia Security of Critical Infrastructure Act", citation: "SOCI 2018 + 2022 amendments",                   jurisdiction: "AU", domain: "critical-infrastructure" },
  "ffiec-cat-2":     { name: "FFIEC Cybersecurity Assessment Tool 2.0",          citation: "FFIEC CAT v2.0",                                  jurisdiction: "US", domain: "financial" },
  "cri-profile-v2.0":{ name: "Cyber Risk Institute Profile v2.0",                citation: "CRI Profile v2.0 (financial-services NIST CSF cross-walk)", jurisdiction: "US", domain: "financial" },
  "m-22-09":         { name: "OMB M-22-09 — Federal Zero Trust Architecture Strategy", citation: "OMB Memorandum M-22-09 (2022-01-26)",     jurisdiction: "US", domain: "cybersecurity" },
  "m-22-18":         { name: "OMB M-22-18 — Software Supply Chain Security",    citation: "OMB Memorandum M-22-18 (2022-09-14)",             jurisdiction: "US", domain: "supply-chain" },
  "nist-800-53-r5-privacy": { name: "NIST SP 800-53 Rev 5 — Privacy Control Family", citation: "NIST SP 800-53 Rev 5 (Privacy overlay)",     jurisdiction: "US", domain: "privacy" },
  "nist-ai-600-1-genai":    { name: "NIST AI 600-1 — Generative AI Profile",    citation: "NIST AI 600-1 (Jul 2024) — companion to AI RMF 1.0", jurisdiction: "US", domain: "ai" },
  "nist-csf-2.0":    { name: "NIST Cybersecurity Framework 2.0",                citation: "NIST CSF 2.0 (Feb 2024)",                         jurisdiction: "US", domain: "cybersecurity" },
  "sb-53":           { name: "California SB-53 — Transparency in Frontier AI Act", citation: "Cal. Health & Safety Code §22757 et seq. (effective 2025-09-29)", jurisdiction: "US-CA", domain: "ai" },
  "nyc-ll144-2024":  { name: "NYC Local Law 144 — Automated Employment Decision Tool Bias Audits", citation: "NYC Local Law 144 of 2021 + 2024 DCWP enforcement update", jurisdiction: "US-NY", domain: "ai" },
  "sox-404":         { name: "Sarbanes-Oxley §404 — Internal Controls over Financial Reporting", citation: "15 U.S.C. §7262",               jurisdiction: "US", domain: "financial-reporting" },
  "soc2-cc1.3":      { name: "SOC 2 Trust Services Criterion CC1.3 — Segregation of Duties", citation: "AICPA Trust Services Criteria CC1.3", jurisdiction: "US", domain: "audit-attestation" },
  "fapi-2.0":        { name: "Financial-grade API 2.0 Final",                   citation: "OpenID Foundation FAPI 2.0 Final (Feb 2025)",     jurisdiction: "international", domain: "financial" },
  "cfpb-1033":       { name: "CFPB §1033 — Personal Financial Data Rights",     citation: "12 CFR Part 1033 (Final Rule 2024-10-22; tiered effective dates from 2026-04-01)", jurisdiction: "US", domain: "financial" },
  "iab-tcf-v2.3":    { name: "IAB Transparency & Consent Framework v2.3",       citation: "IAB Europe TCF v2.3 (Sep 2024)",                  jurisdiction: "EU", domain: "advertising" },
  "iab-mspa":        { name: "IAB Multi-State Privacy Agreement",               citation: "IAB Tech Lab MSPA + Global Privacy Platform",     jurisdiction: "US", domain: "privacy" },
  "tcpa-10dlc":      { name: "TCPA 10DLC Messaging Compliance",                 citation: "47 U.S.C. §227 + CTIA 10DLC + FCC 1:1 disclosure rule", jurisdiction: "US", domain: "telecommunications" },
  "fda-21cfr11":     { name: "FDA 21 CFR Part 11 — Electronic Records / Signatures", citation: "21 CFR Part 11",                          jurisdiction: "US", domain: "life-sciences" },
  "fda-annex-11":    { name: "EU GMP Annex 11 — Computerized Systems",          citation: "EudraLex Vol. 4 Annex 11",                        jurisdiction: "EU", domain: "life-sciences" },
  "sec-17a-4":       { name: "SEC Rule 17a-4(f) — Broker-Dealer Record Preservation", citation: "17 CFR §240.17a-4(f)",                      jurisdiction: "US", domain: "financial-records" },
  "finra-4511":      { name: "FINRA Rule 4511 — Books and Records",             citation: "FINRA Rule 4511 (incorporating SEA Rule 17a-4)",  jurisdiction: "US", domain: "financial-records" },
  "sec-1.05":        { name: "SEC Cybersecurity Risk Management — Item 1.05 Form 8-K", citation: "17 CFR §229.106 + Item 1.05 (effective 2023-12-18)", jurisdiction: "US", domain: "financial-reporting" },
  "ny-2-d":          { name: "NY Education Law §2-d — Student Privacy",         citation: "N.Y. Educ. Law §2-d",                             jurisdiction: "US-NY", domain: "education" },
  "il-soppa":        { name: "Illinois Student Online Personal Protection Act", citation: "105 ILCS 85",                                     jurisdiction: "US-IL", domain: "education" },
  "ca-sopipa":       { name: "California Student Online Personal Information Protection Act", citation: "Cal. Bus. & Prof. Code §22584",   jurisdiction: "US-CA", domain: "education" },
  "ct-pa-5-2":       { name: "Connecticut Public Act 5-2 — Student Data Privacy", citation: "Conn. Public Act No. 16-189",                  jurisdiction: "US-CT", domain: "education" },
  "tx-hb-4504":      { name: "Texas HB 4504 — Student Data Privacy",            citation: "Tex. Educ. Code §32.151",                          jurisdiction: "US-TX", domain: "education" },
  "va-sb-1376":      { name: "Virginia SB 1376 — Student Data Privacy",         citation: "Va. Code §22.1-289.01",                            jurisdiction: "US-VA", domain: "education" },
  "staterramp":      { name: "StateRAMP / TX-RAMP / AZ-RAMP / GovRAMP Family",  citation: "StateRAMP Program (FedRAMP-Moderate cross-walk)",  jurisdiction: "US", domain: "cybersecurity" },
  "irap":            { name: "Australia Information Security Registered Assessors Program / Essential Eight / ISM", citation: "ASD IRAP + ISM",                      jurisdiction: "AU", domain: "cybersecurity" },
  "bsi-c5":          { name: "Germany BSI C5 — Cloud Computing Compliance Catalogue", citation: "BSI Cloud Computing Compliance Criteria Catalogue (C5:2020)", jurisdiction: "DE", domain: "cybersecurity" },
  "ens-es":          { name: "Spain Esquema Nacional de Seguridad",             citation: "Real Decreto 311/2022",                            jurisdiction: "ES", domain: "cybersecurity" },
  "uk-g-cloud":      { name: "UK G-Cloud Framework",                            citation: "UK Crown Commercial Service G-Cloud 14",          jurisdiction: "UK", domain: "cybersecurity" },
  "nist-800-53":              { name: "NIST SP 800-53 Rev 5 — Security & Privacy Controls", citation: "NIST SP 800-53 Rev 5",                jurisdiction: "US", domain: "cybersecurity" },
  "nist-ai-rmf-1.0":          { name: "NIST AI Risk Management Framework 1.0",  citation: "NIST AI 100-1 (Jan 2023)",                        jurisdiction: "US", domain: "ai" },
  "iso-42001-2023":           { name: "ISO/IEC 42001:2023 — AI Management System", citation: "ISO/IEC 42001:2023",                          jurisdiction: "international", domain: "ai" },
  "iso-23894-2023":           { name: "ISO/IEC 23894:2023 — AI Risk Management",  citation: "ISO/IEC 23894:2023",                            jurisdiction: "international", domain: "ai" },
  "owasp-llm-top-10-2025":    { name: "OWASP Top 10 for LLM Applications 2025",  citation: "OWASP LLM Top 10 v2025",                          jurisdiction: "international", domain: "ai" },
  "owasp-asvs-v5.0":          { name: "OWASP Application Security Verification Standard v5.0", citation: "OWASP ASVS v5.0",                   jurisdiction: "international", domain: "cybersecurity" },
  "nist-800-218-ssdf":        { name: "NIST SP 800-218 — Secure Software Development Framework", citation: "NIST SP 800-218 v1.1",          jurisdiction: "US", domain: "supply-chain" },
  "nist-800-82-r3":           { name: "NIST SP 800-82 Rev 3 — OT Security Guide", citation: "NIST SP 800-82 Rev 3",                          jurisdiction: "US", domain: "operational-technology" },
  "nist-800-63b-rev4":        { name: "NIST SP 800-63B Rev 4 — Digital Identity Authentication", citation: "NIST SP 800-63B Rev 4",         jurisdiction: "US", domain: "identity" },
  "iec-62443-3-3":            { name: "IEC 62443-3-3 — IACS System Security",     citation: "IEC 62443-3-3:2013",                              jurisdiction: "international", domain: "operational-technology" },
  "fedramp-rev5-moderate":    { name: "FedRAMP Rev 5 Moderate Baseline",          citation: "GSA FedRAMP Rev 5 (Moderate baseline)",         jurisdiction: "US", domain: "cybersecurity" },
  "hipaa-security-rule":      { name: "HIPAA Security Rule — Technical Safeguards", citation: "45 CFR §164.312",                            jurisdiction: "US", domain: "health" },
  "hitrust-csf-v11.4":        { name: "HITRUST Common Security Framework v11.4",  citation: "HITRUST CSF v11.4",                              jurisdiction: "US", domain: "health" },
  "nerc-cip-007-6":           { name: "NERC CIP-007-6 — BES Cyber System Security Management", citation: "NERC CIP-007-6",                  jurisdiction: "US", domain: "energy" },
  "psd2-rts-sca":             { name: "EU PSD2 RTS on Strong Customer Authentication", citation: "Commission Delegated Regulation 2018/389",  jurisdiction: "EU", domain: "financial" },
  "swift-cscf-v2026":         { name: "SWIFT Customer Security Controls Framework v2026", citation: "SWIFT CSCF v2026",                       jurisdiction: "international", domain: "financial" },
  "slsa-v1.0-build-l3":       { name: "SLSA v1.0 Build Track Level 3",            citation: "SLSA Specification v1.0",                       jurisdiction: "international", domain: "supply-chain" },
  "vex-csaf-2.1":             { name: "OASIS CSAF 2.1 — VEX",                     citation: "OASIS CSAF 2.1",                                  jurisdiction: "international", domain: "supply-chain" },
  "cyclonedx-v1.6":           { name: "CycloneDX v1.6 SBOM",                      citation: "OWASP CycloneDX v1.6",                            jurisdiction: "international", domain: "supply-chain" },
  "spdx-v3.0":                { name: "SPDX v3.0 SBOM",                            citation: "Linux Foundation SPDX v3.0",                     jurisdiction: "international", domain: "supply-chain" },
  "owasp-wstg-v5":            { name: "OWASP Web Security Testing Guide v5",      citation: "OWASP WSTG v5",                                   jurisdiction: "international", domain: "cybersecurity" },
  "ptes":                     { name: "Penetration Testing Execution Standard",   citation: "PTES (community standard)",                       jurisdiction: "international", domain: "cybersecurity" },
  "nist-800-115":             { name: "NIST SP 800-115 — Technical Guide to Information Security Testing", citation: "NIST SP 800-115",     jurisdiction: "US", domain: "cybersecurity" },
  "cwe-top-25-2024":          { name: "CWE Top 25 Most Dangerous Software Weaknesses (2024)", citation: "MITRE CWE Top 25 (2024)",          jurisdiction: "international", domain: "cybersecurity" },
  "cis-controls-v8":          { name: "CIS Controls v8",                          citation: "Center for Internet Security CIS Controls v8",    jurisdiction: "international", domain: "cybersecurity" },
  "cmmc-2.0-level-2":         { name: "CMMC 2.0 Level 2 — Advanced",              citation: "32 CFR Part 170 + NIST SP 800-171 Rev 2",        jurisdiction: "US", domain: "cybersecurity" },
  "cmmc-2.0-level-1":         { name: "CMMC 2.0 Level 1 — Foundational",          citation: "32 CFR Part 170 + FAR 52.204-21",                jurisdiction: "US", domain: "cybersecurity" },
  "cmmc-2.0-level-3":         { name: "CMMC 2.0 Level 3 — Expert",                citation: "32 CFR Part 170 + NIST SP 800-172 enhanced",     jurisdiction: "US", domain: "cybersecurity" },
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
  return Object.prototype.hasOwnProperty.call(REGIME_MAP, posture) ? REGIME_MAP[posture] : null;
}

var POSTURE_DEFAULTS = Object.freeze({
  "hipaa": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
    sealEnvelopeFloor:        "aad",
  }),
  "pci-dss": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  false,
    sealEnvelopeFloor:        "aad",
  }),
  "gdpr": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
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
  "lgpd-br": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "pipl-cn": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "dpdp": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "uk-gdpr": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "appi-jp": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "pdpa-sg": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "modpa": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "nydfs-500": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "hipaa-2026": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "quebec-25": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "fl-fdbr": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "hitech": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "ferpa": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "co-ai":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "il-hb3773":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "tx-traiga":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ut-aipa":     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nyc-ll144":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ca-tfaia":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "kr-ai-basic": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cn-ai-label": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "iso-42001":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-23894":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ca-sb942":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ca-ab853":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eaa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "wcag-2-2":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-data-act": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "coppa":           Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "coppa-2025":      Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "glba-safeguards": Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "uk-duaa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cl-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "pipa-kr":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "au-privacy":      Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "mx-lfpdppp":      Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ar-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "th-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vn-pdp":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "id-pdp":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "my-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ny-safe-kids":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ny-saffe":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "md-kids-code":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vt-aadc":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "gina":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vppa":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "can-spam":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "il-gipa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "hhs-repro-24":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-pf-1.1":     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "dsa":             Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "dga":             Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-cer":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-cyber-sol":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eidas-2":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cmmc-2.0":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cjis-v6":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-27001-2022":  Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-27002-2022":  Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "iso-27017":       Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-27018":       Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-27701":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-800-66-r2":  Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ehds":            Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "circia":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-53":             Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-ai-rmf-1.0":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-42001-2023":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-23894-2023":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "owasp-llm-top-10-2025":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "owasp-asvs-v5.0":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-800-218-ssdf":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-82-r3":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-63b-rev4":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "iec-62443-3-3":           Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "fedramp-rev5-moderate":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true, fipsMode: false }),
  "hipaa-security-rule":     Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "hitrust-csf-v11.4":       Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nerc-cip-007-6":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "psd2-rts-sca":            Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "swift-cscf-v2026":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "slsa-v1.0-build-l3":      Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "vex-csaf-2.1":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cyclonedx-v1.6":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "spdx-v3.0":               Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "owasp-wstg-v5":           Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ptes":                    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-115":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cwe-top-25-2024":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cis-controls-v8":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cmmc-2.0-level-1":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cmmc-2.0-level-2":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cmmc-2.0-level-3":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true, fipsMode: false }),
  "42-cfr-part-2":           Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "hti-1":                   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "uscdi-v4":                Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "irs-1075":                Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-800-172-r3":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true, fipsMode: false }),
  "tlp-2.0":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "soci-au":                 Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nis2":                    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cra":                     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ffiec-cat-2":             Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cri-profile-v2.0":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "m-22-09":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "m-22-18":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-53-r5-privacy":  Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-ai-600-1-genai":     Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-csf-2.0":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "sb-53":                   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nyc-ll144-2024":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-ai-act":               Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ai-act":                  Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ca-ab-853":               Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cac-genai-label":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
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
 * Recognized keys per posture include `backupEncryptionRequired`,
 * `auditChainSignedRequired`, `tlsMinVersion`,
 * `requireVacuumAfterErase`, and `sealEnvelopeFloor` — the floors
 * enforced by `b.backup`, `b.audit`, the TLS minimum-version gate,
 * `b.cryptoField`'s residual-erasure pass, and `b.cryptoField`'s
 * field-level seal-envelope gate. Keys not declared for a posture
 * return `null` (no floor), so reading `sealEnvelopeFloor` for a
 * posture that doesn't pin one is the back-compat no-op signal.
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
 *   // → ["ccpa", "gdpr", "lgpd-br", ...] — every posture whose
 *   //    domain is "privacy" (the full set grows as regimes are added)
 *
 *   b.compliance.posturesByDomain("health");
 *   // → ["hipaa", "wmhmda", ...] — every "health"-domain posture
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
 *   // → ["gdpr", "dora", "nis2", ...] — every EU-jurisdiction posture
 *   //    (the full set grows as regimes are added)
 *
 *   b.compliance.posturesByJurisdiction("US");
 *   // → ["hipaa", "soc2", "sox", ...] — every US-jurisdiction posture
 *
 *   b.compliance.posturesByJurisdiction("US-CA");
 *   // → ["ccpa", ...] — every US-CA (California) posture
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

/**
 * @primitive b.compliance.artifactStandards
 * @signature b.compliance.artifactStandards()
 * @since     0.9.57
 * @status    stable
 *
 * Return the set of SBOM / VEX artifact standards the framework can
 * emit. These are FORMAT FAMILIES, not regulatory regimes — pinning
 * one of these names as the deployment's compliance posture conflates
 * "format I emit" with "regulatory floor I meet". Pin
 * the regulatory regime (FedRAMP / SSDF / HIPAA / etc.) via
 * `b.compliance.set()` and surface the emitted artifact standards via
 * this read-only catalog.
 *
 * @example
 *   b.compliance.artifactStandards();
 *   // → ["cyclonedx-v1.6", "spdx-v3.0", "vex-csaf-2.1"]
 */
function artifactStandards() {
  return ARTIFACT_STANDARDS.slice();
}

/**
 * @primitive b.compliance.fipsMode
 * @signature b.compliance.fipsMode(enable?)
 * @since     0.9.57
 * @status    stable
 * @related   b.compliance.set
 *
 * Get or set the FIPS-mode flag. When `enable === true`, the
 * framework's audit-chain signing path (b.audit.sign) switches from
 * the PQC-first default (SLH-DSA-SHAKE-256f) to a FIPS-140-3
 * validated AES-GCM + SHA-384 path so a FedRAMP / CMMC L3 boundary
 * can pin the audit signer to a validated module.
 *
 * Call BEFORE b.compliance.set() so the fips_conflict audit warning
 * doesn't fire at posture-set time. Cannot be toggled after posture
 * is pinned — runtime switches create half-set crypto state. Returns
 * the current flag value when called with no argument.
 *
 * @example
 *   b.compliance.fipsMode(true);          // opt into FIPS-validated path
 *   b.compliance.set("fedramp-rev5-moderate");
 *   b.compliance.fipsMode();              // → true
 */
function fipsMode(enable) {
  if (enable === undefined) return STATE.fipsMode === true;
  if (typeof enable !== "boolean") {
    throw new ComplianceError("compliance/bad-fips-mode",
      "compliance.fipsMode: argument must be boolean when supplied (got " +
      typeof enable + ")");
  }
  if (STATE.posture) {
    throw new ComplianceError("compliance/fips-after-set",
      "compliance.fipsMode: posture is already pinned ('" + STATE.posture +
      "'); FIPS-mode must be set BEFORE b.compliance.set() — runtime " +
      "switches create half-set crypto state.");
  }
  STATE.fipsMode = enable;
  _emitAudit("compliance.fips_mode.set", { fipsMode: enable });
  return STATE.fipsMode;
}

var CROSS_BORDER_REGULATED_POSTURES = Object.freeze([
  "gdpr", "uk-gdpr", "dpdp", "pipl-cn", "lgpd-br", "appi-jp", "pdpa-sg",
]);

/**
 * @primitive b.compliance.isCrossBorderRegulated
 * @signature b.compliance.isCrossBorderRegulated(posture)
 * @since     0.14.24
 * @compliance gdpr
 * @related   b.compliance.current, b.cryptoField.declarePerRowResidency
 *
 * Returns true when `posture` is one of the cross-border regulated
 * postures (gdpr / uk-gdpr / dpdp / pipl-cn / lgpd-br / appi-jp /
 * pdpa-sg) — the jurisdictions whose transfer restrictions flip the
 * data-residency write gates from advisory to refusing. The set
 * itself is exported as `CROSS_BORDER_REGULATED_POSTURES`; this
 * helper is the membership test the local (`b.db.from`) and external
 * (`b.externalDb.query`) gates share. Non-string and unknown postures
 * return false.
 *
 * @example
 *   b.compliance.isCrossBorderRegulated("gdpr");      // → true
 *   b.compliance.isCrossBorderRegulated("soc2");      // → false
 *   b.compliance.isCrossBorderRegulated(null);        // → false
 */
function isCrossBorderRegulated(posture) {
  if (typeof posture !== "string" || posture.length === 0) return false;
  return CROSS_BORDER_REGULATED_POSTURES.indexOf(posture) !== -1;
}

var _REGION_WILDCARDS = Object.freeze(["global", "unrestricted", "any", "*"]);

/**
 * @primitive b.compliance.normalizeRegionTag
 * @signature b.compliance.normalizeRegionTag(tag)
 * @since     0.14.27
 * @compliance gdpr
 * @related   b.compliance.isRegionCompatible, b.compliance.isCrossBorderRegulated
 *
 * Canonicalize an operator-supplied residency region tag so the same
 * region declared as `"EU"`, `"eu"`, or `" Eu "` compares equal. Lower-
 * cases and trims the tag; folds the no-constraint wildcards
 * (`"global"` / `"unrestricted"` / `"any"` / `"*"`) to `"unrestricted"`.
 * Returns `null` for non-string / empty input.
 *
 * This is an ADDITIVE helper composed OVER the residency write gates
 * (`b.db.from` local, `b.externalDb.query` backend/replica) — it does
 * not change the gate internals. Callers normalize their tags with it
 * BEFORE handing them to the gate so case / wildcard drift (`"EU"` vs
 * `"eu"` vs `"global"`) doesn't read as a region mismatch.
 *
 * @example
 *   b.compliance.normalizeRegionTag("EU");           // → "eu"
 *   b.compliance.normalizeRegionTag(" eu ");         // → "eu"
 *   b.compliance.normalizeRegionTag("global");       // → "unrestricted"
 *   b.compliance.normalizeRegionTag("unrestricted"); // → "unrestricted"
 *   b.compliance.normalizeRegionTag(null);           // → null
 */
function normalizeRegionTag(tag) {
  if (typeof tag !== "string") return null;
  var t = tag.trim().toLowerCase();
  if (t.length === 0) return null;
  if (_REGION_WILDCARDS.indexOf(t) !== -1) return "unrestricted";
  return t;
}

/**
 * @primitive b.compliance.isRegionCompatible
 * @signature b.compliance.isRegionCompatible(a, b)
 * @since     0.14.27
 * @compliance gdpr
 * @related   b.compliance.normalizeRegionTag, b.compliance.isCrossBorderRegulated
 *
 * Returns `true` when two residency region tags are compatible for a
 * same-region write/replication after normalization: identical
 * normalized regions are compatible, and a wildcard (`"global"` /
 * `"unrestricted"`) on EITHER side is compatible. Different concrete
 * regions (`"eu"` vs `"us"`) are NOT compatible — a cross-border
 * transfer the operator must opt into explicitly at the gate.
 *
 * Mirrors the residency gate's compatibility rule (identical-or-
 * wildcard) but over NORMALIZED tags, so it is case- and wildcard-drift
 * insensitive. ADDITIVE helper composed over the gate — it does not
 * change `_residencyCompatible` in db-query.js / external-db.js.
 * Missing/non-string tags on either side normalize to `null`, treated
 * as "no constraint" → compatible (matches the gate's
 * `!primaryTag || !replicaTag` short-circuit).
 *
 * @example
 *   b.compliance.isRegionCompatible("EU", "eu");            // → true
 *   b.compliance.isRegionCompatible("eu", "global");        // → true
 *   b.compliance.isRegionCompatible("unrestricted", "us");  // → true
 *   b.compliance.isRegionCompatible("eu", "us");            // → false
 *   b.compliance.isRegionCompatible("EU", null);            // → true
 */
function isRegionCompatible(a, b) {
  var na = normalizeRegionTag(a);
  var nb = normalizeRegionTag(b);
  if (na === null || nb === null) return true;
  if (na === nb) return true;
  if (na === "unrestricted" || nb === "unrestricted") return true;
  return false;
}

module.exports = {
  set:                    set,
  current:                current,
  isCrossBorderRegulated: isCrossBorderRegulated,
  normalizeRegionTag:     normalizeRegionTag,
  isRegionCompatible:     isRegionCompatible,
  CROSS_BORDER_REGULATED_POSTURES: CROSS_BORDER_REGULATED_POSTURES,
  assert:                 assert,
  clear:                  clear,
  describe:               describe,
  posturesByDomain:       posturesByDomain,
  posturesByJurisdiction: posturesByJurisdiction,
  list:                   list,
  postureDefault:         postureDefault,
  sanctions:              sanctions,
  aiAct:                  aiAct,
  artifactStandards:      artifactStandards,
  fipsMode:               fipsMode,
  KNOWN_POSTURES:         KNOWN_POSTURES,
  POSTURE_DEFAULTS:       POSTURE_DEFAULTS,
  ARTIFACT_STANDARDS:     ARTIFACT_STANDARDS,
  REGIME_MAP:             REGIME_MAP,
  ComplianceError:        ComplianceError,
  _resetForTest:          _resetForTest,
};
