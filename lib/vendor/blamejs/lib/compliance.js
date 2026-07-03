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

// Postures whose floor implies an outbound-DLP gate (b.redact's
// classifier presets cover exactly these regimes). Pinning one of these
// does NOT auto-install outbound DLP — the compliance coordinator holds
// no httpClient / mail / webhook handles — so set() emits a one-time
// `compliance.posture.outbound_dlp_unwired` warning when none is wired,
// so the gap is grep-able in the audit chain instead of a silent paper-
// compliance hole (CWE-200 / CWE-201 outbound data exposure).
var OUTBOUND_DLP_FLOOR_POSTURES = Object.freeze([
  "hipaa", "pci-dss", "gdpr", "soc2", "fapi-2.0", "fapi-2.0-message-signing",
]);

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
  "ai-act",      // EU AI Act (added 2026 — legacy short name)
  "eu-ai-act",   // EU AI Act (canonical name; v0.12.26 added with Art. 50 cascade)
  "ca-ab-853",   // California AB-853 model-generated content watermarking (effective 2026; v0.12.26)
  "cac-genai-label", // China CAC GenAI Service Measures synthetic-content labelling (v0.12.26)
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
  "fapi-2.0-message-signing", // FAPI 2.0 Message Signing profile — adds JARM mandate + signed-request-object enforcement
  "cfpb-1033",       // CFPB §1033 / FDX consumer-financial-data sharing (deadline past for $250B+ banks 2026-04-01)
  "iab-tcf-v2.3",    // IAB Transparency & Consent Framework v2.3 with disclosedVendors (deadline past 2026-02-28)
  "iab-mspa",        // IAB Multi-State Privacy Agreement / Global Privacy Platform universal opt-out
  "tcpa-10dlc",      // TCPA 10DLC carrier-shaped consent + FCC 1:1 disclosure
  "fda-21cfr11",     // FDA 21 CFR Part 11 — audit-trail + electronic signatures (general-purpose subset)
  "fda-annex-11",    // EU GMP Annex 11 — computerized systems (Part-11 equivalent)
  "sec-1.05",        // SEC Cybersecurity Disclosure Item 1.05 — material-incident 8-K filing                                  // regulatory identifier, not bytes
  // ---- US state student-data privacy (F5.1 posture group) ----
  "ny-2-d",          // NY Education Law §2-d
  "il-soppa",        // Illinois Student Online Personal Protection Act
  "ca-sopipa",       // California Student Online Personal Information Protection Act
  "ct-pa-5-2",       // Connecticut Public Act 5-2
  "tx-hb-4504",      // Texas HB 4504                                                                                            // statute identifier, not bytes
  "va-sb-1376",      // Virginia SB 1376                                                                                         // statute identifier, not bytes
  // ---- EU government / cloud-region ----
  "staterramp",      // StateRAMP / TX-RAMP / AZ-RAMP / GovRAMP family (FedRAMP-Moderate cross-walks)
  "irap",            // Australia IRAP / Essential Eight / ISM
  "bsi-c5",          // Germany BSI C5
  "ens-es",          // Spain Esquema Nacional de Seguridad
  "uk-g-cloud",      // UK G-Cloud
  // ---- 2026 effective deadlines ----
  "modpa",           // Maryland Online Data Privacy Act (effective 2025-10-01) — strict data-min
  "nydfs-500",       // NYDFS 23 NYCRR 500 Amendment 2 — financial cybersecurity (multi-factor + asset inventory + governance)
  "hipaa-2026",      // HHS HIPAA Security Rule 2026-Q4 final — extends hipaa with mandatory MFA + asset inventory + 72h restoration testing
  "quebec-25",       // Quebec Law 25 final phase (effective 2026-09-22) — DPIA + automated-decision opt-out
  // ---- US state consumer-privacy postures ----
  // Each posture carries per-state cure-period, profiling opt-out
  // and minor-consent metadata via b.dsr.stateRules(state). The
  // generic DSR primitive (b.dsr.submit) covers ~80% of the surface;
  // these postures fill in the per-state drift.
  "vcdpa",           // Virginia Consumer Data Protection Act
  "co-cpa",          // Colorado Privacy Act
  "ctdpa",           // Connecticut Data Privacy Act
  "ucpa",            // Utah Consumer Privacy Act
  "tdpsa",           // Texas Data Privacy and Security Act
  "or-cpa",          // Oregon Consumer Privacy Act
  "mt-cdpa",         // Montana Consumer Data Privacy Act
  "ia-icdpa",        // Iowa Consumer Data Protection Act
  "in-indpa",        // Indiana Consumer Data Protection Act
  "de-dpdpa",        // Delaware Personal Data Privacy Act
  "nh-nhpa",         // New Hampshire SB 255 Consumer Privacy Act
  "nj-njdpa",        // New Jersey Data Privacy Act
  "ky-kcdpa",        // Kentucky Consumer Data Protection Act
  "tn-tipa",         // Tennessee Information Protection Act
  "mn-mncdpa",       // Minnesota Consumer Data Privacy Act
  "ri-ricpa",        // Rhode Island Consumer Privacy Act
  "ne-dpa",          // Nebraska Data Privacy Act
  "nv-sb370",        // Nevada SB 370 Consumer Health Data Privacy
  "ca-aadc",         // California Age-Appropriate Design Code (partial preliminary injunction; track for re-enforcement)
  "ct-sb3",          // Connecticut SB 3 Consumer Health Data
  "tx-cubi",         // Texas Capture or Use of Biometric Identifier
  "fl-fdbr",         // Florida Digital Bill of Rights (SB 262, effective 2024-07-01) — narrow scope ($1B+ revenue threshold)
  // ---- AI-governance postures ----
  // State + sectoral AI regulations crystallizing through 2026. Each
  // posture is a flag that operators pin alongside their base
  // privacy/sectoral posture; the floors enforce audit-chain signing
  // and posture-cascade visibility so AI-decision audit trails meet
  // regulator expectations even when the base posture is unregulated.
  "co-ai",           // Colorado AI Act SB24-205 (postponed to 2026-06-30; stay pending)
  "il-hb3773",       // Illinois HB 3773 — IHRA AI amendment (effective 2026-01-01)
  "tx-traiga",       // Texas Responsible AI Governance Act HB 149 (effective 2026-01-01)
  "ut-aipa",         // Utah AI Disclosure Act (UAIPA + 2025 amendments; sunset 2027-07-01)
  "nyc-ll144",       // NYC Local Law 144 — Automated Employment Decision Tools (in force)                                    // regulatory identifier, not bytes
  "ca-tfaia",        // California SB 53 — Transparency in Frontier AI Act (effective 2026-01-01)
  "kr-ai-basic",     // South Korea AI Basic Act (effective 2026-01-22)
  "cn-ai-label",     // China Measures for Labelling of AI-Generated Content (effective 2025-09-01)
  // ---- AI management cross-walks ----
  "iso-42001",       // ISO/IEC 42001:2023 — AI Management System
  "iso-23894",       // ISO/IEC 23894:2023 — AI Risk Management Guidance
  // ---- content-credentials posture flags ----
  "ca-sb942",        // California SB-942 (Cal. Bus. & Prof. Code §22757) gen-AI disclosure (effective 2026-08-02)             // regulatory identifier + date, not bytes
  "ca-ab853",        // California AB-853 platform-side gen-AI detection (effective 2026-08-02)                                // regulatory identifier + date, not bytes
  // ---- substrate-to-posture cleanup ----
  "eaa",             // EU Accessibility Act / Directive (EU) 2019/882 (effective 2025-06-28)
  "wcag-2-2",        // W3C Web Content Accessibility Guidelines 2.2 (Oct 2023 Recommendation)
  "eu-data-act",     // EU Data Act / Regulation (EU) 2023/2854 (effective 2025-09-12)
  "hitech",          // Health Information Technology for Economic and Clinical Health Act (2009)
  "ferpa",           // Family Educational Rights and Privacy Act (20 U.S.C. §1232g)
  "dpdp",            // India Digital Personal Data Protection Act 2023 (rules-pending; cascade tier exists)
  // ---- privacy 2026 sweep ----
  // US federal child / financial privacy
  "coppa",           // Children's Online Privacy Protection Act (15 U.S.C. §6501)
  "coppa-2025",      // COPPA 2025 Amendment (FTC final 2025-04-22; effective 2026-06-23 — biometric expansion + knowing-collection disclosure)
  "glba-safeguards", // GLBA Safeguards Rule 2024 Amendment (16 CFR Part 314 — effective 2024-05-13)                            // CFR title number, not bytes
  // UK
  "uk-duaa",         // UK Data (Use and Access) Act 2025 (Royal Assent 2025-06-19; replaces DPDI Bill)
  // Latin America
  "cl-pdpa",         // Chile Ley 21.719 (enacted 2024-12-13; effective 2026-12-01)
  "mx-lfpdppp",      // Mexico LFPDPPP + 2025 secondary reform
  "ar-pdpa",         // Argentina PDPA (Ley 25.326 + 2024 modernization bill)
  // APAC
  "pipa-kr",         // South Korea Personal Information Protection Act (2023 major amendment)
  "au-privacy",      // Australia Privacy Act + 2024 Amendment Act (first tranche 2024-12-10; statutory tort 2025-06-10)
  "th-pdpa",         // Thailand PDPA (effective 2022-06-01)
  "vn-pdp",          // Vietnam PDP Decree 13/2023 + 2025 PDP Law (effective 2026-01-01)
  "id-pdp",          // Indonesia Personal Data Protection Law (effective 2024-10-17)
  "my-pdpa",         // Malaysia PDPA + 2024 amendments (effective 2025-04-30)
  // US state child privacy / age-appropriate design codes
  "ny-safe-kids",    // NY Child Data Protection Act / SAFE for Kids Act (effective 2025-06-20)
  "ny-saffe",        // NY Stop Addictive Feeds Exploitation for Kids Act (effective 2025-06-20)
  "md-kids-code",    // Maryland Age-Appropriate Design Code (enacted 2024)
  "vt-aadc",         // Vermont Age-Appropriate Design Code (enacted 2024)
  // US cross-cutting privacy / sectoral
  "gina",            // Genetic Information Nondiscrimination Act (effective 2009-11-21)
  "vppa",            // Video Privacy Protection Act (1988; class-action pixel-tracking surface)
  "can-spam",        // CAN-SPAM Act (effective 2004-01-01)
  "il-gipa",         // Illinois Genetic Information Privacy Act (post-2024 amendment private right of action)
  "hhs-repro-24",    // HHS Reproductive Health HIPAA Amendment (effective 2024-12-23)
  // NIST cross-walks
  "nist-pf-1.1",     // NIST Privacy Framework 1.1 (final 2025-04-14)
  // EU non-personal-data + adjacent
  "dsa",             // EU Digital Services Act (Regulation 2022/2065; fully applicable 2024-02-17)
  "dga",             // EU Data Governance Act (Regulation 2022/868; applicable 2023-09-24)                                     // calendar day, not bytes
  "eu-cer",          // EU Critical Entities Resilience Directive (2022/2557; transposition 2024-10-17)
  "eu-cyber-sol",    // EU Cyber Solidarity Act (Regulation 2025/38; effective 2025-02-04)
  "eidas-2",         // eIDAS 2 / EUDI Wallet (Regulation 2024/1183; rollout 2026-2027)
  // ---- sectoral + cybersecurity directives ----
  "cmmc-2.0",        // US DoD Cybersecurity Maturity Model Certification 2.0 (effective 2025-Q1)
  "cjis-v6",         // FBI Criminal Justice Information Services Security Policy v6.0 (Dec 2024)
  "iso-27001-2022",  // ISO/IEC 27001:2022 — Information Security Management System
  "iso-27002-2022",  // ISO/IEC 27002:2022 — Code of practice for information security controls
  "iso-27017",       // ISO/IEC 27017 — Cloud-services security controls
  "iso-27018",       // ISO/IEC 27018 — PII protection in public-cloud processors
  "iso-27701",       // ISO/IEC 27701 — Privacy Information Management System
  "nist-800-66-r2",  // NIST SP 800-66 Rev 2 — HIPAA Security Rule implementation guidance                                       // NIST publication number, not bytes
  "ehds",            // EU European Health Data Space (Regulation 2025/327; phased 2027-2029)
  "circia",          // US Cyber Incident Reporting for Critical Infrastructure Act (final rule pending)
  // ---- exceptd framework-control-gap closure ----
  // Postures added to recognise every framework cited in the
  // exceptd 2026-05-11 framework-control-gaps catalog. Each posture
  // either (a) maps to a framework the operator must audit against,
  // or (b) recognises a security testing methodology / SBOM /
  // supply-chain attestation standard. Operators pin the posture
  // and the framework's cascade defaults + audit emissions match
  // the named regime's evidence expectations.
  "nist-800-53",                 // NIST SP 800-53 Rev 5 — full Moderate / High baseline
  "nist-ai-rmf-1.0",             // NIST AI Risk Management Framework 1.0
  "iso-42001-2023",              // ISO/IEC 42001:2023 — AI management system (alias for v0.8.81 iso-42001 entry, kept for posture-vocabulary stability)                                              // standard publication year, not bytes
  "iso-23894-2023",              // ISO/IEC 23894:2023 — AI risk management guidance (alias)
  "owasp-llm-top-10-2025",       // OWASP Top 10 for LLM Applications 2025
  "owasp-asvs-v5.0",             // OWASP Application Security Verification Standard v5.0
  "nist-800-218-ssdf",           // NIST SP 800-218 Secure Software Development Framework v1.1                                                                                                            // NIST pub number, not bytes
  "nist-800-82-r3",              // NIST SP 800-82 Rev 3 — OT security guide                                                       // NIST pub number, not bytes
  "nist-800-63b-rev4",           // NIST SP 800-63B Rev 4 — Digital Identity (AAL/IAL/FAL)
  "iec-62443-3-3",               // IEC 62443-3-3 — IACS system security
  "fedramp-rev5-moderate",       // FedRAMP Rev 5 Moderate baseline
  "hipaa-security-rule",         // HIPAA Security Rule 45 CFR §164.312 (technical safeguards)                                     // CFR section, not bytes
  "hitrust-csf-v11.4",           // HITRUST CSF v11.4
  "nerc-cip-007-6",              // NERC CIP-007-6 — BES Cyber System Security Management
  "psd2-rts-sca",                // EU PSD2 RTS on Strong Customer Authentication (Commission Delegated Regulation 2018/389)
  "swift-cscf-v2026",            // SWIFT Customer Security Controls Framework v2026
  "slsa-v1.0-build-l3",          // SLSA v1.0 Build Track Level 3
  "vex-csaf-2.1",                // VEX via OASIS CSAF 2.1 — b.vex primitive ships this
  "cyclonedx-v1.6",              // CycloneDX v1.6 SBOM — framework ships sbom.cdx.json
  "spdx-v3.0",                   // SPDX v3.0 SBOM — framework ships sbom.spdx.json (v0.9.6+)
  "owasp-wstg-v5",               // OWASP Web Security Testing Guide v5
  "ptes",                        // Penetration Testing Execution Standard
  "nist-800-115",                // NIST SP 800-115 Technical Guide to Information Security Testing                               // NIST pub number, not bytes
  "cwe-top-25-2024",             // CWE Top 25 Most Dangerous Software Weaknesses (2024)
  "cis-controls-v8",             // CIS Controls v8
  "cmmc-2.0-level-2",            // CMMC 2.0 Level 2 (Advanced) — 110 NIST 800-171 Rev 2 controls                                                                                                          // NIST pub number / level, not bytes
  // ---- granular CMMC level distinction ----
  // CMMC 2.0 maturity levels carry distinct control-mapping
  // expectations: Level 1 = 15 controls (FAR 52.204-21), Level 2 =
  // 110 controls (NIST 800-171 Rev 2), Level 3 = additional NIST
  // 800-172 enhanced controls. The umbrella "cmmc-2.0" posture
  // remains for back-compat with existing operators; the explicit
  // L1/L2/L3 postures are the recommended pin for new deployments.
  "cmmc-2.0-level-1",            // CMMC 2.0 Level 1 (Foundational) — 15 FAR controls; FCI-only data        // regulatory identifier, not bytes
  "cmmc-2.0-level-3",            // CMMC 2.0 Level 3 (Expert) — NIST 800-172 enhanced controls atop L2       // regulatory identifier, not bytes
  // ---- promote POSTURE_DEFAULTS-only entries into the
  // canonical KNOWN_POSTURES surface so operators can actually
  // `b.compliance.set(...)` them. Each entry had cascade
  // configuration wired but couldn't be pinned because set()'s
  // KNOWN_POSTURES check refused unknown strings.
  "42-cfr-part-2",               // 42 CFR Part 2 — Confidentiality of Substance Use Disorder Patient Records (HHS final rule 2024-02-08)                                                                                  // CFR section identifier, not bytes
  "hti-1",                       // ONC HTI-1 — Health IT certification + algorithm transparency (45 CFR Part 170; effective 2024-12-31)
  "uscdi-v4",                    // USCDI v4 — US Core Data for Interoperability v4 (ONC; 2024-01)                                          // version identifier, not bytes
  "irs-1075",                    // IRS Publication 1075 — Tax Information Security Guidelines (Rev. 11-2023)                              // publication number, not bytes
  "nist-800-172-r3",             // NIST SP 800-172 Rev 3 — Enhanced Security Requirements for CUI                                          // publication number, not bytes
  "tlp-2.0",                     // FIRST Traffic Light Protocol 2.0 — information-sharing classifications (TLP:CLEAR / GREEN / AMBER / AMBER+STRICT / RED)
  "soci-au",                     // Australia Security of Critical Infrastructure Act (SOCI 2018) + 2022 amendments
  "ffiec-cat-2",                 // FFIEC Cybersecurity Assessment Tool 2.0 (federal financial institution exam)                            // tool version, not bytes
  "cri-profile-v2.0",            // Cyber Risk Institute Profile v2.0 — financial-services framework mapping (NIST CSF cross-walk)         // version identifier, not bytes
  "m-22-09",                     // OMB M-22-09 — Federal Zero Trust Architecture Strategy
  "m-22-18",                     // OMB M-22-18 — Enhancing Software Supply Chain Security (SSDF attestation)
  "nist-800-53-r5-privacy",      // NIST SP 800-53 Rev 5 — Privacy Control Family overlay                                                   // publication number, not bytes
  "nist-ai-600-1-genai",         // NIST AI 600-1 — Generative AI Profile (companion to AI RMF 1.0)                                          // publication number, not bytes
  "nist-csf-2.0",                // NIST Cybersecurity Framework 2.0 (Feb 2024)                                                              // framework version, not bytes
  "sb-53",                       // California SB-53 — Transparency in Frontier AI Act (effective 2025-09-29)                                // statute identifier, not bytes
  "nyc-ll144-2024",              // NYC Local Law 144 — Automated Employment Decision Tool bias audits (2024 enforcement update)             // statute identifier, not bytes
]);

// Artifact standards (SBOM / VEX format families) are NOT
// regulatory regimes. Pinning a posture like `cyclonedx-v1.6` to
// cascade audit + TLS floors conflates the act of EMITTING a SBOM
// format with the regulatory floor an operator needs. Operators who
// emit CycloneDX SBOMs do so because of an underlying regime
// (FedRAMP SBOM requirement, SSDF PW.4, etc.) — not because emitting
// the format itself defines the floor.
//
// b.compliance.artifactStandards exposes the format catalog as a
// READ-ONLY channel — operators pick a format (or set of formats)
// for SBOM / VEX emission without affecting the regulatory posture
// cascade. The names remain in KNOWN_POSTURES for back-compat
// (existing operators may have pinned them); pinning them via
// b.compliance.set emits a `compliance.posture.format_as_regime`
// audit warning so the misconfiguration is grep-able in the audit
// chain.
var ARTIFACT_STANDARDS = Object.freeze([
  "cyclonedx-v1.6",          // CycloneDX 1.6 SBOM
  "spdx-v3.0",               // SPDX 3.0 SBOM
  "vex-csaf-2.1",            // VEX via OASIS CSAF 2.1
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

  // Emit a `format_as_regime` audit warning when an
  // operator pins an artifact-standard format (cyclonedx-v1.6 /
  // spdx-v3.0 / vex-csaf-2.1) as the regulatory posture. These names
  // remain in KNOWN_POSTURES for back-compat but pinning them as the
  // primary regime conflates "I emit this SBOM/VEX format" with "my
  // regulatory floor is X". Operators should pin the regulatory
  // regime (FedRAMP / SSDF / HIPAA / etc.) and surface artifact
  // standards via b.compliance.artifactStandards.
  if (ARTIFACT_STANDARDS.indexOf(posture) !== -1) {
    _emitAudit("compliance.posture.format_as_regime",
      { posture: posture, artifactStandards: ARTIFACT_STANDARDS,
        recommendation: "Artifact standards describe what SBOM/VEX format the deployment emits — not the regulatory floor. Pin the underlying regime (e.g. 'nist-800-218-ssdf', 'fedramp-rev5-moderate') and surface emitted formats via b.compliance.artifactStandards()." },
      "warning");
  }

  // Emit `fips_conflict` audit warning when posture is
  // FedRAMP / CMMC L3 AND the framework's PQC-first crypto defaults
  // are active without an explicit fipsMode opt-in. Operators see
  // this in the audit chain and either (a) document the deviation
  // in their SSP or (b) set b.compliance.fipsMode(true) before set()
  // to switch the audit-signing path to FIPS-validated AES-GCM +
  // SHA-384.
  var FIPS_BOUNDARY_POSTURES = ["fedramp-rev5-moderate", "cmmc-2.0-level-3"];
  if (FIPS_BOUNDARY_POSTURES.indexOf(posture) !== -1 && !STATE.fipsMode) {
    _emitAudit("compliance.posture.fips_conflict",
      { posture: posture,
        cryptoDefaults: "PQC-first (ML-KEM-1024 / SLH-DSA-SHAKE-256f / XChaCha20-Poly1305 / SHA3-512)",
        fipsMode: false,
        recommendation: "Call b.compliance.fipsMode(true) BEFORE b.compliance.set() to switch b.audit.sign to FIPS-140-3 validated AES-GCM + SHA-384, or document the PQC-first deviation in the SSP." },
      "warning");
  }

  // Cascade the posture into every primitive that owns a
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
  // TZ awareness. Auditors expect timestamps in UTC.
  // process.env.TZ controls Node's local-time conversion for any
  // operator code that uses non-UTC formatters; under regulated
  // postures (hipaa / pci-dss / sox / gdpr / soc2) emit a boot
  // warning if it's set to a non-UTC value or unset (which means
  // host-default which on most cloud images IS UTC but isn't
  // guaranteed). Pure signal — no behavior change.
  var REGULATED = ["hipaa", "pci-dss", "sox", "gdpr", "soc2", "fda-21cfr11"];
  if (REGULATED.indexOf(posture) !== -1) {
    var tz = process.env.TZ;                                                                  // allow:raw-process-env-bootstrap — bootstrap signal, no operator-supplied default needed
    if (typeof tz === "string" && tz !== "UTC" && tz !== "Etc/UTC") {
      _emitAudit("compliance.posture.tz_warning",
        { posture: posture, tz: tz, recommendation: "Set TZ=UTC under regulated postures so audit timestamps align with regulator expectations." },
        "warning");
    }
  }

  // Outbound-DLP wiring signal. A posture whose floor implies an
  // outbound-DLP gate is being pinned, but set() cannot install the
  // interceptors itself (no httpClient / mail / webhook handles). Warn
  // once when nothing is wired so the gap is visible in the audit chain
  // rather than a silent paper-compliance hole. Fires at most once per
  // pin (set() is idempotent for the same posture).
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

// _applyPostureCascade — walks every primitive that
// participates in posture-conditioned defaults and asks it to merge
// the named posture into its state. Each step is best-effort at the
// audit-emission level (a primitive that isn't loaded yet emits
// 'skipped'); each step's success/skipped emits its own audit row so
// operators can confirm the cascade landed without re-reading
// state.posture per primitive.
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
  // Reserved for tests + operator-controlled tear-down. Emits an audit
  // row so the chain shows the posture was intentionally cleared.
  if (STATE.posture) {
    _emitAudit("compliance.posture.cleared", { previous: STATE.posture });
  }
  STATE.posture = null;
  STATE.setAt   = null;
  // Cascade the reset the same way set() cascades the posture — otherwise a
  // primitive that inherits the active posture (e.g. retention.complianceFloor)
  // keeps applying the stale floor after the global posture was cleared.
  _applyPostureCascade(null);
}

function _resetForTest() {
  STATE.posture  = null;
  STATE.setAt    = null;
  STATE.fipsMode = false;
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
  // v0.8.77 — US state consumer-privacy postures
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
  // ---- AI governance ----
  "co-ai":       { name: "Colorado AI Act",                            citation: "C.R.S. §6-1-1701 et seq. SB24-205 (postponed to 2026-06-30; enforcement stayed)", jurisdiction: "US-CO", domain: "ai-governance" },
  "il-hb3773":   { name: "Illinois HB 3773 — AI in Employment",        citation: "775 ILCS 5 IHRA AI amendment (effective 2026-01-01)", jurisdiction: "US-IL", domain: "ai-governance" },
  "tx-traiga":   { name: "Texas Responsible AI Governance Act",        citation: "Tex. Bus. & Com. Code Ch. 552 HB 149 (effective 2026-01-01)", jurisdiction: "US-TX", domain: "ai-governance" },
  "ut-aipa":     { name: "Utah AI Disclosure Act (UAIPA)",             citation: "Utah Code §13-2-12 SB149 + 2025 amendments (sunset 2027-07-01)", jurisdiction: "US-UT", domain: "ai-governance" },
  "nyc-ll144":   { name: "NYC Automated Employment Decision Tools Law", citation: "NYC Admin. Code §20-870 et seq. Local Law 144 (in force 2023-07-05)", jurisdiction: "US-NY-NYC", domain: "ai-governance" },
  "ca-tfaia":    { name: "California Transparency in Frontier AI Act",  citation: "Cal. Bus. & Prof. Code §22757.10 et seq. SB 53 (effective 2026-01-01)", jurisdiction: "US-CA", domain: "ai-governance" },
  "kr-ai-basic": { name: "South Korea AI Basic Act",                    citation: "Framework Act on Development of AI (effective 2026-01-22)", jurisdiction: "KR", domain: "ai-governance" },
  "cn-ai-label": { name: "China — Measures for Labelling AI-Generated Content", citation: "CAC + MIIT + Ministry of Public Security + NRTA Order (effective 2025-09-01)", jurisdiction: "CN", domain: "ai-governance" },
  // ---- AI management cross-walks ----
  "iso-42001":   { name: "ISO/IEC 42001 — AI Management System",        citation: "ISO/IEC 42001:2023", jurisdiction: "international", domain: "ai-governance" },
  "iso-23894":   { name: "ISO/IEC 23894 — AI Risk Management",          citation: "ISO/IEC 23894:2023", jurisdiction: "international", domain: "ai-governance" },
  // ---- content-credentials posture flags ----
  "ca-sb942":    { name: "California Gen-AI Provenance Disclosure",     citation: "Cal. Bus. & Prof. Code §22757 SB-942 (effective 2026-08-02)", jurisdiction: "US-CA", domain: "content-credentials" },
  "ca-ab853":    { name: "California Platform Gen-AI Detection",        citation: "Cal. Bus. & Prof. Code §22757 AB-853 (effective 2026-08-02)", jurisdiction: "US-CA", domain: "content-credentials" },
  // ---- substrate-to-posture cleanup ----
  "eaa":         { name: "EU Accessibility Act",                        citation: "Directive (EU) 2019/882 (effective 2025-06-28)", jurisdiction: "EU", domain: "accessibility" },
  "wcag-2-2":    { name: "W3C Web Content Accessibility Guidelines 2.2", citation: "W3C Recommendation (Oct 2023)", jurisdiction: "international", domain: "accessibility" },
  "eu-data-act": { name: "EU Data Act",                                 citation: "Regulation (EU) 2023/2854 (effective 2025-09-12)", jurisdiction: "EU", domain: "data-sharing" },
  "hitech":      { name: "Health Information Technology for Economic and Clinical Health Act", citation: "Pub. L. 111-5, Title XIII, Subtitle D (2009)", jurisdiction: "US", domain: "health" },
  "ferpa":       { name: "Family Educational Rights and Privacy Act",   citation: "20 U.S.C. §1232g; 34 CFR Part 99", jurisdiction: "US", domain: "student-records" },
  "dpdp":        { name: "Digital Personal Data Protection Act 2023",   citation: "Act 22 of 2023 (India; rules pending)", jurisdiction: "IN", domain: "privacy" },
  // ---- privacy 2026 sweep ----
  // US federal
  "coppa":           { name: "Children's Online Privacy Protection Act",         citation: "15 U.S.C. §§6501-6506; 16 CFR Part 312 (effective 2000-04-21)", jurisdiction: "US", domain: "child-privacy" },
  "coppa-2025":      { name: "COPPA 2025 Amendment",                              citation: "FTC final rule (2025-04-22; effective 2026-06-23) — biometric expansion + knowing-collection-13-and-under disclosure", jurisdiction: "US", domain: "child-privacy" },
  "glba-safeguards": { name: "GLBA Safeguards Rule 2024 Amendment",               citation: "16 CFR Part 314 (effective 2024-05-13)", jurisdiction: "US", domain: "financial-privacy" },
  "gina":            { name: "Genetic Information Nondiscrimination Act",        citation: "Pub. L. 110-233; 42 U.S.C. §2000ff et seq. (effective 2009-11-21)", jurisdiction: "US", domain: "genetic-privacy" },
  "vppa":            { name: "Video Privacy Protection Act",                     citation: "18 U.S.C. §2710 (effective 1988-11-05)", jurisdiction: "US", domain: "consumer-privacy" },
  "can-spam":        { name: "CAN-SPAM Act",                                     citation: "15 U.S.C. §§7701-7713; 16 CFR Part 316 (effective 2004-01-01)", jurisdiction: "US", domain: "consumer-privacy" },
  "il-gipa":         { name: "Illinois Genetic Information Privacy Act",         citation: "410 ILCS 513 (private right of action post-2024 amendment)", jurisdiction: "US-IL", domain: "genetic-privacy" },
  "hhs-repro-24":    { name: "HHS Reproductive Health HIPAA Amendment 2024",     citation: "45 CFR Parts 160, 164 — Final Rule (effective 2024-12-23)", jurisdiction: "US", domain: "health" },
  // NIST cross-walk
  "nist-pf-1.1":     { name: "NIST Privacy Framework 1.1",                       citation: "NIST PF 1.1 (final 2025-04-14)", jurisdiction: "US", domain: "privacy" },
  // UK
  "uk-duaa":         { name: "UK Data (Use and Access) Act 2025",                citation: "DUAA c. 26 (Royal Assent 2025-06-19; replaces DPDI Bill)", jurisdiction: "UK", domain: "privacy" },
  // Latin America
  "cl-pdpa":         { name: "Chile Ley 21.719 Protección de Datos Personales",  citation: "Ley 21.719 (enacted 2024-12-13; effective 2026-12-01)", jurisdiction: "CL", domain: "privacy" },
  "mx-lfpdppp":      { name: "Mexico LFPDPPP + 2025 reform",                     citation: "Ley Federal de Protección de Datos Personales en Posesión de los Particulares (2010 + 2025 secondary reform)", jurisdiction: "MX", domain: "privacy" },
  "ar-pdpa":         { name: "Argentina Personal Data Protection Act",            citation: "Ley 25.326 + 2024 modernization bill (pending)", jurisdiction: "AR", domain: "privacy" },
  // APAC
  "pipa-kr":         { name: "South Korea Personal Information Protection Act",   citation: "PIPA 2011 + 2023 major amendment (phased 2023-09-15 / 2024-03-15)", jurisdiction: "KR", domain: "privacy" },
  "au-privacy":      { name: "Australia Privacy Act + 2024 Amendment Act",        citation: "Privacy Act 1988 + Privacy and Other Legislation Amendment Act 2024 (first tranche 2024-12-10; statutory tort 2025-06-10)", jurisdiction: "AU", domain: "privacy" },
  "th-pdpa":         { name: "Thailand Personal Data Protection Act",             citation: "PDPA B.E. 2562 (2019; full effect 2022-06-01)", jurisdiction: "TH", domain: "privacy" },
  "vn-pdp":          { name: "Vietnam Personal Data Protection Law",              citation: "Decree 13/2023 + PDP Law (effective 2026-01-01)", jurisdiction: "VN", domain: "privacy" },
  "id-pdp":          { name: "Indonesia Personal Data Protection Law",            citation: "Law 27 of 2022 (effective 2024-10-17)", jurisdiction: "ID", domain: "privacy" },
  "my-pdpa":         { name: "Malaysia Personal Data Protection Act",             citation: "PDPA 2010 + 2024 amendments (effective 2025-04-30)", jurisdiction: "MY", domain: "privacy" },
  // US state child privacy
  "ny-safe-kids":    { name: "NY Child Data Protection Act / SAFE for Kids Act",  citation: "N.Y. Gen. Bus. Law §899-ff et seq. (effective 2025-06-20)", jurisdiction: "US-NY", domain: "child-privacy" },
  "ny-saffe":        { name: "NY Stop Addictive Feeds Exploitation for Kids Act", citation: "N.Y. Gen. Bus. Law §1500 et seq. (effective 2025-06-20)", jurisdiction: "US-NY", domain: "child-privacy" },
  "md-kids-code":    { name: "Maryland Age-Appropriate Design Code",              citation: "Md. Code Ann., Com. Law §14-4901 et seq. (enacted 2024)", jurisdiction: "US-MD", domain: "child-privacy" },
  "vt-aadc":         { name: "Vermont Age-Appropriate Design Code",               citation: "Vt. Stat. Ann. tit. 9 §2447 et seq. (enacted 2024)", jurisdiction: "US-VT", domain: "child-privacy" },
  // EU non-personal-data + adjacent
  "dsa":             { name: "EU Digital Services Act",                          citation: "Regulation (EU) 2022/2065 (fully applicable 2024-02-17)", jurisdiction: "EU", domain: "platform-governance" },
  "dga":             { name: "EU Data Governance Act",                           citation: "Regulation (EU) 2022/868 (applicable 2023-09-24)", jurisdiction: "EU", domain: "data-sharing" },
  "eu-cer":          { name: "EU Critical Entities Resilience Directive",        citation: "Directive (EU) 2022/2557 (transposition 2024-10-17)", jurisdiction: "EU", domain: "cybersecurity" },
  "eu-cyber-sol":    { name: "EU Cyber Solidarity Act",                          citation: "Regulation (EU) 2025/38 (effective 2025-02-04)", jurisdiction: "EU", domain: "cybersecurity" },
  "eidas-2":         { name: "eIDAS 2 / EUDI Wallet",                            citation: "Regulation (EU) 2024/1183 (rollout 2026-2027)", jurisdiction: "EU", domain: "identity" },
  // ---- sectoral + cybersecurity directives ----
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
  // ---- REGIME_MAP backfill for KNOWN_POSTURES without
  // describe() coverage. Each entry resolves `b.compliance.describe
  // (posture)` → { name, citation, jurisdiction, domain } so admin
  // UI / generated audit reports rendering "running under <name>
  // (<citation>)" stops getting null.
  // ---- POSTURE_DEFAULTS-orphan postures promoted into KNOWN_POSTURES ----
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
  // ---- Pre-existing KNOWN_POSTURES that lacked REGIME_MAP records ----
  "sox-404":         { name: "Sarbanes-Oxley §404 — Internal Controls over Financial Reporting", citation: "15 U.S.C. §7262",               jurisdiction: "US", domain: "financial-reporting" },
  "soc2-cc1.3":      { name: "SOC 2 Trust Services Criterion CC1.3 — Segregation of Duties", citation: "AICPA Trust Services Criteria CC1.3", jurisdiction: "US", domain: "audit-attestation" },
  "fapi-2.0":        { name: "Financial-grade API 2.0 Final",                   citation: "OpenID Foundation FAPI 2.0 Final (Feb 2025)",     jurisdiction: "international", domain: "financial" },
  "cfpb-1033":       { name: "CFPB §1033 — Personal Financial Data Rights",     citation: "12 CFR Part 1033 (Final Rule 2024-10-22; tiered effective dates from 2026-04-01)", jurisdiction: "US", domain: "financial" },
  "iab-tcf-v2.3":    { name: "IAB Transparency & Consent Framework v2.3",       citation: "IAB Europe TCF v2.3 (Sep 2024)",                  jurisdiction: "EU", domain: "advertising" },
  "iab-mspa":        { name: "IAB Multi-State Privacy Agreement",               citation: "IAB Tech Lab MSPA + Global Privacy Platform",     jurisdiction: "US", domain: "privacy" },
  "tcpa-10dlc":      { name: "TCPA 10DLC Messaging Compliance",                 citation: "47 U.S.C. §227 + CTIA 10DLC + FCC 1:1 disclosure rule", jurisdiction: "US", domain: "telecommunications" },
  "fda-21cfr11":     { name: "FDA 21 CFR Part 11 — Electronic Records / Signatures", citation: "21 CFR Part 11",                          jurisdiction: "US", domain: "life-sciences" },
  "fda-annex-11":    { name: "EU GMP Annex 11 — Computerized Systems",          citation: "EudraLex Vol. 4 Annex 11",                        jurisdiction: "EU", domain: "life-sciences" },
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
  // ---- REGIME_MAP backfill (cybersecurity / AI / supply-chain frameworks) ----
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

// POSTURE_DEFAULTS — per-posture configuration knobs that primitives
// (b.backup, b.retention, b.audit, b.cryptoField, b.db, etc.) consult
// when the operator hasn't passed an explicit value. Not user-facing
// config — primitives look up here at boot to enforce regulatory
// floors.
//
// Keys per posture:
//   backupEncryptionRequired  — backup.create refuses encrypt:false
//   auditChainSignedRequired  — audit emissions MUST be ML-DSA-87 chain-signed
//   tlsMinVersion             — minimum TLS version (string e.g. "TLSv1.3")
//   sessionAbsoluteTimeoutMs  — hard session expiry ceiling
//   requireVacuumAfterErase   — cryptoField.eraseRow must call
//                               b.db.vacuumAfterErase({ mode: "full" })
//                               so freed B-tree index pages don't linger
//                               with sealed-column ciphertext readable
//                               from a forensic disk image. GDPR Art. 17
//                               + DPDP §12 + LGPD-BR Art. 18 + PIPL-CN
//                               Art. 47 all require effective erasure;
//                               leftover index residue defeats it.
//   sealEnvelopeFloor         — minimum field-level seal envelope a
//                               sealed-column table may declare under
//                               this posture: "plain" (vault.seal, no
//                               AAD), "aad" (AEAD-bound to table/row/
//                               column via b.vault.aad), or "per-row-key"
//                               (K_row crypto-shred). cryptoField.
//                               registerTable refuses a table whose
//                               declared envelope is below the floor when
//                               this posture is the globally-pinned one.
//                               PCI-DSS Req. 3.5/3.6 (PAN render
//                               unreadable, key-management binding) and
//                               HIPAA 45 CFR 164.312(a)(2)(iv) +
//                               164.312(e)(2)(ii) (encryption that
//                               resists ciphertext relocation, CWE-311 /
//                               CWE-326) need an AAD-bound envelope at
//                               minimum so a DB-write attacker cannot
//                               copy a sealed cell between rows. Absent
//                               on a posture → no floor (back-compat;
//                               plain envelopes keep registering).
//
// This table is the single source-of-truth — duplicating values into
// per-primitive defaults would drift the moment a regulator updates.
var POSTURE_DEFAULTS = Object.freeze({
  "hipaa": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
    // 45 CFR 164.312(a)(2)(iv) + (e)(2)(ii) — ePHI encryption must
    // resist ciphertext relocation; a plain vault.seal cell can be
    // copied between rows undetected (CWE-311 / CWE-326). AAD-bound
    // envelope is the floor.
    sealEnvelopeFloor:        "aad",
  }),
  "pci-dss": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  false,
    // PCI-DSS v4 Req. 3.5 (PAN unreadable) + Req. 3.6 (key-management
    // binding) — the seal must bind cardholder data to its storage
    // location so a relocated ciphertext fails to verify. AAD-bound
    // envelope is the floor.
    sealEnvelopeFloor:        "aad",
  }),
  "gdpr": Object.freeze({
    backupEncryptionRequired: false,           // GDPR Art. 32 says "appropriate" — not mandatory floor
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
  // UK GDPR (DPA 2018 + retained EU GDPR) — Art. 17 right to erasure
  // applies identically to GDPR, including residual B-tree pages.
  "uk-gdpr": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // Japan APPI — deletion/cessation right with residue-cleanup floor.
  "appi-jp": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // Singapore PDPA — right to erasure with effectiveness floor.
  "pdpa-sg": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // v0.8.70 — 2026 effective deadlines
  "modpa": Object.freeze({
    // Maryland Online Data Privacy Act (effective 2026-10-01) —
    // unique among US state privacy laws for its strict data-
    // minimization standard ("reasonably necessary"). The cascade
    // floors mirror GDPR-tier audit + at-rest encryption.
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "nydfs-500": Object.freeze({
    // NYDFS 23 NYCRR 500 Amendment 2 — financial cyber. Adds
    // mandatory MFA, annual penetration test, asset inventory,
    // governance reporting. Floor: encrypted backups + signed
    // audit chain (already true), TLS 1.3 minimum.
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "hipaa-2026": Object.freeze({
    // HHS HIPAA Security Rule final 2026-Q4 — extends hipaa with
    // mandatory MFA, asset inventory, 72h restoration testing,
    // expanded encryption-at-rest scope.
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  "quebec-25": Object.freeze({
    // Quebec Law 25 final phase (effective 2026-09-22) — DPIA
    // mandatory for high-risk processing + automated-decision
    // explanation right. Cascade floor: encrypted backups + signed
    // audit chain.
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // v0.8.81 — Florida Digital Bill of Rights SB 262 (effective
  // 2024-07-01). Narrow scope ($1B+ revenue threshold); privacy-tier
  // floor matching peer state consumer-privacy postures.
  "fl-fdbr": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // v0.8.81 — HITECH Act extends HIPAA; treat as HIPAA-tier floor
  // (encrypted backups, signed audit chain, vacuum-after-erase).
  "hitech": Object.freeze({
    backupEncryptionRequired: true,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // v0.8.81 — FERPA covers student educational records; treat as
  // privacy-tier with full erasure-residue cleanup (record-purge
  // workflows for transferred students).
  "ferpa": Object.freeze({
    backupEncryptionRequired: false,
    auditChainSignedRequired: true,
    tlsMinVersion:            "TLSv1.3",
    requireVacuumAfterErase:  true,
  }),
  // v0.8.81 — AI-governance postures share an audit-chain-signed
  // floor so AI-decision audit trails survive forensic challenge
  // (NYC LL144 annual bias audit, IL HB 3773 employment notice
  // chain, Colorado AI Act impact-assessment records, Utah UAIPA
  // disclosure ledger). TLS-1.3 minimum + signed chain only; no
  // vacuum-after-erase mandate at this tier.
  "co-ai":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "il-hb3773":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "tx-traiga":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ut-aipa":     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nyc-ll144":   Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ca-tfaia":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }), // Frontier-AI critical-incident records: encrypted at rest, residue-clean on erasure
  "kr-ai-basic": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cn-ai-label": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // v0.8.81 — ISO/IEC 42001 + 23894 — voluntary AI management
  // certifications. Cascade matches the strictest peer (audit-chain
  // signed + TLS 1.3); operators chasing ISO certification under a
  // base regulated posture get strict cumulative floors via
  // postureDefault() reads.
  "iso-42001":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-23894":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.81 — California SB-942 + AB-853 are content-credentials
  // posture flags, not data-floor regulations. Cascade leaves
  // operator-controlled defaults in place (no backup encryption
  // mandate, no residue-vacuum mandate); the meaningful effect rides
  // through b.contentCredentials manifest emission, not the data
  // tier. TLS 1.3 retained as the framework-wide floor.
  "ca-sb942":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "ca-ab853":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // v0.8.81 — EAA + WCAG 2.2 are accessibility postures; no data-
  // floor cascade. The meaningful effect rides through
  // b.guardHtml.wcag + b.compliance-eaa primitives.
  "eaa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "wcag-2-2":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // v0.8.81 — EU Data Act covers B2G + IoT-data sharing; cascade
  // floor matches GDPR-tier audit signing + TLS 1.3.
  "eu-data-act": Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — COPPA + 2025 Amendment: child-data deletion + age-verification
  // floor (operator-facing rule: when a covered child is identified, knowing-
  // collection beyond age 13 requires verifiable parental consent; on
  // withdrawal, full residue cleanup applies). Cascade: signed audit chain
  // + vacuum-after-erase + TLS 1.3.
  "coppa":           Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "coppa-2025":      Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — GLBA Safeguards 2024 Amendment: financial-tier cascade
  // matching pci-dss + nydfs-500 floor (encrypted backups + signed audit +
  // TLS 1.3). No vacuum-after-erase mandate at this tier.
  "glba-safeguards": Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // v0.8.82 — UK DUAA 2025: privacy-tier with GDPR-equivalent floor
  // (signed audit + TLS 1.3 + vacuum-after-erase per UK GDPR Art. 17).
  "uk-duaa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — Chile Ley 21.719: GDPR-equivalent privacy floor with
  // strict effective-erasure obligation under the right-to-erasure
  // article (Art. 8). Cascade mirrors gdpr.
  "cl-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — Korea PIPA: privacy-tier with full erasure-residue cleanup
  // under the right-to-erasure article. Cascade matches gdpr/lgpd-br tier.
  "pipa-kr":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — Australia Privacy Act 2024 Amendment: privacy-tier with
  // statutory-tort exposure. Encrypted backups + signed audit + vacuum-
  // after-erase per statutory right-to-erasure.
  "au-privacy":      Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — Other LATAM + APAC postures share the GDPR-equivalent
  // privacy floor.
  "mx-lfpdppp":      Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ar-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "th-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vn-pdp":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "id-pdp":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "my-pdpa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — US state child-privacy + cross-cutting US statutes.
  "ny-safe-kids":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "ny-saffe":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "md-kids-code":    Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vt-aadc":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "gina":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "vppa":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "can-spam":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "il-gipa":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "hhs-repro-24":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.82 — NIST Privacy Framework 1.1 cross-walk posture; cascade
  // matches gdpr-tier audit signing.
  "nist-pf-1.1":     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // v0.8.82 — EU platform/data/cyber adjacent: audit-chain signed,
  // TLS 1.3, no special data-tier mandate at this layer.
  "dsa":             Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "dga":             Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-cer":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eu-cyber-sol":    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "eidas-2":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // v0.8.86 — sectoral + cybersecurity directives. DoD CMMC + FBI
  // CJIS + healthcare regimes share an encrypted-at-rest + signed-
  // audit-chain floor; ISO 27001/27002 + ISO 27017/27018/27701 are
  // operator-adopted governance standards with the same baseline.
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
  // ---- exceptd framework-control-gap closure cascade ----
  "nist-800-53":             Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // NIST AI-RMF MANAGE.4.3 / ISO 23894 §6.5 / ISO 42001
  // §A.6 require encrypted backups for AI system state (model
  // weights, training data, prompt logs all contain regulated
  // payload). All AI-domain postures now enforce backupEncryption.
  "nist-ai-rmf-1.0":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-42001-2023":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "iso-23894-2023":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "owasp-llm-top-10-2025":   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // OWASP ASVS v5.0 §8.3.4 (sensitive-data deletion)
  // requires post-delete storage reclamation. Set requireVacuumAfterErase
  // so operators pinning ASVS v5.0 inherit the proper floor.
  "owasp-asvs-v5.0":         Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "nist-800-218-ssdf":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-82-r3":          Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "nist-800-63b-rev4":       Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "iec-62443-3-3":           Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // FedRAMP Rev 5 Moderate baseline references FIPS 140-3
  // validated cryptography for protect-against-disclosure controls
  // (SC-13, SC-28). The framework's PQC-first defaults (ML-KEM-1024,
  // XChaCha20-Poly1305, SHA3-512) are NOT FIPS-140-3 validated as of
  // the FedRAMP Rev 5 baseline publication — FIPS modules are still
  // being certified for the ML-KEM / ML-DSA primitives upstream.
  //
  // Conflict resolution: PQC-first remains the framework default
  // — the framework refuses to weaken security middleware to fit a
  // posture flag. Operators in a FedRAMP boundary opt into
  // `fipsMode: true` to
  // switch `b.audit.sign` from SLH-DSA-SHAKE-256f to FIPS-validated
  // AES-GCM + SHA-384 for the audit-chain signing path. The runtime
  // emits a `compliance.posture.fips_conflict` audit warning when
  // posture=fedramp-rev5-moderate AND fipsMode is NOT set so the
  // conflict is grep-able in the audit chain.
  //
  // Operators pinning this posture without setting fipsMode are
  // signaling "ship the PQC-first defaults and accept that the
  // FedRAMP boundary will need to document the deviation in their
  // SSP." The audit warning is the operator-visible signal.
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
  // CMMC 2.0 levels differ in control mapping:
  //   L1 (Foundational, 15 FAR controls, FCI data only) — encrypted
  //       backups NOT mandated; audit-chain encouraged.
  //   L2 (Advanced, 110 NIST 800-171 Rev 2 controls, CUI data) —
  //       encrypted backups + signed audit + post-erase vacuum.
  //   L3 (Expert, NIST 800-172 enhanced atop L2) — same control floor
  //       as L2 plus operator-attested enhanced practices the
  //       framework can't auto-cascade (FIPS 140-3 boundary,
  //       continuous monitoring).
  "cmmc-2.0-level-1":        Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  "cmmc-2.0-level-2":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  "cmmc-2.0-level-3":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true, fipsMode: false }),
  // ---- sectoral catch-up ----
  // 42 CFR Part 2 — Substance Use Disorder records confidentiality
  // (HHS final rule 2024-04-16 aligns Part 2 with HIPAA but retains
  // a stricter consent floor; encrypted backups + signed audit chain
  // + post-erase vacuum because the rule narrows the consent window
  // and operators must demonstrate effective erasure on revocation).
  "42-cfr-part-2":           Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // ONC HTI-1 final rule (45 CFR Part 170 / 89 FR 1192, effective
  // 2024-12-31) — health IT certification. Brings algorithmic
  // transparency / DSI (Decision Support Interventions) requirements.
  // Cascade: encrypted backups + signed audit + vacuum (PHI-tier).
  "hti-1":                   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // USCDI v4 (ONC October 2023) — US Core Data for Interoperability
  // standard data classes for EHR exchange. PHI-tier cascade.
  "uscdi-v4":                Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // IRS Publication 1075 — Federal Tax Information (FTI) safeguards.
  // FTI-tier: encrypted at rest, signed audit, vacuum after erasure
  // (Pub 1075 §4.3 requires sanitization on disposal).
  "irs-1075":                Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // NIST 800-172 Rev 3 — Enhanced Security Requirements for Protecting
  // CUI. Layered atop 800-171 / CMMC-L2. FIPS-validated crypto
  // floor — same operator-opt-in flag pattern as fedramp-rev5-moderate.
  "nist-800-172-r3":         Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true, fipsMode: false }),
  // FIRST Traffic Light Protocol 2.0 (August 2022) — controls sharing
  // of cyber threat information. Cascade: signed audit chain (the
  // protocol's normative effect is on the audit + sharing surface,
  // not data-at-rest).
  "tlp-2.0":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // Security of Critical Infrastructure Act 2018 (Australia, SOCI Act)
  // + 2021/2022 amendments — critical-infrastructure cyber + ENS
  // (Enhanced Cyber Security Obligations). Cascade: encrypted backups
  // + signed audit (ENS §30CT data-integrity obligation).
  "soci-au":                 Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // EU NIS 2 Directive (Directive (EU) 2022/2555) — transposition
  // deadline 2024-10-17. Cybersecurity for essential + important
  // entities. Encrypted backups + signed audit chain (Art. 21(2)(d)
  // requires backup management + crisis recovery).
  "nis2":                    Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // EU Cyber Resilience Act (Reg. (EU) 2024/2847) — product
  // cybersecurity; full applicability 2027-12-11 with reporting
  // obligations starting 2026-09-11. SUPPLY-tier cascade.
  "cra":                     Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // FFIEC Cybersecurity Assessment Tool 2.0 — financial-tier; aligns
  // with NIST CSF 2.0 + CRI Profile. Cascade matches glba-safeguards.
  "ffiec-cat-2":             Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // CRI Profile v2.0 (Cyber Risk Institute, May 2024) — financial-tier
  // cyber risk + NIST CSF 2.0 cross-walk.
  "cri-profile-v2.0":        Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // OMB M-22-09 — Moving to Zero Trust (US federal). Cascade: signed
  // audit + TLS 1.3 (the memorandum's normative effect rides through
  // the identity + segmentation surfaces).
  "m-22-09":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // OMB M-22-18 — Enhancing the Security of the Software Supply Chain
  // (the SSDF / attestation requirement). SUPPLY-tier — audit-chain
  // signed for the attestation records.
  "m-22-18":                 Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // NIST 800-53 Rev 5 Privacy baseline — additive privacy controls
  // overlay. Cascade: vacuum-after-erase per PT-2(2) and SI-12.
  "nist-800-53-r5-privacy":  Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // NIST AI-RMF Generative AI Profile (NIST AI 600-1, July 2024) —
  // generative AI risk management overlay. AI-tier cascade.
  "nist-ai-600-1-genai":     Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // NIST CSF 2.0 (February 2024) — Cybersecurity Framework with the
  // GOVERN function added.
  "nist-csf-2.0":            Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // SB 53 / California Frontier AI Disclosure (effective 2026 fiscal)
  // — frontier-model critical incident disclosure ledger.
  "sb-53":                   Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // NYC Local Law 144 (2023) — Automated Employment Decision Tools
  // (bias-audit + candidate notice) — bias-audit posture (already
  // present as "nyc-ll144"); 2024 amendment adds annual re-audit
  // signing.
  "nyc-ll144-2024":          Object.freeze({ backupEncryptionRequired: false, auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: false }),
  // Regulation (EU) 2024/1689 (EU AI Act) — Art. 50 transparency
  // obligations enter force 2026-08-02 (v0.12.12 disclosure
  // primitives). High-risk system providers must audit-chain
  // every model-training + deployment event (Art. 12 logging) +
  // sign the chain (Art. 15 cybersecurity / accuracy /
  // robustness). Vacuum-after-erase covers Art. 50(4) synthetic-
  // content provenance — when a model-generated image is
  // erased from a system's storage, the residual EXIF / metadata
  // entries pointing at the model must be cleared too.
  "eu-ai-act":               Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // The legacy `ai-act` short
  // name carries the SAME cascade as `eu-ai-act` so deployments
  // pinned to the legacy alias get the new encryption / audit /
  // TLS / vacuum floors instead of falling through to null. The
  // back-compat KNOWN_POSTURES entry exists; the POSTURE_DEFAULTS
  // row was missing.
  "ai-act":                  Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // California AB-853 (effective 2026) — model-generated content
  // watermarking + provenance. Same encryption + audit posture
  // as eu-ai-act (these regimes line up); requireVacuumAfterErase
  // tracks the erase-of-watermarked-content invariant.
  "ca-ab-853":               Object.freeze({ backupEncryptionRequired: true,  auditChainSignedRequired: true, tlsMinVersion: "TLSv1.3", requireVacuumAfterErase: true  }),
  // China CAC Generative AI Service Measures (effective 2023-08;
  // 2024 mandatory-labelling amendment). Synthetic-content
  // labelling per Art. 12 + algorithm filing per Art. 4.
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
 * Recognised keys per posture include `backupEncryptionRequired`,
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

// Postures whose jurisdictions restrict cross-border data transfer
// (GDPR Art 44-46 / UK-GDPR / DPDP §16 / PIPL Art 38 / LGPD Art 33 /
// APPI Art 28 / PDPA §26). The residency write gates (db-query local,
// external-db backend/replica) refuse mismatched writes under these;
// other postures observe-and-audit only.
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

// Region-tag wildcards. Both spellings mean "no residency constraint"
// across the framework — the external-db gate uses "unrestricted" as
// its default + wildcard, while the local db-query / external-db row
// gates also accept "global" as the region-neutral row tag. Normalizing
// folds both to "unrestricted" so callers reason about one wildcard.
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
  if (na === null || nb === null) return true;            // no constraint either side
  if (na === nb) return true;                             // identical region (post-normalize)
  if (na === "unrestricted" || nb === "unrestricted") return true; // wildcard either side
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
