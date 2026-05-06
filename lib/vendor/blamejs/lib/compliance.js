"use strict";
/**
 * b.compliance — top-level compliance-posture coordinator.
 *
 * Sets a global posture (`hipaa` / `pci-dss` / `gdpr` / `soc2` /
 * `dora`) that primitives with a `compliancePosture` opt fall back to
 * when the operator hasn't passed one explicitly. Single source of
 * truth for "what regulatory posture is this deployment running
 * under?".
 *
 *   b.compliance.set("hipaa");
 *   b.compliance.current();        // → "hipaa"
 *   b.compliance.assert("hipaa");  // throws if not the named posture
 *
 *   // Every primitive with a compliancePosture opt now picks "hipaa"
 *   // by default:
 *   var gate = b.guardCsv.gate({});               // hipaa overlay applied
 *   var ttl  = b.retention.complianceFloor("hipaa", customTtl);
 *
 * Boot-time only — `set()` MUST run before the primitives it
 * coordinates are first used. Runtime switches are forbidden because
 * they would create a half-set state across primitives that have
 * already initialized.
 *
 * Audit emission: `compliance.posture.set` on every successful
 * `set()`, `compliance.posture.cleared` on `clear()`. Operators
 * tracking deploys can grep audit for these to reconstruct posture
 * history per deployment.
 */

var lazyRequire = require("./lazy-require");
var sanctions = require("./compliance-sanctions");
var aiAct     = require("./compliance-ai-act");
var { ComplianceError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

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
}

function current() {
  return STATE.posture;
}

function assert(posture) {
  if (STATE.posture !== posture) {
    throw new ComplianceError("compliance/assertion-failed",
      "compliance.assert('" + posture + "'): current posture is " +
      JSON.stringify(STATE.posture));
  }
}

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

function describe(posture) {
  return REGIME_MAP[posture] || null;
}

// posturesByDomain — list every posture that maps to the named
// domain (privacy / health / payment / cybersecurity / etc.).
// Operators rendering compliance dashboards grouped by domain pull
// the per-domain posture list with this; admin UIs that show "we
// satisfy the privacy regimes for {users.country}" use it to pick
// the right posture name without hand-rolling the lookup.
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
  sanctions:              sanctions,
  aiAct:                  aiAct,
  KNOWN_POSTURES:         KNOWN_POSTURES,
  REGIME_MAP:             REGIME_MAP,
  ComplianceError:        ComplianceError,
  _resetForTest:          _resetForTest,
};
