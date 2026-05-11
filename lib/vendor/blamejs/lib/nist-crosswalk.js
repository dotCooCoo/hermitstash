"use strict";
/**
 * @module     b.nistCrosswalk
 * @nav        Audit & Compliance
 * @title      NIST control crosswalk
 * @order      150
 * @slug       nist-crosswalk
 *
 * @intro
 *   Crosswalk catalog mapping NIST control IDs — SP 800-53 Rev 5 (federal
 *   systems), NIST CSF 2.0 (cyber risk management), SP 800-171 Rev 3
 *   (CUI / non-federal), and SP 800-218 SSDF (secure software development)
 *   — to the framework primitives that satisfy them. Used by operators
 *   producing System Security Plans (SSPs), POAMs, ATO packages, or
 *   CMMC self-assessments to show evidence-of-control coverage at the
 *   primitive level.
 *
 *   The catalog is intentionally NOT exhaustive — controls that are
 *   purely organizational (e.g. PS-1 Personnel Security Policy) or
 *   purely physical (e.g. PE-3 Physical Access Control) are absent;
 *   only controls a framework can demonstrably help an operator meet
 *   are mapped.
 *
 * @card
 *   Maps NIST 800-53 Rev 5, CSF 2.0, 800-171 Rev 3, and 800-218 SSDF
 *   control IDs to framework primitives so operators can show
 *   evidence-of-control at the SSP / ATO level.
 */

var framework_error = require("./framework-error");
var validateOpts    = require("./validate-opts");

var NistCrosswalkError = framework_error.defineClass(
  "NistCrosswalkError",
  "nist-crosswalk"
);

// Catalog shape:
//   { catalog: "800-53r5" | "csf-2.0" | "800-171r3" | "800-218",
//     controls: { <id>: { name, family, primitives: [...], notes? } } }
//
// `primitives` lists the framework `b.X` paths that satisfy the control;
// operators reproduce this evidence in their SSP.
var CATALOGS = {
  "800-53r5": {
    family: "NIST SP 800-53 Rev 5 (Security and Privacy Controls for Information Systems and Organizations)",
    controls: {
      "AC-2":  { name: "Account Management", primitives: ["b.session", "b.auth.password", "b.permissions", "b.auth.lockout"] },
      "AC-3":  { name: "Access Enforcement", primitives: ["b.permissions", "b.middleware.requireAuth", "b.middleware.requireAal", "b.middleware.requireStepUp"] },
      "AC-4":  { name: "Information Flow Enforcement", primitives: ["b.middleware.cors", "b.ssrfGuard", "b.httpClient.allowedHosts", "b.middleware.networkAllowlist"] },
      "AC-5":  { name: "Separation of Duties", primitives: ["b.dualControl", "b.ddlChangeControl", "b.audit.assertSegregation"] },
      "AC-6":  { name: "Least Privilege", primitives: ["b.permissions", "b.middleware.dbRoleFor", "b.mcp.capability"] },
      "AC-7":  { name: "Unsuccessful Logon Attempts", primitives: ["b.auth.lockout", "b.authBotChallenge"] },
      "AC-12": { name: "Session Termination", primitives: ["b.session", "b.atoKillSwitch"] },
      "AC-17": { name: "Remote Access", primitives: ["b.middleware.requireAuth", "b.mtlsCa", "b.network.tls"] },
      "AC-25": { name: "Reference Monitor", primitives: ["b.permissions", "b.middleware.requireAuth", "b.middleware.bearerAuth"] },
      "AU-2":  { name: "Event Logging", primitives: ["b.audit", "b.observability"] },
      "AU-3":  { name: "Content of Audit Records", primitives: ["b.audit", "b.fda21cfr11"] },
      "AU-4":  { name: "Audit Log Storage Capacity", primitives: ["b.audit", "b.logStream"] },
      "AU-6":  { name: "Audit Record Review, Analysis, and Reporting", primitives: ["b.auditDailyReview"] },
      "AU-9":  { name: "Protection of Audit Information", primitives: ["b.audit", "b.audit.signCheckpoint", "b.configDrift"] },
      "AU-10": { name: "Non-repudiation", primitives: ["b.audit.signCheckpoint", "b.webhook.sign", "b.crypto.httpSig"] },
      "AU-12": { name: "Audit Record Generation", primitives: ["b.audit", "b.audit.safeEmit"] },
      "AU-14": { name: "Session Audit", primitives: ["b.audit", "b.session"] },
      "CA-7":  { name: "Continuous Monitoring", primitives: ["b.configDrift", "b.honeytoken", "b.audit"] },
      "CM-2":  { name: "Baseline Configuration", primitives: ["b.configDrift", "b.configDrift.verifyVendorIntegrity"] },
      "CM-3":  { name: "Configuration Change Control", primitives: ["b.ddlChangeControl", "b.dualControl"] },
      "CM-5":  { name: "Access Restrictions for Change", primitives: ["b.ddlChangeControl", "b.dualControl", "b.permissions"] },
      "CM-7":  { name: "Least Functionality", primitives: ["b.processSpawn", "b.sandbox", "b.middleware.networkAllowlist"] },
      "CP-9":  { name: "System Backup", primitives: ["b.backup", "b.backup.scheduleTest", "b.backupBundle.verifyManifestSignature"] },
      "CP-10": { name: "System Recovery and Reconstitution", primitives: ["b.restore", "b.restore.rollback", "b.drRunbook"] },
      "IA-2":  { name: "Identification and Authentication (Organizational Users)", primitives: ["b.auth.password", "b.auth.passkey", "b.auth.totp", "b.session"] },
      "IA-3":  { name: "Device Identification and Authentication", primitives: ["b.mtlsCa", "b.sessionDeviceBinding", "b.auth.dpop"] },
      "IA-4":  { name: "Identifier Management", primitives: ["b.auth", "b.apiKey"] },
      "IA-5":  { name: "Authenticator Management", primitives: ["b.auth.password", "b.auth.password.policy", "b.apiKey"] },
      "IA-8":  { name: "Identification and Authentication (Non-Organizational Users)", primitives: ["b.auth.oauth", "b.auth.saml", "b.auth.openidFederation"] },
      "IA-11": { name: "Re-authentication", primitives: ["b.auth.stepUp", "b.middleware.requireStepUp"] },
      "IA-12": { name: "Identity Proofing", primitives: ["b.auth.aal"] },
      "IR-4":  { name: "Incident Handling", primitives: ["b.incident", "b.incident.report", "b.atoKillSwitch"] },
      "IR-5":  { name: "Incident Monitoring", primitives: ["b.honeytoken", "b.auditDailyReview"] },
      "IR-6":  { name: "Incident Reporting", primitives: ["b.dora", "b.nis2", "b.cra", "b.secCyber", "b.breach.deadline"] },
      "IR-8":  { name: "Incident Response Plan", primitives: ["b.drRunbook", "b.incident"] },
      "MP-6":  { name: "Media Sanitization", primitives: ["b.cryptoField.eraseRow", "b.db.eraseHard", "b.subject.eraseHard"] },
      "RA-5":  { name: "Vulnerability Monitoring and Scanning", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "SA-15": { name: "Development Process, Standards, and Tools", primitives: ["b.audit", "b.configDrift"] },
      "SC-2":  { name: "Separation of System and User Functionality", primitives: ["b.sandbox", "b.processSpawn"] },
      "SC-7":  { name: "Boundary Protection", primitives: ["b.ssrfGuard", "b.middleware.cors", "b.middleware.networkAllowlist", "b.httpClient.allowedHosts"] },
      "SC-8":  { name: "Transmission Confidentiality and Integrity", primitives: ["b.network.tls", "b.crypto", "b.crypto.httpSig"] },
      "SC-12": { name: "Cryptographic Key Establishment and Management", primitives: ["b.vault", "b.crypto", "b.crypto.hpke"] },
      "SC-13": { name: "Cryptographic Protection", primitives: ["b.crypto", "b.vault", "b.cryptoField", "b.network.tls"] },
      "SC-17": { name: "Public Key Infrastructure Certificates", primitives: ["b.mtlsCa", "b.acme", "b.network.tls.ct"] },
      "SC-23": { name: "Session Authenticity", primitives: ["b.session", "b.tlsExporter"] },
      "SC-28": { name: "Protection of Information at Rest", primitives: ["b.vault", "b.cryptoField", "b.cryptoField.declarePerRowKey"] },
      "SI-2":  { name: "Flaw Remediation", primitives: ["b.configDrift", "b.configDrift.verifyVendorIntegrity"] },
      "SI-3":  { name: "Malicious Code Protection", primitives: ["b.guardAll", "b.fileType", "b.honeytoken"] },
      "SI-4":  { name: "System Monitoring", primitives: ["b.audit", "b.metrics", "b.tracing", "b.honeytoken"] },
      "SI-7":  { name: "Software, Firmware, and Information Integrity", primitives: ["b.configDrift.verifyVendorIntegrity", "b.audit.signCheckpoint"] },
      "SI-10": { name: "Information Input Validation", primitives: ["b.safeJson", "b.safeUrl", "b.guardAll", "b.middleware.bodyParser"] },
      "SI-11": { name: "Error Handling", primitives: ["b.errorPage", "b.middleware.errorHandler"] },
      "SI-12": { name: "Information Management and Retention", primitives: ["b.retention", "b.legalHold"] },
      "SR-3":  { name: "Supply Chain Controls and Processes", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "SR-4":  { name: "Provenance", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "SR-11": { name: "Component Authenticity", primitives: ["b.configDrift.verifyVendorIntegrity"] },
    },
  },
  "csf-2.0": {
    family: "NIST Cybersecurity Framework 2.0 (Feb 2024)",
    controls: {
      "GV.OC":  { name: "Organizational Context",      primitives: ["b.compliance"] },
      "GV.RM":  { name: "Risk Management Strategy",    primitives: ["b.compliance", "b.dora", "b.cra"] },
      "GV.RR":  { name: "Roles, Responsibilities, and Authorities", primitives: ["b.permissions", "b.audit.bindActor", "b.dualControl"] },
      "GV.PO":  { name: "Policy",                      primitives: ["b.compliance"] },
      "GV.OV":  { name: "Oversight",                   primitives: ["b.audit", "b.auditDailyReview"] },
      "GV.SC":  { name: "Cybersecurity Supply Chain Risk Management", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "ID.AM":  { name: "Asset Management",            primitives: ["b.configDrift"] },
      "ID.RA":  { name: "Risk Assessment",             primitives: ["b.compliance"] },
      "ID.IM":  { name: "Improvement",                 primitives: ["b.audit", "b.honeytoken"] },
      "PR.AA":  { name: "Identity Management, Authentication, and Access Control", primitives: ["b.session", "b.auth", "b.permissions"] },
      "PR.AT":  { name: "Awareness and Training",      primitives: [] },
      "PR.DS":  { name: "Data Security",               primitives: ["b.vault", "b.cryptoField", "b.network.tls", "b.crypto"] },
      "PR.PS":  { name: "Platform Security",           primitives: ["b.middleware.securityHeaders", "b.sandbox", "b.processSpawn"] },
      "PR.IR":  { name: "Technology Infrastructure Resilience", primitives: ["b.cluster", "b.scheduler", "b.retry"] },
      "DE.CM":  { name: "Continuous Monitoring",       primitives: ["b.audit", "b.metrics", "b.honeytoken", "b.configDrift"] },
      "DE.AE":  { name: "Adverse Event Analysis",      primitives: ["b.auditDailyReview", "b.honeytoken"] },
      "RS.MA":  { name: "Incident Management",         primitives: ["b.incident"] },
      "RS.AN":  { name: "Incident Analysis",           primitives: ["b.auditTools.forensicSnapshot"] },
      "RS.CO":  { name: "Incident Response Reporting and Communication", primitives: ["b.dora", "b.nis2", "b.cra", "b.secCyber", "b.breach.deadline"] },
      "RS.MI":  { name: "Incident Mitigation",         primitives: ["b.atoKillSwitch"] },
      "RC.RP":  { name: "Incident Recovery Plan Execution", primitives: ["b.restore", "b.restore.rollback", "b.drRunbook"] },
      "RC.CO":  { name: "Incident Recovery Communication", primitives: ["b.dora", "b.nis2"] },
    },
  },
  "800-171r3": {
    family: "NIST SP 800-171 Rev 3 (CUI Protection)",
    controls: {
      "03.01.01": { name: "Account Management",            primitives: ["b.session", "b.auth.password", "b.permissions"] },
      "03.01.02": { name: "Access Enforcement",            primitives: ["b.permissions", "b.middleware.requireAuth"] },
      "03.01.03": { name: "Information Flow Enforcement",  primitives: ["b.ssrfGuard", "b.middleware.cors", "b.middleware.networkAllowlist"] },
      "03.01.04": { name: "Separation of Duties",          primitives: ["b.dualControl", "b.ddlChangeControl"] },
      "03.01.05": { name: "Least Privilege",               primitives: ["b.permissions", "b.middleware.dbRoleFor"] },
      "03.01.07": { name: "Privileged Functions",          primitives: ["b.breakGlass", "b.dualControl"] },
      "03.01.08": { name: "Unsuccessful Logon Attempts",   primitives: ["b.auth.lockout"] },
      "03.01.10": { name: "Session Lock + Termination",    primitives: ["b.session"] },
      "03.03.01": { name: "Event Logging",                 primitives: ["b.audit"] },
      "03.03.02": { name: "Audit Log Contents",            primitives: ["b.audit", "b.fda21cfr11"] },
      "03.03.05": { name: "Audit Log Reduction + Reporting", primitives: ["b.auditDailyReview"] },
      "03.03.08": { name: "Audit Log Protection",          primitives: ["b.audit.signCheckpoint"] },
      "03.04.01": { name: "Baseline Configuration",        primitives: ["b.configDrift"] },
      "03.04.02": { name: "Configuration Settings",        primitives: ["b.middleware.securityHeaders", "b.compliance"] },
      "03.05.01": { name: "User Identification + Authentication", primitives: ["b.auth.password", "b.auth.passkey", "b.session"] },
      "03.05.05": { name: "Device Identification + Authentication", primitives: ["b.mtlsCa", "b.sessionDeviceBinding"] },
      "03.05.07": { name: "Authenticator Management",      primitives: ["b.auth.password.policy"] },
      "03.06.01": { name: "Incident Handling",             primitives: ["b.incident"] },
      "03.06.02": { name: "Incident Monitoring",           primitives: ["b.honeytoken", "b.auditDailyReview"] },
      "03.06.03": { name: "Incident Reporting",            primitives: ["b.incident.report", "b.breach.deadline"] },
      "03.08.03": { name: "Media Sanitization",            primitives: ["b.cryptoField.eraseRow", "b.db.eraseHard"] },
      "03.13.01": { name: "Boundary Protection",           primitives: ["b.ssrfGuard", "b.middleware.networkAllowlist"] },
      "03.13.02": { name: "Network + Application Protection", primitives: ["b.middleware.securityHeaders", "b.middleware.cors"] },
      "03.13.08": { name: "Transmission Confidentiality + Integrity", primitives: ["b.network.tls", "b.crypto"] },
      "03.13.11": { name: "Cryptographic Protection",      primitives: ["b.crypto", "b.vault", "b.cryptoField"] },
      "03.14.01": { name: "Flaw Remediation",              primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "03.14.06": { name: "System Monitoring",             primitives: ["b.audit", "b.metrics", "b.honeytoken"] },
    },
  },
  "800-218": {
    family: "NIST SP 800-218 (Secure Software Development Framework v1.1)",
    controls: {
      "PO.1": { name: "Prepare the Organization — Software Development Security", primitives: ["b.security.assertProduction"] },
      "PO.3": { name: "Implement Supporting Toolchains", primitives: ["b.configDrift"] },
      "PO.5": { name: "Implement and Maintain Secure Environments", primitives: ["b.security.assertProduction", "b.compliance"] },
      "PS.1": { name: "Protect All Forms of Code from Unauthorized Access and Tampering", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "PS.3": { name: "Archive and Protect Each Software Release", primitives: [] },
      "PW.1": { name: "Design Software to Meet Security Requirements", primitives: ["b.compliance"] },
      "PW.4": { name: "Reuse Existing, Well-Secured Software", primitives: ["b.configDrift.verifyVendorIntegrity"] },
      "PW.5": { name: "Create Source Code Adhering to Secure Coding Practices", primitives: [] },
      "PW.6": { name: "Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security", primitives: ["b.configDrift"] },
      "PW.7": { name: "Review and/or Analyze Human-Readable Code to Identify Vulnerabilities", primitives: [] },
      "PW.8": { name: "Test Executable Code to Identify Vulnerabilities", primitives: [] },
      "PW.9": { name: "Configure Software to Have Secure Settings by Default", primitives: ["b.middleware.securityHeaders", "b.compliance"] },
      "RV.1": { name: "Identify and Confirm Vulnerabilities on an Ongoing Basis", primitives: [] },
      "RV.2": { name: "Assess, Prioritize, and Remediate Vulnerabilities", primitives: [] },
      "RV.3": { name: "Analyze Vulnerabilities to Identify Their Root Causes", primitives: ["b.auditTools.forensicSnapshot"] },
    },
  },
};

/**
 * @primitive b.nistCrosswalk.controls
 * @signature b.nistCrosswalk.controls(catalog)
 * @since     0.8.77
 * @related   b.nistCrosswalk.coverage
 *
 * Returns the control catalog map for one of: `800-53r5`, `csf-2.0`,
 * `800-171r3`, `800-218`.
 *
 * @example
 *   var sp80053 = b.nistCrosswalk.controls("800-53r5");
 *   console.log(sp80053["AC-3"].primitives);
 *   // → ["b.permissions", "b.middleware.requireAuth", ...]
 */
function controls(catalog) {
  if (typeof catalog !== "string" || !CATALOGS[catalog]) {
    throw new NistCrosswalkError("nist-crosswalk/unknown-catalog",
      "controls: unknown catalog '" + catalog + "'. Known: " +
      Object.keys(CATALOGS).join(", "));
  }
  return CATALOGS[catalog].controls;
}

/**
 * @primitive b.nistCrosswalk.coverage
 * @signature b.nistCrosswalk.coverage(opts)
 * @since     0.8.77
 *
 * Given a list of control IDs the operator's SSP claims to satisfy,
 * returns `{ covered, uncovered, primitives }` — `covered` lists the
 * IDs in the catalog with at least one mapped primitive, `uncovered`
 * lists IDs with no mapping, `primitives` is the deduplicated set of
 * framework primitives evidencing coverage. Use the output to bind
 * SSP control descriptions to specific framework callouts.
 *
 * @opts
 *   {
 *     catalog:    "800-53r5" | "csf-2.0" | "800-171r3" | "800-218",
 *     controlIds: string[],
 *   }
 *
 * @example
 *   var rv = b.nistCrosswalk.coverage({
 *     catalog:    "800-53r5",
 *     controlIds: ["AC-2", "AC-3", "AC-99-fake"],
 *   });
 *   // rv.covered     → ["AC-2", "AC-3"]
 *   // rv.uncovered   → ["AC-99-fake"]
 *   // rv.primitives  → ["b.session", "b.auth.password", "b.permissions", ...]
 */
function coverage(opts) {
  validateOpts.requireObject(opts, "nistCrosswalk.coverage",
    NistCrosswalkError, "nist-crosswalk/bad-opts");
  if (!Array.isArray(opts.controlIds)) {
    throw new NistCrosswalkError("nist-crosswalk/bad-control-ids",
      "coverage: opts.controlIds must be an array");
  }
  var cat = controls(opts.catalog);
  var covered   = [];
  var uncovered = [];
  var prims     = new Set();
  opts.controlIds.forEach(function (id) {
    var entry = cat[id];
    if (entry && Array.isArray(entry.primitives) && entry.primitives.length > 0) {
      covered.push(id);
      entry.primitives.forEach(function (p) { prims.add(p); });
    } else {
      uncovered.push(id);
    }
  });
  return {
    catalog:    opts.catalog,
    covered:    covered,
    uncovered:  uncovered,
    primitives: Array.from(prims).sort(),
  };
}

/**
 * @primitive b.nistCrosswalk.listCatalogs
 * @signature b.nistCrosswalk.listCatalogs()
 * @since     0.8.77
 *
 * Returns `[{ id, family, count }]` — the catalogs known to the
 * crosswalk + how many control IDs are mapped in each.
 *
 * @example
 *   b.nistCrosswalk.listCatalogs();
 *   // → [{ id: "800-53r5", family: "...", count: 50 }, ...]
 */
function listCatalogs() {
  return Object.keys(CATALOGS).map(function (id) {
    var cat = CATALOGS[id];
    return {
      id:     id,
      family: cat.family,
      count:  Object.keys(cat.controls).length,
    };
  });
}

module.exports = {
  controls:           controls,
  coverage:           coverage,
  listCatalogs:       listCatalogs,
  NistCrosswalkError: NistCrosswalkError,
};
