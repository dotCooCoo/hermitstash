// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.drRunbook
 * @nav    Compliance
 * @title  DR Runbook
 *
 * @intro
 *   Disaster-recovery runbook executor — composes pre-recorded
 *   regulatory steps, operator confirmation gates, and the framework's
 *   audit chain into a posture-appropriate Markdown runbook a
 *   regulator can read alongside `b.audit`.
 *
 *   `b.drRunbook.emit` walks the operator's posture (one of `hipaa`,
 *   `pci-dss`, `gdpr`, `soc2`, `dora`), pulls breach-disclosure
 *   deadlines from the operator-supplied `b.budr` registry, summarizes
 *   `b.backup` configuration, captures `b.cluster` topology, and
 *   writes a single Markdown file under `outDir`. Each emit also
 *   records a `dr.runbook.emitted` audit event with the posture, the
 *   output path, and the section count — so the operator
 *   confirmation chain has an immutable record of which runbook
 *   version was last produced.
 *
 *   Posture-driven citations:
 *
 *   - hipaa   — 45 CFR §164.308(a)(7) contingency plan +
 *               §164.310(a)(2)(i) facility-recovery checklist
 *   - pci-dss — PCI DSS v4.0.1 Req. 12.10 (containment / eradication /
 *               recovery)
 *   - gdpr    — Regulation (EU) 2016/679 Art. 32, 33 (72h notification),
 *               34
 *   - soc2    — AICPA TSC CC7.4 / CC9.1 (recovery objectives + change
 *               control)
 *   - dora    — Regulation (EU) 2022/2554 Art. 11, 12, 24
 *
 *   The runbook is plain Markdown — operators commit it under
 *   `docs/dr/` and version it with their service. Re-emitting
 *   overwrites the file in place via `atomicFile.writeSync`, so an
 *   operator-supplied template change ships through git review before
 *   the runbook lands.
 *
 * @card
 *   Disaster-recovery runbook executor — composes pre-recorded regulatory steps, operator confirmation gates, and the framework's audit chain into a posture-appropriate Markdown runbook a regulator can read alongside `b.audit`.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var C = require("./constants");
var atomicFile = require("./atomic-file");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DrRunbookError = defineClass("DrRunbookError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

// Posture-specific content blocks. The framework owns the regulatory
// citations; operators fill in environment-specific commands.
var POSTURE_BLOCKS = {
  "hipaa": {
    citation: "45 CFR §164.308(a)(7)(ii)(B-D); §164.310(a)(2)(i)",
    summary:  "HIPAA Security Rule contingency plan — covers data-backup, " +
              "disaster recovery, emergency-mode operation, testing/revision, " +
              "and applications/data-criticality analysis.",
    rtoLabel: "Maximum Tolerable Downtime",
    requiredSections: ["Backup", "Restore", "Test", "Roles", "Notification"],
  },
  "pci-dss": {
    citation: "PCI DSS v4.0.1 Requirement 12.10",
    summary:  "PCI DSS incident-response capability — preserves cardholder " +
              "data integrity through detection, containment, eradication, " +
              "recovery, post-incident review.",
    rtoLabel: "Recovery Time Objective",
    requiredSections: ["Backup", "Restore", "Test", "Roles", "Notification", "Card-Brand-Notification"],
  },
  "gdpr": {
    citation: "Regulation (EU) 2016/679 Articles 32, 33, 34",
    summary:  "GDPR security-of-processing + breach-notification timeline. " +
              "Personal-data breach → supervisory authority within 72h, " +
              "data subjects without undue delay where high-risk.",
    rtoLabel: "Recovery Time Objective",
    requiredSections: ["Backup", "Restore", "Test", "Roles", "Notification", "Article-33-Timeline"],
  },
  "soc2": {
    citation: "AICPA TSC CC7.4 / CC9.1",
    summary:  "SOC 2 availability commitments — recovery objectives, change " +
              "control around recovery procedures, and continuous monitoring.",
    rtoLabel: "Recovery Time Objective",
    requiredSections: ["Backup", "Restore", "Test", "Roles", "Change-Control"],
  },
  "dora": {
    citation: "Regulation (EU) 2022/2554 Articles 11, 12, 24",
    summary:  "DORA operational-resilience plan — covers ICT business " +
              "continuity, response/recovery, third-party-risk, and major-" +
              "incident reporting (Article 17).",
    rtoLabel: "Recovery Time Objective",
    requiredSections: ["Backup", "Restore", "Test", "Roles", "Notification", "Article-17-Timeline"],
  },
};

function _formatMs(ms) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) return "—";
  if (ms >= C.TIME.hours(1)) return (ms / C.TIME.hours(1)).toFixed(2) + "h";
  if (ms >= C.TIME.minutes(1)) return (ms / C.TIME.minutes(1)).toFixed(2) + "m";
  return Math.floor(ms / C.TIME.seconds(1)) + "s";
}

function _section(title, body) {
  return "## " + title + "\n\n" + body + "\n";
}

function _renderRoles(contacts) {
  contacts = contacts || {};
  var keys = Object.keys(contacts);
  if (keys.length === 0) {
    return "_No contacts supplied. Populate `contacts:` opt at emit time " +
           "before this runbook is operator-actionable._";
  }
  var rows = ["| Role | Contact |", "| ---- | ------- |"];
  for (var i = 0; i < keys.length; i++) {
    rows.push("| " + keys[i] + " | " + String(contacts[keys[i]]) + " |");
  }
  return rows.join("\n");
}

function _renderServices(services, postureBlock) {
  if (!services || services.length === 0) {
    return "_No service-level recovery objectives supplied._";
  }
  var lines = [
    "| Service | " + (postureBlock.rtoLabel || "RTO") + " | RPO |",
    "| ------- | ----- | --- |",
  ];
  for (var i = 0; i < services.length; i++) {
    var s = services[i];
    lines.push("| " + (s.name || "—") + " | " + _formatMs(s.rtoMs) +
               " | " + _formatMs(s.rpoMs) + " |");
  }
  return lines.join("\n");
}

function _renderBackup(backup) {
  if (!backup) {
    return "_No backup primitive bound. Wire `backup:` opt or document " +
           "operator-managed backup procedure here._";
  }
  var name = (backup.storage && backup.storage.name) || "custom";
  return "Backup engine: `b.backup` with **" + name + "** storage backend. " +
         "Run `await backup.run()` to take an ad-hoc snapshot; the " +
         "framework's scheduler emits scheduled snapshots on the operator's " +
         "cron expression. Bundle integrity: SHA3-512 plaintext checksum + " +
         "per-blob XChaCha20-Poly1305 AEAD + ML-DSA-87 signed manifest.";
}

function _renderCluster(cluster) {
  if (!cluster) {
    return "_No cluster primitive bound. Single-node deployment: backups + " +
           "audit-chain + restore-bundle are the only recovery surface._";
  }
  // cluster.isClusterMode is the operator-stable accessor; everything
  // else is internal.
  var isCluster = false;
  try { isCluster = !!(cluster.isClusterMode && cluster.isClusterMode()); }
  catch (_e) { /* tolerate unwired cluster handle */ }
  if (!isCluster) {
    return "Cluster module imported but currently in **single-node** mode. " +
           "Recovery procedure is point-in-time restore from the most " +
           "recent backup bundle.";
  }
  return "Cluster mode active. Recovery procedure:\n\n" +
         "1. Verify external-db reachability (`SELECT 1` against the " +
         "operator's pool).\n" +
         "2. Confirm leader-election keepalive — a fresh boot must " +
         "stand-down for an existing leader.\n" +
         "3. On total-cluster loss, restore the framework's local DB on a " +
         "single node FIRST, then bring secondaries online.\n";
}

function _renderBudrDeadlines(budrInstance, posture) {
  if (!budrInstance) {
    return "_No b.budr instance bound. Wire `budr:` opt to surface posture-" +
           "specific breach-disclosure deadlines._";
  }
  // budr exports list() — pull every declaration matching the posture so
  // the runbook surfaces exactly which deadlines fire on a confirmed
  // breach.
  var entries;
  try { entries = budrInstance.list && budrInstance.list({ posture: posture }); }
  catch (_e) { entries = null; }
  if (!entries || entries.length === 0) {
    return "_No breach-disclosure deadlines registered under posture `" +
           posture + "`. Register via `b.budr.declare(...)` for the framework " +
           "to surface them here._";
  }
  var lines = ["| Regulator | Trigger | Deadline |", "| --------- | ------- | -------- |"];
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    lines.push("| " + (e.regulator || "—") + " | " + (e.trigger || "—") +
               " | " + (e.deadline || "—") + " |");
  }
  return lines.join("\n");
}

function _renderTest(posture) {
  return "Backup-restore drills MUST run periodically — register through " +
         "`b.backup.scheduleTest({ cron, restoreTo, verify, posture: '" +
         posture + "' })`. The framework emits `backup.test.passed` / " +
         "`backup.test.failed` so a missed drill is visible in the audit " +
         "chain. Recommended cadence:\n\n" +
         "- HIPAA §164.308(a)(7)(ii)(D): documented periodic tests.\n" +
         "- PCI DSS 12.10.2: annual + after major changes.\n" +
         "- DORA Art. 24: at least annually.\n";
}

/**
 * @primitive b.drRunbook.emit
 * @signature b.drRunbook.emit(opts)
 * @since     0.7.25
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, dora
 * @related   b.budr.declare, b.audit.safeEmit
 *
 * Render and write the posture-specific runbook. Returns
 * `{ paths, posture, sectionCount }` after the file lands at
 * `outDir/<filename>` (default filename: `runbook-<posture>.md`).
 *
 * Service-level recovery objectives are emitted as a Markdown table
 * keyed off `services[].rtoMs` and `services[].rpoMs`; values are
 * formatted via `b.constants.TIME` granularity (hours / minutes /
 * seconds). Optional bindings (`budr`, `cluster`, `backup`) populate
 * matching sections when wired and surface a `_No <X> bound_`
 * placeholder otherwise so the runbook never silently drops a
 * required section.
 *
 * Throws `DrRunbookError("dr-runbook/unknown-posture")` when `posture`
 * is not in the supported list.
 *
 * @opts
 *   outDir:   string,                     // directory to write into (required)
 *   posture:  "hipaa"|"pci-dss"|"gdpr"|"soc2"|"dora",
 *   services: Array<{name, rtoMs, rpoMs}>,
 *   rtoMs:    number,                     // service-level RTO in ms
 *   rpoMs:    number,                     // service-level RPO in ms
 *   contacts: object,                     // role -> contact string
 *   budr:     object,                     // b.budr-shaped registry
 *   cluster:  object,                     // b.cluster handle
 *   backup:   object,                     // b.backup handle
 *   audit:    boolean,                    // default: true
 *   filename: string,                     // override `runbook-<posture>.md`
 *
 * @example
 *   var report = await b.drRunbook.emit({
 *     outDir:   "/tmp/blamejs-runbook-demo",
 *     posture:  "hipaa",
 *     services: [
 *       { name: "api-edge", rtoMs: b.constants.TIME.minutes(15), rpoMs: b.constants.TIME.minutes(5) },
 *     ],
 *     rtoMs:    b.constants.TIME.hours(4),
 *     rpoMs:    b.constants.TIME.minutes(15),
 *     contacts: { incidentCommander: "alice@example.com" },
 *     audit:    false,
 *   });
 *   report.posture;      // → "hipaa"
 *   report.sectionCount; // → 9
 *   report.paths.length; // → 1
 */
async function emit(opts) {
  validateOpts.requireObject(opts, "drRunbook.emit", DrRunbookError);
  validateOpts(opts, [
    "outDir", "posture", "services", "rtoMs", "rpoMs",
    "contacts", "budr", "cluster", "backup", "audit", "filename",
  ], "drRunbook.emit");

  validateOpts.requireNonEmptyString(opts.outDir,
    "drRunbook.emit: outDir", DrRunbookError, "dr-runbook/no-outdir");
  validateOpts.requireNonEmptyString(opts.posture,
    "drRunbook.emit: posture", DrRunbookError, "dr-runbook/no-posture");
  if (!Object.prototype.hasOwnProperty.call(POSTURE_BLOCKS, opts.posture)) {
    throw new DrRunbookError("dr-runbook/unknown-posture",
      "drRunbook.emit: posture '" + opts.posture + "' not in supported list (" +
      Object.keys(POSTURE_BLOCKS).join(", ") + ")");
  }
  if (opts.services !== undefined && !Array.isArray(opts.services)) {
    throw new DrRunbookError("dr-runbook/bad-services",
      "drRunbook.emit: services must be an array of {name, rtoMs, rpoMs}");
  }
  validateOpts.optionalPositiveFinite(opts.rtoMs,
    "drRunbook.emit: rtoMs", DrRunbookError, "dr-runbook/bad-rto");
  validateOpts.optionalPositiveFinite(opts.rpoMs,
    "drRunbook.emit: rpoMs", DrRunbookError, "dr-runbook/bad-rpo");

  var auditOn = opts.audit !== false;
  var postureBlock = POSTURE_BLOCKS[opts.posture];

  var sections = [];
  sections.push("# Disaster Recovery Runbook — " + opts.posture.toUpperCase());
  sections.push("");
  sections.push("**Posture citation:** " + postureBlock.citation);
  sections.push("");
  sections.push("**Generated:** " + new Date().toISOString());
  sections.push("");
  sections.push(postureBlock.summary);
  sections.push("");
  sections.push(_section("Recovery Objectives",
    "**Service-level RTO:** " + _formatMs(opts.rtoMs) + "  \n" +
    "**Service-level RPO:** " + _formatMs(opts.rpoMs) + "\n\n" +
    _renderServices(opts.services, postureBlock)));
  sections.push(_section("Roles & Contacts", _renderRoles(opts.contacts)));
  sections.push(_section("Backup", _renderBackup(opts.backup)));
  sections.push(_section("Cluster Topology", _renderCluster(opts.cluster)));
  sections.push(_section("Restore Procedure",
    "1. Identify the most recent verified backup bundle: " +
    "`await backup.list()` → highest bundleId.\n" +
    "2. Verify the manifest signature: " +
    "`await b.backupBundle.verifyManifestSignature(bundle, opts)`.\n" +
    "3. Restore staging dir: `await backup.read(bundleId, '/restore/staging')`.\n" +
    "4. Decrypt + verify: `await b.restoreBundle.extract({ bundleDir, " +
    "passphrase, outDir, vaultKeyJsonOnly: false })`.\n" +
    "5. Verify audit chain on the restored DB: " +
    "`await b.auditChain.verify({ db: restoredDb })`.\n" +
    "6. Resume cluster operation only after the chain verifies.\n"));
  sections.push(_section("Backup-Restore Test", _renderTest(opts.posture)));
  sections.push(_section("Breach-Disclosure Deadlines",
    _renderBudrDeadlines(opts.budr, opts.posture)));
  sections.push(_section("Notification & Reporting",
    "Operator wires the disclosure-channel routing (regulator portals, " +
    "press release, customer email, status-page) outside this primitive. " +
    "The framework's `b.audit` chain is the source-of-truth timeline " +
    "regulators expect; preserve it across the recovery."));
  sections.push(_section("Posture-Specific Required Sections",
    "- " + postureBlock.requiredSections.join("\n- ")));

  var body = sections.join("\n");

  // Ensure outDir exists.
  if (!nodeFs.existsSync(opts.outDir)) {
    nodeFs.mkdirSync(opts.outDir, { recursive: true });
  }
  var filename = opts.filename || ("runbook-" + opts.posture + ".md");
  var outPath = nodePath.join(opts.outDir, filename);
  atomicFile.writeSync(outPath, body, { fileMode: 0o644 });

  if (auditOn) {
    try {
      audit().safeEmit({
        action:   "dr.runbook.emitted",
        outcome:  "success",
        metadata: {
          posture:      opts.posture,
          path:         outPath,
          sectionCount: sections.filter(function (s) { return s.indexOf("## ") === 0; }).length,
        },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  return {
    paths:        [outPath],
    posture:      opts.posture,
    sectionCount: sections.filter(function (s) { return s.indexOf("## ") === 0; }).length,
  };
}

module.exports = {
  emit:           emit,
  POSTURE_BLOCKS: POSTURE_BLOCKS,
  DrRunbookError: DrRunbookError,
};
