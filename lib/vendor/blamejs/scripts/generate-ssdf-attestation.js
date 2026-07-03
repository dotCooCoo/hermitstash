// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Emit a NIST SP 800-218 (SSDF) / OMB M-22-18 producer self-attestation
// as a machine-readable JSON artifact, attached to each GitHub release.
//
// Run via:
//   node scripts/generate-ssdf-attestation.js \
//     --version 0.15.7 --commit <sha> --date 2026-06-13T00:00:00Z \
//     > ssdf-attestation.json
//
//   # or with --out:
//   node scripts/generate-ssdf-attestation.js --out ssdf-attestation.json
//
// Wired into .github/workflows/npm-publish.yml alongside the SBOM +
// cosign + SLSA steps. Downstream consumers who require SSDF supplier-
// compliance evidence (OMB M-22-18 / M-23-16 self-attestation) download
// this from the release page.
//
// WHAT THIS IS — AND IS NOT.
//   This is a PRODUCER SELF-ATTESTATION, the machine-readable companion
//   to the CISA / OMB "Secure Software Development Attestation Form". It
//   is the producer's own assertion that the SSDF practices below are in
//   force, mapped to the framework's REAL implementing controls. It is
//   NOT a third-party audit, NOT a FedRAMP authorization, and NOT a CMVP
//   validation. Its trust derives entirely from the release boundary that
//   carries it: the SSH-signed tag, the SLSA L3 npm provenance, the
//   Sigstore-keyless SBOM signatures, and the ML-DSA-65 release-signing
//   sidecar — the same four trust roots documented in SECURITY.md sign
//   this file by signing the release that contains it. A consumer who
//   verifies those roots is verifying that THIS attestation came from the
//   producer of record; the claims inside are the producer's assertions,
//   verifiable against the cited controls in the source tree at the
//   release commit.
//
// Each statement carries its NIST SSDF practice IDs (PO/PS/PW/RV.*) and
// names the specific implementing control so the assertion is auditable,
// not aspirational. Output is deterministic: the timestamp comes from
// --date / SOURCE_DATE_EPOCH (never an unseeded clock), and the same
// inputs produce byte-identical output.

var fs   = require("node:fs");
var path = require("node:path");

var ROOT     = path.resolve(__dirname, "..");
var PKG_PATH = path.join(ROOT, "package.json");

// ---------------------------------------------------------------------
// Argument + environment resolution. Config-time inputs THROW on bad
// shape (operator catches a typo at invocation), per the three-tier
// validation discipline — this is an entry-point script, not a hot path.
// ---------------------------------------------------------------------

function _parseArgs(argv) {
  var out = {};
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--out")          { out.out     = argv[++i]; continue; }
    if (a === "--version")      { out.version = argv[++i]; continue; }
    if (a === "--commit")       { out.commit  = argv[++i]; continue; }
    if (a === "--date")         { out.date    = argv[++i]; continue; }
    if (a === "--repository")   { out.repository = argv[++i]; continue; }
    if (a === "-h" || a === "--help") { out.help = true; continue; }
    throw new Error("generate-ssdf-attestation: unrecognized argument: " + a);
  }
  return out;
}

// Deterministic timestamp resolution: --date (RFC 3339) wins; else
// SOURCE_DATE_EPOCH (seconds since the Unix epoch, the reproducible-build
// convention) is parsed; else fail closed. We NEVER call an unseeded
// clock — a reproducible artifact must produce identical bytes from
// identical inputs.
function _resolveTimestamp(args, env) {
  if (typeof args.date === "string" && args.date.length > 0) {
    var t = new Date(args.date);
    if (isNaN(t.getTime())) {
      throw new TypeError("generate-ssdf-attestation: --date is not a valid date: " + args.date);
    }
    return t.toISOString();
  }
  var epoch = env.SOURCE_DATE_EPOCH;
  if (typeof epoch === "string" && epoch.length > 0) {
    if (!/^[0-9]+$/.test(epoch)) {
      throw new TypeError("generate-ssdf-attestation: SOURCE_DATE_EPOCH must be integer seconds, got: " + epoch);
    }
    var secs = parseInt(epoch, 10);
    if (!isFinite(secs) || secs < 0) {
      throw new TypeError("generate-ssdf-attestation: SOURCE_DATE_EPOCH out of range: " + epoch);
    }
    return new Date(secs * 1000).toISOString();
  }
  throw new Error(
    "generate-ssdf-attestation: no deterministic timestamp source. " +
    "Pass --date <RFC3339> or set SOURCE_DATE_EPOCH (no unseeded clock is used)."
  );
}

// Software version: --version wins; else package.json. Cross-check when
// both are present so a tag/package drift fails the cut here too.
function _resolveVersion(args, pkg) {
  if (typeof args.version === "string" && args.version.length > 0) {
    if (pkg.version && args.version !== pkg.version) {
      throw new Error(
        "generate-ssdf-attestation: --version (" + args.version +
        ") does not match package.json version (" + pkg.version + ")"
      );
    }
    return args.version;
  }
  if (typeof pkg.version === "string" && pkg.version.length > 0) return pkg.version;
  throw new Error("generate-ssdf-attestation: no version (pass --version or set package.json version)");
}

// Source-control commit: --commit wins; else GITHUB_SHA; else null
// (a locally-generated attestation that omits the commit is honest about
// not knowing it rather than fabricating one).
function _resolveCommit(args, env) {
  if (typeof args.commit === "string" && args.commit.length > 0) return args.commit;
  var sha = env.GITHUB_SHA;
  if (typeof sha === "string" && sha.length > 0) return sha;
  return null;
}

// Normalize the package.json repository field to a bare https URL.
function _resolveRepository(args, pkg) {
  if (typeof args.repository === "string" && args.repository.length > 0) return args.repository;
  var r = pkg.repository;
  var url = (r && typeof r === "object" && typeof r.url === "string") ? r.url
          : (typeof r === "string" ? r : "");
  url = url.replace(/^git\+/, "").replace(/\.git$/, "");
  if (url.length === 0) return null;
  return url;
}

// ---------------------------------------------------------------------
// The attestation document.
//
// Structure follows the OMB M-22-18 / CISA "Secure Software Development
// Attestation Form": producer identity, software identity, then the four
// attestation-statement groups the Form covers. Each statement is mapped
// to its NIST SP 800-218 v1.1 practice ID(s) and the framework control
// that implements it, so the assertion is checkable against the source
// tree at `commit`.
//
// SSDF practice families:
//   PO  Prepare the Organization
//   PS  Protect the Software
//   PW  Produce Well-Secured Software
//   RV  Respond to Vulnerabilities
// ---------------------------------------------------------------------

// The four M-22-18 Form attestation groups (the questions a producer
// answers "yes" to on the Form), each backed by SSDF-practice-mapped
// statements naming the framework's real implementing control.
function _attestationStatements() {
  return [
    {
      "id": "secure-build-environment",
      "form_section": "1. Secure software development environment",
      "summary": "Software is developed and built in secure environments with separated, least-privilege, ephemeral CI.",
      "statements": [
        {
          "ssdf": ["PO.5.1", "PO.5.2"],
          "claim": "Builds run only in GitHub-hosted ephemeral runners; every release job declares the minimum permissions it needs and elevates per-job (workflow-level contents:read; id-token:write only where OIDC signing requires it).",
          "control": ".github/workflows/npm-publish.yml job-level permissions blocks; no self-hosted runners.",
        },
        {
          "ssdf": ["PO.3.1", "PO.3.2", "PS.1.1"],
          "claim": "The build environment's integrity is established by SLSA Build L3 provenance: a non-falsifiable attestation binds the published artifact to the exact workflow run, commit, and tag that produced it.",
          "control": "slsa-framework/slsa-github-generator generator_generic_slsa3.yml@v2.1.0 emits blamejs-<version>.intoto.jsonl; npm publish --provenance attaches the SLSA v1 provenance to the registry tarball.",
        },
        {
          "ssdf": ["PO.5.1"],
          "claim": "Third-party GitHub Actions are SHA-pinned (the one tag-pinned exception, the SLSA reusable workflow, is required by its builder-fetch and is documented + detector-allowlisted); a currency gate fails the release if any pin falls behind upstream.",
          "control": ".github/workflows/*.yml SHA pins; scripts/check-actions-currency.js runs on every PR and in the release flow.",
        },
      ],
    },
    {
      "id": "provenance-and-component-trust",
      "form_section": "2. Provenance and trust of software components",
      "summary": "The provenance of code and components is established and maintained; a complete SBOM accompanies every release.",
      "statements": [
        {
          "ssdf": ["PW.4.1", "PW.4.4"],
          "claim": "Zero npm runtime dependencies. Every third-party library is vendored under lib/vendor/ and pinned by SHA-256 in MANIFEST.json; the release refuses to publish if any runtime dependency component appears in the SBOM.",
          "control": "lib/vendor/MANIFEST.json (per-artifact SHA-256 + version + license + source); npm-publish.yml runtime-deps gate; b.configDrift.verifyVendorIntegrity re-checks each artifact's SHA-256 at boot.",
        },
        {
          "ssdf": ["PS.3.1", "PS.3.2"],
          "claim": "Each release ships a complete CycloneDX 1.6 SBOM (npm-tree view + vendored-bundle view with per-file SHA-256 and purl) so consumers can inventory exactly what ships inside the tarball.",
          "control": "sbom.cdx.json (npm tree) + sbom.vendored.cdx.json (scripts/build-vendored-sbom.js); both attached to the GitHub release.",
        },
        {
          "ssdf": ["PS.2.1"],
          "claim": "Release integrity is verifiable through four independent trust roots, each detecting tampering with the others: SLSA L3 npm provenance, Sigstore-keyless SBOM signatures, SSH-signed annotated tags, and an ML-DSA-65 (FIPS 204) release-signing sidecar over the tarball.",
          "control": "cosign sign-blob (sbom.*.sigstore); SSH-signed tags enforced server-side by the release-tags ruleset; <tarball>.mldsa.sig via the framework's vendored ML-DSA-65 primitive. Verification recipes in SECURITY.md.",
        },
      ],
    },
    {
      "id": "trusted-source-and-vuln-checking",
      "form_section": "3. Trusted source-code supply chains and automated vulnerability checking",
      "summary": "Good-faith effort to maintain trusted source-code supply chains and to perform automated vulnerability scanning on every release.",
      "statements": [
        {
          "ssdf": ["RV.1.1", "RV.1.2", "PW.7.2"],
          "claim": "Every release is scanned for known vulnerabilities before publish: OSV-Scanner runs against both SBOMs and the vendored tree, and the release fails on any finding. A vendored-dependency currency gate refuses a stale, potentially-vulnerable pin.",
          "control": "OSV-Scanner step in npm-publish.yml (--sbom both + -r lib/vendor/); scripts/check-vendor-currency.js.",
        },
        {
          "ssdf": ["PW.8.2", "PW.7.1"],
          "claim": "Adversarial-input parsers are continuously fuzzed (coverage-guided libFuzzer via jazzer.js) and the pattern-catalog gate refuses any new parser primitive that lands without a matching fuzz harness.",
          "control": "fuzz/*.fuzz.js harnesses; ClusterFuzzLite per-PR + daily batch; coverage gate in test/layer-0-primitives/codebase-patterns.test.js.",
        },
        {
          "ssdf": ["PS.1.1", "PO.5.2"],
          "claim": "Source-side supply-chain integrity is enforced at the repository boundary: protected default branch (no force-push, no non-linear merge, required status checks, required signed commits) and protected release tags (no deletion, no re-pointing) so a published tag cannot be silently rewritten.",
          "control": "main-protection + release-tags GitHub rulesets; the sha-to-tag-verify workflow refuses a tag whose commit is not on main's first-parent PR-merged history.",
        },
      ],
    },
    {
      "id": "vulnerability-disclosure-and-response",
      "form_section": "4. Vulnerability disclosure and response",
      "summary": "A vulnerability disclosure program and a process to respond to and remediate reported vulnerabilities are maintained.",
      "statements": [
        {
          "ssdf": ["RV.1.3", "RV.2.1"],
          "claim": "A coordinated vulnerability-disclosure process is published: a private reporting channel, an encryption option for sensitive reports, and committed first-response / triage / fix-release windows by severity.",
          "control": "SECURITY.md (security@blamejs.com, maintainer PGP key, response-time table); GitHub private security advisories.",
        },
        {
          "ssdf": ["RV.2.2", "RV.3.3"],
          "claim": "Fixes are delivered through a stable, signed release path with a public LTS / deprecation policy; remediations are described in operator-facing release notes and the CHANGELOG drawn from a single structured source.",
          "control": "scripts/release.js orchestrated flow; CHANGELOG.md + release-notes/<version>.json single source; LTS-CALENDAR.md.",
        },
        {
          "ssdf": ["RV.3.1", "RV.3.4"],
          "claim": "Root-cause analysis is institutional: a confirmed defect class is swept framework-wide and encoded as a recurrence detector so the same class cannot silently reappear in a later release.",
          "control": "codebase-patterns class-level detectors (test/layer-0-primitives/codebase-patterns.test.js); behavioral regression tests ship with each fix.",
        },
      ],
    },
  ];
}

function buildAttestation(opts) {
  var pkg = opts.pkg;
  return {
    "$schema_note": "NIST SP 800-218 (SSDF v1.1) / OMB M-22-18 producer self-attestation, machine-readable form.",
    "attestation_type": "producer-self-attestation",
    "attestation_format": "blamejs/ssdf-attestation",
    "attestation_format_version": "1.0",
    "framework": {
      "name": "NIST SP 800-218",
      "title": "Secure Software Development Framework (SSDF) Version 1.1",
      "reference_form": "OMB M-22-18 / CISA Secure Software Development Attestation Form",
    },
    "generated": opts.timestamp,
    "producer": {
      // The producer of record. This is a self-attestation: the producer
      // asserts the statements below, signed implicitly by the release
      // boundary (SSH-signed tag + SLSA provenance + PQC sidecar).
      "name": "blamejs",
      "url": "https://blamejs.com/",
      "security_contact": "security@blamejs.com",
      "vulnerability_disclosure": "https://github.com/blamejs/blamejs/security",
    },
    "software": {
      "name": pkg.name || "@blamejs/core",
      "version": opts.version,
      "repository": opts.repository,
      "commit": opts.commit,
      "license": pkg.license || null,
    },
    "attestation_statement":
      "blamejs attests, as the producer of " + (pkg.name || "@blamejs/core") +
      " version " + opts.version + ", that the secure software development " +
      "practices enumerated below are followed for this release, mapped to " +
      "NIST SP 800-218 (SSDF v1.1) practices. This is a self-attestation; " +
      "its authenticity is bound to the signed release artifacts described " +
      "in SECURITY.md (SSH-signed tag, SLSA L3 provenance, Sigstore SBOM " +
      "signatures, ML-DSA-65 release-signing sidecar).",
    "sections": _attestationStatements(),
    "verification": {
      "note": "This attestation is not independently signed; it is covered by the four release trust roots that sign the release containing it.",
      "trust_roots": [
        "SLSA L3 npm provenance (npm publish --provenance + blamejs-<version>.intoto.jsonl)",
        "Sigstore-keyless SBOM signatures (sbom.cdx.json.sigstore, sbom.vendored.cdx.json.sigstore)",
        "SSH-signed annotated git tag (release-tags ruleset, enforced server-side)",
        "ML-DSA-65 release-signing sidecar (<tarball>.mldsa.sig, FIPS 204)",
      ],
      "recipes": "SECURITY.md -> 'Verifying release authenticity'",
    },
  };
}

function main() {
  var args = _parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stderr.write(
      "Usage: node scripts/generate-ssdf-attestation.js " +
      "[--version <v>] [--commit <sha>] [--date <RFC3339>] " +
      "[--repository <url>] [--out <path>]\n" +
      "Timestamp source (required, deterministic): --date or SOURCE_DATE_EPOCH.\n"
    );
    return;
  }

  var pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(PKG_PATH, "utf8"));
  } catch (e) {
    process.stderr.write("[generate-ssdf-attestation] failed to read package.json: " + e.message + "\n");
    process.exit(1);
    return;
  }

  var doc = buildAttestation({
    pkg:        pkg,
    version:    _resolveVersion(args, pkg),
    commit:     _resolveCommit(args, process.env),     // allow:raw-process-env — env-driven release script
    repository: _resolveRepository(args, pkg),
    timestamp:  _resolveTimestamp(args, process.env),  // allow:raw-process-env — env-driven release script
  });

  var json = JSON.stringify(doc, null, 2) + "\n";

  if (typeof args.out === "string" && args.out.length > 0) {
    fs.writeFileSync(args.out, json);
    process.stderr.write("[generate-ssdf-attestation] wrote " + args.out + "\n");
  } else {
    process.stdout.write(json);
  }
}

main();
