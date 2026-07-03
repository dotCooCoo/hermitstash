// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardEnvelope
 * @nav        Guards
 * @title      Guard Envelope
 * @order      455
 *
 * @intro
 *   RFC 7489 §3.1 DMARC Identifier Alignment validator. Gates the
 *   envelope-vs-header domain relationship at the MX listener's
 *   end-of-DATA boundary so a sender that passes SPF / DKIM under
 *   one domain but spoofs the user-visible `From:` header under
 *   another is refused before the message reaches the mail-store.
 *
 *   ## What aligns with what
 *
 *   DMARC's central identifier is **RFC 5322 `From:` domain** — the
 *   user-visible header field. Alignment requires at least one of:
 *
 *     - **SPF alignment** — `RFC5321.MailFrom` domain (envelope-from)
 *       passed SPF (RFC 7208) AND matches the From-header domain.
 *     - **DKIM alignment** — at least one DKIM signature with `d=<X>`
 *       verified (RFC 6376) AND `<X>` matches the From-header domain.
 *
 *   Match semantics (RFC 7489 §3.1.1 / §3.1.2):
 *
 *     - **Strict (`s`)** — exact FQDN match. `From: alice@example.com`
 *       requires the authenticated identifier to be exactly
 *       `example.com`.
 *     - **Relaxed (`r`)** — organizational-domain match (via Public
 *       Suffix List). `From: alice@mail.example.com` aligns with
 *       SPF `bounces.example.com` because both share organizational
 *       domain `example.com`. Relaxed is the spec default per
 *       RFC 7489 §6.2.
 *
 *   ## Why this primitive vs. b.mail.auth.dmarc.evaluate
 *
 *   `b.mail.auth.dmarc.evaluate` (existing) is the FULL DMARC policy
 *   evaluation: parse DMARC TXT record, evaluate pct sampling,
 *   compute final disposition (none / quarantine / reject), produce
 *   the aggregate-report tuple. It composes the alignment check
 *   internally.
 *
 *   `b.guardEnvelope.check` exposes JUST the alignment primitive so:
 *
 *     - The v0.9.36 MX listener can short-circuit on alignment fail
 *       before even running the upstream DMARC TXT lookup.
 *     - Operator middleware composing a custom anti-spoofing policy
 *       can reuse the alignment primitive without dragging in the
 *       full DMARC machinery (TXT parse, aggregate reporting, …).
 *     - Tests against alignment edge cases don't have to mock the
 *       full DMARC pipeline.
 *
 *   Both primitives produce the same alignment verdict for the same
 *   input — `b.guardEnvelope` is the focused gate; `b.mail.auth.dmarc`
 *   is the orchestrator.
 *
 *   ## Verdict shape
 *
 *   ```js
 *   {
 *     spf:    { aligned: bool, mode: "strict"|"relaxed", domain: string, fromDomain: string },
 *     dkim:   [{ aligned: bool, mode, signingDomain, fromDomain }, …],
 *     aligned: bool,      // at least one of SPF/DKIM aligned
 *     action: "accept" | "refuse"
 *   }
 *   ```
 *
 *   When operator's profile is `strict` and neither SPF nor DKIM
 *   aligns, action = `"refuse"`. Under `permissive`, action is
 *   always `"accept"` (the primitive computes alignment but doesn't
 *   gate on it — operator decides downstream from the verdict).
 *
 *   ## CVE / threat model
 *
 *   - **Display-name spoofing class** — `From: "Bank Of Foo" <a@evil.com>`
 *     where SPF passes for `evil.com` and DKIM signs `evil.com`: this
 *     primitive ALIGNS (both `evil.com`), so the spoof passes DMARC.
 *     Defense lives upstream in `b.guardEmail` (display-name vs
 *     domain mismatch detection).
 *   - **Envelope-vs-header spoofing** (the class this PRIMITIVE
 *     defends): `MAIL FROM:<service@aws-bounces.com>` SPF passes for
 *     aws-bounces.com, but `From: payments@your-bank.example` —
 *     misalignment refused under strict.
 *   - **Same-org-different-subdomain attack** under strict: legitimate
 *     mail from `bounces.example.com` to alignment-strict `example.com`
 *     is REFUSED — operator opts to relaxed for cross-subdomain mail.
 *   - **Public-suffix confusion** — relaxed mode uses
 *     `b.publicSuffix.organizationalDomain` which composes the
 *     vendored PSL; an attacker can't claim `co.uk` as their org
 *     domain because PSL classifies it as a public suffix.
 *
 * @card
 *   RFC 7489 §3.1 DMARC Identifier Alignment validator. Strict / relaxed match between RFC 5322 From-header domain and SPF MailFrom + DKIM d= identifiers. Composes b.publicSuffix.organizationalDomain for relaxed mode. Refuses envelope-vs-header spoofs at the MX boundary before mail-store touch.
 */

var { defineClass }    = require("./framework-error");
var lazyRequire        = require("./lazy-require");
var publicSuffix       = require("./public-suffix");
var gateContract       = require("./gate-contract");

var audit              = lazyRequire(function () { return require("./audit"); });

var GuardEnvelopeError = defineClass("GuardEnvelopeError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  // Strict: gate refuses on alignment fail. Default for HIPAA / PCI /
  // GDPR / SOC2 / banking / regulated mail.
  strict:     { gateOnFailure: true,  defaultMode: "relaxed" },
  // Balanced: gate refuses on alignment fail but defaults to relaxed
  // mode (RFC 7489 §6.2 default). For most operator deployments.
  balanced:   { gateOnFailure: true,  defaultMode: "relaxed" },
  // Permissive: compute alignment but always accept; operator
  // pipelines downstream consume the verdict for score-tagging.
  permissive: { gateOnFailure: false, defaultMode: "relaxed" },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

/**
 * @primitive b.guardEnvelope.check
 * @signature b.guardEnvelope.check(ctx, opts?)
 * @since     0.9.36
 * @status    stable
 * @related   b.publicSuffix.organizationalDomain, b.guardEmail.validateMessage
 *
 * Evaluate DMARC Identifier Alignment between the user-visible
 * `From:` header domain and the authenticated identifiers (SPF
 * MailFrom + DKIM d=). Returns the alignment verdict.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   spfMode:   "strict" | "relaxed",                      // per-call override (RFC 7489 §6.2)
 *   dkimMode:  "strict" | "relaxed",                      // per-call override
 *   audit:     b.audit namespace,
 *
 * @example
 *   var v = b.guardEnvelope.check({
 *     fromHeaderDomain: "example.com",
 *     spfResult:        { result: "pass", domain: "bounces.example.com" },
 *     dkimResults:      [{ result: "pass", signingDomain: "example.com" }],
 *   });
 *   if (v.action === "refuse") return reply(550, "5.7.1 DMARC alignment fail");
 */
function check(ctx, opts) {
  opts = opts || {};
  var profile = gateContract.resolveProfileName(opts, COMPLIANCE_POSTURES, DEFAULT_PROFILE);
  if (!Object.prototype.hasOwnProperty.call(PROFILES, profile)) {
    throw new GuardEnvelopeError("guard-envelope/bad-profile",
      "check: unknown profile '" + profile + "'");
  }
  var caps = PROFILES[profile];
  var spfMode  = opts.spfMode  || caps.defaultMode;
  var dkimMode = opts.dkimMode || caps.defaultMode;
  if (spfMode !== "strict" && spfMode !== "relaxed") {
    throw new GuardEnvelopeError("guard-envelope/bad-mode",
      "check: spfMode must be 'strict' or 'relaxed'");
  }
  if (dkimMode !== "strict" && dkimMode !== "relaxed") {
    throw new GuardEnvelopeError("guard-envelope/bad-mode",
      "check: dkimMode must be 'strict' or 'relaxed'");
  }
  var auditImpl = opts.audit || audit();

  if (!ctx || typeof ctx !== "object") {
    throw new GuardEnvelopeError("guard-envelope/bad-input",
      "check: ctx must be a plain object");
  }
  if (typeof ctx.fromHeaderDomain !== "string" || ctx.fromHeaderDomain.length === 0) {
    throw new GuardEnvelopeError("guard-envelope/bad-input",
      "check: ctx.fromHeaderDomain must be a non-empty string");
  }
  var fromDomain = ctx.fromHeaderDomain.toLowerCase();

  // SPF alignment.
  var spfVerdict = _spfVerdict(ctx.spfResult, fromDomain, spfMode);

  // DKIM alignment — one entry per signature.
  var dkimResults = Array.isArray(ctx.dkimResults) ? ctx.dkimResults : [];
  var dkimVerdicts = dkimResults.map(function (r) {
    return _dkimVerdict(r, fromDomain, dkimMode);
  });

  var anyAligned = spfVerdict.aligned || dkimVerdicts.some(function (d) { return d.aligned; });
  var action = anyAligned || !caps.gateOnFailure ? "accept" : "refuse";

  _emitAudit(auditImpl, anyAligned ? "guard.envelope.aligned" : "guard.envelope.misaligned", {
    fromDomain:  fromDomain,
    spfAligned:  spfVerdict.aligned,
    dkimAligned: dkimVerdicts.some(function (d) { return d.aligned; }),
    profile:     profile,
  });

  return {
    spf:     spfVerdict,
    dkim:    dkimVerdicts,
    aligned: anyAligned,
    action:  action,
  };
}

function _spfVerdict(spfResult, fromDomain, mode) {
  var verdict = {
    aligned:    false,
    mode:       mode,
    domain:     null,
    fromDomain: fromDomain,
    spfPass:    false,
  };
  if (!spfResult || typeof spfResult !== "object") return verdict;
  verdict.spfPass = spfResult.result === "pass";
  if (typeof spfResult.domain !== "string" || spfResult.domain.length === 0) return verdict;
  verdict.domain = spfResult.domain.toLowerCase();
  if (!verdict.spfPass) return verdict;
  verdict.aligned = _domainAligned(verdict.domain, fromDomain, mode);
  return verdict;
}

function _dkimVerdict(dkimResult, fromDomain, mode) {
  var verdict = {
    aligned:       false,
    mode:          mode,
    signingDomain: null,
    fromDomain:    fromDomain,
    dkimPass:      false,
  };
  if (!dkimResult || typeof dkimResult !== "object") return verdict;
  verdict.dkimPass = dkimResult.result === "pass";
  if (typeof dkimResult.signingDomain !== "string" || dkimResult.signingDomain.length === 0) return verdict;
  verdict.signingDomain = dkimResult.signingDomain.toLowerCase();
  if (!verdict.dkimPass) return verdict;
  verdict.aligned = _domainAligned(verdict.signingDomain, fromDomain, mode);
  return verdict;
}

function _domainAligned(authDomain, fromDomain, mode) {
  if (mode === "strict") {
    return authDomain === fromDomain;
  }
  // Relaxed — organizational-domain match via PSL.
  var orgAuth, orgFrom;
  try {
    orgAuth = publicSuffix.organizationalDomain(authDomain);
    orgFrom = publicSuffix.organizationalDomain(fromDomain);
  } catch (_e) { return false; }
  if (!orgAuth || !orgFrom) return false;
  return orgAuth === orgFrom;
}

function _emitAudit(auditImpl, action, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({
        action:   action,
        outcome:  "success",
        metadata: metadata,
      });
    }
  } catch (_e) { /* drop-silent — audit failure must not block accept loop */ }
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "envelope",
  entry:      check,
  entryName:  "check",
  errorClass: GuardEnvelopeError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME:           "envelope",
    KIND:           "envelope-alignment",
    _domainAligned: _domainAligned,
  },
});
