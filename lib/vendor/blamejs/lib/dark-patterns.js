// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.darkPatterns
 * @nav    Compliance
 * @title  Dark Patterns
 *
 * @intro
 *   FTC dark-patterns compliance — refusal helpers for fake-urgency,
 *   confirm-shaming, drip-pricing, hidden-cost, sneak-into-basket
 *   patterns.
 *
 *   The FTC's Negative Option Rule (effective 2024; expanded 2025-26
 *   via state click-to-cancel laws) requires that the steps to cancel
 *   a subscription be no more burdensome than the steps to subscribe.
 *   The framework can't measure pixel-level UI parity from server
 *   code; what it ships is an attestation primitive: operators record
 *   a signup-flow snapshot (clicks, CTA text + font weight + contrast
 *   ratio, confirmations, channel, login requirement) and a matching
 *   cancel-flow snapshot. The framework computes the parity verdict
 *   against a posture (`ftc-2024` / `ca-sb942` / `strict`), audits
 *   the result, and ships a middleware that refuses cancel-route
 *   traffic with HTTP 451 when no passing attestation is on file.
 *
 * @card
 *   FTC dark-patterns compliance — refusal helpers for fake-urgency, confirm-shaming, drip-pricing, hidden-cost, sneak-into-basket patterns.
 */

var audit = require("./audit");
var { defineClass } = require("./framework-error");

var STR_LEN_MAX     = 256;                                                                  // string-length cap, not bytes
var FONT_WEIGHT_MAX = 1000;                                                                 // CSS font-weight ceiling (CSS Fonts L4)
var DarkPatternsError = defineClass("DarkPatternsError", { alwaysPermanent: true });

var CHANNELS = ["web", "mobile", "phone", "email", "in-person", "mail"];

var POSTURES = {
  // FTC Negative Option Rule baseline — clicks must not exceed signup;
  // cancel must use the same channel; contrast/font weight must not
  // degrade.
  "ftc-2024": {
    toleranceClicks:    0,
    requireSameChannel: true,
    toleranceContrast:  4.5,
    requireSameFont:    true,
  },
  // California SB-942 / AB-2863 — stricter; cancel UI must use same
  // medium AND require <= signup confirmations.
  "ca-sb942": {
    toleranceClicks:    0,
    requireSameChannel: true,
    toleranceContrast:  4.5,
    requireSameFont:    true,
    requireSameConfirmations: true,
  },
  "strict": {
    toleranceClicks:    0,
    requireSameChannel: true,
    toleranceContrast:  7.0,
    requireSameFont:    true,
    requireSameConfirmations: true,
  },
};

function _validateFlowOpts(opts, label, errorClass) {
  if (!opts || typeof opts !== "object") {
    throw errorClass.factory("dark-patterns/bad-opts",
      "darkPatterns.record" + label + ": opts required");
  }
  if (CHANNELS.indexOf(opts.channel) === -1) {
    throw errorClass.factory("dark-patterns/bad-channel",
      "darkPatterns: channel must be one of " + CHANNELS.join(","));
  }
  if (typeof opts.clickCount !== "number" || !isFinite(opts.clickCount) ||
      opts.clickCount < 1 || opts.clickCount > 50 ||
      Math.floor(opts.clickCount) !== opts.clickCount) {
    throw errorClass.factory("dark-patterns/bad-clicks",
      "darkPatterns: clickCount must be integer 1..50");
  }
  if (!opts.cta || typeof opts.cta !== "object") {
    throw errorClass.factory("dark-patterns/bad-cta",
      "darkPatterns: cta object required (text, fontWeight, contrastRatio)");
  }
  if (typeof opts.cta.text !== "string" || opts.cta.text.length === 0 ||
      opts.cta.text.length > STR_LEN_MAX) {
    throw errorClass.factory("dark-patterns/bad-cta-text",
      "darkPatterns: cta.text must be 1-256 char string");
  }
  if (typeof opts.cta.fontWeight !== "number" || opts.cta.fontWeight < 100 ||
      opts.cta.fontWeight > FONT_WEIGHT_MAX) {
    throw errorClass.factory("dark-patterns/bad-font-weight",
      "darkPatterns: cta.fontWeight must be 100..1000");
  }
  if (typeof opts.cta.contrastRatio !== "number" ||
      opts.cta.contrastRatio < 1 || opts.cta.contrastRatio > 21) {
    throw errorClass.factory("dark-patterns/bad-contrast",
      "darkPatterns: cta.contrastRatio must be 1..21");
  }
  if (typeof opts.confirmations !== "number" ||
      opts.confirmations < 0 || opts.confirmations > 10 ||
      Math.floor(opts.confirmations) !== opts.confirmations) {
    throw errorClass.factory("dark-patterns/bad-confirmations",
      "darkPatterns: confirmations must be integer 0..10");
  }
  if (typeof opts.resourceId !== "string" || opts.resourceId.length === 0 ||
      opts.resourceId.length > STR_LEN_MAX) {
    throw errorClass.factory("dark-patterns/bad-resource-id",
      "darkPatterns: resourceId must be 1-256 char string");
  }
}

/**
 * @primitive b.darkPatterns.recordSignupFlow
 * @signature b.darkPatterns.recordSignupFlow(opts)
 * @since     0.8.44
 * @related   b.darkPatterns.recordCancelFlow, b.darkPatterns.assertParity, b.darkPatterns.attest
 *
 * Capture a frozen snapshot of an operator-attested signup flow.
 * Validates every input strictly: channel must be one of the allowed
 * channels, click count is an integer 1..50, CTA carries a non-empty
 * label plus CSS font weight 100..1000 and WCAG contrast 1..21,
 * confirmations are an integer 0..10. The frozen result feeds
 * `assertParity` paired with the matching cancel-flow snapshot.
 *
 * @opts
 *   channel:        "web" | "mobile" | "phone" | "email" | "in-person" | "mail",
 *   clickCount:     number,                // integer 1..50
 *   cta:            { text: string, fontWeight: number, contrastRatio: number },
 *   confirmations:  number,                // integer 0..10
 *   requiresLogin:  boolean,
 *   resourceId:     string,                // links signup<->cancel
 *
 * @example
 *   var signup = b.darkPatterns.recordSignupFlow({
 *     channel:       "web",
 *     clickCount:    2,
 *     cta:           { text: "Subscribe", fontWeight: 700, contrastRatio: 7.2 },
 *     confirmations: 1,
 *     requiresLogin: false,
 *     resourceId:    "plan-pro-2026",
 *   });
 *   signup.kind;          // → "signup"
 *   signup.clickCount;    // → 2
 */
function recordSignupFlow(opts) {
  _validateFlowOpts(opts, "SignupFlow", DarkPatternsError);
  return Object.freeze({
    kind:          "signup",
    channel:       opts.channel,
    clickCount:    opts.clickCount,
    cta: Object.freeze({
      text:          opts.cta.text,
      fontWeight:    opts.cta.fontWeight,
      contrastRatio: opts.cta.contrastRatio,
    }),
    confirmations: opts.confirmations,
    requiresLogin: opts.requiresLogin === true,
    resourceId:    opts.resourceId,
    recordedAt:    Date.now(),
  });
}

/**
 * @primitive b.darkPatterns.recordCancelFlow
 * @signature b.darkPatterns.recordCancelFlow(opts)
 * @since     0.8.44
 * @related   b.darkPatterns.recordSignupFlow, b.darkPatterns.assertParity, b.darkPatterns.attest
 *
 * Capture a frozen snapshot of the cancel-flow counterpart. Same
 * validation discipline and field shape as `recordSignupFlow` so the
 * two snapshots are directly comparable. The `resourceId` MUST match
 * the signup snapshot's `resourceId`; `assertParity` enforces this.
 *
 * @opts
 *   channel:        "web" | "mobile" | "phone" | "email" | "in-person" | "mail",
 *   clickCount:     number,                // integer 1..50
 *   cta:            { text: string, fontWeight: number, contrastRatio: number },
 *   confirmations:  number,                // integer 0..10
 *   requiresLogin:  boolean,
 *   resourceId:     string,                // must match signup
 *
 * @example
 *   var cancel = b.darkPatterns.recordCancelFlow({
 *     channel:       "web",
 *     clickCount:    2,
 *     cta:           { text: "Cancel subscription", fontWeight: 700, contrastRatio: 7.2 },
 *     confirmations: 1,
 *     requiresLogin: false,
 *     resourceId:    "plan-pro-2026",
 *   });
 *   cancel.kind;          // → "cancel"
 *   cancel.resourceId;    // → "plan-pro-2026"
 */
function recordCancelFlow(opts) {
  _validateFlowOpts(opts, "CancelFlow", DarkPatternsError);
  return Object.freeze({
    kind:          "cancel",
    channel:       opts.channel,
    clickCount:    opts.clickCount,
    cta: Object.freeze({
      text:          opts.cta.text,
      fontWeight:    opts.cta.fontWeight,
      contrastRatio: opts.cta.contrastRatio,
    }),
    confirmations: opts.confirmations,
    requiresLogin: opts.requiresLogin === true,
    resourceId:    opts.resourceId,
    recordedAt:    Date.now(),
  });
}

/**
 * @primitive b.darkPatterns.assertParity
 * @signature b.darkPatterns.assertParity(signup, cancel, opts)
 * @since     0.8.44
 * @related   b.darkPatterns.recordSignupFlow, b.darkPatterns.recordCancelFlow, b.darkPatterns.attest
 *
 * Compare a signup snapshot against a cancel snapshot under a named
 * posture. Reports every parity breach: extra clicks beyond
 * `toleranceClicks`, channel mismatch, contrast below the posture
 * floor or degraded by more than 0.5 vs signup, font-weight
 * regression, added confirmations, login required only on cancel.
 * Returns `{ ok, breaches, posture }`. Postures: `ftc-2024` (FTC
 * baseline), `ca-sb942` (California stricter), `strict` (contrast
 * floor 7.0).
 *
 * @opts
 *   posture:           "ftc-2024" | "ca-sb942" | "strict",
 *   toleranceClicks:   number,             // override posture default
 *   toleranceContrast: number,             // override posture default
 *   errorClass:        Error,              // override DarkPatternsError
 *
 * @example
 *   var signup = b.darkPatterns.recordSignupFlow({
 *     channel: "web", clickCount: 2,
 *     cta: { text: "Subscribe", fontWeight: 700, contrastRatio: 7.2 },
 *     confirmations: 1, requiresLogin: false, resourceId: "plan-pro-2026",
 *   });
 *   var cancel = b.darkPatterns.recordCancelFlow({
 *     channel: "web", clickCount: 5,
 *     cta: { text: "Cancel", fontWeight: 400, contrastRatio: 3.0 },
 *     confirmations: 3, requiresLogin: true, resourceId: "plan-pro-2026",
 *   });
 *   var verdict = b.darkPatterns.assertParity(signup, cancel, { posture: "ftc-2024" });
 *   verdict.ok;                            // → false
 *   verdict.breaches.map(function (b2) { return b2.kind; });
 *   // → ["click-count", "contrast-below-floor", "contrast-degradation",
 *   //    "font-weight-degradation", "confirmation-step-added",
 *   //    "login-required-only-for-cancel"]
 */
function assertParity(signup, cancel, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || DarkPatternsError;
  if (!signup || signup.kind !== "signup") {
    throw errorClass.factory("dark-patterns/bad-signup-flow",
      "darkPatterns.assertParity: signup must be a recorded signup flow");
  }
  if (!cancel || cancel.kind !== "cancel") {
    throw errorClass.factory("dark-patterns/bad-cancel-flow",
      "darkPatterns.assertParity: cancel must be a recorded cancel flow");
  }
  if (signup.resourceId !== cancel.resourceId) {
    throw errorClass.factory("dark-patterns/resource-mismatch",
      "darkPatterns.assertParity: resourceId differs between flows");
  }
  var postureName = opts.posture || "ftc-2024";
  // Own-property lookup: postureName is operator input, so a bare
  // `POSTURES[postureName]` with a truthiness guard would let a prototype key
  // ("constructor") resolve to an inherited member and run under it (fail-open).
  if (!Object.prototype.hasOwnProperty.call(POSTURES, postureName)) {
    throw errorClass.factory("dark-patterns/bad-posture",
      "darkPatterns.assertParity: unknown posture " + postureName);
  }
  var posture = POSTURES[postureName];

  var toleranceClicks   = typeof opts.toleranceClicks === "number"
    ? opts.toleranceClicks : posture.toleranceClicks;
  var toleranceContrast = typeof opts.toleranceContrast === "number"
    ? opts.toleranceContrast : posture.toleranceContrast;

  var breaches = [];

  if (cancel.clickCount > signup.clickCount + toleranceClicks) {
    breaches.push({
      kind:     "click-count",
      detail:   "cancel " + cancel.clickCount + " > signup " + signup.clickCount +
                " + tolerance " + toleranceClicks,
    });
  }
  if (posture.requireSameChannel && cancel.channel !== signup.channel) {
    breaches.push({
      kind:   "channel-mismatch",
      detail: "signup=" + signup.channel + " cancel=" + cancel.channel,
    });
  }
  if (cancel.cta.contrastRatio < toleranceContrast) {
    breaches.push({
      kind:   "contrast-below-floor",
      detail: "cancel contrast " + cancel.cta.contrastRatio +
              " < required " + toleranceContrast,
    });
  }
  if (cancel.cta.contrastRatio < signup.cta.contrastRatio - 0.5) {
    breaches.push({
      kind:   "contrast-degradation",
      detail: "cancel " + cancel.cta.contrastRatio +
              " < signup " + signup.cta.contrastRatio + " - 0.5",
    });
  }
  if (posture.requireSameFont && cancel.cta.fontWeight < signup.cta.fontWeight) {
    breaches.push({
      kind:   "font-weight-degradation",
      detail: "cancel " + cancel.cta.fontWeight +
              " < signup " + signup.cta.fontWeight,
    });
  }
  if (posture.requireSameConfirmations &&
      cancel.confirmations > signup.confirmations) {
    breaches.push({
      kind:   "confirmation-step-added",
      detail: "cancel " + cancel.confirmations +
              " > signup " + signup.confirmations,
    });
  }
  if (cancel.requiresLogin && !signup.requiresLogin) {
    breaches.push({
      kind:   "login-required-only-for-cancel",
      detail: "signup did not require login; cancel does",
    });
  }

  return { ok: breaches.length === 0, breaches: breaches, posture: postureName };
}

/**
 * @primitive b.darkPatterns.attest
 * @signature b.darkPatterns.attest(opts)
 * @since     0.8.44
 * @related   b.darkPatterns.recordSignupFlow, b.darkPatterns.recordCancelFlow, b.darkPatterns.assertParity, b.darkPatterns.middleware
 *
 * One-shot composer used by operators that capture both flows during
 * a UI regression test: builds the two snapshots, runs `assertParity`,
 * and emits an audit row keyed `darkpatterns.attest` whose outcome is
 * `success` on parity-clean or `denied` on any breach. Returns the
 * full attestation envelope (id, both snapshots, verdict, signedAt)
 * suitable for persistence and lookup by the cancel-route middleware.
 *
 * @opts
 *   signup:  recordSignupFlow opts shape,
 *   cancel:  recordCancelFlow opts shape,
 *   posture: "ftc-2024" | "ca-sb942" | "strict",
 *   audit:   boolean,                      // default true
 *
 * @example
 *   var att = b.darkPatterns.attest({
 *     signup: {
 *       channel: "web", clickCount: 2,
 *       cta: { text: "Subscribe", fontWeight: 700, contrastRatio: 7.2 },
 *       confirmations: 1, requiresLogin: false, resourceId: "plan-pro-2026",
 *     },
 *     cancel: {
 *       channel: "web", clickCount: 2,
 *       cta: { text: "Cancel subscription", fontWeight: 700, contrastRatio: 7.2 },
 *       confirmations: 1, requiresLogin: false, resourceId: "plan-pro-2026",
 *     },
 *     posture: "ftc-2024",
 *   });
 *   att.verdict.ok;     // → true
 *   att.id;             // → "plan-pro-2026"
 */
function attest(opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || DarkPatternsError;
  var signup = recordSignupFlow(opts.signup || {});
  var cancel = recordCancelFlow(opts.cancel || {});
  var verdict = assertParity(signup, cancel, {
    errorClass: errorClass,
    posture:    opts.posture,
  });
  var auditOn = opts.audit !== false;
  if (auditOn) {
    audit.safeEmit({
      action:   "darkpatterns.attest",
      outcome:  verdict.ok ? "success" : "denied",
      reason:   verdict.ok ? null : "parity-breach",
      metadata: {
        resourceId: signup.resourceId,
        posture:    verdict.posture,
        breaches:   verdict.breaches.map(function (b) { return b.kind; }),
      },
    });
  }
  return {
    id:         signup.resourceId,
    signupFlow: signup,
    cancelFlow: cancel,
    verdict:    verdict,
    signedAt:   Date.now(),
  };
}

/**
 * @primitive b.darkPatterns.middleware
 * @signature b.darkPatterns.middleware(opts)
 * @since     0.8.44
 * @related   b.darkPatterns.attest, b.darkPatterns.assertParity
 *
 * Mount on the cancel-route handler. Resolves a `resourceId` from
 * the inbound request via the operator's `resourceIdFromReq`, looks
 * up the corresponding attestation via `lookupAttestation`, and
 * refuses with HTTP 451 (Unavailable for Legal Reasons) when no
 * attestation exists or the on-file verdict shows a parity breach.
 * Audits the refusal under `darkpatterns.cancel_blocked`.
 *
 * @opts
 *   lookupAttestation: function (resourceId) -> attestation | Promise,
 *   resourceIdFromReq: function (req) -> string,
 *   errorClass:        Error,              // override DarkPatternsError
 *
 * @example
 *   var attestations = new Map();
 *   var mw = b.darkPatterns.middleware({
 *     resourceIdFromReq: function (req) { return req.headers["x-plan-id"]; },
 *     lookupAttestation: function (id) { return attestations.get(id); },
 *   });
 *   // mount mw on the DELETE /subscription handler — refuses with 451
 *   // when the operator has no passing parity attestation on file.
 */
function middleware(opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || DarkPatternsError;
  if (typeof opts.lookupAttestation !== "function") {
    throw errorClass.factory("dark-patterns/bad-opts",
      "darkPatterns.middleware: lookupAttestation function required");
  }
  if (typeof opts.resourceIdFromReq !== "function") {
    throw errorClass.factory("dark-patterns/bad-opts",
      "darkPatterns.middleware: resourceIdFromReq function required");
  }

  return function darkPatternsMw(req, res, next) {
    Promise.resolve().then(function () {
      var resourceId;
      try { resourceId = opts.resourceIdFromReq(req); }
      catch (e) {
        return _refuse(res, "darkPatterns: resourceIdFromReq threw: " + e.message);
      }
      if (typeof resourceId !== "string" || resourceId.length === 0) {
        return _refuse(res, "darkPatterns: missing resourceId");
      }
      return Promise.resolve(opts.lookupAttestation(resourceId)).then(function (att) {
        if (!att || !att.verdict || !att.verdict.ok) {
          audit.safeEmit({
            action:   "darkpatterns.cancel_blocked",
            outcome:  "denied",
            reason:   att && att.verdict ? "parity-breach" : "no-attestation",
            metadata: { resourceId: resourceId, breaches: att && att.verdict ? att.verdict.breaches.map(function (b) { return b.kind; }) : [] },
          });
          if (typeof res.setHeader === "function") {
            res.setHeader("Content-Type", "application/json");
          }
          res.statusCode = 451;
          res.end(JSON.stringify({
            error: "cancel-flow-not-attested",
            detail: att && att.verdict ? att.verdict.breaches : "no attestation on file",
          }));
          return;
        }
        if (typeof next === "function") next();
      });
    }).catch(function (e) {
      _refuse(res, "darkPatterns middleware error: " + (e && e.message));
    });
    function _refuse(r, msg) {
      if (typeof r.setHeader === "function") r.setHeader("Content-Type", "application/json");
      r.statusCode = 500;
      r.end(JSON.stringify({ error: msg }));
    }
  };
}

module.exports = {
  recordSignupFlow:  recordSignupFlow,
  recordCancelFlow:  recordCancelFlow,
  assertParity:      assertParity,
  attest:            attest,
  middleware:        middleware,
  POSTURES:          Object.keys(POSTURES),
  CHANNELS:          CHANNELS.slice(),
  DarkPatternsError: DarkPatternsError,
};
