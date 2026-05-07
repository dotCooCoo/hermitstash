"use strict";
/**
 * FTC Dark-Patterns / Click-to-Cancel UX-parity attestation.
 *
 * The FTC's Negative Option Rule (effective 2024; expanded 2025-2026
 * via state click-to-cancel laws) requires that the steps to cancel a
 * subscription / withdraw consent be no more burdensome than the
 * steps to subscribe / grant consent. The standard breakdown:
 *
 *   - prominence parity        — same call-to-action visibility
 *   - click-count parity       — cancel <= signup
 *   - contrast / font parity   — accessible-text contrast and font
 *                                weight match
 *   - method parity            — operator that signed up over the web
 *                                must let the subject cancel over the
 *                                web (not phone-only)
 *   - confirmation parity      — single-confirmation if signup was
 *                                single-confirmation
 *
 * The framework can't measure pixel-level UI parity from server code.
 * What it CAN do is provide a primitive that:
 *
 *   1. Records an operator-attested signup-flow snapshot (clicks,
 *      visible call-to-action text, font weight, contrast ratio).
 *   2. Records an attested cancel-flow snapshot.
 *   3. Computes the parity verdict and emits an audit trail.
 *   4. Refuses to emit a "consent-withdrawn" event in postures that
 *      require parity if the snapshots show degradation.
 *
 * Public API:
 *
 *   darkPatterns.recordSignupFlow(opts) -> snapshot
 *   darkPatterns.recordCancelFlow(opts) -> snapshot
 *     opts: {
 *       channel:     "web" | "mobile" | "phone" | "email" | "in-person",
 *       clickCount:  integer 1..50,
 *       cta:         { text, fontWeight, contrastRatio },
 *       confirmations: integer 0..10,
 *       requiresLogin: bool,
 *       resourceId:  operator-supplied id linking signup<->cancel,
 *     }
 *
 *   darkPatterns.assertParity(signup, cancel, opts) -> { ok, breaches }
 *     opts:
 *       toleranceClicks      — how many extra cancel clicks tolerated
 *                              (default 0).
 *       toleranceContrast    — minimum contrast ratio absolute value
 *                              required of cancel (default 4.5 — AA).
 *       posture              — "ftc-2024" | "ca-sb942" | "strict".
 *       errorClass           — DarkPatternsError (mapped to McpError
 *                              namespace? no — uses a dedicated class).
 *
 *   darkPatterns.attest(opts) -> { id, signupFlow, cancelFlow, verdict, signedAt }
 *     One-shot composer used by operators that capture both flows
 *     during a regression test of their UI.
 *
 *   darkPatterns.middleware(opts) -> middleware(req, res, next)
 *     Attached to the cancel-flow endpoint. Verifies the operator has
 *     a parity attestation on file (via opts.lookupAttestation) and
 *     refuses with 451 (legal reasons) if missing.
 */

var audit = require("./audit");
var { defineClass } = require("./framework-error");

var STR_LEN_MAX     = 256;                                                                  // allow:raw-byte-literal — string-length cap, not bytes
var FONT_WEIGHT_MAX = 1000;                                                                 // allow:raw-byte-literal — CSS font-weight ceiling (CSS Fonts L4)
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
    throw errorClass.factory("BAD_OPTS",
      "darkPatterns.record" + label + ": opts required");
  }
  if (CHANNELS.indexOf(opts.channel) === -1) {
    throw errorClass.factory("BAD_CHANNEL",
      "darkPatterns: channel must be one of " + CHANNELS.join(","));
  }
  if (typeof opts.clickCount !== "number" || !isFinite(opts.clickCount) ||
      opts.clickCount < 1 || opts.clickCount > 50 ||
      Math.floor(opts.clickCount) !== opts.clickCount) {
    throw errorClass.factory("BAD_CLICKS",
      "darkPatterns: clickCount must be integer 1..50");
  }
  if (!opts.cta || typeof opts.cta !== "object") {
    throw errorClass.factory("BAD_CTA",
      "darkPatterns: cta object required (text, fontWeight, contrastRatio)");
  }
  if (typeof opts.cta.text !== "string" || opts.cta.text.length === 0 ||
      opts.cta.text.length > STR_LEN_MAX) {
    throw errorClass.factory("BAD_CTA_TEXT",
      "darkPatterns: cta.text must be 1-256 char string");
  }
  if (typeof opts.cta.fontWeight !== "number" || opts.cta.fontWeight < 100 ||
      opts.cta.fontWeight > FONT_WEIGHT_MAX) {
    throw errorClass.factory("BAD_FONT_WEIGHT",
      "darkPatterns: cta.fontWeight must be 100..1000");
  }
  if (typeof opts.cta.contrastRatio !== "number" ||
      opts.cta.contrastRatio < 1 || opts.cta.contrastRatio > 21) {
    throw errorClass.factory("BAD_CONTRAST",
      "darkPatterns: cta.contrastRatio must be 1..21");
  }
  if (typeof opts.confirmations !== "number" ||
      opts.confirmations < 0 || opts.confirmations > 10 ||
      Math.floor(opts.confirmations) !== opts.confirmations) {
    throw errorClass.factory("BAD_CONFIRMATIONS",
      "darkPatterns: confirmations must be integer 0..10");
  }
  if (typeof opts.resourceId !== "string" || opts.resourceId.length === 0 ||
      opts.resourceId.length > STR_LEN_MAX) {
    throw errorClass.factory("BAD_RESOURCE_ID",
      "darkPatterns: resourceId must be 1-256 char string");
  }
}

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

function assertParity(signup, cancel, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || DarkPatternsError;
  if (!signup || signup.kind !== "signup") {
    throw errorClass.factory("BAD_SIGNUP_FLOW",
      "darkPatterns.assertParity: signup must be a recorded signup flow");
  }
  if (!cancel || cancel.kind !== "cancel") {
    throw errorClass.factory("BAD_CANCEL_FLOW",
      "darkPatterns.assertParity: cancel must be a recorded cancel flow");
  }
  if (signup.resourceId !== cancel.resourceId) {
    throw errorClass.factory("RESOURCE_MISMATCH",
      "darkPatterns.assertParity: resourceId differs between flows");
  }
  var postureName = opts.posture || "ftc-2024";
  var posture = POSTURES[postureName];
  if (!posture) {
    throw errorClass.factory("BAD_POSTURE",
      "darkPatterns.assertParity: unknown posture " + postureName);
  }

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

function middleware(opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || DarkPatternsError;
  if (typeof opts.lookupAttestation !== "function") {
    throw errorClass.factory("BAD_OPTS",
      "darkPatterns.middleware: lookupAttestation function required");
  }
  if (typeof opts.resourceIdFromReq !== "function") {
    throw errorClass.factory("BAD_OPTS",
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
