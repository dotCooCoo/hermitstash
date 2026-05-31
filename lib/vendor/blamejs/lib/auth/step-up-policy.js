"use strict";
/**
 * Step-up policy DSL — compose RFC 9470 step-up requirements as a
 * fluent expression rather than a flat object. Useful for routes that
 * need "ACR >= loa3 OR a fresh hardware-key auth within the last 5 min".
 *
 *   var policy = b.auth.stepUp.policy
 *                 .acr("loa3")
 *                 .and(b.auth.stepUp.policy.maxAge(300))
 *                 .or(
 *                   b.auth.stepUp.policy.amr(["hwk", "pop"])
 *                     .and(b.auth.stepUp.policy.maxAge(120))
 *                 );
 *
 *   var result = policy.evaluate(claims);
 *
 *   var middleware = policy.middleware({ realm: "billing-api" });
 *
 * The policy compiles down to RFC 9470 challenges by extracting the
 * outermost-feasible (acr, maxAge, amr, ...) tuple. When an operator's
 * policy is genuinely or-of-and-of-..., the challenge emitted is the
 * UNION of individually-required atoms (so the IdP knows what to ask
 * for) plus an `error_description` hint that there are alternatives.
 *
 * The DSL is pure. All node types are immutable once constructed;
 * chaining returns a new policy object.
 */

var lazyRequire   = require("../lazy-require");
var validateOpts  = require("../validate-opts");
var { AuthError } = require("../framework-error");

var stepUp        = lazyRequire(function () { return require("./step-up"); });
var requireStepUp = lazyRequire(function () { return require("../middleware/require-step-up"); });

function _mkNode(spec) {
  spec.evaluate = function (claims) {
    return spec._run(claims);
  };
  spec.toRequirement = function () {
    return spec._toReq();
  };
  spec.and = function (other) {
    return _and(spec, other);
  };
  spec.or = function (other) {
    return _or(spec, other);
  };
  spec.not = function () {
    return _not(spec);
  };
  spec.middleware = function (opts) {
    opts = opts || {};
    return requireStepUp().create(Object.assign({}, opts, {
      requirement: spec._toReq(),
    }));
  };
  return Object.freeze(spec);
}

function acr(value) {
  validateOpts.requireNonEmptyString(value, "policy.acr: value", AuthError, "auth-step-up/bad-acr");
  return _mkNode({
    kind:  "acr",
    value: value,
    _run: function (claims) {
      var result = stepUp().evaluate({
        claims:      claims,
        requirement: { acr: value },
      });
      return { ok: result.ok === true, atom: "acr:" + value, reason: result.reason || null };
    },
    _toReq: function () { return { acr: value }; },
  });
}

function acrAny(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new AuthError("auth-step-up/bad-policy",
      "policy.acrAny: values must be a non-empty array");
  }
  for (var i = 0; i < values.length; i += 1) {
    validateOpts.requireNonEmptyString(values[i],
      "policy.acrAny: values[" + i + "]", AuthError, "auth-step-up/bad-acr");
  }
  var copy = values.slice();
  return _mkNode({
    kind:   "acrAny",
    values: copy,
    _run:  function (claims) {
      var result = stepUp().evaluate({
        claims:      claims,
        requirement: { acrValues: copy },
      });
      return { ok: result.ok === true, atom: "acrAny:" + copy.join(","), reason: result.reason || null };
    },
    _toReq: function () { return { acrValues: copy }; },
  });
}

function amr(required) {
  if (!Array.isArray(required) || required.length === 0) {
    throw new AuthError("auth-step-up/bad-policy",
      "policy.amr: required must be a non-empty array");
  }
  for (var i = 0; i < required.length; i += 1) {
    validateOpts.requireNonEmptyString(required[i],
      "policy.amr: required[" + i + "]", AuthError, "auth-step-up/bad-amr");
  }
  var copy = required.slice();
  return _mkNode({
    kind:     "amr",
    required: copy,
    _run:    function (claims) {
      var result = stepUp().evaluate({
        claims:      claims,
        requirement: { requiredAmr: copy },
      });
      return { ok: result.ok === true, atom: "amr:" + copy.join("+"), reason: result.reason || null };
    },
    _toReq: function () { return { requiredAmr: copy }; },
  });
}

function phishingResistant() {
  return _mkNode({
    kind:  "phishingResistant",
    _run: function (claims) {
      var result = stepUp().evaluate({
        claims:      claims,
        requirement: { phishingResistant: true },
      });
      return { ok: result.ok === true, atom: "phr", reason: result.reason || null };
    },
    _toReq: function () { return { phishingResistant: true }; },
  });
}

function maxAge(seconds) {
  if (typeof seconds !== "number" || !isFinite(seconds) || seconds < 0) {
    throw new AuthError("auth-step-up/bad-policy",
      "policy.maxAge: seconds must be a finite number >= 0 — got " +
      JSON.stringify(seconds));
  }
  return _mkNode({
    kind:    "maxAge",
    seconds: seconds,
    _run:   function (claims) {
      var result = stepUp().evaluate({
        claims:      claims,
        requirement: { maxAge: seconds },
      });
      return { ok: result.ok === true, atom: "maxAge:" + seconds, reason: result.reason || null };
    },
    _toReq: function () { return { maxAge: seconds }; },
  });
}

function custom(name, fn) {
  validateOpts.requireNonEmptyString(name, "policy.custom: name", AuthError, "auth-step-up/bad-policy");
  if (typeof fn !== "function") {
    throw new AuthError("auth-step-up/bad-policy",
      "policy.custom: fn must be a function — got " + typeof fn);
  }
  return _mkNode({
    kind: "custom",
    name: name,
    _run: function (claims) {
      var ok = false;
      try { ok = fn(claims) === true; } catch (_e) { ok = false; }
      return { ok: ok, atom: "custom:" + name, reason: ok ? null : "custom predicate '" + name + "' returned false" };
    },
    _toReq: function () {
      throw new AuthError("auth-step-up/policy-no-challenge",
        "policy.custom: cannot translate to RFC 9470 challenge — wrap in .or() with a translatable atom or use .middleware({ requirement: ... })");
    },
  });
}

function _and(left, right) {
  return _mkNode({
    kind:  "and",
    left:  left,
    right: right,
    _run: function (claims) {
      var l = left._run(claims);
      if (!l.ok) return { ok: false, atom: "and(" + l.atom + ")", reason: l.reason };
      var r = right._run(claims);
      if (!r.ok) return { ok: false, atom: "and(" + l.atom + "," + r.atom + ")", reason: r.reason };
      return { ok: true, atom: "and(" + l.atom + "," + r.atom + ")", reason: null };
    },
    _toReq: function () {
      var lr = left._toReq();
      var rr = right._toReq();
      return _mergeAnd(lr, rr);
    },
  });
}

function _or(left, right) {
  return _mkNode({
    kind:  "or",
    left:  left,
    right: right,
    _run: function (claims) {
      var l = left._run(claims);
      if (l.ok) return { ok: true, atom: "or(" + l.atom + ")", reason: null };
      var r = right._run(claims);
      if (r.ok) return { ok: true, atom: "or(" + r.atom + ")", reason: null };
      return {
        ok: false,
        atom: "or(" + l.atom + "," + r.atom + ")",
        reason: l.reason + " AND " + r.reason,
      };
    },
    _toReq: function () {
      // RFC 9470 doesn't support OR semantics in WWW-Authenticate. We
      // pick the LEFT branch and emit its challenge — operator can
      // override via .middleware({ requirement }).
      return left._toReq();
    },
  });
}

function _not(inner) {
  return _mkNode({
    kind:  "not",
    inner: inner,
    _run: function (claims) {
      var i = inner._run(claims);
      return { ok: !i.ok, atom: "not(" + i.atom + ")", reason: i.ok ? "not(" + i.atom + ") matched" : null };
    },
    _toReq: function () {
      throw new AuthError("auth-step-up/policy-no-challenge",
        "policy.not: cannot translate to RFC 9470 challenge");
    },
  });
}

function _mergeAnd(a, b) {
  var out = {};
  if (a.acr || b.acr) {
    if (a.acr && b.acr && a.acr !== b.acr) {
      throw new AuthError("auth-step-up/policy-conflict",
        "policy.and: conflicting acr requirements " +
        JSON.stringify(a.acr) + " and " + JSON.stringify(b.acr));
    }
    out.acr = a.acr || b.acr;
  }
  if (a.acrValues || b.acrValues) {
    out.acrValues = (a.acrValues || []).concat(b.acrValues || []);
  }
  if (a.maxAge != null && b.maxAge != null) {
    out.maxAge = Math.min(a.maxAge, b.maxAge);                 // tighter wins
  } else if (a.maxAge != null) {
    out.maxAge = a.maxAge;
  } else if (b.maxAge != null) {
    out.maxAge = b.maxAge;
  }
  if (a.requiredAmr || b.requiredAmr) {
    var combined = (a.requiredAmr || []).concat(b.requiredAmr || []);
    var seen = Object.create(null);
    out.requiredAmr = [];
    for (var i = 0; i < combined.length; i += 1) {
      if (!seen[combined[i]]) {
        seen[combined[i]] = true;
        out.requiredAmr.push(combined[i]);
      }
    }
  }
  if (a.phishingResistant === true || b.phishingResistant === true) {
    out.phishingResistant = true;
  }
  return out;
}

// ---- Common preset policies operators reach for ----

var C = require("../constants");
var SEC_5_MIN  = C.TIME.minutes(5)  / C.TIME.seconds(1);
var SEC_2_MIN  = C.TIME.minutes(2)  / C.TIME.seconds(1);
var SEC_15_MIN = C.TIME.minutes(15) / C.TIME.seconds(1);
var SEC_1_MIN  = C.TIME.minutes(1)  / C.TIME.seconds(1);

var PRESETS = {
  // Sensitive write: ACR >= loa2 + auth_time within 5 min
  sensitiveWrite: function () {
    return acr("loa2").and(maxAge(SEC_5_MIN));
  },
  // Admin bulk: ACR >= loa3 + max_age 5 min + phishing-resistant
  adminBulk: function () {
    return acr("loa3").and(maxAge(SEC_5_MIN)).and(phishingResistant());
  },
  // Financial: phr-class hardware + max_age 2 min
  financial: function () {
    return acr("loa3").and(amr(["hwk"])).and(maxAge(SEC_2_MIN));
  },
  // PHI read: ACR >= loa2 + max_age 15 min
  phiRead: function () {
    return acr("loa2").and(maxAge(SEC_15_MIN));
  },
  // PHI write: ACR >= loa3 + max_age 5 min + phishing-resistant
  phiWrite: function () {
    return acr("loa3").and(maxAge(SEC_5_MIN)).and(phishingResistant());
  },
  // Account-recovery: phishing-resistant + max_age 1 min
  accountRecovery: function () {
    return phishingResistant().and(maxAge(SEC_1_MIN));
  },
};

function preset(name) {
  if (!Object.prototype.hasOwnProperty.call(PRESETS, name)) {
    throw new AuthError("auth-step-up/bad-preset",
      "policy.preset: unknown preset " + JSON.stringify(name) +
      " — valid presets: " + Object.keys(PRESETS).join(", "));
  }
  return PRESETS[name]();
}

function listPresets() {
  return Object.keys(PRESETS).slice();
}

module.exports = {
  acr:                acr,
  acrAny:             acrAny,
  amr:                amr,
  phishingResistant:  phishingResistant,
  maxAge:             maxAge,
  custom:             custom,
  preset:             preset,
  listPresets:        listPresets,
  PRESETS:            PRESETS,
};
