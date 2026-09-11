// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire      = require("../lazy-require");
var validateOpts     = require("../validate-opts");
var safeJson         = require("../safe-json");
var structuredFields = require("../structured-fields");
var codepointClass   = require("../codepoint-class");
var C                = require("../constants");
var { AuthError }    = require("../framework-error");

var acr            = require("./acr-vocabulary");
var authTime       = require("./auth-time-tracker");
var elevation      = lazyRequire(function () { return require("./elevation-grant"); });
var audit          = lazyRequire(function () { return require("../audit"); });

var INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication";
var DEFAULT_REALM                    = "api";

function _readPresentedClaims(claims) {
  return authTime.readClaims(claims);
}

function _quote(value) {
  if (typeof value !== "string") value = String(value);
  for (var i = 0; i < value.length; i += 1) {
    var code = value.charCodeAt(i);
    if (codepointClass.isForbiddenControlChar(code, { forbidTab: true })) {
      throw new AuthError("auth-step-up/bad-challenge",
        "challenge value contains control character at index " + i);
    }
    if (value.charAt(i) === '"' || value.charAt(i) === "\\") {
      throw new AuthError("auth-step-up/bad-challenge",
        "challenge value contains illegal character " +
        JSON.stringify(value.charAt(i)) + " at index " + i);
    }
  }
  return '"' + value + '"';
}

function _validateRequirement(requirement, label) {
  if (!requirement || typeof requirement !== "object") {
    throw new AuthError("auth-step-up/bad-requirement",
      label + ": requirement must be an object — got " +
      JSON.stringify(requirement));
  }
  validateOpts(requirement, [
    "acr", "acrValues", "maxAge", "requiredAmr", "phishingResistant",
    "authorizationDetails",
  ], label);
  if (requirement.acr != null) {
    validateOpts.requireNonEmptyString(requirement.acr,
      label + ": acr", AuthError, "auth-step-up/bad-acr");
  }
  if (requirement.acrValues != null) {
    if (!Array.isArray(requirement.acrValues) || requirement.acrValues.length === 0) {
      throw new AuthError("auth-step-up/bad-acr",
        label + ": acrValues must be a non-empty string array");
    }
    for (var i = 0; i < requirement.acrValues.length; i += 1) {
      validateOpts.requireNonEmptyString(requirement.acrValues[i],
        label + ": acrValues[" + i + "]", AuthError, "auth-step-up/bad-acr");
    }
  }
  if (requirement.maxAge != null) {
    if (typeof requirement.maxAge !== "number" || !isFinite(requirement.maxAge) ||
        requirement.maxAge < 0) {
      throw new AuthError("auth-step-up/bad-max-age",
        label + ": maxAge must be a finite number >= 0 — got " +
        JSON.stringify(requirement.maxAge));
    }
  }
  if (requirement.requiredAmr != null) {
    if (!Array.isArray(requirement.requiredAmr)) {
      throw new AuthError("auth-step-up/bad-amr",
        label + ": requiredAmr must be a string array");
    }
    for (var j = 0; j < requirement.requiredAmr.length; j += 1) {
      validateOpts.requireNonEmptyString(requirement.requiredAmr[j],
        label + ": requiredAmr[" + j + "]", AuthError, "auth-step-up/bad-amr");
    }
  }
  if (requirement.phishingResistant != null &&
      typeof requirement.phishingResistant !== "boolean") {
    throw new AuthError("auth-step-up/bad-requirement",
      label + ": phishingResistant must be boolean — got " +
      JSON.stringify(requirement.phishingResistant));
  }
}

function evaluate(opts) {
  opts = opts || {};
  var claims      = opts.claims;
  var requirement = opts.requirement;
  if (!requirement || typeof requirement !== "object") {
    return { ok: false, error: "no_requirement", reason: "evaluate: requirement object missing" };
  }
  // Hot-path drop-silent: do not throw on typo — return structured
  try { _validateRequirement(requirement, "auth.stepUp.evaluate"); }
  catch (err) { return { ok: false, error: "bad_requirement", reason: err.message }; }

  var presented = _readPresentedClaims(claims);
  var now       = (typeof opts.now === "number") ? opts.now : Math.floor(Date.now() / C.TIME.seconds(1));

  if (typeof requirement.acr === "string") {
    if (!acr.isRegistered(requirement.acr)) {
      return {
        ok: false, error: "unknown_acr",
        reason: "evaluate: required acr is not registered: " + requirement.acr,
        requirement: requirement,
      };
    }
    if (!acr.meets(presented.acr, requirement.acr)) {
      return {
        ok: false, error: INSUFFICIENT_USER_AUTHENTICATION,
        reason:  "presented acr " + JSON.stringify(presented.acr) +
                 " does not meet required " + JSON.stringify(requirement.acr),
        requirement: requirement, presented: presented,
      };
    }
  }
  if (Array.isArray(requirement.acrValues) && requirement.acrValues.length > 0) {
    if (!acr.meetsAny(presented.acr, requirement.acrValues)) {
      return {
        ok: false, error: INSUFFICIENT_USER_AUTHENTICATION,
        reason: "presented acr " + JSON.stringify(presented.acr) +
                " does not meet any of " + JSON.stringify(requirement.acrValues),
        requirement: requirement, presented: presented,
      };
    }
  }
  if (typeof requirement.maxAge === "number") {
    if (!authTime.freshEnough(claims, requirement.maxAge, now)) {
      return {
        ok: false, error: INSUFFICIENT_USER_AUTHENTICATION,
        reason: "auth_time stale or missing — required max_age=" +
                requirement.maxAge + "s, age=" + authTime.ageSec(claims, now),
        requirement: requirement, presented: presented,
      };
    }
  }
  if (Array.isArray(requirement.requiredAmr) && requirement.requiredAmr.length > 0) {
    if (!acr.amrSatisfiesRequiredList(presented.amr, requirement.requiredAmr)) {
      return {
        ok: false, error: INSUFFICIENT_USER_AUTHENTICATION,
        reason: "presented amr " + JSON.stringify(presented.amr) +
                " does not include all required " + JSON.stringify(requirement.requiredAmr),
        requirement: requirement, presented: presented,
      };
    }
  }
  if (requirement.phishingResistant === true) {
    if (!acr.amrIncludesPhishingResistant(presented.amr)) {
      return {
        ok: false, error: INSUFFICIENT_USER_AUTHENTICATION,
        reason: "presented amr " + JSON.stringify(presented.amr) +
                " does not include any phishing-resistant method",
        requirement: requirement, presented: presented,
      };
    }
  }
  return { ok: true, presented: presented };
}

function buildChallenge(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "requirement", "realm", "error", "errorDescription", "scope",
  ], "auth.stepUp.buildChallenge");
  _validateRequirement(opts.requirement, "auth.stepUp.buildChallenge");
  var realm   = (typeof opts.realm === "string" && opts.realm.length > 0) ? opts.realm : DEFAULT_REALM;
  var errCode = (typeof opts.error === "string" && opts.error.length > 0)
    ? opts.error : INSUFFICIENT_USER_AUTHENTICATION;
  var errDesc = (typeof opts.errorDescription === "string" && opts.errorDescription.length > 0)
    ? opts.errorDescription : "A higher level of authentication is required";

  var parts = [];
  parts.push('realm=' + _quote(realm));
  parts.push('error=' + _quote(errCode));
  parts.push('error_description=' + _quote(errDesc));
  if (typeof opts.scope === "string" && opts.scope.length > 0) {
    parts.push('scope=' + _quote(opts.scope));
  }

  var req = opts.requirement;
  if (typeof req.acr === "string" && req.acr.length > 0) {
    parts.push('acr_values=' + _quote(req.acr));
  } else if (Array.isArray(req.acrValues) && req.acrValues.length > 0) {
    parts.push('acr_values=' + _quote(req.acrValues.join(" ")));
  }
  if (typeof req.maxAge === "number") {
    parts.push('max_age=' + _quote(String(req.maxAge)));
  }
  if (Array.isArray(req.requiredAmr) && req.requiredAmr.length > 0) {
    parts.push('amr_values=' + _quote(req.requiredAmr.join(" ")));
  }
  if (Array.isArray(req.authorizationDetails) && req.authorizationDetails.length > 0) {
    parts.push('authorization_details=' + _quote(JSON.stringify(req.authorizationDetails)));
  }
  return "Bearer " + parts.join(", ");
}

function parseAuthorizationDetails(value) {
  if (typeof value !== "string") {
    throw new AuthError("auth-step-up/bad-rar",
      "parseAuthorizationDetails: value must be a JSON string — got " +
      typeof value);
  }
  var parsed;
  try { parsed = safeJson.parse(value, { maxBytes: C.BYTES.kib(64) }); }
  catch (e) {
    throw new AuthError("auth-step-up/bad-rar",
      "parseAuthorizationDetails: invalid JSON — " + e.message);
  }
  if (!Array.isArray(parsed)) {
    throw new AuthError("auth-step-up/bad-rar",
      "parseAuthorizationDetails: value must be a JSON array — got " +
      typeof parsed);
  }
  for (var i = 0; i < parsed.length; i += 1) {
    var entry = parsed[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new AuthError("auth-step-up/bad-rar",
        "parseAuthorizationDetails[" + i + "]: must be an object");
    }
    if (typeof entry.type !== "string" || entry.type.length === 0) {
      throw new AuthError("auth-step-up/bad-rar",
        "parseAuthorizationDetails[" + i + "]: missing required 'type' field");
    }
  }
  return parsed;
}

function emitAuditRequired(label, requirement, presented, req) {
  try {
    audit().safeEmit({
      action:  "auth.stepup.required",
      outcome: "denied",
      actor:   { route: req && (req.url || req.pathname) || null,
                 userId: req && req.user && req.user.id || null },
      metadata: {
        label:        label || "stepUp",
        requirement:  _summarizeRequirement(requirement),
        presented:    _summarizePresented(presented),
      },
    });
  } catch (_e) { /* drop-silent */ }
}

function emitAuditSatisfied(label, requirement, presented, req) {
  try {
    audit().safeEmit({
      action:  "auth.stepup.satisfied",
      outcome: "success",
      actor:   { route: req && (req.url || req.pathname) || null,
                 userId: req && req.user && req.user.id || null },
      metadata: {
        label:        label || "stepUp",
        requirement:  _summarizeRequirement(requirement),
        presented:    _summarizePresented(presented),
      },
    });
  } catch (_e) { /* drop-silent */ }
}

function _summarizeRequirement(req) {
  if (!req || typeof req !== "object") return null;
  return {
    acr:               req.acr || null,
    acrValues:         Array.isArray(req.acrValues) ? req.acrValues.slice() : null,
    maxAge:            (typeof req.maxAge === "number") ? req.maxAge : null,
    requiredAmr:       Array.isArray(req.requiredAmr) ? req.requiredAmr.slice() : null,
    phishingResistant: req.phishingResistant === true ? true : false,
  };
}

function _summarizePresented(presented) {
  if (!presented || typeof presented !== "object") return null;
  return {
    acr:       presented.acr || null,
    amr:       Array.isArray(presented.amr) ? presented.amr.slice() : null,
    auth_time: presented.auth_time || null,
  };
}

function parseChallenge(headerValue) {
  if (typeof headerValue !== "string") return null;
  if (structuredFields.containsControlBytes(headerValue)) return null;
  var idx = headerValue.toLowerCase().indexOf("bearer");
  if (idx === -1) return null;
  var rest = headerValue.slice(idx + "bearer".length).trim();
  if (rest.length === 0) return null;
  var out = { error: null, scope: null, acrValues: null, maxAge: null, raw: {} };
  var kvps = structuredFields.parseKeyValuePieces(_splitWwwAuth(rest));
  structuredFields.forEachKeyValue(kvps, function (key, val) {
    val = structuredFields.stripDoubleQuotes(val);
    out.raw[key] = val;
    if (key === "error")              out.error     = val;
    else if (key === "scope")         out.scope     = val;
    else if (key === "acr_values")    out.acrValues = val.split(/\s+/);
    else if (key === "max_age") {
      var ma = parseInt(val, 10);
      if (isFinite(ma) && ma >= 0) out.maxAge = ma;
    }
  });
  return out;
}

function _splitWwwAuth(raw) {
  var tokens = [];
  var cursor = 0;
  var inQuoted = false;
  var current = "";
  while (cursor < raw.length) {
    var ch = raw.charAt(cursor);
    if (inQuoted) {
      current += ch;
      if (ch === "\\" && cursor + 1 < raw.length) {
        current += raw.charAt(cursor + 1);
        cursor += 2;
        continue;
      }
      if (ch === '"') inQuoted = false;
      cursor += 1;
      continue;
    }
    if (ch === '"') { inQuoted = true; current += ch; cursor += 1; continue; }
    if (ch === ",") {
      tokens.push(current);
      current = "";
      cursor += 1;
      continue;
    }
    current += ch;
    cursor += 1;
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

var policy        = lazyRequire(function () { return require("./step-up-policy"); });

module.exports = {
  evaluate:                  evaluate,
  buildChallenge:            buildChallenge,
  parseChallenge:            parseChallenge,
  parseAuthorizationDetails: parseAuthorizationDetails,
  acr:                       acr,
  authTime:                  authTime,
  get policy()               { return policy(); },
  grant:                     {
    create:           function (opts) { return elevation().create(opts); },
    verify:           function (token, opts) { return elevation().verify(token, opts); },
    revoke:           function (jti, opts) { return elevation().revoke(jti, opts); },
    isRevoked:        function (jti) { return elevation().isRevoked(jti); },
    list:             function () { return elevation().list(); },
    setSigningKey:    function (key) { return elevation().setSigningKey(key); },
    _resetForTests:   function () { return elevation()._resetForTests(); },
  },
  emitAuditRequired:   emitAuditRequired,
  emitAuditSatisfied:  emitAuditSatisfied,
  INSUFFICIENT_USER_AUTHENTICATION: INSUFFICIENT_USER_AUTHENTICATION,
};
