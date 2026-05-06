"use strict";
/**
 * Flag targeting — rule-based evaluation against an operator's
 * evaluation-context object (subject id, role, region, custom
 * attributes). Operators describe targeting in declarative JSON; the
 * framework evaluates without expression-injection risk.
 *
 * Rule shape:
 *
 *   { variant: "on", conditions: [
 *       { attribute: "user.role",   op: "eq",  value: "admin" },
 *       { attribute: "user.region", op: "in",  value: ["EU", "UK"] },
 *       { attribute: "user.tier",   op: "gte", value: 2 },
 *   ] }
 *
 * Operators are: eq / neq / in / nin / gt / gte / lt / lte / startsWith
 * / endsWith / contains / regex / exists / not_exists / between.
 *
 * Evaluation is conjunctive across `conditions` (all must pass for
 * the variant to apply). Multiple rules are evaluated in declaration
 * order; first match wins. If no rule matches, the flag's default
 * variant is returned.
 *
 * Per the validation-tier policy: rule-shape validation throws at
 * boot (config-time entry-point); evaluation hot-path returns
 * structured falsey on bad-shape rather than throwing.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var VALID_OPS = [
  "eq", "neq", "in", "nin", "gt", "gte", "lt", "lte",
  "starts_with", "ends_with", "contains",
  "regex", "exists", "not_exists", "between",
];

function _readPath(ctx, attribute) {
  if (typeof attribute !== "string" || attribute.length === 0) return undefined;
  if (!ctx || typeof ctx !== "object") return undefined;
  var parts = attribute.split(".");
  var current = ctx;
  for (var i = 0; i < parts.length; i += 1) {
    if (current == null || typeof current !== "object") return undefined;
    current = current[parts[i]];
  }
  return current;
}

function _evaluateCondition(condition, ctx) {
  if (!condition || typeof condition !== "object") return false;
  if (typeof condition.op !== "string") return false;
  if (VALID_OPS.indexOf(condition.op) === -1) return false;

  var presented = _readPath(ctx, condition.attribute);
  switch (condition.op) {
    case "eq":           return presented === condition.value;
    case "neq":          return presented !== condition.value;
    case "in":           return Array.isArray(condition.value) &&
                                condition.value.indexOf(presented) !== -1;
    case "nin":          return Array.isArray(condition.value) &&
                                condition.value.indexOf(presented) === -1;
    case "gt":           return typeof presented === "number" &&
                                typeof condition.value === "number" &&
                                presented > condition.value;
    case "gte":          return typeof presented === "number" &&
                                typeof condition.value === "number" &&
                                presented >= condition.value;
    case "lt":           return typeof presented === "number" &&
                                typeof condition.value === "number" &&
                                presented < condition.value;
    case "lte":          return typeof presented === "number" &&
                                typeof condition.value === "number" &&
                                presented <= condition.value;
    case "starts_with":  return typeof presented === "string" &&
                                typeof condition.value === "string" &&
                                presented.indexOf(condition.value) === 0;
    case "ends_with":    return typeof presented === "string" &&
                                typeof condition.value === "string" &&
                                presented.length >= condition.value.length &&
                                presented.slice(-condition.value.length) === condition.value;
    case "contains":     return typeof presented === "string" &&
                                typeof condition.value === "string" &&
                                presented.indexOf(condition.value) !== -1;
    case "regex":
      // Regex bounded — operator-supplied regex compiled at rule-validate
      // time and re-used here. Refuse to evaluate if regex isn't pre-
      // compiled (defense against runtime regex compilation per call).
      if (!(condition._compiledRegex instanceof RegExp)) return false;
      return typeof presented === "string" &&
             condition._compiledRegex.test(presented);
    case "exists":       return presented !== undefined;
    case "not_exists":   return presented === undefined;
    case "between":      return Array.isArray(condition.value) &&
                                condition.value.length === 2 &&
                                typeof presented === "number" &&
                                presented >= condition.value[0] &&
                                presented <= condition.value[1];
    default:             return false;
  }
}

function evaluateRules(rules, ctx, defaultVariant) {
  if (!Array.isArray(rules)) return { variant: defaultVariant, ruleIndex: -1, reason: "default" };
  for (var i = 0; i < rules.length; i += 1) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") continue;
    if (!Array.isArray(rule.conditions)) continue;
    var allPass = true;
    for (var j = 0; j < rule.conditions.length; j += 1) {
      if (!_evaluateCondition(rule.conditions[j], ctx)) {
        allPass = false; break;
      }
    }
    if (allPass) {
      return { variant: rule.variant, ruleIndex: i, reason: "targeting_match" };
    }
  }
  return { variant: defaultVariant, ruleIndex: -1, reason: "default" };
}

function validateRules(rules, label) {
  label = label || "rules";
  if (rules == null) return [];
  if (!Array.isArray(rules)) {
    throw new FlagError("flag/bad-rules",
      label + ": rules must be an array of rule objects");
  }
  var validated = [];
  for (var i = 0; i < rules.length; i += 1) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw new FlagError("flag/bad-rule",
        label + "[" + i + "]: rule must be an object");
    }
    validateOpts(rule, ["variant", "conditions", "weight"], label + "[" + i + "]");
    validateOpts.requireNonEmptyString(rule.variant, label + "[" + i + "].variant",
      FlagError, "flag/bad-rule");
    if (!Array.isArray(rule.conditions)) {
      throw new FlagError("flag/bad-rule",
        label + "[" + i + "].conditions: must be an array");
    }
    var validatedConds = [];
    for (var j = 0; j < rule.conditions.length; j += 1) {
      var cond = rule.conditions[j];
      var clabel = label + "[" + i + "].conditions[" + j + "]";
      if (!cond || typeof cond !== "object") {
        throw new FlagError("flag/bad-condition",
          clabel + ": condition must be an object");
      }
      validateOpts(cond, ["attribute", "op", "value"], clabel);
      validateOpts.requireNonEmptyString(cond.attribute, clabel + ".attribute",
        FlagError, "flag/bad-condition");
      if (VALID_OPS.indexOf(cond.op) === -1) {
        throw new FlagError("flag/bad-condition",
          clabel + ".op: must be one of " + VALID_OPS.join(", ") +
          " - got " + JSON.stringify(cond.op));
      }
      var validatedCond = {
        attribute: cond.attribute,
        op:        cond.op,
        value:     cond.value,
      };
      if (cond.op === "regex") {
        if (typeof cond.value !== "string") {
          throw new FlagError("flag/bad-condition",
            clabel + ".value: regex op requires a string value");
        }
        if (cond.value.length > 200) {
          throw new FlagError("flag/bad-condition",
            clabel + ".value: regex pattern must be <= 200 chars (DoS defense)");
        }
        try {
          // allow:dynamic-regex — operator-supplied targeting pattern, length-bounded to 200 chars above
          validatedCond._compiledRegex = new RegExp(cond.value);
        } catch (e) {
          throw new FlagError("flag/bad-condition",
            clabel + ".value: invalid regex - " + e.message);
        }
      }
      if (cond.op === "between") {
        if (!Array.isArray(cond.value) || cond.value.length !== 2 ||
            typeof cond.value[0] !== "number" || typeof cond.value[1] !== "number") {
          throw new FlagError("flag/bad-condition",
            clabel + ".value: between op requires [number, number]");
        }
      }
      if ((cond.op === "in" || cond.op === "nin") && !Array.isArray(cond.value)) {
        throw new FlagError("flag/bad-condition",
          clabel + ".value: " + cond.op + " op requires an array value");
      }
      validatedConds.push(validatedCond);
    }
    validated.push({
      variant:    rule.variant,
      conditions: validatedConds,
      weight:     (typeof rule.weight === "number") ? rule.weight : null,
    });
  }
  return validated;
}

module.exports = {
  evaluateRules:  evaluateRules,
  validateRules:  validateRules,
  VALID_OPS:      VALID_OPS,
  _readPath:      _readPath,
  FlagError:      FlagError,
};
