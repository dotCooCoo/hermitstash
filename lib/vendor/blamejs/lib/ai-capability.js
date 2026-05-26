"use strict";
/**
 * @module b.ai.capability
 * @nav    AI
 * @title  AI capability routing
 *
 * @intro
 *   A capability registry + capability-aware router for AI model
 *   fleets. NIST AI RMF (AI 100-1) MAP 2.x requires documenting each
 *   model's capabilities and limitations; the Model Cards convention
 *   (Mitchell et al., 2019) formalizes that descriptor. This module
 *   turns those descriptors into a routing decision: given a set of
 *   requirements (context window, modalities, tool use, reasoning
 *   tier, …), pick the <em>cheapest</em> model in the fleet that
 *   satisfies all of them, or fall back deterministically.
 *
 *   <code>b.ai.capability.create({ models })</code> builds a registry
 *   from operator-supplied descriptors and returns:
 *
 *   - <code>describe(modelId)</code> — the frozen descriptor.
 *   - <code>list()</code> — every registered model id.
 *   - <code>register(modelId, descriptor)</code> — add / replace one.
 *   - <code>satisfies(modelId, requirements)</code> —
 *     <code>{ ok, failures }</code> where each failure names the
 *     requirement, the need, and what the model has.
 *   - <code>route({ requirements, fallback?, costBasis? })</code> —
 *     the cheapest satisfying model, or the fallback, or a refusal.
 *
 *   A descriptor carries: <code>maxContextTokens</code>,
 *   <code>maxOutputTokens</code>, <code>modalitiesIn</code> /
 *   <code>modalitiesOut</code> (arrays — e.g. <code>"text"</code>,
 *   <code>"image"</code>, <code>"audio"</code>, <code>"video"</code>),
 *   <code>toolUse</code>, <code>structuredOutput</code>,
 *   <code>fineTunable</code>, <code>reasoningTier</code>
 *   (<code>"none" | "basic" | "standard" | "advanced"</code>,
 *   ordered), <code>citationSupport</code>,
 *   <code>promptCachingMaxTokens</code>, and the cost rates
 *   <code>costPer1kInputTokens</code> / <code>costPer1kOutputTokens</code>.
 *
 *   <strong>Routing picks the cheapest match.</strong> When a
 *   <code>costBasis</code> (<code>{ inputTokens, outputTokens }</code>)
 *   is supplied the router estimates the per-call cost and ranks by
 *   it; otherwise it ranks by the sum of the per-1k rates. Ties break
 *   by model id so the choice is deterministic. Routing to the
 *   cheapest sufficient model is the front-line defense against
 *   over-provisioning spend — it composes with
 *   <code>b.ai.quota</code>'s <code>cost-usd</code> dimension, where
 *   the chosen descriptor's rate feeds the budget charge.
 *
 *   Refusing to route a request to a model that cannot satisfy it
 *   (missing modality, too-small context window, no tool use) catches
 *   a capability mismatch before the inference call burns tokens on a
 *   guaranteed-bad result.
 *
 * @card
 *   Capability registry + cheapest-satisfying-model router for AI
 *   model fleets (context / modalities / tool use / reasoning tier /
 *   cost). Composes with b.ai.quota cost budgets.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var AiCapabilityError = defineClass("AiCapabilityError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

// Ordered reasoning tiers — a requirement of `minReasoningTier:
// "standard"` is satisfied by "standard" or "advanced", not "basic".
var REASONING_TIERS = ["none", "basic", "standard", "advanced"];

// Cost rates are quoted per 1000 tokens (industry convention; the
// descriptor fields are costPer1kInputTokens / costPer1kOutputTokens).
// Dividing a token count by this rate unit converts a per-1k rate into
// the per-token multiplier — a rate denominator, not a byte size.
var COST_RATE_TOKEN_UNIT = 1000;   // allow:raw-byte-literal — per-1k-token cost-rate denominator, not a byte count

var DESCRIPTOR_KEYS = [
  "maxContextTokens", "maxOutputTokens", "modalitiesIn", "modalitiesOut",
  "toolUse", "structuredOutput", "fineTunable", "reasoningTier",
  "citationSupport", "promptCachingMaxTokens",
  "costPer1kInputTokens", "costPer1kOutputTokens", "provider", "version",
];

var REQUIREMENT_KEYS = [
  "minContextTokens", "minOutputTokens", "modalitiesIn", "modalitiesOut",
  "toolUse", "structuredOutput", "fineTunable", "minReasoningTier",
  "citationSupport", "minPromptCachingTokens",
];

function _isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n > 0 && Math.floor(n) === n;
}
function _isNonNegFinite(n) {
  return typeof n === "number" && isFinite(n) && n >= 0;
}
function _isStringArray(a) {
  if (!Array.isArray(a)) return false;
  for (var i = 0; i < a.length; i++) {
    if (typeof a[i] !== "string" || a[i].length === 0) return false;
  }
  return true;
}

// Normalize + validate one descriptor at registration time so a typo
// (negative cost, unknown reasoning tier, non-array modality list)
// surfaces at config time rather than as a silent mis-route.
function _normalizeDescriptor(modelId, d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: descriptor for '" + modelId + "' must be a plain object");
  }
  validateOpts(d, DESCRIPTOR_KEYS, "ai.capability descriptor['" + modelId + "']");

  if (!_isPositiveInt(d.maxContextTokens)) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: '" + modelId + "'.maxContextTokens must be a positive integer");
  }
  var maxOut = (d.maxOutputTokens == null) ? d.maxContextTokens : d.maxOutputTokens;
  if (!_isPositiveInt(maxOut)) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: '" + modelId + "'.maxOutputTokens must be a positive integer");
  }

  var modIn = (d.modalitiesIn == null) ? ["text"] : d.modalitiesIn;
  var modOut = (d.modalitiesOut == null) ? ["text"] : d.modalitiesOut;
  if (!_isStringArray(modIn) || !_isStringArray(modOut)) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: '" + modelId + "'.modalitiesIn / modalitiesOut must be arrays of non-empty strings");
  }

  var tier = (d.reasoningTier == null) ? "standard" : d.reasoningTier;
  if (REASONING_TIERS.indexOf(tier) === -1) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: '" + modelId + "'.reasoningTier must be one of " + REASONING_TIERS.join(" / "));
  }

  var cachingMax = (d.promptCachingMaxTokens == null) ? 0 : d.promptCachingMaxTokens;
  var costIn = (d.costPer1kInputTokens == null) ? 0 : d.costPer1kInputTokens;
  var costOut = (d.costPer1kOutputTokens == null) ? 0 : d.costPer1kOutputTokens;
  if (!_isNonNegFinite(cachingMax) || !_isNonNegFinite(costIn) || !_isNonNegFinite(costOut)) {
    throw new AiCapabilityError("aiCapability/bad-descriptor",
      "ai.capability: '" + modelId + "'.promptCachingMaxTokens / costPer1kInputTokens / " +
      "costPer1kOutputTokens must be non-negative finite numbers");
  }

  return Object.freeze({
    modelId:                modelId,
    maxContextTokens:       d.maxContextTokens,
    maxOutputTokens:        maxOut,
    modalitiesIn:           Object.freeze(modIn.slice()),
    modalitiesOut:          Object.freeze(modOut.slice()),
    toolUse:                d.toolUse === true,
    structuredOutput:       d.structuredOutput === true,
    fineTunable:            d.fineTunable === true,
    reasoningTier:          tier,
    citationSupport:        d.citationSupport === true,
    promptCachingMaxTokens: cachingMax,
    costPer1kInputTokens:   costIn,
    costPer1kOutputTokens:  costOut,
    provider:               (typeof d.provider === "string") ? d.provider : null,
    version:                (typeof d.version === "string") ? d.version : null,
  });
}

/**
 * @primitive b.ai.capability.create
 * @signature b.ai.capability.create(opts)
 * @since     0.12.28
 * @status    stable
 * @compliance soc2
 * @related   b.ai.quota.create, b.ai.modelManifest.build
 *
 * Build a capability registry + router from operator-supplied model
 * descriptors. Returns <code>{ describe, list, register, satisfies,
 * route }</code>. Pair it with <code>b.ai.quota</code>:
 * <code>route()</code> picks the cheapest model that meets the
 * request, and the chosen descriptor's cost rate feeds the
 * <code>cost-usd</code> budget charge.
 *
 * @opts
 *   {
 *     models: {                       // required, ≥ 1 entry
 *       [modelId: string]: {
 *         maxContextTokens:        number,    // required, positive int
 *         maxOutputTokens?:        number,    // default: maxContextTokens
 *         modalitiesIn?:           string[],  // default: ["text"]
 *         modalitiesOut?:          string[],  // default: ["text"]
 *         toolUse?:                boolean,   // default: false
 *         structuredOutput?:       boolean,   // default: false
 *         fineTunable?:            boolean,   // default: false
 *         reasoningTier?:          string,    // none|basic|standard|advanced
 *         citationSupport?:        boolean,   // default: false
 *         promptCachingMaxTokens?: number,    // default: 0
 *         costPer1kInputTokens?:   number,    // default: 0
 *         costPer1kOutputTokens?:  number,    // default: 0
 *         provider?:               string,
 *         version?:                string,
 *       }
 *     },
 *     audit?: boolean,                // default: true (route decisions)
 *   }
 *
 * @example
 *   var fleet = b.ai.capability.create({
 *     models: {
 *       "haiku":  { maxContextTokens: 200000, reasoningTier: "basic",
 *                   costPer1kInputTokens: 0.001, costPer1kOutputTokens: 0.005 },
 *       "opus":   { maxContextTokens: 200000, reasoningTier: "advanced",
 *                   toolUse: true, modalitiesIn: ["text", "image"],
 *                   costPer1kInputTokens: 0.015, costPer1kOutputTokens: 0.075 },
 *     },
 *   });
 *   var pick = fleet.route({
 *     requirements: { minContextTokens: 100000, toolUse: true,
 *                     modalitiesIn: ["text", "image"] },
 *     costBasis:    { inputTokens: 4000, outputTokens: 500 },
 *   });
 *   // → { modelId: "opus", descriptor: {...}, estimatedCost: 0.0975, reason: "cheapest-of-1" }
 */
function create(opts) {
  validateOpts.requireObject(opts, "ai.capability.create", AiCapabilityError);
  validateOpts(opts, ["models", "audit"], "ai.capability.create");

  if (!opts.models || typeof opts.models !== "object" || Array.isArray(opts.models)) {
    throw new AiCapabilityError("aiCapability/bad-models",
      "ai.capability.create: models must be a plain object { modelId: descriptor }");
  }
  var ids = Object.keys(opts.models);
  if (ids.length === 0) {
    throw new AiCapabilityError("aiCapability/bad-models",
      "ai.capability.create: models must declare at least one model");
  }

  var registry = new Map();
  for (var i = 0; i < ids.length; i++) {
    registry.set(ids[i], _normalizeDescriptor(ids[i], opts.models[ids[i]]));
  }
  var auditOn = opts.audit !== false;

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} });
    } catch (_e) { /* audit best-effort — drop-silent */ }
  }

  function describe(modelId) {
    var d = registry.get(modelId);
    if (!d) {
      throw new AiCapabilityError("aiCapability/unknown-model",
        "ai.capability.describe: unknown model '" + modelId + "'");
    }
    return d;
  }

  function list() {
    return Array.from(registry.keys());
  }

  function register(modelId, descriptor) {
    validateOpts.requireNonEmptyString(modelId,
      "ai.capability.register: modelId", AiCapabilityError, "aiCapability/bad-model");
    registry.set(modelId, _normalizeDescriptor(modelId, descriptor));
    return registry.get(modelId);
  }

  // Returns { ok, failures } — every unmet requirement names what was
  // needed and what the model has, so a caller can surface a precise
  // capability-mismatch reason instead of a bare boolean.
  function _evaluate(descriptor, requirements) {
    var failures = [];
    function fail(requirement, need, have) {
      failures.push({ requirement: requirement, need: need, have: have });
    }
    if (requirements.minContextTokens != null &&
        descriptor.maxContextTokens < requirements.minContextTokens) {
      fail("minContextTokens", requirements.minContextTokens, descriptor.maxContextTokens);
    }
    if (requirements.minOutputTokens != null &&
        descriptor.maxOutputTokens < requirements.minOutputTokens) {
      fail("minOutputTokens", requirements.minOutputTokens, descriptor.maxOutputTokens);
    }
    if (requirements.modalitiesIn != null) {
      for (var a = 0; a < requirements.modalitiesIn.length; a++) {
        if (descriptor.modalitiesIn.indexOf(requirements.modalitiesIn[a]) === -1) {
          fail("modalitiesIn", requirements.modalitiesIn[a], descriptor.modalitiesIn);
        }
      }
    }
    if (requirements.modalitiesOut != null) {
      for (var b = 0; b < requirements.modalitiesOut.length; b++) {
        if (descriptor.modalitiesOut.indexOf(requirements.modalitiesOut[b]) === -1) {
          fail("modalitiesOut", requirements.modalitiesOut[b], descriptor.modalitiesOut);
        }
      }
    }
    if (requirements.toolUse === true && descriptor.toolUse !== true) {
      fail("toolUse", true, false);
    }
    if (requirements.structuredOutput === true && descriptor.structuredOutput !== true) {
      fail("structuredOutput", true, false);
    }
    if (requirements.fineTunable === true && descriptor.fineTunable !== true) {
      fail("fineTunable", true, false);
    }
    if (requirements.citationSupport === true && descriptor.citationSupport !== true) {
      fail("citationSupport", true, false);
    }
    if (requirements.minReasoningTier != null &&
        REASONING_TIERS.indexOf(descriptor.reasoningTier) <
        REASONING_TIERS.indexOf(requirements.minReasoningTier)) {
      fail("minReasoningTier", requirements.minReasoningTier, descriptor.reasoningTier);
    }
    if (requirements.minPromptCachingTokens != null &&
        descriptor.promptCachingMaxTokens < requirements.minPromptCachingTokens) {
      fail("minPromptCachingTokens", requirements.minPromptCachingTokens, descriptor.promptCachingMaxTokens);
    }
    return { ok: failures.length === 0, failures: failures };
  }

  function _validateRequirements(requirements) {
    if (requirements == null) return {};
    if (typeof requirements !== "object" || Array.isArray(requirements)) {
      throw new AiCapabilityError("aiCapability/bad-requirements",
        "ai.capability: requirements must be a plain object");
    }
    validateOpts(requirements, REQUIREMENT_KEYS, "ai.capability requirements");
    if (requirements.minReasoningTier != null &&
        REASONING_TIERS.indexOf(requirements.minReasoningTier) === -1) {
      throw new AiCapabilityError("aiCapability/bad-requirements",
        "ai.capability: minReasoningTier must be one of " + REASONING_TIERS.join(" / "));
    }
    if (requirements.modalitiesIn != null && !_isStringArray(requirements.modalitiesIn)) {
      throw new AiCapabilityError("aiCapability/bad-requirements",
        "ai.capability: requirements.modalitiesIn must be an array of non-empty strings");
    }
    if (requirements.modalitiesOut != null && !_isStringArray(requirements.modalitiesOut)) {
      throw new AiCapabilityError("aiCapability/bad-requirements",
        "ai.capability: requirements.modalitiesOut must be an array of non-empty strings");
    }
    // Numeric minimums are compared with `<` against the descriptor; a
    // non-numeric value (NaN, "128k", a bad parse) makes that compare
    // false and SILENTLY satisfies the requirement, so an undersized
    // model could be selected. Reject non-finite / negative here so a
    // malformed requirement fails fast instead of fail-open.
    var numericMins = ["minContextTokens", "minOutputTokens", "minPromptCachingTokens"];
    for (var ni = 0; ni < numericMins.length; ni++) {
      var nk = numericMins[ni];
      if (requirements[nk] != null && !_isNonNegFinite(requirements[nk])) {
        throw new AiCapabilityError("aiCapability/bad-requirements",
          "ai.capability: requirements." + nk + " must be a non-negative finite number");
      }
    }
    // Boolean opt-in requirements are matched with `=== true`; a
    // non-boolean (truthy 1, "false") would silently fail to require
    // the capability. Reject non-booleans so the intent is explicit.
    var booleanReqs = ["toolUse", "structuredOutput", "fineTunable", "citationSupport"];
    for (var bi = 0; bi < booleanReqs.length; bi++) {
      var bk = booleanReqs[bi];
      if (requirements[bk] != null && typeof requirements[bk] !== "boolean") {
        throw new AiCapabilityError("aiCapability/bad-requirements",
          "ai.capability: requirements." + bk + " must be a boolean");
      }
    }
    return requirements;
  }

  function satisfies(modelId, requirements) {
    return _evaluate(describe(modelId), _validateRequirements(requirements));
  }

  // Per-call cost estimate. With a costBasis the estimate is the
  // real per-call spend (input + output tokens at the model's rates);
  // without one it is the sum of the per-1k rates — a stable proxy
  // for "cheaper model" when the caller hasn't sized the request.
  function _estimateCost(descriptor, costBasis) {
    if (costBasis) {
      var inTok = _isNonNegFinite(costBasis.inputTokens) ? costBasis.inputTokens : 0;
      var outTok = _isNonNegFinite(costBasis.outputTokens) ? costBasis.outputTokens : 0;
      return (inTok / COST_RATE_TOKEN_UNIT) * descriptor.costPer1kInputTokens +
             (outTok / COST_RATE_TOKEN_UNIT) * descriptor.costPer1kOutputTokens;
    }
    return descriptor.costPer1kInputTokens + descriptor.costPer1kOutputTokens;
  }

  function route(routeOpts) {
    routeOpts = routeOpts || {};
    validateOpts(routeOpts, ["requirements", "fallback", "costBasis"], "ai.capability.route");
    var requirements = _validateRequirements(routeOpts.requirements);
    var costBasis = null;
    if (routeOpts.costBasis != null) {
      if (typeof routeOpts.costBasis !== "object" || Array.isArray(routeOpts.costBasis)) {
        throw new AiCapabilityError("aiCapability/bad-requirements",
          "ai.capability.route: costBasis must be a plain object { inputTokens, outputTokens }");
      }
      validateOpts(routeOpts.costBasis, ["inputTokens", "outputTokens"],
        "ai.capability.route costBasis");
      // A malformed costBasis field silently underprices a candidate
      // and biases the "cheapest" choice toward the wrong model — fail
      // fast instead. An absent field is fine (treated as 0 tokens on
      // that side); a present-but-non-numeric field is rejected.
      var cbFields = ["inputTokens", "outputTokens"];
      for (var ci = 0; ci < cbFields.length; ci++) {
        var ck = cbFields[ci];
        if (routeOpts.costBasis[ck] != null && !_isNonNegFinite(routeOpts.costBasis[ck])) {
          throw new AiCapabilityError("aiCapability/bad-requirements",
            "ai.capability.route: costBasis." + ck + " must be a non-negative finite number");
        }
      }
      costBasis = routeOpts.costBasis;
    }

    // Collect every satisfying model, then pick the cheapest. Tie
    // break by model id (lexicographic) so the choice is deterministic
    // across calls and across nodes.
    var candidates = [];
    var modelIds = Array.from(registry.keys());
    for (var i = 0; i < modelIds.length; i++) {
      var d = registry.get(modelIds[i]);
      if (_evaluate(d, requirements).ok) {
        candidates.push({ modelId: modelIds[i], descriptor: d, cost: _estimateCost(d, costBasis) });
      }
    }
    candidates.sort(function (x, y) {
      if (x.cost !== y.cost) return x.cost - y.cost;
      return x.modelId < y.modelId ? -1 : (x.modelId > y.modelId ? 1 : 0);
    });

    if (candidates.length > 0) {
      var pick = candidates[0];
      _emitAudit("ai/capability-routed", "allowed", {
        modelId: pick.modelId, candidateCount: candidates.length,
        estimatedCost: pick.cost, requirements: requirements,
      });
      return {
        modelId:       pick.modelId,
        descriptor:    pick.descriptor,
        estimatedCost: pick.cost,
        reason:        "cheapest-of-" + candidates.length,
      };
    }

    // No model satisfies the requirements.
    if (routeOpts.fallback != null) {
      var fb = registry.get(routeOpts.fallback);
      if (!fb) {
        throw new AiCapabilityError("aiCapability/unknown-model",
          "ai.capability.route: fallback '" + routeOpts.fallback + "' is not a registered model");
      }
      _emitAudit("ai/capability-fallback", "allowed", {
        modelId: routeOpts.fallback, requirements: requirements,
      });
      return {
        modelId:       routeOpts.fallback,
        descriptor:    fb,
        estimatedCost: _estimateCost(fb, costBasis),
        reason:        "fallback",
      };
    }

    _emitAudit("ai/capability-no-candidate", "denied", { requirements: requirements });
    throw new AiCapabilityError("aiCapability/no-candidate",
      "ai.capability.route: no registered model satisfies the requirements " +
      "and no fallback was supplied");
  }

  return {
    describe:  describe,
    list:      list,
    register:  register,
    satisfies: satisfies,
    route:     route,
  };
}

module.exports = {
  create:             create,
  REASONING_TIERS:    REASONING_TIERS,
  AiCapabilityError:  AiCapabilityError,
};
