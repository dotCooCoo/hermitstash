"use strict";
/**
 * Flag providers — backend implementations that produce flag values
 * for a given (flagKey, evaluationContext) tuple.
 *
 * Three first-party providers ship with the framework:
 *
 *   localFile({ path, watch?, signature? })
 *     Reads a JSON file at boot and on change-events. Each flag entry
 *     describes default-variant + variants + targeting-rules +
 *     percentage-rollouts.
 *
 *   memory({ flags })
 *     In-process map of flagKey to flag-spec. Useful for tests and
 *     for operators who treat flags as code (compiled into the boot
 *     image).
 *
 *   environmentVariable({ envVarPattern, prefix })
 *     Reads a flag's value from process.env. Useful for boot-time
 *     toggles bound to deployment configuration.
 *
 * Operators with a remote-flag-management plane (LaunchDarkly, flagd,
 * Unleash, OpenFeature gRPC) wire their own provider implementing the
 * `evaluate(flagKey, ctx)` contract and pass it to b.flag.create.
 *
 * Provider contract:
 *
 *   provider.evaluate(flagKey, ctx) -> {
 *     value:    any,            // resolved value (boolean / string / number / object)
 *     variant:  string,         // variant name ("on" / "off" / "treatment-A" / ...)
 *     reason:   string,         // "default" | "targeting_match" | "split" | ...
 *     metadata: object,         // optional per-provider hints
 *   }
 *
 *   provider.list() -> string[]   list of registered flag keys (for tooling)
 *   provider.kind   -> "local-file" | "memory" | "environment" | <operator-defined>
 */

var nodeFs = require("node:fs");
var validateOpts   = require("./validate-opts");
var lazyRequire    = require("./lazy-require");
var safeJson       = require("./safe-json");
var C              = require("./constants");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var targeting = require("./flag-targeting");
var contextMod = lazyRequire(function () { return require("./flag-evaluation-context"); });

function _validateFlagSpec(flagKey, spec) {
  if (!spec || typeof spec !== "object") {
    throw new FlagError("flag/bad-spec",
      "flag spec for " + JSON.stringify(flagKey) + " must be an object");
  }
  validateOpts(spec, [
    "default", "variants", "rules", "rollout",
    "description", "tags", "kind",
  ], "flag spec for " + flagKey);
  if (spec.variants == null || typeof spec.variants !== "object") {
    throw new FlagError("flag/bad-spec",
      flagKey + ": variants object is required (variantName -> value)");
  }
  if (typeof spec.default !== "string" ||
      !Object.prototype.hasOwnProperty.call(spec.variants, spec.default)) {
    throw new FlagError("flag/bad-spec",
      flagKey + ": default must be a variant name; got " + JSON.stringify(spec.default));
  }
  if (spec.rules != null) {
    targeting.validateRules(spec.rules, flagKey + ".rules");
    // Every rule's variant must be a registered variant.
    for (var i = 0; i < spec.rules.length; i += 1) {
      var v = spec.rules[i].variant;
      if (!Object.prototype.hasOwnProperty.call(spec.variants, v)) {
        throw new FlagError("flag/bad-spec",
          flagKey + ".rules[" + i + "].variant: " + JSON.stringify(v) +
          " is not a registered variant");
      }
    }
  }
  if (spec.rollout != null) {
    if (!Array.isArray(spec.rollout)) {
      throw new FlagError("flag/bad-spec",
        flagKey + ".rollout: must be an array of { variant, percentage } entries");
    }
    var sum = 0;
    for (var j = 0; j < spec.rollout.length; j += 1) {
      var entry = spec.rollout[j];
      if (!entry || typeof entry !== "object" ||
          typeof entry.variant !== "string" ||
          typeof entry.percentage !== "number" ||
          entry.percentage < 0 || entry.percentage > 100) {
        throw new FlagError("flag/bad-spec",
          flagKey + ".rollout[" + j + "]: must be { variant: string, percentage: 0..100 }");
      }
      if (!Object.prototype.hasOwnProperty.call(spec.variants, entry.variant)) {
        throw new FlagError("flag/bad-spec",
          flagKey + ".rollout[" + j + "].variant: " + JSON.stringify(entry.variant) +
          " is not a registered variant");
      }
      sum += entry.percentage;
    }
    if (sum > 100.0001) {
      throw new FlagError("flag/bad-spec",
        flagKey + ".rollout: percentage sum must be <= 100; got " + sum);
    }
  }
}

function memory(opts) {
  opts = opts || {};
  validateOpts(opts, ["flags"], "flag.providers.memory");
  if (!opts.flags || typeof opts.flags !== "object") {
    throw new FlagError("flag/bad-provider",
      "providers.memory: flags object required (flagKey -> spec)");
  }
  var flags = {};
  for (var key in opts.flags) {
    if (!Object.prototype.hasOwnProperty.call(opts.flags, key)) continue;
    _validateFlagSpec(key, opts.flags[key]);
    flags[key] = opts.flags[key];
  }
  return _makeProvider("memory", flags);
}

function localFile(opts) {
  opts = opts || {};
  validateOpts(opts, ["path", "watch"], "flag.providers.localFile");
  validateOpts.requireNonEmptyString(opts.path,
    "providers.localFile: path", FlagError, "flag/bad-provider");
  var raw;
  try { raw = nodeFs.readFileSync(opts.path, "utf8"); }
  catch (e) {
    throw new FlagError("flag/bad-provider",
      "providers.localFile: cannot read file " + JSON.stringify(opts.path) +
      " - " + e.message);
  }
  var parsed;
  try { parsed = safeJson.parse(raw, { maxBytes: C.BYTES.mib(1) }); }
  catch (e) {
    throw new FlagError("flag/bad-provider",
      "providers.localFile: invalid JSON in " + opts.path + " - " + e.message);
  }
  if (!parsed || typeof parsed !== "object" || !parsed.flags) {
    throw new FlagError("flag/bad-provider",
      "providers.localFile: file must export { flags: { flagKey: spec, ... } }");
  }
  for (var key in parsed.flags) {
    if (!Object.prototype.hasOwnProperty.call(parsed.flags, key)) continue;
    _validateFlagSpec(key, parsed.flags[key]);
  }
  var provider = _makeProvider("local-file", parsed.flags);
  provider._path = opts.path;
  if (opts.watch === true) {
    try {
      nodeFs.watch(opts.path, { persistent: false }, function () {
        try {
          var nextRaw = nodeFs.readFileSync(opts.path, "utf8");
          var nextParsed = safeJson.parse(nextRaw, { maxBytes: C.BYTES.mib(1) });
          if (nextParsed && nextParsed.flags) {
            for (var k in nextParsed.flags) {
              if (Object.prototype.hasOwnProperty.call(nextParsed.flags, k)) {
                _validateFlagSpec(k, nextParsed.flags[k]);
              }
            }
            provider._replace(nextParsed.flags);
          }
        } catch (_e) { /* drop-silent on hot-path reload */ }
      });
    } catch (_w) { /* watch unavailable - non-fatal */ }
  }
  return provider;
}

function environmentVariable(opts) {
  opts = opts || {};
  validateOpts(opts, ["prefix", "flags"], "flag.providers.environmentVariable");
  var prefix = (typeof opts.prefix === "string" && opts.prefix.length > 0)
    ? opts.prefix
    : "FLAG_";
  if (!opts.flags || typeof opts.flags !== "object") {
    throw new FlagError("flag/bad-provider",
      "providers.environmentVariable: flags object required to bound the surface");
  }
  var resolved = {};
  for (var key in opts.flags) {
    if (!Object.prototype.hasOwnProperty.call(opts.flags, key)) continue;
    _validateFlagSpec(key, opts.flags[key]);
    var envName = prefix + key.toUpperCase().replace(/[-.]/g, "_");
    var envValue = process.env[envName];
    var clone = Object.assign({}, opts.flags[key]);
    if (typeof envValue === "string" && envValue.length > 0) {
      // Map known env semantics: "true"/"false" override boolean flags
      // by replacing the default variant. Operators wanting richer
      // overrides ship a different provider.
      var variantNames = Object.keys(opts.flags[key].variants);
      if (variantNames.indexOf(envValue) !== -1) {
        clone.default = envValue;
      } else if (envValue === "true" && variantNames.indexOf("on")  !== -1) {
        clone.default = "on";
      } else if (envValue === "false" && variantNames.indexOf("off") !== -1) {
        clone.default = "off";
      }
    }
    resolved[key] = clone;
  }
  return _makeProvider("environment", resolved);
}

function _makeProvider(kind, initialFlags) {
  var flags = initialFlags;
  var provider = {
    kind: kind,
    list: function () { return Object.keys(flags); },
    get:  function (flagKey) { return flags[flagKey] || null; },
    _replace: function (newFlags) { flags = newFlags; },
    evaluate: function (flagKey, ctx) {
      var spec = flags[flagKey];
      if (!spec) {
        return {
          value:    undefined,
          variant:  null,
          reason:   "flag_not_found",
          metadata: { flagKey: flagKey, provider: kind },
        };
      }
      // 1. Targeting rules
      var targetingResult = targeting.evaluateRules(spec.rules || [], ctx, spec.default);
      if (targetingResult.reason === "targeting_match") {
        return _buildResult(flagKey, spec, targetingResult.variant,
                            "targeting_match", { ruleIndex: targetingResult.ruleIndex });
      }
      // 2. Percentage rollout
      if (Array.isArray(spec.rollout) && spec.rollout.length > 0) {
        var tk = (ctx && typeof ctx.targetingKey === "string") ? ctx.targetingKey : "";
        if (tk.length > 0) {
          var bucket = contextMod().bucketOf(tk, flagKey);
          var cumulative = 0;
          for (var i = 0; i < spec.rollout.length; i += 1) {
            cumulative += spec.rollout[i].percentage;
            if (bucket < cumulative) {
              return _buildResult(flagKey, spec, spec.rollout[i].variant,
                                  "split", { bucket: bucket });
            }
          }
        }
      }
      // 3. Default variant
      return _buildResult(flagKey, spec, spec.default, "default", {});
    },
  };
  return provider;
}

function _buildResult(flagKey, spec, variantName, reason, metaAdd) {
  var value = spec.variants[variantName];
  if (value === undefined) {
    // Unknown variant from rollout/rule (validated at registration,
    // so this only fires if a rule passed validation but referenced
    // a since-deleted variant).
    value = spec.variants[spec.default];
    variantName = spec.default;
    reason = "default_fallback";
  }
  var metadata = { flagKey: flagKey, provider: spec._provider || null };
  if (metaAdd) {
    for (var k in metaAdd) {
      if (Object.prototype.hasOwnProperty.call(metaAdd, k)) metadata[k] = metaAdd[k];
    }
  }
  return { value: value, variant: variantName, reason: reason, metadata: metadata };
}

module.exports = {
  memory:               memory,
  localFile:            localFile,
  environmentVariable:  environmentVariable,
  _validateFlagSpec:    _validateFlagSpec,
  FlagError:            FlagError,
};
