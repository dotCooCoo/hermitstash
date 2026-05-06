"use strict";
/**
 * b.flag — feature-flag client per the OpenFeature specification
 * (https://openfeature.dev/specification/).
 *
 *   var flag = b.flag.create({
 *     provider: b.flag.providers.localFile({ path: "./flags.json" }),
 *     defaultEvaluationContext: { environment: "production" },
 *   });
 *
 *   var enabled = flag.getBoolean("new-checkout-flow", { targetingKey: req.user.id });
 *   var sample  = flag.getString ("greeting-banner", { targetingKey: req.user.id }, "default-text");
 *   var rate    = flag.getNumber ("upsell-rate",     { targetingKey: req.user.id }, 0);
 *   var cfg     = flag.getObject ("checkout-config", { targetingKey: req.user.id }, {});
 *
 *   var details = flag.getDetails("new-checkout-flow", ctx);
 *   //  → { value, variant, reason, metadata }
 *
 *   flag.middleware()  → request-time middleware that attaches a
 *                         per-request `flag` accessor onto req.
 *
 * Per the validation-tier policy: create() throws on bad opts; the
 * hot-path getValue / getBoolean / etc. NEVER throw — they return the
 * operator-supplied default + emit `flag.evaluation.error` on the
 * audit chain so the operator sees the problem without taking down
 * the request.
 */

var validateOpts   = require("./validate-opts");
var lazyRequire    = require("./lazy-require");
var providersMod   = require("./flag-providers");
var contextMod     = require("./flag-evaluation-context");
var targeting      = require("./flag-targeting");
var cacheMod       = require("./flag-cache");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

function _validateHooks(rawHooks) {
  var out = { before: [], after: [], error: [], finally: [] };
  if (rawHooks == null) return out;
  if (typeof rawHooks !== "object") {
    throw new FlagError("flag/bad-hooks",
      "create: hooks must be an object { before, after, error, finally }");
  }
  var stages = ["before", "after", "error", "finally"];
  for (var i = 0; i < stages.length; i += 1) {
    var stage = stages[i];
    if (rawHooks[stage] == null) continue;
    var arr = Array.isArray(rawHooks[stage]) ? rawHooks[stage] : [rawHooks[stage]];
    for (var j = 0; j < arr.length; j += 1) {
      if (typeof arr[j] !== "function") {
        throw new FlagError("flag/bad-hooks",
          "create: hooks." + stage + "[" + j + "] must be a function");
      }
    }
    out[stage] = arr.slice();
  }
  return out;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "provider", "providers", "defaultEvaluationContext",
    "audit", "errorHandler", "hooks",
  ], "flag.create");
  var providers = [];
  if (opts.provider) {
    if (typeof opts.provider.evaluate !== "function") {
      throw new FlagError("flag/bad-provider",
        "create: provider must implement .evaluate(flagKey, ctx)");
    }
    providers.push(opts.provider);
  }
  if (Array.isArray(opts.providers)) {
    for (var i = 0; i < opts.providers.length; i += 1) {
      if (typeof opts.providers[i].evaluate !== "function") {
        throw new FlagError("flag/bad-provider",
          "create: providers[" + i + "] must implement .evaluate()");
      }
      providers.push(opts.providers[i]);
    }
  }
  if (providers.length === 0) {
    throw new FlagError("flag/no-provider",
      "create: at least one provider is required - pass `provider` or `providers`");
  }
  var defaultCtx = contextMod.create(opts.defaultEvaluationContext || {});
  var auditOn    = opts.audit !== false;
  var errorHandler = (typeof opts.errorHandler === "function")
    ? opts.errorHandler : null;
  var hooks = _validateHooks(opts.hooks);

  function _emitErrorAudit(flagKey, err, ctx) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "flag.evaluation.error",
        outcome:  "fail",
        actor:    { targetingKey: ctx && ctx.targetingKey || null },
        metadata: {
          flagKey: flagKey,
          message: err && err.message || String(err),
          code:    err && err.code || "flag/unknown",
        },
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _runHook(stage, info) {
    var arr = hooks[stage];
    if (!arr || arr.length === 0) return;
    for (var i = 0; i < arr.length; i += 1) {
      try { arr[i](info); } catch (_e) { /* drop-silent — hooks are observability, not blocking */ }
    }
  }

  function _evaluate(flagKey, ctx) {
    var mergedCtx = contextMod.merge(defaultCtx, ctx || {});
    var startMs = Date.now();
    _runHook("before", { flagKey: flagKey, ctx: mergedCtx });
    for (var i = 0; i < providers.length; i += 1) {
      try {
        var result = providers[i].evaluate(flagKey, mergedCtx);
        if (result && result.reason !== "flag_not_found") {
          if (auditOn) {
            try {
              audit().safeEmit({
                action:   "flag.evaluated",
                outcome:  "success",
                actor:    { targetingKey: mergedCtx.targetingKey || null },
                metadata: {
                  flagKey:  flagKey,
                  variant:  result.variant,
                  reason:   result.reason,
                  provider: providers[i].kind || null,
                },
              });
            } catch (_e) { /* drop-silent */ }
          }
          _runHook("after", { flagKey: flagKey, ctx: mergedCtx, result: result, elapsedMs: Date.now() - startMs });
          _runHook("finally", { flagKey: flagKey, ctx: mergedCtx, result: result });
          return result;
        }
      } catch (err) {
        _emitErrorAudit(flagKey, err, mergedCtx);
        _runHook("error", { flagKey: flagKey, ctx: mergedCtx, err: err });
        if (errorHandler) {
          try { errorHandler({ flagKey: flagKey, err: err, ctx: mergedCtx }); }
          catch (_e2) { /* drop-silent */ }
        }
      }
    }
    var notFound = {
      value:    undefined,
      variant:  null,
      reason:   "flag_not_found",
      metadata: { flagKey: flagKey, providers: providers.map(function (p) { return p.kind; }) },
    };
    _runHook("after", { flagKey: flagKey, ctx: mergedCtx, result: notFound, elapsedMs: Date.now() - startMs });
    _runHook("finally", { flagKey: flagKey, ctx: mergedCtx, result: notFound });
    return notFound;
  }

  function _coerceBoolean(v) {
    if (v === true || v === false) return v;
    if (v === "true")  return true;
    if (v === "false") return false;
    if (v === 1) return true;
    if (v === 0) return false;
    return null;
  }

  return {
    getValue: function (flagKey, ctx, defaultValue) {
      var r = _evaluate(flagKey, ctx);
      if (r.value === undefined) return defaultValue;
      return r.value;
    },
    getDetails: function (flagKey, ctx) {
      return _evaluate(flagKey, ctx);
    },
    getBoolean: function (flagKey, ctx, defaultValue) {
      var r = _evaluate(flagKey, ctx);
      if (r.value === undefined) return defaultValue === true;
      var coerced = _coerceBoolean(r.value);
      return coerced != null ? coerced : (defaultValue === true);
    },
    getString: function (flagKey, ctx, defaultValue) {
      var r = _evaluate(flagKey, ctx);
      if (typeof r.value === "string") return r.value;
      return (typeof defaultValue === "string") ? defaultValue : "";
    },
    getNumber: function (flagKey, ctx, defaultValue) {
      var r = _evaluate(flagKey, ctx);
      if (typeof r.value === "number" && isFinite(r.value)) return r.value;
      return (typeof defaultValue === "number") ? defaultValue : 0;
    },
    getObject: function (flagKey, ctx, defaultValue) {
      var r = _evaluate(flagKey, ctx);
      if (r.value && typeof r.value === "object") return r.value;
      return defaultValue == null ? {} : defaultValue;
    },
    list: function () {
      var keys = Object.create(null);
      for (var i = 0; i < providers.length; i += 1) {
        if (typeof providers[i].list === "function") {
          var arr = providers[i].list();
          for (var j = 0; j < arr.length; j += 1) keys[arr[j]] = true;
        }
      }
      return Object.keys(keys);
    },
    providers: providers.slice(),
    defaultEvaluationContext: defaultCtx,
    getValues: function (flagKeys, ctx) {
      var out = {};
      if (!Array.isArray(flagKeys)) return out;
      for (var i = 0; i < flagKeys.length; i += 1) {
        var k = flagKeys[i];
        if (typeof k !== "string") continue;
        var r = _evaluate(k, ctx);
        out[k] = r.value;
      }
      return out;
    },
    getDetailsAll: function (flagKeys, ctx) {
      var out = {};
      if (!Array.isArray(flagKeys)) return out;
      for (var i = 0; i < flagKeys.length; i += 1) {
        var k = flagKeys[i];
        if (typeof k !== "string") continue;
        out[k] = _evaluate(k, ctx);
      }
      return out;
    },
    addProvider: function (next) {
      if (!next || typeof next.evaluate !== "function") {
        throw new FlagError("flag/bad-provider",
          "addProvider: provider must implement .evaluate()");
      }
      providers.push(next);
      return providers.length;
    },
    removeProvider: function (target) {
      var before = providers.length;
      for (var i = providers.length - 1; i >= 0; i -= 1) {
        if (providers[i] === target) providers.splice(i, 1);
      }
      return before - providers.length;
    },
    middleware: function (mwOpts) {
      mwOpts = mwOpts || {};
      validateOpts(mwOpts, ["userKey"], "flag.middleware");
      var self = this;
      return function flagMiddleware(req, res, next) {
        var reqCtx = contextMod.fromRequest(req, {
          userKey: mwOpts.userKey,
        });
        req.flag = {
          getBoolean: function (k, def)         { return self.getBoolean(k, reqCtx, def); },
          getString:  function (k, def)         { return self.getString (k, reqCtx, def); },
          getNumber:  function (k, def)         { return self.getNumber (k, reqCtx, def); },
          getObject:  function (k, def)         { return self.getObject (k, reqCtx, def); },
          getValue:   function (k, def)         { return self.getValue  (k, reqCtx, def); },
          getDetails: function (k)              { return self.getDetails(k, reqCtx); },
          ctx:        reqCtx,
        };
        return next();
      };
    },
  };
}

module.exports = {
  create:           create,
  providers:        providersMod,
  context:          contextMod,
  targeting:        targeting,
  cache:            cacheMod.cache,
  FlagError:        FlagError,
};
