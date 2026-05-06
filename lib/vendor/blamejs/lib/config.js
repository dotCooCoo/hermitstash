"use strict";
/**
 * config — schema-validated environment configuration.
 *
 * Operators read process.env throughout their app code. A typo in the
 * key name OR a value in the wrong shape (port="abc", flag="yas")
 * surfaces three days later as a mysterious 500. This primitive validates
 * env at boot via b.safeSchema so the app refuses to start with broken
 * config.
 *
 *   var config = b.config.create({
 *     schema: b.safeSchema.object({
 *       NODE_ENV:        b.safeSchema.enum_(["development", "test", "production"]),
 *       PORT:            b.config.coerce.number().default(3000),
 *       LOG_LEVEL:       b.safeSchema.enum_(["debug", "info", "warn", "error"]).default("info"),
 *       SESSION_SECRET:  b.safeSchema.string().min(32),
 *       DATABASE_URL:    b.safeSchema.string().url(),
 *       REDIS_URL:       b.safeSchema.string().url().optional(),
 *       FEATURE_X:       b.config.coerce.boolean().default(false),
 *     }),
 *     // env: process.env (default) — operators in tests pass a fake object
 *     // redactKeys: ["SESSION_SECRET", "DATABASE_URL"] — never log these
 *   });
 *
 *   config.value          → the validated, typed value object
 *   config.value.PORT     → 3000 (Number, not "3000")
 *   config.boot()         → throws ConfigError on validation failure;
 *                           returns the validated value otherwise
 *
 * The factory immediately runs validation — the throw at create() time
 * is intentional. Operators want config errors at app boot, not at
 * the first request that touches the broken value.
 */
var safeSchema = require("./safe-schema");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var REDACT_MASK = "[REDACTED]";

var ConfigError = defineClass("ConfigError", { alwaysPermanent: true });

// Coercion shapes most operators want for env values: number, integer,
// boolean — env is always a string at the source so coerce. Operators
// who want stricter parsing chain .refine() or use raw schemas.
var coerce = {
  number: function () {
    return safeSchema.preprocess(function (v) {
      if (v === undefined || v === null || v === "") return v;
      var n = Number(v);
      return isNaN(n) ? v : n;
    }, safeSchema.number());
  },
  boolean: function () {
    return safeSchema.preprocess(function (v) {
      if (typeof v === "boolean") return v;
      if (v === "1" || v === "true"  || v === "yes") return true;
      if (v === "0" || v === "false" || v === "no")  return false;
      return v;  // pass through — schema rejects non-boolean
    }, safeSchema.boolean());
  },
};

function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new ConfigError("config/bad-opts",
      "create: opts is required (must include opts.schema)");
  }
  validateOpts(opts, ["schema", "env", "redactKeys"], "config.create");
  if (!opts.schema || typeof opts.schema.parse !== "function") {
    throw new ConfigError("config/bad-schema",
      "create: opts.schema must be a b.safeSchema instance (built via b.safeSchema.object({...}))");
  }
  var env = opts.env || process.env;
  if (env !== process.env && (typeof env !== "object" || env === null)) {
    throw new ConfigError("config/bad-env",
      "create: opts.env must be an object (default process.env)");
  }
  var redactKeys = Array.isArray(opts.redactKeys) ? opts.redactKeys.slice() : [];
  for (var i = 0; i < redactKeys.length; i++) {
    if (typeof redactKeys[i] !== "string" || redactKeys[i].length === 0) {
      throw new ConfigError("config/bad-redact-keys",
        "create: redactKeys[" + i + "] must be a non-empty string");
    }
  }
  // Filter env to a plain object — process.env's prototype chain
  // includes inherited Object.prototype keys we don't want to validate.
  var input = {};
  for (var k in env) {
    if (Object.prototype.hasOwnProperty.call(env, k)) input[k] = env[k];
  }

  var result = opts.schema.safeParse(input);
  if (!result.ok) {
    var msg = "config validation failed:\n";
    for (var ei = 0; ei < result.errors.length; ei++) {
      var err = result.errors[ei];
      msg += "  - " + err.path.join(".") + ": " + err.message + "\n";
    }
    throw new ConfigError("config/validation-failed", msg);
  }

  var value = result.value;

  function redactedView() {
    // For logging the validated config without leaking secrets — useful
    // at boot ("loaded config: { NODE_ENV: 'production', PORT: 3000, ... }").
    var out = {};
    for (var k in value) {
      if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
      out[k] = redactKeys.indexOf(k) !== -1 ? REDACT_MASK : value[k];
    }
    return out;
  }

  return {
    value:    value,
    get:      function (key) { return value[key]; },
    has:      function (key) { return Object.prototype.hasOwnProperty.call(value, key); },
    redacted: redactedView,
  };
}

module.exports = {
  create:      create,
  ConfigError: ConfigError,
  coerce:      coerce,
};
