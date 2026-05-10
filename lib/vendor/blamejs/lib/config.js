"use strict";
/**
 * @module b.config
 * @nav    Tools
 * @title  Config
 *
 * @intro
 *   Schema-validated environment configuration. Operators read
 *   `process.env` throughout their app; a typo in the key name OR a
 *   value in the wrong shape (`port="abc"`, `flag="yas"`) surfaces
 *   three days later as a mysterious 500. `b.config.create` validates
 *   env at boot through `b.safeSchema` so the app refuses to start
 *   with broken config — the throw happens at `create()` time, not
 *   at the first request that touches the broken value.
 *
 *   `b.config.coerce.number()` and `b.config.coerce.boolean()` wrap
 *   schema leaves with the env-friendly preprocessors most operators
 *   want (env values are always strings at the source). `loadDbBacked`
 *   composes `create` with periodic DB-row polling so a row update in
 *   `_blamejs_config_overrides` surfaces without restart, and falls
 *   back to the last-good value on validation failure.
 *
 * @card
 *   Schema-validated environment configuration.
 */
var safeSchema = require("./safe-schema");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var lazyAudit = lazyRequire(function () { return require("./audit"); });

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

/**
 * @primitive b.config.create
 * @signature b.config.create(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.config.loadDbBacked, b.safeSchema.object
 *
 * Validate env against a `b.safeSchema` shape and return a frozen
 * config handle (`value` / `get` / `has` / `redacted` / `subscribe` /
 * `reload`). Throws `ConfigError` synchronously when validation fails
 * — the operator sees broken config at boot rather than at the first
 * request that touches the value. The handle's `reload(overlay)`
 * applies a new env-shaped overlay on top of the validated baseline,
 * notifies subscribers on success, and falls back to the prior value
 * on failure.
 *
 * @opts
 *   schema:      b.safeSchema instance (required; built via b.safeSchema.object({...})),
 *   env:         object  (env bag; default process.env),
 *   redactKeys:  Array<string>  (keys masked by `.redacted()` for log output),
 *
 * @example
 *   var s = b.safeSchema;
 *   var cfg = b.config.create({
 *     schema: s.object({
 *       NODE_ENV: s.enum_(["development", "test", "production"]),
 *       PORT:     b.config.coerce.number().default(3000),
 *     }),
 *     env: { NODE_ENV: "production", PORT: "8080" },
 *     redactKeys: [],
 *   });
 *   cfg.value.NODE_ENV;     // → "production"
 *   cfg.value.PORT;         // → 8080  (Number, not "8080")
 *   cfg.has("PORT");        // → true
 */
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

  // Hot-reload subscribers — operators wire updateOnReload(newValue)
  // into module-cached config-derived state so a row update in
  // _blamejs_config_overrides surfaces without restart.
  var subscribers = [];
  function subscribe(fn) {
    if (typeof fn !== "function") {
      throw new ConfigError("config/bad-subscriber",
        "config.subscribe: fn must be a function");
    }
    subscribers.push(fn);
    return function unsubscribe() {
      var ix = subscribers.indexOf(fn);
      if (ix !== -1) subscribers.splice(ix, 1);
    };
  }

  // Apply a new env-shaped overlay (e.g., from a DB row) on top of
  // the validated baseline. Refuses on validation failure, falls
  // back to prior `value`. Notifies subscribers AFTER the swap on
  // any successful overlay application.
  function reload(overlay) {
    if (!overlay || typeof overlay !== "object") {
      throw new ConfigError("config/bad-overlay",
        "config.reload(overlay): overlay must be an object");
    }
    var merged = Object.assign({}, input, overlay);
    var result2 = opts.schema.safeParse(merged);
    if (!result2.ok) {
      var msg = "config.reload validation failed:\n";
      for (var ei2 = 0; ei2 < result2.errors.length; ei2++) {
        var err2 = result2.errors[ei2];
        msg += "  - " + err2.path.join(".") + ": " + err2.message + "\n";
      }
      throw new ConfigError("config/reload-validation-failed", msg);
    }
    value = result2.value;
    for (var si = 0; si < subscribers.length; si++) {
      try { subscribers[si](value); } catch (_e) { /* operator hook */ }
    }
    return value;
  }

  return {
    value:     value,
    get:       function (key) { return value[key]; },
    has:       function (key) { return Object.prototype.hasOwnProperty.call(value, key); },
    redacted:  redactedView,
    subscribe: subscribe,
    reload:    reload,
  };
}

/**
 * @primitive b.config.loadDbBacked
 * @signature b.config.loadDbBacked(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.config.create, b.safeAsync.repeating
 *
 * Compose `b.config.create` with a periodic DB-row fetch. Operators
 * keep canonical config values in
 * `_blamejs_config_overrides(key TEXT PRIMARY KEY, value TEXT)`; this
 * helper polls every `intervalMs`, applies the rows as an overlay
 * via the underlying handle's `reload`, and re-validates. Reload
 * failures emit a `config.reload.failed` audit row but DO NOT
 * clobber the previous value — the running app stays on the
 * last-good config. The returned handle is the same shape as
 * `create()` plus a `.stop()` method that halts the poller.
 *
 * @opts
 *   schema:      b.safeSchema instance (required),
 *   env:         object  (env baseline; default process.env),
 *   redactKeys:  Array<string>,
 *   fetchRows:   async () => Array<{ key: string, value: string }>  (required),
 *   intervalMs:  number   (positive finite poll interval),
 *   audit:       boolean  (default true; reserved for future per-poll audit),
 *
 * @example
 *   var s = b.safeSchema;
 *   var cfg = b.config.loadDbBacked({
 *     schema: s.object({
 *       FEATURE_X: b.config.coerce.boolean().default(false),
 *     }),
 *     env:        { FEATURE_X: "false" },
 *     fetchRows:  async function () {
 *       return [{ key: "FEATURE_X", value: "true" }];
 *     },
 *     intervalMs: 60 * 1000,
 *   });
 *   cfg.value.FEATURE_X;    // → false  (until first poll tick lands)
 *   cfg.stop();             // halt the poller on shutdown
 */
function loadDbBacked(opts) {
  opts = opts || {};
  validateOpts(opts, ["schema", "env", "redactKeys", "fetchRows", "intervalMs", "audit"],
    "config.loadDbBacked");
  if (typeof opts.fetchRows !== "function") {
    throw new ConfigError("config/bad-fetch-rows",
      "loadDbBacked: opts.fetchRows must be a function returning [{key,value}]");
  }
  if (typeof opts.intervalMs !== "number" || !isFinite(opts.intervalMs) || opts.intervalMs <= 0) {
    throw new ConfigError("config/bad-interval",
      "loadDbBacked: opts.intervalMs must be a positive finite number");
  }
  var cfg = create({ schema: opts.schema, env: opts.env, redactKeys: opts.redactKeys });
  var stopped = false;
  async function _tick() {
    if (stopped) return;
    var rows;
    try { rows = await opts.fetchRows(); }
    catch (e) {
      try {
        lazyAudit().safeEmit({
          action: "config.reload.failed", outcome: "failure",
          metadata: { phase: "fetch", reason: e && e.message },
        });
      } catch (_e) { /* audit best-effort */ }
      return;
    }
    if (!Array.isArray(rows)) return;
    var overlay = {};
    for (var i = 0; i < rows.length; i++) {
      if (rows[i] && typeof rows[i].key === "string") {
        overlay[rows[i].key] = rows[i].value;
      }
    }
    try { cfg.reload(overlay); }
    catch (e) {
      try {
        lazyAudit().safeEmit({
          action: "config.reload.failed", outcome: "failure",
          metadata: { phase: "validate", reason: e && e.message },
        });
      } catch (_e) { /* audit best-effort */ }
    }
  }
  var handle = safeAsync.repeating(_tick, opts.intervalMs, { name: "config-db-reload" });
  cfg.stop = function () { stopped = true; if (handle) { handle.stop(); handle = null; } };
  return cfg;
}

module.exports = {
  create:        create,
  loadDbBacked:  loadDbBacked,
  ConfigError:   ConfigError,
  coerce:        coerce,
};
