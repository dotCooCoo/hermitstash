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

var audit = lazyRequire(function () { return require("./audit"); });

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

  // `.value` is a getter, not a captured property. Without this,
  // `cfg.value.X` reads from the object that was current at create()
  // and never reflects subsequent reload() updates — operators looking
  // at `cfg.value.FEATURE_X` would see stale values forever, while
  // `cfg.get("FEATURE_X")` saw fresh ones. The @primitive docs
  // (loadDbBacked example) promise `cfg.value.X` always works, so the
  // getter is the contract.
  var handle = {
    get:       function (key) { return value[key]; },
    has:       function (key) { return Object.prototype.hasOwnProperty.call(value, key); },
    redacted:  redactedView,
    subscribe: subscribe,
    reload:    reload,
  };
  Object.defineProperty(handle, "value", {
    get: function () { return value; },
    enumerable: true,
  });
  return handle;
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
 * last-good config.
 *
 * Returns immediately with a synchronous handle, but kicks off one
 * immediate hydration tick on construction so the first DB read
 * happens at t=0 rather than t=intervalMs. Callers that need to wait
 * for first-data-applied can `await handle.hydrated` before the app
 * starts serving traffic; the Promise resolves after the first tick
 * settles (success OR audit-on-failure path) and never rejects, so
 * the boot path never deadlocks on a temporarily-unreachable DB.
 *
 * The returned handle is the same shape as `create()` plus:
 *   - `.hydrated` — Promise<void> for the first tick
 *   - `.refresh()`— run one tick on demand (save-triggered reload);
 *                   returns Promise<void> that never rejects
 *   - `.stop()`   — halts the poller
 *
 * Three tiers of precedence (highest wins): the DB-row overlay
 * resolved at each `_tick` > the `opts.env` baseline > defaults
 * declared on the schema (`s.string().default(...)` and friends).
 * The `.subscribe(fn)` callback registered through `create()` fires
 * synchronously inside every successful reload — operators reach for
 * it to invalidate caches, recompute derived state, or hot-rebuild
 * middleware that closed over the previous config value.
 *
 * @opts
 *   schema:         b.safeSchema instance (required),
 *   env:            object  (env baseline; default process.env),
 *   redactKeys:     Array<string>,
 *   fetchRows:      async () => Array<{ key: string, value: string }>  (required),
 *   intervalMs:     number   (positive finite poll interval),
 *   transformValue: (row) => string | Promise<string>   (optional per-row
 *                   transform — receives `{ key, value, ...rest }` so the
 *                   row can carry envelope metadata; returns the value
 *                   that flows into the schema. Common shape: unseal a
 *                   `b.vault`-sealed ciphertext column before validation.
 *                   Rows whose transform throws or returns a non-string
 *                   are skipped with a `config.reload.failed` audit so a
 *                   single bad row never crashes the poller),
 *   audit:          boolean  (default true; reserved for future per-poll audit),
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
 *
 * @example
 *   // Sealed values — column stores `b.vault.seal(plain)` ciphertext.
 *   var cfg = b.config.loadDbBacked({
 *     schema:     s.object({ STRIPE_SECRET: s.string() }),
 *     fetchRows:  async function () {
 *       return await db.all("SELECT key, sealed FROM _config WHERE sealed IS NOT NULL");
 *     },
 *     transformValue: function (row) {
 *       return b.vault.unseal(row.sealed).toString("utf8");
 *     },
 *     intervalMs: 30 * 1000,
 *   });
 *
 * @example
 *   // Save-triggered reload — admin UI writes a row, fires refresh()
 *   // so the new value is active immediately without waiting for
 *   // intervalMs. cfg.subscribe(...) sees the change inline.
 *   var cfg = b.config.loadDbBacked({
 *     schema:     s.object({ FEATURE_X: b.config.coerce.boolean().default(false) }),
 *     fetchRows:  async function () { return await db.all("SELECT key, value FROM _config"); },
 *     intervalMs: 5 * 60 * 1000,                  // safety-net interval
 *   });
 *   await cfg.hydrated;                            // boot path waits
 *   cfg.subscribe(function (next) { cache.invalidate(); });
 *
 *   adminApp.post("/settings", async function (req, res) {
 *     await db.run("INSERT OR REPLACE INTO _config(key,value) VALUES (?,?)",
 *                  req.body.key, req.body.value);
 *     await cfg.refresh();                         // active immediately
 *     res.json({ ok: true });
 *   });
 */
function loadDbBacked(opts) {
  opts = opts || {};
  validateOpts(opts, ["schema", "env", "redactKeys", "fetchRows", "intervalMs", "transformValue", "audit"],
    "config.loadDbBacked");
  if (typeof opts.fetchRows !== "function") {
    throw new ConfigError("config/bad-fetch-rows",
      "loadDbBacked: opts.fetchRows must be a function returning [{key,value}]");
  }
  if (typeof opts.intervalMs !== "number" || !isFinite(opts.intervalMs) || opts.intervalMs <= 0) {
    throw new ConfigError("config/bad-interval",
      "loadDbBacked: opts.intervalMs must be a positive finite number");
  }
  var transformValue = validateOpts.optionalFunction(
    opts.transformValue, "loadDbBacked: opts.transformValue",
    ConfigError, "config/bad-transform-value") || null;
  var cfg = create({ schema: opts.schema, env: opts.env, redactKeys: opts.redactKeys });
  var stopped = false;
  // Concurrency guard. _tick() runs `await opts.fetchRows()` + per-row
  // `await transformValue(row)`, so multiple ticks (poll firing while
  // refresh() is in-flight, or two refresh()es back-to-back) can
  // overlap. Without coordination, whichever tick FINISHES last applies
  // its overlay last — and "finishes last" is not "started last" when
  // fetchRows latency varies. The result: an admin save followed by
  // await refresh() can be silently rolled back by an older in-flight
  // tick whose fetchRows started before the save.
  //
  // Fix: every tick claims a monotonic seq at start. At apply time, if
  // a newer tick has already applied (ticksAppliedMax >= my seq), drop
  // — its data is more recent than mine. The seq check + reload are
  // both synchronous (no awaits between them) so the check-and-apply
  // is atomic on Node's single thread. fetch / transform failures do
  // NOT advance ticksAppliedMax: they short-circuit before the apply
  // path, leaving newer ticks free to apply later.
  var ticksStarted = 0;
  var ticksAppliedMax = -1;
  async function _tick() {
    if (stopped) return;
    var mySeq = ++ticksStarted;
    var rows;
    try { rows = await opts.fetchRows(); }
    catch (e) {
      try {
        audit().safeEmit({
          action: "config.reload.failed", outcome: "failure",
          metadata: { phase: "fetch", reason: e && e.message },
        });
      } catch (_e) { /* audit best-effort */ }
      return;
    }
    if (!Array.isArray(rows)) return;
    var overlay = {};
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || typeof row.key !== "string") continue;
      var value = row.value;
      if (transformValue) {
        try {
          value = await transformValue(row);
        } catch (e) {
          try {
            audit().safeEmit({
              action: "config.reload.failed", outcome: "failure",
              metadata: { phase: "transform", key: row.key, reason: e && e.message },
            });
          } catch (_e) { /* audit best-effort */ }
          continue;
        }
        if (typeof value !== "string") {
          try {
            audit().safeEmit({
              action: "config.reload.failed", outcome: "failure",
              metadata: { phase: "transform", key: row.key, reason: "transformValue did not return a string" },
            });
          } catch (_e) { /* audit best-effort */ }
          continue;
        }
      }
      overlay[row.key] = value;
    }
    // Drop-stale: a tick that started after me has already finished and
    // applied its newer fetch — my overlay would clobber fresher data.
    if (mySeq <= ticksAppliedMax) {
      try {
        audit().safeEmit({
          action: "config.reload.skipped", outcome: "success",
          metadata: { phase: "stale-tick", mySeq: mySeq, appliedMax: ticksAppliedMax },
        });
      } catch (_e) { /* audit best-effort */ }
      return;
    }
    // Advance the watermark ONLY after a successful reload. A newer
    // tick whose validation fails must not suppress an older in-flight
    // tick that still has valid data — otherwise refresh(valid)
    // followed by refresh(invalid) could silently keep the previous
    // config active even though the valid update is about to land.
    try {
      cfg.reload(overlay);
      ticksAppliedMax = mySeq;
    }
    catch (e) {
      try {
        audit().safeEmit({
          action: "config.reload.failed", outcome: "failure",
          metadata: { phase: "validate", reason: e && e.message },
        });
      } catch (_e) { /* audit best-effort */ }
    }
  }
  // Fire one immediate hydration before the interval kicks in so
  // callers can `await cfg.hydrated` and not get an empty config window
  // (env defaults only) for the first intervalMs of process lifetime.
  // The interval still fires every intervalMs afterwards for ongoing
  // drift detection. The hydration Promise NEVER rejects — _tick
  // swallows fetch / transform / validate failures via audit, matching
  // the established "last-good config stays in place" contract.
  cfg.hydrated = _tick();
  var handle = safeAsync.repeating(_tick, opts.intervalMs, { name: "config-db-reload" });
  // Save-triggered reload — admin save handlers / settings-management
  // UIs invoke cfg.refresh() right after writing a row to drop the
  // intervalMs-worth of staleness latency between save and active.
  // Returns the same Promise<void> shape as cfg.hydrated: resolves
  // after the tick settles (success OR audit-on-failure), never
  // rejects so the save handler never deadlocks on a flaky DB.
  // Subscribers fire synchronously inside cfg.reload() within the
  // tick, matching the save-then-invalidate-cache pattern operators
  // expect when an admin flips a feature flag.
  cfg.refresh = function () { return _tick(); };
  cfg.stop = function () { stopped = true; if (handle) { handle.stop(); handle = null; } };
  return cfg;
}

module.exports = {
  create:        create,
  loadDbBacked:  loadDbBacked,
  ConfigError:   ConfigError,
  coerce:        coerce,
};
