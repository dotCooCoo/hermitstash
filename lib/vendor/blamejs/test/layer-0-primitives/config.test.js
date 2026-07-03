// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.config — schema-validated environment configuration.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var s     = b.safeSchema;

async function run() {
  // ---- Surface ----
  check("b.config namespace present",        typeof b.config === "object");
  check("b.config.create is fn",             typeof b.config.create === "function");
  check("b.config.coerce.number is fn",      typeof b.config.coerce.number === "function");
  check("b.config.coerce.boolean is fn",     typeof b.config.coerce.boolean === "function");
  check("b.config.ConfigError is class",     typeof b.config.ConfigError === "function");

  // ---- Happy path ----
  var schema = s.object({
    NODE_ENV:        s.enum_(["development", "test", "production"]),
    PORT:            b.config.coerce.number(),
    LOG_LEVEL:       s.enum_(["debug", "info", "warn", "error"]).default("info"),
    SESSION_SECRET:  s.string().min(8),
    FEATURE_X:       b.config.coerce.boolean().default(false),
  });

  var c1 = b.config.create({
    schema: schema,
    env: {
      NODE_ENV:       "production",
      PORT:           "3000",
      SESSION_SECRET: "super-long-secret-value",
      FEATURE_X:      "true",
    },
  });
  check("create: returns a config instance",   typeof c1 === "object");
  check("create: value is the validated obj",  c1.value && typeof c1.value === "object");
  check("create: NODE_ENV preserved",          c1.value.NODE_ENV === "production");
  check("create: PORT coerced to number",      c1.value.PORT === 3000);
  check("create: LOG_LEVEL applied default",   c1.value.LOG_LEVEL === "info");
  check("create: SESSION_SECRET preserved",    c1.value.SESSION_SECRET === "super-long-secret-value");
  check("create: FEATURE_X coerced to true",   c1.value.FEATURE_X === true);
  check("create: c.get accessor",              c1.get("PORT") === 3000);
  check("create: c.has true for known",        c1.has("PORT") === true);
  check("create: c.has false for unknown",     c1.has("NOPE") === false);

  // Boolean coercion variants
  var bools = b.config.create({
    schema: s.object({
      A: b.config.coerce.boolean(),
      B: b.config.coerce.boolean(),
      C: b.config.coerce.boolean(),
      D: b.config.coerce.boolean(),
    }),
    env: { A: "1", B: "yes", C: "0", D: "false" },
  });
  check("coerce.boolean: '1' → true",      bools.value.A === true);
  check("coerce.boolean: 'yes' → true",    bools.value.B === true);
  check("coerce.boolean: '0' → false",     bools.value.C === false);
  check("coerce.boolean: 'false' → false", bools.value.D === false);

  // ---- redacted view ----
  var c2 = b.config.create({
    schema: s.object({
      PUBLIC: s.string(),
      SECRET: s.string(),
    }),
    env: { PUBLIC: "ok", SECRET: "hunter2" },
    redactKeys: ["SECRET"],
  });
  var redacted = c2.redacted();
  check("redacted: public values intact",   redacted.PUBLIC === "ok");
  check("redacted: secret masked",          redacted.SECRET === "[REDACTED]");
  check("redacted: original value intact",  c2.value.SECRET === "hunter2");

  // ---- validation failure throws at create() ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("validate: " + label,  threw && codeRe.test(threw.code || ""));
  }

  rejects("missing required key",
    function () {
      b.config.create({
        schema: s.object({ REQUIRED: s.string() }),
        env: {},
      });
    },
    /config\/validation-failed/);

  rejects("wrong shape",
    function () {
      b.config.create({
        schema: s.object({ PORT: b.config.coerce.number() }),
        env: { PORT: "not-a-number" },
      });
    },
    /config\/validation-failed/);

  rejects("enum value not in list",
    function () {
      b.config.create({
        schema: s.object({ NODE_ENV: s.enum_(["development", "production"]) }),
        env: { NODE_ENV: "staging" },
      });
    },
    /config\/validation-failed/);

  // ---- create() rejects bad opts ----
  rejects("opts missing",
    function () { b.config.create(); },
    /config\/bad-opts/);

  rejects("schema not provided",
    function () { b.config.create({}); },
    /config\/bad-schema/);

  rejects("schema not a safeSchema",
    function () { b.config.create({ schema: { wrong: "shape" } }); },
    /config\/bad-schema/);

  rejects("redactKeys with empty string",
    function () {
      b.config.create({
        schema: s.object({ X: s.string() }),
        env: { X: "v" },
        redactKeys: [""],
      });
    },
    /config\/bad-redact-keys/);
}

async function _testLoadDbBacked() {
  var threw;
  try {
    b.config.loadDbBacked({
      schema: { safeParse: function () { return { ok: true, value: {} }; }, parse: function () { return {}; } },
      fetchRows: "not-a-function",
      intervalMs: 1000,
    });
  } catch (e) { threw = e; }
  helpers.check("config.loadDbBacked: fetchRows must be a function",
    threw && threw.code === "config/bad-fetch-rows");

  var threw2;
  try {
    b.config.loadDbBacked({
      schema: { safeParse: function () { return { ok: true, value: {} }; }, parse: function () { return {}; } },
      fetchRows: function () { return []; },
      intervalMs: -1,
    });
  } catch (e) { threw2 = e; }
  helpers.check("config.loadDbBacked: intervalMs must be positive finite",
    threw2 && threw2.code === "config/bad-interval");

  var threw3;
  try {
    b.config.loadDbBacked({
      schema:         { safeParse: function () { return { ok: true, value: {} }; }, parse: function () { return {}; } },
      fetchRows:      function () { return []; },
      intervalMs:     1000,
      transformValue: "not-a-function",
    });
  } catch (e) { threw3 = e; }
  helpers.check("config.loadDbBacked: transformValue must be a function",
    threw3 && threw3.code === "config/bad-transform-value");
}

async function _testLoadDbBackedTransformValue() {
  // Per-row transform — common shape is sealed-value unseal. We use a
  // simple `sealed:<plain>` transform so the test stays vendor-free.
  var s = b.safeSchema;
  var rows = [
    { key: "STRIPE_SECRET", sealed: "sealed:sk_live_AAA" },
    { key: "JWT_KEY",       sealed: "sealed:jwt_BBB" },
    { key: "BAD_KEY",       sealed: "missing-prefix" },     // transform throws → row skipped
  ];
  var transformCalls = 0;
  var cfg = b.config.loadDbBacked({
    schema:         s.object({
      STRIPE_SECRET: s.string().default("env-fallback-stripe"),
      JWT_KEY:       s.string().default("env-fallback-jwt"),
      BAD_KEY:       s.string().default("env-fallback-bad"),
    }),
    env:            {},
    fetchRows:      function () { return rows; },
    intervalMs:     50,
    transformValue: function (row) {
      transformCalls += 1;
      if (typeof row.sealed !== "string" || row.sealed.indexOf("sealed:") !== 0) {
        throw new Error("bad seal prefix");
      }
      return row.sealed.slice("sealed:".length);
    },
  });
  await cfg.hydrated;
  helpers.check("loadDbBacked: transformValue ran per row",
    transformCalls >= 3);
  helpers.check("loadDbBacked: transformValue unseals STRIPE_SECRET",
    cfg.value.STRIPE_SECRET === "sk_live_AAA");
  helpers.check("loadDbBacked: transformValue unseals JWT_KEY",
    cfg.value.JWT_KEY === "jwt_BBB");
  helpers.check("loadDbBacked: transformValue failure falls back to env default",
    cfg.value.BAD_KEY === "env-fallback-bad");
  cfg.stop();
}

async function _testLoadDbBackedRefresh() {
  // Save-triggered reload: refresh() runs one tick on demand, so
  // admin save handlers don't wait intervalMs for the new value to
  // become active. Subscribers fire synchronously inside the reload.
  var s = b.safeSchema;
  var current = "initial";
  var observed = [];
  var cfg = b.config.loadDbBacked({
    schema:     s.object({ K: s.string().default("d") }),
    env:        {},
    fetchRows:  function () { return [{ key: "K", value: current }]; },
    intervalMs: 60 * 1000,   // 60s — well outside the test budget;
                             // refresh() must drive every update
  });
  await cfg.hydrated;
  helpers.check("loadDbBacked.refresh: initial hydration applied",
    cfg.value.K === "initial");

  cfg.subscribe(function (v) { observed.push(v.K); });

  // Simulate admin save → write row → fire refresh().
  current = "post-save-1";
  await cfg.refresh();
  helpers.check("loadDbBacked.refresh: post-save value active immediately",
    cfg.value.K === "post-save-1");
  helpers.check("loadDbBacked.refresh: subscriber fired with new value",
    observed[observed.length - 1] === "post-save-1");

  // A second save, to confirm refresh() is repeatable + subscribers
  // get every transition.
  current = "post-save-2";
  await cfg.refresh();
  helpers.check("loadDbBacked.refresh: second save propagates",
    cfg.value.K === "post-save-2");
  helpers.check("loadDbBacked.refresh: subscribers see every transition",
    observed.indexOf("post-save-1") !== -1 && observed.indexOf("post-save-2") !== -1);

  // refresh() returns a Promise that resolves (never rejects) even
  // when the underlying fetch throws — last-good value stays put.
  var brokenCfg = b.config.loadDbBacked({
    schema:     s.object({ K: s.string().default("d") }),
    env:        {},
    fetchRows:  function () { throw new Error("simulated db outage"); },
    intervalMs: 60 * 1000,
  });
  await brokenCfg.hydrated;
  var rejected = false;
  await brokenCfg.refresh().catch(function () { rejected = true; });
  helpers.check("loadDbBacked.refresh: never rejects on fetch failure",
    rejected === false);
  helpers.check("loadDbBacked.refresh: last-good value preserved on fetch failure",
    brokenCfg.value.K === "d");
  brokenCfg.stop();
  cfg.stop();
}

async function _testLoadDbBackedConcurrentRefreshRace() {
  // Two refresh()es back-to-back where the FIRST fetchRows is slower
  // than the SECOND. Without sequence-guarded apply, the older read
  // resolves last and overwrites the newer save. Verifies the
  // drop-stale invariant: the latest-STARTED tick's data wins,
  // regardless of which tick finishes last.
  var s = b.safeSchema;
  var saveOrder = [];
  var current = "initial";
  var callIndex = 0;
  var cfg = b.config.loadDbBacked({
    schema:     s.object({ K: s.string().default("d") }),
    env:        {},
    fetchRows:  async function () {
      callIndex += 1;
      var mine = callIndex;            // capture per-call so concurrent
                                       // calls don't read each other's index
      var captured = current;
      var lat = (mine === 1) ? 200 : 20;  // first slow, second fast
      saveOrder.push("fetch-" + mine + "-start@" + captured);
      await helpers.passiveObserve(lat, "config-refresh: simulated fetch latency #" + mine);
      saveOrder.push("fetch-" + mine + "-end@" + captured);
      return [{ key: "K", value: captured }];
    },
    intervalMs: 60 * 1000,             // poll out of test window
  });
  await cfg.hydrated;
  helpers.check("concurrent-refresh: initial hydration applied",
    cfg.value.K === "initial");

  // Reset so the race is between two refresh()es only (hydration
  // already ran with callIndex=1 above; advance counters so the
  // race's "first call" is slow, "second" is fast).
  callIndex = 0;

  // Save 1, refresh — fetch will be slow (200ms).
  current = "save-1";
  var p1 = cfg.refresh();
  // Wait until the slow refresh has entered its fetch, so refresh2's
  // seq is strictly greater.
  await helpers.waitUntil(function () {
    return saveOrder.some(function (e) { return e.indexOf("fetch-1-start") === 0; });
  }, { label: "concurrent-refresh: slow refresh has entered its fetch" });
  // Save 2, refresh — fetch will be fast (20ms).
  current = "save-2";
  var p2 = cfg.refresh();

  // p2 should resolve first (faster fetch) and leave cfg at "save-2".
  // p1 should resolve later but DROP its older overlay.
  await Promise.all([p1, p2]);
  helpers.check("concurrent-refresh: latest save wins (save-2)",
    cfg.value.K === "save-2");

  // Verify the slow tick actually finished AFTER the fast tick — i.e.,
  // the race scenario the user described actually occurred.
  var fastEndIx = saveOrder.indexOf("fetch-2-end@save-2");
  var slowEndIx = saveOrder.indexOf("fetch-1-end@save-1");
  helpers.check("concurrent-refresh: slow tick finished after fast tick",
    fastEndIx !== -1 && slowEndIx !== -1 && slowEndIx > fastEndIx);
  cfg.stop();
}

async function _testLoadDbBackedFailedReloadDoesNotSuppressOlderValid() {
  // refresh(valid)-slow followed by refresh(invalid)-fast. The newer
  // tick finishes first and fails validation; without the
  // "advance-only-on-success" invariant, the failed reload would
  // bump the high-water mark to seq=2 and cause the older valid
  // tick (seq=1) to drop as stale when it finally lands —
  // silently keeping stale config active even though a valid update
  // was in-flight at the time.
  var s = b.safeSchema;
  var fetchOrder = [];
  var callIndex = 0;
  var nextValue = "valid-data";   // hydration uses this
  var cfg = b.config.loadDbBacked({
    schema:     s.object({ K: s.string().min(4).default("default-ok") }),
    env:        {},
    fetchRows:  async function () {
      callIndex += 1;
      var mine = callIndex;
      var captured = nextValue;
      fetchOrder.push("start-" + mine);
      // Hydration (#1) fast, refresh1 (#2) slow, refresh2 (#3) fast.
      var lat = (mine === 2) ? 200 : 20;
      await helpers.passiveObserve(lat, "failed-reload: simulated fetch latency #" + mine);
      return [{ key: "K", value: captured }];
    },
    intervalMs: 60 * 1000,
  });
  await cfg.hydrated;
  helpers.check("failed-reload: initial hydration applied valid value",
    cfg.value.K === "valid-data");

  // refresh1 — slow valid (200ms).
  nextValue = "newer-valid-data";
  var p1 = cfg.refresh();
  // Wait until refresh1 has entered its fetch so refresh2's seq is strictly greater.
  await helpers.waitUntil(function () {
    return fetchOrder.indexOf("start-2") !== -1;
  }, { label: "failed-reload: refresh1 (slow) has entered its fetch" });
  // refresh2 — fast invalid (will fail s.string().min(4) at apply).
  nextValue = "x";
  var p2 = cfg.refresh();

  await Promise.all([p1, p2]);

  // refresh2 (newer-finishes-first) reload threw, watermark NOT
  // advanced. refresh1 (older-finishes-later) still passes the
  // stale-check, applies its valid overlay. cfg has "newer-valid-data".
  helpers.check("failed-reload: older valid tick applied after newer invalid failed",
    cfg.value.K === "newer-valid-data");
  cfg.stop();
}

async function _testLoadDbBackedAuditKnob() {
  // The `audit` opt gates the per-poll config.reload.* audit emissions.
  // Default (omitted) emits; audit:false silences. We drive the fetch
  // failure path (config.reload.failed) and observe b.audit.safeEmit —
  // config.js emits through the shared audit module instance.
  var s = b.safeSchema;
  var realSafeEmit = b.audit.safeEmit;
  var reloadEvents = [];
  b.audit.safeEmit = function (rec) {
    if (rec && typeof rec.action === "string" && rec.action.indexOf("config.reload.") === 0) {
      reloadEvents.push(rec.action);
    }
    return realSafeEmit.call(b.audit, rec);
  };
  try {
    // Default — audit fires on the fetch failure.
    var cfgDefault = b.config.loadDbBacked({
      schema:     s.object({ K: s.string().default("d") }),
      env:        {},
      fetchRows:  function () { throw new Error("simulated db outage"); },
      intervalMs: 60 * 1000,
    });
    await cfgDefault.hydrated;
    helpers.check("loadDbBacked.audit default: config.reload.failed emitted",
      reloadEvents.indexOf("config.reload.failed") !== -1);
    cfgDefault.stop();

    // audit:false — same failure, zero emissions.
    reloadEvents.length = 0;
    var cfgSilent = b.config.loadDbBacked({
      schema:     s.object({ K: s.string().default("d") }),
      env:        {},
      fetchRows:  function () { throw new Error("simulated db outage"); },
      intervalMs: 60 * 1000,
      audit:      false,
    });
    await cfgSilent.hydrated;
    helpers.check("loadDbBacked.audit false: no config.reload.* emissions",
      reloadEvents.length === 0);
    cfgSilent.stop();
  } finally {
    b.audit.safeEmit = realSafeEmit;
  }
}

async function _testCryptoFieldDocAliases() {
  // sealDoc / unsealDoc are doc-shaped aliases of sealRow / unsealRow.
  helpers.check("b.cryptoField.sealDoc exists",
    typeof b.cryptoField.sealDoc === "function");
  helpers.check("b.cryptoField.unsealDoc exists",
    typeof b.cryptoField.unsealDoc === "function");
  helpers.check("b.cryptoField.sealDoc === sealRow",
    b.cryptoField.sealDoc === b.cryptoField.sealRow);
  helpers.check("b.cryptoField.unsealDoc === unsealRow",
    b.cryptoField.unsealDoc === b.cryptoField.unsealRow);
}

async function _testHotReload() {
  var s = b.safeSchema;
  var cfg = b.config.create({
    schema: s.object({ X: s.string() }),
    env: { X: "first" },
  });
  helpers.check("config.create: subscribe is a function", typeof cfg.subscribe === "function");
  helpers.check("config.create: reload is a function",    typeof cfg.reload === "function");

  var observed;
  cfg.subscribe(function (v) { observed = v; });
  cfg.reload({ X: "second" });
  helpers.check("config.reload: value updated", cfg.get("X") === "second");
  helpers.check("config.reload: subscriber notified", observed && observed.X === "second");
}

module.exports = { run: async function () {
  await run();
  await _testLoadDbBacked();
  await _testLoadDbBackedTransformValue();
  await _testLoadDbBackedRefresh();
  await _testLoadDbBackedConcurrentRefreshRace();
  await _testLoadDbBackedFailedReloadDoesNotSuppressOlderValid();
  await _testLoadDbBackedAuditKnob();
  await _testCryptoFieldDocAliases();
  await _testHotReload();
} };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
