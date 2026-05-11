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
  await _testCryptoFieldDocAliases();
  await _testHotReload();
} };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
