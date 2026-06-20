"use strict";
/**
 * b.flag — feature-flag primitive (OpenFeature spec).
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function run() {
  // ---- shape ----
  check("b.flag is object",                      typeof b.flag === "object");
  check("b.flag.create is fn",                   typeof b.flag.create === "function");
  check("b.flag.providers.memory",               typeof b.flag.providers.memory === "function");
  check("b.flag.providers.localFile",            typeof b.flag.providers.localFile === "function");
  check("b.flag.providers.environmentVariable",  typeof b.flag.providers.environmentVariable === "function");
  check("b.flag.context.create",                 typeof b.flag.context.create === "function");
  check("b.flag.context.fromRequest",            typeof b.flag.context.fromRequest === "function");

  // ---- providers.memory ----
  var memProvider = b.flag.providers.memory({
    flags: {
      "new-checkout": {
        default: "off",
        variants: { off: false, on: true },
      },
      "greeting": {
        default: "default",
        variants: { default: "Hello", admin: "Welcome admin" },
        rules: [
          { variant: "admin", conditions: [
            { attribute: "role", op: "eq", value: "admin" },
          ]},
        ],
      },
      "rollout-feature": {
        default: "off",
        variants: { off: false, on: true },
        rollout: [
          { variant: "on",  percentage: 50 },
          { variant: "off", percentage: 50 },
        ],
      },
    },
  });
  check("memProvider.kind",                      memProvider.kind === "memory");
  check("memProvider.list",                      memProvider.list().length === 3);

  // ---- bad spec validation ----
  rejects("provider: bad spec - no variants",
    function () {
      b.flag.providers.memory({ flags: { x: { default: "on" } } });
    }, /variants object is required/);
  rejects("provider: default not in variants",
    function () {
      b.flag.providers.memory({ flags: { x: { default: "ghost", variants: { on: true } } } });
    }, /default must be a variant/);
  rejects("provider: rule variant not in variants",
    function () {
      b.flag.providers.memory({
        flags: { x: { default: "off", variants: { off: false, on: true },
          rules: [{ variant: "ghost", conditions: [{ attribute: "x", op: "eq", value: 1 }] }] } },
      });
    }, /not a registered variant/);
  rejects("provider: rollout percentage > 100",
    function () {
      b.flag.providers.memory({
        flags: { x: { default: "off", variants: { off: false, on: true },
          rollout: [{ variant: "on", percentage: 60 }, { variant: "off", percentage: 50 }] } },
      });
    }, /sum must be <= 100/);
  rejects("provider: rule with bad op",
    function () {
      b.flag.providers.memory({
        flags: { x: { default: "off", variants: { off: false, on: true },
          rules: [{ variant: "on", conditions: [{ attribute: "x", op: "nope", value: 1 }] }] } },
      });
    }, /must be one of/);

  // ---- create ----
  rejects("create: no provider",
    function () { b.flag.create({}); }, /at least one provider/);
  rejects("create: bad provider",
    function () { b.flag.create({ provider: { evaluate: "not-fn" } }); }, /must implement/);

  var flag = b.flag.create({
    provider: memProvider,
    defaultEvaluationContext: { environment: "test" },
    audit: false,
  });

  // ---- getBoolean ----
  check("getBoolean: default off",               flag.getBoolean("new-checkout", { targetingKey: "u1" }) === false);
  check("getBoolean: missing flag → default",    flag.getBoolean("ghost-flag", {}, false) === false);
  check("getBoolean: missing flag → true default", flag.getBoolean("ghost-flag", {}, true) === true);

  // ---- getString with targeting match ----
  check("getString: admin gets admin variant",   flag.getString("greeting", { role: "admin" }) === "Welcome admin");
  check("getString: non-admin gets default",     flag.getString("greeting", { role: "user" }) === "Hello");

  // ---- getDetails ----
  var details = flag.getDetails("greeting", { role: "admin" });
  check("getDetails: variant",                   details.variant === "admin");
  check("getDetails: reason",                    details.reason === "targeting_match");
  check("getDetails: ruleIndex",                 details.metadata.ruleIndex === 0);

  // ---- list ----
  var keys = flag.list();
  check("flag.list: 3 keys",                     keys.length === 3);

  // ---- evaluation context ----
  var ctx = b.flag.context.create({ targetingKey: "user-42", role: "admin", region: "EU" });
  check("context.create: targetingKey",          ctx.targetingKey === "user-42");
  check("context.create: frozen",                Object.isFrozen(ctx));
  rejects("context.create: bad targetingKey",
    function () { b.flag.context.create({ targetingKey: 42 }); }, /must be a string/);
  rejects("context.create: poisoned key skipped",
    function () { b.flag.context.create([1, 2, 3]); }, /plain object/);

  var merged = b.flag.context.merge(ctx, { tier: "gold" });
  check("context.merge: keeps base",             merged.targetingKey === "user-42");
  check("context.merge: adds overlay",           merged.tier === "gold");

  // An own poisoned key (constructor / __proto__ / prototype) on a merge source
  // is skipped — the merge routes through validateOpts.assignOwnEnumerable, a
  // prototype-pollution defense the prior hand-rolled own-key copy lacked.
  var poison = {};
  Object.defineProperty(poison, "constructor", { value: "EVIL", enumerable: true, configurable: true });
  var safeMerged = b.flag.context.merge({ targetingKey: "u" }, poison);
  check("context.merge: skips an own poisoned 'constructor' key",
        safeMerged.constructor !== "EVIL" && safeMerged.targetingKey === "u");

  // bucketOf is deterministic
  var b1 = b.flag.context.bucketOf("user-42", "test-flag");
  var b2 = b.flag.context.bucketOf("user-42", "test-flag");
  check("bucketOf: deterministic",               b1 === b2);
  check("bucketOf: in [0, 100)",                 b1 >= 0 && b1 < 100);

  // fromRequest
  var ctxFromReq = b.flag.context.fromRequest({
    user: { id: "u-123", role: "admin", email: "a@b.c" },
    headers: { "accept-language": "en-US,en;q=0.9", "user-agent": "test-agent" },
  });
  check("fromRequest: targetingKey from user.id", ctxFromReq.targetingKey === "u-123");
  check("fromRequest: role",                     ctxFromReq.role === "admin");
  check("fromRequest: locale",                   ctxFromReq.locale === "en-US");

  // anonymous fallback
  var ctxAnon = b.flag.context.fromRequest({ headers: { "x-forwarded-for": "1.2.3.4", "user-agent": "ua" } });
  check("fromRequest: anon targetingKey",        ctxAnon.targetingKey.indexOf("anon:") === 0);

  // explicit tenantKey supplies the tenant id (gateway-resolved tenancy)
  var ctxTenant = b.flag.context.fromRequest(
    { user: { id: "u-1" }, headers: {} },
    { tenantKey: "tenant-explicit" });
  check("fromRequest: tenantKey sets tenantId",  ctxTenant.tenantId === "tenant-explicit");

  // tenantKey overrides the tenant id derived from req.user.tenantId
  var ctxTenantOverride = b.flag.context.fromRequest(
    { user: { id: "u-2", tenantId: "from-user" }, headers: {} },
    { tenantKey: "from-opts" });
  check("fromRequest: tenantKey overrides req.user.tenantId", ctxTenantOverride.tenantId === "from-opts");

  // default unchanged: no tenantKey → tenantId still derived from req.user
  var ctxTenantDefault = b.flag.context.fromRequest(
    { user: { id: "u-3", tenantId: "user-tenant" }, headers: {} });
  check("fromRequest: no tenantKey keeps req.user.tenantId", ctxTenantDefault.tenantId === "user-tenant");

  // empty-string tenantKey is ignored (falls back to req.user.tenantId)
  var ctxTenantEmpty = b.flag.context.fromRequest(
    { user: { id: "u-4", tenantId: "user-tenant" }, headers: {} },
    { tenantKey: "" });
  check("fromRequest: empty tenantKey ignored",  ctxTenantEmpty.tenantId === "user-tenant");

  // ---- targeting evaluation ----
  var t = b.flag.targeting;
  check("targeting.VALID_OPS",                   Array.isArray(t.VALID_OPS) && t.VALID_OPS.length > 10);

  // various ops
  var rules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "role", op: "eq", value: "admin" }] },
    { variant: "v2", conditions: [{ attribute: "tier", op: "gte", value: 5 }] },
    { variant: "v3", conditions: [{ attribute: "region", op: "in", value: ["EU", "UK"] }] },
    { variant: "v4", conditions: [{ attribute: "name", op: "starts_with", value: "ad" }] },
    { variant: "v5", conditions: [{ attribute: "email", op: "regex", value: "@example\\.com$" }] },
  ]);

  var r1 = t.evaluateRules(rules, { role: "admin" }, "default");
  check("targeting: eq matches",                 r1.variant === "v1");

  var r2 = t.evaluateRules(rules, { tier: 10 }, "default");
  check("targeting: gte matches",                r2.variant === "v2");

  var r3 = t.evaluateRules(rules, { region: "UK" }, "default");
  check("targeting: in matches",                 r3.variant === "v3");

  var r4 = t.evaluateRules(rules, { name: "admin-bot" }, "default");
  check("targeting: starts_with matches",        r4.variant === "v4");

  var r5 = t.evaluateRules(rules, { email: "user@example.com" }, "default");
  check("targeting: regex matches",              r5.variant === "v5");

  var rd = t.evaluateRules(rules, {}, "default");
  check("targeting: default fallback",           rd.variant === "default");

  // exists / not_exists
  var existsRules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "tier", op: "exists", value: null }] },
    { variant: "v2", conditions: [{ attribute: "missing", op: "not_exists", value: null }] },
  ]);
  var re1 = t.evaluateRules(existsRules, { tier: "gold" }, "default");
  check("targeting: exists matches",             re1.variant === "v1");
  var re2 = t.evaluateRules(existsRules, {}, "default");
  check("targeting: not_exists matches",         re2.variant === "v2");

  // between
  var betweenRules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "age", op: "between", value: [18, 65] }] },
  ]);
  check("targeting: between in range",           t.evaluateRules(betweenRules, { age: 30 }, "default").variant === "v1");
  check("targeting: between below",              t.evaluateRules(betweenRules, { age: 5 }, "default").variant === "default");

  // regex DoS bound
  rejects("targeting: regex over 200 chars",
    function () {
      var huge = new Array(220).fill("a").join("");
      t.validateRules([{ variant: "v", conditions: [{ attribute: "x", op: "regex", value: huge }] }]);
    },
    /must be <= 200/);

  // bad regex
  rejects("targeting: bad regex",
    function () {
      t.validateRules([{ variant: "v", conditions: [{ attribute: "x", op: "regex", value: "(unclosed" }] }]);
    },
    /invalid regex/);

  // nested attribute path
  var pathRules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "user.role", op: "eq", value: "admin" }] },
  ]);
  var pr = t.evaluateRules(pathRules, { user: { role: "admin" } }, "default");
  check("targeting: nested path resolves",       pr.variant === "v1");

  // ---- percentage rollout ----
  // 100% rollout to "on"
  var allOnFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "rollout-100": {
          default: "off",
          variants: { off: false, on: true },
          rollout: [{ variant: "on", percentage: 100 }],
        },
      },
    }),
    audit: false,
  });
  check("rollout 100%: every key gets on",       allOnFlag.getBoolean("rollout-100", { targetingKey: "u-1" }) === true);
  check("rollout 100%: another key also on",     allOnFlag.getBoolean("rollout-100", { targetingKey: "u-9999" }) === true);

  // 50% rollout — distribution
  var rolloutFlag = b.flag.create({
    provider: memProvider,
    audit: false,
  });
  var onCount = 0, offCount = 0;
  for (var i = 0; i < 200; i += 1) {
    var v = rolloutFlag.getBoolean("rollout-feature", { targetingKey: "user-" + i });
    if (v) onCount += 1; else offCount += 1;
  }
  check("rollout 50%: roughly even split",       Math.abs(onCount - offCount) < 80);
  var s1 = rolloutFlag.getBoolean("rollout-feature", { targetingKey: "user-1" });
  var s2 = rolloutFlag.getBoolean("rollout-feature", { targetingKey: "user-1" });
  check("rollout 50%: stickiness",                s1 === s2);

  // ---- environmentVariable provider ----
  process.env.FLAG_NEW_CHECKOUT = "true";
  var envProvider = b.flag.providers.environmentVariable({
    prefix: "FLAG_",
    flags: {
      "new-checkout": { default: "off", variants: { off: false, on: true } },
    },
  });
  var envFlag = b.flag.create({ provider: envProvider, audit: false });
  check("env provider: env override → on",       envFlag.getBoolean("new-checkout", { targetingKey: "u" }) === true);
  delete process.env.FLAG_NEW_CHECKOUT;

  rejects("env provider: missing flags spec",
    function () { b.flag.providers.environmentVariable({ prefix: "FLAG_" }); }, /flags object required/);

  // ---- localFile provider ----
  var fs = require("fs");
  var path = require("path");
  var os  = require("os");
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-flag-"));
  var flagsPath = path.join(tmpDir, "flags.json");
  fs.writeFileSync(flagsPath, JSON.stringify({
    flags: {
      "feature-x": { default: "on", variants: { on: true, off: false } },
    },
  }));
  var fileProvider = b.flag.providers.localFile({ path: flagsPath });
  check("localFile.kind",                        fileProvider.kind === "local-file");
  check("localFile evaluates",                   fileProvider.evaluate("feature-x", {}).value === true);
  fs.unlinkSync(flagsPath);
  fs.rmdirSync(tmpDir);

  rejects("localFile: missing path",
    function () { b.flag.providers.localFile({}); }, /path/);
  rejects("localFile: nonexistent file",
    function () { b.flag.providers.localFile({ path: "/no/such/file.json" }); }, /cannot read/);

  // ---- middleware ----
  var mw = flag.middleware();
  check("middleware: factory returns fn",        typeof mw === "function");
  var req = {
    user: { id: "u-mw", role: "admin" },
    headers: { "accept-language": "en" },
  };
  var calledNext = 0;
  mw(req, {}, function () { calledNext += 1; });
  check("middleware: calls next",                calledNext === 1);
  check("middleware: req.flag attached",         typeof req.flag === "object");
  check("middleware: req.flag.getBoolean",       typeof req.flag.getBoolean === "function");
  check("middleware: req.flag.getString admin",  req.flag.getString("greeting") === "Welcome admin");
  check("middleware: req.flag.ctx",              req.flag.ctx.targetingKey === "u-mw");

  // ---- multi-provider fallback ----
  var primary = b.flag.providers.memory({
    flags: { "shared": { default: "primary", variants: { primary: "P", secondary: "S" } } },
  });
  var secondary = b.flag.providers.memory({
    flags: { "only-in-secondary": { default: "v", variants: { v: "secondary-value" } } },
  });
  var multi = b.flag.create({
    providers: [primary, secondary],
    audit: false,
  });
  check("multi-provider: hits primary first",    multi.getString("shared", {}) === "P");
  check("multi-provider: falls to secondary",    multi.getString("only-in-secondary", {}) === "secondary-value");

  // ---- error handler ----
  var seen = null;
  var brokenProvider = {
    kind: "broken",
    evaluate: function () { throw new Error("provider broken"); },
    list: function () { return ["broken-flag"]; },
  };
  var errFlag = b.flag.create({
    provider: brokenProvider,
    errorHandler: function (info) { seen = info; },
    audit: false,
  });
  var fallback = errFlag.getBoolean("broken-flag", {}, true);
  check("errorHandler: returns default",         fallback === true);
  check("errorHandler: invoked",                 seen != null && seen.flagKey === "broken-flag");

  // ---- type coercion ----
  var coerceFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "as-string-true":  { default: "v", variants: { v: "true" } },
        "as-number":       { default: "v", variants: { v: 42 } },
        "as-object":       { default: "v", variants: { v: { foo: "bar" } } },
      },
    }),
    audit: false,
  });
  check("getBoolean: string true coerced",       coerceFlag.getBoolean("as-string-true", {}, false) === true);
  check("getNumber: returns number",             coerceFlag.getNumber("as-number", {}, 0) === 42);
  check("getObject: returns object",             coerceFlag.getObject("as-object", {}, {}).foo === "bar");
  check("getNumber: no flag → default",          coerceFlag.getNumber("ghost", {}, 99) === 99);
  check("getObject: no flag → default",          coerceFlag.getObject("ghost", {}, { x: 1 }).x === 1);

  // ---- batch evaluation ----
  var batchFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "feature-a": { default: "on",  variants: { on: true, off: false } },
        "feature-b": { default: "off", variants: { on: true, off: false } },
        "feature-c": { default: "v",   variants: { v: 42 } },
      },
    }),
    audit: false,
  });
  var values = batchFlag.getValues(["feature-a", "feature-b", "feature-c"], {});
  check("getValues: feature-a true",             values["feature-a"] === true);
  check("getValues: feature-b false",            values["feature-b"] === false);
  check("getValues: feature-c 42",               values["feature-c"] === 42);
  var allDetails = batchFlag.getDetailsAll(["feature-a", "feature-b"], {});
  check("getDetailsAll: feature-a",              allDetails["feature-a"].variant === "on");
  check("getDetailsAll: feature-b reason",       allDetails["feature-b"].reason === "default");

  // batch with empty
  check("getValues: not-array returns {}",       Object.keys(batchFlag.getValues(null, {})).length === 0);

  // ---- addProvider / removeProvider ----
  var dynFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: { "x": { default: "a", variants: { a: 1, b: 2 } } },
    }),
    audit: false,
  });
  check("dyn: 1 provider initial",               dynFlag.providers.length === 1);
  var extra = b.flag.providers.memory({
    flags: { "y": { default: "v", variants: { v: "extra" } } },
  });
  var newCount = dynFlag.addProvider(extra);
  check("dyn: addProvider returns new count",     newCount === 2);
  check("dyn: y resolves through extra",          dynFlag.getString("y", {}, "fallback") === "extra");
  rejects("addProvider: bad provider",
    function () { dynFlag.addProvider({ noEvaluate: true }); }, /must implement/);
  var removed = dynFlag.removeProvider(extra);
  check("dyn: removeProvider returns 1",          removed === 1);
  check("dyn: y no longer resolves",              dynFlag.getString("y", {}, "fallback") === "fallback");

  // ---- bucket distribution stickiness across reload ----
  var bucketFlag1 = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "rollout-x": {
          default: "off",
          variants: { off: false, on: true },
          rollout: [{ variant: "on", percentage: 30 }, { variant: "off", percentage: 70 }],
        },
      },
    }),
    audit: false,
  });
  var v1 = bucketFlag1.getDetails("rollout-x", { targetingKey: "user-stable" });
  // recreate a new client from a fresh provider with the same spec
  var bucketFlag2 = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "rollout-x": {
          default: "off",
          variants: { off: false, on: true },
          rollout: [{ variant: "on", percentage: 30 }, { variant: "off", percentage: 70 }],
        },
      },
    }),
    audit: false,
  });
  var v2 = bucketFlag2.getDetails("rollout-x", { targetingKey: "user-stable" });
  check("rollout: stable across re-create",      v1.variant === v2.variant);

  // ---- evaluation chain: targeting THEN rollout ----
  var chainFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "experiment": {
          default: "control",
          variants: { control: "C", treatment: "T", admin: "A" },
          rules: [
            { variant: "admin", conditions: [{ attribute: "role", op: "eq", value: "admin" }] },
          ],
          rollout: [
            { variant: "treatment", percentage: 50 },
            { variant: "control",   percentage: 50 },
          ],
        },
      },
    }),
    audit: false,
  });
  // admin always gets admin
  var ad = chainFlag.getDetails("experiment", { targetingKey: "u-1", role: "admin" });
  check("chain: admin role bypasses rollout",     ad.variant === "admin" && ad.reason === "targeting_match");
  // non-admin gets rollout
  var nonAd = chainFlag.getDetails("experiment", { targetingKey: "u-1", role: "user" });
  check("chain: non-admin uses rollout",          nonAd.reason === "split");

  // ---- targeting: numeric coercion safety ----
  var numRules = t.validateRules([
    { variant: "v", conditions: [{ attribute: "n", op: "gt", value: 5 }] },
  ]);
  check("targeting: gt with non-number",          t.evaluateRules(numRules, { n: "10" }, "default").variant === "default");
  check("targeting: gt missing attribute",        t.evaluateRules(numRules, {}, "default").variant === "default");

  // ---- targeting: in non-array",
  var inRules = t.validateRules([
    { variant: "v", conditions: [{ attribute: "x", op: "in", value: ["a", "b", "c"] }] },
  ]);
  check("targeting: in array match",              t.evaluateRules(inRules, { x: "b" }, "default").variant === "v");
  check("targeting: in no match",                 t.evaluateRules(inRules, { x: "z" }, "default").variant === "default");

  // ---- cache wrapper ----
  check("b.flag.cache is fn",                    typeof b.flag.cache === "function");
  rejects("cache: bad downstream",
    function () { b.flag.cache({}); }, /must implement/);
  rejects("cache: ttlMs too small",
    function () { b.flag.cache(memProvider, { ttlMs: 100 }); }, /ttlMs/);

  var cachedProvider = b.flag.cache(memProvider, { ttlMs: 5000, maxEntries: 50 });
  check("cache: kind",                           cachedProvider.kind === "cache:memory");
  // First eval = miss
  var cf1 = cachedProvider.evaluate("new-checkout", { targetingKey: "u-cache" });
  check("cache: first eval works",                cf1.reason === "default");
  var stats1 = cachedProvider.stats();
  check("cache stats: 1 miss",                    stats1.misses === 1);
  check("cache stats: 0 hits",                    stats1.hits === 0);
  check("cache stats: size 1",                    stats1.size === 1);
  // Second eval = hit
  cachedProvider.evaluate("new-checkout", { targetingKey: "u-cache" });
  var stats2 = cachedProvider.stats();
  check("cache stats: 1 hit",                     stats2.hits === 1);
  check("cache stats: hit ratio",                 stats2.hitRatio === 0.5);
  // Different targetingKey = miss
  cachedProvider.evaluate("new-checkout", { targetingKey: "u-other" });
  check("cache stats: 2 misses",                  cachedProvider.stats().misses === 2);
  // No targetingKey = bypass cache
  cachedProvider.evaluate("new-checkout", {});
  check("cache stats: bypass no-tk",              cachedProvider.stats().size === 2);
  // Bust
  var prevSize = cachedProvider.bust();
  check("cache bust: returns prev size",          prevSize === 2);
  check("cache bust: cleared",                    cachedProvider.stats().size === 0);

  // Cache flag-not-found is NOT cached (operator may add later)
  var cachedProvider2 = b.flag.cache(memProvider, { ttlMs: 5000 });
  cachedProvider2.evaluate("ghost-flag", { targetingKey: "u" });
  check("cache: not_found is not cached",         cachedProvider2.stats().size === 0);

  // ---- bad rule shapes caught at validation ----
  rejects("targeting: bad rule (no variant)",
    function () { t.validateRules([{ conditions: [] }]); }, /variant/);
  rejects("targeting: bad rule (no conditions array)",
    function () { t.validateRules([{ variant: "v", conditions: "x" }]); }, /must be an array/);
  rejects("targeting: between not 2-element array",
    function () {
      t.validateRules([{ variant: "v", conditions: [{ attribute: "x", op: "between", value: [1] }] }]);
    },
    /\[number, number\]/);
  rejects("targeting: in not array",
    function () {
      t.validateRules([{ variant: "v", conditions: [{ attribute: "x", op: "in", value: "a" }] }]);
    },
    /requires an array value/);
  rejects("targeting: regex non-string",
    function () {
      t.validateRules([{ variant: "v", conditions: [{ attribute: "x", op: "regex", value: 42 }] }]);
    },
    /requires a string value/);

  // ---- multi-condition AND ----
  var andRules = t.validateRules([
    { variant: "v", conditions: [
      { attribute: "role", op: "eq", value: "admin" },
      { attribute: "tier", op: "gte", value: 5 },
      { attribute: "region", op: "in", value: ["EU", "UK"] },
    ]},
  ]);
  check("targeting AND: all match",               t.evaluateRules(andRules, { role: "admin", tier: 10, region: "EU" }, "default").variant === "v");
  check("targeting AND: missing role",            t.evaluateRules(andRules, { tier: 10, region: "EU" }, "default").variant === "default");
  check("targeting AND: tier below",              t.evaluateRules(andRules, { role: "admin", tier: 3, region: "EU" }, "default").variant === "default");
  check("targeting AND: wrong region",            t.evaluateRules(andRules, { role: "admin", tier: 10, region: "US" }, "default").variant === "default");

  // ---- environmentVariable provider mapping options ----
  process.env.FLAG_TIER_FEATURE = "treatment";
  var envP2 = b.flag.providers.environmentVariable({
    prefix: "FLAG_",
    flags: {
      "tier-feature": {
        default: "control",
        variants: { control: "C", treatment: "T", admin: "A" },
      },
    },
  });
  var envFlag2 = b.flag.create({ provider: envP2, audit: false });
  check("env provider: variant-name override",   envFlag2.getString("tier-feature", {}) === "T");
  delete process.env.FLAG_TIER_FEATURE;

  // env false → off
  process.env.FLAG_TF2 = "false";
  var envP3 = b.flag.providers.environmentVariable({
    prefix: "FLAG_",
    flags: {
      "tf2": { default: "on", variants: { on: true, off: false } },
    },
  });
  check("env provider: 'false' → off variant",   b.flag.create({ provider: envP3, audit: false }).getBoolean("tf2", {}) === false);
  delete process.env.FLAG_TF2;

  // env unrecognized value → keeps default
  process.env.FLAG_TF3 = "garbage";
  var envP4 = b.flag.providers.environmentVariable({
    prefix: "FLAG_",
    flags: {
      "tf3": { default: "on", variants: { on: true, off: false } },
    },
  });
  check("env provider: bad value keeps default",  b.flag.create({ provider: envP4, audit: false }).getBoolean("tf3", {}) === true);
  delete process.env.FLAG_TF3;

  // ---- localFile bad-JSON ----
  var fs2 = require("fs");
  var path2 = require("path");
  var os2 = require("os");
  var tmp2 = fs2.mkdtempSync(path2.join(os2.tmpdir(), "blamejs-flag-"));
  var badPath = path2.join(tmp2, "bad.json");
  fs2.writeFileSync(badPath, "{not valid json");
  rejects("localFile: invalid JSON",
    function () { b.flag.providers.localFile({ path: badPath }); }, /invalid JSON/);
  // localFile missing flags key
  var noflags = path2.join(tmp2, "noflags.json");
  fs2.writeFileSync(noflags, JSON.stringify({ other: 1 }));
  rejects("localFile: missing flags key",
    function () { b.flag.providers.localFile({ path: noflags }); }, /must export.*flags/);
  fs2.unlinkSync(badPath);
  fs2.unlinkSync(noflags);
  fs2.rmdirSync(tmp2);

  // ---- targeting: contains / ends_with ----
  var stringRules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "email", op: "contains", value: "admin" }] },
    { variant: "v2", conditions: [{ attribute: "name",  op: "ends_with", value: "_test" }] },
  ]);
  check("targeting contains",                    t.evaluateRules(stringRules, { email: "admin@x.com" }, "default").variant === "v1");
  check("targeting ends_with",                    t.evaluateRules(stringRules, { name: "user_test" }, "default").variant === "v2");
  check("targeting ends_with no match",           t.evaluateRules(stringRules, { name: "user" }, "default").variant === "default");

  // neq / nin / lt / lte
  var negRules = t.validateRules([
    { variant: "skip-admin", conditions: [{ attribute: "role", op: "neq", value: "admin" }] },
    { variant: "blocked",    conditions: [{ attribute: "country", op: "nin", value: ["KP", "IR"] }] },
    { variant: "young",      conditions: [{ attribute: "age", op: "lt", value: 18 }] },
    { variant: "max-tier",   conditions: [{ attribute: "tier", op: "lte", value: 100 }] },
  ]);
  check("targeting neq",                         t.evaluateRules(negRules, { role: "user" }, "default").variant === "skip-admin");
  check("targeting nin (allowed)",               t.evaluateRules(negRules, { role: "admin", country: "US" }, "default").variant === "blocked");
  check("targeting lt",                          t.evaluateRules(negRules, { role: "admin", country: "KP", age: 12 }, "default").variant === "young");
  check("targeting lte",                         t.evaluateRules(negRules, { role: "admin", country: "KP", age: 30, tier: 50 }, "default").variant === "max-tier");

  // ---- evaluator: malformed rule survives without crashing ----
  // Bypass validateRules so we can inject a malformed rule directly
  var malformed = [
    { /* no variant, no conditions */ },
    { variant: "x", conditions: [{ /* no op */ attribute: "x", value: 1 }] },
    null,
  ];
  // evaluator should skip them and return default
  var rmf = t.evaluateRules(malformed, { x: 1 }, "default");
  check("targeting: malformed rules → default",  rmf.variant === "default");

  // ---- bucketOf: empty inputs ----
  check("bucketOf: empty targetingKey",          b.flag.context.bucketOf("", "f") === 0);
  check("bucketOf: empty flagKey",               b.flag.context.bucketOf("u", "") === 0);
  check("bucketOf: non-string",                  b.flag.context.bucketOf(null, null) === 0);

  // ---- hooks ----
  var hookCalls = [];
  var hookFlag = b.flag.create({
    provider: memProvider,
    audit: false,
    hooks: {
      before:  function (info) { hookCalls.push("before:" + info.flagKey); },
      after:   function (info) { hookCalls.push("after:"  + info.flagKey + ":" + info.result.reason); },
      finally: function (info) { hookCalls.push("finally:" + info.flagKey); },
    },
  });
  hookCalls.length = 0;
  hookFlag.getBoolean("new-checkout", { targetingKey: "u" });
  check("hooks: before fired",                    hookCalls.indexOf("before:new-checkout") !== -1);
  check("hooks: after fired with reason",         hookCalls.indexOf("after:new-checkout:default") !== -1);
  check("hooks: finally fired",                   hookCalls.indexOf("finally:new-checkout") !== -1);
  check("hooks: order before-after-finally",      hookCalls[0].indexOf("before") === 0);

  // multiple hooks per stage
  var multi1 = 0, multi2 = 0;
  var multiHookFlag = b.flag.create({
    provider: memProvider,
    audit: false,
    hooks: {
      after: [
        function () { multi1 += 1; },
        function () { multi2 += 1; },
      ],
    },
  });
  multiHookFlag.getBoolean("new-checkout", { targetingKey: "u" });
  check("hooks: multiple per stage",              multi1 === 1 && multi2 === 1);

  // hook throwing doesn't break evaluation
  var safeHookFlag = b.flag.create({
    provider: memProvider,
    audit: false,
    hooks: {
      before: function () { throw new Error("hook explodes"); },
    },
  });
  check("hooks: throwing hook doesn't break eval", safeHookFlag.getBoolean("new-checkout", { targetingKey: "u" }) === false);

  // error hook fires on provider failure
  var errorSeen = null;
  var errFlag2 = b.flag.create({
    provider: brokenProvider,
    audit: false,
    hooks: {
      error: function (info) { errorSeen = info; },
    },
  });
  errFlag2.getBoolean("broken-flag", {}, true);
  check("hooks: error fired on provider error",   errorSeen != null && errorSeen.flagKey === "broken-flag");

  rejects("hooks: bad shape (not object)",
    function () { b.flag.create({ provider: memProvider, hooks: "string" }); }, /must be an object/);
  rejects("hooks: non-function entry",
    function () { b.flag.create({ provider: memProvider, hooks: { before: "not-a-fn" } }); }, /must be a function/);

  // ---- middleware: anonymous request ----
  var anonMw = flag.middleware();
  var anonReq = { headers: { "x-forwarded-for": "5.6.7.8", "user-agent": "test-ua" } };
  anonMw(anonReq, {}, function () {});
  check("middleware: anonymous targetingKey",     anonReq.flag.ctx.targetingKey.indexOf("anon:") === 0);

  // ---- override middleware userKey ----
  var customMw = flag.middleware({ userKey: "explicit-key" });
  var customReq = { user: { id: "should-be-ignored" }, headers: {} };
  customMw(customReq, {}, function () {});
  check("middleware: explicit userKey wins",      customReq.flag.ctx.targetingKey === "explicit-key");

  // ---- middleware.flagContext (separate from per-client middleware) ----
  check("b.middleware.flagContext is fn",        typeof b.middleware.flagContext === "function");

  var ctxMw = b.middleware.flagContext({
    userKeyHeader: "x-user-id",
    extractAttributes: function (req) {
      return { tenantId: req.tenantId, environment: "test" };
    },
  });
  var ctxReq1 = {
    headers: { "x-user-id": "u-101" },
    tenantId: "tenant-A",
  };
  var ctxNext = 0;
  ctxMw(ctxReq1, {}, function () { ctxNext += 1; });
  check("flagContext mw: calls next",            ctxNext === 1);
  check("flagContext mw: req.flagCtx attached", typeof ctxReq1.flagCtx === "object");
  check("flagContext mw: targetingKey from header", ctxReq1.flagCtx.targetingKey === "u-101");
  check("flagContext mw: tenantId augmented",   ctxReq1.flagCtx.tenantId === "tenant-A");
  check("flagContext mw: environment augmented", ctxReq1.flagCtx.environment === "test");
  check("flagContext mw: ctx is frozen",        Object.isFrozen(ctxReq1.flagCtx));

  // explicit userKey wins
  var ctxMw2 = b.middleware.flagContext({ userKey: "fixed-key" });
  var ctxReq2 = { headers: { "x-user-id": "should-be-ignored" } };
  ctxMw2(ctxReq2, {}, function () {});
  check("flagContext mw: explicit userKey wins", ctxReq2.flagCtx.targetingKey === "fixed-key");

  // tenantKeyHeader
  var ctxMw3 = b.middleware.flagContext({ tenantKeyHeader: "x-tenant" });
  var ctxReq3 = { headers: { "x-tenant": "acme" } };
  ctxMw3(ctxReq3, {}, function () {});
  check("flagContext mw: tenantKeyHeader",      ctxReq3.flagCtx.tenantId === "acme");

  // bad extractAttributes throws at config time
  rejects("flagContext mw: bad extractAttributes",
    function () {
      b.middleware.flagContext({ extractAttributes: "not-a-fn" });
    },
    /must be a function/);

  // ---- localFile spec validation propagates ----
  var fs3 = require("fs");
  var path3 = require("path");
  var os3 = require("os");
  var tmp3 = fs3.mkdtempSync(path3.join(os3.tmpdir(), "blamejs-flag-"));
  var badSpecPath = path3.join(tmp3, "bad-spec.json");
  fs3.writeFileSync(badSpecPath, JSON.stringify({
    flags: {
      "broken": { default: "ghost", variants: { on: true, off: false } },
    },
  }));
  rejects("localFile: bad spec propagates",
    function () { b.flag.providers.localFile({ path: badSpecPath }); }, /default must be a variant/);
  fs3.unlinkSync(badSpecPath);
  fs3.rmdirSync(tmp3);

  // ---- multi-rule order: first match wins ----
  var orderRules = t.validateRules([
    { variant: "v1", conditions: [{ attribute: "tier", op: "gte", value: 5 }] },
    { variant: "v2", conditions: [{ attribute: "tier", op: "gte", value: 1 }] },
  ]);
  check("targeting: first match wins (v1)",      t.evaluateRules(orderRules, { tier: 10 }, "default").variant === "v1");
  check("targeting: tier 3 → v2 (v1 skipped)",   t.evaluateRules(orderRules, { tier: 3 }, "default").variant === "v2");
  check("targeting: tier 0 → default",           t.evaluateRules(orderRules, { tier: 0 }, "default").variant === "default");

  // ---- comprehensive details ----
  var det = batchFlag.getDetails("feature-c", { targetingKey: "u" });
  check("getDetails: variant",                   det.variant === "v");
  check("getDetails: value",                     det.value === 42);
  check("getDetails: reason default",            det.reason === "default");
  check("getDetails: metadata.flagKey",          det.metadata.flagKey === "feature-c");

  // missing flag details
  var missDet = batchFlag.getDetails("ghost-flag-x", {});
  check("getDetails: missing → flag_not_found",  missDet.reason === "flag_not_found");
  check("getDetails: missing → providers list",  Array.isArray(missDet.metadata.providers));

  // ---- environment provider unknown variant + boolean fallback ----
  process.env.FLAG_TEST_X = "on";
  var envBoolP = b.flag.providers.environmentVariable({
    prefix: "FLAG_",
    flags: { "test-x": { default: "off", variants: { on: true, off: false } } },
  });
  check("env provider: 'on' → on variant",       b.flag.create({ provider: envBoolP, audit: false }).getBoolean("test-x", {}) === true);
  delete process.env.FLAG_TEST_X;

  // ---- evaluation with nested-attribute custom ctx ----
  var nestedCtxFlag = b.flag.create({
    provider: b.flag.providers.memory({
      flags: {
        "deep-flag": {
          default: "off",
          variants: { off: false, on: true },
          rules: [
            { variant: "on", conditions: [
              { attribute: "user.profile.tier", op: "eq", value: "platinum" },
            ]},
          ],
        },
      },
    }),
    audit: false,
  });
  check("nested ctx: matches deep path",         nestedCtxFlag.getBoolean("deep-flag", {
    targetingKey: "u", user: { profile: { tier: "platinum" } },
  }) === true);
  check("nested ctx: missing path → default",    nestedCtxFlag.getBoolean("deep-flag", {
    targetingKey: "u", user: { profile: {} },
  }) === false);

  // ---- targeting: nested array conditions ----
  var deepRules = t.validateRules([
    { variant: "v", conditions: [
      { attribute: "user.profile.tier", op: "in", value: ["gold", "platinum"] },
      { attribute: "user.country", op: "neq", value: "blocked" },
    ]},
  ]);
  check("targeting nested in",                   t.evaluateRules(deepRules, {
    user: { profile: { tier: "platinum" }, country: "US" },
  }, "default").variant === "v");
  check("targeting nested miss",                 t.evaluateRules(deepRules, {
    user: { profile: { tier: "silver" }, country: "US" },
  }, "default").variant === "default");

  // ---- targeting: poisoned key skipped ----
  var poisonedCtx = b.flag.context.create({ targetingKey: "ok", "__proto__": "ignored" });
  // Object.prototype.__proto__ is a regular accessor; verify our walker
  // doesn't follow it.
  check("context: poisoned key skipped",         poisonedCtx.targetingKey === "ok");

  // ---- providers list iteration ----
  var listOnly = b.flag.providers.memory({
    flags: {
      "alpha": { default: "v", variants: { v: 1 } },
      "beta":  { default: "v", variants: { v: 2 } },
      "gamma": { default: "v", variants: { v: 3 } },
    },
  });
  var listKeys = listOnly.list().sort();
  check("providers.list: 3 keys",                listKeys.length === 3);
  check("providers.list: alphabetical-ish",      listKeys[0] === "alpha");

  // .get retrieves spec
  check("providers.get: returns spec",           listOnly.get("alpha").default === "v");
  check("providers.get: missing returns null",   listOnly.get("ghost") === null);

  // ---- evaluate via spec.kind ----
  var providerWithKind = b.flag.providers.memory({
    flags: {
      "kind-flag": {
        default: "off",
        kind: "boolean",
        description: "Toggle for the kind-flag",
        tags: ["experimental"],
        variants: { off: false, on: true },
      },
    },
  });
  check("provider: spec retains description",    providerWithKind.get("kind-flag").description === "Toggle for the kind-flag");
  check("provider: spec retains tags",           providerWithKind.get("kind-flag").tags[0] === "experimental");
  check("provider: spec retains kind",           providerWithKind.get("kind-flag").kind === "boolean");

  // ---- providers throws on duplicate registration via _validateFlagSpec ----
  rejects("provider: rule with bad regex condition",
    function () {
      b.flag.providers.memory({
        flags: { x: { default: "off", variants: { off: false, on: true },
          rules: [{ variant: "on", conditions: [{ attribute: "x", op: "regex", value: "(unclosed" }] }] }, },
      });
    },
    /invalid regex/);

  // ---- bucketOf distribution sanity ----
  var bucket0 = b.flag.context.bucketOf("user-A", "flag-X");
  var bucket1 = b.flag.context.bucketOf("user-A", "flag-Y");
  check("bucket: different flag → different bucket (likely)",
                                                  bucket0 !== bucket1 || bucket0 === 0);

  // ---- weight on rules (operator hint, not enforced by evaluator) ----
  var weightedRules = t.validateRules([
    { variant: "v1", weight: 100, conditions: [{ attribute: "x", op: "exists", value: null }] },
  ]);
  check("rules: weight retained",                weightedRules[0].weight === 100);

  console.log("OK — flag tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
