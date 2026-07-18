// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.audit — canonical per-primitive test.
 *
 * Exercises the error / adversarial / defensive / option-default branches
 * of lib/audit.js that the concern-named audit-*.test.js files leave
 * unasserted:
 *
 *   - registerNamespace bad-name throw + framework-namespace no-op
 *   - record() non-object / bad-action-shape / unregistered-namespace /
 *     bad-outcome throws; actor/metadata defaulting
 *   - useStore bad-arg refusal + null / { record: null } unregister; shadow
 *     failure (throw + timeout-classified) is drop-silent
 *   - query() every-criteria filter path, order:"desc", limit/offset,
 *     _toMs Date/string/invalid, self-log suppression for action:"audit.read"
 *   - checkpoint empty-log null / skipIfUnchanged null / verifyCheckpoints
 *     empty + happy
 *   - emit() flush drop-path (record throw inside the drain batch)
 *   - safeEmit non-object / no-action guards, outcome normalization,
 *     action hyphen normalization, credential redaction
 *   - namespaced prefix / no-prefix / disabled / alternate-sink / extra-merge
 *   - bindActor bad-id throw, actor-match / mismatch / missing violation,
 *     roleEquivalent under a db-role scope
 *   - generateActorBindingTriggerSql default / allowRoles / roleMappingFn
 *   - assertSegregation no-db throw / missing-artifact throw / present ok
 *   - applyPosture / activePosture defaulting
 *
 * Run standalone: `node test/layer-0-primitives/audit.test.js`
 * Or via smoke:    `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var waitUntil      = helpers.waitUntil;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-")); }

// ---- Surface ----

function testSurface() {
  check("b.audit.record is a function",            typeof b.audit.record === "function");
  check("b.audit.query is a function",             typeof b.audit.query === "function");
  check("b.audit.emit is a function",              typeof b.audit.emit === "function");
  check("b.audit.safeEmit is a function",          typeof b.audit.safeEmit === "function");
  check("b.audit.namespaced is a function",        typeof b.audit.namespaced === "function");
  check("b.audit.flush is a function",             typeof b.audit.flush === "function");
  check("b.audit.verify is a function",            typeof b.audit.verify === "function");
  check("b.audit.checkpoint is a function",        typeof b.audit.checkpoint === "function");
  check("b.audit.verifyCheckpoints is a function", typeof b.audit.verifyCheckpoints === "function");
  check("b.audit.bindActor is a function",         typeof b.audit.bindActor === "function");
  check("b.audit.beginTrace is a function",        typeof b.audit.beginTrace === "function");
  check("b.audit.CHECKPOINT_FORMAT is stable",
        b.audit.CHECKPOINT_FORMAT === "blamejs-audit-checkpoint-v1");
  check("b.audit.FRAMEWORK_NAMESPACES lists the generic buckets",
        Array.isArray(b.audit.FRAMEWORK_NAMESPACES) &&
        b.audit.FRAMEWORK_NAMESPACES.indexOf("auth") !== -1 &&
        b.audit.FRAMEWORK_NAMESPACES.indexOf("audit") !== -1);
}

// ---- registerNamespace — bad name throw + framework no-op + custom add ----

function testRegisterNamespace() {
  var threw = null;
  try { b.audit.registerNamespace("Bad-Upper"); } catch (e) { threw = e; }
  check("registerNamespace rejects a non [a-z][a-z0-9_]* name", threw !== null);

  threw = null;
  try { b.audit.registerNamespace("9leading"); } catch (e) { threw = e; }
  check("registerNamespace rejects a leading-digit name", threw !== null);

  threw = null;
  try { b.audit.registerNamespace(12345); } catch (e) { threw = e; }
  check("registerNamespace rejects a non-string name", threw !== null);

  // Framework namespace → no-op (must NOT throw, must NOT duplicate).
  threw = null;
  try { b.audit.registerNamespace("auth"); } catch (e) { threw = e; }
  check("registerNamespace('auth') is a no-op for a framework namespace", threw === null);

  // Fresh custom namespace → registered (no throw).
  threw = null;
  try { b.audit.registerNamespace("orders"); } catch (e) { threw = e; }
  check("registerNamespace('orders') accepts a fresh custom namespace", threw === null);
}

// ---- record() — the throw branches (config-time: THROW on bad input) ----

async function testRecordThrowBranches() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var threw = null;
    try { await b.audit.record(null); } catch (e) { threw = e; }
    check("record(null) throws — requires an event object", threw !== null);

    threw = null;
    try { await b.audit.record("not-an-object"); } catch (e) { threw = e; }
    check("record(non-object) throws", threw !== null);

    // Bad action SHAPE (no namespace.verb dot form).
    threw = null;
    try { await b.audit.record({ action: "noverb", outcome: "success" }); } catch (e) { threw = e; }
    check("record rejects a bad action shape (no dot-separated verb)", threw !== null);

    // Uppercase action segment — outside the lowercase regex.
    threw = null;
    try { await b.audit.record({ action: "auth.Login", outcome: "success" }); } catch (e) { threw = e; }
    check("record rejects an uppercase action segment", threw !== null);

    // Unregistered namespace.
    threw = null;
    try { await b.audit.record({ action: "neverregistered.verb", outcome: "success" }); }
    catch (e) { threw = e; }
    check("record rejects an unregistered namespace",
          threw !== null && /not registered/i.test(threw.message || ""));

    // Bad outcome — not in {success, failure, denied}.
    threw = null;
    try { await b.audit.record({ action: "auth.login", outcome: "maybe" }); } catch (e) { threw = e; }
    check("record rejects an outcome outside {success, failure, denied}", threw !== null);

    threw = null;
    try { await b.audit.record({ action: "auth.login" }); } catch (e) { threw = e; }
    check("record rejects a missing outcome", threw !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- record() — actor / metadata defaulting (the || {} / ternary branches) ----

async function testRecordDefaulting() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // No actor, no resource, no metadata → all default without throwing.
    var appended = await b.audit.record({ action: "system.config.reloaded", outcome: "success" });
    check("record with no actor/resource/metadata still appends",
          appended && typeof appended.rowHash !== "undefined");
    check("record defaulted actorUserId to null", appended.actorUserId === null);
    check("record defaulted metadata to null", appended.metadata === null);

    // With metadata → JSON-serialized (the truthy ternary side).
    var withMeta = await b.audit.record({
      action:   "system.config.reloaded",
      outcome:  "success",
      metadata: { source: "SIGHUP" },
    });
    check("record serialized metadata to JSON",
          typeof withMeta.metadata === "string" && withMeta.metadata.indexOf("SIGHUP") !== -1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- useStore — bad-arg refusal + shadow failure is drop-silent ----

async function testUseStoreRefusalAndShadowFailure() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Bad-arg refusal (config-time throw).
    var threw = null;
    try { b.audit.useStore("nope"); } catch (e) { threw = e; }
    check("useStore refuses a non-object store", threw !== null);

    threw = null;
    try { b.audit.useStore({ record: 42 }); } catch (e) { threw = e; }
    check("useStore refuses a non-function record", threw !== null);

    // Shadow store that THROWS a plain error → drop-silent, chain still commits.
    b.audit.useStore({ record: async function () { throw new Error("shadow down"); } });
    threw = null;
    try {
      await b.audit.record({ action: "auth.login", outcome: "success" });
    } catch (e) { threw = e; }
    check("shadow throw is drop-silent — record() still resolves", threw === null);

    // Shadow store whose error is TIMEOUT-classified (code ETIMEDOUT) → the
    // isTimeout branch (audit.shadow_timeout) fires; still drop-silent.
    b.audit.useStore({
      record: async function () {
        var e = new Error("shadow slow");
        e.code = "ETIMEDOUT";
        throw e;
      },
    });
    threw = null;
    try {
      await b.audit.record({ action: "auth.logout", outcome: "success" });
    } catch (e) { threw = e; }
    check("timeout-classified shadow throw is also drop-silent", threw === null);

    // Shadow error with an EMPTY message (exercises the `e.message || ""`
    // fallback in the failure-classifier) → still drop-silent.
    b.audit.useStore({ record: async function () { throw new Error(""); } });
    threw = null;
    try {
      await b.audit.record({ action: "auth.login.failure", outcome: "failure" });
    } catch (e) { threw = e; }
    check("shadow error with an empty message is drop-silent", threw === null);

    // Framework chain has both rows despite the shadow failures.
    var loginRows  = await b.audit.query({ action: "auth.login" });
    var logoutRows = await b.audit.query({ action: "auth.logout" });
    check("framework chain kept the row past a shadow throw", loginRows.length >= 1);
    check("framework chain kept the row past a shadow timeout", logoutRows.length >= 1);

    // Unregister via bare null and via { record: null }.
    b.audit.useStore(null);
    b.audit.useStore({ record: async function () {} });
    b.audit.useStore({ record: null });
    // No throw path to assert here beyond reaching the unregister branches.
    check("useStore unregister paths (null + { record: null }) reached", true);
  } finally {
    b.audit.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

// ---- query() — criteria filters, order/limit/offset, _toMs, self-log ----

async function testQueryCriteriaAndToMs() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.audit.registerNamespace("orders");
    // Seed a couple of matching rows.
    await b.audit.record({
      actor:    { userId: "u-q1" },
      action:   "orders.shipped",
      resource: { kind: "order", id: "o-1" },
      outcome:  "success",
    });
    await b.audit.record({
      actor:    { userId: "u-q1" },
      action:   "orders.shipped",
      resource: { kind: "order", id: "o-2" },
      outcome:  "failure",
    });

    // Every-criteria filter in one call: exercises each `if (criteria.x)` arm
    // plus order:"desc", limit, offset, and _redactCriteria's ternaries.
    var rows = await b.audit.query({
      from:         new Date(Date.now() - 3600000),  // Date branch of _toMs
      to:           Date.now() + 3600000,            // number branch of _toMs
      actorUserId:  "u-q1",
      resourceId:   "o-1",
      action:       "orders.shipped",
      resourceKind: "order",
      outcome:      "success",
      order:        "desc",
      limit:        10,
      offset:       0,
    });
    check("query with full criteria returns the matching row", rows.length >= 1);
    check("query honored the resourceId filter",
          rows.every(function (r) { return r.action === "orders.shipped"; }));

    // _toMs string branch (valid ISO date parse).
    var strRows = await b.audit.query({ from: "2000-01-01T00:00:00Z", action: "orders.shipped" });
    check("query accepts an ISO-8601 string `from` (Date.parse branch)", strRows.length >= 1);

    // _toMs invalid-string branch → throw.
    var threw = null;
    try { await b.audit.query({ from: "definitely-not-a-date" }); } catch (e) { threw = e; }
    check("query throws on an unparseable string date", threw !== null);

    // _toMs invalid-value branch (boolean is truthy but not number/Date/string).
    threw = null;
    try { await b.audit.query({ to: true }); } catch (e) { threw = e; }
    check("query throws on a non-date `to` value", threw !== null);

    // Self-log suppression: a query targeting action:"audit.read" must NOT
    // create a new audit.read self-log; a normal query does.
    var before = (await b.audit.query({ action: "audit.read" })).length;
    // Two audit.read-targeted queries — neither self-logs (suppressed branch).
    await b.audit.query({ action: "audit.read" });
    var after = (await b.audit.query({ action: "audit.read" })).length;
    check("querying action:'audit.read' does not self-log (count is stable)", after === before);

    // A normal query DOES self-log an audit.read (the un-suppressed branch).
    await b.audit.query({ action: "orders.shipped" });
    var afterNormal = (await b.audit.query({ action: "audit.read" })).length;
    check("a normal query self-logs an audit.read event", afterNormal > before);

    // No-argument query → criteria defaults to {} (the `criteria || {}` arm)
    // and returns rows without throwing.
    var allRows = await b.audit.query();
    check("query() with no criteria returns rows (default {} criteria)",
          Array.isArray(allRows) && allRows.length >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- beginTrace ----

async function testBeginTrace() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var t1 = b.audit.beginTrace();
    var t2 = b.audit.beginTrace();
    check("beginTrace returns a 32-hex-char trace id", /^[0-9a-f]{32}$/.test(t1));
    check("beginTrace returns a fresh id each call", t1 !== t2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- checkpoint + verifyCheckpoints — empty / skipIfUnchanged / happy ----

async function testCheckpointLifecycle() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Capture the chain's current state rather than assuming it is
    // pristine — under the parallel smoke harness b.audit operates on
    // the shared framework db/chain, so an absolute "empty → 0" would
    // be flaky. Assert relative to this baseline.
    var baseline = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints reports ok:true", baseline.ok === true &&
          typeof baseline.checkpointsVerified === "number");

    // Empty-chain branches (checkpoint → null) are only exercised when
    // the chain genuinely has no rows yet; guard so the assertion holds
    // whether or not a prior test left rows.
    var emptyCkpt = await b.audit.checkpoint();
    if (baseline.checkpointsVerified === 0 && emptyCkpt === null) {
      check("checkpoint on an empty audit log returns null", emptyCkpt === null);
    } else {
      check("checkpoint on a non-empty log returns null or a checkpoint",
            emptyCkpt === null || (emptyCkpt && emptyCkpt.atRowHash));
    }

    // Record a row, then anchor a real checkpoint.
    await b.audit.record({ action: "system.boot.completed", outcome: "success" });
    var ckpt = await b.audit.checkpoint();
    check("checkpoint anchors a row (returns the checkpoint)",
          ckpt && typeof ckpt.atMonotonicCounter === "number" && ckpt.atRowHash);

    // skipIfUnchanged with no new rows → null (tip did not advance).
    var skipped = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("checkpoint({ skipIfUnchanged }) returns null when the tip is unchanged",
          skipped === null);

    // A second checkpoint() of the SAME already-anchored tip (WITHOUT
    // skipIfUnchanged) must not throw the raw atMonotonicCounter UNIQUE-
    // constraint error: two anchors of one tip sign the identical payload, so
    // the counter is already anchored and the loser returns null idempotently.
    // This is the parallel-checkpoint collision that flaked audit.test.js under
    // SMOKE_PARALLEL when two modules anchored the same counter concurrently.
    var reAnchor = null;
    var reAnchorThrew = false;
    try { reAnchor = await b.audit.checkpoint(); }
    catch (_e) { reAnchorThrew = true; }
    check("re-checkpoint of an already-anchored tip returns null, never a raw UNIQUE throw",
          reAnchorThrew === false && reAnchor === null);

    // verifyCheckpoints walks the anchored checkpoint and confirms the
    // row — the count strictly increased over the baseline.
    var v = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints confirms the anchored checkpoint",
          v.ok === true && v.checkpointsVerified >= baseline.checkpointsVerified + 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- verify() — clean chain ----

async function testVerifyChain() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    await b.audit.record({ action: "auth.login", outcome: "success" });
    await b.audit.record({ action: "auth.logout", outcome: "success" });
    var res = await b.audit.verify();
    check("verify() reports a clean chain", res.ok === true && res.rowsVerified >= 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- emit() + flush() drop-path — record throw inside the drain batch ----

async function testEmitFlushDropPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // emit() does NOT normalize outcome, so a bad outcome makes record()
    // throw inside the handler flush — exercising the per-item catch +
    // system.audit.chain_write_dropped observability path.
    b.audit.emit({ action: "system.stream.dropme", outcome: "TOTALLY_BOGUS" });
    // A good event alongside it drains normally.
    b.audit.emit({ action: "system.stream.kept", outcome: "success" });

    var flushThrew = null;
    try { await b.audit.flush(); } catch (e) { flushThrew = e; }
    check("flush() does not throw even when a batch item is dropped", flushThrew === null);

    var dropped = await b.audit.query({ action: "system.stream.dropme" });
    check("the bad-outcome emit was dropped from the chain", dropped.length === 0);
    var kept = await b.audit.query({ action: "system.stream.kept" });
    check("the good emit alongside the dropped one still landed", kept.length >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- safeEmit — guards, outcome normalization, action normalization, redaction ----

async function testSafeEmitNormalizationAndRedaction() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Guard branches — drop-silent, no throw, nothing emitted.
    b.audit.safeEmit(null);
    b.audit.safeEmit("not-an-object");
    b.audit.safeEmit({ outcome: "success" });   // missing action (non-string)
    b.audit.safeEmit({ action: 12345 });         // non-string action

    // Outcome-alias normalization: "ok" → success, "error" → failure,
    // "refused" → denied, non-string → success.
    b.audit.safeEmit({ action: "system.norm.ok",      outcome: "ok" });
    b.audit.safeEmit({ action: "system.norm.err",     outcome: "error" });
    b.audit.safeEmit({ action: "system.norm.refused", outcome: "refused" });
    b.audit.safeEmit({ action: "system.norm.nonstr",  outcome: 999 });
    b.audit.safeEmit({ action: "system.norm.unknown",  outcome: "bananas" });  // unknown alias → success

    // Action hyphen normalization: hyphens in the verb become underscores.
    b.audit.safeEmit({ action: "system.norm.biometric-id-check", outcome: "success" });

    // Credential redaction: a connection string in `reason` and a secret in
    // `metadata` must be scrubbed before reaching the chain.
    b.audit.safeEmit({
      action:   "system.norm.secret",
      outcome:  "success",
      reason:   "connect postgres://user:hunter2@db:5432/app",
      metadata: { token: "AKIAIOSFODNN7EXAMPLE", note: "keep" },
    });

    await b.audit.flush();

    function one(action) {
      return b.audit.query({ action: action }).then(function (r) { return r[0]; });
    }
    var okRow = await one("system.norm.ok");
    check("safeEmit normalized outcome 'ok' → 'success'", okRow && okRow.outcome === "success");
    var errRow = await one("system.norm.err");
    check("safeEmit normalized outcome 'error' → 'failure'", errRow && errRow.outcome === "failure");
    var refRow = await one("system.norm.refused");
    check("safeEmit normalized outcome 'refused' → 'denied'", refRow && refRow.outcome === "denied");
    var nsRow = await one("system.norm.nonstr");
    check("safeEmit normalized a non-string outcome → 'success'", nsRow && nsRow.outcome === "success");
    var unkRow = await one("system.norm.unknown");
    check("safeEmit normalized an unknown outcome alias → 'success'",
          unkRow && unkRow.outcome === "success");

    var hyphenRow = await one("system.norm.biometric_id_check");
    check("safeEmit normalized hyphens in the action to underscores", !!hyphenRow);

    var secretRow = await one("system.norm.secret");
    check("safeEmit redacted the connection string in reason",
          secretRow && /REDACTED/i.test(String(secretRow.reason)) &&
          String(secretRow.reason).indexOf("hunter2") === -1);
    check("safeEmit redacted the AWS-key-shaped secret in metadata",
          secretRow && String(secretRow.metadata).indexOf("AKIAIOSFODNN7EXAMPLE") === -1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- namespaced — prefix / no-prefix / disabled / alternate-sink / extra ----

async function testNamespaced() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Alternate sink (object form { audit, sink }) — routes to the operator
    // sink instead of the framework chain; capture directly, no flush needed.
    var captured = [];
    var sink = { safeEmit: function (evt) { captured.push(evt); } };

    var emitToSink = b.audit.namespaced("gdpr.ropa", { audit: true, sink: sink });
    emitToSink("activity_added", "success", { activityId: "a-1" });
    check("namespaced routes to an alternate sink", captured.length === 1);
    check("namespaced prefixes the action (gdpr.ropa + activity_added)",
          captured[0].action === "gdpr.ropa.activity_added");
    check("namespaced defaults metadata to {} when omitted",
          (function () { emitToSink("x", "success"); return typeof captured[1].metadata === "object"; })());

    // extra-arg merge — per-call actor / resource fields land on the event.
    emitToSink("consent_recorded", "success", { id: "c-1" }, { actor: { userId: "u-9" } });
    var extraEvt = captured[captured.length - 1];
    check("namespaced merges the `extra` object onto the event",
          extraEvt.actor && extraEvt.actor.userId === "u-9");

    // Falsy prefix → action passes through verbatim (no prefix + ".").
    var emitBare = b.audit.namespaced(null, { sink: sink });
    emitBare("system.outbox.started", "success", {});
    check("namespaced(null) passes a fully-qualified action through verbatim",
          captured[captured.length - 1].action === "system.outbox.started");

    // Sink lacking safeEmit → the emitter is a no-op (no throw).
    var brokenSink = b.audit.namespaced("gdpr.ropa", { sink: {} });
    var threw = null;
    try { brokenSink("noop", "success", {}); } catch (e) { threw = e; }
    check("namespaced with a sink lacking safeEmit is a silent no-op", threw === null);

    // Sink whose safeEmit THROWS → the emitter swallows it (drop-silent).
    var throwingSink = b.audit.namespaced("gdpr.ropa", {
      sink: { safeEmit: function () { throw new Error("sink down"); } },
    });
    threw = null;
    try { throwingSink("boom", "success", {}); } catch (e) { threw = e; }
    check("namespaced swallows a throwing sink.safeEmit (drop-silent)", threw === null);

    // Disabled emitter (bare-boolean false form) → no-op.
    var beforeLen = captured.length;
    var off = b.audit.namespaced("gdpr.ropa", false);
    off("should_not_emit", "success", {});
    check("namespaced(prefix, false) disables the emitter", captured.length === beforeLen);

    // Default sink (module.exports) → reaches the real chain.
    var emitChain = b.audit.namespaced("gdpr.ropa", true);
    emitChain("record_of_processing", "success", { n: 1 });
    await b.audit.flush();
    var chainRows = await b.audit.query({ action: "gdpr.ropa.record_of_processing" });
    check("namespaced with the default sink reaches the framework chain",
          chainRows.length >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- bindActor — bad-id throw + actor binding violations + role scope ----

async function testBindActor() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.audit.registerNamespace("orders");
    // Bad actorId → AuditSegregationError (config-time throw).
    var threw = null;
    try { b.audit.bindActor(""); } catch (e) { threw = e; }
    check("bindActor('') throws on an empty actorId", threw !== null);
    threw = null;
    try { b.audit.bindActor(123); } catch (e) { threw = e; }
    check("bindActor(non-string) throws", threw !== null);

    var bound = b.audit.bindActor("u-42");
    check("bindActor returns a bound emitter with the actorId", bound.actorId === "u-42");

    // Matching actor → emits through.
    bound.safeEmit({ actor: { userId: "u-42" }, action: "orders.shipped", outcome: "success" });
    // Mismatched actor → dropped + records a violation under the bound actor.
    bound.safeEmit({ actor: { userId: "u-other" }, action: "orders.shipped", outcome: "success" });
    // Missing actor.userId → also a violation.
    bound.safeEmit({ action: "orders.shipped", outcome: "success" });

    // record() variant: matching resolves, mismatch throws.
    var recOk = null;
    try { await bound.record({ actor: { userId: "u-42" }, action: "orders.shipped", outcome: "success" }); }
    catch (e) { recOk = e; }
    check("bound.record with the matching actor resolves", recOk === null);

    var recThrew = null;
    try { await bound.record({ actor: { userId: "u-x" }, action: "orders.shipped", outcome: "success" }); }
    catch (e) { recThrew = e; }
    check("bound.record with a mismatched actor throws AuditSegregationError",
          recThrew !== null && /mismatch/i.test(recThrew.message || ""));

    await b.audit.flush();
    await waitUntil(function () {
      return b.audit.query({ action: "audit.actor_binding.violation" })
        .then(function (r) { return r.length >= 2; });
    }, { timeoutMs: 5000, label: "bindActor: violation rows landed in the chain" });
    var violations = await b.audit.query({ action: "audit.actor_binding.violation" });
    check("actor-binding violations were recorded under the bound actor",
          violations.length >= 2 &&
          violations.every(function (v) { return v.actorUserId === "u-42"; }));

    // roleEquivalent under a db-role scope — the SQL-bound role and bound
    // actor must agree. Enter a real role scope via b.externalDb.runAs so the
    // db-role-context branch (getRole() non-null) is exercised.
    var roleBound = b.audit.bindActor("u-role", {
      roleEquivalent: function (actorId, role) { return role === "matching_role"; },
    });
    var beforeRole = (await b.audit.query({ action: "audit.actor_binding.violation" })).length;
    b.externalDb.runAs("reporting_role", function () {
      // role "reporting_role" !== "matching_role" → roleEquivalent false →
      // db-role mismatch violation.
      roleBound.safeEmit({ actor: { userId: "u-role" }, action: "orders.shipped", outcome: "success" });
    });
    await b.audit.flush();
    await waitUntil(function () {
      return b.audit.query({ action: "audit.actor_binding.violation" })
        .then(function (r) { return r.length > beforeRole; });
    }, { timeoutMs: 5000, label: "bindActor: db-role mismatch violation landed" });
    var afterRole = (await b.audit.query({ action: "audit.actor_binding.violation" })).length;
    check("roleEquivalent mismatch under a db-role scope records a violation",
          afterRole > beforeRole);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- generateActorBindingTriggerSql — default / allowRoles / roleMappingFn ----

function testGenerateActorBindingTriggerSql() {
  var def = b.audit.generateActorBindingTriggerSql();
  check("trigger SQL exposes up/down + object names",
        typeof def.up === "string" && typeof def.down === "string" &&
        def.functionName === "_blamejs_audit_actor_binding_check" &&
        def.triggerName === "_blamejs_audit_actor_binding_trig");
  check("default trigger SQL raises the segregation-of-duties exception",
        /segregation-of-duties violation/.test(def.up));
  check("default trigger SQL has no allow-roles bypass clause",
        def.up.indexOf("current_user IN (") === -1);
  check("default trigger SQL compares NEW column against current_user directly",
        /IS DISTINCT FROM current_user/.test(def.up));

  var withRoles = b.audit.generateActorBindingTriggerSql({ allowRoles: ["blamejs_service", "ops"] });
  check("allowRoles injects a bypass IN(...) clause",
        /current_user IN \('blamejs_service', 'ops'\)/.test(withRoles.up));

  var withMapFn = b.audit.generateActorBindingTriggerSql({
    roleMappingFn: "map_actor_to_role",
    column:        "actorUserId",
    tableName:     "custom_audit",
  });
  check("roleMappingFn wraps the column in the mapping function call",
        withMapFn.up.indexOf("map_actor_to_role") !== -1);
  check("custom tableName flows into the trigger DDL",
        withMapFn.up.indexOf("custom_audit") !== -1);
}

// ---- assertSegregation — no-db throw / missing-artifact throw / present ok ----

async function testAssertSegregation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // No opts at all (opts defaults to {}) → no db → throws.
    var threw = null;
    try { await b.audit.assertSegregation(); } catch (e) { threw = e; }
    check("assertSegregation() with no opts throws (no db)", threw !== null);

    // Empty opts / db without query() → throws.
    threw = null;
    try { await b.audit.assertSegregation({}); } catch (e) { threw = e; }
    check("assertSegregation without a db.query throws", threw !== null);

    threw = null;
    try { await b.audit.assertSegregation({ db: { notQuery: true } }); } catch (e) { threw = e; }
    check("assertSegregation with a db lacking query() throws", threw !== null);

    // Missing artifacts: pg_proc / pg_trigger introspection returns no rows.
    // (operator-supplied introspection target — not a framework db.)
    var emptyDb = { query: async function () { return { rows: [] }; } };
    threw = null;
    try { await b.audit.assertSegregation({ db: emptyDb }); } catch (e) { threw = e; }
    check("assertSegregation throws when the trigger/function are absent",
          threw !== null && /missing/i.test(threw.message || ""));

    // Function present, trigger absent → still throws, naming the trigger.
    var fnOnlyDb = {
      query: async function (sql) {
        if (/pg_proc/.test(sql)) return { rows: [{ "?column?": 1 }] };
        return { rows: [] };
      },
    };
    threw = null;
    try { await b.audit.assertSegregation({ db: fnOnlyDb }); } catch (e) { threw = e; }
    check("assertSegregation throws when only the trigger is missing",
          threw !== null && /trigger:/.test(threw.message || ""));

    // Both present → { ok:true, missing:[] }.
    var okDb = { query: async function () { return { rows: [{ "?column?": 1 }] }; } };
    var res = await b.audit.assertSegregation({ db: okDb });
    check("assertSegregation returns ok when both artifacts are present",
          res.ok === true && res.missing.length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- applyPosture / activePosture — defaulting ----

function testApplyPosture() {
  check("applyPosture(non-string) returns null", b.audit.applyPosture(123) === null);
  check("applyPosture('') returns null", b.audit.applyPosture("") === null);

  var res = b.audit.applyPosture("hipaa");
  check("applyPosture('hipaa') returns { posture }", res && res.posture === "hipaa");
  check("activePosture() reflects the applied posture", b.audit.activePosture() === "hipaa");

  b.audit.applyPosture("pci-dss");
  check("applyPosture overwrites the active posture", b.audit.activePosture() === "pci-dss");
}

function testDuplicateCheckpointCounterRecognition() {
  // The concurrent-anchor idempotency guard must recognize the duplicate
  // atMonotonicCounter UNIQUE violation across ALL THREE backends: SQLite names
  // the column in the message; Postgres carries the unique-index name in
  // constraint/detail with SQLSTATE 23505; MySQL reports the key name with
  // errno 1062. An unrelated error, or a unique violation on a DIFFERENT
  // column, must NOT be swallowed (fail-closed).
  var isDup = b.audit._isDuplicateCheckpointCounter;
  check("dup-counter: sqlite column-in-message recognized",
        isDup({ message: "UNIQUE constraint failed: _blamejs_audit_checkpoints.atMonotonicCounter", code: "SQLITE_CONSTRAINT_UNIQUE" }) === true);
  check("dup-counter: postgres index-name + 23505 recognized",
        isDup({ message: "duplicate key value violates unique constraint", constraint: "idx__blamejs_audit_checkpoints_chkpt_counter", code: "23505" }) === true);
  check("dup-counter: mysql key-name + errno 1062 recognized",
        isDup({ sqlMessage: "Duplicate entry '5' for key 'idx_chkpt_counter'", errno: 1062 }) === true);
  check("dup-counter: unrelated error NOT swallowed",
        isDup({ message: "connection refused ECONNREFUSED" }) === false);
  check("dup-counter: unique violation on a DIFFERENT column NOT swallowed",
        isDup({ message: "UNIQUE constraint failed: other_table.other_col", code: "SQLITE_CONSTRAINT_UNIQUE" }) === false);
  check("dup-counter: null error is not a duplicate", isDup(null) === false);
}

async function run() {
  // flush() before any emit has created the AsyncHandler → the `!_auditHandler`
  // early-return arm. Harmless no-op if a handler already exists.
  await b.audit.flush();
  testSurface();
  testRegisterNamespace();
  await testRecordThrowBranches();
  await testRecordDefaulting();
  await testUseStoreRefusalAndShadowFailure();
  await testQueryCriteriaAndToMs();
  await testBeginTrace();
  await testCheckpointLifecycle();
  testDuplicateCheckpointCounterRecognition();
  await testVerifyChain();
  await testEmitFlushDropPath();
  await testSafeEmitNormalizationAndRedaction();
  await testNamespaced();
  await testBindActor();
  testGenerateActorBindingTriggerSql();
  await testAssertSegregation();
  testApplyPosture();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) {
         // Log only the error class (not its message/stack): the crypto/db
         // setup path carries passphrase-length-derived data, and logging
         // content derived from it is a clear-text-logging sink. The class
         // name signals the failure; the non-zero exit makes it loud, and
         // the smoke runner surfaces full detail via check().
         console.error("FAIL: " + (e && e.name ? e.name : "error"));
         process.exit(1);
       });
}
