// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ddlChangeControl — formal DDL approval / change-control workflow.
 */

var fs   = require("fs");
var os   = require("os");
var path = require("path");

var helpers        = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _fakeAudit() {
  var emitted = [];
  return {
    safeEmit: function (event) { emitted.push(event); },
    _emitted: emitted,
  };
}

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ddlcc-")); }

function testSurface() {
  check("ddlChangeControl.create is a function",
        typeof b.ddlChangeControl.create === "function");
  check("STATES.PROPOSED",  b.ddlChangeControl.STATES.PROPOSED  === "proposed");
  check("STATES.APPROVED",  b.ddlChangeControl.STATES.APPROVED  === "approved");
  check("STATES.APPLIED",   b.ddlChangeControl.STATES.APPLIED   === "applied");
  check("STATES.REJECTED",  b.ddlChangeControl.STATES.REJECTED  === "rejected");
  check("STATES.FAILED",    b.ddlChangeControl.STATES.FAILED    === "failed");
  check("POSTURES_REQUIRING_CHANGE_CONTROL lists sox-404",
        b.ddlChangeControl.POSTURES_REQUIRING_CHANGE_CONTROL.indexOf("sox-404") !== -1);
  check("frameworkError.DdlChangeControlError exposed",
        typeof b.frameworkError.DdlChangeControlError === "function");
  check("ddlChangeControl.DdlChangeControlError is fn",
        typeof b.ddlChangeControl.DdlChangeControlError === "function");
}

async function testProposeApproveApply() {
  var fakeAudit = _fakeAudit();
  var ddl = b.ddlChangeControl.create({
    audit:     fakeAudit,
    approvers: 2,
  });
  var prop = await ddl.propose("ALTER TABLE x ADD COLUMN y TEXT", {
    proposer: "alice",
    reason:   "feature-A",
  });
  check("propose returns changeId + sqlHash",
        typeof prop.changeId === "string" && typeof prop.sqlHash === "string");
  check("ddl.change.proposed audit emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "ddl.change.proposed"; }));

  var rv1 = await ddl.approve(prop.changeId, "bob");
  check("first approval count = 1, threshold not met",
        rv1.signaturesCount === 1 && rv1.thresholdMet === false);
  var rv2 = await ddl.approve(prop.changeId, "carol");
  check("second approval count = 2, threshold met",
        rv2.signaturesCount === 2 && rv2.thresholdMet === true);

  var ranSql = null;
  var apply = await ddl.applyApproved(prop.changeId, async function (sql) {
    ranSql = sql; return { ok: true };
  });
  check("applyApproved ran the SQL",
        ranSql === "ALTER TABLE x ADD COLUMN y TEXT");
  check("applyApproved returns result",
        apply.result && apply.result.ok === true);
  check("ddl.change.applied audit emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "ddl.change.applied"; }));
}

async function testInsufficientApprovals() {
  var ddl = b.ddlChangeControl.create({
    audit:     _fakeAudit(),
    approvers: 2,
  });
  var prop = await ddl.propose("ALTER TABLE x ADD COLUMN y TEXT", {
    proposer: "alice",
  });
  await ddl.approve(prop.changeId, "bob");
  var threw = null;
  try {
    await ddl.applyApproved(prop.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("insufficient approvals refuse apply",
        threw && /insufficient-approvals/.test(threw.code || ""));
}

async function testSelfApprovalUnderPosture() {
  var ddl = b.ddlChangeControl.create({
    audit:     _fakeAudit(),
    approvers: 2,
    posture:   "sox-404",
  });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  var threw = null;
  try { await ddl.approve(prop.changeId, "alice"); } catch (e) { threw = e; }
  check("self-approval denied under sox-404",
        threw && /self-approval-denied/.test(threw.code || ""));
}

async function testDuplicateApproval() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.approve(prop.changeId, "bob");
  var threw = null;
  try { await ddl.approve(prop.changeId, "bob"); } catch (e) { threw = e; }
  check("duplicate approval refused",
        threw && /duplicate-approval/.test(threw.code || ""));
}

async function testRejectThenApply() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.reject(prop.changeId, "reviewer", "not safe");
  var threw = null;
  try {
    await ddl.applyApproved(prop.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("apply after reject refused",
        threw && /already-rejected/.test(threw.code || ""));
}

function testWindowSpecParsing() {
  var fakeAudit = _fakeAudit();
  // Should parse:
  var ddl1 = b.ddlChangeControl.create({
    audit: fakeAudit, approvers: 1, windowSpec: "always",
  });
  check("always window OK", ddl1.windowSpec === "always");
  var ddl2 = b.ddlChangeControl.create({
    audit: fakeAudit, approvers: 1, windowSpec: "Mon-Fri 09:00-17:00 UTC",
  });
  check("Mon-Fri 09-17 window OK", ddl2.windowSpec === "Mon-Fri 09:00-17:00 UTC");

  // Bad input throws
  var threw = null;
  try {
    b.ddlChangeControl.create({
      audit: fakeAudit, approvers: 1, windowSpec: "Mon 09:00-17:00 EST",
    });
  } catch (e) { threw = e; }
  check("non-UTC window refused",
        threw && /bad-window/.test(threw.code || ""));
}

async function testSqlTamperRefused() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.approve(prop.changeId, "bob");
  // Tamper the stored SQL via b.ddlChangeControl get + manual edit:
  // Without an exposed mutator, simulate by creating a second instance
  // sharing a custom store and tampering directly.
  var byId = new Map();
  var customStore = {
    get: function (id) { return byId.get(id) || null; },
    put: function (id, c) { byId.set(id, c); },
    list: function () { return Array.from(byId.values()); },
  };
  var ddl2 = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, store: customStore,
  });
  var prop2 = await ddl2.propose("ORIGINAL", { proposer: "p" });
  await ddl2.approve(prop2.changeId, "bob");
  // Tamper:
  var raw = customStore.get(prop2.changeId);
  raw.sql = "EVIL";
  customStore.put(prop2.changeId, raw);
  var threw = null;
  try {
    await ddl2.applyApproved(prop2.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("sql tamper refused",
        threw && /sql-tampered/.test(threw.code || ""));
}

// ---- error / adversarial / default branches added for coverage ----

function _codeOf(fn) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  return threw ? (threw.code || "") : null;
}

async function _asyncCode(fn) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  return threw ? (threw.code || "") : null;
}

function testCreateOptionValidation() {
  // approvers must be a positive integer.
  check("approvers=0 rejected", /bad-approvers/.test(_codeOf(function () {
    b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 0 });
  })));
  check("approvers=NaN rejected", /bad-approvers/.test(_codeOf(function () {
    b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: NaN });
  })));
  check("approvers non-number rejected", /bad-approvers/.test(_codeOf(function () {
    b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: "two" });
  })));
  // approvers floored to an integer.
  var ddlFloor = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 3.9 });
  check("fractional approvers floored", ddlFloor.approvers === 3);

  // SOX / PCI posture forces approvers >= 2.
  check("pci-dss + approvers=1 rejected", /insufficient-approvers/.test(_codeOf(function () {
    b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1, posture: "pci-dss" });
  })));
  check("sox + approvers=1 rejected", /insufficient-approvers/.test(_codeOf(function () {
    b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1, posture: "sox" });
  })));
}

function testWindowSpecGrammarErrors() {
  function bad(spec) {
    return _codeOf(function () {
      b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1, windowSpec: spec });
    });
  }
  // Non-string but truthy value reaches the parser.
  check("numeric windowSpec rejected", /bad-window/.test(bad(42)));
  // Wrong field count (missing UTC token).
  check("two-token windowSpec rejected", /bad-window/.test(bad("Mon 09:00-17:00")));
  // Malformed day-range.
  check("A-B-C day range rejected", /bad-window/.test(bad("Mon-Tue-Wed 09:00-17:00 UTC")));
  check("unknown day in range rejected", /bad-window/.test(bad("Xxx-Fri 09:00-17:00 UTC")));
  // Malformed single day.
  check("unknown single day rejected", /bad-window/.test(bad("Xyz 09:00-17:00 UTC")));
  // Hour-range shape errors.
  check("hour-range missing dash rejected", /bad-window/.test(bad("Wed 09:00 UTC")));
  check("non-two-digit hour rejected", /bad-window/.test(bad("Wed 9:00-17:00 UTC")));
  check("hour out of range rejected", /bad-window/.test(bad("Wed 25:00-26:00 UTC")));
  check("start >= end rejected", /bad-window/.test(bad("Wed 17:00-09:00 UTC")));
}

function testWindowSpecReverseAndSingleDay() {
  // Reverse day-range wraps across the week (Fri..Sat..Sun..Mon).
  var ddlRev = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, windowSpec: "Fri-Mon 09:00-17:00 UTC",
  });
  check("reverse day-range parses", ddlRev.windowSpec === "Fri-Mon 09:00-17:00 UTC");
  // Comma list mixing a single day and a forward range.
  var ddlMix = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, windowSpec: "Wed,Fri-Sat 10:00-12:00 UTC",
  });
  check("single-day + range comma list parses",
        ddlMix.windowSpec === "Wed,Fri-Sat 10:00-12:00 UTC");
}

async function testProposeValidation() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  check("empty sql rejected", /bad-sql/.test(await _asyncCode(function () {
    return ddl.propose("", { proposer: "alice" });
  })));
  check("non-string sql rejected", /bad-sql/.test(await _asyncCode(function () {
    return ddl.propose(123, { proposer: "alice" });
  })));
  check("missing proposer rejected", /missing-proposer/.test(await _asyncCode(function () {
    return ddl.propose("ALTER TABLE x ADD y TEXT", {});
  })));
  check("empty proposer rejected", /missing-proposer/.test(await _asyncCode(function () {
    return ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "" });
  })));
}

async function testApproveValidation() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });

  check("approve empty changeId rejected", /bad-id/.test(await _asyncCode(function () {
    return ddl.approve("", "bob");
  })));
  check("approve empty approver rejected", /missing-approver/.test(await _asyncCode(function () {
    return ddl.approve(prop.changeId, "");
  })));
  check("approve unknown change rejected", /unknown-change/.test(await _asyncCode(function () {
    return ddl.approve("does-not-exist", "bob");
  })));

  // already-rejected branch.
  var rejd = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
  var pr = await rejd.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await rejd.reject(pr.changeId, "reviewer", "no");
  check("approve of rejected change refused", /already-rejected/.test(await _asyncCode(function () {
    return rejd.approve(pr.changeId, "bob");
  })));

  // already-applied branch (approvers:1 so one approval + apply completes).
  var app = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var pa = await app.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await app.approve(pa.changeId, "bob");
  await app.applyApproved(pa.changeId, async function () { return { ok: true }; });
  check("approve of applied change refused", /already-applied/.test(await _asyncCode(function () {
    return app.approve(pa.changeId, "carol");
  })));
}

async function testRejectValidation() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });

  check("reject empty changeId rejected", /bad-id/.test(await _asyncCode(function () {
    return ddl.reject("", "reviewer", "reason");
  })));
  check("reject empty reviewer rejected", /missing-reviewer/.test(await _asyncCode(function () {
    return ddl.reject(prop.changeId, "", "reason");
  })));
  check("reject unknown change rejected", /unknown-change/.test(await _asyncCode(function () {
    return ddl.reject("nope", "reviewer", "reason");
  })));

  // reject after apply -> already-applied.
  await ddl.approve(prop.changeId, "bob");
  await ddl.applyApproved(prop.changeId, async function () { return { ok: true }; });
  check("reject of applied change refused", /already-applied/.test(await _asyncCode(function () {
    return ddl.reject(prop.changeId, "reviewer", "too late");
  })));
}

async function testApplyApprovedValidation() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });

  check("non-function runner rejected", /bad-runner/.test(await _asyncCode(function () {
    return ddl.applyApproved(prop.changeId, "not-a-function");
  })));
  check("apply unknown change rejected", /unknown-change/.test(await _asyncCode(function () {
    return ddl.applyApproved("nope", async function () { return null; });
  })));

  // already-applied branch on applyApproved itself.
  await ddl.approve(prop.changeId, "bob");
  await ddl.applyApproved(prop.changeId, async function () { return { ok: true }; });
  check("re-apply refused", /already-applied/.test(await _asyncCode(function () {
    return ddl.applyApproved(prop.changeId, async function () { return null; });
  })));
}

async function testWindowEnforcementAtApply() {
  // 2026-07-08 is a Wednesday (UTC); 2026-07-12 is a Sunday (UTC).
  var WED_NOON = Date.UTC(2026, 6, 8, 12, 0, 0);
  var WED_2000 = Date.UTC(2026, 6, 8, 20, 0, 0);
  var SUN_NOON = Date.UTC(2026, 6, 12, 12, 0, 0);

  // In-window apply succeeds.
  var okAudit = _fakeAudit();
  var ddlOk = b.ddlChangeControl.create({
    audit: okAudit, approvers: 1,
    windowSpec: "Mon-Fri 09:00-17:00 UTC",
    now: function () { return WED_NOON; },
  });
  var pOk = await ddlOk.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await ddlOk.approve(pOk.changeId, "bob");
  var ran = false;
  await ddlOk.applyApproved(pOk.changeId, async function () { ran = true; return { ok: true }; });
  check("in-window apply runs", ran === true);

  // Day matches but the hour is outside the window -> refused.
  var hourAudit = _fakeAudit();
  var ddlHour = b.ddlChangeControl.create({
    audit: hourAudit, approvers: 1,
    windowSpec: "Mon-Fri 09:00-17:00 UTC",
    now: function () { return WED_2000; },
  });
  var pHour = await ddlHour.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await ddlHour.approve(pHour.changeId, "bob");
  check("out-of-hours apply refused", /window-closed/.test(await _asyncCode(function () {
    return ddlHour.applyApproved(pHour.changeId, async function () { return null; });
  })));
  check("window-closed refusal audited",
        hourAudit._emitted.some(function (e) {
          return e.action === "ddl.change.apply_refused" &&
                 e.metadata && e.metadata.reason === "window-closed";
        }));

  // Day itself is outside the allowed set -> refused.
  var dayAudit = _fakeAudit();
  var ddlDay = b.ddlChangeControl.create({
    audit: dayAudit, approvers: 1,
    windowSpec: "Mon-Fri 09:00-17:00 UTC",
    now: function () { return SUN_NOON; },
  });
  var pDay = await ddlDay.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await ddlDay.approve(pDay.changeId, "bob");
  check("out-of-day apply refused", /window-closed/.test(await _asyncCode(function () {
    return ddlDay.applyApproved(pDay.changeId, async function () { return null; });
  })));

  // An "always" window never gates apply, whatever the clock reads.
  var ddlAlways = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, windowSpec: "always",
    now: function () { return SUN_NOON; },
  });
  var pAlways = await ddlAlways.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await ddlAlways.approve(pAlways.changeId, "bob");
  var ranAlways = false;
  await ddlAlways.applyApproved(pAlways.changeId, async function () {
    ranAlways = true; return { ok: true };
  });
  check("always window applies regardless of day/hour", ranAlways === true);
}

async function testRunnerFailurePath() {
  var fakeAudit = _fakeAudit();
  var ddl = b.ddlChangeControl.create({ audit: fakeAudit, approvers: 1 });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await ddl.approve(prop.changeId, "bob");

  var threw = null;
  try {
    await ddl.applyApproved(prop.changeId, async function () {
      throw new Error("runner boom");
    });
  } catch (e) { threw = e; }
  check("runner error propagates", threw && /runner boom/.test(threw.message || ""));

  var state = ddl.get(prop.changeId);
  check("failed runner sets state=failed",
        state && state.state === b.ddlChangeControl.STATES.FAILED);
  check("failed runner records applyError",
        state && /runner boom/.test(state.applyError || ""));
  check("failure emits ddl.change.applied outcome=failure",
        fakeAudit._emitted.some(function (e) {
          return e.action === "ddl.change.applied" && e.outcome === "failure";
        }));
}

async function testListAndGet() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
  var p1 = await ddl.propose("ALTER TABLE a ADD c1 TEXT", { proposer: "alice" });
  await ddl.approve(p1.changeId, "bob");
  var p2 = await ddl.propose("ALTER TABLE a ADD c2 TEXT", { proposer: "carol" });

  var listed = ddl.list();
  check("list returns both changes", listed.length === 2);
  var entry = listed.find(function (c) { return c.changeId === p1.changeId; });
  check("list entry carries proposer + approvals",
        entry && entry.proposer === "alice" && entry.approvals.length === 1 &&
        entry.approvals[0].approver === "bob");
  check("list entry omits raw sql",
        entry && !Object.prototype.hasOwnProperty.call(entry, "sql"));

  var got = ddl.get(p2.changeId);
  check("get returns a deep snapshot with sql",
        got && got.sql === "ALTER TABLE a ADD c2 TEXT" && got.state === "proposed");
  // Mutating the snapshot must not affect stored state.
  got.sql = "MUTATED";
  check("get returns an isolated clone",
        ddl.get(p2.changeId).sql === "ALTER TABLE a ADD c2 TEXT");
  check("get of unknown change returns null", ddl.get("no-such-id") === null);
}

async function testSelfApprovalOptAndPostureOverride() {
  // selfApproval:true lets the proposer approve their own change (no posture).
  var ddlSelf = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, selfApproval: true,
  });
  var ps = await ddlSelf.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  var rv = await ddlSelf.approve(ps.changeId, "alice");
  check("selfApproval:true permits proposer approval", rv.thresholdMet === true);

  // posture forces selfApproval false even when explicitly requested.
  var ddlForced = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 2, posture: "sox", selfApproval: true,
  });
  var pf = await ddlForced.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  check("posture overrides selfApproval:true",
        /self-approval-denied/.test(await _asyncCode(function () {
          return ddlForced.approve(pf.changeId, "alice");
        })));
}

async function testSignedPayloads() {
  // signWith returning a Buffer -> base64-encoded signatures stored.
  var bufDdl = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1,
    signWith: function (bytes) {
      check("signWith receives a Buffer", Buffer.isBuffer(bytes));
      return Buffer.from("buf-signature");
    },
  });
  var pb = await bufDdl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  var snapB = bufDdl.get(pb.changeId);
  check("buffer proposal signature stored base64",
        snapB && snapB.proposalSignature === Buffer.from("buf-signature").toString("base64"));
  await bufDdl.approve(pb.changeId, "bob");
  var snapB2 = bufDdl.get(pb.changeId);
  check("buffer approval signature stored base64",
        snapB2 && snapB2.approvals[0].signature ===
          Buffer.from("buf-signature").toString("base64"));

  // signWith returning a string -> coerced via String().
  var strDdl = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1,
    signWith: function () { return "str-signature"; },
  });
  var psn = await strDdl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await strDdl.approve(psn.changeId, "bob");
  var snapS = strDdl.get(psn.changeId);
  check("string proposal signature stored verbatim",
        snapS && snapS.proposalSignature === "str-signature");
  check("string approval signature stored verbatim",
        snapS && snapS.approvals[0].signature === "str-signature");
}

async function testAuditOptionalAndEdgeDefaults() {
  // create() with no opts at all -> full defaults (approvers 2, no posture).
  var defaults = b.ddlChangeControl.create();
  check("create() with no opts defaults approvers=2", defaults.approvers === 2);
  check("create() with no opts has null posture", defaults.posture === null);

  // No audit configured — the whole lifecycle runs with _emit short-circuited.
  var noAudit = b.ddlChangeControl.create({ approvers: 1 });
  var pna = await noAudit.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await noAudit.approve(pna.changeId, "bob");
  var outNa = await noAudit.applyApproved(pna.changeId, async function () { return { ok: true }; });
  check("lifecycle works with no audit sink", outNa.result.ok === true);

  // Audit whose safeEmit throws — emissions are best-effort and swallowed.
  var throwingAudit = { safeEmit: function () { throw new Error("audit down"); } };
  var badAuditDdl = b.ddlChangeControl.create({ audit: throwingAudit, approvers: 1 });
  var pta = await badAuditDdl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  check("throwing audit does not break propose", typeof pta.changeId === "string");

  // propose called with no options object at all -> defaults, then proposer check.
  var defOpts = b.ddlChangeControl.create({ approvers: 1 });
  check("propose without options rejects on missing proposer",
        /missing-proposer/.test(await _asyncCode(function () {
          return defOpts.propose("ALTER TABLE x ADD y TEXT");
        })));

  // Self-approval denied with NO posture -> error text falls back to "default".
  var noPosture = b.ddlChangeControl.create({ approvers: 1 });
  var pnp = await noPosture.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  var selfErr = null;
  try { await noPosture.approve(pnp.changeId, "alice"); } catch (e) { selfErr = e; }
  check("self-approval denied without posture", selfErr &&
        /self-approval-denied/.test(selfErr.code || ""));
  check("self-approval message names default posture",
        selfErr && /'default'/.test(selfErr.message || ""));

  // reject with no reason -> stored rejection.reason is null.
  var rej = b.ddlChangeControl.create({ approvers: 1 });
  var prj = await rej.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await rej.reject(prj.changeId, "reviewer");
  var rjSnap = rej.get(prj.changeId);
  check("reject without reason sets state=rejected",
        rjSnap && rjSnap.state === b.ddlChangeControl.STATES.REJECTED);
  check("reject without reason stores null reason",
        rjSnap && rjSnap.rejection && rjSnap.rejection.reason === null);

  // Runner throwing a non-Error value -> applyError coerced via String().
  var strFail = b.ddlChangeControl.create({ approvers: 1 });
  var psf = await strFail.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  await strFail.approve(psf.changeId, "bob");
  var nonErr = null;
  try {
    await strFail.applyApproved(psf.changeId, async function () {
      throw "plain-string-failure"; // eslint-disable-line no-throw-literal
    });
  } catch (e) { nonErr = e; }
  check("non-Error runner throw propagates", nonErr === "plain-string-failure");
  var sfSnap = strFail.get(psf.changeId);
  check("non-Error failure coerced into applyError",
        sfSnap && sfSnap.applyError === "plain-string-failure" &&
        sfSnap.state === b.ddlChangeControl.STATES.FAILED);
}

async function testRealDdlApplyAndRefusalOnLiveDb() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
    var sql = "CREATE TABLE ddl_scratch (id INTEGER PRIMARY KEY, note TEXT)";
    var prop = await ddl.propose(sql, {
      proposer: "alice", reason: "scratch table", ticket: "OPS-1",
    });

    function tableExists() {
      var row = b.db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ddl_scratch'"
      ).get();
      return !!row;
    }
    var runner = async function (ddlSql) { b.db.runSql(ddlSql); return { created: true }; };

    // Unapproved change is refused and the live schema is untouched.
    var refused = null;
    try { await ddl.applyApproved(prop.changeId, runner); } catch (e) { refused = e; }
    check("live: unapproved apply refused",
          refused && /insufficient-approvals/.test(refused.code || ""));
    check("live: schema not mutated by refused change", tableExists() === false);

    // Two independent approvers clear the threshold, then the runner applies it.
    await ddl.approve(prop.changeId, "bob");
    await ddl.approve(prop.changeId, "carol");
    var out = await ddl.applyApproved(prop.changeId, runner);
    check("live: approved apply returns runner result",
          out.result && out.result.created === true);
    check("live: schema mutated after approved apply", tableExists() === true);
    check("live: change recorded as applied",
          ddl.get(prop.changeId).state === b.ddlChangeControl.STATES.APPLIED);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  await testProposeApproveApply();
  await testInsufficientApprovals();
  await testSelfApprovalUnderPosture();
  await testDuplicateApproval();
  await testRejectThenApply();
  testWindowSpecParsing();
  await testSqlTamperRefused();
  testCreateOptionValidation();
  testWindowSpecGrammarErrors();
  testWindowSpecReverseAndSingleDay();
  await testProposeValidation();
  await testApproveValidation();
  await testRejectValidation();
  await testApplyApprovedValidation();
  await testWindowEnforcementAtApply();
  await testRunnerFailurePath();
  await testListAndGet();
  await testSelfApprovalOptAndPostureOverride();
  await testSignedPayloads();
  await testAuditOptionalAndEdgeDefaults();
  await testRealDdlApplyAndRefusalOnLiveDb();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
