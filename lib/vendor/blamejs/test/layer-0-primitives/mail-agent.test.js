// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.agent — multi-method facade. RBAC + posture + dispatch +
 * 5-guard validation layer + worker-pool / queue dispatch contract.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeFs  = require("node:fs");
var nodeOs  = require("node:os");
var nodePath = require("node:path");

function _msg(headers, body) {
  return headers.join("\r\n") + "\r\n\r\n" + (body || "");
}

async function _setup(label) {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailagent-" + label + "-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  var nodeSqlite = require("node:sqlite");
  var dbPath = nodePath.join(dataDir, "store.db");
  var dbHandle = new nodeSqlite.DatabaseSync(dbPath);
  var store = b.mailStore.create({ backend: dbHandle });
  return { dataDir: dataDir, db: dbHandle, store: store };
}

function _teardown(fx) {
  try { if (fx.db && fx.db.close) fx.db.close(); } catch (_e) { /* best-effort */ }
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  try { nodeFs.rmSync(fx.dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("mail.agent.create is fn",   typeof b.mail.agent.create === "function");
  check("mail.agent.consumer is fn", typeof b.mail.agent.consumer === "function");
  check("MailAgentError is fn",      typeof b.mail.agent.MailAgentError === "function");
  check("SCOPE_FOR_METHOD frozen",   Object.isFrozen(b.mail.agent.SCOPE_FOR_METHOD));
  check("COMPOSE_HINT frozen",       Object.isFrozen(b.mail.agent.COMPOSE_HINT));
}

async function testCreateRequiresStore() {
  var threw = null;
  try { b.mail.agent.create({}); } catch (e) { threw = e; }
  check("create: refuses missing store", threw && (threw.code || "").indexOf("mail-agent/bad-store") !== -1);
}

async function testFoldersFetch() {
  var fx = await _setup("folders");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };
    var f = await agent.folders({ actor: actor });
    check("folders: returns 6 default", f.folders.length >= 6);
    var msg = _msg([
      "From: a@x", "To: b@y", "Subject: hi",
      "Message-Id: <m@x>", "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "body");
    var meta = fx.store.appendMessage("INBOX", msg);
    var fetched = await agent.fetch({ actor: actor, folder: "INBOX", objectId: meta.objectid });
    check("fetch: unseals subject", fetched.subject === "hi");
    check("fetch: returns modseq",  fetched.modseq === 1);

    var miss = await agent.fetch({ actor: actor, folder: "INBOX", objectId: "obj_nope" });
    check("fetch: miss returns null", miss === null);
  } finally { _teardown(fx); }
}

async function testSearchThread() {
  var fx = await _setup("search");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };
    var meta1 = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: thread-root", "Message-Id: <root@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    var meta2 = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: re: root", "Message-Id: <m2@x>",
      "In-Reply-To: <root@x>", "References: <root@x>",
      "Date: Wed, 14 May 2026 12:01:00 +0000",
    ], "x"));
    var r = await agent.search({ actor: actor, folder: "INBOX" });
    check("search: returns 2 rows", r.rows.length === 2);
    check("search: nextModseq tracked", r.nextModseq > 0);

    var t = await agent.thread({ actor: actor, objectId: meta2.objectid });
    check("thread: 2 hops", t.thread.length === 2);
    check("thread: root first", t.thread[0] === meta1.objectid);
  } finally { _teardown(fx); }
}

async function testFlagMoveDelete() {
  var fx = await _setup("flagmove");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };
    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: hi", "Message-Id: <m@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    var f = await agent.flag({
      actor: actor, folder: "INBOX", objectIds: [meta.objectid], set: ["\\Seen"],
    });
    check("flag: changed",  f.changed === 1);
    var f2 = await agent.fetch({ actor: actor, folder: "INBOX", objectId: meta.objectid });
    check("flag: \\Seen visible after fetch", f2.flags.indexOf("\\Seen") !== -1);

    var mv = await agent.move({
      actor: actor, fromFolder: "INBOX", toFolder: "Archive", objectIds: [meta.objectid],
    });
    check("move: 1 changed",  mv.changed === 1);

    var miss = await agent.fetch({ actor: actor, folder: "INBOX", objectId: meta.objectid });
    check("move: gone from INBOX", miss === null);
    var hit  = await agent.fetch({ actor: actor, folder: "Archive", objectId: meta.objectid });
    check("move: now in Archive",  hit && hit.subject === "hi");

    var del = await agent.delete({
      actor: actor, folder: "Archive", objectIds: [meta.objectid],
    });
    check("delete: soft-delete moved to Trash", del.changed === 1);
    var inTrash = await agent.fetch({ actor: actor, folder: "Trash", objectId: meta.objectid });
    check("delete: in Trash now", inTrash && inTrash.flags.indexOf("\\Deleted") !== -1);
  } finally { _teardown(fx); }
}

async function testExpungeHardDelete() {
  // Hard expunge — composes legal-hold + retention-floor refusal
  // gates before the destructive SQL runs.
  var fx = await _setup("expunge");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };

    // Append + move to Trash (soft-delete) so we have material to expunge.
    var m1 = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: doomed-1", "Message-Id: <m1@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    var m2 = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: doomed-2", "Message-Id: <m2@x>",
      "Date: Wed, 14 May 2026 12:00:01 +0000",
    ], "x"));
    var m3 = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: held", "Message-Id: <m3@x>",
      "Date: Wed, 14 May 2026 12:00:02 +0000",
    ], "x"));
    fx.store.moveMessages("INBOX", "Trash", [m1.objectid, m2.objectid, m3.objectid]);

    // Place m3 on legal hold — expunge must refuse it specifically.
    fx.store.setLegalHold([m3.objectid], { hold: true });

    var rv = await agent.expunge({
      actor:    actor,
      folder:   "Trash",
      objectIds: [m1.objectid, m2.objectid, m3.objectid],
    });
    check("expunge: 2 deleted, 1 refused",
      rv.deleted.length === 2 && rv.refused.length === 1);
    check("expunge: refusal reason is legal-hold",
      rv.refused[0].reason === "legal-hold" && rv.refused[0].id === m3.objectid);
    check("expunge: m1 + m2 actually gone",
      fx.store.fetchByObjectId("Trash", m1.objectid) === null &&
      fx.store.fetchByObjectId("Trash", m2.objectid) === null);
    check("expunge: m3 still in Trash (legal hold)",
      fx.store.fetchByObjectId("Trash", m3.objectid) !== null);

    // Unknown id refuses with not-in-folder.
    var rv2 = await agent.expunge({
      actor:    actor,
      folder:   "Trash",
      objectIds: ["obj_does-not-exist"],
    });
    check("expunge: unknown id refused with not-in-folder",
      rv2.deleted.length === 0 && rv2.refused.length === 1 &&
      rv2.refused[0].reason === "not-in-folder");

    // Duplicate objectids in input MUST NOT drive quota negative.
    // Codex P1 on v0.11.23 PR #127: hardExpunge previously appended
    // the same row twice when the same id appeared twice, causing
    // double quota decrement + duplicate ids in `deleted`. The store
    // now dedupes at entry; the agent passes through.
    var dupMeta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: dup-test", "Message-Id: <md@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    fx.store.moveMessages("INBOX", "Trash", [dupMeta.objectid]);
    var quotaBefore = fx.store.quota("Trash");
    var rvDup = await agent.expunge({
      actor:    actor,
      folder:   "Trash",
      objectIds: [dupMeta.objectid, dupMeta.objectid, dupMeta.objectid],
    });
    var quotaAfter = fx.store.quota("Trash");
    check("expunge: duplicate ids collapsed to single delete",
      rvDup.deleted.length === 1 && rvDup.deleted[0] === dupMeta.objectid);
    check("expunge: duplicate-id quota stays non-negative",
      quotaAfter.usedBytes >= 0 && quotaAfter.usedCount >= 0);
    check("expunge: duplicate-id quota decrements exactly once",
      (quotaBefore.usedCount - quotaAfter.usedCount) === 1);
  } finally { _teardown(fx); }
}

async function testExpungeRetentionFloor() {
  // Retention floor refusal — under HIPAA posture, complianceFloor
  // returns the regulator-mandated minimum retention TTL. A
  // newly-appended message refuses expunge with `retention-floor`.
  var fx = await _setup("expungefloor");
  try {
    var agent = b.mail.agent.create({ store: fx.store, posture: "hipaa" });
    // HIPAA posture requires actor.purposeOfUse per
    // guardMailQuery.validateActor's POSTURE_ACTOR_FIELDS table.
    var actor = { id: "u1", purposeOfUse: "treatment" };
    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: too-young-to-die", "Message-Id: <m@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    fx.store.moveMessages("INBOX", "Trash", [meta.objectid]);

    var rv = await agent.expunge({
      actor:    actor,
      folder:   "Trash",
      objectIds: [meta.objectid],
    });
    check("expunge: HIPAA-posture refuses young message",
      rv.deleted.length === 0 && rv.refused.length === 1 &&
      rv.refused[0].reason === "retention-floor");
    check("expunge: refusal carries floorMs + posture metadata",
      rv.refused[0].floorMs > 0 && rv.refused[0].posture === "hipaa");
    check("expunge: message still in Trash",
      fx.store.fetchByObjectId("Trash", meta.objectid) !== null);
  } finally { _teardown(fx); }
}

async function testNotImplemented() {
  var fx = await _setup("notimpl");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };
    await expectRejection("compose throws not-implemented",
      agent.compose({ actor: actor, draft: {} }), "mail-agent/not-implemented");
    await expectRejection("send throws not-implemented",
      agent.send({ actor: actor }), "mail-agent/not-implemented");
    await expectRejection("export throws not-implemented",
      agent.export({ actor: actor }), "mail-agent/not-implemented");
    await expectRejection("import throws not-implemented",
      agent.import({ actor: actor }), "mail-agent/not-implemented");
    await expectRejection("mdn.send throws not-implemented",
      agent.mdn.send({ actor: actor }), "mail-agent/not-implemented");
    await expectRejection("sieve.activate throws not-implemented",
      agent.sieve.activate({ actor: actor, name: "x" }), "mail-agent/not-implemented");
  } finally { _teardown(fx); }
}

async function testPosture() {
  var fx = await _setup("posture");
  try {
    var agent = b.mail.agent.create({ store: fx.store, posture: "hipaa" });
    await expectRejection("posture: hipaa rejects missing purposeOfUse",
      agent.folders({ actor: { id: "u1" } }), "mail-query/missing-posture-field");
    var ok = await agent.folders({ actor: { id: "u1", purposeOfUse: "TREATMENT" } });
    check("posture: hipaa accepts complete actor", Array.isArray(ok.folders));
  } finally { _teardown(fx); }
}

async function testPermissions() {
  var fx = await _setup("perm");
  try {
    var perms = b.permissions.create({
      roles: {
        reader: { permissions: ["mail:read"] },
        writer: { permissions: ["mail:read", "mail:write", "mail:move"] },
      },
      auditFailures: false, auditSuccess: false,
    });
    var agent = b.mail.agent.create({ store: fx.store, permissions: perms });

    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: hi", "Message-Id: <m@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));

    var reader = { id: "r1", roles: ["reader"] };
    var writer = { id: "w1", roles: ["writer"] };

    var hit = await agent.fetch({ actor: reader, folder: "INBOX", objectId: meta.objectid });
    check("perm: reader can fetch",   hit && hit.subject === "hi");

    await expectRejection("perm: reader cannot move",
      agent.move({ actor: reader, fromFolder: "INBOX", toFolder: "Archive", objectIds: [meta.objectid] }),
      "mail-agent/permission-denied");

    var mv = await agent.move({
      actor: writer, fromFolder: "INBOX", toFolder: "Archive", objectIds: [meta.objectid],
    });
    check("perm: writer can move", mv.changed === 1);
  } finally { _teardown(fx); }
}

async function testQuota() {
  var fx = await _setup("quota");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var q = await agent.quota({ actor: { id: "u1" }, folder: "INBOX" });
    check("quota: returns shape", typeof q.usedBytes === "number");
  } finally { _teardown(fx); }
}

async function testDispatchValidation() {
  var fx = await _setup("dispatch");
  try {
    var threw = null;
    try {
      b.mail.agent.create({ store: fx.store, dispatch: { mode: "queue" } });
    } catch (e) { threw = e; }
    check("dispatch: queue mode requires queue", threw && (threw.code || "").indexOf("mail-agent/no-queue") !== -1);

    var threw2 = null;
    try {
      b.mail.agent.create({ store: fx.store, dispatch: { mode: "wat" } });
    } catch (e) { threw2 = e; }
    check("dispatch: bad mode refused", threw2 && (threw2.code || "").indexOf("mail-agent/bad-dispatch-mode") !== -1);
  } finally { _teardown(fx); }
}

async function testDispatchRouting() {
  var fx = await _setup("dispatch-route");
  try {
    // Mode "local" — facade calls run inline.
    var agentLocal = b.mail.agent.create({ store: fx.store, dispatch: { mode: "local" } });
    var folders = await agentLocal.folders({ actor: { id: "u1" } });
    check("dispatch.local: folders runs inline", Array.isArray(folders.folders));

    // Mode "queue" — sync-result method refused until orchestrator's
    // result-bus lands at v0.9.21.
    var enqueued = [];
    var fakeQueue = {
      enqueue: async function (topic, payload) {
        enqueued.push({ topic: topic, payload: payload });
        return { jobId: "j" + enqueued.length };
      },
      consume: function () { /* unused */ },
    };
    var agentQueue = b.mail.agent.create({
      store: fx.store, dispatch: { mode: "queue", queue: fakeQueue },
    });
    await expectRejection("dispatch.queue: fetch (sync-result) refused until result-bus",
      agentQueue.fetch({ actor: { id: "u1" }, folder: "INBOX", objectId: "x" }),
      "mail-agent/queue-result-bus-deferred");

    // Heavy method (search) under "queue" enqueues + returns jobId.
    var r = await agentQueue.search({ actor: { id: "u1" } });
    check("dispatch.queue: search enqueues",       r.enqueued === true && typeof r.jobId === "string");
    check("dispatch.queue: published to topic",    enqueued.length === 1);
    check("dispatch.queue: envelope carries method", enqueued[0].payload.method === "search");
    check("dispatch.queue: envelope carries posture", enqueued[0].payload.posture === null);

    // Mode "auto" — fast-path stays local; heavy method routes to queue.
    var agentAuto = b.mail.agent.create({
      store: fx.store, dispatch: { mode: "auto", queue: fakeQueue },
    });
    var f2 = await agentAuto.folders({ actor: { id: "u1" } });
    check("dispatch.auto: folders stays local", Array.isArray(f2.folders));
    var r2 = await agentAuto.search({ actor: { id: "u1" } });
    check("dispatch.auto: search routes to queue", r2.enqueued === true);
  } finally { _teardown(fx); }
}

async function testConsumerSurface() {
  var threw = null;
  try { b.mail.agent.consumer({}); } catch (e) { threw = e; }
  check("consumer: refuses missing agent", threw && (threw.code || "").indexOf("mail-agent/bad-agent") !== -1);
}

async function testGuardsExposed() {
  check("guards.query",     b.mail.agent.guards.query === b.guardMailQuery);
  check("guards.compose",   b.mail.agent.guards.compose === b.guardMailCompose);
  check("guards.reply",     b.mail.agent.guards.reply === b.guardMailReply);
  check("guards.move",      b.mail.agent.guards.move === b.guardMailMove);
  check("guards.sieve",     b.mail.agent.guards.sieve === b.guardMailSieve);
  check("guards.messageId", b.mail.agent.guards.messageId === b.guardMessageId);
}

// A grammar-valid RFC 5228 script (fileinto is a known capability) — the
// happy path through b.safeSieve's parser under agent.sieve.put.
var VALID_SIEVE =
  'require ["fileinto"];\r\n' +
  'if header :contains "Subject" "[bug]" { fileinto "bugs"; }\r\n';

async function testCreateErrorBranches() {
  // create() entry-point validation THROWS (config-time tier) on every
  // malformed opts shape before an agent is ever built.
  var fx = await _setup("create-err");
  try {
    var e1 = null;
    try { b.mail.agent.create(); } catch (e) { e1 = e; }
    check("create: null opts refused",
      e1 instanceof b.mail.agent.MailAgentError && (e1.code || "").indexOf("mail-agent/bad-opts") !== -1);

    var e1b = null;
    try { b.mail.agent.create("nope"); } catch (e) { e1b = e; }
    check("create: non-object opts refused",
      e1b && (e1b.code || "").indexOf("mail-agent/bad-opts") !== -1);

    // A store object that lacks the b.mailStore fingerprint method.
    var e2 = null;
    try { b.mail.agent.create({ store: { notAStore: true } }); } catch (e) { e2 = e; }
    check("create: store without fetchByObjectId refused",
      e2 && (e2.code || "").indexOf("mail-agent/bad-store") !== -1);

    // A real store but an unknown compliance posture.
    var e3 = null;
    try { b.mail.agent.create({ store: fx.store, posture: "not-a-posture" }); } catch (e) { e3 = e; }
    check("create: unknown posture refused",
      e3 && (e3.code || "").indexOf("mail-agent/bad-posture") !== -1);
  } finally { _teardown(fx); }
}

async function testDispatchOptionValidation() {
  // _validateDispatch THROWS on each malformed dispatch field, and
  // ACCEPTS the well-formed values that exercise the positive branch of
  // every typeof/range guard.
  var fx = await _setup("dispatch-opts");
  try {
    var eWp = null;
    try { b.mail.agent.create({ store: fx.store, dispatch: { workerPool: {} } }); } catch (e) { eWp = e; }
    check("dispatch: workerPool without .run() refused",
      eWp && (eWp.code || "").indexOf("mail-agent/bad-worker-pool") !== -1);

    var eTtNeg = null;
    try { b.mail.agent.create({ store: fx.store, dispatch: { taskTimeoutMs: -5 } }); } catch (e) { eTtNeg = e; }
    check("dispatch: negative taskTimeoutMs refused",
      eTtNeg && (eTtNeg.code || "").indexOf("mail-agent/bad-task-timeout") !== -1);

    var eTtNaN = null;
    try { b.mail.agent.create({ store: fx.store, dispatch: { taskTimeoutMs: NaN } }); } catch (e) { eTtNaN = e; }
    check("dispatch: non-finite taskTimeoutMs refused",
      eTtNaN && (eTtNaN.code || "").indexOf("mail-agent/bad-task-timeout") !== -1);

    var eDc = null;
    try { b.mail.agent.create({ store: fx.store, dispatch: { queueDepthCap: -1 } }); } catch (e) { eDc = e; }
    check("dispatch: negative queueDepthCap refused",
      eDc && (eDc.code || "").indexOf("mail-agent/bad-queue-depth-cap") !== -1);

    var eVk = null;
    try { b.mail.agent.create({ store: fx.store, dispatch: { vaultKeyDelivery: "sideband" } }); } catch (e) { eVk = e; }
    check("dispatch: unknown vaultKeyDelivery refused",
      eVk && (eVk.code || "").indexOf("mail-agent/bad-vault-key-delivery") !== -1);

    // Positive branch: every explicit value well-formed → agent builds.
    var agentOk = b.mail.agent.create({
      store: fx.store,
      dispatch: {
        mode: "local",
        workerPool: { run: function () { return null; } },
        taskTimeoutMs: 5000,
        queueDepthCap: 16,
        vaultKeyDelivery: "main-only",
        queueTopic: "custom.topic",
      },
    });
    check("dispatch: well-formed explicit fields accepted",
      typeof agentOk.folders === "function" &&
      agentOk._ctx.dispatch.vaultKeyDelivery === "main-only" &&
      agentOk._ctx.dispatch.queueDepthCap === 16 &&
      agentOk._ctx.dispatch.queueTopic === "custom.topic");
  } finally { _teardown(fx); }
}

async function testIdentityResolver() {
  // opts.identity accepts a resolver function OR a plain object map; a
  // missing/garbage value yields a null-returning resolver. Only the
  // create() path exercises _identityResolver.
  var fx = await _setup("identity");
  try {
    var agentFn = b.mail.agent.create({
      store: fx.store,
      identity: function (actorId) { return { email: actorId + "@x.example", name: actorId }; },
    });
    check("identity: function resolver stored",
      typeof agentFn._ctx.identity === "function" &&
      agentFn._ctx.identity("u1").email === "u1@x.example");

    var agentMap = b.mail.agent.create({
      store: fx.store,
      identity: { u1: { email: "u1@x.example", name: "One" } },
    });
    check("identity: object map resolver looks up by id",
      agentMap._ctx.identity("u1").name === "One" && agentMap._ctx.identity("nobody") === null);

    var agentNone = b.mail.agent.create({ store: fx.store, identity: 42 });
    check("identity: garbage spec yields null resolver",
      agentNone._ctx.identity("u1") === null);
  } finally { _teardown(fx); }
}

async function testAuditOverride() {
  // When opts.audit exposes safeEmit, the agent routes every audit
  // event through it (not the default b.audit). The outcome field flips
  // to "failure" for denied/not_implemented events.
  var fx = await _setup("audit-override");
  try {
    var seen = [];
    var agent = b.mail.agent.create({
      store: fx.store,
      audit: { safeEmit: function (rec) { seen.push(rec); } },
    });
    var actor = { id: "u1", roles: ["clinician"] };
    await agent.folders({ actor: actor });
    check("audit-override: success event routed to override",
      seen.length === 1 && seen[0].action === "mail.agent.folders.success" &&
      seen[0].outcome === "success" && seen[0].actor.id === "u1");

    await expectRejection("audit-override: not-implemented rejects",
      agent.compose({ actor: actor }), "mail-agent/not-implemented");
    var last = seen[seen.length - 1];
    check("audit-override: not_implemented event marked failure",
      last.action === "mail.agent.not_implemented" && last.outcome === "failure");

    // A permission_denied event routed through the override marks the
    // "denied" branch of the outcome selector.
    var deniedSeen = [];
    var perms = b.permissions.create({
      roles: { reader: { permissions: ["mail:read"] } },
      auditFailures: false, auditSuccess: false,
    });
    var denyAgent = b.mail.agent.create({
      store: fx.store, permissions: perms,
      audit: { safeEmit: function (rec) { deniedSeen.push(rec); } },
    });
    var reader = { id: "r1", roles: ["reader"] };
    await expectRejection("audit-override: denied move rejects permission-denied",
      denyAgent.move({ actor: reader, fromFolder: "INBOX", toFolder: "Archive", objectIds: [] }),
      "mail-agent/permission-denied");
    var denyEvt = deniedSeen[deniedSeen.length - 1];
    check("audit-override: permission_denied event marked failure",
      denyEvt && denyEvt.action === "mail.agent.permission_denied" && denyEvt.outcome === "failure");
  } finally { _teardown(fx); }
}

async function testMethodBadArgs() {
  // Defensive per-method arg-shape guards return a rejected promise with
  // mail-agent/bad-args for each malformed consumer call.
  var fx = await _setup("bad-args");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };

    await expectRejection("fetch: non-string folder refused",
      agent.fetch({ actor: actor, folder: 123, objectId: "x" }), "mail-agent/bad-args");
    await expectRejection("fetch: non-string objectId refused",
      agent.fetch({ actor: actor, folder: "INBOX", objectId: 7 }), "mail-agent/bad-args");
    await expectRejection("thread: non-string objectId refused",
      agent.thread({ actor: actor, objectId: 7 }), "mail-agent/bad-args");
    await expectRejection("flag: non-array objectIds refused",
      agent.flag({ actor: actor, folder: "INBOX", objectIds: "not-array" }), "mail-agent/bad-args");
    await expectRejection("flag: non-string folder refused",
      agent.flag({ actor: actor, folder: 5, objectIds: [] }), "mail-agent/bad-args");
    await expectRejection("delete: non-string folder refused",
      agent.delete({ actor: actor, folder: 5, objectIds: [] }), "mail-agent/bad-args");
    await expectRejection("expunge: non-array objectIds refused",
      agent.expunge({ actor: actor, folder: "Trash", objectIds: "x" }), "mail-agent/bad-args");

    // _entry itself refuses a missing args object (drives every method).
    await expectRejection("folders: missing args object refused",
      agent.folders(), "mail-agent/bad-args");

    // Missing-actor audit path exercises _actorShape's <unknown> fallback:
    // a not-implemented call with no actor and no permissions still emits
    // the audit event with a synthesized actor id.
    await expectRejection("compose: missing actor still rejects not-implemented",
      agent.compose({}), "mail-agent/not-implemented");
  } finally { _teardown(fx); }
}

async function testDeleteInTrash() {
  // delete() of a message already in Trash short-circuits to a
  // \Deleted flag-set (no re-move); the message stays in Trash flagged.
  var fx = await _setup("delete-trash");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };
    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: bin-me", "Message-Id: <t@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    fx.store.moveMessages("INBOX", "Trash", [meta.objectid]);

    var r = await agent.delete({ actor: actor, folder: "Trash", objectIds: [meta.objectid] });
    check("delete-in-Trash: flags without re-move", r.changed === 1);
    var still = fx.store.fetchByObjectId("Trash", meta.objectid);
    check("delete-in-Trash: message remains in Trash, flagged \\Deleted",
      still !== null && still.flags.indexOf("\\Deleted") !== -1);
  } finally { _teardown(fx); }
}

async function testSievePut() {
  // sieve.put runs a two-stage validation: the agent shape guard, then
  // the full b.safeSieve RFC 5228 grammar parse. A grammar-valid script
  // returns { ok, requiredCaps }; an unknown capability is refused with
  // mail-agent/sieve-parse-error. Run under HIPAA posture so _profileFor
  // resolves against a set posture too.
  var fx = await _setup("sieve-put");
  try {
    var agent = b.mail.agent.create({ store: fx.store, posture: "hipaa" });
    var actor = { id: "u1", purposeOfUse: "TREATMENT" };

    var ok = await agent.sieve.put({
      actor: actor, name: "my-filter", script: VALID_SIEVE, ownedNames: ["my-filter"],
    });
    check("sieve.put: valid script accepted with requiredCaps",
      ok.ok === true && Array.isArray(ok.requiredCaps) && ok.requiredCaps.indexOf("fileinto") !== -1);

    // Grammar-valid shape but an unknown capability — b.safeSieve
    // refuses at require-time, surfaced as sieve-parse-error.
    await expectRejection("sieve.put: unknown capability refused at parse",
      agent.sieve.put({
        actor: actor, name: "bad-filter",
        script: 'require ["nonsense-capability"];\r\nkeep;\r\n',
        ownedNames: ["bad-filter"],
      }), "mail-agent/sieve-parse-error");
  } finally { _teardown(fx); }
}

async function testCheckPermissionNoActor() {
  // With a permissions instance but NO posture, a not-implemented method
  // whose args omit actor reaches _checkPermission's no-actor guard
  // (validateActor is skipped when posture is null).
  var fx = await _setup("perm-noactor");
  try {
    var perms = b.permissions.create({
      roles: { writer: { permissions: ["mail:write"] } },
      auditFailures: false, auditSuccess: false,
    });
    var agent = b.mail.agent.create({ store: fx.store, permissions: perms });
    // _checkPermission runs at the entry (config-time tier) and THROWS
    // synchronously — the facade method never returns its promise here.
    var threw = null;
    try { agent.compose({}); } catch (e) { threw = e; }
    check("checkPermission: missing actor refused with no-actor",
      threw && (threw.code || "").indexOf("mail-agent/no-actor") !== -1);
  } finally { _teardown(fx); }
}

async function testDefaultsAndFilters() {
  // Cover the option-default branches: quota without a folder falls back
  // to INBOX; flag without set/unset defaults both to []; search with a
  // text + modseq filter drives the FTS path and the hasText audit flag.
  var fx = await _setup("defaults");
  try {
    var agent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };

    var q = await agent.quota({ actor: actor });
    check("quota: folder defaults to INBOX", typeof q.usedBytes === "number");

    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: needle-subject", "Message-Id: <d@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "findme body"));

    var f = await agent.flag({ actor: actor, folder: "INBOX", objectIds: [meta.objectid] });
    check("flag: absent set/unset default to empty", f.changed === 0 || typeof f.changed === "number");

    var r = await agent.search({
      actor: actor, folder: "INBOX",
      filter: { text: "needle", modseq: { gt: 0 } },
    });
    check("search: text+modseq filter returns the matching row",
      Array.isArray(r.rows) && r.rows.length >= 1);

    // No folder → defaults to INBOX (the `args.folder || "INBOX"` branch).
    var r2 = await agent.search({ actor: actor });
    check("search: folder defaults to INBOX", Array.isArray(r2.rows) && r2.rows.length >= 1);
  } finally { _teardown(fx); }
}

async function testPostureNotImplementedAndFloorMiss() {
  // Under a set posture, a not-implemented method still runs the
  // posture actor-field validation at entry before rejecting. And an
  // expunge under a posture with no regulator-mandated retention floor
  // (GDPR carries no fixed mail-retention minimum here) applies floorMs=0
  // so eligible messages are hard-deleted.
  var fx = await _setup("posture-notimpl");
  try {
    var agent = b.mail.agent.create({ store: fx.store, posture: "hipaa" });

    // Posture set + actor MISSING the required field → validateActor
    // throws the posture-field error (not the not-implemented reject).
    var eMissing = null;
    try { await agent.compose({ actor: { id: "u1" } }); } catch (e) { eMissing = e; }
    check("not-implemented under posture: missing field refused first",
      eMissing && (eMissing.code || "").indexOf("mail-query/missing-posture-field") !== -1);

    // Posture set + complete actor → passes validateActor, then rejects
    // not-implemented (the posture-truthy branch of _notImplemented).
    await expectRejection("not-implemented under posture: complete actor rejects not-implemented",
      agent.compose({ actor: { id: "u1", purposeOfUse: "TREATMENT" } }), "mail-agent/not-implemented");

    // GDPR posture: valid for create, absent from the retention floor
    // table → floorMs resolves to 0, so a young message is expungeable.
    var gdprAgent = b.mail.agent.create({ store: fx.store, posture: "gdpr" });
    var gdprActor = { id: "u1", lawfulBasis: "consent" };
    var meta = fx.store.appendMessage("INBOX", _msg([
      "From: a@x", "To: b@y", "Subject: gdpr-erase", "Message-Id: <g@x>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
    ], "x"));
    fx.store.moveMessages("INBOX", "Trash", [meta.objectid]);
    var rv = await gdprAgent.expunge({ actor: gdprActor, folder: "Trash", objectIds: [meta.objectid] });
    check("expunge under GDPR (no floor): message hard-deleted",
      rv.deleted.length === 1 && rv.refused.length === 0 &&
      fx.store.fetchByObjectId("Trash", meta.objectid) === null);
  } finally { _teardown(fx); }
}

async function testConsumerErrorBranches() {
  // consumer() entry validation THROWS on every malformed opts shape.
  var fx = await _setup("consumer-err");
  try {
    var innerAgent = b.mail.agent.create({ store: fx.store });

    var eNull = null;
    try { b.mail.agent.consumer(null); } catch (e) { eNull = e; }
    check("consumer: null opts refused",
      eNull && (eNull.code || "").indexOf("mail-agent/bad-opts") !== -1);

    var eQ = null;
    try { b.mail.agent.consumer({ agent: innerAgent, queue: { notAQueue: true } }); } catch (e) { eQ = e; }
    check("consumer: queue without consume refused",
      eQ && (eQ.code || "").indexOf("mail-agent/bad-queue") !== -1);

    var fakeQueue = { consume: function () {}, enqueue: function () {} };
    var eMc0 = null;
    try { b.mail.agent.consumer({ agent: innerAgent, queue: fakeQueue, maxConcurrency: 0 }); } catch (e) { eMc0 = e; }
    check("consumer: zero maxConcurrency refused",
      eMc0 && (eMc0.code || "").indexOf("mail-agent/bad-max-concurrency") !== -1);

    var eMcNaN = null;
    try { b.mail.agent.consumer({ agent: innerAgent, queue: fakeQueue, maxConcurrency: NaN }); } catch (e) { eMcNaN = e; }
    check("consumer: non-finite maxConcurrency refused",
      eMcNaN && (eMcNaN.code || "").indexOf("mail-agent/bad-max-concurrency") !== -1);

    // Explicit numeric maxConcurrency accepted (positive branch of the
    // typeof ternary) — build only, no start.
    var consExplicit = b.mail.agent.consumer({ agent: innerAgent, queue: fakeQueue, maxConcurrency: 3 });
    check("consumer: explicit maxConcurrency accepted", typeof consExplicit.start === "function");
  } finally { _teardown(fx); }
}

async function testConsumerDispatch() {
  // Drive the consumer's real subscribe → dispatch → stop loop against a
  // fake queue that captures the envelope handler. Covers direct-method
  // routing, dotted-method routing, unknown-method refusal, double-start
  // refusal, and the stopped-drop guard.
  var fx = await _setup("consumer-dispatch");
  try {
    var innerAgent = b.mail.agent.create({ store: fx.store });
    var actor = { id: "u1" };

    var handler = null;
    var subscribeCount = 0;
    var unsubscribed = false;
    var fakeQueue = {
      consume: async function (topic, fn, subOpts) {
        subscribeCount += 1;
        handler = fn;
        check("consumer: consume receives maxConcurrency opt",
          subOpts && subOpts.maxConcurrency === 4 && topic === "mail.agent.tasks");
        return { unsubscribe: async function () { unsubscribed = true; } };
      },
      enqueue: async function () { return { jobId: "j1" }; },
    };

    // maxConcurrency omitted → default 4 (negative branch of the ternary).
    var cons = b.mail.agent.consumer({ agent: innerAgent, queue: fakeQueue });
    await cons.start();
    check("consumer: start subscribes once", subscribeCount === 1 && typeof handler === "function");

    await expectRejection("consumer: double start refused",
      cons.start(), "mail-agent/already-started");

    // Direct-method routing → agent.folders.
    var fres = await handler({ method: "folders", args: { actor: actor } });
    check("consumer: direct method routes to agent.folders", Array.isArray(fres.folders));

    // Dotted-method routing → agent.sieve.put.
    var sres = await handler({
      method: "sieve.put",
      args: { actor: actor, name: "cf", script: VALID_SIEVE, ownedNames: ["cf"] },
    });
    check("consumer: dotted method routes to agent.sieve.put", sres.ok === true);

    // Unknown flat method refused.
    await expectRejection("consumer: unknown method refused",
      handler({ method: "bogus", args: {} }), "mail-agent/unknown-method");

    // Missing method refused (falls through to the unknown-method throw).
    await expectRejection("consumer: missing method refused",
      handler({ args: {} }), "mail-agent/unknown-method");

    // Dotted method whose namespace/leaf is unknown refused.
    await expectRejection("consumer: unknown dotted method refused",
      handler({ method: "sieve.nope", args: {} }), "mail-agent/unknown-method");

    // stop() unsubscribes; a post-stop envelope is dropped silently.
    await cons.stop();
    check("consumer: stop unsubscribes", unsubscribed === true);
    var dropped = await handler({ method: "folders", args: { actor: actor } });
    check("consumer: stopped consumer drops the envelope", dropped === undefined);
  } finally { _teardown(fx); }
}

async function run() {
  testSurface();
  await testCreateRequiresStore();
  await testFoldersFetch();
  await testSearchThread();
  await testFlagMoveDelete();
  await testExpungeHardDelete();
  await testExpungeRetentionFloor();
  await testNotImplemented();
  await testPosture();
  await testPermissions();
  await testQuota();
  await testDispatchValidation();
  await testDispatchRouting();
  await testConsumerSurface();
  await testGuardsExposed();
  await testCreateErrorBranches();
  await testDispatchOptionValidation();
  await testIdentityResolver();
  await testAuditOverride();
  await testMethodBadArgs();
  await testDeleteInTrash();
  await testSievePut();
  await testCheckPermissionNoActor();
  await testDefaultsAndFilters();
  await testPostureNotImplementedAndFloorMiss();
  await testConsumerErrorBranches();
  await testConsumerDispatch();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
