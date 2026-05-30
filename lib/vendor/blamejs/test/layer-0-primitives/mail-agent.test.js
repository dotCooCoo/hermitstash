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
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
