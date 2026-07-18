// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mailStore — byte-level mail-store substrate. Tests the API
 * surface + atomic append + sealed-column round-trip + CONDSTORE
 * modseq + threading + quota + legal-hold.
 *
 * Uses an in-memory sqlite via b.localDbThin so the test doesn't
 * depend on b.db's full init / vault setup. cryptoField sealing is
 * exercised via b.vault.init({ mode: "plaintext" }).
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

async function _setupStore(label) {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailstore-" + label + "-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  // Use node:sqlite directly via DatabaseSync — same shape as
  // b.localDb.thin wraps. The store needs { prepare(sql) → { run,
  // get, all } } which DatabaseSync provides directly.
  var nodeSqlite = require("node:sqlite");
  var dbPath = nodePath.join(dataDir, "store.db");
  var dbHandle = new nodeSqlite.DatabaseSync(dbPath);
  return { dataDir: dataDir, db: dbHandle };
}

function _teardown(fx) {
  try { if (fx.db && fx.db.close) fx.db.close(); } catch (_e) { /* best-effort */ }
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  try { nodeFs.rmSync(fx.dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

function testSurface() {
  check("mailStore.create is fn",      typeof b.mailStore.create === "function");
  check("mailStore.DEFAULT_FOLDERS is array", Array.isArray(b.mailStore.DEFAULT_FOLDERS));
  check("mailStore.MailStoreError is fn", typeof b.mailStore.MailStoreError === "function");
}

async function testBootstrap() {
  var fx = await _setupStore("bootstrap");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var folders = store.listFolders();
    var names = folders.map(function (f) { return f.name; });
    check("bootstrap: INBOX created",   names.indexOf("INBOX") !== -1);
    check("bootstrap: Sent created",    names.indexOf("Sent") !== -1);
    check("bootstrap: Drafts created",  names.indexOf("Drafts") !== -1);
    check("bootstrap: Trash created",   names.indexOf("Trash") !== -1);
    check("bootstrap: Junk created",    names.indexOf("Junk") !== -1);
    check("bootstrap: Archive created", names.indexOf("Archive") !== -1);
  } finally { _teardown(fx); }
}

async function testAppendFetchRoundtrip() {
  var fx = await _setupStore("append");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var msg = _msg([
      "From: alice@example.com",
      "To: bob@example.com",
      "Subject: Hello",
      "Message-Id: <m1@example.com>",
      "Date: Wed, 14 May 2026 12:00:00 +0000",
      "Content-Type: text/plain; charset=utf-8",
    ], "Hello, world!");
    var meta = store.appendMessage("INBOX", msg);
    check("append: returns objectid",     typeof meta.objectid === "string" && meta.objectid.indexOf("obj_") === 0);
    check("append: returns modseq",       meta.modseq === 1);
    check("append: returns size",         meta.sizeBytes === Buffer.byteLength(msg));
    check("append: threadRootId is self", meta.threadRootId === meta.objectid);

    var fetched = store.fetchByObjectId("INBOX", meta.objectid);
    check("fetch: round-trip subject",     fetched.subject === "Hello");
    check("fetch: round-trip from",        fetched.from === "alice@example.com");
    check("fetch: round-trip to",          fetched.to === "bob@example.com");
    check("fetch: round-trip body text",   fetched.bodyText === "Hello, world!");
    check("fetch: round-trip messageId",   fetched.messageId === "<m1@example.com>");
    check("fetch: round-trip modseq",      fetched.modseq === 1);
    check("fetch: flags empty initially",  Array.isArray(fetched.flags) && fetched.flags.length === 0);
    check("fetch: legalHold false",        fetched.legalHold === false);
  } finally { _teardown(fx); }
}

async function testCondstoreModseq() {
  var fx = await _setupStore("condstore");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var ids = [];
    for (var i = 0; i < 3; i += 1) {
      var meta = store.appendMessage("INBOX",
        _msg(["From: a@x", "To: b@x", "Subject: M" + i, "Message-Id: <" + i + "@x>"], "body " + i));
      ids.push(meta);
    }
    check("modseq: strictly monotonic", ids[0].modseq < ids[1].modseq && ids[1].modseq < ids[2].modseq);

    // queryByModseq(sinceModseq=1) returns 2 + 3 only.
    var sinceFirst = store.queryByModseq("INBOX", { sinceModseq: 1 });
    check("queryByModseq: returns rows since modseq",
          sinceFirst.length === 2 && sinceFirst[0].modseq === 2 && sinceFirst[1].modseq === 3);

    // queryByModseq(sinceModseq=0) returns all 3.
    var all = store.queryByModseq("INBOX", { sinceModseq: 0 });
    check("queryByModseq: all when sinceModseq=0", all.length === 3);
  } finally { _teardown(fx); }
}

async function testThreading() {
  var fx = await _setupStore("thread");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var root = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: Original", "Message-Id: <root@x>"], "first"));
    var reply1 = store.appendMessage("INBOX",
      _msg(["From: b@x", "Subject: Re: Original",
            "Message-Id: <r1@x>", "In-Reply-To: <root@x>",
            "References: <root@x>"], "reply 1"));
    var reply2 = store.appendMessage("INBOX",
      _msg(["From: c@x", "Subject: Re: Original",
            "Message-Id: <r2@x>", "In-Reply-To: <r1@x>",
            "References: <root@x> <r1@x>"], "reply 2"));
    check("thread: root is self",     root.threadRootId === root.objectid);
    check("thread: reply1 → root",    reply1.threadRootId === root.objectid);
    check("thread: reply2 → root",    reply2.threadRootId === root.objectid);

    var threadIds = store.threadFor(reply2.objectid);
    check("thread: lists all 3 in chronological order",
          threadIds.length === 3 && threadIds[0] === root.objectid);
  } finally { _teardown(fx); }
}

async function testFlags() {
  var fx = await _setupStore("flags");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var meta = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: F", "Message-Id: <f@x>"], "body"));
    store.setFlags("INBOX", [meta.objectid], { set: ["\\Seen", "\\Flagged"] });
    var fetched = store.fetchByObjectId("INBOX", meta.objectid);
    check("flags: \\Seen set",     fetched.flags.indexOf("\\Seen") !== -1);
    check("flags: \\Flagged set",  fetched.flags.indexOf("\\Flagged") !== -1);

    store.setFlags("INBOX", [meta.objectid], { unset: ["\\Seen"] });
    var fetched2 = store.fetchByObjectId("INBOX", meta.objectid);
    check("flags: \\Seen unset",   fetched2.flags.indexOf("\\Seen") === -1);
    check("flags: \\Flagged still set",
                                   fetched2.flags.indexOf("\\Flagged") !== -1);
  } finally { _teardown(fx); }
}

async function testQuota() {
  var fx = await _setupStore("quota");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX", _msg(["From: a@x", "Subject: 1", "Message-Id: <1@x>"], "body1"));
    store.appendMessage("INBOX", _msg(["From: a@x", "Subject: 2", "Message-Id: <2@x>"], "body22"));
    var q = store.quota("INBOX");
    check("quota: usedCount = 2", q.usedCount === 2);
    check("quota: usedBytes > 0", q.usedBytes > 0);
  } finally { _teardown(fx); }
}

async function testLegalHold() {
  var fx = await _setupStore("legal");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var meta = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: H", "Message-Id: <h@x>"], "body"));
    store.setLegalHold([meta.objectid], { hold: true });
    var fetched = store.fetchByObjectId("INBOX", meta.objectid);
    check("legalHold: flag set", fetched.legalHold === true);
    store.setLegalHold([meta.objectid], { hold: false });
    var fetched2 = store.fetchByObjectId("INBOX", meta.objectid);
    check("legalHold: flag cleared", fetched2.legalHold === false);
  } finally { _teardown(fx); }
}

async function testSealedColumnsActuallySealed() {
  var fx = await _setupStore("sealed");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX",
      _msg(["From: alice@example.com", "Subject: secret-subject",
            "Message-Id: <s@x>"], "secret-body-content"));

    // Inspect raw row — sealed columns must NOT appear as plaintext.
    var raw = fx.db.prepare(
      "SELECT subject, from_addr, body_text FROM " + store._tablePrefix + "_messages LIMIT 1"
    ).get();
    check("sealed: subject column starts with vault:",
          typeof raw.subject === "string" && raw.subject.indexOf("vault:") === 0);
    check("sealed: from_addr column starts with vault:",
          typeof raw.from_addr === "string" && raw.from_addr.indexOf("vault:") === 0);
    check("sealed: body_text column starts with vault:",
          typeof raw.body_text === "string" && raw.body_text.indexOf("vault:") === 0);

    // Inspect plaintext column — must NOT be sealed.
    var plain = fx.db.prepare(
      "SELECT modseq, size_bytes FROM " + store._tablePrefix + "_messages LIMIT 1"
    ).get();
    check("plaintext: modseq plain (forensic-queryable)",
          typeof plain.modseq === "number");
    check("plaintext: size_bytes plain (forensic-queryable)",
          typeof plain.size_bytes === "number");
  } finally { _teardown(fx); }
}

async function testRefusesBadInput() {
  var fx = await _setupStore("bad");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var threw = null;
    try { store.appendMessage("INBOX", 42); }
    catch (e) { threw = e; }
    check("refuses non-Buffer/string",
          threw && (threw.code || "").indexOf("mail-store/bad-input") !== -1);

    // Tight maxMessageBytes via store-level opt — verify safeMime gate fires
    var smallStore = b.mailStore.create({
      backend: fx.db, tablePrefix: "tinystore", maxMessageBytes: 1000,
      safeMimeOpts: { maxMessageBytes: 10 },
    });
    var threw2 = null;
    try { smallStore.appendMessage("INBOX", "From: a@x\r\nMessage-Id: <z@x>\r\n\r\nbody"); }
    catch (e) { threw2 = e; }
    check("refuses oversize via safeMime opts",
          threw2 && ((threw2.code || "").indexOf("safe-mime/") !== -1 || (threw2.code || "").indexOf("mail-store/") !== -1));

    var threw3 = null;
    try { store.appendMessage("NoSuchFolder", _msg(["From: a@x", "Message-Id: <x@x>"], "body")); }
    catch (e) { threw3 = e; }
    check("refuses missing folder",
          threw3 && (threw3.code || "").indexOf("mail-store/no-folder") !== -1);
  } finally { _teardown(fx); }
}

async function testCustomFolder() {
  var fx = await _setupStore("custom");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var f = store.createFolder("Projects.Acme", { role: null });
    check("custom: folder exists", f && f.name === "Projects.Acme");
    var meta = store.appendMessage("Projects.Acme",
      _msg(["From: a@x", "Subject: Proj", "Message-Id: <p@x>"], "body"));
    check("custom: append works", typeof meta.objectid === "string");
  } finally { _teardown(fx); }
}

async function testMoveMessages() {
  var fx = await _setupStore("move");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var msg = _msg(["From: a@x", "To: b@y", "Subject: hi", "Message-Id: <m@x>",
                    "Date: Wed, 14 May 2026 12:00:00 +0000"], "body");
    var meta = store.appendMessage("INBOX", msg);

    // Pre-move quota: INBOX has 1 message + its bytes; Archive has 0.
    var qInbox0 = store.quota("INBOX");
    var qArch0  = store.quota("Archive");
    check("move-pre: INBOX count = 1", qInbox0.usedCount === 1);
    check("move-pre: Archive count = 0", qArch0.usedCount === 0);
    check("move-pre: INBOX bytes = msg size", qInbox0.usedBytes === meta.sizeBytes);

    // Move INBOX → Archive. Per RFC 7162 each folder owns its own
    // modseq; moved row joins destination's sequence at dstModseq.
    var r = store.moveMessages("INBOX", "Archive", [meta.objectid]);
    check("move: 1 changed", r.changed === 1);
    check("move: fromModseq bumped", typeof r.fromModseq === "number" && r.fromModseq > 0);
    check("move: toModseq bumped",   typeof r.toModseq === "number"   && r.toModseq > 0);

    // Post-move quota: INBOX zeroed, Archive carries the bytes.
    var qInbox1 = store.quota("INBOX");
    var qArch1  = store.quota("Archive");
    check("move-post: INBOX count = 0", qInbox1.usedCount === 0);
    check("move-post: Archive count = 1", qArch1.usedCount === 1);
    check("move-post: bytes moved", qArch1.usedBytes === meta.sizeBytes && qInbox1.usedBytes === 0);

    // Moved row's modseq should match destination's modseq_max (joined dest sequence).
    var fetched = store.fetchByObjectId("Archive", meta.objectid);
    check("move: row modseq matches dst", fetched.modseq === r.toModseq);
  } finally { _teardown(fx); }
}

async function testSearch() {
  var fx = await _setupStore("search");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var m1 = store.appendMessage("INBOX",
      _msg(["From: alice@example.com", "To: bob@example.com",
            "Subject: Kubernetes deploy notes", "Message-Id: <s1@x>"],
           "the kubernetes cluster is healthy"));
    var m2 = store.appendMessage("INBOX",
      _msg(["From: carol@example.com", "To: bob@example.com",
            "Subject: Lunch plans", "Message-Id: <s2@x>"],
           "want to grab lunch tomorrow"));

    // Body/subject text MATCH (FTS5 IN-subquery via whereMatch).
    var r1 = store.search("INBOX", { text: "kubernetes" });
    check("search: text=kubernetes hits only m1",
          r1.rows.length === 1 && r1.rows[0].objectid === m1.objectid && !!r1.matchExpr);

    // Subject-only column MATCH.
    var r2 = store.search("INBOX", { subject: "lunch" });
    check("search: subject=lunch hits only m2",
          r2.rows.length === 1 && r2.rows[0].objectid === m2.objectid);

    // Address column MATCH (from/to share addr_toks).
    var r3 = store.search("INBOX", { from: "alice@example.com" });
    check("search: from=alice hits only m1",
          r3.rows.length === 1 && r3.rows[0].objectid === m1.objectid);

    // No surviving tokens → empty result set, not a fallback.
    var r4 = store.search("INBOX", { text: "nonexistentterm" });
    check("search: no-match returns zero rows", r4.rows.length === 0);

    // No text-side filter → falls through to the modseq cursor.
    var r5 = store.search("INBOX", {});
    check("search: no-filter falls back to modseq cursor", r5.rows.length === 2);
  } finally { _teardown(fx); }
}

async function testHardExpunge() {
  var fx = await _setupStore("expunge");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var m1 = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: keep", "Message-Id: <e1@x>"], "keep me"));
    var m2 = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: drop", "Message-Id: <e2@x>"], "drop me"));
    var q0 = store.quota("INBOX");
    check("expunge-pre: 2 messages", q0.usedCount === 2);

    // hardExpunge resolves the candidate set through json_each(?).
    var ex = store.hardExpunge("INBOX", [m2.objectid]);
    check("expunge: m2 deleted", ex.deleted.length === 1 && ex.deleted[0] === m2.objectid);
    check("expunge: nothing refused", ex.refused.length === 0);

    // Row + FTS row + quota all reflect the delete.
    check("expunge: m2 fetch is null", store.fetchByObjectId("INBOX", m2.objectid) === null);
    check("expunge: m1 still present", store.fetchByObjectId("INBOX", m1.objectid) !== null);
    check("expunge: FTS no longer matches m2",
          store.search("INBOX", { subject: "drop" }).rows.length === 0);
    var q1 = store.quota("INBOX");
    check("expunge: quota decremented to 1", q1.usedCount === 1);

    // A legal-held message is refused, not deleted.
    store.setLegalHold([m1.objectid], { hold: true });
    var ex2 = store.hardExpunge("INBOX", [m1.objectid]);
    check("expunge: legal-held refused",
          ex2.deleted.length === 0 && ex2.refused.length === 1 &&
          ex2.refused[0].reason === "legal-hold");
    check("expunge: held m1 still present", store.fetchByObjectId("INBOX", m1.objectid) !== null);
  } finally { _teardown(fx); }
}

async function testRefusesBadBackend() {
  var threw = null;
  try { b.mailStore.create({ backend: {} }); }
  catch (e) { threw = e; }
  check("refuses backend without .prepare",
        threw && (threw.code || "").indexOf("mail-store/bad-backend") !== -1);
}

async function testByteCapMultibyte() {
  // maxBodyBytes is a BYTE cap on the decoded body text. A multibyte body
  // under the char count but over the byte cap must be refused.
  var fx = await _setupStore("bytecap");
  try {
    var store = b.mailStore.create({ backend: fx.db, maxBodyBytes: 30 });
    var mb = String.fromCharCode(0x4e2d).repeat(15); // 15 chars / 45 UTF-8 bytes; cap 30
    var msg = _msg(["From: a@example.com", "To: b@example.com", "Subject: x",
      "Date: Wed, 14 May 2026 12:00:00 +0000", "Content-Type: text/plain; charset=utf-8"], mb);
    var threw = null;
    try { store.appendMessage("INBOX", msg); } catch (e) { threw = e; }
    check("mailStore byte-cap: multibyte body over byte cap refused",
      threw && threw.code === "mail-store/oversize-body");
  } finally { _teardown(fx); }
}

async function testBadTablePrefix() {
  var fx = await _setupStore("badprefix");
  try {
    var threw = null;
    try { b.mailStore.create({ backend: fx.db, tablePrefix: "bad-prefix!;DROP" }); }
    catch (e) { threw = e; }
    check("create: invalid tablePrefix refused",
          threw && (threw.code || "").indexOf("mail-store/bad-table-prefix") !== -1);
  } finally { _teardown(fx); }
}

async function testBadHeaderIds() {
  var fx = await _setupStore("badids");
  try {
    var store = b.mailStore.create({ backend: fx.db });

    // Unbracketed Message-Id is refused under the strict default profile.
    var t1 = null;
    try { store.appendMessage("INBOX", _msg(["From: a@x", "Subject: s", "Message-Id: bareid@example.com"], "body")); }
    catch (e) { t1 = e; }
    check("append: bad Message-Id refused",
          t1 && (t1.code || "").indexOf("mail-store/bad-message-id") !== -1);

    // Valid Message-Id but unbracketed In-Reply-To.
    var t2 = null;
    try {
      store.appendMessage("INBOX",
        _msg(["From: a@x", "Subject: s", "Message-Id: <ok1@x>", "In-Reply-To: notbracketed@x"], "body"));
    } catch (e) { t2 = e; }
    check("append: bad In-Reply-To refused",
          t2 && (t2.code || "").indexOf("mail-store/bad-in-reply-to") !== -1);

    // Valid Message-Id but a References entry that fails the msg-id grammar.
    var t3 = null;
    try {
      store.appendMessage("INBOX",
        _msg(["From: a@x", "Subject: s", "Message-Id: <ok2@x>", "References: <good@x> notbracketed@x"], "body"));
    } catch (e) { t3 = e; }
    check("append: bad References entry refused",
          t3 && (t3.code || "").indexOf("mail-store/bad-references") !== -1);
  } finally { _teardown(fx); }
}

async function testOversizeMessageDirect() {
  var fx = await _setupStore("oversize");
  try {
    var store = b.mailStore.create({ backend: fx.db, maxMessageBytes: 10 });
    var threw = null;
    try { store.appendMessage("INBOX", _msg(["From: a@x", "Subject: big", "Message-Id: <big@x>"], "way over ten bytes of body")); }
    catch (e) { threw = e; }
    check("append: message over maxMessageBytes refused",
          threw && threw.code === "mail-store/oversize-message");
  } finally { _teardown(fx); }
}

async function testMissingFolderEveryReader() {
  var fx = await _setupStore("nofolder");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    function noFolder(label, fn) {
      var threw = null;
      try { fn(); } catch (e) { threw = e; }
      check(label + ": missing folder refused",
            threw && (threw.code || "").indexOf("mail-store/no-folder") !== -1);
    }
    noFolder("search",        function () { store.search("Ghost", { text: "x" }); });
    noFolder("queryByModseq", function () { store.queryByModseq("Ghost", {}); });
    noFolder("quota",         function () { store.quota("Ghost"); });
    noFolder("fetchByObjectId", function () { store.fetchByObjectId("Ghost", "obj_x"); });
    noFolder("hardExpunge",   function () { store.hardExpunge("Ghost", ["obj_x"]); });
    noFolder("moveMessages/from", function () { store.moveMessages("Ghost", "INBOX", []); });
    noFolder("moveMessages/to",   function () { store.moveMessages("INBOX", "Ghost", []); });
  } finally { _teardown(fx); }
}

async function testMoveBadObjectids() {
  var fx = await _setupStore("movebad");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var threw = null;
    try { store.moveMessages("INBOX", "Archive", "not-an-array"); }
    catch (e) { threw = e; }
    check("moveMessages: non-array objectids refused",
          threw && (threw.code || "").indexOf("mail-store/bad-input") !== -1);
  } finally { _teardown(fx); }
}

async function testCreateFolderBadName() {
  var fx = await _setupStore("badfolder");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var threw = null;
    try { store.createFolder("Bad Name With Spaces"); }
    catch (e) { threw = e; }
    check("createFolder: name outside [A-Za-z0-9_.-]+ refused",
          threw && (threw.code || "").indexOf("mail-store/bad-folder-name") !== -1);
  } finally { _teardown(fx); }
}

async function testQuotaAndThreadEmptyStates() {
  var fx = await _setupStore("empty");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    // A freshly-created folder has no quota row yet — quota() returns
    // zeroed defaults rather than throwing.
    store.createFolder("EmptyBox");
    var q = store.quota("EmptyBox");
    check("quota: fresh folder returns zeroed defaults",
          q.usedBytes === 0 && q.usedCount === 0 && q.capBytes === null && q.capCount === null);

    // threadFor on an unknown objectid returns an empty array.
    check("threadFor: unknown objectid → []",
          Array.isArray(store.threadFor("obj_missing")) && store.threadFor("obj_missing").length === 0);

    // fetchByObjectId on a present folder but missing id returns null.
    check("fetchByObjectId: unknown id → null",
          store.fetchByObjectId("INBOX", "obj_missing") === null);
  } finally { _teardown(fx); }
}

async function testHardExpungeEdgeCases() {
  var fx = await _setupStore("expungeedge");
  try {
    var store = b.mailStore.create({ backend: fx.db });

    // Empty objectid set — no-op result shape.
    var e0 = store.hardExpunge("INBOX", []);
    check("hardExpunge: empty set → empty result",
          e0.rows.length === 0 && e0.deleted.length === 0 && e0.refused.length === 0);

    // Non-array objectids — same no-op result shape.
    var eNull = store.hardExpunge("INBOX", null);
    check("hardExpunge: non-array set → empty result",
          eNull.rows.length === 0 && eNull.deleted.length === 0 && eNull.refused.length === 0);

    // Unknown id — refused with not-in-folder, nothing deleted.
    var eMiss = store.hardExpunge("INBOX", ["obj_notthere"]);
    check("hardExpunge: unknown id refused not-in-folder",
          eMiss.deleted.length === 0 && eMiss.refused.length === 1 &&
          eMiss.refused[0].reason === "not-in-folder");

    // Duplicate ids must be deduplicated so quota is not driven negative.
    var meta = store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: dup", "Message-Id: <dup@x>"], "dup body"));
    var eDup = store.hardExpunge("INBOX", [meta.objectid, meta.objectid]);
    check("hardExpunge: duplicate id collapses to one delete",
          eDup.deleted.length === 1 && eDup.deleted[0] === meta.objectid);
    var qAfter = store.quota("INBOX");
    check("hardExpunge: dedup keeps quota non-negative",
          qAfter.usedCount === 0 && qAfter.usedBytes === 0);
  } finally { _teardown(fx); }
}

async function testSearchColumnFiltersAndPagination() {
  var fx = await _setupStore("searchcols");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var m1 = store.appendMessage("INBOX",
      _msg(["From: alice@example.com", "To: dave@example.com",
            "Subject: quarterly report", "Message-Id: <c1@x>"],
           "the pipeline throughput doubled"));
    store.appendMessage("INBOX",
      _msg(["From: erin@example.com", "To: frank@example.com",
            "Subject: lunch", "Message-Id: <c2@x>"],
           "grab a sandwich"));

    // body-column MATCH.
    var rb = store.search("INBOX", { body: "throughput" });
    check("search: body filter hits only m1",
          rb.rows.length === 1 && rb.rows[0].objectid === m1.objectid);

    // to-address MATCH (addr_toks shared by from/to).
    var rt = store.search("INBOX", { to: "dave@example.com" });
    check("search: to filter hits only m1",
          rt.rows.length === 1 && rt.rows[0].objectid === m1.objectid);

    // Stopword-only term → no surviving tokens → falls back to the modseq
    // cursor (distinct from the empty-FTS-result branch) and carries a
    // nextModseq.
    var rs = store.search("INBOX", { subject: "the" });
    check("search: stopword-only term falls back to modseq cursor",
          rs.rows.length === 2 && typeof rs.nextModseq === "number" && rs.matchExpr === undefined);

    // Garbage limit floors to the default page size; oversized limit caps
    // at 1000 — neither throws through b.sql's integer-only limit().
    var rGarbage = store.search("INBOX", { text: "sandwich", limit: "not-a-number" });
    check("search: garbage limit tolerated", rGarbage.rows.length === 1);
    var rHuge = store.search("INBOX", { body: "throughput", limit: 999999 });
    check("search: oversized limit capped without throw", rHuge.rows.length === 1);
  } finally { _teardown(fx); }
}

async function testSearchPaginationSinceModseq() {
  var fx = await _setupStore("searchpage");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    for (var i = 0; i < 3; i += 1) {
      store.appendMessage("INBOX",
        _msg(["From: a@x", "Subject: report " + i, "Message-Id: <p" + i + "@x>"],
             "shared keyword body content"));
    }
    // Page 1 — one row via the FTS MATCH path, nextModseq advances.
    var page1 = store.search("INBOX", { body: "keyword", limit: 1 });
    check("search: FTS page 1 returns one row",
          page1.rows.length === 1 && typeof page1.nextModseq === "number");
    // Page 2 — resume from nextModseq, the FTS window excludes page 1.
    var page2 = store.search("INBOX", { body: "keyword", sinceModseq: page1.nextModseq, limit: 10 });
    check("search: FTS pagination resumes past page 1",
          page2.rows.length === 2 && page2.rows[0].modseq > page1.nextModseq);
  } finally { _teardown(fx); }
}

async function testSearchFtsUnavailableFallback() {
  var fx = await _setupStore("ftsunavail");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX",
      _msg(["From: a@x", "Subject: indexed subject", "Message-Id: <u1@x>"], "indexed body"));

    // Corrupt the on-disk FTS format marker so _ftsIndexUsable() reads
    // the index as non-final. search() must fall back to the modseq
    // cursor and flag ftsUnavailable rather than returning partial /
    // wrong-scheme FTS hits.
    fx.db.prepare("UPDATE " + store._tablePrefix + "_meta SET value = 'rebuilding' WHERE key = 'fts_format'").run();

    var r = store.search("INBOX", { subject: "indexed" });
    check("search: stale FTS marker falls back to modseq cursor",
          r.ftsUnavailable === true && r.rows.length === 1 && typeof r.nextModseq === "number");
  } finally { _teardown(fx); }
}

async function run() {
  await testBadTablePrefix();
  await testBadHeaderIds();
  await testOversizeMessageDirect();
  await testMissingFolderEveryReader();
  await testMoveBadObjectids();
  await testCreateFolderBadName();
  await testQuotaAndThreadEmptyStates();
  await testHardExpungeEdgeCases();
  await testSearchColumnFiltersAndPagination();
  await testSearchPaginationSinceModseq();
  await testSearchFtsUnavailableFallback();
  await testByteCapMultibyte();
  testSurface();
  await testBootstrap();
  await testAppendFetchRoundtrip();
  await testCondstoreModseq();
  await testThreading();
  await testFlags();
  await testQuota();
  await testLegalHold();
  await testSealedColumnsActuallySealed();
  await testRefusesBadInput();
  await testCustomFolder();
  await testMoveMessages();
  await testSearch();
  await testHardExpunge();
  await testRefusesBadBackend();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
