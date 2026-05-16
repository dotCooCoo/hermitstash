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

async function testRefusesBadBackend() {
  var threw = null;
  try { b.mailStore.create({ backend: {} }); }
  catch (e) { threw = e; }
  check("refuses backend without .prepare",
        threw && (threw.code || "").indexOf("mail-store/bad-backend") !== -1);
}

async function run() {
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
  await testRefusesBadBackend();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
