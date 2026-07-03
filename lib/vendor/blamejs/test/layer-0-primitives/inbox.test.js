// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.inbox — transactional dedupe-on-receive (companion to b.outbox).
 *
 * Smoke covers the primitive against an in-memory mock externalDb that
 * implements transaction(fn) + query(sql, args). Real Postgres / SQLite
 * round-trips live in test/integration.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && pattern.test(msg));
}

function _makeFakeExternalDb() {
  var rows = [];
  var lastChanges = 0;
  var fakeXdb = {
    dialect: "sqlite",
    query: async function (sql, args) {
      var sqlLower = sql.toLowerCase();
      // recordReceive composes through b.sql.upsert(...).doNothing()
      // .returning(...) -> `INSERT INTO ... ON CONFLICT (...) DO NOTHING
      // RETURNING "message_id"`. Match either that or the legacy
      // `INSERT OR IGNORE ... RETURNING` shape. The b.sql column order is
      // [message_id, source, ...] so args[0] = mid, args[1] = src.
      var isDedupeInsert = sqlLower.indexOf("insert or ignore") !== -1 ||
        (sqlLower.indexOf("insert into") !== -1 &&
         sqlLower.indexOf("on conflict") !== -1 &&
         sqlLower.indexOf("do nothing") !== -1);
      if (isDedupeInsert) {
        var src = args[1], mid = args[0];
        var existing = rows.filter(function (r) { return r.source === src && r.message_id === mid; });
        if (existing.length === 0) {
          rows.push({ message_id: mid, source: src, received_at: new Date().toISOString(), processed_at: null, metadata_json: args[2] });
          lastChanges = 1;
          // RETURNING — DO NOTHING returns one row on a fresh insert, none
          // on a duplicate. The migrated path RETURNs "message_id" (the
          // portable presence sentinel); the freshness check only reads
          // rows.length, so return the inserted message_id row.
          if (sqlLower.indexOf("returning") !== -1) {
            return { rows: [{ message_id: mid }] };
          }
        } else {
          lastChanges = 0;
          if (sqlLower.indexOf("returning") !== -1) {
            return { rows: [] };
          }
        }
        return { rows: [] };
      }
      if (sqlLower.indexOf("select changes()") !== -1) {
        return { rows: [{ c: lastChanges }] };
      }
      if (sqlLower.indexOf("update") !== -1 && sqlLower.indexOf("processed_at") !== -1) {
        var src2 = args[0], mid2 = args[1];
        for (var i = 0; i < rows.length; i += 1) {
          if (rows[i].source === src2 && rows[i].message_id === mid2) {
            rows[i].processed_at = new Date().toISOString();
          }
        }
        return { rows: [] };
      }
      if (sqlLower.indexOf("select count") !== -1) {
        var processed = rows.filter(function (r) { return r.processed_at != null; }).length;
        return { rows: [{ total: rows.length, processed: processed }] };
      }
      if (sqlLower.indexOf("select 1 from") !== -1) {
        var src3 = args[0], mid3 = args[1];
        var hits = rows.filter(function (r) { return r.source === src3 && r.message_id === mid3; });
        return { rows: hits.length > 0 ? [{ "1": 1 }] : [] };
      }
      if (sqlLower.indexOf("delete from") !== -1) {
        lastChanges = rows.length;
        rows.length = 0;
        return { rows: [] };
      }
      if (sqlLower.indexOf("create table") !== -1 || sqlLower.indexOf("create index") !== -1) {
        return { rows: [] };
      }
      return { rows: [] };
    },
  };
  return {
    xdb: fakeXdb,
    db: {
      dialect: "sqlite",
      transaction: async function (fn) { return await fn(fakeXdb); },
    },
  };
}

async function testByteCapMultibyte() {
  // maxPayloadBytes is a BYTE cap on the serialized metadata. A multibyte
  // value under the char count but over the byte cap must be refused.
  var fake = _makeFakeExternalDb();
  var inbox = b.inbox.create({ externalDb: fake.db, table: "bytecap_inbox", audit: false, maxPayloadBytes: 30 });
  var mb = String.fromCharCode(0x4e2d).repeat(15); // 15 chars / 45 UTF-8 bytes
  var threw = null;
  try {
    await inbox.recordReceive({ messageId: "mb-1", source: "kafka:test", metadata: { note: mb } }, fake.xdb);
  } catch (e) { threw = e; }
  check("inbox byte-cap: multibyte metadata over byte cap refused",
    threw && threw.code === "inbox/bad-receive");
}

async function run() {
  await testByteCapMultibyte();
  check("b.inbox is object",                      typeof b.inbox === "object");
  check("b.inbox.create is fn",                   typeof b.inbox.create === "function");

  rejects("inbox.create: missing externalDb",
    function () { b.inbox.create({ table: "x" }); }, /externalDb/);
  var fake = _makeFakeExternalDb();
  rejects("inbox.create: bad table name",
    function () { b.inbox.create({ externalDb: fake.db, table: "bad-name" }); }, /not a safe SQL identifier/);
  // A non-finite byte/length cap must be refused — Infinity would disable the
  // cap and admit unbounded stored payloads / identifiers.
  rejects("inbox.create: maxPayloadBytes Infinity refused",
    function () { b.inbox.create({ externalDb: fake.db, table: "t", maxPayloadBytes: Infinity }); }, /maxPayloadBytes|finite/);
  rejects("inbox.create: messageIdMaxLen Infinity refused",
    function () { b.inbox.create({ externalDb: fake.db, table: "t", messageIdMaxLen: Infinity }); }, /messageIdMaxLen|finite/);

  var inbox = b.inbox.create({
    externalDb: fake.db,
    table: "test_inbox",
    audit: false,
  });
  check("inbox.create: returns instance",         typeof inbox.handle === "function");
  check("inbox.create: table",                    inbox.table === "test_inbox");

  await inbox.declareSchema(fake.xdb);

  // First receive: fresh (handler fires).
  var first = await inbox.handle({
    messageId: "msg-1", source: "kafka:test",
  }, async function (xdb) {
    return "first-handler-result";
  });
  check("inbox.handle: first receive fresh",      first.fresh === true);
  check("inbox.handle: handler result",            first.result === "first-handler-result");

  // Second receive of the same (source, messageId): duplicate (handler does not fire).
  var dup = await inbox.handle({
    messageId: "msg-1", source: "kafka:test",
  }, async function () {
    throw new Error("must not run on duplicate");
  });
  check("inbox.handle: duplicate skips handler",  dup.fresh === false);
  check("inbox.handle: duplicate result null",    dup.result === null);

  // Different source, same message-id → fresh.
  var fresh2 = await inbox.handle({
    messageId: "msg-1", source: "kafka:other",
  }, async function () { return "ok"; });
  check("inbox.handle: different source fresh",   fresh2.fresh === true);

  var threwSource = false;
  try {
    await inbox.handle({ messageId: "x" }, async function () {});
  } catch (e) { threwSource = true; check("inbox.handle: missing source", /source/.test(e.message)); }
  check("inbox.handle: missing source threw",     threwSource);

  var threwHandler = false;
  try {
    await inbox.handle({ messageId: "x", source: "y" }, "not a function");
  } catch (e) { threwHandler = true; check("inbox.handle: bad handler", /handler must be/.test(e.message)); }
  check("inbox.handle: bad handler threw",        threwHandler);

  // recordReceive low-level API.
  var freshLow = await inbox.recordReceive({
    messageId: "low-1", source: "kafka:test",
  }, fake.xdb);
  check("inbox.recordReceive: fresh",             freshLow === true);
  var dupLow = await inbox.recordReceive({
    messageId: "low-1", source: "kafka:test",
  }, fake.xdb);
  check("inbox.recordReceive: duplicate",         dupLow === false);

  await inbox.markProcessed({ messageId: "low-1", source: "kafka:test" }, fake.xdb);

  var stats = await inbox.getStats();
  check("inbox.getStats: total > 0",              stats.total > 0);

  var deleted = await inbox.sweep();
  check("inbox.sweep: returns deleted count",     typeof deleted === "number");

  // retentionDays: Infinity means "retain indefinitely" — sweep() must be a
  // no-op (delete nothing), not compute an invalid horizon. Before the fix the
  // sqlite path threw RangeError on `new Date(now - Infinity).toISOString()`.
  var foreverInbox = b.inbox.create({
    externalDb: fake.db, table: "forever_inbox", audit: false, retentionDays: Infinity,
  });
  await foreverInbox.declareSchema(fake.xdb);
  var foreverDeleted = await foreverInbox.sweep();
  check("inbox.sweep: retentionDays Infinity retains all (no-op, no throw)", foreverDeleted === 0);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (err) { console.error(err.stack || err); process.exit(1); });
}
