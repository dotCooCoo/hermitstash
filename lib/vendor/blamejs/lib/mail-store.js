// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mailStore
 * @nav        Mail
 * @title      Mail Store
 * @order      810
 *
 * @intro
 *   Byte-level mail-store substrate — the foundation every above-the-
 *   wire mail primitive composes (`b.mail.agent` at v0.9.20,
 *   `b.mail.server.mx` at v0.9.23, `b.mail.server.submission` at
 *   v0.9.24, IMAP/JMAP/POP3 at v0.9.27-29, ManageSieve at v0.9.30,
 *   DAV at v0.9.32).
 *
 *   No auth, no audit, no posture-enforcement at THIS layer — those
 *   live in the agent above. The store is the lowest-level
 *   atomic-append + sealed-column shape over a pluggable backend.
 *
 *   **Pluggable backend**: sqlite via `b.db` (default), or any object
 *   exposing `prepare(sql) → { run, get, all }` over a SQLite-compatible
 *   database. Schema is bootstrapped at `create()` when `init !== false`.
 *
 *   **Sealed by default**: `subject` / `from_addr` / `to_addrs` /
 *   `cc_addrs` / `reply_to` / `body_text` / `body_html` are registered as sealed via
 *   `b.cryptoField.sealRow`. A DB dump leaks zero recoverable PII
 *   content. Plaintext (forensic-queryable without unsealing):
 *   `objectid`, `modseq`, `internal_date`, `received_at`, `flags`,
 *   `size_bytes`, `legal_hold`, `from_hash`, `message_id_hash`.
 *
 *   **CONDSTORE-ready**: per-folder monotonic `modseq` counter
 *   (RFC 7162). Every state-changing op (`append` / `setFlags` /
 *   `delete`) bumps modseq atomically.
 *
 *   **JMAP-ready**: per-message `objectid` (RFC 8474) — stable
 *   cross-protocol identity. IMAP's UID + UIDVALIDITY + JMAP's
 *   Email/get's `id` all map to `objectid`.
 *
 *   **Threading at append**: JWZ algorithm + RFC 5256/9051 root via
 *   `Message-Id` + `In-Reply-To` + `References`. Threading state is
 *   maintained in the messages table itself (`thread_root_id` column)
 *   so JMAP `Thread/get` is a single index lookup.
 *
 *   **One thread belongs to one account**: every message carries a
 *   `thread_scope`, taken from `appendOpts.threadScope` or from the
 *   `owner` of the folder it lands in, and both the `Message-Id` lookup
 *   that picks a root and `threadFor` match only rows in that scope. A
 *   store that holds more than one account's folders gives each folder an
 *   `owner` at `createFolder`; without one, every folder shares the scope
 *   `""` and the store threads as a single account's store. `moveMessages`
 *   refuses a move between folders with different owners. Rows written
 *   before a scope existed carry `""`, and RFC 8621 §3 makes `threadId`
 *   immutable, so moving them into per-account scopes means reinserting
 *   them with new objectids.
 *
 *   **Attachment facts recorded at append**: `has_attachment` and
 *   `attachment_count` are filled from the parse the append already does, and
 *   carried in both the fetch and the listing projections as `hasAttachment`
 *   and `attachmentCount`. A mailbox page and the RFC 8621 `hasAttachment`
 *   property read them from the row rather than re-reading and re-parsing
 *   every message: measured on 2 MB messages at a page size of 50, deriving
 *   them per render cost 7.5 s against 192 ms for the listing alone.
 *
 *   **Quota substrate**: per-user + per-folder `usedBytes` / `usedCount`
 *   counters maintained atomically with append/delete. The
 *   v0.9.33 IMAP-QUOTA / JMAP-Quotas surface reads these directly.
 *
 *   **Legal hold**: `legal_hold` column composes existing
 *   `b.legalHold` primitive. Held messages refuse `delete` regardless
 *   of caller; only `b.legalHold.release` can flip the flag.
 *
 *   Parses messages on append via `b.safeMime.parse` (bounded
 *   substrate, defends CVE-2024-39929 + CVE-2026-26312). Validates
 *   `Message-Id` via `b.guardMessageId.validate`.
 *
 *   **Recipients for a reply**: `fetchByObjectId` returns `to`, `cc`,
 *   and `replyTo`. Each holds every instance of its header joined with
 *   `", "`, and an empty string when the message has none. `cc` and
 *   `replyTo` are `null` for a message appended before the store
 *   recorded them; `create()` adds their columns to an existing store,
 *   and the store keeps no raw message bytes to fill them in from.
 *   `Bcc` is not recorded.
 *
 * @card
 *   Byte-level mail-store substrate — pluggable backend (sqlite default), sealed-by-default subject/from/to/body, CONDSTORE modseq, JMAP objectid, threading at append, quota + legal-hold substrate. Foundation for the entire mail stack.
 */

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var bCrypto = require("./crypto");
var cryptoField = require("./crypto-field");
var dbSchema = require("./db-schema");
var vault = require("./vault");
var safeBuffer = require("./safe-buffer");
var safeMime = require("./safe-mime");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var guardMessageId = require("./guard-message-id");
var mailStoreFts = require("./mail-store-fts");
var { defineClass } = require("./framework-error");

var MailStoreError = defineClass("MailStoreError", { alwaysPermanent: true });

var DEFAULT_TABLE_PREFIX = "blamejs_mail";
var DEFAULT_MAX_MESSAGE_BYTES = C.BYTES.mib(50);
var DEFAULT_MAX_BODY_BYTES    = C.BYTES.mib(25);

var FTS_FORMAT_META_KEY = "fts_format";
var UIDVALIDITY_META_KEY = "uidvalidity_high_water";

var _openTransactions = new WeakSet();
var FTS_REBUILDING_SENTINEL = "rebuilding";

var INBOX_NAME = "INBOX";

function _isInboxName(name) {
  var text = String(name);
  return text.length === INBOX_NAME.length &&
    codepointClass.matchesAtFolded(text, 0, INBOX_NAME);
}

function _canonicalFolderName(name) {
  return _isInboxName(name) ? "INBOX" : name;
}

var DEFAULT_FOLDERS = Object.freeze([
  { name: "INBOX",   role: "inbox" },
  { name: "Sent",    role: "sent" },
  { name: "Drafts",  role: "drafts" },
  { name: "Trash",   role: "trash" },
  { name: "Junk",    role: "junk" },
  { name: "Archive", role: "archive" },
]);

/**
 * @primitive b.mailStore.create
 * @signature b.mailStore.create(opts)
 * @since     0.9.19
 * @status    stable
 * @related   b.safeMime, b.guardMessageId, b.cryptoField
 *
 * Build a mail-store handle. Returns an object with `appendMessage` /
 * `fetchByObjectId` / `search` / `queryByModseq` / `setFlags` /
 * `createFolder` / `listFolders` / `threadFor` / `quota` /
 * `moveMessages` / `setLegalHold` / `hardExpunge`.
 *
 * @opts
 *   backend:     object,   // required — sqlite-shaped { prepare(sql) → { run, get, all }, transaction(fn) }
 *   tablePrefix: string,   // default "blamejs_mail" — validated via safeSql.validateIdentifier
 *   init:        boolean,  // default true — bootstrap schema + register sealed fields + insert default folders
 *   compliance:  string,   // hipaa | pci-dss | gdpr | soc2 — pins sealing posture (default off → sealed-by-default uses framework defaults)
 *   maxMessageBytes: number,  // default 50 MiB
 *   maxBodyBytes:    number,  // default 25 MiB
 *   safeMimeOpts: object,  // pass-through to b.safeMime.parse
 *
 * `createFolder(name, { role, parentId, owner })` records `owner` as the
 * account that holds the folder, and `appendMessage(folder, bytes, {
 * threadScope })` names the scope directly. Both default to `""`.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.vault.init({ dataDir });
 *   await b.db.init({ dataDir, schema: [] });
 *   var store = b.mailStore.create({ backend: b.db });
 *   var meta = store.appendMessage("INBOX", messageBuffer);
 *   meta.objectid;   // → "obj_01HXYZ..."
 *   meta.modseq;     // → 42 (monotonic)
 */
function create(opts) {
  opts = opts || {};
  if (!opts.backend || typeof opts.backend.prepare !== "function") {
    throw new MailStoreError("mail-store/bad-backend",
      "mailStore.create: opts.backend must be sqlite-shaped (.prepare(sql) → { run, get, all })");
  }
  var prefix = opts.tablePrefix || DEFAULT_TABLE_PREFIX;
  try { safeSql.validateIdentifier(prefix); }
  catch (e) {
    throw new MailStoreError("mail-store/bad-table-prefix",
      "mailStore.create: tablePrefix is not a valid SQL identifier: " + e.message);
  }
  var messagesTable = prefix + "_messages";
  var foldersTable  = prefix + "_folders";
  var flagsTable    = prefix + "_flags";
  var quotaTable    = prefix + "_quota";
  var ftsTable      = prefix + "_messages_fts";
  var metaTable     = prefix + "_meta";
  var subscriptionsTable = prefix + "_subscriptions";
  var SQL = { dialect: "sqlite", quoteName: true };
  var qQuota = safeSql.quoteIdentifier(quotaTable, "sqlite", { allowReserved: true });

  var maxMessageBytes = opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : DEFAULT_MAX_MESSAGE_BYTES;
  var maxBodyBytes    = opts.maxBodyBytes    !== undefined ? opts.maxBodyBytes    : DEFAULT_MAX_BODY_BYTES;
  var safeMimeOpts = opts.safeMimeOpts || {};
  var doInit = opts.init !== false;

  var db = opts.backend;

  cryptoField.registerTable(messagesTable, {
    sealedFields: ["subject", "from_addr", "to_addrs", "cc_addrs", "reply_to", "body_text", "body_html"],
    derivedHashes: {
      from_hash:       { from: "from_addr",  normalize: _normalizeAddr },
      message_id_hash: { from: "message_id", normalize: _normalizeMsgId },
    },
  });

  if (doInit) {
    _ensureSchema(db, {
      messagesTable: messagesTable, foldersTable: foldersTable,
      flagsTable: flagsTable, quotaTable: quotaTable,
      ftsTable: ftsTable, metaTable: metaTable,
      subscriptionsTable: subscriptionsTable,
    });
    _ensureDefaultFolders(db, foldersTable);
    _seedUidvalidityHighWater();
    _separateSharedUidvalidity();
  }

  var stmtInsertMsg = db.prepare(sql.insert(messagesTable, SQL)
    .columns([
      "objectid", "folder_id", "modseq", "internal_date", "received_at",
      "size_bytes", "message_id", "message_id_hash", "in_reply_to",
      "references_csv", "thread_root_id", "thread_scope", "subject", "from_addr", "from_hash",
      "to_addrs", "cc_addrs", "reply_to", "body_text", "body_html", "legal_hold",
      "has_attachment", "attachment_count",
    ])
    .values([
      "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?",
      "?", "?",
    ]).toSql().sql);
  var stmtBumpFolderModseqExact = db.prepare(sql.update(foldersTable, SQL)
    .set("modseq_max", "?").where("name", "?").toSql().sql);
  var stmtBumpFolderModseq = {
    run: function (modseq, name) {
      return stmtBumpFolderModseqExact.run(modseq, _resolvedFolderName(name));
    },
  };
  var stmtGetFolderByNameExact = db.prepare(sql.select(foldersTable, SQL)
    .columns(["id", "name", "role", "parent_id", "modseq_max", "uidvalidity", "owner"])
    .where("name", "?").toSql().sql);
  var stmtGetFolderByName  = {
    get: function (name) {
      var exact = stmtGetFolderByNameExact.get(String(name));
      if (exact || !_isInboxName(name)) return exact;
      return stmtGetFolderByNameExact.get(INBOX_NAME);
    },
  };
  function _resolvedFolderName(name) {
    var folder = stmtGetFolderByName.get(name);
    return folder ? folder.name : _canonicalFolderName(name);
  }
  var stmtFetchMsg         = db.prepare(sql.select(messagesTable, SQL)
    .where("objectid", "?").where("folder_id", "?").toSql().sql);
  function _queryByModseqStmt(limit) {
    var n = Math.floor(Number(limit));
    if (!isFinite(n) || n < 0) n = 1000;
    return db.prepare(sql.select(messagesTable, SQL)
      .columns(["objectid", "modseq", "size_bytes", "internal_date", "legal_hold",
                "has_attachment", "attachment_count"])
      .where("folder_id", "?").whereOp("modseq", ">", "?")
      .orderBy("modseq", "asc").limit(n).toSql().sql);
  }
  function _queryByModseqRows(folderId, sinceModseq, limit) {
    return _queryByModseqStmt(limit).all(folderId, sinceModseq);
  }
  var stmtFlagsForMsg      = db.prepare(sql.select(flagsTable, SQL)
    .columns(["flag"]).where("objectid", "?").toSql().sql);
  var stmtSetFlag          = db.prepare(sql.upsert(flagsTable, SQL)
    .columns(["objectid", "flag", "set_at"]).values({ objectid: "?", flag: "?", set_at: "?" })
    .onConflict(["objectid", "flag"]).doNothing().toSql().sql);
  var stmtUnsetFlag        = db.prepare(sql.delete(flagsTable, SQL)
    .where("objectid", "?").where("flag", "?").toSql().sql);
  var stmtLegalHold        = db.prepare(sql.update(messagesTable, SQL)
    .set("legal_hold", "?").where("objectid", "?").toSql().sql);
  var stmtMoveByObjectId   = db.prepare(sql.update(messagesTable, SQL)
    .set("folder_id", "?").set("modseq", "?")
    .where("objectid", "?").where("folder_id", "?").toSql().sql);
  var stmtSizeByObjectId   = db.prepare(sql.select(messagesTable, SQL)
    .columns(["size_bytes"]).where("objectid", "?").where("folder_id", "?").toSql().sql);
  var stmtDecrementQuota   = db.prepare(sql.update(quotaTable, SQL)
    .setRaw("used_bytes", qQuota + ".\"used_bytes\" - ?", ["?"])
    .setRaw("used_count", qQuota + ".\"used_count\" - ?", ["?"])
    .where("folder_id", "?").toSql().sql);
  var stmtThreadFor        = db.prepare(sql.select(messagesTable, SQL)
    .columns(["objectid"]).where("thread_root_id", "?").where("thread_scope", "?")
    .orderBy("received_at", "asc").toSql().sql);
  var stmtFindThreadByMsgId = db.prepare(sql.select(messagesTable, SQL)
    .columns(["objectid", "thread_root_id"])
    .where("message_id_hash", "?").where("thread_scope", "?")
    .orderBy("received_at", "asc").orderBy("objectid", "asc")
    .limit(1).toSql().sql);
  var stmtInsertFolder     = db.prepare(sql.insert(foldersTable, SQL)
    .columns(["name", "role", "parent_id", "modseq_max", "uidvalidity", "owner"])
    .values(["?", "?", "?", "?", "?", "?"]).toSql().sql);
  var stmtListFolders      = db.prepare(sql.select(foldersTable, SQL)
    .columns(["id", "name", "role", "parent_id", "modseq_max", "owner", "uidvalidity"])
    .toSql().sql);
  var stmtListSubscriptions = db.prepare(sql.select(subscriptionsTable, SQL)
    .columns(["name"]).toSql().sql);
  var stmtSubscribe        = db.prepare(sql.upsert(subscriptionsTable, SQL)
    .columns(["name"]).values({ name: "?" }).onConflict(["name"]).doNothing().toSql().sql);
  var stmtUnsubscribe      = db.prepare(sql.delete(subscriptionsTable, SQL)
    .where("name", "?").toSql().sql);

  function _setSubscribed(rawName, value, who) {
    var name = _resolvedFolderName(rawName);
    if (value === 0) {
      stmtUnsubscribe.run(String(name));
      return { name: String(name), subscribed: false };
    }
    return _runInTransaction(db, function () {
      var folder = stmtGetFolderByName.get(name);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          who + ": no folder named '" + name + "'");
      }
      stmtSubscribe.run(folder.name);
      return { name: folder.name, subscribed: true };
    });
  }

  function _subscribedNames() {
    var out = Object.create(null);
    var rows = stmtListSubscriptions.all();
    for (var i = 0; i < rows.length; i += 1) out[rows[i].name] = true;
    return out;
  }
  var stmtQuotaForFolder   = db.prepare(sql.select(quotaTable, SQL)
    .columns(["used_bytes", "used_count", "cap_bytes", "cap_count"])
    .where("folder_id", "?").toSql().sql);
  var stmtBumpQuota        = db.prepare(sql.upsert(quotaTable, SQL)
    .columns(["folder_id", "used_bytes", "used_count", "cap_bytes", "cap_count"])
    .values({ folder_id: "?", used_bytes: "?", used_count: "?", cap_bytes: "?", cap_count: "?" })
    .onConflict(["folder_id"])
    .doUpdate({
      used_bytes: qQuota + ".\"used_bytes\" + EXCLUDED.\"used_bytes\"",
      used_count: qQuota + ".\"used_count\" + EXCLUDED.\"used_count\"",
    }).toSql().sql);
  var stmtSelectForExpunge = db.prepare(sql.select(messagesTable, SQL)
    .columns(["objectid", "folder_id", "size_bytes", "received_at", "legal_hold"])
    .where("folder_id", "?").whereInJsonEach("objectid", "?").toSql().sql);
  var stmtDeleteMsg        = db.prepare(sql.delete(messagesTable, SQL)
    .where("objectid", "?").toSql().sql);
  var stmtDeleteFlags      = db.prepare(sql.delete(flagsTable, SQL)
    .where("objectid", "?").toSql().sql);
  var stmtInsertFts        = db.prepare(sql.insert(ftsTable, SQL)
    .columns(["objectid", "subject_toks", "addr_toks", "body_toks"])
    .values(["?", "?", "?", "?"]).toSql().sql);
  var stmtDeleteFts        = db.prepare(sql.delete(ftsTable, SQL)
    .where("objectid", "?").toSql().sql);

  function _readFtsMarker() {
    try {
      var row = db.prepare(sql.select(metaTable, SQL)
        .columns(["value"]).where("key", "?").toSql().sql)
        .get(FTS_FORMAT_META_KEY);
      return row ? row.value : null;
    } catch (_e) {
      return null;
    }
  }
  var CURRENT_FTS_FMT = String(mailStoreFts.FTS_FORMAT_VERSION);
  function _ftsIndexUsable() {
    return _readFtsMarker() === CURRENT_FTS_FMT;
  }

  function _reindexFts() {
    var fmt = _readFtsMarker();
    if (fmt === CURRENT_FTS_FMT) return { reindexed: false, reason: "current" };

    var ftsCountRow = db.prepare(sql.select(ftsTable, SQL).count("*", "n").toSql().sql).get();
    var ftsCount = (ftsCountRow && ftsCountRow.n) || 0;
    var msgCountRow = db.prepare(sql.select(messagesTable, SQL).count("*", "n").toSql().sql).get();
    var msgCount = (msgCountRow && msgCountRow.n) || 0;

    if (fmt === null && ftsCount === 0 && msgCount === 0) {
      _writeFtsMarker(CURRENT_FTS_FMT);
      return { reindexed: false, reason: "fresh" };
    }

    if (!vault.isInitialized()) {
      throw new MailStoreError("mail-store/fts-reindex-vault-uninitialized",
        "mailStore.create: FTS index format is stale (marker=" +
        JSON.stringify(fmt) + ", current=" + CURRENT_FTS_FMT + ") and a " +
        "reindex from the sealed messages table requires the vault - call " +
        "b.vault.init(...) BEFORE b.mailStore.create(...). Refusing to leave " +
        "a stale, wrong-scheme search index queryable.");
    }

    _writeFtsMarker(FTS_REBUILDING_SENTINEL);

    var allRows;
    db.prepare("BEGIN IMMEDIATE").run();
    try {
      allRows = db.prepare(sql.select(messagesTable, SQL).toSql().sql).all();
      db.prepare(sql.delete(ftsTable, SQL).allowNoWhere().toSql().sql).run();
      for (var i = 0; i < allRows.length; i += 1) {
        var clear = cryptoField.unsealRow(messagesTable, allRows[i]);
        var ftsRow = mailStoreFts.rowFromMessage(messagesTable, {
          objectid: clear.objectid,
          subject:  clear.subject   || "",
          from:     clear.from_addr || "",
          to:       clear.to_addrs  || "",
          body:     clear.body_text || "",
        });
        stmtInsertFts.run(ftsRow.objectid, ftsRow.subject_toks,
          ftsRow.addr_toks, ftsRow.body_toks);
      }
      db.prepare("COMMIT").run();
    } catch (e) {
      try { db.prepare("ROLLBACK").run(); } catch (_re) { /* best-effort */ }
      throw new MailStoreError("mail-store/fts-reindex-failed",
        "mailStore.create: FTS reindex from the sealed messages table " +
        "failed and was rolled back (the prior index is intact); retry " +
        "after resolving: " + ((e && e.message) || String(e)));
    }

    _writeFtsMarker(CURRENT_FTS_FMT);
    return { reindexed: true, rows: allRows.length };
  }

  function _writeFtsMarker(value) {
    db.prepare(sql.upsert(metaTable, SQL)
      .columns(["key", "value"]).values({ key: "?", value: "?" })
      .onConflict(["key"]).doUpdateFromExcluded(["value"]).toSql().sql)
      .run(FTS_FORMAT_META_KEY, value);
  }

  function _recordedUidvalidityHighWater() {
    try {
      var row = db.prepare(sql.select(metaTable, SQL)
        .columns(["value"]).where("key", "?").toSql().sql).get(UIDVALIDITY_META_KEY);
      if (row && row.value !== null && row.value !== undefined) {
        var parsed = parseInt(String(row.value), 10);
        if (isFinite(parsed) && parsed > 0) return parsed;
      }
    } catch (_e) { return 0; }
    return 0;
  }

  function _seedUidvalidityHighWater() {
    try { return _runInTransaction(db, _seedOnce); }
    catch (e) {
      if (e && e.code === "mail-store/unusable-transaction") return _seedOnce();
      throw e;
    }
  }

  function _seedOnce() {
    var recorded = _recordedUidvalidityHighWater();
    var highest = recorded;
      try {
        var rows = db.prepare(sql.select(foldersTable, SQL)
          .columns(["uidvalidity"]).toSql().sql).all();
        for (var i = 0; i < rows.length; i += 1) {
          var value = parseInt(String(rows[i].uidvalidity), 10);
          if (isFinite(value) && value > highest) highest = value;
        }
      } catch (_e) { /* a store without the table yet has nothing to seed from */ }
      if (highest > recorded) {
        db.prepare(sql.upsert(metaTable, SQL)
          .columns(["key", "value"]).values({ key: "?", value: "?" })
          .onConflict(["key"]).doUpdateFromExcluded(["value"]).toSql().sql)
          .run(UIDVALIDITY_META_KEY, String(highest));
      }
      return highest;
  }

  function _allocateUidvalidity() {
    var now = Math.floor(Date.now() / 1000);
    var seen = _recordedUidvalidityHighWater();
    var next = now > seen ? now : seen + 1;
    db.prepare(sql.upsert(metaTable, SQL)
      .columns(["key", "value"]).values({ key: "?", value: "?" })
      .onConflict(["key"]).doUpdateFromExcluded(["value"]).toSql().sql)
      .run(UIDVALIDITY_META_KEY, String(next));
    return next;
  }

  function _nextUidvalidity() {
    return _runInTransaction(db, _allocateUidvalidity);
  }

  function _sharingFolderIds() {
    var rows;
    try {
      rows = db.prepare(sql.select(foldersTable, SQL)
        .columns(["id", "uidvalidity"]).toSql().sql).all();
    } catch (_e) { return []; }
    rows.sort(function (a, c) { return Number(a.id) - Number(c.id); });
    var taken = Object.create(null);
    var sharing = [];
    for (var i = 0; i < rows.length; i += 1) {
      var value = String(rows[i].uidvalidity);
      if (taken[value] === true) { sharing.push(rows[i].id); continue; }
      taken[value] = true;
    }
    return sharing;
  }

  function _separateSharedUidvalidity() {
    var sharing = _sharingFolderIds();
    if (sharing.length === 0) return;
    var stmt = db.prepare(sql.update(foldersTable, SQL)
      .set("uidvalidity", "?").where("id", "?").toSql().sql);
    function _separateOnce() {
      for (var i = 0; i < sharing.length; i += 1) {
        stmt.run(_allocateUidvalidity(), sharing[i]);
      }
    }
    try { _runInTransaction(db, _separateOnce); }
    catch (e) {
      if (e && e.code === "mail-store/unusable-transaction") { _separateOnce(); return; }
      throw e;
    }
  }

  if (doInit) {
    _reindexFts();
  }

  return {
    appendMessage:    function (folderName, rawBytes, appendOpts) {
      var args = {
        db: db, messagesTable: messagesTable,
        stmtInsertMsg: stmtInsertMsg,
        stmtInsertFts: stmtInsertFts,
        stmtBumpFolderModseq: stmtBumpFolderModseq,
        stmtGetFolderByName: stmtGetFolderByName,
        stmtFindThreadByMsgId: stmtFindThreadByMsgId,
        stmtBumpQuota: stmtBumpQuota,
        folderName: folderName, rawBytes: rawBytes, appendOpts: appendOpts || {},
        safeMimeOpts: safeMimeOpts,
        maxMessageBytes: maxMessageBytes,
        maxBodyBytes: maxBodyBytes,
      };
      return _runInTransaction(db, function () { return _appendMessage(args); });
    },
    fetchByObjectId:  function (folderName, objectid) {
      return _fetchByObjectId({
        db: db, messagesTable: messagesTable,
        stmtGetFolderByName: stmtGetFolderByName,
        stmtFetchMsg: stmtFetchMsg,
        stmtFlagsForMsg: stmtFlagsForMsg,
        folderName: folderName, objectid: objectid,
      });
    },
    search:           function (folderName, filter) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "search: folder '" + folderName + "' not found");
      }
      var f = filter || {};
      var sinceModseq = f.sinceModseq || 0;
      var limit = Math.floor(Number(f.limit));
      if (!isFinite(limit) || limit < 0) limit = 100;
      if (limit > 1000) limit = 1000;

      if (!_ftsIndexUsable()) {
        var nonFinal = _queryByModseqRows(folder.id, sinceModseq, limit);
        return {
          rows: nonFinal.map(function (r) {
            return {
              objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
              internalDate: r.internal_date, legalHold: r.legal_hold === 1,
              hasAttachment: _attachmentFlag(r.has_attachment),
              attachmentCount: _attachmentNumber(r.attachment_count),
            };
          }),
          nextModseq: nonFinal.length > 0 ? nonFinal[nonFinal.length - 1].modseq : sinceModseq,
          ftsUnavailable: true,
        };
      }

      var matchClauses = [];
      function addMatch(filterKey, term) {
        if (!term) return;
        var m = mailStoreFts.columnAndFieldFor(filterKey);
        if (!m) return;
        var expr = mailStoreFts.buildMatchExpression(messagesTable, m.field, term);
        if (expr) matchClauses.push(m.column + ":(" + expr + ")");
      }
      if (f.subject) addMatch("subject", f.subject);
      if (f.body)    addMatch("body",    f.body);
      if (f.from)    addMatch("from",    f.from);
      if (f.to)      addMatch("to",      f.to);
      if (f.text) {
        var perCol = ["subject", "body", "from"].map(function (key) {
          var m = mailStoreFts.columnAndFieldFor(key);
          var perColExpr = mailStoreFts.buildMatchExpression(messagesTable, m.field, f.text);
          return perColExpr ? "(" + m.column + ":(" + perColExpr + "))" : null;
        }).filter(Boolean);
        if (perCol.length > 0) {
          matchClauses.push("(" + perCol.join(" OR ") + ")");
        }
      }

      if (matchClauses.length === 0) {
        var fallback = _queryByModseqRows(folder.id, sinceModseq, limit);
        return {
          rows: fallback.map(function (r) {
            return {
              objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
              internalDate: r.internal_date, legalHold: r.legal_hold === 1,
              hasAttachment: _attachmentFlag(r.has_attachment),
              attachmentCount: _attachmentNumber(r.attachment_count),
            };
          }),
          nextModseq: fallback.length > 0 ? fallback[fallback.length - 1].modseq : sinceModseq,
        };
      }

      var matchExpr = matchClauses.join(" AND ");
      var ftsSub = sql.select(ftsTable, SQL)
        .columns(["objectid"]).whereMatch(ftsTable, "?");
      var matchStmt = db.prepare(sql.select(messagesTable, SQL)
        .columns(["objectid", "modseq", "size_bytes", "internal_date", "legal_hold",
                "has_attachment", "attachment_count"])
        .where("folder_id", "?").whereOp("modseq", ">", "?")
        .whereIn("objectid", ftsSub)
        .orderBy("modseq", "asc").limit(limit).toSql().sql);
      var rows = matchStmt.all(folder.id, sinceModseq, matchExpr);
      return {
        rows: rows.map(function (r) {
          return {
            objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
            internalDate: r.internal_date, legalHold: r.legal_hold === 1,
            hasAttachment: _attachmentFlag(r.has_attachment),
            attachmentCount: _attachmentNumber(r.attachment_count),
          };
        }),
        nextModseq: rows.length > 0 ? rows[rows.length - 1].modseq : sinceModseq,
        matchExpr: matchExpr,
      };
    },
    queryByModseq:    function (folderName, queryOpts) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "queryByModseq: folder '" + folderName + "' not found");
      }
      var sinceModseq = (queryOpts && queryOpts.sinceModseq) || 0;
      var limit = (queryOpts && queryOpts.limit) || 1000;
      var rows = _queryByModseqRows(folder.id, sinceModseq, limit);
      return rows.map(function (r) {
        return {
          objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
          internalDate: r.internal_date, legalHold: r.legal_hold === 1,
          hasAttachment: _attachmentFlag(r.has_attachment),
          attachmentCount: _attachmentNumber(r.attachment_count),
        };
      });
    },
    setFlags:         function (folderName, objectids, flagOpts) {
      return _setFlags({
        db: db, messagesTable: messagesTable,
        stmtGetFolderByName: stmtGetFolderByName,
        stmtBumpFolderModseq: stmtBumpFolderModseq,
        stmtSetFlag: stmtSetFlag,
        stmtUnsetFlag: stmtUnsetFlag,
        folderName: folderName, objectids: objectids, flagOpts: flagOpts || {},
      });
    },
    createFolder:     function (name, folderOpts) {
      try { safeSql.validateIdentifier(name); } catch (_e) {
        if (!/^[A-Za-z0-9_.-]+$/.test(name)) {
          throw new MailStoreError("mail-store/bad-folder-name",
            "createFolder: name must match [A-Za-z0-9_.-]+");
        }
      }
      if (_isInboxName(name) && name !== "INBOX") {
        throw new MailStoreError("mail-store/reserved-folder-name",
          "createFolder: '" + name + "' differs from INBOX only in case, and INBOX " +
          "is the delivery target; pick a name that is not a spelling of it");
      }
      var fo = folderOpts || {};
      var role = fo.role || null;
      var parentId = fo.parentId || null;
      var owner = fo.owner === undefined || fo.owner === null ? "" : fo.owner;
      if (typeof owner !== "string") {
        throw new MailStoreError("mail-store/bad-folder-owner",
          "createFolder: owner must be a string naming the account that holds the folder");
      }
      return _runInTransaction(db, function () {
        stmtInsertFolder.run(name, role, parentId, 0, _nextUidvalidity(), owner);
        return stmtGetFolderByName.get(name);
      });
    },
    listFolders:      function () {
      var subscribed = _subscribedNames();
      return stmtListFolders.all().map(function (row) {
        row.subscribed = subscribed[row.name] === true;
        return row;
      });
    },
    listSubscriptions: function () { return Object.keys(_subscribedNames()).sort(); },
    deleteFolder:     function (name) {
      if (_isInboxName(name)) {
        throw new MailStoreError("mail-store/inbox-undeletable",
          "deleteFolder: INBOX is the delivery target and cannot be deleted");
      }
      var stmtDoomed = db.prepare(sql.select(messagesTable, SQL)
        .columns(["objectid", "legal_hold"]).where("folder_id", "?").toSql().sql);
      var stmtChildren = db.prepare(sql.select(foldersTable, SQL)
        .columns(["name"]).where("parent_id", "?").toSql().sql);
      var stmtDropFlags = db.prepare(sql.delete(flagsTable, SQL)
        .where("objectid", "?").toSql().sql);
      var stmtDropMessages = db.prepare(sql.delete(messagesTable, SQL)
        .where("folder_id", "?").toSql().sql);
      var stmtDropQuota = db.prepare(sql.delete(quotaTable, SQL)
        .where("folder_id", "?").toSql().sql);
      var stmtDropFolder = db.prepare(sql.delete(foldersTable, SQL)
        .where("id", "?").toSql().sql);
      return _runInTransaction(db, function () {
        var folder = stmtGetFolderByName.get(name);
        if (!folder) {
          throw new MailStoreError("mail-store/no-folder",
            "deleteFolder: no folder named '" + name + "'");
        }
        var children = stmtChildren.all(folder.id);
        if (children.length > 0) {
          throw new MailStoreError("mail-store/folder-has-children",
            "deleteFolder: '" + name + "' is the parent of " + children.length +
            " folder" + (children.length === 1 ? "" : "s") + " (" +
            children.slice(0, 5).map(function (c) { return c.name; }).join(", ") +
            "); delete or reparent them first");
        }
        var doomed = stmtDoomed.all(folder.id);
        var held = doomed.filter(function (m) { return m.legal_hold === 1; });
        if (held.length > 0) {
          throw new MailStoreError("mail-store/folder-holds-legal-hold",
            "deleteFolder: '" + name + "' holds " + held.length + " message" +
            (held.length === 1 ? "" : "s") + " under legal hold; release the hold " +
            "before deleting the folder");
        }
        for (var i = 0; i < doomed.length; i += 1) {
          stmtDropFlags.run(doomed[i].objectid);
          stmtDeleteFts.run(doomed[i].objectid);
        }
        stmtDropMessages.run(folder.id);
        stmtDropQuota.run(folder.id);
        stmtDropFolder.run(folder.id);
        return { name: folder.name, deleted: true };
      });
    },
    renameFolder:     function (fromName, toName) {
      if (_isInboxName(fromName)) {
        throw new MailStoreError("mail-store/inbox-unrenamable",
          "renameFolder: RFC 9051 6.3.6 renaming INBOX moves its messages to the " +
          "new mailbox and leaves INBOX in place, which this store does not do; " +
          "create the destination and move the messages instead");
      }
      if (_isInboxName(toName)) {
        throw new MailStoreError("mail-store/reserved-folder-name",
          "renameFolder: '" + toName + "' is a spelling of INBOX, and a folder " +
          "under that name can never be deleted or renamed again");
      }
      try { safeSql.validateIdentifier(toName); } catch (_e) {
        if (!/^[A-Za-z0-9_.-]+$/.test(toName)) {
          throw new MailStoreError("mail-store/bad-folder-name",
            "renameFolder: name must match [A-Za-z0-9_.-]+");
        }
      }
      var stmtRenameFolder = db.prepare(sql.update(foldersTable, SQL)
        .set("name", "?").where("id", "?").toSql().sql);
      return _runInTransaction(db, function () {
        var folder = stmtGetFolderByName.get(fromName);
        if (!folder) {
          throw new MailStoreError("mail-store/no-folder",
            "renameFolder: no folder named '" + fromName + "'");
        }
        if (stmtGetFolderByName.get(toName)) {
          throw new MailStoreError("mail-store/folder-exists",
            "renameFolder: '" + toName + "' already exists");
        }
        stmtRenameFolder.run(toName, folder.id);
        return stmtGetFolderByName.get(toName);
      });
    },
    subscribeFolder:  function (name) { return _setSubscribed(name, 1, "subscribeFolder"); },
    unsubscribeFolder: function (name) { return _setSubscribed(name, 0, "unsubscribeFolder"); },
    threadFor:        function (objectid) {
      var msg = db.prepare(sql.select(messagesTable, SQL)
        .columns(["thread_root_id", "thread_scope"]).where("objectid", "?").toSql().sql)
        .get(objectid);
      if (!msg) return [];
      return stmtThreadFor.all(msg.thread_root_id, msg.thread_scope || "")
        .map(function (r) { return r.objectid; });
    },
    quota:            function (folderName) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "quota: folder '" + folderName + "' not found");
      }
      var q = stmtQuotaForFolder.get(folder.id);
      if (!q) return { usedBytes: 0, usedCount: 0, capBytes: null, capCount: null };
      return { usedBytes: q.used_bytes, usedCount: q.used_count, capBytes: q.cap_bytes, capCount: q.cap_count };
    },
    moveMessages:     function (fromFolderName, toFolderName, objectids) {
      return _moveMessages({
        stmtGetFolderByName: stmtGetFolderByName,
        stmtBumpFolderModseq: stmtBumpFolderModseq,
        stmtMoveByObjectId: stmtMoveByObjectId,
        stmtSizeByObjectId: stmtSizeByObjectId,
        stmtDecrementQuota: stmtDecrementQuota,
        stmtBumpQuota: stmtBumpQuota,
        fromFolderName: fromFolderName, toFolderName: toFolderName,
        objectids: objectids,
      });
    },
    setLegalHold:     function (objectids, holdOpts) {
      var hold = (holdOpts && holdOpts.hold) ? 1 : 0;
      objectids.forEach(function (oid) { stmtLegalHold.run(hold, oid); });
      return { changed: objectids.length };
    },
    hardExpunge:      function (folderName, objectids) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "hardExpunge: folder '" + folderName + "' not found");
      }
      if (!Array.isArray(objectids) || objectids.length === 0) {
        return { rows: [], deleted: [], refused: [] };
      }
      var seenIds = Object.create(null);
      var uniqueIds = [];
      for (var ui = 0; ui < objectids.length; ui += 1) {
        if (!seenIds[objectids[ui]]) {
          seenIds[objectids[ui]] = true;
          uniqueIds.push(objectids[ui]);
        }
      }
      objectids = uniqueIds;
      var rows = stmtSelectForExpunge.all(folder.id, JSON.stringify(objectids));
      var byId = Object.create(null);
      rows.forEach(function (r) { byId[r.objectid] = r; });
      var refused = [];
      var toDelete = [];
      for (var i = 0; i < objectids.length; i += 1) {
        var oid = objectids[i];
        var row = byId[oid];
        if (!row) {
          refused.push({ id: oid, reason: "not-in-folder" });
          continue;
        }
        if (row.legal_hold === 1) {
          refused.push({ id: oid, reason: "legal-hold" });
          continue;
        }
        toDelete.push(row);
      }
      if (toDelete.length === 0) return { rows: rows, deleted: [], refused: refused };

      var totalBytes = 0;
      var modseqBump = Date.now();
      function _runTxn() {
        for (var di = 0; di < toDelete.length; di += 1) {
          stmtDeleteFlags.run(toDelete[di].objectid);
          stmtDeleteFts.run(toDelete[di].objectid);
          stmtDeleteMsg.run(toDelete[di].objectid);
          totalBytes += toDelete[di].size_bytes || 0;
        }
        stmtBumpFolderModseq.run(modseqBump, folderName);
        if (totalBytes > 0 || toDelete.length > 0) {
          stmtDecrementQuota.run(totalBytes, toDelete.length, folder.id);
        }
      }
      _runInTransaction(db, _runTxn);
      return {
        rows:    rows,
        deleted: toDelete.map(function (r) { return r.objectid; }),
        refused: refused,
      };
    },
    _backend:         db,
    _tablePrefix:     prefix,
  };
}

function _trackableHandle(db) {
  return db !== null && (typeof db === "object" || typeof db === "function") ? db : null;
}

function _alreadyInTransaction(db) {
  var handle = _trackableHandle(db);
  if (handle !== null && _openTransactions.has(handle)) return true;
  return !!(db && db.isTransaction === true);
}

var _savepointSeq = 0;

function _nextSavepointName() {
  _savepointSeq += 1;
  return "blamejs_mail_sp_" + _savepointSeq;
}

function _openSavepointOrNull(db) {
  if (!db || typeof db.prepare !== "function") return null;
  var name = _nextSavepointName();
  try { db.prepare("SAVEPOINT " + name).run(); }
  catch (_e) { return null; }
  return name;
}

function _undoSavepoint(db, name) {
  try {
    db.prepare("ROLLBACK TO " + name).run();
    db.prepare("RELEASE " + name).run();
    return;
  } catch (_e) { /* the transaction-level abort below is the remaining answer */ }
  try { db.prepare("ROLLBACK").run(); } catch (_e) { /* nothing was left open */ }
}

function _runUnderSavepoint(db, name, fn) {
  var out;
  try {
    out = fn();
  } catch (e) {
    _undoSavepoint(db, name);
    throw e;
  }
  try {
    db.prepare("RELEASE " + name).run();
  } catch (e) {
    _undoSavepoint(db, name);
    throw e;
  }
  return out;
}

function _runInSavepoint(db, fn) {
  if (!db || typeof db.prepare !== "function") return fn();
  var name = _nextSavepointName();
  db.prepare("SAVEPOINT " + name).run();
  return _runUnderSavepoint(db, name, fn);
}

function _runInTransaction(db, fn) {
  if (_alreadyInTransaction(db)) return _runInSavepoint(db, fn);
  var handle = _trackableHandle(db);
  if (handle === null) return _runInTransactionOuter(db, fn);
  _openTransactions.add(handle);
  try { return _runInTransactionOuter(db, fn); }
  finally { _openTransactions.delete(handle); }
}

function _runInTransactionOuter(db, fn) {
  var name = _openSavepointOrNull(db);
  if (name !== null) return _runUnderSavepoint(db, name, fn);
  if (db && typeof db.transaction !== "function" && typeof db.prepare === "function") {
    return dbSchema.runInTransaction(db, fn);
  }
  if (!db || typeof db.transaction !== "function") return fn();
  var ran = false;
  var out = db.transaction(function () { ran = true; return fn(); });
  if (ran) return out;
  if (typeof out === "function") return out();
  throw new MailStoreError("mail-store/unusable-transaction",
    "backend.transaction(fn) neither ran the callback nor returned a function " +
    "to run it — the write cannot be made atomic, so it is not attempted");
}

function _attachmentFlag(value) {
  if (value === null || value === undefined) return null;
  return value === 1;
}

function _attachmentNumber(value) {
  if (value === null || value === undefined) return null;
  return value;
}

function _appendMessage(args) {
  var rawBytes = args.rawBytes;
  if (!Buffer.isBuffer(rawBytes) && typeof rawBytes !== "string") {
    throw new MailStoreError("mail-store/bad-input",
      "appendMessage: rawBytes must be Buffer or string");
  }
  var buf = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes, "utf8");
  if (safeBuffer.byteLengthOf(buf) > args.maxMessageBytes) {
    throw new MailStoreError("mail-store/oversize-message",
      "appendMessage: " + buf.length + " bytes exceeds maxMessageBytes=" + args.maxMessageBytes);
  }
  var folder = args.stmtGetFolderByName.get(args.folderName);
  if (!folder) {
    throw new MailStoreError("mail-store/no-folder",
      "appendMessage: folder '" + args.folderName + "' not found");
  }

  var tree = safeMime.parse(buf, args.safeMimeOpts);

  var messageId = _extractMessageId(tree);
  if (messageId) {
    try { guardMessageId.validate(messageId); }
    catch (e) {
      throw new MailStoreError("mail-store/bad-message-id",
        "appendMessage: Message-Id refused: " + e.message);
    }
  }
  var inReplyTo = _extractMessageId(tree, "in-reply-to");
  if (inReplyTo) {
    try { guardMessageId.validate(inReplyTo); }
    catch (e) {
      throw new MailStoreError("mail-store/bad-in-reply-to",
        "appendMessage: In-Reply-To refused: " + e.message);
    }
  }
  var refList = _extractReferencesList(tree);
  for (var __ri = 0; __ri < refList.length; __ri += 1) {
    try { guardMessageId.validate(refList[__ri]); }
    catch (e2) {
      throw new MailStoreError("mail-store/bad-references",
        "appendMessage: References entry refused: " + e2.message);
    }
  }
  var referencesCsv = refList.join(",");
  var subject = tree.headers.get("subject") || "";
  var fromAddr = tree.headers.get("from") || "";
  var toAddrs = (tree.headers.getAll("to") || []).join(", ");
  var ccAddrs = (tree.headers.getAll("cc") || []).join(", ");
  var replyTo = (tree.headers.getAll("reply-to") || []).join(", ");

  var textPart = safeMime.extractText(tree, { prefer: "plain" });
  var htmlPart = safeMime.extractText(tree, { prefer: "html" });
  var bodyText = textPart ? textPart.body : "";
  var bodyHtml = htmlPart && htmlPart.contentType === "text/html" ? htmlPart.body : "";

  if (safeBuffer.byteLengthOf(bodyText) > args.maxBodyBytes || safeBuffer.byteLengthOf(bodyHtml) > args.maxBodyBytes) {
    throw new MailStoreError("mail-store/oversize-body",
      "appendMessage: body exceeds maxBodyBytes=" + args.maxBodyBytes);
  }

  var threadScope = args.appendOpts.threadScope !== undefined &&
                    args.appendOpts.threadScope !== null
    ? args.appendOpts.threadScope
    : (folder.owner || "");
  if (typeof threadScope !== "string") {
    throw new MailStoreError("mail-store/bad-thread-scope",
      "appendMessage: threadScope must be a string naming the account the thread belongs to");
  }

  var threadRootId = _findThreadRoot({
    messageId: messageId, inReplyTo: inReplyTo, referencesCsv: referencesCsv,
    stmtFindThreadByMsgId: args.stmtFindThreadByMsgId,
    messagesTable: args.messagesTable,
    threadScope: threadScope,
  });

  var objectid = "obj_" + bCrypto.generateToken(16);
  var modseq = (folder.modseq_max || 0) + 1;
  if (!threadRootId) threadRootId = objectid;

  var internalDate = Date.now();
  var receivedAt = internalDate;

  var row = {
    objectid:         objectid,
    folder_id:        folder.id,
    modseq:           modseq,
    internal_date:    internalDate,
    received_at:      receivedAt,
    size_bytes:       buf.length,
    message_id:       messageId || "",
    in_reply_to:      inReplyTo || "",
    references_csv:   referencesCsv || "",
    thread_root_id:   threadRootId,
    thread_scope:     threadScope,
    subject:          subject,
    from_addr:        fromAddr,
    to_addrs:         toAddrs,
    cc_addrs:         ccAddrs,
    reply_to:         replyTo,
    body_text:        bodyText,
    body_html:        bodyHtml,
  };
  var attachments = safeMime.extractAttachments(tree);
  var sealed = cryptoField.sealRow(args.messagesTable, row);

  args.stmtInsertMsg.run(
    sealed.objectid, sealed.folder_id, sealed.modseq, sealed.internal_date,
    sealed.received_at, sealed.size_bytes, sealed.message_id, sealed.message_id_hash,
    sealed.in_reply_to, sealed.references_csv, sealed.thread_root_id,
    sealed.thread_scope,
    sealed.subject, sealed.from_addr, sealed.from_hash, sealed.to_addrs,
    sealed.cc_addrs, sealed.reply_to, sealed.body_text, sealed.body_html, 0,
    attachments.length > 0 ? 1 : 0, attachments.length
  );
  args.stmtBumpFolderModseq.run(modseq, args.folderName);
  args.stmtBumpQuota.run(folder.id, buf.length, 1, null, null);

  var ftsRow = mailStoreFts.rowFromMessage(args.messagesTable, {
    objectid: objectid,
    subject:  subject,
    from:     fromAddr,
    to:       toAddrs,
    body:     bodyText,
  });
  args.stmtInsertFts.run(ftsRow.objectid, ftsRow.subject_toks, ftsRow.addr_toks, ftsRow.body_toks);

  return { objectid: objectid, modseq: modseq, sizeBytes: buf.length, threadRootId: threadRootId };
}

function _fetchByObjectId(args) {
  var folder = args.stmtGetFolderByName.get(args.folderName);
  if (!folder) {
    throw new MailStoreError("mail-store/no-folder",
      "fetchByObjectId: folder '" + args.folderName + "' not found");
  }
  var row = args.stmtFetchMsg.get(args.objectid, folder.id);
  if (!row) return null;

  var unsealed = cryptoField.unsealRow(args.messagesTable, row);
  var flags = args.stmtFlagsForMsg.all(args.objectid).map(function (r) { return r.flag; });

  return {
    objectid:       unsealed.objectid,
    modseq:         unsealed.modseq,
    folder:         args.folderName,
    internalDate:   unsealed.internal_date,
    receivedAt:     unsealed.received_at,
    sizeBytes:      unsealed.size_bytes,
    messageId:      unsealed.message_id || null,
    inReplyTo:      unsealed.in_reply_to || null,
    referencesCsv:  unsealed.references_csv || null,
    threadRootId:   unsealed.thread_root_id,
    hasAttachment:  _attachmentFlag(unsealed.has_attachment),
    attachmentCount: _attachmentNumber(unsealed.attachment_count),
    subject:        unsealed.subject,
    from:           unsealed.from_addr,
    to:             unsealed.to_addrs,
    cc:             unsealed.cc_addrs === undefined ? null : unsealed.cc_addrs,
    replyTo:        unsealed.reply_to === undefined ? null : unsealed.reply_to,
    bodyText:       unsealed.body_text,
    bodyHtml:       unsealed.body_html,
    flags:          flags,
    legalHold:      row.legal_hold === 1,
  };
}

function _moveMessages(args) {
  var fromFolder = args.stmtGetFolderByName.get(args.fromFolderName);
  if (!fromFolder) {
    throw new MailStoreError("mail-store/no-folder",
      "moveMessages: from-folder '" + args.fromFolderName + "' not found");
  }
  var toFolder = args.stmtGetFolderByName.get(args.toFolderName);
  if (!toFolder) {
    throw new MailStoreError("mail-store/no-folder",
      "moveMessages: to-folder '" + args.toFolderName + "' not found");
  }
  if ((fromFolder.owner || "") !== (toFolder.owner || "")) {
    throw new MailStoreError("mail-store/cross-account-move",
      "moveMessages: '" + args.fromFolderName + "' is held by '" +
      (fromFolder.owner || "") + "' and '" + args.toFolderName + "' by '" +
      (toFolder.owner || "") + "'; a message keeps the thread of the account it " +
      "was filed under, so copy it into the other account instead");
  }
  if (!Array.isArray(args.objectids)) {
    throw new MailStoreError("mail-store/bad-input",
      "moveMessages: objectids must be an array");
  }
  var srcModseq = (fromFolder.modseq_max || 0) + 1;
  var dstModseq = (toFolder.modseq_max  || 0) + 1;
  var changed = 0;
  var movedBytes = 0;
  for (var i = 0; i < args.objectids.length; i += 1) {
    var size = args.stmtSizeByObjectId.get(args.objectids[i], fromFolder.id);
    var bytes = size ? size.size_bytes : 0;
    var r = args.stmtMoveByObjectId.run(toFolder.id, dstModseq, args.objectids[i], fromFolder.id);
    if (r && r.changes) {
      changed += r.changes;
      movedBytes += bytes;
    }
  }
  if (changed > 0) {
    args.stmtDecrementQuota.run(movedBytes, changed, fromFolder.id);
    args.stmtBumpQuota.run(toFolder.id, movedBytes, changed, null, null);
  }
  args.stmtBumpFolderModseq.run(srcModseq, args.fromFolderName);
  args.stmtBumpFolderModseq.run(dstModseq, args.toFolderName);
  return { changed: changed, fromModseq: srcModseq, toModseq: dstModseq };
}

function _setFlags(args) {
  var folder = args.stmtGetFolderByName.get(args.folderName);
  if (!folder) {
    throw new MailStoreError("mail-store/no-folder",
      "setFlags: folder '" + args.folderName + "' not found");
  }
  var newModseq = (folder.modseq_max || 0) + 1;
  var setFlags   = (args.flagOpts.set   || []);
  var unsetFlags = (args.flagOpts.unset || []);
  var changed = 0;
  args.objectids.forEach(function (oid) {
    setFlags.forEach(function (f) {
      var r = args.stmtSetFlag.run(oid, f, Date.now());
      if (r && r.changes) changed += r.changes;
    });
    unsetFlags.forEach(function (f) {
      var r = args.stmtUnsetFlag.run(oid, f);
      if (r && r.changes) changed += r.changes;
    });
  });
  if (args.objectids.length > 0 && (setFlags.length > 0 || unsetFlags.length > 0)) {
    var CHUNK = 500;
    for (var i = 0; i < args.objectids.length; i += CHUNK) {
      var chunk = args.objectids.slice(i, i + CHUNK);
      var stmtText = sql.update(args.messagesTable, { dialect: "sqlite", quoteName: true })
        .set("modseq", "?")
        .whereIn("objectid", chunk.map(function () { return "?"; }))
        .toSql().sql;
      var stmt = args.db.prepare(stmtText);
      stmt.run.apply(stmt, [newModseq].concat(chunk));
    }
  }
  args.stmtBumpFolderModseq.run(newModseq, args.folderName);
  return { changed: changed, modseq: newModseq };
}

function _findThreadRoot(args) {
  var candidates = [];
  if (args.inReplyTo) candidates.push(args.inReplyTo);
  if (args.referencesCsv) {
    var refs = args.referencesCsv.split(",").map(function (s) { return s.trim(); });
    for (var i = refs.length - 1; i >= 0; i -= 1) {
      if (refs[i]) candidates.push(refs[i]);
    }
  }
  for (var c = 0; c < candidates.length; c += 1) {
    var lookup = cryptoField.lookupHash(args.messagesTable, "message_id", candidates[c]);
    if (!lookup) continue;
    var row = args.stmtFindThreadByMsgId.get(lookup.value, args.threadScope);
    if (!row && lookup.legacyValue != null && lookup.legacyValue !== lookup.value) {
      row = args.stmtFindThreadByMsgId.get(lookup.legacyValue, args.threadScope);
    }
    if (row) return row.thread_root_id;
  }
  return null;
}

function _extractMessageId(tree, headerName) {
  var name = headerName || "message-id";
  var raw = tree.headers.get(name);
  if (!raw) return null;
  var v = String(raw).trim();
  return v;
}

function _extractReferencesList(tree) {
  var raw = tree.headers.get("references");
  if (!raw) return [];
  return String(raw).split(/\s+/).filter(function (s) { return s.length > 0; });
}

function _normalizeAddr(s) {
  return String(s).toLowerCase().trim();
}

function _normalizeMsgId(s) {
  var v = String(s).trim();
  if (v.charAt(0) === "<" && v.charAt(v.length - 1) === ">") {
    v = v.slice(1, -1);
  }
  return v.toLowerCase();
}

function _ensureSchema(db, tables) {
  var DDL = { dialect: "sqlite", quoteName: true };
  var foldersTable  = tables.foldersTable;
  var messagesTable = tables.messagesTable;
  var flagsTable    = tables.flagsTable;
  var quotaTable    = tables.quotaTable;
  var ftsTable      = tables.ftsTable;
  var metaTable     = tables.metaTable;
  var subscriptionsTable = tables.subscriptionsTable;

  function _ddl(built) { db.prepare(built.sql).run(); }

  _ddl(sql.createTable(foldersTable, [
    { name: "id",          autoIncrement: true },
    { name: "name",        type: "text", notNull: true, unique: true },
    { name: "role",        type: "text" },
    { name: "parent_id",   type: "int" },
    { name: "modseq_max",  type: "int", notNull: true, default: 0 },
    { name: "uidvalidity", type: "int", notNull: true },
    { name: "owner",       type: "text" },
  ], DDL));

  _ddl(sql.createTable(subscriptionsTable, [
    { name: "name", type: "text", notNull: true, unique: true },
  ], DDL));
  _ddl(sql.createIndex(foldersTable + "_role_idx", foldersTable, ["role"], DDL));
  function _folderColumns() {
    return db.prepare(sql.catalog.tableInfo(foldersTable).sql).all()
      .map(function (c) { return c.name; });
  }
  if (_folderColumns().indexOf("owner") === -1) {
    try {
      _ddl(sql.alterTable(foldersTable, { addColumn: { name: "owner", type: "text" } }, DDL));
    } catch (e) {
      if (_folderColumns().indexOf("owner") === -1) throw e;
    }
  }

  _ddl(sql.createTable(messagesTable, [
    { name: "objectid",        type: "text", primaryKey: true },
    { name: "folder_id",       type: "int",  notNull: true,
      references: { table: foldersTable, column: "id" } },
    { name: "modseq",          type: "int",  notNull: true },
    { name: "internal_date",   type: "int",  notNull: true },
    { name: "received_at",     type: "int",  notNull: true },
    { name: "size_bytes",      type: "int",  notNull: true },
    { name: "message_id",      type: "text" },
    { name: "message_id_hash", type: "text" },
    { name: "in_reply_to",     type: "text" },
    { name: "references_csv",  type: "text" },
    { name: "thread_root_id",  type: "text", notNull: true },
    { name: "thread_scope",    type: "text", notNull: true, default: "" },
    { name: "has_attachment",  type: "int" },
    { name: "attachment_count", type: "int" },
    { name: "subject",         type: "text" },
    { name: "from_addr",       type: "text" },
    { name: "from_hash",       type: "text" },
    { name: "to_addrs",        type: "text" },
    { name: "cc_addrs",        type: "text" },
    { name: "reply_to",        type: "text" },
    { name: "body_text",       type: "text" },
    { name: "body_html",       type: "text" },
    { name: "legal_hold",      type: "int",  notNull: true, default: 0 },
  ], DDL));
  function _messageColumns() {
    return db.prepare(sql.catalog.tableInfo(messagesTable).sql).all()
      .map(function (c) { return c.name; });
  }
  var presentColumns = _messageColumns();
  ["cc_addrs", "reply_to"].forEach(function (col) {
    if (presentColumns.indexOf(col) !== -1) return;
    try {
      _ddl(sql.alterTable(messagesTable, { addColumn: { name: col, type: "text" } }, DDL));
    } catch (e) {
      if (_messageColumns().indexOf(col) === -1) throw e;
    }
  });
  if (presentColumns.indexOf("thread_scope") === -1) {
    try {
      _ddl(sql.alterTable(messagesTable,
        { addColumn: { name: "thread_scope", type: "text", notNull: true, default: "" } }, DDL));
    } catch (e) {
      if (_messageColumns().indexOf("thread_scope") === -1) throw e;
    }
  }
  ["has_attachment", "attachment_count"].forEach(function (col) {
    if (presentColumns.indexOf(col) !== -1) return;
    try {
      _ddl(sql.alterTable(messagesTable, { addColumn: { name: col, type: "int" } }, DDL));
    } catch (e) {
      if (_messageColumns().indexOf(col) === -1) throw e;
    }
  });
  _ddl(sql.createIndex(messagesTable + "_thread_scope_msgid_idx", messagesTable,
    ["thread_scope", "message_id_hash"], DDL));
  ["modseq", "thread_root_id", "message_id_hash", "from_hash", "received_at", "legal_hold"]
    .forEach(function (col) {
      _ddl(sql.createIndex(messagesTable + "_" + col + "_idx", messagesTable, [col], DDL));
    });

  _ddl(sql.createTable(flagsTable, [
    { name: "objectid", type: "text", notNull: true,
      references: { table: messagesTable, column: "objectid", onDelete: "CASCADE" } },
    { name: "flag",     type: "text", notNull: true },
    { name: "set_at",   type: "int",  notNull: true },
  ], Object.assign({ primaryKey: ["objectid", "flag"] }, DDL)));

  _ddl(sql.createTable(quotaTable, [
    { name: "folder_id",  type: "int", primaryKey: true,
      references: { table: foldersTable, column: "id" } },
    { name: "used_bytes", type: "int", notNull: true, default: 0 },
    { name: "used_count", type: "int", notNull: true, default: 0 },
    { name: "cap_bytes",  type: "int" },
    { name: "cap_count",  type: "int" },
  ], DDL));

  _ddl(sql.createVirtualTable(ftsTable, {
    columns: [
      { name: "objectid", unindexed: true },
      "subject_toks", "addr_toks", "body_toks",
    ],
    tokenize: "unicode61 remove_diacritics 2",
  }));

  _ddl(sql.createTable(metaTable, [
    { name: "key",   type: "text", primaryKey: true },
    { name: "value", type: "text" },
  ], DDL));
}

function _ensureDefaultFolders(db, foldersTable) {
  var existing = db.prepare(sql.select(foldersTable, { dialect: "sqlite", quoteName: true })
    .columns(["id"]).toSql().sql).all();
  if (existing.length > 0) return;
  var stmtText = sql.upsert(foldersTable, { dialect: "sqlite", quoteName: true })
    .columns(["name", "role", "parent_id", "modseq_max", "uidvalidity"])
    .values({ name: "?", role: "?", parent_id: "?", modseq_max: "?", uidvalidity: "?" })
    .onConflict(["name"]).doNothing().toSql().sql;
  var stmt = db.prepare(stmtText);
  var uv = Math.floor(Date.now() / 1000);
  DEFAULT_FOLDERS.forEach(function (f, i) {
    stmt.run(f.name, f.role, null, 0, uv + i);
  });
}

module.exports = {
  create:             create,
  DEFAULT_FOLDERS:    DEFAULT_FOLDERS,
  MailStoreError:     MailStoreError,
  fts:                mailStoreFts,
};
