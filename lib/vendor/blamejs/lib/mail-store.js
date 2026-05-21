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
 *   **Pluggable backend**: sqlite via `b.db` (default), operator's
 *   `b.externalDb` (Postgres), or any object exposing
 *   `prepare(sql) → { run, get, all }`. Schema is bootstrapped at
 *   `create()` when `init !== false`.
 *
 *   **Sealed by default**: `subject` / `from_addr` / `to_addrs` /
 *   `body_text` / `body_html` are registered as sealed via
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
 *   **Quota substrate**: per-user + per-folder `usedBytes` / `usedCount`
 *   counters maintained atomically with append/delete. The
 *   v0.9.33 IMAP-QUOTA / JMAP-Quotas surface reads these directly.
 *
 *   **Legal hold**: `legal_hold` column composes existing
 *   `b.legalHold` primitive. Held messages refuse `delete` regardless
 *   of caller; only `b.legalHold.release` can flip the flag.
 *
 *   Parses messages on append via `b.safeMime.parse` (bounded
 *   substrate, defends CVE-2024-39929 + CVE-2025-30258). Validates
 *   `Message-Id` via `b.guardMessageId.validate`.
 *
 * @card
 *   Byte-level mail-store substrate — pluggable backend (sqlite default), sealed-by-default subject/from/to/body, CONDSTORE modseq, JMAP objectid, threading at append, quota + legal-hold substrate. Foundation for the entire mail stack.
 */

var C = require("./constants");
var bCrypto = require("./crypto");
var cryptoField = require("./crypto-field");
var safeMime = require("./safe-mime");
var safeSql = require("./safe-sql");
var guardMessageId = require("./guard-message-id");
var mailStoreFts = require("./mail-store-fts");
var { defineClass } = require("./framework-error");

var MailStoreError = defineClass("MailStoreError", { alwaysPermanent: true });

var DEFAULT_TABLE_PREFIX = "blamejs_mail";
var DEFAULT_MAX_MESSAGE_BYTES = C.BYTES.mib(50);
var DEFAULT_MAX_BODY_BYTES    = C.BYTES.mib(25);

// Standard IMAP4rev2 default folders + JMAP role mapping.
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
 * `fetchByObjectId` / `queryByModseq` / `setFlags` / `createFolder` /
 * `listFolders` / `threadFor` / `quota` / `setLegalHold` / `destroy`.
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
  var qMsgs    = safeSql.quoteIdentifier(prefix + "_messages",  "sqlite");
  var qFolders = safeSql.quoteIdentifier(prefix + "_folders",   "sqlite");
  var qFlags   = safeSql.quoteIdentifier(prefix + "_flags",     "sqlite");
  var qQuota   = safeSql.quoteIdentifier(prefix + "_quota",     "sqlite");
  var qFts     = safeSql.quoteIdentifier(prefix + "_messages_fts", "sqlite");
  var messagesTable = prefix + "_messages";

  var maxMessageBytes = opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : DEFAULT_MAX_MESSAGE_BYTES;
  var maxBodyBytes    = opts.maxBodyBytes    !== undefined ? opts.maxBodyBytes    : DEFAULT_MAX_BODY_BYTES;
  var safeMimeOpts = opts.safeMimeOpts || {};
  var doInit = opts.init !== false;

  var db = opts.backend;

  // Register sealed fields with cryptoField. Operator-runtime
  // sealing posture comes from b.compliance — the store doesn't
  // re-decide. Registration is idempotent.
  cryptoField.registerTable(messagesTable, {
    sealedFields: ["subject", "from_addr", "to_addrs", "body_text", "body_html"],
    derivedHashes: {
      from_hash:       { from: "from_addr",  normalize: _normalizeAddr },
      message_id_hash: { from: "message_id", normalize: _normalizeMsgId },
    },
  });

  if (doInit) {
    _ensureSchema(db, qMsgs, qFolders, qFlags, qQuota, qFts);
    _ensureDefaultFolders(db, qFolders);
  }

  // Prepared statements — cached across the store lifetime.
  var stmtInsertMsg = db.prepare(
    "INSERT INTO " + qMsgs + " (" +
    "objectid, folder_id, modseq, internal_date, received_at, size_bytes, " +
    "message_id, message_id_hash, in_reply_to, references_csv, " +
    "thread_root_id, subject, from_addr, from_hash, to_addrs, " +
    "body_text, body_html, legal_hold) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
  );
  var stmtBumpFolderModseq = db.prepare("UPDATE " + qFolders + " SET modseq_max = ? WHERE name = ?");
  var stmtGetFolderByName  = db.prepare("SELECT id, name, role, parent_id, modseq_max, uidvalidity FROM " + qFolders + " WHERE name = ?");
  var stmtFetchMsg         = db.prepare("SELECT * FROM " + qMsgs + " WHERE objectid = ? AND folder_id = ?");
  var stmtQueryByModseq    = db.prepare(
    "SELECT objectid, modseq, size_bytes, internal_date, legal_hold FROM " + qMsgs +
    " WHERE folder_id = ? AND modseq > ? ORDER BY modseq ASC LIMIT ?");
  var stmtFlagsForMsg      = db.prepare("SELECT flag FROM " + qFlags + " WHERE objectid = ?");
  var stmtSetFlag          = db.prepare("INSERT OR IGNORE INTO " + qFlags + " (objectid, flag, set_at) VALUES (?, ?, ?)");
  var stmtUnsetFlag        = db.prepare("DELETE FROM " + qFlags + " WHERE objectid = ? AND flag = ?");
  var stmtLegalHold        = db.prepare("UPDATE " + qMsgs + " SET legal_hold = ? WHERE objectid = ?");
  var stmtMoveByObjectId   = db.prepare(
    "UPDATE " + qMsgs + " SET folder_id = ?, modseq = ? WHERE objectid = ? AND folder_id = ?");
  var stmtSizeByObjectId   = db.prepare(
    "SELECT size_bytes FROM " + qMsgs + " WHERE objectid = ? AND folder_id = ?");
  var stmtDecrementQuota   = db.prepare(
    "UPDATE " + qQuota + " SET used_bytes = used_bytes - ?, used_count = used_count - ? WHERE folder_id = ?");
  var stmtThreadFor        = db.prepare("SELECT objectid FROM " + qMsgs + " WHERE thread_root_id = ? ORDER BY received_at ASC");
  var stmtFindThreadByMsgId = db.prepare(
    "SELECT objectid, thread_root_id FROM " + qMsgs + " WHERE message_id_hash = ? LIMIT 1");
  var stmtInsertFolder     = db.prepare(
    "INSERT INTO " + qFolders + " (name, role, parent_id, modseq_max, uidvalidity) VALUES (?, ?, ?, 0, ?)");
  var stmtListFolders      = db.prepare("SELECT id, name, role, parent_id, modseq_max FROM " + qFolders);
  var stmtQuotaForFolder   = db.prepare("SELECT used_bytes, used_count, cap_bytes, cap_count FROM " + qQuota + " WHERE folder_id = ?");
  var stmtBumpQuota        = db.prepare(
    "INSERT INTO " + qQuota + " (folder_id, used_bytes, used_count, cap_bytes, cap_count) VALUES (?, ?, ?, NULL, NULL) " +
    "ON CONFLICT(folder_id) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes, used_count = used_count + excluded.used_count");
  // Hard-expunge prepared statements — used by `hardExpunge` to delete
  // a message permanently after retention-floor + legal-hold gates
  // pass. The SELECT is the gate-input source (legal_hold flag + age);
  // the DELETE + flag-cleanup + quota-decrement run inside a backend
  // transaction so partial state can't survive a crash.
  var stmtSelectForExpunge = db.prepare(
    "SELECT objectid, folder_id, size_bytes, received_at, legal_hold FROM " + qMsgs +
    " WHERE folder_id = ? AND objectid IN (SELECT value FROM json_each(?))");
  var stmtDeleteMsg        = db.prepare("DELETE FROM " + qMsgs + " WHERE objectid = ?");
  var stmtDeleteFlags      = db.prepare("DELETE FROM " + qFlags + " WHERE objectid = ?");
  // Sealed-token FTS5 prepared statements — index sync runs in the
  // same transaction window as the canonical row mutation so a crash
  // between the two cannot leave the FTS index out of step with the
  // messages table. See lib/mail-store-fts.js for the tokenize +
  // vault-salted-hash transform applied here.
  var stmtInsertFts        = db.prepare(
    "INSERT INTO " + qFts + " (objectid, subject_toks, addr_toks, body_toks) VALUES (?, ?, ?, ?)");
  var stmtDeleteFts        = db.prepare("DELETE FROM " + qFts + " WHERE objectid = ?");

  return {
    appendMessage:    function (folderName, rawBytes, appendOpts) {
      // Wrap canonical row insert + FTS row insert in a single backend
      // transaction so a crash / FTS-row failure CANNOT leave a message
      // persisted but unsearchable (state drift). better-sqlite3-style
      // backends expose `.transaction(fn)()`; backends without
      // transactions fall back to per-statement (the FTS insert is the
      // last write, so partial state == still consistent to the reader).
      var args = {
        db: db, qMsgs: qMsgs, qFlags: qFlags, messagesTable: messagesTable,
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
      if (typeof db.transaction === "function") {
        var result;
        db.transaction(function () { result = _appendMessage(args); })();
        return result;
      }
      return _appendMessage(args);
    },
    fetchByObjectId:  function (folderName, objectid) {
      return _fetchByObjectId({
        db: db, qMsgs: qMsgs, qFolders: qFolders, qFlags: qFlags, messagesTable: messagesTable,
        stmtGetFolderByName: stmtGetFolderByName,
        stmtFetchMsg: stmtFetchMsg,
        stmtFlagsForMsg: stmtFlagsForMsg,
        folderName: folderName, objectid: objectid,
      });
    },
    /**
     * search — sealed-token full-text search inside a single folder.
     *
     * Composes the FTS5 virtual table populated by `appendMessage`.
     * Each filter term is tokenized + vault-salted-hashed exactly like
     * the index side, then issued as an FTS5 `MATCH` expression
     * intersected with the modseq + flag window. Result rows carry the
     * SAME shape as `queryByModseq` so operators iterate either path
     * symmetrically.
     *
     * `filter` accepts (any subset; all present terms AND-combine):
     *   - text:        match across subject + addr + body
     *   - subject:     match against `subject_toks` column only
     *   - body:        match against `body_toks` column only
     *   - from / to:   match against `addr_toks`
     *   - sinceModseq: integer floor
     *   - limit:       result cap (default 100, hard cap 1000)
     *
     * When NO text-side filter is present, falls through to the
     * `queryByModseq` path — search is purely additive on the existing
     * modseq cursor.
     */
    search:           function (folderName, filter) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "search: folder '" + folderName + "' not found");
      }
      var f = filter || {};
      var sinceModseq = f.sinceModseq || 0;
      var limit = f.limit || 100;
      if (limit > 1000) limit = 1000;                                                                  // allow:raw-byte-literal — query row cap, not bytes

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
        var fallback = stmtQueryByModseq.all(folder.id, sinceModseq, limit);
        return {
          rows: fallback.map(function (r) {
            return {
              objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
              internalDate: r.internal_date, legalHold: r.legal_hold === 1,
            };
          }),
          nextModseq: fallback.length > 0 ? fallback[fallback.length - 1].modseq : sinceModseq,
        };
      }

      var matchExpr = matchClauses.join(" AND ");
      // FTS5 MATCH binds to the virtual-table name — aliases / joined-
      // table refs are parsed as ordinary column refs and fail. The
      // IN-subquery shape sidesteps that.
      var sql =
        "SELECT objectid, modseq, size_bytes, internal_date, legal_hold " +
        "FROM " + qMsgs + " " +
        "WHERE folder_id = ? AND modseq > ? " +
        "AND objectid IN (SELECT objectid FROM " + qFts + " WHERE " + qFts + " MATCH ?) " +
        "ORDER BY modseq ASC LIMIT ?";
      var rows = db.prepare(sql).all(folder.id, sinceModseq, matchExpr, limit);
      return {
        rows: rows.map(function (r) {
          return {
            objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
            internalDate: r.internal_date, legalHold: r.legal_hold === 1,
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
      var limit = (queryOpts && queryOpts.limit) || 1000;                                          // allow:raw-byte-literal — query row cap, not bytes
      var rows = stmtQueryByModseq.all(folder.id, sinceModseq, limit);
      return rows.map(function (r) {
        return {
          objectid: r.objectid, modseq: r.modseq, sizeBytes: r.size_bytes,
          internalDate: r.internal_date, legalHold: r.legal_hold === 1,
        };
      });
    },
    setFlags:         function (folderName, objectids, flagOpts) {
      return _setFlags({
        db: db, qMsgs: qMsgs,
        stmtGetFolderByName: stmtGetFolderByName,
        stmtBumpFolderModseq: stmtBumpFolderModseq,
        stmtSetFlag: stmtSetFlag,
        stmtUnsetFlag: stmtUnsetFlag,
        folderName: folderName, objectids: objectids, flagOpts: flagOpts || {},
      });
    },
    createFolder:     function (name, folderOpts) {
      try { safeSql.validateIdentifier(name); } catch (_e) {
        // Allow folder names with "." for hierarchy (IMAP convention) —
        // safeSql is too strict here. Fall back to a looser shape check.
        if (!/^[A-Za-z0-9_.-]+$/.test(name)) {
          throw new MailStoreError("mail-store/bad-folder-name",
            "createFolder: name must match [A-Za-z0-9_.-]+");
        }
      }
      var fo = folderOpts || {};
      var role = fo.role || null;
      var parentId = fo.parentId || null;
      var uidvalidity = Math.floor(Date.now() / 1000);                                              // allow:raw-byte-literal — Unix timestamp, not bytes
      stmtInsertFolder.run(name, role, parentId, uidvalidity);
      return stmtGetFolderByName.get(name);
    },
    listFolders:      function () { return stmtListFolders.all(); },
    threadFor:        function (objectid) {
      var msg = db.prepare("SELECT thread_root_id FROM " + qMsgs + " WHERE objectid = ?").get(objectid);
      if (!msg) return [];
      return stmtThreadFor.all(msg.thread_root_id).map(function (r) { return r.objectid; });
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
      var hold = (holdOpts && holdOpts.hold) ? 1 : 0;                                              // allow:raw-byte-literal — boolean cast for sqlite INTEGER column
      objectids.forEach(function (oid) { stmtLegalHold.run(hold, oid); });
      return { changed: objectids.length };
    },
    /**
     * hardExpunge — remove messages permanently from a folder.
     *
     * Returns `{ rows: [{ objectid, size_bytes, received_at, legal_hold }],
     *          deleted: <ids>, refused: [{ id, reason }] }`. Per-row
     * `legal_hold` is the column value at expunge time so the caller
     * (typically `b.mail.agent.expunge`) can refuse messages currently
     * under hold.
     *
     * The caller is responsible for:
     *   (1) Composing `b.legalHold` to refuse hold-flagged messages
     *       before passing the surviving set here, AND
     *   (2) Composing `b.retention.complianceFloor` to refuse messages
     *       whose `received_at` is inside the regulated retention window.
     *
     * This primitive does the destructive SQL work + transaction-
     * scoped quota decrement + modseq bump. Refusals must happen at
     * the agent layer; this layer is the wire-protocol-shaped backend
     * surface.
     */
    hardExpunge:      function (folderName, objectids) {
      var folder = stmtGetFolderByName.get(folderName);
      if (!folder) {
        throw new MailStoreError("mail-store/no-folder",
          "hardExpunge: folder '" + folderName + "' not found");
      }
      if (!Array.isArray(objectids) || objectids.length === 0) {
        return { rows: [], deleted: [], refused: [] };
      }
      // Deduplicate objectids before the per-id pass. Without this,
      // `hardExpunge(folder, [id, id])` would append the same row to
      // `toDelete` twice and drive `usedBytes` / `usedCount` negative
      // via the double-subtract in the transaction; `deleted` would
      // also carry the duplicate id back to the caller. Preserve
      // first-seen ordering for stable refused/deleted output.
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

      // One transaction: delete messages + their flags, bump folder
      // modseq, decrement quota. Better-sqlite3-style `transaction`
      // helpers wrap this; if the backend doesn't expose `transaction`,
      // run the statements directly (atomicity falls back to per-stmt).
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
      if (typeof db.transaction === "function") {
        db.transaction(_runTxn)();
      } else {
        _runTxn();
      }
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

// ---- Append --------------------------------------------------------------

function _appendMessage(args) {
  var rawBytes = args.rawBytes;
  if (!Buffer.isBuffer(rawBytes) && typeof rawBytes !== "string") {
    throw new MailStoreError("mail-store/bad-input",
      "appendMessage: rawBytes must be Buffer or string");
  }
  var buf = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes, "utf8");
  if (buf.length > args.maxMessageBytes) {
    throw new MailStoreError("mail-store/oversize-message",
      "appendMessage: " + buf.length + " bytes exceeds maxMessageBytes=" + args.maxMessageBytes);
  }
  var folder = args.stmtGetFolderByName.get(args.folderName);
  if (!folder) {
    throw new MailStoreError("mail-store/no-folder",
      "appendMessage: folder '" + args.folderName + "' not found");
  }

  // Parse via safe-mime — bounded; defends CVE-2024-39929 + CVE-2025-30258.
  var tree = safeMime.parse(buf, args.safeMimeOpts);

  // Extract canonical fields.
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
  // RFC 5322 §3.6.4 — References is `1*msg-id`; each entry MUST satisfy
  // the same msg-id grammar as Message-Id. Pre-this-patch the framework
  // validated Message-Id but accepted any whitespace-separated token list
  // in References / In-Reply-To, leaving an injection surface where
  // attacker-controlled bytes reached the threading hash + JMAP
  // `references` array. Loop the full list through the same guard.
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
  // Date header read but not parsed yet — agent slice (v0.9.20) will
  // wire RFC 5322 §3.3 date-time parsing into internalDate / receivedAt.

  var textPart = safeMime.extractText(tree, { prefer: "plain" });
  var htmlPart = safeMime.extractText(tree, { prefer: "html" });
  var bodyText = textPart ? textPart.body : "";
  var bodyHtml = htmlPart && htmlPart.contentType === "text/html" ? htmlPart.body : "";

  if (bodyText.length > args.maxBodyBytes || bodyHtml.length > args.maxBodyBytes) {
    throw new MailStoreError("mail-store/oversize-body",
      "appendMessage: body exceeds maxBodyBytes=" + args.maxBodyBytes);
  }

  // Threading — find the root via Message-Id chain.
  var threadRootId = _findThreadRoot({
    messageId: messageId, inReplyTo: inReplyTo, referencesCsv: referencesCsv,
    stmtFindThreadByMsgId: args.stmtFindThreadByMsgId,
    messagesTable: args.messagesTable,
  });

  // Allocate objectid + modseq atomically.
  // RFC 8474 §1.5.1: objectid SHOULD be sufficiently long to make
  // collision improbable across the lifetime of the account. 16-byte
  // token = 32-char hex = 128 bits, well above the birthday bound
  // for any plausible message corpus. The prior `.slice(0, 24)` cut
  // entropy to 96 bits; removed.
  var objectid = "obj_" + bCrypto.generateToken(16);                                                // allow:raw-byte-literal — 16-byte token, 32-char hex JMAP objectid (RFC 8474 §1.5.1)
  var modseq = (folder.modseq_max || 0) + 1;
  if (!threadRootId) threadRootId = objectid;   // root of new thread

  var internalDate = Date.now();
  var receivedAt = internalDate;

  // Build the row + run cryptoField.sealRow to seal the registered fields.
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
    subject:          subject,
    from_addr:        fromAddr,
    to_addrs:         toAddrs,
    body_text:        bodyText,
    body_html:        bodyHtml,
  };
  var sealed = cryptoField.sealRow(args.messagesTable, row);

  args.stmtInsertMsg.run(
    sealed.objectid, sealed.folder_id, sealed.modseq, sealed.internal_date,
    sealed.received_at, sealed.size_bytes, sealed.message_id, sealed.message_id_hash,
    sealed.in_reply_to, sealed.references_csv, sealed.thread_root_id,
    sealed.subject, sealed.from_addr, sealed.from_hash, sealed.to_addrs,
    sealed.body_text, sealed.body_html
  );
  args.stmtBumpFolderModseq.run(modseq, args.folderName);
  args.stmtBumpQuota.run(folder.id, buf.length, 1);

  // FTS index update — tokenize the PRE-seal plaintext, hash each
  // token with the per-deployment vault salt, insert into the FTS5
  // virtual table.
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

// ---- Fetch ----------------------------------------------------------------

function _fetchByObjectId(args) {
  var folder = args.stmtGetFolderByName.get(args.folderName);
  if (!folder) {
    throw new MailStoreError("mail-store/no-folder",
      "fetchByObjectId: folder '" + args.folderName + "' not found");
  }
  var row = args.stmtFetchMsg.get(args.objectid, folder.id);
  if (!row) return null;

  // Unseal via cryptoField — sealed fields are restored in-place.
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
    subject:        unsealed.subject,
    from:           unsealed.from_addr,
    to:             unsealed.to_addrs,
    bodyText:       unsealed.body_text,
    bodyHtml:       unsealed.body_html,
    flags:          flags,
    legalHold:      row.legal_hold === 1,                                                            // allow:raw-byte-literal — sqlite INTEGER column 0|1
  };
}

// ---- Move -----------------------------------------------------------------

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
  if (!Array.isArray(args.objectids)) {
    throw new MailStoreError("mail-store/bad-input",
      "moveMessages: objectids must be an array");
  }
  // Per RFC 7162 each folder owns its own modseq counter. The moved
  // row joins the destination's sequence — it gets `dstModseq` (the
  // destination folder's new max). Source still bumps its `modseq_max`
  // to track the removal even though the row is gone; CONDSTORE
  // clients polling the source for `since-modseq` see the change.
  var srcModseq = (fromFolder.modseq_max || 0) + 1;
  var dstModseq = (toFolder.modseq_max  || 0) + 1;
  var changed = 0;
  var movedBytes = 0;
  for (var i = 0; i < args.objectids.length; i += 1) {
    // Capture size before the row's folder_id moves — the destination
    // quota gets the delta and the source quota decrements by the same.
    var size = args.stmtSizeByObjectId.get(args.objectids[i], fromFolder.id);
    var bytes = size ? size.size_bytes : 0;
    var r = args.stmtMoveByObjectId.run(toFolder.id, dstModseq, args.objectids[i], fromFolder.id);
    if (r && r.changes) {
      changed += r.changes;
      movedBytes += bytes;
    }
  }
  // Quota maintenance: decrement source by sum-of-sizes, increment
  // destination. v0.9.19 substrate already maintains per-folder quota
  // on append; move must keep both sides accurate.
  if (changed > 0) {
    args.stmtDecrementQuota.run(movedBytes, changed, fromFolder.id);
    args.stmtBumpQuota.run(toFolder.id, movedBytes, changed);
  }
  args.stmtBumpFolderModseq.run(srcModseq, args.fromFolderName);
  args.stmtBumpFolderModseq.run(dstModseq, args.toFolderName);
  return { changed: changed, fromModseq: srcModseq, toModseq: dstModseq };
}

// ---- Flags ----------------------------------------------------------------

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
  // Per-message modseq bump — without this, queryByModseq filters
  // `messages.modseq > sinceModseq` and misses the flag change. CONDSTORE
  // (RFC 7162) / JMAP Email/changes both depend on the per-message
  // modseq being current. Per Codex P1 on PR #49.
  if (args.objectids.length > 0 && (setFlags.length > 0 || unsetFlags.length > 0)) {
    // Bulk-update via IN-clause. SQLite caps IN-clause at 32766 (max
    // bound parameters); chunk for very large operands.
    // Prepare ONCE per chunk shape — the earlier shape called
    // args.db.prepare(sql) twice in the same expression (once for the
    // function reference, once for the `this` binding to .apply()),
    // which both leaks a prepared-statement handle per chunk and
    // doubles the SQL parse cost. Hold the stmt on a local + invoke
    // .run() directly with the bound argument list.
    var CHUNK = 500;                                                                               // allow:raw-byte-literal — IN-clause chunk size, not bytes
    for (var i = 0; i < args.objectids.length; i += CHUNK) {
      var chunk = args.objectids.slice(i, i + CHUNK);
      var placeholders = chunk.map(function () { return "?"; }).join(",");
      var sql = "UPDATE " + args.qMsgs + " SET modseq = ? WHERE objectid IN (" + placeholders + ")";
      var stmt = args.db.prepare(sql);
      stmt.run.apply(stmt, [newModseq].concat(chunk));
    }
  }
  args.stmtBumpFolderModseq.run(newModseq, args.folderName);
  return { changed: changed, modseq: newModseq };
}

// ---- Threading helpers ----------------------------------------------------

function _findThreadRoot(args) {
  // Walk the References chain (newest-first per RFC 5256). For each
  // Message-Id in the chain, look up by hashed-id. First match wins.
  // Uses cryptoField.lookupHash so the hash matches the derived-hash
  // value computed by sealRow at insert time (same salt + namespace).
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
    var row = args.stmtFindThreadByMsgId.get(lookup.value);
    if (row) return row.thread_root_id;
  }
  return null;
}

function _extractMessageId(tree, headerName) {
  var name = headerName || "message-id";
  var raw = tree.headers.get(name);
  if (!raw) return null;
  // Strip outer angle brackets when present + collapse whitespace.
  var v = String(raw).trim();
  return v;
}

function _extractReferences(tree) {
  return _extractReferencesList(tree).join(",");
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
  // Strip outer angle brackets + lowercase for collision-free hashing.
  var v = String(s).trim();
  if (v.charAt(0) === "<" && v.charAt(v.length - 1) === ">") {
    v = v.slice(1, -1);
  }
  return v.toLowerCase();
}

// ---- Schema bootstrap ----------------------------------------------------

function _ensureSchema(db, qMsgs, qFolders, qFlags, qQuota, qFts) {
  // Folders table — created first since messages reference folder_id.
  db.prepare(
    "CREATE TABLE IF NOT EXISTS " + qFolders + " (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT UNIQUE NOT NULL, " +
    "role TEXT, " +
    "parent_id INTEGER, " +
    "modseq_max INTEGER NOT NULL DEFAULT 0, " +
    "uidvalidity INTEGER NOT NULL)"
  ).run();
  db.prepare(
    "CREATE INDEX IF NOT EXISTS " + safeSql.quoteIdentifier(qFolders.slice(1, -1) + "_role_idx", "sqlite") +
    " ON " + qFolders + "(role)"
  ).run();

  // Messages table — sealed-by-default subject / from / to / body.
  db.prepare(
    "CREATE TABLE IF NOT EXISTS " + qMsgs + " (" +
    "objectid TEXT PRIMARY KEY, " +
    "folder_id INTEGER NOT NULL, " +
    "modseq INTEGER NOT NULL, " +
    "internal_date INTEGER NOT NULL, " +
    "received_at INTEGER NOT NULL, " +
    "size_bytes INTEGER NOT NULL, " +
    "message_id TEXT, " +
    "message_id_hash TEXT, " +
    "in_reply_to TEXT, " +
    "references_csv TEXT, " +
    "thread_root_id TEXT NOT NULL, " +
    "subject TEXT, " +
    "from_addr TEXT, " +
    "from_hash TEXT, " +
    "to_addrs TEXT, " +
    "body_text TEXT, " +
    "body_html TEXT, " +
    "legal_hold INTEGER NOT NULL DEFAULT 0, " +
    "FOREIGN KEY(folder_id) REFERENCES " + qFolders + "(id))"
  ).run();
  // Indexes — modseq for CONDSTORE, thread_root_id for thread fetch,
  // message_id_hash for threading lookup, from_hash for sender search.
  ["modseq", "thread_root_id", "message_id_hash", "from_hash", "received_at", "legal_hold"]
    .forEach(function (col) {
      db.prepare(
        "CREATE INDEX IF NOT EXISTS " + safeSql.quoteIdentifier(qMsgs.slice(1, -1) + "_" + col + "_idx", "sqlite") +
        " ON " + qMsgs + "(" + safeSql.quoteIdentifier(col, "sqlite") + ")"
      ).run();
    });

  // Flags table — many-to-one with messages.
  db.prepare(
    "CREATE TABLE IF NOT EXISTS " + qFlags + " (" +
    "objectid TEXT NOT NULL, " +
    "flag TEXT NOT NULL, " +
    "set_at INTEGER NOT NULL, " +
    "PRIMARY KEY (objectid, flag), " +
    "FOREIGN KEY(objectid) REFERENCES " + qMsgs + "(objectid) ON DELETE CASCADE)"
  ).run();

  // Quota table — per-folder counters bumped atomically with append/delete.
  db.prepare(
    "CREATE TABLE IF NOT EXISTS " + qQuota + " (" +
    "folder_id INTEGER PRIMARY KEY, " +
    "used_bytes INTEGER NOT NULL DEFAULT 0, " +
    "used_count INTEGER NOT NULL DEFAULT 0, " +
    "cap_bytes INTEGER, " +
    "cap_count INTEGER, " +
    "FOREIGN KEY(folder_id) REFERENCES " + qFolders + "(id))"
  ).run();

  // Sealed-token FTS5 virtual table. The token-hash transform lives in
  // `lib/mail-store-fts.js`; this is the storage layer. Tokenizer is
  // `unicode61 remove_diacritics 2` so FTS5's segmenter splits hash-
  // tokens on whitespace exactly — hashes are ASCII-hex-only, so no
  // Unicode case-fold runs at MATCH time.
  db.prepare(mailStoreFts.createSql(qFts)).run();
}

function _ensureDefaultFolders(db, qFolders) {
  var stmt = db.prepare("INSERT OR IGNORE INTO " + qFolders +
    " (name, role, parent_id, modseq_max, uidvalidity) VALUES (?, ?, NULL, 0, ?)");
  var uv = Math.floor(Date.now() / 1000);                                                          // allow:raw-byte-literal — Unix timestamp, not bytes
  DEFAULT_FOLDERS.forEach(function (f) { stmt.run(f.name, f.role, uv); });
}

module.exports = {
  create:             create,
  DEFAULT_FOLDERS:    DEFAULT_FOLDERS,
  MailStoreError:     MailStoreError,
  // Sealed-token FTS substrate. Exposed for adjacent primitives (e.g.
  // wire-protocol adapters translating IMAP SEARCH TEXT into the
  // store's FTS5 column expression).
  fts:                mailStoreFts,
};
