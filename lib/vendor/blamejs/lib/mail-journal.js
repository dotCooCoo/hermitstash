"use strict";

/**
 * @module     b.mail.journal
 * @nav        Mail
 * @title      Mail journal (WORM)
 * @order      260
 * @since      0.9.57
 *
 * @intro
 *   Write-Once-Read-Many (WORM) journal archive for inbound + outbound
 *   mail. Financial-services regulations ([SEC 17a-4(f)](https://www.ecfr.gov/current/title-17/chapter-II/part-240/section-240.17a-4),
 *   [FINRA Rule 4511](https://www.finra.org/rules-guidance/rulebooks/finra-rules/4511)),
 *   [HIPAA §164.312(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164#p-164.312(b)) audit-trail
 *   requirements, and [MiFID II Article 16(7)](https://www.esma.europa.eu/sites/default/files/library/mifid-ii-recordkeeping-final-report.pdf)
 *   EU financial-communications retention all require a tamper-evident,
 *   retention-bound, legal-hold-aware copy of every message that
 *   crosses the mail boundary. v0.9.57 lands that primitive as a thin
 *   composition over the framework's existing WORM substrate.
 *
 *   What it composes:
 *
 *     - `b.objectStore.bucketOps({ objectLockEnabled: true })` — the
 *       WORM storage layer. Object Lock (S3 / Azure Immutable Blob /
 *       GCS retention-policy) is the substrate that makes "write once"
 *       enforceable at the storage layer, not just policy.
 *     - `b.vault.seal` — every journaled payload (headers + envelope
 *       + body) is sealed at rest with the operator's vault key. The
 *       DB row keeps forensic-queryable plaintext columns
 *       (`journalId`, `direction`, `archivedAt`, `actorId`,
 *       `messageId`, `sizeBytes`, `regimes[]`, `legalHold`,
 *       `storageKey`); everything else lives in the single sealed
 *       blob column.
 *     - `b.legalHold` — every entry carries a `legalHold` flag. Once
 *       set, the entry is exempt from retention-window expiry even
 *       after the floor passes.
 *     - `b.retention.complianceFloor` — per-regime retention windows
 *       (HIPAA 6yr, SOX 7yr, MiFID II 5yr, FINRA / SEC 17a-4 6yr).
 *       Operator declares which regimes apply via `regimes: ["sec-17a-4",
 *       "finra-4511", "hipaa"]`; the journal computes the longest
 *       window across all declared regimes and tags every entry.
 *     - `b.audit.safeEmit` — every record / read / list operation
 *       emits an audit event on the framework's existing audit chain.
 *
 *   What it does NOT do:
 *
 *     - **No delete surface.** The WORM bucket enforces immutability;
 *       this primitive doesn't even expose `delete()`. Operators who
 *       need GDPR Art. 17 erasure on a journaled message MUST crypto-
 *       erase via `b.cryptoField.eraseRow` (rotates the per-row key
 *       so the sealed bytes become permanently undecryptable) — the
 *       operator's posture choice between "regulatory record-keeping
 *       overrides the erasure right" and "right-to-be-forgotten
 *       overrides record-keeping". The framework refuses to pick.
 *     - **No automated expiry.** `expireSurface()` returns the list of
 *       entries past their retention floor + not under legal hold;
 *       operators decide what to do with that list (it's typically
 *       "leave them; the storage cost is negligible and the audit
 *       trail benefit is real").
 *     - **No MX / submission auto-wiring.** v0.9.57 ships the
 *       primitive; the next slice will wire `record()` from the
 *       v0.9.46 MX listener + v0.9.47 submission listener so every
 *       accepted inbound + outbound message journals automatically.
 *
 * @card
 *   WORM journal archive for inbound + outbound mail. SEC 17a-4 /
 *   FINRA 4511 / HIPAA §164.312(b) / MiFID II Article 16(7) compliant
 *   by composition; no new storage / crypto / retention vocabulary.
 */

var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { defineClass } = require("./framework-error");
var lazyRequire = require("./lazy-require");

var MailJournalError = defineClass("MailJournalError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

// Regime → retention-floor (ms). Per-regime values mirror the
// b.retention.COMPLIANCE_RETENTION_FLOOR_MS table for the postures
// that share names; mail-journal extends with finance-specific
// regimes that don't map 1:1 to a single retention posture.
var REGIME_FLOOR_MS = Object.freeze({
  "sec-17a-4":  C.TIME.days(365 * 6),                                                                 // SEC Rule 17a-4(f) — 6 years
  "finra-4511": C.TIME.days(365 * 6),                                                                 // FINRA Rule 4511 — 6 years (parity with SEC)
  "hipaa":      C.TIME.days(365 * 6),                                                                 // HIPAA §164.316(b)(2)(i)
  "mifid-ii":   C.TIME.days(365 * 5),                                                                 // MiFID II Art. 16(7) — 5 years minimum
  "sox":        C.TIME.days(365 * 7),                                                                 // SOX §802 — 7 years
  "gdpr":       C.TIME.days(365 * 6),                                                                 // GDPR-adjacent communications floor (UK ICO + ePrivacy guidance)
  "soc2":       C.TIME.days(365),                                                                     // 1 year — SOC 2 audit window
});

var ALLOWED_DIRECTIONS = Object.freeze({ inbound: 1, outbound: 1, internal: 1 });

function _validateRegimes(regimes) {
  if (!Array.isArray(regimes) || regimes.length === 0) {
    throw new MailJournalError("mail-journal/bad-regimes",
      "b.mail.journal.create: opts.regimes must be a non-empty array of regime names " +
      "(known: " + Object.keys(REGIME_FLOOR_MS).join(", ") + ")");
  }
  if (regimes.length > 16) {                                                                          // regime-list cap
    throw new MailJournalError("mail-journal/bad-regimes",
      "b.mail.journal.create: opts.regimes must contain at most 16 entries");
  }
  for (var i = 0; i < regimes.length; i++) {
    var r = regimes[i];
    if (!Object.prototype.hasOwnProperty.call(REGIME_FLOOR_MS, r)) {
      throw new MailJournalError("mail-journal/bad-regimes",
        "b.mail.journal.create: unknown regime '" + r + "' (known: " +
        Object.keys(REGIME_FLOOR_MS).join(", ") + ")");
    }
  }
}

function _computedFloor(regimes) {
  var maxMs = 0;
  for (var i = 0; i < regimes.length; i++) {
    var ms = REGIME_FLOOR_MS[regimes[i]];
    if (ms > maxMs) maxMs = ms;
  }
  return maxMs;
}

/**
 * @primitive  b.mail.journal.create
 * @signature  b.mail.journal.create(opts)
 * @since      0.9.57
 * @status     stable
 * @compliance hipaa, sox-404, soc2, dora
 * @related    b.objectStore, b.cryptoField, b.legalHold, b.retention.complianceFloor
 *
 * Returns a journal handle bound to the operator-supplied WORM bucket.
 * The bucket SHOULD have Object Lock / immutability enabled at the
 * storage layer (S3 ObjectLockEnabled, Azure Immutable Blob, GCS
 * retention-policy) — the journal primitive emits an audit warning at
 * create-time if the bucket reports `objectLockEnabled: false`, but
 * doesn't refuse since some operator deployments use FS-level WORM
 * via filesystem ACLs the framework can't introspect.
 *
 * @opts
 *   storage:     b.objectStore.bucketOps handle,
 *   regimes:     string[],
 *   vault:       b.vault handle,
 *   legalHold:   b.legalHold handle,
 *   db:          b.db handle,
 *   audit:       b.audit namespace,
 *   namespace:   string,
 *
 * @example
 *   var journal = b.mail.journal.create({
 *     storage:    operatorWormBucket,
 *     regimes:    ["sec-17a-4", "finra-4511"],
 *     vault:      b.vault,
 *     legalHold:  b.legalHold,
 *     db:         b.db,
 *   });
 *   await journal.record({
 *     direction:  "inbound",
 *     actorId:    "compliance",
 *     messageId:  "<abc@example.com>",
 *     headers:    { from: "alice@x.com", to: "bob@y.com", subject: "Q3 results" },
 *     bodyBytes:  rfc822Bytes,
 *     envelope:   { mailFrom: "alice@x.com", rcptTo: ["bob@y.com"] },
 *   });
 */
function create(opts) {
  validateOpts.requireObject(opts, "b.mail.journal.create",
    MailJournalError, "mail-journal/bad-opts");
  if (!opts.storage || typeof opts.storage.putObject !== "function") {
    throw new MailJournalError("mail-journal/bad-storage",
      "b.mail.journal.create: opts.storage must be a b.objectStore.bucketOps handle " +
      "(must expose putObject / getObject / listObjects)");
  }
  if (!opts.vault || typeof opts.vault.seal !== "function") {
    throw new MailJournalError("mail-journal/bad-vault",
      "b.mail.journal.create: opts.vault must be a b.vault handle");
  }
  if (!opts.legalHold || typeof opts.legalHold.isHeld !== "function") {
    throw new MailJournalError("mail-journal/bad-legal-hold",
      "b.mail.journal.create: opts.legalHold must be a b.legalHold handle (must expose isHeld)");
  }
  if (!opts.db || typeof opts.db.runSql !== "function") {
    throw new MailJournalError("mail-journal/bad-db",
      "b.mail.journal.create: opts.db must be a b.db handle (must expose runSql)");
  }
  _validateRegimes(opts.regimes);

  var namespace = typeof opts.namespace === "string" && opts.namespace.length > 0 ?
                  opts.namespace : "mail-journal";
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(namespace)) {                                                     // namespace token shape
    throw new MailJournalError("mail-journal/bad-namespace",
      "b.mail.journal.create: opts.namespace must match [a-zA-Z0-9_-]{1,64}");
  }
  var floorMs = _computedFloor(opts.regimes);

  function _emit(action, outcome, metadata) {
    var auditMod = opts.audit || audit();
    if (!auditMod || typeof auditMod.safeEmit !== "function") return;
    try {
      auditMod.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit must not throw inside journal write */ }
  }

  // Plaintext index table — keeps `journalId` / `direction` / `actorId`
  // / `messageId` / `archivedAt` / `sizeBytes` / `regimes` / `legalHold`
  // queryable without unsealing the payload. The payload (headers +
  // body) lives in the WORM bucket sealed via b.cryptoField.sealRow.
  //
  // The journal table is an operator-namespaced local table (NOT a
  // framework `_blamejs_` table that clusterStorage rewrites), so every
  // statement composes b.sql with quoteName:true — b.sql validates the
  // identifier through b.safeSql and emits the dialect-quoted form,
  // running against opts.db (the local sqlite handle) directly. `_t()`
  // opens each verb builder pre-bound to this table so the name resolves
  // in exactly one place.
  var rawTable = "_mail_journal_" + namespace.replace(/-/g, "_");
  var TBL_OPTS = { dialect: "sqlite", quoteName: true };
  function _t(verb) { return sql[verb](rawTable, TBL_OPTS); }

  // Bootstrap DDL — CREATE TABLE + the archived_at / message_id indexes.
  // runSql is a multi-statement helper, so the three b.sql DDL strings
  // join with `;` into one call (each b.sql build is a single validated
  // statement; the join is the multi-statement boundary runSql expects).
  var ddl = [
    sql.createTable(rawTable, [
      { name: "journal_id",     type: "text", primaryKey: true },
      { name: "direction",      type: "text", notNull: true },
      { name: "actor_id",       type: "text" },
      { name: "message_id",     type: "text" },
      { name: "archived_at",    type: "int",  notNull: true },
      { name: "size_bytes",     type: "int",  notNull: true },
      { name: "regimes",        type: "text", notNull: true },
      { name: "floor_until",    type: "int",  notNull: true },
      { name: "legal_hold",     type: "int",  notNull: true, default: 0 },
      { name: "storage_key",    type: "text", notNull: true, unique: true },
      { name: "sealed_payload", type: "blob", notNull: true },
    ], TBL_OPTS).sql,
    sql.createIndex(rawTable + "_archived_at_idx", rawTable, ["archived_at"], TBL_OPTS).sql,
    sql.createIndex(rawTable + "_message_id_idx",  rawTable, ["message_id"],  TBL_OPTS).sql,
  ].join(";");
  opts.db.runSql(ddl);

  async function record(req) {
    validateOpts.requireObject(req, "mail.journal.record",
      MailJournalError, "mail-journal/bad-record");
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_DIRECTIONS, req.direction)) {
      throw new MailJournalError("mail-journal/bad-direction",
        "mail.journal.record: opts.direction must be 'inbound' | 'outbound' | 'internal'");
    }
    validateOpts.requireNonEmptyString(req.actorId,
      "mail.journal.record: opts.actorId", MailJournalError, "mail-journal/bad-actor");
    if (typeof req.messageId !== "string" || req.messageId.length === 0 || req.messageId.length > 1024) {  // Message-Id cap
      throw new MailJournalError("mail-journal/bad-message-id",
        "mail.journal.record: opts.messageId must be a non-empty string");
    }
    if (!Buffer.isBuffer(req.bodyBytes)) {
      throw new MailJournalError("mail-journal/bad-body",
        "mail.journal.record: opts.bodyBytes must be a Buffer");
    }
    if (safeBuffer.byteLengthOf(req.bodyBytes) > C.BYTES.mib(256)) {                                                    // per-message cap
      throw new MailJournalError("mail-journal/too-large",
        "mail.journal.record: message " + req.bodyBytes.length + " bytes exceeds 256 MiB cap");
    }

    var journalId  = "j" + Date.now().toString(36) + "-" +
                     require("node:crypto").randomBytes(8).toString("hex");                           // 8-byte rand
    var archivedAt = Date.now();
    var sizeBytes  = req.bodyBytes.length;
    var storageKey = namespace + "/" + archivedAt + "/" + journalId + ".eml.sealed";

    // Seal the whole payload (headers + envelope + body) as a single
    // `vault:`-prefixed string. The vault.seal primitive is the right
    // shape here — we're encrypting one logical blob, not a row with
    // mixed sealed/plaintext columns. (cryptoField.sealRow is for the
    // row-level mixed-column case; mail-journal's WORM rows split
    // forensic-queryable plaintext columns from one sealed payload
    // blob, so a single vault.seal call is the cleaner fit.)
    var payloadJson = JSON.stringify({
      direction: req.direction,
      messageId: req.messageId,
      headers:   req.headers || {},
      envelope:  req.envelope || {},
      body:      req.bodyBytes.toString("base64"),
    });
    var sealedBlob = opts.vault.seal(payloadJson);

    await opts.storage.putObject(storageKey, sealedBlob, {
      contentType: "application/octet-stream",
      metadata:    { journalId: journalId, direction: req.direction, archivedAt: String(archivedAt) },
    });

    var regimesJson = JSON.stringify(opts.regimes);
    var floorUntil  = archivedAt + floorMs;
    // Auto-derive the legal-hold flag from the registry: an entry whose actor is
    // under an active legal hold is born held, exempt from retention expiry even
    // after the floor passes (the doc's "every entry carries a legalHold flag").
    // setLegalHold remains the manual override. isHeld already treats a lapsed
    // (retainUntil-expired) hold as not-held, so a stale hold won't over-flag.
    var actorHeld = !!opts.legalHold.isHeld(req.actorId);
    // b.sql quotes every column + binds every value as a placeholder.
    var insBuilt = _t("insert").values({
      journal_id:     journalId,
      direction:      req.direction,
      actor_id:       req.actorId,
      message_id:     req.messageId,
      archived_at:    archivedAt,
      size_bytes:     sizeBytes,
      regimes:        regimesJson,
      floor_until:    floorUntil,
      legal_hold:     actorHeld ? 1 : 0,
      storage_key:    storageKey,
      sealed_payload: sealedBlob,
    }).toSql();
    opts.db.runSql(insBuilt.sql, insBuilt.params);

    _emit("mail.journal.record", "success", {
      journalId:  journalId,
      direction:  req.direction,
      messageId:  req.messageId,
      sizeBytes:  sizeBytes,
      regimes:    opts.regimes,
      floorUntil: floorUntil,
      storageKey: storageKey,
    });
    return { journalId: journalId, archivedAt: archivedAt, storageKey: storageKey, floorUntil: floorUntil };
  }

  async function getById(journalId) {
    if (typeof journalId !== "string" || journalId.length === 0 || journalId.length > 256) {          // id cap
      throw new MailJournalError("mail-journal/bad-id",
        "mail.journal.getById: journalId must be a non-empty string");
    }
    var gbBuilt = _t("select")
      .columns(["direction", "message_id", "archived_at", "size_bytes", "regimes",
                "floor_until", "legal_hold", "storage_key", "sealed_payload"])
      .where("journal_id", journalId)
      .toSql();
    var rows = opts.db.runSql(gbBuilt.sql, gbBuilt.params);
    if (!rows || rows.length === 0) return null;
    var r = rows[0];
    var unsealed = safeJson.parse(opts.vault.unseal(r.sealed_payload));
    _emit("mail.journal.read", "success", { journalId: journalId });
    return {
      journalId:  journalId,
      direction:  r.direction,
      messageId:  r.message_id,
      archivedAt: r.archived_at,
      sizeBytes:  r.size_bytes,
      regimes:    safeJson.parse(r.regimes),
      floorUntil: r.floor_until,
      legalHold:  !!r.legal_hold,
      storageKey: r.storage_key,
      headers:    unsealed.headers,
      envelope:   unsealed.envelope,
      bodyBytes:  Buffer.from(unsealed.body, "base64"),
    };
  }

  function list(filter) {
    filter = filter || {};
    var limit = numericBounds.isPositiveFiniteInt(filter.limit) ? Math.min(filter.limit, 1000) : 100; // list page cap
    // Each filter term is an optional .where() leaf (AND-composed); b.sql
    // quotes the columns + binds the values. A diagnostic clause list is
    // kept for the audit metadata (the prior `filter: clauses` field).
    var clauses = [];
    var qb = _t("select").columns(["journal_id", "direction", "actor_id", "message_id",
      "archived_at", "size_bytes", "regimes", "floor_until", "legal_hold", "storage_key"]);
    if (filter.direction && ALLOWED_DIRECTIONS[filter.direction]) {
      qb.where("direction", filter.direction); clauses.push("direction = ?");
    }
    if (typeof filter.since === "number" && numericBounds.isPositiveFiniteInt(filter.since)) {
      qb.whereOp("archived_at", ">=", filter.since); clauses.push("archived_at >= ?");
    }
    if (typeof filter.until === "number" && numericBounds.isPositiveFiniteInt(filter.until)) {
      qb.whereOp("archived_at", "<", filter.until); clauses.push("archived_at < ?");
    }
    if (filter.actorId && typeof filter.actorId === "string") {
      qb.where("actor_id", filter.actorId); clauses.push("actor_id = ?");
    }
    var listBuilt = qb.orderBy("archived_at", "desc").limit(limit).toSql();
    var rows = opts.db.runSql(listBuilt.sql, listBuilt.params);
    _emit("mail.journal.list", "success", { count: rows ? rows.length : 0, filter: clauses });
    return (rows || []).map(function (r) {
      return {
        journalId:  r.journal_id,
        direction:  r.direction,
        actorId:    r.actor_id,
        messageId:  r.message_id,
        archivedAt: r.archived_at,
        sizeBytes:  r.size_bytes,
        regimes:    safeJson.parse(r.regimes),
        floorUntil: r.floor_until,
        legalHold:  !!r.legal_hold,
        storageKey: r.storage_key,
      };
    });
  }

  function expireSurface(now) {
    if (now === undefined) now = Date.now();
    // legal_hold = 0 binds as a value (the prior inline `0` literal).
    var esBuilt = _t("select")
      .columns(["journal_id", "archived_at", "floor_until", "message_id", "regimes"])
      .whereOp("floor_until", "<", now)
      .where("legal_hold", 0)
      .orderBy("archived_at", "asc")
      .limit(1000)                                                                                  // expiry-surface cap
      .toSql();
    var rows = opts.db.runSql(esBuilt.sql, esBuilt.params);
    _emit("mail.journal.expire_surface", "success", { count: rows ? rows.length : 0, now: now });
    return (rows || []).map(function (r) {
      return {
        journalId:  r.journal_id,
        archivedAt: r.archived_at,
        floorUntil: r.floor_until,
        messageId:  r.message_id,
        regimes:    safeJson.parse(r.regimes),
      };
    });
  }

  function setLegalHold(journalId, onHold) {
    if (typeof journalId !== "string" || journalId.length === 0) {
      throw new MailJournalError("mail-journal/bad-id",
        "mail.journal.setLegalHold: journalId required");
    }
    var lhBuilt = _t("update")
      .set("legal_hold", onHold ? 1 : 0)
      .where("journal_id", journalId)
      .toSql();
    opts.db.runSql(lhBuilt.sql, lhBuilt.params);
    _emit("mail.journal.legal_hold_change", "success", { journalId: journalId, onHold: !!onHold });
  }

  return {
    record:        record,
    getById:       getById,
    list:          list,
    expireSurface: expireSurface,
    setLegalHold:  setLegalHold,
    namespace:     namespace,
    regimes:       opts.regimes.slice(),
    floorMs:       floorMs,
  };
}

module.exports = {
  create:           create,
  REGIME_FLOOR_MS:  REGIME_FLOOR_MS,
  MailJournalError: MailJournalError,
};
