"use strict";
/**
 * Consent log — GDPR Art. 6/7 lawful-basis tracking with hash chain.
 *
 * consent_log is baked into db.js's schema runner alongside audit_log.
 * Same tamper-evidence design: per-row SHA3-512 hash chain, append-only,
 * verified at boot.
 *
 * Lawful-basis consistency: any audit-recorded operation declared under
 * `lawfulBasis: 'consent'` should reference a current consent_log entry.
 * The framework records consent grants/withdrawals here; enforcement of
 * consent before processing is the app's responsibility — query
 * `consent.isActive(subjectId, purpose)` at the trust boundary.
 *
 * Public API:
 *   consent.grant({ subjectId, purpose, lawfulBasis, scope?, channel, evidenceRef? })
 *   consent.withdraw({ subjectId, purpose, reason? })
 *   consent.isGranted({ subjectId, purpose }) → boolean
 *   consent.history(subjectId) → array of consent_log rows (decrypted)
 *   consent.verify() → { ok, rowsVerified, breakAt? }
 */
var auditChain = require("./audit-chain");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var chainWriter = require("./chain-writer");
var safeAsync = require("./safe-async");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var { ClusterError } = require("./framework-error");

// Wall-clock cap on the tip upsert. Same value as audit's
// FRAMEWORK_SQL_TIMEOUT_MS — a misbehaving external-db driver
// shouldn't hang a consent write forever.
var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

var LAWFUL_BASES = ["consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"];
var ACTIONS = ["granted", "withdrawn", "expired", "superseded"];

var HASHABLE_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "subjectId", "subjectIdHash",
  "purpose", "lawfulBasis", "action",
  "scope", "channel", "evidenceRef",
];

var db = lazyRequire(function () { return require("./db"); });

// Race-safe chain append for consent_log. Inherits the same Mutex /
// counter-primer / retry-wrapped reads / timeout-bounded writes that
// audit_log uses. (Before this primitive landed, consent.js had a chain-
// fork race identical to audit.js's pre-Mutex bug; switching to chain-
// writer fixes it as a side effect of consolidating the duplication.)
var _chainWriter = chainWriter.create({
  table:           "consent_log",
  hashableColumns: HASHABLE_COLS,
  columnsForInsert: [
    "_id", "recordedAt", "monotonicCounter",
    "subjectId", "subjectIdHash",
    "purpose", "lawfulBasis", "action",
    "scope", "channel", "evidenceRef",
    "prevHash", "rowHash", "nonce", "fencingToken",
  ],
});

// ---- Public API ----

function grant(opts) {
  cluster.requireLeader();
  if (!opts || !opts.subjectId || !opts.purpose || !opts.lawfulBasis || !opts.channel) {
    throw new Error("consent.grant requires { subjectId, purpose, lawfulBasis, channel }");
  }
  if (LAWFUL_BASES.indexOf(opts.lawfulBasis) === -1) {
    throw new Error("invalid lawfulBasis: '" + opts.lawfulBasis + "' (must be one of " + LAWFUL_BASES.join(", ") + ")");
  }
  return _appendConsentRow({
    subjectId:    opts.subjectId,
    purpose:      opts.purpose,
    lawfulBasis:  opts.lawfulBasis,
    action:       "granted",
    scope:        opts.scope ? JSON.stringify(opts.scope) : null,
    channel:      opts.channel,
    evidenceRef:  opts.evidenceRef || null,
  });
}

function withdraw(opts) {
  cluster.requireLeader();
  if (!opts || !opts.subjectId || !opts.purpose) {
    throw new Error("consent.withdraw requires { subjectId, purpose }");
  }
  return _appendConsentRow({
    subjectId:    opts.subjectId,
    purpose:      opts.purpose,
    lawfulBasis:  "consent",
    action:       "withdrawn",
    scope:        null,
    channel:      opts.channel || "api",
    evidenceRef:  opts.reason ? "reason:" + opts.reason : null,
  });
}

function isGranted(opts) {
  if (!opts || !opts.subjectId || !opts.purpose) {
    throw new Error("consent.isGranted requires { subjectId, purpose }");
  }
  // Find the most recent consent row for this (subjectId, purpose).
  // subjectId is sealed → look up via subjectIdHash (derived).
  var hash = db().hashFor("consent_log", "subjectId", opts.subjectId);
  if (!hash) {
    throw new Error("consent_log subjectId is missing a derived hash — schema misconfigured");
  }
  var row = db().prepare(
    "SELECT action FROM consent_log WHERE subjectIdHash = ? AND purpose = ? " +
    "ORDER BY monotonicCounter DESC LIMIT 1"
  ).get(hash, opts.purpose);
  if (!row) return false;
  return row.action === "granted";
}

function history(subjectId) {
  if (!subjectId) throw new Error("consent.history requires a subjectId");
  var hash = db().hashFor("consent_log", "subjectId", subjectId);
  if (!hash) {
    throw new Error("consent_log subjectId is missing a derived hash — schema misconfigured");
  }
  var rows = db().from("consent_log")
    .where({ subjectIdHash: hash })
    .orderBy("monotonicCounter", "asc")
    .all();
  return rows;
}

async function verify(opts) {
  return await auditChain.verifyChain(
    function (sql, params) { return clusterStorage.executeAll(sql, params || []); },
    "consent_log",
    opts
  );
}

// ---- Internal: append a chain-linked row ----

async function _appendConsentRow(fields) {
  if (ACTIONS.indexOf(fields.action) === -1) {
    throw new Error("invalid consent action: " + fields.action);
  }
  var row = await _chainWriter.append({
    subjectId:        fields.subjectId,
    purpose:          fields.purpose,
    lawfulBasis:      fields.lawfulBasis,
    action:           fields.action,
    scope:            fields.scope,
    channel:          fields.channel,
    evidenceRef:      fields.evidenceRef,
  });
  // Cluster mode: keep _blamejs_consent_tip current so cluster.init's
  // boot-time rollback check has an authoritative tip to compare
  // against. Mirrors the audit-tip upsert pattern from audit.js with
  // the same WHERE-clause fencing guard.
  if (cluster.isClusterMode()) {
    await _upsertConsentTip(
      Number(row.monotonicCounter),
      row.rowHash,
      String(row.recordedAt),
      cluster.fencingToken()
    );
  }
  return row;
}

async function _upsertConsentTip(counter, rowHash, signedAt, fencingToken) {
  // Single atomic INSERT … ON CONFLICT DO UPDATE … WHERE … RETURNING.
  // Same canonical fencing-token guard as _blamejs_audit_tip: the
  // WHERE clause enforces monotonic-non-decreasing fencingToken at
  // the DB level so a partitioned old leader can't overwrite the tip
  // even if its application-layer cluster.requireLeader() gate let
  // the call through.
  var result = await safeAsync.withTimeout(
    clusterStorage.execute(
      "INSERT INTO _blamejs_consent_tip " +
      "  (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('consent', ?, ?, ?, ?) " +
      "ON CONFLICT (scope) DO UPDATE SET " +
      "  atMonotonicCounter = EXCLUDED.atMonotonicCounter, " +
      "  rowHash            = EXCLUDED.rowHash, " +
      "  signedAt           = EXCLUDED.signedAt, " +
      "  fencingToken       = EXCLUDED.fencingToken " +
      "WHERE _blamejs_consent_tip.fencingToken <= EXCLUDED.fencingToken " +
      "RETURNING fencingToken",
      [counter, rowHash, signedAt, fencingToken]
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "consent.upsertConsentTip" }
  );
  if (!result.rows || result.rows.length === 0) {
    throw new ClusterError(
      "FENCED_OUT",
      "consent-tip update rejected: incoming fencingToken=" + fencingToken +
      " is below the stored token (this leader has been fenced out " +
      "by a higher-token successor)",
      true
    );
  }
}

// ---- Test helpers ----

function _resetForTest() {
  _chainWriter._resetForTest();
  db.reset();
}

module.exports = {
  grant:         grant,
  withdraw:      withdraw,
  isGranted:     isGranted,
  history:       history,
  verify:        verify,
  LAWFUL_BASES:  LAWFUL_BASES,
  ACTIONS:       ACTIONS,
  _resetForTest: _resetForTest,
};
