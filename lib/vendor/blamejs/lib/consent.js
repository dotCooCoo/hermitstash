"use strict";
/**
 * @module b.consent
 * @nav    Identity
 * @title  Consent
 *
 * @intro
 *   Consent-record chain — every grant / withdrawal / expiry / supersede
 *   for a (subjectId, purpose) pair lands in `consent_log` as one
 *   append-only, hash-chained row. Same tamper-evidence design as
 *   `audit_log`: per-row SHA3-512 hash chain over the sealed payload,
 *   verified at boot, refuse-to-boot on a break.
 *
 *   GDPR Art. 7 demands controllers be able to demonstrate the data
 *   subject consented; CCPA / CPRA Title 1.81.5 requires evidence the
 *   consumer exercised opt-out. consent_log carries `subjectId` (sealed)
 *   + `purpose` + `lawfulBasis` + `channel` + operator-supplied
 *   `evidenceRef` so a regulator request resolves to a specific row,
 *   tied to the audit chain via shared chain-writer primitives.
 *
 *   Lawful-basis vocabulary tracks the GDPR Art. 6(1) enumeration:
 *   `consent`, `contract`, `legal_obligation`, `vital_interests`,
 *   `public_task`, `legitimate_interests`. Any audit event declaring
 *   `lawfulBasis: 'consent'` should reference a current consent_log
 *   entry — the framework records the grants and withdrawals here;
 *   enforcement at the trust boundary is the app's call (typical shape:
 *   `if (!b.consent.isGranted({ subjectId, purpose })) return 403`).
 *
 *   `purpose` is free-form, but values matching the recognized-purpose
 *   vocabulary (`b.consent.recognizedPurpose` / `listPurposes`) carry
 *   lawful-basis constraints `grant()` enforces — e.g. `educational-only`
 *   (FERPA school-official exception / California SOPIPA) refuses a
 *   `legitimate_interests` basis.
 *
 *   Cluster mode keeps `_blamejs_consent_tip` current with a fenced
 *   `INSERT … ON CONFLICT DO UPDATE … WHERE fencingToken <= EXCLUDED`
 *   so a partitioned old leader cannot rewrite the tip even if its
 *   application-layer leader gate let the call through. Followers
 *   refuse `grant` / `withdraw` with `NotLeaderError`.
 *
 * @card
 *   Consent-record chain — every grant / withdrawal / expiry / supersede for a (subjectId, purpose) pair lands in `consent_log` as one append-only, hash-chained row.
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

// Recognized consent purposes. A purpose value matching a key here carries
// lawful-basis constraints that grant() enforces; any other (free-form)
// purpose string stays valid and unconstrained, so the vocabulary is opt-in
// and never breaks operators passing their own purpose names. FERPA's
// school-official exception + California SOPIPA make "educational-only" the
// canonical constrained purpose.
//
// Null-prototype map: the purpose value is operator-controlled, so a plain
// object would let a free-form purpose colliding with an Object.prototype
// member ("toString" / "constructor" / "__proto__") resolve to the prototype
// value instead of undefined — recognizedPurpose() would return a function
// and grant() would enter the recognized branch for a value listPurposes()
// never exposes. A null prototype makes every unrecognized key resolve to
// undefined (CWE-1321 defense).
var PURPOSES = Object.freeze(Object.assign(Object.create(null), {
  "educational-only": Object.freeze({
    purpose:                 "educational-only",
    forbidsLawfulBasis:      Object.freeze(["legitimate_interests"]),
    commercialUseProhibited: true,
    dataMinimization:        true,
    citation:                "FERPA 34 CFR 99.31(a)(1) school-official exception; Cal. SB 1177 SOPIPA 22584(b)(1)-(4); 16 CFR 312.5(c)(10) FTC school-authorized COPPA consent",
    notes:                   "K-12 / school-official use only; no targeted advertising, no commercial profiling, no sale. Lawful basis must be school authorization (consent / public_task / legal_obligation), not legitimate_interests. The commercial-use prohibition is an operator trust-boundary obligation — isGranted() does not re-derive it.",
  }),
}));

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

/**
 * @primitive  b.consent.grant
 * @signature  b.consent.grant(opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.consent.withdraw, b.consent.isGranted, b.consent.history
 *
 * Append a "granted" row to consent_log for a (subjectId, purpose) pair.
 * Refuses on a follower (cluster mode). Lawful-basis must come from the
 * GDPR Art. 6(1) enumeration; an unknown value throws synchronously
 * before touching the chain.
 *
 * @opts
 *   subjectId:   string,                          // sealed at rest
 *   purpose:     string,                          // e.g. "marketing"
 *   lawfulBasis: "consent" | "contract" | "legal_obligation"
 *              | "vital_interests" | "public_task"
 *              | "legitimate_interests",
 *   scope:       object,                          // optional, JSON-serialized
 *   channel:     string,                          // "web-banner" / "api" / ...
 *   evidenceRef: string,                          // optional pointer to UI snapshot
 *
 * @example
 *   await b.consent.grant({
 *     subjectId:   "u-42",
 *     purpose:     "marketing",
 *     lawfulBasis: "consent",
 *     scope:       { channels: ["email", "sms"] },
 *     channel:     "web-banner-v3",
 *     evidenceRef: "snapshot-2026-05-09T14:00:00Z",
 *   });
 *   // → { _id, monotonicCounter, rowHash, prevHash, ... }
 */
function grant(opts) {
  cluster.requireLeader();
  if (!opts || !opts.subjectId || !opts.purpose || !opts.lawfulBasis || !opts.channel) {
    throw new Error("consent.grant requires { subjectId, purpose, lawfulBasis, channel }");
  }
  if (LAWFUL_BASES.indexOf(opts.lawfulBasis) === -1) {
    throw new Error("invalid lawfulBasis: '" + opts.lawfulBasis + "' (must be one of " + LAWFUL_BASES.join(", ") + ")");
  }
  // Recognized-purpose vocabulary (opt-in): when the purpose matches a
  // PURPOSES key, enforce its lawful-basis constraints. Free-form purposes
  // remain unconstrained, so operators passing their own purpose names are
  // unaffected.
  var recognized = PURPOSES[opts.purpose];
  if (recognized) {
    if (recognized.forbidsLawfulBasis && recognized.forbidsLawfulBasis.indexOf(opts.lawfulBasis) !== -1) {
      throw new Error("consent.grant: purpose '" + opts.purpose + "' forbids lawfulBasis '" +
        opts.lawfulBasis + "' (" + recognized.citation + ")");
    }
    if (recognized.requiresLawfulBasis && recognized.requiresLawfulBasis.length > 0 &&
        recognized.requiresLawfulBasis.indexOf(opts.lawfulBasis) === -1) {
      throw new Error("consent.grant: purpose '" + opts.purpose + "' requires lawfulBasis in [" +
        recognized.requiresLawfulBasis.join(", ") + "] (" + recognized.citation + ")");
    }
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

/**
 * @primitive  b.consent.recognizedPurpose
 * @signature  b.consent.recognizedPurpose(name)
 * @since      0.14.14
 * @status     stable
 * @compliance ferpa, ca-sopipa, coppa, gdpr
 * @related    b.consent.grant, b.consent.listPurposes, b.consent.isGranted
 *
 * Look up a recognized consent purpose by value. Recognized purposes carry
 * lawful-basis constraints that `grant()` enforces; the `educational-only`
 * purpose (FERPA school-official exception / SOPIPA) forbids a
 * `legitimate_interests` basis and marks the data commercial-use-prohibited.
 * That commercial-use prohibition is an operator trust-boundary obligation —
 * `isGranted()` does not re-derive it. Returns the frozen entry, or `null`
 * for a free-form purpose (which remains valid for `grant()`).
 *
 * @opts
 *   name: string,   // a purpose value, e.g. "educational-only"
 *
 * @example
 *   b.consent.recognizedPurpose("educational-only");
 *   // → { purpose: "educational-only", forbidsLawfulBasis: ["legitimate_interests"], ... }
 *   b.consent.recognizedPurpose("marketing");   // → null (free-form)
 */
function recognizedPurpose(name) {
  return PURPOSES[name] || null;
}

/**
 * @primitive  b.consent.listPurposes
 * @signature  b.consent.listPurposes()
 * @since      0.14.14
 * @status     stable
 * @related    b.consent.recognizedPurpose, b.consent.grant
 *
 * Return the recognized-purpose values as a frozen array. Free-form
 * purposes are not listed — they remain valid for `grant()` but carry no
 * lawful-basis constraint.
 *
 * @example
 *   b.consent.listPurposes();   // → ["educational-only"]
 */
function listPurposes() {
  return Object.freeze(Object.keys(PURPOSES));
}

/**
 * @primitive  b.consent.withdraw
 * @signature  b.consent.withdraw(opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa
 * @related    b.consent.grant, b.consent.isGranted
 *
 * Append a "withdrawn" row to consent_log. After this lands,
 * `isGranted` returns `false` for the same (subjectId, purpose). Pair
 * with a downstream sweep over data-classes that depended on the
 * lawful basis (typical pattern: cascade into `b.retention` or
 * `b.subject.erase`).
 *
 * @opts
 *   subjectId: string,
 *   purpose:   string,
 *   reason:    string,                            // optional, recorded as evidenceRef
 *   channel:   string,                            // optional, defaults to "api"
 *
 * @example
 *   await b.consent.withdraw({
 *     subjectId: "u-42",
 *     purpose:   "marketing",
 *     reason:    "user-self-service-portal",
 *   });
 *   // → { _id, monotonicCounter, rowHash, ... }
 */
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

/**
 * @primitive  b.consent.isGranted
 * @signature  b.consent.isGranted(opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa
 * @related    b.consent.grant, b.consent.withdraw, b.consent.history
 *
 * Returns `true` when the most recent consent_log row for the
 * (subjectId, purpose) pair has action `granted`. Lookups go through
 * the derived `subjectIdHash` so the sealed `subjectId` column never
 * needs to be unsealed for the query. Safe on followers (read-only).
 *
 * @opts
 *   subjectId: string,
 *   purpose:   string,
 *
 * @example
 *   if (!b.consent.isGranted({ subjectId: "u-42", purpose: "marketing" })) {
 *     res.statusCode = 403;
 *     return res.end("consent required");
 *   }
 *   // → true / false
 */
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

/**
 * @primitive  b.consent.history
 * @signature  b.consent.history(subjectId)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa
 * @related    b.consent.grant, b.consent.withdraw, b.subject.export
 *
 * Returns every consent_log row for `subjectId`, oldest first, decrypted
 * by the framework's row reader. Composes into `b.subject.export` for
 * GDPR Art. 15 / CCPA §1798.110 right-of-access responses without the
 * caller having to walk the chain manually.
 *
 * @example
 *   var rows = b.consent.history("u-42");
 *   rows.forEach(function (r) {
 *     console.log(r.recordedAt, r.purpose, r.action, r.lawfulBasis);
 *   });
 *   // → [{ recordedAt, purpose, action, lawfulBasis, channel, ... }]
 */
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

/**
 * @primitive  b.consent.verify
 * @signature  b.consent.verify(opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, soc2
 * @related    b.audit.verify, b.consent.grant
 *
 * Verify the consent_log hash chain end-to-end. Recomputes each row's
 * `rowHash` from the sealed-form columns + nonce + `prevHash`, walking
 * from genesis to tip. Returns `{ ok, rowsVerified, breakAt? }` — a
 * regulator-ready integrity check that auditors can run without
 * holding the vault key.
 *
 * @opts
 *   from: number,                                 // optional monotonicCounter floor
 *   to:   number,                                 // optional monotonicCounter ceiling
 *
 * @example
 *   var report = await b.consent.verify();
 *   if (!report.ok) {
 *     console.error("consent chain break at row", report.breakAt);
 *   }
 *   // → { ok: true, rowsVerified: 1024 }
 */
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
  grant:             grant,
  withdraw:          withdraw,
  isGranted:         isGranted,
  history:           history,
  verify:            verify,
  recognizedPurpose: recognizedPurpose,
  listPurposes:      listPurposes,
  LAWFUL_BASES:      LAWFUL_BASES,
  PURPOSES:          PURPOSES,
  ACTIONS:           ACTIONS,
  _resetForTest:     _resetForTest,
};
