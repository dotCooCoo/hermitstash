// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.auditChain
 * @nav    Observability
 * @title  Audit Chain Primitives
 *
 * @intro
 *   Low-level audit-chain hash + verify primitives — `b.audit` composes
 *   on top of these so operators rarely call them directly. Every audit
 *   row carries `prevHash` + `rowHash` + `nonce` and the chain math is:
 *
 *     rowHash = SHA3-512(
 *       prevHash || canonicalize(row-fields-except-hash) || nonce
 *     )
 *
 *   Each row's `prevHash` equals the previous row's `rowHash` in
 *   monotonic-counter order. The first row uses `ZERO_HASH` as the
 *   anchor. `verifyChain` walks every row forward, recomputing each
 *   hash; any mismatch returns `{ ok: false, reason, breakAt, ... }`
 *   and the caller (audit boot, `b.cli verify-chain`, restore-rollback,
 *   forensic snapshot) decides whether to refuse-to-boot or just log.
 *
 *   Checkpoint signing (SLH-DSA-SHAKE-256f over `(atRow || atRowHash)`)
 *   lives in `b.auditSign`. This module owns the chain hash math only;
 *   verification is O(n) over `audit_log` rows.
 *
 *   Operators reach for `b.auditChain.verifyChain` directly when
 *   restoring from backup (verify the restored DB before promoting it),
 *   when running a forensic offline check, or when extending the chain
 *   primitive into a custom append-only table. Day-to-day appends go
 *   through `b.audit.record` / `b.audit.safeEmit`.
 *
 * @card
 *   Low-level audit-chain hash + verify primitives — `b.audit` composes on top of these so operators rarely call them directly.
 */
var auditSign = require("./audit-sign");
var canonicalJson = require("./canonical-json");
var C = require("./constants");
var clusterStorage = require("./cluster-storage");
var frameworkSchema = require("./framework-schema");
var numericBounds = require("./numeric-bounds");
var sql = require("./sql");
var safeSql = require("./safe-sql");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var { sha3Hash } = require("./crypto");

function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

var SHA3_512_BYTES   = C.BYTES.bytes(64);
var SHA3_512_HEX_LEN = SHA3_512_BYTES * 2;

var ZERO_HASH = "0".repeat(SHA3_512_HEX_LEN);

var PURGE_ANCHOR_FORMAT = "blamejs-purge-anchor-v1";

var PURGE_ANCHOR_DELIMITER = "\n";

/**
 * @primitive b.auditChain.purgeAnchorPayload
 * @signature b.auditChain.purgeAnchorPayload(anchor, opts?)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.verifyPurgeAnchor, b.auditSign.sign, b.auditTools.purge
 *
 * Canonical signed bytes for a purge anchor. Every field a reader acts on is
 * covered: the boundary counter and row hash the chain walk adopts, the
 * archive identifier an operator would follow to recover the deleted rows, the
 * time it happened, and the scope, so an anchor cannot be lifted into a
 * different scope's row.
 *
 * Throws `TypeError` if a string field contains a newline — see
 * `b.auditChain.verifyPurgeAnchor` for why that is refused rather than escaped.
 *
 * @opts
 *   layout: string,  // default: "current". Also "no-checkpoint-digest", "no-digest" and "no-range", which reproduce the payload as it stood before each field joined it — for VERIFYING an anchor written by an earlier build, never for signing a new one
 *
 * @example
 *   var sig = b.auditSign.sign(b.auditChain.purgeAnchorPayload(anchor));
 */
function purgeAnchorPayload(anchor, opts) {
  if (!anchor || typeof anchor !== "object") {
    throw new TypeError("purgeAnchorPayload: anchor must be an object");
  }
  var scope  = anchor.scope == null ? "audit" : String(anchor.scope);
  var hash   = String(anchor.lastPurgedRowHash);
  var bundle = String(anchor.archiveBundleId);
  var rowsDigest = anchor.archiveRowsDigest == null ? "" : String(anchor.archiveRowsDigest);
  var ckptDigest = anchor.archiveCheckpointDigest == null
    ? "" : String(anchor.archiveCheckpointDigest);
  var manifestDigest = anchor.archiveManifestDigest == null
    ? "" : String(anchor.archiveManifestDigest);
  var strings = [["scope", scope], ["lastPurgedRowHash", hash],
                 ["archiveBundleId", bundle], ["archiveRowsDigest", rowsDigest],
                 ["archiveCheckpointDigest", ckptDigest],
                 ["archiveManifestDigest", manifestDigest]];
  for (var i = 0; i < strings.length; i += 1) {
    if (strings[i][1].indexOf(PURGE_ANCHOR_DELIMITER) !== -1) {
      throw new TypeError("purgeAnchorPayload: " + strings[i][0] +
        " must not contain a newline");
    }
  }
  var counter = Number(anchor.lastPurgedCounter);
  var purgedAt = Number(anchor.purgedAt);
  if (!numericBounds.isIncrementableSafeInt(counter)) {
    throw new TypeError("purgeAnchorPayload: lastPurgedCounter must be a whole " +
      "non-negative number the chain can resume above while staying below 2^53 " +
      "— at or past that, two distinct stored values render identically and one " +
      "signature would cover both, and the first counter after the boundary " +
      "would alias another");
  }
  if (!Number.isSafeInteger(purgedAt)) {
    throw new TypeError("purgeAnchorPayload: purgedAt must be a whole number below 2^53");
  }
  var fencingToken = Number(anchor.fencingToken == null ? 0 : anchor.fencingToken);
  if (!numericBounds.isNonNegativeSafeInt(fencingToken)) {
    throw new TypeError("purgeAnchorPayload: fencingToken must be a whole " +
      "non-negative number below 2^53");
  }
  var firstPurgedCounter = Number(
    anchor.firstPurgedCounter == null ? 0 : anchor.firstPurgedCounter);
  if (!numericBounds.isNonNegativeSafeInt(firstPurgedCounter)) {
    throw new TypeError("purgeAnchorPayload: firstPurgedCounter must be a whole " +
      "non-negative number below 2^53");
  }
  var head =
    PURGE_ANCHOR_FORMAT + "\n" +
    scope + "\n" +
    String(counter) + "\n" +
    hash + "\n" +
    bundle + "\n" +
    String(purgedAt) + "\n" +
    String(fencingToken);
  var layout = (opts && opts.layout) || "current";
  if (layout === "no-range") return Buffer.from(head, "utf8");
  var withRange = head + "\n" + String(firstPurgedCounter);
  if (layout === "no-digest") return Buffer.from(withRange, "utf8");
  var withRows = withRange + "\n" + rowsDigest;
  if (layout === "no-checkpoint-digest") return Buffer.from(withRows, "utf8");
  var withCkpt = withRows + "\n" + ckptDigest;
  if (layout === "no-manifest-digest") return Buffer.from(withCkpt, "utf8");
  return Buffer.from(withCkpt + "\n" + manifestDigest, "utf8");
}

/**
 * @primitive b.auditChain.purgeAnchorSignatureVerifies
 * @signature b.auditChain.purgeAnchorSignatureVerifies(anchor, signature, publicKeyPem)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.purgeAnchorPayload, b.auditChain.verifyPurgeAnchor
 *
 * Does `signature` cover this purge anchor under `publicKeyPem`?
 * True when it verifies against the current signed payload, or
 * against the payload as it stood before a field joined it — each of
 * those retries gated on the field it omits still being empty, which
 * is the only state an anchor predating that field can be in.
 *
 * Whether an anchor is GENUINE is a narrower question than whether it
 * may be BELIEVED: this says only that the signature covers the
 * fields, and answers nothing about which key was authorized, whether
 * the named archive still exists, or whether the boundary is
 * contiguous. Use `b.auditChain.verifyPurgeAnchor` to decide an
 * anchor; use this when the key to check against is already settled —
 * repairing an anchor signed under a rotated-out key, for instance.
 *
 * @example
 *   var ok = b.auditChain.purgeAnchorSignatureVerifies(
 *     anchorRow, anchorRow.signature, pemOfTheKeyItNames);
 *   // → true when the signature covers the anchor's own fields
 */
function purgeAnchorSignatureVerifies(row, signature, publicKeyPem) {
  var sig = Buffer.isBuffer(signature) ? signature : Buffer.from(signature || "");
  var storedRange  = Number(row.firstPurgedCounter == null ? 0 : row.firstPurgedCounter);
  var storedDigest = row.archiveRowsDigest == null ? "" : String(row.archiveRowsDigest);
  var storedCkpt   = row.archiveCheckpointDigest == null
    ? "" : String(row.archiveCheckpointDigest);
  var storedManifest = row.archiveManifestDigest == null
    ? "" : String(row.archiveManifestDigest);
  var layouts = [
    { layout: "current",              when: true },
    { layout: "no-manifest-digest",   when: storedManifest === "" },
    { layout: "no-checkpoint-digest", when: storedManifest === "" && storedCkpt === "" },
    { layout: "no-digest",            when: storedManifest === "" && storedCkpt === "" &&
                                            storedDigest === "" },
    { layout: "no-range",             when: storedManifest === "" && storedCkpt === "" &&
                                            storedDigest === "" && storedRange === 0 },
  ];
  for (var li = 0; li < layouts.length; li += 1) {
    if (!layouts[li].when) continue;
    try {
      if (auditSign.verify(purgeAnchorPayload(row, { layout: layouts[li].layout }),
        sig, publicKeyPem)) return true;
    } catch (_e) { /* a layout this anchor cannot be rendered in is not a match */ }
  }
  return false;
}

/**
 * @primitive b.auditChain.verifyPurgeAnchor
 * @signature b.auditChain.verifyPurgeAnchor(row, opts?)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.purgeAnchorPayload, b.auditChain.verifyChain, b.auditTools.purge
 *
 * Decide whether a purge-anchor row may be believed. Returns a `status`
 * rather than a boolean, because the three ways an anchor can fail to verify
 * call for three different reactions and collapsing them produces either a
 * false alarm on a healthy volume or a silent pass on a tampered one:
 *
 * - `absent` — no anchor row. Nothing was purged; verify from `ZERO_HASH`.
 * - `valid` — the signature covers the fields, under a key on record.
 * - `unsigned` — no signature. Refused unless the caller acknowledges it
 *   (see `allowUnsigned`), because an unsigned anchor is what the attack
 *   writes AND what an installation purged by an older version already has.
 * - `forged` — a signature that does not verify, or names a key nothing on
 *   this volume knows. Someone edited the anchor.
 * - `unchecked` — a signature that could not be checked at all, because this
 *   process holds no signing key. A verifier opening a database file directly
 *   is in exactly this position, and reporting its anchor as forged would
 *   raise an alarm about a volume nobody touched.
 * - `corrupt` — the fields are not the right shape to act on.
 *
 * Pass `resolvePublicKey(fingerprint)` when the caller holds the key material
 * itself, which offline verification does; without it the anchor is checked
 * against `b.auditSign`'s own keys and public-key history.
 *
 * @opts
 *   resolvePublicKey: function, // (fingerprint) => PEM | null — offline key source
 *   resolveArchive:   function, // (archiveBundleId, { firstCounter, lastCounter, lastRowHash }) => truthy if the archive can still be produced; an anchor naming one that cannot is refused. Several slices can share the checkpoint that covers them, so the id alone does not name one bundle — match the range too
 *   allowUnsignedPurgeAnchor:  boolean, // default: false — accept an anchor written before signing existed
 *   allowUncheckedPurgeAnchor: boolean, // default: false — accept an anchor whose signature could not be checked at all; only for a caller with no signing posture, and the result still reports signatureVerified: false
 *   allowUnsigned:    boolean,  // default: false — accept a pre-signing anchor
 *
 * @example
 *   var v = b.auditChain.verifyPurgeAnchor(row);
 *   if (v.status !== "valid") throw new Error(v.reason);
 */
function verifyPurgeAnchor(row, opts) {
  opts = opts || {};
  if (row == null) return { status: "absent", reason: "no purge anchor" };
  if (typeof row !== "object") {
    return { status: "corrupt", reason: "purge anchor is not a row" };
  }

  var hash    = row.lastPurgedRowHash;
  var counter = Number(row.lastPurgedCounter);
  if (!safeBuffer.isHex(hash, SHA3_512_HEX_LEN)) {
    return { status: "corrupt", reason: "corrupted purge anchor: lastPurgedRowHash is not a SHA3-512 hex digest" };
  }
  if (!numericBounds.isIncrementableSafeInt(counter)) {
    return { status: "corrupt", reason: "corrupted purge anchor: lastPurgedCounter is not a whole non-negative number the chain can resume above while staying below 2^53" };
  }

  var signature   = row.signature;
  var fingerprint = row.publicKeyFingerprint;
  var signatureEmpty = signature == null ||
    (Buffer.isBuffer(signature) ? signature.length === 0 : String(signature) === "");
  var fingerprintEmpty = fingerprint == null || String(fingerprint) === "";

  if (signatureEmpty !== fingerprintEmpty) {
    return { status: "corrupt", counter: counter, hash: hash,
      reason: "corrupted purge anchor: it carries " +
        (signatureEmpty ? "a key fingerprint but no signature"
                        : "a signature but no key fingerprint") +
        " — half of a signature was removed" };
  }

  if (signatureEmpty) {
    if (opts.allowUnsigned) {
      return { status: "unsigned", accepted: true, counter: counter, hash: hash,
        reason: "purge anchor carries no signature and was accepted by explicit acknowledgement" };
    }
    return { status: "unsigned", accepted: false, counter: counter, hash: hash,
      reason: "purge anchor carries no signature — it licenses " + counter +
        " missing rows and nothing proves this framework wrote it" };
  }

  try { purgeAnchorPayload(row); }
  catch (e) { return { status: "corrupt", reason: "corrupted purge anchor: " + e.message }; }

  var publicKeyPem = null, resolveFailed = false;
  try {
    publicKeyPem = typeof opts.resolvePublicKey === "function"
      ? opts.resolvePublicKey(String(fingerprint))
      : auditSign.publicKeyLicensingDeletion(String(fingerprint));
  } catch (_e) {
    resolveFailed = true;
  }
  if (resolveFailed) {
    return { status: "unchecked", counter: counter, hash: hash,
      reason: "purge anchor signature could not be checked: no audit-signing key is available to this process" };
  }
  if (!publicKeyPem) {
    var knownButRotated = false;
    if (typeof opts.resolvePublicKey !== "function") {
      try {
        knownButRotated = !!auditSign.getPublicKeyByFingerprint(String(fingerprint));
      } catch (_e) { knownButRotated = false; }
    }
    if (knownButRotated) {
      return { status: "rotated-key", counter: counter, hash: hash,
        reason: "purge anchor is signed under a key that has since been rotated out. " +
          "A rotated key is recorded in the unsealed public-key history, which anyone " +
          "who can write the audit store can also write, so it cannot license deleted " +
          "rows. Re-sign the anchor under the live key with " +
          "b.auditTools.signExistingPurgeAnchor()" };
    }
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor is signed under a key this volume has no record of" };
  }

  var resolvedFingerprint = null;
  try { resolvedFingerprint = auditSign.fingerprintOf(publicKeyPem); }
  catch (_e) { resolvedFingerprint = null; }
  if (resolvedFingerprint !== String(fingerprint)) {
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor names key " + String(fingerprint).slice(0, 16) +
        "... but the key resolved for that name hashes to " +
        (resolvedFingerprint === null ? "nothing readable" : resolvedFingerprint.slice(0, 16) + "...") +
        " — the signature would have been checked against a key the anchor does not name" };
  }

  if (!purgeAnchorSignatureVerifies(row, signature, publicKeyPem)) {
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor signature does not cover its own fields — the anchor was edited after it was written" };
  }
  return { status: "valid", counter: counter, hash: hash,
    firstCounter: Number(row.firstPurgedCounter == null ? 0 : row.firstPurgedCounter),
    fingerprint: String(fingerprint) };
}

var PURGE_ANCHOR_LEGACY_COLUMNS = ["scope", "lastPurgedCounter", "lastPurgedRowHash",
  "archiveBundleId", "purgedAt"];
var PURGE_ANCHOR_SIGNATURE_COLUMNS = ["signature", "publicKeyFingerprint"];
var PURGE_ANCHOR_VERSIONED_COLUMNS = ["fencingToken", "firstPurgedCounter",
                                      "archiveRowsDigest", "archiveCheckpointDigest",
                                      "archiveManifestDigest"];

var PURGE_ANCHOR_PROJECTIONS = (function () {
  var ladder = [];
  for (var kept = PURGE_ANCHOR_VERSIONED_COLUMNS.length; kept >= 0; kept -= 1) {
    ladder.push(PURGE_ANCHOR_LEGACY_COLUMNS.concat(
      PURGE_ANCHOR_SIGNATURE_COLUMNS,
      PURGE_ANCHOR_VERSIONED_COLUMNS.slice(0, kept)));
  }
  ladder.push(PURGE_ANCHOR_LEGACY_COLUMNS);
  return ladder;
})();

async function _selectPurgeAnchor(queryAllAsync, columns) {
  // allow:hand-rolled-sql — bare logical key.
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .columns(columns)
    .where("scope", "audit")
    .toSql();
  var rows = await queryAllAsync(built.sql, built.params);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function _isMissingRelation(e) {
  if (clusterStorage.missingRelationCode(e)) return true;
  var msg = (e && e.message) || "";
  return /no such table|relation .* does not exist|undefined table|doesn't exist|42P01|42S02|1146/i.test(msg);
}
function _isMissingColumn(e) {
  if (clusterStorage.missingColumnCode(e)) return true;
  var msg = (e && e.message) || "";
  return /no such column|column .* does not exist|unknown column|42703|42S22|1054/i.test(msg);
}

async function _readPurgeAnchorRow(queryAllAsync) {
  var lastMissingColumn = null;
  for (var i = 0; i < PURGE_ANCHOR_PROJECTIONS.length; i += 1) {
    try {
      return await _selectPurgeAnchor(queryAllAsync, PURGE_ANCHOR_PROJECTIONS[i]);
    } catch (e) {
      if (_isMissingRelation(e)) return null;
      if (!_isMissingColumn(e)) throw e;
      lastMissingColumn = e;
    }
  }
  throw lastMissingColumn;
}

/**
 * @primitive b.auditChain.canonicalize
 * @signature b.auditChain.canonicalize(row, excludeKeys)
 * @since     0.6.67
 * @related   b.auditChain.computeRowHash
 *
 * RFC 8785 (JSON Canonicalization Scheme) serialization of an audit
 * row's logical fields, used as the middle slice of the row-hash
 * preimage. Sorted keys, Buffer values rendered as hex, every other
 * value passed through the shared `lib/canonical-json` walker so the
 * four canonicalize sites in the framework (chain, audit-tools,
 * config-drift, pagination) emit byte-identical output.
 *
 * @example
 *   var bytes = b.auditChain.canonicalize(
 *     { actor: "u-42", action: "auth.login.success", recordedAt: 1700000000000 },
 *     ["prevHash", "rowHash", "nonce"]
 *   );
 *   // → '{"action":"auth.login.success","actor":"u-42","recordedAt":1700000000000}'
 */
function canonicalize(row, excludeKeys) {
  var ex = new Set(excludeKeys || []);
  var keys = Object.keys(row).filter(function (k) { return !ex.has(k); }).sort();
  var pairs = {};
  for (var i = 0; i < keys.length; i++) {
    pairs[keys[i]] = row[keys[i]];
  }
  return canonicalJson.stringify(pairs);
}

/**
 * @primitive b.auditChain.computeRowHash
 * @signature b.auditChain.computeRowHash(prevHash, rowFields, nonce)
 * @since     0.4.0
 * @related   b.auditChain.verifyChain, b.auditChain.canonicalize
 *
 * Compute a row's `rowHash` given its predecessor's hash, the row's
 * logical fields (already excluding `prevHash` / `rowHash` / `nonce`),
 * and the row's nonce buffer. The hash is `SHA3-512(prevHashBytes ||
 * canonicalize(rowFields) || nonce)`, returned as a 128-char lowercase
 * hex string.
 *
 * `prevHash` must be the 128-char hex form (use `b.auditChain.ZERO_HASH`
 * for the chain anchor). `nonce` must be a non-empty Buffer; the
 * framework writes 16 random bytes per row.
 *
 * @example
 *   var rowHash = b.auditChain.computeRowHash(
 *     b.auditChain.ZERO_HASH,
 *     { action: "system.boot", recordedAt: 1700000000000, outcome: "success" },
 *     Buffer.from("0123456789abcdef0123456789abcdef", "hex")
 *   );
 *   // → "<128-char SHA3-512 hex>"
 */
function computeRowHash(prevHash, rowFields, nonce) {
  if (typeof prevHash !== "string" || prevHash.length !== SHA3_512_HEX_LEN) {
    throw new Error("prevHash must be a " + SHA3_512_HEX_LEN +
      "-char hex string (SHA3-512); got length " +
      (prevHash && prevHash.length));
  }
  if (!Buffer.isBuffer(nonce) || nonce.length === 0) {
    throw new Error("nonce must be a non-empty Buffer");
  }
  var canonical = canonicalize(rowFields);
  var input = Buffer.concat([
    Buffer.from(prevHash, "hex"),
    Buffer.from(canonical, "utf8"),
    nonce,
  ]);
  return sha3Hash(input);
}

/**
 * @primitive b.auditChain.getChainTip
 * @signature b.auditChain.getChainTip(queryOneAsync, tableName, opts?)
 * @since     0.4.0
 * @related   b.auditChain.verifyChain, b.auditChain.computeRowHash
 *
 * Read the current chain tip (last row's `rowHash` + `monotonicCounter`)
 * for a given audit table. Empty tables return
 * `{ prevHash: ZERO_HASH, counter: 0 }` so callers can treat first-row
 * insert and append uniformly. Async so operator-supplied external-db
 * drivers can use any await-able query function of the shape
 * `async (sql, params?) -> row | null`.
 *
 * Pass `{ chainKey, keyValue }` to scope the tip to one partition of a
 * multi-chain table (one chain per account / device / tenant) — the tip read
 * filters `WHERE <chainKey> = ?` with the value bound, never interpolated.
 *
 * @opts
 *   chainKey:  string,   // partition column for a multi-chain table
 *   keyValue:  any,      // the partition value to scope the tip to (bound)
 *
 * @example
 *   async function queryOne(sql) {
 *     var rows = await myDriver.query(sql);
 *     return rows[0] || null;
 *   }
 *   var tip = await b.auditChain.getChainTip(queryOne, "audit_log");
 *   // → { prevHash: "<128-char hex>", counter: 4217 }
 */
async function getChainTip(queryOneAsync, tableName, opts) {
  opts = opts || {};
  var q = sql.select(tableName, _sqlOpts())
    .columns(["rowHash", "monotonicCounter"])
    .orderBy("monotonicCounter", "desc")
    .limit(1);
  if (opts.chainKey) {
    safeSql.validateIdentifier(opts.chainKey);
    q = q.where(opts.chainKey, opts.keyValue);
  }
  var built = q.toSql();
  var row = await queryOneAsync(built.sql, built.params);
  if (!row) return { prevHash: ZERO_HASH, counter: 0 };
  frameworkSchema.coerceRow(row);
  return { prevHash: row.rowHash, counter: row.monotonicCounter };
}

/**
 * @primitive b.auditChain.verifyChain
 * @signature b.auditChain.verifyChain(queryAllAsync, tableName, opts)
 * @since     0.4.0
 * @related   b.auditChain.getChainTip, b.audit.verify, b.auditTools.archive
 *
 * Walk the entire chain forward, recomputing each row's hash and
 * comparing against the stored `prevHash` / `rowHash`. Returns
 * `{ ok: true, table, rowsVerified, lastHash }` on a clean walk, or
 * `{ ok: false, table, rowsVerified, breakAt, breakRowId, reason,
 * expected, actual }` on the first mismatch. Callers decide how to
 * react — `b.audit.verify` refuses-to-boot, `b.cli verify-chain`
 * exits non-zero, `b.restoreRollback` blocks promotion.
 *
 * For `audit_log`: if a `_blamejs_audit_purge_anchor` row exists and its
 * signature verifies, the walk starts at `lastPurgedCounter+1` with
 * `prevHash = lastPurgedRowHash`. The anchor is written by
 * `b.auditTools.purge` after a successful archive and lets the chain math
 * survive deletion of historical rows without the archive bundle as source
 * of truth.
 *
 * The signature proves this framework wrote the anchor. It does not prove the
 * archive it names still exists or holds those rows, and nothing here can
 * check that — only the consumer knows where bundles live. Pass
 * `resolveArchive(archiveBundleId, range)` to supply that check: an anchor
 * naming an archive that cannot be produced then STOPS the verify rather than
 * licensing the gap. The `range` carries the counters and row hash the anchor
 * covers, because several archived slices can share the checkpoint that covers
 * them and so share the identifier — matching on the identifier alone would
 * accept an older sibling as proof the anchored bundle is still there. Without
 * a resolver the walk proceeds and the result reports
 * `purgeAnchor.archiveResolved: false`, so a caller is never told an archive
 * was verified when none was looked for.
 *
 * Pass `{ chainKey }` to verify a MULTI-chain table partitioned by a key
 * column (one chain per account / device / tenant): each key's sub-chain is
 * walked independently from `ZERO_HASH`, and the first break in any key returns
 * `{ ok:false, chainKey, breakAt, ... }`. Under `chainKey`, `maxRows` is
 * per-sub-chain and `maxChains` bounds the partition fan-out, failing closed
 * when exceeded. The `audit_log` purge-anchor logic is single-chain-only and
 * is skipped when a `chainKey` is given.
 *
 * @opts
 *   maxRows:   number,   // stop after N rows per (sub-)chain (default: walk every row)
 *   chainKey:  string,   // partition column — verify each sub-chain independently
 *   maxChains: number,   // max partitions to verify under chainKey (default 100000; fails closed)
 *   from:      number,   // single-chain only: verify rows with monotonicCounter >= from, anchored at the predecessor's rowHash (incremental verify after a known-good checkpoint)
 *   to:        number,   // single-chain only: verify rows with monotonicCounter <= to
 *
 * @example
 *   async function queryAll(sql) { return await myDriver.query(sql); }
 *   var result = await b.auditChain.verifyChain(queryAll, "audit_log", {});
 *   // → { ok: true, table: "audit_log", rowsVerified: 4217, lastHash: "<hex>" }
 */
function _walkRows(rows, tableName, startPrevHash, opts) {
  var prevHash = startPrevHash;
  if (rows.length === 0) {
    return { ok: true, table: tableName, rowsVerified: 0, lastHash: prevHash };
  }
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.prevHash !== prevHash) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: i,
        breakAt:      i,
        breakRowId:   row._id,
        reason:       "prevHash mismatch",
        expected:     prevHash,
        actual:       row.prevHash,
      };
    }
    var fields = Object.assign({}, row);
    delete fields.prevHash;
    delete fields.rowHash;
    delete fields.nonce;
    delete fields.fencingToken;
    var nonceBuf = Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
    var computed = computeRowHash(prevHash, fields, nonceBuf);
    if (computed !== row.rowHash) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: i,
        breakAt:      i,
        breakRowId:   row._id,
        reason:       "rowHash mismatch",
        expected:     computed,
        actual:       row.rowHash,
      };
    }
    prevHash = row.rowHash;

    if (opts.maxRows && i >= opts.maxRows - 1) break;
  }
  var verifiedCount = opts.maxRows ? Math.min(rows.length, opts.maxRows) : rows.length;
  return { ok: true, table: tableName, rowsVerified: verifiedCount, lastHash: prevHash };
}

async function verifyChain(queryAllAsync, tableName, opts) {
  opts = opts || {};

  ["resolveArchive", "resolvePublicKey"].forEach(function (name) {
    var badShape = validateOpts.definedFunctionMessage(
      opts[name], "verifyChain: opts." + name);
    if (badShape) throw new TypeError(badShape);
  });

  if (opts.chainKey) {
    safeSql.validateIdentifier(opts.chainKey);
    var keysBuilt = sql.select(tableName, _sqlOpts())
      .distinct()
      .columns([opts.chainKey])
      .orderBy(opts.chainKey, "asc")
      .toSql();
    var keyRows = frameworkSchema.coerceRows(await queryAllAsync(keysBuilt.sql, keysBuilt.params));
    var maxChains = numericBounds.isPositiveFiniteInt(opts.maxChains) ? opts.maxChains : 100000;
    if (keyRows.length > maxChains) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: 0,
        reason:       "too many chains: " + keyRows.length + " partitions exceeds maxChains " + maxChains,
      };
    }
    var totalVerified = 0;
    var lastHashByKey = {};
    for (var ki = 0; ki < keyRows.length; ki++) {
      var keyValue = keyRows[ki][opts.chainKey];
      var rowsBuiltK = sql.select(tableName, _sqlOpts())
        .where(opts.chainKey, keyValue)
        .orderBy("monotonicCounter", "asc")
        .toSql();
      var rowsK = frameworkSchema.coerceRows(await queryAllAsync(rowsBuiltK.sql, rowsBuiltK.params));
      var resK = _walkRows(rowsK, tableName, ZERO_HASH, opts);
      if (!resK.ok) { resK.chainKey = keyValue; return resK; }
      totalVerified += resK.rowsVerified;
      lastHashByKey[String(keyValue)] = resK.lastHash;
    }
    return {
      ok:           true,
      table:        tableName,
      rowsVerified: totalVerified,
      chains:       keyRows.length,
      lastHashByKey: lastHashByKey,
    };
  }

  var prevHash = ZERO_HASH;
  var skipBeforeCounter = 0;
  var anchorReport = null;
  if (tableName === "audit_log") {
    var anchorRow = await _readPurgeAnchorRow(queryAllAsync);
    var verdict = verifyPurgeAnchor(anchorRow, {
      resolvePublicKey: opts.resolvePublicKey,
      allowUnsigned:    opts.allowUnsignedPurgeAnchor === true,
    });
    var uncheckedAccepted = verdict.status === "unchecked" &&
      opts.allowUncheckedPurgeAnchor === true;
    if (verdict.status !== "absent") {
      if (verdict.status !== "valid" &&
          !(verdict.status === "unsigned" && verdict.accepted) &&
          !uncheckedAccepted) {
        var out = { ok: false, table: tableName, rowsVerified: 0, reason: verdict.reason };
        if (verdict.status === "unchecked") out.purgeAnchorUnchecked = true;
        return out;
      }
      var archiveResolved = false;
      if (typeof opts.resolveArchive === "function") {
        var producible;
        try {
          producible = await opts.resolveArchive(String(anchorRow.archiveBundleId), {
            firstCounter: Number(anchorRow.firstPurgedCounter || 0),
            lastCounter:  Number(anchorRow.lastPurgedCounter),
            lastRowHash:  String(anchorRow.lastPurgedRowHash),
            rowsDigest:   anchorRow.archiveRowsDigest == null
                          ? "" : String(anchorRow.archiveRowsDigest),
            checkpointDigest: anchorRow.archiveCheckpointDigest == null
                          ? "" : String(anchorRow.archiveCheckpointDigest),
            manifestDigest: anchorRow.archiveManifestDigest == null
                          ? "" : String(anchorRow.archiveManifestDigest),
          });
        } catch (e) {
          return { ok: false, table: tableName, rowsVerified: 0,
            reason: "purge anchor's archive '" + anchorRow.archiveBundleId +
              "' could not be resolved: " + ((e && e.message) || String(e)) };
        }
        if (!producible) {
          return { ok: false, table: tableName, rowsVerified: 0,
            reason: "purge anchor names archive '" + anchorRow.archiveBundleId +
              "', which could not be produced — the rows it accounts for are " +
              "missing and nothing can show what they were" };
        }
        archiveResolved = true;
      }

      prevHash = verdict.hash;
      skipBeforeCounter = verdict.counter;
      anchorReport = {
        honored:           true,
        belowCounter:      verdict.counter,
        signatureVerified: verdict.status === "valid",
        archiveResolved:   archiveResolved,
        archiveBundleId:   String(anchorRow.archiveBundleId),
        archiveCoversFrom: Number(anchorRow.firstPurgedCounter || 0),
        archiveCoversTo:   verdict.counter,
        licensedFrom:      0,
      };
      if (verdict.fingerprint) anchorReport.publicKeyFingerprint = verdict.fingerprint;
    }
  }

  var fromCounter = (opts.from != null && isFinite(Number(opts.from))) ? Number(opts.from) : null;
  var toCounter   = (opts.to != null && isFinite(Number(opts.to)))   ? Number(opts.to)   : null;

  var rowsBuilt = sql.select(tableName, _sqlOpts())
    .orderBy("monotonicCounter", "asc")
    .toSql();
  var rows = await queryAllAsync(rowsBuilt.sql, rowsBuilt.params);
  rows = frameworkSchema.coerceRows(rows);

  if (fromCounter != null && fromCounter > skipBeforeCounter + 1) {
    var pred = null;
    for (var pi = 0; pi < rows.length; pi++) {
      var pc = Number(rows[pi].monotonicCounter);
      if (pc < fromCounter && pc > skipBeforeCounter) pred = rows[pi]; else if (pc >= fromCounter) break;
    }
    if (pred) {
      if (!safeBuffer.isHex(pred.rowHash, SHA3_512_HEX_LEN)) {
        return { ok: false, table: tableName, rowsVerified: 0, reason: "incremental-verify anchor row has a corrupt rowHash" };
      }
      prevHash = pred.rowHash;
      skipBeforeCounter = Math.max(skipBeforeCounter, Number(pred.monotonicCounter));
    }
  }

  if (skipBeforeCounter > 0 || toCounter != null) {
    rows = rows.filter(function (r) {
      var c = Number(r.monotonicCounter);
      if (c <= skipBeforeCounter) return false;
      if (toCounter != null && c > toCounter) return false;
      return true;
    });
  }

  var walked = _walkRows(rows, tableName, prevHash, opts);
  if (anchorReport) walked.purgeAnchor = anchorReport;
  return walked;
}

module.exports = {
  ZERO_HASH:          ZERO_HASH,
  canonicalize:       canonicalize,
  computeRowHash:     computeRowHash,
  getChainTip:        getChainTip,
  purgeAnchorPayload: purgeAnchorPayload,
  purgeAnchorSignatureVerifies: purgeAnchorSignatureVerifies,
  verifyChain:        verifyChain,
  verifyPurgeAnchor:  verifyPurgeAnchor,
};
