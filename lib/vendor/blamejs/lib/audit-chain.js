"use strict";
/**
 * Audit hash chain — tamper-evidence math.
 *
 * Per the compliance spec ("Tamper evidence (the chain + checkpoint signing)"
 * in the roadmap):
 *
 *   rowHash = SHA3-512(
 *     prevHash || canonicalize(row-fields-except-hash) || nonce
 *   )
 *
 * Each row's prevHash equals the previous row's rowHash (in monotonic-counter
 * order). The first row uses ZERO_HASH as prevHash. Verification walks the
 * chain forward; any row whose prevHash doesn't match the running hash, or
 * whose rowHash recomputes differently, breaks the chain.
 *
 * Checkpoint signing (ML-DSA-87 over (atRow || atRowHash)) lives in
 * lib/audit-sign.js. This module owns the chain hash math only;
 * verification is O(n) and walks every row at boot.
 */
var canonicalJson = require("./canonical-json");
var C = require("./constants");
var { sha3Hash } = require("./crypto");

// SHA3-512 outputs 64 bytes; routed through C.BYTES so the file's byte
// arithmetic has one source of truth. Hex-encoded width is twice the
// byte count.
var SHA3_512_BYTES   = C.BYTES.bytes(64);
var SHA3_512_HEX_LEN = SHA3_512_BYTES * 2;

// All-zero SHA3-512 sentinel prevHash for the first row.
var ZERO_HASH = "0".repeat(SHA3_512_HEX_LEN);

// Canonicalize a row for hashing. Excludes the hash/nonce columns themselves
// and any caller-specified columns. Sorted keys, JSON-encoded values; Buffer
// values converted to hex for stable byte serialization. Routes through
// the shared `lib/canonical-json` walker so the four canonicalize sites
// (this one, audit-tools, config-drift, pagination) share one
// implementation of the bug-class fix that started in v0.6.60 and
// completed in v0.6.67.
function canonicalize(row, excludeKeys) {
  var ex = new Set(excludeKeys || []);
  var keys = Object.keys(row).filter(function (k) { return !ex.has(k); }).sort();
  var pairs = {};
  for (var i = 0; i < keys.length; i++) {
    pairs[keys[i]] = row[keys[i]];
  }
  return canonicalJson.stringify(pairs);
}

// Compute a row's hash given its predecessor's hash, the row's logical fields
// (already excluding prevHash, rowHash, nonce), and the row's nonce buffer.
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

// Read the current chain tip (last row's rowHash + monotonicCounter) for a
// given audit table. Async to accommodate operator-supplied external-db
// drivers; queryOneAsync is `async (sql, params?) → row | null`.
async function getChainTip(queryOneAsync, tableName) {
  var row = await queryOneAsync(
    'SELECT rowHash, monotonicCounter FROM "' + tableName + '" ' +
    "ORDER BY monotonicCounter DESC LIMIT 1"
  );
  if (!row) return { prevHash: ZERO_HASH, counter: 0 };
  return { prevHash: row.rowHash, counter: row.monotonicCounter };
}

// Walk the entire chain forward, recomputing each row's hash. Returns an
// object describing the result; callers decide how to react (refuse-to-boot,
// log warning, etc.). queryAllAsync is `async (sql, params?) → rows`.
//
// audit_log only: if a `_blamejs_audit_purge_anchor` row exists, the walk
// starts at lastPurgedCounter+1 with prevHash = lastPurgedRowHash. The
// anchor is written by audit-tools.purge() after a successful archive,
// and lets the chain math survive deletion of historical rows without
// the bundle as the source of truth.
async function verifyChain(queryAllAsync, tableName, opts) {
  opts = opts || {};

  var prevHash = ZERO_HASH;
  var skipBeforeCounter = 0;
  if (tableName === "audit_log") {
    var anchor;
    try {
      anchor = await queryAllAsync(
        "SELECT lastPurgedCounter, lastPurgedRowHash FROM _blamejs_audit_purge_anchor " +
        "WHERE scope = 'audit'"
      );
    } catch (_e) {
      // Anchor table may not exist on a deployment that has never been
      // through a purge. Treat as no anchor.
      anchor = [];
    }
    if (Array.isArray(anchor) && anchor.length > 0) {
      prevHash = anchor[0].lastPurgedRowHash;
      skipBeforeCounter = Number(anchor[0].lastPurgedCounter);
    }
  }

  var rows = await queryAllAsync(
    'SELECT * FROM "' + tableName + '" ORDER BY monotonicCounter ASC'
  );
  if (skipBeforeCounter > 0) {
    rows = rows.filter(function (r) {
      return Number(r.monotonicCounter) > skipBeforeCounter;
    });
  }

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
    // fencingToken is cluster-coordination bookkeeping — orthogonal to
    // tamper-evidence. Excluded from chain hash inputs so deployments
    // upgrading from a pre-cluster schema (no fencingToken column) verify
    // identically before and after the ALTER TABLE.
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
  return { ok: true, table: tableName, rowsVerified: rows.length, lastHash: prevHash };
}

module.exports = {
  ZERO_HASH:      ZERO_HASH,
  canonicalize:   canonicalize,
  computeRowHash: computeRowHash,
  getChainTip:    getChainTip,
  verifyChain:    verifyChain,
};
