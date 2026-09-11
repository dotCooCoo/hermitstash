// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.agent.idempotency
 * @nav        Agent
 * @title      Agent Idempotency
 * @order      55
 *
 * @intro
 *   Cross-dispatch idempotency keys honored at every agent consumer
 *   boundary. Composes the v0.9.15 sealed `b.middleware.idempotencyKey`
 *   patterns (namespace-hashed keys, sealed result columns) into a
 *   generic agent-shaped surface:
 *
 *     - **`instance.get(method, actorId, key)`** — returns cached
 *       result envelope or `null`. The result blob unseals via
 *       `b.cryptoField` when a vault is configured.
 *     - **`instance.put(method, actorId, key, result, opts?)`** —
 *       serialize (`b.safeJson.stringify`), seal the result blob at rest
 *       via `b.cryptoField` (when a vault is configured — the default in
 *       a booted app; vault-less, the blob is stored as-is), persist
 *       with TTL.
 *       Refuses if the same `(method, actorId, key)` already has a
 *       cached entry whose `requestFingerprint` differs from the
 *       supplied args fingerprint (defends key-reuse-different-args
 *       attack).
 *     - **`instance.invalidate(method, actorId, key)`** — operator
 *       opt-out (e.g., a saga compensation that needs to allow a
 *       fresh retry).
 *     - **`instance.gc({ olderThanMs })`** — periodic cleanup, wires
 *       into `b.scheduler`.
 *
 *   JMAP §3.7 requires method-level idempotency ("if Email/set is
 *   retried with the same accountId+id, the server MUST return the
 *   same result"). With v0.9.22 every mutating agent method honors
 *   `args.idempotencyKey` and the consumer side dedupes BEFORE
 *   running — at-least-once delivery on the queue + at-most-once at
 *   the consumer = exactly-once end-to-end.
 *
 *   ```js
 *   var idem = b.agent.idempotency.create({
 *     store: myBackingStore,
 *     ttlMs: b.C.TIME.hours(24),
 *   });
 *
 *   var result = await agent.move({
 *     actor: u, fromFolder: "INBOX", toFolder: "Archive", objectIds: [oid],
 *     idempotencyKey: "jmap-req-abc",
 *   });
 *
 *   // Retry returns cached result, doesn't re-bump modseq:
 *   var result2 = await agent.move({
 *     actor: u, fromFolder: "INBOX", toFolder: "Archive", objectIds: [oid],
 *     idempotencyKey: "jmap-req-abc",
 *   });
 *   ```
 *
 * @card
 *   JMAP retry-safe semantics for every agent method. Keys hashed at
 *   the boundary; results sealed + persisted with TTL; consumer-side
 *   dedup at the dispatch boundary turns at-least-once + at-most-once
 *   into exactly-once.
 */

var lazyRequire       = require("./lazy-require");
var C                 = require("./constants");
var { defineClass }   = require("./framework-error");
var bCrypto           = require("./crypto");
var safeJson          = require("./safe-json");
var guardIdempotencyKey = require("./guard-idempotency-key");
var agentAudit        = require("./agent-audit");
var { boundedMap }    = require("./bounded-map");
var vaultAad          = require("./vault-aad");
var validateOpts      = require("./validate-opts");

var DEFAULT_IN_MEMORY_MAX_ENTRIES = 100000;

var audit             = lazyRequire(function () { return require("./audit"); });
var cryptoField       = lazyRequire(function () { return require("./crypto-field"); });
var vault             = lazyRequire(function () { return require("./vault"); });

var AgentIdempotencyError = defineClass("AgentIdempotencyError", { alwaysPermanent: true });

var DEFAULT_TTL_MS        = C.TIME.hours(24);
var MAX_RESULT_BYTES      = C.BYTES.mib(1);

var SEAL_TABLE = "agent_idempotency";
var _sealTableRegistered = false;
function _ensureSealTable() {
  if (_sealTableRegistered) return;
  cryptoField().registerTable(SEAL_TABLE, {
    sealedFields: ["resultBlob"],
    aad:          true,
    rowIdField:   "keyHash",
  });
  _sealTableRegistered = true;
}

/**
 * @primitive b.agent.idempotency.create
 * @signature b.agent.idempotency.create(opts)
 * @since     0.9.22
 * @status    stable
 * @related   b.agent.orchestrator.create, b.middleware.idempotencyKey.dbStore
 *
 * Create an idempotency instance for an agent. Operator supplies a
 * backing store implementing `{ get, put, delete, gc }`; framework
 * ships an in-memory default for single-process deployments.
 *
 * @opts
 *   store:        { get, put, delete, gc },     // optional; in-memory default
 *   audit:        b.audit namespace,            // optional
 *   ttlMs:        number,                        // default 24h
 *   maxResultBytes: number,                      // default 1 MiB per entry
 *   fingerprintArgs: boolean,                    // default true
 *
 * @example
 *   var idem = b.agent.idempotency.create({});
 *   var existing = await idem.get("move", "u1", "jmap-req-abc");
 *   if (existing) return existing.result;
 *   var result = await mailAgent.move(args);
 *   await idem.put("move", "u1", "jmap-req-abc", result, { requestFingerprint: "..." });
 */
function create(opts) {
  opts = opts || {};
  var store = opts.store || _inMemoryBackend(opts.maxInMemoryEntries);
  validateOpts.requireMethods(store, ["get", "put", "delete"],
    "create: store", AgentIdempotencyError, "agent-idempotency/bad-store");
  var ttlMs = typeof opts.ttlMs === "number" ? opts.ttlMs : DEFAULT_TTL_MS;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new AgentIdempotencyError("agent-idempotency/bad-ttl",
      "create: opts.ttlMs must be a positive finite number");
  }
  var maxResultBytes = typeof opts.maxResultBytes === "number" ? opts.maxResultBytes : MAX_RESULT_BYTES;
  var fingerprintArgs = opts.fingerprintArgs !== false;
  var auditImpl = opts.audit || audit();

  return {
    get:        function (method, actorId, key)                       { return _get(store, method, actorId, key, auditImpl, ttlMs, maxResultBytes); },
    put:        function (method, actorId, key, result, putOpts)      { return _put(store, method, actorId, key, result, putOpts || {}, ttlMs, maxResultBytes, fingerprintArgs, auditImpl); },
    putIfAbsent: function (method, actorId, key, putOpts)             { return _putIfAbsent(store, method, actorId, key, putOpts || {}, ttlMs, maxResultBytes, fingerprintArgs, auditImpl); },
    invalidate: function (method, actorId, key)                       { return _invalidate(store, method, actorId, key, auditImpl); },
    gc:         function (gcOpts)                                     { return _gc(store, gcOpts || {}, auditImpl); },
    fingerprintArgs: _fingerprintArgs,
    keyHash:    _keyHash,
    AgentIdempotencyError: AgentIdempotencyError,
  };
}

async function _putIfAbsent(store, method, actorId, key, putOpts, ttlMs, maxResultBytes, fingerprintArgs, auditImpl) {
  _checkArgs(method, actorId, key);
  guardIdempotencyKey.validate(key);
  var hash = _keyHash(method, actorId, key);
  var requestFingerprint = putOpts.requestFingerprint ||
    (fingerprintArgs && putOpts.args ? _fingerprintArgs(putOpts.args) : null);
  var now = Date.now();
  var pendingRow = {
    method:             method,
    actorIdHash:        _actorIdHash(actorId),
    keyHash:            hash,
    requestFingerprint: requestFingerprint,
    resultBlob:         null,
    firstAt:            now,
    lastWrittenAt:      now,
    replayCount:        0,
    expiresAt:          now + ttlMs,
    status:             "pending",
  };
  var inserted = false;
  if (typeof store.putIfAbsent === "function") {
    inserted = await store.putIfAbsent(method, actorId, hash, pendingRow);
  } else {
    var existing0 = await store.get(method, actorId, hash);
    if (!existing0) {
      await store.put(method, actorId, hash, pendingRow);
      inserted = true;
    }
  }
  if (inserted) {
    _safeAudit(auditImpl, "agent.idempotency.claimed", null, {
      method: method, actorIdHash: _truncHash(pendingRow.actorIdHash),
    });
    return { alreadyClaimed: false, fingerprint: requestFingerprint };
  }
  var existing = await store.get(method, actorId, hash);
  if (!existing) {
    return { alreadyClaimed: false, fingerprint: requestFingerprint };
  }
  if (existing.requestFingerprint && requestFingerprint &&
      existing.requestFingerprint !== requestFingerprint) {
    _safeAudit(auditImpl, "agent.idempotency.key_reuse_different_args", null, {
      method: method, actorIdHash: _truncHash(existing.actorIdHash),
    });
    throw new AgentIdempotencyError("agent-idempotency/key-reuse-different-args",
      "putIfAbsent: key '" + key + "' reused with different args for method '" + method +
      "' — refused per JMAP §3.7 semantics");
  }
  if (existing.status === "pending") {
    return { alreadyClaimed: true, pending: true, firstAt: existing.firstAt };
  }
  var unsealed = existing;
  if (vault().isInitialized()) {
    _ensureSealTable();
    unsealed = cryptoField().unsealRow(SEAL_TABLE, existing);
  }
  var result;
  try { result = safeJson.parse(unsealed.resultBlob, { maxBytes: maxResultBytes }); }
  catch (e) {
    throw new AgentIdempotencyError("agent-idempotency/corrupt-result",
      "putIfAbsent: cached result failed to parse — " + (e && e.message ? e.message : String(e)));
  }
  return {
    alreadyClaimed: true,
    pending:        false,
    result:         result,
    firstAt:        existing.firstAt,
    replayCount:    existing.replayCount || 0,
  };
}

async function _get(store, method, actorId, key, auditImpl, ttlMs, maxResultBytes) {
  _checkArgs(method, actorId, key);
  guardIdempotencyKey.validate(key);
  var hash = _keyHash(method, actorId, key);
  var row = await store.get(method, actorId, hash);
  if (!row) return null;
  if (row.expiresAt && row.expiresAt < Date.now()) {
    await store.delete(method, actorId, hash);
    _safeAudit(auditImpl, "agent.idempotency.expired", null,
      { method: method, actorIdHash: _truncHash(_actorIdHash(actorId)) });
    return null;
  }
  if (row.resultBlob === null || row.resultBlob === undefined) return null;
  var unsealed = row;
  if (vault().isInitialized()) {
    _ensureSealTable();
    unsealed = cryptoField().unsealRow(SEAL_TABLE, row);
  }
  var result;
  try {
    result = safeJson.parse(unsealed.resultBlob, { maxBytes: maxResultBytes });
  } catch (e) {
    throw new AgentIdempotencyError("agent-idempotency/corrupt-result",
      "get: cached result failed to parse — " + (e && e.message ? e.message : String(e)));
  }
  var updatedReplayCount;
  if (typeof store.incrementReplayCount === "function") {
    var updated = await store.incrementReplayCount(method, actorId, hash);
    var inc = updated && updated.replayCount != null ? Number(updated.replayCount) : NaN;
    updatedReplayCount = Number.isFinite(inc) ? inc : (Number(row.replayCount) || 0) + 1;
  } else {
    _safeAudit(auditImpl, "agent.idempotency.non_atomic_increment", null, {
      method: method, actorIdHash: _truncHash(_actorIdHash(actorId)),
      warning: "store lacks incrementReplayCount — counter may race under concurrent retries",
    });
    updatedReplayCount = (row.replayCount || 0) + 1;
    row.replayCount    = updatedReplayCount;
    row.lastReplayedAt = Date.now();
    await store.put(method, actorId, hash, row);
  }
  _safeAudit(auditImpl, "agent.idempotency.replay", null, {
    method: method, actorIdHash: _truncHash(_actorIdHash(actorId)),
    firstAt: row.firstAt, replayCount: updatedReplayCount,
  });
  return {
    result:               result,
    firstAt:              row.firstAt,
    lastReplayedAt:       row.lastReplayedAt || Date.now(),
    replayCount:          updatedReplayCount,
    requestFingerprint:   row.requestFingerprint,
  };
}

async function _put(store, method, actorId, key, result, putOpts, ttlMs, maxResultBytes, fingerprintArgs, auditImpl) {
  _checkArgs(method, actorId, key);
  guardIdempotencyKey.validate(key);
  var hash = _keyHash(method, actorId, key);
  var existing = await store.get(method, actorId, hash);
  var requestFingerprint = putOpts.requestFingerprint ||
    (fingerprintArgs && putOpts.args ? _fingerprintArgs(putOpts.args) : null);

  if (existing && existing.requestFingerprint && requestFingerprint &&
      existing.requestFingerprint !== requestFingerprint) {
    _safeAudit(auditImpl, "agent.idempotency.key_reuse_different_args", null, {
      method: method, actorIdHash: _truncHash(_actorIdHash(actorId)),
    });
    throw new AgentIdempotencyError("agent-idempotency/key-reuse-different-args",
      "put: key '" + key + "' reused with different args for method '" + method +
      "' — refused per JMAP §3.7 semantics");
  }
  var resultBlob;
  try { resultBlob = safeJson.stringify(result); }
  catch (e) {
    throw new AgentIdempotencyError("agent-idempotency/bad-result",
      "put: result not JSON-serializable: " + (e && e.message ? e.message : String(e)));
  }
  if (Buffer.byteLength(resultBlob, "utf8") > maxResultBytes) {
    throw new AgentIdempotencyError("agent-idempotency/result-too-big",
      "put: serialized result " + Buffer.byteLength(resultBlob, "utf8") +
      " bytes exceeds maxResultBytes=" + maxResultBytes);
  }
  var now = Date.now();
  var row = {
    method:             method,
    actorIdHash:        _actorIdHash(actorId),
    keyHash:            hash,
    requestFingerprint: requestFingerprint,
    resultBlob:         resultBlob,
    firstAt:            existing && existing.firstAt ? existing.firstAt : now,
    lastWrittenAt:      now,
    replayCount:        existing ? (existing.replayCount || 0) : 0,
    expiresAt:          now + ttlMs,
  };
  var sealedRow = row;
  if (vault().isInitialized()) {
    _ensureSealTable();
    sealedRow = cryptoField().sealRow(SEAL_TABLE, row);
  }
  await store.put(method, actorId, hash, sealedRow);
  _safeAudit(auditImpl, "agent.idempotency.put", null, {
    method: method, actorIdHash: _truncHash(row.actorIdHash),
    resultBytes: Buffer.byteLength(resultBlob, "utf8"),
  });
}

async function _invalidate(store, method, actorId, key, auditImpl) {
  _checkArgs(method, actorId, key);
  guardIdempotencyKey.validate(key);
  var hash = _keyHash(method, actorId, key);
  await store.delete(method, actorId, hash);
  _safeAudit(auditImpl, "agent.idempotency.invalidated", null, {
    method: method, actorIdHash: _truncHash(_actorIdHash(actorId)),
  });
}

async function _gc(store, opts, auditImpl) {
  if (typeof store.gc !== "function") {
    return { purged: 0 };
  }
  var olderThanMs = typeof opts.olderThanMs === "number" ? opts.olderThanMs : 0;
  var cutoff = Date.now() - olderThanMs;
  var r = await store.gc({ expiresAtBefore: cutoff });
  _safeAudit(auditImpl, "agent.idempotency.gc", null, {
    purged: r && r.purged ? r.purged : 0,
  });
  return r || { purged: 0 };
}

function _keyHash(method, actorId, key) {
  return bCrypto.namespaceHash("agent.idempotency",
    method + "\0" + actorId + "\0" + key);
}

function _actorIdHash(actorId) {
  return bCrypto.namespaceHash("agent.idempotency.actor", String(actorId));
}

function _truncHash(hash) {
  if (typeof hash !== "string") return "";
  return hash.slice(0, 16);
}

function _fingerprintArgs(args) {
  var argsClone = Object.assign({}, args);
  delete argsClone.idempotencyKey;
  delete argsClone._traceContext;
  if (argsClone._postureChain && typeof argsClone._postureChain === "object" &&
      Array.isArray(argsClone._postureChain.postureSet)) {
    argsClone._postureSet = argsClone._postureChain.postureSet.slice().sort();
  }
  delete argsClone._postureChain;
  var canonical;
  try { canonical = safeJson.canonical(argsClone); }
  catch (_e) { canonical = "[unserializable]"; }
  return bCrypto.namespaceHash("agent.idempotency.fingerprint", canonical);
}

function _checkArgs(method, actorId, key) {
  if (typeof method !== "string" || method.length === 0) {
    throw new AgentIdempotencyError("agent-idempotency/bad-method",
      "method must be a non-empty string");
  }
  if (typeof actorId !== "string" || actorId.length === 0) {
    throw new AgentIdempotencyError("agent-idempotency/bad-actor-id",
      "actorId must be a non-empty string");
  }
}

function _inMemoryBackend(maxEntries) {
  var map = boundedMap({ maxEntries: maxEntries || DEFAULT_IN_MEMORY_MAX_ENTRIES, policy: "evict-oldest" });
  function _k(method, actorId, hash) { return method + "\0" + actorId + "\0" + hash; }
  return {
    get:    function (method, actorId, hash) {
      return Promise.resolve(map.get(_k(method, actorId, hash)) || null);
    },
    put:    function (method, actorId, hash, row) {
      map.set(_k(method, actorId, hash), row);
      return Promise.resolve();
    },
    putIfAbsent: function (method, actorId, hash, row) {
      var k = _k(method, actorId, hash);
      if (map.has(k)) return Promise.resolve(false);
      map.set(k, row);
      return Promise.resolve(true);
    },
    incrementReplayCount: function (method, actorId, hash) {
      var k = _k(method, actorId, hash);
      var row = map.get(k);
      if (!row) return Promise.resolve(null);
      row.replayCount    = (row.replayCount || 0) + 1;
      row.lastReplayedAt = Date.now();
      return Promise.resolve(Object.assign({}, row));
    },
    delete: function (method, actorId, hash) {
      map.delete(_k(method, actorId, hash));
      return Promise.resolve();
    },
    gc:     function (gcOpts) {
      var cutoff = gcOpts && gcOpts.expiresAtBefore ? gcOpts.expiresAtBefore : 0;
      var purged = 0;
      map.forEach(function (row, k) {
        if (row.expiresAt && row.expiresAt <= cutoff) {
          map.delete(k);
          purged += 1;
        }
      });
      return Promise.resolve({ purged: purged });
    },
  };
}

function _safeAudit(auditImpl, action, actor, metadata) {
  agentAudit.safeAudit(auditImpl, action, actor, metadata);
}

/**
 * @primitive b.agent.idempotency.reseal
 * @signature b.agent.idempotency.reseal(opts)
 * @since      0.14.12
 * @status     stable
 * @compliance gdpr, soc2
 * @related    b.vault.getKeysJson, b.cryptoField.sealRow
 *
 * Re-seals every AAD-bound cached-result cell on an operator-supplied
 * store from the OLD vault keypair to the NEW one, out-of-band. The
 * in-tree vault-key rotation pipeline only walks tables inside `db.enc`,
 * so an operator-supplied idempotency store is unreachable to it — after a
 * keypair rotation its cells would otherwise be orphaned under the retired
 * root (CWE-320). Composes the same AAD-cell re-seal the rotation pipeline
 * uses, rebuilding each cell's AAD from the registered schema (one source
 * of truth). Only AAD-sealed cells are touched; plain rows pass through.
 *
 * @opts
 *   store:       Object,   // { listAll(): rows[], putResealed(row) } (sync or async)
 *   oldRootJson: string,   // b.vault.getKeysJson() of the retired keypair
 *   newRootJson: string,   // b.vault.getKeysJson() of the new keypair
 *
 * @example
 *   await b.agent.idempotency.reseal({ store: durableStore, oldRootJson: oldKeys, newRootJson: newKeys });
 *   // → { table: "agent_idempotency", resealed: 12 }
 */
function reseal(args) {
  args = args || {};
  validateOpts.requireNonEmptyString(args.oldRootJson,
    "reseal: oldRootJson (b.vault.getKeysJson() of the OLD keypair)",
    AgentIdempotencyError, "agent-idempotency/bad-root");
  validateOpts.requireNonEmptyString(args.newRootJson,
    "reseal: newRootJson (b.vault.getKeysJson() of the NEW keypair)",
    AgentIdempotencyError, "agent-idempotency/bad-root");
  var store = args.store;
  validateOpts.requireMethods(store, ["listAll", "putResealed"],
    "reseal: operator store (so every persisted row can be re-sealed out-of-band)",
    AgentIdempotencyError, "agent-idempotency/bad-reseal-store");
  _ensureSealTable();
  var schema = cryptoField().getSchema(SEAL_TABLE);
  return Promise.resolve(store.listAll()).then(function (rows) {
    if (!Array.isArray(rows)) {
      throw new AgentIdempotencyError("agent-idempotency/bad-reseal-store",
        "reseal: store.listAll() must resolve to an array of rows");
    }
    var chain = Promise.resolve();
    var resealed = 0;
    rows.forEach(function (row) {
      if (!row || typeof row !== "object") return;
      var changed = false;
      for (var f = 0; f < schema.sealedFields.length; f += 1) {
        var column = schema.sealedFields[f];
        var value = row[column];
        if (typeof value !== "string" || !vaultAad.isAadSealed(value)) continue;
        var aadParts = cryptoField()._aadParts(schema, SEAL_TABLE, column, row);
        row[column] = vaultAad.resealRoot(value, aadParts, args.oldRootJson, args.newRootJson);
        changed = true;
      }
      if (changed) {
        resealed += 1;
        chain = chain.then(function () { return store.putResealed(row); });
      }
    });
    return chain.then(function () { return { table: SEAL_TABLE, resealed: resealed }; });
  });
}

module.exports = {
  create:                 create,
  reseal:                 reseal,
  AgentIdempotencyError:  AgentIdempotencyError,
  guards: {
    key: guardIdempotencyKey,
  },
  AAD_ROTATION: {
    table:         SEAL_TABLE,
    rowIdField:    "keyHash",
    schemaVersion: "1",
    backend:       "external",
    reseal:        reseal,
  },
};
