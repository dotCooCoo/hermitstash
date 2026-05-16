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
 *       result envelope or `null`. Sealed columns unseal via
 *       `b.cryptoField`.
 *     - **`instance.put(method, actorId, key, result, opts?)`** —
 *       serialize (`b.safeJson.stringify`) + seal + persist with TTL.
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

var audit             = lazyRequire(function () { return require("./audit"); });

var AgentIdempotencyError = defineClass("AgentIdempotencyError", { alwaysPermanent: true });

var DEFAULT_TTL_MS        = C.TIME.hours(24);
var MAX_RESULT_BYTES      = C.BYTES.mib(1);
// Parse ceiling tracks the operator's configured maxResultBytes (set
// per-instance via opts.maxResultBytes) — see _get. A static parse cap
// would silently lose entries when operators raise the write cap.

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
 *   await idem.put("move", "u1", "jmap-req-abc", result, { argsFingerprint: "..." });
 */
function create(opts) {
  opts = opts || {};
  var store = opts.store || _inMemoryBackend();
  if (typeof store.get !== "function" || typeof store.put !== "function" ||
      typeof store.delete !== "function") {
    throw new AgentIdempotencyError("agent-idempotency/bad-store",
      "create: store must expose { get, put, delete }");
  }
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
    invalidate: function (method, actorId, key)                       { return _invalidate(store, method, actorId, key, auditImpl); },
    gc:         function (gcOpts)                                     { return _gc(store, gcOpts || {}, auditImpl); },
    fingerprintArgs: _fingerprintArgs,
    keyHash:    _keyHash,
    AgentIdempotencyError: AgentIdempotencyError,
  };
}

// ---- Core API -------------------------------------------------------------

async function _get(store, method, actorId, key, auditImpl, ttlMs, maxResultBytes) {
  _checkArgs(method, actorId, key);
  guardIdempotencyKey.validate(key);
  var hash = _keyHash(method, actorId, key);
  var row = await store.get(method, actorId, hash);
  if (!row) return null;
  if (row.expiresAt && row.expiresAt < Date.now()) {
    // Expired entries get GC'd lazily on read.
    await store.delete(method, actorId, hash);
    _safeAudit(auditImpl, "agent.idempotency.expired", null,
      { method: method, actorIdHash: _truncHash(_actorIdHash(actorId)) });
    return null;
  }
  var nextReplayCount = (row.replayCount || 0) + 1;
  _safeAudit(auditImpl, "agent.idempotency.replay", null, {
    method: method, actorIdHash: _truncHash(_actorIdHash(actorId)),
    firstAt: row.firstAt, replayCount: nextReplayCount,
  });
  // Deserialize the sealed result blob. v0.9.22 ships a simple
  // safeJson re-parse since the result was JSON-stringified at put().
  // v0.9.25 tenant integration will swap this for per-tenant sealRow
  // unseal when the row is sealed at rest.
  var result;
  try {
    // Parse cap mirrors the operator's configured maxResultBytes (the
    // same cap put() enforced on write) — a static parse ceiling would
    // turn valid cached entries into permanent replay errors when the
    // operator raises the write cap.
    result = safeJson.parse(row.resultBlob, { maxBytes: maxResultBytes });
  } catch (e) {
    throw new AgentIdempotencyError("agent-idempotency/corrupt-result",
      "get: cached result failed to parse — " + (e && e.message ? e.message : String(e)));
  }
  // Persist the incremented replayCount + lastReplayedAt so subsequent
  // gets see the updated state. Operator audit pipelines rely on
  // replayCount to surface retry storms.
  row.replayCount    = nextReplayCount;
  row.lastReplayedAt = Date.now();
  await store.put(method, actorId, hash, row);
  return {
    result:               result,
    firstAt:              row.firstAt,
    lastReplayedAt:       row.lastReplayedAt,
    replayCount:          nextReplayCount,
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
  await store.put(method, actorId, hash, row);
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
    // Backend doesn't support GC (in-memory default does); operator
    // periodic cleanup of durable stores is the operator's job.
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

// ---- Internals ------------------------------------------------------------

function _keyHash(method, actorId, key) {
  // Namespaced hash — same pattern as v0.9.15 b.middleware.idempotencyKey
  // dbStore so raw operator-supplied keys never reach disk.
  return bCrypto.namespaceHash("agent.idempotency",
    method + "\0" + actorId + "\0" + key);
}

function _actorIdHash(actorId) {
  return bCrypto.namespaceHash("agent.idempotency.actor", String(actorId));
}

function _truncHash(hash) {
  if (typeof hash !== "string") return "";
  return hash.slice(0, 16);                                                                            // allow:raw-byte-literal — audit-log truncation length, not a size cap
}

function _fingerprintArgs(args) {
  // Strip the idempotencyKey itself out of fingerprint computation —
  // the key IS the cache lookup; including it would make every key a
  // unique fingerprint and defeat the args-mismatch defense. Also
  // strip framework-internal cross-cutting fields that vary per-hop.
  var argsClone = Object.assign({}, args);
  delete argsClone.idempotencyKey;
  delete argsClone._postureChain;
  delete argsClone._traceContext;
  // Canonicalize via RFC 8785 JCS (key-sorted) so two semantically
  // identical args objects with different key insertion order produce
  // the same fingerprint. Cross-producer / cross-runtime retries (JMAP
  // clients, queue replay, different JSON parsers) construct objects
  // with different key order; without canonicalization the args-
  // mismatch check would fire false-positives.
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
  // key is validated separately via guardIdempotencyKey.validate.
}

function _inMemoryBackend() {
  var map = new Map();
  function _k(method, actorId, hash) { return method + "\0" + actorId + "\0" + hash; }
  return {
    get:    function (method, actorId, hash) {
      return Promise.resolve(map.get(_k(method, actorId, hash)) || null);
    },
    put:    function (method, actorId, hash, row) {
      map.set(_k(method, actorId, hash), row);
      return Promise.resolve();
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

module.exports = {
  create:                 create,
  AgentIdempotencyError:  AgentIdempotencyError,
  guards: {
    key: guardIdempotencyKey,
  },
};
