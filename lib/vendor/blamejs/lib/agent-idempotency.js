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

// The default in-memory backend is keyed on (method, actorId, keyHash) —
// the key hash comes from request-supplied idempotency keys, so a flood of
// distinct keys would grow the Map without bound (gc only reclaims EXPIRED
// rows, and only if the operator wires a scheduler to call it). Cap it.
// Evict-oldest degrades gracefully under flood: the worst case is a dropped
// dedup record, so a retry of that one key re-executes — never an OOM.
// Operators who need a hard guarantee at scale supply a durable `opts.store`.
var DEFAULT_IN_MEMORY_MAX_ENTRIES = 100000;

var audit             = lazyRequire(function () { return require("./audit"); });
var cryptoField       = lazyRequire(function () { return require("./crypto-field"); });
var vault             = lazyRequire(function () { return require("./vault"); });

var AgentIdempotencyError = defineClass("AgentIdempotencyError", { alwaysPermanent: true });

var DEFAULT_TTL_MS        = C.TIME.hours(24);
var MAX_RESULT_BYTES      = C.BYTES.mib(1);

// At-rest sealing of the cached result. The result envelope can hold
// mail-move / search payloads, so the serialized blob is sealed via
// b.cryptoField before it reaches the backing store and unsealed on
// read — when a vault is configured (the default in a booted app via
// b.start). Without a vault there is no key, so the blob is stored
// as-is, the same vault-less mode the orchestrator's salted-FNV
// fallback supports. AAD binds each ciphertext to its keyHash (the row
// identity) so a DB-write attacker cannot copy a sealed result between
// rows. Rows written while vault-less (or before sealing landed) are
// plain JSON; unsealRow passes a non-`vault:` value through unchanged.
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
    // putIfAbsent gates concurrent retries at the cache
    // boundary so only one consumer runs the handler. Operator wraps:
    //   var claim = await idem.putIfAbsent(method, actor, key, args);
    //   if (claim.alreadyClaimed) return claim.result; // another retry won
    //   var result = await agent[method](args);
    //   await idem.put(method, actor, key, result, { args });
    putIfAbsent: function (method, actorId, key, putOpts)             { return _putIfAbsent(store, method, actorId, key, putOpts || {}, ttlMs, maxResultBytes, fingerprintArgs, auditImpl); },
    invalidate: function (method, actorId, key)                       { return _invalidate(store, method, actorId, key, auditImpl); },
    gc:         function (gcOpts)                                     { return _gc(store, gcOpts || {}, auditImpl); },
    fingerprintArgs: _fingerprintArgs,
    keyHash:    _keyHash,
    AgentIdempotencyError: AgentIdempotencyError,
  };
}

// Atomic claim/check/run pattern. Returns one of:
//   { alreadyClaimed: false, fingerprint }          — caller runs the handler
//   { alreadyClaimed: true,  pending: true }        — another in-flight claim holds the slot
//   { alreadyClaimed: true,  result: <cached> }     — prior handler completed; cached result
//
// Per JMAP §3.7 + draft-ietf-httpapi-idempotency-key §5, exactly-once
// semantics require an atomic claim BEFORE running the handler — the
// prior get→put pattern raced when two consumers picked the same
// envelope off the queue at the same instant. Operators with a SQL/
// Redis backend implement `store.putIfAbsent(key, value) → boolean`
// (true on insert, false on existing row); the in-memory fallback
// emulates via a synchronous Map check.
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
  // Operator-supplied putIfAbsent path. Returns truthy when the row
  // was inserted (we won the claim); falsy when the row already
  // existed (another retry won OR a completed result is cached).
  var inserted = false;
  if (typeof store.putIfAbsent === "function") {
    inserted = await store.putIfAbsent(method, actorId, hash, pendingRow);
  } else {
    // Backends without atomic putIfAbsent fall back to optimistic-
    // get-then-put. The race window is narrow but real; operators
    // with strict exactly-once requirements wire the atomic store.
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
  // We lost the claim — load the existing row.
  var existing = await store.get(method, actorId, hash);
  if (!existing) {
    // Race: insert+immediate-delete. Tell the caller it's safe to
    // retry; the caller's retry policy decides whether to back off.
    return { alreadyClaimed: false, fingerprint: requestFingerprint };
  }
  // Defense-in-depth: caller's args must match. Operator MAY pass a
  // different result type than originally cached only if the
  // fingerprint matches — protects against logic-bug downgrade.
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
  // Completed cached result.
  var result;
  try { result = safeJson.parse(existing.resultBlob, { maxBytes: maxResultBytes }); }
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
  // Unseal the result blob into a copy (when a vault is configured;
  // vault-less or pre-sealing rows are plain JSON and used as-is). The
  // original sealed `row` is preserved so the replay-count re-put below
  // cannot round-trip plaintext back to the store.
  var unsealed = row;
  if (vault().isInitialized()) {
    _ensureSealTable();
    unsealed = cryptoField().unsealRow(SEAL_TABLE, row);
  }
  var result;
  try {
    // Parse cap mirrors the operator's configured maxResultBytes (the
    // same cap put() enforced on write) — a static parse ceiling would
    // turn valid cached entries into permanent replay errors when the
    // operator raises the write cap.
    result = safeJson.parse(unsealed.resultBlob, { maxBytes: maxResultBytes });
  } catch (e) {
    throw new AgentIdempotencyError("agent-idempotency/corrupt-result",
      "get: cached result failed to parse — " + (e && e.message ? e.message : String(e)));
  }
  // Atomic replayCount increment. The prior shape
  // (read row → mutate → put row) raced two concurrent retries: each
  // saw replayCount=N, both wrote replayCount=N+1, so the counter
  // missed bumps and the put-with-fresh-result race-clobbered prior
  // increments. Operators wire `store.incrementReplayCount` with
  // `UPDATE ... SET replay_count = replay_count + 1 RETURNING *`
  // (atomic at the DB layer); in-memory backend is naturally atomic.
  // When the store doesn't expose the helper, fall back to read-
  // modify-write with an audit emit so operators know the posture.
  var updatedReplayCount;
  if (typeof store.incrementReplayCount === "function") {
    var updated = await store.incrementReplayCount(method, actorId, hash);
    updatedReplayCount = updated && updated.replayCount ? updated.replayCount : (row.replayCount || 0) + 1;
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
  // Seal the result blob at rest when a vault is configured (keyHash is
  // populated above, so the AAD binding resolves). resultBlob stays the
  // plaintext local for the audit byte-count below.
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
  return hash.slice(0, 16);                                                                            // audit-log truncation length, not a size cap
}

function _fingerprintArgs(args) {
  // Strip the idempotencyKey itself out of fingerprint computation —
  // the key IS the cache lookup; including it would make every key a
  // unique fingerprint and defeat the args-mismatch defense. Strip
  // _traceContext (varies per-hop, doesn't change result).
  //
  // DO NOT strip _postureChain. The prior shape ignored
  // _postureChain.postureSet, so a request made under
  // postureSet:["hipaa","pci-dss"] cached the same result that a
  // downgrade attempt under postureSet:["pci-dss"] would replay
  // (elevated-posture cached output returned to a less-privileged
  // caller). Including the sorted postureSet in the fingerprint binds
  // the cached result to its compliance context — defense-in-depth
  // alongside the boundary-time downgrade refusal in
  // b.agent.postureChain._validate.
  var argsClone = Object.assign({}, args);
  delete argsClone.idempotencyKey;
  delete argsClone._traceContext;
  if (argsClone._postureChain && typeof argsClone._postureChain === "object" &&
      Array.isArray(argsClone._postureChain.postureSet)) {
    argsClone._postureSet = argsClone._postureChain.postureSet.slice().sort();
  }
  delete argsClone._postureChain;                                                                        // chainTrail + enteredAt vary per-hop; postureSet binds via _postureSet
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

function _inMemoryBackend(maxEntries) {
  // boundedMap validates maxEntries (throws bounded-map/bad-max-entries on a
  // non-positive-int); undefined falls back to the default ceiling.
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
    // Atomic insert. Map.set is synchronous so the
    // get+set pair below is naturally race-free within the in-memory
    // backend (V8 single-threaded). Returns true when inserted, false
    // when the row already exists.
    putIfAbsent: function (method, actorId, hash, row) {
      var k = _k(method, actorId, hash);
      if (map.has(k)) return Promise.resolve(false);
      map.set(k, row);
      return Promise.resolve(true);
    },
    // Atomic replayCount increment. Operators wiring
    // a SQL backend implement this with `UPDATE ... SET
    // replay_count = replay_count + 1 WHERE keyHash = $1 RETURNING *`
    // — read-modify-write race-free. In-memory backend is naturally
    // race-free; returns a SNAPSHOT of the row at the moment of
    // increment so two concurrent callers each see their own
    // replayCount (operator's SQL backend RETURNING * does the same).
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

// ---- Vault-key rotation: out-of-band reseal hook -------------------------
//
// The cached-result column is AAD-sealed on an OPERATOR-SUPPLIED backing
// store (opts.store / the in-memory default), NOT in the framework's db.enc.
// The vault-key rotation pipeline (b.vaultRotate.rotate) only walks tables
// that live inside db.enc, so it cannot reach this store — the rows would be
// ORPHANED under the old vault root after a rotation (CWE-320 cryptographic-
// key-management failure: ciphertext stranded under a retired key, then
// unreadable once the old keypair is destroyed). This reseal hook lets an
// operator rotate the store out-of-band, composing the SAME explicit-root
// primitive the in-tree pipeline uses (vaultAad.resealRoot) and the SAME
// AAD builder the seal path used (cryptoField._aadParts) so the re-sealed
// AAD tuple is byte-identical — one source of truth, no drift.
//
// Reseal store contract (the durable SQL / Redis backend the operator
// already wired for opts.store also exposes):
//   - listAll()        → array of every stored row (each row carries the
//                        sealed `resultBlob` column + its keyHash identity).
//   - putResealed(row) → write the row back, addressed by its own stored
//                        identity (keyHash). Distinct from the per-request
//                        put(method, actorId, key) because reseal addresses
//                        a row by the row identity already on disk, not by
//                        the raw idempotency key (which is never stored —
//                        only its namespaced keyHash is).
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
  // listAll / putResealed may be sync (in-memory) or async (durable SQL /
  // Redis). Thread both through Promise.resolve so either shape works.
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
        // Only AAD-sealed cells need rotating. Vault-less / pre-sealing rows
        // carry plain JSON; a plain `vault:` cell would have been written by
        // a non-AAD path that doesn't exist for this table — leave both
        // untouched (resealRoot would throw not-sealed on a plain value).
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
  // AAD_ROTATION — the vault-key rotation descriptor every framework module
  // that seals an {aad:true} table on an OPERATOR-SUPPLIED store (outside
  // db.enc) exports, so an operator can register it with a rotation eager-
  // sweep and the codebase-patterns detect-and-refuse gate can confirm no
  // such external-store table is silently orphaned. `backend: "external"`
  // flags that the in-tree b.vaultRotate.rotate pipeline cannot reach it.
  AAD_ROTATION: {
    table:         SEAL_TABLE,
    rowIdField:    "keyHash",
    schemaVersion: "1",
    backend:       "external",
    reseal:        reseal,
  },
};
