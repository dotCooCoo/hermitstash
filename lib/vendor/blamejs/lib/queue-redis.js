// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Redis-protocol queue adapter — backs b.queue with Redis instead of
 * the framework's main DB. Lets operators run multiple app nodes that
 * share a single queue without each needing to be cluster leader,
 * since Redis itself is the coordination point.
 *
 * Storage layout (operator-overridable prefix, default "blamejs:queue"):
 *   <prefix>:job:<jobId>           HASH   — full job record (sealed payload + lastError)
 *   <prefix>:q:<queue>:ready       ZSET   — member=jobId, score=availableAtMs (lease index)
 *   <prefix>:q:<queue>:inflight    ZSET   — member=jobId, score=leaseExpiresAtMs (sweep index)
 *   <prefix>:q:<queue>:dlq         ZSET   — member=jobId, score=finishedAtMs (failed jobs)
 *   <prefix>:q:<queue>:queues      SET    — registry of known queue names (for purge/size scans)
 *
 * Atomicity: lease / sweep / fail / complete all run as Lua scripts so
 * the inflight-zset / ready-zset / job-hash mutations land in a single
 * Redis op without a window for concurrent consumers to double-lease
 * or for sweep to race a complete.
 *
 * Field-crypto integration: payload + lastError seal/unseal go through
 * cryptoField.sealRow("_blamejs_jobs", row) and unsealRow(...) — the
 * SAME crypto-field config the local backend uses, keyed by the
 * "_blamejs_jobs" table name. Operators configuring sealedFields on the
 * jobs table get the same protection on Redis as on SQLite.
 *
 * Cron-repeat: handled at complete()-time in JS (not Lua) — re-enqueues
 * the next firing as a fresh jobId with availableAt = next-cron-fire.
 *
 * Out of scope (defer to follow-up patches):
 *   - Redis Cluster (slot-routing across multi-node Redis)
 *   - Sentinel (managed primary failover)
 */
var C = require("./constants");
var cryptoField = require("./crypto-field");
var { generateToken } = require("./crypto");
var lazyRequire = require("./lazy-require");
var redisClient = require("./redis-client");
var safeJson = require("./safe-json");
var scheduler = require("./scheduler");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-redis → vault → db → audit) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

var DEFAULT_PREFIX = "blamejs:queue";

// ---- Lua scripts ----
//
// LEASE_LUA — atomically pull up to maxRows jobs from the ready zset
// whose availableAt is <= nowMs, move them to the inflight zset with
// score = leaseExpiresAt, increment attempts, flip status, and return
// the jobIds in priority order. The JS side then HGETALLs each id.
//
// Priority semantics — matches queue-local's `ORDER BY priority DESC,
// availableAt ASC, enqueuedAt ASC` over the same `WHERE availableAt
// <= nowMs` filter. The Redis ZSET orders by availableAt only (the
// score), which is enough to filter "ready vs not-yet-ready" via
// ZRANGEBYSCORE 0..nowMs but NOT enough to surface a high-priority
// job ahead of an earlier-availableAt low-priority job. So we
// over-fetch maxRows*5 candidates by score, HMGET the priority +
// availableAt for each, sort priority-DESC / availableAt-ASC server-
// side in Lua, and lease the top maxRows. The over-fetch factor is
// chosen so a queue with a typical priority distribution surfaces
// the right jobs without scanning the entire ready set; queues with
// >5x as many priority-0 jobs as priority-N jobs would still pull
// the top-priority ones first.
//
// KEYS[1] = ready zset
// KEYS[2] = inflight zset
// ARGV[1] = nowMs
// ARGV[2] = leaseExpiresAt
// ARGV[3] = maxRows
// ARGV[4] = job-key prefix (e.g. "blamejs:queue:job:")
var LEASE_LUA = [
  'local readyKey = KEYS[1]',
  'local inflightKey = KEYS[2]',
  'local nowMs = tonumber(ARGV[1])',
  'local leaseExpiresAt = tonumber(ARGV[2])',
  'local maxRows = tonumber(ARGV[3])',
  'local jobKeyPrefix = ARGV[4]',
  'local oversample = maxRows * 5',
  'local jobIds = redis.call("ZRANGEBYSCORE", readyKey, 0, nowMs, "LIMIT", 0, oversample)',
  'if #jobIds == 0 then return {} end',
  // Pull priority + availableAt + enqueuedAt for each candidate so the
  // sort uses the same triple queue-local sorts on. enqueuedAt is the
  // tiebreaker among same-priority same-availableAt jobs (FIFO within
  // a priority lane).
  'local rows = {}',
  'for i = 1, #jobIds do',
  '  local jobId = jobIds[i]',
  '  local h = redis.call("HMGET", jobKeyPrefix..jobId, "priority", "availableAt", "enqueuedAt")',
  '  rows[i] = { jobId, tonumber(h[1] or "0") or 0, tonumber(h[2] or "0") or 0, tonumber(h[3] or "0") or 0 }',
  'end',
  // priority DESC, availableAt ASC, enqueuedAt ASC.
  'table.sort(rows, function(a, b)',
  '  if a[2] ~= b[2] then return a[2] > b[2] end',
  '  if a[3] ~= b[3] then return a[3] < b[3] end',
  '  return a[4] < b[4]',
  'end)',
  'local picked = {}',
  'local n = math.min(maxRows, #rows)',
  'for i = 1, n do',
  '  local jobId = rows[i][1]',
  '  redis.call("ZREM", readyKey, jobId)',
  '  redis.call("ZADD", inflightKey, leaseExpiresAt, jobId)',
  '  redis.call("HINCRBY", jobKeyPrefix..jobId, "attempts", 1)',
  '  redis.call("HSET", jobKeyPrefix..jobId,',
  '             "status", "inflight",',
  '             "leasedAt", nowMs,',
  '             "leaseExpiresAt", leaseExpiresAt)',
  '  picked[i] = jobId',
  'end',
  'return picked',
].join("\n");

// SWEEP_LUA — find jobs in inflight whose lease expired, push back to
// ready with score=nowMs (so they're immediately leasable again).
//
// KEYS[1] = inflight zset
// KEYS[2] = ready zset
// ARGV[1] = nowMs
// ARGV[2] = job-key prefix
var SWEEP_LUA = [
  'local inflightKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local nowMs = tonumber(ARGV[1])',
  'local jobKeyPrefix = ARGV[2]',
  'local expired = redis.call("ZRANGEBYSCORE", inflightKey, 0, nowMs)',
  'local count = 0',
  'for i = 1, #expired do',
  '  local jobId = expired[i]',
  '  redis.call("ZREM", inflightKey, jobId)',
  '  redis.call("ZADD", readyKey, nowMs, jobId)',
  '  redis.call("HSET", jobKeyPrefix..jobId, "status", "pending", "leaseExpiresAt", "")',
  '  count = count + 1',
  'end',
  'return count',
].join("\n");

// COMPLETE_LUA — atomically remove from inflight zset, flip status to
// done, set finishedAt. Returns 1 if the job was inflight, 0 otherwise.
//
// Lease fencing: ARGV[3] is the caller's leased `attempts` value (the
// inflight `attempts` at the time it leased), or "" to skip the check.
// `attempts` is HINCRBY'd once per lease, so it uniquely identifies a
// lease generation. If the stored attempts no longer matches, the caller
// no longer owns the lease — its lease expired, was swept, and the job was
// re-leased to another worker (whose lease incremented attempts) — so a
// late completion from the stale holder returns 0 without marking the
// in-progress job done. (The ZREM-removed gate alone can't catch this: the
// inflight member is just the jobId, present again under the new lease.)
//
// KEYS[1] = inflight zset
// KEYS[2] = job hash key
// ARGV[1] = jobId (member to ZREM)
// ARGV[2] = nowMs
// ARGV[3] = expected leased attempts ("" = no fence)
var COMPLETE_LUA = [
  'local inflightKey = KEYS[1]',
  'local jobKey = KEYS[2]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local fenceAttempt = ARGV[3]',
  'if fenceAttempt ~= "" then',
  '  local cur = redis.call("HGET", jobKey, "attempts")',
  '  if cur == false or tostring(cur) ~= fenceAttempt then return 0 end',
  'end',
  'local removed = redis.call("ZREM", inflightKey, jobId)',
  'if removed == 1 then',
  '  redis.call("HSET", jobKey, "status", "done", "finishedAt", nowMs, "leaseExpiresAt", "")',
  'end',
  'return removed',
].join("\n");

// FAIL_LUA — decide retry vs DLQ based on the row's current attempts
// vs maxAttempts (read from HASH for race-freedom). Gated on the job
// still being inflight (ZREM removed == 1): a stale fail() on a job that
// is no longer inflight returns -1 and mutates nothing. Retry: ZADD ready
// at score=nextAvailableAt, status=pending, return 0. DLQ: ZADD dlq at
// score=nowMs, status=failed, return 1.
//
// KEYS[1] = inflight zset
// KEYS[2] = ready zset
// KEYS[3] = dlq zset
// KEYS[4] = job hash key
// ARGV[1] = jobId
// ARGV[2] = nowMs
// ARGV[3] = sealedErr (string; "" if no error)
// ARGV[4] = nextAvailableAt
// ARGV[5] = expected leased attempts ("" = no fence) — see COMPLETE_LUA
var FAIL_LUA = [
  'local inflightKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local dlqKey = KEYS[3]',
  'local jobKey = KEYS[4]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local sealedErr = ARGV[3]',
  'local nextAvailableAt = tonumber(ARGV[4])',
  'local fenceAttempt = ARGV[5]',
  'local attempts = tonumber(redis.call("HGET", jobKey, "attempts")) or 0',
  'local maxAttempts = tonumber(redis.call("HGET", jobKey, "maxAttempts")) or 5',
  // Lease fencing: a stale fail() from a worker whose lease expired and whose
  // job was re-leased to another worker (which incremented attempts) must not
  // re-queue or DLQ the job the new worker is still running. If the stored
  // attempts no longer matches the caller's leased attempts, return -1 and
  // mutate nothing — same fence as COMPLETE_LUA.
  'if fenceAttempt ~= "" and tostring(attempts) ~= fenceAttempt then return -1 end',
  // Lease-ownership guard: only act if THIS call removed the job from inflight.
  // A stale fail() — the worker's lease expired, sweepExpired re-queued the job,
  // and another worker completed it — must not re-queue a job that is no longer
  // inflight (it would resurrect a completed job for re-execution). Mirrors
  // queue-local fail()'s `WHERE status='inflight'` guard. Returns -1 so the
  // caller can report "did not act" rather than a retry/dlq outcome.
  'local removed = redis.call("ZREM", inflightKey, jobId)',
  'if removed ~= 1 then return -1 end',
  'if sealedErr ~= "" then redis.call("HSET", jobKey, "lastError", sealedErr) end',
  'redis.call("HSET", jobKey, "leaseExpiresAt", "")',
  'if attempts < maxAttempts then',
  '  redis.call("HSET", jobKey, "status", "pending", "availableAt", nextAvailableAt)',
  '  redis.call("ZADD", readyKey, nextAvailableAt, jobId)',
  '  return 0',  // retried
  'else',
  '  redis.call("HSET", jobKey, "status", "failed", "finishedAt", nowMs, "availableAt", "")',
  '  redis.call("ZADD", dlqKey, nowMs, jobId)',
  '  return 1',  // landed in dlq
  'end',
].join("\n");

// EXTEND_LUA — push leaseExpiresAt forward iff the job is still inflight
// AND the caller still owns the lease. ARGV[3] is the caller's leased
// attempts ("" = no fence); a stale extend from a worker whose job was
// re-leased (attempts moved on) returns 0 without touching the new
// holder's lease — same fence as COMPLETE_LUA. Note `attempts` is not
// changed by an extend, so a worker can extend its own lease repeatedly.
//
// KEYS[1] = inflight zset
// KEYS[2] = job hash key
// ARGV[1] = jobId
// ARGV[2] = newExpiry
// ARGV[3] = expected leased attempts ("" = no fence)
var EXTEND_LUA = [
  'local inflightKey = KEYS[1]',
  'local jobKey = KEYS[2]',
  'local jobId = ARGV[1]',
  'local newExpiry = tonumber(ARGV[2])',
  'local fenceAttempt = ARGV[3]',
  'local score = redis.call("ZSCORE", inflightKey, jobId)',
  'if score == false then return 0 end',
  'if fenceAttempt ~= "" then',
  '  local cur = redis.call("HGET", jobKey, "attempts")',
  '  if cur == false or tostring(cur) ~= fenceAttempt then return 0 end',
  'end',
  'redis.call("ZADD", inflightKey, newExpiry, jobId)',
  'redis.call("HSET", jobKey, "leaseExpiresAt", newExpiry)',
  'return 1',
].join("\n");

// DLQ_RETRY_LUA — pull a job out of dlq, reset attempts, ZADD ready.
//
// KEYS[1] = dlq zset
// KEYS[2] = ready zset
// KEYS[3] = job hash key
// ARGV[1] = jobId
// ARGV[2] = nowMs
var DLQ_RETRY_LUA = [
  'local dlqKey = KEYS[1]',
  'local readyKey = KEYS[2]',
  'local jobKey = KEYS[3]',
  'local jobId = ARGV[1]',
  'local nowMs = tonumber(ARGV[2])',
  'local removed = redis.call("ZREM", dlqKey, jobId)',
  'if removed == 0 then return 0 end',
  'redis.call("HSET", jobKey,',
  '           "status", "pending",',
  '           "attempts", 0,',
  '           "availableAt", nowMs,',
  '           "lastError", "",',
  '           "finishedAt", "",',
  '           "leasedAt", "",',
  '           "leaseExpiresAt", "")',
  'redis.call("ZADD", readyKey, nowMs, jobId)',
  'return 1',
].join("\n");

// ---- Adapter ----

function create(opts) {
  opts = opts || {};
  if (typeof opts.url !== "string" || opts.url.length === 0) {
    throw _err("INVALID_CONFIG",
      "queue-redis: opts.url is required (e.g. redis://localhost:6379/0)", true);
  }
  var prefix = typeof opts.keyPrefix === "string" && opts.keyPrefix.length > 0
                    ? opts.keyPrefix : DEFAULT_PREFIX;

  var client = redisClient.create(redisClient.pickClientOpts(opts));

  // Lazy connect — defer first connect until the first operation so
  // queue.init({ backends }) doesn't have to be async.
  var connectPromise = null;
  function _ensureConnected() {
    if (client.isOpen()) return Promise.resolve();
    if (!connectPromise) connectPromise = client.connect();
    return connectPromise;
  }

  // ---- Key helpers ----
  function _jobKey(jobId)         { return prefix + ":job:" + jobId; }
  function _readyKey(queueName)   { return prefix + ":q:" + queueName + ":ready"; }
  function _inflightKey(queueName){ return prefix + ":q:" + queueName + ":inflight"; }
  function _dlqKey(queueName)     { return prefix + ":q:" + queueName + ":dlq"; }
  function _queuesKey()           { return prefix + ":queues"; }
  function _jobKeyPrefix()        { return prefix + ":job:"; }
  function _flowKey(flowId)       { return prefix + ":flow:" + flowId; }

  // ---- Row encoding ----
  //
  // Redis HSET fields are flat string-or-binary. Encode a JS object
  // into HSET-friendly args while preserving null/undefined as missing
  // (HDEL on update; never sent on insert) and boolean/number/buffer
  // as their natural string form.
  function _hsetArgs(jobId, fieldsObj) {
    var args = ["HSET", _jobKey(jobId)];
    Object.keys(fieldsObj).forEach(function (k) {
      var v = fieldsObj[k];
      if (v === null || v === undefined) return;     // skip
      args.push(k);
      if (Buffer.isBuffer(v))      args.push(v);
      else if (v === true || v === false) args.push(v ? "1" : "0");
      else                          args.push(String(v));
    });
    return args;
  }

  // Decode an HGETALL reply (alternating field/value Buffers) into a
  // plain object with Buffer/string values as appropriate. Returns
  // null when the hash didn't exist (HGETALL on missing key returns []).
  function _decodeHash(hashArr) {
    if (!hashArr || hashArr.length === 0) return null;
    var out = {};
    for (var i = 0; i + 1 < hashArr.length; i += 2) {
      var k = Buffer.isBuffer(hashArr[i]) ? hashArr[i].toString("utf8") : String(hashArr[i]);
      out[k] = Buffer.isBuffer(hashArr[i + 1]) ? hashArr[i + 1].toString("utf8") : hashArr[i + 1];
    }
    return out;
  }

  // Shape a leased row into the same { jobId, queueName, payload, ... }
  // contract queue-local returns from _shapeLeasedRow.
  function _shapeLeasedRow(jobId, raw) {
    if (!raw) return null;
    // The cryptoField seal-table registry KEY (matches db.js's registerTable
    // literal), not a SQL table name; this adapter holds no SQL (Redis
    // ZSET/HASH ops). Keep it byte-identical so payload + lastError unseal.
    // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
    var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
    return {
      jobId:          jobId,
      queueName:      unsealed.queueName,
      payload:        unsealed.payload ? safeJson.parse(unsealed.payload) : null,
      attempts:       Number(unsealed.attempts),
      maxAttempts:    Number(unsealed.maxAttempts),
      traceId:        unsealed.traceId || null,
      classification: unsealed.classification || null,
      enqueuedAt:     Number(unsealed.enqueuedAt),
      leaseExpiresAt: Number(unsealed.leaseExpiresAt),
      repeatCron:     unsealed.repeatCron     || null,
      repeatTimezone: unsealed.repeatTimezone || null,
      flowId:         unsealed.flowId         || null,
      flowChildName:  unsealed.flowChildName  || null,
    };
  }

  // ---- Public adapter ops ----

  async function enqueue(queueName, payload, opts2) {
    await _ensureConnected();
    opts2 = opts2 || {};
    var nowMs = Date.now();
    // Same SCHEDULING PRECEDENCE rule as queue-local: opts.availableAt
    // wins when finite; relative form is shorthand only.
    var availableAt;
    if (typeof opts2.availableAt === "number" && isFinite(opts2.availableAt)) {
      availableAt = opts2.availableAt;
    } else {
      availableAt = nowMs + (opts2.delaySeconds ? C.TIME.seconds(opts2.delaySeconds) : 0);
    }
    var jobId = generateToken(C.BYTES.bytes(16));
    var row = {
      _id:             jobId,
      queueName:       queueName,
      payload:         payload === undefined ? null : JSON.stringify(payload),
      status:          "pending",
      enqueuedAt:      nowMs,
      availableAt:     availableAt,
      attempts:        0,
      maxAttempts:     opts2.maxAttempts != null ? opts2.maxAttempts : 5,
      lastError:       null,
      finishedAt:      null,
      traceId:         opts2.traceId || null,
      classification:  opts2.classification || null,
      priority:        (typeof opts2.priority === "number" && isFinite(opts2.priority))
                          ? Math.floor(opts2.priority) : 0,
      repeatCron:      opts2.repeat && typeof opts2.repeat.cron === "string"
                          ? opts2.repeat.cron : null,
      repeatTimezone:  opts2.repeat && typeof opts2.repeat.timezone === "string"
                          ? opts2.repeat.timezone : null,
      flowId:          typeof opts2.flowId === "string" ? opts2.flowId : null,
      flowChildName:   typeof opts2.flowChildName === "string" ? opts2.flowChildName : null,
      dependsOn:       Array.isArray(opts2.dependsOn) && opts2.dependsOn.length > 0
                          ? JSON.stringify(opts2.dependsOn) : null,
    };
    // cryptoField seal-table registry KEY (db.js registers payload + lastError
    // under this literal), not a SQL table; this Redis adapter holds no SQL.
    // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
    var sealed = cryptoField.sealRow("_blamejs_jobs", row);

    // Pipeline: HSET job + ZADD ready + SADD queues + (if flowId)
    // SADD flow set. Pipelined writes hit Redis without round-trips
    // between them. The flow set is the per-flow registry that
    // complete() walks to release dependents — it lets us avoid a
    // SCAN over every job hash when releasing children, matching the
    // queue-local pattern of "SELECT siblings WHERE flowId = ?".
    var hsetArgs = _hsetArgs(jobId, sealed);
    var pipeline = [
      client.command.apply(null, hsetArgs),
      client.command("ZADD", _readyKey(queueName), String(availableAt), jobId),
      client.command("SADD", _queuesKey(), queueName),
    ];
    if (row.flowId) {
      pipeline.push(client.command("SADD", _flowKey(row.flowId), jobId));
    }
    await Promise.all(pipeline);

    return {
      jobId:          jobId,
      queueName:      queueName,
      enqueuedAt:     nowMs,
      availableAt:    availableAt,
      classification: row.classification,
    };
  }

  async function lease(queueName, leaseMs, count) {
    await _ensureConnected();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;

    var jobIdsRaw = await client.runScript(
      LEASE_LUA, 2,
      _readyKey(queueName), _inflightKey(queueName),
      String(nowMs), String(leaseExpiresAt), String(maxRows), _jobKeyPrefix()
    );
    if (!jobIdsRaw || jobIdsRaw.length === 0) return [];

    var jobIds = jobIdsRaw.map(function (x) {
      return Buffer.isBuffer(x) ? x.toString("utf8") : String(x);
    });

    // Fetch each job's full record. Pipelined HGETALLs.
    var hashes = await Promise.all(jobIds.map(function (id) {
      return client.command("HGETALL", _jobKey(id));
    }));
    var leased = [];
    for (var i = 0; i < jobIds.length; i++) {
      var raw = _decodeHash(hashes[i]);
      var shaped = _shapeLeasedRow(jobIds[i], raw);
      if (shaped) leased.push(shaped);
    }
    return leased;
  }

  async function extendLease(jobId, additionalMs, opts) {
    await _ensureConnected();
    if (typeof additionalMs !== "number" || additionalMs <= 0) {
      throw _err("INVALID_LEASE_EXTENSION",
        "extendLease: additionalMs must be a positive number", true);
    }
    var fence = (opts && opts.attempt != null) ? String(opts.attempt) : "";
    var newExpiry = Date.now() + additionalMs;
    // We don't know which queue the job belongs to without a HGET, so
    // fetch queueName first (avoids storing inflight by queue, which
    // would otherwise need a global secondary index).
    var qBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (qBuf === null || qBuf === undefined) return false;
    var queueName = Buffer.isBuffer(qBuf) ? qBuf.toString("utf8") : String(qBuf);
    var rv = await client.runScript(
      EXTEND_LUA, 2,
      _inflightKey(queueName), _jobKey(jobId),
      jobId, String(newExpiry), fence
    );
    return rv === 1;
  }

  async function complete(jobId, opts) {
    await _ensureConnected();
    var nowMs = Date.now();
    var fence = (opts && opts.attempt != null) ? String(opts.attempt) : "";
    // Read row first to act on cron-repeat metadata. Same shape as
    // queue-local: SELECT row → flip status → if repeatCron, enqueue
    // next firing.
    var rawArr = await client.command("HGETALL", _jobKey(jobId));
    var raw = _decodeHash(rawArr);
    if (!raw) return false;
    var queueName = raw.queueName || "unknown";

    var removed = await client.runScript(
      COMPLETE_LUA, 2,
      _inflightKey(queueName), _jobKey(jobId),
      jobId, String(nowMs), fence
    );
    // Only the completer that won the inflight->done transition (removed === 1)
    // runs the post-completion side effects. If the ZREM matched nothing the
    // job was already completed, or its lease expired and sweepExpired re-queued
    // it (possibly re-leased to another worker) — a stale completer must NOT
    // re-enqueue the cron repeat (duplicate firing) or release flow children
    // twice. Mirrors queue-local's `WHERE status='inflight'` rowcount guard.
    if (Number(removed) !== 1) return false;

    if (raw.repeatCron) {
      try {
        // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
        var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
        var cron = scheduler.parseCron(unsealed.repeatCron);
        var nextMs = scheduler.nextCronFire(
          cron, new Date(nowMs), unsealed.repeatTimezone || null);
        await enqueue(unsealed.queueName,
          unsealed.payload ? safeJson.parse(unsealed.payload) : null,
          {
            availableAt:     nextMs,
            repeat:          { cron: unsealed.repeatCron, timezone: unsealed.repeatTimezone },
            priority:        Number(unsealed.priority) || 0,
            classification:  unsealed.classification || null,
            traceId:         unsealed.traceId || null,
          });
      } catch (_e) { /* best-effort — cron resumes next tick if op fixes the issue */ }
    }

    // Flow propagation: walk siblings whose dependsOn includes this
    // jobId (or this job's flowChildName) and bump availableAt to now
    // if ALL their deps are now complete. Mirrors queue-local's
    // _maybeReleaseFlowChildren, but uses a per-flow Redis SET as
    // the sibling registry instead of a SQL SELECT.
    if (raw.flowId) {
      try {
        await _maybeReleaseFlowChildren(raw.flowId, jobId, raw.flowChildName || null, nowMs);
      } catch (_e) { /* best-effort — sweepExpired retries if a deps check fails */ }
      // The completed job stays in the flow set so a LATER sibling
      // whose dependsOn includes this job's flowChildName can still
      // find a "done" sibling when its own complete() walks the flow.
      // The set is purge()'d when the queue is purged or — for the
      // typical case where the operator wants to reclaim flow memory
      // after the whole flow finishes — by an explicit operator call
      // to purge() OR by letting `_maybeReleaseFlowChildren` reach a
      // state where every sibling has status='done' (which the
      // operator can detect via b.queue.dlqList / app-level queries).
    }
    return true;
  }

  async function _maybeReleaseFlowChildren(flowId, completedJobId, completedChildName, nowMs) {
    var flowKey = _flowKey(flowId);
    var members = await client.command("SMEMBERS", flowKey);
    if (!members || members.length === 0) return;

    // Pull dependsOn + status + flowChildName for every sibling in one
    // pipelined batch — far cheaper than per-sibling HMGET round trips.
    var siblingIds = members.map(function (m) {
      return Buffer.isBuffer(m) ? m.toString("utf8") : String(m);
    }).filter(function (id) { return id !== completedJobId; });
    if (siblingIds.length === 0) return;

    var hmgetCalls = siblingIds.map(function (sibId) {
      return client.command("HMGET", _jobKey(sibId),
        "dependsOn", "status", "flowChildName");
    });
    var results = await Promise.all(hmgetCalls);

    // For each pending sibling with a dependsOn array, check if all
    // deps are satisfied (the just-completed job AND any prior
    // already-done sibling in the flow).
    for (var i = 0; i < siblingIds.length; i++) {
      var sibId = siblingIds[i];
      var rv = results[i];
      if (!rv || rv.length < 3) continue;
      var rawDeps  = rv[0] && (Buffer.isBuffer(rv[0]) ? rv[0].toString("utf8") : String(rv[0]));
      var status   = rv[1] && (Buffer.isBuffer(rv[1]) ? rv[1].toString("utf8") : String(rv[1]));
      if (!rawDeps || status !== "pending") continue;
      var deps;
      try { deps = safeJson.parse(rawDeps, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { continue; }
      if (!Array.isArray(deps) || deps.length === 0) continue;

      // Resolve each dep against the just-completed job (id or child
      // name) OR a prior-completed sibling in the flow.
      var allDone = true;
      for (var d = 0; d < deps.length; d++) {
        var dep = deps[d];
        if (dep === completedJobId) continue;
        if (completedChildName && dep === completedChildName) continue;
        // Look up by id first; if no hit, fall back to scanning the
        // flow set for a sibling whose flowChildName matches.
        var depHash = await client.command("HMGET", _jobKey(dep), "status", "flowId");
        if (depHash && depHash[0]) {
          var depStatus = Buffer.isBuffer(depHash[0]) ? depHash[0].toString("utf8") : String(depHash[0]);
          var depFlow   = depHash[1] ? (Buffer.isBuffer(depHash[1]) ? depHash[1].toString("utf8") : String(depHash[1])) : "";
          if (depStatus === "done" && depFlow === flowId) continue;
        }
        // Scan the flow's set for a child-name match — cheap because
        // a flow typically has 5-50 children, not thousands.
        var matched = false;
        for (var s = 0; s < siblingIds.length && !matched; s++) {
          if (siblingIds[s] === sibId) continue;
          var sRv = results[s];
          if (!sRv || !sRv[2]) continue;
          var sName = Buffer.isBuffer(sRv[2]) ? sRv[2].toString("utf8") : String(sRv[2]);
          var sStatus = sRv[1] ? (Buffer.isBuffer(sRv[1]) ? sRv[1].toString("utf8") : String(sRv[1])) : "";
          if (sName === dep && sStatus === "done") matched = true;
        }
        if (!matched) { allDone = false; break; }
      }

      if (allDone) {
        // Read queueName so the ZADD targets the right ready zset.
        var qBuf = await client.command("HGET", _jobKey(sibId), "queueName");
        if (!qBuf) continue;
        var queueName = Buffer.isBuffer(qBuf) ? qBuf.toString("utf8") : String(qBuf);
        await Promise.all([
          client.command("HSET", _jobKey(sibId), "availableAt", String(nowMs)),
          client.command("ZADD", _readyKey(queueName), String(nowMs), sibId),
        ]);
      }
    }
  }

  async function fail(jobId, errorMessage, retryDelayMs) {
    await _ensureConnected();
    var nowMs = Date.now();
    // b.queue.consume passes the object form `{ retryDelayMs, attempt }`
    // (matching the queue-local backend); accept it as well as a bare-number
    // third arg. Without this the object failed the `typeof === "number"` test
    // below and the delay was forced to 0, so the documented exponential
    // backoff was silently discarded and a failing job re-leased
    // immediately on the redis backend (retry storm). `attempt` is the
    // caller's leased attempts value, used to fence a stale fail() (see
    // FAIL_LUA).
    var fence = "";
    if (retryDelayMs && typeof retryDelayMs === "object") {
      if (retryDelayMs.attempt != null) fence = String(retryDelayMs.attempt);
      retryDelayMs = retryDelayMs.retryDelayMs;
    }
    if (typeof retryDelayMs !== "number" || !isFinite(retryDelayMs) || retryDelayMs < 0) {
      retryDelayMs = 0;
    }
    var nextAvailableAt = nowMs + retryDelayMs;

    var queueBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (queueBuf === null || queueBuf === undefined) return false;
    var queueName = Buffer.isBuffer(queueBuf) ? queueBuf.toString("utf8") : String(queueBuf);

    var sealedErr = errorMessage ? vault().seal(String(errorMessage)) : "";

    var rv = await client.runScript(
      FAIL_LUA, 4,
      _inflightKey(queueName), _readyKey(queueName), _dlqKey(queueName), _jobKey(jobId),
      jobId, String(nowMs), sealedErr, String(nextAvailableAt), fence
    );
    // -1 = stale fail() on a job no longer inflight (already completed or
    // re-leased) — it did not retry or DLQ. 0 = retried, 1 = landed in dlq.
    // Mirrors queue-local fail()'s `rowCount > 0`.
    return Number(rv) !== -1;
  }

  async function sweepExpired() {
    await _ensureConnected();
    // Walk every known queue; the queues SET keeps the list current
    // (enqueue SADDs the name).
    var qs = await client.command("SMEMBERS", _queuesKey());
    if (!qs || qs.length === 0) return 0;
    var nowMs = Date.now();
    var totals = await Promise.all(qs.map(function (qBuf) {
      var queueName = Buffer.isBuffer(qBuf) ? qBuf.toString("utf8") : String(qBuf);
      return client.runScript(
        SWEEP_LUA, 2,
        _inflightKey(queueName), _readyKey(queueName),
        String(nowMs), _jobKeyPrefix());
    }));
    return totals.reduce(function (acc, n) { return acc + Number(n || 0); }, 0);
  }

  async function size(queueName) {
    await _ensureConnected();
    var [r, i] = await Promise.all([
      client.command("ZCARD", _readyKey(queueName)),
      client.command("ZCARD", _inflightKey(queueName)),
    ]);
    return Number(r || 0) + Number(i || 0);
  }

  async function purge(queueName) {
    await _ensureConnected();
    // Walk the ready + inflight + dlq zsets, collect every job id,
    // also clear each job from its flow set (if any), then DEL the
    // job hashes + zsets + queues-membership. Flow sets are cleared
    // job-by-job because a single flow can span multiple queues, and
    // we only want to evict THIS queue's contributors.
    var [readyMembers, inflightMembers, dlqMembers] = await Promise.all([
      client.command("ZRANGE", _readyKey(queueName),    "0", "-1"),
      client.command("ZRANGE", _inflightKey(queueName), "0", "-1"),
      client.command("ZRANGE", _dlqKey(queueName),      "0", "-1"),
    ]);
    var allIds = [].concat(readyMembers || [], inflightMembers || [], dlqMembers || [])
      .map(function (b) { return Buffer.isBuffer(b) ? b.toString("utf8") : String(b); });
    // Pull the flowId for each job (if set) so we can SREM from the
    // matching flow set BEFORE we DEL the job hash.
    var flowIdLookups = await Promise.all(allIds.map(function (id) {
      return client.command("HGET", _jobKey(id), "flowId");
    }));
    var flowSrems = [];
    for (var fi = 0; fi < allIds.length; fi++) {
      var fIdBuf = flowIdLookups[fi];
      if (!fIdBuf) continue;
      var fId = Buffer.isBuffer(fIdBuf) ? fIdBuf.toString("utf8") : String(fIdBuf);
      if (fId) flowSrems.push(client.command("SREM", _flowKey(fId), allIds[fi]));
    }
    var dels = allIds.map(function (id) { return client.command("DEL", _jobKey(id)); });
    var zdrops = [
      client.command("DEL", _readyKey(queueName)),
      client.command("DEL", _inflightKey(queueName)),
      client.command("DEL", _dlqKey(queueName)),
      client.command("SREM", _queuesKey(), queueName),
    ];
    await Promise.all(flowSrems.concat(dels, zdrops));
    return allIds.length;
  }

  async function dlqList(queueName, opts2) {
    await _ensureConnected();
    opts2 = opts2 || {};
    var limit = (typeof opts2.limit === "number" && opts2.limit > 0) ? opts2.limit : 100;
    // Newest failures first — score is finishedAtMs, so ZREVRANGE.
    var ids = await client.command(
      "ZREVRANGE", _dlqKey(queueName), "0", String(limit - 1));
    if (!ids || ids.length === 0) return [];
    var idStrs = ids.map(function (b) { return Buffer.isBuffer(b) ? b.toString("utf8") : String(b); });
    var hashes = await Promise.all(idStrs.map(function (id) {
      return client.command("HGETALL", _jobKey(id));
    }));
    var out = [];
    for (var i = 0; i < idStrs.length; i++) {
      var raw = _decodeHash(hashes[i]);
      if (!raw) continue;
      // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
      var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
      out.push({
        jobId:          idStrs[i],
        queueName:      unsealed.queueName,
        payload:        unsealed.payload ? safeJson.parse(unsealed.payload) : null,
        status:         unsealed.status,
        enqueuedAt:     Number(unsealed.enqueuedAt),
        finishedAt:     unsealed.finishedAt ? Number(unsealed.finishedAt) : null,
        attempts:       Number(unsealed.attempts),
        maxAttempts:    Number(unsealed.maxAttempts),
        lastError:      unsealed.lastError || null,
        traceId:        unsealed.traceId || null,
        classification: unsealed.classification || null,
      });
    }
    return out;
  }

  async function dlqRetry(jobId) {
    await _ensureConnected();
    var nowMs = Date.now();
    var queueBuf = await client.command("HGET", _jobKey(jobId), "queueName");
    if (queueBuf === null || queueBuf === undefined) return false;
    var queueName = Buffer.isBuffer(queueBuf) ? queueBuf.toString("utf8") : String(queueBuf);
    var rv = await client.runScript(
      DLQ_RETRY_LUA, 3,
      _dlqKey(queueName), _readyKey(queueName), _jobKey(jobId),
      jobId, String(nowMs)
    );
    return rv === 1;
  }

  async function dlqSize(queueName) {
    await _ensureConnected();
    var n = await client.command("ZCARD", _dlqKey(queueName));
    return Number(n || 0);
  }

  async function shutdown() {
    try { await client.close(); } catch (_e) { /* best effort */ }
  }

  return {
    protocol:     "redis",
    enqueue:      enqueue,
    lease:        lease,
    extendLease:  extendLease,
    complete:     complete,
    fail:         fail,
    sweepExpired: sweepExpired,
    size:         size,
    purge:        purge,
    dlqList:      dlqList,
    dlqRetry:     dlqRetry,
    dlqSize:      dlqSize,
    shutdown:     shutdown,
    // Diagnostic — exposed for tests + ops dashboards
    _client:      client,
    _prefix:      function () { return prefix; },
  };
}

module.exports = { create: create };
