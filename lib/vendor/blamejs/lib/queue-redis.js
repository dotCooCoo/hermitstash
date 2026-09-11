// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
  'local rows = {}',
  'for i = 1, #jobIds do',
  '  local jobId = jobIds[i]',
  '  local h = redis.call("HMGET", jobKeyPrefix..jobId, "priority", "availableAt", "enqueuedAt")',
  '  rows[i] = { jobId, tonumber(h[1] or "0") or 0, tonumber(h[2] or "0") or 0, tonumber(h[3] or "0") or 0 }',
  'end',
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
  'if fenceAttempt ~= "" and tostring(attempts) ~= fenceAttempt then return -1 end',
  'local removed = redis.call("ZREM", inflightKey, jobId)',
  'if removed ~= 1 then return -1 end',
  'if sealedErr ~= "" then redis.call("HSET", jobKey, "lastError", sealedErr) end',
  'redis.call("HSET", jobKey, "leaseExpiresAt", "")',
  'if attempts < maxAttempts then',
  '  redis.call("HSET", jobKey, "status", "pending", "availableAt", nextAvailableAt)',
  '  redis.call("ZADD", readyKey, nextAvailableAt, jobId)',
  '  return 0',
  'else',
  '  redis.call("HSET", jobKey, "status", "failed", "finishedAt", nowMs, "availableAt", "")',
  '  redis.call("ZADD", dlqKey, nowMs, jobId)',
  '  return 1',
  'end',
].join("\n");

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

function create(opts) {
  opts = opts || {};
  if (typeof opts.url !== "string" || opts.url.length === 0) {
    throw _err("queue-redis/invalid-config",
      "queue-redis: opts.url is required (e.g. redis://localhost:6379/0)", true);
  }
  var prefix = typeof opts.keyPrefix === "string" && opts.keyPrefix.length > 0
                    ? opts.keyPrefix : DEFAULT_PREFIX;

  var client = redisClient.create(redisClient.pickClientOpts(opts));

  var connectPromise = null;
  function _ensureConnected() {
    if (client.isOpen()) return Promise.resolve();
    if (!connectPromise) connectPromise = client.connect();
    return connectPromise;
  }

  function _jobKey(jobId)         { return prefix + ":job:" + jobId; }
  function _readyKey(queueName)   { return prefix + ":q:" + queueName + ":ready"; }
  function _inflightKey(queueName){ return prefix + ":q:" + queueName + ":inflight"; }
  function _dlqKey(queueName)     { return prefix + ":q:" + queueName + ":dlq"; }
  function _queuesKey()           { return prefix + ":queues"; }
  function _jobKeyPrefix()        { return prefix + ":job:"; }
  function _flowKey(flowId)       { return prefix + ":flow:" + flowId; }

  function _hsetArgs(jobId, fieldsObj) {
    var args = ["HSET", _jobKey(jobId)];
    Object.keys(fieldsObj).forEach(function (k) {
      var v = fieldsObj[k];
      if (v === null || v === undefined) return;
      args.push(k);
      if (Buffer.isBuffer(v))      args.push(v);
      else if (v === true || v === false) args.push(v ? "1" : "0");
      else                          args.push(String(v));
    });
    return args;
  }

  function _decodeHash(hashArr) {
    if (!hashArr || hashArr.length === 0) return null;
    var out = {};
    for (var i = 0; i + 1 < hashArr.length; i += 2) {
      var k = Buffer.isBuffer(hashArr[i]) ? hashArr[i].toString("utf8") : String(hashArr[i]);
      out[k] = Buffer.isBuffer(hashArr[i + 1]) ? hashArr[i + 1].toString("utf8") : hashArr[i + 1];
    }
    return out;
  }

  function _shapeLeasedRow(jobId, raw) {
    if (!raw) return null;
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

  async function enqueue(queueName, payload, opts2) {
    await _ensureConnected();
    opts2 = opts2 || {};
    var nowMs = Date.now();
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
    // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
    var sealed = cryptoField.sealRow("_blamejs_jobs", row);

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
      throw _err("queue-redis/invalid-lease-extension",
        "extendLease: additionalMs must be a positive number", true);
    }
    var fence = (opts && opts.attempt != null) ? String(opts.attempt) : "";
    var newExpiry = Date.now() + additionalMs;
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
    var rawArr = await client.command("HGETALL", _jobKey(jobId));
    var raw = _decodeHash(rawArr);
    if (!raw) return false;
    var queueName = raw.queueName || "unknown";

    var removed = await client.runScript(
      COMPLETE_LUA, 2,
      _inflightKey(queueName), _jobKey(jobId),
      jobId, String(nowMs), fence
    );
    if (Number(removed) !== 1) return false;

    if (raw.repeatCron) {
      try {
        // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
        var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
        var cron = scheduler.parseCron(unsealed.repeatCron);
        var nextMs = scheduler.nextCronFire(
          cron, new Date(nowMs), unsealed.repeatTimezone || null);
        var repeatMax = Number(unsealed.maxAttempts);
        await enqueue(unsealed.queueName,
          unsealed.payload ? safeJson.parse(unsealed.payload) : null,
          {
            availableAt:     nextMs,
            repeat:          { cron: unsealed.repeatCron, timezone: unsealed.repeatTimezone },
            priority:        Number(unsealed.priority) || 0,
            maxAttempts:     (isFinite(repeatMax) && repeatMax > 0) ? repeatMax : undefined,
            classification:  unsealed.classification || null,
            traceId:         unsealed.traceId || null,
          });
      } catch (_e) { /* best-effort — cron resumes next tick if op fixes the issue */ }
    }

    if (raw.flowId) {
      try {
        await _maybeReleaseFlowChildren(raw.flowId, jobId, raw.flowChildName || null, nowMs);
      } catch (_e) { /* best-effort — sweepExpired retries if a deps check fails */ }
    }
    return true;
  }

  async function _maybeReleaseFlowChildren(flowId, completedJobId, completedChildName, nowMs) {
    var flowKey = _flowKey(flowId);
    var members = await client.command("SMEMBERS", flowKey);
    if (!members || members.length === 0) return;

    var siblingIds = members.map(function (m) {
      return Buffer.isBuffer(m) ? m.toString("utf8") : String(m);
    }).filter(function (id) { return id !== completedJobId; });
    if (siblingIds.length === 0) return;

    var hmgetCalls = siblingIds.map(function (sibId) {
      return client.command("HMGET", _jobKey(sibId),
        "dependsOn", "status", "flowChildName");
    });
    var results = await Promise.all(hmgetCalls);

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

      var allDone = true;
      for (var d = 0; d < deps.length; d++) {
        var dep = deps[d];
        if (dep === completedJobId) continue;
        if (completedChildName && dep === completedChildName) continue;
        var depHash = await client.command("HMGET", _jobKey(dep), "status", "flowId");
        if (depHash && depHash[0]) {
          var depStatus = Buffer.isBuffer(depHash[0]) ? depHash[0].toString("utf8") : String(depHash[0]);
          var depFlow   = depHash[1] ? (Buffer.isBuffer(depHash[1]) ? depHash[1].toString("utf8") : String(depHash[1])) : "";
          if (depStatus === "done" && depFlow === flowId) continue;
        }
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
    return Number(rv) !== -1;
  }

  async function sweepExpired() {
    await _ensureConnected();
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
    var [readyMembers, inflightMembers, dlqMembers] = await Promise.all([
      client.command("ZRANGE", _readyKey(queueName),    "0", "-1"),
      client.command("ZRANGE", _inflightKey(queueName), "0", "-1"),
      client.command("ZRANGE", _dlqKey(queueName),      "0", "-1"),
    ]);
    var allIds = [].concat(readyMembers || [], inflightMembers || [], dlqMembers || [])
      .map(function (b) { return Buffer.isBuffer(b) ? b.toString("utf8") : String(b); });
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
    _client:      client,
    _prefix:      function () { return prefix; },
  };
}

module.exports = { create: create };
