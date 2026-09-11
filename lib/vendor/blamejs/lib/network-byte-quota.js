// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");
var boundedMap = require("./bounded-map");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var ByteQuotaError = defineClass("ByteQuotaError", { alwaysPermanent: true });

var BINS_PER_DAY = 24;
var BIN_MS = C.TIME.hours(1);
var ACCOUNT_MAX_RETRIES = 6;

function _hourBin(nowMs) { return Math.floor(nowMs / BIN_MS); }
function _newEntry()    { return { bins: new Array(BINS_PER_DAY).fill(0), startHour: 0 }; }

function _slideAndSum(entry, nowHour) {
  if (entry.startHour === 0) entry.startHour = nowHour - (BINS_PER_DAY - 1);
  var advance = nowHour - (entry.startHour + (BINS_PER_DAY - 1));
  var moved = false;
  if (advance > 0) {
    moved = true;
    if (advance >= BINS_PER_DAY) {
      for (var i = 0; i < BINS_PER_DAY; i++) entry.bins[i] = 0;
    } else {
      for (var j = 0; j < BINS_PER_DAY - advance; j++) entry.bins[j] = entry.bins[j + advance];
      for (var k = BINS_PER_DAY - advance; k < BINS_PER_DAY; k++) entry.bins[k] = 0;
    }
    entry.startHour = nowHour - (BINS_PER_DAY - 1);
  }
  var total = 0;
  for (var t = 0; t < BINS_PER_DAY; t++) total += entry.bins[t];
  return { entry: entry, total: total, moved: moved };
}

function _memoryBackend() {
  var store = new Map();
  function _get(key) {
    return boundedMap.getOrInsert(store, key, function () { return _newEntry(); });
  }
  return {
    async total(key, nowMs) {
      return _slideAndSum(_get(key), _hourBin(nowMs)).total;
    },
    async account(key, bytes, nowMs) {
      var slid = _slideAndSum(_get(key), _hourBin(nowMs));
      slid.entry.bins[BINS_PER_DAY - 1] += bytes;
    },
    async reset(key) {
      store.delete(key);
    },
    async snapshot(nowMs) {
      var nowHour = _hourBin(nowMs);
      var out = [];
      for (var key of store.keys()) {
        var slid = _slideAndSum(_get(key), nowHour);
        out.push({ key: key, total: slid.total });
      }
      return out;
    },
    _resetForTest: function () { store.clear(); },
  };
}

function _cacheBackend(cache) {
  function _key(k) { return "byteQuota:" + k; }
  function _coerce(raw) {
    return raw && typeof raw === "object" && Array.isArray(raw.bins) ? raw : _newEntry();
  }
  return {
    async total(key, nowMs) {
      var slid = _slideAndSum(_coerce(await cache.get(_key(key))), _hourBin(nowMs));
      return slid.total;
    },
    async account(key, bytes, nowMs) {
      var nowHour = _hourBin(nowMs);
      for (var attempt = 0; ; attempt++) {
        try {
          await cache.update(_key(key), function (current) {
            var slid = _slideAndSum(_coerce(current), nowHour);
            slid.entry.bins[BINS_PER_DAY - 1] += bytes;
            return { value: slid.entry };
          }, { ttlMs: BIN_MS * BINS_PER_DAY });
          return;
        } catch (e) {
          if (e && e.code === "cache/update-contention" && attempt < ACCOUNT_MAX_RETRIES) continue;
          throw e;
        }
      }
    },
    async reset(key) {
      if (typeof cache.delete === "function") await cache.delete(_key(key));
      else if (typeof cache.del === "function") await cache.del(_key(key));
      else await cache.set(_key(key), _newEntry(), { ttlMs: 1 });
    },
    async snapshot(_nowMs) { return []; },
  };
}

function _requirePositiveBytes(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-quota",
      "network.byteQuota: " + name + " must be a positive finite number; " +
      "use b.constants.BYTES.gib(N) / mib(N) for readable values"
    );
  }
}

function _requireNonNegativeBytes(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-bytes",
      "network.byteQuota: " + name + " must be a non-negative finite number, got " + JSON.stringify(value)
    );
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-key",
      "network.byteQuota: key must be a non-empty string, got " + JSON.stringify(key)
    );
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["bytesPerDay", "cache", "audit", "now"], "network.byteQuota");
  _requirePositiveBytes("bytesPerDay", opts.bytesPerDay);
  var bytesPerDay = opts.bytesPerDay;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };
  var backend;
  if (opts.cache && typeof opts.cache.get === "function") {
    if (typeof opts.cache.update !== "function") {
      throw new ByteQuotaError(
        "byte-quota/cache-no-atomic-update",
        "network.byteQuota: a cache backing a byte quota must support atomic update() — " +
        "a plain get/set cache loses concurrent byte charges on the shared path; " +
        "use b.cache.create(...), which provides it"
      );
    }
    backend = _cacheBackend(opts.cache);
  } else {
    backend = _memoryBackend();
  }

  var _emitAudit = audit().namespaced("network.byte_quota", opts.audit);

  var _emitMetric = observability().namespaced("network.byte_quota");

  async function check(key, bytes) {
    _requireKey(key);
    _requireNonNegativeBytes("bytes", bytes);
    var nowMs = now();
    var total;
    try { total = await backend.total(key, nowMs); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "check", error: (e && e.message) || String(e) });
      return {
        allowed:   true,
        total:     0,
        remaining: bytesPerDay,
        quota:     bytesPerDay,
        retryAfterSec: 0,
        degraded:  true,
      };
    }
    var projected = total + bytes;
    var remaining = Math.max(0, bytesPerDay - total);
    if (projected > bytesPerDay) {
      _emitMetric("refused", 1, { reason: "quota-exceeded" });
      _emitAudit("exceeded", "denied", { key: key, total: total, requested: bytes, quota: bytesPerDay });
      return {
        allowed:   false,
        total:     total,
        remaining: remaining,
        quota:     bytesPerDay,
        retryAfterSec: Math.ceil(BIN_MS / C.TIME.seconds(1)),
        degraded:  false,
      };
    }
    return {
      allowed:   true,
      total:     total,
      remaining: Math.max(0, bytesPerDay - projected),
      quota:     bytesPerDay,
      retryAfterSec: 0,
      degraded:  false,
    };
  }

  async function record(key, bytes) {
    _requireKey(key);
    _requireNonNegativeBytes("bytes", bytes);
    if (bytes === 0) return;
    var nowMs = now();
    try { await backend.account(key, bytes, nowMs); }
    catch (e) {
      if (e && e.code === "cache/unsupported") {
        throw new ByteQuotaError(
          "byte-quota/cache-no-atomic-update",
          "network.byteQuota: the configured cache backend does not support atomic update() — " +
          "a byte quota cannot enforce on a get/set-only backend; use a cache whose backend " +
          "implements update (the memory or cluster backend)"
        );
      }
      _emitAudit("backend_error", "failure", { phase: "record", key: key, bytes: bytes, error: (e && e.message) || String(e) });
      // Drop-silent after the audit.
      return;
    }
    _emitMetric("recorded", bytes, {});
  }

  async function reset(key) {
    _requireKey(key);
    try { await backend.reset(key); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "reset", error: (e && e.message) || String(e) });
    }
  }

  async function snapshot() {
    var nowMs = now();
    try {
      var rows = await backend.snapshot(nowMs);
      return rows.map(function (r) {
        return {
          key:       r.key,
          total:     r.total,
          quota:     bytesPerDay,
          remaining: Math.max(0, bytesPerDay - r.total),
        };
      });
    } catch (e) {
      _emitAudit("backend_error", "failure", { phase: "snapshot", error: (e && e.message) || String(e) });
      return [];
    }
  }

  return {
    check:    check,
    record:   record,
    reset:    reset,
    snapshot: snapshot,
    _backend: backend,
    _bytesPerDay: bytesPerDay,
    _now: now,
  };
}

module.exports = {
  create:           create,
  ByteQuotaError:   ByteQuotaError,
  BINS_PER_DAY:     BINS_PER_DAY,
  _memoryBackend:   _memoryBackend,
  _cacheBackend:    _cacheBackend,
  _slideAndSum:     _slideAndSum,
};
