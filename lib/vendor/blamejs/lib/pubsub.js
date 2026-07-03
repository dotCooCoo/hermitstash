// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.pubsub
 * @nav    Communication
 * @title  Pubsub
 *
 * @intro
 *   Cluster-aware pub/sub channel for in-process and cross-replica
 *   messaging. Three backends share one operator API:
 *
 *     local    — in-process `Map<channel, Set<handler>>`; publish
 *                dispatches synchronously before returning. Single-node
 *                deploys pay zero coordination overhead.
 *     cluster  — shared `_blamejs_pubsub_messages` table polled at
 *                `pollIntervalMs`; publish writes a row + dispatches
 *                locally; other nodes pick up rows via
 *                `id > lastSeenId AND publishedBy <> selfNodeId`. The
 *                default for any `b.cluster`-aware deploy.
 *     redis    — Redis PUB/SUB on `lib/redis-client.js`. One connection
 *                enters subscribe mode (demultiplexed via
 *                `setOnPushMessage`); publish goes through a separate
 *                command-mode connection.
 *
 *   Pattern subscribe accepts glob-style topic matchers (`*` matches one
 *   `.`-delimited segment, `**` matches any suffix). Channel names cap
 *   at 1 KiB to defeat pathological matcher inputs. Subscribe /
 *   unsubscribe is ref-counted across local handlers so the remote
 *   backend only carries one subscription per scoped channel.
 *
 *   Local dispatch always happens BEFORE `publish()` resolves regardless
 *   of backend — same-node subscribers see the payload with near-zero
 *   latency. Handler errors are caught and logged via the boot logger;
 *   they never abort dispatch to siblings. Bad-shape remote payloads
 *   drop silently after a logged warning so one malformed cross-node
 *   message can't poison the local handler chain.
 *
 * @card
 *   Cluster-aware pub/sub channel for in-process and cross-replica messaging.
 */
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var boundedMap = require("./bounded-map");
var { defineClass } = require("./framework-error");

var audit  = lazyRequire(function () { return require("./audit"); });
var logger = lazyRequire(function () { return require("./log").boot("pubsub"); });
// Backend dispatch — lazy so pubsub-cluster / pubsub-redis (which depend
// on this file's exports for their own framework integration) don't
// load-cycle on first import.
var pubsubCluster = lazyRequire(function () { return require("./pubsub-cluster"); });
var pubsubRedis   = lazyRequire(function () { return require("./pubsub-redis"); });

var PubsubError = defineClass("PubsubError");

function _err(code, message) { return new PubsubError(code, message, true); }

function _resolveBackend(opts) {
  var requested = opts.backend;
  if (requested && typeof requested === "object") {
    validateOpts.requireMethods(requested, ["publishRemote", "start", "stop"],
      "pubsub: custom backend", PubsubError, "BAD_BACKEND", true);
    return Object.assign({ name: "custom" }, requested);
  }
  if (!requested || requested === "local") {
    return { name: "local", publishRemote: null, start: null, stop: null };
  }
  if (requested === "cluster") {
    return pubsubCluster().create(opts);
  }
  if (requested === "redis") {
    return pubsubRedis().create(opts);
  }
  throw _err("UNKNOWN_BACKEND",
    "pubsub: unknown backend '" + requested +
    "' (must be 'local', 'cluster', 'redis', or { publishRemote, start, stop })");
}

// Glob-style: '*' matches any single segment (no '.'); '**' matches any
// suffix. Operators wanting full Redis-pattern semantics use the redis
// backend's PSUBSCRIBE which the redis client routes natively.
//
// Hand-rolled matcher (no `new RegExp` from operator input) so a hostile
// operator-supplied pattern can't compile a backtracking regex (ReDoS).
// Channel length is bounded to defeat pathological inputs even on
// well-behaved patterns; pubsub channel names in practice are well under
// 1 KiB and the framework's own callers never exceed it.
var _MAX_CHANNEL_LEN = C.BYTES.kib(1);

function _matchGlobPart(part, channel, fromIdx) {
  // Within one '**'-bounded part, match a sequence of '*'-separated
  // literals against channel[fromIdx..] WITHOUT crossing '.' boundaries.
  // Returns the matched length, or -1 on no match.
  var segments = part.split("*");
  var pos = fromIdx;
  for (var i = 0; i < segments.length; i++) {
    var lit = segments[i];
    if (i === 0) {
      if (channel.substr(pos, lit.length) !== lit) return -1;
      pos += lit.length;
    } else if (i === segments.length - 1) {
      // Trailing literal: search forward in this segment (no '.' jump).
      var hardStop = channel.indexOf(".", pos);
      var searchEnd = hardStop === -1 ? channel.length : hardStop;
      if (lit === "") { pos = searchEnd; break; }
      var found = channel.lastIndexOf(lit, searchEnd - lit.length);
      if (found < pos) return -1;
      pos = found + lit.length;
    } else {
      // Middle literal: find next occurrence within current segment.
      var hardStop2 = channel.indexOf(".", pos);
      var searchEnd2 = hardStop2 === -1 ? channel.length : hardStop2;
      var f2 = channel.indexOf(lit, pos);
      if (f2 < 0 || f2 + lit.length > searchEnd2) return -1;
      pos = f2 + lit.length;
    }
  }
  return pos - fromIdx;
}

function _matchPattern(pattern, channel) {
  if (pattern === channel) return true;
  if (typeof channel !== "string" || channel.length > _MAX_CHANNEL_LEN) return false;
  if (typeof pattern !== "string" || pattern.length > _MAX_CHANNEL_LEN) return false;
  if (pattern.indexOf("*") === -1) return false;
  // Split on '**' — each part is a glob that matches without crossing '.';
  // between parts any char (including '.') is consumed greedily.
  var parts = pattern.split("**");
  if (parts.length === 1) {
    // No '**'; pattern must consume the entire channel and only '*'
    // (single-segment) wildcards are allowed.
    var len = _matchGlobPart(parts[0], channel, 0);
    return len === channel.length;
  }
  // Anchor the head.
  var headLen = _matchGlobPart(parts[0], channel, 0);
  if (headLen < 0) return false;
  var idx = headLen;
  // Match middle parts: each must appear somewhere after idx, in order,
  // separated by arbitrary content (since '**' consumes anything).
  for (var p = 1; p < parts.length - 1; p++) {
    var found = -1;
    for (var probe = idx; probe <= channel.length; probe++) {
      var n = _matchGlobPart(parts[p], channel, probe);
      if (n >= 0) { found = probe + n; break; }
    }
    if (found < 0) return false;
    idx = found;
  }
  // Tail: must reach end of channel.
  var tail = parts[parts.length - 1];
  if (tail === "") return true;
  for (var t = idx; t <= channel.length; t++) {
    var tn = _matchGlobPart(tail, channel, t);
    if (tn >= 0 && t + tn === channel.length) return true;
  }
  return false;
}

/**
 * @primitive b.pubsub.create
 * @signature b.pubsub.create(opts)
 * @since     0.6.34
 * @status    stable
 * @related   b.cluster, b.websocketChannels
 *
 * Build a pub/sub instance bound to one of the supported backends.
 * Returned object exposes `subscribe(channel, handler)` /
 * `subscribePattern(pattern, handler)` for receive,
 * `unsubscribe(token)` for cleanup, `publish(channel, payload)` for
 * fan-out, and `close()` for teardown. Tokens returned by subscribe
 * are opaque records; pass them back to `unsubscribe` verbatim.
 *
 * Throws `PubsubError("UNKNOWN_BACKEND")` when `opts.backend` is not
 * one of `"local"`, `"cluster"`, `"redis"`, or a custom backend object
 * implementing `{ publishRemote, start, stop }`. Throws
 * `PubsubError("BAD_BACKEND")` when a custom backend object is missing
 * those methods.
 *
 * @opts
 *   backend:         "local" | "cluster" | "redis" | object  // default "local"
 *   cluster:         object,                                 // required for backend "cluster"
 *   pollIntervalMs:  number,                                 // cluster poll cadence; default 100ms
 *   retentionMs:     number,                                 // cluster row retention; default 60_000
 *   pruneEveryMs:    number,                                 // cluster prune cadence; default 300_000
 *   redisUrl:        string,                                 // required for backend "redis"
 *   redisPassword:   string,
 *   redisUsername:   string,
 *   redisTls:        boolean,
 *   redisCa:         string | Buffer,
 *   redisServername: string,
 *   topicPrefix:     string,                                 // scopes every channel as `<prefix>:<channel>`
 *   audit:           boolean,                                // default false; emit system.pubsub.publish
 *
 * @example
 *   var ps = b.pubsub.create({ backend: "local" });
 *
 *   var token = ps.subscribe("user.created", function (payload, ev) {
 *     console.log(ev.channel, ev.source, payload.id);
 *     // → user.created local 42
 *   });
 *
 *   await ps.publish("user.created", { id: 42 });
 *   ps.unsubscribe(token);
 *   await ps.close();
 *
 * @example
 *   // Glob-style topic matchers: '*' matches one segment, '**' any suffix.
 *   var ps = b.pubsub.create({ backend: "local" });
 *
 *   ps.subscribePattern("orders.*.created", function (payload, ev) {
 *     console.log(ev.channel);
 *     // → orders.eu.created
 *   });
 *
 *   ps.subscribePattern("audit.**", function (payload, ev) {
 *     console.log(ev.channel);
 *     // → audit.security.login.failed
 *   });
 *
 *   await ps.publish("orders.eu.created", { orderId: "ord_1" });
 *   await ps.publish("audit.security.login.failed", { userId: "u_7" });
 *   await ps.close();
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "backend", "cluster", "audit", "topicPrefix",
    "pollIntervalMs", "retentionMs", "pruneEveryMs",
    "redisUrl", "redisPassword", "redisUsername", "redisTls",
    "redisCa", "redisServername",
  ], "b.pubsub");

  var topicPrefix = opts.topicPrefix || "";
  var auditOn = !!opts.audit;
  var backend = _resolveBackend(opts);

  // channel -> Set<token-record>; token-record is { channel, handler, isPattern }.
  // Tokens are objects so unsubscribe is O(1) without hashing.
  var exactSubs   = new Map();
  var patternSubs = new Set();
  var closed      = false;

  function _scoped(channel) {
    return topicPrefix ? topicPrefix + ":" + channel : channel;
  }
  function _unscope(scopedChannel) {
    if (!topicPrefix) return scopedChannel;
    if (scopedChannel.indexOf(topicPrefix + ":") === 0) {
      return scopedChannel.slice(topicPrefix.length + 1);
    }
    return scopedChannel;
  }

  function _localDispatch(channel, payload, source, meta) {
    var ev = Object.assign({ channel: channel, source: source || "local" },
                            meta || {});
    var dispatched = 0;
    var exact = exactSubs.get(channel);
    if (exact) {
      for (var rec of exact) {
        try { rec.handler(payload, ev); dispatched++; }
        catch (e) {
          try { logger().warn("pubsub handler threw on '" + channel +
            "': " + ((e && e.message) || String(e))); }
          catch (_e) { /* logger best-effort */ }
        }
      }
    }
    for (var prec of patternSubs) {
      if (_matchPattern(prec.channel, channel)) {
        try { prec.handler(payload, ev); dispatched++; }
        catch (e) {
          try { logger().warn("pubsub pattern handler threw on '" +
            channel + "' (pattern '" + prec.channel + "'): " +
            ((e && e.message) || String(e))); }
          catch (_e) { /* logger best-effort */ }
        }
      }
    }
    return dispatched;
  }

  // Backend invokes this when a remote node's record arrives.
  function _onRemoteMessage(scopedChannel, rawPayload, meta) {
    var channel = _unscope(scopedChannel);
    var payload;
    try {
      payload = (typeof rawPayload === "string" ||
                 (rawPayload && Buffer.isBuffer(rawPayload)))
        ? safeJson.parse(Buffer.isBuffer(rawPayload)
                          ? rawPayload.toString("utf8")
                          : rawPayload)
        : rawPayload;
    } catch (e) {
      try { logger().warn("pubsub remote payload parse failed on '" +
        channel + "': " + ((e && e.message) || String(e))); }
      catch (_e) { /* */ }
      return;
    }
    _localDispatch(channel, payload, "remote", meta || {});
  }

  if (typeof backend.start === "function") {
    backend.start(_onRemoteMessage);
  }

  // Track which scoped channels we've subscribed remotely so we can
  // ref-count and unsubscribe when the last local handler goes away.
  var remoteSubCount = new Map();

  async function _maybeRemoteSubscribe(scopedChannel, isPattern) {
    var n = (remoteSubCount.get(scopedChannel) || 0) + 1;
    remoteSubCount.set(scopedChannel, n);
    if (n === 1 && typeof backend.subscribeRemote === "function") {
      try { await backend.subscribeRemote(scopedChannel, isPattern); }
      catch (e) {
        // Roll back the count so a retry isn't blocked by stale bookkeeping.
        remoteSubCount.set(scopedChannel, n - 1);
        throw e;
      }
    }
  }
  async function _maybeRemoteUnsubscribe(scopedChannel, isPattern) {
    var n = (remoteSubCount.get(scopedChannel) || 1) - 1;
    if (n <= 0) {
      remoteSubCount.delete(scopedChannel);
      if (typeof backend.unsubscribeRemote === "function") {
        try { await backend.unsubscribeRemote(scopedChannel, isPattern); }
        catch (_e) { /* unsubscribe failure is informational */ }
      }
    } else {
      remoteSubCount.set(scopedChannel, n);
    }
  }

  function subscribe(channel, handler) {
    if (closed) throw _err("CLOSED", "pubsub.subscribe: instance closed");
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("BAD_OPT", "pubsub.subscribe: channel must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw _err("BAD_OPT", "pubsub.subscribe: handler must be a function");
    }
    var rec = { channel: channel, handler: handler, isPattern: false };
    var set = boundedMap.getOrInsert(exactSubs, channel, function () { return new Set(); });
    set.add(rec);
    // Remote subscribe is fire-and-forget from the caller's perspective;
    // the redis backend awaits the SUBSCRIBE ack internally before its
    // promise resolves, so a sync subscribe() that returns the token
    // doesn't strand the operator if they immediately publish().
    _maybeRemoteSubscribe(_scoped(channel), false).catch(function (e) {
      try { logger().warn("pubsub subscribeRemote('" + channel + "') failed: " +
        ((e && e.message) || String(e))); }
      catch (_e) { /* */ }
    });
    return rec;
  }

  function subscribePattern(pattern, handler) {
    if (closed) throw _err("CLOSED", "pubsub.subscribePattern: instance closed");
    if (typeof pattern !== "string" || pattern.length === 0) {
      throw _err("BAD_OPT", "pubsub.subscribePattern: pattern must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw _err("BAD_OPT", "pubsub.subscribePattern: handler must be a function");
    }
    var rec = { channel: pattern, handler: handler, isPattern: true };
    patternSubs.add(rec);
    _maybeRemoteSubscribe(_scoped(pattern), true).catch(function (e) {
      try { logger().warn("pubsub subscribePatternRemote('" + pattern + "') failed: " +
        ((e && e.message) || String(e))); }
      catch (_e) { /* */ }
    });
    return rec;
  }

  function unsubscribe(token) {
    if (!token || typeof token !== "object") return;
    if (token.isPattern) {
      if (patternSubs.delete(token)) {
        _maybeRemoteUnsubscribe(_scoped(token.channel), true);
      }
      return;
    }
    var set = exactSubs.get(token.channel);
    if (set && set.delete(token)) {
      if (set.size === 0) exactSubs.delete(token.channel);
      _maybeRemoteUnsubscribe(_scoped(token.channel), false);
    }
  }

  async function publish(channel, payload) {
    if (closed) throw _err("CLOSED", "pubsub.publish: instance closed");
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("BAD_OPT", "pubsub.publish: channel must be a non-empty string");
    }
    var local = _localDispatch(channel, payload, "local");
    var remote = 0;
    if (typeof backend.publishRemote === "function") {
      try {
        var rv = await backend.publishRemote(_scoped(channel), payload);
        remote = (rv && typeof rv === "object" && Number.isFinite(rv.remote))
          ? rv.remote : 1;
      } catch (e) {
        if (auditOn) {
          try { audit().safeEmit({
            action: "system.pubsub.publish_failed",
            outcome: "failure",
            metadata: { channel: channel, error: (e && e.message) || String(e) },
          }); } catch (_e) { /* */ }
        }
        throw e;
      }
    }
    if (auditOn) {
      try { audit().safeEmit({
        action: "system.pubsub.publish",
        outcome: "success",
        metadata: { channel: channel, localDispatched: local, remoteWritten: remote },
      }); } catch (_e) { /* */ }
    }
    return { local: local, remote: remote };
  }

  async function close() {
    if (closed) return;
    closed = true;
    if (typeof backend.stop === "function") {
      try { await backend.stop(); } catch (_e) { /* close failure is informational */ }
    }
    exactSubs.clear();
    patternSubs.clear();
    remoteSubCount.clear();
  }

  return {
    backend:          function () { return backend.name; },
    subscribe:        subscribe,
    subscribePattern: subscribePattern,
    unsubscribe:      unsubscribe,
    publish:          publish,
    close:            close,
    // Diagnostic — exposed for tests + observability.
    _state: function () {
      return {
        backend:        backend.name,
        exactChannels:  exactSubs.size,
        patternCount:   patternSubs.size,
        remoteSubCount: remoteSubCount.size,
        closed:         closed,
      };
    },
    _matchPatternForTest: _matchPattern,
  };
}

module.exports = { create: create, PubsubError: PubsubError };
