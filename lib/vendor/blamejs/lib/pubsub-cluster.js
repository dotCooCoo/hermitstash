"use strict";
/**
 * pubsub-cluster — table-polling backend for `lib/pubsub.js`.
 *
 * Generalizes the polling pattern previously inlined in
 * `lib/websocket-channels.js`. One shared table
 * `_blamejs_pubsub_messages` carries every cross-node fan-out event;
 * subscribers on each node poll the table at `pollIntervalMs` and
 * dispatch new rows past their last-seen id. Independent pubsub
 * instances on the same database isolate via `topicPrefix` (see
 * lib/pubsub.js).
 *
 * Trade-offs vs. the redis backend:
 *   - No external dependency — re-uses the cluster DB the framework
 *     already requires for leader election, queues, sessions, etc.
 *   - Latency floor is the polling interval (default 100ms). Operators
 *     wanting <10ms cross-node latency switch to the redis backend.
 *   - Survives transient network blips between app nodes; missed rows
 *     are picked up on the next poll until retentionMs elapses.
 *
 * Schema: `_blamejs_pubsub_messages (id, topic, payload, publishedAt,
 * publishedBy)`. Created by `lib/cluster-storage.js` migrations.
 */
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var lazyRequire = require("./lazy-require");

var logger = lazyRequire(function () { return require("./log").boot("pubsub-cluster"); });

var DEFAULT_POLL_INTERVAL_MS = 100;
var DEFAULT_RETENTION_MS     = C.TIME.minutes(1);
var DEFAULT_PRUNE_EVERY_MS   = C.TIME.minutes(5);

function create(opts) {
  var clusterInstance = opts.cluster;
  var pollIntervalMs = Number(opts.pollIntervalMs) || DEFAULT_POLL_INTERVAL_MS;
  var retentionMs    = Number(opts.retentionMs)    || DEFAULT_RETENTION_MS;
  var pruneEveryMs   = Number(opts.pruneEveryMs)   || DEFAULT_PRUNE_EVERY_MS;

  var lastSeenId  = 0;
  var primed      = false;
  var lastPruneAt = 0;
  var pollTimer   = null;
  var stopped     = false;

  function _nodeId() {
    if (clusterInstance && typeof clusterInstance.currentNodeId === "function") {
      return clusterInstance.currentNodeId();
    }
    return "single-node-local";
  }

  async function publishRemote(scopedChannel, payload) {
    var serialized = JSON.stringify(payload);
    await clusterStorage.execute(
      "INSERT INTO _blamejs_pubsub_messages " +
      "(topic, payload, publishedAt, publishedBy) VALUES (?, ?, ?, ?)",
      [scopedChannel, serialized, Date.now(), _nodeId()]
    );
    return { remote: 1 };
  }

  async function _poll(onRemoteMessage) {
    if (stopped) return;
    var nodeId = _nodeId();
    try {
      // First poll: prime lastSeenId to the current MAX so we don't
      // re-dispatch every historical row on startup.
      if (!primed) {
        var primer = await clusterStorage.execute(
          "SELECT COALESCE(MAX(id), 0) AS maxId FROM _blamejs_pubsub_messages",
          []
        );
        if (primer.rows && primer.rows[0]) {
          lastSeenId = Number(primer.rows[0].maxId) || 0;
        }
        primed = true;
        return;
      }
      var result = await clusterStorage.execute(
        "SELECT id, topic, payload, publishedAt, publishedBy " +
        "FROM _blamejs_pubsub_messages " +
        "WHERE id > ? AND publishedBy <> ? ORDER BY id ASC",
        [lastSeenId, nodeId]
      );
      var rows = result.rows || [];
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        try {
          onRemoteMessage(row.topic, row.payload, {
            publishedBy: row.publishedBy,
            publishedAt: Number(row.publishedAt) || null,
          });
        } catch (e) {
          try { logger().warn("malformed pubsub fan-out row id=" + row.id +
            ": " + ((e && e.message) || String(e))); }
          catch (_e) { /* logger best-effort */ }
        }
        if (Number(row.id) > lastSeenId) lastSeenId = Number(row.id);
      }

      // Rate-limited prune of expired rows.
      var now = Date.now();
      if (now - lastPruneAt >= pruneEveryMs) {
        lastPruneAt = now;
        await clusterStorage.execute(
          "DELETE FROM _blamejs_pubsub_messages WHERE publishedAt < ?",
          [now - retentionMs]
        );
      }
    } catch (e) {
      try { logger().warn("pubsub-cluster poll failed: " +
        ((e && e.message) || String(e))); }
      catch (_e) { /* */ }
    }
  }

  function start(onRemoteMessage) {
    if (pollTimer) return;
    stopped = false;
    var tick = function () {
      _poll(onRemoteMessage).then(function () {
        if (stopped) return;
        pollTimer = setTimeout(tick, pollIntervalMs);
        if (typeof pollTimer.unref === "function") pollTimer.unref();
      }, function () {
        if (stopped) return;
        pollTimer = setTimeout(tick, pollIntervalMs);
        if (typeof pollTimer.unref === "function") pollTimer.unref();
      });
    };
    pollTimer = setTimeout(tick, 0);
    if (typeof pollTimer.unref === "function") pollTimer.unref();
  }

  function stop() {
    stopped = true;
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  return {
    name:           "cluster",
    publishRemote:  publishRemote,
    start:          start,
    stop:           stop,
    // Cluster backend doesn't need explicit subscribeRemote — every
    // node sees every row. The pubsub.js wrapper still tracks the
    // remoteSubCount for parity with backends that DO need it.
    subscribeRemote:   null,
    unsubscribeRemote: null,
  };
}

module.exports = { create: create };
