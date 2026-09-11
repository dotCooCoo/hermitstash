// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var clusterStorage = require("./cluster-storage");
var frameworkSchema = require("./framework-schema");
var sql = require("./sql");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var logger = lazyRequire(function () { return require("./log").boot("pubsub-cluster"); });

var PubsubError = defineClass("PubsubError");

var MESSAGES_TABLE = frameworkSchema.tableName("_blamejs_pubsub_messages");   // allow:hand-rolled-sql — single canonical logical-name reference

function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

var DEFAULT_POLL_INTERVAL_MS = 100;
var DEFAULT_RETENTION_MS     = C.TIME.minutes(1);
var DEFAULT_PRUNE_EVERY_MS   = C.TIME.minutes(5);

function create(opts) {
  var clusterInstance = opts.cluster;
  validateOpts.optionalPositiveInt(opts.pollIntervalMs,
    "pubsub: pollIntervalMs", PubsubError, "pubsub-cluster/bad-opt");
  validateOpts.optionalPositiveInt(opts.retentionMs,
    "pubsub: retentionMs", PubsubError, "pubsub-cluster/bad-opt");
  validateOpts.optionalPositiveInt(opts.pruneEveryMs,
    "pubsub: pruneEveryMs", PubsubError, "pubsub-cluster/bad-opt");
  var pollIntervalMs = opts.pollIntervalMs !== undefined ? opts.pollIntervalMs : DEFAULT_POLL_INTERVAL_MS;
  var retentionMs    = opts.retentionMs    !== undefined ? opts.retentionMs    : DEFAULT_RETENTION_MS;
  var pruneEveryMs   = opts.pruneEveryMs   !== undefined ? opts.pruneEveryMs   : DEFAULT_PRUNE_EVERY_MS;

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
    var built = sql.insert(MESSAGES_TABLE, _sqlOpts()).values({
      topic:       scopedChannel,
      payload:     serialized,
      publishedAt: Date.now(),
      publishedBy: _nodeId(),
    }).toSql();
    await clusterStorage.execute(built.sql, built.params);
    return { remote: 1 };
  }

  async function _poll(onRemoteMessage) {
    if (stopped) return;
    var nodeId = _nodeId();
    try {
      if (!primed) {
        var primerBuilt = sql.select(MESSAGES_TABLE, _sqlOpts()).max("id", "maxId").toSql();
        var primer = await clusterStorage.execute(primerBuilt.sql, primerBuilt.params);
        if (primer.rows && primer.rows[0]) {
          lastSeenId = Number(primer.rows[0].maxId) || 0;
        }
        primed = true;
        return;
      }
      var pollBuilt = sql.select(MESSAGES_TABLE, _sqlOpts())
        .columns(["id", "topic", "payload", "publishedAt", "publishedBy"])
        .where("id", ">", lastSeenId)
        .where("publishedBy", "<>", nodeId)
        .orderBy("id", "asc")
        .toSql();
      var result = await clusterStorage.execute(pollBuilt.sql, pollBuilt.params);
      var rows = result.rows || [];
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        safeAsync.safeApply(onRemoteMessage, [row.topic, row.payload, {
          publishedBy: row.publishedBy,
          publishedAt: Number(row.publishedAt) || null,
        }], function (e) {
          try { logger().warn("malformed pubsub fan-out row id=" + row.id +
            ": " + ((e && e.message) || String(e))); }
          catch (_e) { /* logger best-effort */ }
        });
        if (Number(row.id) > lastSeenId) lastSeenId = Number(row.id);
      }

      var now = Date.now();
      if (now - lastPruneAt >= pruneEveryMs) {
        lastPruneAt = now;
        var pruneBuilt = sql.delete(MESSAGES_TABLE, _sqlOpts())
          .where("publishedAt", "<", now - retentionMs).toSql();
        await clusterStorage.execute(pruneBuilt.sql, pruneBuilt.params);
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
    subscribeRemote:   null,
    unsubscribeRemote: null,
  };
}

module.exports = { create: create };
