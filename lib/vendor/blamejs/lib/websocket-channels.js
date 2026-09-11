// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire = require("./lazy-require");
var pubsub = require("./pubsub");
var boundedMap = require("./bounded-map");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit  = lazyRequire(function () { return require("./audit"); });
var logger = lazyRequire(function () { return require("./log").boot("websocket-channels"); });

var WebSocketChannelsError = defineClass("WebSocketChannelsError");

function _err(code, message) {
  return new WebSocketChannelsError(code, message, true);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "backend", "audit", "cluster",
    "pollIntervalMs", "retentionMs", "pruneEveryMs",
    "redisUrl", "redisPassword", "redisUsername", "redisTls",
    "redisCa", "redisServername",
    "topicPrefix",
  ], "b.websocket");
  var auditOn = !!opts.audit;

  var ps = pubsub.create({
    backend:        opts.backend,
    cluster:        opts.cluster,
    pollIntervalMs: opts.pollIntervalMs,
    retentionMs:    opts.retentionMs,
    pruneEveryMs:   opts.pruneEveryMs,
    redisUrl:       opts.redisUrl,
    redisPassword:  opts.redisPassword,
    redisUsername:  opts.redisUsername,
    redisTls:       opts.redisTls,
    redisCa:        opts.redisCa,
    redisServername: opts.redisServername,
    topicPrefix:    opts.topicPrefix || "",
  });
  var backendName = ps.backend();

  var channelToConns = new Map();
  var channelToToken = new Map();
  var connToChannels = new WeakMap();
  var attachedConns = new Set();

  function _localDispatch(channel, payload) {
    var subs = channelToConns.get(channel);
    if (!subs || subs.size === 0) return 0;
    var msg;
    try { msg = JSON.stringify({ channel: channel, payload: payload }); }
    catch (e) {
      throw _err("websocket-channels/invalid-payload",
        "publish payload is not JSON-serializable: " + (e && e.message));
    }
    var sent = 0;
    for (var conn of subs) {
      try { conn.send(msg); sent++; }
      catch (_e) { /* dead connection — auto-detach handles cleanup */ }
    }
    return sent;
  }

  var lastDispatchCount = 0;
  function _onPubsubMessage(payload, ev) {
    var n = _localDispatch(ev.channel, payload);
    lastDispatchCount += n;
  }

  function attach(conn) {
    if (!conn || typeof conn.send !== "function") {
      throw _err("websocket-channels/invalid-conn", "attach(conn) requires a connection with .send()");
    }
    if (connToChannels.has(conn)) return;
    connToChannels.set(conn, new Set());
    attachedConns.add(conn);
    if (typeof conn.on === "function") {
      conn.on("close", function () { detach(conn); });
    }
  }

  function detach(conn) {
    var chans = connToChannels.get(conn);
    if (!chans) return;
    for (var c of chans) {
      var subs = channelToConns.get(c);
      if (subs) {
        subs.delete(conn);
        if (subs.size === 0) {
          channelToConns.delete(c);
          var token = channelToToken.get(c);
          if (token) {
            ps.unsubscribe(token);
            channelToToken.delete(c);
          }
        }
      }
    }
    connToChannels.delete(conn);
    attachedConns.delete(conn);
  }

  function subscribe(conn, channel) {
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("websocket-channels/invalid-channel", "subscribe: channel must be a non-empty string");
    }
    boundedMap.requirePresent(connToChannels, conn, function () {
      throw _err("websocket-channels/not-attached", "subscribe: connection must be attach()-ed first");
    });
    var subs = boundedMap.getOrInsert(channelToConns, channel, function () {
      var token = ps.subscribe(channel, _onPubsubMessage);
      channelToToken.set(channel, token);
      return new Set();
    });
    subs.add(conn);
    connToChannels.get(conn).add(channel);
  }

  function unsubscribe(conn, channel) {
    var subs = channelToConns.get(channel);
    if (subs) {
      subs.delete(conn);
      if (subs.size === 0) {
        channelToConns.delete(channel);
        var token = channelToToken.get(channel);
        if (token) {
          ps.unsubscribe(token);
          channelToToken.delete(channel);
        }
      }
    }
    var chans = connToChannels.get(conn);
    if (chans) chans.delete(channel);
  }

  async function publish(channel, payload) {
    if (typeof channel !== "string" || channel.length === 0) {
      throw _err("websocket-channels/invalid-channel", "publish: channel must be a non-empty string");
    }
    try { JSON.stringify(payload); }
    catch (e) {
      throw _err("websocket-channels/invalid-payload",
        "publish payload is not JSON-serializable: " + (e && e.message));
    }
    lastDispatchCount = 0;
    var remoteSent = false;
    var localCount = 0;
    try {
      var rv = await ps.publish(channel, payload);
      localCount = lastDispatchCount;
      remoteSent = (rv && rv.remote > 0);
    } catch (e) {
      try {
        logger().error("publishRemote failed for channel '" + channel + "': " +
          ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    }
    if (auditOn) {
      audit().safeEmit({
        action:   "system.ws.publish",
        metadata: {
          channel:        channel,
          backend:        backendName,
          localDelivered: localCount,
          remoteSent:     remoteSent,
        },
      });
    }
    return { localDelivered: localCount, remoteSent: remoteSent };
  }

  function localSubscribers(channel) {
    var subs = channelToConns.get(channel);
    return subs ? Array.from(subs) : [];
  }

  function localSubscriberCount(channel) {
    var subs = channelToConns.get(channel);
    return subs ? subs.size : 0;
  }

  function channels() {
    return Array.from(channelToConns.keys());
  }

  function connectionChannels(conn) {
    var chans = connToChannels.get(conn);
    return chans ? Array.from(chans) : [];
  }

  function attachedCount() {
    return attachedConns.size;
  }

  async function close() {
    for (var token of channelToToken.values()) ps.unsubscribe(token);
    channelToToken.clear();
    channelToConns.clear();
    for (var conn of attachedConns) connToChannels.delete(conn);
    attachedConns.clear();
    await ps.close();
  }

  return {
    backend:               backendName,
    attach:                attach,
    detach:                detach,
    subscribe:             subscribe,
    unsubscribe:           unsubscribe,
    publish:               publish,
    localSubscribers:      localSubscribers,
    localSubscriberCount:  localSubscriberCount,
    channels:              channels,
    connectionChannels:    connectionChannels,
    attachedCount:         attachedCount,
    close:                 close,
    _injectRemoteMessage:  function (channel, payload) {
      _localDispatch(channel, payload);
    },
  };
}

module.exports = {
  create:                  create,
  WebSocketChannelsError:  WebSocketChannelsError,
};
