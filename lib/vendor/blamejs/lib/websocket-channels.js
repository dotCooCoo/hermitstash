"use strict";
/**
 * websocket-channels — channel/room hub layered over `lib/websocket.js`.
 *
 * `lib/websocket.js` owns the wire protocol (RFC 6455 + 8441 frame
 * parsing, masking, control frames). This module owns the higher-level
 * subscription bookkeeping: connections subscribe to named channels,
 * publish() fans out a payload to every subscriber. Cross-node fan-out
 * is delegated to `b.pubsub` so cache-cluster invalidation, websocket
 * channels, and any future cross-node primitive share the same
 * transport (cluster table, Redis PUB/SUB, or operator-supplied).
 *
 * Public API:
 *
 *   var hub = b.websocketChannels.create({
 *     // Pub/sub backend opts — passed through to b.pubsub.create.
 *     backend:        'local' | 'cluster' | 'redis' | { custom },
 *     // cluster opts:
 *     cluster:        clusterInstance,
 *     pollIntervalMs: C.TIME.ms? — default 100ms
 *     retentionMs:    C.TIME.ms? — default 60s
 *     // redis opts:
 *     redisUrl:       string?
 *     redisPassword:  string?
 *     redisUsername:  string?
 *     redisTls:       boolean?
 *     redisCa:        string|Buffer?
 *     // common:
 *     topicPrefix:    string?    — default "ws" so independent
 *                                   pubsub primitives sharing a
 *                                   backend (cache, etc.) don't
 *                                   collide on channel names.
 *     audit:          boolean    — emit system.ws.publish on each publish
 *   });
 *
 *   r.ws("/socket", function (conn) {
 *     hub.attach(conn);                       // tracks lifecycle, auto-detach on close
 *     hub.subscribe(conn, "chat:room-1");
 *     hub.subscribe(conn, "presence:user-42");
 *   });
 *
 *   await hub.publish("chat:room-1", { user: "alice", text: "hi" });
 *
 *   hub.localSubscribers("chat:room-1");      // → [conn, ...]
 *   hub.localSubscriberCount("chat:room-1");  // → number
 *   hub.channels();                           // → ["chat:room-1", ...]
 *   hub.connectionChannels(conn);             // → ["chat:room-1", ...]
 *
 * Backend semantics live in `lib/pubsub.js`. The hub here is responsible
 * for the WebSocket-specific connection lifecycle (attach / detach),
 * the channel-to-conn map, and serialization of payloads for the local
 * dispatch path; the cross-node delivery is one pubsub.subscribe per
 * channel the hub joins, with the hub's `_localDispatch` as the handler.
 *
 * Error policy: a connection's send() that throws (closed socket, peer
 * gone) does NOT break dispatch to other subscribers. The throwing
 * subscriber is silently skipped; auto-detach on the connection's
 * 'close' event removes it from future fan-out.
 */

var lazyRequire = require("./lazy-require");
var pubsub = require("./pubsub");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit  = lazyRequire(function () { return require("./audit"); });
var logger = lazyRequire(function () { return require("./log").boot("websocket-channels"); });

var WebSocketChannelsError = defineClass("WebSocketChannelsError");

function _err(code, message) {
  return new WebSocketChannelsError(code, message, true);
}

// ---- Hub ----

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

  // Pub/sub fan-out is delegated to b.pubsub. The hub owns one pubsub
  // instance per WebSocket-channels primitive; topicPrefix defaults to
  // "ws" so independent pubsub primitives sharing the same backend
  // (cache cluster invalidation, app-level pubsub) don't collide on
  // channel names.
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
    // Default empty so pre-existing operators / tests that publish on
    // raw channel names keep working unchanged. Operators sharing one
    // pubsub backend across cache + websockets + custom primitives
    // pass a topicPrefix to isolate.
    topicPrefix:    opts.topicPrefix || "",
  });
  var backendName = ps.backend();

  // channel -> Set<connection>
  var channelToConns = new Map();
  // channel -> pubsub-token (one subscribe per channel the hub
  // currently has any local listener on; refcounted via the local
  // map's size).
  var channelToToken = new Map();
  // connection -> Set<channel>  (WeakMap so dropped conns don't leak)
  var connToChannels = new WeakMap();
  // Tracked connection set for surface methods that need to enumerate
  // connections (e.g. close-all-on-shutdown).
  var attachedConns = new Set();

  function _localDispatch(channel, payload) {
    var subs = channelToConns.get(channel);
    if (!subs || subs.size === 0) return 0;
    var msg;
    try { msg = JSON.stringify({ channel: channel, payload: payload }); }
    catch (e) {
      throw _err("INVALID_PAYLOAD",
        "publish payload is not JSON-serializable: " + (e && e.message));
    }
    var sent = 0;
    for (var conn of subs) {
      try { conn.send(msg); sent++; }
      catch (_e) { /* dead connection — auto-detach handles cleanup */ }
    }
    return sent;
  }

  // Pubsub message arrivals dispatch to local WebSocket connections.
  // For local-backend pubsub the handler runs synchronously inside
  // ps.publish(), so we accumulate the per-publish delivery count via
  // the `dispatchTallies` map keyed by channel + sequence id — the
  // hub's publish() reads it back after ps.publish() resolves.
  var lastDispatchCount = 0;
  function _onPubsubMessage(payload, ev) {
    var n = _localDispatch(ev.channel, payload);
    lastDispatchCount += n;
  }

  function attach(conn) {
    if (!conn || typeof conn.send !== "function") {
      throw _err("INVALID_CONN", "attach(conn) requires a connection with .send()");
    }
    if (connToChannels.has(conn)) return;  // idempotent
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
      throw _err("INVALID_CHANNEL", "subscribe: channel must be a non-empty string");
    }
    if (!connToChannels.has(conn)) {
      throw _err("NOT_ATTACHED", "subscribe: connection must be attach()-ed first");
    }
    if (!channelToConns.has(channel)) {
      channelToConns.set(channel, new Set());
      // First local listener for this channel — open a pubsub
      // subscription so cross-node fan-out reaches us.
      var token = ps.subscribe(channel, _onPubsubMessage);
      channelToToken.set(channel, token);
    }
    channelToConns.get(channel).add(conn);
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
      throw _err("INVALID_CHANNEL", "publish: channel must be a non-empty string");
    }
    // Pre-validate JSON serializability so circular / unserializable
    // payloads throw INVALID_PAYLOAD on the operator's await rather
    // than disappearing into the pubsub dispatcher's per-handler
    // try/catch (where they'd surface only as a warn-level log).
    try { JSON.stringify(payload); }
    catch (e) {
      throw _err("INVALID_PAYLOAD",
        "publish payload is not JSON-serializable: " + (e && e.message));
    }
    lastDispatchCount = 0;
    var remoteSent = false;
    var localCount = 0;
    try {
      var rv = await ps.publish(channel, payload);
      // ps.publish invokes _onPubsubMessage synchronously for the
      // local-backend; lastDispatchCount holds the conn-level count.
      // For remote-only backends the handler doesn't fire until a poll
      // tick / push event arrives — at that point the message goes to
      // every node including this one (publishedBy filter excluded for
      // pubsub-cluster, redis sees its own publish via its subscribe
      // socket too). So lastDispatchCount captures the local fan-out.
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
    // Drop all subscriptions. Connections are not closed — that's the
    // operator's call (`router.closeWebSockets()` is the framework's
    // hook for graceful shutdown).
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
    // Test hook — directly inject a remote message as if the pubsub
    // backend's transport just received it.
    _injectRemoteMessage:  function (channel, payload) {
      _localDispatch(channel, payload);
    },
  };
}

module.exports = {
  create:                  create,
  WebSocketChannelsError:  WebSocketChannelsError,
};
