"use strict";
/**
 * pubsub-redis — Redis PUB/SUB backend for `lib/pubsub.js`.
 *
 * Two connections per pubsub instance:
 *
 *   subscriberConn — placed in subscribe mode via SUBSCRIBE /
 *                    PSUBSCRIBE. The `lib/redis-client.js` push hook
 *                    (`setOnPushMessage`) demultiplexes server-pushed
 *                    "message" / "pmessage" frames from
 *                    SUBSCRIBE/UNSUBSCRIBE acks. Subscribe-mode
 *                    connections can't issue arbitrary commands;
 *                    splitting publisher off is mandatory.
 *   publisherConn  — issues PUBLISH commands against the same Redis
 *                    instance. Uses normal command pipelining.
 *
 * The framework's `lib/redis-client.js` is single-connection-per-create
 * — both connections use the same options (URL / password / TLS / CA).
 *
 * Channels are passed through to Redis with the topicPrefix already
 * applied by `lib/pubsub.js`; this backend doesn't add any naming
 * conventions of its own.
 */
var C = require("./constants");
var fwCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var redisClient = require("./redis-client");
var safeJson = require("./safe-json");

var logger = lazyRequire(function () { return require("./log").boot("pubsub-redis"); });

function create(opts) {
  if (typeof opts.redisUrl !== "string" || opts.redisUrl.length === 0) {
    throw new Error("pubsub-redis: redisUrl is required");
  }
  // Per-instance nonce stamped on every outgoing payload so the
  // SUBSCRIBE socket can recognize its own publishes and skip
  // dispatching them (the framework's pubsub.publish() already did
  // the local dispatch synchronously before awaiting the remote
  // write — without this filter every same-instance publish would
  // double-fire local handlers).
  var instanceNonce = fwCrypto.generateToken(C.BYTES.bytes(8));

  var clientOpts = redisClient.pickClientOpts(opts, "redis");

  var subscriberConn = null;
  var publisherConn  = null;
  var connectPromise = null;
  var stopped = false;
  var savedOnRemoteMessage = null;

  // Inbound demultiplex — the redis-client routes "message" /
  // "pmessage" frames here. Strip the {_psnode, p} envelope; if the
  // nonce matches this instance, the message is our own publish
  // looping back through Redis — skip dispatch (pubsub.js already
  // dispatched locally in publish()). Otherwise forward to the
  // dispatcher with the unwrapped payload string.
  function _onPush(ev) {
    if (!savedOnRemoteMessage) return;
    var rawPayload = ev.payload;
    var payloadStr = Buffer.isBuffer(rawPayload)
      ? rawPayload.toString("utf8") : String(rawPayload);
    var inner = payloadStr;
    // Redis pubsub frames are bounded by Redis's own bulk-string limit;
    // cap the envelope parse at 16 MiB to keep this hot path fast and
    // defeat a hostile publisher inflating one frame to 512 MB.
    try {
      var envelope = safeJson.parse(payloadStr, { maxBytes: C.BYTES.mib(16) });
      if (envelope && typeof envelope === "object" &&
          typeof envelope._psnode === "string") {
        if (envelope._psnode === instanceNonce) return;  // own publish
        inner = JSON.stringify(envelope.p);
      }
    } catch (e) {
      // Not an envelope — forward as-is for operators publishing raw
      // strings via redis CLI etc. (Parse failure is the expected path
      // for raw-string publishers; not log-worthy.)
      void e;
    }
    try {
      savedOnRemoteMessage(ev.channel, inner, {
        pattern: ev.pattern || null,
      });
    } catch (e) {
      try { logger().warn("pubsub-redis push dispatch failed: " +
        ((e && e.message) || String(e))); }
      catch (_e) { /* */ }
    }
  }

  async function _ensureConnected() {
    if (stopped) throw new Error("pubsub-redis: backend stopped");
    if (subscriberConn && publisherConn) return;
    if (connectPromise) return connectPromise;
    connectPromise = (async function () {
      subscriberConn = redisClient.create(Object.assign({}, clientOpts, {
        onPushMessage: _onPush,
      }));
      publisherConn = redisClient.create(clientOpts);
      await Promise.all([subscriberConn.connect(), publisherConn.connect()]);
    })();
    try { await connectPromise; }
    finally { connectPromise = null; }
  }

  async function publishRemote(scopedChannel, payload) {
    await _ensureConnected();
    var serialized = JSON.stringify({ _psnode: instanceNonce, p: payload });
    var n = await publisherConn.command("PUBLISH", scopedChannel, serialized);
    return { remote: Number(n) || 0 };
  }

  async function subscribeRemote(scopedChannel, isPattern) {
    await _ensureConnected();
    var cmd = isPattern ? "PSUBSCRIBE" : "SUBSCRIBE";
    await subscriberConn.command(cmd, scopedChannel);
  }

  async function unsubscribeRemote(scopedChannel, isPattern) {
    if (!subscriberConn || !subscriberConn.isOpen()) return;
    var cmd = isPattern ? "PUNSUBSCRIBE" : "UNSUBSCRIBE";
    try { await subscriberConn.command(cmd, scopedChannel); }
    catch (_e) { /* unsubscribe failure is informational */ }
  }

  function start(onRemoteMessage) {
    savedOnRemoteMessage = onRemoteMessage;
    // Lazy connect — first subscribe / publish opens the sockets. This
    // keeps `b.pubsub.create()` synchronous-safe on a misconfigured
    // redis URL: the validation throw lands on the first publish/subscribe
    // call, where the operator can catch it.
  }

  async function stop() {
    stopped = true;
    savedOnRemoteMessage = null;
    if (subscriberConn) {
      try { await subscriberConn.close(); }
      catch (e) {
        try { logger().debug("subscriber-close-failed: " +
          ((e && e.message) || String(e))); }
        catch (_e) { /* logger best-effort */ }
      }
      subscriberConn = null;
    }
    if (publisherConn) {
      try { await publisherConn.close(); }
      catch (e) {
        try { logger().debug("publisher-close-failed: " +
          ((e && e.message) || String(e))); }
        catch (_e) { /* logger best-effort */ }
      }
      publisherConn = null;
    }
  }

  return {
    name:              "redis",
    publishRemote:     publishRemote,
    subscribeRemote:   subscribeRemote,
    unsubscribeRemote: unsubscribeRemote,
    start:             start,
    stop:              stop,
  };
}

module.exports = { create: create };
