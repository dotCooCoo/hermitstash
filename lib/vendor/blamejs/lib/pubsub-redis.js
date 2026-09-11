// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var redisClient = require("./redis-client");
var safeJson = require("./safe-json");

var logger = lazyRequire(function () { return require("./log").boot("pubsub-redis"); });

function create(opts) {
  if (typeof opts.redisUrl !== "string" || opts.redisUrl.length === 0) {
    throw new Error("pubsub-redis: redisUrl is required");
  }
  var instanceNonce = bCrypto.generateToken(C.BYTES.bytes(8));

  var clientOpts = redisClient.pickClientOpts(opts, "redis");

  var subscriberConn = null;
  var publisherConn  = null;
  var connectPromise = null;
  var stopped = false;
  var savedOnRemoteMessage = null;

  function _onPush(ev) {
    if (!savedOnRemoteMessage) return;
    var rawPayload = ev.payload;
    var payloadStr = Buffer.isBuffer(rawPayload)
      ? rawPayload.toString("utf8") : String(rawPayload);
    var inner = payloadStr;
    try {
      var envelope = safeJson.parse(payloadStr, { maxBytes: C.BYTES.mib(16) });
      if (envelope && typeof envelope === "object" &&
          typeof envelope._psnode === "string") {
        if (envelope._psnode === instanceNonce) return;
        inner = JSON.stringify(envelope.p);
      }
    } catch (e) {
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
