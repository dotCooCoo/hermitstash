"use strict";

/**
 * supersedeSameInstance — a reconnecting client reclaims the slot held by its
 * OWN stale connection, and nothing else.
 *
 * Background: the per-key connection count is only decremented in a socket's
 * close handler, and an unclean drop is not noticed until the pong-timeout
 * fires a heartbeat or two later. A client reconnecting inside that window can
 * be refused by the per-key ceiling because of its own ghost.
 *
 * The obvious fix — close the previous connection for the same (apiKey, bundle)
 * — is WRONG, and these tests exist mainly to keep it wrong. One key
 * legitimately holds several concurrent connections to one bundle, and the E2E
 * suite asserts that two subscribers on the same key and bundle both receive
 * events. Only the client-supplied instance id distinguishes "this same client
 * is back" from "another client is also here".
 */

var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");

var reg = require("../../lib/sync-registry");

function fakeWs(readyState) {
  return {
    readyState: readyState || "open",
    closed: null,
    close: function (code, reason) { this.readyState = "closing"; this.closed = { code: code, reason: reason }; },
  };
}

// Register exactly as the /sync/ws upgrade handler does.
function register(bundleId, keyId, instanceId, ws) {
  if (!reg.syncConnections.has(bundleId)) reg.syncConnections.set(bundleId, new Set());
  var entry = { ws: ws || fakeWs("open"), apiKeyId: keyId, instanceId: instanceId, counted: true };
  reg.syncConnections.get(bundleId).add(entry);
  var c = reg.apiKeyConnectionCount.get(keyId) || 0;
  reg.apiKeyConnectionCount.set(keyId, c + 1);
  return entry;
}

// Replay the upgrade handler's guarded close-handler decrement.
function simulateClose(entry, keyId) {
  if (!entry.counted) return;
  entry.counted = false;
  var c = reg.apiKeyConnectionCount.get(keyId) || 0;
  if (c > 1) reg.apiKeyConnectionCount.set(keyId, c - 1);
  else reg.apiKeyConnectionCount.delete(keyId);
}

function clearAll() {
  reg.syncConnections.clear();
  reg.apiKeyConnectionCount.clear();
  reg.caRotationAckCallbacks.clear();
}

describe("sync-registry supersedeSameInstance", function () {
  beforeEach(clearAll);

  it("closes the client's own stale connection and frees its slot", function () {
    var ghost = register("bundle-A", "key-1", "inst-aaa");
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 1);

    var n = reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.equal(n, 1, "the same instance's prior connection is superseded");
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), undefined, "its slot is released immediately");
    assert.equal(ghost.counted, false, "marked uncounted so its late close is a no-op");
    assert.equal(ghost.ws.closed.code, 4409, "closed with the superseded code");
  });

  it("NEVER closes a different instance on the same key and bundle", function () {
    // This is the case the earlier (key,bundle) approach broke, and that the
    // E2E multi-subscriber tests assert.
    var other = register("bundle-A", "key-1", "inst-bbb");
    register("bundle-A", "key-1", "inst-aaa");
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 2);

    var n = reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.equal(n, 1, "only the matching instance is superseded");
    assert.ok(reg.syncConnections.get("bundle-A").has(other), "the other subscriber survives");
    assert.equal(other.ws.closed, null, "and its socket is never closed");
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 1);
  });

  it("does nothing when the client sent no instance id", function () {
    // An older client sends no header. Superseding on anything else would be a
    // guess, so the correct behaviour is to leave every connection alone.
    var a = register("bundle-A", "key-1", null);
    var b = register("bundle-A", "key-1", null);
    assert.equal(reg.supersedeSameInstance("bundle-A", "key-1", null), 0);
    assert.equal(reg.supersedeSameInstance("bundle-A", "key-1", undefined), 0);
    assert.ok(reg.syncConnections.get("bundle-A").has(a));
    assert.ok(reg.syncConnections.get("bundle-A").has(b));
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 2, "no slot is released");
  });

  it("does not match the same instance id under a different key", function () {
    // Instance ids are client-supplied and not globally unique; they are only
    // meaningful within one key.
    var other = register("bundle-A", "key-2", "inst-aaa");
    register("bundle-A", "key-1", "inst-aaa");

    var n = reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.equal(n, 1);
    assert.ok(reg.syncConnections.get("bundle-A").has(other), "the other key's connection is untouched");
    assert.equal(reg.apiKeyConnectionCount.get("key-2"), 1);
  });

  it("leaves the same instance's connection on a different bundle alone", function () {
    var otherBundle = register("bundle-B", "key-1", "inst-aaa");
    register("bundle-A", "key-1", "inst-aaa");

    reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.ok(reg.syncConnections.get("bundle-B").has(otherBundle),
      "a client may hold one connection per bundle; only this bundle's is superseded");
  });

  it("never double-decrements when the ghost's close handler runs late", function () {
    var ghost = register("bundle-A", "key-1", "inst-aaa");
    register("bundle-B", "key-1", "inst-aaa");        // same key, keeps the count > 0
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 2);

    reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 1);
    simulateClose(ghost, "key-1");                     // the socket finally closes
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 1, "the slot is not released twice");
  });

  it("frees the slot so a reconnect lands under the ceiling", function () {
    register("bundle-A", "key-1", "inst-aaa");         // the ghost
    reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa");
    assert.equal(reg.apiKeyConnectionCount.get("key-1") || 0, 0);
    register("bundle-A", "key-1", "inst-aaa");         // the reconnect
    assert.equal(reg.apiKeyConnectionCount.get("key-1"), 1, "the reconnect is the sole live connection");
  });

  it("does not re-close a socket that is already closing", function () {
    var dead = fakeWs("closed");
    register("bundle-A", "key-1", "inst-aaa", dead);
    assert.equal(reg.supersedeSameInstance("bundle-A", "key-1", "inst-aaa"), 1);
    assert.equal(dead.closed, null, "a non-open socket is dropped without a second close()");
  });

});
