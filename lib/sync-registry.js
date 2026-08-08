/**
 * Shared WebSocket sync connection registry.
 *
 * server.js owns the /sync/ws upgrade handler and populates these Maps on
 * connect/disconnect. routes/admin.js consumes them during CA regeneration
 * to push `ca:rotation` messages to every live sync client. Extracting the
 * state here avoids a server.js ↔ routes/admin.js circular require.
 *
 * Maps are pass-by-reference — both importers share the same instances.
 */

// Map<bundleId, Set<{ws, apiKeyId}>>
var syncConnections = new Map();

// Map<apiKeyId, number> — active connection count per key (used for per-key
// connection-limit enforcement).
var apiKeyConnectionCount = new Map();

// CA-rotation ack tracking. The admin regeneration endpoint registers a
// callback per apiKeyId before broadcasting `ca:rotation`; the WS message
// handler fires the callback when the matching `ca:rotation-ack` arrives.
// Keyed by apiKeyId (string), value is a function(void).
var caRotationAckCallbacks = new Map();

// WebSocket close code for a connection superseded by a reconnect from the SAME
// client instance. Private-use range (4000–4999), mirroring the existing 4401
// "credential revoked" convention by echoing an HTTP status: 409 Conflict.
var SUPERSEDED_CLOSE_CODE = 4409;

/**
 * Drop a client's OWN earlier connection when it reconnects, identified by the
 * instance id it sent on the upgrade.
 *
 * Why an instance id and not (apiKey, bundle): a single key legitimately holds
 * several concurrent connections to one bundle — separate devices, or a browser
 * alongside a daemon — and two E2E tests assert that two subscribers on the same
 * key and bundle both receive events. Matching on (apiKey, bundle) would close
 * one of them. The instance id is the only signal that distinguishes "this same
 * client is back" from "a different client is also here", so it is the only safe
 * key to supersede on.
 *
 * The problem it solves: the per-key connection count is decremented in the
 * socket's close handler, but an unclean drop is not noticed until the
 * pong-timeout fires a heartbeat or two later. Until then the dead connection
 * still occupies a slot, so a client reconnecting inside that window can be
 * refused by the ceiling on account of its own ghost. Superseding frees the slot
 * immediately.
 *
 * Callers that have no instance id (an older client that sends no header) get a
 * no-op — nothing is closed, and behaviour is exactly as before.
 *
 * Returns the number of connections superseded.
 */
function supersedeSameInstance(bundleId, keyId, instanceId) {
  if (!instanceId) return 0;                 // no id — never guess; supersede nothing
  var conns = syncConnections.get(bundleId);
  if (!conns) return 0;
  var superseded = 0;
  conns.forEach(function (entry) {
    if (entry.apiKeyId !== keyId || entry.instanceId !== instanceId) return;
    conns.delete(entry);
    // Release the slot here, and mark the entry so its own (late) close handler
    // does not decrement the same slot a second time.
    if (entry.counted) {
      entry.counted = false;
      var c = apiKeyConnectionCount.get(keyId) || 0;
      if (c > 1) apiKeyConnectionCount.set(keyId, c - 1);
      else apiKeyConnectionCount.delete(keyId);
    }
    superseded++;
    try {
      if (entry.ws && entry.ws.readyState === "open") {
        entry.ws.close(SUPERSEDED_CLOSE_CODE, "superseded by reconnect");
      }
    } catch (_e) { /* allow:silent-catch — stale socket may already be closing */ }
  });
  if (conns.size === 0) syncConnections.delete(bundleId);
  return superseded;
}

/**
 * Flatten syncConnections into an array of { ws, apiKeyId, bundleId } for
 * live sockets only. Used by the CA regeneration flow.
 *
 * b.websocket exposes readyState as a string ("open" | "closing" | "closed");
 * the numeric values from the npm `ws` package don't apply.
 */
function listSyncConnections() {
  var out = [];
  syncConnections.forEach(function (conns, bundleId) {
    conns.forEach(function (entry) {
      if (entry.ws && entry.ws.readyState === "open") {
        out.push({ ws: entry.ws, apiKeyId: entry.apiKeyId, bundleId: bundleId });
      }
    });
  });
  return out;
}

module.exports = {
  syncConnections: syncConnections,
  apiKeyConnectionCount: apiKeyConnectionCount,
  caRotationAckCallbacks: caRotationAckCallbacks,
  listSyncConnections: listSyncConnections,
  supersedeSameInstance: supersedeSameInstance,
  SUPERSEDED_CLOSE_CODE: SUPERSEDED_CLOSE_CODE,
};
