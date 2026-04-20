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

/**
 * Flatten syncConnections into an array of { ws, apiKeyId, bundleId } for
 * live sockets only (readyState === 1). Used by the CA regeneration flow.
 */
function listSyncConnections() {
  var out = [];
  syncConnections.forEach(function (conns, bundleId) {
    conns.forEach(function (entry) {
      if (entry.ws && entry.ws.readyState === 1) {
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
};
