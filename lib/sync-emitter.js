/**
 * Sync event emitter — bridges file mutations to WebSocket connections.
 * Single in-process EventEmitter for all sync bundles.
 */
var { EventEmitter } = require("node:events");
var syncEmitter = new EventEmitter();
syncEmitter.setMaxListeners(100); // support many concurrent sync connections
module.exports = syncEmitter;
