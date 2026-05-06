"use strict";
/**
 * events — framework-wide cross-cutting signal bus.
 *
 * A thin wrapper around Node's EventEmitter, exposed as `b.events`,
 * dedicated to framework-emitted breach-detection and integrity signals.
 * Operators wire listeners to PagerDuty / Opsgenie / a Slack webhook /
 * a notification queue and the framework fires them on the specific
 * high-signal conditions documented in `EVENTS` below.
 *
 * Why a separate emitter (not Node's built-in EventEmitter directly):
 *   - One bus the framework controls — operators don't have to chase
 *     emit calls across modules to know what's available.
 *   - Best-effort emit semantics: a listener throwing must NOT break
 *     the framework's refuse-to-boot fail-fast. emit() catches and
 *     swallows listener errors.
 *   - Stable event names exported as constants — operators reference
 *     b.events.EVENTS.AUDIT_CHAIN_BREAK rather than typing the string.
 *   - _resetForTest() clears listeners between tests without touching
 *     consumer state.
 *
 * Public API:
 *   b.events.on(name, fn)               register listener
 *   b.events.off(name, fn)              unregister listener
 *   b.events.once(name, fn)             register single-fire listener
 *   b.events.emit(name, payload)        fire (best-effort; listener
 *                                       errors logged + swallowed)
 *   b.events.listenerCount(name)        diagnostic
 *   b.events.EVENTS                     stable name constants
 *
 * Example operator wiring (sync — synchronous I/O only inside the handler
 * since process.exit may follow on certain framework signals):
 *
 *   b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function (info) {
 *     fs.writeFileSync("/var/run/blamejs-chain-break.flag",
 *       JSON.stringify({ at: Date.now(), info: info }));
 *   });
 *
 * For async fan-out (PagerDuty webhook, etc.) the listener should hand
 * off to a queue — synchronous I/O in the listener is safe but blocking
 * network calls would delay the framework's fail-fast path on signals
 * that lead to process.exit.
 */

var nodeEvents = require("node:events");
var { boot } = require("./log");

var log = boot("events");

// Stable event names. Adding a new emit point means adding it here so
// operators discover it via tab-completion / api-snapshot diff.
var EVENTS = Object.freeze({
  // Audit hash chain failed verification — verify() returned ok=false.
  // Framework refuses to boot on this signal but emits FIRST so the
  // operator's listener gets a chance to log/page before process.exit.
  AUDIT_CHAIN_BREAK:       "audit:chain-break",
  // Audit checkpoint signature failed verification (forgery attempt or
  // key rotation without history retention). Same fail-fast pattern.
  AUDIT_CHECKPOINT_BREAK:  "audit:checkpoint-break",
  // db.audit.tip sidecar shows a higher monotonic counter than the
  // current audit_log MAX — DB was rolled back to an older snapshot.
  AUDIT_ROLLBACK_DETECTED: "audit:rollback-detected",
  // NTP boot-check found drift outside the configured threshold.
  // Severity is "warning" (5min–1hr) or "fatal" (>=1hr); payload
  // includes the actual drift in ms.
  NTP_DRIFT:               "audit:ntp-drift",
  // api-encrypt middleware rejected an inbound request: AEAD failure,
  // stale timestamp, replay, or malformed envelope. Payload carries
  // { reason, ip, path, ts } so operators can wire alerting on the
  // shape of attempted attacks without exposing why-it-failed back
  // to the requester.
  API_ENCRYPT_FAILURE:     "audit:api-encrypt-failure",
});

var _emitter = new nodeEvents.EventEmitter();
// Removing the default 10-listener cap on the framework bus — operators
// may wire more than ten listeners (notify, structured-log mirror, audit
// sidecar, file flag writer, etc.) and the warning isn't useful here.
_emitter.setMaxListeners(0);

function on(name, fn) {
  _emitter.on(name, fn);
  return _emitter;
}

function off(name, fn) {
  _emitter.off(name, fn);
  return _emitter;
}

function once(name, fn) {
  _emitter.once(name, fn);
  return _emitter;
}

// Best-effort emit. A listener throwing must not propagate — framework
// callers (e.g. db.init's chain-verify FATAL path) emit immediately
// before process.exit and can't tolerate a listener crashing the exit
// path. We log+swallow per-listener errors so the rest of the listeners
// still fire.
function emit(name, payload) {
  // rawListeners returns the wrapper functions including the auto-
  // removing wrapper that once() registers. Calling the wrapper triggers
  // its internal removeListener, so once() semantics work even though
  // we don't go through _emitter.emit (which propagates listener throws
  // and would defeat the best-effort contract).
  var listeners = _emitter.rawListeners(name);
  for (var i = 0; i < listeners.length; i++) {
    try {
      listeners[i](payload);
    } catch (e) {
      log.error("listener for event '" + name + "' threw: " +
        ((e && e.message) || String(e)));
    }
  }
  return listeners.length > 0;
}

function listenerCount(name) {
  return _emitter.listenerCount(name);
}

function _resetForTest() {
  _emitter.removeAllListeners();
}

module.exports = {
  on:             on,
  off:            off,
  once:           once,
  emit:           emit,
  listenerCount:  listenerCount,
  EVENTS:         EVENTS,
  _resetForTest:  _resetForTest,
};
