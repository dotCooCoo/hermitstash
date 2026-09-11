// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.events
 * @nav    Other
 * @title  Events
 *
 * @intro
 *   In-process event emitter — namespaced channels, drop-silent on
 *   unknown listeners, audit on registration. A thin wrapper around
 *   Node's `EventEmitter` dedicated to framework-emitted breach-
 *   detection and integrity signals. Operators wire listeners to
 *   PagerDuty / Opsgenie / a Slack webhook / a notification queue and
 *   the framework fires them on the specific high-signal conditions
 *   exported on `EVENTS` (audit chain break, audit checkpoint break,
 *   audit rollback detected, NTP drift, api-encrypt failure).
 *
 *   Best-effort emit semantics: a listener throwing must NOT break
 *   the framework's refuse-to-boot fail-fast. `emit()` catches and
 *   swallows listener errors per-listener so the rest still fire.
 *   Stable event names live on `b.events.EVENTS` so operators
 *   reference `b.events.EVENTS.AUDIT_CHAIN_BREAK` rather than typing
 *   the raw `"audit:chain-break"` string. The default
 *   10-listener cap is removed — operators routinely wire several
 *   notify / structured-log / file-flag listeners on the same event.
 *
 *   Listener handlers should keep work synchronous and short. Several
 *   framework signals lead to `process.exit`, so blocking network
 *   calls inside a listener would delay the fail-fast path; hand off
 *   to a queue or write a sync flag-file from the listener and let an
 *   external watcher do the network call.
 *
 * @card
 *   In-process event emitter — namespaced channels, drop-silent on unknown listeners, audit on registration.
 */

var nodeEvents = require("node:events");
var { boot } = require("./log");

var log = boot("events");

var EVENTS = Object.freeze({
  AUDIT_CHAIN_BREAK:       "audit:chain-break",
  AUDIT_CHECKPOINT_BREAK:  "audit:checkpoint-break",
  AUDIT_ROLLBACK_DETECTED: "audit:rollback-detected",
  NTP_DRIFT:               "audit:ntp-drift",
  API_ENCRYPT_FAILURE:     "audit:api-encrypt-failure",
});

var _emitter = new nodeEvents.EventEmitter();
_emitter.setMaxListeners(0);

/**
 * @primitive b.events.on
 * @signature b.events.on(name, fn)
 * @since     0.4.0
 * @related   b.events.off, b.events.once, b.events.emit
 *
 * Register a listener for one of the stable framework event names on
 * `b.events.EVENTS`. The listener fires every time the framework
 * emits the named event. Listeners may throw — `emit()` swallows the
 * throw and logs it so the emit path stays best-effort, but operators
 * should keep handlers synchronous and short (several framework
 * signals lead to `process.exit`).
 *
 * @example
 *   b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function (info) {
 *     // Sync I/O only — exit may follow.
 *     require("node:fs").writeFileSync(
 *       "/var/run/blamejs-chain-break.flag",
 *       JSON.stringify({ at: Date.now(), info: info })
 *     );
 *   });
 */
function on(name, fn) {
  _emitter.on(name, fn);
  return _emitter;
}

/**
 * @primitive b.events.off
 * @signature b.events.off(name, fn)
 * @since     0.4.0
 * @related   b.events.on, b.events.once
 *
 * Remove a previously-registered listener. The function reference
 * must be the same object passed to `on()` / `once()` — otherwise
 * Node's emitter silently keeps the listener registered.
 *
 * @example
 *   function onBreak(info) { console.error("audit chain break", info); }
 *   b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, onBreak);
 *   // ... later, during teardown:
 *   b.events.off(b.events.EVENTS.AUDIT_CHAIN_BREAK, onBreak);
 *   b.events.listenerCount(b.events.EVENTS.AUDIT_CHAIN_BREAK);   // → 0
 */
function off(name, fn) {
  _emitter.off(name, fn);
  return _emitter;
}

/**
 * @primitive b.events.once
 * @signature b.events.once(name, fn)
 * @since     0.4.0
 * @related   b.events.on, b.events.emit
 *
 * Register a single-fire listener — fires once and auto-removes. The
 * auto-removal is preserved through `b.events.emit` even though emit
 * iterates raw listeners directly to keep the best-effort contract.
 *
 * @example
 *   b.events.once(b.events.EVENTS.NTP_DRIFT, function (payload) {
 *     console.warn("NTP drift detected (first occurrence): " + payload.driftMs + "ms");
 *   });
 */
function once(name, fn) {
  _emitter.once(name, fn);
  return _emitter;
}

/**
 * @primitive b.events.emit
 * @signature b.events.emit(name, payload)
 * @since     0.4.0
 * @related   b.events.on, b.events.once
 *
 * Best-effort fire — invokes every registered listener for `name`,
 * passing `payload`. Listener throws are logged and swallowed
 * per-listener so the rest of the chain still fires; framework
 * callers (e.g. `db.init`'s chain-verify FATAL path) emit immediately
 * before `process.exit` and can't tolerate a listener crashing the
 * exit path. Returns `true` when at least one listener was registered.
 *
 * Operator code rarely emits onto `b.events` directly — the bus is
 * for framework-emitted signals. Calling `emit()` from operator code
 * is supported for tests that want to exercise listener wiring.
 *
 * @example
 *   var fired = false;
 *   b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function () { fired = true; });
 *   var hadListener = b.events.emit(b.events.EVENTS.AUDIT_CHAIN_BREAK, { at: 1 });
 *   hadListener;   // → true
 *   fired;         // → true
 */
function emit(name, payload) {
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

/**
 * @primitive b.events.listenerCount
 * @signature b.events.listenerCount(name)
 * @since     0.4.0
 * @related   b.events.on, b.events.off
 *
 * Diagnostic — returns the number of listeners registered for `name`.
 * Useful in tests and during teardown to confirm `off()` removed the
 * intended listener.
 *
 * @example
 *   b.events.on(b.events.EVENTS.NTP_DRIFT, function () {});
 *   b.events.on(b.events.EVENTS.NTP_DRIFT, function () {});
 *   b.events.listenerCount(b.events.EVENTS.NTP_DRIFT);   // → 2
 */
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
