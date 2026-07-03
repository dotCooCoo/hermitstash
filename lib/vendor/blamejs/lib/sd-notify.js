// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.sdNotify
 * @nav    Process
 * @title  systemd Notify
 *
 * @intro
 *   `sd_notify` protocol surface for daemons running under
 *   `Type=notify` systemd units. Composes the standard lifecycle
 *   messages — `READY=1` on boot, `WATCHDOG=1` on heartbeat,
 *   `STOPPING=1` on shutdown, `RELOADING=1` on hot-reload — against
 *   the `$NOTIFY_SOCKET` env var systemd populates for the child
 *   process.
 *
 *   Transport: Node has no unix-DGRAM socket support in its `dgram`
 *   module, so the v1 path shells out to `systemd-notify(1)` via
 *   `execFile` (NOT `exec` — no shell-string parsing on the
 *   message bytes). Operators running under systemd already have
 *   `systemd-tools` installed by definition, so the dependency is
 *   no expansion of the trust surface.
 *
 *   Compose with `b.appShutdown` for the STOPPING signal: register a
 *   priority-0 phase that calls `b.sdNotify.stopping()` so systemd
 *   sees the shutdown intent before the framework tears anything
 *   down. Compose with a periodic `WATCHDOG=1` against the unit's
 *   `WatchdogSec=` interval so systemd auto-restarts the daemon if
 *   the event loop wedges.
 *
 *   When `$NOTIFY_SOCKET` is unset (process running outside systemd
 *   — bare invocation, foreground dev, container without
 *   `--notify-ready`), every call is a no-op that surfaces a single
 *   boot-time audit entry. Operators get observability of the
 *   degraded state without per-call log noise.
 *
 * @card
 *   sd_notify protocol for systemd Type=notify daemons — READY / WATCHDOG / STOPPING / RELOADING. Composes b.appShutdown for shutdown signaling.
 */

var { execFile } = require("node:child_process");
var C = require("./constants");
var safeEnv = require("./parsers/safe-env");
var audit = require("./audit");
var { defineClass } = require("./framework-error");

var SdNotifyError = defineClass("SdNotifyError", { alwaysPermanent: true });

// Whitelist of sd_notify state= values we ship as named helpers. The
// underlying `send({ state })` accepts any string but the helpers are
// the operator-facing surface — `READY=1` etc. — and the audit log
// records the named state, not arbitrary payload bytes.
var KNOWN_STATES = Object.freeze({
  ready:     "READY=1",
  stopping:  "STOPPING=1",
  reloading: "RELOADING=1",
  watchdog:  "WATCHDOG=1",
});

function _notifySocketPath() {
  var p = safeEnv.readVar("NOTIFY_SOCKET");
  if (typeof p !== "string" || p.length === 0) return null;
  // Abstract namespace socket (Linux-only) prefixed with `@` —
  // systemd-notify(1) accepts the same form, so we don't normalize.
  return p;
}

function _runNotify(payload) {
  return new Promise(function (resolve, reject) {
    var args = [];
    var lines = String(payload).split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      if (lines[i].length > 0) args.push(lines[i]);
    }
    if (args.length === 0) { resolve(); return; }
    // execFile (not exec) — no shell evaluation; the message bytes
    // pass through argv exactly. systemd-notify accepts one or more
    // KEY=VALUE arguments. The `--no-block` flag returns immediately
    // without waiting for the notification to be processed.
    execFile("systemd-notify", ["--no-block"].concat(args),
      { timeout: C.TIME.seconds(5), windowsHide: true },
      function (err) {
        if (err) reject(err);
        else resolve();
      });
  });
}

/**
 * @primitive b.sdNotify.send
 * @signature b.sdNotify.send(opts)
 * @since     0.10.8
 * @status    stable
 * @related   b.sdNotify.ready, b.sdNotify.stopping, b.appShutdown.create
 *
 * Generic sd_notify dispatch. Sends one or more `KEY=VALUE` payload
 * lines to systemd via `systemd-notify(1)`. No-op when
 * `$NOTIFY_SOCKET` is unset (foreground / container without
 * `--notify-ready` / non-systemd init). Returns a Promise resolving
 * on dispatch success.
 *
 * @opts
 *   state:    string,                     // e.g. "READY=1" / "STOPPING=1"
 *   status:   string,                     // free-form status text → `STATUS=`
 *   mainpid:  number,                     // PID override → `MAINPID=`
 *   audit:    boolean,                     // default true
 *
 * @example
 *   await b.sdNotify.send({ state: "READY=1", status: "Listening on :8080" });
 */
function send(opts) {
  opts = opts || {};
  var lines = [];
  if (typeof opts.state === "string" && opts.state.length > 0) lines.push(opts.state);
  if (typeof opts.status === "string" && opts.status.length > 0) {
    // STATUS= permits arbitrary UTF-8 except newline — refuse newline
    // so a hostile status string can't smuggle a second key.
    if (opts.status.indexOf("\n") !== -1 || opts.status.indexOf("\r") !== -1) {
      throw new SdNotifyError("sd-notify/control-char-in-status",
        "send: status field must not contain CR/LF (sd_notify framing)");
    }
    lines.push("STATUS=" + opts.status);
  }
  if (opts.mainpid !== undefined) {
    if (typeof opts.mainpid !== "number" || !isFinite(opts.mainpid) ||
        Math.floor(opts.mainpid) !== opts.mainpid || opts.mainpid < 1) {
      throw new SdNotifyError("sd-notify/bad-mainpid",
        "send: mainpid must be a positive integer");
    }
    lines.push("MAINPID=" + opts.mainpid);
  }
  if (lines.length === 0) return Promise.resolve();

  var socketPath = _notifySocketPath();
  if (socketPath === null) {
    if (opts.audit !== false) {
      try {
        audit.safeEmit({
          action:   "sdnotify.send.skipped",
          outcome:  "denied",
          metadata: { reason: "no-notify-socket", state: opts.state || null },
        });
      } catch (_e) { /* drop-silent */ }
    }
    return Promise.resolve();
  }
  var auditOn = opts.audit !== false;
  return _runNotify(lines.join("\n")).then(function () {
    if (auditOn) {
      try {
        audit.safeEmit({
          action:   "sdnotify.send",
          outcome:  "success",
          metadata: { state: opts.state || null, status: opts.status || null },
        });
      } catch (_e) { /* drop-silent */ }
    }
  }).catch(function (err) {
    if (auditOn) {
      try {
        audit.safeEmit({
          action:   "sdnotify.send",
          outcome:  "failure",
          metadata: { state: opts.state || null, error: (err && err.message) || String(err) },
        });
      } catch (_e2) { /* drop-silent */ }
    }
    throw new SdNotifyError("sd-notify/dispatch-failed",
      "send: systemd-notify dispatch failed: " + ((err && err.message) || String(err)));
  });
}

/**
 * @primitive b.sdNotify.ready
 * @signature b.sdNotify.ready(opts?)
 * @since     0.10.8
 * @status    stable
 * @related   b.sdNotify.send, b.sdNotify.stopping
 *
 * Send `READY=1` to systemd, signaling boot complete. Use once the
 * listener is bound and the daemon is accepting work.
 *
 * @opts
 *   status:  string,    // free-form status text → STATUS=
 *
 * @opts
 *   status:  string,    // free-form status text → STATUS=
 *   audit:   boolean,    // default true
 *
 * @example
 *   await b.sdNotify.ready({ status: "Listening on :8080" });
 */
function ready(opts) {
  return send(Object.assign({}, opts || {}, { state: KNOWN_STATES.ready }));
}

/**
 * @primitive b.sdNotify.stopping
 * @signature b.sdNotify.stopping(opts?)
 * @since     0.10.8
 * @status    stable
 * @related   b.sdNotify.send, b.appShutdown.create
 *
 * Send `STOPPING=1`. Operators wire this into `b.appShutdown` as the
 * earliest shutdown phase (priority 0) so systemd sees the shutdown
 * intent before any teardown begins.
 *
 * @opts
 *   status:  string,    // free-form status text → STATUS=
 *   audit:   boolean,    // default true
 *
 * @example
 *   b.appShutdown.create({ name: "sd-notify-stopping", priority: 0,
 *     run: function () { return b.sdNotify.stopping(); } });
 */
function stopping(opts) {
  return send(Object.assign({}, opts || {}, { state: KNOWN_STATES.stopping }));
}

/**
 * @primitive b.sdNotify.reloading
 * @signature b.sdNotify.reloading(opts?)
 * @since     0.10.8
 * @status    stable
 *
 * Send `RELOADING=1` then (after the reload completes) `READY=1`.
 * Use during hot-config-reload paths; systemd treats the unit as
 * "reloading" until the next `READY=1`.
 *
 * @opts
 *   status:  string,    // free-form status text → STATUS=
 *   audit:   boolean,    // default true
 *
 * @example
 *   await b.sdNotify.reloading();
 *   await reloadConfig();
 *   await b.sdNotify.ready();
 */
function reloading(opts) {
  return send(Object.assign({}, opts || {}, { state: KNOWN_STATES.reloading }));
}

/**
 * @primitive b.sdNotify.watchdog
 * @signature b.sdNotify.watchdog(opts?)
 * @since     0.10.8
 * @status    stable
 *
 * Send `WATCHDOG=1`. Operators with `WatchdogSec=` configured on
 * their unit call this periodically (e.g. every `WatchdogSec/2`)
 * so systemd auto-restarts the daemon when the event loop wedges.
 *
 * @opts
 *   audit:   boolean,    // default true
 *
 * @example
 *   setInterval(function () { b.sdNotify.watchdog(); }, 15000);
 */
function watchdog(opts) {
  return send(Object.assign({}, opts || {}, { state: KNOWN_STATES.watchdog }));
}

module.exports = {
  send:          send,
  ready:         ready,
  stopping:      stopping,
  reloading:     reloading,
  watchdog:      watchdog,
  isAvailable:   function () { return _notifySocketPath() !== null; },
  SdNotifyError: SdNotifyError,
};
