// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");
var safeAsync = require("./safe-async");

function tearDownH2Session(session) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e1) { /* best-effort graceful */ }
  try { if (typeof session.destroy === "function") session.destroy(); }
  catch (_e2) { /* best-effort socket teardown */ }
}

var DEFAULT_DRAIN_GRACE_MS = C.TIME.seconds(30);
function drainH2Session(session, graceMs) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e) { /* best-effort graceful close */ }
  var grace = typeof graceMs === "number" && graceMs > 0 ? graceMs : DEFAULT_DRAIN_GRACE_MS;

  var lastMoved = null;
  var watch = safeAsync.repeating(function () {
    if (session.destroyed) { watch.stop(); return; }
    var sock = session.socket;
    var moved = sock ? (Number(sock.bytesRead) || 0) + (Number(sock.bytesWritten) || 0) : 0;
    if (moved !== lastMoved) { lastMoved = moved; return; }
    watch.stop();
    try { if (typeof session.destroy === "function") session.destroy(); }
    catch (_e) { /* best-effort socket teardown */ }
  }, grace, { name: "h2-drain-watch" });
}

module.exports = {
  tearDownH2Session: tearDownH2Session,
  drainH2Session:    drainH2Session,
};
