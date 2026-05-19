"use strict";
/**
 * b.sdNotify — sd_notify protocol surface.
 *
 * Tests run in-process without a real $NOTIFY_SOCKET (the helper is
 * a graceful no-op in that mode). End-to-end systemd-notify dispatch
 * is exercised in integration tests when NOTIFY_SOCKET is set.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function testIsAvailableReportsState() {
  var hadSocket = process.env.NOTIFY_SOCKET;
  delete process.env.NOTIFY_SOCKET;
  check("isAvailable false when unset", b.sdNotify.isAvailable() === false);
  process.env.NOTIFY_SOCKET = "/run/sock";
  check("isAvailable true when set",    b.sdNotify.isAvailable() === true);
  if (hadSocket === undefined) delete process.env.NOTIFY_SOCKET;
  else process.env.NOTIFY_SOCKET = hadSocket;
}

async function testNoopWithoutSocket() {
  var hadSocket = process.env.NOTIFY_SOCKET;
  delete process.env.NOTIFY_SOCKET;
  // Should resolve cleanly without spawning systemd-notify.
  await b.sdNotify.ready();
  await b.sdNotify.stopping();
  await b.sdNotify.reloading();
  await b.sdNotify.watchdog({ audit: false });
  check("no-op without NOTIFY_SOCKET resolves", true);
  if (hadSocket === undefined) delete process.env.NOTIFY_SOCKET;
  else process.env.NOTIFY_SOCKET = hadSocket;
  // Typed error class is exported.
  check("SdNotifyError exported", typeof b.sdNotify.SdNotifyError === "function");
}

function testStatusRefusesNewline() {
  var threw = false;
  try {
    b.sdNotify.send({ state: "READY=1", status: "line1\nline2", audit: false });
  } catch (_e) { threw = true; }
  check("CR/LF in status throws", threw);
}

function testMainpidValidation() {
  var threw = false;
  try { b.sdNotify.send({ state: "READY=1", mainpid: 1.5, audit: false }); }
  catch (_e) { threw = true; }
  check("non-int mainpid throws", threw);

  threw = false;
  try { b.sdNotify.send({ state: "READY=1", mainpid: 0, audit: false }); }
  catch (_e) { threw = true; }
  check("zero mainpid throws", threw);
}

async function run() {
  await testIsAvailableReportsState();
  await testNoopWithoutSocket();
  testStatusRefusesNewline();
  testMainpidValidation();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };
