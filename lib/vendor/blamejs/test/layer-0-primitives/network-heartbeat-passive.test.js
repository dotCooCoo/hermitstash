"use strict";
/**
 * b.network.heartbeat.passive — passive (server-pushes-pings) keepalive
 * watchdog. Exercises recordPong rearming, single-shot onTimeout firing,
 * stop() cancellation, and shape-validation throws.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _delay(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function testSurface() {
  check("network.heartbeat.passive is a function",
        typeof b.network.heartbeat.passive === "function");
}

async function testTimeoutFiresOnce() {
  var fires = 0;
  var pongs = 0;
  var h = b.network.heartbeat.passive({
    timeoutMs: 30,
    onPong: function () { pongs += 1; },
    onTimeout: function () { fires += 1; },
  });
  await _delay(80);
  check("timeout fires once after grace window",
        fires === 1);
  check("no pong callback invoked when no pong recorded",
        pongs === 0);
  await _delay(40);
  check("timeout still single-shot (does not re-fire)",
        fires === 1);
  // recordPong after timeout returns false (already stopped).
  check("recordPong after timeout returns false",
        h.recordPong() === false);
}

async function testRecordPongRearms() {
  var fires = 0;
  var pongs = 0;
  // 200ms timeout + 60ms inter-pong delay so SMOKE_PARALLEL=64 + CI
  // runner contention (setTimeout drift can exceed 50ms under load)
  // doesn't time out before the rearming pongs land.
  var h = b.network.heartbeat.passive({
    timeoutMs: 200,
    onPong:    function (e) { pongs += 1; check("onPong gets pongCount", typeof e.pongCount === "number"); },
    onTimeout: function () { fires += 1; },
  });
  await _delay(60);
  h.recordPong();
  await _delay(60);
  h.recordPong();
  await _delay(60);
  check("no timeout while pongs keep arriving",
        fires === 0);
  check("each recordPong fires onPong",
        pongs === 2);
  await _delay(300);
  check("timeout fires once recordPong stops",
        fires === 1);
  h.stop();
}

async function testStopBeforeTimeout() {
  var fires = 0;
  var h = b.network.heartbeat.passive({
    timeoutMs: 30,
    onTimeout: function () { fires += 1; },
  });
  check("stop() before timeout returns true", h.stop() === true);
  check("stop() second time returns false",   h.stop() === false);
  await _delay(60);
  check("timeout never fires after stop",
        fires === 0);
}

function testValidation() {
  var threw1 = false;
  try { b.network.heartbeat.passive({ onTimeout: "nope" }); }
  catch (e) { threw1 = e.code === "heartbeat/bad-on-timeout"; }
  check("non-function onTimeout throws bad-on-timeout", threw1);

  var threw2 = false;
  try {
    b.network.heartbeat.passive({
      timeoutMs: -1,
      onTimeout: function () {},
    });
  } catch (e) { threw2 = e.code === "heartbeat/bad-timeout"; }
  check("negative timeoutMs throws bad-timeout", threw2);

  var threw3 = false;
  try {
    b.network.heartbeat.passive({
      onTimeout: function () {},
      onPong:    "not-a-fn",
    });
  } catch (e) { threw3 = e.code === "heartbeat/bad-on-pong"; }
  check("non-function onPong throws bad-on-pong", threw3);

  var threw4 = false;
  try {
    b.network.heartbeat.passive({
      onTimeout: function () {},
      bogus:     true,
    });
  } catch (e) { threw4 = /unknown option/.test(e.message); }
  check("unknown opts key refuses via validateOpts", threw4);
}

async function run() {
  testSurface();
  await testTimeoutFiresOnce();
  await testRecordPongRearms();
  await testStopBeforeTimeout();
  testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
