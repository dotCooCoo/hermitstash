// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// #126: SSE _writeRaw wrote to the response with no regard for backpressure
// and no bound on the outbound buffer. res.write() returns false when the
// socket's send buffer is full; a slow/stalled client never drains, so the
// server's writable buffer (res.writableLength) grows without bound — one
// stuck connection can exhaust the server heap (memory-exhaustion DoS).
//
// The fix caps the per-channel buffered bytes (maxBufferedBytes) and evicts
// the slow consumer (closes the channel + throws sse/backpressure) once the
// buffer blows the cap, instead of buffering indefinitely.
//
// RED on the buggy tree: send() can be called unbounded against a stalled
// client and never refuses; the channel stays open. GREEN after the fix:
// send() throws sse/backpressure once the buffer exceeds the cap and the
// channel is closed.

var EventEmitter = require("events");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// A response whose socket never drains: every write accumulates into
// writableLength and write() reports backpressure (false) past the highwater.
function _stalledRes(highWaterBytes) {
  var res = new EventEmitter();
  var buffered = 0;
  res.writableLength = 0;
  res.setHeader   = function () {};
  res.flushHeaders = function () {};
  res.write = function (chunk) {
    buffered += Buffer.byteLength(chunk, "utf8");
    res.writableLength = buffered;        // stalled client: nothing is ever flushed
    return buffered < highWaterBytes;     // false once over the socket highwater
  };
  res.end = function () {};
  return res;
}

async function run() {
  var req = { method: "GET", url: "/events", headers: {}, httpVersionMajor: 1, on: function () {} };
  var res = _stalledRes(b.constants.BYTES.kib(64));

  var capBytes = b.constants.BYTES.kib(8);
  var channel = b.sse.create(req, res, {
    heartbeatMs:      0,           // no heartbeat noise
    audit:            false,
    maxBufferedBytes: capBytes,
  });

  var threw = null;
  var sends = 0;
  var event = { data: "x".repeat(512) };   // ~520 bytes serialized
  try {
    for (var i = 0; i < 100000 && threw === null; i++) {
      channel.send(event);
      sends += 1;
    }
  } catch (e) { threw = e; }

  check("#126 send() refuses once the outbound buffer blows maxBufferedBytes",
        threw !== null && threw.code === "sse/backpressure");
  check("#126 the slow-consumer channel is closed on eviction",
        channel.closed === true);
  // The buffer cap is ~8 KiB and events are ~520 B, so eviction must fire
  // within a few dozen sends — never the full 100k unbounded loop.
  check("#126 buffering is bounded (evicted well before the unbounded loop ended)",
        sends > 0 && sends < 1000);
  check("#126 res.writableLength stayed near the cap, not unbounded",
        res.writableLength < capBytes + b.constants.BYTES.kib(2));

  // A HEALTHY client (write() drains, writableLength stays ~0) is never evicted.
  var healthyRes = new EventEmitter();
  healthyRes.writableLength = 0;
  healthyRes.setHeader = function () {};
  healthyRes.flushHeaders = function () {};
  healthyRes.write = function () { healthyRes.writableLength = 0; return true; };
  healthyRes.end = function () {};
  var healthy = b.sse.create(req, healthyRes, { heartbeatMs: 0, audit: false, maxBufferedBytes: capBytes });
  for (var j = 0; j < 5000; j++) healthy.send(event);
  check("#126 a healthy (draining) client is never evicted by the cap",
        healthy.closed === false);
  healthy.close();

  console.log("OK — sse backpressure / bounded-buffer tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
