// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.streamThrottle
 * @nav        Network
 * @title      Stream Throttle
 * @order      130
 * @slug       stream-throttle
 *
 * @card
 *   Shared token-bucket bandwidth limiter for `node:stream` pipelines.
 *   Caps aggregate bytes-per-second across N concurrent streams that
 *   draw from the same bucket — the missing primitive between per-
 *   request rate-limit and per-process worker pool.
 *
 * @intro
 *   `b.streamThrottle.create({ bytesPerSec, burstBytes })` returns a
 *   token bucket that hands out `transform()` instances; every
 *   transform consumes from the same shared bucket. Operators wiring
 *   bulk-transfer daemons (object-storage fan-out, log shippers,
 *   replication readers) compose a single throttle and apply it
 *   to every concurrent transfer — N parallel transforms share the
 *   `bytesPerSec` budget rather than each getting their own.
 *
 *   Algorithm:
 *
 *   - Bucket holds up to `burstBytes` tokens (default = `bytesPerSec`,
 *     i.e. one second of headroom). Tokens refill at `bytesPerSec`
 *     bytes per second, capped at `burstBytes`. Refill is computed
 *     lazily on every chunk write so there is no per-throttle timer.
 *   - On each chunk, the transform asks the bucket for the chunk's
 *     byte count. If enough tokens are available, the chunk passes
 *     immediately and the tokens are decremented. If not, the
 *     transform sleeps for `ceil((bytes - tokens) / bytesPerSec * 1000)`
 *     ms and then retries — the chunk is forwarded as-is once the
 *     debt is paid.
 *
 *   Composes with:
 *
 *   - `node:stream.pipeline(src, throttle.transform(), dst)` — the
 *     transform is a regular `stream.Transform`, so backpressure
 *     flows in both directions without operator wiring.
 *   - `b.appShutdown` — the throttle has no background timer; once
 *     every transform finishes its `_transform`, the bucket is
 *     garbage-collected with the surrounding daemon.
 *
 *   Refusal posture:
 *
 *   - `bytesPerSec <= 0` / non-finite throws `stream-throttle/bad-rate`.
 *   - `burstBytes < bytesPerSec` throws `stream-throttle/bad-burst`
 *     (smaller burst than refill rate would stall on a single full-rate
 *     chunk forever).
 *   - Chunks larger than `burstBytes` would never fit in the bucket;
 *     `transform({ allowOversize: true })` opts into splitting them
 *     across multiple wait windows. Default refuses with a typed error
 *     so operators catch this at config time.
 *
 *   RFC + reference:
 *
 *   - [RFC 2697 srTCM](https://www.rfc-editor.org/rfc/rfc2697.html) — single-rate
 *     three-color marker, the canonical token-bucket shape this primitive
 *     implements (single PIR + CBS, no committed burst tier).
 *   - [Wikipedia: Token bucket](https://en.wikipedia.org/wiki/Token_bucket).
 */

var nodeStream = require("node:stream");
var { defineClass } = require("./framework-error");

var StreamThrottleError = defineClass("StreamThrottleError", { alwaysPermanent: true });

// Milliseconds-per-second conversion factor — used for rate arithmetic
// (bytes/sec ↔ wait-ms). This is a unit-conversion constant, not a
// memory cap or protocol-byte literal; the framework's C.TIME / C.BYTES
// helpers don't apply.
var MS_PER_SECOND = 1000;
var NS_PER_MS     = 1e6;                                                                              // ns/ms unit conversion
var MS_PER_SECOND_HRTIME = 1000;

/**
 * @primitive b.streamThrottle.create
 * @signature b.streamThrottle.create(opts)
 * @since     0.10.13
 * @status    stable
 * @related   b.streamThrottle
 *
 * Create a shared token bucket. Returns `{ transform(opts?), state() }`.
 * `transform(tOpts?)` returns a `stream.Transform` that consumes from
 * the shared bucket; multiple transforms returned from the same
 * bucket share the rate budget. `state()` returns
 * `{ bytesPerSec, burstBytes, tokens, lastRefillMs }` for observation.
 *
 * Refill resilience: `_refill` clamps elapsed-since-last-refill to
 * the "empty-to-full" duration (`burstBytes / bytesPerSec` seconds)
 * so an NTP clock step or VM resume can't credit hours of pent-up
 * tokens into the bucket in a single call.
 *
 * @opts
 *   bytesPerSec:  number,    // refill rate (bytes per second; required, > 0)
 *   burstBytes:   number,    // bucket capacity (default = bytesPerSec)
 *
 * `transform(tOpts)` opts:
 *   allowOversize: boolean,  // permit chunks larger than burstBytes (default false)
 *   maxWaitMs:     number,   // per-chunk wait ceiling — when set, any
 *                            //   computed wait > maxWaitMs refuses the chunk
 *                            //   with `stream-throttle/wait-exceeds-max`
 *                            //   instead of silently pinning the pipeline.
 *
 * @example
 *   var throttle = b.streamThrottle.create({ bytesPerSec: 5 * 1024 * 1024 });
 *   await new Promise(function (resolve, reject) {
 *     require("node:stream").pipeline(src, throttle.transform(), dst,
 *       function (e) { return e ? reject(e) : resolve(); });
 *   });
 */
function create(opts) {
  opts = opts || {};
  if (typeof opts.bytesPerSec !== "number" || !isFinite(opts.bytesPerSec) || opts.bytesPerSec <= 0) {
    throw new StreamThrottleError("stream-throttle/bad-rate",
      "streamThrottle.create: opts.bytesPerSec must be a finite number > 0, got " + opts.bytesPerSec);
  }
  var bytesPerSec = opts.bytesPerSec;
  var burstBytes  = opts.burstBytes !== undefined ? opts.burstBytes : bytesPerSec;
  if (typeof burstBytes !== "number" || !isFinite(burstBytes) || burstBytes <= 0) {
    throw new StreamThrottleError("stream-throttle/bad-burst",
      "streamThrottle.create: opts.burstBytes must be a finite number > 0, got " + burstBytes);
  }
  if (burstBytes < bytesPerSec) {
    throw new StreamThrottleError("stream-throttle/bad-burst",
      "streamThrottle.create: opts.burstBytes (" + burstBytes + ") must be >= bytesPerSec (" +
      bytesPerSec + ") — a smaller burst than refill rate stalls forever on a single full-rate chunk");
  }
  var tokens     = burstBytes;
  var lastRefill = _hrtimeMs();

  // Cap how far elapsed-since-last-refill can stretch in one call.
  // Without the cap, a system clock jump (NTP step / VM resume / a
  // process suspended in a debugger) credits the bucket with enough
  // tokens to drain hours of pent-up backlog in a single chunk —
  // defeating the rate ceiling for the recovery window. The cap
  // is `burstBytes / bytesPerSec` seconds — exactly the time it
  // takes to refill an empty bucket to full at the configured rate
  // — so legitimate idle periods recover correctly while clock
  // skew never overshoots.
  var maxElapsedMs = Math.ceil((burstBytes / bytesPerSec) * MS_PER_SECOND);

  function _refill() {
    var now      = _hrtimeMs();
    var elapsed  = now - lastRefill;
    if (elapsed > maxElapsedMs) elapsed = maxElapsedMs;
    if (elapsed > 0) {
      tokens     = Math.min(burstBytes, tokens + (elapsed / MS_PER_SECOND) * bytesPerSec);
      lastRefill = now;
    }
  }

  function _consume(bytes, allowOversize) {
    if (bytes > burstBytes && !allowOversize) {
      throw new StreamThrottleError("stream-throttle/oversize-chunk",
        "chunk of " + bytes + " bytes exceeds burstBytes=" + burstBytes +
        "; pass transform({ allowOversize: true }) to split across wait windows");
    }
    _refill();
    if (tokens >= bytes) {
      tokens -= bytes;
      return 0;
    }
    // Bucket has a deficit. Deduct the full chunk's bytes — the bucket
    // goes negative — and tell the caller to wait for the deficit to
    // refill. Subsequent _refill() calls re-accumulate from there, so
    // the next consume sees an accurate budget. A parallel transform
    // hitting the same bucket while it is negative also waits.
    var deficitBytes = bytes - tokens;
    var waitMs       = Math.ceil((deficitBytes / bytesPerSec) * MS_PER_SECOND);
    tokens -= bytes;
    return waitMs;
  }

  function transform(tOpts) {
    tOpts = tOpts || {};
    var allowOversize = tOpts.allowOversize === true;
    // Per-chunk wait ceiling. A misconfigured operator passing
    // chunkBytes / bytesPerSec ratios that schedule a 10-minute
    // single-chunk wait would otherwise pin the pipeline silently;
    // when `maxWaitMs` is set, any computed wait > maxWaitMs refuses
    // the chunk with `stream-throttle/wait-exceeds-max`. Defaults to
    // omitted (no ceiling) for back-compat with operators wanting
    // the historical "wait however long" behavior.
    var maxWaitMs = tOpts.maxWaitMs;
    if (maxWaitMs !== undefined &&
        (typeof maxWaitMs !== "number" || !isFinite(maxWaitMs) || maxWaitMs <= 0)) {
      throw new StreamThrottleError("stream-throttle/bad-max-wait",
        "transform: maxWaitMs must be a finite number > 0, got " + maxWaitMs);
    }
    return new nodeStream.Transform({
      transform: function (chunk, _enc, cb) {
        var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        var bytes = buf.length;
        var waitMs;
        try { waitMs = _consume(bytes, allowOversize); }
        catch (e) { cb(e); return; }
        if (maxWaitMs !== undefined && waitMs > maxWaitMs) {
          cb(new StreamThrottleError("stream-throttle/wait-exceeds-max",
            "computed wait " + waitMs + "ms exceeds maxWaitMs=" + maxWaitMs +
            " (chunk=" + bytes + " bytes, rate=" + bytesPerSec + " bytes/s) — " +
            "reduce chunk size, increase rate, or raise maxWaitMs"));
          return;
        }
        if (waitMs === 0) { cb(null, buf); return; }
        setTimeout(function () { cb(null, buf); }, waitMs);
      },
    });
  }

  function state() {
    _refill();
    return {
      bytesPerSec: bytesPerSec,
      burstBytes:  burstBytes,
      tokens:      tokens,
      lastRefillMs: lastRefill,
    };
  }

  return { transform: transform, state: state };
}

function _hrtimeMs() {
  // hrtime returns [s, ns] integer pair; convert to ms float.
  var t = process.hrtime();
  return t[0] * MS_PER_SECOND_HRTIME + t[1] / NS_PER_MS;
}

module.exports = {
  create:              create,
  StreamThrottleError: StreamThrottleError,
};
