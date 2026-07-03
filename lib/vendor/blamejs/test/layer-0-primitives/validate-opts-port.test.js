// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.validateOpts.optionalPort — RFC 6335 §6 port-range validator — plus the
// representative connection entry-point wiring (ntpCheck.querySingle; the other
// five sites compose the identical guard).

var helpers     = require("../helpers");
var b           = helpers.b;
var check       = helpers.check;
var redisClient = require("../../lib/redis-client");

function _thrCode(fn) { try { fn(); return null; } catch (e) { return e.code || e.message; } }

function run() {
  var vo = b.validateOpts;
  check("optionalPort is a function", typeof vo.optionalPort === "function");

  // pass-through + valid ports
  check("optionalPort(undefined) → undefined", vo.optionalPort(undefined) === undefined);
  check("optionalPort(null) → null",           vo.optionalPort(null) === null);
  check("optionalPort(443) → 443",             vo.optionalPort(443, "p") === 443);
  check("optionalPort(1) accepted",            vo.optionalPort(1, "p") === 1);
  check("optionalPort(65535) accepted",        vo.optionalPort(65535, "p") === 65535);

  // 0 rejected by default, accepted with allowZero (ephemeral listen-bind)
  check("optionalPort(0) throws by default",   _thrCode(function () { vo.optionalPort(0, "p"); }) !== null);
  check("optionalPort(0, allowZero) → 0",      vo.optionalPort(0, "p", undefined, undefined, { allowZero: true }) === 0);

  // out-of-range / non-integer / wrong-type all throw
  [65536, -1, 0.5, "443", NaN, Infinity, "x", true, {}].forEach(function (bad, i) {
    check("optionalPort rejects bad value #" + i + " (" + String(bad) + ")",
          _thrCode(function () { vo.optionalPort(bad, "p"); }) !== null);
  });
  // 65536 is out of range even with allowZero
  check("optionalPort(65536, allowZero) still throws",
        _thrCode(function () { vo.optionalPort(65536, "p", undefined, undefined, { allowZero: true }); }) !== null);

  // message carries numericBounds.shape() so Infinity / "443" stay visible
  var msg = _thrCode(function () { vo.optionalPort(Infinity, "p"); });
  check("optionalPort message shows the bad shape", typeof msg === "string" && /Infinity/.test(msg));

  // typed-error class + code via a defineClass-built framework error
  check("optionalPort routes a typed error class + code",
        _thrCode(function () { vo.optionalPort(-1, "p", b.ntpCheck.NtpCheckError, "ntp/bad-port"); }) === "ntp/bad-port");

  // plain Error when no errorClass is supplied
  var plain = null;
  try { vo.optionalPort(-1, "p"); } catch (e) { plain = e; }
  check("optionalPort throws a plain Error with no errorClass", (plain instanceof Error) && !plain.code);

  // representative entry-point wiring: ntpCheck.querySingle rejects a bad port
  // synchronously (before the Promise) with a typed NtpCheckError.
  check("b.ntpCheck.NtpCheckError is a constructor", typeof b.ntpCheck.NtpCheckError === "function");
  check("ntpCheck.querySingle({port:-1}) throws ntp/bad-port",
        _thrCode(function () { b.ntpCheck.querySingle("pool.ntp.org", { port: -1 }); }) === "ntp/bad-port");
  check("ntpCheck.querySingle({port:70000}) throws ntp/bad-port",
        _thrCode(function () { b.ntpCheck.querySingle("pool.ntp.org", { port: 70000 }); }) === "ntp/bad-port");

  // A url-supplied connection port must be range-checked too — the opts.port
  // guard alone misses a port resolved from the url, so redis://h:0 (parsed to
  // port 0) would otherwise reach an outbound connect. create() is inert until
  // .connect(), so a valid url throws nothing.
  check("redis url-port 0 rejected at create (resolved-port guard)",
        _thrCode(function () { redisClient.create({ url: "redis://localhost:0" }); }) !== null);
  check("redis url-port out-of-range rejected at create",
        _thrCode(function () { redisClient.create({ url: "redis://localhost:99999" }); }) !== null);
  check("redis valid url-port accepted (no throw at create)",
        _thrCode(function () { redisClient.create({ url: "redis://localhost:6379" }); }) === null);
}

module.exports = { run: run };
