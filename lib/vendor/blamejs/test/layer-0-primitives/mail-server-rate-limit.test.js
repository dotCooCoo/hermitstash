// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("surface: b.mail.server.rateLimit namespace",
    typeof b.mail.server.rateLimit === "object");
  check("surface: create is fn", typeof b.mail.server.rateLimit.create === "function");
  check("surface: DEFAULTS object", typeof b.mail.server.rateLimit.DEFAULTS === "object");
  check("surface: error class",   typeof b.mail.server.rateLimit.MailServerRateLimitError === "function");
}

function testBadOptsRefused() {
  function expectThrow(label, opts, codeMatch) {
    var threw = null;
    try { b.mail.server.rateLimit.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses negative concurrent-per-ip",
    { maxConcurrentConnectionsPerIp: -5 }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses Infinity rate",
    { connectionsPerIpPerMinute: Infinity }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses non-integer auth-failure cap",
    { authFailuresPerIpPer15Min: 1.5 }, "mail-server-rate-limit/bad-bound");
  expectThrow("refuses non-bool disabled",
    { disabled: "yes" }, "mail-server-rate-limit/bad-disabled");
  expectThrow("refuses array as opts",
    [], "mail-server-rate-limit/bad-opts");
}

function testConcurrentCap() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 3,
    connectionsPerIpPerMinute:     100,    // headroom — rate isn't the gate here
  });
  check("admit #1", rl.admitConnection("1.2.3.4").ok === true);
  check("admit #2", rl.admitConnection("1.2.3.4").ok === true);
  check("admit #3", rl.admitConnection("1.2.3.4").ok === true);
  var refuse4 = rl.admitConnection("1.2.3.4");
  check("admit #4 refused (cap=3)",
    refuse4.ok === false && refuse4.reason === "concurrent-per-ip");
  // Different IP — its own slot
  check("admit #1 from other IP", rl.admitConnection("5.6.7.8").ok === true);
  // release frees a slot
  rl.releaseConnection("1.2.3.4");
  check("admit after release", rl.admitConnection("1.2.3.4").ok === true);
}

function testRatePerMinuteCap() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 1000,   // headroom — concurrent isn't the gate
    connectionsPerIpPerMinute:     5,
  });
  for (var i = 0; i < 5; i += 1) {
    var v = rl.admitConnection("9.9.9.9");
    check("rate admit #" + (i + 1), v.ok === true);
    rl.releaseConnection("9.9.9.9");   // close immediately, only rate matters
  }
  var refused = rl.admitConnection("9.9.9.9");
  check("rate admit #6 refused",
    refused.ok === false && refused.reason === "rate-per-ip");
}

function testAuthFailureBudget() {
  var rl = b.mail.server.rateLimit.create({
    authFailuresPerIpPer15Min: 3,
  });
  check("auth admit clean by default", rl.checkAuthAdmit("11.22.33.44").ok === true);
  rl.noteAuthFailure("11.22.33.44");
  rl.noteAuthFailure("11.22.33.44");
  rl.noteAuthFailure("11.22.33.44");
  var refused = rl.checkAuthAdmit("11.22.33.44");
  check("auth admit refused at cap",
    refused.ok === false && refused.reason === "auth-failures-per-ip");
  // Different IP unaffected
  check("auth admit clean for other IP", rl.checkAuthAdmit("44.55.66.77").ok === true);
}

function testDisabledSkipsAll() {
  var rl = b.mail.server.rateLimit.create({
    maxConcurrentConnectionsPerIp: 1,
    connectionsPerIpPerMinute:     1,
    authFailuresPerIpPer15Min:     1,
    disabled:                      true,
  });
  // Even way past the caps, admit always returns ok
  for (var i = 0; i < 50; i += 1) {
    check("disabled admit #" + i, rl.admitConnection("0.0.0.0").ok === true);
  }
  for (var j = 0; j < 50; j += 1) rl.noteAuthFailure("0.0.0.0");
  check("disabled auth admit always ok",
    rl.checkAuthAdmit("0.0.0.0").ok === true);
  check("disabled isDisabled() returns true", rl.isDisabled() === true);
}

// ---- b.mail.server.rateLimit.resolve — spec → limiter contract ----
//
// Every mail server (IMAP / POP3 / SMTP MX / Submission / ManageSieve)
// runs its operator-supplied `rateLimit` opt through resolve() so the
// spec contract is identical across protocols: `false` disables,
// an already-built limiter passes through untouched, anything else is
// treated as create() options.
function testResolveFalseDisables() {
  var rl = b.mail.server.rateLimit.resolve(false);
  check("resolve(false): returns a disabled limiter", rl.isDisabled() === true);
  // A disabled limiter always admits, even far past any cap.
  var allOk = true;
  for (var i = 0; i < 50; i += 1) {
    if (rl.admitConnection("203.0.113.7").ok !== true) { allOk = false; break; }
  }
  check("resolve(false): admitConnection always admits", allOk === true);
}

function testResolvePassesThroughExistingLimiter() {
  var made = b.mail.server.rateLimit.create({ maxConcurrentConnectionsPerIp: 1 });
  var resolved = b.mail.server.rateLimit.resolve(made);
  check("resolve(limiter): returns the SAME limiter object unchanged",
    resolved === made);
}

function testResolveOptsBuildLimiter() {
  // A plain-object spec is treated as create() options — the cap must
  // actually take effect (proves the opts flowed through create()).
  var rl = b.mail.server.rateLimit.resolve({ maxConcurrentConnectionsPerIp: 1 });
  check("resolve(opts): typeof is a built limiter", typeof rl.admitConnection === "function");
  check("resolve(opts): admit #1 ok", rl.admitConnection("198.51.100.9").ok === true);
  var refused = rl.admitConnection("198.51.100.9");
  check("resolve(opts): admit #2 refused at cap=1",
    refused.ok === false && refused.reason === "concurrent-per-ip");
  check("resolve(opts): not disabled", rl.isDisabled() === false);
}

function testResolveUndefinedUsesDefaults() {
  // resolve() / resolve(null) → create({}) with defaults: a working,
  // non-disabled limiter that admits within the default cap.
  var rlUndef = b.mail.server.rateLimit.resolve();
  check("resolve(undefined): returns a working limiter",
    typeof rlUndef.admitConnection === "function" && rlUndef.isDisabled() === false);
  check("resolve(undefined): admits a first connection",
    rlUndef.admitConnection("192.0.2.5").ok === true);

  var rlNull = b.mail.server.rateLimit.resolve(null);
  check("resolve(null): returns a working limiter",
    typeof rlNull.admitConnection === "function" && rlNull.isDisabled() === false);
}

function run() {
  testSurface();
  testBadOptsRefused();
  testConcurrentCap();
  testRatePerMinuteCap();
  testAuthFailureBudget();
  testDisabledSkipsAll();
  testResolveFalseDisables();
  testResolvePassesThroughExistingLimiter();
  testResolveOptsBuildLimiter();
  testResolveUndefinedUsesDefaults();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-rate-limit] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
