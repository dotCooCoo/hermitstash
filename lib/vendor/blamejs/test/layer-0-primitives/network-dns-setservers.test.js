// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.setServers — resolver-list validation and failure atomicity.
 *
 * setServers takes an operator-supplied resolver list, so it is a config-time
 * entry point: bad input must throw a typed DnsError, and a rejected list must
 * leave the previously-configured resolvers in place.
 *
 * The port is validated here rather than deferred to node:dns because node:dns
 * does not merely reject an IPv4 resolver whose explicit port is zero — it
 * fails a native assertion and ABORTS the process (exit 134,
 * `node::cares_wrap::SetServers`, cares_wrap.cc). That abort is not catchable,
 * so an operator config carrying `1.2.3.4:0` would be an unrecoverable crash
 * rather than a startup error.
 *
 * The zero-port case therefore runs in a CHILD process: if the validation is
 * ever removed, this test must report a failure rather than kill the runner it
 * is running inside.
 */

var nodeChildProcess = require("node:child_process");
var nodePath = require("node:path");
var helpers = require("../helpers");

var b = helpers.b;
var check = helpers.check;

var REPO_ROOT = nodePath.join(__dirname, "..", "..");

// Run one setServers candidate in a child and report how the process ended.
function _inChild(server) {
  var script =
    "var d = require(" + JSON.stringify(nodePath.join(REPO_ROOT, "index.js").split("\\").join("/")) + ").network.dns;" +
    "try { d.setServers([process.argv[1]]); console.log('ACCEPTED'); }" +
    "catch (e) { console.log('THREW ' + (e.code || e.message)); }";
  var rv = nodeChildProcess.spawnSync(process.execPath, ["-e", script, server], { encoding: "utf8" });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").trim().split("\n").pop() || "",
    aborted: rv.status === 134 || /Assertion failed/.test(rv.stderr || ""),
  };
}

function testZeroPortDoesNotAbortTheProcess() {
  // The exact shape that trips the native assertion.
  var zero = _inChild("127.0.0.1:0");
  check("setServers: a zero-port IPv4 resolver does NOT abort the process",
    zero.aborted === false);
  check("setServers: a zero-port IPv4 resolver exits cleanly having thrown",
    zero.status === 0 && /^THREW dns\//.test(zero.stdout));

  // Leading zeros parse to the same port and trip the same assertion.
  var zeroPadded = _inChild("127.0.0.1:00");
  check("setServers: a zero-padded zero port does NOT abort the process",
    zeroPadded.aborted === false);
  check("setServers: a zero-padded zero port exits cleanly having thrown",
    zeroPadded.status === 0 && /^THREW dns\//.test(zeroPadded.stdout));

  // The bracketed IPv6 form reaches a different code path in node:dns that
  // never aborted; it must still be refused, for one consistent contract.
  var v6Zero = _inChild("[::1]:0");
  check("setServers: a zero-port IPv6 resolver is refused too, not accepted",
    v6Zero.status === 0 && /^THREW dns\//.test(v6Zero.stdout));

  // A resolver the framework accepts must still be accepted in a child.
  var good = _inChild("127.0.0.1:53");
  check("setServers: a well-formed resolver with a port is still accepted",
    good.status === 0 && good.stdout === "ACCEPTED");
}

function _refuses(label, server, code) {
  var err = null;
  try { b.network.dns.setServers([server]); } catch (e) { err = e; }
  check(label, !!err && err.name === "DnsError" && (!code || err.code === code));
}

function testPortRangeIsValidated() {
  // 65536 is one past the maximum. node:dns accepted it silently, so a typo'd
  // port reached the resolver layer instead of failing at configuration.
  _refuses("setServers: a port above 65535 is refused", "127.0.0.1:65536");
  _refuses("setServers: a wildly out-of-range port is refused", "127.0.0.1:999999");

  // These already failed inside node:dns; they must keep failing, as DnsError.
  _refuses("setServers: a negative port is refused", "127.0.0.1:-1");
  _refuses("setServers: a non-numeric port is refused", "127.0.0.1:x");
  _refuses("setServers: an empty port is refused", "127.0.0.1:");

  // Shape guards that predate this hardening.
  _refuses("setServers: a non-IP string is refused", "not-an-ip");
  _refuses("setServers: an empty string entry is refused", "", "dns/bad-server");

  var errArr = null;
  try { b.network.dns.setServers([]); } catch (e) { errArr = e; }
  check("setServers: an empty list is refused",
    !!errArr && errArr.code === "dns/bad-servers");

  var errType = null;
  try { b.network.dns.setServers([42]); } catch (e) { errType = e; }
  check("setServers: a non-string entry is refused",
    !!errType && errType.code === "dns/bad-server");
}

function testValidResolversAreStillAccepted() {
  b.network.dns.setServers(["127.0.0.1"]);
  check("setServers: a bare IPv4 resolver is accepted",
    b.network.dns.getServers().indexOf("127.0.0.1") !== -1);

  b.network.dns.setServers(["127.0.0.1:5353"]);
  check("setServers: an IPv4 resolver with a port is accepted",
    b.network.dns.getServers().join(",").indexOf("127.0.0.1") !== -1);

  b.network.dns.setServers(["[::1]:5353"]);
  check("setServers: a bracketed IPv6 resolver with a port is accepted",
    b.network.dns.getServers().length === 1);

  b.network.dns.setServers(["::1"]);
  check("setServers: a bare IPv6 resolver is accepted",
    b.network.dns.getServers().length === 1);

  b.network.dns.setServers(["127.0.0.1", "1.1.1.1:53"]);
  check("setServers: a multi-entry list is accepted whole",
    b.network.dns.getServers().length === 2);
}

function testRejectedListLeavesTheConfiguredResolversIntact() {
  // Establish a known-good list, then offer a bad one. The framework must not
  // end up advertising a resolver it refused — a caller reading getServers()
  // after a failed set would otherwise believe a rejected value is live, and
  // the system-resolver path would parse it as if it were configured.
  b.network.dns.setServers(["127.0.0.1", "1.1.1.1:53"]);
  var before = b.network.dns.getServers().join(",");

  var codes = [];
  ["127.0.0.1:x", "127.0.0.1:65536", "not-an-ip"].forEach(function (bad) {
    try { b.network.dns.setServers([bad]); }
    catch (e) { codes.push(e.code); }
    check("setServers(" + JSON.stringify(bad) + "): the previous resolver list survives the rejection",
      b.network.dns.getServers().join(",") === before);
  });
  check("setServers: every rejection above was a typed DnsError", codes.length === 3);

  // A rejection part-way through a multi-entry list must not apply the valid
  // prefix either — the list is set whole or not at all.
  try { b.network.dns.setServers(["8.8.8.8", "127.0.0.1:0"]); } catch (_e) { /* expected */ }
  check("setServers: a list with one bad entry applies NONE of it",
    b.network.dns.getServers().join(",") === before);
}

async function run() {
  var original = b.network.dns.getServers();
  try {
    testZeroPortDoesNotAbortTheProcess();
    testPortRangeIsValidated();
    testValidResolversAreStillAccepted();
    testRejectedListLeavesTheConfiguredResolversIntact();
  } finally {
    // Leave the process resolving exactly as it was found.
    try {
      if (original && original.length > 0) b.network.dns.setServers(original);
    } catch (_e) { /* best effort */ }
    try { b.network.dns.clearCache(); } catch (_e) { /* best effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns-setservers] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
