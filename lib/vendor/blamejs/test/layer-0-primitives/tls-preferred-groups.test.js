"use strict";
/**
 * b.network.tls.preferredGroups + b.network.tls.pqc.* — RFC 9794
 * named-group ordering surface tests.
 *
 * Validates that the framework default puts X25519MLKEM768 first
 * (RFC 9794 default), SecP256r1MLKEM768 second (RFC 9794 optional),
 * SecP384r1MLKEM1024 third, and X25519 fourth (classical fallback).
 * Operator opt-out via setKeyShares / preferredGroups.set replaces
 * the list.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testPreferredGroupsSurface() {
  check("network.tls.preferredGroups.set is a function",
        typeof b.network.tls.preferredGroups.set === "function");
  check("network.tls.preferredGroups.get is a function",
        typeof b.network.tls.preferredGroups.get === "function");
  check("network.tls.preferredGroups.reset is a function",
        typeof b.network.tls.preferredGroups.reset === "function");
}

function testRfc9794DefaultOrdering() {
  b.network.tls.preferredGroups.reset();
  var groups = b.network.tls.preferredGroups.get();
  check("default is array with at least 4 groups",
        Array.isArray(groups) && groups.length >= 4);
  check("default group[0] is X25519MLKEM768 (RFC 9794 default)",
        groups[0] === "X25519MLKEM768");
  check("default group[1] is SecP256r1MLKEM768 (RFC 9794 optional)",
        groups[1] === "SecP256r1MLKEM768");
  check("default contains SecP384r1MLKEM1024",
        groups.indexOf("SecP384r1MLKEM1024") !== -1);
  check("default contains X25519 fallback",
        groups.indexOf("X25519") !== -1);
}

function testOperatorOptOut() {
  var prior = b.network.tls.preferredGroups.get();
  try {
    b.network.tls.preferredGroups.set(["X25519"]);
    check("operator opt-out leaves only X25519",
          b.network.tls.preferredGroups.get().join(",") === "X25519");
  } finally {
    b.network.tls.preferredGroups.reset();
  }
  check("reset restores default ordering with X25519MLKEM768 first",
        b.network.tls.preferredGroups.get()[0] === "X25519MLKEM768");
  check("reset restored default length",
        b.network.tls.preferredGroups.get().length === prior.length);
}

function testPqcAliasMatchesPreferredGroups() {
  b.network.tls.preferredGroups.reset();
  var viaPqc = b.network.tls.pqc.getKeyShares();
  var viaPref = b.network.tls.preferredGroups.get();
  check("pqc.getKeyShares matches preferredGroups.get",
        viaPqc.join(",") === viaPref.join(","));
}

function testApplyToContextEmitsGroups() {
  b.network.tls.preferredGroups.reset();
  var ctx = b.network.tls.applyToContext({ base: {} });
  check("applyToContext emits groups string",
        typeof ctx.groups === "string" && ctx.groups.indexOf("X25519MLKEM768") === 0);
  check("applyToContext groups string contains SecP256r1MLKEM768",
        ctx.groups.indexOf("SecP256r1MLKEM768") !== -1);
}

async function run() {
  testPreferredGroupsSurface();
  testRfc9794DefaultOrdering();
  testOperatorOptOut();
  testPqcAliasMatchesPreferredGroups();
  testApplyToContextEmitsGroups();
}

module.exports = { run: run };
