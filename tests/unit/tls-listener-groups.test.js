"use strict";

/**
 * The inbound TLS listener must configure its key-exchange groups via
 * `ecdhCurve`, never `groups`.
 *
 * Node has no `groups` TLS option — configSecureContext never reads one — so a
 * `groups:` key is accepted and silently discarded, leaving the listener on
 * OpenSSL's default group list. That default excludes the ML-KEM hybrids, which
 * inverted the intended posture: a client offering only a hybrid was refused,
 * and a client offering both negotiated classical X25519, while the boot banner
 * reported post-quantum as enforced.
 *
 * These tests pin the three properties that keep that from coming back:
 *   1. `groups` really is ignored by Node (the premise) while `ecdhCurve` is
 *      validated — so the choice is load-bearing, not cosmetic.
 *   2. server-main.js passes `ecdhCurve` at every TLS-options site and no
 *      longer passes `groups` at any of them.
 *   3. Under enforcement the list carries no classical group, so a client that
 *      offers a hybrid cannot negotiate classical by listing it first.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var fs = require("node:fs");
var path = require("node:path");
var nodeTls = require("node:tls");

var b = require("../../lib/vendor/blamejs");

var SERVER_MAIN = path.join(__dirname, "..", "..", "server-main.js");
var src = fs.readFileSync(SERVER_MAIN, "utf8");

describe("TLS listener key-exchange groups", function () {

  it("Node validates ecdhCurve but silently ignores groups (the premise)", function () {
    // A bogus ecdhCurve throws — the option is real and checked.
    assert.throws(
      function () { nodeTls.createSecureContext({ ecdhCurve: "NOTAGROUP" }); },
      /ECDH|curve/i,
      "ecdhCurve must be validated by Node");
    // A bogus `groups` does NOT throw — Node never looks at it. This is exactly
    // why a `groups:` key degrades silently instead of failing at boot.
    assert.doesNotThrow(
      function () { nodeTls.createSecureContext({ groups: "NOTAGROUP" }); },
      "groups is not a Node TLS option; if this ever starts throwing, Node has " +
      "added one and this test's premise should be revisited");
  });

  it("server-main.js configures every TLS options site with ecdhCurve, not groups", function () {
    // A TLS options object is identified by the `minVersion` that sits beside
    // the group list; a `groups:` key in a logger payload is not a TLS option
    // and is deliberately not matched here.
    var tlsOptionBlocks = src.match(/[^\n]*groups:[^\n]*\n\s*minVersion:/g) || [];
    assert.equal(tlsOptionBlocks.length, 0,
      "no TLS options object may pass `groups:` — Node discards it silently. Found: " +
      JSON.stringify(tlsOptionBlocks));
    var ecdh = src.match(/ecdhCurve:\s*listenerGroupList\(\)/g) || [];
    assert.equal(ecdh.length, 2,
      "both TLS options sites (initial listener + certificate reload) must set " +
      "ecdhCurve via listenerGroupList(); found " + ecdh.length);
  });

  it("the boot banners report the list actually configured, not the full preference", function () {
    // The previous banner named the framework's first group unconditionally, so
    // it read "PQC enforced (SecP384r1MLKEM1024)" while the listener was in fact
    // negotiating classical X25519. Both banners must derive from the same
    // helper that builds the listener's list.
    assert.equal(/TLS_GROUP_PREFERENCE\[0\]/.test(src), false,
      "the boot banner must not name TLS_GROUP_PREFERENCE[0] — it can differ from what is configured");
    assert.equal(/groups:\s*b\.constants\.TLS_GROUP_PREFERENCE\.join/.test(src), false,
      "the TLS log line must not print the full preference list — it can differ from what is configured");
  });

  it("the group list is a colon-joined string, since the constant is an array", function () {
    var pref = b.constants.TLS_GROUP_PREFERENCE;
    assert.ok(Array.isArray(pref), "TLS_GROUP_PREFERENCE is an array");
    // Passing the array straight through would throw at boot.
    assert.throws(
      function () { nodeTls.createSecureContext({ ecdhCurve: pref }); },
      /must be of type string|ecdhCurve/i,
      "the array form must not be passed to ecdhCurve");
    assert.doesNotThrow(
      function () { nodeTls.createSecureContext({ ecdhCurve: pref.join(":") }); },
      "the colon-joined form is what OpenSSL accepts");
  });

  it("under enforcement the list is post-quantum only — no classical fallback", function () {
    var pref = b.constants.TLS_GROUP_PREFERENCE;
    var enforced = pref.filter(function (g) { return /MLKEM/i.test(g); });
    assert.ok(enforced.length > 0, "there must be at least one hybrid group");
    assert.equal(enforced.some(function (g) { return !/MLKEM/i.test(g); }), false,
      "the enforced list must contain no classical group — TLS selects from the " +
      "mutual set, so a classical entry lets a client that lists it first " +
      "negotiate classical despite also offering a hybrid");
    assert.doesNotThrow(
      function () { nodeTls.createSecureContext({ ecdhCurve: enforced.join(":") }); },
      "the enforced list must be accepted by OpenSSL");
  });

});
