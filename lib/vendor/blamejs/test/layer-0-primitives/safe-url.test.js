// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeUrl protocol-allowlist presets — the three frozen scheme arrays a
 * caller passes as opts.allowedProtocols, proven through the real parse gate
 * rather than by shape checks alone.
 *
 * Each preset is asserted for its advertised contents AND its gating behavior:
 * a URL whose scheme is IN the preset parses and returns the matching
 * protocol; a URL whose scheme is OUT of it refuses with
 * safe-url/protocol-disallowed. ALLOW_WS_TLS is the headline case — it permits
 * wss: and refuses cleartext ws:. The presets are also confirmed frozen, as the
 * docs promise (a shared allowlist must not be mutable by one caller).
 */

var { check, b } = require("../helpers");

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// ---- ALLOW_WS_TLS (["wss:"]) ----

function testAllowWsTls() {
  check("b.safeUrl.ALLOW_WS_TLS is the advertised secure-WS allowlist",
        b.safeUrl.ALLOW_WS_TLS.join(",") === "wss:");
  check("ALLOW_WS_TLS is frozen (a shared preset must be immutable)",
        Object.isFrozen(b.safeUrl.ALLOW_WS_TLS));

  // Permits wss:, refuses cleartext ws: — the secure-WebSocket default.
  check("parse with ALLOW_WS_TLS accepts a wss: URL",
        b.safeUrl.parse("wss://example.com/stream", {
          allowedProtocols: b.safeUrl.ALLOW_WS_TLS,
        }).protocol === "wss:");
  check("parse with ALLOW_WS_TLS refuses a cleartext ws: URL",
        _code(function () {
          b.safeUrl.parse("ws://example.com/stream", {
            allowedProtocols: b.safeUrl.ALLOW_WS_TLS,
          });
        }) === "safe-url/protocol-disallowed");
}

// ---- ALLOW_WS_ALL (["ws:", "wss:"]) ----

function testAllowWsAll() {
  check("b.safeUrl.ALLOW_WS_ALL is the advertised ws+wss allowlist",
        b.safeUrl.ALLOW_WS_ALL.join(",") === "ws:,wss:");
  check("ALLOW_WS_ALL is frozen", Object.isFrozen(b.safeUrl.ALLOW_WS_ALL));

  // Opt-in cleartext WebSocket: both ws: and wss: parse.
  check("parse with ALLOW_WS_ALL accepts a cleartext ws: URL",
        b.safeUrl.parse("ws://127.0.0.1:9000/stream", {
          allowedProtocols: b.safeUrl.ALLOW_WS_ALL,
        }).protocol === "ws:");
  check("parse with ALLOW_WS_ALL accepts a wss: URL",
        b.safeUrl.parse("wss://example.com/stream", {
          allowedProtocols: b.safeUrl.ALLOW_WS_ALL,
        }).protocol === "wss:");
  // But it is a WebSocket allowlist — an https: URL is a category error here.
  check("parse with ALLOW_WS_ALL refuses a non-WebSocket https: URL",
        _code(function () {
          b.safeUrl.parse("https://example.com/", {
            allowedProtocols: b.safeUrl.ALLOW_WS_ALL,
          });
        }) === "safe-url/protocol-disallowed");
}

// ---- ALLOW_ANY (["http:", "https:", "ws:", "wss:"]) ----

function testAllowAny() {
  check("b.safeUrl.ALLOW_ANY is every framework-supported scheme",
        b.safeUrl.ALLOW_ANY.join(",") === "http:,https:,ws:,wss:");
  check("b.safeUrl.ALLOW_ANY has the advertised length of 4",
        b.safeUrl.ALLOW_ANY.length === 4);
  check("ALLOW_ANY is frozen", Object.isFrozen(b.safeUrl.ALLOW_ANY));

  // Every supported scheme parses under ALLOW_ANY and returns its protocol.
  var supported = [
    { url: "http://example.com/",  protocol: "http:" },
    { url: "https://example.com/", protocol: "https:" },
    { url: "ws://example.com/",    protocol: "ws:" },
    { url: "wss://example.com/",   protocol: "wss:" },
  ];
  for (var i = 0; i < supported.length; i += 1) {
    check("parse with ALLOW_ANY accepts " + supported[i].protocol,
          b.safeUrl.parse(supported[i].url, {
            allowedProtocols: b.safeUrl.ALLOW_ANY,
          }).protocol === supported[i].protocol);
  }
  // A scheme outside the framework-supported set still refuses.
  check("parse with ALLOW_ANY refuses an unsupported ftp: scheme",
        _code(function () {
          b.safeUrl.parse("ftp://example.com/file", {
            allowedProtocols: b.safeUrl.ALLOW_ANY,
          });
        }) === "safe-url/protocol-disallowed");
}

async function run() {
  testAllowWsTls();
  testAllowWsAll();
  testAllowAny();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
