// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A spec-clean authorization-code flow: PKCE S256, state present,
// allowlisted redirect_uri, single `code` response_type.
var BENIGN_FLOW = Object.freeze({
  response_type: "code",
  redirect_uri:  "https://app.example.com/callback",
  state:         "csrf-rand-1",
  scope:         "openid profile",
  code_challenge: "abc123def456ghi789jkl012mno345pqr678",
  code_challenge_method: "S256",
});

var ALLOWED_REDIRECTS = Object.freeze(["https://app.example.com/callback"]);

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testSanitize() {
  // Benign: a well-formed flow passes through unchanged (OAuth bundles
  // can't be partially repaired — clean or refused).
  var out = b.guardOauth.sanitize(BENIGN_FLOW, {
    profile: "strict",
    allowedRedirectUris: ALLOWED_REDIRECTS,
  });
  check("guardOauth.sanitize benign passthrough", out === BENIGN_FLOW);

  // Hostile: no PKCE at all — OAuth 2.1 mandates PKCE for every client;
  // sanitize throws rather than returning the downgraded flow.
  var pkceErr = expectThrows("guardOauth.sanitize pkce-missing throws",
    function () {
      b.guardOauth.sanitize({
        response_type: "code",
        redirect_uri:  "https://app.example.com/callback",
        scope:         "openid",
      }, { profile: "strict" });
    },
    "oauth.pkce-missing");
  check("guardOauth.sanitize pkce GuardOauthError",
    pkceErr instanceof b.guardOauth.GuardOauthError);

  // Hostile: `plain` PKCE method under strict is a downgrade-attack
  // class — refused (require-s256).
  expectThrows("guardOauth.sanitize pkce plain-method throws",
    function () {
      b.guardOauth.sanitize({
        response_type: "code",
        redirect_uri:  "https://app.example.com/callback",
        state:         "s1",
        scope:         "openid",
        code_challenge: "abc123def456ghi789jkl012mno345pqr678",
        code_challenge_method: "plain",
      }, { profile: "strict", allowedRedirectUris: ALLOWED_REDIRECTS });
    },
    "oauth.pkce-method");
}

async function testGate() {
  var oauthGate = b.guardOauth.gate({
    profile: "strict",
    allowedRedirectUris: ALLOWED_REDIRECTS,
  });

  // Benign flow → serve.
  var served = await oauthGate.check({ oauthFlow: BENIGN_FLOW });
  check("guardOauth.gate benign serves", served.ok === true && served.action === "serve");

  // Hostile: redirect_uri not on the operator allowlist — the canonical
  // loose-match account-takeover class. Gate refuses before the token
  // exchange, even though state/PKCE are present.
  var refused = await oauthGate.check({
    oauthFlow: {
      response_type: "code",
      redirect_uri:  "https://attacker.example/callback",
      state:         "csrf-rand-1",
      scope:         "openid",
      code_challenge: "abc123def456ghi789jkl012mno345pqr678",
      code_challenge_method: "S256",
    },
  });
  check("guardOauth.gate hostile redirect refuses",
    refused.ok === false && refused.action === "refuse");
  check("guardOauth.gate redirect-uri-not-allowed kind",
    (refused.issues || []).some(function (i) { return i.kind === "redirect-uri-not-allowed"; }));

  // Hostile: replay — a code the operator's seenCodeStore has already
  // seen is a critical code-reuse refuse (RFC 6749 §10.5).
  var replayGate = b.guardOauth.gate({
    profile: "strict",
    allowedRedirectUris: ALLOWED_REDIRECTS,
    seenCodeStore: { hasSeen: function () { return true; } },
  });
  var replay = await replayGate.check({
    oauthFlow: Object.assign({}, BENIGN_FLOW, { code: "authcode-123" }),
  });
  check("guardOauth.gate replayed code refuses",
    replay.ok === false && replay.action === "refuse");
  check("guardOauth.gate code-reused kind",
    (replay.issues || []).some(function (i) { return i.kind === "code-reused"; }));

  // Fail-closed: a seenCodeStore that errors can't prove the code is
  // unused → refuse (code-reuse-unverifiable), never silently serve.
  var errGate = b.guardOauth.gate({
    profile: "strict",
    allowedRedirectUris: ALLOWED_REDIRECTS,
    seenCodeStore: { hasSeen: function () { throw new Error("store down"); } },
  });
  var failClosed = await errGate.check({
    oauthFlow: Object.assign({}, BENIGN_FLOW, { code: "authcode-123" }),
  });
  check("guardOauth.gate replay-store error fails closed",
    failClosed.ok === false && failClosed.action === "refuse");
  check("guardOauth.gate code-reuse-unverifiable kind",
    (failClosed.issues || []).some(function (i) { return i.kind === "code-reuse-unverifiable"; }));

  // No flow on the ctx → serve (nothing to gate).
  var empty = await oauthGate.check({});
  check("guardOauth.gate absent flow serves", empty.ok === true && empty.action === "serve");
}

async function run() {
  testSanitize();
  await testGate();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
