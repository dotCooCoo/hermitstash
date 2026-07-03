// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardOauth code-reuse (replay) defense must FAIL CLOSED when the operator's
 * seenCodeStore errors. A store-lookup failure means "could not prove the
 * authorization code is unused" — which is a denial, not "the code is fresh".
 * Pre-fix the seenCodeStore.hasSeen() call was wrapped in a drop-silent catch,
 * so a backend outage silently skipped the replay check and the code was
 * accepted (codeReusePolicy is "reject" at every profile, so the defense is
 * meant to be unconditional).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

var BENIGN_FLOW = {
  response_type: "code",
  redirect_uri:  "https://app.example.com/callback",
  state:         "csrf-rand-1",
  scope:         "openid profile",
  code_challenge: "abc123def456ghi789jkl012mno345pqr678",
  code_challenge_method: "S256",
  code:          "auth-code-xyz",
};
var OPTS = {
  profile: "strict",
  allowedRedirectUris: ["https://app.example.com/callback"],
};

async function run() {
  // Control 1 — store says "not seen": the flow validates.
  var freshStore = { hasSeen: function () { return false; } };
  var rvFresh = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: freshStore }));
  check("guard-oauth: an unused code with a working store validates", rvFresh.ok === true);

  // Control 2 — store says "seen": the replay is refused.
  var seenStore = { hasSeen: function () { return true; } };
  var rvSeen = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: seenStore }));
  check("guard-oauth: a replayed code (store hit) is refused",
        rvSeen.ok === false && rvSeen.issues.some(function (i) { return i.ruleId === "oauth.code-reused"; }));

  // THE FIX — store THROWS (backend outage): must fail closed, not accept.
  var throwingStore = { hasSeen: function () { throw new Error("replay store backend unavailable"); } };
  var rvErr = b.guardOauth.validate(BENIGN_FLOW, Object.assign({}, OPTS, { seenCodeStore: throwingStore }));
  check("guard-oauth: a replay-store error FAILS CLOSED (code not accepted)", rvErr.ok === false);
  check("guard-oauth: a replay-store error surfaces a could-not-verify refusal",
        rvErr.issues.some(function (i) { return i.ruleId === "oauth.code-reuse-unverifiable"; }));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
