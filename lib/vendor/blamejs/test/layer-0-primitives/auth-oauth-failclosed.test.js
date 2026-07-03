// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.oauth — fail-closed replay gates + reserved authorization-param
 * guards.
 *
 * Two classes of defect are pinned here, each driven through the public
 * b.auth.oauth surface:
 *
 *   1. Replay gates that compared a store/callback result against a single
 *      boolean LITERAL (`=== true` / `=== false`) instead of testing its
 *      truthiness. An operator store that speaks the natural Redis/SQL shape
 *      (SETNX → 1/0, EXISTS → 1/0, COUNT(*) → integer) returns a truthy or
 *      falsy NON-boolean, so the exact-literal comparison misses and the
 *      one-time-use / anti-replay refusal is silently skipped (fail OPEN).
 *      Covered entry points: refreshAccessToken (legacy seen + atomic
 *      checkAndInsert) and verifyClientAttestation (seenJti).
 *
 *   2. authorizationUrl / pushAuthorizationRequest merged operator-supplied
 *      extraParams with no reserved-key guard, so an extraParams key could
 *      overwrite a framework-managed security parameter (redirect_uri /
 *      state / code_challenge / …). The builder still RETURNED the framework
 *      state + PKCE verifier, so the returned values silently diverged from
 *      what the URL actually carried — a broken CSRF / PKCE binding.
 *      endSessionUrl already guarded this; authorizationUrl and PAR did not.
 *
 * A replayed refresh token / attestation PoP that is exchanged instead of
 * refused, and a state/verifier that disagrees with the URL, are both the
 * observable RED symptoms.
 */

var http    = require("node:http");
var crypto  = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var X = b.auth.oauth;

// Reject an ASYNC call (Promise) with a specific OAuthError code.
async function arejects(label, fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label, threw !== null && threw.code === code);
}

// Assert an ASYNC call RESOLVES (does not throw) — guards against a fix that
// over-closes and refuses a legitimate first-sighting / allowed param.
async function aresolves(label, fn) {
  var ok = false;
  try { await fn(); ok = true; } catch (_e) { ok = false; }
  check(label, ok);
}

// Combined authorization-server stand-in: OIDC discovery + a token endpoint
// that mints a fresh token set + a PAR endpoint that returns a request_uri.
// Discovery advertises S256 so the PKCE-downgrade gate passes.
function _spawnAsServer() {
  var holder = { value: null };
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname === "/.well-known/openid-configuration") {
      var doc = {
        issuer:                                holder.value,
        authorization_endpoint:                holder.value + "/auth",
        token_endpoint:                        holder.value + "/token",
        jwks_uri:                              holder.value + "/jwks",
        pushed_authorization_request_endpoint: holder.value + "/par",
        code_challenge_methods_supported:      ["S256"],
      };
      var body = JSON.stringify(doc);
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
      return;
    }
    if (u.pathname === "/token" && req.method === "POST") {
      var out = JSON.stringify({
        access_token:  "at-" + crypto.randomBytes(4).toString("hex"),
        token_type:    "Bearer",
        expires_in:    3600,
        refresh_token: "rt-rotated",
      });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(out) });
      res.end(out);
      return;
    }
    if (u.pathname === "/par" && req.method === "POST") {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var par = JSON.stringify({ request_uri: "urn:ietf:params:oauth:request_uri:xyz", expires_in: 90 });
        res.writeHead(201, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(par) });
        res.end(par);
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  server._holder = holder;
  return server;
}

async function _listen(server) {
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var issuer = "http://127.0.0.1:" + server.address().port;
  server._holder.value = issuer;
  return issuer;
}

// A discovery-backed client that talks to the local stand-in AS.
function _asClient(issuer, extra) {
  var opts = {
    issuer:        issuer,
    clientId:      "rp-failclosed",
    clientSecret:  "fc-secret",
    redirectUri:   "https://rp.example/cb",
    scope:         ["openid", "profile"],
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  };
  if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
  return X.create(opts);
}

// A static-endpoint client — authorizationUrl builds fully offline.
function _staticClient() {
  return X.create({
    issuer:                "https://static.example",
    clientId:              "rp-static-fc",
    redirectUri:           "https://rp.example/cb",
    scope:                 ["openid", "profile"],
    isOidc:                true,
    authorizationEndpoint: "https://static.example/auth",
    tokenEndpoint:         "https://static.example/token",
  });
}

async function _bug1RefreshReplayGates(issuer) {
  var oa = _asClient(issuer);

  // Legacy seen() — the docstring says "returns truthy when the SAME
  // refresh_token was presented before". A store fronting Redis EXISTS /
  // SISMEMBER or a SQL COUNT returns 1 (truthy non-boolean) on a replay.
  // The `=== true` gate missed it and exchanged the stolen token.
  await arejects("refresh: legacy seen() returning 1 (truthy) refuses replay",
                 function () { return oa.refreshAccessToken("rt", { seen: function () { return 1; } }); },
                 "auth-oauth/refresh-token-replay");
  await arejects("refresh: legacy seen() returning true refuses replay",
                 function () { return oa.refreshAccessToken("rt", { seen: function () { return true; } }); },
                 "auth-oauth/refresh-token-replay");

  // Atomic checkAndInsert — contract: truthy when it was the first insert
  // (unseen); a store returning 0 (SETNX not-set / INSERT affected 0 rows)
  // signals a replay. The `inserted === false` normalization missed the 0.
  await arejects("refresh: checkAndInsert() returning 0 (falsy) refuses replay",
                 function () { return oa.refreshAccessToken("rt", { checkAndInsert: function () { return 0; } }); },
                 "auth-oauth/refresh-token-replay");
  await arejects("refresh: checkAndInsert() returning false refuses replay",
                 function () { return oa.refreshAccessToken("rt", { checkAndInsert: function () { return false; } }); },
                 "auth-oauth/refresh-token-replay");

  // Fail-closed must not become fail-shut: a genuine first sighting
  // (truthy insert / falsy seen) still proceeds to the token endpoint.
  await aresolves("refresh: checkAndInsert() returning 1 (first sighting) is allowed",
                  function () { return oa.refreshAccessToken("rt", { checkAndInsert: function () { return 1; } }); });
  await aresolves("refresh: legacy seen() returning 0 (unseen) is allowed",
                  function () { return oa.refreshAccessToken("rt", { seen: function () { return 0; } }); });
}

async function _bug1AttestationSeenJti() {
  var attKp  = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instPub = instKp.publicKey.export({ format: "jwk" });
  var attPub  = attKp.publicKey.export({ format: "jwk" });
  var att = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey, instanceKeyJwk: instPub });

  function freshPop() {
    return X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as" });
  }
  function verify(seenJti) {
    return X.verifyClientAttestation(att, freshPop(),
      { attesterJwk: attPub, expectedAudience: "https://as", seenJti: seenJti });
  }

  // seenJti contract: returns truthy when the jti was UNSEEN. A store
  // returning 0 for an already-seen jti is a replay — the `unseen === false`
  // gate missed the 0 and accepted the replayed PoP.
  await arejects("attestation: seenJti() returning 0 (seen) refuses replay",
                 function () { return verify(function () { return 0; }); },
                 "auth-oauth/attestation-pop-replay");
  await arejects("attestation: seenJti() returning false refuses replay",
                 function () { return verify(function () { return false; }); },
                 "auth-oauth/attestation-pop-replay");
  await aresolves("attestation: seenJti() returning 1 (unseen) is allowed",
                  function () { return verify(function () { return 1; }); });
}

async function _bug2AuthorizationUrlReserved() {
  var oa = _staticClient();
  var reserved = ["redirect_uri", "state", "code_challenge", "code_challenge_method",
                  "client_id", "response_type", "scope", "nonce", "response_mode",
                  "authorization_details"];
  // Await each refusal sequentially so a failure is attributed to its key.
  for (var j = 0; j < reserved.length; j++) {
    var extra = {}; extra[reserved[j]] = "attacker-controlled";
    await arejects("authorizationUrl: extraParams cannot overwrite reserved '" + reserved[j] + "'",
                   (function (e) { return function () { return oa.authorizationUrl({ extraParams: e }); }; })(extra),
                   "auth-oauth/reserved-extra-param");
  }

  // Non-reserved extraParams still pass through and the returned state
  // matches what the URL carries (binding intact).
  var built = await oa.authorizationUrl({ extraParams: { audience: "https://api.example", resource: "https://rs.example" } });
  var url = new URL(built.url);
  check("authorizationUrl: non-reserved extraParams pass through (audience)",
        url.searchParams.get("audience") === "https://api.example");
  check("authorizationUrl: returned state matches the URL state (binding intact)",
        typeof built.state === "string" && built.state.length > 0 &&
        url.searchParams.get("state") === built.state);
}

async function _bug2ParReserved(issuer) {
  var oa = _asClient(issuer);
  await arejects("PAR: extraParams cannot overwrite reserved 'redirect_uri'",
                 function () { return oa.pushAuthorizationRequest({ extraParams: { redirect_uri: "https://evil.example/cb" } }); },
                 "auth-oauth/reserved-extra-param");
  await arejects("PAR: extraParams cannot overwrite reserved 'state'",
                 function () { return oa.pushAuthorizationRequest({ extraParams: { state: "smuggled" } }); },
                 "auth-oauth/reserved-extra-param");
  await aresolves("PAR: non-reserved extraParams still push successfully",
                  function () { return oa.pushAuthorizationRequest({ extraParams: { audience: "https://api.example" } }); });
}

async function run() {
  var server = _spawnAsServer();
  var issuer = await _listen(server);
  try {
    await _bug1RefreshReplayGates(issuer);
    await _bug1AttestationSeenJti();
    await _bug2AuthorizationUrlReserved();
    await _bug2ParReserved(issuer);
  } finally {
    server.close();
  }
  console.log("auth-oauth-failclosed checks passed");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
