// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * DPoP htu reconstruction must peer-gate X-Forwarded-Proto / X-Forwarded-Host
 * (RFC 9449 §4.3). The htu (scheme + authority + path) is cryptographically
 * bound in the proof, so if the server builds it from a forgeable forwarded
 * header trusted from ANY caller, a direct attacker can forge
 * X-Forwarded-Proto: https / a victim X-Forwarded-Host and make a proof signed
 * for one origin validate against another (htu confusion).
 *
 * dpop previously honored both via a bare boolean opts.trustForwardedHeaders,
 * which trusted the headers with no immediate-peer check — the same forgeable
 * class csrf-protect / security-headers / cors already closed via the
 * peer-gated requestHelpers resolvers. This brings dpop onto the same
 * fail-closed model: trustForwardedHeaders is refused on its own, and proto +
 * host resolve through b.requestHelpers.trustedProtocol / trustedHost, honoring
 * the forwarded headers only from a declared trusted-proxy peer.
 *
 * Covers the two new peer-gated primitives (requestHost / trustedHost), the
 * dpop create()-time refusal, and the end-to-end htu decision.
 *
 * Run standalone: node test/layer-0-primitives/dpop-htu-peergating.test.js
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _ns() { return b.nonceStore.create({ backend: "memory" }); }

function _mkRes() {
  var res = {
    statusCode: 200, headersSent: false, _status: null, _body: null, _ended: false,
    writeHead: function (s) { res._status = s; res.statusCode = s; res.headersSent = true; return res; },
    setHeader: function () {},
    getHeader: function () { return undefined; },
    end: function (bdy) { res._ended = true; if (bdy != null) res._body = bdy; },
    json: function (o) { res._status = res._status || res.statusCode; res._body = JSON.stringify(o); res._ended = true; },
  };
  return res;
}

// ---- requestHost / trustedHost primitives ----

function testRequestHostPrimitive() {
  var base = {
    headers: { host: "real.example.com", "x-forwarded-host": "forged.evil.test" },
    socket: { remoteAddress: "203.0.113.9", encrypted: false },
  };

  // default (no trustProxy): the forwarded header is ignored, the request's own
  // Host is returned.
  check("requestHost: default ignores X-Forwarded-Host, uses Host",
        b.requestHelpers.requestHost(base) === "real.example.com");
  check("requestHost: default with trustProxy:false ignores forwarded",
        b.requestHelpers.requestHost(base, { trustProxy: false }) === "real.example.com");

  // peer-gated predicate: peer NOT trusted → forged header ignored.
  var notTrusted = function (addr) { return addr === "10.0.0.1"; };
  check("requestHost: predicate ignores X-Forwarded-Host from an untrusted peer",
        b.requestHelpers.requestHost(base, { trustProxy: notTrusted }) === "real.example.com");

  // peer-gated predicate: peer trusted → forwarded header honored.
  var trusted = function (addr) { return addr === "203.0.113.9"; };
  check("requestHost: predicate honors X-Forwarded-Host from a trusted peer",
        b.requestHelpers.requestHost(base, { trustProxy: trusted }) === "forged.evil.test");

  // legacy true: honored unconditionally (spoofable — documented).
  check("requestHost: legacy true honors forwarded (leftmost hop)",
        b.requestHelpers.requestHost(base, { trustProxy: true }) === "forged.evil.test");

  // absent host → null.
  check("requestHost: returns null when no host present",
        b.requestHelpers.requestHost({ headers: {} }) === null);
}

function testTrustedHostPrimitive() {
  var base = {
    headers: { host: "real.example.com", "x-forwarded-host": "forged.evil.test" },
    socket: { remoteAddress: "203.0.113.9", encrypted: false },
  };

  // No options → not peer-gated, forwarded ignored.
  var plain = b.requestHelpers.trustedHost();
  check("trustedHost: no opts is not peerGated", plain.peerGated === false);
  check("trustedHost: no opts ignores X-Forwarded-Host", plain.resolve(base) === "real.example.com");

  // trustedProxies covering the peer → peer-gated, forwarded honored.
  var gated = b.requestHelpers.trustedHost({ trustedProxies: ["203.0.113.0/24"] });
  check("trustedHost: trustedProxies is peerGated", gated.peerGated === true);
  check("trustedHost: honors X-Forwarded-Host from a trusted-proxy peer",
        gated.resolve(base) === "forged.evil.test");

  // trustedProxies NOT covering the peer → forged header ignored.
  var gatedMiss = b.requestHelpers.trustedHost({ trustedProxies: ["10.0.0.0/8"] });
  check("trustedHost: ignores X-Forwarded-Host from a non-trusted peer",
        gatedMiss.resolve(base) === "real.example.com");

  // hostResolver lets the operator own it.
  var owned = b.requestHelpers.trustedHost({ hostResolver: function () { return "owned.example.com"; } });
  check("trustedHost: hostResolver is peerGated", owned.peerGated === true);
  check("trustedHost: hostResolver owns the value", owned.resolve(base) === "owned.example.com");

  // bad hostResolver → TypeError at construction.
  var threw = null;
  try { b.requestHelpers.trustedHost({ hostResolver: 123 }); } catch (e) { threw = e; }
  check("trustedHost: non-function hostResolver throws", threw instanceof TypeError);
}

// ---- dpop create()-time refusal of the spoofable legacy boolean ----

function testDpopRefusesBareTrustForwardedHeaders() {
  var threw = null;
  try {
    b.middleware.dpop({ replayStore: _ns(), trustForwardedHeaders: true });
  } catch (e) { threw = e; }
  check("dpop: bare trustForwardedHeaders:true is refused at create()", threw !== null);
  check("dpop: refusal names the spoofable risk + trustedProxies migration",
        threw && /spoofable|trustedProxies/i.test(String(threw.message || threw)));

  // WITH trustedProxies it mounts (the operator declared the trust edge).
  var ok = null;
  try {
    ok = b.middleware.dpop({ replayStore: _ns(), trustForwardedHeaders: true, trustedProxies: ["10.0.0.0/8"] });
  } catch (e) { ok = e; }
  check("dpop: trustForwardedHeaders:true WITH trustedProxies mounts", typeof ok === "function");

  // Default (no forwarded trust) mounts cleanly.
  var def = null;
  try { def = b.middleware.dpop({ replayStore: _ns() }); } catch (e) { def = e; }
  check("dpop: default (no forwarded trust) mounts", typeof def === "function");

  // getHtu owns the entire URI → _reconstructHtu (and the forwarded headers) is
  // never consulted, so a leftover trustForwardedHeaders:true is moot and must
  // NOT fail construction (the refusal only matters when htu is reconstructed).
  var withGetHtu = null;
  try {
    withGetHtu = b.middleware.dpop({
      replayStore: _ns(),
      trustForwardedHeaders: true,
      getHtu: function () { return "https://api.example.com/resource"; },
    });
  } catch (e) { withGetHtu = e; }
  check("dpop: trustForwardedHeaders:true WITH getHtu mounts (reconstruction bypassed)",
        typeof withGetHtu === "function");
}

// ---- end-to-end: a forged X-Forwarded-Proto/Host from a non-trusted peer
//      must NOT be used to reconstruct the htu (the bound proof is rejected);
//      from a trusted-proxy peer it IS honored. ----

async function _proofForHttps(key) {
  return b.auth.dpop.buildProof({
    htm: "POST",
    htu: "https://api.example.com/resource",
    privateKey: key,
    algorithm: "ES256",
  });
}

function _forgedReq(proof) {
  return {
    method: "POST",
    url: "/resource",
    headers: {
      host: "api.example.com",
      "x-forwarded-proto": "https",
      "x-forwarded-host": "api.example.com",
      dpop: proof,
    },
    socket: { remoteAddress: "203.0.113.9", encrypted: false },   // plain HTTP from a direct caller
  };
}

async function testForgedForwardedNotHonored() {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var keyPem = kp.privateKey.export({ type: "pkcs8", format: "pem" });

  // Peer 203.0.113.9 is NOT in trustedProxies (10.0.0.0/8) → forged
  // X-Forwarded-Proto:https is ignored → htu reconstructed as http://… →
  // the proof signed for https://api.example.com/resource MUST be rejected.
  var mw = b.middleware.dpop({ replayStore: _ns(), trustedProxies: ["10.0.0.0/8"] });
  var proof = await _proofForHttps(keyPem);
  var req = _forgedReq(proof);
  var res = _mkRes();
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  check("forged XFP from untrusted peer: htu stays http → proof rejected (401)",
        res._status === 401 && nextCalled === false);
  check("forged XFP from untrusted peer: handler not reached", req.dpop === undefined);
}

async function testTrustedPeerForwardedHonored() {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var keyPem = kp.privateKey.export({ type: "pkcs8", format: "pem" });

  // Peer 203.0.113.9 IS in trustedProxies (203.0.113.0/24) → X-Forwarded-Proto
  // :https + X-Forwarded-Host honored → htu = https://api.example.com/resource
  // matches the proof → it verifies and the request proceeds.
  var mw = b.middleware.dpop({ replayStore: _ns(), trustedProxies: ["203.0.113.0/24"] });
  var proof = await _proofForHttps(keyPem);
  var req = _forgedReq(proof);
  var res = _mkRes();
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  check("trusted-proxy peer: XFP honored → htu https → proof verifies (next called)",
        nextCalled === true && res._status !== 401);
  check("trusted-proxy peer: req.dpop attached for downstream binding",
        req.dpop && typeof req.dpop.jkt === "string");
}

async function run() {
  testRequestHostPrimitive();
  testTrustedHostPrimitive();
  testDpopRefusesBareTrustForwardedHeaders();
  await testForgedForwardedNotHonored();
  await testTrustedPeerForwardedHonored();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
