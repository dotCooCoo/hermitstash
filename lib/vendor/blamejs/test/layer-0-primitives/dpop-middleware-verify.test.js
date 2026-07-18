// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.dpop — request-path verification, the server-managed nonce
 * challenge lifecycle (RFC 9449 §8), access-token (ath) binding, the getNonce
 * callback, htu reconstruction edges, DPoP-header shape enforcement (§4.1), and
 * the 401 response-shaping knobs (onDeny / problemDetails / audit).
 *
 * These drive the exported middleware — b.middleware.dpop(opts) — with real
 * DPoP proofs built by b.auth.dpop.buildProof (node:crypto keypairs), exercising
 * the adversarial branches a proof-of-possession verifier must fail closed on:
 *
 *   - a stale / missing / wrong / malformed server-managed nonce
 *   - a proof whose ath does not bind the presented access token
 *   - an htu that cannot be reconstructed, or carries a stale iat, or a
 *     disallowed algorithm, or a mismatched method
 *   - two proofs smuggled in one comma-joined header value, and an
 *     array-valued DPoP header (§4.1: exactly one proof per request)
 *
 * A verify that accepted any of these would be a fail-open proof gate.
 *
 * Run standalone: node test/layer-0-primitives/dpop-middleware-verify.test.js
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var HTU = "https://api.example.com/resource";
var HTM = "POST";

function _ns() { return b.nonceStore.create({ backend: "memory" }); }

function _ecPem() {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return kp.privateKey.export({ type: "pkcs8", format: "pem" });
}

function _proof(keyPem, over) {
  var o = {
    htm: HTM,
    htu: HTU,
    privateKey: keyPem,
    algorithm: "ES256",
  };
  if (over) for (var k in over) o[k] = over[k];
  return b.auth.dpop.buildProof(o);
}

// Hand-sign a proof from an explicit header/payload so tests can smuggle a
// nonce claim of a hostile shape (empty string / number) that buildProof would
// never emit — the malformed value must still be rejected by the middleware's
// server-managed nonce check after the signature verifies.
function _b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function _handSign(keyPem, payload) {
  var priv = nodeCrypto.createPrivateKey({ key: keyPem, format: "pem" });
  var pubJwk = nodeCrypto.createPublicKey(priv).export({ format: "jwk" });
  var header = { typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y } };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), { key: priv, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + _b64url(sig);
}

// mockReq/mockRes are the framework's own fixtures (b.testing.*); reuse them
// rather than hand-rolling a res shape.
function _req(over) {
  var opts = {
    method: HTM,
    url:    "/resource",
    headers: { host: "api.example.com" },
    socket:  { remoteAddress: "203.0.113.9", encrypted: true },
  };
  if (over) for (var k in over) {
    if (k === "headers") { for (var h in over.headers) opts.headers[h] = over.headers[h]; }
    else opts[k] = over[k];
  }
  return b.testing.mockReq(opts);
}

// Drive one request through the middleware; capture status / body / headers /
// whether next() ran.
async function _call(mw, req) {
  var res = b.testing.mockRes();
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  var cap = res._captured();
  return { res: res, cap: cap, nextCalled: nextCalled, status: cap.status, req: req };
}

// ---- server-managed nonce (requireNonce) challenge + accept round trip ----

async function testNonceChallengeAndAccept() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    requireNonce: true,
    getHtu: function () { return HTU; },
  });

  // 1) No proof at all → 401 use_dpop_nonce + a fresh DPoP-Nonce challenge.
  var r1 = await _call(mw, _req());
  check("nonce challenge: no-proof request is 401", r1.status === 401);
  check("nonce challenge: error is use_dpop_nonce", /use_dpop_nonce/.test(r1.cap.body));
  var n1 = r1.cap.headers["dpop-nonce"];
  check("nonce challenge: server issues a DPoP-Nonce header", typeof n1 === "string" && n1.length > 0);

  // 2) A proof carrying the issued nonce is accepted → next() runs, req.dpop set,
  //    and the response refreshes DPoP-Nonce.
  var goodProof = await _proof(key, { nonce: n1 });
  var r2 = await _call(mw, _req({ headers: { dpop: goodProof } }));
  check("nonce accept: valid nonce → next() called", r2.nextCalled === true);
  check("nonce accept: req.dpop attached with jkt", r2.req.dpop && typeof r2.req.dpop.jkt === "string");
  check("nonce accept: response refreshes DPoP-Nonce", typeof r2.res.getHeader("DPoP-Nonce") === "string");

  // 3) A proof WITHOUT a nonce (but otherwise valid) → verify passes, the
  //    server-managed check rejects → 401 use_dpop_nonce. Fail closed.
  var noNonce = await _proof(key);
  var r3 = await _call(mw, _req({ headers: { dpop: noNonce } }));
  check("nonce missing: proof lacking a nonce is refused (401)", r3.status === 401);
  check("nonce missing: refusal is use_dpop_nonce", /use_dpop_nonce/.test(r3.cap.body));
  check("nonce missing: handler not reached", r3.req.dpop === undefined && r3.nextCalled === false);

  // 4) A proof carrying a WRONG (unrecognized) nonce → 401. Not fail-open.
  var wrongProof = await _proof(key, { nonce: "AAAAAAAAAAAAAAAAAAAAAA" });
  var r4 = await _call(mw, _req({ headers: { dpop: wrongProof } }));
  check("nonce wrong: unrecognized nonce is refused (401)", r4.status === 401);
  check("nonce wrong: handler not reached", r4.nextCalled === false);
}

// A malformed nonce claim (empty string / non-string) inside an otherwise-valid
// signed proof must not slip past the rolling-pair accept check.
async function testMalformedNonceClaimRefused() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    requireNonce: true,
    getHtu: function () { return HTU; },
  });
  var iat = Math.floor(Date.now() / 1000);

  // The empty-string / non-string nonce claims sit in a validly-signed proof,
  // so verify() passes and the server-managed nonce check is what must reject
  // them — asserting use_dpop_nonce proves we reached that check rather than
  // bouncing off a signature failure.
  var emptyNonce = _handSign(key, { jti: "jti-empty-1", htm: HTM, htu: HTU, iat: iat, nonce: "" });
  var rEmpty = await _call(mw, _req({ headers: { dpop: emptyNonce } }));
  check("nonce empty-string claim: refused via the nonce check (use_dpop_nonce)",
        rEmpty.status === 401 && rEmpty.nextCalled === false && /use_dpop_nonce/.test(rEmpty.cap.body));

  var numNonce = _handSign(key, { jti: "jti-num-1", htm: HTM, htu: HTU, iat: iat, nonce: 12345 });
  var rNum = await _call(mw, _req({ headers: { dpop: numNonce } }));
  check("nonce non-string claim: refused via the nonce check (use_dpop_nonce)",
        rNum.status === 401 && rNum.nextCalled === false && /use_dpop_nonce/.test(rNum.cap.body));
}

// The rolling pair keeps the previous nonce valid across a rotation so an
// in-flight client one rotation behind is not kicked off (RFC 9449 §8).
async function testNoncePreviousAcceptedAcrossRotation() {
  var key = _ecPem();
  var t0 = Date.now();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    requireNonce: true,
    nonceRotateSec: 0.01,   // 10ms — rotate lazily on the next access after the window
    getHtu: function () { return HTU; },
  });

  // Issue the first (current) nonce via a challenge.
  var r1 = await _call(mw, _req());
  var n1 = r1.cap.headers["dpop-nonce"];
  check("rotation: first nonce issued", typeof n1 === "string" && n1.length > 0);

  // Let the rotation window elapse (poll, don't sleep). One waitUntil poll is
  // ~25ms, comfortably past the 10ms window.
  await helpers.waitUntil(function () { return Date.now() - t0 >= 40; }, {
    timeoutMs: 5000,
    label: "dpop nonce rotation: rotate window (10ms) elapsed",
  });

  // A proof built with the now-previous nonce n1 must still be accepted: the
  // access rotates current→previous, and n1 matches previous.
  var proofN1 = await _proof(key, { nonce: n1 });
  var r2 = await _call(mw, _req({ headers: { dpop: proofN1 } }));
  check("rotation: proof with the previous nonce still accepted", r2.nextCalled === true);
  var n2 = r2.res.getHeader("DPoP-Nonce");
  check("rotation: response carries the rotated (new current) nonce", typeof n2 === "string" && n2 !== n1);
}

// shutdown() drains the manager: it issues no fresh nonces and refuses every
// presented one, so the surrounding middleware 401s while the new instance owns
// the trust anchor.
async function testNonceManagerShutdown() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    requireNonce: true,
    getHtu: function () { return HTU; },
  });
  var r1 = await _call(mw, _req());
  var n1 = r1.cap.headers["dpop-nonce"];

  mw.shutdown();

  var proofN1 = await _proof(key, { nonce: n1 });
  var r2 = await _call(mw, _req({ headers: { dpop: proofN1 } }));
  check("shutdown: a previously-valid nonce is now refused (401)", r2.status === 401 && r2.nextCalled === false);
  check("shutdown: no fresh DPoP-Nonce is issued", !r2.cap.headers["dpop-nonce"]);
}

// revoke() rotates both slots immediately: the outstanding nonce is invalidated
// but the manager keeps serving fresh nonces afterward.
async function testNonceManagerRevoke() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    requireNonce: true,
    getHtu: function () { return HTU; },
  });
  var r1 = await _call(mw, _req());
  var n1 = r1.cap.headers["dpop-nonce"];

  mw.revoke();

  // The old nonce is dead.
  var proofOld = await _proof(key, { nonce: n1 });
  var rOld = await _call(mw, _req({ headers: { dpop: proofOld } }));
  check("revoke: the outstanding nonce is invalidated (401)", rOld.status === 401 && rOld.nextCalled === false);

  // A fresh challenge yields a working new nonce.
  var r2 = await _call(mw, _req());
  var n2 = r2.cap.headers["dpop-nonce"];
  check("revoke: manager still issues fresh nonces", typeof n2 === "string" && n2 !== n1);
  var proofNew = await _proof(key, { nonce: n2 });
  var rNew = await _call(mw, _req({ headers: { dpop: proofNew } }));
  check("revoke: a proof with the new nonce is accepted", rNew.nextCalled === true);
}

// The lifecycle hooks are no-ops (never throw) when requireNonce is off.
function testLifecycleHooksNoopWithoutNonce() {
  var mw = b.middleware.dpop({ replayStore: _ns() });
  var threw = null;
  try { mw.shutdown(); mw.revoke(); } catch (e) { threw = e; }
  check("lifecycle: shutdown()/revoke() are no-ops when requireNonce is off", threw === null);
}

// ---- access-token (ath) binding ----

async function testAthBinding() {
  var key = _ecPem();
  var token = "access-token-abc123";
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    getAccessToken: function () { return token; },
  });

  // Proof bound to the presented token → ath matches → next().
  var bound = await _proof(key, { accessToken: token });
  var rOk = await _call(mw, _req({ headers: { dpop: bound } }));
  check("ath: proof bound to the presented token verifies", rOk.nextCalled === true);

  // Proof with NO ath while a token is presented → 401 (missing-ath).
  var noAth = await _proof(key);
  var rMissing = await _call(mw, _req({ headers: { dpop: noAth } }));
  check("ath: proof with no ath but a presented token is refused", rMissing.status === 401 && rMissing.nextCalled === false);

  // Proof bound to a DIFFERENT token → 401 (ath-mismatch). Not fail-open.
  var otherBound = await _proof(key, { accessToken: "some-other-token" });
  var rMismatch = await _call(mw, _req({ headers: { dpop: otherBound } }));
  check("ath: proof bound to a different token is refused", rMismatch.status === 401 && rMismatch.nextCalled === false);
}

// A throwing getAccessToken is swallowed (drop-silent request-shape reader): the
// proof proceeds without ath binding rather than crashing the request.
async function testGetAccessTokenThrowSwallowed() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    getAccessToken: function () { throw new Error("boom extracting bearer"); },
  });
  var proof = await _proof(key);
  var r = await _call(mw, _req({ headers: { dpop: proof } }));
  check("getAccessToken throw: swallowed → no ath enforced → proof proceeds", r.nextCalled === true);
}

// ---- getNonce callback (operator-owned nonce, requireNonce off) ----

async function testGetNonceCallback() {
  var key = _ecPem();
  var serverNonce = "server-issued-nonce-xyz";
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    getNonce: function () { return serverNonce; },
  });

  // Proof carrying the expected nonce → next().
  var good = await _proof(key, { nonce: serverNonce });
  var rOk = await _call(mw, _req({ headers: { dpop: good } }));
  check("getNonce: proof with the expected nonce verifies", rOk.nextCalled === true);

  // Proof with no nonce → verify throws missing-nonce → 401 use_dpop_nonce.
  var noNonce = await _proof(key);
  var rMissing = await _call(mw, _req({ headers: { dpop: noNonce } }));
  check("getNonce: missing nonce is refused with use_dpop_nonce",
        rMissing.status === 401 && /use_dpop_nonce/.test(rMissing.cap.body) && rMissing.nextCalled === false);

  // Proof with a mismatched nonce → 401 use_dpop_nonce.
  var wrong = await _proof(key, { nonce: "not-the-server-nonce" });
  var rWrong = await _call(mw, _req({ headers: { dpop: wrong } }));
  check("getNonce: mismatched nonce is refused with use_dpop_nonce",
        rWrong.status === 401 && /use_dpop_nonce/.test(rWrong.cap.body));
}

// getNonce returning null skips nonce enforcement; a throwing getNonce is
// swallowed the same way (documented drop-silent).
async function testGetNonceNullAndThrow() {
  var key = _ecPem();
  var mwNull = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    getNonce: function () { return null; },
  });
  var p1 = await _proof(key);
  var r1 = await _call(mwNull, _req({ headers: { dpop: p1 } }));
  check("getNonce null: nonce enforcement skipped → proof proceeds", r1.nextCalled === true);

  var mwThrow = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    getNonce: function () { throw new Error("nonce lookup failed"); },
  });
  var p2 = await _proof(key);
  var r2 = await _call(mwThrow, _req({ headers: { dpop: p2 } }));
  check("getNonce throw: swallowed → proof proceeds", r2.nextCalled === true);
}

// ---- htu reconstruction edges + method binding ----

async function testHtuReconstructStripsQueryAndFragment() {
  var key = _ecPem();

  // No getHtu: proto/host are reconstructed from the (TLS) socket + Host header.
  // The proof binds https://api.example.com/resource; the request URL carries a
  // query + fragment that must be stripped before comparison (RFC 9449 §4.3).
  var proof = await _proof(key);
  var rQ = await _call(b.middleware.dpop({ replayStore: _ns() }),
                       _req({ url: "/resource?foo=1&bar=2", headers: { dpop: proof } }));
  check("htu: query string is stripped before comparison → proof verifies", rQ.nextCalled === true);

  var proof2 = await _proof(key, { jti: "jti-frag-1" });
  var rF = await _call(b.middleware.dpop({ replayStore: _ns() }),
                       _req({ url: "/resource#section", headers: { dpop: proof2 } }));
  check("htu: fragment is stripped before comparison → proof verifies", rF.nextCalled === true);

  // A request with no url reconstructs the root path "/".
  var rootProof = await _proof(key, { htu: "https://api.example.com/", jti: "jti-root-1" });
  var rootReq = b.testing.mockReq({ method: HTM, headers: { host: "api.example.com", dpop: rootProof }, socket: { encrypted: true } });
  delete rootReq.url;
  var rRoot = await _call(b.middleware.dpop({ replayStore: _ns() }), rootReq);
  check("htu: absent url reconstructs the root path → proof verifies", rRoot.nextCalled === true);
}

async function testHtuCannotReconstruct() {
  var key = _ecPem();

  // getHtu returns an empty string → htu falsy → 401 "could not reconstruct".
  var mwEmpty = b.middleware.dpop({ replayStore: _ns(), getHtu: function () { return ""; } });
  var proof = await _proof(key);
  var rEmpty = await _call(mwEmpty, _req({ headers: { dpop: proof } }));
  check("htu empty: getHtu returning '' → 401 could not reconstruct",
        rEmpty.status === 401 && /could not reconstruct/.test(rEmpty.cap.body));

  // No Host header + no forwarded trust → default host resolver returns null →
  // reconstruction fails → 401.
  var mwRecon = b.middleware.dpop({ replayStore: _ns() });
  var proof2 = await _proof(key, { jti: "jti-nohost-1" });
  var noHostReq = b.testing.mockReq({ method: HTM, url: "/resource", headers: { dpop: proof2 }, socket: { remoteAddress: "203.0.113.9", encrypted: true } });
  delete noHostReq.headers.host;
  var rRecon = await _call(mwRecon, noHostReq);
  check("htu no-host: reconstruction fails → 401", rRecon.status === 401 && rRecon.nextCalled === false);
}

async function testMethodMismatchAndMissing() {
  var key = _ecPem();
  var mw = b.middleware.dpop({ replayStore: _ns(), getHtu: function () { return HTU; } });

  // Proof built for POST, request is GET → htm mismatch → 401.
  var proof = await _proof(key);
  var rMis = await _call(mw, _req({ method: "GET", headers: { dpop: proof } }));
  check("htm mismatch: POST proof on a GET request is refused", rMis.status === 401 && rMis.nextCalled === false);

  // Missing method → htm "" → verify rejects a bad htm → 401 (fail closed).
  var proof2 = await _proof(key, { jti: "jti-nomethod-1" });
  var noMethodReq = b.testing.mockReq({ url: "/resource", headers: { host: "api.example.com", dpop: proof2 }, socket: { encrypted: true } });
  noMethodReq.method = "";
  var rNo = await _call(mw, noMethodReq);
  check("htm missing: empty method is refused (401)", rNo.status === 401 && rNo.nextCalled === false);
}

// ---- algorithm allowlist + iat freshness enforced at the middleware ----

async function testAlgorithmAllowlist() {
  var key = _ecPem();
  // Allow only EdDSA; an ES256 proof must be refused (alg not in the list).
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    algorithms: ["EdDSA"],
    getHtu: function () { return HTU; },
  });
  var es256 = await _proof(key);
  var r = await _call(mw, _req({ headers: { dpop: es256 } }));
  check("algorithms: an ES256 proof outside the allowlist is refused", r.status === 401 && r.nextCalled === false);
}

async function testIatWindow() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    iatWindowSec: 60,
    getHtu: function () { return HTU; },
  });
  // A proof issued 1000s ago is outside a 60s window → 401.
  var stale = await _proof(key, { iat: Math.floor(Date.now() / 1000) - 1000 });
  var r = await _call(mw, _req({ headers: { dpop: stale } }));
  check("iat window: a stale proof (iat far in the past) is refused", r.status === 401 && r.nextCalled === false);
}

// ---- DPoP header shape (RFC 9449 §4.1: exactly one proof per request) ----

async function testMissingHeaderNoNonce() {
  var mw = b.middleware.dpop({ replayStore: _ns() });
  var r = await _call(mw, _req());   // no dpop header
  check("missing header: 401 invalid_dpop_proof (no nonce manager)",
        r.status === 401 && /invalid_dpop_proof/.test(r.cap.body) && !r.cap.headers["dpop-nonce"]);
}

async function testCommaJoinedProofsRefused() {
  var key = _ecPem();
  var mw = b.middleware.dpop({ replayStore: _ns(), getHtu: function () { return HTU; } });
  var p1 = await _proof(key);
  var p2 = await _proof(key, { jti: "jti-comma-2" });
  var r = await _call(mw, _req({ headers: { dpop: p1 + "," + p2 } }));
  check("comma-joined: two proofs in one header value are refused",
        r.status === 401 && /multiple DPoP proofs/.test(r.cap.body) && r.nextCalled === false);
}

// RFC 9449 §4.1 — an array-valued DPoP header (more than one header line) must
// be refused AS a multiple-proof condition. The non-string guard used to shadow
// this branch, mislabeling it "DPoP header required"; the array case must reach
// its own diagnostic and never verify.
async function testArrayHeaderRefused() {
  var mw = b.middleware.dpop({ replayStore: _ns(), getHtu: function () { return HTU; } });
  var r = await _call(mw, _req({ headers: { dpop: ["proof-a", "proof-b"] } }));
  check("array header: an array-valued DPoP header is refused (401)",
        r.status === 401 && r.nextCalled === false);
  check("array header: refusal reports the RFC 9449 §4.1 multiple-header condition",
        /multiple DPoP headers/.test(r.cap.body));
}

// ---- 401 response-shaping knobs ----

async function testOnDenyHook() {
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    getHtu: function () { return HTU; },
    onDeny: function (req, res) { res.writeHead(499, { "content-type": "text/plain" }); res.end("owned"); },
  });
  var r = await _call(mw, _req());   // no proof → deny path → onDeny owns it
  check("onDeny: the operator hook owns the refusal response", r.status === 499 && r.cap.body === "owned");
}

async function testProblemDetails() {
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    problemDetails: true,
    getHtu: function () { return HTU; },
  });
  var r = await _call(mw, _req());   // no proof → deny path → problem+json
  // problemDetails.respond writes res.statusCode directly (not via writeHead).
  check("problemDetails: refusal is 401", r.res.statusCode === 401);
  var ct = r.res.getHeader("content-type") || "";
  check("problemDetails: content-type is application/problem+json", /problem\+json/.test(ct));
}

async function testAuditOffDoesNotThrow() {
  var key = _ecPem();
  var mw = b.middleware.dpop({
    replayStore: _ns(),
    audit: false,
    getHtu: function () { return HTU; },
  });
  // Success path with audit off.
  var good = await _proof(key);
  var rOk = await _call(mw, _req({ headers: { dpop: good } }));
  check("audit off: success path runs without emitting audit", rOk.nextCalled === true);
  // Failure path with audit off.
  var rBad = await _call(mw, _req({ headers: { dpop: "not-a-jwt" } }));
  check("audit off: failure path refuses without emitting audit", rBad.status === 401 && rBad.nextCalled === false);
}

// ---- create()-time option refusals ----

function testCreateOptionRefusals() {
  var threw1 = null;
  try { b.middleware.dpop({ replayStore: _ns(), nonceStore: {} }); } catch (e) { threw1 = e; }
  check("create: the obsolete nonceStore opt is refused", threw1 !== null && /nonceStore/.test(String(threw1.message || threw1)));

  var threw2 = null;
  try { b.middleware.dpop({ replayStore: _ns(), nonceWindowSec: 30 }); } catch (e) { threw2 = e; }
  check("create: the obsolete nonceWindowSec opt is refused", threw2 !== null && /nonceWindowSec/.test(String(threw2.message || threw2)));

  // Bad nonceRotateSec under requireNonce → throws at create().
  var threw3 = null;
  try { b.middleware.dpop({ replayStore: _ns(), requireNonce: true, nonceRotateSec: -5 }); } catch (e) { threw3 = e; }
  check("create: a non-positive nonceRotateSec is refused under requireNonce", threw3 !== null);

  // No-arg call: opts defaults to {} then the required replayStore is missing.
  var threw4 = null;
  try { b.middleware.dpop(); } catch (e) { threw4 = e; }
  check("create: no-arg call fails closed on the missing replay store", threw4 !== null);
}

async function run() {
  await testNonceChallengeAndAccept();
  await testMalformedNonceClaimRefused();
  await testNoncePreviousAcceptedAcrossRotation();
  await testNonceManagerShutdown();
  await testNonceManagerRevoke();
  testLifecycleHooksNoopWithoutNonce();
  await testAthBinding();
  await testGetAccessTokenThrowSwallowed();
  await testGetNonceCallback();
  await testGetNonceNullAndThrow();
  await testHtuReconstructStripsQueryAndFragment();
  await testHtuCannotReconstruct();
  await testMethodMismatchAndMissing();
  await testAlgorithmAllowlist();
  await testIatWindow();
  await testMissingHeaderNoNonce();
  await testCommaJoinedProofsRefused();
  await testArrayHeaderRefused();
  await testOnDenyHook();
  await testProblemDetails();
  await testAuditOffDoesNotThrow();
  testCreateOptionRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
