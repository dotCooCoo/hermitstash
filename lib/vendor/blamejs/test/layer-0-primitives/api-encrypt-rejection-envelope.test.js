"use strict";
/**
 * api-encrypt — protocol-level rejection bodies must ride the session
 * envelope on an ESTABLISHED per-session encrypted channel (#361).
 *
 * A client on a keyed per-session channel that sends a stale / replayed
 * / malformed request used to get an UNENCRYPTED { error: <code> } back,
 * leaking — in cleartext, over an otherwise-encrypted channel — which
 * validation tripped. The rejection must instead be wrapped exactly like
 * a successful response ({ _ct, _sid, _ctr }), with plaintext reserved
 * for pre-session handshake errors where no session context exists yet.
 *
 * Run standalone:
 *   node test/layer-0-primitives/api-encrypt-rejection-envelope.test.js
 * Or via smoke: node test/smoke.js
 */

var helpers  = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _bodyReq = helpers._bodyReq;
var _bodyRes = helpers._bodyRes;

function _newFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

function _mkRes() {
  var res = _bodyRes();
  // Mirror the router's res.json convention so the response-encryption
  // wrap chains correctly (the router installs this in production).
  res.json = function (data) {
    res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  };
  res.statusCode = 200;
  return res;
}

function _serverKeypair() {
  return b.crypto.generateEncryptionKeyPair();
}

// On an established per-session channel a rejection that consumes a
// persisted response counter (the post-claim tag-mismatch path) MUST be an
// encrypted envelope, not a plaintext { error } — leaking, in cleartext over
// an otherwise-encrypted channel, which check tripped. RED before #361
// (rejection emitted as plaintext JSON); GREEN once _writeRejection wraps it
// in the session envelope. The session must remain USABLE afterwards: the
// rejection rides a response counter the server actually persisted (the
// atomic claim ran before the decrypt failed), so the client's monotonic
// _ctr check still holds on the next genuine response.
async function testRejectionEncryptedOnEstablishedSession() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:      keypair,
    audit:        false,
    keying:       "per-session",
    sessionTtlMs: 60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap the session (ctr=1) — establishes the keyed channel.
  var first = clientCtx.encryptRequest({ user: "alice" });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true, n: 1 }); });
  await fin1;
  check("bootstrap returns 200", res1._endedStatus === 200);
  var resp1 = JSON.parse(res1._captured);
  check("bootstrap response is encrypted", typeof resp1._ct === "string");
  first.decryptResponse(resp1);   // advances the client's response counter

  // Valid second request (ctr=2) — server now expects ctr>2.
  var second = clientCtx.encryptRequest({ user: "alice", action: "ping" });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: true, n: 2 }); });
  await fin2;
  check("second request returns 200", res2._endedStatus === 200);
  second.decryptResponse(JSON.parse(res2._captured));

  // Third request with a FRESH counter (ctr=3) but a corrupted ciphertext:
  // it passes the shape / expiry / rotation / replay gates AND wins the
  // atomic (sid, ctr) claim — so the server persists the consumed response
  // counter — then fails the AEAD decrypt. This rejection rides the session
  // envelope under that persisted counter (the leak vector #361 closes).
  var third = clientCtx.encryptRequest({ user: "alice", action: "tamper" });
  var req3 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req3.body = JSON.parse(JSON.stringify(third.body));
  req3.body._ct = Buffer.from("corrupted-ciphertext-bytes").toString("base64");
  var res3 = _mkRes();
  var fin3 = _newFinish(res3);
  await mw(req3, res3, function () {
    check("tampered ciphertext must NOT reach next()", false);
  });
  await fin3;

  check("tampered request on established session returns 400", res3._endedStatus === 400);

  var rejBody = JSON.parse(res3._captured);
  // The core assertion: the rejection is an ENCRYPTED envelope, NOT a
  // plaintext { error: ... }. On the buggy tree rejBody.error is the
  // cleartext code and rejBody._ct is absent.
  check("rejection body carries NO plaintext error field",
        rejBody.error === undefined);
  check("rejection body is an encrypted envelope (_ct present)",
        typeof rejBody._ct === "string");
  check("rejection envelope is bound to the session sid",
        rejBody._sid === first.body._sid);
  check("rejection envelope carries a response counter",
        typeof rejBody._ctr === "number");

  // The encrypted rejection must decrypt under the session key to reveal
  // the error code only to the legitimate key-holder — and decrypting it
  // advances the client's response counter.
  var plain = third.decryptResponse(rejBody);
  check("decrypted rejection reveals the error code to the key-holder",
        plain && typeof plain.error === "string" && plain.error.length > 0);

  // P2 regression guard: the session must still be usable. The encrypted
  // rejection consumed a counter the server PERSISTED (it won the claim), so
  // the next genuine request's response counter is strictly above the one
  // the client just saw — decrypting it must NOT throw a replay error.
  var fourth = clientCtx.encryptRequest({ user: "alice", action: "after-reject" });
  var req4 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req4.body = fourth.body;
  var res4 = _mkRes();
  var fin4 = _newFinish(res4);
  await mw(req4, res4, function () { res4.json({ ok: true, n: 4 }); });
  await fin4;
  check("a genuine request after an encrypted rejection still returns 200",
        res4._endedStatus === 200);
  var afterReject = fourth.decryptResponse(JSON.parse(res4._captured));
  check("its response decrypts cleanly (counter stayed monotonic)",
        afterReject && afterReject.ok === true && afterReject.n === 4);
}

// P2: the two GENERIC surviving-session rejections (monotonic-counter replay
// and atomic-claim loss) return BEFORE the consumed response counter is
// persisted. Encrypting them would emit a _ctr the client tracks as consumed
// while the server never records it — so the next genuine response reuses
// that _ctr and the client refuses it as a replay, bricking the session.
// They must stay PLAINTEXT (their body is generic — no session-lifecycle
// reason leaks), and the session must remain usable across the rejection.
// RED before the P2 fix (replay rejection encrypted → the follow-up valid
// response desyncs → decryptResponse throws); GREEN after.
async function testReplayRejectionStaysPlaintextAndSessionSurvives() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session", sessionTtlMs: 60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap + one valid request so the channel is established (lastReqCtr=2).
  var first = clientCtx.encryptRequest({ user: "bob" });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true, n: 1 }); });
  await fin1;
  first.decryptResponse(JSON.parse(res1._captured));

  var second = clientCtx.encryptRequest({ user: "bob", action: "ping" });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: true, n: 2 }); });
  await fin2;
  second.decryptResponse(JSON.parse(res2._captured));

  // REPLAY the second request verbatim (stale _ctr=2 <= lastReqCtr=2). This
  // is the monotonic-replay path: it must refuse, and the refusal stays
  // plaintext so no unpersisted response counter is consumed.
  var reqR = _bodyReq("POST", { "content-type": "application/json" }, "");
  reqR.body = JSON.parse(JSON.stringify(second.body));
  var resR = _mkRes();
  var finR = _newFinish(resR);
  await mw(reqR, resR, function () { check("replay must NOT reach next()", false); });
  await finR;
  check("replay on established session returns 400", resR._endedStatus === 400);
  var replBody = JSON.parse(resR._captured);
  check("replay rejection is generic PLAINTEXT (no consumed counter)",
        replBody.error === "encrypted-payload-rejected" && replBody._ct === undefined);

  // The session must still work: a genuine next request (ctr=3) succeeds and
  // its response decrypts cleanly. On the pre-P2 tree the replay rejection
  // was an encrypted envelope whose _ctr the client consumed, so this
  // decryptResponse would throw CLIENT_RESPONSE_REPLAY.
  var third = clientCtx.encryptRequest({ user: "bob", action: "after-replay" });
  var req3 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req3.body = third.body;
  var res3 = _mkRes();
  var fin3 = _newFinish(res3);
  await mw(req3, res3, function () { res3.json({ ok: true, n: 3 }); });
  await fin3;
  check("a genuine request after a plaintext replay rejection returns 200",
        res3._endedStatus === 200);
  var afterReplay = third.decryptResponse(JSON.parse(res3._captured));
  check("its response decrypts cleanly (replay rejection did not desync the counter)",
        afterReplay && afterReplay.ok === true && afterReplay.n === 3);
}

// A pre-session handshake error — a bootstrap envelope whose _ek does not
// decrypt — has no session context yet, so the rejection MUST stay
// plaintext (the client cannot derive a session key to read an encrypted
// body it never established).
async function testHandshakeErrorStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session", sessionTtlMs: 60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap shape, but corrupt _ek so it fails to decrypt to a session
  // key — no session is ever established.
  var first = clientCtx.encryptRequest({ user: "mallory" });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = JSON.parse(JSON.stringify(first.body));
  req.body._ek = Buffer.from("not-a-valid-envelope").toString("base64");
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("handshake failure must NOT reach next()", false);
  });
  await fin;

  check("handshake error returns 400", res._endedStatus === 400);
  var body = JSON.parse(res._captured);
  check("pre-session handshake error stays PLAINTEXT (has error field)",
        typeof body.error === "string" && body.error.length > 0);
  check("pre-session handshake error is NOT an encrypted envelope",
        body._ct === undefined);
}

// A subsequent-shape request with a sid the server never saw is also a
// pre-session error (no key to encrypt under) — must stay plaintext.
async function testUnknownSidStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session",
  });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = {
    _ct:  Buffer.from("nope").toString("base64"),
    _ts:  Date.now(),
    _sid: "12345678-1234-4234-8234-123456789012",
    _ctr: 5,
  };
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("unknown sid must NOT reach next()", false);
  });
  await fin;
  check("unknown-sid returns 401", res._endedStatus === 401);
  var body = JSON.parse(res._captured);
  check("unknown-sid rejection stays plaintext (no session to key under)",
        typeof body.error === "string" && body._ct === undefined);
}

// Per-request mode never establishes a session, so its rejections stay
// plaintext (regression guard: the fix must not encrypt per-request
// errors, which have no session key on req).
async function testPerRequestModeRejectionStaysPlaintext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = { _ct: "garbage", _ts: Date.now() };   // no _ek/_nonce → shape error
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("per-request shape error must NOT reach next()", false);
  });
  await fin;
  check("per-request rejection returns 400", res._endedStatus === 400);
  var body = JSON.parse(res._captured);
  check("per-request rejection stays plaintext",
        typeof body.error === "string" && body._ct === undefined);
}

async function run() {
  await testRejectionEncryptedOnEstablishedSession();
  await testReplayRejectionStaysPlaintextAndSessionSurvives();
  await testHandshakeErrorStaysPlaintext();
  await testUnknownSidStaysPlaintext();
  await testPerRequestModeRejectionStaysPlaintext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); console.error(e.stack); process.exit(1); }
  );
}
