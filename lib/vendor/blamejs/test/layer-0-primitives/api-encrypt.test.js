"use strict";
/**
 * api-encrypt — end-to-end PQC payload encryption middleware.
 *
 * Covers nonce-store backends (memory, cluster, custom), the round-
 * trip request/response shape, replay rejection, stale-timestamp
 * rejection, AEAD tampering rejection, exempt-path bypass, and the
 * client helper.
 *
 * Run standalone: `node test/layer-0-primitives/api-encrypt.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var _bodyReq       = helpers._bodyReq;
var _bodyRes       = helpers._bodyRes;

// Register the finish listener BEFORE the middleware runs, otherwise
// res.end() fires synchronously inside the route handler and the
// listener attached afterward never sees it.
function _newFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

function _mkRes() {
  var res = _bodyRes();
  // Mirror the router's res.json convention so api-encrypt's wrap
  // chains correctly. The router would normally install this.
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

// ---- Nonce-store ----

async function testNonceStoreSurface() {
  check("b.nonceStore exposed",                  typeof b.nonceStore === "object");
  check("b.nonceStore.create is fn",             typeof b.nonceStore.create === "function");
  check("NonceStoreError is a class",            typeof b.nonceStore.NonceStoreError === "function");
}

async function testNonceStoreMemoryBasics() {
  var store = b.nonceStore.create({ backend: "memory" });
  check("memory backend reports name",           store.name === "memory");
  var expireAt = Date.now() + 60_000;
  check("first sighting returns true",           (await store.checkAndInsert("a", expireAt)) === true);
  check("repeat returns false (replay)",         (await store.checkAndInsert("a", expireAt)) === false);
  check("different nonce returns true",          (await store.checkAndInsert("b", expireAt)) === true);
  store.close();
}

async function testNonceStoreMemoryRejectsBadInput() {
  var store = b.nonceStore.create({ backend: "memory" });
  var threw = null;
  try { await store.checkAndInsert("", Date.now() + 60_000); } catch (e) { threw = e; }
  check("empty nonce rejected",                  threw && threw.code === "INVALID_NONCE");
  threw = null;
  try { await store.checkAndInsert("x", "later"); } catch (e) { threw = e; }
  check("non-number expireAt rejected",          threw && threw.code === "INVALID_EXPIRE");
  store.close();
}

async function testNonceStoreMemoryPurge() {
  var store = b.nonceStore.create({ backend: "memory" });
  var now = Date.now();
  await store.checkAndInsert("expiredA", now - 1000);
  await store.checkAndInsert("expiredB", now - 1);
  await store.checkAndInsert("fresh",    now + 60_000);
  check("size before purge: 3",                  store._size() === 3);
  var removed = await store.purgeExpired();
  check("purgeExpired returned 2",               removed === 2);
  check("size after purge: 1",                   store._size() === 1);
  // Expired nonce becomes reusable after purge — the framework
  // refuses replay only WITHIN the window.
  check("post-purge insert returns true",        (await store.checkAndInsert("expiredA", now + 60_000)) === true);
  store.close();
}

async function testNonceStoreClusterBasics() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ns-"));
  try {
    await setupTestDb(tmpDir);
    var store = b.nonceStore.create({ backend: "cluster" });
    check("cluster backend reports name",          store.name === "cluster");
    var expireAt = Date.now() + 60_000;
    check("cluster first sighting true",          (await store.checkAndInsert("c1", expireAt)) === true);
    check("cluster replay false",                 (await store.checkAndInsert("c1", expireAt)) === false);

    // A SECOND cluster store talking to the same DB sees the row too —
    // that's the whole point of cluster mode.
    var store2 = b.nonceStore.create({ backend: "cluster" });
    check("second instance sees the same row",    (await store2.checkAndInsert("c1", expireAt)) === false);
    check("second instance accepts new nonce",    (await store2.checkAndInsert("c2", expireAt)) === true);

    // Purge respects expireAt
    await store.checkAndInsert("oldA", Date.now() - 5000);
    var removed = await store.purgeExpired();
    check("cluster purgeExpired removed >= 1",    removed >= 1);

    store.close();
    store2.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testNonceStoreCustomBackend() {
  var calls = [];
  var custom = {
    checkAndInsert: function (n, e) {
      calls.push({ nonce: n, expireAt: e });
      return Promise.resolve(calls.length === 1);
    },
  };
  var store = b.nonceStore.create({ backend: custom });
  check("custom backend name='custom'",          store.name === "custom");
  check("first call returns true",               (await store.checkAndInsert("x", Date.now() + 60_000)) === true);
  check("second call returns false",             (await store.checkAndInsert("x", Date.now() + 60_000)) === false);
  check("custom backend got both calls",         calls.length === 2);
  // Default purgeExpired stub returns 0
  check("default purgeExpired returns 0",        (await store.purgeExpired()) === 0);
  store.close();
}

async function testNonceStoreUnknownBackend() {
  var threw = null;
  try { b.nonceStore.create({ backend: "memcached" }); } catch (e) { threw = e; }
  check("unknown backend rejected",              threw && threw.code === "UNKNOWN_BACKEND");
}

// ---- api-encrypt middleware ----

async function testApiEncryptKeypairValidated() {
  var threw = null;
  try { b.middleware.apiEncrypt({}); } catch (e) { threw = e; }
  check("missing keypair rejected at create",   threw && threw.code === "INVALID_KEYPAIR");
  threw = null;
  try {
    b.middleware.apiEncrypt({ keypair: { publicKey: "pem", privateKey: "pem" } });
  } catch (e) { threw = e; }
  check("non-hybrid keypair rejected",           threw && threw.code === "INVALID_KEYPAIR");
  threw = null;
  try { b.middleware.apiEncrypt({ keypairs: [] }); } catch (e) { threw = e; }
  check("empty keypairs array rejected",         threw && threw.code === "INVALID_KEYPAIR");
}

async function testApiEncryptMultiKeypairRotation() {
  // Build two server keypairs. The "active" keypair encrypts new
  // bootstraps; the previous one stays in the array so in-flight
  // requests still encrypted to it continue to decrypt.
  var prevKp = _serverKeypair();
  var newKp  = _serverKeypair();

  // Old client was bootstrapped against prevKp. Its outbound request
  // will encrypt _ek to prevKp's pubkey.
  var oldClient = b.middleware.apiEncrypt.client({ pubkey: prevKp });

  // Server middleware in rotation overlap: keypairs = [new, prev].
  var mw = b.middleware.apiEncrypt({
    keypairs: [newKp, prevKp],
    audit:    false,
  });

  var oldCall = oldClient.encryptRequest({ from: "old client" });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = oldCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);

  await mw(req, res, function () {
    check("rotation: req.body decrypted via prevKp", req.body.from === "old client");
    res.json({ ok: true });
  });
  await fin;

  check("rotation: 200 from server",            res._endedStatus === 200);
  var responseBody = JSON.parse(res._captured);
  // Old client decrypts the response with the session key it generated;
  // session key derives from prevKp encapsulation but the response is
  // wrapped with the same session key, so it round-trips.
  var plain = oldCall.decryptResponse(responseBody);
  check("rotation: old client decrypts response", plain.ok === true);

  // After rotation completes, dropping prevKp from the array means
  // old-client requests stop decrypting.
  var mwPostRotation = b.middleware.apiEncrypt({
    keypairs: [newKp],
    audit:    false,
  });
  var oldCall2 = oldClient.encryptRequest({ from: "post-rotation" });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = oldCall2.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mwPostRotation(req2, res2, function () {
    check("post-rotation: should not have called next", false);
  });
  await fin2;
  check("post-rotation: request rejected",      res2._endedStatus === 400);
}

async function testApiEncryptPublishesActiveKeypair() {
  var prevKp = _serverKeypair();
  var newKp  = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypairs: [newKp, prevKp],
    audit:    false,
  });
  var handler = mw.publishPublicKey();
  var req = _bodyReq("GET", {}, "");
  var res = _mkRes();
  handler(req, res);
  var body = JSON.parse(res._captured);
  check("publishes the active (first) keypair", body.publicKey === newKp.publicKey);
  check("does not publish previous keypair",    body.publicKey !== prevKp.publicKey);
}

async function testApiEncryptRoundTrip() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });

  var clientCall = clientCtx.encryptRequest({ user: "alice", action: "ping" });
  check("client.body has _ek/_ct/_ts/_nonce",
        typeof clientCall.body._ek === "string" &&
        typeof clientCall.body._ct === "string" &&
        typeof clientCall.body._ts === "number" &&
        typeof clientCall.body._nonce === "string");

  // Simulate a request that bodyParser already parsed.
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);

  var nextCalled = false;
  await mw(req, res, function () {
    nextCalled = true;
    check("middleware: req.body replaced with cleartext",
          req.body && req.body.user === "alice" && req.body.action === "ping");
    check("middleware: req.apiEncryptSessionKey stashed",
          Buffer.isBuffer(req.apiEncryptSessionKey) &&
          req.apiEncryptSessionKey.length === 32);
    res.json({ ok: true, echo: req.body });
  });
  await fin;

  check("middleware called next()",              nextCalled === true);
  check("response status 200",                   res._endedStatus === 200);

  var responseBody = JSON.parse(res._captured);
  check("response body has _ct only",            typeof responseBody._ct === "string" && !responseBody._ek);
  var plain = clientCall.decryptResponse(responseBody);
  check("client decrypted response",             plain && plain.ok === true && plain.echo.user === "alice");
}

async function testApiEncryptRejectsMissingShape() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = { msg: "not encrypted" };
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("middleware did NOT call next on missing shape", false);
  });
  await fin;
  check("missing-shape returns 400",             res._endedStatus === 400);
  check("missing-shape body says 'required'",    /encrypted-payload-required/.test(res._captured));
}

async function testApiEncryptRejectsStaleTimestamp() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:        keypair,
    audit:          false,
    replayWindowMs: 1000,   // 1 second window
  });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });
  // Backdate the timestamp past the window
  clientCall.body._ts = Date.now() - 10_000;

  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () { check("should not have called next", false); });
  await fin;
  check("stale ts returns 400",                  res._endedStatus === 400);
  check("stale ts uses generic rejection body",  /encrypted-payload-rejected/.test(res._captured));
}

async function testApiEncryptRejectsReplay() {
  var keypair = _serverKeypair();
  var nonceStore = b.nonceStore.create({ backend: "memory" });
  var mw = b.middleware.apiEncrypt({
    keypair:    keypair,
    audit:      false,
    nonceStore: nonceStore,
  });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });

  // First request: succeeds.
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = clientCall.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true }); });
  await fin1;
  check("first request: 200",                    res1._endedStatus === 200);

  // Replay the same body (same _ek, _ct, _ts, _nonce) → rejected.
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = clientCall.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { check("replay should not call next", false); });
  await fin2;
  check("replay: 400",                           res2._endedStatus === 400);
  check("replay uses generic rejection body",    /encrypted-payload-rejected/.test(res2._captured));

  nonceStore.close();
  mw.close();
}

async function testApiEncryptRejectsTamperedCiphertext() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var clientCall = clientCtx.encryptRequest({ x: 1 });

  // Flip a byte deep inside the ciphertext.
  var ctBuf = Buffer.from(clientCall.body._ct, "base64");
  ctBuf[ctBuf.length - 5] ^= 0xff;
  clientCall.body._ct = ctBuf.toString("base64");

  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = clientCall.body;
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () { check("tampered ct should not reach handler", false); });
  await fin;
  check("tampered ct: 400",                      res._endedStatus === 400);
}

async function testApiEncryptExemptPathBypass() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:     keypair,
    audit:       false,
    exemptPaths: ["/healthz", "/.well-known"],
  });
  var req = _bodyReq("GET", {}, "");
  req.url = "/healthz";
  req.pathname = "/healthz";
  req.body = undefined;
  var res = _mkRes();
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  check("exempt path: next called",              nextCalled === true);

  // /.well-known/blamejs-pubkey is also exempt because of the prefix rule.
  var req2 = _bodyReq("GET", {}, "");
  req2.url = "/.well-known/blamejs-pubkey";
  req2.pathname = "/.well-known/blamejs-pubkey";
  var res2 = _mkRes();
  var nextCalled2 = false;
  await mw(req2, res2, function () { nextCalled2 = true; });
  check("exempt prefix: next called",            nextCalled2 === true);
}

async function testApiEncryptPublishPublicKey() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var handler = mw.publishPublicKey();
  check("publishPublicKey returns a fn",         typeof handler === "function");

  var req = _bodyReq("GET", {}, "");
  var res = _mkRes();
  handler(req, res);
  // res.json is sync in our mock — read what it wrote.
  var body = JSON.parse(res._captured);
  check("published publicKey matches",           body.publicKey === keypair.publicKey);
  check("published ecPublicKey matches",         body.ecPublicKey === keypair.ecPublicKey);
  check("published kemId is hybrid",             body.kemId === b.constants.ACTIVE.KEM);
  check("private keys NOT published",
        !("privateKey" in body) && !("ecPrivateKey" in body));
}

async function testApiEncryptEventOnFailure() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var captured = [];
  var listener = function (info) { captured.push(info); };
  b.events.on(b.events.EVENTS.API_ENCRYPT_FAILURE, listener);
  try {
    var req = _bodyReq("POST", { "content-type": "application/json" }, "");
    req.body = { msg: "oops" };
    req.url = "/api/x";
    req.pathname = "/api/x";
    var res = _mkRes();
    var fin = _newFinish(res);
    await mw(req, res, function () {});
    await fin;
    check("event fired on failure",                captured.length === 1);
    check("event payload carries reason",          captured[0].reason === "shape");
    check("event payload carries path",            captured[0].path === "/api/x");
  } finally {
    b.events.off(b.events.EVENTS.API_ENCRYPT_FAILURE, listener);
  }
}

async function testApiEncryptAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ae-"));
  try {
    await setupTestDb(tmpDir);
    var keypair = _serverKeypair();
    var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: true });

    // Tampered ct → audit emits failure
    var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
    var call = clientCtx.encryptRequest({ x: 1 });
    var ctBuf = Buffer.from(call.body._ct, "base64");
    ctBuf[ctBuf.length - 1] ^= 0xff;
    call.body._ct = ctBuf.toString("base64");

    var req = _bodyReq("POST", { "content-type": "application/json" }, "");
    req.body = call.body;
    req.url = "/api/y";
    req.pathname = "/api/y";
    var res = _mkRes();
    var fin = _newFinish(res);
    await mw(req, res, function () {});
    await fin;

    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.api_encrypt.failure" });
    check("audit row written for failure",         rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit metadata carries reason=tag",     meta.reason === "tag");
    check("audit metadata carries path",           meta.path === "/api/y");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testApiEncryptClientRejectsBadPubkey() {
  var threw = null;
  try { b.middleware.apiEncrypt.client({ pubkey: null }); } catch (e) { threw = e; }
  check("client rejects null pubkey",             threw && threw.code === "CLIENT_INVALID_PUBKEY");
  threw = null;
  try { b.middleware.apiEncrypt.client({ pubkey: { publicKey: "pem" } }); } catch (e) { threw = e; }
  check("client rejects non-hybrid pubkey",       threw && threw.code === "CLIENT_INVALID_PUBKEY");
}

async function testApiEncryptContentTypeScoping() {
  // Default contentTypes = ["application/json"]. Requests with a
  // non-JSON Content-Type bypass the middleware entirely (they're
  // treated as a public route the operator chose to expose).
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  var req = _bodyReq("POST", { "content-type": "multipart/form-data; boundary=---x" }, "");
  req.body = { not: "encrypted" };
  var res = _mkRes();
  var nextCalled = false;
  await mw(req, res, function () { nextCalled = true; });
  check("non-JSON Content-Type bypasses middleware", nextCalled === true);
  check("body not replaced",                         req.body && req.body.not === "encrypted");

  // Explicit null disables the filter — every non-exempt request is
  // treated as encrypted regardless of Content-Type.
  var mwAll = b.middleware.apiEncrypt({
    keypair:      keypair,
    audit:        false,
    contentTypes: null,
  });
  var req2 = _bodyReq("POST", { "content-type": "text/plain" }, "");
  req2.body = { not: "encrypted" };
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mwAll(req2, res2, function () { check("contentTypes:null should not allow non-encrypted bodies through", false); });
  await fin2;
  check("contentTypes:null rejects raw body without _ek", res2._endedStatus === 400);

  // Custom list — operator wired form-encoded clients too.
  var mwForm = b.middleware.apiEncrypt({
    keypair:      keypair,
    audit:        false,
    contentTypes: ["application/json", "application/x-www-form-urlencoded"],
  });
  var req3 = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded" }, "");
  req3.body = { not: "encrypted" };
  var res3 = _mkRes();
  var fin3 = _newFinish(res3);
  await mwForm(req3, res3, function () { check("custom contentTypes should reject non-encrypted body", false); });
  await fin3;
  check("custom contentTypes catches form-encoded request", res3._endedStatus === 400);
}

async function testApiEncryptNonceHashedBeforeStorage() {
  // The cluster nonce store should never see the raw client nonce —
  // the middleware hashes via sha3 before passing to checkAndInsert.
  // Verify by pinning the cluster store and reading the table.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ae-"));
  try {
    await setupTestDb(tmpDir);
    var keypair = _serverKeypair();
    var nonceStore = b.nonceStore.create({ backend: "cluster" });
    var mw = b.middleware.apiEncrypt({
      keypair:    keypair,
      nonceStore: nonceStore,
      audit:      false,
    });
    var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
    var call = clientCtx.encryptRequest({ x: 1 });
    var rawNonce = call.body._nonce;

    var req = _bodyReq("POST", { "content-type": "application/json" }, "");
    req.body = call.body;
    var res = _mkRes();
    var fin = _newFinish(res);
    await mw(req, res, function () { res.json({ ok: true }); });
    await fin;
    check("hashed nonce: 200 first request",      res._endedStatus === 200);

    // The DB row's PRIMARY KEY is the SHA3 hash, not the raw nonce.
    var rows = b.db.prepare(
      "SELECT nonceHash FROM _blamejs_api_encrypt_nonces"
    ).all();
    check("hashed nonce: exactly one row stored", rows.length === 1);
    check("hashed nonce: row holds hash, not raw",
          rows[0].nonceHash !== rawNonce);
    check("hashed nonce: hash is sha3 of raw",
          rows[0].nonceHash === b.crypto.sha3Hash(rawNonce, "hex"));

    nonceStore.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testApiEncryptDerivedPruneInterval() {
  // pruneIntervalMs defaults to max(30s, replayWindowMs / 2) — derived
  // from replayWindowMs so tight-window deploys get correct cadence
  // automatically. Verify by calling the middleware twice; pruneExpired
  // should fire on the second call when (now - lastPruneAt) crosses the
  // half-window threshold.
  var keypair = _serverKeypair();
  var pruneCalls = 0;
  var fakeStore = {
    name:           "fake",
    checkAndInsert: function () { return Promise.resolve(true); },
    purgeExpired:   function () { pruneCalls++; return Promise.resolve(0); },
    close:          function () {},
  };
  var mw = b.middleware.apiEncrypt({
    keypair:        keypair,
    nonceStore:     fakeStore,
    replayWindowMs: 60_000,        // 1 min window
    // pruneIntervalMs defaults to 30_000 (max(30s, 60000/2))
    audit:          false,
  });
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });

  // First request — lastPruneAt is 0, so prune fires.
  var c1 = clientCtx.encryptRequest({ n: 1 });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = c1.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: 1 }); });
  await fin1;

  // Second request immediately after — lastPruneAt is ~now, prune skipped.
  var c2 = clientCtx.encryptRequest({ n: 2 });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = c2.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: 2 }); });
  await fin2;

  // Allow microtasks for the .catch chain
  await new Promise(function (r) { setImmediate(r); });
  check("derived prune: fires once across two close-together requests",
        pruneCalls === 1);
}

async function testApiEncryptHttpClientHelperShape() {
  var pub = _serverKeypair();
  var enc = b.httpClient.encrypted({ pubkey: pub });
  check("httpClient.encrypted returns request fn", typeof enc.request === "function");

  // Reject missing url + path
  var threw = null;
  try { await enc.request({ method: "POST", body: { x: 1 } }); }
  catch (e) { threw = e; }
  check("rejects request without url or path",     threw && threw.code === "CLIENT_INVALID_URL");

  // Reject path without baseUrl
  threw = null;
  try { await enc.request({ path: "/foo", body: { x: 1 } }); }
  catch (e) { threw = e; }
  check("rejects path without baseUrl",            threw && threw.code === "CLIENT_INVALID_URL");
}

async function testApiEncryptHttpClientRoundTrip() {
  // End-to-end: a real http server with the middleware mounted, and
  // b.httpClient.encrypted as the caller. Demonstrates the full
  // server-to-server flow.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aeh-"));
  try {
    await setupTestDb(tmpDir);

    var http = require("http");
    var keypair = _serverKeypair();
    var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });

    // Tiny server: only POST /api/echo, body parsed manually then
    // handed to the middleware.
    var server = http.createServer(function (req, res) {
      // Mirror the router's res.json convention.
      res.json = function (data) {
        res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      req.pathname = req.url.split("?")[0];
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        try { req.body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch (_e) { req.body = null; }
        mw(req, res, function () {
          res.json({ echo: req.body, server: "ok" });
        });
      });
    });
    var port = await helpers.listenOnRandomPort(server);

    var enc = b.httpClient.encrypted({
      pubkey:  keypair,                          // operators normally fetch from /.well-known
      baseUrl: "http://127.0.0.1:" + port,
      // Allow http for the test fixture (production uses https).
      method:  "POST",
    });
    var resp = await enc.request({
      path:             "/api/echo",
      body:             { user: "alice", n: 42 },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    check("httpClient.encrypted: 200",            resp.statusCode === 200);
    check("httpClient.encrypted: body decrypted", resp.body && resp.body.echo &&
                                                  resp.body.echo.user === "alice" &&
                                                  resp.body.echo.n === 42);
    check("httpClient.encrypted: server tag present", resp.body && resp.body.server === "ok");

    server.close();
    mw.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testApiEncryptClientRejectsBadResponse() {
  var keypair = _serverKeypair();
  var clientCtx = b.middleware.apiEncrypt.client({ pubkey: keypair });
  var call = clientCtx.encryptRequest({ x: 1 });
  var threw = null;
  try { call.decryptResponse({}); } catch (e) { threw = e; }
  check("client rejects response missing _ct",    threw && threw.code === "CLIENT_RESPONSE_SHAPE");
}

// ---- per-session keying mode (v0.7.3) ----

async function testApiEncryptPerSessionDefaultIsPerRequest() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({ keypair: keypair, audit: false });
  check("apiEncrypt: default keying is per-request", mw.keying === "per-request");
  check("apiEncrypt: per-request mode has no sessionStore", mw.sessionStore === null);
}

async function testApiEncryptPerSessionRejectsBadKeyingValue() {
  var keypair = _serverKeypair();
  var threw = null;
  try {
    b.middleware.apiEncrypt({ keypair: keypair, audit: false, keying: "every-second" });
  } catch (e) { threw = e; }
  check("apiEncrypt: rejects keying='every-second' at create-time",
        threw && /keying must be 'per-request' .* or 'per-session'/.test(threw.message));
}

async function testApiEncryptPerSessionRejectsBadTtl() {
  var keypair = _serverKeypair();
  var threw = null;
  try {
    b.middleware.apiEncrypt({
      keypair: keypair, audit: false,
      keying: "per-session", sessionTtlMs: -1,
    });
  } catch (e) { threw = e; }
  check("apiEncrypt: rejects negative sessionTtlMs",
        threw && /sessionTtlMs/.test(threw.message));
}

async function testApiEncryptPerSessionRejectsBadStore() {
  var keypair = _serverKeypair();
  var threw = null;
  try {
    b.middleware.apiEncrypt({
      keypair: keypair, audit: false,
      keying: "per-session",
      sessionStore: { get: function () {} },   // missing set / delete
    });
  } catch (e) { threw = e; }
  check("apiEncrypt: rejects sessionStore missing set/delete",
        threw && /sessionStore must expose/.test(threw.message));
}

async function testApiEncryptPerSessionBootstrapAndReuse() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:        keypair,
    audit:          false,
    keying:         "per-session",
    sessionTtlMs:   60_000,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // First request — bootstrap envelope
  var first = clientCtx.encryptRequest({ user: "alice" });
  check("per-session first req: has _ek", typeof first.body._ek === "string");
  check("per-session first req: has _sid (UUID)",
        typeof first.body._sid === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(first.body._sid));
  check("per-session first req: _ctr starts at 1", first.body._ctr === 1);

  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: true, n: 1 }); });
  await fin1;
  check("per-session first req: 200", res1._endedStatus === 200);

  var resp1 = JSON.parse(res1._captured);
  check("per-session response: has _sid", resp1._sid === first.body._sid);
  check("per-session response: has _ctr=1", resp1._ctr === 1);
  check("per-session response: no _ek (response is session-keyed)", !resp1._ek);
  var plain1 = first.decryptResponse(resp1);
  check("per-session response decrypts: ok=true n=1", plain1.ok === true && plain1.n === 1);

  // Second request — reuse session, no _ek
  var second = clientCtx.encryptRequest({ user: "alice", action: "ping" });
  check("per-session second req: NO _ek (KEM amortized)", !second.body._ek);
  check("per-session second req: NO _nonce (counter replaces nonce)", !second.body._nonce);
  check("per-session second req: same _sid as first", second.body._sid === first.body._sid);
  check("per-session second req: _ctr=2", second.body._ctr === 2);

  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () {
    check("per-session second req: req.body decrypted",
          req2.body.user === "alice" && req2.body.action === "ping");
    res2.json({ ok: true, n: 2 });
  });
  await fin2;
  check("per-session second req: 200", res2._endedStatus === 200);
  var resp2 = JSON.parse(res2._captured);
  check("per-session response 2: _ctr=2 (monotonic)", resp2._ctr === 2);
  var plain2 = second.decryptResponse(resp2);
  check("per-session response 2 decrypts", plain2.n === 2);
}

async function testApiEncryptPerSessionUnknownSid() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session",
  });
  // Subsequent-shape request with sid the server has never seen.
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = {
    _ct: Buffer.from("nope").toString("base64"),
    _ts: Date.now(),
    _sid: "12345678-1234-4234-8234-123456789012",
    _ctr: 5,
  };
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () {
    check("middleware did NOT call next on unknown sid", false);
  });
  await fin;
  check("per-session unknown-sid: 401", res._endedStatus === 401);
  check("per-session unknown-sid: body says session-unknown",
        /session-unknown/.test(res._captured));
}

async function testApiEncryptPerSessionCounterReplay() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session",
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  // Bootstrap + valid second request bring server's lastReqCtr to 2
  var first = clientCtx.encryptRequest({ n: 1 });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: 1 }); });
  await fin1;

  var second = clientCtx.encryptRequest({ n: 2 });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: 2 }); });
  await fin2;

  // Replay the SECOND request — same _ctr=2 as already-seen.
  var req3 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req3.body = second.body;
  var res3 = _mkRes();
  var fin3 = _newFinish(res3);
  await mw(req3, res3, function () {
    check("replay should NOT reach next()", false);
  });
  await fin3;
  check("per-session replayed counter: 400", res3._endedStatus === 400);
}

async function testApiEncryptPerSessionExpiry() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false,
    keying: "per-session",
    sessionTtlMs: 1,                // 1ms — expires immediately
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  var first = clientCtx.encryptRequest({ n: 1 });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: 1 }); });
  await fin1;

  // Wait so the session row is past expiresAt (sessionTtlMs is 1).
  await helpers.passiveObserve(20, "apiEncrypt: sessionTtlMs=1 row past expiresAt");

  var second = clientCtx.encryptRequest({ n: 2 });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () {
    check("expired session should NOT reach next()", false);
  });
  await fin2;
  check("per-session expired: 401", res2._endedStatus === 401);
  check("per-session expired: body says session-expired or session-unknown",
        /session-expired|session-unknown/.test(res2._captured));
}

async function testApiEncryptPerSessionMaxResponses() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair:             keypair,
    audit:               false,
    keying:              "per-session",
    sessionMaxResponses: 1,                // session ends after 1 response
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  var first = clientCtx.encryptRequest({ n: 1 });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: 1 }); });
  await fin1;
  check("per-session maxResponses first req: 200", res1._endedStatus === 200);

  // Second request exceeds the cap.
  var second = clientCtx.encryptRequest({ n: 2 });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () {
    check("rotated session should NOT reach next()", false);
  });
  await fin2;
  check("per-session maxResponses exceeded: 401", res2._endedStatus === 401);
  check("per-session maxResponses exceeded: body says rotation-required",
        /session-rotation-required/.test(res2._captured));
}

async function testApiEncryptPerSessionResponseCounterMonotonic() {
  var keypair = _serverKeypair();
  var mw = b.middleware.apiEncrypt({
    keypair: keypair, audit: false, keying: "per-session",
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });

  var first = clientCtx.encryptRequest({ n: 1 });
  var req1 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req1.body = first.body;
  var res1 = _mkRes();
  var fin1 = _newFinish(res1);
  await mw(req1, res1, function () { res1.json({ ok: 1 }); });
  await fin1;
  var resp1 = JSON.parse(res1._captured);
  // Client tampers: replays the same response (same _ctr).
  var threw = null;
  try { first.decryptResponse(resp1); }
  catch (_e) { /* first decrypt fine */ }

  // Now submit the second request and feed back response 1 again — client
  // helper rejects because counter is not strictly increasing.
  var second = clientCtx.encryptRequest({ n: 2 });
  var req2 = _bodyReq("POST", { "content-type": "application/json" }, "");
  req2.body = second.body;
  var res2 = _mkRes();
  var fin2 = _newFinish(res2);
  await mw(req2, res2, function () { res2.json({ ok: 2 }); });
  await fin2;
  threw = null;
  try { second.decryptResponse(resp1); } catch (e) { threw = e; }
  check("client rejects replayed response (counter not strictly increasing)",
        threw && threw.code === "CLIENT_RESPONSE_REPLAY");
}

async function testApiEncryptPerSessionSessionInfo() {
  var keypair = _serverKeypair();
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });
  var info0 = clientCtx.sessionInfo();
  check("sessionInfo before any request: sid is null",  info0.sid === null);
  check("sessionInfo before any request: reqCtr=0",    info0.reqCtr === 0);
  clientCtx.encryptRequest({ x: 1 });
  var info1 = clientCtx.sessionInfo();
  check("sessionInfo after first req: sid populated",   typeof info1.sid === "string");
  check("sessionInfo after first req: reqCtr=1",       info1.reqCtr === 1);
  clientCtx.encryptRequest({ x: 2 });
  var info2 = clientCtx.sessionInfo();
  check("sessionInfo after second req: reqCtr=2",      info2.reqCtr === 2);
  check("sessionInfo: sid stable across requests",      info1.sid === info2.sid);
}

async function testApiEncryptPerSessionResetRotates() {
  var keypair = _serverKeypair();
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });
  var first = clientCtx.encryptRequest({ n: 1 });
  var sid1 = first.body._sid;
  clientCtx.resetSession();
  var second = clientCtx.encryptRequest({ n: 2 });
  check("client resetSession rotates sid",              second.body._sid !== sid1);
  check("client resetSession resets ctr to 1",          second.body._ctr === 1);
  check("client resetSession: bootstrap envelope again", typeof second.body._ek === "string");
}

async function testApiEncryptObservabilityCounters() {
  var keypair = _serverKeypair();
  var emitted = [];
  var fakeObs = {
    safeEvent: function (name, value, labels) {
      emitted.push({ name: name, value: value, labels: labels });
    },
    event: function () {},
  };
  var mw = b.middleware.apiEncrypt({
    keypair:       keypair,
    audit:         false,
    keying:        "per-session",
    observability: fakeObs,
  });
  var clientCtx = b.middleware.apiEncrypt.client({
    pubkey: keypair, keying: "per-session",
  });
  var first = clientCtx.encryptRequest({ n: 1 });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "");
  req.body = first.body;
  var res = _mkRes();
  var fin = _newFinish(res);
  await mw(req, res, function () { res.json({ ok: 1 }); });
  await fin;
  var hasCreated = emitted.some(function (e) { return e.name === "apiEncrypt.session.created"; });
  check("observability emits apiEncrypt.session.created on bootstrap", hasCreated);
}

async function run() {
  await testNonceStoreSurface();
  await testNonceStoreMemoryBasics();
  await testNonceStoreMemoryRejectsBadInput();
  await testNonceStoreMemoryPurge();
  await testNonceStoreClusterBasics();
  await testNonceStoreCustomBackend();
  await testNonceStoreUnknownBackend();

  await testApiEncryptKeypairValidated();
  await testApiEncryptRoundTrip();
  await testApiEncryptRejectsMissingShape();
  await testApiEncryptRejectsStaleTimestamp();
  await testApiEncryptRejectsReplay();
  await testApiEncryptRejectsTamperedCiphertext();
  await testApiEncryptExemptPathBypass();
  await testApiEncryptPublishPublicKey();
  await testApiEncryptEventOnFailure();
  await testApiEncryptAuditEmit();
  await testApiEncryptClientRejectsBadPubkey();
  await testApiEncryptClientRejectsBadResponse();
  await testApiEncryptMultiKeypairRotation();
  await testApiEncryptPublishesActiveKeypair();
  await testApiEncryptContentTypeScoping();
  await testApiEncryptNonceHashedBeforeStorage();
  await testApiEncryptDerivedPruneInterval();
  await testApiEncryptHttpClientHelperShape();
  await testApiEncryptHttpClientRoundTrip();

  // v0.7.3 — per-session keying mode
  await testApiEncryptPerSessionDefaultIsPerRequest();
  await testApiEncryptPerSessionRejectsBadKeyingValue();
  await testApiEncryptPerSessionRejectsBadTtl();
  await testApiEncryptPerSessionRejectsBadStore();
  await testApiEncryptPerSessionBootstrapAndReuse();
  await testApiEncryptPerSessionUnknownSid();
  await testApiEncryptPerSessionCounterReplay();
  await testApiEncryptPerSessionExpiry();
  await testApiEncryptPerSessionMaxResponses();
  await testApiEncryptPerSessionResponseCounterMonotonic();
  await testApiEncryptPerSessionSessionInfo();
  await testApiEncryptPerSessionResetRotates();
  await testApiEncryptObservabilityCounters();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); console.error(e.stack); process.exit(1); }
  );
}
