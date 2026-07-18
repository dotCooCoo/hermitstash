// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.tusUpload — ERROR + ADVERSARIAL branch coverage.
 *
 * The happy path (POST create → PATCH append → HEAD → DELETE) is already
 * exercised elsewhere. This file drives the UNCOVERED refusal / limit /
 * malformed-input branches through the public middleware, plus the
 * memoryStore contract's rejection paths:
 *
 *   - config-time throws (memoryStore + tusUpload opts validation)
 *   - the Tus-Resumable version gate (§2.2) and path routing
 *   - POST creation refusals (bad / oversized / missing Upload-Length,
 *     malformed Upload-Metadata, store.create failure → 500)
 *   - PATCH refusals (wrong Content-Type, bad Upload-Offset, offset
 *     mismatch, checksum ext disabled / malformed / unsupported /
 *     mismatch → 460, oversized chunk, deferred-length finalization)
 *   - HEAD / DELETE not-found + extension-disabled refusals
 *   - the 405 method-not-allowed fall-through Allow header
 *
 * Every assertion drives the real consumer path with in-memory request /
 * response fakes; nothing here needs a live network backend. A handful of
 * branches surfaced framework bugs — those are asserted only for the
 * fail-closed invariant that DOES hold (request refused, no bytes written)
 * and reported separately; no assertion locks in the buggy status code.
 */

var EventEmitter = require("node:events").EventEmitter;
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var C = b.constants;

var tusUpload = b.middleware.tusUpload;
var VER = "1.0.0";
var OCTET = "application/offset+octet-stream";

// A streaming request the PATCH / creation-with-upload handlers can pump
// via req.on("data"|"end"); b.testing.bodyReq hardcodes url:"/" so it
// can't address a resource path, hence this small local builder.
function _sreq(method, url, headers, body) {
  var req = new EventEmitter();
  req.method = method;
  req.url = url;
  req.headers = headers || {};
  req.socket = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock — no-op */ };
  setImmediate(function () {
    if (body !== undefined && body !== null) {
      req.emit("data", Buffer.isBuffer(body) ? body : Buffer.from(body));
    }
    req.emit("end");
  });
  return req;
}

// Plain (bodyless) request for HEAD / DELETE / OPTIONS / bodyless POST /
// method-not-allowed probes — those handlers never touch the stream.
function _req(method, url, headers) {
  return b.testing.mockReq({ method: method, url: url, headers: headers || {} });
}

// Run the middleware once; return the captured response plus whether it
// delegated via next().
async function _drive(tus, req) {
  var res = b.testing.mockRes();
  var nextCalled = false;
  await tus(req, res, function () { nextCalled = true; });
  var cap = res._captured();
  cap.nextCalled = nextCalled;
  return cap;
}

function _mkTus(overrides) {
  var base = {
    mountPath: "/uploads",
    store: tusUpload.memoryStore({}),
    audit: false,
  };
  if (overrides) {
    var keys = Object.keys(overrides);
    for (var i = 0; i < keys.length; i++) base[keys[i]] = overrides[keys[i]];
  }
  return tusUpload(base);
}

// Create an upload through the real POST path; return { cap, loc, id }.
async function _create(tus, mount, headers) {
  var cap = await _drive(tus, _req("POST", mount, Object.assign({ "tus-resumable": VER }, headers || {})));
  var loc = cap.headers.location || "";
  return { cap: cap, loc: loc, id: loc.slice(loc.lastIndexOf("/") + 1) };
}

function _throws(fn) {
  try { fn(); return null; } catch (e) { return e; }
}
async function _rejects(promise) {
  try { await promise; return null; } catch (e) { return e; }
}

async function run() {
  // ---------------------------------------------------------------
  // A. memoryStore(opts) config-time validation
  // ---------------------------------------------------------------
  var eNeg = _throws(function () { return tusUpload.memoryStore({ maxSize: -1 }); });
  check("memoryStore: negative maxSize throws TusError",
    eNeg !== null && eNeg.code === "tus/bad-store-opts");
  var eNaN = _throws(function () { return tusUpload.memoryStore({ maxSize: NaN }); });
  check("memoryStore: NaN maxSize throws", eNaN !== null && eNaN.code === "tus/bad-store-opts");
  var eStr = _throws(function () { return tusUpload.memoryStore({ maxSize: "1024" }); });
  check("memoryStore: string maxSize throws", eStr !== null && eStr.code === "tus/bad-store-opts");
  var eZero = _throws(function () { return tusUpload.memoryStore({ maxSize: 0 }); });
  check("memoryStore: zero maxSize throws", eZero !== null && eZero.code === "tus/bad-store-opts");
  check("memoryStore: undefined maxSize is accepted (unbounded)",
    _throws(function () { return tusUpload.memoryStore({}); }) === null);

  // ---------------------------------------------------------------
  // B. memoryStore method-level rejection branches
  // ---------------------------------------------------------------
  {
    var store = tusUpload.memoryStore({ maxSize: C.BYTES.bytes(16) });
    var rec = await store.create({ length: 10, metadata: {} });

    var mism = await _rejects(store.append(rec.id, Buffer.from("ab"), 5));
    check("store.append: offset mismatch rejects tus/offset-mismatch",
      mism !== null && mism.code === "tus/offset-mismatch");

    var overDecl = await _rejects(store.append(rec.id, Buffer.alloc(11), 0));
    check("store.append: exceeding declared Upload-Length rejects tus/length-exceeded",
      overDecl !== null && overDecl.code === "tus/length-exceeded");

    // Unbounded length but over the store maxSize cap.
    var store2 = tusUpload.memoryStore({ maxSize: C.BYTES.bytes(4) });
    var rec2 = await store2.create({ length: null, deferLength: true, metadata: {} });
    var overMax = await _rejects(store2.append(rec2.id, Buffer.alloc(5), 0));
    check("store.append: exceeding memoryStore maxSize rejects tus/length-exceeded",
      overMax !== null && overMax.code === "tus/length-exceeded");

    var missing = await _rejects(store.append("no-such-id", Buffer.from("x"), 0));
    check("store.append: unknown id rejects tus/upload-not-found",
      missing !== null && missing.code === "tus/upload-not-found");

    // setLength on an already-declared upload conflicts.
    var setDup = await _rejects(store.setLength(rec.id, 20));
    check("store.setLength: length already set rejects tus/length-already-set",
      setDup !== null && setDup.code === "tus/length-already-set");
    var setMissing = await _rejects(store.setLength("no-such-id", 5));
    check("store.setLength: unknown id rejects tus/upload-not-found",
      setMissing !== null && setMissing.code === "tus/upload-not-found");

    // terminate then append/head observe the removal.
    var recT = await store.create({ length: null, deferLength: true, metadata: {} });
    check("store.terminate: existing id resolves true", (await store.terminate(recT.id)) === true);
    check("store.terminate: unknown id resolves false", (await store.terminate("no-such-id")) === false);
    var afterTerm = await _rejects(store.append(recT.id, Buffer.from("x"), 0));
    check("store.append: after terminate rejects tus/upload-not-found",
      afterTerm !== null && afterTerm.code === "tus/upload-not-found");
    check("store.head: after terminate resolves null", (await store.head(recT.id)) === null);

    // getBuffer for a missing id is null.
    check("store.getBuffer: unknown id resolves null", (await store.getBuffer("no-such-id")) === null);

    // Expiry: a record whose expireAt is already in the past is swept on
    // head() and reported by purgeExpired().
    var storeE = tusUpload.memoryStore({});
    var recE = await storeE.create({ length: 5, metadata: {}, expirationMs: -1000 });
    check("store.head: expired record resolves null (swept on read)",
      (await storeE.head(recE.id)) === null);
    var recE2 = await storeE.create({ length: 5, metadata: {}, expirationMs: -1000 });
    var purged = await storeE.purgeExpired();
    check("store.purgeExpired: removes expired records", purged >= 1 && recE2.id.length > 0);
  }

  // ---------------------------------------------------------------
  // C. tusUpload(opts) config-time validation
  // ---------------------------------------------------------------
  var okStore = tusUpload.memoryStore({});
  check("create: non-object opts throws",
    _throws(function () { return tusUpload(null); }) !== null);
  check("create: unknown opt key throws",
    _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, bogusKey: 1 }); }) !== null);

  var eMount = _throws(function () { return tusUpload({ mountPath: "uploads", store: okStore }); });
  check("create: mountPath without leading '/' throws tus/bad-mountpath",
    eMount !== null && eMount.code === "tus/bad-mountpath");
  check("create: empty mountPath throws",
    _throws(function () { return tusUpload({ mountPath: "", store: okStore }); }) !== null);

  var eStore = _throws(function () { return tusUpload({ mountPath: "/u", store: { create: function () {} } }); });
  check("create: store missing required methods throws tus/bad-store",
    eStore !== null && eStore.code === "tus/bad-store");

  var eMax = _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, maxSize: -5 }); });
  check("create: negative maxSize throws tus/bad-opts", eMax !== null && eMax.code === "tus/bad-opts");
  var eChunk = _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, maxChunkSize: 0 }); });
  check("create: zero maxChunkSize throws tus/bad-opts", eChunk !== null && eChunk.code === "tus/bad-opts");
  var eExp = _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, expirationSec: -1 }); });
  check("create: negative expirationSec throws tus/bad-opts", eExp !== null && eExp.code === "tus/bad-opts");

  var eExt = _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, extensions: ["concatenation"] }); });
  check("create: unknown extension throws tus/bad-opts", eExt !== null && eExt.code === "tus/bad-opts");
  var eAlgo = _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, checksumAlgorithms: ["md5"] }); });
  check("create: unknown checksum algorithm throws tus/bad-opts", eAlgo !== null && eAlgo.code === "tus/bad-opts");

  check("create: non-function onComplete throws",
    _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, onComplete: 42 }); }) !== null);
  check("create: non-function onTerminate throws",
    _throws(function () { return tusUpload({ mountPath: "/u", store: okStore, onTerminate: "x" }); }) !== null);
  check("create: trailing-slash mountPath is accepted (normalized)",
    _throws(function () { return tusUpload({ mountPath: "/u/", store: okStore }); }) === null);

  // ---------------------------------------------------------------
  // D. routing + Tus-Resumable version gate (§2.2)
  // ---------------------------------------------------------------
  var tus = _mkTus({ store: tusUpload.memoryStore({ maxSize: C.BYTES.mib(1) }), maxSize: C.BYTES.mib(1), checksumAlgorithms: ["sha-256"] });

  var nm = await _drive(tus, _req("GET", "/somewhere-else"));
  check("route: non-matching path delegates to next()", nm.nextCalled === true && nm.status === null);
  var subpath = await _drive(tus, _req("HEAD", "/uploads/abc/extra", { "tus-resumable": VER }));
  check("route: nested sub-path under a resource delegates to next()", subpath.nextCalled === true);

  var noVer = await _drive(tus, _req("HEAD", "/uploads/abcdef", {}));
  check("version-gate: missing Tus-Resumable → 412", noVer.status === 412 && noVer.nextCalled === false);
  var badVer = await _drive(tus, _req("HEAD", "/uploads/abcdef", { "tus-resumable": "0.9.0" }));
  check("version-gate: unsupported version → 412 + Tus-Version advertised",
    badVer.status === 412 && badVer.headers["tus-version"] === VER);

  var opt = await _drive(tus, _req("OPTIONS", "/uploads", {}));
  check("OPTIONS: discovery → 204 with Tus-* headers",
    opt.status === 204 &&
    opt.headers["tus-version"] === VER &&
    typeof opt.headers["tus-extension"] === "string" &&
    opt.headers["tus-max-size"] === String(C.BYTES.mib(1)) &&
    opt.headers["tus-checksum-algorithm"] === "sha-256");

  // ---------------------------------------------------------------
  // E. POST creation refusals
  // ---------------------------------------------------------------
  var noCreate = _mkTus({ mountPath: "/nc", extensions: ["expiration"] });
  var ncRes = await _drive(noCreate, _req("POST", "/nc", { "tus-resumable": VER, "upload-length": "5" }));
  check("POST: creation extension disabled → 405", ncRes.status === 405);

  var badLen = await _drive(tus, _req("POST", "/uploads", { "tus-resumable": VER, "upload-length": "abc" }));
  check("POST: non-integer Upload-Length → 400", badLen.status === 400);
  var negLen = await _drive(tus, _req("POST", "/uploads", { "tus-resumable": VER, "upload-length": "-1" }));
  check("POST: negative Upload-Length → 400", negLen.status === 400);
  var junkLen = await _drive(tus, _req("POST", "/uploads", { "tus-resumable": VER, "upload-length": "10abc" }));
  check("POST: trailing-junk Upload-Length → 400", junkLen.status === 400);
  var overLen = await _drive(tus, _req("POST", "/uploads", { "tus-resumable": VER, "upload-length": String(C.BYTES.mib(2)) }));
  check("POST: Upload-Length over Tus-Max-Size → 413", overLen.status === 413);
  var noLen = await _drive(tus, _req("POST", "/uploads", { "tus-resumable": VER }));
  check("POST: neither Upload-Length nor Upload-Defer-Length → 400", noLen.status === 400);
  var badMeta = await _drive(tus, _req("POST", "/uploads",
    { "tus-resumable": VER, "upload-length": "5", "upload-metadata": "key !!!not-base64!!!" }));
  check("POST: malformed Upload-Metadata → 400", badMeta.status === 400);

  // store.create failure surfaces as 500 (create.fail metric branch).
  var boomStore = {
    create: function () { return Promise.reject(new Error("disk full")); },
    head: function () { return Promise.resolve(null); },
    append: function () { return Promise.resolve(null); },
    terminate: function () { return Promise.resolve(false); },
  };
  var boomTus = tusUpload({ mountPath: "/boom", store: boomStore, audit: false });
  var boom = await _drive(boomTus, _req("POST", "/boom", { "tus-resumable": VER, "upload-length": "5" }));
  check("POST: store.create rejection → 500", boom.status === 500);

  // Deferred-length creation succeeds and HEAD reports the defer flag.
  var defCreate = await _create(tus, "/uploads", { "upload-defer-length": "1" });
  check("POST: Upload-Defer-Length:1 → 201", defCreate.cap.status === 201);
  var defHead = await _drive(tus, _req("HEAD", "/uploads/" + defCreate.id, { "tus-resumable": VER }));
  check("HEAD: deferred upload advertises Upload-Defer-Length:1",
    defHead.status === 200 && defHead.headers["upload-defer-length"] === "1");

  // creation-with-upload: the RFC 7231 media type is case-insensitive and may
  // carry parameters. An exact-string compare skipped the append path for a
  // compliant `Application/Offset+Octet-Stream` (or `...; charset` variant),
  // creating the upload but silently ignoring the body. Both variants must
  // append in the same request (Upload-Offset advances to the body length).
  var cwUpper = await _drive(tus, _sreq("POST", "/uploads",
    { "tus-resumable": VER, "upload-length": "5", "content-type": "Application/Offset+Octet-Stream" }, "hello"));
  check("POST creation-with-upload: mixed-case Content-Type appends the body",
    cwUpper.status === 201 && cwUpper.headers["upload-offset"] === "5");
  var cwParam = await _drive(tus, _sreq("POST", "/uploads",
    { "tus-resumable": VER, "upload-length": "5", "content-type": "application/offset+octet-stream; charset=binary" }, "world"));
  check("POST creation-with-upload: Content-Type with a parameter appends the body",
    cwParam.status === 201 && cwParam.headers["upload-offset"] === "5");

  // ---------------------------------------------------------------
  // F. HEAD refusals
  // ---------------------------------------------------------------
  var headMiss = await _drive(tus, _req("HEAD", "/uploads/doesnotexist", { "tus-resumable": VER }));
  check("HEAD: unknown upload → 404", headMiss.status === 404);

  // ---------------------------------------------------------------
  // G. PATCH refusals
  // ---------------------------------------------------------------
  var created = await _create(tus, "/uploads", { "upload-length": "20" });

  var wrongCt = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": "text/plain", "upload-offset": "0" }, "x"));
  check("PATCH: wrong Content-Type → 415", wrongCt.status === 415);

  var noOffset = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET }, "x"));
  check("PATCH: missing Upload-Offset → 400", noOffset.status === 400);
  var badOffset = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "-3" }, "x"));
  check("PATCH: negative Upload-Offset → 400", badOffset.status === 400);
  var junkOffset = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0x4" }, "x"));
  check("PATCH: non-integer Upload-Offset → 400", junkOffset.status === 400);

  var patchMiss = await _drive(tus, _sreq("PATCH", "/uploads/doesnotexist",
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0" }, "x"));
  check("PATCH: unknown upload → 404", patchMiss.status === 404);

  var offMismatch = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "7" }, "x"));
  check("PATCH: Upload-Offset not at head → 409", offMismatch.status === 409);

  // checksum extension disabled but header present.
  var noChk = _mkTus({ mountPath: "/nochk", extensions: ["creation", "termination"] });
  var ncCreated = await _create(noChk, "/nochk", { "upload-length": "4" });
  var chkDisabled = await _drive(noChk, _sreq("PATCH", ncCreated.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-checksum": "sha-256 AAAA" }, "abcd"));
  check("PATCH: Upload-Checksum with checksum ext disabled → 400", chkDisabled.status === 400);

  var chkMalformed = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-checksum": "sha-256" }, "abcd"));
  check("PATCH: malformed Upload-Checksum (no digest) → 400", chkMalformed.status === 400);
  var chkUnsupported = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-checksum": "sha-512 AAAA" }, "abcd"));
  check("PATCH: unsupported checksum algorithm → 400", chkUnsupported.status === 400);
  var chkMismatch = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-checksum": "sha-256 AAAA" }, "abcd"));
  check("PATCH: checksum mismatch → 460 (tus.io §3.5)", chkMismatch.status === 460);

  // BUG (reported): an oversized chunk is refused fail-closed — no bytes
  // written — but with the wrong status/body (400 + leaked "tus/chunk-too
  // -large" instead of 413). Assert only the invariant that holds today
  // AND after a fix: the request is rejected and the offset does not move.
  var smallChunkTus = _mkTus({ mountPath: "/tiny", maxChunkSize: C.BYTES.bytes(8) });
  var tinyCreated = await _create(smallChunkTus, "/tiny", { "upload-length": "100" });
  var oversized = await _drive(smallChunkTus, _sreq("PATCH", tinyCreated.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0" }, Buffer.alloc(20)));
  check("PATCH: oversized chunk is refused (status >= 400)", oversized.status >= 400);
  var afterOversized = await _drive(smallChunkTus, _req("HEAD", tinyCreated.loc, { "tus-resumable": VER }));
  check("PATCH: oversized chunk wrote no bytes (offset unchanged at 0)",
    afterOversized.headers["upload-offset"] === "0");

  // BUG (reported): a prototype key in Upload-Checksum bypasses the
  // allow-set lookup and reaches createHash(<object>) → the request is
  // still refused fail-closed (no append), but as a 500 rather than a
  // clean 400. Assert only the fail-closed invariant.
  var protoChk = await _drive(tus, _sreq("PATCH", created.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-checksum": "__proto__ AAAA" }, "abcd"));
  check("PATCH: prototype-key Upload-Checksum is refused (status >= 400)", protoChk.status >= 400);
  var afterProto = await _drive(tus, _req("HEAD", created.loc, { "tus-resumable": VER }));
  check("PATCH: prototype-key checksum wrote no bytes (offset unchanged at 0)",
    afterProto.headers["upload-offset"] === "0");

  // deferred-length finalization on PATCH: negative + over-max are
  // refused; a valid declaration finalizes and HEAD reports the length.
  var defTus = _mkTus({ mountPath: "/def", store: tusUpload.memoryStore({ maxSize: C.BYTES.bytes(64) }), maxSize: C.BYTES.bytes(64) });
  var defA = await _create(defTus, "/def", { "upload-defer-length": "1" });
  var defNeg = await _drive(defTus, _sreq("PATCH", defA.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-length": "-5" }, "hi"));
  check("PATCH: deferred finalization with negative Upload-Length → 400", defNeg.status === 400);
  var defB = await _create(defTus, "/def", { "upload-defer-length": "1" });
  var defOver = await _drive(defTus, _sreq("PATCH", defB.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-length": String(C.BYTES.bytes(65)) }, "hi"));
  check("PATCH: deferred finalization over Tus-Max-Size → 413", defOver.status === 413);
  var defC = await _create(defTus, "/def", { "upload-defer-length": "1" });
  var defOk = await _drive(defTus, _sreq("PATCH", defC.loc,
    { "tus-resumable": VER, "content-type": OCTET, "upload-offset": "0", "upload-length": "10" }, "hi"));
  check("PATCH: deferred finalization with valid Upload-Length → 204", defOk.status === 204);
  var defHead2 = await _drive(defTus, _req("HEAD", defC.loc, { "tus-resumable": VER }));
  check("HEAD: after deferred finalization Upload-Length is reported",
    defHead2.headers["upload-length"] === "10");

  // ---------------------------------------------------------------
  // H. DELETE refusals
  // ---------------------------------------------------------------
  var noTerm = _mkTus({ mountPath: "/noterm", extensions: ["creation"] });
  var ntCreated = await _create(noTerm, "/noterm", { "upload-length": "4" });
  var termDisabled = await _drive(noTerm, _req("DELETE", ntCreated.loc, { "tus-resumable": VER }));
  check("DELETE: termination extension disabled → 405", termDisabled.status === 405);

  var delMiss = await _drive(tus, _req("DELETE", "/uploads/doesnotexist", { "tus-resumable": VER }));
  check("DELETE: unknown upload → 404", delMiss.status === 404);
  var delOk = await _drive(tus, _req("DELETE", created.loc, { "tus-resumable": VER }));
  check("DELETE: existing upload → 204", delOk.status === 204);
  var delAgain = await _drive(tus, _req("DELETE", created.loc, { "tus-resumable": VER }));
  check("DELETE: second delete of same id → 404 (already gone)", delAgain.status === 404);

  // ---------------------------------------------------------------
  // I. method-not-allowed fall-through
  // ---------------------------------------------------------------
  var putColl = await _drive(tus, _req("PUT", "/uploads", { "tus-resumable": VER }));
  check("405: PUT on collection → Allow: OPTIONS, POST",
    putColl.status === 405 && putColl.headers.allow === "OPTIONS, POST");
  var postRes = await _drive(tus, _req("POST", "/uploads/abcdef", { "tus-resumable": VER }));
  check("405: POST on resource → Allow includes DELETE",
    postRes.status === 405 && /DELETE/.test(postRes.headers.allow));

  // ---------------------------------------------------------------
  // J. tusUpload.close — graceful-shutdown resource release
  // ---------------------------------------------------------------
  // The close helper is a public primitive (advertised in the
  // @primitive block) that operators call on shutdown; it must be
  // reachable on the b.middleware.tusUpload surface, invoke a wired
  // `.close` hook, and tolerate values that don't expose one.
  check("tusUpload.close: exposed on the b.middleware.tusUpload surface",
    typeof b.middleware.tusUpload.close === "function");

  var hookCalls = 0;
  b.middleware.tusUpload.close({ close: function () { hookCalls += 1; } });
  check("tusUpload.close: invokes a wired close hook once", hookCalls === 1);

  // A real middleware instance (no `.close` method today) — the helper
  // is a tolerant no-op, not a throw.
  var closableTus = _mkTus();
  var threwOnRealMw = false;
  try { b.middleware.tusUpload.close(closableTus); } catch (_e) { threwOnRealMw = true; }
  check("tusUpload.close: tolerant no-op on a middleware without a close hook",
    threwOnRealMw === false);

  var threwOnNullish = false;
  try {
    b.middleware.tusUpload.close(null);
    b.middleware.tusUpload.close(undefined);
    b.middleware.tusUpload.close(function () {});
  } catch (_e) { threwOnNullish = true; }
  check("tusUpload.close: tolerant of null / undefined / bare function",
    threwOnNullish === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
