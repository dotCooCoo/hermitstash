// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.requireBoundKey — Bearer-API-key auth with scope +
 * bound-fields + peer-cert-fingerprint binding.
 *
 * Security-critical middleware: every missing / mismatched / expired /
 * malformed binding MUST fail closed (401/403/400/500/503, never
 * next()). These tests drive the real middleware run through
 * b.testing.mockReq / mockRes and assert it refuses on every hostile
 * or omitted input, and only calls next() when every check passes.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Drive the async middleware to completion. Returns the captured
// response, whether next() ran, and the (possibly mutated) req.
async function _drive(mw, req) {
  var res = b.testing.mockRes();
  var nextCalled = false;
  var threw = null;
  try {
    await mw(req, res, function () { nextCalled = true; });
  } catch (e) {
    threw = e;
  }
  return {
    res:        res,
    captured:   res._captured(),
    nextCalled: nextCalled,
    threw:      threw,
    req:        req,
  };
}

function _bearerReq(token, extra) {
  var opts = extra || {};
  opts.headers = Object.assign({ authorization: "Bearer " + token }, opts.headers || {});
  return b.testing.mockReq(opts);
}

// A resolver that only knows one key.
function _resolverFor(record) {
  return async function (apiKey) {
    return apiKey === "valid-key" ? record : null;
  };
}

async function run() {
  var RequireBoundKeyError = b.middleware.requireBoundKey.RequireBoundKeyError ||
    require("../../lib/middleware/require-bound-key").RequireBoundKeyError;

  // ---------------------------------------------------------------
  // Config-time validation — entry-point tier THROWS on bad opts.
  // ---------------------------------------------------------------
  var threwNoResolver = false;
  try { b.middleware.requireBoundKey({ audit: false }); }
  catch (e) { threwNoResolver = e instanceof RequireBoundKeyError; }
  check("config: missing resolver throws RequireBoundKeyError", threwNoResolver);

  var threwBadResolver = false;
  try { b.middleware.requireBoundKey({ resolver: "not-a-fn", audit: false }); }
  catch (e) { threwBadResolver = e instanceof RequireBoundKeyError; }
  check("config: non-function resolver throws", threwBadResolver);

  var threwEmptyScope = false;
  try {
    b.middleware.requireBoundKey({
      resolver: async function () { return null; },
      requiredScopes: ["ok", ""], audit: false,
    });
  } catch (e) { threwEmptyScope = e instanceof RequireBoundKeyError; }
  check("config: empty-string scope throws bad-scope", threwEmptyScope);

  var threwNonStringScope = false;
  try {
    b.middleware.requireBoundKey({
      resolver: async function () { return null; },
      requiredScopes: [123], audit: false,
    });
  } catch (e) { threwNonStringScope = e instanceof RequireBoundKeyError; }
  check("config: non-string scope throws bad-scope", threwNonStringScope);

  var threwBadGetter = false;
  try {
    b.middleware.requireBoundKey({
      resolver: async function () { return null; },
      getBoundField: { tenantId: "not-a-fn" }, audit: false,
    });
  } catch (e) { threwBadGetter = e instanceof RequireBoundKeyError; }
  check("config: non-function bound-field getter throws", threwBadGetter);

  var threwUnknownOpt = false;
  try {
    b.middleware.requireBoundKey({
      resolver: async function () { return null; },
      notAnOpt: true, audit: false,
    });
  } catch (_e) { threwUnknownOpt = true; }
  check("config: unknown opt rejected by validateOpts", threwUnknownOpt);

  // ---------------------------------------------------------------
  // Bearer header parsing — fail closed on every non-token shape.
  // ---------------------------------------------------------------
  var okRecord = { id: "k1", scopes: ["webhook.ingest"], boundFields: {} };
  var scopedMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(okRecord),
    requiredScopes: ["webhook.ingest"],
    audit: false,
  });

  var noHeader = await _drive(scopedMw, b.testing.mockReq({ headers: {} }));
  check("parse: no Authorization header → 401 no-bearer-token",
    noHeader.captured.status === 401 && !noHeader.nextCalled);
  check("parse: no-bearer-token body carries reason",
    /no-bearer-token/.test(noHeader.captured.body));
  check("parse: 401 no-token challenge omits error code (RFC 6750 §3)",
    noHeader.captured.headers["www-authenticate"] === 'Bearer realm="api"');
  check("parse: refusal carries Cache-Control no-store",
    /no-store/.test(String(noHeader.captured.headers["cache-control"])));

  var basicAuth = await _drive(scopedMw,
    b.testing.mockReq({ headers: { authorization: "Basic dXNlcjpwYXNz" } }));
  check("parse: non-Bearer scheme → 401, fail closed",
    basicAuth.captured.status === 401 && !basicAuth.nextCalled);

  var lowerBearer = await _drive(scopedMw,
    b.testing.mockReq({ headers: { authorization: "bearer valid-key" } }));
  check("parse: lowercase 'bearer' scheme is not accepted (case-sensitive) → 401",
    lowerBearer.captured.status === 401 && !lowerBearer.nextCalled);

  var emptyToken = await _drive(scopedMw,
    b.testing.mockReq({ headers: { authorization: "Bearer " } }));
  check("parse: 'Bearer ' with no token → 401, fail closed",
    emptyToken.captured.status === 401 && !emptyToken.nextCalled);

  var spacedToken = await _drive(scopedMw,
    b.testing.mockReq({ headers: { authorization: "Bearer  has space" } }));
  check("parse: token containing a space is rejected → 401",
    spacedToken.captured.status === 401 && !spacedToken.nextCalled);

  // Uppercase header name still resolves (some proxies capitalize).
  var upperName = await _drive(scopedMw,
    b.testing.mockReq({ headers: { Authorization: "Bearer valid-key" } }));
  check("parse: 'Authorization' (capitalized) header accepted → next()",
    upperName.nextCalled === true);

  // ---------------------------------------------------------------
  // Resolver contract — fail closed on throw / null / non-object.
  // ---------------------------------------------------------------
  var throwingMw = b.middleware.requireBoundKey({
    resolver: async function () { throw new Error("db down"); },
    audit: false,
  });
  var resolverThrew = await _drive(throwingMw, _bearerReq("anything"));
  check("resolver: throw → 503 resolver-unavailable, fail closed",
    resolverThrew.captured.status === 503 && !resolverThrew.nextCalled && !resolverThrew.threw);
  check("resolver: 503 challenge advertises scheme without auth-error code",
    resolverThrew.captured.headers["www-authenticate"] === 'Bearer realm="api"');

  var unknownKeyMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(okRecord), audit: false,
  });
  var unknownKey = await _drive(unknownKeyMw, _bearerReq("bogus-key"));
  check("resolver: unknown key (null record) → 401 key-unknown-or-revoked",
    unknownKey.captured.status === 401 && !unknownKey.nextCalled &&
    /key-unknown-or-revoked/.test(unknownKey.captured.body));
  check("resolver: 401 invalid_token challenge on unknown key",
    /invalid_token/.test(String(unknownKey.captured.headers["www-authenticate"])));

  var nonObjMw = b.middleware.requireBoundKey({
    resolver: async function () { return "i-am-a-string"; }, audit: false,
  });
  var nonObj = await _drive(nonObjMw, _bearerReq("valid-key"));
  check("resolver: non-object return → 401, fail closed",
    nonObj.captured.status === 401 && !nonObj.nextCalled);

  var undefMw = b.middleware.requireBoundKey({
    resolver: async function () { return undefined; }, audit: false,
  });
  var undef = await _drive(undefMw, _bearerReq("valid-key"));
  check("resolver: undefined return → 401, fail closed",
    undef.captured.status === 401 && !undef.nextCalled);

  // ---------------------------------------------------------------
  // Scope check — required scope not held → 403 insufficient_scope.
  // ---------------------------------------------------------------
  var missingScopeMw = b.middleware.requireBoundKey({
    resolver: _resolverFor({ id: "k2", scopes: ["other.scope"], boundFields: {} }),
    requiredScopes: ["webhook.ingest"], audit: false,
  });
  var missingScope = await _drive(missingScopeMw, _bearerReq("valid-key"));
  check("scope: required scope not held → 403 missing-scope, fail closed",
    missingScope.captured.status === 403 && !missingScope.nextCalled &&
    /missing-scope/.test(missingScope.captured.body));
  check("scope: 403 challenge is insufficient_scope",
    /insufficient_scope/.test(String(missingScope.captured.headers["www-authenticate"])));

  // A record with a non-array `scopes` must be treated as no scopes.
  var badScopesMw = b.middleware.requireBoundKey({
    resolver: _resolverFor({ id: "k3", scopes: "webhook.ingest", boundFields: {} }),
    requiredScopes: ["webhook.ingest"], audit: false,
  });
  var badScopes = await _drive(badScopesMw, _bearerReq("valid-key"));
  check("scope: string (non-array) scopes treated as empty → 403, fail closed",
    badScopes.captured.status === 403 && !badScopes.nextCalled);

  // ---------------------------------------------------------------
  // Bound-field binding — missing / mismatched / getter-error close.
  // ---------------------------------------------------------------
  var boundRecord = { id: "k4", scopes: [], boundFields: { tenantId: "acme" } };

  // Registered bound field but no getter configured → 500 (misconfig).
  var noGetterMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(boundRecord), audit: false,
  });
  var noGetter = await _drive(noGetterMw, _bearerReq("valid-key"));
  check("bound-field: registered field w/o getter → 500 bound-field-no-getter, fail closed",
    noGetter.captured.status === 500 && !noGetter.nextCalled &&
    /bound-field-no-getter/.test(noGetter.captured.body));

  var tenantGetterMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(boundRecord),
    getBoundField: { tenantId: function (req) { return req.headers["x-tenant-id"]; } },
    audit: false,
  });

  // Field absent on request → 400 bound-field-missing.
  var fieldMissing = await _drive(tenantGetterMw, _bearerReq("valid-key"));
  check("bound-field: absent on request → 400 bound-field-missing, fail closed",
    fieldMissing.captured.status === 400 && !fieldMissing.nextCalled &&
    /bound-field-missing/.test(fieldMissing.captured.body));
  check("bound-field: 400 challenge is invalid_request",
    /invalid_request/.test(String(fieldMissing.captured.headers["www-authenticate"])));

  // Field present but WRONG value → 403 bound-field-mismatch.
  var fieldWrong = await _drive(tenantGetterMw,
    _bearerReq("valid-key", { headers: { "x-tenant-id": "evil-corp" } }));
  check("bound-field: mismatched value → 403 bound-field-mismatch, fail closed",
    fieldWrong.captured.status === 403 && !fieldWrong.nextCalled &&
    /bound-field-mismatch/.test(fieldWrong.captured.body));

  // Field present with an empty string → treated as missing → 400.
  var fieldEmpty = await _drive(tenantGetterMw,
    _bearerReq("valid-key", { headers: { "x-tenant-id": "" } }));
  check("bound-field: empty-string value → 400 bound-field-missing, fail closed",
    fieldEmpty.captured.status === 400 && !fieldEmpty.nextCalled);

  // Getter throwing → 400 bound-field-getter-threw (no crash).
  var getterThrowsMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(boundRecord),
    getBoundField: { tenantId: function () { throw new Error("boom"); } },
    audit: false,
  });
  var getterThrew = await _drive(getterThrowsMw, _bearerReq("valid-key"));
  check("bound-field: getter throw → 400 bound-field-getter-threw, no uncaught crash",
    getterThrew.captured.status === 400 && !getterThrew.nextCalled && !getterThrew.threw);

  // Getter returns a non-string (number) → treated as missing → 400.
  var getterNumberMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(boundRecord),
    getBoundField: { tenantId: function () { return 12345; } },
    audit: false,
  });
  var getterNumber = await _drive(getterNumberMw, _bearerReq("valid-key"));
  check("bound-field: non-string getter return → 400 bound-field-missing, fail closed",
    getterNumber.captured.status === 400 && !getterNumber.nextCalled);

  // Correct bound-field value → passes.
  var fieldOk = await _drive(tenantGetterMw,
    _bearerReq("valid-key", { headers: { "x-tenant-id": "acme" } }));
  check("bound-field: correct value → next() called",
    fieldOk.nextCalled === true && fieldOk.captured.status === null);

  // ---------------------------------------------------------------
  // Peer-cert fingerprint pinning — the mTLS cross-check.
  // ---------------------------------------------------------------
  var rawCert = Buffer.from("blamejs-test-peer-cert-der-bytes-not-a-real-x509");
  var fp = b.crypto.hashCertFingerprint(rawCert);
  var pinnedRecord = { id: "k5", scopes: [], boundFields: {}, peerCertFingerprints: [fp.hex] };

  var pinnedMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(pinnedRecord), audit: false,
  });

  // No peer cert presented at all → 401 peer-cert-required.
  var noPeer = await _drive(pinnedMw, _bearerReq("valid-key"));
  check("peer-cert: pinned key + no peer cert → 401 peer-cert-required, fail closed",
    noPeer.captured.status === 401 && !noPeer.nextCalled &&
    /peer-cert-required/.test(noPeer.captured.body));

  // Peer cert whose fingerprint is NOT pinned → 403 peer-cert-not-pinned.
  var wrongCert = Buffer.from("some-entirely-different-peer-cert-bytes");
  var wrongReq = _bearerReq("valid-key");
  wrongReq.peerCert = { raw: wrongCert };
  var notPinned = await _drive(pinnedMw, wrongReq);
  check("peer-cert: unpinned fingerprint → 403 peer-cert-not-pinned, fail closed",
    notPinned.captured.status === 403 && !notPinned.nextCalled &&
    /peer-cert-not-pinned/.test(notPinned.captured.body));

  // Peer cert whose fingerprint IS pinned (derived from raw) → passes.
  var goodReq = _bearerReq("valid-key");
  goodReq.peerCert = { raw: rawCert };
  var pinnedOk = await _drive(pinnedMw, goodReq);
  check("peer-cert: pinned fingerprint derived from raw cert → next() called",
    pinnedOk.nextCalled === true);

  // Pre-attached req.peerFingerprint (from an upstream requireMtls) that
  // matches, with the raw cert also present → passes.
  var preFpReq = _bearerReq("valid-key");
  preFpReq.peerCert = { raw: rawCert };
  preFpReq.peerFingerprint = { hex: fp.hex, colon: fp.colon };
  var preFpOk = await _drive(pinnedMw, preFpReq);
  check("peer-cert: pre-attached matching peerFingerprint + raw → next() called",
    preFpOk.nextCalled === true);

  // tolerateMissingPeerCert bypass — dev-fixture escape hatch. Pinned
  // key, no cert, but the opt is explicitly set → passes (audited).
  var tolerateMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(pinnedRecord),
    tolerateMissingPeerCert: true, audit: false,
  });
  var tolerated = await _drive(tolerateMw, _bearerReq("valid-key"));
  check("peer-cert: tolerateMissingPeerCert bypass → next() called (audited)",
    tolerated.nextCalled === true);

  // Fail-closed edge — req.peerFingerprint set by upstream but the raw
  // cert is NOT attached. Must refuse cleanly, never throw an uncaught
  // TypeError (which would hang the request instead of returning a
  // structured refusal).
  var fpNoCertReq = _bearerReq("valid-key");
  fpNoCertReq.peerFingerprint = { hex: fp.hex, colon: fp.colon };
  var fpNoCert = await _drive(pinnedMw, fpNoCertReq);
  check("peer-cert: peerFingerprint present but no raw cert → clean refusal, no uncaught crash",
    fpNoCert.threw === null && !fpNoCert.nextCalled &&
    (fpNoCert.captured.status === 401 || fpNoCert.captured.status === 403));

  // ---------------------------------------------------------------
  // Success path — req.apiKey populated, bearer secret never re-exposed.
  // ---------------------------------------------------------------
  var successMw = b.middleware.requireBoundKey({
    resolver: _resolverFor({
      id: "k9", scopes: ["webhook.ingest", "extra"],
      boundFields: { tenantId: "acme" },
    }),
    requiredScopes: ["webhook.ingest"],
    getBoundField: { tenantId: function (req) { return req.headers["x-tenant-id"]; } },
    audit: false,
  });
  var success = await _drive(successMw,
    _bearerReq("valid-key", { headers: { "x-tenant-id": "acme" } }));
  check("success: all checks pass → next() called", success.nextCalled === true);
  check("success: req.apiKey.id attached", success.req.apiKey && success.req.apiKey.id === "k9");
  check("success: req.apiKey.scopes copied", success.req.apiKey &&
    success.req.apiKey.scopes.indexOf("webhook.ingest") !== -1);
  check("success: req.apiKey never re-exposes the bearer secret",
    success.req.apiKey && JSON.stringify(success.req.apiKey).indexOf("valid-key") === -1);
  check("success: req.apiKey.boundFields is a copy of registered",
    success.req.apiKey && success.req.apiKey.boundFields.tenantId === "acme");

  // ---------------------------------------------------------------
  // Refusal customization — onDeny hook + problemDetails mode.
  // ---------------------------------------------------------------
  var onDenyCalls = [];
  var onDenyMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(okRecord), audit: false,
    onDeny: function (req, res, info) {
      onDenyCalls.push(info);
      res.writeHead(418, { "content-type": "text/plain" });
      res.end("teapot");
    },
  });
  var onDenyRes = await _drive(onDenyMw, b.testing.mockReq({ headers: {} }));
  check("onDeny: hook owns the refusal (418) and receives reason info",
    onDenyRes.captured.status === 418 && onDenyCalls.length === 1 &&
    onDenyCalls[0].reason === "no-bearer-token" && !onDenyRes.nextCalled);

  var problemMw = b.middleware.requireBoundKey({
    resolver: _resolverFor(okRecord), audit: false, problemDetails: true,
  });
  var problemRes = await _drive(problemMw,
    b.testing.mockReq({ headers: { accept: "application/problem+json" } }));
  // problemDetails.respond commits status via res.statusCode; the machine
  // status also rides in the RFC 9457 document body.
  check("problemDetails: emits application/problem+json and fails closed",
    /application\/problem\+json/.test(String(problemRes.captured.headers["content-type"])) &&
    /"status":\s*401/.test(problemRes.captured.body) &&
    !problemRes.nextCalled && !problemRes.threw);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
