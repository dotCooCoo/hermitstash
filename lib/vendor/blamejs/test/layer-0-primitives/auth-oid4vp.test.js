// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.auth.oid4vp (OpenID4VP 1.0 verifier).
 *
 * Dedicated behavioral coverage for the verifier surface only exercised
 * indirectly by federation-vc-suite before now: the DCQL validator's
 * every refusal branch, createRequest option handling, the DCQL matcher
 * (format / issuer_values / credential_sets / null-and-index path walk),
 * and — the high-yield path — verifyResponse composing the real SD-JWT
 * VC verifier.
 *
 * Fixtures are real: SD-JWT VC presentations are minted with the
 * framework's own b.auth.sdJwtVc.issue + present (holder-bound via cnf,
 * KB-JWT signed over ES256) and verified offline through the
 * issuerKeyResolver DI seam — no network. The adversarial checks pin the
 * fail-closed contracts: a presentation whose vct sits OUTSIDE a 2+
 * vct_values DCQL filter is refused (over-disclosure defense, oid4vp.js
 * ~506-513); a presentation bound to the wrong audience or a stale nonce
 * fails closed; requireKeyAttestation with no attestation refuses.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");

// One issuer + one holder keypair reused across the file (P-256 / ES256).
var ISSUER_KP = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var HOLDER_KP = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

var CLIENT_ID   = "https://verifier.example";
var RESPONSE_URI = "https://verifier.example/vp";

function _mkVerifier(extra) {
  return b.auth.oid4vp.verifier.create(Object.assign({
    clientId:          CLIENT_ID,
    responseUri:       RESPONSE_URI,
    issuerKeyResolver: function () { return ISSUER_KP.publicKey; },
  }, extra || {}));
}

// Mint a holder-bound SD-JWT VC and present it (KB-JWT over audience+nonce).
function _present(o) {
  var holderJwk = HOLDER_KP.publicKey.export({ format: "jwk" });
  var sd = b.auth.sdJwtVc.issue({
    issuer:               "https://issuer",
    vct:                  o.vct,
    claims:               o.claims,
    selectivelyDisclosed: Object.keys(o.claims),
    issuerKey:            ISSUER_KP.privateKey,
    algorithm:            "ES256",
    holderKey:            holderJwk,
  });
  return b.auth.sdJwtVc.present({
    sdJwt:               sd.token,
    disclosedClaimNames: o.disclosed || Object.keys(o.claims),
    audience:            o.audience,
    nonce:               o.nonce,
    holderKey:           HOLDER_KP.privateKey,
    algorithm:           "ES256",
  }).presentation;
}

// Run a synchronous fn and return the thrown error's .code (or null).
function _syncCode(fn) {
  try { fn(); return null; }
  catch (e) { return e && e.code; }
}
// Await a promise and return the rejection's .code (or null on resolve).
async function _rejectCode(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

// ---- create(): config-time validation --------------------------------

function testVerifierCreateValidation() {
  check("create: non-object opts refused",
        _syncCode(function () { b.auth.oid4vp.verifier.create(null); }) !== null);

  check("create: missing clientId refused",
        _syncCode(function () {
          b.auth.oid4vp.verifier.create({ responseUri: RESPONSE_URI, issuerKeyResolver: function () {} });
        }) === "auth-oid4vp/no-client-id");

  check("create: missing responseUri refused",
        _syncCode(function () {
          b.auth.oid4vp.verifier.create({ clientId: CLIENT_ID, issuerKeyResolver: function () {} });
        }) === "auth-oid4vp/no-response-uri");

  check("create: non-function issuerKeyResolver refused",
        _syncCode(function () {
          b.auth.oid4vp.verifier.create({ clientId: CLIENT_ID, responseUri: RESPONSE_URI, issuerKeyResolver: "nope" });
        }) === "auth-oid4vp/no-resolver");

  var v = _mkVerifier();
  check("create: valid opts expose the verifier surface",
        v && typeof v.createRequest === "function" &&
        typeof v.verifyResponse === "function" &&
        typeof v.matchDcql === "function" &&
        v.clientId === CLIENT_ID && v.responseUri === RESPONSE_URI);
}

// ---- _validateDcql: every refusal branch (through matchDcql) ----------

function testDcqlValidatorRefusals() {
  function code(dcql) { return _syncCode(function () { b.auth.oid4vp.matchDcql([], dcql); }); }

  check("dcql: null query refused",
        code(null) === "auth-oid4vp/bad-dcql");
  check("dcql: array query refused",
        code([]) === "auth-oid4vp/bad-dcql");
  check("dcql: missing credentials refused",
        code({}) === "auth-oid4vp/no-credentials");
  check("dcql: empty credentials array refused",
        code({ credentials: [] }) === "auth-oid4vp/no-credentials");
  check("dcql: non-object credential entry refused",
        code({ credentials: [null] }) === "auth-oid4vp/bad-credential-query");
  check("dcql: missing credential id refused",
        code({ credentials: [{ format: "vc+sd-jwt" }] }) === "auth-oid4vp/no-credential-id");
  check("dcql: duplicate credential id refused",
        code({ credentials: [
          { id: "c", format: "vc+sd-jwt" },
          { id: "c", format: "vc+sd-jwt" },
        ] }) === "auth-oid4vp/duplicate-id");
  check("dcql: missing format refused",
        code({ credentials: [{ id: "c" }] }) === "auth-oid4vp/no-format");
  check("dcql: non-array claims refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt", claims: "x" }] }) === "auth-oid4vp/bad-claims");
  check("dcql: empty claim path refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt", claims: [{ path: [] }] }] }) === "auth-oid4vp/bad-claim-path");
  check("dcql: non-array claim path refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt", claims: [{ path: "given_name" }] }] }) === "auth-oid4vp/bad-claim-path");
  check("dcql: non-string/number/null path segment refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt", claims: [{ path: [true] }] }] }) === "auth-oid4vp/bad-claim-segment");
  check("dcql: non-array claim.values refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt", claims: [{ path: ["x"], values: "v" }] }] }) === "auth-oid4vp/bad-claim-values");
  check("dcql: non-array credential_sets refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt" }], credential_sets: "x" }) === "auth-oid4vp/bad-credential-sets");
  check("dcql: empty set options refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt" }], credential_sets: [{ options: [] }] }) === "auth-oid4vp/bad-set-options");
  check("dcql: non-array set option refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt" }], credential_sets: [{ options: ["c"] }] }) === "auth-oid4vp/bad-set-option");
  check("dcql: set option referencing unknown id refused",
        code({ credentials: [{ id: "c", format: "vc+sd-jwt" }], credential_sets: [{ options: [["ghost"]] }] }) === "auth-oid4vp/unknown-set-id");

  // A null path segment IS accepted (array wildcard) — proves the
  // segment-type guard admits the spec-legal shapes.
  check("dcql: null path segment accepted (array wildcard)",
        _syncCode(function () {
          b.auth.oid4vp.matchDcql(
            [{ id: "c", format: "vc+sd-jwt", claims: { arr: [{ v: 1 }] } }],
            { credentials: [{ id: "c", format: "vc+sd-jwt", claims: [{ path: ["arr", null, "v"] }] }] });
        }) === null);
}

// ---- createRequest: option handling ----------------------------------

function testCreateRequest() {
  var v = _mkVerifier();

  check("createRequest: missing dcql refused",
        _syncCode(function () { v.createRequest({}); }) === "auth-oid4vp/no-dcql");
  check("createRequest: invalid dcql surfaces validator refusal",
        _syncCode(function () { v.createRequest({ dcql: { credentials: [] } }); }) === "auth-oid4vp/no-credentials");

  var dcql = { credentials: [{ id: "id-card", format: "vc+sd-jwt", claims: [{ path: ["given_name"] }] }] };

  // Defaults: response_mode direct_post, generated 128-bit nonce/state,
  // no aud key when the caller omits it.
  var def = v.createRequest({ dcql: dcql });
  check("createRequest: defaults response_type/mode + embeds dcql",
        def.request.response_type === "vp_token" &&
        def.request.response_mode === "direct_post" &&
        def.request.client_id === CLIENT_ID &&
        def.request.response_uri === RESPONSE_URI &&
        def.request.dcql_query === dcql);
  check("createRequest: generated nonce + state are non-empty and distinct",
        typeof def.nonce === "string" && def.nonce.length > 0 &&
        typeof def.state === "string" && def.state.length > 0 &&
        def.nonce !== def.state);
  check("createRequest: nonce/state on request mirror the return",
        def.request.nonce === def.nonce && def.request.state === def.state);
  check("createRequest: no aud key when omitted",
        !("aud" in def.request));

  // Overrides: responseMode / nonce / state / aud all honored.
  var ov = v.createRequest({
    dcql: dcql, responseMode: "direct_post.jwt",
    nonce: "fixed-nonce", state: "fixed-state", aud: "https://aud.example",
  });
  check("createRequest: responseMode override honored",
        ov.request.response_mode === "direct_post.jwt");
  check("createRequest: nonce/state overrides honored",
        ov.nonce === "fixed-nonce" && ov.state === "fixed-state");
  check("createRequest: aud override reflected on request",
        ov.request.aud === "https://aud.example");
}

// ---- matchDcql: structural matcher paths ------------------------------

function testMatchDcqlPaths() {
  var dcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: ["https://vct/identity"] },
      claims: [{ path: ["given_name"] }] },
  ] };

  // presentations must be an array.
  var notArr = b.auth.oid4vp.matchDcql("not-an-array", dcql);
  check("matchDcql: non-array presentations → invalid with error",
        notArr.valid === false && notArr.errors.length > 0);

  // presentation missing an id.
  var noId = b.auth.oid4vp.matchDcql([{ format: "vc+sd-jwt", claims: {} }], dcql);
  check("matchDcql: presentation missing id → invalid",
        noId.valid === false && /missing id/.test(noId.errors[0]));

  // format mismatch → the credential does not satisfy the query.
  var badFmt = b.auth.oid4vp.matchDcql([
    { id: "id-card", format: "mso_mdoc", claims: { vct: "https://vct/identity", given_name: "A" } },
  ], dcql);
  check("matchDcql: format mismatch refused",
        badFmt.valid === false && badFmt.errors.length > 0);

  // issuer_values filter — hit and miss.
  var issDcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { issuer_values: ["https://trusted-issuer"] } },
  ] };
  var issHit = b.auth.oid4vp.matchDcql([
    { id: "id-card", format: "vc+sd-jwt", claims: { iss: "https://trusted-issuer", given_name: "A" } },
  ], issDcql);
  check("matchDcql: issuer_values match accepted", issHit.valid === true);
  var issMiss = b.auth.oid4vp.matchDcql([
    { id: "id-card", format: "vc+sd-jwt", claims: { iss: "https://rogue-issuer" } },
  ], issDcql);
  check("matchDcql: issuer_values mismatch refused",
        issMiss.valid === false && issMiss.errors.length > 0);

  // A pure-credentials query (no credential_sets): a missing credential
  // is an error via the else-branch.
  var missing = b.auth.oid4vp.matchDcql([], dcql);
  check("matchDcql: missing credential (no sets) → invalid",
        missing.valid === false && /missing from presentation/.test(missing.errors[0]));

  // credential_sets with required:false — an unsatisfied optional set is
  // NOT an error.
  var optDcql = {
    credentials: [
      { id: "id-card",  format: "vc+sd-jwt", claims: [{ path: ["given_name"] }] },
      { id: "passport", format: "vc+sd-jwt", claims: [{ path: ["number"] }] },
    ],
    credential_sets: [
      { options: [["id-card"]],  required: true },
      { options: [["passport"]], required: false },
    ],
  };
  var optRes = b.auth.oid4vp.matchDcql([
    { id: "id-card", format: "vc+sd-jwt", claims: { given_name: "A" } },
  ], optDcql);
  check("matchDcql: unsatisfied optional credential_set is not an error",
        optRes.valid === true && !!optRes.matched["id-card"] && !optRes.matched.passport);

  // A required credential_set with no satisfied option → error.
  var reqRes = b.auth.oid4vp.matchDcql([], {
    credentials: [{ id: "id-card", format: "vc+sd-jwt" }],
    credential_sets: [{ options: [["id-card"]], required: true }],
  });
  check("matchDcql: unsatisfied required credential_set refused",
        reqRes.valid === false && /not satisfied/.test(reqRes.errors[0]));
}

// ---- verifyResponse: input-shape refusals -----------------------------

async function testVerifyResponseInputGuards() {
  var v = _mkVerifier();
  var dcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: ["https://vct/identity"] },
      claims: [{ path: ["given_name"] }] },
  ] };

  check("verifyResponse: missing dcql throws",
        (await _rejectCode(v.verifyResponse({ vpToken: {}, nonce: "n" }))) === "auth-oid4vp/no-dcql");
  check("verifyResponse: missing nonce throws",
        (await _rejectCode(v.verifyResponse({ vpToken: {}, dcql: dcql }))) === "auth-oid4vp/no-nonce");
  check("verifyResponse: empty-string nonce throws",
        (await _rejectCode(v.verifyResponse({ vpToken: {}, dcql: dcql, nonce: "" }))) === "auth-oid4vp/no-nonce");

  // Legacy single-string vp_token with a MULTI-credential DCQL is refused
  // (can't bind an unlabeled token to one of several credential queries).
  var multiDcql = { credentials: [
    { id: "id-card",  format: "vc+sd-jwt", claims: [{ path: ["given_name"] }] },
    { id: "passport", format: "vc+sd-jwt", claims: [{ path: ["number"] }] },
  ] };
  check("verifyResponse: legacy string vp_token + multi-credential refused",
        (await _rejectCode(v.verifyResponse({ vpToken: "sometoken", dcql: multiDcql, nonce: "n" })))
          === "auth-oid4vp/legacy-multi-credential");

  // Array / non-object vp_token → bad-vp-token.
  check("verifyResponse: array vp_token refused",
        (await _rejectCode(v.verifyResponse({ vpToken: ["x"], dcql: dcql, nonce: "n" })))
          === "auth-oid4vp/bad-vp-token");
  check("verifyResponse: numeric vp_token refused",
        (await _rejectCode(v.verifyResponse({ vpToken: 42, dcql: dcql, nonce: "n" })))
          === "auth-oid4vp/bad-vp-token");

  // A vp_token key not present in the DCQL query is recorded as an error,
  // not silently accepted.
  var stray = await v.verifyResponse({ vpToken: { "ghost": "tok" }, dcql: dcql, nonce: "n" });
  check("verifyResponse: vp_token key absent from DCQL → error, invalid",
        stray.valid === false && stray.errors.some(function (e) { return /not present in DCQL query/.test(e); }));

  // A non-string presentation value → error.
  var nonStr = await v.verifyResponse({ vpToken: { "id-card": 123 }, dcql: dcql, nonce: "n" });
  check("verifyResponse: non-string presentation → error, invalid",
        nonStr.valid === false && nonStr.errors.some(function (e) { return /is not a string/.test(e); }));
}

// ---- verifyResponse: real SD-JWT VC round-trips -----------------------

async function testVerifyResponseRoundTrip() {
  var v = _mkVerifier();
  var VCT = "https://vct/identity";
  var dcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: [VCT] },
      claims: [{ path: ["given_name"] }] },
  ] };
  var req = v.createRequest({ dcql: dcql });

  var pres = _present({
    vct: VCT, claims: { given_name: "Alice", family_name: "Smith" },
    disclosed: ["given_name"], audience: CLIENT_ID, nonce: req.nonce,
  });

  // Object-keyed vp_token — the canonical DCQL path.
  var ok = await v.verifyResponse({ vpToken: { "id-card": pres }, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: object-keyed round-trip valid",
        ok.valid === true && ok.errors.length === 0 &&
        ok.presentations.length === 1 &&
        ok.presentations[0].claims.given_name === "Alice" &&
        ok.presentations[0].claims.family_name === undefined &&
        !!ok.matched["id-card"]);

  // Legacy single-string vp_token with a single-credential DCQL binds to
  // the lone credential id.
  var okLegacy = await v.verifyResponse({ vpToken: pres, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: legacy string vp_token binds to lone credential",
        okLegacy.valid === true && !!okLegacy.matched["id-card"]);

  // Array-of-presentations under one id — each verified.
  var okArr = await v.verifyResponse({ vpToken: { "id-card": [pres] }, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: array-valued presentation verified",
        okArr.valid === true && okArr.presentations.length === 1);
}

// ---- verifyResponse: fail-closed adversarial contracts ----------------

async function testVerifyResponseFailClosed() {
  var VCT = "https://vct/identity";
  var dcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: [VCT] },
      claims: [{ path: ["given_name"] }] },
  ] };
  var v = _mkVerifier();
  var req = v.createRequest({ dcql: dcql });

  // Wrong audience: the KB-JWT is bound to a DIFFERENT verifier than the
  // one checking it → refused (audience-redirection defense).
  var wrongAud = _present({ vct: VCT, claims: { given_name: "Alice" },
    audience: "https://attacker.example", nonce: req.nonce });
  var rWrongAud = await v.verifyResponse({ vpToken: { "id-card": wrongAud }, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: wrong-audience presentation refused",
        rWrongAud.valid === false && rWrongAud.errors.length > 0);

  // Stale / forged nonce: presentation bound to nonce A, verified under
  // nonce B → refused (replay defense).
  var goodPres = _present({ vct: VCT, claims: { given_name: "Alice" },
    audience: CLIENT_ID, nonce: req.nonce });
  var rStaleNonce = await v.verifyResponse({ vpToken: { "id-card": goodPres }, dcql: dcql, nonce: "a-stale-nonce" });
  check("verifyResponse: stale-nonce (replay) presentation refused",
        rStaleNonce.valid === false && rStaleNonce.errors.length > 0);

  // requireKeyAttestation with an ordinary presentation (no key_attestation
  // header) → refused.
  var rAttest = await v.verifyResponse({
    vpToken: { "id-card": goodPres }, dcql: dcql, nonce: req.nonce, requireKeyAttestation: true });
  check("verifyResponse: requireKeyAttestation with no attestation refused",
        rAttest.valid === false && rAttest.errors.length > 0);
}

// ---- verifyResponse: per-presentation vct enforcement -----------------

async function testVerifyResponseVctEnforcement() {
  var v = _mkVerifier();

  // (A) Single vct_values → expectedVct pinned; a presentation with a
  // DIFFERENT vct fails inside the SD-JWT VC verifier (fail-closed).
  var pinnedDcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: ["https://vct/identity"] },
      claims: [{ path: ["given_name"] }] },
  ] };
  var reqPin = v.createRequest({ dcql: pinnedDcql });
  var wrongVctPres = _present({ vct: "https://vct/passport", claims: { given_name: "Alice" },
    audience: CLIENT_ID, nonce: reqPin.nonce });
  var rPin = await v.verifyResponse({ vpToken: { "id-card": wrongVctPres }, dcql: pinnedDcql, nonce: reqPin.nonce });
  check("verifyResponse: pinned single vct_values rejects a mismatched vct",
        rPin.valid === false && rPin.errors.length > 0);

  // (B) Two+ vct_values → verify runs WITHOUT expectedVct, then the
  // manual membership check runs. In-list vct is accepted...
  var listDcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: ["https://vct/identity", "https://vct/passport"] },
      claims: [{ path: ["given_name"] }] },
  ] };
  var reqList = v.createRequest({ dcql: listDcql });
  var inListPres = _present({ vct: "https://vct/passport", claims: { given_name: "Alice" },
    audience: CLIENT_ID, nonce: reqList.nonce });
  var rInList = await v.verifyResponse({ vpToken: { "id-card": inListPres }, dcql: listDcql, nonce: reqList.nonce });
  check("verifyResponse: 2+ vct_values accepts an in-list vct",
        rInList.valid === true && rInList.presentations.length === 1 &&
        rInList.presentations[0].claims.vct === "https://vct/passport");

  // ...and a vct OUTSIDE the 2+ list is REFUSED (over-disclosure defense).
  // A valid signature + correct audience/nonce is not enough: the holder
  // must present a credential type the query actually asked for. Without
  // the manual membership check this would slip through, since expectedVct
  // is not pinned for a 2+ list.
  var outListPres = _present({ vct: "https://vct/driver-license", claims: { given_name: "Alice" },
    audience: CLIENT_ID, nonce: reqList.nonce });
  var rOutList = await v.verifyResponse({ vpToken: { "id-card": outListPres }, dcql: listDcql, nonce: reqList.nonce });
  check("verifyResponse: 2+ vct_values REFUSES an out-of-list vct (over-disclosure defense)",
        rOutList.valid === false &&
        rOutList.errors.some(function (e) { return /not in DCQL vct_values/.test(e); }));
  check("verifyResponse: out-of-list vct is not surfaced as a presentation",
        rOutList.presentations.length === 0);
}

// ---- verifyResponse: audience override (create({ audience })) ---------

async function testVerifyResponseAudienceOverride() {
  var OVERRIDE_AUD = "https://audience-override.example";
  var v = _mkVerifier({ audience: OVERRIDE_AUD });
  var VCT = "https://vct/identity";
  var dcql = { credentials: [
    { id: "id-card", format: "vc+sd-jwt",
      meta: { vct_values: [VCT] },
      claims: [{ path: ["given_name"] }] },
  ] };
  var req = v.createRequest({ dcql: dcql });

  // A presentation bound to the override audience verifies — proving the
  // override, not clientId, is the audience the verifier binds to.
  var presOk = _present({ vct: VCT, claims: { given_name: "Alice" },
    audience: OVERRIDE_AUD, nonce: req.nonce });
  var rOk = await v.verifyResponse({ vpToken: { "id-card": presOk }, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: audience override — presentation bound to override verifies",
        rOk.valid === true);

  // A presentation bound to clientId (the default) is REFUSED when an
  // override audience is configured — the override is honored, not ignored.
  var presClientId = _present({ vct: VCT, claims: { given_name: "Alice" },
    audience: CLIENT_ID, nonce: req.nonce });
  var rReject = await v.verifyResponse({ vpToken: { "id-card": presClientId }, dcql: dcql, nonce: req.nonce });
  check("verifyResponse: audience override — presentation bound to clientId refused",
        rReject.valid === false && rReject.errors.length > 0);
}

async function run() {
  testVerifierCreateValidation();
  testDcqlValidatorRefusals();
  testCreateRequest();
  testMatchDcqlPaths();
  await testVerifyResponseInputGuards();
  await testVerifyResponseRoundTrip();
  await testVerifyResponseFailClosed();
  await testVerifyResponseVctEnforcement();
  await testVerifyResponseAudienceOverride();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[auth-oid4vp] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
