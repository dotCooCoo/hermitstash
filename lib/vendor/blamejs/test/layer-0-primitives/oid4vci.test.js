// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for b.auth.oid4vci — OpenID for Verifiable Credential Issuance
 * 1.0 (issuer side): credential_offer + pre-authorized_code /token
 * exchange + /credential proof-JWT verification + SD-JWT VC minting.
 *
 * Drives the real consumer path (issuer.create → createCredentialOffer
 * → exchangePreAuthorizedCode → issueCredential → metadata). Proof JWTs
 * are minted with real holder keys so the true cryptographic verify path
 * executes; the error / adversarial / defensive branches are reached
 * with hand-crafted proof bytes (real key where a signature must verify,
 * dummy signature where a structural guard throws first). No network —
 * all stores are in-process b.cache instances.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var nodeCrypto = require("node:crypto");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var AuthError = require("../../lib/framework-error").AuthError;

var oid4vci = b.auth.oid4vci;
var sdJwtVc = b.auth.sdJwtVc;

var ISSUER_URL = "https://issuer.example.com";

// ---- key + JWK helpers ----

function _newEcKey(curve) {
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: curve || "P-256" });
}
function _jwk(publicKey) {
  return publicKey.export({ format: "jwk" });
}

var _ecJwk = _jwk(_newEcKey("P-256").publicKey);   // reusable public JWK for key-presence-only crafts

var _nsCounter = 0;
function _ns(prefix) { _nsCounter += 1; return prefix + "." + _nsCounter + "." + Date.now(); }
function _cache() { return b.cache.create({ namespace: _ns("oid4vci.test"), ttlMs: 60000 }); }

// A conforming get/set/del store that signals a MISS with `null` rather
// than `undefined` — the shape a Map / Redis / SQL-row-backed store
// commonly returns. A framework b.cache returns `undefined` on a miss;
// this store is a plausible operator implementation the issuer accepts via
// the documented `cNonceStore` opt. Used to prove the c_nonce replay check
// fails CLOSED regardless of the store's miss sentinel.
function _nullMissStore() {
  var m = new Map();
  return {
    get: async function (k) { return m.has(k) ? m.get(k) : null; },
    set: async function (k, v) { m.set(k, v); },
    del: async function (k) { var had = m.has(k); m.delete(k); return had; },
  };
}

// ---- proof-JWT crafting ----

function _b64uJson(o) {
  return Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
}

function _hashByAlg(alg) {
  var m = { ES256: "sha256", ES384: "sha384", ES512: "sha512",
            PS256: "sha256", PS384: "sha384", PS512: "sha512",
            RS256: "sha256", RS384: "sha384", RS512: "sha512", EdDSA: null };
  return m[alg];
}

function _signProof(header, payload, privateKey, alg) {
  var si = _b64uJson(header) + "." + _b64uJson(payload);
  var input = Buffer.from(si, "ascii");
  var sig;
  if (alg === "EdDSA") {
    sig = nodeCrypto.sign(null, input, privateKey);
  } else if (alg.indexOf("PS") === 0) {
    sig = nodeCrypto.sign(_hashByAlg(alg), input, {
      key: privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  } else if (alg.indexOf("ES") === 0) {
    sig = nodeCrypto.sign(_hashByAlg(alg), input, { key: privateKey, dsaEncoding: "ieee-p1363" });
  } else {
    sig = nodeCrypto.sign(_hashByAlg(alg), input, privateKey);
  }
  return si + "." + sig.toString("base64url");
}

// A fully valid holder-signed proof JWT. Real signature so _verifyProofJwt's
// final crypto check succeeds. Overridable so a single field can be
// corrupted to drive one branch. NOT a mock — mints real signed bytes.
function _makeProof(o) {
  o = o || {};
  var alg = o.alg || "ES256";
  var kp = o.keyPair || _newEcKey("P-256");
  var nowSec = Math.floor(Date.now() / 1000);
  var header = Object.assign({
    typ: "openid4vci-proof+jwt",
    alg: alg,
    jwk: _jwk(kp.publicKey),
  }, o.headerOverride || {});
  if (o.headerDelete) o.headerDelete.forEach(function (k) { delete header[k]; });
  var payload = Object.assign({
    aud:   o.aud !== undefined ? o.aud : ISSUER_URL,
    nonce: o.nonce,
    iat:   o.iat !== undefined ? o.iat : nowSec,
  }, o.payloadOverride || {});
  return { jwt: _signProof(header, payload, o.signWith || kp.privateKey, alg), keyPair: kp };
}

// A structurally-crafted proof with a dummy signature — for the guards that
// throw BEFORE the crypto verify (typ/alg/crit/key-presence/aud/nonce/iat/
// x5c-parse/kid-resolve). header/payload extras merge onto minimal defaults.
function _craftProof(headerExtra, payloadExtra, sig) {
  var nowSec = Math.floor(Date.now() / 1000);
  var header  = Object.assign({ typ: "openid4vci-proof+jwt", alg: "ES256" }, headerExtra || {});
  var payload = Object.assign({ aud: ISSUER_URL, iat: nowSec }, payloadExtra || {});
  return _b64uJson(header) + "." + _b64uJson(payload) + "." + (sig || "AAAA");
}

// ---- issuer construction ----

function _sdJwtIssuer() {
  var kp = _newEcKey("P-256");
  return sdJwtVc.issuer.create({
    issuerUrl: ISSUER_URL,
    keys: [{ kid: "k1", privateKey: kp.privateKey, algorithm: "ES256" }],
    activeKid: "k1",
  });
}

function _createOpts(overrides) {
  return Object.assign({
    credentialIssuerUrl: ISSUER_URL,
    credentialEndpoint:  ISSUER_URL + "/credential",
    tokenEndpoint:       ISSUER_URL + "/token",
    sdJwtIssuer:         _sdJwtIssuer(),
    supportedCredentials: {
      "id-card-1": {
        format: "vc+sd-jwt",
        vct:    "https://example.com/vct/identity",
        claims: { given_name: {}, family_name: {} },
      },
    },
  }, overrides || {});
}

function _create(overrides) {
  return oid4vci.issuer.create(_createOpts(overrides));
}

async function _issued(overrides) {
  var issuer = _create(overrides);
  var offer  = await issuer.createCredentialOffer({ subject: "user-9", credentialIds: ["id-card-1"] });
  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  return { issuer: issuer, accessToken: tokens.access_token, cNonce: tokens.c_nonce };
}

async function _expectThrow(label, code, fn) {
  var err = null;
  try { await fn(); } catch (e) { err = e; }
  check(label, err && (code == null || err.code === code));
  return err;
}

function _expectThrowSync(label, code, fn) {
  var err = null;
  try { fn(); } catch (e) { err = e; }
  check(label, err && (code == null || err.code === code));
  return err;
}

// convenience: issue against a token-bearing session with a given proof
function _issue(s, proof, extra) {
  return s.issuer.issueCredential(Object.assign({
    accessToken: s.accessToken,
    credentialIdentifier: "id-card-1",
    proof: proof,
    claims: { given_name: "Alice", family_name: "Smith" },
  }, extra || {}));
}

// ---- happy path: full offer → token → credential flow ----

async function testFullFlowHappyPath() {
  var issuer = _create();
  var offer = await issuer.createCredentialOffer({
    subject: "user-42", credentialIds: ["id-card-1"],
  });
  check("offer: deepLink is an openid-credential-offer:// deep link",
        typeof offer.deepLink === "string" &&
        offer.deepLink.indexOf("openid-credential-offer://") === 0);
  check("offer: preAuthCode is a 256-bit hex string",
        typeof offer.preAuthCode === "string" && offer.preAuthCode.length === 64);
  check("offer: offerUri points at the issuer",
        offer.offerUri.indexOf(ISSUER_URL) === 0);
  check("offer: credential_configuration_ids echoed",
        offer.offer.credential_configuration_ids[0] === "id-card-1");
  check("offer: no tx_code when none requested",
        offer.offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].tx_code === undefined);

  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  check("token: access_token issued", typeof tokens.access_token === "string" && tokens.access_token.length === 64);
  check("token: token_type Bearer", tokens.token_type === "Bearer");
  check("token: c_nonce issued", typeof tokens.c_nonce === "string" && tokens.c_nonce.length === 32);
  check("token: authorization_details maps credential id",
        tokens.authorization_details[0].credential_configuration_id === "id-card-1" &&
        tokens.authorization_details[0].type === "openid_credential");

  var proof = _makeProof({ aud: ISSUER_URL, nonce: tokens.c_nonce });
  var cred = await issuer.issueCredential({
    accessToken: tokens.access_token,
    credentialIdentifier: "id-card-1",
    proof: proof.jwt,
    claims: { given_name: "Alice", family_name: "Smith" },
  });
  check("credential: format vc+sd-jwt", cred.format === "vc+sd-jwt");
  check("credential: SD-JWT VC string returned", typeof cred.credential === "string" && cred.credential.indexOf("~") !== -1);
  check("credential: fresh c_nonce rotated", typeof cred.c_nonce === "string" && cred.c_nonce !== tokens.c_nonce);

  // Single-use default: the access token is consumed → a replay is refused.
  var proof2 = _makeProof({ aud: ISSUER_URL, nonce: cred.c_nonce });
  await _expectThrow("issue: single-use access token refuses replay",
    "auth-oid4vci/invalid-access-token",
    function () { return issuer.issueCredential({
      accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
      proof: proof2.jwt, claims: { given_name: "Bob" } }); });
}

async function testMetadataDocument() {
  var issuer = _create();
  var md = issuer.metadata();
  check("metadata: credential_issuer", md.credential_issuer === ISSUER_URL);
  check("metadata: credential_endpoint", md.credential_endpoint === ISSUER_URL + "/credential");
  check("metadata: token_endpoint", md.token_endpoint === ISSUER_URL + "/token");
  check("metadata: authorization_servers defaults to [issuer]",
        Array.isArray(md.authorization_servers) && md.authorization_servers[0] === ISSUER_URL);
  var cfg = md.credential_configurations_supported["id-card-1"];
  check("metadata: configuration format", cfg.format === "vc+sd-jwt");
  check("metadata: default cryptographic_binding_methods jwk",
        cfg.cryptographic_binding_methods_supported[0] === "jwk");
  check("metadata: default signing alg ES256",
        cfg.credential_signing_alg_values_supported[0] === "ES256");
  check("metadata: proof_types_supported carries proofAlgs",
        cfg.proof_types_supported.jwt.proof_signing_alg_values_supported.indexOf("ES256") !== -1);
}

async function testMetadataCustomFields() {
  var issuer = _create({
    authorizationServers: ["https://as.example.com"],
    proofAlgorithms: ["ES256", "EdDSA"],
    supportedCredentials: {
      "vip": {
        format: "dc+sd-jwt",
        vct:    "https://example.com/vct/vip",
        claims: { tier: {} },
        cryptographic_binding_methods_supported: ["cose_key"],
        credential_signing_alg_values_supported: ["EdDSA"],
        display: [{ name: "VIP Card", locale: "en-US" }],
      },
    },
  });
  var md = issuer.metadata();
  check("metadata: custom authorization_servers reflected",
        md.authorization_servers[0] === "https://as.example.com");
  var cfg = md.credential_configurations_supported["vip"];
  check("metadata: custom binding methods reflected", cfg.cryptographic_binding_methods_supported[0] === "cose_key");
  check("metadata: custom signing algs reflected", cfg.credential_signing_alg_values_supported[0] === "EdDSA");
  check("metadata: display block passed through", cfg.display[0].name === "VIP Card");
  check("metadata: dc+sd-jwt format accepted", cfg.format === "dc+sd-jwt");
}

// ---- create(): config-time validation ----

function testCreateRequireObject() {
  _expectThrowSync("create: null opts rejected", null, function () { oid4vci.issuer.create(null); });
  _expectThrowSync("create: string opts rejected", null, function () { oid4vci.issuer.create("nope"); });
  _expectThrowSync("create: number opts rejected", null, function () { oid4vci.issuer.create(7); });
}

function testCreateMissingRequiredStrings() {
  _expectThrowSync("create: missing credentialIssuerUrl", "auth-oid4vci/no-issuer-url",
    function () { oid4vci.issuer.create(_createOpts({ credentialIssuerUrl: 123 })); });
  _expectThrowSync("create: missing credentialEndpoint", "auth-oid4vci/no-credential-endpoint",
    function () { oid4vci.issuer.create(_createOpts({ credentialEndpoint: 123 })); });
  _expectThrowSync("create: missing tokenEndpoint", "auth-oid4vci/no-token-endpoint",
    function () { oid4vci.issuer.create(_createOpts({ tokenEndpoint: 123 })); });
}

function testCreateNoSdJwtIssuer() {
  _expectThrowSync("create: sdJwtIssuer without issue() rejected", "auth-oid4vci/no-sd-jwt-issuer",
    function () { oid4vci.issuer.create(_createOpts({ sdJwtIssuer: { notIssue: 1 } })); });
}

function testCreateNoSupportedCredentials() {
  _expectThrowSync("create: empty supportedCredentials rejected", "auth-oid4vci/no-supported-credentials",
    function () { oid4vci.issuer.create(_createOpts({ supportedCredentials: {} })); });
}

function testCreateBadCredentialSpec() {
  _expectThrowSync("create: non-object credential spec rejected", "auth-oid4vci/bad-credential-spec",
    function () { oid4vci.issuer.create(_createOpts({ supportedCredentials: { x: "not-an-object" } })); });
}

function testCreateUnsupportedFormat() {
  _expectThrowSync("create: unsupported credential format rejected", "auth-oid4vci/unsupported-format",
    function () { oid4vci.issuer.create(_createOpts({
      supportedCredentials: { x: { format: "image/jpeg", vct: "https://y" } } })); });
  _expectThrowSync("create: missing credential format rejected", "auth-oid4vci/unsupported-format",
    function () { oid4vci.issuer.create(_createOpts({
      supportedCredentials: { x: { vct: "https://y" } } })); });
}

function testCreateNoVct() {
  _expectThrowSync("create: missing vct rejected", "auth-oid4vci/no-vct",
    function () { oid4vci.issuer.create(_createOpts({
      supportedCredentials: { x: { format: "vc+sd-jwt" } } })); });
  _expectThrowSync("create: empty vct rejected", "auth-oid4vci/no-vct",
    function () { oid4vci.issuer.create(_createOpts({
      supportedCredentials: { x: { format: "vc+sd-jwt", vct: "" } } })); });
}

function testCreateBadResolveKidType() {
  _expectThrowSync("create: non-function resolveKid rejected at config time",
    "auth-oid4vci/bad-resolve-kid",
    function () { oid4vci.issuer.create(_createOpts({ resolveKid: "not-a-function" })); });
  _expectThrowSync("create: non-function validateX5c rejected at config time",
    "auth-oid4vci/bad-validate-x5c",
    function () { oid4vci.issuer.create(_createOpts({ validateX5c: 42 })); });
}

// ---- createCredentialOffer(): defensive branches ----

async function testOfferBadSubject() {
  var issuer = _create();
  await _expectThrow("offer: missing subject rejected", "auth-oid4vci/no-subject",
    function () { return issuer.createCredentialOffer({ credentialIds: ["id-card-1"] }); });
  await _expectThrow("offer: empty subject rejected", "auth-oid4vci/no-subject",
    function () { return issuer.createCredentialOffer({ subject: "", credentialIds: ["id-card-1"] }); });
  await _expectThrow("offer: no opts at all rejected", "auth-oid4vci/no-subject",
    function () { return issuer.createCredentialOffer(); });
}

async function testOfferBadCredentialIds() {
  var issuer = _create();
  await _expectThrow("offer: missing credentialIds rejected", "auth-oid4vci/no-credential-ids",
    function () { return issuer.createCredentialOffer({ subject: "u" }); });
  await _expectThrow("offer: empty credentialIds rejected", "auth-oid4vci/no-credential-ids",
    function () { return issuer.createCredentialOffer({ subject: "u", credentialIds: [] }); });
  await _expectThrow("offer: non-array credentialIds rejected", "auth-oid4vci/no-credential-ids",
    function () { return issuer.createCredentialOffer({ subject: "u", credentialIds: "id-card-1" }); });
}

async function testOfferUnknownCredentialId() {
  var issuer = _create();
  await _expectThrow("offer: unknown credentialId rejected", "auth-oid4vci/unknown-credential-id",
    function () { return issuer.createCredentialOffer({ subject: "u", credentialIds: ["ghost"] }); });
}

async function testOfferBadTxCode() {
  var issuer = _create();
  await _expectThrow("offer: string txCode rejected", "auth-oid4vci/bad-tx-code",
    function () { return issuer.createCredentialOffer({ subject: "u", credentialIds: ["id-card-1"], txCode: "1234" }); });
  await _expectThrow("offer: txCode without string value rejected", "auth-oid4vci/bad-tx-code",
    function () { return issuer.createCredentialOffer({ subject: "u", credentialIds: ["id-card-1"], txCode: { length: 4 } }); });
}

async function testOfferTxCodeDefaults() {
  var issuer = _create();
  var offer = await issuer.createCredentialOffer({
    subject: "u", credentialIds: ["id-card-1"], txCode: { value: "1234" },
  });
  var tx = offer.offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].tx_code;
  check("offer: tx_code default length is 4", tx.length === 4);
  check("offer: tx_code default input_mode numeric", tx.input_mode === "numeric");
  check("offer: tx_code description omitted when absent", tx.description === undefined);
  check("offer: hasTxCode reflected in return", offer.offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] === offer.preAuthCode);
}

async function testOfferTxCodeExplicit() {
  var issuer = _create();
  var offer = await issuer.createCredentialOffer({
    subject: "u", credentialIds: ["id-card-1"],
    txCode: { value: "998877", length: 6, input_mode: "text", description: "Enter the PIN from the kiosk" },
  });
  var tx = offer.offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].tx_code;
  check("offer: tx_code explicit length honored", tx.length === 6);
  check("offer: tx_code explicit input_mode honored", tx.input_mode === "text");
  check("offer: tx_code description honored", tx.description === "Enter the PIN from the kiosk");
}

// ---- exchangePreAuthorizedCode(): defensive branches ----

async function testExchangeMissingCode() {
  var issuer = _create();
  await _expectThrow("exchange: missing pre-auth code rejected", "auth-oid4vci/missing-pre-auth-code",
    function () { return issuer.exchangePreAuthorizedCode({}); });
  await _expectThrow("exchange: empty pre-auth code rejected", "auth-oid4vci/missing-pre-auth-code",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: "" }); });
  await _expectThrow("exchange: no opts rejected", "auth-oid4vci/missing-pre-auth-code",
    function () { return issuer.exchangePreAuthorizedCode(); });
}

async function testExchangeUnknownCode() {
  var issuer = _create();
  await _expectThrow("exchange: unknown pre-auth code rejected", "auth-oid4vci/invalid-pre-auth-code",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: "deadbeef-not-issued" }); });
}

async function testExchangeTxCodeRequired() {
  var issuer = _create();
  var offer = await issuer.createCredentialOffer({
    subject: "u", credentialIds: ["id-card-1"], txCode: { value: "1234" },
  });
  await _expectThrow("exchange: tx_code required but omitted", "auth-oid4vci/missing-tx-code",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode }); });
  await _expectThrow("exchange: tx_code required but empty", "auth-oid4vci/missing-tx-code",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode, txCode: "" }); });
  // Code is NOT consumed on a missing tx_code — a subsequent correct call still works.
  var ok = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode, txCode: "1234" });
  check("exchange: tx_code path not consumed on prior missing-tx-code", typeof ok.access_token === "string");
}

async function testExchangeTxCodeMismatch() {
  var issuer = _create();
  var offer = await issuer.createCredentialOffer({
    subject: "u", credentialIds: ["id-card-1"], txCode: { value: "1234" },
  });
  await _expectThrow("exchange: wrong tx_code rejected", "auth-oid4vci/tx-code-mismatch",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode, txCode: "9999" }); });
  // Not consumed on mismatch: the correct tx_code still redeems it.
  var ok = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode, txCode: "1234" });
  check("exchange: correct tx_code redeems after a mismatch", typeof ok.access_token === "string");
}

async function testExchangeAlreadyRedeemedRace() {
  // The atomic single-use delete: the loser of a concurrent redemption sees
  // del() return false. Simulated deterministically by overriding the store's
  // del to return false while the entry is still gettable.
  var codeStore = _cache();
  var issuer = _create({ codeStore: codeStore });
  var offer = await issuer.createCredentialOffer({ subject: "u", credentialIds: ["id-card-1"] });
  codeStore.del = function () { return Promise.resolve(false); };
  await _expectThrow("exchange: lost single-use delete race refused", "auth-oid4vci/invalid-pre-auth-code",
    function () { return issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode }); });
}

// ---- issueCredential(): non-proof defensive branches ----

async function testIssueMissingAccessToken() {
  var issuer = _create();
  await _expectThrow("issue: missing access token rejected", "auth-oid4vci/missing-access-token",
    function () { return issuer.issueCredential({ credentialIdentifier: "id-card-1", proof: "x", claims: {} }); });
  await _expectThrow("issue: empty access token rejected", "auth-oid4vci/missing-access-token",
    function () { return issuer.issueCredential({ accessToken: "", proof: "x", claims: {} }); });
  await _expectThrow("issue: no opts rejected", "auth-oid4vci/missing-access-token",
    function () { return issuer.issueCredential(); });
}

async function testIssueInvalidAccessToken() {
  var issuer = _create();
  await _expectThrow("issue: unknown access token rejected", "auth-oid4vci/invalid-access-token",
    function () { return issuer.issueCredential({ accessToken: "never-issued", credentialIdentifier: "id-card-1", proof: "x", claims: {} }); });
}

async function testIssueWrongCredentialIdentifier() {
  var s = await _issued();
  await _expectThrow("issue: credentialIdentifier outside token's set rejected",
    "auth-oid4vci/wrong-credential-identifier",
    function () { return s.issuer.issueCredential({ accessToken: s.accessToken, credentialIdentifier: "other-id", proof: "x", claims: {} }); });
  await _expectThrow("issue: non-string credentialIdentifier rejected",
    "auth-oid4vci/wrong-credential-identifier",
    function () { return s.issuer.issueCredential({ accessToken: s.accessToken, proof: "x", claims: {} }); });
}

async function testIssueUnknownCredentialId() {
  // A record whose credentialIds carries an id NOT in supportedCredentials
  // (defensive — createCredentialOffer forbids it). Pre-seed a store to reach
  // the guard directly on the real issueCredential path.
  var atStore = _cache();
  var issuer = _create({ accessTokenStore: atStore });
  await atStore.set("seeded-token", { subject: "u", credentialIds: ["ghost-id"] });
  await _expectThrow("issue: credentialId in token but not configured rejected",
    "auth-oid4vci/unknown-credential-id",
    function () { return issuer.issueCredential({ accessToken: "seeded-token", credentialIdentifier: "ghost-id", proof: "x.y.z", claims: {} }); });
}

async function testIssueNoClaims() {
  var s = await _issued();
  var proof = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  await _expectThrow("issue: missing claims rejected", "auth-oid4vci/no-claims",
    function () { return s.issuer.issueCredential({ accessToken: s.accessToken, credentialIdentifier: "id-card-1", proof: proof.jwt }); });
  var s2 = await _issued();
  var proof2 = _makeProof({ aud: ISSUER_URL, nonce: s2.cNonce });
  await _expectThrow("issue: non-object claims rejected", "auth-oid4vci/no-claims",
    function () { return s2.issuer.issueCredential({ accessToken: s2.accessToken, credentialIdentifier: "id-card-1", proof: proof2.jwt, claims: "alice" }); });
}

async function testIssueAccessTokenConsumedRace() {
  // The single-use access-token claim is an atomic delete; the loser sees
  // del() return false → access-token-consumed. Simulated by overriding the
  // access-token store's del to return false after a real proof verifies.
  var atStore = _cache();
  var s = await _issued({ accessTokenStore: atStore });
  var proof = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  atStore.del = function () { return Promise.resolve(false); };
  await _expectThrow("issue: lost single-use token claim refused", "auth-oid4vci/access-token-consumed",
    function () { return _issue(s, proof.jwt); });
}

async function testIssueMintThrowsRestoresToken() {
  // The operator's sdJwtIssuer throws AFTER the single-use token is claimed;
  // the token must be restored so a retry can succeed (the claim only guards
  // against a concurrent double-mint, not against a failed mint).
  var throwingIssuer = {
    issue: function () { return Promise.reject(new Error("signer KMS outage")); },
  };
  var s = await _issued({ sdJwtIssuer: throwingIssuer });
  var proof = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  var err1 = await _expectThrow("issue: mint failure propagates the operator error", null,
    function () { return _issue(s, proof.jwt); });
  check("issue: propagated error is the signer outage", err1 && /KMS outage/.test(err1.message));
  // Token was restored: a second attempt reaches the mint again (throws the
  // same operator error) rather than access-token-consumed.
  var proof2 = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  var err2 = await _expectThrow("issue: token restored after mint failure (retryable)", null,
    function () { return _issue(s, proof2.jwt); });
  check("issue: retry hits the signer again, not a consumed-token refusal",
        err2 && err2.code !== "auth-oid4vci/access-token-consumed");
}

async function testIssueSingleUseOptOut() {
  var s = await _issued({ accessTokenSingleUse: false });
  var proof1 = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  var cred1 = await _issue(s, proof1.jwt);
  check("issue: opt-out first issuance succeeds", cred1.format === "vc+sd-jwt");
  // Token NOT consumed — a second issuance with the rotated c_nonce works.
  var proof2 = _makeProof({ aud: ISSUER_URL, nonce: cred1.c_nonce });
  var cred2 = await _issue(s, proof2.jwt);
  check("issue: opt-out access token is reusable", cred2.format === "vc+sd-jwt");
}

async function testIssueCustomDisclosureAndTtl() {
  var s = await _issued();
  var proof = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce });
  var cred = await s.issuer.issueCredential({
    accessToken: s.accessToken, credentialIdentifier: "id-card-1", proof: proof.jwt,
    claims: { given_name: "Alice", family_name: "Smith" },
    selectivelyDisclosed: ["given_name"],
    ttlMs: 3600000,
  });
  check("issue: explicit selectivelyDisclosed + ttlMs issues a credential", cred.format === "vc+sd-jwt");
}

async function testIssueProofMaxAgeCustom() {
  // proofMaxAgeMs widens the iat-too-old window; a proof older than the
  // 10-minute default still verifies under a 20-minute policy.
  var s = await _issued({ proofMaxAgeMs: 1200000 });   // 20 minutes in ms
  var nowSec = Math.floor(Date.now() / 1000);
  var proof = _makeProof({ aud: ISSUER_URL, nonce: s.cNonce, iat: nowSec - 900 });   // 15 min ago
  var cred = await _issue(s, proof.jwt);
  check("issue: proofMaxAgeMs override accepts an aged-but-in-window proof", cred.format === "vc+sd-jwt");
}

// ---- _verifyProofJwt: structural / payload branches ----

async function testProofEmptyOrTooLong() {
  var s = await _issued();
  await _expectThrow("proof: empty string rejected", "auth-oid4vci/bad-proof",
    function () { return _issue(s, ""); });
  await _expectThrow("proof: non-string rejected", "auth-oid4vci/bad-proof",
    function () { return _issue(s, 12345); });
  var s2 = await _issued();
  await _expectThrow("proof: over-size proof rejected", "auth-oid4vci/bad-proof",
    function () { return _issue(s2, "x".repeat(40000)); });
}

async function testProofNotThreeParts() {
  var s = await _issued();
  await _expectThrow("proof: not 3 dot-parts rejected", "auth-oid4vci/malformed-proof",
    function () { return _issue(s, "only.two"); });
}

async function testProofBadDecode() {
  var s = await _issued();
  var proof = Buffer.from("not-json-at-all", "utf8").toString("base64url") + "." + _b64uJson({}) + ".AAAA";
  await _expectThrow("proof: undecodable header rejected", "auth-oid4vci/bad-proof-decode",
    function () { return _issue(s, proof); });
}

async function testProofWrongTyp() {
  var s = await _issued();
  var proof = _craftProof({ typ: "JWT", jwk: _ecJwk }, { nonce: s.cNonce });
  await _expectThrow("proof: wrong typ rejected", "auth-oid4vci/wrong-proof-typ",
    function () { return _issue(s, proof); });
}

async function testProofUnsupportedAlgAllowlist() {
  var s = await _issued();
  var proof = _craftProof({ alg: "HS256", jwk: _ecJwk }, { nonce: s.cNonce });
  await _expectThrow("proof: alg outside issuer set refused before key lookup",
    "auth-oid4vci/unsupported-proof-alg",
    function () { return _issue(s, proof); });
}

async function testProofCritRefused() {
  var s = await _issued();
  var withCrit = _craftProof({ jwk: _ecJwk, crit: ["unknown-ext"] }, { nonce: s.cNonce });
  await _expectThrow("proof: non-empty crit refused", "auth-oid4vci/unknown-crit",
    function () { return _issue(s, withCrit); });
  var badCrit = _craftProof({ jwk: _ecJwk, crit: "not-an-array" }, { nonce: s.cNonce });
  await _expectThrow("proof: non-array crit refused", "auth-oid4vci/unknown-crit",
    function () { return _issue(s, badCrit); });
}

async function testProofNoKey() {
  var s = await _issued();
  var proof = _craftProof({}, { nonce: s.cNonce });   // no jwk / kid / x5c
  await _expectThrow("proof: no holder-key binding rejected", "auth-oid4vci/no-key-in-proof",
    function () { return _issue(s, proof); });
}

async function testProofWrongAud() {
  var s = await _issued();
  var proof = _craftProof({ jwk: _ecJwk }, { aud: "https://evil.example", nonce: s.cNonce });
  await _expectThrow("proof: wrong aud rejected", "auth-oid4vci/wrong-proof-aud",
    function () { return _issue(s, proof); });
}

async function testProofCNonceExpired() {
  var cNonceStore = _cache();
  var s = await _issued({ cNonceStore: cNonceStore });
  await cNonceStore.del(s.accessToken);   // c_nonce TTL elapsed before /credential
  var proof = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: "whatever" });
  await _expectThrow("proof: expected c_nonce missing/expired rejected", "auth-oid4vci/c-nonce-expired",
    function () { return _issue(s, proof); });
}

async function testProofWrongNonce() {
  var s = await _issued();
  var wrong = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: "not-the-nonce" });
  await _expectThrow("proof: nonce mismatch rejected (replay defense)", "auth-oid4vci/wrong-proof-nonce",
    function () { return _issue(s, wrong); });
  var s2 = await _issued();
  var numeric = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: 12345 });
  await _expectThrow("proof: non-string nonce rejected", "auth-oid4vci/wrong-proof-nonce",
    function () { return _issue(s2, numeric); });
}

// A c_nonce store that signals a miss with `null` (not `undefined`) MUST
// still fail closed. Before the fix, a null store-miss fell through the
// nonce compare entirely: a forged proof carrying ANY nonce was accepted
// and a credential minted bound to the attacker's key. Batch mode
// (accessTokenSingleUse: false) keeps the access token valid past the
// c_nonce's shorter TTL, so an attacker who lets the c_nonce expire can
// reach /credential with a live token and no valid nonce.
async function testProofCNonceNullStoreMissFailsClosed() {
  var cNonceStore = _nullMissStore();
  var issuer = _create({ cNonceStore: cNonceStore, accessTokenSingleUse: false });
  var offer  = await issuer.createCredentialOffer({ subject: "user-9", credentialIds: ["id-card-1"] });
  var tokens = await issuer.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });

  // A valid c_nonce present → issuance succeeds (the store's null-miss
  // sentinel must not break the happy path).
  var good = _makeProof({ aud: ISSUER_URL, nonce: tokens.c_nonce });
  var cred = await issuer.issueCredential({
    accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
    proof: good.jwt, claims: { given_name: "Alice" },
  });
  check("null-miss store: valid c_nonce still issues", cred.format === "vc+sd-jwt");

  // Simulate the c_nonce expiring while the access token is still live —
  // the store now returns null on get(). A forged proof with a garbage
  // nonce (never issued) MUST be refused, not accepted.
  await cNonceStore.del(tokens.access_token);
  check("null-miss store: get() returns null on miss",
        (await cNonceStore.get(tokens.access_token)) === null);
  var forged = _makeProof({ aud: ISSUER_URL, nonce: "attacker-garbage-nonce-not-issued" });
  await _expectThrow("null-miss store: absent c_nonce refuses forged proof (fail-closed)",
    "auth-oid4vci/c-nonce-expired",
    function () {
      return issuer.issueCredential({
        accessToken: tokens.access_token, credentialIdentifier: "id-card-1",
        proof: forged.jwt, claims: { given_name: "Mallory" },
      });
    });
}

async function testProofNoIat() {
  var s = await _issued();
  var proof = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: s.cNonce, iat: undefined });
  await _expectThrow("proof: missing iat rejected", "auth-oid4vci/no-proof-iat",
    function () { return _issue(s, proof); });
}

async function testProofIatFuture() {
  var s = await _issued();
  var nowSec = Math.floor(Date.now() / 1000);
  var proof = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: s.cNonce, iat: nowSec + 3600 });
  await _expectThrow("proof: future iat rejected", "auth-oid4vci/proof-iat-future",
    function () { return _issue(s, proof); });
}

async function testProofIatTooOld() {
  var s = await _issued();
  var nowSec = Math.floor(Date.now() / 1000);
  var proof = _craftProof({ jwk: _ecJwk }, { aud: ISSUER_URL, nonce: s.cNonce, iat: nowSec - 3600 });
  await _expectThrow("proof: stale iat rejected", "auth-oid4vci/proof-iat-too-old",
    function () { return _issue(s, proof); });
}

// ---- _verifyProofJwt: kid resolution ----

async function testKidNoResolver() {
  var s = await _issued();   // no resolveKid configured
  var proof = _craftProof({ kid: "holder-kid-1" }, { nonce: s.cNonce });
  await _expectThrow("proof: kid without inline jwk and no resolver refused",
    "auth-oid4vci/kid-resolver-not-supported",
    function () { return _issue(s, proof); });
}

async function testKidResolverThrows() {
  var s = await _issued({ resolveKid: function () { throw new Error("kid DB down"); } });
  var proof = _craftProof({ kid: "holder-kid-1" }, { nonce: s.cNonce });
  var err = await _expectThrow("proof: resolveKid throw wrapped as typed refusal",
    "auth-oid4vci/kid-resolver-failed",
    function () { return _issue(s, proof); });
  check("proof: resolver error message surfaced for operator debugging",
        err && /kid DB down/.test(err.message));
}

async function testKidResolverUnresolved() {
  var s = await _issued({ resolveKid: function () { return null; } });
  var proof = _craftProof({ kid: "holder-kid-1" }, { nonce: s.cNonce });
  await _expectThrow("proof: resolveKid returning no key refused", "auth-oid4vci/kid-unresolved",
    function () { return _issue(s, proof); });
}

async function testKidResolverBadShape() {
  var s = await _issued({ resolveKid: function () { return { not: "a-key" }; } });
  var proof = _craftProof({ kid: "holder-kid-1" }, { nonce: s.cNonce });
  await _expectThrow("proof: resolveKid returning a non-key object refused",
    "auth-oid4vci/bad-resolved-key",
    function () { return _issue(s, proof); });
}

async function testKidResolverKeyObject() {
  var holder = _newEcKey("P-256");
  var s = await _issued({ resolveKid: function () { return holder.publicKey; } });   // KeyObject
  var proof = _makeProof({ keyPair: holder, aud: ISSUER_URL, nonce: s.cNonce,
    headerOverride: { kid: "holder-kid-1" }, headerDelete: ["jwk"] });
  var cred = await _issue(s, proof.jwt);
  check("proof: kid → resolved KeyObject verifies and issues", cred.format === "vc+sd-jwt");
}

async function testKidResolverJwk() {
  var holder = _newEcKey("P-256");
  var s = await _issued({ resolveKid: function () { return _jwk(holder.publicKey); } });   // JWK
  var proof = _makeProof({ keyPair: holder, aud: ISSUER_URL, nonce: s.cNonce,
    headerOverride: { kid: "holder-kid-1" }, headerDelete: ["jwk"] });
  var cred = await _issue(s, proof.jwt);
  check("proof: kid → resolved JWK verifies and issues", cred.format === "vc+sd-jwt");
}

async function testKidResolverAlgKtyMismatch() {
  // resolveKid hands back an EC key but the proof header declares EdDSA
  // (requires kty=OKP) → CVE-2026-22817 alg-confusion cross-check refuses.
  var ecHolder = _newEcKey("P-256");
  var s = await _issued({ resolveKid: function () { return _jwk(ecHolder.publicKey); } });
  var proof = _craftProof({ alg: "EdDSA", kid: "holder-kid-1" }, { nonce: s.cNonce });
  await _expectThrow("proof: resolved-key alg/kty mismatch refused",
    "auth-jwt-external/alg-kty-mismatch",
    function () { return _issue(s, proof); });
}

// ---- _verifyProofJwt: x5c parse guards ----

async function testX5cNotArrayOrEmpty() {
  var s = await _issued();
  await _expectThrow("proof: empty x5c array rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s, _craftProof({ x5c: [] }, { nonce: s.cNonce })); });
  var s2 = await _issued();
  await _expectThrow("proof: non-array x5c rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s2, _craftProof({ x5c: "not-an-array" }, { nonce: s2.cNonce })); });
}

async function testX5cBadEntry() {
  var s = await _issued();
  await _expectThrow("proof: non-string x5c entry rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s, _craftProof({ x5c: [123] }, { nonce: s.cNonce })); });
  var s2 = await _issued();
  await _expectThrow("proof: empty x5c entry rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s2, _craftProof({ x5c: [""] }, { nonce: s2.cNonce })); });
}

async function testX5cNonBase64() {
  var s = await _issued();
  // base64url-only characters ('-', '_') are invalid standard base64 (RFC 7515 §4.1.6)
  await _expectThrow("proof: base64url chars in x5c rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s, _craftProof({ x5c: ["abcd-efgh_"] }, { nonce: s.cNonce })); });
}

async function testX5cBadBase64RoundTrip() {
  var s = await _issued();
  // 'AB' is in the standard alphabet but does not round-trip through base64.
  await _expectThrow("proof: non-round-tripping x5c base64 rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s, _craftProof({ x5c: ["AB"] }, { nonce: s.cNonce })); });
}

async function testX5cNotDerCert() {
  var s = await _issued();
  var notACert = Buffer.from("this is valid base64 but not a DER certificate", "utf8").toString("base64");
  await _expectThrow("proof: unparseable DER cert in x5c rejected", "auth-oid4vci/bad-x5c",
    function () { return _issue(s, _craftProof({ x5c: [notACert] }, { nonce: s.cNonce })); });
}

// ---- _verifyProofJwt: alg / signature ----

async function testProofAlgKtyMismatchInline() {
  var s = await _issued();
  // Inline EC jwk with an EdDSA-declaring header → alg-confusion cross-check.
  var proof = _craftProof({ alg: "EdDSA", jwk: _ecJwk }, { nonce: s.cNonce });
  await _expectThrow("proof: inline jwk alg/kty mismatch refused",
    "auth-jwt-external/alg-kty-mismatch",
    function () { return _issue(s, proof); });
}

async function testProofAlgAllowedButUnhashable() {
  // ML-DSA-65 passes the issuer allowlist and the alg/kty cross-check (AKP
  // key) and imports, but has no entry in the JWS hash map → refused.
  var mldsa = nodeCrypto.generateKeyPairSync("ml-dsa-65");
  var s = await _issued({ proofAlgorithms: ["ML-DSA-65"] });
  var proof = _craftProof({ alg: "ML-DSA-65", jwk: _jwk(mldsa.publicKey) }, { nonce: s.cNonce });
  await _expectThrow("proof: allowed-but-unhashable alg refused", "auth-oid4vci/unsupported-proof-alg",
    function () { return _issue(s, proof); });
}

async function testProofBadSignature() {
  var s = await _issued();
  var keyA = _newEcKey("P-256");
  var keyB = _newEcKey("P-256");
  // Header advertises keyA, but the JWS is signed by keyB → signature fails.
  var proof = _makeProof({ keyPair: keyA, signWith: keyB.privateKey, aud: ISSUER_URL, nonce: s.cNonce });
  await _expectThrow("proof: bad signature rejected (holder does not hold the bound key)",
    "auth-oid4vci/proof-bad-signature",
    function () { return _issue(s, proof.jwt); });
}

async function testProofEdDSAHappy() {
  var holder = nodeCrypto.generateKeyPairSync("ed25519");
  var s = await _issued();   // EdDSA is in the default proofAlgorithms
  var proof = _makeProof({ keyPair: holder, alg: "EdDSA", aud: ISSUER_URL, nonce: s.cNonce });
  var cred = await _issue(s, proof.jwt);
  check("proof: EdDSA holder proof verifies and issues", cred.format === "vc+sd-jwt");
}

async function testProofES384Happy() {
  var holder = _newEcKey("P-384");
  var s = await _issued({ proofAlgorithms: ["ES384"] });
  var proof = _makeProof({ keyPair: holder, alg: "ES384", aud: ISSUER_URL, nonce: s.cNonce });
  var cred = await _issue(s, proof.jwt);
  check("proof: ES384 holder proof verifies and issues", cred.format === "vc+sd-jwt");
}

async function testProofPS256Happy() {
  var holder = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var s = await _issued({ proofAlgorithms: ["PS256"] });
  var proof = _makeProof({ keyPair: holder, alg: "PS256", aud: ISSUER_URL, nonce: s.cNonce });
  var cred = await _issue(s, proof.jwt);
  check("proof: PS256 (RSA-PSS) holder proof verifies and issues", cred.format === "vc+sd-jwt");
}

// ---- _verifyProofJwt: x5c (RFC 7515 §4.1.6) cert-bound holder key ----

async function testX5cCertBoundPaths() {
  // A real leaf certificate whose SPKI is the holder key, minted by the
  // framework's own CA (b.mtlsCa) so the proof can be signed by the matching
  // private key. No network — the CA is local, keyed off a temp data dir.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-oid4vci-x5c-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
    var leaf = await ca.generateClientCert({ cn: "holder.wallet.local", validityDays: 7 });
    var leafPriv = nodeCrypto.createPrivateKey(leaf.key);                 // EC P-384
    var x5cEntry = new nodeCrypto.X509Certificate(leaf.cert).raw.toString("base64");

    function _x5cProof(nonce) {
      var nowSec = Math.floor(Date.now() / 1000);
      var header  = { typ: "openid4vci-proof+jwt", alg: "ES384", x5c: [x5cEntry] };
      var payload = { aud: ISSUER_URL, nonce: nonce, iat: nowSec };
      return _signProof(header, payload, leafPriv, "ES384");             // P-384 → ES384
    }

    // (1) Happy: leaf-cert SPKI binds the holder key; validateX5c runs; verifies.
    var seen = null;
    var s1 = await _issued({
      proofAlgorithms: ["ES384"],
      validateX5c: function (chainDers, header) {
        seen = { n: chainDers.length, isBuf: Buffer.isBuffer(chainDers[0]), typ: header.typ };
      },
    });
    var cred = await _issue(s1, _x5cProof(s1.cNonce));
    check("proof: x5c leaf-cert-bound proof verifies and issues", cred.format === "vc+sd-jwt");
    check("proof: validateX5c received the parsed DER chain buffers",
          seen && seen.n === 1 && seen.isBuf === true && seen.typ === "openid4vci-proof+jwt");

    // (2) validateX5c throws a plain Error → wrapped as a typed x5c-rejected.
    var s2 = await _issued({ proofAlgorithms: ["ES384"],
      validateX5c: function () { throw new Error("untrusted attestation CA"); } });
    await _expectThrow("proof: validateX5c plain-throw wrapped as x5c-rejected",
      "auth-oid4vci/x5c-rejected",
      function () { return _issue(s2, _x5cProof(s2.cNonce)); });

    // (3) validateX5c throws an AuthError → preserved verbatim, not re-wrapped.
    var s3 = await _issued({ proofAlgorithms: ["ES384"],
      validateX5c: function () { throw new AuthError("auth-oid4vci/custom-x5c-policy", "revoked leaf"); } });
    var err3 = await _expectThrow("proof: validateX5c AuthError preserved verbatim",
      "auth-oid4vci/custom-x5c-policy",
      function () { return _issue(s3, _x5cProof(s3.cNonce)); });
    check("proof: validateX5c AuthError not re-wrapped as x5c-rejected",
          err3 && err3.code === "auth-oid4vci/custom-x5c-policy");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---- Run all ----

async function run() {
  await testFullFlowHappyPath();
  await testMetadataDocument();
  await testMetadataCustomFields();

  testCreateRequireObject();
  testCreateMissingRequiredStrings();
  testCreateNoSdJwtIssuer();
  testCreateNoSupportedCredentials();
  testCreateBadCredentialSpec();
  testCreateUnsupportedFormat();
  testCreateNoVct();
  testCreateBadResolveKidType();

  await testOfferBadSubject();
  await testOfferBadCredentialIds();
  await testOfferUnknownCredentialId();
  await testOfferBadTxCode();
  await testOfferTxCodeDefaults();
  await testOfferTxCodeExplicit();

  await testExchangeMissingCode();
  await testExchangeUnknownCode();
  await testExchangeTxCodeRequired();
  await testExchangeTxCodeMismatch();
  await testExchangeAlreadyRedeemedRace();

  await testIssueMissingAccessToken();
  await testIssueInvalidAccessToken();
  await testIssueWrongCredentialIdentifier();
  await testIssueUnknownCredentialId();
  await testIssueNoClaims();
  await testIssueAccessTokenConsumedRace();
  await testIssueMintThrowsRestoresToken();
  await testIssueSingleUseOptOut();
  await testIssueCustomDisclosureAndTtl();
  await testIssueProofMaxAgeCustom();

  await testProofEmptyOrTooLong();
  await testProofNotThreeParts();
  await testProofBadDecode();
  await testProofWrongTyp();
  await testProofUnsupportedAlgAllowlist();
  await testProofCritRefused();
  await testProofNoKey();
  await testProofWrongAud();
  await testProofCNonceExpired();
  await testProofWrongNonce();
  await testProofCNonceNullStoreMissFailsClosed();
  await testProofNoIat();
  await testProofIatFuture();
  await testProofIatTooOld();

  await testKidNoResolver();
  await testKidResolverThrows();
  await testKidResolverUnresolved();
  await testKidResolverBadShape();
  await testKidResolverKeyObject();
  await testKidResolverJwk();
  await testKidResolverAlgKtyMismatch();

  await testX5cNotArrayOrEmpty();
  await testX5cBadEntry();
  await testX5cNonBase64();
  await testX5cBadBase64RoundTrip();
  await testX5cNotDerCert();

  await testProofAlgKtyMismatchInline();
  await testProofAlgAllowedButUnhashable();
  await testProofBadSignature();
  await testProofEdDSAHappy();
  await testProofES384Happy();
  await testProofPS256Happy();

  await testX5cCertBoundPaths();

  if (require.main === module) {
    console.log("oid4vci.test.js: " + helpers.getChecks() + " checks passed");
  }
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
