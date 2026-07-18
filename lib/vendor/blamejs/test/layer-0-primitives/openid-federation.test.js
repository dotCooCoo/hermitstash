// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.openidFederation — OpenID Federation 1.0 trust-chain primitive.
 *
 * Exercises the error / adversarial / defensive / option-default branches of
 * every public surface:
 *
 *   parseEntityStatement — empty / oversize / non-3-segment / bad-decode /
 *     wrong-typ / unsupported-alg rejections.
 *   verifyEntityStatement — no-keys / no-matching-kid / kid-less refuse +
 *     opt-in / alg-kty confusion refuse (CVE-2026-22817) / PS256 padding
 *     branch / bad-signature / iat-future / expired / missing-iss-sub /
 *     tunable clock skew.
 *   applyMetadataPolicy — bad-metadata / bad-chain guards and every OIDF
 *     §6.2 operator (value / default / add / one_of / subset_of /
 *     superset_of / essential / unknown), each with its non-array and
 *     constraint-violation rejection, plus top-down multi-node narrowing.
 *   buildTrustChain — opts / leaf / anchors validation; self-statement
 *     iss==sub==entity_id; no-authority-hints; iss/sub-mismatch + throwing
 *     hint → no-ascent; cyclic authority_hints → chain-cycle; maxDepth →
 *     chain-too-deep; subordinate-pins-no-jwks → no-attested-jwks; the
 *     default httpClient fetcher (fetch-failed / empty-response / success)
 *     and default subordinate fetcher (no-fetch-endpoint / success).
 *   resolveLeaf — no-kind guard + happy effective-metadata resolution.
 *
 * Keys are generated in-process; a self-signed statement verifies and a
 * wrong-key / tampered one is refused. No network: the default-fetcher
 * paths stub httpClient.request in-memory and restore it in finally.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("crypto");
var httpClient = require("../../lib/http-client");

// ---- entity-statement minting (in-process keys) --------------------------

function _b64url(buf) { return Buffer.from(buf).toString("base64url"); }

// Generate an EC P-256 entity: private key + public JWK (kid-tagged) + a
// single-key JWKS. ES256 is the OIDF default and the cheapest keygen.
function _ecEntity(kid) {
  var kp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = kp.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  return { priv: kp.privateKey, jwk: jwk, jwks: { keys: [jwk] } };
}

// One reusable RSA entity for the PS256 padding branch (RSA keygen is slow).
var _sharedRsa = null;
function _rsaEntity(kid) {
  if (!_sharedRsa) {
    _sharedRsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); // allow:raw-byte-literal — RSA modulus bits
  }
  var jwk = _sharedRsa.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  return { priv: _sharedRsa.privateKey, jwk: jwk, jwks: { keys: [jwk] } };
}

// Mint a signed entity-statement+jwt. `mopts`:
//   alg      — "ES256" (default) | "PS256"
//   noKid    — omit header.kid (kid-less-statement path)
//   headerTyp/headerAlg — override header fields for parse-branch tests
//   tamper   — flip the signature so verify fails
function _mint(priv, kid, claims, mopts) {
  mopts = mopts || {};
  var alg    = mopts.alg || "ES256";
  var header = { typ: mopts.headerTyp || "entity-statement+jwt", alg: mopts.headerAlg || alg };
  if (!mopts.noKid) header.kid = kid;
  var input  = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(claims));
  var sig;
  if (alg === "PS256") {
    sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), {
      key:        priv,
      padding:    nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  } else {
    sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: priv, dsaEncoding: "ieee-p1363" });
  }
  if (mopts.tamper) { sig = Buffer.from(sig); sig[0] ^= 0xff; }
  return input + "." + _b64url(sig);
}

var _NOW = Math.floor(Date.now() / 1000);                                        // allow:raw-byte-literal — seconds-per-ms
function _cfg(id, entity, extra) {
  var c = { iss: id, sub: id, iat: _NOW, exp: _NOW + 3600, jwks: entity.jwks };  // allow:raw-byte-literal — 1h validity
  if (extra) Object.keys(extra).forEach(function (k) { c[k] = extra[k]; });
  return c;
}

// Assert an async call rejects with an AuthError whose code matches `re`.
async function _rejects(label, fn, re) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label, !!threw && re.test(threw.code || ""));
}

// Assert a sync call throws with a code matching `re`.
function _throws(label, fn, re) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && re.test(threw.code || ""));
}

// Build a chain array for applyMetadataPolicy: one leaf node whose
// superior-signed subordinate statement carries `policyForKind`, plus a
// terminating anchor node (no `.subordinate`, skipped by the walker).
function _policyChain(policyForKind, kind) {
  var mp = {}; mp[kind] = policyForKind;
  return [{ subordinate: { metadata_policy: mp } }, { claims: { iss: "anchor" } }];
}

// ---- parseEntityStatement branches ---------------------------------------

function testParseRejections() {
  _throws("parse: empty string → bad-statement",
    function () { b.auth.openidFederation.parseEntityStatement(""); }, /bad-statement/);
  _throws("parse: oversize input → bad-statement",
    function () { b.auth.openidFederation.parseEntityStatement("x".repeat(70000)); }, /bad-statement/);
  _throws("parse: non-string input → bad-statement",
    function () { b.auth.openidFederation.parseEntityStatement(null); }, /bad-statement/);
  _throws("parse: 2-segment token → malformed",
    function () { b.auth.openidFederation.parseEntityStatement("aaa.bbb"); }, /malformed/);
  _throws("parse: header not JSON → bad-decode",
    function () {
      var bad = _b64url("not json{") + "." + _b64url(JSON.stringify({ iss: "x" })) + "." + _b64url("s");
      b.auth.openidFederation.parseEntityStatement(bad);
    }, /bad-decode/);
  _throws("parse: wrong header.typ → wrong-typ",
    function () {
      var e = _ecEntity("k");
      b.auth.openidFederation.parseEntityStatement(_mint(e.priv, "k", _cfg("https://x", e), { headerTyp: "JWT" }));
    }, /wrong-typ/);
  _throws("parse: unsupported header.alg → unsupported-alg",
    function () {
      var e = _ecEntity("k");
      // Sign with a real ES256 sig but advertise an unsupported alg in the header.
      b.auth.openidFederation.parseEntityStatement(_mint(e.priv, "k", _cfg("https://x", e), { headerAlg: "HS256" }));
    }, /unsupported-alg/);
}

// ---- verifyEntityStatement branches --------------------------------------

function testVerifyKeySelection() {
  var e   = _ecEntity("kid-a");
  var jwt = _mint(e.priv, "kid-a", _cfg("https://x", e));

  // Happy self-verify + tunable clock skew (the maxClockSkewSec true branch).
  var claims = b.auth.openidFederation.verifyEntityStatement(jwt, e.jwks, { maxClockSkewSec: 300 });
  check("verify: valid self-signed statement returns claims", claims.iss === "https://x");

  _throws("verify: jwks with no keys array → no-keys",
    function () { b.auth.openidFederation.verifyEntityStatement(jwt, {}); }, /no-keys/);
  _throws("verify: jwks with empty keys → no-keys",
    function () { b.auth.openidFederation.verifyEntityStatement(jwt, { keys: [] }); }, /no-keys/);

  // header.kid present but no JWKS key matches it.
  var otherJwk = JSON.parse(JSON.stringify(e.jwk)); otherJwk.kid = "different";
  _throws("verify: kid with no matching JWKS key → no-matching-kid",
    function () { b.auth.openidFederation.verifyEntityStatement(jwt, { keys: [otherJwk] }); }, /no-matching-kid/);
}

function testVerifyKidless() {
  var e         = _ecEntity("kid-a");
  var kidlessJwt = _mint(e.priv, "kid-a", _cfg("https://x", e), { noKid: true });

  // Kid-less refused by default (single key, no opt-in).
  _throws("verify: kid-less statement refused by default → kid-required",
    function () { b.auth.openidFederation.verifyEntityStatement(kidlessJwt, e.jwks); }, /kid-required/);

  // Kid-less refused even with opt-in when JWKS has >1 key.
  var twoKeyJwks = { keys: [e.jwk, _ecEntity("kid-b").jwk] };
  _throws("verify: kid-less with multi-key JWKS refused even with opt-in → kid-required",
    function () { b.auth.openidFederation.verifyEntityStatement(kidlessJwt, twoKeyJwks, { allowKidlessJwks: true }); },
    /kid-required/);

  // Kid-less accepted only with single-key JWKS + explicit opt-in.
  var claims = b.auth.openidFederation.verifyEntityStatement(kidlessJwt, e.jwks, { allowKidlessJwks: true });
  check("verify: kid-less single-key JWKS accepted with allowKidlessJwks", claims.iss === "https://x");
}

function testVerifyAlgKtyConfusion() {
  // CVE-2026-22817 — a statement declaring alg ES256 but resolving to an RSA
  // JWK (same kid) must be refused before node:crypto ever sees the key.
  var ec  = _ecEntity("shared");
  var rsa = _rsaEntity("shared");
  var jwt = _mint(ec.priv, "shared", _cfg("https://x", ec)); // header alg ES256
  _throws("verify: alg ES256 over RSA JWK refused (alg/kty confusion)",
    function () { b.auth.openidFederation.verifyEntityStatement(jwt, rsa.jwks); }, /alg-kty-mismatch/);
}

function testVerifyPs256() {
  // The PS* padding branch: mint a PS256 statement with an RSA key and verify.
  var rsa = _rsaEntity("rsa-ps");
  var jwt = _mint(rsa.priv, "rsa-ps", _cfg("https://ps.example", rsa), { alg: "PS256" });
  var claims = b.auth.openidFederation.verifyEntityStatement(jwt, rsa.jwks);
  check("verify: valid PS256 statement verifies", claims.iss === "https://ps.example");
}

function testVerifySignatureAndTime() {
  var e = _ecEntity("k");

  _throws("verify: tampered signature → bad-signature",
    function () { b.auth.openidFederation.verifyEntityStatement(_mint(e.priv, "k", _cfg("https://x", e), { tamper: true }), e.jwks); },
    /bad-signature/);

  _throws("verify: iat in the future → iat-future",
    function () {
      var c = _cfg("https://x", e); c.iat = _NOW + 100000; c.exp = _NOW + 200000;
      b.auth.openidFederation.verifyEntityStatement(_mint(e.priv, "k", c), e.jwks);
    }, /iat-future/);

  _throws("verify: iat missing → iat-future",
    function () {
      var c = _cfg("https://x", e); delete c.iat;
      b.auth.openidFederation.verifyEntityStatement(_mint(e.priv, "k", c), e.jwks);
    }, /iat-future/);

  _throws("verify: expired statement → expired",
    function () {
      var c = _cfg("https://x", e); c.iat = _NOW - 200000; c.exp = _NOW - 100000;
      b.auth.openidFederation.verifyEntityStatement(_mint(e.priv, "k", c), e.jwks);
    }, /expired/);

  _throws("verify: missing iss/sub → missing-iss-sub",
    function () {
      var c = _cfg("https://x", e); delete c.iss; delete c.sub;
      b.auth.openidFederation.verifyEntityStatement(_mint(e.priv, "k", c), e.jwks);
    }, /missing-iss-sub/);
}

// ---- applyMetadataPolicy: guards + every OIDF §6.2 operator ---------------

function testPolicyGuards() {
  _throws("applyMetadataPolicy: non-object metadata → bad-metadata",
    function () { b.auth.openidFederation.applyMetadataPolicy(null, [], "openid_relying_party"); }, /bad-metadata/);
  _throws("applyMetadataPolicy: non-array chain → bad-chain",
    function () { b.auth.openidFederation.applyMetadataPolicy({}, "nope", "openid_relying_party"); }, /bad-chain/);
  _throws("applyMetadataPolicy: rules not an object → bad-policy-rules",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({}, _policyChain({ client_name: "scalar" }, "k"), "k");
    }, /bad-policy-rules/);
}

function testPolicyOperators() {
  var K = "openid_relying_party";
  function apply(meta, pol) { return b.auth.openidFederation.applyMetadataPolicy(meta, _policyChain(pol, K), K); }

  // value — overrides.
  check("policy value: sets claim to fixed value",
    apply({ client_name: "orig" }, { client_name: { value: "fixed" } }).client_name === "fixed");

  // default — only when absent.
  check("policy default: fills absent claim",
    apply({}, { contacts: { default: ["a@b.c"] } }).contacts[0] === "a@b.c");
  check("policy default: leaves present claim untouched",
    apply({ contacts: ["keep@x"] }, { contacts: { default: ["a@b.c"] } }).contacts[0] === "keep@x");

  // add — array append; non-array rejected.
  _throws("policy add: non-array value → bad-policy-add",
    function () { apply({}, { redirect_uris: { add: "not-array" } }); }, /bad-policy-add/);
  var added = apply({ redirect_uris: ["u1"] }, { redirect_uris: { add: ["u1", "u2"] } }).redirect_uris;
  check("policy add: appends only new values", added.length === 2 && added[1] === "u2");
  check("policy add: seeds absent claim as array",
    apply({}, { redirect_uris: { add: ["u1"] } }).redirect_uris[0] === "u1");

  // one_of.
  _throws("policy one_of: non-array value → bad-policy-one-of",
    function () { apply({ subject_type: "public" }, { subject_type: { one_of: "public" } }); }, /bad-policy-one-of/);
  _throws("policy one_of: value not in set → policy-one-of-failed",
    function () { apply({ subject_type: "pairwise" }, { subject_type: { one_of: ["public"] } }); }, /policy-one-of-failed/);
  check("policy one_of: value in set passes",
    apply({ subject_type: "public" }, { subject_type: { one_of: ["public", "pairwise"] } }).subject_type === "public");

  // subset_of.
  _throws("policy subset_of: non-array value → bad-policy-subset-of",
    function () { apply({ scopes: ["a"] }, { scopes: { subset_of: "a" } }); }, /bad-policy-subset-of/);
  _throws("policy subset_of: value outside allowed → policy-subset-of-failed",
    function () { apply({ scopes: ["a", "z"] }, { scopes: { subset_of: ["a", "b"] } }); }, /policy-subset-of-failed/);
  check("policy subset_of: subset passes",
    apply({ scopes: ["a"] }, { scopes: { subset_of: ["a", "b"] } }).scopes[0] === "a");

  // superset_of.
  _throws("policy superset_of: non-array value → bad-policy-superset-of",
    function () { apply({ grant_types: ["x"] }, { grant_types: { superset_of: "x" } }); }, /bad-policy-superset-of/);
  _throws("policy superset_of: missing required value → policy-superset-of-failed",
    function () { apply({ grant_types: ["authorization_code"] }, { grant_types: { superset_of: ["refresh_token"] } }); },
    /policy-superset-of-failed/);
  check("policy superset_of: contains all required passes",
    apply({ grant_types: ["authorization_code", "refresh_token"] },
      { grant_types: { superset_of: ["refresh_token"] } }).grant_types.length === 2);

  // essential.
  _throws("policy essential: required-but-absent → policy-essential-failed",
    function () { apply({}, { sector_identifier_uri: { essential: true } }); }, /policy-essential-failed/);
  check("policy essential: present claim passes",
    apply({ sector_identifier_uri: "https://s" }, { sector_identifier_uri: { essential: true } }).sector_identifier_uri === "https://s");

  // unknown operator refuses loudly.
  _throws("policy: unknown operator → unknown-policy-op",
    function () { apply({}, { client_name: { bogus_op: 1 } }); }, /unknown-policy-op/);
}

function testPolicyMultiNodeNarrowing() {
  // Top-down: the anchor-signed (intermediate) policy is applied before the
  // intermediate-signed (leaf) policy. Both narrow the effective metadata.
  var K = "openid_relying_party";
  var chain = [
    { subordinate: { metadata_policy: { "openid_relying_party": { grant_types: { subset_of: ["authorization_code", "refresh_token"] } } } } },
    { subordinate: { metadata_policy: { "openid_relying_party": { scopes: { default: ["openid"] } } } } },
    { claims: { iss: "https://anchor.example" } },
  ];
  var eff = b.auth.openidFederation.applyMetadataPolicy(
    { grant_types: ["authorization_code"] }, chain, K);
  check("policy multi-node: anchor subset_of + intermediate default both applied",
    eff.grant_types[0] === "authorization_code" && eff.scopes[0] === "openid");
}

// The chain levels' policies are MERGED (OIDF 1.0 §6.1.5.3) so a subordinate can
// only narrow a superior's constraint, never override it — the pre-merge
// sequential apply let a leaf-ward `value` silently overwrite the anchor's.
function testPolicyMergeCrossLevel() {
  var K = "openid_relying_party";
  function chainOf(anchorPolicy, subPolicy) {
    // leaf-first: chain[0].subordinate = the intermediate's policy on the leaf
    // (lower); chain[1].subordinate = the anchor's policy on the intermediate.
    return [
      { subordinate: { metadata_policy: { "openid_relying_party": subPolicy } } },
      { subordinate: { metadata_policy: { "openid_relying_party": anchorPolicy } } },
      { claims: { iss: "https://anchor.example" } },
    ];
  }
  _throws("policy merge: conflicting cross-level value refused (trust downgrade)",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({},
        chainOf({ token_endpoint_auth_method: { value: "private_key_jwt" } },
                { token_endpoint_auth_method: { value: "none" } }), K);
    }, /policy-merge-conflict/);
  var same = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ token_endpoint_auth_method: { value: "x" } },
            { token_endpoint_auth_method: { value: "x" } }), K);
  check("policy merge: identical cross-level value applies", same.token_endpoint_auth_method === "x");
  _throws("policy merge: one_of intersects (subordinate narrows the anchor's set)",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({ grant_types: "a" },
        chainOf({ grant_types: { one_of: ["a", "b", "c"] } },
                { grant_types: { one_of: ["b", "c"] } }), K);
    }, /one-of/);
  var u = b.auth.openidFederation.applyMetadataPolicy({ scope: [] },
    chainOf({ scope: { add: ["x"] } }, { scope: { add: ["y"] } }), K);
  check("policy merge: add unions across levels",
    u.scope.indexOf("x") !== -1 && u.scope.indexOf("y") !== -1);

  // Cross-operator downgrades: a subordinate must not escape a superior's
  // constraint by expressing an override with a DIFFERENT operator. The merged
  // constraint is enforced against the FINAL value at apply time, so each is
  // refused -- a value outside the merged one_of, an add widening past the
  // merged subset_of, a value dropping a superset_of-mandated member.
  _throws("policy merge: subordinate value cannot override a superior one_of",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({},
        chainOf({ token_endpoint_auth_method: { one_of: ["private_key_jwt"] } },
                { token_endpoint_auth_method: { value: "none" } }), K);
    }, /policy-one-of-failed/);
  _throws("policy merge: subordinate add cannot widen past a superior subset_of",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({ scope: ["read"] },
        chainOf({ scope: { subset_of: ["read"] } },
                { scope: { add: ["write"] } }), K);
    }, /policy-subset-of-failed/);
  _throws("policy merge: subordinate value cannot drop a superior superset_of member",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({ grant_types: ["authorization_code"] },
        chainOf({ grant_types: { superset_of: ["authorization_code"] } },
                { grant_types: { value: ["implicit"] } }), K);
    }, /policy-superset-of-failed/);

  // Consistent cross-operator combinations remain valid narrowings.
  var withinSub = b.auth.openidFederation.applyMetadataPolicy({ scope: [] },
    chainOf({ scope: { subset_of: ["read", "write"] } }, { scope: { add: ["read"] } }), K);
  check("policy merge: add within subset_of applies", withinSub.scope[0] === "read");
  var defOneOf = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ subject_type: { one_of: ["public", "pairwise"] } },
            { subject_type: { default: "public" } }), K);
  check("policy merge: default consistent with one_of applies", defOneOf.subject_type === "public");
  // A subordinate MAY pin an exact `value` INSIDE the superior's one_of set (a
  // valid narrowing, OIDF 6.1.3.1.1); only a value OUTSIDE it is the downgrade.
  var vInSet = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ token_endpoint_auth_method: { one_of: ["private_key_jwt", "self_signed_tls_client_auth"] } },
            { token_endpoint_auth_method: { value: "private_key_jwt" } }), K);
  check("policy merge: value consistent with a superior one_of applies",
    vInSet.token_endpoint_auth_method === "private_key_jwt");
  // A subordinate cannot WIDEN an anchor's exact `value` with `add` (the union
  // would escape the pin) nor pair it with `default` -- value combines with a
  // constraint, never with another modifier.
  _throws("policy merge: subordinate add cannot widen an anchor pinned value",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({ grant_types: ["authorization_code"] },
        chainOf({ grant_types: { value: ["authorization_code"] } },
                { grant_types: { add: ["implicit"] } }), K);
    }, /policy-merge-conflict/);
  // `value` + `add` is a no-op (allowed) when `add` is already within the pin;
  // `value` + `default` is a no-op (the pinned value wins) -- neither widens.
  var vAddNoop = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ grant_types: { value: ["authorization_code", "refresh_token"] } },
            { grant_types: { add: ["refresh_token"] } }), K);
  check("policy merge: value + add within the pin is a no-op",
    vAddNoop.grant_types.length === 2 && vAddNoop.grant_types.indexOf("refresh_token") !== -1);
  var vDefault = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ subject_type: { value: "public" } },
            { subject_type: { default: "pairwise" } }), K);
  check("policy merge: value + default applies the pinned value", vDefault.subject_type === "public");
  // `superset_of` is satisfied by the FINAL value, so a co-present `add` need not
  // itself supply the mandated member when the leaf already carries it.
  var addSuperLeaf = b.auth.openidFederation.applyMetadataPolicy({ grant_types: ["authorization_code"] },
    chainOf({ grant_types: { superset_of: ["authorization_code"] } },
            { grant_types: { add: ["refresh_token"] } }), K);
  check("policy merge: add + superset_of satisfied by leaf metadata applies",
    addSuperLeaf.grant_types.indexOf("authorization_code") !== -1 &&
    addSuperLeaf.grant_types.indexOf("refresh_token") !== -1);
  // A space-delimited scope value is validated as a subset of the merged subset_of.
  var scopeVal = b.auth.openidFederation.applyMetadataPolicy({},
    chainOf({ scope: { subset_of: ["openid", "email"] } },
            { scope: { value: "openid email" } }), K);
  check("policy merge: scope-string value within subset_of applies", scopeVal.scope === "openid email");
  // Disjoint one_of across levels intersects to the empty set -> refused (no
  // value could ever satisfy the chain), not silently accepted when absent.
  _throws("policy merge: disjoint one_of across levels refused",
    function () {
      b.auth.openidFederation.applyMetadataPolicy({},
        chainOf({ subject_type: { one_of: ["public"] } },
                { subject_type: { one_of: ["pairwise"] } }), K);
    }, /policy-merge-conflict/);
}

// subset_of constrains an array-valued claim; a leaf that self-declares the
// claim as a scalar (or object) must NOT skip the anchor's allow-list -- it
// fails closed, symmetric with superset_of. A leaf controls its own base
// metadata, so a type-confused scalar would otherwise smuggle a forbidden value.
function testPolicySubsetOfArrayType() {
  var K = "openid_relying_party";
  function apply(meta, pol) { return b.auth.openidFederation.applyMetadataPolicy(meta, _policyChain(pol, K), K); }
  // A space-delimited string claim (OAuth `scope`, OIDF 6.1.3.1.8) is processed
  // as an array: a subset passes; the string type is preserved on the result.
  var okScope = apply({ scope: "openid email" }, { scope: { subset_of: ["openid", "email", "profile"] } });
  check("policy subset_of: scope string within allow-list passes", okScope.scope === "openid email");
  _throws("policy subset_of: scope string with a forbidden token refused",
    function () { apply({ scope: "openid admin" }, { scope: { subset_of: ["openid", "email"] } }); },
    /policy-subset-of-failed/);
  // A claim the leaf type-confuses into a scalar cannot smuggle a forbidden value
  // past the allow-list -- the split tokens are each checked.
  _throws("policy subset_of: scalar with a forbidden token refused (no allow-list bypass)",
    function () { apply({ grant_types: "authorization_code implicit" }, { grant_types: { subset_of: ["authorization_code"] } }); },
    /policy-subset-of-failed/);
  // A genuine non-array, non-string value (object/number) is malformed -> refused.
  _throws("policy subset_of: non-array object claim fails closed",
    function () { apply({ grant_types: { x: 1 } }, { grant_types: { subset_of: ["authorization_code"] } }); },
    /policy-subset-of-failed/);
  // An absent claim under subset_of stays absent -- subset_of does not require
  // presence (that is `essential`), it only constrains a value that IS present.
  var absent = apply({}, { grant_types: { subset_of: ["authorization_code"] } });
  check("policy subset_of: absent claim stays absent", absent.grant_types === undefined);
}

// A metadata_policy claim name, or a base-metadata key, of __proto__ /
// constructor / prototype must be refused (prototype-pollution guard) and must
// never write Object.prototype -- the policy and metadata arrive as
// attacker-influenced JSON, and the merge accumulates into a shared object.
function testPolicyPrototypePollution() {
  var K = "openid_relying_party";
  function chain(pol) {
    return [{ subordinate: { metadata_policy: { "openid_relying_party": pol } } }, { claims: { iss: "https://a" } }];
  }
  delete Object.prototype.polluted;
  delete Object.prototype.value;
  // A poisoned CLAIM name in a policy block (JSON wire path -> own __proto__ key).
  _throws("policy: __proto__ claim name refused (no prototype pollution)",
    function () { b.auth.openidFederation.applyMetadataPolicy({}, chain(JSON.parse('{"__proto__":{"value":"x"}}')), K); },
    /poisoned-policy-key/);
  _throws("policy: constructor claim name refused",
    function () { b.auth.openidFederation.applyMetadataPolicy({}, chain(JSON.parse('{"constructor":{"value":"x"}}')), K); },
    /poisoned-policy-key/);
  // A poisoned key in the leaf's base metadata.
  _throws("policy: __proto__ base-metadata key refused",
    function () {
      b.auth.openidFederation.applyMetadataPolicy(JSON.parse('{"__proto__":{"polluted":true}}'),
        chain({ client_name: { value: "x" } }), K);
    }, /poisoned-metadata-key/);
  check("policy: Object.prototype left unpolluted",
    ({}).polluted === undefined && ({}).value === undefined);
}

// ---- buildTrustChain: input validation -----------------------------------

async function testChainValidation() {
  await _rejects("buildTrustChain: missing opts → throws",
    function () { return b.auth.openidFederation.buildTrustChain(); }, /./);
  await _rejects("buildTrustChain: missing leafEntityId → no-leaf",
    function () { return b.auth.openidFederation.buildTrustChain({ trustAnchors: { a: {} } }); }, /no-leaf/);
  await _rejects("buildTrustChain: empty trustAnchors map → no-anchors",
    function () { return b.auth.openidFederation.buildTrustChain({ leafEntityId: "https://rp", trustAnchors: {} }); },
    /no-anchors/);
  await _rejects("buildTrustChain: non-object trustAnchors → no-anchors",
    function () { return b.auth.openidFederation.buildTrustChain({ leafEntityId: "https://rp", trustAnchors: "x" }); },
    /no-anchors/);
}

// A leaf→anchor pair fetcher over an in-memory map keyed by URL, plus an
// explicit subordinate fetcher. `sub` is the anchor-signed statement about
// the leaf. Returns { fetcher, fetchSubordinate }.
function _memFetchers(byUrl, subByAuthority) {
  return {
    fetcher: function (url) {
      if (Object.prototype.hasOwnProperty.call(byUrl, url)) return Promise.resolve(byUrl[url]);
      return Promise.reject(new Error("no fixture for " + url));
    },
    fetchSubordinate: function (authority) {
      var v = subByAuthority[authority];
      if (typeof v === "function") return v();
      if (v === undefined) return Promise.reject(new Error("no subordinate for " + authority));
      return Promise.resolve(v);
    },
  };
}

// Build a valid leaf + anchor set of statements + fetchers.
function _validChainFixture(opts) {
  opts = opts || {};
  var leaf   = _ecEntity("leaf-k");
  var anchor = _ecEntity("anchor-k");
  var leafId = "https://rp.example", anchorId = "https://anchor.example";
  var leafCfg = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf, {
    authority_hints: [anchorId],
    metadata: { openid_relying_party: { client_name: "RP", contacts: ["x@rp"] } },
  }));
  var anchorCfg = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor));
  // Anchor-signed subordinate statement about the leaf; pins the leaf jwks.
  var subClaims = { iss: anchorId, sub: leafId, iat: _NOW, exp: _NOW + 3600 };   // allow:raw-byte-literal — 1h validity
  if (!opts.noJwks) subClaims.jwks = leaf.jwks;
  if (opts.policy) subClaims.metadata_policy = opts.policy;
  var subStmt = _mint(anchor.priv, "anchor-k", subClaims);
  var byUrl = {};
  byUrl[leafId + "/.well-known/openid-federation"]   = leafCfg;
  byUrl[anchorId + "/.well-known/openid-federation"] = anchorCfg;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function () { return Promise.resolve(subStmt); };
  return { leaf: leaf, anchor: anchor, leafId: leafId, anchorId: anchorId,
           anchorJwks: anchor.jwks, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate };
}

async function testChainHappyAndResolve() {
  var f = _validChainFixture({ policy: { openid_relying_party: { contacts: { default: ["fallback@rp"] } } } });
  var anchors = {}; anchors[f.anchorId] = f.anchorJwks;

  var chain = await b.auth.openidFederation.buildTrustChain({
    leafEntityId: f.leafId, trustAnchors: anchors, fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate,
  });
  check("buildTrustChain: 2-node chain leaf+anchor", chain.length === 2 &&
    chain[0].role === "leaf" && chain[1].role === "trust_anchor");

  var resolved = await b.auth.openidFederation.resolveLeaf({
    leafEntityId: f.leafId, trustAnchors: anchors, kind: "openid_relying_party",
    fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate,
  });
  check("resolveLeaf: returns effective metadata + trust anchor",
    resolved.trustAnchor === f.anchorId && resolved.effectiveMetadata.client_name === "RP");

  await _rejects("resolveLeaf: missing kind → no-kind",
    function () {
      return b.auth.openidFederation.resolveLeaf({ leafEntityId: f.leafId, trustAnchors: anchors,
        fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate });
    }, /no-kind/);

  // A kind the leaf does not declare resolves from an empty metadata base
  // (the `leafClaims.metadata[kind] || {}` fallback) — no crash.
  var opResolved = await b.auth.openidFederation.resolveLeaf({
    leafEntityId: f.leafId, trustAnchors: anchors, kind: "openid_provider",
    fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate,
  });
  check("resolveLeaf: undeclared kind resolves from empty metadata base",
    opResolved.effectiveMetadata && Object.keys(opResolved.effectiveMetadata).length === 0);
}

async function testChainSelfStatement() {
  // Entity config whose iss != entity_id → bad-self-statement.
  var leaf   = _ecEntity("leaf-k");
  var leafId = "https://rp.example";
  var badCfg = _mint(leaf.priv, "leaf-k", _cfg("https://evil.example", leaf, { sub: leafId, authority_hints: ["https://a"] }));
  var byUrl = {}; byUrl[leafId + "/.well-known/openid-federation"] = badCfg;
  var m = _memFetchers(byUrl, {});
  await _rejects("buildTrustChain: iss!=entity_id → bad-self-statement",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId,
        trustAnchors: { "https://a": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /bad-self-statement/);
}

async function testChainLeafWithoutJwks() {
  // A leaf entity config that publishes no jwks: the self-statement verify
  // falls back to an empty JWKS and is refused (no-keys) rather than being
  // waved through — the `parsedEC.claims.jwks || {}` fallback.
  var leaf   = _ecEntity("leaf-k");
  var leafId = "https://rp.example";
  var cfg = _mint(leaf.priv, "leaf-k", { iss: leafId, sub: leafId, iat: _NOW, exp: _NOW + 3600, authority_hints: ["https://a"] });
  var byUrl = {}; byUrl[leafId + "/.well-known/openid-federation"] = cfg;
  var m = _memFetchers(byUrl, {});
  await _rejects("buildTrustChain: entity config with no jwks → no-keys",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId,
        trustAnchors: { "https://a": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /no-keys/);
}

async function testChainNoAuthorityHints() {
  var leaf   = _ecEntity("leaf-k");
  var leafId = "https://rp.example";
  var cfg = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf)); // no authority_hints
  var byUrl = {}; byUrl[leafId + "/.well-known/openid-federation"] = cfg;
  var m = _memFetchers(byUrl, {});
  await _rejects("buildTrustChain: leaf without authority_hints → no-authority-hints",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId,
        trustAnchors: { "https://anchor": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /no-authority-hints/);
}

async function testChainNoAscent() {
  // Three hints exercising each ascent-failure arm: a malformed subordinate
  // (parse throws a CODED AuthError), an iss/sub-mismatched subordinate
  // (skipped via continue), and a plain uncoded rejection. None yields an
  // ascent → no-ascent aggregating every reason.
  var leaf   = _ecEntity("leaf-k");
  var leafId = "https://rp.example";
  var authA = "https://a.example", authB = "https://b.example",
      authC = "https://c.example", authD = "https://d.example";
  var cfg = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf, { authority_hints: [authA, authB, authC, authD] }));
  var byUrl = {}; byUrl[leafId + "/.well-known/openid-federation"] = cfg;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function (authority) {
    if (authority === authA) return Promise.resolve("not.a.valid.jwt"); // parse → coded AuthError
    if (authority === authB) {
      // wrong iss (not authB) → iss-sub-mismatch, skipped via continue.
      return Promise.resolve(_mint(leaf.priv, "leaf-k", { iss: "https://wrong", sub: leafId, iat: _NOW, exp: _NOW + 3600, jwks: leaf.jwks }));
    }
    if (authority === authC) return Promise.reject(new Error("network down")); // uncoded → "unknown"
    // A non-Error rejection: coded but message-less → String(err) diagnostic fallback.
    return Promise.reject({ code: "custom/opaque-reject" });
  };
  await _rejects("buildTrustChain: no hint yields a valid subordinate → no-ascent",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId,
        trustAnchors: { "https://anchor": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /no-ascent/);
}

async function testChainCycle() {
  // A → B → A : the revisit of A is refused as a cyclic authority_hints graph.
  var a = _ecEntity("a-k"), bEnt = _ecEntity("b-k");
  var idA = "https://a.example", idB = "https://b.example";
  var cfgA = _mint(a.priv, "a-k", _cfg(idA, a, { authority_hints: [idB] }));
  var cfgB = _mint(bEnt.priv, "b-k", _cfg(idB, bEnt, { authority_hints: [idA] }));
  var byUrl = {};
  byUrl[idA + "/.well-known/openid-federation"] = cfgA;
  byUrl[idB + "/.well-known/openid-federation"] = cfgB;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function (authority, sub) {
    // A well-formed subordinate iss=authority sub=sub, so the cycle guard
    // (not an iss/sub-mismatch) is what refuses.
    var signer = authority === idA ? a : bEnt;
    var kid    = authority === idA ? "a-k" : "b-k";
    return Promise.resolve(_mint(signer.priv, kid, { iss: authority, sub: sub, iat: _NOW, exp: _NOW + 3600, jwks: (sub === idA ? a : bEnt).jwks }));
  };
  await _rejects("buildTrustChain: cyclic authority_hints → chain-cycle",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: idA,
        trustAnchors: { "https://never": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /chain-cycle/);
}

async function testChainTooDeep() {
  // maxDepth 1: leaf ascends once to an intermediate, the loop budget is spent
  // before an anchor is reached → chain-too-deep.
  var leaf = _ecEntity("leaf-k"), inter = _ecEntity("int-k");
  var leafId = "https://rp.example", interId = "https://int.example";
  var cfg = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf, { authority_hints: [interId] }));
  var byUrl = {}; byUrl[leafId + "/.well-known/openid-federation"] = cfg;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function (authority, sub) {
    return Promise.resolve(_mint(inter.priv, "int-k", { iss: authority, sub: sub, iat: _NOW, exp: _NOW + 3600, jwks: leaf.jwks }));
  };
  await _rejects("buildTrustChain: maxDepth exceeded → chain-too-deep",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, maxDepth: 1,
        trustAnchors: { "https://anchor": {} }, fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /chain-too-deep/);
}

async function testChainNoAttestedJwks() {
  // A structurally valid leaf→anchor chain where the anchor-signed
  // subordinate pins NO jwks → Phase-2 refuses with no-attested-jwks.
  var f = _validChainFixture({ noJwks: true });
  var anchors = {}; anchors[f.anchorId] = f.anchorJwks;
  await _rejects("buildTrustChain: subordinate pins no jwks → no-attested-jwks",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: f.leafId, trustAnchors: anchors,
        fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate });
    }, /no-attested-jwks/);
}

// ---- self-config bound to superior-attested (pinned) keys ----------------
// The trust decision for an entity's effective metadata is that its Entity
// Configuration (the metadata source) was signed by a key the superior
// ATTESTS for it — not merely self-signed. Phase 1 self-verifies the config
// against its OWN self-published jwks (integrity only); Phase 2 must re-bind
// the config to the keys the superior's subordinate statement pins.

async function testChainLeafConfigNotBoundToPinnedKeys() {
  // Fail-open repro: an attacker controls the leaf's .well-known endpoint but
  // NOT its federation-attested key. They serve a self-signed config carrying
  // forged metadata + their own jwks (Phase-1 self-verify passes); the honest
  // anchor's subordinate statement pins the leaf's REAL keys. The chain must
  // refuse — the forged config was not signed by an attested key. Same kid on
  // both keys forces a signature check (not a kid mismatch).
  var honest = _ecEntity("leaf-k");
  var evil   = _ecEntity("leaf-k");
  var anchor = _ecEntity("anchor-k");
  var leafId = "https://rp.example", anchorId = "https://anchor.example";

  var forgedLeafCfg = _mint(evil.priv, "leaf-k", _cfg(leafId, evil, {
    authority_hints: [anchorId],
    metadata: { openid_relying_party: { client_name: "ATTACKER", redirect_uris: ["https://evil.example/cb"] } },
  }));
  var anchorCfg = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor));
  var subStmt = _mint(anchor.priv, "anchor-k",
    { iss: anchorId, sub: leafId, iat: _NOW, exp: _NOW + 3600, jwks: honest.jwks });  // allow:raw-byte-literal — 1h validity

  var byUrl = {};
  byUrl[leafId + "/.well-known/openid-federation"]   = forgedLeafCfg;
  byUrl[anchorId + "/.well-known/openid-federation"] = anchorCfg;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function () { return Promise.resolve(subStmt); };
  var anchors = {}; anchors[anchorId] = anchor.jwks;

  await _rejects("buildTrustChain: leaf config signed by non-attested key refused",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, trustAnchors: anchors,
        fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /bad-signature/);

  await _rejects("resolveLeaf: forged leaf metadata never resolved (config unbound to pinned keys)",
    function () {
      return b.auth.openidFederation.resolveLeaf({ leafEntityId: leafId, trustAnchors: anchors,
        kind: "openid_relying_party", fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate });
    }, /bad-signature/);
}

// Build a 3-node leaf → intermediate → anchor fixture. `opts.forgeIntermediate`
// re-signs the intermediate's self-config with an attacker key of the SAME kid
// while the anchor still pins the intermediate's REAL keys.
function _threeNodeFixture(opts) {
  opts = opts || {};
  var leaf   = _ecEntity("leaf-k");
  var inter  = _ecEntity("int-k");
  var anchor = _ecEntity("anchor-k");
  var leafId = "https://rp.example", interId = "https://int.example", anchorId = "https://anchor.example";

  var interSigner = opts.forgeIntermediate ? _ecEntity("int-k") : inter;

  var leafCfg   = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf, {
    authority_hints: [interId],
    metadata: { openid_relying_party: { client_name: "RP" } },
  }));
  // Self-jwks matches whoever signed it so the Phase-1 self-verify passes.
  var interCfg  = _mint(interSigner.priv, "int-k", _cfg(interId, interSigner, { authority_hints: [anchorId] }));
  var anchorCfg = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor));

  // Anchor-signed subordinate about the intermediate pins the intermediate's
  // REAL keys; intermediate-signed subordinate about the leaf pins the leaf's.
  var subInter = _mint(anchor.priv, "anchor-k",
    { iss: anchorId, sub: interId, iat: _NOW, exp: _NOW + 3600, jwks: inter.jwks });  // allow:raw-byte-literal — 1h validity
  var subLeaf  = _mint(inter.priv, "int-k",
    { iss: interId, sub: leafId, iat: _NOW, exp: _NOW + 3600, jwks: leaf.jwks });     // allow:raw-byte-literal — 1h validity

  var byUrl = {};
  byUrl[leafId + "/.well-known/openid-federation"]   = leafCfg;
  byUrl[interId + "/.well-known/openid-federation"]  = interCfg;
  byUrl[anchorId + "/.well-known/openid-federation"] = anchorCfg;
  var m = _memFetchers(byUrl, {});
  m.fetchSubordinate = function (authority) {
    if (authority === interId)  return Promise.resolve(subLeaf);
    if (authority === anchorId) return Promise.resolve(subInter);
    return Promise.reject(new Error("no subordinate for " + authority));
  };
  var anchors = {}; anchors[anchorId] = anchor.jwks;
  return { leafId: leafId, interId: interId, anchorId: anchorId, anchors: anchors,
           fetcher: m.fetcher, fetchSubordinate: m.fetchSubordinate };
}

async function testChainThreeNodeHappy() {
  // A full leaf → intermediate → anchor chain resolves and exercises the
  // Phase-2 pinned-key config verify for an INTERMEDIATE node (not just the
  // leaf) on the honest path.
  var f = _threeNodeFixture();
  var chain = await b.auth.openidFederation.buildTrustChain({
    leafEntityId: f.leafId, trustAnchors: f.anchors, fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate });
  check("buildTrustChain: 3-node leaf+intermediate+anchor chain",
    chain.length === 3 && chain[0].role === "leaf" &&
    chain[1].role === "intermediate" && chain[2].role === "trust_anchor");

  var resolved = await b.auth.openidFederation.resolveLeaf({
    leafEntityId: f.leafId, trustAnchors: f.anchors, kind: "openid_relying_party",
    fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate });
  check("resolveLeaf: 3-node chain resolves effective metadata",
    resolved.trustAnchor === f.anchorId && resolved.effectiveMetadata.client_name === "RP");
}

async function testChainIntermediateConfigNotBoundToPinnedKeys() {
  // The fail-open one hop up: a forged INTERMEDIATE self-config (attacker key,
  // same kid) with the anchor pinning the intermediate's REAL keys must fail
  // the chain — proving the pinned-key config binding covers every non-anchor
  // node, not just the leaf.
  var f = _threeNodeFixture({ forgeIntermediate: true });
  await _rejects("buildTrustChain: intermediate config signed by non-attested key refused",
    function () {
      return b.auth.openidFederation.buildTrustChain({ leafEntityId: f.leafId, trustAnchors: f.anchors,
        fetcher: f.fetcher, fetchSubordinate: f.fetchSubordinate });
    }, /bad-signature/);
}

// ---- default httpClient fetcher + default subordinate fetcher ------------
// These stub httpClient.request (the same module instance openid-federation
// lazy-requires) so no explicit fetcher/fetchSubordinate is passed and the
// framework's own fetch closures execute. Restored in finally.

async function _withStubbedRequest(handler, fn) {
  var orig = httpClient.request;
  httpClient.request = handler;
  try { return await fn(); }
  finally { httpClient.request = orig; }
}

async function testDefaultFetcherErrorPaths() {
  var leafId = "https://rp.example";
  await _withStubbedRequest(function () { return Promise.resolve({ statusCode: 404 }); }, function () {
    return _rejects("default fetcher: non-2xx status → fetch-failed",
      function () {
        return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, trustAnchors: { "https://a": {} } });
      }, /fetch-failed/);
  });
  await _withStubbedRequest(function () { return Promise.resolve({ statusCode: 200, body: null }); }, function () {
    return _rejects("default fetcher: empty body → empty-response",
      function () {
        return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, trustAnchors: { "https://a": {} } });
      }, /empty-response/);
  });
}

async function testDefaultSubordinateFetcher() {
  // Full chain over the default httpClient fetcher AND the default subordinate
  // fetcher (federation_fetch_endpoint discovery). Covers the success return
  // of both closures.
  var leaf   = _ecEntity("leaf-k");
  var anchor = _ecEntity("anchor-k");
  var leafId = "https://rp.example", anchorId = "https://anchor.example";
  var fetchEp = anchorId + "/fetch";
  var leafCfg = _mint(leaf.priv, "leaf-k", _cfg(leafId, leaf, {
    authority_hints: [anchorId], metadata: { openid_relying_party: { client_name: "RP" } },
  }));
  var anchorCfg = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor, { federation_fetch_endpoint: fetchEp }));
  var subStmt = _mint(anchor.priv, "anchor-k", { iss: anchorId, sub: leafId, iat: _NOW, exp: _NOW + 3600, jwks: leaf.jwks });
  var route = {};
  route[leafId + "/.well-known/openid-federation"]   = leafCfg;
  route[anchorId + "/.well-known/openid-federation"] = anchorCfg;

  function handler(reqOpts) {
    var u = reqOpts.url;
    if (route[u]) return Promise.resolve({ statusCode: 200, body: Buffer.from(route[u], "utf8") });
    if (u.indexOf(fetchEp) === 0) return Promise.resolve({ statusCode: 200, body: Buffer.from(subStmt, "utf8") });
    return Promise.resolve({ statusCode: 404 });
  }
  var anchors = {}; anchors[anchorId] = anchor.jwks;
  await _withStubbedRequest(handler, function () {
    return (async function () {
      var chain = await b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, trustAnchors: anchors });
      check("default subordinate fetcher: full chain via federation_fetch_endpoint",
        chain.length === 2 && chain[1].role === "trust_anchor");
    })();
  });

  // no-fetch-endpoint: anchor config omits federation_fetch_endpoint → the
  // default subordinate fetcher throws, surfaced through the ascent path.
  var anchorNoEp = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor));
  var route2 = {};
  route2[leafId + "/.well-known/openid-federation"]   = leafCfg;
  route2[anchorId + "/.well-known/openid-federation"] = anchorNoEp;
  function handler2(reqOpts) {
    var u = reqOpts.url;
    if (route2[u]) return Promise.resolve({ statusCode: 200, body: Buffer.from(route2[u], "utf8") });
    return Promise.resolve({ statusCode: 404 });
  }
  await _withStubbedRequest(handler2, function () {
    return _rejects("default subordinate fetcher: no federation_fetch_endpoint → no-ascent (no-fetch-endpoint)",
      function () { return b.auth.openidFederation.buildTrustChain({ leafEntityId: leafId, trustAnchors: anchors }); },
      /no-ascent/);
  });
}

async function run() {
  testParseRejections();
  testVerifyKeySelection();
  testVerifyKidless();
  testVerifyAlgKtyConfusion();
  testVerifyPs256();
  testVerifySignatureAndTime();
  testPolicyGuards();
  testPolicyOperators();
  testPolicyMultiNodeNarrowing();
  testPolicyMergeCrossLevel();
  testPolicySubsetOfArrayType();
  testPolicyPrototypePollution();
  await testChainValidation();
  await testChainHappyAndResolve();
  await testChainSelfStatement();
  await testChainLeafWithoutJwks();
  await testChainNoAuthorityHints();
  await testChainNoAscent();
  await testChainCycle();
  await testChainTooDeep();
  await testChainNoAttestedJwks();
  await testChainLeafConfigNotBoundToPinnedKeys();
  await testChainThreeNodeHappy();
  await testChainIntermediateConfigNotBoundToPinnedKeys();
  await testDefaultFetcherErrorPaths();
  await testDefaultSubordinateFetcher();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
