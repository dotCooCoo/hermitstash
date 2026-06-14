"use strict";
/**
 * v0.8.62 federation / VC slice — Layer 0 coverage for:
 *   - b.xmlC14n            (canonicalize, canonicalizeElementById, single-match invariant)
 *   - b.auth.saml          (sp.buildAuthnRequest, sp.verifyResponse signature path)
 *   - b.auth.openidFederation (entity statement parse + verify, metadata-policy operators)
 *   - b.auth.oid4vp        (DCQL validator + matcher)
 *   - b.auth.oid4vci       (issuer config validation, metadata, offer creation shape,
 *                           kid-only proof resolution via resolveKid, x5c leaf-cert
 *                           proof binding + validateX5c hook, expired-c_nonce typed refusal)
 *   - b.auth.ciba          (client.create validation + binding-message rules)
 *   - b.auth.sdJwtVc       (key_attestation header surfaces through present)
 *   - b.session.isAnonymous + b.session.create({ anonymous: true })
 *   - b.db.fileLifecycle   (decryptToTmp + flushNow + snapshot round-trip)
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var nodeCrypto     = require("node:crypto");
var asn1           = require("../../lib/asn1-der");

// ---- xmlC14n ----------------------------------------------------------

function testXmlC14nBasic() {
  var xml = "<a:foo xmlns:a=\"urn:x\" a:b=\"1\"><a:bar/></a:foo>";
  var c = b.xmlC14n.canonicalize(xml).toString("utf8");
  check("c14n: empty element expanded to open+close", c.indexOf("<a:bar></a:bar>") !== -1);
  check("c14n: namespace attribute preserved",        c.indexOf("xmlns:a=\"urn:x\"") !== -1);

  // Doctype refused
  var threw = false;
  try { b.xmlC14n.canonicalize("<!DOCTYPE foo><foo/>"); }
  catch (e) { threw = /doctype/i.test(e.message); }
  check("c14n: <!DOCTYPE> refused",                   threw);

  // parse() exposed for SAML's parsed-tree consumers
  var tree = b.xmlC14n.parse("<root><a/></root>");
  check("c14n: parse returns element node",           tree && tree.type === "element" && tree.name === "root");

  // XmlC14nError class exposed for instanceof checks
  threw = false;
  try { b.xmlC14n.parse(""); }
  catch (e) { threw = e instanceof b.xmlC14n.XmlC14nError; }
  check("c14n: errors are XmlC14nError instances",    threw);
}

function testXmlC14nSingleMatchInvariant() {
  // Two elements with the same ID — must refuse loudly.
  var xml = "<root><a ID=\"x\"/><b ID=\"x\"/></root>";
  var threw = false;
  try { b.xmlC14n.canonicalizeElementById(xml, "x"); }
  catch (e) { threw = /elements share/.test(e.message); }
  check("c14n: duplicate-ID refused (signature-wrapping defense)", threw);

  // Zero matches throws too.
  threw = false;
  try { b.xmlC14n.canonicalizeElementById("<root><a ID=\"y\"/></root>", "x"); }
  catch (e) { threw = /no element with/.test(e.message); }
  check("c14n: zero-match ID refused",                threw);

  // Unique match returns the canonicalized element.
  var bytes = b.xmlC14n.canonicalizeElementById("<root><a ID=\"x\"/></root>", "x");
  check("c14n: unique-ID match canonicalizes",        bytes.toString("utf8").indexOf("ID=\"x\"") !== -1);

  // Escape helpers (exported v0.9.1 to defend SAML AuthnRequest /
  // metadata builders against XML injection from operator-supplied
  // URLs / IDs).
  check("escapeAttrValue: ampersand",
        b.xmlC14n.escapeAttrValue("a&b") === "a&amp;b");
  check("escapeAttrValue: double quote",
        b.xmlC14n.escapeAttrValue("a\"b") === "a&quot;b");
  check("escapeAttrValue: less-than",
        b.xmlC14n.escapeAttrValue("a<b") === "a&lt;b");
  check("escapeAttrValue: CR + LF + HT folded to entities",
        b.xmlC14n.escapeAttrValue("a\r\n\tb") === "a&#xD;&#xA;&#x9;b");

  check("escapeText: ampersand",
        b.xmlC14n.escapeText("a&b") === "a&amp;b");
  check("escapeText: less-than",
        b.xmlC14n.escapeText("a<b") === "a&lt;b");
  check("escapeText: greater-than",
        b.xmlC14n.escapeText("a>b") === "a&gt;b");
  check("escapeText: CR folded to entity",
        b.xmlC14n.escapeText("a\rb") === "a&#xD;b");
}

// ---- SAML SP ----------------------------------------------------------

function testSamlSpAuthnRequest() {
  var sp = b.auth.saml.sp.create({
    entityId:                    "https://sp.example.com",
    assertionConsumerServiceUrl: "https://sp.example.com/saml/acs",
    idpEntityId:                 "https://idp.example.com",
    idpSsoUrl:                   "https://idp.example.com/sso",
    idpCertPem:                  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
  });
  var ar = sp.buildAuthnRequest();
  check("SAML: AuthnRequest has redirectUrl",         typeof ar.redirectUrl === "string" && ar.redirectUrl.indexOf("SAMLRequest=") !== -1);
  check("SAML: AuthnRequest has id",                  typeof ar.id === "string" && ar.id.length > 0);
  check("SAML: SP metadata contains entityId",        sp.metadata().indexOf("https://sp.example.com") !== -1);
}

function testSamlSpRefusesUnsigned() {
  var sp = b.auth.saml.sp.create({
    entityId:                    "https://sp.example.com",
    assertionConsumerServiceUrl: "https://sp.example.com/saml/acs",
    idpEntityId:                 "https://idp.example.com",
    idpSsoUrl:                   "https://idp.example.com/sso",
    idpCertPem:                  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
  });
  // Unsigned response — must refuse.
  var unsigned = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
    "<saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com</saml:Issuer>" +
    "<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>" +
    "</samlp:Response>";
  var threw = false;
  try { sp.verifyResponse(Buffer.from(unsigned, "utf8").toString("base64")); }
  catch (e) { threw = /unsigned/i.test(e.message); }
  check("SAML: unsigned Response refused",            threw);
}

// ---- OpenID Federation ------------------------------------------------

function testFederationParseAndPolicy() {
  // parseEntityStatement on a hand-rolled JWS-shaped string with the
  // right typ but a fake signature — the parser doesn't verify, so
  // it returns claims + header. verifyEntityStatement DOES verify
  // and throws.
  var header = { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" };
  var claims = { iss: "https://leaf.example", sub: "https://leaf.example",
                 iat: Math.floor(Date.now() / 1000),
                 exp: Math.floor(Date.now() / 1000) + 600,
                 jwks: { keys: [] }, authority_hints: ["https://parent.example"] };
  var jwt = Buffer.from(JSON.stringify(header)).toString("base64url") + "." +
            Buffer.from(JSON.stringify(claims)).toString("base64url") + "." +
            "fake-sig";
  var parsed = b.auth.openidFederation.parseEntityStatement(jwt);
  check("federation: parse returns header.typ",       parsed.header.typ === "entity-statement+jwt");
  check("federation: parse returns claims.iss",       parsed.claims.iss === "https://leaf.example");

  // metadata_policy operators — value/default/one_of/subset_of/superset_of.
  // Per OIDF §6.2 the policy comes from the SUPERIOR-SIGNED subordinate
  // statement about the entity (`chain[i].subordinate.metadata_policy`),
  // NOT the entity's own self-config — so each chain node carries the
  // policy under `.subordinate`.
  var meta = { application_type: "web", redirect_uris: ["https://leaf/cb"] };
  var chain = [
    { subordinate: { metadata_policy: { openid_relying_party: {
      application_type: { one_of: ["web", "native"] },
      grant_types: { default: ["authorization_code"] },
    } } } },
  ];
  var eff = b.auth.openidFederation.applyMetadataPolicy(meta, chain, "openid_relying_party");
  check("federation: one_of accepts allowed value",   eff.application_type === "web");
  check("federation: default fills absent claim",     Array.isArray(eff.grant_types) && eff.grant_types[0] === "authorization_code");

  // one_of refuses out-of-set
  var threw = false;
  try {
    b.auth.openidFederation.applyMetadataPolicy({ application_type: "bad" }, [
      { subordinate: { metadata_policy: { openid_relying_party: { application_type: { one_of: ["web", "native"] } } } } },
    ], "openid_relying_party");
  } catch (e) { threw = /not in/.test(e.message); }
  check("federation: one_of rejects out-of-set value", threw);

  // unknown operator refused
  threw = false;
  try {
    b.auth.openidFederation.applyMetadataPolicy({ x: 1 }, [
      { subordinate: { metadata_policy: { openid_relying_party: { x: { bogus: 1 } } } } },
    ], "openid_relying_party");
  } catch (e) { threw = /unknown operator/.test(e.message); }
  check("federation: unknown policy op refused",      threw);

  // M2: a leaf's OWN self-config metadata_policy is IGNORED — only the
  // superior-signed subordinate statement constrains the entity. A leaf
  // that self-declares a widening policy can't drop the anchor's rules.
  var ignored = b.auth.openidFederation.applyMetadataPolicy(
    { application_type: "web" },
    [{ claims: { metadata_policy: { openid_relying_party: {
        application_type: { value: "native" } } } } }],
    "openid_relying_party");
  check("federation M2: leaf self-config metadata_policy ignored",
        ignored.application_type === "web");
}

// ---- OpenID Federation trust-chain (multi-element, real signatures) ---

// Mint an EC P-256 entity: keypair + a single-key JWKS carrying `kid`.
function _fedEntity(kid) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = kp.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "ES256";
  return { kp: kp, kid: kid, jwks: { keys: [jwk] } };
}

// Sign an entity-statement+jwt (ES256) with the given signing entity.
function _signEntityStatement(signer, claims) {
  var header = { typ: "entity-statement+jwt", alg: "ES256", kid: signer.kid };
  var iat = Math.floor(Date.now() / 1000);
  var full = Object.assign({ iat: iat, exp: iat + 3600 }, claims);
  var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(full));
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
    { key: signer.kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + _b64url(sig);
}

async function testFederationTrustChainMultiElement() {
  var ANCHOR = "https://anchor.example";
  var INT    = "https://intermediate.example";
  var LEAF   = "https://leaf.example";

  var anchor = _fedEntity("anchor-1");
  var inter  = _fedEntity("inter-1");
  var leaf   = _fedEntity("leaf-1");

  // Self-configs (each self-signed over its own jwks).
  var anchorCfg = _signEntityStatement(anchor, { iss: ANCHOR, sub: ANCHOR, jwks: anchor.jwks });
  var interCfg  = _signEntityStatement(inter,  { iss: INT,  sub: INT,  jwks: inter.jwks, authority_hints: [ANCHOR] });
  // Leaf self-declares a wide scope ("openid profile email") + a single
  // redirect_uri; the superior policy will force the scope down and
  // confirm the redirect_uri is within the allowed subset.
  var leafMeta  = { openid_relying_party: { redirect_uris: ["https://leaf.example/cb"],
                                            scope: "openid profile email" } };
  var leafCfg   = _signEntityStatement(leaf, { iss: LEAF, sub: LEAF, jwks: leaf.jwks,
                                               authority_hints: [INT], metadata: leafMeta });

  // Superior-signed subordinate statements.
  //   anchor → about intermediate  (pins intermediate's real jwks)
  var subAboutInter = _signEntityStatement(anchor, { iss: ANCHOR, sub: INT, jwks: inter.jwks });
  //   intermediate → about leaf  (pins leaf's jwks + constrains the leaf
  //   via metadata_policy: subset_of on redirect_uris + value on scope)
  var leafPolicy = { openid_relying_party: {
    redirect_uris: { subset_of: ["https://leaf.example/cb", "https://leaf.example/cb2"] },
    scope:         { value: "openid" },
  } };
  var subAboutLeaf = _signEntityStatement(inter, { iss: INT, sub: LEAF, jwks: leaf.jwks,
                                                   metadata_policy: leafPolicy });

  function _fetcher(url) {
    if (url === ANCHOR + "/.well-known/openid-federation") return Promise.resolve(anchorCfg);
    if (url === INT + "/.well-known/openid-federation")    return Promise.resolve(interCfg);
    if (url === LEAF + "/.well-known/openid-federation")   return Promise.resolve(leafCfg);
    return Promise.reject(new Error("404 " + url));
  }
  function _fetchSubordinate(authority, sub) {
    if (authority === ANCHOR && sub === INT)  return Promise.resolve(subAboutInter);
    if (authority === INT    && sub === LEAF) return Promise.resolve(subAboutLeaf);
    return Promise.reject(new Error("no subordinate " + authority + "→" + sub));
  }

  var opts = {
    leafEntityId: LEAF,
    trustAnchors: { "https://anchor.example": anchor.jwks },
    fetcher: _fetcher,
    fetchSubordinate: _fetchSubordinate,
  };

  // Success path: chain builds leaf→anchor, roles assigned, attested
  // jwks flowed down from the pinned anchor.
  var chain = await b.auth.openidFederation.buildTrustChain(opts);
  check("federation chain: leaf-first, anchor-last",
        chain.length === 3 && chain[0].role === "leaf" &&
        chain[1].role === "intermediate" && chain[2].role === "trust_anchor");
  check("federation chain: leaf carries superior-signed subordinate statement",
        chain[0].subordinate && chain[0].subordinate.iss === INT && chain[0].subordinate.sub === LEAF);

  // M2: the SUPERIOR-SIGNED metadata_policy is enforced (anchor→leaf,
  // narrow-only). `value` forces scope down to "openid"; subset_of
  // confirms the leaf's lone redirect_uri is within the allowed set.
  var resolved = await b.auth.openidFederation.resolveLeaf(Object.assign({ kind: "openid_relying_party" }, opts));
  check("federation M2: superior-signed value narrows leaf scope",
        resolved.effectiveMetadata.scope === "openid");
  check("federation M2: leaf redirect_uri within superior subset_of accepted",
        Array.isArray(resolved.effectiveMetadata.redirect_uris) &&
        resolved.effectiveMetadata.redirect_uris.length === 1 &&
        resolved.effectiveMetadata.redirect_uris[0] === "https://leaf.example/cb");
}

async function testFederationSubsetOfRefusesWidening() {
  // M2 refutation: a leaf that declares a redirect_uri OUTSIDE the
  // superior-signed subset_of must be REFUSED — the leaf cannot widen
  // past the anchor/intermediate constraint by self-declaration.
  var threw = null;
  try {
    b.auth.openidFederation.applyMetadataPolicy(
      { redirect_uris: ["https://leaf.example/cb", "https://leaf.example/evil"] },
      [{ subordinate: { metadata_policy: { openid_relying_party: {
          redirect_uris: { subset_of: ["https://leaf.example/cb"] } } } } }],
      "openid_relying_party");
  } catch (e) { threw = e; }
  check("federation M2: leaf redirect_uri outside superior subset_of refused",
        threw && threw.code === "auth-openid-federation/policy-subset-of-failed");

  // And the leaf's OWN self-config can't relax that subset — self-config
  // policy is never read, so a self-declared wide subset is ignored while
  // the superior subset still binds.
  var eff = b.auth.openidFederation.applyMetadataPolicy(
    { scope: "openid" },
    [{ claims:      { metadata_policy: { openid_relying_party: { scope: { value: "admin" } } } },
      subordinate: { metadata_policy: { openid_relying_party: { scope: { value: "openid" } } } } }],
    "openid_relying_party");
  check("federation M2: superior value wins over leaf self-config",
        eff.scope === "openid");
}

async function testFederationSubordinateVerifiedAgainstAttestedKeys() {
  // M5: the intermediate's SELF-PUBLISHED config jwks differ from the
  // jwks the anchor ATTESTS for it. An attacker controlling the
  // intermediate endpoint serves attacker keys in the self-config AND
  // signs the leaf's subordinate statement with those attacker keys.
  // The verifier MUST verify the leaf statement against the
  // anchor-attested (genuine) intermediate keys, so the attacker-signed
  // statement is rejected.
  var ANCHOR = "https://anchor.example";
  var INT    = "https://intermediate.example";
  var LEAF   = "https://leaf.example";

  var anchor    = _fedEntity("anchor-1");
  var interReal = _fedEntity("inter-1");        // anchor attests THESE keys
  // The attacker self-publishes a DIFFERENT keypair under the SAME kid so
  // the kid lookup matches the attested key slot — the only thing that
  // can stop it is verifying against the attested key bytes (signature
  // mismatch), which is exactly what the fix does.
  var interEvil = _fedEntity("inter-1");        // same kid, different key
  var leaf      = _fedEntity("leaf-1");

  var anchorCfg = _signEntityStatement(anchor, { iss: ANCHOR, sub: ANCHOR, jwks: anchor.jwks });
  // Intermediate self-config: ATTACKER keys (TOCTOU — served at the
  // self-config fetch). Self-signed with the attacker key so the
  // self-statement integrity check passes.
  var interCfg  = _signEntityStatement(interEvil, { iss: INT, sub: INT, jwks: interEvil.jwks, authority_hints: [ANCHOR] });
  var leafCfg   = _signEntityStatement(leaf, { iss: LEAF, sub: LEAF, jwks: leaf.jwks, authority_hints: [INT] });

  // Anchor attests the REAL intermediate keys.
  var subAboutInter = _signEntityStatement(anchor, { iss: ANCHOR, sub: INT, jwks: interReal.jwks });
  // The leaf's subordinate statement is signed with the ATTACKER key
  // (interEvil) — it verifies against interEvil's self-published jwks
  // (the pre-fix path) but NOT against the anchor-attested interReal keys.
  var subAboutLeaf = _signEntityStatement(interEvil, { iss: INT, sub: LEAF, jwks: leaf.jwks });

  function _fetcher(url) {
    if (url === ANCHOR + "/.well-known/openid-federation") return Promise.resolve(anchorCfg);
    if (url === INT + "/.well-known/openid-federation")    return Promise.resolve(interCfg);
    if (url === LEAF + "/.well-known/openid-federation")   return Promise.resolve(leafCfg);
    return Promise.reject(new Error("404 " + url));
  }
  function _fetchSubordinate(authority, sub) {
    if (authority === ANCHOR && sub === INT)  return Promise.resolve(subAboutInter);
    if (authority === INT    && sub === LEAF) return Promise.resolve(subAboutLeaf);
    return Promise.reject(new Error("no subordinate " + authority + "→" + sub));
  }

  var threw = null;
  try {
    await b.auth.openidFederation.buildTrustChain({
      leafEntityId: LEAF,
      trustAnchors: { "https://anchor.example": anchor.jwks },
      fetcher: _fetcher,
      fetchSubordinate: _fetchSubordinate,
    });
  } catch (e) { threw = e; }
  // A cryptographic refusal proves the attested-key gate held: the
  // attacker-signed statement fails against the anchor-attested key bytes.
  check("federation M5: leaf statement signed by attacker self-jwks is refused",
        threw && (threw.code === "auth-openid-federation/bad-signature" ||
                  threw.code === "auth-openid-federation/no-matching-kid"));

  // Positive control: when the leaf statement is signed by the REAL
  // (anchor-attested) intermediate key, the chain builds.
  var subAboutLeafGood = _signEntityStatement(interReal, { iss: INT, sub: LEAF, jwks: leaf.jwks });
  function _fetchSubordinateGood(authority, sub) {
    if (authority === ANCHOR && sub === INT)  return Promise.resolve(subAboutInter);
    if (authority === INT    && sub === LEAF) return Promise.resolve(subAboutLeafGood);
    return Promise.reject(new Error("no subordinate " + authority + "→" + sub));
  }
  var built = await b.auth.openidFederation.buildTrustChain({
    leafEntityId: LEAF,
    trustAnchors: { "https://anchor.example": anchor.jwks },
    fetcher: _fetcher,
    fetchSubordinate: _fetchSubordinateGood,
  });
  check("federation M5: leaf statement signed by anchor-attested key builds",
        built.length === 3 && built[2].role === "trust_anchor");
  // The attested intermediate key bytes (interReal), not the self-
  // published attacker key bytes (interEvil), are reflected on the
  // intermediate node — same kid, so compare the EC x-coordinate.
  check("federation M5: intermediate node carries anchor-attested key bytes",
        built[1].claims.jwks &&
        built[1].claims.jwks.keys[0].x === interReal.jwks.keys[0].x &&
        built[1].claims.jwks.keys[0].x !== interEvil.jwks.keys[0].x);
}

// ---- OID4VP DCQL ------------------------------------------------------

function testDcqlMatch() {
  var dcql = {
    credentials: [
      { id: "id-card", format: "vc+sd-jwt", meta: { vct_values: ["https://example.com/vct/identity"] },
        claims: [{ path: ["given_name"] }] },
    ],
  };
  var pres = [{ id: "id-card", format: "vc+sd-jwt",
    claims: { vct: "https://example.com/vct/identity", given_name: "Alice" } }];
  var ok = b.auth.oid4vp.matchDcql(pres, dcql);
  check("DCQL: matched credential satisfies query",  ok.valid);
  check("DCQL: matched map populated",                !!ok.matched["id-card"]);

  // Wrong vct → refused
  var pres2 = [{ id: "id-card", format: "vc+sd-jwt",
    claims: { vct: "https://example.com/vct/passport", given_name: "Alice" } }];
  var bad = b.auth.oid4vp.matchDcql(pres2, dcql);
  check("DCQL: wrong vct produces match error",       !bad.valid && bad.errors.length > 0);

  // credential_sets with options
  var dcql2 = {
    credentials: [
      { id: "id-card", format: "vc+sd-jwt", claims: [{ path: ["x"] }] },
      { id: "passport", format: "vc+sd-jwt", claims: [{ path: ["y"] }] },
    ],
    credential_sets: [{ options: [["id-card"], ["passport"]], required: true }],
  };
  var oneOption = b.auth.oid4vp.matchDcql([
    { id: "id-card", format: "vc+sd-jwt", claims: { x: 1 } },
  ], dcql2);
  check("DCQL: credential_set options — one branch satisfied",  oneOption.valid);

  // Validation refuses bad shape
  var threw = false;
  try { b.auth.oid4vp.matchDcql([], { credentials: [] }); }
  catch (e) { threw = /non-empty array/.test(e.message); }
  check("DCQL: empty credentials array refused",      threw);

  // ---- null path-segment = array wildcard (OpenID4VP 1.0 §7.1.1) ----
  function _dcqlValid(path, claimsObj, values) {
    var q = { credentials: [{ id: "c", format: "vc+sd-jwt",
      claims: [values ? { path: path, values: values } : { path: path }] }] };
    return b.auth.oid4vp.matchDcql([{ id: "c", format: "vc+sd-jwt", claims: claimsObj }], q).valid;
  }
  var degrees = { degrees: [{ type: "BachelorDegree" }, { type: "MasterDegree" }] };
  check("DCQL null: any-element type matches",          _dcqlValid(["degrees", null, "type"], degrees));
  check("DCQL null: value-match on any element (hit)",  _dcqlValid(["degrees", null, "type"], degrees, ["MasterDegree"]));
  check("DCQL null: value-match on any element (miss)", !_dcqlValid(["degrees", null, "type"], degrees, ["PhD"]));
  // null on a non-array node → clean non-match, never throws (holder data, not config)
  var threwNull = false; var nullNonArray = true;
  try { nullNonArray = _dcqlValid(["degrees", null], { degrees: "not-an-array" }); }
  catch (_e) { threwNull = true; }
  check("DCQL null on non-array does not throw",        !threwNull);
  check("DCQL null on non-array is a non-match",        !nullNonArray);
  // null at the leaf → match iff the array holds any defined element
  check("DCQL null at leaf matches non-empty array",    _dcqlValid(["tags", null], { tags: ["a", "b"] }));
  check("DCQL null at leaf misses empty array",         !_dcqlValid(["tags", null], { tags: [] }));
  // nested null wildcards recurse to arbitrary depth
  check("DCQL nested null wildcards match",             _dcqlValid(["a", null, "b", null], { a: [{ b: [1, 2] }] }));

  // ---- numeric path segment = non-negative integer array index ----
  // OpenID4VP 1.0 §7.1.1: a numeric claim-path segment is an array
  // index and MUST be a non-negative integer. Config-time / entry-point
  // tier — _validateDcql throws AuthError on the bad shape (driven here
  // through the public matchDcql, which calls _validateDcql first).
  function _segThrows(segment) {
    var q = { credentials: [{ id: "c", format: "vc+sd-jwt",
      claims: [{ path: ["arr", segment] }] }] };
    var threw = null;
    try { b.auth.oid4vp.matchDcql([], q); } catch (e) { threw = e; }
    return threw;
  }
  function _segAccepted(segment) {
    var q = { credentials: [{ id: "c", format: "vc+sd-jwt",
      claims: [{ path: ["arr", segment] }] }] };
    var threw = null;
    try { b.auth.oid4vp.matchDcql([{ id: "c", format: "vc+sd-jwt", claims: { arr: [1, 2, 3] } }], q); }
    catch (e) { threw = e; }
    return threw === null;
  }
  var segNeg = _segThrows(-1);
  check("DCQL: negative index segment throws AuthError",
        !!segNeg && segNeg.code === "auth-oid4vp/bad-claim-segment");
  var segFrac = _segThrows(1.5);
  check("DCQL: fractional index segment throws AuthError",
        !!segFrac && segFrac.code === "auth-oid4vp/bad-claim-segment");
  var segNaN = _segThrows(NaN);
  check("DCQL: NaN index segment throws AuthError",
        !!segNaN && segNaN.code === "auth-oid4vp/bad-claim-segment");
  var segInf = _segThrows(Infinity);
  check("DCQL: Infinity index segment throws AuthError",
        !!segInf && segInf.code === "auth-oid4vp/bad-claim-segment");
  check("DCQL: zero index segment accepted",     _segAccepted(0));
  check("DCQL: positive index segment accepted", _segAccepted(2));
}

// ---- OID4VCI issuer config -------------------------------------------

function testOid4vciIssuerConfig() {
  // Bad config → throws
  var threw = false;
  try {
    b.auth.oid4vci.issuer.create({
      credentialIssuerUrl: "https://issuer.example",
      credentialEndpoint:  "https://issuer.example/credential",
      tokenEndpoint:       "https://issuer.example/token",
      sdJwtIssuer:         { issue: function () {} },
      supportedCredentials: {},
    });
  } catch (e) { threw = /supportedCredentials must be a non-empty map/.test(e.message); }
  check("OID4VCI: empty supportedCredentials refused", threw);

  threw = false;
  try {
    b.auth.oid4vci.issuer.create({
      credentialIssuerUrl: "https://issuer.example",
      credentialEndpoint:  "https://issuer.example/credential",
      tokenEndpoint:       "https://issuer.example/token",
      sdJwtIssuer:         { issue: function () {} },
      supportedCredentials: { "x": { format: "bogus", vct: "https://x" } },
    });
  } catch (e) { threw = /\.format must be one of/.test(e.message); }
  check("OID4VCI: unknown format refused",             threw);

  // Valid config exposes metadata()
  var iss = b.auth.oid4vci.issuer.create({
    credentialIssuerUrl: "https://issuer.example",
    credentialEndpoint:  "https://issuer.example/credential",
    tokenEndpoint:       "https://issuer.example/token",
    sdJwtIssuer:         { issue: async function () { return { token: "fake-sd-jwt" }; } },
    supportedCredentials: {
      "id-card-1": { format: "vc+sd-jwt", vct: "https://example.com/vct/identity",
                     claims: { given_name: {}, family_name: {} } },
    },
  });
  var meta = iss.metadata();
  check("OID4VCI: metadata has credential_issuer",     meta.credential_issuer === "https://issuer.example");
  check("OID4VCI: metadata has configurations",        !!meta.credential_configurations_supported["id-card-1"]);
}

// ---- OID4VCI kid-only proof via resolveKid ---------------------------

// Build a holder-signed openid4vci-proof+jwt with a `kid` header and no
// inline `jwk` (the EUDI-Wallet attested-key shape). ES256 over the
// holder EC key.
function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function _signKidProof(holderPrivKey, kid, aud, nonce) {
  var header  = { typ: "openid4vci-proof+jwt", alg: "ES256", kid: kid };
  var payload = { aud: aud, nonce: nonce, iat: Math.floor(Date.now() / 1000) };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"),
    { key: holderPrivKey, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + _b64url(sig);
}

async function _runIssuanceWithProof(issuerOpts, proofForNonce) {
  var captured = { holderKey: null };
  var iss = b.auth.oid4vci.issuer.create(Object.assign({
    credentialIssuerUrl: "https://issuer.example",
    credentialEndpoint:  "https://issuer.example/credential",
    tokenEndpoint:       "https://issuer.example/token",
    sdJwtIssuer:         { issue: async function (a) { captured.holderKey = a.holderKey; return { token: "fake-sd-jwt" }; } },
    supportedCredentials: {
      "id-card-1": { format: "vc+sd-jwt", vct: "https://example.com/vct/identity",
                     claims: { given_name: {} } },
    },
  }, issuerOpts));
  var offer  = await iss.createCredentialOffer({ subject: "user-7", credentialIds: ["id-card-1"] });
  var tokens = await iss.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });
  var rv = await iss.issueCredential({
    accessToken:          tokens.access_token,
    credentialIdentifier: "id-card-1",
    proof:                proofForNonce(tokens.c_nonce),
    claims:               { given_name: "Alice" },
  });
  return { rv: rv, captured: captured };
}

async function testOid4vciKidResolver() {
  var holderKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var holderPubJwk = holderKp.publicKey.export({ format: "jwk" });
  var aud = "https://issuer.example";

  // Config-time: a non-function resolveKid is refused at create().
  var threw = false;
  try {
    b.auth.oid4vci.issuer.create({
      credentialIssuerUrl: aud, credentialEndpoint: aud + "/credential", tokenEndpoint: aud + "/token",
      sdJwtIssuer: { issue: async function () { return { token: "x" }; } },
      supportedCredentials: { "id-card-1": { format: "vc+sd-jwt", vct: "https://x" } },
      resolveKid: "not-a-function",
    });
  } catch (e) { threw = /resolveKid.*must be a function/.test(e.message); }
  check("OID4VCI: non-function resolveKid refused at config time", threw);

  // kid-only proof with a matching resolveKid → verifies + binds cnf.
  var resolved = await _runIssuanceWithProof(
    { resolveKid: function (kid) { return kid === "holder-key-1" ? holderPubJwk : null; } },
    function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  check("OID4VCI: kid-only proof with resolveKid issues credential",
        resolved.rv && resolved.rv.credential === "fake-sd-jwt");
  check("OID4VCI: resolved holder key bound to cnf",
        resolved.captured.holderKey && resolved.captured.holderKey.x === holderPubJwk.x);

  // resolveKid may return a node:crypto KeyObject (exported to JWK for cnf).
  var resolvedKo = await _runIssuanceWithProof(
    { resolveKid: function () { return holderKp.publicKey; } },
    function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  check("OID4VCI: resolveKid KeyObject return verifies + exports cnf JWK",
        resolvedKo.captured.holderKey && resolvedKo.captured.holderKey.kty === "EC");

  // kid-only proof with NO resolveKid configured → clear refusal (back-compat).
  threw = false;
  try {
    await _runIssuanceWithProof(
      {},
      function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  } catch (e) { threw = /kid-resolver-not-supported/.test(e.code) || /resolveKid/.test(e.message); }
  check("OID4VCI: kid-only proof without resolveKid still refused", threw);

  // resolveKid returns a WRONG key (different holder) → signature fails cleanly.
  var otherKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  threw = false;
  try {
    await _runIssuanceWithProof(
      { resolveKid: function () { return otherKp.publicKey.export({ format: "jwk" }); } },
      function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  } catch (e) { threw = /proof-bad-signature|signature verification failed/.test(e.message); }
  check("OID4VCI: resolveKid wrong key fails signature verification", threw);

  // resolveKid returns garbage (no key) → clean refusal, no crash.
  threw = false;
  try {
    await _runIssuanceWithProof(
      { resolveKid: function () { return null; } },
      function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  } catch (e) { threw = /kid-unresolved/.test(e.code) || /returned no key/.test(e.message); }
  check("OID4VCI: resolveKid returning no key refused cleanly", threw);

  // resolveKid that THROWS → wrapped as a stable AuthError code, not an
  // unhandled rejection. The resolver is operator code, so its own
  // message is allowed through for operator debugging.
  threw = false;
  var isAuthErr = false;
  try {
    await _runIssuanceWithProof(
      { resolveKid: function () { throw new Error("resolver-backend-down"); } },
      function (nonce) { return _signKidProof(holderKp.privateKey, "holder-key-1", aud, nonce); });
  } catch (e) {
    threw = /kid-resolver-failed/.test(e.code) || /resolveKid threw/.test(e.message);
    isAuthErr = e instanceof b.frameworkError.AuthError;
  }
  check("OID4VCI: resolveKid throwing yields kid-resolver-failed", threw);
  check("OID4VCI: resolveKid failure is a typed AuthError", isAuthErr);
}

// ---- OID4VCI x5c proof (RFC 7515 §4.1.6 / OID4VCI §8.2.1.1) -----------

// Build a self-signed P-256 EC leaf certificate (the holder cert the
// wallet ships in `x5c`). The cert's private key signs the proof JWT;
// the leaf SPKI is the holder key the issuer binds cnf to. Returns the
// raw DER + the EC private key. Mirrors content-credentials.test.js's
// in-tree DER cert minting (no openssl dependency).
function _makeEcLeafCert(cn) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });        // full EC SubjectPublicKeyInfo (alg id + curve + point)
  var name = asn1.writeSequence([asn1.writeSet([asn1.writeSequence([
    asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);             // CN=<cn>
  var sigAlgId = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]); // ecdsa-with-SHA256
  var version  = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var serial   = asn1.writeInteger(Buffer.from([0x2c]));
  var now = Date.now();
  function _utc(d) { var s = d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"; return asn1.writeNode(0x17, Buffer.from(s, "ascii")); }
  var validity = asn1.writeSequence([_utc(new Date(now - 86400000)), _utc(new Date(now + 86400000 * 3650))]);
  var tbs = asn1.writeSequence([version, serial, sigAlgId, name, validity, name, spki]);
  var tbsSig = nodeCrypto.sign("sha256", tbs, kp.privateKey);             // ECDSA sig is DER-encoded (X509 default)
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(tbsSig, 0)]);
  return { certDer: certDer, privateKey: kp.privateKey };
}

// Build a holder-signed openid4vci-proof+jwt carrying an `x5c` chain
// (standard base64, leaf first) and no inline jwk/kid. ES256 over the
// leaf cert's EC private key.
function _signX5cProof(leafPrivKey, x5cArray, aud, nonce) {
  var header  = { typ: "openid4vci-proof+jwt", alg: "ES256", x5c: x5cArray };
  var payload = { aud: aud, nonce: nonce, iat: Math.floor(Date.now() / 1000) };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"),
    { key: leafPrivKey, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + _b64url(sig);
}

async function testOid4vciX5cProof() {
  var aud  = "https://issuer.example";
  var leaf = _makeEcLeafCert("Holder Wallet Leaf");
  var leafB64 = leaf.certDer.toString("base64");                          // standard base64 (RFC 7515 §4.1.6)
  var leafPubJwk = nodeCrypto.createPublicKey(leaf.privateKey).export({ format: "jwk" });

  // SUCCESS PATH — x5c-only proof, no operator validateX5c hook. The
  // leaf SPKI binds at the same self-asserted trust as inline jwk; the
  // proof signature proves the holder controls the key. End-to-end:
  // offer → token → credential issued, cnf bound to the leaf SPKI.
  var ok = await _runIssuanceWithProof(
    {},
    function (nonce) { return _signX5cProof(leaf.privateKey, [leafB64], aud, nonce); });
  check("OID4VCI: x5c-only proof issues credential (success path)",
        ok.rv && ok.rv.credential === "fake-sd-jwt");
  check("OID4VCI: x5c leaf SPKI bound to cnf",
        ok.captured.holderKey && ok.captured.holderKey.kty === "EC" &&
        ok.captured.holderKey.x === leafPubJwk.x);

  // SUCCESS PATH — operator validateX5c hook receives the leaf DER + the
  // header and may pass. Confirms the chain buffers + header reach the hook.
  var seen = { chainLen: 0, headerAlg: null, leafIsBuffer: false };
  var okHook = await _runIssuanceWithProof(
    { validateX5c: function (chainDerBuffers, header) {
        seen.chainLen     = chainDerBuffers.length;
        seen.headerAlg    = header.alg;
        seen.leafIsBuffer = Buffer.isBuffer(chainDerBuffers[0]);
      } },
    function (nonce) { return _signX5cProof(leaf.privateKey, [leafB64], aud, nonce); });
  check("OID4VCI: validateX5c hook passing issues credential",
        okHook.rv && okHook.rv.credential === "fake-sd-jwt");
  check("OID4VCI: validateX5c hook receives leaf DER buffer + header.alg",
        seen.chainLen === 1 && seen.headerAlg === "ES256" && seen.leafIsBuffer === true);

  // REFUSAL — operator validateX5c throws → typed AuthError refusal, not
  // an unhandled rejection.
  var threw = false, isAuthErr = false;
  try {
    await _runIssuanceWithProof(
      { validateX5c: function () { throw new Error("untrusted-attestation-ca"); } },
      function (nonce) { return _signX5cProof(leaf.privateKey, [leafB64], aud, nonce); });
  } catch (e) {
    threw = /x5c-rejected/.test(e.code) && /untrusted-attestation-ca/.test(e.message);
    isAuthErr = e instanceof b.frameworkError.AuthError;
  }
  check("OID4VCI: validateX5c throwing yields typed x5c-rejected", threw);
  check("OID4VCI: validateX5c refusal is a typed AuthError", isAuthErr);

  // REFUSAL — wrong leaf key (proof signed by a DIFFERENT EC key than the
  // cert carries) → signature verification fails cleanly.
  var otherLeaf = _makeEcLeafCert("Imposter Leaf");
  threw = false;
  try {
    await _runIssuanceWithProof(
      {},
      function (nonce) { return _signX5cProof(otherLeaf.privateKey, [leafB64], aud, nonce); });
  } catch (e) { threw = /proof-bad-signature/.test(e.code) || /signature verification failed/.test(e.message); }
  check("OID4VCI: x5c proof signed by non-leaf key fails signature", threw);

  // MALFORMED x5c — each shape refused with a typed code (not a crash).
  function _refusedX5c(x5cVal, label) {
    var t = false, typed = false;
    return _runIssuanceWithProof(
      {},
      function (nonce) {
        // Build a proof whose header carries the malformed x5c; the proof
        // never reaches signature verification — it's refused at parse.
        var header  = { typ: "openid4vci-proof+jwt", alg: "ES256", x5c: x5cVal };
        var payload = { aud: aud, nonce: nonce, iat: Math.floor(Date.now() / 1000) };
        var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
        var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
          { key: leaf.privateKey, dsaEncoding: "ieee-p1363" });
        return input + "." + _b64url(sig);
      }
    ).then(
      function () { check("OID4VCI: malformed x5c (" + label + ") refused", false); },
      function (e) {
        t = /bad-x5c/.test(e.code);
        typed = e instanceof b.frameworkError.AuthError;
        check("OID4VCI: malformed x5c (" + label + ") refused typed", t && typed);
      });
  }
  await _refusedX5c([], "empty array");
  await _refusedX5c([""], "empty string entry");
  await _refusedX5c(["@@@not-base64@@@"], "non-base64 entry");
  // base64url chars (- / _) are invalid for x5c (standard base64 only).
  // Inject them unconditionally: leafB64's '+' / '/' population varies per
  // generated cert, so replacing only the first such char is a no-op on the
  // ~0.4% of certs that carry neither — which would leave a still-valid cert
  // that is correctly accepted, making this refusal assertion flake. Prepend
  // the base64url-only chars so the malformed entry is guaranteed every run.
  await _refusedX5c(["-_" + leafB64.slice(2)], "base64url-charset entry");
  // valid base64 but not a parseable DER certificate.
  await _refusedX5c([Buffer.from("not a certificate").toString("base64")], "non-DER-cert entry");

  // non-array x5c — header.x5c truthy-but-not-array. _parseX5cChain
  // refuses. (header.jwk/kid absent so the x5c branch is taken.)
  await _refusedX5c({ "0": leafB64 }, "object not array");
}

// ---- OID4VCI expired c_nonce (typed refusal, not TypeError) ----------

async function testOid4vciCNonceExpired() {
  var aud = "https://issuer.example";
  var holderKp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var holderJwk = holderKp.publicKey.export({ format: "jwk" });

  // A cNonceStore whose get() always returns undefined simulates the
  // c_nonce TTL (5m) elapsing before /credential is called while the
  // access token (15m) is still live — cNonceStore.get returns undefined
  // on miss/expiry. set/del are accepted no-ops so issuance can proceed
  // up to the proof check.
  var expiredCNonceStore = {
    set: async function () {},
    get: async function () { return undefined; },
    del: async function () {},
  };

  var iss = b.auth.oid4vci.issuer.create({
    credentialIssuerUrl: aud,
    credentialEndpoint:  aud + "/credential",
    tokenEndpoint:       aud + "/token",
    sdJwtIssuer:         { issue: async function () { return { token: "fake-sd-jwt" }; } },
    supportedCredentials: {
      "id-card-1": { format: "vc+sd-jwt", vct: "https://example.com/vct/identity",
                     claims: { given_name: {} } },
    },
    cNonceStore: expiredCNonceStore,
  });
  var offer  = await iss.createCredentialOffer({ subject: "user-9", credentialIds: ["id-card-1"] });
  var tokens = await iss.exchangePreAuthorizedCode({ preAuthCode: offer.preAuthCode });

  // The proof carries SOME nonce (the wallet's last-seen c_nonce), but
  // the store has expired the expected value → undefined. Pre-fix this
  // crashed with a raw TypeError from timingSafeEqual(nonce, undefined);
  // now it must refuse with the typed c-nonce-expired code. Use an
  // inline-jwk proof so the key path succeeds and the ONLY failure is
  // the expired c_nonce.
  function _signJwkProof(priv, jwk, a, nonce) {
    var header  = { typ: "openid4vci-proof+jwt", alg: "ES256", jwk: jwk };
    var payload = { aud: a, nonce: nonce, iat: Math.floor(Date.now() / 1000) };
    var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
    var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: priv, dsaEncoding: "ieee-p1363" });
    return input + "." + _b64url(sig);
  }
  var proof = _signJwkProof(holderKp.privateKey, holderJwk, aud, "stale-nonce");

  var threw = false, isAuthErr = false, isTypeError = false;
  try {
    await iss.issueCredential({
      accessToken:          tokens.access_token,
      credentialIdentifier: "id-card-1",
      proof:                proof,
      claims:               { given_name: "Alice" },
    });
  } catch (e) {
    threw = /c-nonce-expired/.test(e.code || "");
    isAuthErr = e instanceof b.frameworkError.AuthError;
    isTypeError = e instanceof TypeError;
  }
  check("OID4VCI: expired c_nonce (store miss) refused with c-nonce-expired", threw);
  check("OID4VCI: expired c_nonce refusal is a typed AuthError", isAuthErr);
  check("OID4VCI: expired c_nonce does NOT throw a raw TypeError", !isTypeError);
}

// ---- CIBA client config ----------------------------------------------

function testCibaConfig() {
  var threw = false;
  try {
    b.auth.ciba.client.create({
      issuer:       "https://idp.example",
      clientId:     "rp-1",
      clientAuth:   "secret",
      // missing clientSecret
      deliveryMode: "poll",
    });
  } catch (e) { threw = /clientSecret required/.test(e.message); }
  check("CIBA: clientAuth='secret' without clientSecret refused", threw);

  threw = false;
  try {
    b.auth.ciba.client.create({
      issuer: "https://idp.example", clientId: "rp-1",
      clientAuth: "secret", clientSecret: "s",
      deliveryMode: "ping", // ping needs notification token
    });
  } catch (e) { threw = /clientNotificationToken required/.test(e.message); }
  check("CIBA: ping mode without clientNotificationToken refused", threw);

  // Valid client builds.
  var c = b.auth.ciba.client.create({
    issuer: "https://idp.example", clientId: "rp-1",
    clientAuth: "secret", clientSecret: "s",
    deliveryMode: "poll",
  });
  check("CIBA: client has startAuthentication",        typeof c.startAuthentication === "function");
  check("CIBA: client has pollToken",                  typeof c.pollToken === "function");
  check("CIBA: client has parseNotification",          typeof c.parseNotification === "function");
}

// ---- SD-JWT key_attestation surface ----------------------------------

async function testSdJwtKeyAttestationStorage() {
  var holderKeyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var holder = b.auth.sdJwtVc.holder.create({
    storage:   b.auth.sdJwtVc.holder.memoryStorage(),
    holderKey: holderKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }),
    algorithm: "ES256",
    auditOn:   false,
  });
  var threw = false;
  try {
    await holder.store({
      id: "c1", sdJwt: "fake.jwt.body", keyAttestation: "not-a-jwt",
    });
  } catch (e) { threw = /bad-key-attestation|3 dot-separated/.test(e.message); }
  check("SD-JWT VC: malformed keyAttestation refused", threw);

  // Well-formed (3-segment) attestation token accepted at store time;
  // verifier-side validation happens later via keyAttestationVerifier.
  await holder.store({
    id: "c2", sdJwt: "fake.jwt.body",
    keyAttestation: "header.payload.sig",
  });
  var rec = await holder.get("c2");
  check("SD-JWT VC: well-formed keyAttestation persisted",
    rec && rec.keyAttestation === "header.payload.sig");
}

// ---- Anonymous sessions + isAnonymous --------------------------------

async function testAnonymousSessions() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-ses-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ anonymous: true });
    check("anon session: token is sealed",              s.token.indexOf("vault:") === 0);
    var info = await b.session.verify(s.token);
    check("anon session: verifies",                     info && typeof info.userId === "string");
    check("anon session: userId has anon: prefix",      b.session.isAnonymous(info.userId));
    check("anon session: real id NOT anonymous",        !b.session.isAnonymous("user-42"));

    // anonymous + userId rejected (mutex)
    var threw = false;
    try { await b.session.create({ anonymous: true, userId: "u-1" }); }
    catch (e) { threw = /not both/.test(e.message); }
    check("anon session: anonymous + userId refused",   threw);

    // destroyAllForUser refuses anon ids
    threw = false;
    try { await b.session.destroyAllForUser(info.userId); }
    catch (e) { threw = /per-session/.test(e.message); }
    check("anon session: destroyAllForUser(anon) refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- b.db.fileLifecycle ----------------------------------------------

async function testFileLifecycle() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fl-"));
  try {
    // Need a vault — set up via the standard test-db helper which
    // initializes vault for us, but we don't actually use the DB.
    await setupTestDb(tmpDir);
    var dataDir = path.join(tmpDir, "fl-data");
    fs.mkdirSync(dataDir);

    var lc = b.db.fileLifecycle({
      dataDir:           dataDir,
      tmpDir:            path.join(tmpDir, "shm"),
      vault:             b.vault,
      label:             "test-fl",
      flushIntervalMs:   60000,
    });
    var dbPath = lc.decryptToTmp();
    check("fileLifecycle: decryptToTmp returns path",   typeof dbPath === "string" && dbPath.indexOf("test-fl") !== -1);

    // Operator opens their own SQLite handle.
    var sqlite = require("node:sqlite");
    var db = new sqlite.DatabaseSync(dbPath);
    db.prepare("CREATE TABLE notes (id INTEGER, txt TEXT)").run();
    db.prepare("INSERT INTO notes VALUES (1, 'hello world')").run();

    // flushNow re-encrypts to encPath.
    lc.flushNow(db);
    check("fileLifecycle: encPath materialized",        fs.existsSync(lc.encPath));

    // snapshot returns Buffer.
    var snap = lc.snapshot(db);
    check("fileLifecycle: snapshot returns Buffer",     Buffer.isBuffer(snap) && snap.length > 0);

    // Close + flush + cleanup.
    lc.flushAndCleanup(db, { removePlaintext: true });
    check("fileLifecycle: plaintext removed after cleanup", !fs.existsSync(dbPath));

    // Round-trip: open a fresh lifecycle against the same encPath +
    // key, verify the data survives.
    var lc2 = b.db.fileLifecycle({
      dataDir:  dataDir,
      tmpDir:   path.join(tmpDir, "shm"),
      vault:    b.vault,
      label:    "test-fl",
    });
    var dbPath2 = lc2.decryptToTmp();
    var db2 = new sqlite.DatabaseSync(dbPath2);
    var row = db2.prepare("SELECT id, txt FROM notes WHERE id = ?").get(1);
    check("fileLifecycle: round-trip preserves data",   row && row.txt === "hello world");
    db2.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testXmlC14nBasic();
  testXmlC14nSingleMatchInvariant();
  testSamlSpAuthnRequest();
  testSamlSpRefusesUnsigned();
  testFederationParseAndPolicy();
  await testFederationTrustChainMultiElement();
  await testFederationSubsetOfRefusesWidening();
  await testFederationSubordinateVerifiedAgainstAttestedKeys();
  testDcqlMatch();
  testOid4vciIssuerConfig();
  await testOid4vciKidResolver();
  await testOid4vciX5cProof();
  await testOid4vciCNonceExpired();
  testCibaConfig();
  await testSdJwtKeyAttestationStorage();
  await testAnonymousSessions();
  await testFileLifecycle();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
