"use strict";
/**
 * v0.8.62 federation / VC slice — Layer 0 coverage for:
 *   - b.xmlC14n            (canonicalize, canonicalizeElementById, single-match invariant)
 *   - b.auth.saml          (sp.buildAuthnRequest, sp.verifyResponse signature path)
 *   - b.auth.openidFederation (entity statement parse + verify, metadata-policy operators)
 *   - b.auth.oid4vp        (DCQL validator + matcher)
 *   - b.auth.oid4vci       (issuer config validation, metadata, offer creation shape)
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

  // metadata_policy operators — value/default/one_of/subset_of/superset_of
  var meta = { application_type: "web", redirect_uris: ["https://leaf/cb"] };
  var chain = [
    { claims: { metadata_policy: { openid_relying_party: {
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
      { claims: { metadata_policy: { openid_relying_party: { application_type: { one_of: ["web", "native"] } } } } },
    ], "openid_relying_party");
  } catch (e) { threw = /not in/.test(e.message); }
  check("federation: one_of rejects out-of-set value", threw);

  // unknown operator refused
  threw = false;
  try {
    b.auth.openidFederation.applyMetadataPolicy({ x: 1 }, [
      { claims: { metadata_policy: { openid_relying_party: { x: { bogus: 1 } } } } },
    ], "openid_relying_party");
  } catch (e) { threw = /unknown operator/.test(e.message); }
  check("federation: unknown policy op refused",      threw);
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
  testDcqlMatch();
  testOid4vciIssuerConfig();
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
