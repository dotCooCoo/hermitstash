"use strict";
/**
 * b.contentCredentials — SB-942 / AB-853 / C2PA manifest builder.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("build is fn",    typeof b.contentCredentials.build === "function");
  check("sign is fn",     typeof b.contentCredentials.sign === "function");
  check("verify is fn",   typeof b.contentCredentials.verify === "function");
  check("required is fn", typeof b.contentCredentials.required === "function");
  check("ContentCredentialsError", typeof b.contentCredentials.ContentCredentialsError === "function");
  check("REQUIRED_FIELDS",         Array.isArray(b.contentCredentials.REQUIRED_FIELDS) &&
                                    b.contentCredentials.REQUIRED_FIELDS.length === 4);

  var manifest = b.contentCredentials.build({
    provider:        "Acme AI Inc.",
    system:          "acme-image-v3",
    systemVersion:   "3.2.1",
    contentId:       "img-2026-05-08-abc123",
    contentType:     "image/png",
  });
  check("build returns frozen manifest", Object.isFrozen(manifest));
  check("manifest aiGenerated true",     manifest.aiGenerated === true);
  check("manifest cites SB-942",         manifest.citations.indexOf("california-sb-942") !== -1);

  var kp = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var env = b.contentCredentials.sign(manifest, { privateKeyPem: kp.privateKey, audit: false });
  check("sign returns envelope", typeof env.signature === "string" && env.signature.length > 0);

  var v = b.contentCredentials.verify(env, kp.publicKey, { audit: false });
  check("verify valid", v.valid === true);

  // Tamper
  var tampered = { manifest: Object.assign({}, env.manifest, { aiGenerated: false }), signature: env.signature };
  var v2 = b.contentCredentials.verify(tampered, kp.publicKey, { audit: false });
  check("verify rejects tampered", v2.valid === false);

  // required() audit
  var missing = b.contentCredentials.required({ provider: "x" });
  check("required missing fields", missing.indexOf("missing-system") !== -1 &&
        missing.indexOf("missing-systemVersion") !== -1 &&
        missing.indexOf("missing-contentId") !== -1);

  // Bad shapes
  var threw = null;
  try { b.contentCredentials.build({}); } catch (e) { threw = e; }
  check("refuses missing required",  threw && threw.code === "MISSING_PROVIDER");

  threw = null;
  try { b.contentCredentials.build({
    provider: "x", system: "x", systemVersion: "not.semver",
    contentId: "y",
  }); } catch (e) { threw = e; }
  check("refuses bad systemVersion", threw && threw.code === "BAD_VERSION");

  threw = null;
  try { b.contentCredentials.build({
    provider: "x", system: "x", systemVersion: "1.0.0",
    contentId: "y", contentType: "not-a-mime",
  }); } catch (e) { threw = e; }
  check("refuses bad contentType",   threw && threw.code === "BAD_CONTENT_TYPE");

  // ---- v0.8.77: COSE_Sign1 interop ----
  check("COSE_ALGS table exported",            typeof b.contentCredentials.COSE_ALGS === "object");
  check("COSE_ALGS includes ml-dsa-87",        b.contentCredentials.COSE_ALGS["ml-dsa-87"] === -50);
  check("COSE_ALGS includes ed25519",          b.contentCredentials.COSE_ALGS["ed25519"] === -8);

  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest2 = b.contentCredentials.build({
    provider:      "Acme",
    system:        "acme-v3",
    systemVersion: "3.2.1",
    contentId:     "img-002",
  });
  var cose = b.contentCredentials.signCose(manifest2, {
    privateKeyPem: pair.privateKey,
    alg:           "ml-dsa-87",
  });
  check("signCose: returns coseSign1 Buffer",  Buffer.isBuffer(cose.coseSign1));
  check("signCose: alg echoed",                cose.alg === "ml-dsa-87");
  check("signCose: CBOR tag 18 (COSE_Sign1)",  cose.coseSign1[0] === 0xD2);
  check("signCose: array of 4 elements",       cose.coseSign1[1] === 0x84);

  threw = null;
  try { b.contentCredentials.signCose(manifest2, { privateKeyPem: pair.privateKey, alg: "unknown" }); }
  catch (e) { threw = e; }
  check("signCose: unknown alg refused",       threw && threw.code === "BAD_ALG");
}

module.exports = { run: run };
