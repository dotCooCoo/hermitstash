"use strict";
/**
 * b.network.tls.buildOptions — TLS request-options builder. Verifies
 * the framework PQC group preference + TLSv1.3 floor land in the
 * returned object, the `ca` normalizer accepts string/Buffer/array
 * inputs, and bad-shape opts throw NetworkTlsError with the
 * documented `network-tls/bad-tls-options` code.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("network.tls.buildOptions is a function",
        typeof b.network.tls.buildOptions === "function");
  check("network.tls.NetworkTlsError is a class",
        typeof b.network.tls.NetworkTlsError === "function");
}

function testDefaults() {
  var opts = b.network.tls.buildOptions();
  check("default minVersion is TLSv1.3",
        opts.minVersion === "TLSv1.3");
  check("default ecdhCurve is the framework PQC list",
        typeof opts.ecdhCurve === "string" &&
        opts.ecdhCurve.indexOf("X25519MLKEM768") === 0);
  check("default groups mirrors ecdhCurve",
        opts.groups === opts.ecdhCurve);
  check("no cert/key/ca/servername when omitted",
        opts.cert === undefined && opts.key === undefined &&
        opts.ca === undefined && opts.servername === undefined);
}

function testNarrowGroups() {
  var opts = b.network.tls.buildOptions({ groups: ["X25519MLKEM768"] });
  check("narrowing to subset of preferred is accepted",
        opts.groups === "X25519MLKEM768");

  var opts2 = b.network.tls.buildOptions({ ecdhCurve: "X25519MLKEM768:X25519" });
  check("string ecdhCurve subset is accepted",
        opts2.ecdhCurve === "X25519MLKEM768:X25519");

  var threw = false;
  try { b.network.tls.buildOptions({ groups: ["NIST_P256"] }); }
  catch (e) {
    threw = e.code === "network-tls/bad-tls-options";
  }
  check("widening to non-preferred group throws bad-tls-options", threw);
}

function testMinVersionLock() {
  var threw = false;
  try { b.network.tls.buildOptions({ minVersion: "TLSv1.2" }); }
  catch (e) {
    threw = e.code === "network-tls/bad-tls-options";
  }
  check("TLSv1.2 minVersion refuses with bad-tls-options", threw);
}

function testCaNormalize() {
  var pem1 = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----";
  var pem2 = "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----";

  var fromString = b.network.tls.buildOptions({ ca: pem1 });
  check("ca string passes through",
        fromString.ca === pem1);

  var fromBuffer = b.network.tls.buildOptions({ ca: Buffer.from(pem1, "utf8") });
  check("ca Buffer normalized to string",
        fromBuffer.ca === pem1);

  var fromArray = b.network.tls.buildOptions({ ca: [pem1, Buffer.from(pem2, "utf8")] });
  check("ca array<string|Buffer> joined with newline",
        fromArray.ca === pem1 + "\n" + pem2);

  var threw = false;
  try { b.network.tls.buildOptions({ ca: [123] }); }
  catch (e) { threw = e.code === "network-tls/bad-tls-options"; }
  check("ca array entry of wrong type refuses", threw);
}

function testSni() {
  var opts = b.network.tls.buildOptions({ sni: "internal.example.com" });
  check("sni maps to servername",
        opts.servername === "internal.example.com");

  var threw = false;
  try { b.network.tls.buildOptions({ sni: "" }); }
  catch (e) { threw = e.code === "network-tls/bad-tls-options"; }
  check("empty sni refuses", threw);
}

function testCertKeyPassThrough() {
  var c = "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----";
  var k = "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----";
  var opts = b.network.tls.buildOptions({ cert: c, key: k });
  check("cert passes through", opts.cert === c);
  check("key passes through",  opts.key  === k);

  var threw = false;
  try { b.network.tls.buildOptions({ cert: 123 }); }
  catch (e) { threw = e.code === "network-tls/bad-tls-options"; }
  check("non-string non-Buffer cert refuses", threw);
}

function testUnknownKey() {
  var threw = false;
  try { b.network.tls.buildOptions({ secureProtocol: "TLSv1_3_method" }); }
  catch (e) { threw = /unknown option/.test(e.message); }
  check("unknown opts key refuses via validateOpts", threw);
}

async function run() {
  testSurface();
  testDefaults();
  testNarrowGroups();
  testMinVersionLock();
  testCaNormalize();
  testSni();
  testCertKeyPassThrough();
  testUnknownKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
