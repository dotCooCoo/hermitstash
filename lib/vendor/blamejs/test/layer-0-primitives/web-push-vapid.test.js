"use strict";
/**
 * b.webPush — RFC 8292 VAPID JWT signer + RFC 8030 push request shape.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testGenerateKeypairShape() {
  var kp = b.webPush.generateVapidKeypair();
  check("keypair has PEM publicKey",         typeof kp.publicKeyPem === "string" && kp.publicKeyPem.indexOf("BEGIN PUBLIC KEY") !== -1);
  check("keypair has PEM privateKey",        typeof kp.privateKeyPem === "string" && kp.privateKeyPem.indexOf("BEGIN PRIVATE KEY") !== -1);
  check("keypair has b64url publicKey >50ch", typeof kp.publicKeyB64Url === "string" && kp.publicKeyB64Url.length > 50);
  check("b64url has no padding",             kp.publicKeyB64Url.indexOf("=") === -1);
}

function testBuildAuthHeaderShape() {
  var kp = b.webPush.generateVapidKeypair();
  var hdr = b.webPush.buildVapidAuthHeader({
    subscription:    { endpoint: "https://fcm.googleapis.com/wp/abc" },
    contact:         "mailto:ops@example.com",
    privateKeyPem:   kp.privateKeyPem,
    publicKeyB64Url: kp.publicKeyB64Url,
  });
  check("header starts with 'vapid t='",        hdr.indexOf("vapid t=") === 0);
  check("header has ', k=' separator",          hdr.indexOf(", k=") !== -1);
  // JWT structure: three b64url parts joined by `.`
  var token = hdr.replace(/^vapid t=/, "").split(", ")[0];
  check("JWT has 3 dot-separated parts",        token.split(".").length === 3);
  var headerJson  = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
  var payloadJson = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  check("JWT alg=ES256",                        headerJson.alg === "ES256");
  check("JWT aud is origin of endpoint",        payloadJson.aud === "https://fcm.googleapis.com");
  check("JWT sub matches contact",              payloadJson.sub === "mailto:ops@example.com");
  check("JWT exp is a number",                  typeof payloadJson.exp === "number" && payloadJson.exp > 0);
}

function testCustomTtl() {
  var kp = b.webPush.generateVapidKeypair();
  var hdr = b.webPush.buildVapidAuthHeader({
    subscription:    { endpoint: "https://push.example.com/abc" },
    contact:         "mailto:x@y",
    privateKeyPem:   kp.privateKeyPem,
    publicKeyB64Url: kp.publicKeyB64Url,
    ttlSec:          60,
  });
  var token = hdr.replace(/^vapid t=/, "").split(", ")[0];
  var payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  var now = Math.floor(Date.now() / 1000);
  check("custom ttl: exp ≤ now + 65", payload.exp <= now + 65);
  check("custom ttl: exp ≥ now + 55", payload.exp >= now + 55);
}

function testRefusesBadContact() {
  var kp = b.webPush.generateVapidKeypair();
  var threw = null;
  try {
    b.webPush.buildVapidAuthHeader({
      subscription:    { endpoint: "https://x/y" },
      contact:         "no-scheme",
      privateKeyPem:   kp.privateKeyPem,
      publicKeyB64Url: kp.publicKeyB64Url,
    });
  } catch (e) { threw = e.code; }
  check("non-mailto/https contact refused", threw === "web-push/bad-contact");
}

function testRefusesBadEndpoint() {
  var kp = b.webPush.generateVapidKeypair();
  var threw = null;
  try {
    b.webPush.buildVapidAuthHeader({
      subscription:    { endpoint: "not a url" },
      contact:         "mailto:x@y",
      privateKeyPem:   kp.privateKeyPem,
      publicKeyB64Url: kp.publicKeyB64Url,
    });
  } catch (e) { threw = e.code; }
  check("non-URL endpoint refused", threw === "web-push/bad-endpoint");
}

function testRefusesNonEcdsaKey() {
  var nodeCrypto = require("node:crypto");
  var rsaKp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength:      2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var threw = null;
  try {
    b.webPush.buildVapidAuthHeader({
      subscription:    { endpoint: "https://x/y" },
      contact:         "mailto:x@y",
      privateKeyPem:   rsaKp.privateKey,
      publicKeyB64Url: "AAA",
    });
  } catch (e) { threw = e.code; }
  check("RSA key refused (VAPID requires ECDSA-P256)", threw === "web-push/bad-key");
}

function testEncryptShape() {
  // Generate a real recipient ECDH-P256 keypair to seed a subscription.
  var nodeCrypto = require("node:crypto");
  var ecdh = nodeCrypto.createECDH("prime256v1");
  ecdh.generateKeys();
  var p256dh = ecdh.getPublicKey().toString("base64url");                                          // 65-byte uncompressed
  var auth   = nodeCrypto.randomBytes(16).toString("base64url");                                   // allow:raw-byte-literal — RFC 8291 §3.2 16-byte auth_secret
  var e = b.webPush.encrypt({
    subscription: { endpoint: "https://push.example/x", keys: { p256dh: p256dh, auth: auth } },
    payload: "hello",
  });
  check("encrypt returns body bytes",
    Buffer.isBuffer(e.body) && e.body.length > 0);
  check("encrypt body starts with 16-byte salt + 4-byte rs + 1-byte idlen + 65-byte ephPub",
    e.body.length > 86);                                                                            // allow:raw-byte-literal — RFC 8188 header floor
  check("encrypt sets Content-Encoding: aes128gcm",
    e.headers && e.headers["Content-Encoding"] === "aes128gcm");
  check("encrypt sets TTL header",
    typeof e.headers.TTL === "string" && /^\d+$/.test(e.headers.TTL));
}

function testWebPushErrorClass() {
  check("WebPushError exported", typeof b.webPush.WebPushError === "function");
  var e = new b.webPush.WebPushError("web-push/test", "synthetic");
  check("WebPushError carries code", e.code === "web-push/test");
}

function run() {
  testGenerateKeypairShape();
  testBuildAuthHeaderShape();
  testCustomTtl();
  testRefusesBadContact();
  testRefusesBadEndpoint();
  testRefusesNonEcdsaKey();
  testEncryptShape();
  testWebPushErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
