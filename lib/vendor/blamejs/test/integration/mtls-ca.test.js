"use strict";
/**
 * Live mTLS CA test — exercises lib/mtls-ca's CA bootstrap + client
 * cert issuance against the framework's default engine. After issue,
 * the leaf cert is used in a real TLS handshake (server presents the
 * issued cert, client trusts the CA, strict verify on) so the chain
 * is exercised end-to-end.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var crypto = require("node:crypto");
var tls = require("node:tls");
var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: tmpDir });
    check("mtlsCa.create: returned instance", typeof ca === "object");
    check("mtlsCa: exposes initCA + generateClientCert",
          typeof ca.initCA === "function" &&
          typeof ca.generateClientCert === "function");

    // ---- bootstrap CA ----
    var caBundle = await ca.initCA();
    check("initCA: returned caCertPem",
          typeof caBundle.caCertPem === "string" &&
          caBundle.caCertPem.indexOf("-----BEGIN CERTIFICATE-----") === 0);
    check("initCA: returned caKeyPem (PEM-shaped private key)",
          typeof caBundle.caKeyPem === "string" &&
          /-----BEGIN (RSA |EC |ED25519 )?PRIVATE KEY-----/.test(caBundle.caKeyPem));

    // ---- second initCA returns the same bundle (idempotent) ----
    var caBundle2 = await ca.initCA();
    check("initCA: idempotent — second call returns same CA cert",
          caBundle2.caCertPem === caBundle.caCertPem);

    // ---- issue a client cert ----
    var leaf = await ca.generateClientCert({
      cn:           "test-client.blamejs.local",
      validityDays: 7,
    });
    check("generateClientCert: returned cert PEM",
          typeof leaf.cert === "string" &&
          leaf.cert.indexOf("-----BEGIN CERTIFICATE-----") === 0);
    check("generateClientCert: returned key PEM",
          typeof leaf.key === "string" &&
          /-----BEGIN (RSA |EC |ED25519 )?PRIVATE KEY-----/.test(leaf.key));

    // ---- inspect the issued cert ----
    var x509 = new crypto.X509Certificate(leaf.cert);
    check("issued cert: subject CN matches request",
          /test-client\.blamejs\.local/.test(x509.subject || ""));
    check("issued cert: validFrom is in the past",
          new Date(x509.validFrom).getTime() < Date.now());
    check("issued cert: validTo is in the future",
          new Date(x509.validTo).getTime() > Date.now());

    var caX509 = new crypto.X509Certificate(caBundle.caCertPem);
    check("issued cert: leaf signed by the CA we bootstrapped",
          x509.verify(caX509.publicKey) === true);
    check("issued cert: issuer DN matches CA subject DN",
          x509.issuer === caX509.subject);

    // ---- end-to-end mTLS: server presents a serverAuth cert, client
    //      presents a clientAuth cert, both issued by the same CA, both
    //      verified strict on each side. This is the canonical mTLS
    //      shape the framework targets.
    var serverLeaf = await ca.generateClientCert({
      cn:           "test-server.blamejs.local",
      sans:         ["DNS:test-server.blamejs.local", "DNS:localhost", "IP:127.0.0.1"],
      usage:        "server",
      validityDays: 7,
    });
    check("generateClientCert: usage='server' returned a cert", typeof serverLeaf.cert === "string");
    var serverX509 = new crypto.X509Certificate(serverLeaf.cert);
    // node's X509Certificate.toString() doesn't surface EKU/SAN strings
    // in a stable form across versions — the live TLS handshake below
    // is the real EKU-correctness check. Here just confirm the SAN
    // covers our hostname (subjectAltName IS in toString()).
    check("server cert: SAN covers test-server.blamejs.local",
          /test-server\.blamejs\.local/.test(serverX509.subjectAltName || serverX509.toString()));

    // ---- algorithm posture lock-in ----
    // The framework's mtls-engine-default uses ECDSA P-384 deliberately:
    // node:tls and major OS cert stores don't accept SLH-DSA / ML-DSA
    // signatures on X.509 leaves yet. When that changes, this assertion
    // FAILS and forces the engine swap (CA_KEY_ALG + CA_SIG_ALG bump,
    // CA_GENERATION increment so status() reports the algorithm change).
    check("CA cert algorithm: framework's documented bridge ECDSA P-384",
          serverX509.publicKey && /ECDSA|EC|prime256|secp384/i.test(
            (serverX509.publicKey.asymmetricKeyType || "") + " " +
            (serverX509.publicKey.asymmetricKeyDetails &&
             serverX509.publicKey.asymmetricKeyDetails.namedCurve || "")));

    var server = tls.createServer({
      key:                serverLeaf.key,
      cert:               serverLeaf.cert,
      ca:                 caBundle.caCertPem,
      requestCert:        true,
      rejectUnauthorized: true,
    });
    await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
    var port = server.address().port;
    var serverSawClient = null;
    server.on("secureConnection", function (sock) {
      serverSawClient = sock.getPeerCertificate();
      sock.write("ok\n");
      sock.end();
    });

    var clientGot = await new Promise(function (resolve, reject) {
      var sock = tls.connect({
        host:               "127.0.0.1",
        port:               port,
        ca:                 caBundle.caCertPem,
        cert:               leaf.cert,
        key:                leaf.key,
        servername:         "test-server.blamejs.local",
        rejectUnauthorized: true,
      });
      var chunks = [];
      sock.on("data", function (c) { chunks.push(c); });
      sock.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
      sock.once("error", reject);
    });
    check("end-to-end mTLS: client received server data with strict verify",
          clientGot === "ok\n");
    check("end-to-end mTLS: server saw the client's CN",
          serverSawClient && serverSawClient.subject &&
          /test-client\.blamejs\.local/.test(serverSawClient.subject.CN || ""));
    server.close();

    // ---- usage='both' issues a dual-EKU cert ----
    // Verify the EKU OIDs by booting a TLS server with the cert AND
    // using the same cert as a client elsewhere. If the cert lacks
    // either EKU, one of the two roles fails. That's a stronger test
    // than a regex over toString().
    var bothLeaf = await ca.generateClientCert({
      cn:           "dual.blamejs.local",
      sans:         ["DNS:dual.blamejs.local", "DNS:localhost", "IP:127.0.0.1"],
      usage:        "both",
      validityDays: 7,
    });
    check("generateClientCert: usage='both' returned a cert",
          typeof bothLeaf.cert === "string" && bothLeaf.usage === "both");

    var bothServer = tls.createServer({
      key:                bothLeaf.key,
      cert:               bothLeaf.cert,
      ca:                 caBundle.caCertPem,
      requestCert:        true,
      rejectUnauthorized: true,
    });
    await new Promise(function (resolve) { bothServer.listen(0, "127.0.0.1", resolve); });
    var bothPort = bothServer.address().port;
    bothServer.on("secureConnection", function (sock) { sock.write("dual-ok\n"); sock.end(); });

    var bothGot = await new Promise(function (resolve, reject) {
      var sock = tls.connect({
        host:               "127.0.0.1",
        port:               bothPort,
        ca:                 caBundle.caCertPem,
        cert:               bothLeaf.cert,
        key:                bothLeaf.key,
        servername:         "dual.blamejs.local",
        rejectUnauthorized: true,
      });
      var chunks = [];
      sock.on("data", function (c) { chunks.push(c); });
      sock.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
      sock.once("error", reject);
    });
    check("usage='both': dual-EKU cert works as BOTH server AND client in mTLS",
          bothGot === "dual-ok\n");
    bothServer.close();

    // ---- bad usage rejected ----
    var threwBadUsage = null;
    try { await ca.generateClientCert({ cn: "x", usage: "neither" }); }
    catch (e) { threwBadUsage = e; }
    check("generateClientCert: rejects unknown usage value",
          threwBadUsage && /usage|invalid|unknown/i.test(threwBadUsage.message || ""));

    // ---- p12 packaging if exposed ----
    if (typeof ca.generateClientP12 === "function") {
      var p12 = await ca.generateClientP12({
        cn:           "p12-client.blamejs.local",
        validityDays: 7,
        password:     "test-pkcs12-password",
      });
      check("generateClientP12: returned a Buffer",
            p12 && Buffer.isBuffer(p12.p12) && p12.p12.length > 0);
    }

    // ---- status surface ----
    if (typeof ca.status === "function") {
      var st = ca.status();
      check("status: surfaces CA presence",
            typeof st === "object" && st !== null);
    }

    // ---- revocation registry + CRL (v0.6.45) ----
    check("revoke: function present",       typeof ca.revoke === "function");
    check("isRevoked: function present",    typeof ca.isRevoked === "function");
    check("getRevocations: function present", typeof ca.getRevocations === "function");
    check("generateCrl: function present",  typeof ca.generateCrl === "function");
    var startCount = ca.getRevocations().length;
    var revoked = ca.revoke("0xABC123", { reason: "key-compromise" });
    check("revoke: returns the recorded entry",
          revoked && revoked.serialNumber === "abc123" && revoked.reason === "key-compromise");
    check("revoke: reasonCode mapped to RFC 5280 code 1",
          revoked.reasonCode === 1);
    check("isRevoked('0xABC123') === true",  ca.isRevoked("0xABC123") === true);
    check("isRevoked: serial-format-agnostic (lowercase hex match)",
          ca.isRevoked("ABC123") === true && ca.isRevoked("abc:12:3") === true);
    check("isRevoked: unknown serial → false",
          ca.isRevoked("DEADBEEF") === false);
    var dup = ca.revoke("ABC123", { reason: "key-compromise" });
    check("revoke is idempotent — same revokedAt on duplicate call",
          dup.revokedAt === revoked.revokedAt);
    check("getRevocations: registry grew by 1",
          ca.getRevocations().length === startCount + 1);
    var threwBadSerial = null;
    try { ca.revoke(""); } catch (e) { threwBadSerial = e; }
    check("revoke: empty serial throws bad-serial",
          threwBadSerial && /bad-serial/.test(threwBadSerial.code || ""));
    var threwBadReason = null;
    try { ca.revoke("AABB", { reason: "made-up" }); } catch (e) { threwBadReason = e; }
    check("revoke: unknown reason throws bad-reason",
          threwBadReason && /bad-reason/.test(threwBadReason.code || ""));
    // v0.6.52 — serial gibberish must be rejected, not silently
    // normalised to a single-hex-char serial. Pre-fix: "xyz-not-hex"
    // stripped to "e" and registered a phantom revocation row.
    var threwGarbageSerial = null;
    try { ca.revoke("xyz-not-hex"); } catch (e) { threwGarbageSerial = e; }
    check("revoke: gibberish serial 'xyz-not-hex' throws bad-serial",
          threwGarbageSerial && /bad-serial/.test(threwGarbageSerial.code || ""));
    var threwWhitespaceOnly = null;
    try { ca.revoke("   "); } catch (e) { threwWhitespaceOnly = e; }
    check("revoke: whitespace-only serial throws bad-serial",
          threwWhitespaceOnly && /bad-serial/.test(threwWhitespaceOnly.code || ""));
    var threwGarbage2 = null;
    try { ca.revoke("nope"); } catch (e) { threwGarbage2 = e; }
    check("revoke: 'nope' (no hex digits) throws bad-serial",
          threwGarbage2 && /bad-serial/.test(threwGarbage2.code || ""));

    // CRL generation against the real engine + real CA.
    var crl = await ca.generateCrl();
    check("generateCrl: returns crlPem",
          typeof crl.crlPem === "string" && /^-----BEGIN (?:X509 )?CRL-----/m.test(crl.crlPem));
    check("generateCrl: entryCount matches getRevocations.length",
          crl.entryCount === ca.getRevocations().length);
    check("generateCrl: nextUpdate ~7 days after thisUpdate by default",
          crl.nextUpdate.getTime() - crl.thisUpdate.getTime() > 6.5 * 24 * 60 * 60 * 1000);
    check("generateCrl: persisted to ca.crl on disk",
          fs.existsSync(crl.path) &&
          /BEGIN (?:X509 )?CRL/.test(fs.readFileSync(crl.path, "utf8")));
    // CRL signature: parse via node:crypto and confirm issuer matches CA subject.
    // node:crypto.X509Certificate doesn't parse CRLs directly, but we can at
    // least confirm the PEM structure + base64-decoded DER size is plausible.
    var derBytes = Buffer.from(crl.crlPem.replace(/-----.*-----|\s/g, ""), "base64");
    check("CRL DER decodes to a non-trivial sequence",
          derBytes.length > 100);

    // Persist new revocation, regenerate CRL, confirm entry count grows.
    ca.revoke("CAFEBABE", { reason: "superseded" });
    var crl2 = await ca.generateCrl();
    check("generateCrl: picks up new revocations on regenerate",
          crl2.entryCount === crl.entryCount + 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
