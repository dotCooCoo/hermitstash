// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa non-breaking CA algorithm-migration primitives (issue #532):
 *   - status().algorithm / .keyType (from the stored cert's public key)
 *   - rotate({ generation, algorithm }) -> { caCertPem, previousCaCertPem }
 *   - commit({ retainPrevious }) + loadTrustBundle() + dropRetained()
 *   - engine + CA-handle canVerifyInTls() loopback probe
 *   - revokeGeneration(n) over the issuance ledger
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs         = require("fs");
var os         = require("os");
var path       = require("path");
var nodeCrypto = require("node:crypto");
var engine     = require("../../lib/mtls-engine-default");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");

var _tmpDirs = [];
function _mkTmp() { var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls532-")); _tmpDirs.push(d); return d; }
function _newCa(extra) { return b.mtlsCa.create(Object.assign({ dataDir: _mkTmp(), caKeySealedMode: "disabled" }, extra || {})); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
// Build a rollback-journal manifest as commit() writes it (Buffers -> base64), for
// fabricating crash states. m: { key, newKey, cert, retainAfter, prevAction, prevData }.
function _journalManifest(m) {
  return JSON.stringify({
    key:         m.key.toString("base64"),
    newKey:      m.newKey != null ? m.newKey.toString("base64") : null,
    cert:        m.cert != null ? m.cert.toString("base64") : null,
    newCert:     m.newCert != null ? m.newCert.toString("base64") : null,
    retainAfter: !!m.retainAfter,
    crlMovedAside: !!m.crlMovedAside,
    prevAction:  m.prevAction,
    prevData:    m.prevData != null ? m.prevData.toString("base64") : null,
  });
}

// A minimal custom engine that issues a P-256 (not P-384) self-signed EC CA,
// to prove status() does NOT mislabel every EC CA as ECDSA-P384-SHA384.
function _p256CaEngine() {
  return {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p256-ca" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
}

// A CA whose algorithm the runtime RECOGNIZES (ml-dsa-44) but the bundled engine does not
// issue (its set is ML-DSA-87 / ML-DSA-65 / ECDSA-P384-SHA384). Used to prove commit()'s
// supported-algorithm gate refuses a recognized-but-unsupported label too, not only a null
// (unclassifiable) one. ML-DSA is no-prehash — no digestAlgorithm.
function _mldsa44CaEngine() {
  return {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ML-DSA-44" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "mldsa44-ca" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
}

// A P-384 / SHA-384 self-signed LEAF (basicConstraints cA:false) + its matching key. Parses,
// classifies as ECDSA-P384-SHA384, and pairs — but is NOT a CA, so a bundled-engine commit() of it
// must be refused (the next generateClientCert() would fail: a non-CA issuer cannot sign leaves).
async function _p384LeafPair() {
  var subtle = pki.webcrypto.subtle;
  var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
  var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
  var now = new Date();
  var certPem = await pki.x509.sign({
    subject:          [{ commonName: "not-a-ca-leaf" }],
    subjectPublicKey: spki,
    serialNumber:     "01",
    notBefore:        now,
    notAfter:         new Date(now.getTime() + 86400000),
    extensions:       { basicConstraints: { cA: false }, keyUsage: ["digitalSignature"] },
  }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
  var keyPem = await pki.key.export(keys.privateKey, { format: "pem" });
  return { caCertPem: certPem, caKeyPem: keyPem };
}

// Parametrized P-384 CA material: a CA cert (basicConstraints cA:true) with a chosen keyUsage set,
// and its matching key exported in a chosen encoding ("pkcs8" default, or "sec1"). Used to exercise
// commit()'s bundled-engine usability preflight — a CA missing cRLSign, or a key in the SEC1
// encoding the bundled toolkit cannot decode.
async function _p384CaMaterial(matOpts) {
  matOpts = matOpts || {};
  var subtle = pki.webcrypto.subtle;
  var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
  var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
  var now = new Date();
  var caCertPem = await pki.x509.sign({
    subject:          [{ commonName: "mat-ca" }, { organizationalUnitName: "CAv1" }],
    subjectPublicKey: spki,
    serialNumber:     "01",
    notBefore:        matOpts.notBefore || now,
    notAfter:         matOpts.notAfter || new Date(now.getTime() + 86400000),
    extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: matOpts.keyUsage || ["keyCertSign", "cRLSign"] },
  }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
  var pkcs8 = await pki.key.export(keys.privateKey, { format: "pem" });
  var caKeyPem = (matOpts.keyType === "sec1")
    ? nodeCrypto.createPrivateKey(pkcs8).export({ type: "sec1", format: "pem" })
    : pkcs8;
  return { caCertPem: caCertPem, caKeyPem: caKeyPem };
}

// A custom engine that issues a P-384 / SHA-384 CA. _certAlgorithm() classifies
// that curve+digest as the framework's bundled label ECDSA-P384-SHA384, but the
// engine's own effective label for that key type is its business — so a rotate()
// under this engine must report the requested/pinned label, not the inference.
function _p384CaEngine() {
  return {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p384-ca" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
}

async function testStatusAlgorithmKeyType() {
  var ca = _newCa();
  var before = ca.status();
  check("status: no CA -> algorithm/keyType null",
        before.exists === false && before.algorithm === null && before.keyType === null);
  await ca.initCA();   // default ML-DSA-87
  var s = ca.status();
  check("status: default CA reports ML-DSA-87 / ml-dsa-87",
        s.algorithm === "ML-DSA-87" && s.keyType === "ml-dsa-87");
  var caEc = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await caEc.initCA();
  var se = caEc.status();
  check("status: classical pin reports ECDSA-P384-SHA384 / ec",
        se.algorithm === "ECDSA-P384-SHA384" && se.keyType === "ec");
}

async function testRotate() {
  var ca = _newCa();
  await ca.initCA();
  var prevCert = ca.loadCert().toString("utf8");
  check("rotate: starts on ML-DSA-87 gen 1",
        ca.status().algorithm === "ML-DSA-87" && ca.status().generation === 1);
  var rot = await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });
  check("rotate: returns caCertPem + the exact previousCaCertPem",
        typeof rot.caCertPem === "string" && rot.previousCaCertPem === prevCert);
  check("rotate: reports new generation + algorithm",
        rot.generation === 2 && rot.algorithm === "ECDSA-P384-SHA384");
  var s2 = ca.status();
  check("rotate: stored CA is now gen 2 ECDSA (mismatch-free flip)",
        s2.generation === 2 && s2.algorithm === "ECDSA-P384-SHA384");
  var leaf = await ca.generateClientCert({ cn: "post-rotate" });
  check("rotate: a leaf issues cleanly under the rotated CA", typeof leaf.cert === "string");

  var caB = _newCa(); await caB.initCA(); await caB.rotate({ generation: 5 });
  check("rotate: backward/equal generation refused",
        (await code2(function () { return caB.rotate({ generation: 3 }); })) === "mtls-ca/bad-generation");

  var caC = _newCa(); await caC.initCA();
  var rc = await caC.rotate({ algorithm: "ECDSA-P384-SHA384" });
  check("rotate: default generation is current + 1", rc.generation === 2);
}

async function testTrustBundleRetention() {
  var ca = _newCa();
  await ca.initCA();
  check("loadTrustBundle: one cert before rotation", (await ca.loadTrustBundle()).length === 1);
  var prevCert = ca.loadCert().toString("utf8");
  await ca.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });   // retainPrevious defaults on
  var bundle = (await ca.loadTrustBundle());
  check("loadTrustBundle: current + retained after rotate",
        bundle.length === 2 && bundle.indexOf(prevCert) !== -1);
  var d = await ca.dropRetained();
  check("dropRetained: ends the window", d.dropped === true && (await ca.loadTrustBundle()).length === 1);
  check("dropRetained: idempotent when nothing retained", (await ca.dropRetained()).dropped === false);

  var ca2 = _newCa(); await ca2.initCA();
  await ca2.rotate({ generation: 2, retainPrevious: false });
  check("rotate({retainPrevious:false}): no retained CA", (await ca2.loadTrustBundle()).length === 1);
}

async function testCanVerifyInTls() {
  check("engine.canVerifyInTls: ECDSA-P384-SHA384 -> true",
        (await engine.canVerifyInTls("ECDSA-P384-SHA384")) === true);
  check("engine.canVerifyInTls: unknown label -> false (fails closed)",
        (await engine.canVerifyInTls("NOT-A-REAL-ALGORITHM")) === false);
  var ca = _newCa();
  await ca.initCA();   // default ML-DSA-87 — the supported Node LTS verifies it
  check("ca.canVerifyInTls: the CA's own algorithm verifies in loopback mTLS",
        (await ca.canVerifyInTls()) === true);
}

async function testRevokeGeneration() {
  var ca = _newCa();
  await ca.initCA();
  var g1a = await ca.generateClientCert({ cn: "gen1-a" });
  var g1b = await ca.generateClientCert({ cn: "gen1-b" });
  await ca.rotate({ generation: 2 });
  var g2 = await ca.generateClientCert({ cn: "gen2-a" });
  var res = await ca.revokeGeneration(2);
  check("revokeGeneration(2): revokes both gen-1 leaves", res.revoked === 2);
  check("revokeGeneration: gen-1 leaves are revoked",
        ca.isRevoked(g1a.fingerprint) && ca.isRevoked(g1b.fingerprint));
  check("revokeGeneration: the gen-2 leaf is NOT revoked", ca.isRevoked(g2.fingerprint) === false);
  check("revokeGeneration: idempotent (re-run revokes 0 new)", (await ca.revokeGeneration(2)).revoked === 0);
  check("revokeGeneration: n=0 refused", code(function () { ca.revokeGeneration(0); }) === "mtls-ca/bad-generation");
  check("revokeGeneration: non-integer n refused", code(function () { ca.revokeGeneration(1.5); }) === "mtls-ca/bad-generation");
}

// A handle created with an algorithm pin that rotate({ algorithm })s to a
// different one must stay usable — the effective pin follows the rotation, so
// the next initCA()/generateClientCert() does not raise mtls-ca/algorithm-mismatch.
async function testRotatePersistsOverrideAlgorithm() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  await ca.rotate({ generation: 2, algorithm: "ML-DSA-87" });
  check("rotate flips the stored CA to ML-DSA-87", ca.status().algorithm === "ML-DSA-87");
  var leaf = await ca.generateClientCert({ cn: "post-rotate-mldsa" });
  check("ECDSA-pinned handle stays usable after rotating to ML-DSA (no algorithm-mismatch)",
        typeof leaf.cert === "string");
  // The reverse pin also sticks: default (ML-DSA) handle rotated to ECDSA issues ECDSA.
  var ca2 = _newCa();
  await ca2.initCA();
  await ca2.rotate({ generation: 2, algorithm: "ECDSA-P384-SHA384" });
  var leaf2 = await ca2.generateClientCert({ cn: "post-rotate-ecdsa" });
  check("default handle stays usable after rotating to ECDSA", typeof leaf2.cert === "string");
}

// rotate() must reject a fractional generation up front — Math.floor would
// silently accept 2.9 as generation 2 and mis-assign the revocation cohort.
async function testRotateRejectsFractionalGeneration() {
  var ca = _newCa();
  await ca.initCA();   // generation 1
  check("rotate: fractional generation 2.9 refused (not floored to 2)",
        (await code2(function () { return ca.rotate({ generation: 2.9 }); })) === "mtls-ca/bad-generation");
  // A whole-number rotation still works after the rejection.
  var r = await ca.rotate({ generation: 2 });
  check("rotate: integer generation still accepted", r.generation === 2);
}

// parseGeneration() must read OU=CAv{N} from a MULTI-VALUED RDN. Node exposes a multi-valued RDN
// (e.g. "CN=x + OU=CAv7") with a " + " attribute separator that the RDN-boundary match must
// recognize — while still excluding an ESCAPED "\+" inside a value ("CN=foo\+OU=CAv9", a literal +
// in the CN value, is NOT a boundary). Else an externally generated gen-7 CA reads as the legacy
// fallback 1, letting status()/rotate() allow generation 2 over it and mis-cohort issuance/revocation.
// Fixtures: openssl self-signed CAs (parseGeneration only parses the subject, no chain verification).
var _MULTIVALUED_RDN_CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBwzCCAUqgAwIBAgIUR69UCMv+o074W1zvQw6ChqcvO88wCgYIKoZIzj0EAwMw\n" +
  "GTEXMAgGA1UEAwwBeDALBgNVBAsMBENBdjcwHhcNMjYwODAxMDAzNDM2WhcNMjYw\n" +
  "ODAyMDAzNDM2WjAZMRcwCAYDVQQDDAF4MAsGA1UECwwEQ0F2NzB2MBAGByqGSM49\n" +
  "AgEGBSuBBAAiA2IABP0cB1yUhJsA8vv2jWgrWp0Pzoyel+OHRHLFJD6Kj1yPieAy\n" +
  "eZskRnKR1LIawpK0FKRxUKVuWW/EPu9mopbHj2v50ON2UUiLNRwdTb6ZNafEOhxG\n" +
  "aBG3whSTXh1WHb//yqNTMFEwHQYDVR0OBBYEFJfC4/drUVMpucaU3OTYFK6ZbUTK\n" +
  "MB8GA1UdIwQYMBaAFJfC4/drUVMpucaU3OTYFK6ZbUTKMA8GA1UdEwEB/wQFMAMB\n" +
  "Af8wCgYIKoZIzj0EAwMDZwAwZAIwWIRwvdjOXuV1Z/ZQr7ovjFZaP7Ta4q5Z2yeg\n" +
  "Kb2ddZ31k9iEZD3MhNBaHNg9ITnzAjAlByOIa2z6c1U7pQq8Lp3ix6a65GJzq9nm\n" +
  "6GksQ6r8bGdL2bvqYPXZYdbC6K/T0DM=\n" +
  "-----END CERTIFICATE-----\n";
var _ESCAPED_PLUS_CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBvTCCAUSgAwIBAgIUGzwKagAotUudwlmaUK7NiqA+UccwCgYIKoZIzj0EAwMw\n" +
  "FjEUMBIGA1UEAwwLZm9vK09VPUNBdjkwHhcNMjYwODAxMDAzNjAxWhcNMjYwODAy\n" +
  "MDAzNjAxWjAWMRQwEgYDVQQDDAtmb28rT1U9Q0F2OTB2MBAGByqGSM49AgEGBSuB\n" +
  "BAAiA2IABHgDvAZ4wrnWM2cJlnEP3zfY8WqTz3F55vnfkTBDVACPORB9k97p5+e8\n" +
  "PGWzQNBdM+5eSABAC/dJF9Frs10X/QGtCsVoDJOAOlXf7l/QvDNMbC/lI/Ah17JH\n" +
  "+aOwam9U46NTMFEwHQYDVR0OBBYEFL2uLN8Gsq5faxHNrUcrBfw4aDZgMB8GA1Ud\n" +
  "IwQYMBaAFL2uLN8Gsq5faxHNrUcrBfw4aDZgMA8GA1UdEwEB/wQFMAMBAf8wCgYI\n" +
  "KoZIzj0EAwMDZwAwZAIwbKpimgrxpavrfLHwyQGfEo6AHxNTDogrQ2EgHAVB6MWJ\n" +
  "dBhoLIjlKEpfBuobGnZrAjAyOgYRJ6iwh6TgLY1VTksfeSAzxgYNYWcHEK+WY7mZ\n" +
  "iGJ3rg0Lyh9YNvbA7gCYaHo=\n" +
  "-----END CERTIFICATE-----\n";
// A legacy CA whose CN VALUE literally contains ",OU=CAv9" — node renders it as "CN=foo\,OU=CAv9"
// (escaped comma). The escaped comma must NOT be read as an RDN separator (parseGeneration -> 1).
var _ESCAPED_COMMA_CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBvTCCAUSgAwIBAgIUQRZUsXjizY3E+sUhJ1rkzqWSS/YwCgYIKoZIzj0EAwMw\n" +
  "FjEUMBIGA1UEAwwLZm9vLE9VPUNBdjkwHhcNMjYwODAxMDE1NTQzWhcNMjYwODAy\n" +
  "MDE1NTQzWjAWMRQwEgYDVQQDDAtmb28sT1U9Q0F2OTB2MBAGByqGSM49AgEGBSuB\n" +
  "BAAiA2IABI3gbTXLRrNowu4lXq/fgt09Wg4XBhtZwG62N2Wo+mQpP2gqqktAAPXA\n" +
  "OYBslSDUu3zTBMPzyinO+YfMDchP8A+g4/PD8xl+An5OrFHA0etNp01TNwBGoIRg\n" +
  "Cp7MlseKOqNTMFEwHQYDVR0OBBYEFHprrljDxStahOJ+WEavHMo1S+c2MB8GA1Ud\n" +
  "IwQYMBaAFHprrljDxStahOJ+WEavHMo1S+c2MA8GA1UdEwEB/wQFMAMBAf8wCgYI\n" +
  "KoZIzj0EAwMDZwAwZAIwDyUvALrqDfldNmAlKyItmnv04WNuLL+EbkI0ROYNcEn2\n" +
  "k7n2p3RBX9Jod+eQvrbCAjAuiReowjBDFuVbEHLcfDkTUg4LI47g9X/Nq9XC4Iav\n" +
  "Bc5B7ldBGEPqY3nJ6FbJrZI=\n" +
  "-----END CERTIFICATE-----\n";
async function testParseGenerationReadsMultiValuedRdn() {
  check("parseGeneration reads OU=CAv7 from a multi-valued RDN (CN=x + OU=CAv7)",
        b.mtlsCa.parseGeneration(_MULTIVALUED_RDN_CA_PEM) === 7);
  check("parseGeneration treats an escaped + inside a value as NOT a boundary (CN=foo\\+OU=CAv9 -> legacy 1)",
        b.mtlsCa.parseGeneration(_ESCAPED_PLUS_CA_PEM) === 1);
  check("parseGeneration treats an escaped , inside a value as NOT a boundary (CN=foo\\,OU=CAv9 -> legacy 1)",
        b.mtlsCa.parseGeneration(_ESCAPED_COMMA_CA_PEM) === 1);
}

// A custom engine may issue a P-256 / P-521 EC CA; status() must not label it
// ECDSA-P384-SHA384 (the framework's sole classical P-384 label).
async function testStatusAlgorithmNullForNonP384Ec() {
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngine() });
  await ca.initCA();
  var s = ca.status();
  check("status: a P-256 EC CA is keyType 'ec' but algorithm null (not mislabeled P-384)",
        s.keyType === "ec" && s.algorithm === null);
}

// rotate({ retainPrevious: false }) must clear a root a PRIOR retained rotation
// left behind, so loadTrustBundle() stops trusting it.
async function testRetainPreviousFalseClearsStaleRoot() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                       // retains -> ca.prev.crt
  check("retained root present after a retained rotation", (await ca.loadTrustBundle()).length === 2);
  await ca.rotate({ generation: 3, retainPrevious: false });
  check("rotate({retainPrevious:false}) clears the stale retained root",
        (await ca.loadTrustBundle()).length === 1);
}

// A ledger write failure must FAIL issuance — an untracked cert can never be
// revoked by revokeGeneration(), so returning it would be a silent hole.
async function testIssuanceLedgerFailsClosed() {
  var throwingStore = { list: function () { return []; }, add: function () { throw new Error("disk full"); } };
  var ca = _newCa({ issuanceStore: throwingStore });
  await ca.initCA();
  check("generateClientCert fails closed when the issuance-ledger write throws",
        (await code2(function () { return ca.generateClientCert({ cn: "untracked" }); }))
          === "mtls-ca/issuance-ledger-write-failed");
}

// A cert revoked by SERIAL only, then swept by revokeGeneration (which supplies
// serial + fingerprint), must become revocable by fingerprint — otherwise the
// require-mtls gate (fingerprint-keyed) would still admit it.
async function testRevokeGenerationBackfillsFingerprint() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "gen1" });
  await ca.revoke(leaf.serialNumber);   // serial-only revocation
  check("serial-only revocation does not yet match the fingerprint",
        ca.isRevoked(leaf.fingerprint) === false);
  await ca.rotate({ generation: 2 });
  check("revokeGeneration backfills the fingerprint onto the serial-only entry (counts 1)",
        (await ca.revokeGeneration(2)).revoked === 1);
  check("the cert is now revoked by fingerprint (gate-enforceable)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A rotation whose CA commit FAILS must not have already destroyed the retained
// root — a client still using it would be stranded by a rotation that never landed.
async function testRetainedRootSurvivesFailedCommit() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });   // retains -> ca.prev.crt
  check("retained root present before the failing rotation", (await ca.loadTrustBundle()).length === 2);
  // Sabotage the next commit at the cert publish so it rolls back.
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 3, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the sabotaged rotation fails", codeSeen === "mtls-ca/commit-failed");
  check("the retained root SURVIVES a failed retainPrevious:false rotation",
        (await ca.loadTrustBundle()).length === 2);
}

// A rotation whose CA commit SUCCEEDS but whose retained-root snapshot fails
// (full/read-only fs) must still succeed — the CA is committed, the algorithm
// override sticks, and the handle keeps issuing. The retained root is secondary.
async function testRotateAbortsWhenRetainedRootWriteFails() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, algorithm: "ECDSA-P384-SHA384", caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  // The required retained-root write fails (a read-only ca.prev.crt directory,
  // disk full). Retention is part of the commit, so the rotation MUST abort rather
  // than publish a new CA while silently omitting the outgoing root (which would
  // reject clients still enrolled under the just-superseded CA, breaking the
  // advertised no-outage migration).
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root write failure");
    return realWrite.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, algorithm: "ML-DSA-87" }); }); }
  finally { atomicFile.writeSync = realWrite; }
  check("rotation aborts when the required retained-root write fails", codeSeen === "mtls-ca/commit-failed");
  check("the original CA survived the aborted rotation (still gen-1 ECDSA)",
        ca.status().generation === 1 && ca.status().algorithm === "ECDSA-P384-SHA384");
  check("the original CA key and cert are unchanged after the aborted rotation",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA still issues under its original algorithm",
        typeof (await ca.generateClientCert({ cn: "post-abort" })).cert === "string");
}

// A P12 archive with no certPem cannot be recorded in the issuance ledger, so it
// could never be revoked by generation — refuse it rather than return it.
async function testP12RequiresLedgerIdentity() {
  var noCertPem = {
    generateCa:     engine.generateCa,
    signClientCert: engine.signClientCert,
    packageP12:     async function () { return { p12: Buffer.from("fake-p12-bytes") }; },
  };
  var ca = _newCa({ engine: noCertPem });
  await ca.initCA();
  check("generateClientP12 refuses a P12 with no certPem (untracked -> unrevocable)",
        (await code2(function () { return ca.generateClientP12({ password: "pw" }); }))
          === "mtls-ca/bad-engine-output");
}

// generateCrl's fingerprint-only omission count must not fold in the serial
// DUPLICATES the CRL dedup drops — otherwise a complete CRL is reported incomplete.
async function testCrlOmissionCountExcludesSerialDupes() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "z1" });
  await ca.revoke(leaf.serialNumber);                 // serial-only, recorded in the ledger
  await ca.revoke({ fingerprint: "cd".repeat(64) });  // a genuine fingerprint-only revocation
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);                        // backfills leaf -> a serial-duplicate entry
  var crl = await ca.generateCrl({ persist: false });
  check("generateCrl omission count counts only genuine fingerprint-only entries (serial dupes excluded)",
        crl.fingerprintOnlyOmitted === 1);
}

// Concurrent rotate() calls must serialize, not both read the same current
// generation and clobber each other's CA + retained root. With only one retained
// grace window at a time, the first opens the window and the second is refused
// rather than silently dropping it.
async function testConcurrentRotationsSerialize() {
  var ca = _newCa();
  await ca.initCA();   // generation 1
  var results = await Promise.allSettled([ca.rotate({}), ca.rotate({})]);
  var fulfilled = results.filter(function (r) { return r.status === "fulfilled"; });
  var rejected  = results.filter(function (r) { return r.status === "rejected"; });
  check("exactly one concurrent retained rotation succeeds, the other is refused",
        fulfilled.length === 1 && rejected.length === 1);
  check("the winner is generation 2 retaining gen-1",
        fulfilled[0].value.generation === 2 && ca.status().generation === 2 && (await ca.loadTrustBundle()).length === 2);
  check("the loser is refused (the open grace window is not silently dropped)",
        rejected[0].reason && rejected[0].reason.code === "mtls-ca/retained-root-exists");
  await ca.dropRetained();
  check("after dropRetained the CA rotates to generation 3", (await ca.rotate({})).generation === 3);
}

// isRevoked() reads an in-memory index (kept in sync by revoke()) rather than
// re-parsing the store per call — assert the index stays correct across a
// build-then-update sequence.
async function testRevocationIndexStaysConsistent() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "idx" });
  check("not revoked before revocation (builds the index)", ca.isRevoked(leaf.fingerprint) === false);
  await ca.revoke({ fingerprint: leaf.fingerprint });
  check("revoked after revoke (index updated incrementally, no store re-scan)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A revocation written through ANOTHER handle over the same data directory must
// be seen by this handle's gate lookup — the index refreshes on a store change.
async function testRevocationIndexRefreshesAcrossHandles() {
  var dir = _mkTmp();
  var caA = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var caB = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await caA.initCA();
  var leaf = await caA.generateClientCert({ cn: "shared" });
  check("handle A: cert not revoked initially (builds its index)",
        caA.isRevoked(leaf.fingerprint) === false);
  await caB.revoke({ fingerprint: leaf.fingerprint });   // revoke through the OTHER handle
  check("handle A picks up a revocation written by handle B (index refreshed via store version)",
        caA.isRevoked(leaf.fingerprint) === true);
}

// Two handles over the same dataDir own separate rotation chains, so the
// pre-commit generation revalidation must refuse the loser instead of both
// committing the same generation and clobbering the retained root.
async function testRotationConflictAcrossHandles() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (o) { await barrier; return engine.generateCa(o); },
  });
  var caA = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var caB = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await caA.initCA();                              // generation 1 on disk, shared
  var bRotate = caB.rotate({ generation: 2 });     // reads gen 1, blocks in generateCa
  await caA.rotate({ generation: 2 });             // commits generation 2 first
  release();                                        // unblock caB's generateCa
  check("a concurrent cross-handle rotation is refused with mtls-ca/rotation-conflict",
        (await code2(function () { return bRotate; })) === "mtls-ca/rotation-conflict");
  check("the CA on disk is the winner's generation 2", caA.status().generation === 2);
}

// canVerifyInTls must probe the PROSPECTIVE algorithm when given, so an
// ECDSA-stored handle pre-flighting a move to ML-DSA tests the target chain,
// not the current one (and a bogus label fails closed rather than passing on
// the stored algorithm).
async function testCanVerifyInTlsProbesTargetAlgorithm() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();   // stored CA is ECDSA
  check("canVerifyInTls() (no arg) probes the stored ECDSA CA",
        (await ca.canVerifyInTls()) === true);
  check("canVerifyInTls('ML-DSA-87') probes the TARGET algorithm (the migration pre-flight)",
        (await ca.canVerifyInTls("ML-DSA-87")) === true);
  check("canVerifyInTls('NOT-A-REAL-ALGORITHM') fails closed (arg is honored, not ignored)",
        (await ca.canVerifyInTls("NOT-A-REAL-ALGORITHM")) === false);
}

// Concurrent issuance against the default ledger must record every certificate
// (the cross-process-locked read-modify-write appends without losing entries).
async function testConcurrentIssuanceAllRecorded() {
  var ca = _newCa();
  await ca.initCA();
  var leaves = await Promise.all([
    ca.generateClientCert({ cn: "c1" }),
    ca.generateClientCert({ cn: "c2" }),
    ca.generateClientCert({ cn: "c3" }),
  ]);
  await ca.rotate({ generation: 2 });
  check("all 3 concurrently-issued certs are recorded (revokeGeneration revokes all 3)",
        (await ca.revokeGeneration(2)).revoked === 3);
  check("each concurrently-issued cert is revoked by fingerprint",
        leaves.every(function (l) { return ca.isRevoked(l.fingerprint); }));
}

// A P-384 EC CA signed with a non-SHA-384 digest must NOT be labeled
// ECDSA-P384-SHA384 — the digest is part of the label, not just the curve.
async function testStatusAlgorithmNullForWrongDigest() {
  var p384Sha512 = {
    generateCa: async function () {
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p384-sha512" }, { organizationalUnitName: "CAv1" }],
        subjectPublicKey: spki,
        serialNumber:     "01",
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha512" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: p384Sha512 });
  await ca.initCA();
  var s = ca.status();
  check("status: a P-384 CA signed with SHA-512 is not labeled ECDSA-P384-SHA384 (digest checked)",
        s.keyType === "ec" && s.algorithm === null);
}

// An issuance whose signing straddles a rotate()+revokeGeneration() for its
// generation must be caught and refused, not returned as a live credential the
// sweep missed (the record races the sweep-read; the watermark closes it).
async function testIssuanceSupersededByGenerationRevocation() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                            // generation 1
  var issuing = ca.generateClientCert({ cn: "in-flight" });   // blocks in signClientCert (gen-1 CA)
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);                 // sweeps gen-1 — the in-flight leaf isn't in the ledger yet
  release();                                    // now _recordIssuance runs, AFTER the sweep
  check("an issuance whose generation was revoked mid-signing is refused (superseded)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// The issuance-vs-sweep watermark must cover a CUSTOM revocation store too — it
// is a separate file, and a list()/add()-only store cannot make its own
// append+sweep atomic.
async function testIssuanceSupersededWithCustomStore() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var revoked = [];
  var customStore = { list: function () { return revoked.slice(); }, add: function (e) { revoked.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine, revocationStore: customStore });
  await ca.initCA();
  var issuing = ca.generateClientCert({ cn: "in-flight-custom" });
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);
  release();
  check("issuance-superseded fires with a custom revocation store (watermark applies to all stores)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A CUSTOM issuanceStore may hold entries the framework never validated (added out of band, not via
// importIssuance — which now requires a fingerprint). revokeGeneration() sweeps them best-effort by
// whatever identity they carry: a fingerprint-less entry revokes by serial only (the operator owns a
// custom store's contents and accepts its per-issuer serial semantics). This exercises the
// serial-only sweep arm for a store the framework cannot enforce fingerprints on.
async function testRevokeGenerationSweepsFingerprintlessCustomStoreEntry() {
  var issued = [{ generation: 1, serialNumber: "aa" }];        // out-of-band entry, no fingerprint
  var customIss = { list: function () { return issued.slice(); }, add: function (e) { issued.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: customIss });
  await ca.initCA();
  var rg = await ca.revokeGeneration(2);                       // revokes gen < 2 -> the gen-1 entry
  check("revokeGeneration sweeps a fingerprint-less custom-store entry by serial", rg.revoked === 1);
  check("the serial-only swept entry is matched by isSerialRevoked", ca.isSerialRevoked("aa") === true);
}

// Clustered deployment: a shared revocation store exposing the optional
// watermark methods coordinates the generation watermark across hosts that each
// have their OWN dataDir, so an issuance on host B is superseded by host A's
// revokeGeneration even though B's local watermark file was never written.
async function testClusteredWatermarkViaStoreMethods() {
  var shared = { revoked: [], wm: 0 };
  function sharedStore() {
    return {
      list: function () { return shared.revoked.slice(); },
      add:  function (e) { shared.revoked.push(e); },
      readGenerationWatermark: function () { return shared.wm; },
      bumpGenerationWatermark: function (n) { if (n > shared.wm) shared.wm = n; },
    };
  }
  // Clustered operation also requires a shared issuance ledger (per-host default
  // ledgers would let revokeGeneration() miss another host's issuances).
  var sharedIssued = [];
  function sharedIssuanceStore() {
    return { list: function () { return sharedIssued.slice(); }, add: function (e) { sharedIssued.push(e); } };
  }
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var hostB = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine, revocationStore: sharedStore(), issuanceStore: sharedIssuanceStore() });
  await hostB.initCA();                              // generation 1 on host B's dataDir
  var issuing = hostB.generateClientCert({ cn: "clustered" });   // blocks in signing
  var hostA = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: sharedStore(), issuanceStore: sharedIssuanceStore() });
  await hostA.initCA();
  await hostA.rotate({ generation: 2 });
  await hostA.revokeGeneration(2);                   // bumps the SHARED watermark
  release();
  check("a clustered shared-store watermark supersedes an issuance on another host",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A CA cert/key pair that stays inconsistent after re-reading must be REFUSED
// (mtls-ca/ca-pair-inconsistent), not signed with, so issuance fails clearly.
async function testInitCaRefusesPersistentPairMismatch() {
  var ca = _newCa();
  await ca.initCA();
  var other = _newCa();
  await other.initCA();
  fs.copyFileSync(other.paths.caKey, ca.paths.caKey);   // ca.key now belongs to a different CA
  check("initCA refuses a persistently mismatched CA cert/key pair (does not sign)",
        (await code2(function () { return ca.generateClientCert({ cn: "mismatch" }); }))
          === "mtls-ca/ca-pair-inconsistent");
}

// If the FINAL cert rename fails after the retained root was rewritten, the prior
// retained root must be restored — a failed rotation cannot strand old-CA clients.
async function testCommitRollsBackRetainedRootOnCertRenameFailure() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();                                     // gen-1, no retained root yet
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  var failed = false;
  try {
    try { await ca.rotate({ generation: 2 }); } catch (_e) { failed = true; }
  } finally { atomicFile.renameWithRetry = realRename; }
  check("a rotation whose cert publication fails is rejected", failed);
  // The prior KEY must be restored — otherwise the new key would sit beside the old
  // cert (a mismatched pair) and the handle would be permanently unusable — and the
  // retained root the failed rotation created must be rolled back (there was none
  // before a first rotation, so ca.prev.crt is removed).
  check("the CA rolls back to the prior key + cert when cert publication fails",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("no stale retained root is left behind by the failed first rotation",
        fs.existsSync(ca.paths.caCertPrev) === false);
  check("the handle still issues after the failed rotation (key + cert pair intact)",
        typeof (await ca.generateClientCert({ cn: "after-failed-rotate" })).cert === "string");
}

// The clustered-watermark methods are all-or-nothing: a store providing only one
// would split the watermark and fail open, so it is refused at construction.
async function testWatermarkMethodsMustBePaired() {
  var base = { list: function () { return []; }, add: function () {} };
  var bumpOnly = Object.assign({}, base, { bumpGenerationWatermark: function () {} });
  var readOnly = Object.assign({}, base, { readGenerationWatermark: function () { return 0; } });
  check("a revocationStore with only bumpGenerationWatermark is refused",
        code(function () { b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: bumpOnly }); })
          === "mtls-ca/bad-revocation-store");
  check("a revocationStore with only readGenerationWatermark is refused",
        code(function () { b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: readOnly }); })
          === "mtls-ca/bad-revocation-store");
}

// A P12 certPem must be NON-EMPTY (it is the ledger identity), but need NOT be
// node-parseable — a custom engine may package an opaque certificate this runtime cannot
// parse, exactly as generateClientCert accepts; _certIdentity still derives a stable
// fingerprint, and parsing cannot prove certPem is the cert inside the encrypted p12.
async function testP12CertPemMustBeNonEmpty() {
  function eng(certPem) {
    return { generateCa: engine.generateCa, signClientCert: engine.signClientCert,
             packageP12: async function () { return { p12: Buffer.from("x"), certPem: certPem }; } };
  }
  var caEmpty = _newCa({ engine: eng("") }); await caEmpty.initCA();
  check("generateClientP12 refuses an empty certPem",
        (await code2(function () { return caEmpty.generateClientP12({ password: "pw" }); })) === "mtls-ca/bad-engine-output");
  var caOpaque = _newCa({ engine: eng("not a parseable certificate") }); await caOpaque.initCA();
  var out = await caOpaque.generateClientP12({ password: "pw" });
  check("generateClientP12 ACCEPTS a non-parseable (opaque) certPem, deriving a fingerprint",
        Buffer.isBuffer(out.p12) && typeof out.fingerprint === "string" && out.fingerprint.length > 0);
}

// A defined rotate() algorithm must be a non-empty label (an empty string would
// be read as a pin here but as "no pin"/"omitted" by the engine and canVerifyInTls).
async function testRotateRejectsEmptyAlgorithm() {
  var ca = _newCa();
  await ca.initCA();
  check("rotate: empty-string algorithm refused",
        (await code2(function () { return ca.rotate({ generation: 2, algorithm: "" }); })) === "mtls-ca/bad-algorithm");
}

// A nested operator path must work: create() creates the lock target's parent
// dir, so the first locked revoke() does not ENOENT on <path>.lock.
async function testNestedPathParentDirsCreated() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", paths: { revocations: "state/revocations.json" } });
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "nested" });
  await ca.revoke({ fingerprint: leaf.fingerprint });
  check("revoke() with a nested paths.revocations succeeds (lock parent dir created)",
        ca.isRevoked(leaf.fingerprint) === true);
}

// A present-but-malformed generation watermark must ABORT issuance (fail closed),
// not report 0 — reporting 0 would let a below-n generation slip through unrevoked.
async function testMalformedWatermarkAbortsIssuance() {
  var ca = _newCa();
  await ca.initCA();
  fs.writeFileSync(ca.paths.revokedGeneration, "not-a-number");
  check("issuance aborts when the revoked-generation watermark is malformed (fails closed)",
        (await code2(function () { return ca.generateClientCert({ cn: "x" }); })) === "mtls-ca/watermark-unreadable");
  // A partially-numeric watermark must NOT parseInt to a lower prefix.
  fs.writeFileSync(ca.paths.revokedGeneration, "1junk");
  check("issuance aborts on a partially-numeric watermark (no parseInt prefix)",
        (await code2(function () { return ca.generateClientCert({ cn: "y" }); })) === "mtls-ca/watermark-unreadable");
}

// importIssuance() backfills leaf identities the ledger doesn't have (pre-#532 /
// out-of-band certs), so revokeGeneration() can then sweep them.
async function testImportIssuanceBackfill() {
  var ca = _newCa();
  await ca.initCA();
  var fp = "ab".repeat(64);   // a 128-hex fingerprint of a pre-existing leaf
  var res = await ca.importIssuance([{ fingerprint: fp, generation: 1 }]);
  check("importIssuance reports the imported count", res.imported === 1);
  await ca.rotate({ generation: 2 });
  check("revokeGeneration revokes an imported pre-upgrade cert", (await ca.revokeGeneration(2)).revoked === 1);
  check("the imported cert is now revoked by fingerprint", ca.isRevoked(fp) === true);
  check("importIssuance rejects a non-array", code(function () { ca.importIssuance("nope"); }) === "mtls-ca/bad-import");
  check("importIssuance rejects an entry without a generation",
        code(function () { ca.importIssuance([{ fingerprint: fp }]); }) === "mtls-ca/bad-import");
}

// importIssuance() exists solely so revokeGeneration() can sweep a backfilled cert. A serial-only
// entry (no fingerprint) would be swept into a fingerprint-null revocation, which isSerialRevoked()
// matches GLOBALLY — a custom CA that reuses that serial after rotation then has its unrelated
// current certificate false-rejected by require-mtls. A serial is unique only per issuer; the
// globally-unique identity the gate pins is the fingerprint, so an imported entry must carry one
// (recording caCert alone is not enough — the live serial lookup does not consult it).
async function testImportRequiresFingerprint() {
  var ca = _newCa();
  await ca.initCA();
  check("importIssuance rejects a serial-only entry (no fingerprint)",
        (await code2(function () { return ca.importIssuance([{ generation: 1, serialNumber: "0a" }]); }))
          === "mtls-ca/bad-import");
  check("importIssuance rejects a serial-only entry even with a caCert issuer recorded",
        (await code2(function () {
          return ca.importIssuance([{ generation: 1, serialNumber: "0a", caCert: ca.loadCert().toString("utf8") }]);
        })) === "mtls-ca/bad-import");
  // A fingerprint-bearing entry (with or without a serial) still imports and is generation-revocable.
  var r = await ca.importIssuance([{ generation: 1, fingerprint: "ab".repeat(64), serialNumber: "0a" }]);
  check("importIssuance accepts a fingerprint-bearing entry", r.imported === 1);
}

// A fingerprint STORED for the require-mtls gate must be the framework's SHA3-512 length (128 hex).
// _normalizeFingerprint validates only hex, so importIssuance()/revoke({fingerprint}) would accept a
// SHA-256 (64-hex) or truncated value, "succeed", yet the gate's 128-hex compare never matches — the
// certificate stays admitted (a silent fail-open). Reject the wrong-length fingerprint at the write.
async function testGateFingerprintLengthEnforced() {
  var ca = _newCa();
  await ca.initCA();
  var sha256Fp = "ab".repeat(32);                 // 64 hex — a SHA-256 fingerprint, not the gate's SHA3-512
  check("importIssuance rejects a non-SHA3-512-length fingerprint",
        (await code2(function () { return ca.importIssuance([{ fingerprint: sha256Fp, generation: 1 }]); }))
          === "mtls-ca/bad-fingerprint");
  check("revoke({fingerprint}) rejects a non-SHA3-512-length fingerprint",
        (await code2(function () { return ca.revoke({ fingerprint: sha256Fp }); }))
          === "mtls-ca/bad-fingerprint");
  var sha3Fp = "cd".repeat(64);                    // 128 hex — a valid SHA3-512 leaf fingerprint
  check("importIssuance accepts a 128-hex SHA3-512 fingerprint",
        (await code2(function () { return ca.importIssuance([{ fingerprint: sha3Fp, generation: 1 }]); })) === "NO-THROW");
  check("revoke({fingerprint}) accepts a 128-hex SHA3-512 fingerprint",
        (await code2(function () { return ca.revoke({ fingerprint: sha3Fp }); })) === "NO-THROW");
}

// The default issuance ledger is READ with a 16 MiB cap (fdSafeReadSync throws over it), but its
// WRITE was uncapped: an append that pushes the file past 16 MiB would succeed and return the signed
// credential, yet every later _list() then fails the framework's own file — disabling future issuance
// and revokeGeneration(). The store must size-check the serialized output and refuse before publishing.
async function testIssuanceRefusedWhenLedgerWouldExceedReadCap() {
  var ca = _newCa();
  await ca.initCA();
  var CAP = 16 * 1024 * 1024;                                   // the store's read cap (C.BYTES.mib(16))
  // Pre-fill the ledger to just under the cap: one valid entry padded so a single further append
  // (~a few hundred bytes) tips the serialized file over the cap.
  var entry = { serialNumber: "01", fingerprint: "ab".repeat(64), generation: 1, caFingerprint: "cd".repeat(64), issuedAt: 1, _pad: "" };
  var emptyBytes = Buffer.byteLength(JSON.stringify({ issued: [entry] }, null, 2) + "\n", "utf8");
  entry._pad = "x".repeat(CAP - emptyBytes - 200);             // file ends ~200 bytes under the cap
  fs.writeFileSync(ca.paths.issuance, JSON.stringify({ issued: [entry] }, null, 2) + "\n");
  var sizeBefore = fs.statSync(ca.paths.issuance).size;
  check("the pre-filled ledger is just under the read cap", sizeBefore < CAP && sizeBefore > CAP - 1024);
  // An issuance now appends one entry, pushing the serialized file over the cap.
  var codeSeen = await code2(function () { return ca.generateClientCert({ cn: "over-cap" }); });
  check("issuance is refused before the ledger exceeds its read cap", codeSeen === "mtls-ca/issuance-ledger-write-failed");
  check("no over-cap file was written (the ledger stays readable)", fs.statSync(ca.paths.issuance).size <= CAP);
}

// loadTrustBundle() must tolerate a concurrent removal of ca.prev.crt between its
// existsSync and its read (a dropRetained()/retainPrevious:false on another
// process) and return the still-valid current CA rather than throwing ENOENT.
async function testLoadTrustBundleToleratesConcurrentPrevRemoval() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });   // ca.prev.crt exists
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) { var err = new Error("ENOENT"); err.code = "ENOENT"; throw err; }
    return realRead.apply(this, arguments);
  };
  var bundle;
  try { bundle = (await ca.loadTrustBundle()); } finally { atomicFile.fdSafeReadSync = realRead; }
  check("loadTrustBundle tolerates a concurrent retained-root removal (returns current CA, no throw)",
        bundle.length === 1);
}

// importIssuance() of a leaf whose generation is already revoked (below the
// watermark) must revoke it — the completed sweep won't see the late append.
async function testImportOfRevokedGenerationIsRevoked() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateClientCert({ cn: "gen1" });
  await ca.rotate({ generation: 2 });
  await ca.revokeGeneration(2);   // watermark = 2
  var fp = "cd".repeat(64);
  var res = await ca.importIssuance([{ fingerprint: fp, generation: 1 }]);
  check("importIssuance revokes an imported cert of an already-revoked generation",
        res.revoked === 1 && ca.isRevoked(fp) === true);
}

// A rotation publishes the CA key and cert as two separate file renames, so a
// crash BETWEEN them (or a power loss during the retained-root fsyncs) leaves
// the new key beside the old cert with the in-memory catch rollback never run —
// the prior key would be unrecoverable and the CA stuck (mtls-ca/ca-pair-
// inconsistent). commit() guards this by writing a durable rollback journal of
// the prior key before overwriting it; initCA()/_rotateImpl() reconcile from it.
async function testInterruptedRotationRecoversFromJournal() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1  = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var journal = ca.paths.caKey + ".rollback";

  // Case 1 — crash AFTER the key rename, BEFORE the cert rename: the live key is
  // the new (gen-2) key, the cert is still the old (gen-1) one, and the journal
  // holds the prior (gen-1) key. A fresh handle must roll BACK to the consistent
  // gen-1 pair so the CA (able to issue leaves and CRLs) survives.
  fs.writeFileSync(ca.paths.caCert, certG1);   // cert never got published (live == journal's prior => interrupted)
  fs.writeFileSync(journal, _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await reopened.generateClientCert({ cn: "after-crash" });
  check("interrupted rotation: the handle recovers and issues after reconciling the rollback journal",
        typeof leaf.cert === "string");
  check("interrupted rotation: the live CA key is restored to the prior (gen-1) key",
        fs.readFileSync(reopened.paths.caKey).equals(keyG1));
  check("interrupted rotation: the spent rollback journal is removed",
        fs.existsSync(journal) === false);

  // Case 2 — crash AFTER the cert rename, BEFORE the journal delete: the new pair
  // is consistent on disk but a stale journal lingers. Recovery must roll FORWARD
  // (keep gen-2, drop the journal), never revert a completed rotation.
  var dir2 = _mkTmp();
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await ca2.initCA();
  var priorKey2 = fs.readFileSync(ca2.paths.caKey);
  var certG1b   = fs.readFileSync(ca2.paths.caCert);
  await ca2.rotate({ generation: 2 });
  var keyG2b  = fs.readFileSync(ca2.paths.caKey);
  var journal2 = ca2.paths.caKey + ".rollback";
  // Live cert (gen-2) differs from the journal's prior cert (gen-1) => COMPLETED.
  fs.writeFileSync(journal2, _journalManifest({
    key: priorKey2, newKey: keyG2b, cert: certG1b, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await reopened2.initCA();
  check("stale journal over a consistent new pair rolls forward: key stays gen-2",
        fs.readFileSync(reopened2.paths.caKey).equals(keyG2b));
  check("stale journal over a consistent new pair is dropped",
        fs.existsSync(journal2) === false);
  check("roll-forward: the gen-2 CA still issues",
        typeof (await reopened2.generateClientCert({ cn: "roll-fwd" })).cert === "string");

  // Keep certG2 referenced so the fixture stays self-documenting.
  check("interrupted-rotation fixture used two distinct generations",
        !certG2.equals(certG1) && !keyG2.equals(keyG1));
}

// An interrupted rotation must recover the RETAINED ROOT too, not just the key.
// commit() overwrites ca.prev.crt with the outgoing cert before the final cert
// rename, so a crash between them (with only a key-recovery journal) would roll
// the active cert back but leave ca.prev.crt clobbered — dropping trust for
// clients still enrolled under the formerly-retained generation. The rollback
// journal is a manifest carrying the prior key AND the prior retained root.
async function testInterruptedRotationRecoversRetainedRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);            // becomes the retained root after gen-2
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = certG1 (retained root P)
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();                                   // end the gen-1 window (only one at a time)
  await ca.rotate({ generation: 3 });                        // gives us a real gen-3 key to pose as "new"
  var keyG3  = fs.readFileSync(ca.paths.caKey);
  var journal = ca.paths.caKey + ".rollback";

  // Fabricate a crash DURING a gen-2 -> gen-3 rotation, AFTER the retained-root
  // update (ca.prev.crt overwritten with the outgoing gen-2 cert) but BEFORE the
  // cert rename: the live key is gen-3, the cert is still gen-2, the retained root
  // was clobbered from certG1 to certG2, and the manifest journals the prior key
  // (gen-2) plus the prior retained root (certG1) to restore.
  fs.writeFileSync(ca.paths.caKey, keyG3);                   // new key published
  fs.writeFileSync(ca.paths.caCert, certG2);                 // cert never got published (live == prior => interrupted)
  fs.writeFileSync(ca.paths.caCertPrev, certG2);             // retained root clobbered (bug surface)
  fs.writeFileSync(journal, _journalManifest({
    key: keyG2, newKey: keyG3, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));

  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await reopened.generateClientCert({ cn: "after-prev-crash" });
  check("interrupted 2nd rotation: the handle recovers and issues", typeof leaf.cert === "string");
  check("interrupted 2nd rotation: the live CA key is rolled back to gen-2",
        fs.readFileSync(reopened.paths.caKey).equals(keyG2));
  check("interrupted 2nd rotation: the retained root is restored (formerly-retained clients keep trust)",
        fs.readFileSync(reopened.paths.caCertPrev).equals(certG1));
  var bundle = (await reopened.loadTrustBundle());
  check("interrupted 2nd rotation: trust bundle is [gen-2 current, gen-1 retained]",
        bundle.length === 2 &&
        Buffer.from(bundle[0]).equals(certG2) && Buffer.from(bundle[1]).equals(certG1));
  check("interrupted 2nd rotation: the spent journal is removed",
        fs.existsSync(journal) === false);
  // keep keyG3 referenced (it is the fabricated new key)
  check("interrupted 2nd rotation fixture: gen-3 key differed from gen-2", !keyG3.equals(keyG2));
}

// An idempotent commit({ retainPrevious:true }) that only REFORMATS the current cert (byte-different,
// same identity) while a grace window is OPEN must not strand the retained root on crash recovery.
// The reformatted cert is byte-different from the journal's prior cert, so reconcile classifies the
// commit COMPLETED and rolls forward — it must PRESERVE the existing ca.prev.crt (priorPrev), not
// delete it (a retainAfter:false derived from outgoingCaCert===null would).
async function testIdempotentRecommitPreservesRetainedRootAcrossCrash() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);            // becomes the retained root after gen-2
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = certG1 (grace window open)
  check("a grace window is open before the reformatted recommit", (await ca.loadTrustBundle()).length === 2);
  var certG2 = ca.loadCert().toString("utf8");
  var keyG2  = ca.loadKey().toString("utf8");
  var journal = ca.paths.caKey + ".rollback";

  // Recommit the CURRENT cert REFORMATTED (CRLF + trailing NL: byte-different, same identity).
  // Simulate a crash AFTER the durable publish but BEFORE the journal delete by no-op'ing the
  // journal unlink for the duration of the commit — so the journal survives to be reconciled.
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) return;   // skip the journal delete -> journal survives (crash)
    return realUnlink.apply(this, arguments);
  };
  try {
    await ca.commit({ caKeyPem: keyG2, caCertPem: certG2.replace(/\n/g, "\r\n") + "\n", retainPrevious: true });
  } finally { fs.unlinkSync = realUnlink; }
  check("the reformatted recommit left the journal on disk (simulated crash)", fs.existsSync(journal) === true);
  check("the grace-window root is still present right after the recommit", fs.existsSync(ca.paths.caCertPrev) === true);

  // Reopen -> reconcile (via issuance). It must PRESERVE the retained root, not delete it.
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.generateClientCert({ cn: "after-idempotent-recommit-crash" });
  check("the spent journal is removed after reconcile", fs.existsSync(journal) === false);
  var bundle = await reopened.loadTrustBundle();
  check("reconcile PRESERVED the grace-window root (still trusted, not stranded)",
        bundle.length === 2 && bundle.some(function (c) { return Buffer.from(c).equals(certG1); }));
}

// A hard-cut commit({ retainPrevious:false }) that republishes the BYTE-IDENTICAL current CA (same
// cert AND key) to close a grace window must not resurrect the retained root on crash recovery. The
// live cert equals the journal's prior cert, so the byte-only completed/interrupted discriminator
// misreads it as INTERRUPTED and restores the removed root. Reconcile must recognize the completed
// hard cut (cert+key unchanged, retainAfter:false, prev already absent) and keep the root removed.
async function testByteIdenticalHardCutDoesNotResurrectRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1 (grace window open)
  check("a grace window is open before the byte-identical hard cut", (await ca.loadTrustBundle()).length === 2);
  var certG2 = ca.loadCert().toString("utf8");               // exact current bytes (NOT reformatted)
  var keyG2  = ca.loadKey().toString("utf8");
  var journal = ca.paths.caKey + ".rollback";

  // Hard-cut recommit of the byte-identical current CA. Simulate a crash after the prev removal +
  // cert publish but BEFORE the journal delete by no-op'ing the journal unlink -> journal survives.
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) { if (String(p) === String(journal)) return; return realUnlink.apply(this, arguments); };
  try {
    await ca.commit({ caKeyPem: keyG2, caCertPem: certG2, retainPrevious: false });
  } finally { fs.unlinkSync = realUnlink; }
  check("the byte-identical hard cut removed the retained root", fs.existsSync(ca.paths.caCertPrev) === false);
  check("the byte-identical hard cut left the journal on disk (simulated crash)", fs.existsSync(journal) === true);

  // Reopen -> reconcile. It must keep the root removed, not restore it.
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.generateClientCert({ cn: "after-byte-identical-hard-cut" });
  check("the spent journal is removed after reconcile", fs.existsSync(journal) === false);
  check("reconcile did NOT resurrect the hard-cut root", fs.existsSync(reopened.paths.caCertPrev) === false);
  check("the trust bundle is just the current CA (grace window stays closed)",
        (await reopened.loadTrustBundle()).length === 1);
}

// A PRESENT issuance ledger with a corrupt schema (valid JSON but no `issued`
// array — an accidental `{}`) MUST fail closed, not be treated as an empty
// ledger. Silently treating it as empty would let the next issuance overwrite it
// with only the new entry, permanently dropping every prior certificate from the
// SOLE index revokeGeneration() consults (those certs would survive revocation).
async function testCorruptIssuanceLedgerSchemaFailsClosed() {
  var ca = _newCa();
  await ca.initCA();
  var first = await ca.generateClientCert({ cn: "ledger-1" });
  check("issuance ledger recorded the first cert", ca.isRevoked(first.fingerprint) === false && typeof first.cert === "string");
  var ledgerBefore = fs.readFileSync(ca.paths.issuance);

  // Corrupt: valid JSON, wrong schema (no `issued` array).
  fs.writeFileSync(ca.paths.issuance, "{}");
  check("revokeGeneration fails closed on a schema-corrupt ledger (not treated as empty)",
        (await code2(function () { return ca.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");
  check("issuance fails closed on a schema-corrupt ledger rather than overwriting it",
        (await code2(function () { return ca.generateClientCert({ cn: "ledger-2" }); }))
          === "mtls-ca/issuance-ledger-write-failed");
  check("the corrupt ledger was NOT overwritten (prior certs not silently dropped)",
        fs.readFileSync(ca.paths.issuance).toString() === "{}");

  // A non-array `issued` is also corruption, and a valid ledger still reads.
  fs.writeFileSync(ca.paths.issuance, JSON.stringify({ issued: "nope" }));
  check("a non-array `issued` is corruption too",
        (await code2(function () { return ca.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");
  fs.writeFileSync(ca.paths.issuance, ledgerBefore);
  check("restoring a well-formed ledger clears the corruption",
        (await code2(function () { return ca.revokeGeneration(2); })) === "NO-THROW");
}

// retainPrevious:false is a HARD trust cutoff: if the old retained root cannot be
// removed (a read-only / blocked ca.prev.crt), the rotation must abort rather than
// publish a new CA while loadTrustBundle() keeps trusting a root the operator
// asked to cut — which would keep admitting certs chained to it.
async function testRotateRetainFalseAbortsWhenRemovalFails() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1 (a retained root exists)
  check("a retained root exists before the hard-cutoff rotation", (await ca.loadTrustBundle()).length === 2);
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  // The retained-root REMOVAL fails (a read-only ca.prev.crt directory). The prev is
  // readable (captured for rollback), but its unlink fails -> the hard cutoff cannot
  // be established, so the rotation aborts rather than publishing a new CA while
  // loadTrustBundle() keeps trusting a root the operator asked to cut.
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root removal failure");
    return realUnlink.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 3, retainPrevious: false }); }); }
  finally { fs.unlinkSync = realUnlink; }
  check("rotate({retainPrevious:false}) aborts when the old root cannot be removed", codeSeen === "mtls-ca/commit-failed");
  check("the CA survived the aborted hard-cutoff rotation (still gen-2)", ca.status().generation === 2);
  check("the CA key and cert are unchanged after the aborted hard-cutoff",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA still issues after the aborted hard-cutoff",
        typeof (await ca.generateClientCert({ cn: "post-cutoff-abort" })).cert === "string");
}

// canVerifyInTls() with no argument derives the label from the stored CA. A custom
// CA this runtime cannot classify (status().algorithm === null) with no create-time
// pin leaves the label undefined; probing the engine with undefined would let one
// that reads an omitted label as "current default" answer for the WRONG algorithm.
// Require an explicit algorithm instead of silently probing undefined.
async function testCanVerifyInTlsRequiresLabelWhenUndeterminable() {
  var dir = _mkTmp();
  var probed = [];
  var eng = _p256CaEngine();
  eng.canVerifyInTls = async function (label) { probed.push(label); return true; };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: eng, caKeySealedMode: "disabled" });
  await ca.initCA();
  check("a P-256 custom CA reports algorithm null (runtime cannot classify it)", ca.status().algorithm === null);
  check("canVerifyInTls() with no argument refuses rather than probing an undeterminable algorithm",
        (await code2(function () { return ca.canVerifyInTls(); })) === "mtls-ca/algorithm-undeterminable");
  check("the engine was NOT probed with an undefined label", probed.indexOf(undefined) === -1);
  var ok = await ca.canVerifyInTls("ECDSA-P384-SHA384");     // an explicit algorithm still delegates
  check("canVerifyInTls(explicit) still delegates to the engine",
        ok === true && probed[probed.length - 1] === "ECDSA-P384-SHA384");
}

// Clustered operation (shared revocationStore + watermark, per-host dataDirs) also
// requires a shared issuanceStore: with the default per-host ledger, revokeGeneration()
// on one host cannot see certs issued on another, leaving them accepted by the shared
// gate. Refuse the fail-open split at construction.
async function testClusteredRevocationStoreRequiresSharedIssuanceStore() {
  function clusteredRevStore() {
    return {
      list: function () { return []; }, add: function () {},
      readGenerationWatermark: function () { return 0; },
      bumpGenerationWatermark: function () {},
    };
  }
  check("a clustered revocationStore without a shared issuanceStore is refused at construction",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: clusteredRevStore() });
        }) === "mtls-ca/bad-issuance-store");
  check("a clustered revocationStore WITH a shared issuanceStore is accepted",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
            revocationStore: clusteredRevStore(),
            issuanceStore: { list: function () { return []; }, add: function () {} } });
        }) === "NO-THROW");
  check("a non-clustered revocationStore still accepts the default per-host ledger",
        code(function () {
          b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
            revocationStore: { list: function () { return []; }, add: function () {} } });
        }) === "NO-THROW");
}

// loadTrustBundle() must never advertise the same root twice: a degenerate state
// where ca.prev.crt == ca.crt (a crash-recovered rollback, or the mixed-snapshot
// race this guards) must dedup to a single-entry bundle rather than [cur, cur].
async function testLoadTrustBundleDedupsIdenticalRetainedRoot() {
  var ca = _newCa();
  await ca.initCA();
  var cur = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caCertPrev, cur);           // ca.prev.crt identical to ca.crt
  var bundle = (await ca.loadTrustBundle());
  check("loadTrustBundle dedups an identical retained root (no [cur, cur])",
        bundle.length === 1 && Buffer.from(bundle[0]).equals(cur));
  fs.rmSync(ca.paths.caCertPrev, { force: true });      // clear the fabricated dup before a real rotation
  await ca.rotate({ generation: 2 });                   // a genuinely-distinct retained root still appears
  check("loadTrustBundle returns [current, retained] for a real retained rotation",
        (await ca.loadTrustBundle()).length === 2);
}

// Only ONE retained grace window at a time: ca.prev.crt holds a single prior root,
// so a second RETAINED rotation would overwrite it and strand clients still under
// the first retained generation. Refuse it until the window is ended explicitly.
async function testRefuseConsecutiveRetainedRotations() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // retains gen-1
  check("a retained root exists after the first retained rotation", (await ca.loadTrustBundle()).length === 2);
  check("a second retained rotation is refused while a root is retained",
        (await code2(function () { return ca.rotate({ generation: 3 }); })) === "mtls-ca/retained-root-exists");
  check("the refused rotation left the CA at gen-2 with its retained root intact",
        ca.status().generation === 2 && (await ca.loadTrustBundle()).length === 2);
  // Ending the window (dropRetained) lets a retained rotation proceed.
  await ca.dropRetained();
  check("after dropRetained, a retained rotation proceeds",
        (await ca.rotate({ generation: 3 })).generation === 3);
  // rotate({ retainPrevious: false }) is always allowed (it hard-cuts the old root).
  await ca.rotate({ generation: 4, retainPrevious: false });
  check("a hard-cut rotation is allowed even while a root is retained", ca.status().generation === 4);
}

// A rotation must ABORT when an existing CA key cannot be captured for the rollback
// journal — proceeding would leave no way to restore the old key if the cert
// publish then fails, stranding the CA on a new-key/old-cert pair.
async function testRotateAbortsWhenPriorKeyUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caKey)) throw new Error("simulated transient key read failure");
    return realRead.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2 }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("rotation aborts when the prior key cannot be captured", codeSeen === "mtls-ca/prior-key-unreadable");
  check("the original key and cert are untouched after the aborted rotation",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the CA still issues after the aborted rotation",
        typeof (await ca.generateClientCert({ cn: "post-keyread-abort" })).cert === "string");
}

// loadTrustBundle() must include a retained root that a crashed rotation left only
// in the rollback journal (before any initCA()/rotate() reconciled it), so a
// restart that loads trust without first reconciling does not drop that cohort.
async function testLoadTrustBundleIncludesUnreconciledJournalRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  var keyG3 = fs.readFileSync(ca.paths.caKey);
  // Fabricate a crashed retainPrevious:false rotation (gen-2 -> gen-3) that
  // journaled gen-1 as the root to restore, then unlinked ca.prev.crt, then died
  // before publishing the cert: the live cert is gen-2, ca.prev.crt is gone, and
  // the journal holds gen-1.
  fs.writeFileSync(ca.paths.caKey, keyG3);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: keyG2.toString("base64"), cert: certG2.toString("base64"),  // live cert == journal's prior cert => interrupted
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = (await reopened.loadTrustBundle());                   // called BEFORE any initCA reconcile
  check("loadTrustBundle includes the current cert and the journal's retained root (no dropped cohort)",
        bundle.length === 2 &&
        Buffer.from(bundle[0]).equals(certG2) && Buffer.from(bundle[1]).equals(certG1));
}

// A SPENT journal — the rotation COMPLETED (including a hard cutoff) but its delete
// failed, so the live cert differs from the journal's recorded prior cert — must
// NOT re-trust its old retained root, which would defeat the completed cutoff and
// which dropRetained() cannot clear.
async function testLoadTrustBundleExcludesSpentJournalRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });                        // gen-3 active, gen-2 retained
  // Leftover SPENT journal from a completed hard-cut rotation: its recorded prior
  // cert is gen-2, but the live cert is gen-3, so the rotation republished
  // (completed). The key bytes are irrelevant to the trust-bundle read.
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: fs.readFileSync(ca.paths.caKey).toString("base64"), cert: certG2.toString("base64"),
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = (await reopened.loadTrustBundle());
  check("loadTrustBundle excludes a spent journal's old retained root (hard cutoff respected)",
        bundle.every(function (c) { return !Buffer.from(c).equals(certG1); }));
}

// loadTrustBundle() reads the crash journal WITHOUT reconciling, so its retained-root check must
// fail closed for a COMPLETED byte-identical HARD CUT: a hard cut that re-committed the same-bytes
// current CA leaves the live cert EQUAL to the journal's prior cert, so the cert-identity discriminator
// (used to exclude a cert-CHANGING spent journal) can't tell completed from interrupted. Re-trusting
// the prevData root would resurrect the root the operator hard-cut (fail-OPEN). Exclude it via retainAfter.
async function testLoadTrustBundleExcludesSpentHardCutRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1, window open
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  // A COMPLETED byte-identical hard cut whose journal delete failed: prev REMOVED, live cert still
  // gen-2 (== journal's prior cert), journal records retainAfter:false + prevAction:restore + gen-1.
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG2, newKey: keyG2, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = await reopened.loadTrustBundle();             // read BEFORE any mutating op reconciles
  check("loadTrustBundle does NOT re-trust a hard-cut root from a spent byte-identical hard-cut journal",
        bundle.length === 1 && Buffer.from(bundle[0]).equals(certG2));
}

// A hard-cut rotation whose cert publish fails AND whose in-memory retained-root
// rollback also fails must KEEP the journal (not delete it on a successful key
// rollback alone), so a later reconcile restores the retained root from the
// journal's prevData rather than permanently losing that cohort's trust.
async function testPartialRollbackKeepsJournalForRetainedRoot() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained (ca.prev.crt = gen-1)
  var certG2 = fs.readFileSync(ca.paths.caCert);
  // A hard-cut rotation to gen-3 that (a) fails the cert publish and (b) fails to
  // restore ca.prev.crt during rollback: key rollback succeeds, prev rollback does
  // not. The journal must survive so the retained root is recoverable.
  var realRename = atomicFile.renameWithRetry;
  var realWrite  = atomicFile.writeSync;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert rename failure");
    return realRename.apply(this, arguments);
  };
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated retained-root restore failure");
    return realWrite.apply(this, arguments);
  };
  var failed = false;
  try {
    try { await ca.rotate({ generation: 3, retainPrevious: false }); } catch (_e) { failed = true; }
  } finally { atomicFile.renameWithRetry = realRename; atomicFile.writeSync = realWrite; }
  check("the hard-cut rotation with a failed cert publish is rejected", failed);
  check("the rollback journal is preserved when the retained-root restore failed",
        fs.existsSync(ca.paths.caKey + ".rollback") === true);
  // A fresh handle reconciles: the live cert still equals the journal's prior cert
  // (gen-2, never republished), so it rolls back and restores gen-1 as the root.
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile restored the retained root from the preserved journal",
        fs.existsSync(reopened.paths.caCertPrev) && fs.readFileSync(reopened.paths.caCertPrev).equals(certG1));
  check("the recovered CA still issues under gen-2",
        typeof (await reopened.generateClientCert({ cn: "post-partial-rollback" })).cert === "string" &&
        fs.readFileSync(reopened.paths.caCert).equals(certG2));
}

// The rollback journal must hold a COMPLETE snapshot of the pre-rotation state.
// If the existing current cert cannot be read for the journal's prior-cert marker,
// commit() aborts before mutating — otherwise a cert:null journal would break the
// interrupted-vs-completed comparison and mis-reconcile the retained root.
async function testCommitAbortsWhenPriorCertUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  var fresh = await engine.generateCa({ generation: 2 });
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCert)) throw new Error("simulated prior-cert read failure");
    return realRead.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("commit aborts when the prior cert cannot be captured", codeSeen === "mtls-ca/prior-cert-unreadable");
  check("the CA still issues after the aborted commit (untouched)",
        typeof (await ca.generateClientCert({ cn: "post-cert-abort" })).cert === "string");
}

// If an existing retained root cannot be read for the rollback journal, commit()
// aborts before mutating — otherwise a failed hard-cut rotation could remove it
// with neither the catch nor a reconcile able to restore it, permanently stranding
// clients in the existing grace window.
async function testCommitAbortsWhenPriorRetainedRootUnreadable() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // ca.prev.crt = gen-1
  var fresh = await engine.generateCa({ generation: 3 });
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.caCertPrev)) throw new Error("simulated prior-retained-root read failure");
    return realRead.apply(this, arguments);
  };
  // Hard-cut (retainPrevious:false) is the scenario the abort protects: it needs the
  // prior retained root for its rollback, so an unreadable one must abort before
  // mutating. (An omitted retainPrevious would be refused earlier as ambiguous.)
  var codeSeen;
  try {
    codeSeen = await code2(function () {
      return ca.commit({ caKeyPem: fresh.caKeyPem, caCertPem: fresh.caCertPem, retainPrevious: false });
    });
  }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("commit aborts when the prior retained root cannot be captured",
        codeSeen === "mtls-ca/prior-retained-root-unreadable");
  check("the retained root and CA survive the aborted commit",
        (await ca.loadTrustBundle()).length === 2 &&
        typeof (await ca.generateClientCert({ cn: "post-prev-abort" })).cert === "string");
}

// dropRetained() must reconcile an interrupted rotation's journal under its lock
// before removing the retained root — otherwise a crashed hard-cut rotation (which
// removed ca.prev.crt but left a journal whose recorded root loadTrustBundle()
// still trusts) would survive dropRetained(), so the grace window never ends.
async function testDropRetainedReconcilesInterruptedJournal() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  // Fabricate an interrupted hard-cut rotation (gen-2 -> gen-3): a consistent gen-2
  // pair on disk, ca.prev.crt gone, and a journal (prior cert gen-2 == live cert)
  // holding gen-1 as the root to restore.
  fs.writeFileSync(ca.paths.caKey, keyG2);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: keyG2.toString("base64"), cert: certG2.toString("base64"),
    prevAction: "restore", prevData: certG1.toString("base64"),
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("interrupted journal surfaces the retained root before dropRetained",
        (await reopened.loadTrustBundle()).some(function (c) { return Buffer.from(c).equals(certG1); }));
  await reopened.dropRetained();
  check("dropRetained reconciles the journal and truly ends the grace window",
        (await reopened.loadTrustBundle()).every(function (c) { return !Buffer.from(c).equals(certG1); }) &&
        fs.existsSync(reopened.paths.caKey + ".rollback") === false);
}

// Reconcile must restore the prior key by BYTES, not gate on _caPairConsistent —
// which returns true for a custom-engine cert/key node cannot parse, so gating on
// it would skip the restore and strand (then permanently brick) a custom-engine CA.
async function testCustomEngineReconcileRestoresKeyByBytes() {
  var dir = _mkTmp();
  var opaqueEngine = {   // node cannot parse these -> _caPairConsistent would say "consistent"
    generateCa: async function (a) {
      return { caCertPem: "OPAQUE-CERT-gen" + a.generation, caKeyPem: "OPAQUE-KEY-gen" + a.generation };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: opaqueEngine, caKeySealedMode: "disabled" });
  await ca.initCA();
  var oldKey  = fs.readFileSync(ca.paths.caKey);
  var oldCert = fs.readFileSync(ca.paths.caCert);
  var newKey  = Buffer.from("OPAQUE-KEY-gen2-NEW");
  // Crash after the key rename, before the cert rename: new key beside old cert.
  fs.writeFileSync(ca.paths.caKey, newKey);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: oldKey, newKey: newKey, cert: oldCert, retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, engine: opaqueEngine, caKeySealedMode: "disabled" });
  await reopened.initCA();   // triggers the locked reconcile
  check("custom-engine reconcile restores the prior key by BYTES (not gated on _caPairConsistent)",
        fs.readFileSync(reopened.paths.caKey).equals(oldKey));
  check("the custom-engine interrupted rotation rolled back the cert unchanged",
        fs.readFileSync(reopened.paths.caCert).equals(oldCert));
}

// An UNPINNED rotation over an existing CA must PRESERVE the stored algorithm, not
// silently adopt the engine default (ML-DSA-87) — otherwise a bare generation bump
// would flip a classical ECDSA CA to ML-DSA and reject legacy peers.
async function testUnpinnedRotatePreservesStoredAlgorithm() {
  var dir = _mkTmp();
  var pinned = b.mtlsCa.create({ dataDir: dir, algorithm: "ECDSA-P384-SHA384", caKeySealedMode: "disabled" });
  await pinned.initCA();
  check("stored CA is ECDSA before rotation", pinned.status().algorithm === "ECDSA-P384-SHA384");
  var unpinned = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // no create-time pin
  var r = await unpinned.rotate({ generation: 2 });                                 // unpinned rotate
  check("unpinned rotate over an ECDSA CA stays ECDSA (no silent flip to ML-DSA)",
        r.algorithm === "ECDSA-P384-SHA384" && unpinned.status().algorithm === "ECDSA-P384-SHA384");
  check("the rotated ECDSA CA still issues",
        typeof (await unpinned.generateClientCert({ cn: "post-unpinned-rotate" })).cert === "string");
}

// A hard-cut rotation supersedes the old generation like revokeGeneration: an
// issuance that straddles it (signed under the now-untrusted old generation) must
// self-revoke rather than return an un-verifiable leaf.
async function testHardCutRotationSupersedesStraddlingIssuance() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var issuing = ca.generateClientCert({ cn: "straddle" });   // blocks in signing under gen-1
  await ca.rotate({ generation: 2, retainPrevious: false }); // hard cut supersedes gen-1
  release();
  check("a leaf straddling a hard-cut rotation self-revokes (issuance-superseded)",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A leaf whose signing began under a generation that is then RETAINED-rotated and
// dropRetained() before issuance finishes chains to a root no longer in the trust
// bundle — it must self-revoke rather than return un-verifiable.
async function testDropRetainedSupersedesStraddlingIssuance() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    signClientCert: async function (a) { await barrier; return engine.signClientCert(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var issuing = ca.generateClientCert({ cn: "straddle-drop" }); // signs under gen-1, blocks
  await ca.rotate({ generation: 2 });                        // gen-1 becomes the retained root
  await ca.dropRetained();                                   // removes gen-1 entirely
  release();
  check("a leaf straddling a rotate + dropRetained (its root dropped) self-revokes",
        (await code2(function () { return issuing; })) === "mtls-ca/issuance-superseded");
}

// A leaf issued under the CURRENT generation with no concurrent removal is NOT
// falsely superseded (its root stays in the trust bundle).
async function testNormalIssuanceNotFalselySuperseded() {
  var ca = _newCa();
  await ca.initCA();
  check("a normal issuance under the current CA is not falsely superseded",
        typeof (await ca.generateClientCert({ cn: "normal" })).cert === "string");
  await ca.rotate({ generation: 2 });   // retained rotation keeps gen-1 in the bundle
  check("issuance under the new generation after a retained rotation is not superseded",
        typeof (await ca.generateClientCert({ cn: "normal-2" })).cert === "string");
}

// Concurrent first-time inits must converge on ONE CA (serialized), not each
// generate a CA and clobber one another (orphaning the loser's just-issued leaf).
async function testConcurrentFirstInitDoesNotClobber() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var genCount = 0;
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (a) { genCount += 1; await barrier; return engine.generateCa(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  var p1 = ca.initCA();
  var p2 = ca.initCA();
  release();
  var r1 = await p1; var r2 = await p2;
  check("concurrent first inits converge on ONE CA (no clobber)", r1.caCertPem === r2.caCertPem);
  check("first-time creation is serialized (one keygen, not two)", genCount === 1);
  check("the CA issues after concurrent init",
        typeof (await ca.generateClientCert({ cn: "post-concurrent-init" })).cert === "string");
}

// A COMPLETED rotation whose key rename didn't durably stick (a Windows/FUSE
// fsyncDir no-op) must be FINISHED from the journal's new key, not left on an
// old-key/new-cert pair the OLD-key-only journal could not repair.
async function testReconcileFinishesCompletedRotationWithLostKey() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1 = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  var certG2 = fs.readFileSync(ca.paths.caCert);
  // Completed gen-1 -> gen-2 (live cert = gen-2) but the key rename was lost (old key).
  fs.writeFileSync(ca.paths.caKey, keyG1);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile finishes a completed rotation whose key rename was lost (restores the new key)",
        fs.readFileSync(reopened.paths.caKey).equals(keyG2) && fs.readFileSync(reopened.paths.caCert).equals(certG2));
  check("the finished CA issues",
        typeof (await reopened.generateClientCert({ cn: "post-lost-key" })).cert === "string");
}

// A COMPLETED hard-cut rotation whose ca.prev.crt unlink didn't durably stick must
// have the resurrected root REMOVED on reconcile — else loadTrustBundle keeps
// trusting a root the operator hard-cut.
async function testReconcileRemovesResurrectedHardCutRoot() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  var keyG3 = fs.readFileSync(ca.paths.caKey);
  // Completed hard-cut gen-2 -> gen-3 (live cert = gen-3, retainAfter false) but the
  // ca.prev.crt unlink was lost: gen-1 resurrected as the retained root.
  fs.writeFileSync(ca.paths.caCertPrev, certG1);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG2, newKey: keyG3, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();
  check("reconcile removes a resurrected hard-cut root on a completed rotation",
        fs.existsSync(reopened.paths.caCertPrev) === false &&
        (await reopened.loadTrustBundle()).every(function (c) { return !Buffer.from(c).equals(certG1); }));
}

// The single-retained-window invariant must hold on EVERY retention entry point,
// including the public commit() path (which calls _commitLocked directly) — not
// just rotate(). Two retained commits without ending the window between them would
// otherwise overwrite the retained root and strand the first cohort.
async function testPublicCommitEnforcesSingleRetainedWindow() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();                                          // gen-1, no retained root
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: true });   // retains gen-1
  check("first retained public commit creates a retained root", (await ca.loadTrustBundle()).length === 2);
  var g3 = await engine.generateCa({ generation: 3 });
  check("a second retained public commit is refused (single window)",
        await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: true }); })
          === "mtls-ca/retained-root-exists");
  check("the refused commit left the retained root intact", (await ca.loadTrustBundle()).length === 2);
}

// A default-engine handle with NO CA stored yet and no pin must probe the engine
// default on a no-argument canVerifyInTls() (the documented fresh-deployment
// pre-flight), NOT refuse with algorithm-undeterminable — an omitted label is
// unambiguous when there is no stored CA to mismatch.
async function testCanVerifyInTlsProbesDefaultBeforeInit() {
  var ca = _newCa();   // default engine, NOT initialized, no create-time pin
  check("no CA is stored yet", ca.status().exists === false);
  var codeSeen = await code2(function () { return ca.canVerifyInTls(); });
  check("canVerifyInTls() before init does not refuse with algorithm-undeterminable",
        codeSeen !== "mtls-ca/algorithm-undeterminable");
  var ok = await ca.canVerifyInTls();
  check("canVerifyInTls() before init probes the default engine (returns a boolean)", typeof ok === "boolean");
}

// The reconcile's journal deletion is NOT best-effort: if it fails, the caller
// (here dropRetained) must fail closed, because a surviving interrupted journal
// would let loadTrustBundle() re-trust its saved root and undo the cutoff.
async function testReconcileJournalDeletionFailurePropagates() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var certG2 = fs.readFileSync(ca.paths.caCert);
  var keyG2  = fs.readFileSync(ca.paths.caKey);
  await ca.dropRetained();
  await ca.rotate({ generation: 3 });
  // Interrupted hard-cut journal: consistent gen-2 pair, ca.prev.crt gone, journal
  // holds gen-1 as the root to restore.
  fs.writeFileSync(ca.paths.caKey, keyG2);
  fs.writeFileSync(ca.paths.caCert, certG2);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  var journal = ca.paths.caKey + ".rollback";
  fs.writeFileSync(journal, _journalManifest({
    key: keyG2, newKey: keyG2, cert: certG2, retainAfter: false, prevAction: "restore", prevData: certG1,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) throw new Error("simulated journal deletion failure");
    return realUnlink.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return reopened.dropRetained(); }); }
  finally { fs.unlinkSync = realUnlink; }
  check("dropRetained fails closed when the reconcile journal deletion fails", codeSeen !== "NO-THROW");
  check("the interrupted journal survives the failed deletion (not silently completed)",
        fs.existsSync(journal) === true);
}

// The public commit() is the LOCKED commit primitive (migration docs direct
// operators to it), so it returns a promise — it takes the rotation lock to
// serialize with a concurrent rotate/init over the same dataDir.
async function testPublicCommitIsLockedPromise() {
  var ca = _newCa();
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });
  var p = ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("public commit() returns a promise (the locked primitive)", p && typeof p.then === "function");
  await p;
  check("the committed CA issues", typeof (await ca.generateClientCert({ cn: "post-public-commit" })).cert === "string");
  // Bad input still throws synchronously (a config-time typo), before the lock.
  check("public commit() validates its argument shape synchronously",
        code(function () { ca.commit({}); }) === "mtls-ca/bad-commit");
}

// A persisted CRL is signed by the CA that produced it; after a rotation it is
// signed by the SUPERSEDED issuer, so rotation must invalidate it (a consumer
// serving the path must not publish a CRL the new CA cannot authenticate).
async function testRotationInvalidatesStaleCrl() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl signed by gen-1
  check("a CRL is persisted before rotation", fs.existsSync(ca.paths.crl) === true);
  await ca.rotate({ generation: 2 });
  check("rotation invalidates the stale CRL signed by the superseded CA",
        fs.existsSync(ca.paths.crl) === false);
  await ca.generateCrl();                                     // operator regenerates under the new CA
  check("generateCrl re-signs the CRL under the new CA after rotation", fs.existsSync(ca.paths.crl) === true);
}

// The public commit() must reconcile a leftover journal FIRST (as rotate does),
// so a crash-left new-key/old-cert state is rolled back before the new commit —
// otherwise the commit records the ORPHANED new key as its prior key and a failed
// publish would roll back to that orphan, losing the actual matching old key.
async function testPublicCommitReconcilesLeftoverJournalFirst() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var keyG1 = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  await ca.rotate({ generation: 2 });
  var keyG2 = fs.readFileSync(ca.paths.caKey);
  // Crashed gen-1 -> gen-2: new key (gen-2) beside old cert (gen-1); journal holds gen-1.
  fs.writeFileSync(ca.paths.caCert, certG1);
  fs.rmSync(ca.paths.caCertPrev, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG2, cert: certG1, retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var g3 = await engine.generateCa({ generation: 3 });
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("public commit whose publish failed rolled back to the ACTUAL gen-1 key (reconciled first)",
        codeSeen === "mtls-ca/commit-failed" && fs.readFileSync(ca.paths.caKey).equals(keyG1));
  check("the CA still issues under the recovered gen-1",
        typeof (await ca.generateClientCert({ cn: "post-public-commit-fail" })).cert === "string");
}

// rotate()'s CAS check (is the current cert still the one snapshotted before generateCa?) must
// compare cert IDENTITY, not exact PEM text: a concurrent idempotent commit() that merely
// REFORMATTED the same cert (CRLF, trailing newline) during generateCa must NOT abort the rotation
// with mtls-ca/rotation-conflict — the issuer and generation are unchanged.
async function testRotationCasToleratesReformattedConcurrentCommit() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var reachedBarrier = false;
  var slowActive = false;                                            // slow ONLY the rotate's generateCa, not initCA's
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (a) { if (slowActive) { reachedBarrier = true; await barrier; } return engine.generateCa(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  var sameCert = ca.loadCert().toString("utf8");
  var sameKey  = ca.loadKey().toString("utf8");
  slowActive = true;
  var rotatePromise = ca.rotate({ generation: 2 });                 // snapshots the gen-1 cert, then blocks in generateCa
  // Wait until the rotation has snapshotted the cert and reached generateCa, THEN idempotently
  // recommit the SAME cert REFORMATTED (so the rotation's snapshot is the ORIGINAL bytes).
  await helpers.waitUntil(function () { return reachedBarrier; },
    { timeoutMs: 5000, label: "rotation-cas: rotate reached generateCa" });
  await ca.commit({ caKeyPem: sameKey, caCertPem: sameCert.replace(/\n/g, "\r\n") + "\n", retainPrevious: false });
  release();
  var code = await code2(function () { return rotatePromise; });
  check("a rotation is NOT aborted by a concurrent idempotent commit that only reformatted the same cert",
        code === "NO-THROW");
}

// The documented rotate() result carries the migration algorithm operators persist.
// For a CUSTOM engine, _certAlgorithm() only understands bundled labels — it would
// report a custom P-384 CA as ECDSA-P384-SHA384, or null for other custom certs.
// The effective label (the explicit rotate({algorithm}), else the create-time pin)
// must be returned instead; certificate inference is reserved for the bundled engine.
async function testRotateReturnsEffectiveCustomEngineLabel() {
  // Explicit rotate({ algorithm }): return the requested custom label, not the
  // bundled cert inference (this P-384/SHA-384 cert would infer ECDSA-P384-SHA384).
  var caA = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p384CaEngine() });
  await caA.initCA();
  var rA = await caA.rotate({ generation: 2, algorithm: "CUSTOM-P384" });
  check("rotate returns the requested custom-engine label, not the bundled cert inference",
        rA.algorithm === "CUSTOM-P384");

  // No rotate({ algorithm }): the effective label is the retained create-time pin.
  // A P-256 custom cert infers to null, so a caller would otherwise record null for
  // a migration whose algorithm is in fact known (the handle's pin).
  var caB = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", algorithm: "CUSTOM-P256", engine: _p256CaEngine() });
  await caB.initCA();
  var rB = await caB.rotate({ generation: 2 });
  check("an unpinned-rotate custom engine returns the retained create-time label, not null",
        rB.algorithm === "CUSTOM-P256");

  // No rotate({ algorithm }) AND no create-time pin: the custom label is genuinely
  // unknown, so the result is null rather than a bundled cert inference.
  var caD = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngine() });
  await caD.initCA();
  var rD = await caD.rotate({ generation: 2 });
  check("an unpinned custom engine with no pin reports a null migration algorithm",
        rD.algorithm === null);

  // The bundled engine still infers from the freshly-issued cert (authoritative — the
  // engine chose the key type), so a default-engine rotate keeps reporting ML-DSA-87.
  var caC = _newCa();
  await caC.initCA();
  var rC = await caC.rotate({ generation: 2 });
  check("a bundled-engine rotate still reports the inferred cert algorithm",
        rC.algorithm === "ML-DSA-87");
}

// generateCrl() must not persist a CRL signed by a CA that ROTATED while it was
// signing — that would recreate the stale-issuer artifact the rotation invalidated.
async function testGenerateCrlSkipsPersistIfCaRotated() {
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { await barrier; return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1
  var crlPromise = ca.generateCrl();                          // signs under gen-1, blocks
  await ca.rotate({ generation: 2 });                         // CA rotates during signing
  release();
  var result = await crlPromise;
  check("generateCrl does NOT persist a CRL signed by a CA that rotated during signing",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
}

// generateCrl() must not persist a CRL whose revocation snapshot a concurrent revoke()/
// revokeGeneration() has already superseded — a revocation that COMPLETED (returned
// success) while we awaited engine.generateCrl() would be dropped from the published CRL,
// so CRL-based clients keep accepting the revoked certificate until the next regeneration.
async function testGenerateCrlSkipsPersistIfRevocationLandedDuringSigning() {
  var duringSign = null;                                       // fires AFTER the snapshot, during signing
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) {
      if (duringSign) { var f = duringSign; duringSign = null; await f(); }
      return engine.generateCrl(a);
    },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  await ca.revoke("01");                                      // one revocation in the snapshot
  duringSign = async function () { await ca.revoke("02"); };  // a revocation COMPLETES during signing
  var result = await ca.generateCrl();                        // snapshots {01}, revokes 02 mid-sign
  check("generateCrl does NOT persist a CRL whose snapshot a concurrent revocation superseded",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
  // A clean regeneration (no concurrent write) publishes a CRL covering every revocation.
  var result2 = await ca.generateCrl();
  check("a clean regeneration persists a CRL covering every completed revocation",
        result2.persisted === true && result2.entryCount === 2 && fs.existsSync(ca.paths.crl) === true);
}

// A NORMAL generateClientCert() completing during signing appends an unrelated fresh serial to the
// issuance ledger (advancing its version()) but does NOT change the CRL's issuer-scoped serial set,
// so the persist must NOT spuriously skip — a coarse version compare would starve CRL publishing on a
// busy CA, leaving a revoked serial's CRL stale for external consumers.
async function testGenerateCrlPersistsDespiteConcurrentNormalIssuance() {
  var duringSign = null;
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { if (duringSign) { var f = duringSign; duringSign = null; await f(); } return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  await ca.revoke("01");
  duringSign = async function () { await ca.generateClientCert({ cn: "concurrent-issue" }); };
  var result = await ca.generateCrl();
  check("generateCrl persists despite a concurrent normal issuance during signing (CRL content unchanged)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// A FINGERPRINT-ONLY revoke() completing during signing adds no serial — it is never in a serial-keyed
// CRL — so the persist must NOT spuriously skip on the advanced revocation version().
async function testGenerateCrlPersistsDespiteConcurrentFingerprintRevoke() {
  var duringSign = null;
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { if (duringSign) { var f = duringSign; duringSign = null; await f(); } return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  await ca.revoke("01");
  duringSign = async function () { await ca.revoke({ fingerprint: "ab".repeat(64) }); };
  var result = await ca.generateCrl();
  check("generateCrl persists despite a concurrent fingerprint-only revoke during signing (not in a serial CRL)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// Exercises the scoped-serial persist fallback (_scopedCrlSerials) over a RICH revocation/issuance
// set: a fingerprint-bearing revocation (resolved via the fingerprint map), a duplicate serial (the
// dedup), and an imported entry with no caCert (caFingerprint null, skipped). A concurrent normal
// issuance during signing forces the fallback, which must still persist (the CRL content is unchanged).
async function testGenerateCrlScopedSerialsFallbackCoversRichState() {
  var duringSign = null;
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { if (duringSign) { var f = duringSign; duringSign = null; await f(); } return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "rich" });                          // issuance: serial+fingerprint+caFingerprint
  await ca.revoke({ serial: leaf.serialNumber, fingerprint: leaf.fingerprint });   // fingerprint-bearing revocation
  await ca.revoke(leaf.serialNumber);                                              // duplicate serial (serial-only)
  await ca.importIssuance([{ fingerprint: "ab".repeat(64), generation: 1 }]);      // no caCert -> caFingerprint null
  duringSign = async function () { await ca.generateClientCert({ cn: "concurrent" }); };
  var result = await ca.generateCrl();
  check("generateCrl persists with a rich revocation/issuance set despite concurrent issuance (scoped-serial fallback)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// The persist re-check must recompute the CRL scope from ONE coherent view of BOTH fresh stores, not
// each store against the other's stale snapshot. A revoke({ serial: X, fingerprint: newFp }) plus an
// importIssuance mapping newFp to the CURRENT issuer, both landing during signing, only reveal that X
// now belongs in the CRL when the fresh revocation and fresh issuance are combined — each single-fresh
// check still excludes X. Publishing the signed (X-omitting) CRL there would drop a revoked serial.
async function testGenerateCrlPersistRecomputesFromCoherentStoreView() {
  var duringSign = null;
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) { if (duringSign) { var f = duringSign; duringSign = null; await f(); } return engine.generateCrl(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();
  var other = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: engine });
  await other.initCA();
  var otherCaCert   = fs.readFileSync(other.paths.caCert, "utf8");
  var currentCaCert = fs.readFileSync(ca.paths.caCert, "utf8");
  var X = "0a1b", oldFp = "aa".repeat(64), newFp = "bb".repeat(64);
  // Pre-existing issuance maps serial X to the OTHER (non-current) issuer, so a serial-only resolution
  // of X excludes it from THIS CA's CRL.
  await ca.importIssuance([{ fingerprint: oldFp, serialNumber: X, generation: 1, caCert: otherCaCert }]);
  duringSign = async function () {
    await ca.revoke({ serial: X, fingerprint: newFp });
    await ca.importIssuance([{ fingerprint: newFp, serialNumber: X, generation: 1, caCert: currentCaCert }]);
  };
  var result = await ca.generateCrl();
  check("generateCrl does NOT publish a CRL whose scope changed under a combined fresh revocation+issuance view",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
  // The operator's next generateCrl (no concurrency) sees X mapped to the current issuer and includes it.
  var result2 = await ca.generateCrl();
  check("the regenerated CRL includes the now-current-issuer serial X", result2.persisted === true && result2.entryCount === 1);
}

// generateCrl() reads the issuance ledger ONCE to resolve each revocation's issuing CA
// (issuer-scoping). If importIssuance() backfills a revoked serial's issuer as a DIFFERENT
// (old) CA while the engine signs, a persist that rechecks only the CA + revocation-store
// version publishes the stale CRL — which still lists that old-issuer serial, false-revoking
// an unrelated current cert that reused the serial. The issuance ledger must be version-checked
// (or serialized) at publication too.
async function testGenerateCrlSkipsPersistIfIssuerBackfilledDuringSigning() {
  var duringSign = null;                                       // fires AFTER the snapshot, during signing
  var slowEngine = Object.assign({}, engine, {
    generateCrl: async function (a) {
      if (duringSign) { var f = duringSign; duringSign = null; await f(); }
      return engine.generateCrl(a);
    },
  });
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                           // gen-1 = the OLD issuer
  var oldCaPem = ca.loadCert().toString("utf8");
  await ca.rotate({ generation: 2 });                          // gen-2 = the current issuer
  await ca.revoke("aa");                                       // serial-only; issuer undeterminable at snapshot -> included
  // During signing, backfill serial "aa"'s issuer as the OLD (gen-1) CA. Had the ledger been
  // read AFTER, "aa" would map to a different issuer and be EXCLUDED from this current-CA CRL.
  duringSign = async function () {
    await ca.importIssuance([{ serialNumber: "aa", fingerprint: "ee".repeat(64), caCert: oldCaPem, generation: 1 }]);
  };
  var result = await ca.generateCrl();                         // snapshots the ledger, backfills mid-sign
  check("generateCrl does NOT persist a CRL whose issuance snapshot a concurrent issuer-backfill superseded",
        result.persisted === false && fs.existsSync(ca.paths.crl) === false);
  // A clean regeneration now reads the backfilled ledger, scopes "aa" to the old issuer, excludes
  // it from the current-CA CRL, and persists (an issuer-scoped-empty CRL is still valid).
  var result2 = await ca.generateCrl();
  check("a clean regeneration excludes the old-issuer serial and persists",
        result2.persisted === true && result2.entryCount === 0 && fs.existsSync(ca.paths.crl) === true);
}

// generateCrl() with a bring-your-own revocationStore (no version() signal) persists
// directly: the framework does not own that store's write lock, so there is no version to
// compare against a concurrent revoke() — the operator owns that store's concurrency. This
// exercises the custom-store snapshot and persist paths (no under-lock version re-check).
async function testGenerateCrlPersistsWithCustomRevocationStore() {
  var entries = [];
  var customStore = { list: function () { return entries.slice(); },
                      add: function (e) { entries.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: customStore });
  await ca.initCA();
  await ca.revoke("0a");
  var result = await ca.generateCrl();
  check("generateCrl persists with a custom revocationStore (no version signal, operator-owned concurrency)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// generateCrl() with a bring-your-own issuanceStore (no version() signal) issuer-scopes and
// persists directly: the framework owns no lock on that store, so there is no version to compare
// against a concurrent importIssuance() — the operator owns its concurrency. Exercises the custom
// issuance-store snapshot + persist arms (no under-lock version re-check).
async function testGenerateCrlPersistsWithCustomIssuanceStore() {
  var issued = [];
  var customIssuance = { list: function () { return issued.slice(); },
                         add: function (e) { issued.push(e); } };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: customIssuance });
  await ca.initCA();
  await ca.revoke("0b");
  var result = await ca.generateCrl();
  check("generateCrl persists with a custom issuanceStore (no version signal, operator-owned concurrency)",
        result.persisted === true && result.entryCount === 1 && fs.existsSync(ca.paths.crl) === true);
}

// A pinned ECDSA handle's in-flight generateClientCert() snapshots the ECDSA CA via
// initCA(); a public commit({ retainPrevious: true }) that installs an ML-DSA CA runs (and
// synchronously refreshes the handle's closed-over algorithm pin) BEFORE the suspended
// issuance reads that pin. The leaf MUST bind to the SNAPSHOTTED ECDSA CA — not the
// refreshed ML-DSA pin — else an ML-DSA leaf is minted under the retained ECDSA root and the
// grace window's legacy peers (the whole reason the root is retained) cannot authenticate it.
// commit()'s rename + pin refresh run synchronously inside atomicFile.lock, so the pin is
// already ML-DSA by the time the issuance's _leafEngineArgs microtask runs — a deterministic
// reproduction of the race, not a timing-dependent flake.
async function testLeafAlgorithmBindsToSnapshotNotRacingPinRefresh() {
  var ca = _newCa({ algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  check("precondition: the pinned handle stored an ECDSA CA",
        ca.status().algorithm === "ECDSA-P384-SHA384");
  var mldsa = await engine.generateCa({ generation: 2 });      // a default (ML-DSA-87) CA
  var certPromise = ca.generateClientCert({ cn: "legacy-peer" });   // snapshots the ECDSA pair
  await ca.commit({ caKeyPem: mldsa.caKeyPem, caCertPem: mldsa.caCertPem, retainPrevious: true });
  var result = await certPromise;
  var leafType = new nodeCrypto.X509Certificate(result.cert).publicKey.asymmetricKeyType;
  check("a leaf issued while commit() refreshes the pin binds to the snapshotted ECDSA CA (ec), not the ML-DSA pin",
        leafType === "ec");
}

// For a custom engine, both status() and canVerifyInTls() must report the persisted custom label,
// not _certAlgorithm's bundled inference — the engine may use a custom label ("CUSTOM-PQC-LABEL")
// for a standard key type (here ML-DSA), and only the persisted label / create-time pin carries it.
async function testCanVerifyInTlsPrefersCustomPinOverInferredLabel() {
  var dir = _mkTmp();
  var probed = [];
  var eng = {
    generateCa:     async function (a) { return engine.generateCa({ generation: a.generation }); },
    signClientCert: engine.signClientCert,
    canVerifyInTls: async function (label) { probed.push(label); return true; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, engine: eng, algorithm: "CUSTOM-PQC-LABEL", caKeySealedMode: "disabled" });
  await ca.initCA();
  check("status() reports the persisted custom label, not the bundled inference (ML-DSA-87)",
        ca.status().algorithm === "CUSTOM-PQC-LABEL");
  await ca.canVerifyInTls();
  check("canVerifyInTls() passes the custom engine's create-time pin, not the inferred bundled label",
        probed[probed.length - 1] === "CUSTOM-PQC-LABEL");
}

// CRL invalidation is part of the commit (under the lock), so the public commit()
// path — not just rotate() — invalidates a persisted CRL when it republishes the CA.
async function testPublicCommitInvalidatesStaleCrl() {
  var ca = _newCa();
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl under gen-1
  check("a CRL is persisted before the public commit", fs.existsSync(ca.paths.crl) === true);
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("a public commit invalidates the stale CRL (the CA cert changed)",
        fs.existsSync(ca.paths.crl) === false);
}

// The rotation compare-and-swap must compare cert IDENTITY, not only the generation
// number: a public commit() that replaces the CA with a DIFFERENT cert at the SAME
// generation while rotate() awaits generateCa() must be detected, so the older
// rotation does not overwrite the later commit.
async function testRotationCasDetectsSameGenerationCommit() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    // Block only the ROTATION's keygen (gen >= 2), so initCA (gen-1) is not stalled.
    generateCa: async function (a) { if (a.generation >= 2) { await barrier; } return engine.generateCa(a); },
  });
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine });
  await ca.initCA();                                          // gen-1 (not blocked)
  var rotating = ca.rotate({ generation: 2 });               // reads gen-1, blocks in generateCa
  // A public commit (default engine) replaces the CA at the SAME generation-1 with a
  // DIFFERENT cert while the rotation is blocked.
  var handle2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var g1b = await engine.generateCa({ generation: 1 });
  await handle2.commit({ caKeyPem: g1b.caKeyPem, caCertPem: g1b.caCertPem, retainPrevious: false });
  release();
  check("the rotation CAS detects a same-generation public commit and refuses",
        (await code2(function () { return rotating; })) === "mtls-ca/rotation-conflict");
  check("the same-generation public commit survives (its cert is the active CA)",
        fs.readFileSync(handle2.paths.caCert).toString("utf8") === g1b.caCertPem);
}

// While a retained grace window is open (ca.prev.crt present), a public commit()
// that OMITS retainPrevious is ambiguous: outgoingCaCert is null (so the single-
// window guard does not fire) AND the hard-cut branch (retainPrevious === false)
// does not fire either, so the old retained root would be left untouched while the
// active cert is replaced — silently dropping trust for the just-superseded
// generation (its cert becomes neither the new current nor the retained root). The
// commit must refuse until the caller states its retention intent.
async function testPublicCommitRefusesRetentionAmbiguityWhileWindowOpen() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.rotate({ generation: 2 });                        // gen-2 active, gen-1 retained (window open)
  var activeBefore = fs.readFileSync(ca.paths.caCert).toString("utf8");   // the gen-2 cert
  check("a retained window is open before the ambiguous commit", (await ca.loadTrustBundle()).length === 2);
  var g3 = await engine.generateCa({ generation: 3 });
  check("a retainPrevious-omitted commit is refused while a grace window is open",
        (await code2(function () { return ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem }); }))
          === "mtls-ca/retention-intent-required");
  check("the refused commit left the active CA cert unchanged (no cohort silently dropped)",
        fs.readFileSync(ca.paths.caCert).toString("utf8") === activeBefore);
  check("both roots are still trusted after the refused commit", (await ca.loadTrustBundle()).length === 2);
  // An explicit retention intent (hard-cut) is still accepted and ends the window.
  await ca.commit({ caKeyPem: g3.caKeyPem, caCertPem: g3.caCertPem, retainPrevious: false });
  check("an explicit retainPrevious:false commit hard-cuts the window",
        fs.readFileSync(ca.paths.caCert).toString("utf8") === g3.caCertPem &&
        (await ca.loadTrustBundle()).length === 1);
}

// A rollback journal that exists but cannot be parsed (or is not a valid manifest)
// is the "rotation in progress / crashed" marker. A mutating open (commit/rotate)
// must NOT continue into _commitLocked — that would overwrite the ONLY durable copy
// of the prior key while snapshotting a possibly-orphaned live key, so a later failed
// publish could restore the orphan and permanently lose the matching key. Fail closed
// (the reconcile is idempotent, so the operator resolves the fault and retries).
async function testMutatingPathFailsClosedOnCorruptRollbackJournal() {
  // (a) Unparseable journal bytes -> a commit refuses.
  var dirA = _mkTmp();
  var caA = b.mtlsCa.create({ dataDir: dirA, caKeySealedMode: "disabled" });
  await caA.initCA();
  fs.writeFileSync(caA.paths.caKey + ".rollback", "not-json{{{");
  var reopenA = b.mtlsCa.create({ dataDir: dirA, caKeySealedMode: "disabled" });
  var g2a = await engine.generateCa({ generation: 2 });
  check("a mutating commit refuses while an UNPARSEABLE rollback journal is present",
        (await code2(function () {
          return reopenA.commit({ caKeyPem: g2a.caKeyPem, caCertPem: g2a.caCertPem, retainPrevious: false });
        })) === "mtls-ca/rollback-journal-corrupt");
  check("the unparseable journal is left intact for the operator to resolve",
        fs.existsSync(reopenA.paths.caKey + ".rollback") === true);
  // (b) Valid JSON but not a rollback manifest (missing the prior-key field) -> rotate refuses.
  var dirB = _mkTmp();
  var caB = b.mtlsCa.create({ dataDir: dirB, caKeySealedMode: "disabled" });
  await caB.initCA();
  fs.writeFileSync(caB.paths.caKey + ".rollback", JSON.stringify({ not: "a manifest" }));
  var reopenB = b.mtlsCa.create({ dataDir: dirB, caKeySealedMode: "disabled" });
  check("a rotate refuses while a schema-invalid rollback journal is present",
        (await code2(function () { return reopenB.rotate({ generation: 2 }); }))
          === "mtls-ca/rollback-journal-corrupt");
}

// Invalidating a persisted CRL is a REQUIRED part of a CA-changing commit (the release
// contract: a rotation invalidates the persisted CRL). The stale CRL is MOVED ASIDE
// before the cert publish; if that move fails (a read-only / separately-configured CRL
// directory), the commit must ABORT and roll the CA back — and the surviving CA's
// still-valid CRL must be left in place, not lost.
async function testRotationAbortsWhenStaleCrlCannotBeMovedAside() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();                                     // persists ca.crl under gen-1
  var crlBefore = fs.readFileSync(ca.paths.crl);
  check("a CRL is persisted before the rotation", crlBefore.length > 0);
  var keyBefore  = fs.readFileSync(ca.paths.caKey);
  var certBefore = fs.readFileSync(ca.paths.caCert);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from) {
    if (String(from) === String(ca.paths.crl)) throw new Error("simulated read-only CRL directory");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the rotation aborts when the stale CRL cannot be moved aside", codeSeen === "mtls-ca/commit-failed");
  check("the CA rolled back (key + cert unchanged) rather than publishing beside a stale CRL",
        fs.readFileSync(ca.paths.caKey).equals(keyBefore) && fs.readFileSync(ca.paths.caCert).equals(certBefore));
  check("the surviving CA's valid CRL is left in place after the aborted rotation",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  check("the surviving CA still issues after the aborted rotation",
        typeof (await ca.generateClientCert({ cn: "post-crl-abort" })).cert === "string");
}

// If a rotation's cert publish fails AFTER the stale CRL was moved aside, the commit
// rolls back — and the CA it reverts to is still active, so its still-valid CRL must be
// RESTORED, not left permanently deleted (a deployment serving the documented CRL path
// must not lose its published revocation data because a rotation failed).
async function testRotationRestoresCrlWhenCertPublishFails() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBefore = fs.readFileSync(ca.paths.crl);
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.rotate({ generation: 2, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the rotation aborts when the cert publish fails", codeSeen === "mtls-ca/commit-failed");
  check("the rolled-back CA's still-valid CRL is restored (not permanently lost)",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  check("no orphan crl.rollback remains after the restore",
        fs.existsSync(ca.paths.crl + ".rollback") === false);
  check("the surviving CA still issues and can regenerate its CRL",
        typeof (await ca.generateClientCert({ cn: "post-crl-restore" })).cert === "string");
}

// A crash between moving the CRL aside and publishing the new cert leaves the CRL at
// crl.rollback with a journal marking an INTERRUPTED rotation. Reconcile on the next
// mutating open must restore it (the CA it rolls back to is still active).
async function testReconcileRestoresCrlForInterruptedRotation() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBytes = fs.readFileSync(ca.paths.crl);
  var keyG1  = fs.readFileSync(ca.paths.caKey);
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.renameSync(ca.paths.crl, ca.paths.crl + ".rollback");    // CRL moved aside
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyG1, newKey: keyG1, cert: certG1,                  // live cert == manifest.cert => interrupted
    retainAfter: false, crlMovedAside: true, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                    // reconciles under the lock
  check("reconcile restores the valid CRL an interrupted rotation moved aside",
        fs.existsSync(reopened.paths.crl) === true && fs.readFileSync(reopened.paths.crl).equals(crlBytes));
  check("the crl.rollback temp is cleared after the reconcile restore",
        fs.existsSync(reopened.paths.crl + ".rollback") === false);
  check("the reconciled CA still issues",
        typeof (await reopened.generateClientCert({ cn: "post-reconcile-crl" })).cert === "string");
}

// A supported custom engine whose CA certificate node:crypto cannot parse (an opaque /
// post-quantum cert) makes parseGeneration() fall back to 0. Recording issuances as
// generation 0 then lets revokeGeneration(1) revoke those CURRENT leaves (0 < 1) and,
// via the bumped watermark, self-revoke every future issuance. An undeterminable
// generation must be recorded as null — skipped by generation-based revocation (still
// revocable by fingerprint), never 0.
async function testOpaqueCustomEngineIssuanceGenerationNotZero() {
  var dir = _mkTmp();
  var opaqueCert = "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNhLW5vdC1wYXJzZWFibGU=\n-----END CERTIFICATE-----";
  var opaqueKey  = "-----BEGIN PRIVATE KEY-----\nb3BhcXVlLWtleQ==\n-----END PRIVATE KEY-----";
  var n = 0;
  var eng = {
    generateCa:     async function () { return { caCertPem: opaqueCert, caKeyPem: opaqueKey }; },
    signClientCert: async function () {
      n += 1;   // distinct opaque leaves -> distinct fingerprints (_certIdentity hashes the bytes)
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZi0" + n + "=\n-----END CERTIFICATE-----", key: "leaf-key-" + n };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  var leaf1 = await ca.generateClientCert({ cn: "opaque-1" });
  var ledger = JSON.parse(fs.readFileSync(ca.paths.issuance, "utf8"));
  check("an opaque custom CA records issuance generation as null (undeterminable), not 0",
        ledger.issued.length === 1 && ledger.issued[0].generation === null);
  var res = await ca.revokeGeneration(1);
  check("revokeGeneration(1) does not sweep an undeterminable-generation leaf",
        res.revoked === 0 && ca.isRevoked(leaf1.fingerprint) === false);
  var leaf2 = await ca.generateClientCert({ cn: "opaque-2" });
  check("a later issuance under the opaque CA does not self-revoke as superseded",
        typeof leaf2.cert === "string" && ca.isRevoked(leaf2.fingerprint) === false);
}

// The fresh-init adoption branch (a concurrent process created the CA under the shared
// dataDir while this pinned handle awaited generateCa) must run the SAME algorithm-pin
// validation as initCA()'s normal existing-CA path — else a pinned handle adopts and
// issues under an incompatible CA.
async function testFreshInitAdoptionValidatesPin() {
  var dir = _mkTmp();
  var release; var barrier = new Promise(function (r) { release = r; });
  var slowEngine = Object.assign({}, engine, {
    generateCa: async function (a) { await barrier; return engine.generateCa(a); },
  });
  var pinned = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine, algorithm: "ECDSA-P384-SHA384" });
  var issuing = pinned.generateClientCert({ cn: "adopt" });  // initCA -> _freshCreateSerialized, blocks in generateCa
  var other = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // ML-DSA default
  await other.initCA();                                      // publishes an ML-DSA CA at the shared dataDir
  release();
  check("the fresh-init adoption branch validates the pin (refuses adopting a different-algorithm CA)",
        (await code2(function () { return issuing; })) === "mtls-ca/algorithm-mismatch");
}

// A handle created with an algorithm pin that migrates its CA to a different algorithm
// via the public commit() path must refresh the pin (like rotate() does) — else the
// next initCA()/generateClientCert() compares the stale pin to the new CA and throws
// algorithm-mismatch, leaving the handle unusable immediately after a successful commit.
async function testPublicCommitRefreshesAlgorithmPin() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();
  var mlSource = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });   // ML-DSA default
  await mlSource.initCA();
  var mlKey  = mlSource.loadKey().toString("utf8");
  var mlCert = mlSource.loadCert().toString("utf8");
  await ca.commit({ caKeyPem: mlKey, caCertPem: mlCert, retainPrevious: false });
  var leaf = await ca.generateClientCert({ cn: "post-commit-migrate" });
  check("a pinned handle stays usable after commit()ing a different-algorithm CA (pin refreshed)",
        typeof leaf.cert === "string");
}

// A key-only cold start (a crashed FIRST init left ca.key with no ca.crt, so the retry's
// _commitLocked captured it as the prior key with cert=null) must still roll a COMPLETED
// init forward: reconcile classifies by the intended NEW cert, so it keeps the published
// key/cert pair instead of restoring the orphaned prior key beside the new cert.
async function testReconcileRollsForwardKeyOnlyInit() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  var other = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await other.initCA();
  var keyOrphan = fs.readFileSync(other.paths.caKey);        // an unrelated prior key
  // Fabricate a COMPLETED key-only init that crashed before deleting the journal: the
  // journal's prior cert is null (none existed when the commit began), its newKey/newCert
  // are the published pair, and the live pair IS that published pair.
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: keyOrphan, newKey: key1, cert: null, newCert: cert1,
    retainAfter: false, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles under the lock
  check("reconcile rolls a completed key-only init FORWARD (keeps the published key, not the orphan)",
        fs.readFileSync(reopened.paths.caKey).equals(key1));
  check("the reconciled key-only CA is a usable pair (issues cleanly)",
        typeof (await reopened.generateClientCert({ cn: "post-keyonly" })).cert === "string");
  check("the journal is cleared after the key-only roll-forward",
        fs.existsSync(reopened.paths.caKey + ".rollback") === false);
}

// A custom engine may use its OWN label (e.g. "CUSTOM-P384") for a standard key type.
// The public commit() pin refresh maps via _certAlgorithm(), which yields BUNDLED
// labels — so refreshing a custom-engine pin would replace its label with the bundled
// one and the next issuance would pass a label the engine rejects. Refresh the pin only
// for the default engine; a custom engine's pin is preserved.
async function testPublicCommitPreservesCustomEnginePin() {
  var dir = _mkTmp();
  var seen = [];
  var eng = {
    generateCa:     async function () { return { caCertPem: "opaque-ca", caKeyPem: "opaque-key" }; },
    signClientCert: async function (a) {
      seen.push(a.algorithm);
      if (a.algorithm !== "CUSTOM-P384") throw new Error("engine only accepts CUSTOM-P384, got " + a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng, algorithm: "CUSTOM-P384" });
  await ca.initCA();
  // Commit a PARSEABLE ECDSA-P384 CA (default engine) through the custom-engine handle.
  var ecSource = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await ecSource.initCA();
  await ca.commit({ caKeyPem: ecSource.loadKey().toString("utf8"), caCertPem: ecSource.loadCert().toString("utf8"), retainPrevious: false });
  var leaf = await ca.generateClientCert({ cn: "post-commit-custom" });
  check("a custom-engine pin survives a public commit (the engine receives CUSTOM-P384, not the bundled label)",
        typeof leaf.cert === "string" && seen[seen.length - 1] === "CUSTOM-P384");
}

// canVerifyInTls() must REJECT an invalid explicit target (empty string / non-string)
// rather than silently falling back to the stored/default algorithm — else a migration
// pre-flight returns true without testing the requested target. create()/rotate() reject
// the same invalid values.
async function testCanVerifyInTlsRejectsInvalidExplicitAlgorithm() {
  var ca = _newCa();
  await ca.initCA();
  check("canVerifyInTls('') rejects an empty explicit target (no silent fallback to the stored CA)",
        (await code2(function () { return ca.canVerifyInTls(""); })) === "mtls-ca/bad-algorithm");
  check("canVerifyInTls(123) rejects a non-string explicit target",
        (await code2(function () { return ca.canVerifyInTls(123); })) === "mtls-ca/bad-algorithm");
  check("canVerifyInTls(null) rejects a null explicit target",
        (await code2(function () { return ca.canVerifyInTls(null); })) === "mtls-ca/bad-algorithm");
}

// A non-boolean retainPrevious (e.g. the string "false" from config) must be REJECTED,
// not interpreted by truthiness: "false" is truthy, so it would retain the outgoing
// root when the operator intended a hard cut (and rotate() retains for every value !==
// literal false). Validate the supplied value is a boolean at both entry points.
async function testNonBooleanRetainPreviousRejected() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });
  check("commit() rejects a non-boolean retainPrevious (the string \"false\" would otherwise retain)",
        (await code2(function () {
          return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: "false" });
        })) === "mtls-ca/bad-retain-previous");
  check("rotate() rejects a non-boolean retainPrevious",
        (await code2(function () { return ca.rotate({ generation: 2, retainPrevious: "false" }); }))
          === "mtls-ca/bad-retain-previous");
  // A proper boolean still works (hard cut to gen 2).
  var r = await ca.rotate({ generation: 2, retainPrevious: false });
  check("rotate() still accepts a boolean retainPrevious",
        typeof r.caCertPem === "string" && ca.status().generation === 2);
  // generateCrl()'s persist is the same !== false truthiness class — a non-boolean must
  // be rejected rather than persisting when the operator meant return-only.
  check("generateCrl() rejects a non-boolean persist (the string \"false\" would otherwise persist)",
        (await code2(function () { return ca.generateCrl({ persist: "false" }); })) === "mtls-ca/bad-persist");
  var crl = await ca.generateCrl({ persist: false });   // a proper boolean still returns without persisting
  check("generateCrl() still accepts a boolean persist", typeof crl.crlPem === "string");
}

// crl.rollback is a fixed name, so an ORPHAN left by a prior commit (whose best-effort
// delete failed after publishing) must NOT be restored by a LATER commit that never
// moved it aside — that would publish a CRL signed by an earlier issuer under the
// still-active CA. The restore is gated on "did THIS commit move the CRL aside".
async function testCommitDoesNotRestoreOrphanCrlRollback() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var staleCrl = Buffer.from("-----BEGIN X509 CRL-----\nc3RhbGUtcm9sbGJhY2s=\n-----END X509 CRL-----\n");
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);          // an orphan from a prior commit
  check("setup: an orphan crl.rollback exists with no current ca.crl",
        fs.existsSync(ca.paths.crl + ".rollback") === true && fs.existsSync(ca.paths.crl) === false);
  // A CA-changing commit that fails its cert publish (its catch runs). It did NOT move a
  // CRL aside (there is no current ca.crl), so its catch must not touch the orphan.
  var g2 = await engine.generateCa({ generation: 2 });
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (from, to) {
    if (String(to) === String(ca.paths.caCert)) throw new Error("simulated cert publish failure");
    return realRename.apply(this, arguments);
  };
  var codeSeen;
  try { codeSeen = await code2(function () { return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false }); }); }
  finally { atomicFile.renameWithRetry = realRename; }
  check("the failed commit aborts", codeSeen === "mtls-ca/commit-failed");
  check("the orphan crl.rollback is NOT restored as the current CRL (it was signed by an earlier issuer)",
        fs.existsSync(ca.paths.crl) === false);
  check("the orphan crl.rollback is left untouched (not this commit's to restore)",
        fs.existsSync(ca.paths.crl + ".rollback") === true && fs.readFileSync(ca.paths.crl + ".rollback").equals(staleCrl));
}

// Reconcile must ALSO not restore an orphan crl.rollback: a journaled commit whose
// crlMovedAside is false did not move a CRL aside, so any crl.rollback present is a
// prior commit's orphan — restoring it would publish a stale-issuer CRL.
async function testReconcileDoesNotRestoreOrphanCrlRollback() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  var staleCrl = Buffer.from("-----BEGIN X509 CRL-----\nb3JwaGFuLXJlY29uY2lsZQ==\n-----END X509 CRL-----\n");
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);     // orphan, no current ca.crl
  // An INTERRUPTED commit's journal that did NOT move a CRL aside (crlMovedAside false).
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: key1, cert: cert1,                     // live cert == manifest.cert => interrupted
    retainAfter: false, crlMovedAside: false, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                    // reconciles under the lock
  check("reconcile does NOT restore an orphan crl.rollback for a commit that did not move a CRL",
        fs.existsSync(reopened.paths.crl) === false &&
        fs.existsSync(reopened.paths.crl + ".rollback") === true &&
        fs.readFileSync(reopened.paths.crl + ".rollback").equals(staleCrl));
}

// A completed rotation whose CRL move-aside was LOST (best-effort fsyncDir did not
// persist the rename) leaves the OLD-issuer CRL live at paths.crl with no crl.rollback,
// while the new cert IS published. Reconcile classifies it completed; it must remove the
// stale live CRL too, not just the (absent) crl.rollback — else the old-issuer CRL stays
// published under the new CA until the operator regenerates.
async function testReconcileRemovesResurrectedLiveCrlOnRollForward() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  await ca.generateCrl();
  var staleCrl = fs.readFileSync(ca.paths.crl);              // CRL signed by cert1 (gen-1 issuer)
  var g2 = await engine.generateCa({ generation: 2 });
  // Crash state: the new cert/key are published, ca.crl still holds the OLD-issuer CRL
  // (the move-aside rename was lost), there is NO crl.rollback, and the journal survived.
  fs.writeFileSync(ca.paths.caKey, g2.caKeyPem);
  fs.writeFileSync(ca.paths.caCert, g2.caCertPem);
  fs.writeFileSync(ca.paths.crl, staleCrl);
  fs.rmSync(ca.paths.crl + ".rollback", { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: Buffer.from(g2.caKeyPem), cert: cert1, newCert: Buffer.from(g2.caCertPem),
    retainAfter: false, crlMovedAside: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles: completed + crlMovedAside
  check("reconcile removes a stale live CRL a lost move-aside left under the new CA (completed roll-forward)",
        fs.existsSync(reopened.paths.crl) === false);
  check("the reconciled CA still issues after removing the resurrected stale CRL",
        typeof (await reopened.generateClientCert({ cn: "post-crl-rollforward" })).cert === "string");
}

// Completed roll-forward where the move-aside STUCK (ca.crl.rollback is present) but the
// post-publish delete of that moved-aside copy did not run before the crash. Reconcile
// must remove the leftover crl.rollback — the superseded issuer's CRL must not linger.
async function testReconcileRemovesLeftoverCrlRollbackOnRollForward() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1  = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  await ca.generateCrl();
  var staleCrl = fs.readFileSync(ca.paths.crl);              // CRL signed by cert1 (gen-1 issuer)
  var g2 = await engine.generateCa({ generation: 2 });
  // Crash state: the new cert/key are published (completed roll-forward), the stale CRL was
  // moved aside to crl.rollback and that rename STUCK, but the post-publish delete of the
  // moved-aside copy did not run; there is no live paths.crl; the journal survived.
  fs.writeFileSync(ca.paths.caKey, g2.caKeyPem);
  fs.writeFileSync(ca.paths.caCert, g2.caCertPem);
  fs.rmSync(ca.paths.crl, { force: true });
  fs.writeFileSync(ca.paths.crl + ".rollback", staleCrl);
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: Buffer.from(g2.caKeyPem), cert: cert1, newCert: Buffer.from(g2.caCertPem),
    retainAfter: false, crlMovedAside: true, prevAction: "delete", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.initCA();                                   // reconciles: completed + crlMovedAside
  check("reconcile removes a leftover moved-aside crl.rollback on a completed roll-forward",
        fs.existsSync(reopened.paths.crl + ".rollback") === false);
  check("no stale CRL is republished under the new CA after the leftover is removed",
        fs.existsSync(reopened.paths.crl) === false);
  check("the reconciled CA still issues after removing the leftover crl.rollback",
        typeof (await reopened.generateClientCert({ cn: "post-crl-leftover" })).cert === "string");
}

// An idempotent recommit of the CURRENT CA with retainPrevious:true supersedes no issuer, so
// it must NOT open the single retained-root window — else the next REAL retained rotation
// fails with mtls-ca/retained-root-exists until the operator calls dropRetained().
async function testIdempotentRetainedCommitDoesNotOpenGraceWindow() {
  var ca = _newCa();
  await ca.initCA();
  var sameKey  = ca.loadKey().toString("utf8");
  var sameCert = ca.loadCert().toString("utf8");
  await ca.commit({ caKeyPem: sameKey, caCertPem: sameCert, retainPrevious: true });
  check("an idempotent retainPrevious:true commit does not open the retained-root window",
        (await ca.loadTrustBundle()).length === 1 && fs.existsSync(ca.paths.caCertPrev) === false);
  // A subsequent REAL retained rotation still succeeds (the window was not spuriously consumed).
  var g2 = await engine.generateCa({ generation: 2 });
  var rotCode = await code2(function () {
    return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: true });
  });
  check("a real retained rotation after an idempotent recommit succeeds (window was free)",
        rotCode === "NO-THROW" && (await ca.loadTrustBundle()).length === 2);
}

// Recommitting the IDENTICAL X.509 certificate with harmless PEM differences (CRLF line
// endings, an extra trailing newline) must be recognized as the same issuer — a byte-exact
// comparison would treat it as new, spuriously opening the single retained-root window.
async function testIdempotentRetainedCommitToleratesPemReformatting() {
  var ca = _newCa();
  await ca.initCA();
  var sameCert = ca.loadCert().toString("utf8");
  var sameKey  = ca.loadKey().toString("utf8");
  var reformatted = sameCert.replace(/\n/g, "\r\n") + "\n";     // CRLF + extra trailing newline
  await ca.commit({ caKeyPem: sameKey, caCertPem: reformatted, retainPrevious: true });
  check("a retained recommit of the same cert with reformatted PEM does not open the retained window",
        (await ca.loadTrustBundle()).length === 1 && fs.existsSync(ca.paths.caCertPrev) === false);
}

// An in-flight issuance checks that its signing root is still in loadTrustBundle() (to catch a
// concurrent hard-cut). That membership check must compare cert IDENTITY: an idempotent commit()
// that republished the SAME root with reformatted PEM during signing leaves the same root under
// different bytes, and a string comparison would falsely revoke the leaf (issuance-superseded).
async function testIssuanceNotRevokedWhenRootRepublishedReformatted() {
  var dir = _mkTmp();
  var caCertPath = null;
  var reformatted = null;
  var eng = Object.assign({}, engine, {
    signClientCert: async function (a) {
      if (reformatted) { fs.writeFileSync(caCertPath, reformatted); }   // republish reformatted mid-sign
      return engine.signClientCert(a);
    },
  });
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  caCertPath = ca.paths.caCert;
  reformatted = fs.readFileSync(ca.paths.caCert, "utf8").replace(/\n/g, "\r\n") + "\n";   // CRLF + newline
  var code = await code2(function () { return ca.generateClientCert({ cn: "straddling-leaf" }); });
  check("an in-flight issuance is NOT revoked when its root is idempotently republished with reformatted PEM",
        code === "NO-THROW");
}

// A CERT-ONLY store (ca.crt present, no key at the destination) is corrupt/half-published:
// committing over it would journal no prior key, so a cert-rename failure after the key rename
// leaves an unrecoverable new-key/old-cert pair. commit() must refuse it before mutating.
async function testCommitRejectsCertOnlyState() {
  var ca = _newCa();
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });
  fs.rmSync(ca.paths.caKey);                                    // corrupt: cert present, key absent
  var code = await code2(function () {
    return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  });
  check("commit refuses a cert-only (key-absent) state rather than leaving an unrecoverable pair",
        code === "mtls-ca/ca-pair-inconsistent");
}

// A migration caller that accidentally supplies a certificate and key from DIFFERENT CA material
// must be rejected before publishing — otherwise commit() succeeds but the next initCA() fails
// ca-pair-inconsistent, leaving an unusable CA that can issue neither certs nor CRLs.
async function testCommitRejectsMismatchedCaPair() {
  var ca = _newCa();
  await ca.initCA();
  var g1cert = ca.loadCert().toString("utf8");                      // this CA's (gen-1) cert
  var other = await engine.generateCa({ generation: 2 });           // an UNRELATED CA's cert+key
  var code = await code2(function () {                               // gen-1 cert + unrelated key = mismatch
    return ca.commit({ caCertPem: g1cert, caKeyPem: other.caKeyPem, retainPrevious: false });
  });
  check("commit refuses a mismatched cert/key pair (the cert's public key doesn't match the key) before publishing",
        code === "mtls-ca/ca-pair-inconsistent");
}

// A bundled-engine commit() must reject a parseable, MATCHING CA pair whose algorithm the bundled
// engine does not support (e.g. a P-256 EC CA). _caPairConsistent verifies only pairing, so such a
// CA would publish, then the next initCA() adopting it throws mtls-ca/algorithm-mismatch (the pin
// requires P-384) — commit() reporting success while leaving every subsequent issuance unavailable.
async function testCommitRejectsUnsupportedBundledAlgorithm() {
  var p256 = await _p256CaEngine().generateCa();                   // a valid, matching P-256 CA pair
  var caPinned = _newCa({ algorithm: "ECDSA-P384-SHA384" });       // the finding's scenario
  check("bundled commit() rejects a P-256 CA on an ECDSA-P384-pinned handle before publishing",
        (await code2(function () { return caPinned.commit({ caKeyPem: p256.caKeyPem, caCertPem: p256.caCertPem }); }))
          === "mtls-ca/unsupported-ca-algorithm");
  check("the rejected commit left storage untouched (no CA published)", caPinned.status().exists === false);
  await caPinned.initCA();                                         // a supported CA still initializes
  check("a supported CA still initializes on the same handle after the rejection",
        caPinned.status().algorithm === "ECDSA-P384-SHA384");
  // Even UNPINNED, the bundled engine cannot drive a P-256 CA, so it is refused too.
  var caUnpinned = _newCa();
  check("bundled commit() rejects a P-256 CA on an unpinned handle as well",
        (await code2(function () { return caUnpinned.commit({ caKeyPem: p256.caKeyPem, caCertPem: p256.caCertPem }); }))
          === "mtls-ca/unsupported-ca-algorithm");

  // A RECOGNIZED-but-unsupported label (ml-dsa-44, outside the engine's ML-DSA-87/65 set) is
  // refused as well — the gate is "supported by the bundled engine", not merely "classifiable".
  var mldsa44 = await _mldsa44CaEngine().generateCa();
  var caMl = _newCa();
  var mlCode = await code2(function () { return caMl.commit({ caKeyPem: mldsa44.caKeyPem, caCertPem: mldsa44.caCertPem }); });
  check("bundled commit() rejects a recognized-but-unsupported ML-DSA-44 CA", mlCode === "mtls-ca/unsupported-ca-algorithm");
}

// A bundled-engine commit() must reject a certificate that is NOT a CA (basicConstraints cA:false —
// e.g. a P-384 LEAF and its matching key). It parses, classifies as a supported ECDSA algorithm, and
// pairs, so the earlier checks accept it — but the bundled engine signs leaves WITH the committed CA,
// so the next generateClientCert() would fail (a non-CA issuer, x509/bad-input). Refuse it up front.
async function testCommitRejectsNonCaCertificate() {
  var leaf = await _p384LeafPair();                               // a valid P-384 leaf + key (cA:false)
  var ca = _newCa();
  check("bundled commit() rejects a non-CA (leaf) certificate before publishing",
        (await code2(function () { return ca.commit({ caKeyPem: leaf.caKeyPem, caCertPem: leaf.caCertPem }); }))
          === "mtls-ca/not-a-ca-certificate");
  check("the rejected commit left storage untouched", ca.status().exists === false);
  // A genuine CA still initializes on the same handle after the rejection.
  await ca.initCA();
  check("a CA certificate still initializes after the non-CA rejection", ca.status().exists === true);
}

// A bundled-engine commit() of a CA key in the common OpenSSL SEC1 encoding (BEGIN EC PRIVATE KEY)
// must still yield a usable CA. createPrivateKey() parses SEC1, so it passes the pairing / algorithm
// checks, but the bundled toolkit decodes only PKCS#8 — the next generateClientCert() would fail
// x509/bad-input. commit() must normalize the committed key to PKCS#8 before publishing.
async function testCommitNormalizesSec1KeyEncoding() {
  var sec1 = await _p384CaMaterial({ keyType: "sec1" });          // valid CA cert + SEC1-encoded key
  var ca = _newCa();
  await ca.commit({ caKeyPem: sec1.caKeyPem, caCertPem: sec1.caCertPem });
  var leaf = await ca.generateClientCert({ cn: "after-sec1-commit" });
  check("a bundled commit() of a SEC1-encoded CA key still issues (key normalized to PKCS#8)",
        typeof leaf.cert === "string" && leaf.cert.length > 0);
  var crl = await ca.generateCrl({ persist: false });
  check("the SEC1-committed CA can also sign CRLs after normalization", typeof crl.crlPem === "string");
}

// A bundled-engine commit() must reject a CA certificate that cannot sign CRLs (keyUsage has
// keyCertSign but omits cRLSign): leaf issuance would succeed but every generateCrl() fails
// crl/bad-input, silently disabling the revocation-export path. node's X509Certificate does not
// expose the KeyUsage extension, so commit() functionally preflights leaf + CRL signing.
async function testCommitRejectsCaWithoutCrlSign() {
  var noCrl = await _p384CaMaterial({ keyUsage: ["keyCertSign"] });   // a CA, but no cRLSign
  var ca = _newCa();
  check("bundled commit() rejects a CA certificate whose key usage omits cRLSign",
        (await code2(function () { return ca.commit({ caKeyPem: noCrl.caKeyPem, caCertPem: noCrl.caCertPem }); }))
          === "mtls-ca/ca-cannot-sign-crl");
  check("the CRL-incapable rejected commit left storage untouched", ca.status().exists === false);
}

// A bundled-engine commit() must reject a CA certificate outside its validity window (expired or
// not-yet-valid). It parses, is a CA, classifies, pairs, and even signs a leaf — but every issued
// leaf chains to that CA, and a TLS peer rejects an expired/not-yet-valid chain (CERT_HAS_EXPIRED),
// so a "successful" migration would make every new credential unusable. Validate the dates up front.
async function testCommitRejectsCaOutsideValidity() {
  var dayMs = 86400000;
  var expired = await _p384CaMaterial({ notBefore: new Date(Date.now() - 2 * dayMs), notAfter: new Date(Date.now() - dayMs) });
  var ca = _newCa();
  check("bundled commit() rejects an expired CA certificate",
        (await code2(function () { return ca.commit({ caKeyPem: expired.caKeyPem, caCertPem: expired.caCertPem }); }))
          === "mtls-ca/ca-outside-validity");
  var notYet = await _p384CaMaterial({ notBefore: new Date(Date.now() + dayMs), notAfter: new Date(Date.now() + 2 * dayMs) });
  check("bundled commit() rejects a not-yet-valid CA certificate",
        (await code2(function () { return ca.commit({ caKeyPem: notYet.caKeyPem, caCertPem: notYet.caCertPem }); }))
          === "mtls-ca/ca-outside-validity");
  check("the out-of-window rejected commits left storage untouched", ca.status().exists === false);
  // A currently-valid CA still commits.
  var valid = await _p384CaMaterial({});
  await ca.commit({ caKeyPem: valid.caKeyPem, caCertPem: valid.caCertPem });
  check("a currently-valid CA still commits", ca.status().exists === true);
}

// A CRL is signed by ONE issuer, and serials are unique only per issuer. generateCrl() must NOT
// publish a revocation whose cert was issued by a DIFFERENT CA identity — under a custom engine
// that reuses serials, that CA's revoked serial would false-revoke the unrelated current
// certificate reusing it. Scoping is by ISSUER IDENTITY (the ledger's caFingerprint), NOT
// generation number: commit() can replace a CA with a different cert at the SAME generation.
async function testCrlScopedToCurrentIssuerIdentity() {
  var issued = [];
  var revoked = [];
  var ca = b.mtlsCa.create({
    dataDir: _mkTmp(), caKeySealedMode: "disabled",
    issuanceStore:   { list: function () { return issued.slice(); },  add: function (e) { issued.push(e); } },
    revocationStore: { list: function () { return revoked.slice(); }, add: function (e) { revoked.push(e); } },
  });
  await ca.initCA();
  var oldCaId = b.crypto.hashCertFingerprint(ca.loadCert().toString("utf8")).hex;   // the superseded CA's identity
  var replacement = await engine.generateCa({ generation: 1 });                     // a DIFFERENT CA at the SAME generation
  await ca.commit({ caKeyPem: replacement.caKeyPem, caCertPem: replacement.caCertPem, retainPrevious: false });
  var newCaId = b.crypto.hashCertFingerprint(ca.loadCert().toString("utf8")).hex;
  check("precondition: same generation, different CA identity",
        ca.status().generation === 1 && oldCaId !== newCaId);
  var fpA = "aa".repeat(64);
  issued.push({ caFingerprint: oldCaId, serialNumber: "0a", fingerprint: fpA });   // cert A issued by the OLD CA
  revoked.push({ serialNumber: "0a", fingerprint: fpA });                          // revoke cert A
  var crl = await ca.generateCrl({ persist: false });
  check("the current CRL excludes a revocation from a different CA identity at the SAME generation",
        crl.entryCount === 0);
}

// generateCrl() dedups two revocations of the SAME serial (a serial-only entry plus a later
// serial+fingerprint one revokeGeneration backfills) to one CRL entry, and skips a malformed
// issuance-ledger entry (no caFingerprint) when resolving issuers.
async function testCrlDedupsAndSkipsMalformedLedgerEntries() {
  var issued = [];
  var revoked = [];
  var ca = b.mtlsCa.create({
    dataDir: _mkTmp(), caKeySealedMode: "disabled",
    issuanceStore:   { list: function () { return issued.slice(); },  add: function (e) { issued.push(e); } },
    revocationStore: { list: function () { return revoked.slice(); }, add: function (e) { revoked.push(e); } },
  });
  await ca.initCA();
  var caId = b.crypto.hashCertFingerprint(ca.loadCert().toString("utf8")).hex;    // the current CA's identity
  var fp = "dd".repeat(64);
  issued.push({ serialNumber: "0c", fingerprint: "cc".repeat(64) });              // MALFORMED: no caFingerprint -> skipped
  issued.push({ caFingerprint: caId, serialNumber: "0b", fingerprint: fp });
  revoked.push({ serialNumber: "0b", fingerprint: null });                        // serial-only revocation
  revoked.push({ serialNumber: "0b", fingerprint: fp });                          // serial+fingerprint (same serial -> dedup)
  var crl = await ca.generateCrl({ persist: false });
  check("generateCrl dedups two revocations of the same serial and tolerates a ledger entry with no caFingerprint",
        crl.entryCount === 1);
}

// isSerialRevoked() (the require-mtls live gate's serial fallback) must match ONLY serial-only
// revocations: a serial is unique per issuer, so a serial+fingerprint revocation is scoped to its
// specific cert by the fingerprint. Matching its serial globally would false-deny a DIFFERENT
// generation's cert reusing the serial (a custom engine that restarts its serial counter).
async function testSerialRevokedMatchesOnlySerialOnlyEntries() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "gen1" });
  await ca.revoke({ serial: leaf.serialNumber, fingerprint: leaf.fingerprint });   // serial+fingerprint
  check("isRevoked matches a serial+fingerprint revocation by fingerprint", ca.isRevoked(leaf.fingerprint) === true);
  check("isSerialRevoked does NOT match a serial+fingerprint revocation (scoped to its cert by fingerprint)",
        ca.isSerialRevoked(leaf.serialNumber) === false);
  await ca.revoke("0abc");                                                          // bare serial-only
  check("isSerialRevoked matches a bare serial-only revocation (the require-mtls serial fallback)",
        ca.isSerialRevoked("0abc") === true);
  check("isSerialRevoked throws on a non-string serial",
        code(function () { return ca.isSerialRevoked(null); }) === "mtls-ca/bad-revocation-key");
}

// A SERIAL-ONLY revoke(serial) must be recorded even when a serial+FINGERPRINT entry already
// exists for that serial (e.g. an older CA generation's cert with a since-reused serial): treating
// it as a duplicate would drop the serial-only entry, so isSerialRevoked() stays false and the gate
// admits the current cert despite the revoke call.
async function testSerialOnlyRevokeNotDedupedAgainstFingerprintEntry() {
  var ca = _newCa();
  await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "old" });
  await ca.revoke({ serial: leaf.serialNumber, fingerprint: leaf.fingerprint });   // serial+fingerprint entry
  check("precondition: the serial is not yet serial-only-revoked", ca.isSerialRevoked(leaf.serialNumber) === false);
  await ca.revoke(leaf.serialNumber);                                              // bare serial-only revoke, same serial
  check("a serial-only revoke(serial) is recorded even when a serial+fingerprint entry exists for the serial",
        ca.isSerialRevoked(leaf.serialNumber) === true);
}

// The BUNDLED engine always emits parseable X.509 material, so commit() to it must reject
// unparseable input — _caPairConsistent returns "consistent" whenever parsing throws (the opaque
// custom fallback), which would otherwise publish garbage that bricks every later issuance.
async function testCommitRejectsUnparseableBundledMaterial() {
  var ca = _newCa();
  await ca.initCA();
  var code2v = await code2(function () {
    return ca.commit({ caCertPem: "garbage-cert-not-pem", caKeyPem: "garbage-key-not-pem", retainPrevious: false });
  });
  check("commit to the bundled engine rejects unparseable cert/key material (mtls-ca/bad-commit)",
        code2v === "mtls-ca/bad-commit");
}

// importIssuance() must record the ISSUING CA's identity (from a supplied caCert) so generateCrl()
// can issuer-scope a backfilled old-CA entry: without it, an imported old-CA revocation whose serial
// a current CA reuses stays in the current CRL, falsely revoking the unrelated current cert.
async function testImportIssuanceRecordsIssuerForCrlScoping() {
  var issued = [];
  var revoked = [];
  var ca = b.mtlsCa.create({
    dataDir: _mkTmp(), caKeySealedMode: "disabled",
    issuanceStore:   { list: function () { return issued.slice(); },  add: function (e) { issued.push(e); } },
    revocationStore: { list: function () { return revoked.slice(); }, add: function (e) { revoked.push(e); } },
  });
  await ca.initCA();
  var oldCaCert = ca.loadCert().toString("utf8");                                  // the (soon-superseded) issuing CA
  await ca.rotate({ generation: 2 });                                             // a DIFFERENT current CA
  var fpA = "aa".repeat(64);
  check("importIssuance rejects a non-string caCert",
        (await code2(function () { return ca.importIssuance([{ generation: 1, serialNumber: "0d", fingerprint: "aa".repeat(64), caCert: 123 }]); })) === "mtls-ca/bad-import");
  await ca.importIssuance([{ generation: 1, serialNumber: "0a", fingerprint: fpA, caCert: oldCaCert }]);
  revoked.push({ serialNumber: "0a", fingerprint: fpA });                          // revoke the imported old-CA cert
  var crl = await ca.generateCrl({ persist: false });
  check("an imported old-CA revocation is issuer-scoped out of the current CRL (caCert recorded on import)",
        crl.entryCount === 0);
}

// A cert-changing commit moves the current CRL aside to a fixed crl.rollback path. If a prior
// commit left an ORPHAN there (best-effort delete failed), on Windows renameSync cannot replace
// it and the move-aside aborts every later rotation. commit() must clear the orphan first.
async function testCommitClearsOrphanCrlRollbackBeforeMoveAside() {
  var atomicFile = require("../../lib/atomic-file");
  var ca = _newCa();
  await ca.initCA();
  await ca.generateCrl();
  fs.writeFileSync(ca.paths.crl + ".rollback", "stale-orphan-crl");                 // orphan from a prior commit
  var g2 = await engine.generateCa({ generation: 2 });
  var realRename = atomicFile.renameWithRetry;
  atomicFile.renameWithRetry = function (src, dest) {                               // simulate Windows rename semantics
    if (String(dest).endsWith("crl.rollback") && fs.existsSync(dest)) {
      throw new Error("EEXIST (simulated Windows: rename cannot replace an existing crl.rollback)");
    }
    return realRename.apply(this, arguments);
  };
  var code;
  try {
    code = await code2(function () {
      return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
    });
  } finally { atomicFile.renameWithRetry = realRename; }
  check("a cert-changing commit clears an orphan crl.rollback before the move-aside (no abort)",
        code === "NO-THROW");
}

// An idempotent recommit of the SAME cert/key does not change the CRL's issuer, so the
// valid CRL must be preserved — not moved aside and deleted like a real rotation.
async function testIdempotentCommitPreservesCrl() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  await ca.generateCrl();
  var crlBefore = fs.readFileSync(ca.paths.crl);
  var sameKey  = ca.loadKey().toString("utf8");
  var sameCert = ca.loadCert().toString("utf8");
  await ca.commit({ caKeyPem: sameKey, caCertPem: sameCert, retainPrevious: false });   // recommit the SAME CA
  check("an idempotent recommit of the same CA preserves the valid CRL (issuer unchanged)",
        fs.existsSync(ca.paths.crl) === true && fs.readFileSync(ca.paths.crl).equals(crlBefore));
  // A DIFFERENT cert still invalidates the CRL (control).
  var g2 = await engine.generateCa({ generation: 2 });
  await ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("committing a DIFFERENT CA still invalidates the stale CRL",
        fs.existsSync(ca.paths.crl) === false);
}

// A SAME-CERT retainPrevious:false hard-cut whose rollback-journal unlink fails must fail
// CLOSED, not report success: the surviving journal has live cert == journal.cert, so the
// next reconcile classifies it INTERRUPTED and restores ca.prev.crt, AND _journalRetainedRoot()
// re-adds it — resurrecting the very root the operator cut while commit() claimed success.
async function testCommitFailsClosedWhenSameCertCutJournalUnlinkFails() {
  var ca = _newCa();
  await ca.initCA();
  await ca.rotate({ generation: 2, retainPrevious: true });   // a retained root (ca.prev.crt) now exists
  var sameKey  = ca.loadKey().toString("utf8");
  var sameCert = ca.loadCert().toString("utf8");
  var journal  = ca.paths.caKey + ".rollback";
  check("precondition: a retained root exists before the hard-cut",
        (await ca.loadTrustBundle()).length === 2);
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) { throw new Error("journal unlink blocked"); }
    return realUnlink.apply(this, arguments);
  };
  var code;
  try {
    code = await code2(function () {
      return ca.commit({ caKeyPem: sameKey, caCertPem: sameCert, retainPrevious: false });
    });
  } finally { fs.unlinkSync = realUnlink; }
  check("a same-cert hard-cut whose journal unlink fails fails CLOSED (mtls-ca/commit-failed), not a false success",
        code === "mtls-ca/commit-failed");
}

// A CERT-CHANGING commit whose journal unlink fails SELF-HEALS: the next reconcile sees live
// cert != journal.cert (COMPLETED) and rolls the leftover forward, so the failure is swallowed
// and the commit succeeds — propagating it would spuriously roll back a genuinely-published CA.
async function testCommitSwallowsJournalUnlinkFailureOnCertChange() {
  var ca = _newCa();
  await ca.initCA();
  var g2 = await engine.generateCa({ generation: 2 });        // a DIFFERENT CA (the cert changes)
  var journal = ca.paths.caKey + ".rollback";
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) { throw new Error("journal unlink blocked"); }
    return realUnlink.apply(this, arguments);
  };
  var code;
  try {
    code = await code2(function () {
      return ca.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
    });
  } finally { fs.unlinkSync = realUnlink; }
  check("a cert-changing commit whose journal unlink fails still SUCCEEDS (the leftover self-heals)",
        code === "NO-THROW");
}

// A pinned CUSTOM-engine handle migrating to a different-algorithm CA via the public commit()
// primitive must be able to supply the NEW effective label: the bundled label cannot be
// inferred from a custom cert, so without it the stale pin is passed to the newly committed
// issuer on the next issuance (reject / incompatible leaf) even though commit() succeeded.
async function testCommitUpdatesCustomEnginePinToSuppliedAlgorithm() {
  var recorded = [];
  var caA = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQQ==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUE=\n-----END PRIVATE KEY-----" };
  var caB = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQg==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUI=\n-----END PRIVATE KEY-----" };
  var eng = {
    generateCa:     async function () { return caA; },
    signClientCert: async function (a) {
      recorded.push(a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: eng, algorithm: "CUSTOM-A" });
  await ca.initCA();
  check("commit rejects a non-string algorithm",
        (await code2(function () {
          return ca.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, algorithm: 123 });
        })) === "mtls-ca/bad-algorithm");
  await ca.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, retainPrevious: false, algorithm: "CUSTOM-B" });
  await ca.generateClientCert({ cn: "after-custom-migrate" });
  check("commit({ algorithm }) updates a custom-engine pin so the next issuance uses the NEW label",
        recorded[recorded.length - 1] === "CUSTOM-B");
}

// The pinned-handle case's sibling: an UNPINNED custom handle (created without algorithm) that
// commits an explicit algorithm must ALSO have it honored. Otherwise the next initCA() snapshot has
// no algorithm, _leafEngineArgs() omits it, and a custom engine whose label can't be inferred from
// the key selects its old default or rejects issuance despite the successful commit — whereas
// rotate({ algorithm }) already applies the label regardless of the handle's prior pin state.
async function testCommitAppliesCustomAlgorithmOnUnpinnedHandle() {
  var recorded = [];
  var caA = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQQ==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUE=\n-----END PRIVATE KEY-----" };
  var caB = { caCertPem: "-----BEGIN CERTIFICATE-----\nQ0EtQg==\n-----END CERTIFICATE-----",
              caKeyPem:  "-----BEGIN PRIVATE KEY-----\na2V5LUI=\n-----END PRIVATE KEY-----" };
  var eng = {
    generateCa:     async function () { return caA; },
    signClientCert: async function (a) {
      recorded.push(a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: eng });   // UNPINNED
  await ca.initCA();
  await ca.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, retainPrevious: false, algorithm: "CUSTOM-B" });
  await ca.generateClientCert({ cn: "after-unpinned-custom-commit" });
  check("commit({ algorithm }) on an UNPINNED custom handle applies the label so the next issuance uses it",
        recorded[recorded.length - 1] === "CUSTOM-B");
}

// A CUSTOM engine whose CA cert is node-parseable (so generation is determinable and rotation works)
// but whose ALGORITHM the framework cannot classify (P-256 -> _certAlgorithm null) — the label is only
// known from the create-time pin / an explicit commit/rotate({algorithm}). `record` collects the label
// each signClientCert receives, so a cross-handle test can observe which label an issuance used.
// A custom engine whose CA key is a Node-PARSEABLE P-384 — so _certAlgorithm() classifies it as the
// bundled "ECDSA-P384-SHA384" — but whose effective label is the operator's own ("CUSTOM-P384"). Used
// to prove status()/probes report the PERSISTED custom label, not the bundled inference.
function _p384CaEngineGen() {
  return {
    canVerifyInTls: async function () { return true; },
    generateCa: async function (genOpts) {
      var gen = (genOpts && genOpts.generation) || 1;
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p384-ca" }, { organizationalUnitName: "CAv" + gen }],
        subjectPublicKey: spki,
        serialNumber:     "0" + gen,
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
    signClientCert: async function () {
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
}

function _p256CaEngineGen(record, genRecord, probeRecord) {
  return {
    canVerifyInTls: async function (label) { if (probeRecord) probeRecord.push(label); return true; },
    generateCa: async function (genOpts) {
      if (genRecord) genRecord.push((genOpts && genOpts.algorithm) || "DEFAULT");
      var gen = (genOpts && genOpts.generation) || 1;
      var subtle = pki.webcrypto.subtle;
      var keys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
      var now = new Date();
      var caCertPem = await pki.x509.sign({
        subject:          [{ commonName: "p256-ca" }, { organizationalUnitName: "CAv" + gen }],
        subjectPublicKey: spki,
        serialNumber:     "0" + gen,
        notBefore:        now,
        notAfter:         new Date(now.getTime() + 86400000),
        extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
      }, { key: keys.privateKey }, { pem: true, digestAlgorithm: "sha384" });
      var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
      return { caCertPem: caCertPem, caKeyPem: caKeyPem };
    },
    signClientCert: async function (a) {
      record.push(a.algorithm);
      return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" };
    },
  };
}

// Two custom-engine handles sharing a dataDir: a commit/rotate({ algorithm:B }) on ONE handle updates
// only its own caAlgorithm closure. The OTHER handle, reading the same stored CA, would snapshot its
// STALE create-time pin and pass A with issuer B (custom labels aren't cert-derivable), so the engine
// rejects or mints an incompatible leaf. The effective custom label must be PERSISTED as shared
// metadata so any handle over the dataDir issues under the CURRENT label.
async function testCustomLabelPersistsAcrossHandles() {
  var dir = _mkTmp();
  var recorded = [];
  var h1 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(recorded), algorithm: "CUSTOM-A" });
  var h2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(recorded), algorithm: "CUSTOM-A" });
  await h1.initCA();
  var caB = await _p256CaEngineGen(recorded).generateCa({ generation: 1 });   // a matching P-256 pair to commit
  await h1.commit({ caKeyPem: caB.caKeyPem, caCertPem: caB.caCertPem, retainPrevious: false, algorithm: "CUSTOM-B" });
  await h2.generateClientCert({ cn: "cross-handle-commit" });
  check("a second shared-dataDir handle issues under the current custom label (B), not its stale pin (A)",
        recorded[recorded.length - 1] === "CUSTOM-B");
  // A rotate({ algorithm }) on h1 likewise persists the new label for h2.
  await h1.rotate({ generation: 2, algorithm: "CUSTOM-C" });
  await h2.generateClientCert({ cn: "cross-handle-rotate" });
  check("the second handle picks up a rotate({ algorithm })'s new custom label too",
        recorded[recorded.length - 1] === "CUSTOM-C");
}

// _readPersistedAlgorithm() edges: an UNPINNED custom create persists nothing (no file), and an EMPTY
// ca.algorithm (a truncated write) is ignored — neither silently forces a wrong label on a sibling.
async function testPersistedAlgorithmReadEdges() {
  var dir = _mkTmp();
  var recorded = [];
  var h1 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(recorded) });   // UNPINNED
  await h1.initCA();
  check("an unpinned custom create persists no algorithm metadata", fs.existsSync(h1.paths.algorithm) === false);
  var h2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(recorded) });   // UNPINNED
  await h2.generateClientCert({ cn: "no-persisted-label" });                                                     // adopts, no file to read
  check("a sibling adopting with no persisted label passes no algorithm (engine default)",
        recorded[recorded.length - 1] === undefined);
  // An EMPTY ca.algorithm (truncated write) is ignored — the handle keeps its own pin.
  fs.writeFileSync(h2.paths.algorithm, "");
  var h3 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(recorded), algorithm: "CUSTOM-Z" });
  await h3.generateClientCert({ cn: "empty-persisted-label" });
  check("an empty persisted-algorithm file is ignored (handle keeps its own pin)",
        recorded[recorded.length - 1] === "CUSTOM-Z");
}

// Cold-start concurrent create: two custom-engine handles with DIFFERENT create-time pins race to
// create the CA (both pass exists()===false, both keygen, then contend for the lock). The loser adopts
// the winner's CA via _freshCreateSerialized's under-lock adopt branch, which must read the WINNER's
// persisted label — else the loser issues under its own stale pin against the winner's CA (rejected /
// incompatible leaf). Both leaves must therefore be signed under the same (winner's) label.
async function testColdStartAdoptReadsPersistedCustomLabel() {
  var dir = _mkTmp();
  var rec = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-A" });
  var B = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-B" });
  await Promise.allSettled([A.generateClientCert({ cn: "a" }), B.generateClientCert({ cn: "b" })]);
  check("a cold-start concurrent-create loser issues under the winner's persisted custom label (both equal)",
        rec.length === 2 && rec[0] === rec[1]);
}

// A BARE rotate({ generation }) (no algorithm) on a custom-engine handle whose caAlgorithm is stale
// (a sibling's create-time pin, or an unpinned cron handle) must mint the new CA under the PERSISTED
// label — the authoritative stored-CA label — not the handle's stale pin. Otherwise it silently
// reverts a completed migration and diverges ca.algorithm from the stored CA (mirroring the
// default engine's stored-algorithm preservation, which reads the label from the cert).
async function testUnpinnedCustomRotatePreservesPersistedLabel() {
  var dir = _mkTmp();
  var rec = [], genRec = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-A" });
  await A.initCA();
  await A.rotate({ generation: 2, algorithm: "CUSTOM-B", retainPrevious: false });   // stored CA + persisted label = CUSTOM-B
  // A stale-pinned sibling (create-time pin CUSTOM-A, never adopted) does a bare rotate.
  var Bh = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec, genRec), algorithm: "CUSTOM-A" });
  await Bh.rotate({ generation: 3 });
  check("a bare rotate on a stale-pinned custom handle mints the new CA under the PERSISTED label, not the stale pin",
        genRec[genRec.length - 1] === "CUSTOM-B");
  // A later adopter now issues under a label consistent with the CA (both are CUSTOM-B).
  var C = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec) });
  await C.generateClientCert({ cn: "after-bare-rotate" });
  check("a later adopter issues under the same label the CA was minted under (CUSTOM-B)",
        rec[rec.length - 1] === "CUSTOM-B");
}

// The custom-engine label write must be crash-ATOMIC with the CA commit: a power loss between the CA
// publish and the ca.algorithm write would leave the label STALE (the old label) against the new CA,
// and every sibling would then issue under the wrong label. The label is journaled, so a
// completed-commit reconcile restores it. Simulate the crash by skipping the label write + journal
// delete during the rotate, then reopen and reconcile.
async function testCustomLabelPersistIsCrashAtomicWithCommit() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var rec = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-A" });
  await A.initCA();                                           // ca.algorithm = CUSTOM-A
  var journal = A.paths.caKey + ".rollback";
  // Rotate to CUSTOM-B, but simulate a crash AFTER the CA is durably published and BEFORE the label
  // write / journal delete: skip the ca.algorithm write and the journal unlink for this rotate.
  var realWrite = atomicFile.writeSync, realUnlink = fs.unlinkSync;
  atomicFile.writeSync = function (p) { if (String(p) === String(A.paths.algorithm)) return; return realWrite.apply(this, arguments); };
  fs.unlinkSync = function (p) { if (String(p) === String(journal)) return; return realUnlink.apply(this, arguments); };
  try { await A.rotate({ generation: 2, algorithm: "CUSTOM-B", retainPrevious: false }); }
  finally { atomicFile.writeSync = realWrite; fs.unlinkSync = realUnlink; }
  check("the crash left ca.algorithm STALE at CUSTOM-A and the journal on disk",
        fs.readFileSync(A.paths.algorithm, "utf8") === "CUSTOM-A" && fs.existsSync(journal) === true);
  // A fresh handle reconciles on adoption and must restore the label to the CA's actual (CUSTOM-B).
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec) });
  await reopened.generateClientCert({ cn: "after-label-crash" });
  check("reconcile restored the custom label to the CA's actual (CUSTOM-B), so issuance uses it",
        rec[rec.length - 1] === "CUSTOM-B");
  check("the spent journal is removed after reconcile", fs.existsSync(journal) === false);
}

// A ca.algorithm label-file write failure AFTER the new key/cert are published must NOT drive the
// commit into the abort-rollback: that catch restores the prior key + retained root but cannot
// un-publish the new certificate, leaving an old-key/new-cert pair, and it deletes the journal that
// would have healed it. For a CA-CHANGING commit the correct behavior is roll-forward — keep the
// published CA and retain the journal so the next reconcile restores the label.
async function testCommitLabelWriteFailureRollsForwardNotAbort() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var rec = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-A" });
  await A.initCA();
  var journal = A.paths.caKey + ".rollback";
  var keyBefore = fs.readFileSync(A.paths.caKey, "utf8");
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(A.paths.algorithm)) throw new Error("simulated ENOSPC writing ca.algorithm");
    return realWrite.apply(this, arguments);
  };
  var threw = null;
  try { await A.rotate({ generation: 2, algorithm: "CUSTOM-B", retainPrevious: false }); }
  catch (e) { threw = e; }
  finally { atomicFile.writeSync = realWrite; }
  check("a label-file write failure does not abort the CA-changing commit", threw === null);
  var keyAfter = fs.readFileSync(A.paths.caKey, "utf8");
  check("the new CA key stayed published (not rolled back to the prior key)", keyAfter !== keyBefore);
  check("the rollback journal survives for reconcile to restore the label", fs.existsSync(journal) === true);
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec) });
  await reopened.generateClientCert({ cn: "after-label-write-fail" });   // adopt -> reconcile restores the label
  check("the published key/cert are a usable pair and reconcile restored the label (issuance uses CUSTOM-B)",
        rec[rec.length - 1] === "CUSTOM-B");
  check("the journal is cleared once reconcile rolls the label forward", fs.existsSync(journal) === false);
}

// canVerifyInTls() with no argument documents that it probes the STORED CA. For a custom engine the
// stored label lives in ca.algorithm (the durable shared file), not this handle's caAlgorithm closure:
// after a sibling handle over the same dataDir migrates the label, this handle's closure is stale, so
// the probe must read the persisted label first (as issuance, cold-start adopt, and rotate now do).
async function testCanVerifyInTlsUsesPersistedLabelAfterSiblingRotation() {
  var dir = _mkTmp();
  var probes = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([], null, probes), algorithm: "CUSTOM-A" });
  await A.initCA();
  var B = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([], null, probes), algorithm: "CUSTOM-A" });
  await B.rotate({ generation: 2, algorithm: "CUSTOM-B", retainPrevious: false });   // sibling persists ca.algorithm = CUSTOM-B
  probes.length = 0;
  var ok = await A.canVerifyInTls();
  check("canVerifyInTls() succeeded probing the stored CA", ok === true);
  check("canVerifyInTls() probed the persisted label (CUSTOM-B), not A's stale closure (CUSTOM-A)",
        probes.length === 1 && probes[0] === "CUSTOM-B");
}

// The roll-forward is gated to CA-CHANGING commits: a SAME-cert label re-stamp whose ca.algorithm
// write fails must FAIL CLOSED (rethrow), because the outer rollback restores a fully consistent prior
// state (unchanged cert + prior key) — reporting success there would leave the stored label silently
// stale against the CA. This exercises the !caCertChanged arm of the label-persist guard.
async function testSameCertLabelRestampWriteFailureFailsClosed() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var rec = [];
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen(rec), algorithm: "CUSTOM-A" });
  await A.initCA();
  var curCert = fs.readFileSync(A.paths.caCert, "utf8");
  var curKey = fs.readFileSync(A.paths.caKey, "utf8");
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(A.paths.algorithm)) throw new Error("simulated ENOSPC writing ca.algorithm");
    return realWrite.apply(this, arguments);
  };
  var threw = null;
  try { await A.commit({ caCertPem: curCert, caKeyPem: curKey, algorithm: "CUSTOM-B" }); }
  catch (e) { threw = e; }
  finally { atomicFile.writeSync = realWrite; }
  check("a same-cert label re-stamp whose ca.algorithm write fails aborts (fails closed)", threw !== null);
}

// A fresh CA creation writes no rollback journal (no prior key to restore), so the create-time custom
// label must be persisted BEFORE the certificate is published — else a failed label write leaves a CA
// installed with no durable label and no journal to heal it, and a sibling handle over the same
// dataDir would issue under its own stale pin. The label going first makes a label-write failure abort
// before any CA is installed.
async function testFreshCreateLabelWriteFailureLeavesNoOrphanCa() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var A = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(A.paths.algorithm)) throw new Error("simulated ENOSPC writing ca.algorithm");
    return realWrite.apply(this, arguments);
  };
  var threw = null;
  try { await A.initCA(); }
  catch (e) { threw = e; }
  finally { atomicFile.writeSync = realWrite; }
  check("initCA fails when the initial custom label cannot be persisted", threw !== null);
  check("a failed initial creation leaves NO CA installed (no certificate without its durable label)",
        fs.existsSync(A.paths.caCert) === false);
  var B = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await B.initCA();
  check("a retry cleanly installs the CA and persists the label",
        fs.existsSync(B.paths.caCert) === true && fs.readFileSync(B.paths.algorithm, "utf8") === "CUSTOM-A");
}

// An INITIAL commit() that bootstraps the first CA writes no rollback journal (no prior key), so like
// a fresh create its custom label must be persisted BEFORE the CA is published. A failed label write
// must abort before the key/cert land — not defer as though a journal will reconcile it (there is
// none), which would install a labelless CA a sibling would issue under its own stale pin.
async function testInitialCustomCommitLabelWriteFailureFailsClosed() {
  var atomicFile = require("../../lib/atomic-file");
  var src = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await src.initCA();
  var extCert = fs.readFileSync(src.paths.caCert, "utf8");
  var extKey  = fs.readFileSync(src.paths.caKey, "utf8");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.algorithm)) throw new Error("simulated ENOSPC writing ca.algorithm");
    return realWrite.apply(this, arguments);
  };
  var threw = null;
  try { await ca.commit({ caCertPem: extCert, caKeyPem: extKey, algorithm: "CUSTOM-A" }); }
  catch (e) { threw = e; }
  finally { atomicFile.writeSync = realWrite; }
  check("an initial custom commit (no prior key, no journal) whose label write fails, fails closed", threw !== null);
  check("a failed initial commit leaves NO CA installed (no certificate without its durable label)",
        fs.existsSync(ca.paths.caCert) === false);
}

// A custom rotation reads label A, then awaits generateCa; a concurrent commit re-labels the
// byte-identical current cert/key as B. The rotation's compare-and-swap checks generation AND cert
// identity AND the persisted label, so it detects the label migration and refuses rather than
// publishing a new CA under A that overwrites the newer B migration.
async function testRotateConflictsWithConcurrentLabelRestamp() {
  var duringGen = null;
  var base = _p256CaEngineGen([]);
  var slowEngine = Object.assign({}, base, {
    generateCa: async function (a) {
      var out = await base.generateCa(a);
      if (duringGen) { var f = duringGen; duringGen = null; await f(); }
      return out;
    },
  });
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: slowEngine, algorithm: "CUSTOM-A" });
  await ca.initCA();
  var curCert = fs.readFileSync(ca.paths.caCert, "utf8");
  var curKey  = fs.readFileSync(ca.paths.caKey, "utf8");
  duringGen = async function () {
    await ca.commit({ caCertPem: curCert, caKeyPem: curKey, algorithm: "CUSTOM-B" });   // re-label the byte-identical CA
  };
  var err = await code2(function () { return ca.rotate({ generation: 2, algorithm: "CUSTOM-A" }); });
  check("a rotation whose CA was re-labelled by a concurrent commit during signing conflicts",
        err === "mtls-ca/rotation-conflict");
  check("the concurrent commit's label (CUSTOM-B) survived the stale rotation",
        fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-B");
}

// A pinned custom handle that bootstraps the CA via commit() WITHOUT redundantly repeating the label
// must still persist ca.algorithm from its effective pin — else a sibling adopts the CA under its own
// stale pin or engine default. _customCommitLabel falls back to the handle's caAlgorithm.
async function testInitialPinnedCommitWithoutOverridePersistsHandleLabel() {
  var src = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await src.initCA();
  var extCert = fs.readFileSync(src.paths.caCert, "utf8");
  var extKey  = fs.readFileSync(src.paths.caKey, "utf8");
  var ca = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await ca.commit({ caCertPem: extCert, caKeyPem: extKey });   // no commit.algorithm override
  check("an initial pinned custom commit without an override persists the handle's label",
        fs.existsSync(ca.paths.algorithm) === true && fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-A");
}

// A non-ENOENT ca.algorithm read failure (permissions, an unreadable/unmounted path, an over-cap read)
// must FAIL CLOSED, not masquerade as "no label" — else a sibling adopts the CA under a stale/default
// label. Only a genuine absent-file race (ENOENT between the existsSync check and the read) is missing.
async function testPersistedLabelReadFailureFailsClosed() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await ca.initCA();
  var realRead = atomicFile.fdSafeReadSync;
  var eacces = new Error("EACCES: permission denied"); eacces.code = "EACCES";
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.algorithm)) throw eacces;
    return realRead.apply(this, arguments);
  };
  var sib = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });
  var threw = null;
  try { await sib.generateClientCert({ cn: "x" }); }   // adoption reads the label
  catch (e) { threw = e; }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("a non-ENOENT ca.algorithm read failure fails closed (adoption aborts)", threw !== null);
  // The ENOENT race branch: a vanished file reads as missing (undefined), not a hard error.
  var enoent = new Error("ENOENT: no such file"); enoent.code = "ENOENT";
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(ca.paths.algorithm)) throw enoent;
    return realRead.apply(this, arguments);
  };
  var probe = null;
  try { probe = await code2(function () { return sib.canVerifyInTls(); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("an ENOENT ca.algorithm race reads as no-label (undeterminable), not a hard read error",
        probe === "mtls-ca/algorithm-undeterminable");
}

// A same-cert re-label whose ca.algorithm write SUCCEEDS but whose journal delete then FAILS is
// rejected (fails closed). The rollback must restore the PRIOR label — else the rejected migration
// leaves the new label active. The journal carries the prior label too, so an interrupted-commit
// reconcile (a crash between the catch's restore and the journal delete) also restores it.
async function testSameCertRelabelJournalDeleteFailureRestoresPriorLabel() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]), algorithm: "CUSTOM-A" });
  await ca.initCA();
  var curCert = fs.readFileSync(ca.paths.caCert, "utf8");
  var curKey  = fs.readFileSync(ca.paths.caKey, "utf8");
  var journal = ca.paths.caKey + ".rollback";
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) throw new Error("simulated journal-delete failure");
    return realUnlink.apply(this, arguments);
  };
  var threw = null;
  try { await ca.commit({ caCertPem: curCert, caKeyPem: curKey, algorithm: "CUSTOM-B" }); }
  catch (e) { threw = e; }
  finally { fs.unlinkSync = realUnlink; }
  check("a same-cert re-label whose journal delete fails is rejected", threw !== null);
  check("the rejected re-label restored the prior label (CUSTOM-A), not left CUSTOM-B active",
        fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-A");
  // status() must NOT report the retained rejected journal's label: the journal is an INTERRUPTED
  // same-cert re-stamp (live cert == its prior cert), so the rollback-restored file label (A) wins.
  check("status() reports the restored label (CUSTOM-A) despite the retained rejected-relabel journal",
        ca.status().algorithm === "CUSTOM-A");
  // The surviving journal reconciles on reopen; the interrupted-commit path restores the prior label.
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });
  await reopened.generateClientCert({ cn: "after-relabel-reject" });
  check("after reconcile the label is still the prior CUSTOM-A", fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-A");
}

// When there was NO prior label (an UNPINNED custom CA being re-labeled), a rejected re-label must
// REMOVE the newly-written ca.algorithm on rollback rather than leave it — the no-prior-label arm of
// the label rollback.
async function testUnpinnedCustomRelabelRejectRemovesLabel() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });   // unpinned: no label file
  await ca.initCA();
  var curCert = fs.readFileSync(ca.paths.caCert, "utf8");
  var curKey  = fs.readFileSync(ca.paths.caKey, "utf8");
  var journal = ca.paths.caKey + ".rollback";
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(journal)) throw new Error("simulated journal-delete failure");
    return realUnlink.apply(this, arguments);
  };
  var threw = null;
  try { await ca.commit({ caCertPem: curCert, caKeyPem: curKey, algorithm: "CUSTOM-B" }); }
  catch (e) { threw = e; }
  finally { fs.unlinkSync = realUnlink; }
  check("an unpinned-CA re-label whose journal delete fails is rejected", threw !== null);
  check("the rejected re-label removed the newly-written label (no prior label to restore)",
        fs.existsSync(ca.paths.algorithm) === false);
}

// status() must report a custom engine's PERSISTED label, not _certAlgorithm's bundled inference: a
// custom P-384 CA labeled "CUSTOM-P384" would otherwise be reported as "ECDSA-P384-SHA384", making
// migration/audit logic act on the wrong algorithm. keyType stays certificate-derived.
async function testStatusReportsPersistedCustomLabel() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p384CaEngineGen(), algorithm: "CUSTOM-P384" });
  await ca.initCA();
  var st = ca.status();
  check("status() reports the persisted custom label (CUSTOM-P384), not the bundled inference",
        st.algorithm === "CUSTOM-P384");
  check("status() still reports the certificate-derived keyType (ec)", st.keyType === "ec");
  // An UNPINNED custom CA has no persisted label, so status() reports null (undeterminable) rather
  // than the misleading bundled guess.
  var dir2 = _mkTmp();
  var unpinned = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", engine: _p384CaEngineGen() });
  await unpinned.initCA();
  check("an unpinned custom CA reports algorithm null (no misleading bundled label)",
        unpinned.status().algorithm === null && unpinned.status().keyType === "ec");
}

// When a CA-changing commit publishes the new CA but its ca.algorithm write fails (deferred), the new
// label lives only in the retained COMPLETED-commit journal until a reconcile runs. The read-only
// status()/canVerifyInTls() paths must report that pending label — not the stale file — so a
// status-only migration/audit process does not act on the wrong algorithm indefinitely.
async function testStatusReportsDeferredLabelFromJournal() {
  var atomicFile = require("../../lib/atomic-file");
  var dir = _mkTmp();
  var probes = [];
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([], null, probes), algorithm: "CUSTOM-A" });
  await ca.initCA();
  var journal = ca.paths.caKey + ".rollback";
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function (p) {
    if (String(p) === String(ca.paths.algorithm)) throw new Error("simulated ENOSPC writing ca.algorithm");
    return realWrite.apply(this, arguments);
  };
  try { await ca.rotate({ generation: 2, algorithm: "CUSTOM-B", retainPrevious: false }); }   // CA-changing; label write deferred
  finally { atomicFile.writeSync = realWrite; }
  check("the deferred label left the file stale (CUSTOM-A) with the completed-commit journal retained",
        fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-A" && fs.existsSync(journal) === true);
  check("status() reports the deferred completed-commit label (CUSTOM-B) from the journal, not the stale file",
        ca.status().algorithm === "CUSTOM-B");
  probes.length = 0;
  await ca.canVerifyInTls();
  check("canVerifyInTls() also probes the deferred label (CUSTOM-B) from the journal",
        probes.length === 1 && probes[0] === "CUSTOM-B");
}

// When an unpinned CA's rejected re-label is left on disk (the catch could not unlink it, so it
// retained the journal), reconcile must REMOVE ca.algorithm — the null-prior sentinel means there is
// no prior label to restore. Else the rejected new label stays active after the fault clears.
async function testReconcileRemovesNullPriorRejectedLabel() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });   // unpinned
  await ca.initCA();
  var curCert = fs.readFileSync(ca.paths.caCert, "utf8");
  var curKey  = fs.readFileSync(ca.paths.caKey, "utf8");
  var journal = ca.paths.caKey + ".rollback";
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {   // fail BOTH the catch's label unlink AND the journal delete (crash-mid-catch analog)
    if (String(p) === String(journal) || String(p) === String(ca.paths.algorithm)) throw new Error("simulated unlink failure");
    return realUnlink.apply(this, arguments);
  };
  var threw = null;
  try { await ca.commit({ caCertPem: curCert, caKeyPem: curKey, algorithm: "CUSTOM-B" }); }
  catch (e) { threw = e; }
  finally { fs.unlinkSync = realUnlink; }
  check("the rejected re-label was left on disk (catch unlink failed) with the journal retained",
        threw !== null && fs.readFileSync(ca.paths.algorithm, "utf8") === "CUSTOM-B" && fs.existsSync(journal) === true);
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: _p256CaEngineGen([]) });
  await reopened.generateClientCert({ cn: "after-null-prior" });   // triggers reconcile
  check("reconcile removed the rejected label (null prior — nothing to restore)",
        fs.existsSync(ca.paths.algorithm) === false);
}

// A stored CA whose generation is UNDETERMINABLE (a custom engine's opaque cert
// node:crypto cannot parse -> status().generation === 0) cannot be rotated: a default
// rotation would mint generation 1 (mis-cohorting the leaves it revokes) and an explicit
// lower/equal generation would be accepted, violating the strictly-increasing invariant.
async function testRotateRefusesUndeterminableGeneration() {
  var dir = _mkTmp();
  var eng = {
    generateCa:     async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNh\n-----END CERTIFICATE-----", caKeyPem: "-----BEGIN PRIVATE KEY-----\nb3BhcXVlLWtleQ==\n-----END PRIVATE KEY-----" }; },
    signClientCert: async function () { return { cert: "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----", key: "k" }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  check("an opaque custom CA reports generation 0 (undeterminable)", ca.status().generation === 0);
  check("rotate({generation}) refuses a CA whose current generation is undeterminable",
        (await code2(function () { return ca.rotate({ generation: 3 }); })) === "mtls-ca/generation-undeterminable");
  check("a default rotate() is refused too (cannot compute a strictly-increasing generation)",
        (await code2(function () { return ca.rotate(); })) === "mtls-ca/generation-undeterminable");
}

// A crash journal that is valid JSON but carries an EMPTY (or non-canonical) base64
// byte field must fail closed: an empty base64 `key` decodes to an empty buffer that,
// written over the live CA key on the interrupted path, permanently destroys the CA.
async function testReconcileRejectsMalformedManifestBase64() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var goodKey  = fs.readFileSync(ca.paths.caKey);
  var goodCert = fs.readFileSync(ca.paths.caCert);
  // Empty base64 key (decodes to an empty buffer). The interrupted path (live cert ==
  // manifest.cert) would write it over the live key.
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: Buffer.alloc(0), newKey: null, cert: goodCert, newCert: null,
    retainAfter: false, prevAction: "leave", prevData: null,
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("reconcile fails closed on an EMPTY base64 key (rollback-journal-corrupt)",
        (await code2(function () { return reopened.initCA(); })) === "mtls-ca/rollback-journal-corrupt");
  check("the live CA key is untouched (not destroyed by an empty-buffer overwrite)",
        fs.readFileSync(ca.paths.caKey).equals(goodKey));
  // A NON-CANONICAL base64 key ("abc" round-trips to "abc=") must also be refused.
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key: "abc", cert: goodCert.toString("base64"), retainAfter: false, prevAction: "leave", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  check("reconcile fails closed on a NON-CANONICAL base64 key",
        (await code2(function () { return reopened2.initCA(); })) === "mtls-ca/rollback-journal-corrupt");
}

// generateClientP12 must accept an OPAQUE (unparseable) certPem from a custom engine —
// the same way generateClientCert does — because _certIdentity() still derives a stable
// fingerprint, and parsing cannot prove the certPem is the cert inside the encrypted P12
// anyway. Rejecting it makes the primitive unusable for a post-quantum custom engine.
async function testGenerateClientP12AcceptsOpaqueCert() {
  var dir = _mkTmp();
  var opaqueLeaf = "-----BEGIN CERTIFICATE-----\nb3BhcXVlLXAxMi1sZWFm\n-----END CERTIFICATE-----";
  var eng = {
    generateCa: async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVlLWNh\n-----END CERTIFICATE-----", caKeyPem: "opaque-key" }; },
    packageP12: async function () { return { p12: Buffer.from("p12-bytes"), certPem: opaqueLeaf, issuedAt: new Date(), expiresAt: new Date() }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng });
  await ca.initCA();
  var out = await ca.generateClientP12({ cn: "opaque-p12", password: "pw" });
  check("generateClientP12 accepts an opaque certPem from a custom engine (fingerprint still derived)",
        Buffer.isBuffer(out.p12) && typeof out.fingerprint === "string" && out.fingerprint.length > 0);
}

// status() must NOT report isLegacy:true for an UNDETERMINABLE generation (an opaque
// cert -> generation 0): that would mislabel a current opaque-engine CA as legacy, and
// an isLegacy-keyed upgrade flow would then rotate() it and hit generation-undeterminable
// — status() and rotate() contradicting each other on the same cert.
async function testStatusIsLegacyFalseForUndeterminableGeneration() {
  var dir = _mkTmp();
  var eng = {
    generateCa:     async function () { return { caCertPem: "-----BEGIN CERTIFICATE-----\nb3BhcXVl\n-----END CERTIFICATE-----", caKeyPem: "opaque-key" }; },
    signClientCert: async function () { return { cert: "x", key: "k" }; },
  };
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: eng, generation: 3 });
  await ca.initCA();
  var s = ca.status();
  check("status: an undeterminable generation (0) is NOT reported as legacy",
        s.generation === 0 && s.isLegacy === false && s.current === 3);
}

// _journalRetainedRoot (the read sibling of reconcile) must validate the journal's base64
// canonically: a malformed prevData would otherwise decode to a garbage NON-empty string
// returned into loadTrustBundle(), and feeding that to a node:tls `ca:` build fails —
// a DoS of the mTLS gate. A corrupt journal's root is left for the locked reconcile.
async function testJournalRetainedRootRejectsMalformedPrevData() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key:  fs.readFileSync(ca.paths.caKey).toString("base64"),
    cert: certG1.toString("base64"),               // == live cert => interrupted
    prevData: "!!!not-canonical-base64",           // malformed: lenient decode -> garbage
    prevAction: "restore",
  }));
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = await reopened.loadTrustBundle();
  check("loadTrustBundle excludes a malformed-prevData journal root (only the current cert)",
        bundle.length === 1 && bundle[0] === certG1.toString("utf8"));
}

// A valid restore-journal is present but the live CA cert is ABSENT (a crash window
// between the retained-root update and the new-cert publish, read before any reconcile).
// _journalRetainedRoot must not trust the journal's old root when it cannot confirm the
// live cert still equals the prior cert — loadTrustBundle returns no root, never throws.
async function testJournalRetainedRootSkippedWhenLiveCertAbsent() {
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var certG1 = fs.readFileSync(ca.paths.caCert);
  fs.writeFileSync(ca.paths.caKey + ".rollback", JSON.stringify({
    key:  fs.readFileSync(ca.paths.caKey).toString("base64"),
    cert: certG1.toString("base64"),               // would match — but the live cert is gone
    prevData: certG1.toString("base64"),           // canonical: a genuine retained root
    prevAction: "restore",
  }));
  fs.rmSync(ca.paths.caCert, { force: true });     // live cert absent -> the existsSync guard is false
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var bundle = await reopened.loadTrustBundle();
  check("loadTrustBundle omits the journal root when the live cert is absent (no throw)",
        Array.isArray(bundle) && bundle.length === 0);
}

// Exhaustive coverage of the reachable error/edge branches accumulated across the
// migration primitives — the paths a happy-path suite skips (bad engine/store output,
// fault-injected reads, undeterminable/superseded generations, key-only/no-CA states).
async function testMtlsCaReachableBranchCoverage() {
  var atomicFile = require("../../lib/atomic-file");

  // rotate() on a FRESH handle (no CA yet): the st.exists=false arms.
  var caFresh = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  var rf = await caFresh.rotate({ generation: 1 });
  check("rotate() on a fresh handle creates a gen-1 CA",
        typeof rf.caCertPem === "string" && caFresh.status().generation === 1);

  // unpinned rotate over a custom P-256 CA: _certAlgorithm -> null -> pin || undefined.
  var caP256 = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: _p256CaEngine() });
  await caP256.initCA();
  check("unpinned rotate over a custom P-256 CA succeeds",
        typeof (await caP256.rotate({ generation: 2 })).caCertPem === "string");

  // rotate() with an engine returning bad generateCa output.
  var caBad = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", engine: {
    generateCa: async function (a) { if (a.generation >= 2) { return { nope: true }; } return engine.generateCa(a); },
    signClientCert: engine.signClientCert } });
  await caBad.initCA();
  check("rotate() rejects an engine that returns bad generateCa output",
        (await code2(function () { return caBad.rotate({ generation: 2 }); })) === "mtls-ca/bad-engine-output");

  // canVerifyInTls with an engine lacking the method.
  var caNoProbe = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
    engine: { generateCa: engine.generateCa, signClientCert: engine.signClientCert } });
  await caNoProbe.initCA();
  check("canVerifyInTls refuses an engine without canVerifyInTls",
        (await code2(function () { return caNoProbe.canVerifyInTls(); })) === "mtls-ca/no-tls-probe");

  // importIssuance edges: non-object entry, missing fingerprint, fingerprint (± serial),
  // superseded-on-import, and a CUSTOM issuanceStore (the Promise.resolve(add()) arm).
  var caImp = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caImp.initCA();
  check("importIssuance rejects a non-object entry",
        (await code2(function () { return caImp.importIssuance([null]); })) === "mtls-ca/bad-import");
  check("importIssuance rejects an entry without a fingerprint",
        (await code2(function () { return caImp.importIssuance([{ generation: 1 }]); })) === "mtls-ca/bad-import");
  var imp = await caImp.importIssuance([{ generation: 1, fingerprint: "ab".repeat(64), serialNumber: "0a" }, { generation: 1, fingerprint: "ba".repeat(64) }]);
  check("importIssuance imports fingerprint entries (with and without a serial)", imp.imported === 2);
  await caImp.revokeGeneration(3);
  // Both a fingerprint-only and a fingerprint+serial below-watermark entry supersede on import,
  // each revoked by its (globally-unique) fingerprint — exercising the superseded sweep.
  check("importIssuance revokes below-watermark fingerprint entries",
        (await caImp.importIssuance([
          { generation: 1, fingerprint: "cd".repeat(64) },
          { generation: 1, fingerprint: "dc".repeat(64), serialNumber: "0f" },
        ])).revoked === 2);
  var customIss = { _l: [], list: function () { return this._l; }, add: function (e) { this._l.push(e); } };
  var caCI = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: customIss });
  await caCI.initCA();
  check("importIssuance with a custom issuanceStore imports through it",
        (await caCI.importIssuance([{ generation: 1, fingerprint: "ef".repeat(64) }])).imported === 1 && customIss._l.length === 1);

  // revokeGeneration: unknown reason, and a real sweep that revokes a below-n leaf.
  var caRev = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caRev.initCA();
  var leaf = await caRev.generateClientCert({ cn: "gen1" });
  check("revokeGeneration rejects an unknown reason",
        (await code2(function () { return caRev.revokeGeneration(2, { reason: "bogus" }); })) === "mtls-ca/bad-reason");
  var rg = await caRev.revokeGeneration(2);
  check("revokeGeneration sweeps and revokes a below-n leaf",
        rg.revoked === 1 && caRev.isRevoked(leaf.fingerprint) === true);
  var revs = caRev.getRevocations();
  check("getRevocations returns a copy of the revocation registry",
        Array.isArray(revs) && revs.length >= 1 && revs !== caRev.getRevocations());

  // A below-watermark issuance self-revokes (issuance-superseded, the gen < watermark arm).
  var caSup = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caSup.initCA();
  await caSup.revokeGeneration(5);
  check("issuing under a below-watermark generation self-revokes",
        (await code2(function () { return caSup.generateClientCert({ cn: "x" }); })) === "mtls-ca/issuance-superseded");

  // A clustered revocationStore whose readGenerationWatermark returns a non-number.
  var sharedIss = { _l: [], list: function () { return this._l; }, add: function (e) { this._l.push(e); } };
  var caWm = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", issuanceStore: sharedIss,
    revocationStore: { list: function () { return []; }, add: function () {},
      readGenerationWatermark: function () { return "nope"; }, bumpGenerationWatermark: function () {} } });
  await caWm.initCA();
  check("issuance fails closed when a clustered watermark is non-numeric",
        (await code2(function () { return caWm.generateClientCert({ cn: "x" }); })) === "mtls-ca/watermark-unreadable");

  // A versioned revocationStore: the version() rebuild arm.
  var verStore = { _l: [], _v: 1, list: function () { return this._l; },
    add: function (e) { this._l.push(e); this._v += 1; }, version: function () { return this._v; } };
  var caVer = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled", revocationStore: verStore });
  await caVer.initCA();
  var lv = await caVer.generateClientCert({ cn: "v" });
  await caVer.revoke(lv.serialNumber);
  check("a versioned revocationStore reflects a revocation via its version() signal",
        caVer.isRevoked(lv.serialNumber) === true);

  // A malformed issuance ledger (parse throws) fails closed — revokeGeneration reads the
  // ledger directly, so it surfaces issuance-corrupt (generateClientCert would wrap it).
  var caIL = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caIL.initCA();
  fs.writeFileSync(caIL.paths.issuance, "not json{{{");
  check("a malformed issuance ledger fails closed (issuance-corrupt)",
        (await code2(function () { return caIL.revokeGeneration(2); })) === "mtls-ca/issuance-corrupt");

  // The issuanceStore.add write throwing fails issuance closed.
  var caIW = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled",
    issuanceStore: { list: function () { return []; }, add: function () { throw new Error("disk full"); } } });
  await caIW.initCA();
  check("issuance fails closed when the ledger write throws",
        (await code2(function () { return caIW.generateClientCert({ cn: "x" }); })) === "mtls-ca/issuance-ledger-write-failed");

  // The local watermark file present-but-unreadable aborts issuance.
  var caWr = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caWr.initCA();
  await caWr.revokeGeneration(2);
  var realRead = atomicFile.fdSafeReadSync;
  atomicFile.fdSafeReadSync = function (p) {
    if (String(p) === String(caWr.paths.revokedGeneration)) { throw new Error("wm read fail"); }
    return realRead.apply(this, arguments);
  };
  var wmErr;
  try { wmErr = await code2(function () { return caWr.generateClientCert({ cn: "x" }); }); }
  finally { atomicFile.fdSafeReadSync = realRead; }
  check("issuance fails closed when the local watermark file is unreadable", wmErr === "mtls-ca/watermark-unreadable");

  // loadTrustBundle on a handle with NO CA (cur null -> []).
  var caNoCa = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  check("loadTrustBundle on a handle with no CA returns []", (await caNoCa.loadTrustBundle()).length === 0);

  // A malformed-JSON rollback journal is tolerated by the trust-bundle read (parse catch).
  var caJ = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caJ.initCA();
  fs.writeFileSync(caJ.paths.caKey + ".rollback", "not-json{{{");
  check("loadTrustBundle tolerates a malformed journal (parse catch)", (await caJ.loadTrustBundle()).length === 1);

  // A key-only commit (ca.crt absent) journals cert:null and publishes the new CA.
  var caK = b.mtlsCa.create({ dataDir: _mkTmp(), caKeySealedMode: "disabled" });
  await caK.initCA();
  fs.rmSync(caK.paths.caCert, { force: true });
  var g2 = await engine.generateCa({ generation: 2 });
  await caK.commit({ caKeyPem: g2.caKeyPem, caCertPem: g2.caCertPem, retainPrevious: false });
  check("a key-only commit (no prior cert) publishes the new CA",
        fs.readFileSync(caK.paths.caCert).toString("utf8") === g2.caCertPem);
}

// Reconcile / journal-read arms that only fire when a crash left files ABSENT: the
// current-cert / current-key reads returning null, a completed journal with no newKey,
// and the trust-read tolerating an absent current cert.
async function testReconcileFileAbsentBranches() {
  // Interrupted crash with BOTH ca.crt and ca.key removed: reconcile's curCertBuf and
  // curKeyRaw null arms, and _journalRetainedRoot's no-current-cert arm.
  var dir = _mkTmp();
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await ca.initCA();
  var key1 = fs.readFileSync(ca.paths.caKey);
  var cert1 = fs.readFileSync(ca.paths.caCert);
  fs.rmSync(ca.paths.caCert, { force: true });
  fs.rmSync(ca.paths.caKey, { force: true });
  fs.writeFileSync(ca.paths.caKey + ".rollback", _journalManifest({
    key: key1, newKey: key1, cert: cert1, newCert: cert1,   // live cert absent => interrupted
    retainAfter: false, crlMovedAside: false, prevAction: "delete", prevData: null,
  }));
  check("loadTrustBundle with a journal and no ca.crt returns []", (await ca.loadTrustBundle()).length === 0);
  var g = await engine.generateCa({ generation: 2 });
  var reopened = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  await reopened.commit({ caKeyPem: g.caKeyPem, caCertPem: g.caCertPem, retainPrevious: false });
  check("commit reconciles a key/cert-absent interrupted journal then publishes",
        fs.readFileSync(reopened.paths.caCert).toString("utf8") === g.caCertPem);

  // Completed key-only journal with NO newKey: the wantKeyBuf null arm (key drive skipped).
  var dir2 = _mkTmp();
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await ca2.initCA();
  var certA = fs.readFileSync(ca2.paths.caCert);
  var keyA = fs.readFileSync(ca2.paths.caKey);
  fs.writeFileSync(ca2.paths.caKey + ".rollback", _journalManifest({
    key: keyA, newKey: null, cert: null, newCert: certA,   // priorCert null, live==newCert => completed; newKey absent
    retainAfter: false, crlMovedAside: false, prevAction: "delete", prevData: null,
  }));
  var reopened2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  await reopened2.initCA();
  check("reconcile of a completed journal with no newKey leaves the live key",
        fs.readFileSync(reopened2.paths.caKey).equals(keyA));
}

// async variant of code() for rejected promises.
async function code2(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code; } }

async function run() {
  try {
    await testStatusAlgorithmKeyType();
    await testRotate();
    await testTrustBundleRetention();
    await testCanVerifyInTls();
    await testRevokeGeneration();
    await testRotatePersistsOverrideAlgorithm();
    await testRotateRejectsFractionalGeneration();
    await testParseGenerationReadsMultiValuedRdn();
    await testStatusAlgorithmNullForNonP384Ec();
    await testRetainPreviousFalseClearsStaleRoot();
    await testIssuanceLedgerFailsClosed();
    await testRevokeGenerationBackfillsFingerprint();
    await testRetainedRootSurvivesFailedCommit();
    await testRotateAbortsWhenRetainedRootWriteFails();
    await testP12RequiresLedgerIdentity();
    await testCrlOmissionCountExcludesSerialDupes();
    await testConcurrentRotationsSerialize();
    await testRevocationIndexStaysConsistent();
    await testRevocationIndexRefreshesAcrossHandles();
    await testRotationConflictAcrossHandles();
    await testCanVerifyInTlsProbesTargetAlgorithm();
    await testConcurrentIssuanceAllRecorded();
    await testStatusAlgorithmNullForWrongDigest();
    await testIssuanceSupersededByGenerationRevocation();
    await testIssuanceSupersededWithCustomStore();
    await testRevokeGenerationSweepsFingerprintlessCustomStoreEntry();
    await testClusteredWatermarkViaStoreMethods();
    await testInitCaRefusesPersistentPairMismatch();
    await testCommitRollsBackRetainedRootOnCertRenameFailure();
    await testWatermarkMethodsMustBePaired();
    await testP12CertPemMustBeNonEmpty();
    await testRotateRejectsEmptyAlgorithm();
    await testNestedPathParentDirsCreated();
    await testMalformedWatermarkAbortsIssuance();
    await testImportIssuanceBackfill();
    await testImportRequiresFingerprint();
    await testLoadTrustBundleToleratesConcurrentPrevRemoval();
    await testImportOfRevokedGenerationIsRevoked();
    await testInterruptedRotationRecoversFromJournal();
    await testInterruptedRotationRecoversRetainedRoot();
    await testIdempotentRecommitPreservesRetainedRootAcrossCrash();
    await testByteIdenticalHardCutDoesNotResurrectRoot();
    await testCorruptIssuanceLedgerSchemaFailsClosed();
    await testRotateRetainFalseAbortsWhenRemovalFails();
    await testCanVerifyInTlsRequiresLabelWhenUndeterminable();
    await testClusteredRevocationStoreRequiresSharedIssuanceStore();
    await testLoadTrustBundleDedupsIdenticalRetainedRoot();
    await testRefuseConsecutiveRetainedRotations();
    await testRotateAbortsWhenPriorKeyUnreadable();
    await testLoadTrustBundleIncludesUnreconciledJournalRoot();
    await testLoadTrustBundleExcludesSpentJournalRoot();
    await testLoadTrustBundleExcludesSpentHardCutRoot();
    await testPartialRollbackKeepsJournalForRetainedRoot();
    await testCommitAbortsWhenPriorCertUnreadable();
    await testCommitAbortsWhenPriorRetainedRootUnreadable();
    await testDropRetainedReconcilesInterruptedJournal();
    await testCustomEngineReconcileRestoresKeyByBytes();
    await testUnpinnedRotatePreservesStoredAlgorithm();
    await testHardCutRotationSupersedesStraddlingIssuance();
    await testDropRetainedSupersedesStraddlingIssuance();
    await testNormalIssuanceNotFalselySuperseded();
    await testConcurrentFirstInitDoesNotClobber();
    await testReconcileFinishesCompletedRotationWithLostKey();
    await testReconcileRemovesResurrectedHardCutRoot();
    await testPublicCommitEnforcesSingleRetainedWindow();
    await testCanVerifyInTlsProbesDefaultBeforeInit();
    await testReconcileJournalDeletionFailurePropagates();
    await testPublicCommitIsLockedPromise();
    await testRotationInvalidatesStaleCrl();
    await testPublicCommitReconcilesLeftoverJournalFirst();
    await testRotationCasToleratesReformattedConcurrentCommit();
    await testRotateReturnsEffectiveCustomEngineLabel();
    await testGenerateCrlSkipsPersistIfCaRotated();
    await testGenerateCrlSkipsPersistIfRevocationLandedDuringSigning();
    await testGenerateCrlPersistsDespiteConcurrentNormalIssuance();
    await testGenerateCrlPersistsDespiteConcurrentFingerprintRevoke();
    await testGenerateCrlScopedSerialsFallbackCoversRichState();
    await testGenerateCrlPersistRecomputesFromCoherentStoreView();
    await testCommitLabelWriteFailureRollsForwardNotAbort();
    await testCanVerifyInTlsUsesPersistedLabelAfterSiblingRotation();
    await testSameCertLabelRestampWriteFailureFailsClosed();
    await testFreshCreateLabelWriteFailureLeavesNoOrphanCa();
    await testInitialCustomCommitLabelWriteFailureFailsClosed();
    await testRotateConflictsWithConcurrentLabelRestamp();
    await testInitialPinnedCommitWithoutOverridePersistsHandleLabel();
    await testPersistedLabelReadFailureFailsClosed();
    await testSameCertRelabelJournalDeleteFailureRestoresPriorLabel();
    await testUnpinnedCustomRelabelRejectRemovesLabel();
    await testStatusReportsPersistedCustomLabel();
    await testStatusReportsDeferredLabelFromJournal();
    await testReconcileRemovesNullPriorRejectedLabel();
    await testGenerateCrlSkipsPersistIfIssuerBackfilledDuringSigning();
    await testGenerateCrlPersistsWithCustomRevocationStore();
    await testGenerateCrlPersistsWithCustomIssuanceStore();
    await testLeafAlgorithmBindsToSnapshotNotRacingPinRefresh();
    await testCanVerifyInTlsPrefersCustomPinOverInferredLabel();
    await testPublicCommitInvalidatesStaleCrl();
    await testRotationCasDetectsSameGenerationCommit();
    await testPublicCommitRefusesRetentionAmbiguityWhileWindowOpen();
    await testMutatingPathFailsClosedOnCorruptRollbackJournal();
    await testRotationAbortsWhenStaleCrlCannotBeMovedAside();
    await testRotationRestoresCrlWhenCertPublishFails();
    await testReconcileRestoresCrlForInterruptedRotation();
    await testOpaqueCustomEngineIssuanceGenerationNotZero();
    await testFreshInitAdoptionValidatesPin();
    await testPublicCommitRefreshesAlgorithmPin();
    await testReconcileRollsForwardKeyOnlyInit();
    await testPublicCommitPreservesCustomEnginePin();
    await testCanVerifyInTlsRejectsInvalidExplicitAlgorithm();
    await testNonBooleanRetainPreviousRejected();
    await testCommitDoesNotRestoreOrphanCrlRollback();
    await testReconcileDoesNotRestoreOrphanCrlRollback();
    await testReconcileRemovesResurrectedLiveCrlOnRollForward();
    await testReconcileRemovesLeftoverCrlRollbackOnRollForward();
    await testIdempotentRetainedCommitDoesNotOpenGraceWindow();
    await testIdempotentRetainedCommitToleratesPemReformatting();
    await testIssuanceNotRevokedWhenRootRepublishedReformatted();
    await testCommitRejectsCertOnlyState();
    await testCommitRejectsMismatchedCaPair();
    await testCommitRejectsUnsupportedBundledAlgorithm();
    await testCommitRejectsNonCaCertificate();
    await testCommitNormalizesSec1KeyEncoding();
    await testCommitRejectsCaWithoutCrlSign();
    await testCommitRejectsCaOutsideValidity();
    await testGateFingerprintLengthEnforced();
    await testIssuanceRefusedWhenLedgerWouldExceedReadCap();
    await testCrlScopedToCurrentIssuerIdentity();
    await testCrlDedupsAndSkipsMalformedLedgerEntries();
    await testSerialRevokedMatchesOnlySerialOnlyEntries();
    await testSerialOnlyRevokeNotDedupedAgainstFingerprintEntry();
    await testCommitRejectsUnparseableBundledMaterial();
    await testImportIssuanceRecordsIssuerForCrlScoping();
    await testCommitClearsOrphanCrlRollbackBeforeMoveAside();
    await testIdempotentCommitPreservesCrl();
    await testCommitFailsClosedWhenSameCertCutJournalUnlinkFails();
    await testCommitSwallowsJournalUnlinkFailureOnCertChange();
    await testCommitUpdatesCustomEnginePinToSuppliedAlgorithm();
    await testCommitAppliesCustomAlgorithmOnUnpinnedHandle();
    await testCustomLabelPersistsAcrossHandles();
    await testPersistedAlgorithmReadEdges();
    await testColdStartAdoptReadsPersistedCustomLabel();
    await testUnpinnedCustomRotatePreservesPersistedLabel();
    await testCustomLabelPersistIsCrashAtomicWithCommit();
    await testRotateRefusesUndeterminableGeneration();
    await testReconcileRejectsMalformedManifestBase64();
    await testGenerateClientP12AcceptsOpaqueCert();
    await testStatusIsLegacyFalseForUndeterminableGeneration();
    await testJournalRetainedRootRejectsMalformedPrevData();
    await testJournalRetainedRootSkippedWhenLiveCertAbsent();
    await testMtlsCaReachableBranchCoverage();
    await testReconcileFileAbsentBranches();
  } finally {
    for (var i = 0; i < _tmpDirs.length; i++) {
      try { fs.rmSync(_tmpDirs[i], { recursive: true, force: true }); } catch (_e) { /* best-effort cleanup */ }
    }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
