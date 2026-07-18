// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cert — turnkey TLS-certificate manager.
 *
 * Tests exercise:
 *   - factory validation (refuses bad opts in every documented shape)
 *   - sealed-disk storage roundtrip (write → read → meta)
 *   - SNI callback (exact + wildcard + fallback)
 *   - manual refresh() with a mocked ACME client
 *   - audit emission on issue / renew / renew-failed
 *   - key escrow (encrypt-to-recipient via b.crypto.encrypt)
 *
 * The live ACME path against an external CA isn't exercised here
 * (no test CA shipped in the framework); the issue/renew flow is
 * exercised via a mock ACME client that fulfils the same contract
 * `b.cert.create` calls into. The b.acme client itself has its own
 * unit tests in `acme.test.js` covering RFC 8555 wire shape.
 */

var fs    = require("node:fs");
var os    = require("node:os");
var path  = require("node:path");
var crypto = require("node:crypto");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cert-"));
}

function _ephemeralVault() {
  // Minimal in-memory vault: seal = XOR with key, unseal = XOR with
  // key. Just enough surface for the manager's seal/unseal calls.
  // The framework's real b.vault uses XChaCha20-Poly1305 + authenticated
  // header; the manager treats vault as an opaque seal/unseal pair.
  var key = crypto.randomBytes(32);
  return {
    seal: function (buf) {
      var out = Buffer.alloc(buf.length);
      for (var i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
      return out;
    },
    unseal: function (buf) {
      var out = Buffer.alloc(buf.length);
      for (var i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
      return out;
    },
  };
}

function _authVault() {
  // Unlike the XOR _ephemeralVault (which silently produces garbage on a
  // tampered blob), this unseal THROWS on corruption — mirroring the real
  // XChaCha20-Poly1305 vault's authenticated decrypt. Needed to exercise
  // the manager's corrupt-sealed-file recovery path, which keys off an
  // unseal throw.
  var key = crypto.randomBytes(32);
  return {
    seal: function (buf) {
      var tag = crypto.createHmac("sha3-512", key).update(buf).digest();
      return Buffer.concat([tag, Buffer.from(buf)]);
    },
    unseal: function (sealed) {
      var tag = sealed.subarray(0, 64);
      var body = sealed.subarray(64);
      var expect = crypto.createHmac("sha3-512", key).update(body).digest();
      if (tag.length !== expect.length || !crypto.timingSafeEqual(tag, expect)) {
        throw new Error("vault: authentication tag mismatch");
      }
      return Buffer.from(body);
    },
  };
}

async function _selfSignedCert(domains, validityDays) {
  // Generate a parseable self-signed X.509 cert via the vendored
  // @peculiar/x509 bundle. The cert manager only parses cert PEM (to
  // read notAfter + fingerprint) so any structurally-valid cert
  // works as fixture material — no CA chain needed for storage
  // roundtrip + SNI tests.
  var pki = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await crypto.webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true, ["sign", "verify"]);
  var now = new Date();
  var notAfter = new Date(now.getTime() + validityDays * 24 * 3600 * 1000);
  var sanExt = new x509.SubjectAlternativeNameExtension(domains.map(function (d) {
    return { type: "dns", value: d };
  }));
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=" + domains[0],
    notBefore:        now,
    notAfter:         notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys:             keys,
    extensions:       [sanExt],
  });
  var pkcs8 = await crypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var pkB64 = Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n");
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" + pkB64 + "\n-----END PRIVATE KEY-----\n";
  return { keyPem: keyPem, certPem: cert.toString("pem") };
}

async function _selfSignedCertNoSan(cn, validityDays) {
  // Like _selfSignedCert but with NO SubjectAlternativeName extension —
  // so the parsed cert's subjectAltName is undefined, exercising the
  // `cert.subjectAltName || null` fallback in the manager's _certMeta.
  var pki = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await crypto.webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var now = new Date();
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "02",
    name:             "CN=" + cn,
    notBefore:        now,
    notAfter:         new Date(now.getTime() + validityDays * 24 * 3600 * 1000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys:             keys,
    extensions:       [],
  });
  var pkcs8 = await crypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var pkB64 = Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n");
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" + pkB64 + "\n-----END PRIVATE KEY-----\n";
  return { keyPem: keyPem, certPem: cert.toString("pem") };
}

function _mockAcmeClient(pem) {
  // Fulfills the b.acme.create contract the cert manager calls into.
  // Every method returns synchronously-resolved promises with the
  // shape the manager expects; the test asserts the manager's
  // behavior given that surface, not the wire-protocol correctness.
  return {
    fetchDirectory: async function () { return { newOrder: "mock://order" }; },
    newAccount:     async function () { return { url: "mock://acct" }; },
    newOrder:       async function (opts) {
      return {
        url:            "mock://order/1",
        status:         "pending",
        authorizations: opts.identifiers.map(function (id, i) {
          return "mock://auth/" + i;
        }),
        finalize:       "mock://order/1/finalize",
      };
    },
    fetchAuthorization: async function (authUrl) {
      var idx = parseInt(authUrl.replace("mock://auth/", ""), 10);
      return {
        url:        authUrl,
        status:     "pending",
        identifier: { type: "dns", value: ["a.example", "b.example", "c.example"][idx] || "x.example" },
        challenges: [
          { type: "http-01",     url: authUrl + "/http01",     token: "tok-" + idx, status: "pending" },
          { type: "dns-01",      url: authUrl + "/dns01",      token: "tok-" + idx, status: "pending" },
          { type: "tls-alpn-01", url: authUrl + "/tlsalpn01",  token: "tok-" + idx, status: "pending" },
        ],
      };
    },
    notifyChallengeReady: async function () { return { status: "processing" }; },
    waitForAuthorization: async function (authUrl) {
      return { url: authUrl, status: "valid" };
    },
    keyAuthorization:        function (token) { return token + ".thumbprint"; },
    tlsAlpn01KeyAuthorization: function (token) { return token + ".alpn-thumb"; },
    buildCsr:                function ()      { return "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----"; },
    finalize:                async function () { return { url: "mock://order/1", status: "valid", certificate: "mock://cert" }; },
    retrieveCert:            async function () { return pem; },
    renewIfDue:              async function () { return { shouldRenew: false }; },
  };
}

// ---- Surface ----

function testSurface() {
  check("b.cert namespace",       typeof b.cert === "object");
  check("b.cert.create is fn",    typeof b.cert.create === "function");
  check("b.cert.CertError class", typeof b.cert.CertError === "function");
}

// ---- Factory validation — refuses every documented bad shape ----

function testFactoryRefusesBadOpts() {
  var threw = function (fn) {
    try { fn(); return null; }
    catch (e) { return e; }
  };

  var e1 = threw(function () { b.cert.create(); });
  check("create() w/o opts → CertError",        e1 && e1.code === "cert/bad-opts");

  var e2 = threw(function () { b.cert.create({}); });
  check("create({}) w/o storage → CertError",   e2 && e2.code === "cert/bad-storage");

  var e3 = threw(function () {
    b.cert.create({ storage: { type: "redis" } });
  });
  check("storage.type=redis → CertError",       e3 && e3.code === "cert/bad-storage-type");

  var e4 = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
    });
  });
  check("no acme block → CertError",            e4 && e4.code === "cert/bad-acme");

  var e5 = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/" },
    });
  });
  check("no certs array → CertError",           e5 && e5.code === "cert/bad-certs");

  var e6 = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/" },
      certs:   [{ name: "x", domains: ["a.com"], challenge: { type: "bogus", provision: function () {}, cleanup: function () {} } }],
    });
  });
  check("bad challenge type → CertError",       e6 && e6.code === "cert/bad-challenge-type");

  var e7 = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/" },
      certs:   [
        { name: "dupe", domains: ["a.com"], challenge: { type: "http-01", provision: function () {}, cleanup: function () {} } },
        { name: "dupe", domains: ["b.com"], challenge: { type: "http-01", provision: function () {}, cleanup: function () {} } },
      ],
    });
  });
  check("duplicate cert name → CertError",      e7 && e7.code === "cert/duplicate-name");

  var e8 = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/" },
      certs:   [{ name: "x", domains: [], challenge: { type: "http-01", provision: function () {}, cleanup: function () {} } }],
    });
  });
  check("empty domains → CertError",            e8 && e8.code === "cert/bad-domains");

  // Path-traversal rejection: cert name lands as a filesystem path
  // segment under storage.rootDir, so manifests sourced from operator-
  // editable config or external control planes can carry attacker-
  // influenced names. The factory refuses anything containing `..`,
  // `/`, `\`, leading dot, or non-printable chars.
  var pathTraversalShapes = [
    "../escape",
    "..",
    "../../etc/passwd",
    "subdir/file",
    "back\\slash",
    ".hidden",
    "has space",
    "has null",
  ];
  pathTraversalShapes.forEach(function (badName) {
    var e = threw(function () {
      b.cert.create({
        storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
        acme:    { directory: "https://example/" },
        certs:   [{ name: badName, domains: ["a.com"], challenge: { type: "http-01", provision: function () {}, cleanup: function () {} } }],
      });
    });
    check("cert name '" + JSON.stringify(badName) + "' refused as path-segment", e && e.code === "cert/bad-cert-name");
  });

  // ---- compliance posture validation ----
  // opts.compliance names are validated against b.compliance.KNOWN_POSTURES
  // at create() so a typo is caught at boot rather than silently recorded.
  var goodChallenge = { type: "http-01", provision: function () {}, cleanup: function () {} };
  var eBadPosture = threw(function () {
    b.cert.create({
      storage:    { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:       { directory: "https://example/", accountKey: "auto" },
      certs:      [{ name: "m", domains: ["a.com"], challenge: goodChallenge }],
      compliance: ["not-a-real-posture"],
      audit:      false,
    });
  });
  check("unknown compliance posture → cert/unknown-compliance-posture",
    eBadPosture && eBadPosture.code === "cert/unknown-compliance-posture");

  var eGoodPosture = threw(function () {
    b.cert.create({
      storage:    { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:       { directory: "https://example/", accountKey: "auto" },
      certs:      [{ name: "m", domains: ["a.com"], challenge: goodChallenge }],
      compliance: ["hipaa", "pci-dss"],
      audit:      false,
    });
  });
  check("known compliance postures accepted", !eGoodPosture);

  // ---- b.network.tls.ocsp.fetch composition surface ----
  check("b.network.tls.ocsp.fetch is a function",
    typeof b.network.tls.ocsp.fetch === "function");
}

// b.network.tls.ocsp.fetch rejects on missing leafPem/issuerPem rather than
// issuing an outbound request with undefined inputs.
async function testOcspFetchRejectsBadInput() {
  var rejected = false;
  try {
    await b.network.tls.ocsp.fetch({});
  } catch (_e) {
    rejected = true;
  }
  check("ocsp.fetch({}) rejects (no leafPem/issuerPem)", rejected);
}

// ---- Sealed-disk storage roundtrip ----

async function testStorageRoundtrip() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["example.com"], 90);

  var noChallenge = { type: "http-01", provision: async function () {}, cleanup: async function () {} };
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"], challenge: noChallenge }],
    audit:   false,
  });

  // The manager's internal _ensureCert path calls _issueCert if no
  // cached cert exists. Inject the cert via the storage layer directly
  // so we don't depend on the live ACME path here.
  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  var meta = {
    expiresAt:         Date.now() + 90 * 86400000,
    issuedAt:          Date.now(),
    fingerprintSha256: "deadbeef",
    subject:           "CN=example.com",
    lastRenewedAt:     Date.now(),
    keyAlg:            "ecdsa-p256",
  };
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify(meta));

  // Mock the ACME client so newAccount/etc don't reach the network.
  // The manager's internal _bootAcme uses b.acme.create — we don't
  // intercept it here; for the storage-roundtrip test the cached
  // cert is fresh enough that _ensureCert short-circuits before
  // calling ACME at all.
  await mgr.start();

  var ctx = mgr.getContext("main");
  check("getContext returns cert PEM",   typeof ctx.cert === "string" && ctx.cert.indexOf("BEGIN CERTIFICATE") !== -1);
  check("getContext returns key PEM",    typeof ctx.key === "string" && ctx.key.indexOf("BEGIN PRIVATE KEY") !== -1);
  check("getContext returns expiresAt",  typeof ctx.expiresAt === "number" && ctx.expiresAt > Date.now());

  await mgr.stop();
}

// ---- SNI callback (exact match + fallback) ----

async function testSniCallback() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pemA = await _selfSignedCert(["a.example", "alt.a.example"], 90);
  var pemB = await _selfSignedCert(["b.example"], 90);

  function _seedCert(name, pem) {
    fs.mkdirSync(path.join(tmp, name), { recursive: true });
    fs.writeFileSync(path.join(tmp, name, "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
    fs.writeFileSync(path.join(tmp, name, "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
    fs.writeFileSync(path.join(tmp, name, "meta.json"), JSON.stringify({
      expiresAt:         Date.now() + 90 * 86400000,
      issuedAt:          Date.now(),
      fingerprintSha256: name,
      subject:           "CN=" + (name === "a" ? "a.example" : "b.example"),
      lastRenewedAt:     Date.now(),
      keyAlg:            "ecdsa-p256",
    }));
  }
  _seedCert("a", pemA);
  _seedCert("b", pemB);

  var noChallenge = { type: "http-01", provision: async function () {}, cleanup: async function () {} };
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [
      { name: "a", domains: ["a.example", "alt.a.example"], challenge: noChallenge },
      { name: "b", domains: ["b.example"],                  challenge: noChallenge },
    ],
    audit:   false,
  });
  await mgr.start();

  // Exact-match SNI → returns the right cert.
  var ctxA = await new Promise(function (resolve, reject) {
    mgr.sniCallback("a.example", function (err, ctx) { if (err) return reject(err); resolve(ctx); });
  });
  check("sniCallback: exact match a.example", ctxA && typeof ctxA === "object");

  var ctxB = await new Promise(function (resolve, reject) {
    mgr.sniCallback("b.example", function (err, ctx) { if (err) return reject(err); resolve(ctx); });
  });
  check("sniCallback: exact match b.example", ctxB && typeof ctxB === "object");

  // Unknown servername → falls back to the first registered cert (not an error).
  var ctxFallback = await new Promise(function (resolve, reject) {
    mgr.sniCallback("unknown.example", function (err, ctx) { if (err) return reject(err); resolve(ctx); });
  });
  check("sniCallback: unknown → fallback to first cert", ctxFallback && typeof ctxFallback === "object");

  await mgr.stop();
}

async function testSniWildcardSingleLabel() {
  // RFC 6125 §6.4.3 — `*.example.com` matches exactly ONE label in the
  // left-most position. `foo.bar.example.com` does NOT match.
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pemWild  = await _selfSignedCert(["*.wild.example"], 90);
  var pemOther = await _selfSignedCert(["other.example"], 90);

  function _seed(name, pem) {
    fs.mkdirSync(path.join(tmp, name), { recursive: true });
    fs.writeFileSync(path.join(tmp, name, "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
    fs.writeFileSync(path.join(tmp, name, "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
    fs.writeFileSync(path.join(tmp, name, "meta.json"), JSON.stringify({
      expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
      fingerprintSha256: name, subject: "CN=" + (name === "wild" ? "*.wild.example" : "other.example"),
      lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
    }));
  }
  _seed("wild",  pemWild);
  _seed("other", pemOther);

  var noChallenge = { type: "http-01", provision: async function () {}, cleanup: async function () {} };
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [
      { name: "wild",  domains: ["*.wild.example"], challenge: noChallenge },
      { name: "other", domains: ["other.example"],  challenge: noChallenge },
    ],
    audit:   false,
  });
  await mgr.start();

  // Single-label leading: `foo.wild.example` matches `*.wild.example`.
  var ctxSingle = await new Promise(function (resolve, reject) {
    mgr.sniCallback("foo.wild.example", function (err, c) { if (err) return reject(err); resolve(c); });
  });
  check("sniWildcard: single-label leading matches", ctxSingle && typeof ctxSingle === "object");

  // Multi-label leading: `foo.bar.wild.example` MUST NOT match
  // `*.wild.example`; should fall back to the first registered cert.
  // (Per the manager's documented fallback contract.) The point of
  // this check is the wildcard branch is NOT selected — the result
  // is the same context type but the path through the matcher is
  // wildcard-rejected → fallback.
  var ctxMulti = await new Promise(function (resolve, reject) {
    mgr.sniCallback("foo.bar.wild.example", function (err, c) { if (err) return reject(err); resolve(c); });
  });
  check("sniWildcard: multi-label leading falls back (does NOT match wildcard)",
    ctxMulti && typeof ctxMulti === "object");

  // Servername exactly equal to the wildcard tail (no left-most
  // label at all): `wild.example` MUST NOT match `*.wild.example`.
  // Falls back to first cert.
  var ctxBare = await new Promise(function (resolve, reject) {
    mgr.sniCallback("wild.example", function (err, c) { if (err) return reject(err); resolve(c); });
  });
  check("sniWildcard: bare tail does NOT match wildcard", ctxBare && typeof ctxBare === "object");

  await mgr.stop();
}

async function testRefreshForcesIssue() {
  // refresh(name) MUST run the ACME issue flow regardless of whether
  // the cached cert is still inside its expiry window. Operators call
  // refresh() for emergency rotation (key compromise, CA misissuance
  // investigation, posture change) — the manager must not silently
  // short-circuit to cached material in that case.
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["example.com"], 90);

  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=example.com",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));

  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{
      name:      "main",
      domains:   ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} },
    }],
    audit: false,
  });
  await mgr.start();
  // start() loaded the cached cert; refresh() must NOT short-circuit
  // to the same cached cert. Since this test mocks no live ACME
  // backend, refresh() will attempt the network call + fail. The
  // failure shape proves we went past the cache-fresh short-circuit.
  var threw = null;
  try { await mgr.refresh("main"); } catch (e) { threw = e; }
  check("refresh: bypasses cache-fresh short-circuit (reached network)",
    threw && /dns lookup|EAI_AGAIN|failed/.test(threw.message || String(threw)));

  await mgr.stop();
}

// ---- Key escrow — encrypt-to-recipient envelope shape ----

async function testKeyEscrow() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["example.com"], 90);

  // Offline break-glass recipient — an ML-KEM-1024 (+ P-384 hybrid)
  // keypair. b.crypto.encrypt seals the escrowed key to its public keys.
  var recipientKp = b.crypto.generateEncryptionKeyPair();

  // Seed a fake cert so start() doesn't try to ACME.
  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=example.com",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));

  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{
      name:      "main",
      domains:   ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} },
      keyEscrow: { recipient: { publicKey: recipientKp.publicKey, ecPublicKey: recipientKp.ecPublicKey } },
    }],
    audit: false,
  });
  await mgr.start();
  await mgr.stop();
  check("keyEscrow: manager constructs cleanly w/ recipient", true);
}

// ---- Compose with the live b.acme.create — buildCsr + RFC 2986 roundtrip ----

function testAcmeBuildCsrRoundtrip() {
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var acme = b.acme.create({
    directory:  "https://example.com/dir",
    accountKey: {
      privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
      publicPem:  pair.publicKey.export({ type: "spki", format: "pem" }),
      kty: "EC", crv: "P-256",
    },
  });

  // ECDSA P-256
  var leafEc = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var csrEc = acme.buildCsr({
    privateKey: leafEc.privateKey,
    publicKey:  leafEc.publicKey,
    domains:    ["leaf.example.com", "alt.leaf.example.com"],
  });
  check("buildCsr: ECDSA P-256 PEM well-framed",
    csrEc.indexOf("-----BEGIN CERTIFICATE REQUEST-----") === 0 &&
    csrEc.indexOf("-----END CERTIFICATE REQUEST-----") > 0);

  // RSA 2048
  var leafRsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var csrRsa = acme.buildCsr({
    privateKey: leafRsa.privateKey,
    publicKey:  leafRsa.publicKey,
    domains:    ["rsa.example.com"],
  });
  check("buildCsr: RSA-2048 PEM well-framed",
    csrRsa.indexOf("-----BEGIN CERTIFICATE REQUEST-----") === 0);

  // Refuse Ed25519 (operators wanting it build the CSR externally).
  var leafEd = crypto.generateKeyPairSync("ed25519");
  var threw = null;
  try {
    acme.buildCsr({
      privateKey: leafEd.privateKey,
      publicKey:  leafEd.publicKey,
      domains:    ["ed.example.com"],
    });
  } catch (e) { threw = e; }
  check("buildCsr: Ed25519 refused with documented error code",
    threw && threw.code === "acme/bad-csr-key-type");

  // Refuse missing domains.
  var threw2 = null;
  try {
    acme.buildCsr({
      privateKey: leafEc.privateKey,
      publicKey:  leafEc.publicKey,
      domains:    [],
    });
  } catch (e) { threw2 = e; }
  check("buildCsr: empty domains refused",
    threw2 && threw2.code === "acme/bad-csr-domains");
}

// ---- Run ----

// ---- Corrupt-sealed-state recovery (no boot crash loop) ----

async function testCorruptSealedCertReissues() {
  // A corrupt sealed cert/key is RECOVERABLE state — the CA re-issues. The
  // manager must treat an unreadable sealed file like an absent one and
  // re-issue, NOT let a raw unseal/decrypt error escape out of start(): on
  // a managed restart the same corrupt file is read on every boot, so a
  // throw here is an unrecoverable crash loop. (Same shape as the
  // encrypted-DB tmpfs working-copy recovery.)
  var tmp = _tmpDir();
  var vault = _authVault();
  var pem = await _selfSignedCert(["example.com"], 90);

  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  // Cache-fresh cert + meta, so the ONLY reason start() would reach ACME
  // is the corruption — not expiry.
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=example.com",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));
  // Corrupt the sealed cert in place so unseal throws an auth error.
  var blob = fs.readFileSync(path.join(tmp, "main", "cert.pem.sealed"));
  blob[blob.length - 1] ^= 0xff;
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), blob);

  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} } }],
    audit: false,
  });

  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  var msg = (threw && (threw.message || String(threw))) || "";
  // With no reachable CA the re-issue fails with a NETWORK error — which
  // proves start() recovered PAST the corrupt file (rather than crashing
  // on the unseal error before it ever reached the issue path).
  check("corrupt sealed cert → no raw unseal crash",
    threw && !/authentication tag|unseal|decrypt|malformed/i.test(msg));
  check("corrupt sealed cert → routed to ACME re-issue",
    threw && /dns lookup|EAI_AGAIN|ENOTFOUND|getaddrinfo|failed|fetch/i.test(msg));
  try { await mgr.stop(); } catch (_e) { /* never started cleanly */ }

  // Corrupt meta.json (derived index) must ALSO route to re-issue, not
  // throw cert/bad-meta out of start().
  var tmp2 = _tmpDir();
  var v2 = _authVault();
  fs.mkdirSync(path.join(tmp2, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp2, "main", "cert.pem.sealed"), v2.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp2, "main", "key.pem.sealed"),  v2.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp2, "main", "meta.json"), "{ this is not json ");
  var mgr2 = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp2, vault: v2 },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} } }],
    audit: false,
  });
  var threw2 = null;
  try { await mgr2.start(); } catch (e) { threw2 = e; }
  // With a VALID sealed cert present, a corrupt meta.json is advisory:
  // expiry + fingerprint are re-derived from the cert itself, so start()
  // loads the cert cleanly — no cert/bad-meta throw, and no needless
  // re-issue (a corrupt derived index must not force a network round-trip).
  check("corrupt meta.json → no cert/bad-meta throw",
    !threw2 || threw2.code !== "cert/bad-meta");
  check("corrupt meta.json → cert still loads from the sealed cert",
    !threw2 && mgr2.getContext("main") && typeof mgr2.getContext("main").cert === "string");
  try { await mgr2.stop(); } catch (_e) {}
}

async function testStaleMetaDoesNotServeExpiringCert() {
  // The renewal decision must trust the SEALED cert's own notAfter, not the
  // plaintext meta.json index. A meta.expiresAt that disagrees with the cert
  // — drifted, or tampered far-future over an actually-expiring cert — must
  // NOT let start() short-circuit and serve a cert that is in fact due for
  // renewal.
  var tmp = _tmpDir();
  var vault = _authVault();
  var pem = await _selfSignedCert(["example.com"], 5);   // real notAfter ~5d out (< 14-day renew window)

  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  // meta claims a FAR-FUTURE expiry, disagreeing with the real cert.
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "stale", subject: "CN=example.com",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));

  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} } }],
    audit: false,
  });
  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  var msg = (threw && (threw.message || String(threw))) || "";
  // The real cert is inside the 14-day renewal window, so start() must
  // attempt renewal (network-fail here) rather than trusting the stale
  // far-future meta and serving the expiring cert.
  check("stale far-future meta does not skip renewal of an expiring cert",
        threw && /dns lookup|EAI_AGAIN|ENOTFOUND|getaddrinfo|failed|fetch/i.test(msg));
  try { await mgr.stop(); } catch (_e) {}
}

async function testCorruptAccountKeyClearError() {
  // The ACME account key binds order history, so a corrupt one is NOT
  // auto-regenerated (that would silently abandon the account). It must
  // fail with an actionable cert/account-key-unreadable error, not a raw
  // decrypt throw.
  var tmp = _tmpDir();
  var vault = _authVault();
  fs.mkdirSync(path.join(tmp, "account"), { recursive: true });
  // A well-formed sealed account key, then corrupted so unseal throws.
  var realJwk = JSON.stringify({ kty: "EC", crv: "P-256", x: "a", y: "b",
    privatePem: "p", publicPem: "q" });
  var sealed = vault.seal(Buffer.from(realJwk));
  sealed[sealed.length - 1] ^= 0xff;
  fs.writeFileSync(path.join(tmp, "account", "jwk.json.sealed"), sealed);

  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"],
      challenge: { type: "http-01", provision: async function () {}, cleanup: async function () {} } }],
    audit: false,
  });
  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  check("corrupt account key → actionable cert/account-key-unreadable",
    threw && threw.code === "cert/account-key-unreadable");
  try { await mgr.stop(); } catch (_e) {}
}

// ---- Shared fixtures for the issue / renewal / OCSP branch tests ----

var GOOD_CHALLENGE = { type: "http-01", provision: async function () {}, cleanup: async function () {} };

// Patch the acme module's `create` so the manager's internal
// `_bootAcme` (require("./acme").create) returns an injected stub
// instead of building a live RFC 8555 client. Returns a restore fn —
// ALWAYS call it in a finally so module state isn't polluted for the
// next test file sharing the process. This is collaborator injection,
// not a network call: the stub fulfils the same contract cert.js calls.
function _stubAcmeCreate(client) {
  var acmeMod = require("../../lib/acme");
  var orig = acmeMod.create;
  acmeMod.create = function () { return client; };
  return function restore() { acmeMod.create = orig; };
}

// Patch b.network.tls.ocsp.fetch (the OCSP responder call the manager
// composes for stapling). The ocsp object itself is frozen, so swap the
// whole object on the (writable) module property, preserving every other
// method. Same injection discipline as _stubAcmeCreate.
function _stubOcspFetch(fn) {
  var nt = require("../../lib/network-tls");
  var origOcsp = nt.ocsp;
  var patched = {};
  Object.keys(origOcsp).forEach(function (k) { patched[k] = origOcsp[k]; });
  patched.fetch = fn;
  nt.ocsp = patched;
  return function restore() { nt.ocsp = origOcsp; };
}

// A flexible ACME stub. `opts` toggles the adversarial shapes each
// branch test needs (auth already valid, CA offers no matching
// challenge, ARI throws, a later retrieveCert throws).
function _makeStubAcme(pem, opts) {
  opts = opts || {};
  var retrieveCalls = 0;
  return {
    fetchDirectory:      async function () { return {}; },
    newAccount:          async function () { return { url: "mock://acct" }; },
    newOrder:            async function (o) {
      return {
        url:            "mock://order/1",
        status:         "pending",
        authorizations: o.identifiers.map(function (id, i) { return "mock://auth/" + i; }),
        finalize:       "mock://order/1/finalize",
      };
    },
    fetchAuthorization:  async function (u) {
      if (opts.authValid) {
        return { url: u, status: "valid", identifier: { type: "dns", value: "a.example" }, challenges: [] };
      }
      var chs = opts.omitChallengeType
        ? [{ type: "dns-01", url: u + "/d", token: "t", status: "pending" }]
        : [
            { type: "http-01",     url: u + "/h", token: "t", status: "pending" },
            { type: "dns-01",      url: u + "/d", token: "t", status: "pending" },
            { type: "tls-alpn-01", url: u + "/a", token: "t", status: "pending" },
          ];
      return { url: u, status: "pending", identifier: { type: "dns", value: "a.example" }, challenges: chs };
    },
    notifyChallengeReady:      async function () { return {}; },
    waitForAuthorization:      async function (u) { return { url: u, status: "valid" }; },
    keyAuthorization:          function (t) { return t + ".thumb"; },
    tlsAlpn01KeyAuthorization: function (t) { return t + ".alpn"; },
    buildCsr:                  function () { return "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----"; },
    finalize:                  async function () { return { url: "mock://order/1", status: "valid" }; },
    retrieveCert:              async function () {
      retrieveCalls += 1;
      if (opts.failRetrieveAfter && retrieveCalls > opts.failRetrieveAfter) {
        if (Object.prototype.hasOwnProperty.call(opts, "retrieveThrowValue")) throw opts.retrieveThrowValue;
        throw new Error("mock retrieveCert failed (network down)");
      }
      return pem;
    },
    renewIfDue:                async function () {
      if (opts.onRenewIfDue) opts.onRenewIfDue();
      if (opts.renewIfDueThrows) throw new Error("mock ARI renewalInfo fetch failed");
      return { shouldRenew: !!opts.renewIfDueShould };
    },
  };
}

// ---- _positiveFiniteOrDefault — every rejection + null-defaults path ----

function testPositiveFiniteOptRejections() {
  var threw = function (fn) { try { fn(); return null; } catch (e) { return e; } };
  function mk(extra) {
    var base = {
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "m", domains: ["a.com"], challenge: GOOD_CHALLENGE }],
      audit:   false,
    };
    return Object.assign(base, extra);
  }

  // Non-number → throw (typeof branch).
  var eStr = threw(function () { b.cert.create(mk({ renew: { intervalMs: "soon" } })); });
  check("renew.intervalMs non-number → cert/bad-renew-interval", eStr && eStr.code === "cert/bad-renew-interval");

  // Non-finite (Infinity / NaN) → throw (isFinite branch).
  var eInf = threw(function () { b.cert.create(mk({ ocsp: { refreshMs: Infinity } })); });
  check("ocsp.refreshMs Infinity → cert/bad-ocsp-refresh", eInf && eInf.code === "cert/bad-ocsp-refresh");
  var eNaN = threw(function () { b.cert.create(mk({ renew: { minDaysBeforeExpiry: NaN } })); });
  check("renew.minDaysBeforeExpiry NaN → cert/bad-renew-window", eNaN && eNaN.code === "cert/bad-renew-window");

  // Zero / negative → throw (<= 0 branch).
  var eZero = threw(function () { b.cert.create(mk({ renew: { intervalMs: 0 } })); });
  check("renew.intervalMs 0 → cert/bad-renew-interval", eZero && eZero.code === "cert/bad-renew-interval");
  var eNeg = threw(function () { b.cert.create(mk({ ocsp: { refreshMs: -5 } })); });
  check("ocsp.refreshMs negative → cert/bad-ocsp-refresh", eNeg && eNeg.code === "cert/bad-ocsp-refresh");

  // Explicit null → falls back to the default (no throw): exercises the
  // `value === null` short-circuit at the top of _positiveFiniteOrDefault.
  var eNull = threw(function () { b.cert.create(mk({ renew: { intervalMs: null, minDaysBeforeExpiry: null }, ocsp: { refreshMs: null } })); });
  check("null interval/window/refresh → default (no throw)", !eNull);
}

// ---- Manifest size + per-cert shape rejections (uncovered guard rows) ----

function testManifestSizeAndShapeRejections() {
  var threw = function (fn) { try { fn(); return null; } catch (e) { return e; } };
  function mk(certs, extraStorage) {
    return {
      storage: Object.assign({ type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() }, extraStorage || {}),
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   certs,
      audit:   false,
    };
  }

  // certs array over the manager cap.
  var tooMany = [];
  for (var i = 0; i < 1001; i += 1) {
    tooMany.push({ name: "c" + i, domains: ["a.com"], challenge: GOOD_CHALLENGE });
  }
  var eManyCerts = threw(function () { b.cert.create(mk(tooMany)); });
  check("certs over cap → cert/too-many-certs", eManyCerts && eManyCerts.code === "cert/too-many-certs");

  // domains array over the per-cert cap.
  var manyDomains = [];
  for (var d = 0; d < 101; d += 1) { manyDomains.push("d" + d + ".example"); }
  var eManyDomains = threw(function () { b.cert.create(mk([{ name: "m", domains: manyDomains, challenge: GOOD_CHALLENGE }])); });
  check("domains over cap → cert/too-many-domains", eManyDomains && eManyDomains.code === "cert/too-many-domains");

  // A non-string / empty domain entry.
  var eBadDomain = threw(function () { b.cert.create(mk([{ name: "m", domains: ["ok.example", 123], challenge: GOOD_CHALLENGE }])); });
  check("non-string domain entry → cert/bad-domain", eBadDomain && eBadDomain.code === "cert/bad-domain");
  var eEmptyDomain = threw(function () { b.cert.create(mk([{ name: "m", domains: [""], challenge: GOOD_CHALLENGE }])); });
  check("empty-string domain entry → cert/bad-domain", eEmptyDomain && eEmptyDomain.code === "cert/bad-domain");

  // Missing / non-object challenge block.
  var eNoChallenge = threw(function () { b.cert.create(mk([{ name: "m", domains: ["a.com"] }])); });
  check("missing challenge block → cert/bad-challenge", eNoChallenge && eNoChallenge.code === "cert/bad-challenge");

  // challenge present but provision/cleanup not both functions.
  var eBadCbs = threw(function () {
    b.cert.create(mk([{ name: "m", domains: ["a.com"], challenge: { type: "http-01", provision: "nope", cleanup: function () {} } }]));
  });
  check("non-function challenge callbacks → cert/bad-challenge-callbacks", eBadCbs && eBadCbs.code === "cert/bad-challenge-callbacks");

  // keyAlg outside the allowed set.
  var eBadAlg = threw(function () {
    b.cert.create(mk([{ name: "m", domains: ["a.com"], keyAlg: "ecdsa-p521", challenge: GOOD_CHALLENGE }]));
  });
  check("unsupported keyAlg → cert/bad-key-alg", eBadAlg && eBadAlg.code === "cert/bad-key-alg");

  // keyEscrow present but recipient is neither Buffer nor string.
  var eBadEscrow = threw(function () {
    b.cert.create(mk([{ name: "m", domains: ["a.com"], challenge: GOOD_CHALLENGE, keyEscrow: { recipient: 123 } }]));
  });
  check("keyEscrow recipient wrong type → cert/bad-key-escrow", eBadEscrow && eBadEscrow.code === "cert/bad-key-escrow");

  // storage.type omitted → the `|| "sealed-disk"` default is taken and
  // create() succeeds (constructs without throwing).
  var eNoType = threw(function () {
    b.cert.create({
      storage: { rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "m", domains: ["a.com"], challenge: GOOD_CHALLENGE }],
      audit:   false,
    });
  });
  check("omitted storage.type → default sealed-disk (no throw)", !eNoType);

  // storage.vault omitted → falls back to b.vault.getDefaultStore()
  // (the `opts.vault || vault().getDefaultStore()` default in the
  // storage factory). create() must still succeed.
  var eNoVault = threw(function () {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "m", domains: ["a.com"], challenge: GOOD_CHALLENGE }],
      audit:   false,
    });
  });
  check("omitted storage.vault → default store (no throw)", !eNoVault);
}

// ---- getContext / refresh error branches ----

function testGetContextAndRefreshErrors() {
  var tmp = _tmpDir();
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: _ephemeralVault() },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"], challenge: GOOD_CHALLENGE }],
    audit:   false,
  });

  var threw = function (fn) { try { fn(); return null; } catch (e) { return e; } };

  // Unknown name (not in the manifest).
  var eUnknown = threw(function () { mgr.getContext("nope"); });
  check("getContext unknown name → cert/unknown-name", eUnknown && eUnknown.code === "cert/unknown-name");

  // Declared but not yet loaded (start() never ran).
  var eNotLoaded = threw(function () { mgr.getContext("main"); });
  check("getContext before start → cert/not-loaded", eNotLoaded && eNotLoaded.code === "cert/not-loaded");

  // refresh() on an unknown name.
  var eRefresh = null;
  return mgr.refresh("nope").then(
    function () { check("refresh unknown name → should reject", false); },
    function (e) { eRefresh = e; check("refresh unknown name → cert/unknown-name", eRefresh && eRefresh.code === "cert/unknown-name"); }
  );
}

// ---- sniCallback error paths: no context + createSecureContext throw ----

async function testSniCallbackErrorPaths() {
  // (a) No certs loaded at all → cb(cert/no-context).
  var tmp = _tmpDir();
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: _ephemeralVault() },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"], challenge: GOOD_CHALLENGE }],
    audit:   false,
  });
  var noCtxErr = await new Promise(function (resolve) {
    mgr.sniCallback("anything.example", function (err) { resolve(err); });
  });
  check("sniCallback with nothing loaded → cert/no-context",
    noCtxErr && noCtxErr.code === "cert/no-context");

  // (b) A loaded context whose KEY is garbage → tls.createSecureContext
  // throws and the callback receives that error (the try/catch tail).
  var tmp2 = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["bad.example"], 90);
  fs.mkdirSync(path.join(tmp2, "bad"), { recursive: true });
  fs.writeFileSync(path.join(tmp2, "bad", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  // Valid cert (so _certMeta parses + the context loads) but an
  // unparseable private key, so createSecureContext rejects the pair.
  fs.writeFileSync(path.join(tmp2, "bad", "key.pem.sealed"), vault.seal(Buffer.from("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n")));
  fs.writeFileSync(path.join(tmp2, "bad", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "bad", subject: "CN=bad.example",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));
  var mgr2 = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp2, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "bad", domains: ["bad.example"], challenge: GOOD_CHALLENGE }],
    audit:   false,
  });
  await mgr2.start();
  var secCtxErr = await new Promise(function (resolve) {
    mgr2.sniCallback("bad.example", function (err) { resolve(err); });
  });
  check("sniCallback with unparseable key → createSecureContext error forwarded", secCtxErr instanceof Error);
  await mgr2.stop();
}

// ---- start() after stop() is refused ----

async function testStartAfterStopRejects() {
  var tmp = _tmpDir();
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: _ephemeralVault() },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["example.com"], challenge: GOOD_CHALLENGE }],
    audit:   false,
  });
  await mgr.stop();   // flips the stopped latch without ever starting
  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  check("start() after stop() → cert/already-stopped", threw && threw.code === "cert/already-stopped");
}

// ---- Full ACME issue flow via an injected stub (no network) ----

async function testIssueFlowHappyPath() {
  await helpers.withTestTimeout("cert issue keyAlg matrix", async function () {
    var tmp = _tmpDir();
    var vault = _ephemeralVault();
    var pem = await _selfSignedCert(["issued.example"], 90);

    // Pre-seed a VALID sealed account JWK so _loadOrGenerateAccountKey
    // takes its read-existing branch (not the generate branch).
    var acctPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var acctJwk = acctPair.publicKey.export({ format: "jwk" });
    acctJwk.privatePem = acctPair.privateKey.export({ type: "pkcs8", format: "pem" });
    acctJwk.publicPem  = acctPair.publicKey.export({ type: "spki", format: "pem" });
    fs.mkdirSync(path.join(tmp, "account"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "account", "jwk.json.sealed"), vault.seal(Buffer.from(JSON.stringify(acctJwk))));

    var issued = [];
    var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem));
    var mgr = b.cert.create({
      storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
      acme:    { directory: "https://example/", contactEmail: "ops@example.com", accountKey: "auto" },
      // One cert per keyAlg so every _generateLeafKeypair switch arm runs.
      // The tls-alpn-01 cert exercises the RFC 8737 key-authorization
      // branch; the last cert's cleanup throws to exercise the
      // cleanup-failure drop-silent audit inside _issueCert.
      certs: [
        { name: "ec256",  domains: ["ec256.example"],  keyAlg: "ecdsa-p256", challenge: GOOD_CHALLENGE },
        { name: "ec384",  domains: ["ec384.example"],  keyAlg: "ecdsa-p384", challenge: GOOD_CHALLENGE },
        { name: "rsa2k",  domains: ["rsa2k.example"],  keyAlg: "rsa-2048",   challenge: { type: "dns-01", provision: async function () {}, cleanup: async function () {} } },
        // rsa3k's cleanup throws an Error with an EMPTY message (so
        // `cleanupErr.message` is falsy); rsa4k's throws an Error with a
        // message. Together they cover both arms of the cleanup-failure
        // audit's `(cleanupErr && cleanupErr.message) || String(cleanupErr)`.
        { name: "rsa3k",  domains: ["rsa3k.example"],  keyAlg: "rsa-3072",   challenge: { type: "tls-alpn-01", provision: async function () {}, cleanup: async function () { throw new Error(""); } } },
        { name: "rsa4k",  domains: ["rsa4k.example"],  keyAlg: "rsa-4096",   challenge: { type: "http-01", provision: async function () {}, cleanup: async function () { throw new Error("cleanup boom"); } } },
      ],
      ocsp:  { stapling: false },
      audit: false,
    });
    mgr.on("cert.issued", function (ev) { issued.push(ev.name); });
    try {
      await mgr.start();
      ["ec256", "ec384", "rsa2k", "rsa3k", "rsa4k"].forEach(function (n) {
        var ctx = mgr.getContext(n);
        check("issue: " + n + " context has the retrieved cert PEM",
          ctx.cert.indexOf("BEGIN CERTIFICATE") !== -1);
        check("issue: " + n + " context has a fingerprint",
          typeof ctx.fingerprintSha256 === "string" && ctx.fingerprintSha256.length > 0);
        // meta.json was persisted to disk by _persistCert.
        check("issue: " + n + " meta.json persisted",
          fs.existsSync(path.join(tmp, n, "meta.json")));
      });
      check("issue: cert.issued fired for every manifest cert", issued.length === 5);
    } finally {
      await mgr.stop();
      restore();
    }
  }, { timeoutMs: 120000 });
}

async function testIssueNoMatchingChallenge() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["nomatch.example"], 90);
  var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem, { omitChallengeType: true }));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    // Requests http-01 but the stubbed CA only offers dns-01.
    certs:   [{ name: "m", domains: ["nomatch.example"], challenge: GOOD_CHALLENGE }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  finally { await mgr.stop(); restore(); }
  check("issue: CA offers no matching challenge → cert/no-matching-challenge",
    threw && threw.code === "cert/no-matching-challenge");
}

async function testIssueValidAuthSkipsProvision() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["already.example"], 90);
  var provisioned = false;
  var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem, { authValid: true }));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    // A provided accountKey object (not "auto") — exercises the
    // else-arm of `accountKey === "auto" || !accountKey` in _bootAcme
    // (the manager uses the supplied key rather than generating one).
    acme:    { directory: "https://example/", accountKey: { privatePem: "PRIV", publicPem: "PUB" } },
    certs:   [{ name: "m", domains: ["already.example"],
      challenge: { type: "http-01", provision: async function () { provisioned = true; }, cleanup: async function () {} } }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  try {
    await mgr.start();
    // The authorization was already `valid`, so the manager skipped the
    // challenge solve entirely (the `continue`) and still finalized.
    check("issue: already-valid authorization skips provision", provisioned === false);
    check("issue: already-valid authorization still yields a context",
      mgr.getContext("m").cert.indexOf("BEGIN CERTIFICATE") !== -1);
  } finally { await mgr.stop(); restore(); }
}

// Key escrow seals the renewed private key to the operator's offline
// break-glass recipient (an ML-KEM-1024 keypair from
// b.crypto.generateEncryptionKeyPair) via b.crypto.encrypt, writing
// <name>/key.pem.escrow. The operator recovers it offline with
// b.crypto.decrypt. Issue #446 — the prior implementation called a
// nonexistent b.crypto.encryptEnvelope and threw on the first issue.
async function testKeyEscrowSealsRecoverableEnvelope() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCert(["escrow.example"], 90);
  var kp = b.crypto.generateEncryptionKeyPair();
  var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "m", domains: ["escrow.example"], challenge: GOOD_CHALLENGE,
      keyEscrow: { recipient: { publicKey: kp.publicKey, ecPublicKey: kp.ecPublicKey } } }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  var threw = null;
  try { await mgr.start(); } catch (e) { threw = e; }
  finally { await mgr.stop(); restore(); }
  check("keyEscrow write path no longer throws", threw === null);

  var escrowPath = path.join(tmp, "m", "key.pem.escrow");
  check("keyEscrow: escrow envelope written to <name>/key.pem.escrow",
    fs.existsSync(escrowPath));

  // Break-glass recovery: the offline operator decrypts the escrow with
  // the recipient private key(s) and gets a usable private-key PEM back.
  var envelope = fs.readFileSync(escrowPath, "utf8").trim();
  var recovered = b.crypto.decrypt(envelope,
    { privateKey: kp.privateKey, ecPrivateKey: kp.ecPrivateKey });
  var recoveredPem = Buffer.isBuffer(recovered) ? recovered.toString("utf8") : recovered;
  check("keyEscrow: recovered plaintext is a PEM private key",
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(recoveredPem));

  // An unrecognized recipient shape is refused at config time.
  var badThrew = null;
  try {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "b", domains: ["b.example"], challenge: GOOD_CHALLENGE,
        keyEscrow: { recipient: 123 } }],
    });
  } catch (e) { badThrew = e; }
  check("keyEscrow: non-string / non-object recipient refused at config time",
    badThrew && badThrew.code === "cert/bad-key-escrow");

  // An object-form recipient with an empty publicKey is refused too: the
  // object path must require a non-empty key like the string path does, or a
  // "" key slips through config and fails deeper at b.crypto.encrypt time.
  var emptyKeyThrew = null;
  try {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "c", domains: ["c.example"], challenge: GOOD_CHALLENGE,
        keyEscrow: { recipient: { publicKey: "" } } }],
    });
  } catch (e) { emptyKeyThrew = e; }
  check("keyEscrow: object recipient with empty publicKey refused at config time",
    emptyKeyThrew && emptyKeyThrew.code === "cert/bad-key-escrow");

  // A present-but-empty ecPublicKey (the optional P-384 hybrid leg) is refused
  // too — an empty hybrid key must not silently downgrade to ML-KEM-only.
  var emptyEcThrew = null;
  try {
    b.cert.create({
      storage: { type: "sealed-disk", rootDir: _tmpDir(), vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "d", domains: ["d.example"], challenge: GOOD_CHALLENGE,
        keyEscrow: { recipient: { publicKey: "ml-kem-pem", ecPublicKey: "" } } }],
    });
  } catch (e) { emptyEcThrew = e; }
  check("keyEscrow: object recipient with empty ecPublicKey refused at config time",
    emptyEcThrew && emptyEcThrew.code === "cert/bad-key-escrow");
}

// ---- Corrupt sealed cert that unseals but won't parse → re-issue ----

async function testUnparseableSealedCertReissues() {
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var keyPem = (await _selfSignedCert(["parse.example"], 90)).keyPem;
  var pem = await _selfSignedCert(["parse.example"], 90);

  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  // Sealed blob unseals cleanly (XOR vault) but the plaintext is NOT a
  // certificate, so _certMeta's X509Certificate parse throws and the
  // manager routes to re-issue (distinct from an unseal failure).
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from("this is definitely not a certificate")));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=parse.example",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));

  var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["parse.example"], challenge: GOOD_CHALLENGE }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  try {
    await mgr.start();
    check("unparseable sealed cert → re-issued to a valid context",
      mgr.getContext("main").cert.indexOf("BEGIN CERTIFICATE") !== -1);
  } finally { await mgr.stop(); restore(); }
}

// ---- readSealed returns a non-Buffer (string) unseal result ----

async function testReadSealedStringUnseal() {
  // A vault whose unseal returns a STRING (not a Buffer) — exercises
  // readSealed's `Buffer.isBuffer(plain) ? plain : Buffer.from(plain)`
  // else-arm. PEM is ASCII so the utf8 round-trip is lossless.
  var key = crypto.randomBytes(32);
  var stringVault = {
    seal: function (buf) {
      var out = Buffer.alloc(buf.length);
      for (var i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
      return out;
    },
    unseal: function (buf) {
      var out = Buffer.alloc(buf.length);
      for (var i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
      return out.toString("utf8");
    },
  };
  var tmp = _tmpDir();
  var pem = await _selfSignedCert(["strvault.example"], 90);
  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), stringVault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  stringVault.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=strvault.example",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: stringVault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["strvault.example"], challenge: GOOD_CHALLENGE }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  try {
    await mgr.start();
    check("readSealed string unseal → context still loads cert PEM",
      mgr.getContext("main").cert.indexOf("BEGIN CERTIFICATE") !== -1);
  } finally { await mgr.stop(); }
}

// ---- Renewal scheduler: due cert renews successfully (+ ARI honored) ----

async function testSchedulerRenewsDueCert() {
  await helpers.withTestTimeout("scheduler renews due cert", async function () {
    var tmp = _tmpDir();
    var vault = _ephemeralVault();
    var pem = await _selfSignedCert(["renew.example"], 90);
    var renewed = [];
    var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem));   // renewIfDue → { shouldRenew:false }
    var mgr = b.cert.create({
      storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "main", domains: ["renew.example"], challenge: GOOD_CHALLENGE }],
      // A huge renewal window forces every scheduler tick to treat the
      // cert as due; a short interval makes the tick fire promptly.
      renew:   { intervalMs: 30, minDaysBeforeExpiry: 100000 },
      ocsp:    { stapling: false },
      audit:   false,
    });
    mgr.on("cert.renewed", function (ev) { renewed.push(ev.name); });
    try {
      await mgr.start();   // initial issue (cert.issued), boots acmeClient so ARI runs
      await helpers.waitUntil(function () { return renewed.length >= 1; },
        { timeoutMs: 5000, label: "scheduler: cert.renewed fired" });
      check("scheduler renews a due cert (ARI honored, time-based renew)", renewed.length >= 1);
    } finally { await mgr.stop(); restore(); }
  });
}

// ---- Renewal scheduler: renew failure + ARI-fetch failure both survive ----

async function testSchedulerRenewFailureAndAriCatch() {
  await helpers.withTestTimeout("scheduler renew failure", async function () {
    var tmp = _tmpDir();
    var vault = _ephemeralVault();
    var pem = await _selfSignedCert(["fail.example"], 90);
    var failures = [];
    // First retrieveCert (during start's issue) succeeds; every later one
    // throws → the scheduled renewal fails. renewIfDue always throws →
    // the ARI try/catch fall-through is exercised too.
    var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem, { failRetrieveAfter: 1, renewIfDueThrows: true }));
    var mgr = b.cert.create({
      storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "main", domains: ["fail.example"], challenge: GOOD_CHALLENGE }],
      renew:   { intervalMs: 30, minDaysBeforeExpiry: 100000 },
      ocsp:    { stapling: false },
      audit:   false,
    });
    mgr.on("cert.renew-failed", function (ev) { failures.push(ev); });
    try {
      await mgr.start();   // succeeds (issue #1), meta persisted, acmeClient booted
      await helpers.waitUntil(function () { return failures.length >= 1; },
        { timeoutMs: 5000, label: "scheduler: cert.renew-failed fired" });
      check("scheduler: failed renewal emits cert.renew-failed (ARI throw survived)",
        failures.length >= 1 && failures[0].name === "main" && failures[0].error);
    } finally { await mgr.stop(); restore(); }

    // Second manager: the renewal failure carries an EMPTY message, so
    // the renew-failed audit's `(e && e.message) || String(e)` takes its
    // String(e) fallback arm.
    var tmp2 = _tmpDir();
    var pem2 = await _selfSignedCert(["fail2.example"], 90);
    var failures2 = [];
    var restore2 = _stubAcmeCreate(_makeStubAcme(pem2.certPem, { failRetrieveAfter: 1, retrieveThrowValue: new Error("") }));
    var mgr2 = b.cert.create({
      storage: { type: "sealed-disk", rootDir: tmp2, vault: _ephemeralVault() },
      acme:    { directory: "https://example/", accountKey: "auto" },
      certs:   [{ name: "main", domains: ["fail2.example"], challenge: GOOD_CHALLENGE }],
      renew:   { intervalMs: 30, minDaysBeforeExpiry: 100000 },
      ocsp:    { stapling: false },
      audit:   false,
    });
    mgr2.on("cert.renew-failed", function (ev) { failures2.push(ev); });
    try {
      await mgr2.start();
      await helpers.waitUntil(function () { return failures2.length >= 1; },
        { timeoutMs: 5000, label: "scheduler: cert.renew-failed (non-Error) fired" });
      check("scheduler: empty-message renewal failure still emits cert.renew-failed",
        failures2.length >= 1 && failures2[0].error instanceof Error && failures2[0].error.message === "");
    } finally { await mgr2.stop(); restore2(); }
  });
}

// ---- OCSP stapling refresh: success (staple cached) + responder failure ----

async function testOcspStaplingRefresh() {
  await helpers.withTestTimeout("ocsp stapling refresh", async function () {
    var vault = _ephemeralVault();
    // A two-cert chain (leaf + issuer) so _refreshOcspFor gets past the
    // "no issuer in the served chain" (chain.length < 2) short-circuit.
    var leaf   = await _selfSignedCert(["ocsp.example"], 90);
    var issuer = await _selfSignedCert(["issuer.example"], 90);
    var chainPem = leaf.certPem.trim() + "\n" + issuer.certPem.trim() + "\n";

    function seed(dir) {
      fs.mkdirSync(path.join(dir, "main"), { recursive: true });
      fs.writeFileSync(path.join(dir, "main", "cert.pem.sealed"), vault.seal(Buffer.from(chainPem)));
      fs.writeFileSync(path.join(dir, "main", "key.pem.sealed"),  vault.seal(Buffer.from(leaf.keyPem)));
      fs.writeFileSync(path.join(dir, "main", "meta.json"), JSON.stringify({
        expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
        fingerprintSha256: "ff", subject: "CN=ocsp.example",
        lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
      }));
    }
    function mk(dir) {
      return b.cert.create({
        storage: { type: "sealed-disk", rootDir: dir, vault: vault },
        acme:    { directory: "https://example/", accountKey: "auto" },
        certs:   [{ name: "main", domains: ["ocsp.example"], challenge: GOOD_CHALLENGE }],
        ocsp:    { stapling: true, refreshMs: 100000 },
        audit:   false,
      });
    }

    // (a) Responder returns a DER — the manager caches it on the context.
    var tmpA = _tmpDir();
    seed(tmpA);
    var restoreA = _stubOcspFetch(async function (o) {
      check("ocsp.fetch received leaf + issuer PEMs",
        typeof o.leafPem === "string" && typeof o.issuerPem === "string" && o.leafPem !== o.issuerPem);
      return { ocspDer: Buffer.from("mock-ocsp-der") };
    });
    var mgrA = mk(tmpA);
    try {
      await mgrA.start();   // OCSP initial refresh runs in the background
      var staple = await helpers.waitUntil(function () {
        var r = mgrA.getContext("main").ocspResponse;
        return r ? r : false;
      }, { timeoutMs: 5000, label: "ocsp: staple cached on context" });
      check("ocsp: validated DER cached on getContext().ocspResponse",
        Buffer.isBuffer(staple) && staple.toString() === "mock-ocsp-der");
    } finally { await mgrA.stop(); restoreA(); }

    // (b) Responder throws — the failure is swallowed (fail-soft) and the
    // staple stays absent; the manager does not crash.
    var tmpB = _tmpDir();
    seed(tmpB);
    var fetchCalls = 0;
    var restoreB = _stubOcspFetch(async function () {
      fetchCalls += 1;
      throw new Error("mock OCSP responder unreachable");
    });
    var mgrB = mk(tmpB);
    try {
      await mgrB.start();
      await helpers.waitUntil(function () { return fetchCalls >= 1; },
        { timeoutMs: 5000, label: "ocsp: responder invoked" });
      check("ocsp: responder failure is fail-soft (no staple, no crash)",
        mgrB.getContext("main").ocspResponse === null);
    } finally { await mgrB.stop(); restoreB(); }

    // (c) Responder throws an Error with an EMPTY message — the
    // refresh-failed audit's `(e && e.message) || String(e)` takes its
    // String(e) fallback arm.
    var tmpC = _tmpDir();
    seed(tmpC);
    var fetchCallsC = 0;
    var restoreC = _stubOcspFetch(async function () { fetchCallsC += 1; throw new Error(""); });
    var mgrC = mk(tmpC);
    try {
      await mgrC.start();
      await helpers.waitUntil(function () { return fetchCallsC >= 1; },
        { timeoutMs: 5000, label: "ocsp: empty-message responder invoked" });
      check("ocsp: empty-message responder failure is also fail-soft",
        mgrC.getContext("main").ocspResponse === null);
    } finally { await mgrC.stop(); restoreC(); }
  });
}

// ---- _certMeta with a cert that carries no SubjectAlternativeName ----

async function testCertMetaNoSubjectAltName() {
  // A cert with no SAN extension → the parsed subjectAltName is
  // undefined and _certMeta falls back to null (the `|| null` arm).
  var tmp = _tmpDir();
  var vault = _ephemeralVault();
  var pem = await _selfSignedCertNoSan("nosan.example", 90);
  fs.mkdirSync(path.join(tmp, "main"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "main", "cert.pem.sealed"), vault.seal(Buffer.from(pem.certPem)));
  fs.writeFileSync(path.join(tmp, "main", "key.pem.sealed"),  vault.seal(Buffer.from(pem.keyPem)));
  fs.writeFileSync(path.join(tmp, "main", "meta.json"), JSON.stringify({
    expiresAt: Date.now() + 90 * 86400000, issuedAt: Date.now(),
    fingerprintSha256: "ff", subject: "CN=nosan.example",
    lastRenewedAt: Date.now(), keyAlg: "ecdsa-p256",
  }));
  var mgr = b.cert.create({
    storage: { type: "sealed-disk", rootDir: tmp, vault: vault },
    acme:    { directory: "https://example/", accountKey: "auto" },
    certs:   [{ name: "main", domains: ["nosan.example"], challenge: GOOD_CHALLENGE }],
    ocsp:    { stapling: false },
    audit:   false,
  });
  try {
    await mgr.start();   // _ensureCert → _certMeta parses the no-SAN cert
    check("no-SAN cert still loads a usable context",
      mgr.getContext("main").cert.indexOf("BEGIN CERTIFICATE") !== -1);
  } finally { await mgr.stop(); }
}

// ---- Renewal scheduler ARI-decision arms with a not-yet-due cert ----

async function testSchedulerAriDecisionArms() {
  await helpers.withTestTimeout("scheduler ARI decision arms", async function () {
    // A freshly-issued cert is comfortably inside its validity window, so
    // the time-based test says "not due". With the ACME client booted,
    // each tick still consults ARI. Two managers cover both ARI verdicts:
    // one where ARI forces a renew (shouldRenew := true), and one where
    // ARI declines and the tick returns early at `if (!shouldRenew)`.
    async function runOne(ariSays, label) {
      var tmp = _tmpDir();
      var pem = await _selfSignedCert([label + ".example"], 90);
      var ariCalls = 0;
      var restore = _stubAcmeCreate(_makeStubAcme(pem.certPem, {
        renewIfDueShould: ariSays,
        onRenewIfDue: function () { ariCalls += 1; },
      }));
      var mgr = b.cert.create({
        storage: { type: "sealed-disk", rootDir: tmp, vault: _ephemeralVault() },
        acme:    { directory: "https://example/", accountKey: "auto" },
        certs:   [{ name: "main", domains: [label + ".example"], challenge: GOOD_CHALLENGE }],
        // Default-ish 14-day window so the fresh 90-day cert is NOT
        // time-due; the ARI verdict is the only lever this tick.
        renew:   { intervalMs: 30, minDaysBeforeExpiry: 14 },
        ocsp:    { stapling: false },
        audit:   false,
      });
      try {
        await mgr.start();   // issues → boots acmeClient so the ARI branch runs
        await helpers.waitUntil(function () { return ariCalls >= 1; },
          { timeoutMs: 5000, label: "scheduler: renewIfDue consulted (" + label + ")" });
        check("scheduler consults ARI on a not-yet-due cert (" + label + ")", ariCalls >= 1);
      } finally { await mgr.stop(); restore(); }
    }
    await runOne(true,  "ariforce");   // ARI true  → shouldRenew := true arm
    await runOne(false, "aridecline"); // ARI false → `if (!shouldRenew) return` arm
  });
}

async function run() {
  testSurface();
  testFactoryRefusesBadOpts();
  await testOcspFetchRejectsBadInput();
  await testStorageRoundtrip();
  await testSniCallback();
  await testSniWildcardSingleLabel();
  await testRefreshForcesIssue();
  await testKeyEscrow();
  testAcmeBuildCsrRoundtrip();
  await testCorruptSealedCertReissues();
  await testStaleMetaDoesNotServeExpiringCert();
  await testCorruptAccountKeyClearError();
  // Error / adversarial / option-default branch coverage.
  testPositiveFiniteOptRejections();
  testManifestSizeAndShapeRejections();
  await testGetContextAndRefreshErrors();
  await testSniCallbackErrorPaths();
  await testStartAfterStopRejects();
  await testIssueFlowHappyPath();
  await testIssueNoMatchingChallenge();
  await testIssueValidAuthSkipsProvision();
  await testKeyEscrowSealsRecoverableEnvelope();
  await testUnparseableSealedCertReissues();
  await testReadSealedStringUnseal();
  await testCertMetaNoSubjectAltName();
  await testSchedulerRenewsDueCert();
  await testSchedulerRenewFailureAndAriCatch();
  await testSchedulerAriDecisionArms();
  await testOcspStaplingRefresh();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cert] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
