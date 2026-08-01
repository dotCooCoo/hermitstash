// Regression coverage for the mTLS SYNC-CA auto-migration to the ML-DSA-87 PQC
// default (lib/mtls-migrate.js), which runs through the b.mtlsCa handle's
// migration primitives (status / canVerifyInTls / rotate({retainPrevious}) /
// loadTrustBundle / dropRetained).
//
// Contract locked here:
//   - The TLS-capability gate (mtlsCa.canVerifyInTls) proves node:tls VERIFIES an
//     ML-DSA client chain — not merely that ML-DSA certs can be issued — and
//     returns true on this OpenSSL >= 3.5 runtime.
//   - maybeMigrate is a strict no-op when there is no CA, when the CA is already
//     PQC, when the CA is operator-provided, when MTLS_CA_ALGORITHM pins the
//     algorithm, or when MTLS_AUTO_MIGRATE is off.
//   - maybeMigrate on a classical (ECDSA-P384) sync CA rotates to ML-DSA-87,
//     retains the superseded cert at ca.prev.crt, and writes the grace marker; a
//     second call is idempotent (already-pqc).
//   - The grace window: graceActive tracks the marker clock; closeOut is a no-op
//     while open, and on expiry drops the retained CA (via dropRetained), deletes
//     the marker, and revokes the superseded (old-generation) SYNC client certs —
//     never the separate classical browser CA's certs.
//   - A client cert issued by the OLD classical CA still verifies against the
//     retained ca.prev.crt through a real mTLS handshake during the grace window.

"use strict";

var os = require("node:os");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeTls = require("node:tls");
var nodeCrypto = require("node:crypto");
var { describe, it, before, beforeEach } = require("node:test");
var assert = require("node:assert");

// Bind the data dir BEFORE any lib module resolves it (constants + the mtls-ca
// singleton capture HERMITSTASH_DATA_DIR at require time).
var DATA_DIR = nodePath.join(os.tmpdir(), "hs-mtls-migrate-test-" + process.pid + "-" + Date.now());
nodeFs.mkdirSync(DATA_DIR, { recursive: true });
process.env.HERMITSTASH_DATA_DIR = DATA_DIR;

var b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var vault = require("../../lib/vault");
var config = require("../../lib/config");
var mtlsCa = require("../../lib/mtls-ca");
var mtlsMigrate = require("../../lib/mtls-migrate");
var certUtils = require("../../lib/cert-utils");
var apiKeysRepo = require("../../app/data/repositories/apiKeys.repo");

var CLASSICAL = "ECDSA-P384-SHA384";

// Every b.mtlsCa on-disk artifact for the sync handle under DATA_DIR, so each
// test starts from a clean CA state. Includes the 0.18.3 migration artifacts
// (ca.prev.crt / issuance ledger / generation watermark / algorithm label) and
// the atomic-commit rollback journal + lock files.
function cleanCaFiles() {
  var names = [
    "ca.crt", "ca.key", "ca.key.sealed", "ca.prev.crt", "ca-migration.json",
    "issuance.json", "revoked-generation", "ca.algorithm",
    "ca.key.rollback", "ca.key.sealed.rollback",
    "ca.crt.lock", "issuance.json.lock", "revocations.json.lock", "revoked-generation.lock",
    "revocations.json", "ca.crl",
  ];
  for (var i = 0; i < names.length; i++) {
    var p = nodePath.join(DATA_DIR, names[i]);
    try { if (nodeFs.existsSync(p)) nodeFs.unlinkSync(p); } catch (_e) { /* best-effort */ }
  }
}

async function installCa(algorithm, generation) {
  var pems = await b.mtlsEngine.generateCa(algorithm ? { generation: generation, algorithm: algorithm } : { generation: generation });
  // commit() is async + locked in blamejs 0.18.3 — awaiting is required or the
  // CA is not on disk when the test reads it back.
  await mtlsCa.commit({ caCertPem: pems.caCertPem, caKeyPem: pems.caKeyPem });
  return pems;
}

// Raw public-key algorithm of a cert (independent of mtlsCa.status()), used to
// assert what the on-disk retained/live cert actually is: "ec:<curve>" for
// classical, otherwise the lowercased key type (e.g. "ml-dsa-87").
function certAlgorithm(pem) {
  var pub = new nodeCrypto.X509Certificate(pem).publicKey;
  var type = String(pub.asymmetricKeyType || "").toLowerCase();
  if (type === "ec") return "ec:" + String((pub.asymmetricKeyDetails && pub.asymmetricKeyDetails.namedCurve) || "").toLowerCase();
  return type;
}

// One mTLS TLSv1.3 loopback; resolves the server-side socket.authorized (the
// authoritative verification result — the client side races it). A local
// handshake resolves deterministically through the server's secureConnection /
// tlsClientError / error events, so no fixed-duration failsafe is needed — a
// pathological hang is caught by node:test's own per-test timeout.
function loopback(opts) {
  var resolveFn;
  var done = new Promise(function (r) { resolveFn = r; });
  var settled = false, server = null;
  function finish(v) { if (settled) return; settled = true; try { if (server) server.close(); } catch (_e) { /* */ } resolveFn(v); }
  server = nodeTls.createServer({
    key: opts.serverLeaf.key, cert: opts.serverLeaf.cert, ca: opts.serverCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, function (sock) { var ok = sock.authorized === true; try { sock.end(); } catch (_e) { /* */ } finish({ authorized: ok }); });
  server.on("tlsClientError", function (e) { finish({ authorized: false, err: e && e.message }); });
  server.on("error", function (e) { finish({ authorized: false, err: e && e.message }); });
  server.listen(0, "127.0.0.1", function () {
    var port = server.address().port;
    var c = nodeTls.connect({
      host: "127.0.0.1", port: port, key: opts.clientLeaf.key, cert: opts.clientLeaf.cert,
      ca: opts.clientCa, minVersion: "TLSv1.3", checkServerIdentity: function () { return undefined; },
    }, function () { try { c.end(); } catch (_e) { /* */ } });
    c.on("error", function () { /* server-side result is authoritative */ });
  });
  return done;
}

describe("mtls-migrate", function () {
  before(async function () { await vault.init(); });
  beforeEach(async function () {
    // Drop any retained root a prior test's rotation left tracked on the shared
    // singleton (clears the handle's retention state + removes ca.prev.crt),
    // then wipe the rest so each test starts from no-CA.
    try { await mtlsCa.dropRetained(); } catch (_e) { /* no retained root / no CA */ }
    cleanCaFiles();
  });

  describe("capability probe", function () {
    it("mtlsCa.canVerifyInTls proves node:tls VERIFIES an ML-DSA client chain (loopback)", async function () {
      var ok = await mtlsCa.canVerifyInTls("ML-DSA-87");
      assert.strictEqual(ok, true, "the ML-DSA mTLS loopback must report the runtime verifies the chain");
    });
  });

  describe("storedSyncCaAlgorithm / isClassicalSyncCa", function () {
    it("returns null / false with no CA on disk", function () {
      assert.strictEqual(mtlsMigrate.storedSyncCaAlgorithm(), null);
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), false);
    });

    it("reports ECDSA-P384-SHA384 + classical for an ECDSA-P384 CA", async function () {
      await installCa(CLASSICAL, 2);
      assert.strictEqual(mtlsMigrate.storedSyncCaAlgorithm(), CLASSICAL);
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), true);
    });

    it("reports ML-DSA-87 + not-classical for a PQC CA", async function () {
      await installCa(null, C.CA_GENERATION);
      assert.strictEqual(mtlsMigrate.storedSyncCaAlgorithm(), "ML-DSA-87");
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), false);
    });
  });

  describe("maybeMigrate guards (no-op)", function () {
    it("no CA -> reason no-ca", async function () {
      var r = await mtlsMigrate.maybeMigrate({});
      assert.deepStrictEqual(r, { migrated: false, reason: "no-ca" });
    });

    it("MTLS_CA_ALGORITHM pin -> reason pinned; nothing retained", async function () {
      await installCa(CLASSICAL, 2);
      process.env.MTLS_CA_ALGORITHM = CLASSICAL;
      try {
        var r = await mtlsMigrate.maybeMigrate({});
        assert.deepStrictEqual(r, { migrated: false, reason: "pinned" });
      } finally { delete process.env.MTLS_CA_ALGORITHM; }
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), false);
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_MIGRATION_MARKER), false);
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), true, "the classical CA is left in place");
    });

    it("operator-provided CA (MTLS_CA_CERT set) -> reason operator-provided-ca; nothing retained", async function () {
      await installCa(CLASSICAL, 2);
      process.env.MTLS_CA_CERT = C.PATHS.CA_CERT;
      try {
        var r = await mtlsMigrate.maybeMigrate({});
        assert.deepStrictEqual(r, { migrated: false, reason: "operator-provided-ca" });
      } finally { delete process.env.MTLS_CA_CERT; }
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), false);
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_MIGRATION_MARKER), false);
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), true, "an operator-provided classical CA is left in place");
    });

    it("MTLS_AUTO_MIGRATE off -> reason auto-migrate-off", async function () {
      await installCa(CLASSICAL, 2);
      var prev = config.mtlsAutoMigrate;
      config.mtlsAutoMigrate = false;
      try {
        var r = await mtlsMigrate.maybeMigrate({});
        assert.deepStrictEqual(r, { migrated: false, reason: "auto-migrate-off" });
      } finally { config.mtlsAutoMigrate = prev; }
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), true);
    });

    it("already ML-DSA -> reason already-pqc", async function () {
      await installCa(null, C.CA_GENERATION);
      var r = await mtlsMigrate.maybeMigrate({});
      assert.deepStrictEqual(r, { migrated: false, reason: "already-pqc" });
    });
  });

  describe("maybeMigrate on a classical sync CA", function () {
    it("rotates to ML-DSA-87, retains prev cert + marker, and is idempotent", async function () {
      var old = await installCa(CLASSICAL, 2);
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), true);

      var r = await mtlsMigrate.maybeMigrate({});
      assert.strictEqual(r.migrated, true);
      assert.strictEqual(r.toAlgorithm, "ML-DSA-87");
      assert.strictEqual(r.toGen, C.CA_GENERATION);
      assert.strictEqual(r.fromAlgorithm, CLASSICAL);

      // (a) ca.prev.crt is exactly the superseded classical cert (rotate retained it)
      assert.ok(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), "ca.prev.crt retained");
      var prevPem = nodeFs.readFileSync(C.PATHS.CA_PREV_CERT, "utf8");
      assert.strictEqual(certAlgorithm(prevPem), "ec:secp384r1");
      assert.strictEqual(prevPem.trim(), old.caCertPem.trim(), "prev cert == the old sync CA cert");

      // (b) marker schema
      assert.ok(nodeFs.existsSync(C.PATHS.CA_MIGRATION_MARKER), "marker written");
      var marker = JSON.parse(nodeFs.readFileSync(C.PATHS.CA_MIGRATION_MARKER, "utf8"));
      assert.strictEqual(typeof marker.startedAt, "number");
      assert.strictEqual(marker.toGen, C.CA_GENERATION);
      assert.strictEqual(marker.graceDays, 30);

      // (c)/(d) the committed sync CA is now ML-DSA-87
      var liveCa = nodeFs.readFileSync(C.PATHS.CA_CERT, "utf8");
      assert.strictEqual(new nodeCrypto.X509Certificate(liveCa).publicKey.asymmetricKeyType, "ml-dsa-87");
      assert.strictEqual(mtlsMigrate.storedSyncCaAlgorithm(), "ML-DSA-87");
      assert.strictEqual(mtlsMigrate.isClassicalSyncCa(), false);

      // grace is now active
      assert.strictEqual(mtlsMigrate.graceActive(), true);
      assert.ok(mtlsMigrate.graceRemainingMs() > 0);

      // idempotent second call: no-op, marker untouched
      var startedAt1 = marker.startedAt;
      var r2 = await mtlsMigrate.maybeMigrate({});
      assert.deepStrictEqual(r2, { migrated: false, reason: "already-pqc" });
      var marker2 = JSON.parse(nodeFs.readFileSync(C.PATHS.CA_MIGRATION_MARKER, "utf8"));
      assert.strictEqual(marker2.startedAt, startedAt1, "marker untouched on the idempotent call");
    });
  });

  describe("grace window", function () {
    it("graceActive is false once startedAt + graceDays is in the past", function () {
      var marker = { startedAt: Date.now() - C.TIME.days(40), fromGen: 2, toGen: C.CA_GENERATION, graceDays: 30 };
      nodeFs.writeFileSync(C.PATHS.CA_MIGRATION_MARKER, JSON.stringify(marker));
      assert.strictEqual(mtlsMigrate.graceActive(), false);
      assert.strictEqual(mtlsMigrate.graceRemainingMs(), 0);
    });

    it("closeOutGraceIfExpired is a no-op while the window is open", async function () {
      await installCa(CLASSICAL, 2);
      await mtlsMigrate.maybeMigrate({});           // rotates + opens a fresh (active) window
      assert.strictEqual(mtlsMigrate.graceActive(), true);
      var r = await mtlsMigrate.closeOutGraceIfExpired({});
      assert.strictEqual(r.closed, false);
      assert.strictEqual(r.reason, "grace-active");
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), true, "prev cert retained while active");
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_MIGRATION_MARKER), true, "marker retained while active");
    });

    it("closeOutGraceIfExpired drops the retained CA + marker and revokes only superseded SYNC certs", async function () {
      // Migrate a real classical CA so the handle retains ca.prev.crt (tracked),
      // then expire the grace clock by backdating the marker's startedAt.
      await installCa(CLASSICAL, 2);
      var mig = await mtlsMigrate.maybeMigrate({});
      assert.strictEqual(mig.migrated, true);
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), true, "retained CA present after migrate");

      var T = Date.now() - C.TIME.days(31);
      var marker = JSON.parse(nodeFs.readFileSync(C.PATHS.CA_MIGRATION_MARKER, "utf8"));
      marker.startedAt = T;
      nodeFs.writeFileSync(C.PATHS.CA_MIGRATION_MARKER, JSON.stringify(marker));

      var oldFp = "oldsync-" + Date.now();
      var freshFp = "freshsync-" + Date.now();
      var browserFp = "browsercert-" + Date.now();
      // Old SYNC cert issued before the window opened -> must be revoked.
      apiKeysRepo.create({ prefix: "old-sync", keyHash: "sync:old", certFingerprint: oldFp, certIssuedAt: new Date(T - C.TIME.days(1)).toISOString() });
      // Sync cert re-issued after the window opened -> must be spared.
      apiKeysRepo.create({ prefix: "fresh-sync", keyHash: "sync:fresh", certFingerprint: freshFp, certIssuedAt: new Date(T + C.TIME.days(1)).toISOString() });
      // Browser cert from the SEPARATE classical browser CA -> never revoked here.
      apiKeysRepo.create({ prefix: "browser", keyHash: "browser:x", certFingerprint: browserFp, certIssuedAt: new Date(T - C.TIME.days(1)).toISOString() });

      assert.strictEqual(mtlsMigrate.graceActive(), false, "the window is expired");
      var r = await mtlsMigrate.closeOutGraceIfExpired({});
      assert.strictEqual(r.closed, true);
      assert.strictEqual(r.revoked, 1, "only the old SYNC cert is revoked");

      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_PREV_CERT), false, "retained CA dropped");
      assert.strictEqual(nodeFs.existsSync(C.PATHS.CA_MIGRATION_MARKER), false, "marker deleted");
      assert.strictEqual(certUtils.isCertRevoked(oldFp), true, "old sync cert revoked");
      assert.strictEqual(certUtils.isCertRevoked(freshFp), false, "re-issued sync cert spared");
      assert.strictEqual(certUtils.isCertRevoked(browserFp), false, "browser cert spared (separate CA)");
    });
  });

  describe("post-migration issuance (cert-expiry reissue path)", function () {
    it("mtlsCa.generateClientCert issues an ML-DSA-87 leaf that chains to the migrated CA", async function () {
      await installCa(CLASSICAL, 2);
      var r = await mtlsMigrate.maybeMigrate({});
      assert.strictEqual(r.migrated, true);

      // The cert-expiry job renews via mtlsCa.initCA() + generateClientCert; the
      // unpinned singleton now issues under the committed ML-DSA-87 CA.
      await mtlsCa.initCA();
      var reissued = await mtlsCa.generateClientCert({ cn: "reissued-client" });
      assert.strictEqual(new nodeCrypto.X509Certificate(reissued.cert).publicKey.asymmetricKeyType, "ml-dsa-87");

      // And the reissued leaf verifies against the live ML-DSA sync CA.
      var newCaPem = nodeFs.readFileSync(C.PATHS.CA_CERT, "utf8");
      var serverLeaf = await b.mtlsEngine.signClientCert({ cn: "srv", usage: "server", sans: ["127.0.0.1"], caCertPem: reissued.ca, caKeyPem: mtlsCa.loadKey().toString() });
      var result = await loopback({
        serverLeaf: serverLeaf,
        clientLeaf: { cert: reissued.cert, key: reissued.key },
        serverCa: [newCaPem],
        clientCa: [newCaPem],
      });
      assert.strictEqual(result.authorized, true, "reissued PQC client cert verifies against the migrated CA: " + (result.err || ""));
    });
  });

  describe("grace loopback", function () {
    it("a client cert from the OLD classical CA still verifies against ca.prev.crt during grace", async function () {
      var old = await installCa(CLASSICAL, 2);
      // Classical leaves issued by the pre-migration CA.
      var oldServerLeaf = await b.mtlsEngine.signClientCert({ cn: "old-srv", usage: "server", sans: ["127.0.0.1"], algorithm: CLASSICAL, caCertPem: old.caCertPem, caKeyPem: old.caKeyPem });
      var oldClientLeaf = await b.mtlsEngine.signClientCert({ cn: "old-cli", usage: "client", algorithm: CLASSICAL, caCertPem: old.caCertPem, caKeyPem: old.caKeyPem });

      var r = await mtlsMigrate.maybeMigrate({});
      assert.strictEqual(r.migrated, true);

      // Reconstruct the server-main trust bundle via the primitive: it returns
      // [new sync CA, retained prev CA].
      var bundle = await mtlsCa.loadTrustBundle();
      assert.strictEqual(bundle.length, 2, "trust bundle carries the new CA + the retained prev CA");
      var prevCaPem = nodeFs.readFileSync(C.PATHS.CA_PREV_CERT, "utf8");

      // Server presents a classical leaf the OLD CA signed; the old client cert
      // must authenticate against ca.prev.crt inside the mixed bundle.
      var result = await loopback({
        serverLeaf: oldServerLeaf,
        clientLeaf: oldClientLeaf,
        serverCa: bundle,
        clientCa: [prevCaPem],
      });
      assert.strictEqual(result.authorized, true, "old classical client verifies via ca.prev.crt: " + (result.err || ""));
    });
  });
});
