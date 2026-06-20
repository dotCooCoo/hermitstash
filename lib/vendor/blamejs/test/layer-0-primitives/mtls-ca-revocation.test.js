"use strict";
/**
 * b.mtlsCa revocation + issuance identity (#322).
 *
 * The require-mtls gate denies by SHA3-512 fingerprint, but revocation used to
 * be keyed only by serial, the registry could only be a plaintext file, and
 * issuance discarded the serial + fingerprint. This proves the three additive
 * fixes: fingerprint-addressable revoke()/isRevoked(), a bring-your-own
 * revocation store, and serial+fingerprint surfaced from issuance.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-revoke-"));
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 1 });

  // ---- #322 part 3: issuance surfaces serial + fingerprint ----
  var issued = await ca.generateClientCert({ cn: "client-1" });
  check("issuance surfaces a hex serialNumber",
    typeof issued.serialNumber === "string" && /^[0-9a-f]+$/.test(issued.serialNumber));
  check("issuance surfaces a 128-hex SHA3-512 fingerprint",
    typeof issued.fingerprint === "string" && issued.fingerprint.length === 128);
  check("the surfaced fingerprint equals the gate's b.crypto.sha3Hash(cert)",
    issued.fingerprint === b.crypto.sha3Hash(issued.cert));

  // ---- #322 part 1: revoke + isRevoked by serial (backward-compat) ----
  ca.revoke(issued.serialNumber, { reason: "superseded" });
  check("revoke(serial) then isRevoked(serial) is true", ca.isRevoked(issued.serialNumber) === true);
  check("a serial that was never revoked reads false", ca.isRevoked("00ff") === false);
  var first = ca.revoke(issued.serialNumber);
  var again = ca.revoke(issued.serialNumber);
  check("revoke is idempotent (revokedAt unchanged)", first.revokedAt === again.revokedAt);

  // ---- #322 part 1: revoke + isRevoked by fingerprint (the gate's key) ----
  var issued2 = await ca.generateClientCert({ cn: "client-2" });
  ca.revoke({ fingerprint: issued2.fingerprint, reason: "keyCompromise" });
  check("revoke({fingerprint}) then isRevoked(fingerprint) is true",
    ca.isRevoked(issued2.fingerprint) === true);
  check("isRevoked tolerates separator/case formatting",
    ca.isRevoked(issued2.fingerprint.toUpperCase()) === true);

  var threwNoKey = false;
  try { ca.revoke({ reason: "x" }); } catch (e) { threwNoKey = /no-revocation-key/.test(e.code || ""); }
  check("revoke with neither serial nor fingerprint throws", threwNoKey);

  // ---- #322 part 2: bring-your-own revocation store ----
  var rows = [];
  var store = { list: function () { return rows.slice(); }, add: function (e) { rows.push(e); } };
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-byostore-"));
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: store });
  ca2.revoke("AB:CD:EF", { reason: "cessationOfOperation" });
  check("BYO store: revoke writes through the operator store (normalized serial)",
    rows.length === 1 && rows[0].serialNumber === "abcdef");
  check("BYO store: isRevoked reads through the operator store", ca2.isRevoked("abcdef") === true);
  check("BYO store: the default revocations.json was not written",
    !fs.existsSync(path.join(dir2, "revocations.json")));

  var threwBadStore = false;
  try {
    b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: { list: 1 } });
  } catch (e) { threwBadStore = /bad-revocation-store/.test(e.code || ""); }
  check("a revocationStore missing list()/add() is refused at create()", threwBadStore);

  // ---- #322 part 3: a custom engine may return a non-X.509 cert shape ----
  // The serial comes from an X.509 parse (best-effort); the fingerprint is a
  // hash of the returned bytes (always available). Optional identity
  // enrichment must never crash issuance.
  var dir3 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-stub-"));
  var stubEngine = {
    generateCa: async function () {
      return { caCertPem: "ENGINE-CA", caKeyPem: "ENGINE-KEY", generation: 1 };
    },
    signClientCert: async function (a) {
      return { cert: "-----BEGIN CERTIFICATE-----\nNOT-X509-" + a.cn + "\n-----END CERTIFICATE-----\n", key: "k" };
    },
  };
  var ca3 = b.mtlsCa.create({ dataDir: dir3, engine: stubEngine, caKeySealedMode: "disabled" });
  var stub = await ca3.generateClientCert({ cn: "stub-client" });
  check("non-X.509 engine cert does not crash issuance", typeof stub.cert === "string");
  check("unparseable cert yields serialNumber null (best-effort)", stub.serialNumber === null);
  check("fingerprint is still surfaced for a non-X.509 cert", stub.fingerprint === b.crypto.sha3Hash(stub.cert));
  ca3.revoke({ fingerprint: stub.fingerprint });
  check("a non-X.509 cert is still revocable by fingerprint", ca3.isRevoked(stub.fingerprint) === true);

  try {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
    fs.rmSync(dir3, { recursive: true, force: true });
  } catch (_e) { /* best-effort */ }
}

module.exports = { run: run };
