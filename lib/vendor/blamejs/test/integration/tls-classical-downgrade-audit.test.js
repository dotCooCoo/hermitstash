"use strict";
/**
 * Live proof of the outbound-TLS classical-downgrade audit. When an outbound
 * connection negotiates classical X25519 (the peer offers no ML-KEM hybrid),
 * the framework emits a `tls.classical_downgrade` audit event; when it
 * negotiates a hybrid, it does not. Azurite (its OpenSSL has no ML-KEM)
 * forces the classical fallback; MinIO-tls (OpenSSL 3.5) negotiates the
 * hybrid. Runs over TLS with the test CA (NODE_EXTRA_CA_CERTS), no bypass.
 */
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var services = require("../helpers/services");
var httpClient = require("../../lib/http-client");
var setupTestDb = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;
var fs = require("node:fs"), os = require("node:os"), path = require("node:path");

async function downgradeRows(sinceMs) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: "tls.classical_downgrade", from: sinceMs - 1000, limit: 100 });
  return (rows || []).map(function (r) {
    var md = r.metadata;
    if (typeof md === "string") { try { md = JSON.parse(md); } catch (_e) { md = {}; } }
    return md || {};
  });
}

async function run() {
  var azu = await services.requireService("azurite");
  if (!azu.ok) throw new Error("azurite unreachable: " + azu.reason);
  var mio = await services.requireService("minioTls");
  if (!mio.ok) throw new Error("minio-tls unreachable: " + mio.reason);

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tlsdown-"));
  try {
    await setupTestDb(dir, []);

    // Classical peer (Azurite — no ML-KEM hybrid). The HTTP response is
    // irrelevant (an unauthenticated GET may 400); the downgrade audit fires
    // on the TLS handshake regardless.
    var t0 = Date.now();
    try { await httpClient.request({ url: "https://127.0.0.1:10000/", method: "GET", allowInternal: true }); } catch (_e) {}
    var afterAzu = await downgradeRows(t0);
    var azuHit = afterAzu.filter(function (m) { return String(m.port) === "10000"; });
    check("classical peer (Azurite) emitted a tls.classical_downgrade audit", azuHit.length >= 1);
    check("downgrade audit names the classical group + host",
      azuHit.some(function (m) { return m.group === "X25519" && m.host === "127.0.0.1"; }));

    // PQC peer (MinIO-tls — negotiates the ML-KEM hybrid). No downgrade for it.
    var t1 = Date.now();
    try { await httpClient.request({ url: "https://127.0.0.1:9443/", method: "GET", allowInternal: true }); } catch (_e) {}
    var afterMio = await downgradeRows(t1);
    var mioHit = afterMio.filter(function (m) { return String(m.port) === "9443"; });
    check("PQC peer (MinIO-tls) emitted NO downgrade audit (hybrid negotiated)", mioHit.length === 0);

    await teardownTestDb(dir);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
  console.log("OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
