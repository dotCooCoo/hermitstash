"use strict";
/**
 * b.backup.scheduleTest — HIPAA §164.308(a)(7)(ii)(D) restore-drill.
 *
 * The drill is the regulator-facing proof that a backup is RESTORABLE,
 * not merely that bytes landed in storage. The framework advertises that
 * scheduleTest:
 *   (1) restores the latest bundle into an operator staging dir,
 *   (2) verifies the bundle manifest's SLH-DSA / ML-DSA signature,
 *   (3) hands the restored bundle + parsed manifest to the operator
 *       verify callback, and
 *   (4) records a pass/fail result in the signed audit chain
 *       (backup.test.passed / backup.test.failed).
 *
 * This drives the real drill end-to-end against a real sealed-at-rest
 * data dir + signed audit chain + local diskStorage backend, then drives
 * a FAILING drill (tampered manifest signature) and asserts it reports
 * failure rather than a false pass.
 *
 * Two dispatch paths are exercised:
 *   - the closure scheduleTest builds (captured + awaited directly so we
 *     observe completion deterministically), and
 *   - the genuine b.scheduler dispatch (instance._fireOnce → drill runs).
 */

var fs   = require("fs");
var os   = require("os");
var path = require("path");

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var waitUntil = helpers.waitUntil;
var { setupTestDb, teardownTestDb } = require("../helpers/db");

// audit_log stores metadata as a JSON string column; query() returns it
// as-is. Parse it for field assertions.
function _meta(row) {
  if (row && typeof row.metadata === "string") {
    try { return JSON.parse(row.metadata); } catch (_e) { return {}; }
  }
  return (row && row.metadata) || {};
}

// A scheduler stand-in whose create() returns a fake whose schedule()
// captures the spec.run closure. This lets us AWAIT the exact drill
// closure scheduleTest registers (the full restore+verify+audit body)
// to completion — the real scheduler's fire path is fire-and-forget.
function _makeCapturingScheduler() {
  var captured = { specs: [] };
  return {
    captured: captured,
    create: function () {
      return {
        schedule: function (spec) {
          captured.specs.push(spec);
          return spec;
        },
        start: function () {},
        stop:  function () {},
      };
    },
  };
}

function _seedSealedDataDir() {
  // Real bytes resembling the framework's encrypted-at-rest layout —
  // an opaque db envelope + the sealed DEK. The drill restores + the
  // operator verify hook confirms the restored bytes round-trip.
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "drill-data-"));
  var dbEnc  = Buffer.from("ENVELOPE-" + b.crypto.generateToken(48), "utf8");
  var keyEnc = Buffer.from("SEALED-DEK-" + b.crypto.generateToken(32), "utf8");
  fs.writeFileSync(path.join(dataDir, "db.enc"), dbEnc);
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), keyEnc);
  return { dataDir: dataDir, dbEnc: dbEnc, keyEnc: keyEnc };
}

async function main() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "drill-fw-"));
  await setupTestDb(tmpDir);

  var seeded = _seedSealedDataDir();
  var storageRoot = fs.mkdtempSync(path.join(os.tmpdir(), "drill-store-"));
  var restoreRoot = fs.mkdtempSync(path.join(os.tmpdir(), "drill-restore-"));

  var storage = b.backup.diskStorage({ root: storageRoot });
  var capSched = _makeCapturingScheduler();

  var engine = b.backup.create({
    dataDir:    seeded.dataDir,
    storage:    storage,
    passphrase: Buffer.from("operator-backup-passphrase-256bit-entropy-here"),
    files: [
      { relativePath: "db.enc",     kind: "raw", required: true },
      { relativePath: "db.key.enc", kind: "raw", required: true },
    ],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
    scheduler:    capSched,
  });

  // ---- Produce a real, signed backup bundle --------------------------
  var runSummary = await engine.run({ metadata: { reason: "drill-fixture" } });
  check("backup.run produced a bundle id", typeof runSummary.bundleId === "string" && runSummary.bundleId.length > 0);
  var bundles = await engine.list();
  check("one bundle is in storage after run", bundles.length === 1);

  // Sanity: the stored bundle's manifest is genuinely signed (the drill's
  // signature-verify step is only meaningful if there is a signature).
  var storedBundleId = bundles[0].bundleId;
  var manifestOnDisk = JSON.parse(
    fs.readFileSync(path.join(storageRoot, storedBundleId, "manifest.json"), "utf8"));
  check("stored manifest carries a signature block",
    manifestOnDisk.signature && typeof manifestOnDisk.signature.value === "string" &&
    manifestOnDisk.signature.value.length > 0);
  var signedFingerprint = manifestOnDisk.signature.fingerprint;

  // =====================================================================
  // PART 1 — PASSING DRILL via the captured closure (awaited to done)
  // =====================================================================
  var verifyCall = null;
  var notifyCalls = [];
  var schedResult = engine.scheduleTest({
    cron:      "0 3 * * 0",
    restoreTo: restoreRoot,
    posture:   "hipaa",
    verify: async function (ctx) {
      // Operator-side verification: confirm the restored payload matches
      // the original sealed bytes AND the framework handed us a parsed,
      // signature-verified manifest + the outDir it restored into.
      verifyCall = {
        outDir:          ctx.outDir,
        bundleId:        ctx.bundleId,
        sigFingerprint:  ctx.sigFingerprint,
        manifestVersion: ctx.manifest && ctx.manifest.version,
        dbEncMatch:      false,
        keyEncMatch:     false,
        outDirExists:    fs.existsSync(ctx.outDir),
      };
      // The bundle stores ENCRYPTED file bytes under files/; decrypt-on-
      // restore is the backup-crypto layer's job and is exercised by the
      // bundle tests. Here the drill's contract is "restored bundle is
      // present + manifest verifies"; the operator hook proves the bundle
      // dir + manifest are real by reading back the manifest's file list
      // and confirming the encrypted blobs exist on disk.
      var allBlobsPresent = ctx.manifest.files.every(function (f) {
        return fs.existsSync(path.join(ctx.outDir, f.encryptedPath));
      });
      verifyCall.allBlobsPresent = allBlobsPresent;
      // Confirm the manifest describes the two files we backed up.
      var rels = ctx.manifest.files.map(function (f) { return f.relativePath; }).sort();
      verifyCall.dbEncMatch  = rels.indexOf("db.enc") !== -1;
      verifyCall.keyEncMatch = rels.indexOf("db.key.enc") !== -1;
      return true;
    },
    notify: async function (info) { notifyCalls.push(info); },
  });

  check("scheduleTest returned an instance handle",
    schedResult && typeof schedResult.name === "string" && schedResult.instance);
  check("scheduleTest registered exactly one scheduler task",
    capSched.captured.specs.length === 1);
  var drillSpec = capSched.captured.specs[0];
  check("the registered task carries the operator cron",
    drillSpec.cron === "0 3 * * 0");
  check("the registered task carries an async run closure",
    typeof drillSpec.run === "function");

  // Fire the real drill closure and await it to completion.
  await drillSpec.run();

  check("(1) drill restored the bundle into a staging dir under restoreTo",
    verifyCall !== null && verifyCall.outDirExists === true &&
    verifyCall.outDir.indexOf(restoreRoot) === 0);
  check("(1b) restored staging dir carried the encrypted file blobs",
    verifyCall.allBlobsPresent === true);
  check("(2) drill verified the manifest signature before calling verify (fingerprint passed through)",
    verifyCall.sigFingerprint === signedFingerprint &&
    typeof verifyCall.sigFingerprint === "string" && verifyCall.sigFingerprint.length > 0);
  check("(3) drill handed the operator a parsed manifest covering the backed-up files",
    verifyCall.manifestVersion === 1 && verifyCall.dbEncMatch && verifyCall.keyEncMatch);
  check("(3b) drill targeted the newest stored bundle",
    verifyCall.bundleId === storedBundleId);

  // (4) pass/fail recorded in the signed audit chain.
  await b.audit.flush();
  var passRows = await b.audit.query({ action: "backup.test.passed" });
  check("(4) drill emitted exactly one backup.test.passed audit row", passRows.length === 1);
  var passMeta = _meta(passRows[0]);
  check("(4b) passed row records the bundle id + posture + fingerprint",
    passMeta.bundleId === storedBundleId &&
    passMeta.posture === "hipaa" &&
    passMeta.fingerprint === signedFingerprint);
  check("(4c) passed row outcome is success", passRows[0].outcome === "success");

  check("notify hook fired with success outcome on a passing drill",
    notifyCalls.length === 1 && notifyCalls[0].outcome === "success" &&
    notifyCalls[0].bundleId === storedBundleId);

  // The drill cleans staging by default — confirm it didn't leave the
  // restore dir behind (regulator drills must not accumulate plaintext-
  // restored bundles).
  check("drill cleaned its staging dir after a passing run",
    !fs.existsSync(verifyCall.outDir));

  // =====================================================================
  // PART 2 — PASSING DRILL via the GENUINE scheduler dispatch path
  // =====================================================================
  // Re-run the drill through a real b.scheduler instance + its _fireOnce
  // test hook so the genuine schedule()/fire path is exercised, not just
  // the captured closure.
  b.scheduler._resetForTest && b.scheduler._resetForTest();
  var realVerifyHit = false;
  var realEngine = b.backup.create({
    dataDir:    seeded.dataDir,
    storage:    storage,
    passphrase: Buffer.from("operator-backup-passphrase-256bit-entropy-here"),
    files: [
      { relativePath: "db.enc",     kind: "raw", required: true },
      { relativePath: "db.key.enc", kind: "raw", required: true },
    ],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
    scheduler:    b.scheduler,
  });
  var realDrill = realEngine.scheduleTest({
    name:      "drill.real.path",
    cron:      "0 4 * * 0",
    restoreTo: restoreRoot,
    posture:   "hipaa",
    verify: async function (ctx) {
      realVerifyHit = ctx && typeof ctx.outDir === "string" &&
        ctx.sigFingerprint === signedFingerprint;
      return true;
    },
  });
  // Fire via the real scheduler dispatch. _fireOnce is fire-and-forget;
  // wait for the drill's audit row to appear.
  realDrill.instance._fireOnce("drill.real.path");
  await waitUntil(async function () {
    await b.audit.flush();
    var rows = await b.audit.query({ action: "backup.test.passed" });
    return rows.length >= 2;
  }, { timeoutMs: 5000, label: "real-scheduler drill: backup.test.passed lands" });
  check("genuine scheduler dispatch ran the drill verify hook", realVerifyHit === true);

  // =====================================================================
  // PART 3 — FAILING DRILL: tamper the stored bundle's manifest signature
  // =====================================================================
  // Flip a byte in the signature value of the stored manifest so the
  // signature no longer verifies. The drill MUST report failure — not a
  // false pass — and MUST NOT call the operator verify hook (verification
  // gates the hand-off).
  var manifestPath = path.join(storageRoot, storedBundleId, "manifest.json");
  var tampered = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  var sigBuf = Buffer.from(tampered.signature.value, "base64");
  sigBuf[0] = sigBuf[0] ^ 0xff;           // corrupt the first signature byte
  tampered.signature.value = sigBuf.toString("base64");
  fs.writeFileSync(manifestPath, JSON.stringify(tampered, null, 2) + "\n");

  var failVerifyCalled = false;
  var failNotify = [];
  var capSched2 = _makeCapturingScheduler();
  var failEngine = b.backup.create({
    dataDir:    seeded.dataDir,
    storage:    storage,
    passphrase: Buffer.from("operator-backup-passphrase-256bit-entropy-here"),
    files: [
      { relativePath: "db.enc",     kind: "raw", required: true },
      { relativePath: "db.key.enc", kind: "raw", required: true },
    ],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
    scheduler:    capSched2,
  });
  failEngine.scheduleTest({
    cron:      "0 5 * * 0",
    restoreTo: restoreRoot,
    posture:   "hipaa",
    verify: async function () { failVerifyCalled = true; return true; },
    notify: async function (info) { failNotify.push(info); },
  });
  await capSched2.captured.specs[0].run();

  check("tampered-signature drill did NOT call the operator verify hook (verify gates hand-off)",
    failVerifyCalled === false);

  await b.audit.flush();
  var failRows = await b.audit.query({ action: "backup.test.failed" });
  check("failing drill emitted a backup.test.failed audit row (no false pass)",
    failRows.length === 1);
  check("failed row outcome is failure", failRows[0].outcome === "failure");
  var failMeta = _meta(failRows[0]);
  check("failed row reason names the signature failure",
    typeof failMeta.reason === "string" && /signature/i.test(failMeta.reason));

  // Critically: the passing-row count must NOT have grown — a tampered
  // bundle must never be recorded as a passed drill.
  var passRowsAfterTamper = await b.audit.query({ action: "backup.test.passed" });
  check("tampering did not produce an additional backup.test.passed row",
    passRowsAfterTamper.length === 2);

  check("notify hook fired with failure outcome on the tampered drill",
    failNotify.length === 1 && failNotify[0].outcome === "failure" &&
    /signature/i.test(failNotify[0].reason || ""));

  // ---- cleanup -------------------------------------------------------
  await teardownTestDb(tmpDir);
  try { fs.rmSync(seeded.dataDir, { recursive: true, force: true }); } catch (_e) {}
  try { fs.rmSync(storageRoot, { recursive: true, force: true }); } catch (_e) {}
  try { fs.rmSync(restoreRoot, { recursive: true, force: true }); } catch (_e) {}

  // check() throws on the first failed assertion, so reaching here means
  // every assertion passed.
  console.log("backup-scheduletest-drill: OK — " + helpers.getChecks() + " checks passed");
}

main().catch(function (e) {
  console.error("FAIL: backup-scheduletest-drill threw:", e && e.stack || e);
  process.exitCode = 1;
});
