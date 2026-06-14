"use strict";
/**
 * b.backup.create — residency posture enforcement.
 *
 * The backup-create residency gate (lib/backup/index.js) is advertised to
 * refuse a cross-border destination under a regulated posture, advise on an
 * undeclared destination, and (the real bug) is blind to per-row residency
 * tags: a deployment whose region is EU but which holds per-row us-east-1
 * rows backs up to an EU destination with no warning about the US rows.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = helpers.fs;
var os   = helpers.os;
var path = helpers.path;

// Capture audit.safeEmit events by call-through wrapping (same spy shape the
// erase-posture-vacuum test uses for vacuumAfterErase). The backup gate emits
// via b.audit.safeEmit, so wrapping it records the advisory.
function captureAudit() {
  var events = [];
  var real = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) {
    try { events.push(ev); } catch (_e) { /* ignore */ }
    return real.call(b.audit, ev);
  };
  return { events: events, restore: function () { b.audit.safeEmit = real; } };
}

async function initDbWithRegion(tmpDir, region) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir:       tmpDir,
    tmpDir:        path.join(tmpDir, "tmpfs"),
    dataResidency: { region: region, allowedStorageRegions: ["us-east-1", "global"] },
    schema: [{
      name: "residents",
      columns: { _id: "TEXT PRIMARY KEY", name: "TEXT", dataRegion: "TEXT" },
    }],
  });
}

// Minimal valid backup opts that reach the residency block in create()
// (dataDir exists, storage/passphrase/files/vaultKeyJson present).
function backupOpts(dataDir, root, extra) {
  fs.writeFileSync(path.join(dataDir, "db.enc"), Buffer.from([1, 2, 3]));
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), Buffer.from([4, 5, 6]));
  var opts = {
    dataDir:      dataDir,
    storage:      b.backup.diskStorage({ root: root }),
    passphrase:   Buffer.from("operator-backup-passphrase-not-secret"),
    files: [
      { relativePath: "db.enc",     kind: "raw", required: true },
      { relativePath: "db.key.enc", kind: "raw", required: true },
    ],
    vaultKeyJson: '{"version":1,"kid":"k1"}',
  };
  if (extra) for (var k in extra) opts[k] = extra[k];
  return opts;
}

function createCode(opts) {
  try { b.backup.create(opts); } catch (e) { return e && e.code; }
  return null;
}

async function run() {
  var tmp  = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backupresid-"));
  var data = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backupresid-data-"));
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backupresid-root-"));
  await initDbWithRegion(tmp, "eu-west-1");
  b.compliance.clear();
  b.compliance.set("gdpr");
  try {
    // ---- Case 1: MISMATCH-REFUSAL (advertised, never tested to throw) ----
    check("gdpr + eu-west-1 db + us-east-1 destination → backup/residency-mismatch",
          createCode(backupOpts(data, root, { residencyTag: "us-east-1" })) ===
          "backup/residency-mismatch");
    // The allowCrossBorder override path must SUCCEED.
    var okOverride = null;
    try {
      okOverride = b.backup.create(backupOpts(data, root, {
        residencyTag: "us-east-1", allowCrossBorder: true,
        legalBasis: "EU SCCs 2021/914",
      }));
    } catch (_e) { okOverride = null; }
    check("allowCrossBorder + legalBasis override creates the engine",
          okOverride && typeof okOverride.run === "function");

    // ---- Case 2: UNDECLARED-ADVISORY (advertised, never tested to emit) ----
    var cap = captureAudit();
    try {
      var engNoTag = b.backup.create(backupOpts(data, root, {}));   // no residencyTag
      check("undeclared residencyTag does NOT throw (advisory, not refusal)",
            engNoTag && typeof engNoTag.run === "function");
    } finally { cap.restore(); }
    check("undeclared residency under gdpr emits backup.residency_undeclared advisory",
          cap.events.some(function (e) { return e && e.action === "backup.residency_undeclared"; }));

    // ---- Case 3: PER-ROW BLINDNESS (the real bug — RED today) ----
    // The deployment region is eu-west-1, but a per-row residency-tagged
    // table admits a us-east-1 row (us-east-1 is in allowedStorageRegions).
    // Backing up to an eu-west-1 destination must warn/refuse about the US
    // rows — today it passes silently because the gate only sees the
    // deployment-level region (eu-west-1 == residencyTag eu-west-1 → clean).
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "global"],
    });
    // The backup advisory reads its table set from this enumerator — assert it
    // directly so the deployment-wide view the gate depends on is covered.
    var declared = b.cryptoField.listPerRowResidency();
    check("listPerRowResidency enumerates the declared table",
          declared.length === 1 && declared[0].table === "residents" &&
          declared[0].residencyColumn === "dataRegion" &&
          declared[0].allowedTags.indexOf("us-east-1") !== -1);
    b.db.from("residents").insertOne({ _id: "row-us", name: "u", dataRegion: "us-east-1" });
    b.db.from("residents").insertOne({ _id: "row-eu", name: "e", dataRegion: "eu-west-1" });

    var cap2 = captureAudit();
    var sawPerRowAdvisory = false;
    var threwPerRow = null;
    try {
      b.backup.create(backupOpts(data, root, { residencyTag: "eu-west-1" }));
    } catch (e) { threwPerRow = e; }
    finally {
      sawPerRowAdvisory = cap2.events.some(function (e) {
        return e && typeof e.action === "string" &&
          /backup\.residency/.test(e.action) &&
          e.metadata && (e.metadata.scope === "per-row" ||
            /per[-_]?row|row[-_]?tag/.test(JSON.stringify(e.metadata)));
      });
      cap2.restore();
    }
    // RED: the US rows must be surfaced — either a per-row cross-border
    // advisory is emitted, or create() refuses. Today neither happens.
    check("per-row us-east-1 rows under an EU destination trigger a cross-border advisory or refusal",
          sawPerRowAdvisory === true ||
          (threwPerRow && threwPerRow.code === "backup/residency-mismatch"));
  } finally {
    b.cryptoField.clearResidencyForTest();
    b.compliance.clear();
    try { b.db.close(); } catch (_e) {}
    b.audit._resetForTest();
    b.db._resetForTest();
    b.vault._resetForTest();
    b.cluster._resetForTest();
    fs.rmSync(tmp,  { recursive: true, force: true });
    fs.rmSync(data, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log("OK — backup residency posture tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
