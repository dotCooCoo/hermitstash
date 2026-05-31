"use strict";
/**
 * b.vaultRotate.rotate — AAD round-trip.
 *
 * Regression for the vault-key rotation orphaning class: a keypair
 * rotation must re-seal, old-root -> new-root,
 *   - vault.aad: data cells (registerTable({ aad: true })),
 *   - the AAD-bound db.key.enc (deployment-context sealed master key), and
 *   - the AAD-bound db.enc envelope (_dbEncAad(dataDir)),
 * so the rotated data dir opens and decrypts under the NEW keypair and no
 * longer under the old one. Before this fix rotate re-sealed only plain
 * `vault:` cells, threw `bad-dbkey` on the AAD-sealed master key, and read
 * db.enc with no AAD — silently orphaning AAD cells while reporting ok.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;

var SECRETS_SCHEMA = [{
  name:          "secrets",
  columns:       { _id: "TEXT PRIMARY KEY", tenantId: "TEXT", secret: "TEXT" },
  sealedFields:  ["secret"],
  aad:           true,
  rowIdField:    "_id",
  schemaVersion: "1",
}];

// Discover every lib module that declares an external AAD_ROTATION descriptor
// by reading its actual export, so the gate-coverage assertion can't drift as
// modules are added. backend:"external" means the store lives outside db.enc
// (an operator-supplied backend) and the rotation pipeline can only refuse and
// point at the module's reseal hook — so every such module MUST be reachable
// from rotate's EXTERNAL_AAD_MODULE_LOADERS or a rotation silently orphans it.
function _discoverExternalAadTables() {
  var libDir = path.join(__dirname, "..", "..", "lib");
  var files = [];
  fs.readdirSync(libDir).forEach(function (name) {
    var full = path.join(libDir, name);
    if (fs.statSync(full).isDirectory()) {
      fs.readdirSync(full).forEach(function (n2) { if (n2.slice(-3) === ".js") files.push(path.join(full, n2)); });
    } else if (name.slice(-3) === ".js") { files.push(full); }
  });
  var tables = [];
  files.forEach(function (f) {
    if (f.replace(/\\/g, "/").indexOf("/vault/rotate.js") !== -1) return;   // the gate consumes; it doesn't declare
    var src = fs.readFileSync(f, "utf8");
    if (src.indexOf("AAD_ROTATION") === -1 || src.indexOf("\"external\"") === -1) return;
    var mod;
    try { mod = require(f); } catch (_e) { return; }
    var desc = mod && mod.AAD_ROTATION;
    if (!desc) return;
    (Array.isArray(desc) ? desc : [desc]).forEach(function (d) {
      if (d && d.backend === "external" && d.table) tables.push(d.table);
    });
  });
  return tables;
}

async function _reset() {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
}

async function run() {
  // Gate-coverage invariant: rotate's external-AAD gate must name every
  // external AAD_ROTATION table any lib module declares. A module that ships
  // the descriptor but isn't wired into EXTERNAL_AAD_MODULE_LOADERS would let
  // rotate() succeed with no acknowledgement, orphaning that store under the
  // retired root (the archive-wrap:tenant-blobs gap caught on PR #293).
  var declaredExternal = _discoverExternalAadTables();
  var gatedExternal    = b.vaultRotate._externalAadTables();
  check("found the external AAD_ROTATION modules (idempotency/orchestrator/tenant/snapshot/archive-wrap)",
    declaredExternal.length >= 6);
  var ungated = declaredExternal.filter(function (t) { return gatedExternal.indexOf(t) === -1; });
  check("rotate's external-AAD gate covers every declared external AAD_ROTATION table (ungated: " + ungated.join(", ") + ")",
    ungated.length === 0);

  var dirNew  = fs.mkdtempSync(path.join(os.tmpdir(), "vr-new-"));
  var dirA    = fs.mkdtempSync(path.join(os.tmpdir(), "vr-a-"));
  var staging = path.join(os.tmpdir(), "vr-stg-" + process.pid + "-" + Date.now());

  try {
    // 1. A fresh, distinct keypair to rotate INTO.
    await _reset();
    await b.vault.init({ dataDir: dirNew, mode: "plaintext" });
    var newKeys = JSON.parse(b.vault.getKeysJson());
    b.vault._resetForTest();

    // 2. The live deployment: vault + encrypted db + an AAD-bound table
    //    carrying one sealed row.
    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    var oldKeys = JSON.parse(b.vault.getKeysJson());
    check("old and new keypairs differ", JSON.stringify(oldKeys) !== JSON.stringify(newKeys));
    await b.db.init({ dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted", auditSigning: false, frameworkTables: false, schema: SECRETS_SCHEMA });

    var sealed = b.cryptoField.sealRow("secrets", { _id: "sec-1", tenantId: "t1", secret: "top-secret-value" });
    check("AAD seal produced a vault.aad: cell (db.init honored aad:true)",
      typeof sealed.secret === "string" && sealed.secret.indexOf("vault.aad:") === 0);
    b.db.from("secrets").insertOne(sealed);
    await b.db.flushToDisk();
    await b.db.close();

    // Detect-and-refuse: without acknowledging the external-AAD agent
    // stores, rotate must refuse rather than silently orphan them.
    var refused = null;
    try {
      await b.vaultRotate.rotate({ dataDir: dirA, stagingDir: staging + "-x", oldKeys: oldKeys, newKeys: newKeys, mode: "plaintext" });
    } catch (e) { refused = e; }
    check("rotate refuses unacknowledged external-AAD stores",
      !!refused && refused.code === "vault-rotate/external-aad-unresealed");

    // 3. Rotate the keypair old -> new.
    // externalAadResealed: true acknowledges the operator-supplied agent
    // stores (idempotency/orchestrator/tenant/snapshot) are handled via
    // their own reseal hooks — this deployment uses none of them.
    var result = await b.vaultRotate.rotate({
      dataDir: dirA, stagingDir: staging, oldKeys: oldKeys, newKeys: newKeys, mode: "plaintext",
      externalAadResealed: true,
    });
    // rotate's own round-trip verify decrypts the staged db.enc with the
    // new keypair and (with oldKeys supplied) regression-checks the old —
    // so ok===true means the AAD cell + db.key.enc + db.enc all rotated.
    check("rotate internal verify ok (AAD cells decrypt under new root, old rejected)",
      !!result.verifyResult && result.verifyResult.ok === true);
    check("rotate processed the sealed row", result.totalRowsProcessed >= 1);

    // 4. Swap staging -> dataDir and re-open under the NEW keypair: proves
    //    db.init's AAD-first open of the rotated db.enc + db.key.enc works
    //    and the data cell decrypts end-to-end.
    ["db.enc", "db.key.enc", "vault.key"].forEach(function (f) {
      var s = path.join(staging, f);
      if (fs.existsSync(s)) fs.copyFileSync(s, path.join(dirA, f));
    });
    try { fs.rmSync(path.join(dirA, "tmpfs"), { recursive: true, force: true }); } catch (_e) { /* fresh decrypt */ }

    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    check("vault now live under the NEW keypair", JSON.stringify(JSON.parse(b.vault.getKeysJson())) === JSON.stringify(newKeys));
    await b.db.init({ dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted", auditSigning: false, frameworkTables: false, schema: SECRETS_SCHEMA });

    var got = b.cryptoField.unsealRow("secrets", b.db.from("secrets").where({ _id: "sec-1" }).first());
    check("AAD cell decrypts after rotation under the new keypair", !!got && got.secret === "top-secret-value");
    await b.db.close();
  } finally {
    await _reset();
    [dirNew, dirA, staging].forEach(function (d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* cleanup */ } });
  }
}

module.exports = { run: run };
