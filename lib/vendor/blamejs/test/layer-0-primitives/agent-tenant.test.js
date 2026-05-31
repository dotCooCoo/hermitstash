"use strict";

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  if (codeMatch instanceof RegExp) {
    check(label, threw && (codeMatch.test(threw.code || "") || codeMatch.test(threw.message || "")));
  } else {
    check(label, threw && ((threw.code || "").indexOf(codeMatch) !== -1 ||
                            (threw.message || "").indexOf(codeMatch) !== -1));
  }
}

function testSurface() {
  check("create is fn",         typeof b.agent.tenant.create === "function");
  check("AgentTenantError",     typeof b.agent.tenant.AgentTenantError === "function");
  check("CROSS_TENANT_ADMIN_SCOPE", typeof b.agent.tenant.CROSS_TENANT_ADMIN_SCOPE === "string");
  var e = new b.agent.tenant.AgentTenantError("agent-tenant/test", "t");
  check("error carries code",   e.code === "agent-tenant/test");
}

async function testRegisterLookupUnregister() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme-clinic", { posture: ["hipaa"] });
  var hit = await tenant.lookup("acme-clinic");
  check("lookup returns row",   hit && hit.tenantId === "acme-clinic");
  check("lookup posture array", Array.isArray(hit.posture) && hit.posture[0] === "hipaa");
  var miss = await tenant.lookup("nope");
  check("lookup miss is null",  miss === null);
  await expectRejection("duplicate register refused",
    tenant.register("acme-clinic", {}), "agent-tenant/duplicate");
}

async function testCheckCrossTenant() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", {});
  await tenant.register("globex", {});
  // Same tenant — OK.
  tenant.check({ id: "u1", tenantId: "acme" }, "acme");
  // Cross-tenant — refused.
  expectThrows("cross-tenant refused",
    function () { tenant.check({ id: "u1", tenantId: "globex" }, "acme"); },
    "agent-tenant/cross-tenant-access-refused");
  // Missing tenantId — refused.
  expectThrows("missing actor.tenantId refused",
    function () { tenant.check({ id: "u1" }, "acme"); },
    "agent-tenant/no-tenant-actor");
  // No actor — refused.
  expectThrows("missing actor refused",
    function () { tenant.check(null, "acme"); }, "agent-tenant/no-actor");
  // Global-scoped agent — no check (tenant id null).
  tenant.check({ id: "u1" }, null);
}

async function testCrossTenantAdminScope() {
  var perms = b.permissions.create({
    roles: {
      admin: { permissions: ["framework-cross-tenant-admin"] },
    },
    auditFailures: false, auditSuccess: false,
  });
  var tenant = b.agent.tenant.create({ permissions: perms });
  await tenant.register("acme", {});
  // Admin actor can cross tenant boundary.
  tenant.check({ id: "admin", tenantId: "ROOT", roles: ["admin"] }, "acme");
}

async function testDerivedKey() {
  var tenant = b.agent.tenant.create({});
  var k1 = tenant.derivedKey("acme", "seal");
  var k2 = tenant.derivedKey("acme", "seal");
  var k3 = tenant.derivedKey("globex", "seal");
  var k4 = tenant.derivedKey("acme", "audit");
  check("derivedKey deterministic",        k1 === k2);
  check("derivedKey per-tenant differs",   k1 !== k3);
  check("derivedKey per-purpose differs",  k1 !== k4);
  check("derivedKey returns string",        typeof k1 === "string" && k1.length > 0);
}

async function testAuditFor() {
  var captured = [];
  var fakeAudit = {
    safeEmit: function (ev) { captured.push(ev); },
  };
  var tenant = b.agent.tenant.create({ audit: fakeAudit });
  var auditA = tenant.auditFor("acme");
  auditA.safeEmit({ action: "mail.fetch", outcome: "success", metadata: { count: 1 } });
  check("auditFor: emit captured",          captured.length === 1);
  check("auditFor: tenantId tagged",         captured[0].metadata.tenantId === "acme");
  check("auditFor: original metadata preserved", captured[0].metadata.count === 1);
}

async function testUnregisterArchiveDefault() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", { posture: ["hipaa"], archivePolicy: "hipaa-6yr" });
  var r = await tenant.unregister("acme", { actor: { id: "admin" } });
  check("unregister default: mode = archived", r.mode === "archived");
  // Tenant no longer in active registry...
  var miss = await tenant.lookup("acme");
  check("unregister: lookup miss after archive", miss === null);
  // ...but visible in archived list (now async — backend may persist
  // the archived row, see SUBSTRATE-19).
  var archived = await tenant.listArchived();
  check("unregister: archived list has entry",
    archived.length === 1 && archived[0].tenantId === "acme");
}

async function testDestroyRequiresPreconditions() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("acme", {});
  // Bare destroy: true → refused, requires step-up.
  await expectRejection("destroy refuses without step-up",
    tenant.unregister("acme", { destroy: true, actor: { id: "admin" } }),
    "agent-tenant/destroy-requires-step-up");
  await expectRejection("destroy refuses without dual-control",
    tenant.unregister("acme", {
      destroy: true, stepUpToken: "abc", actor: { id: "admin" },
    }),
    "agent-tenant/destroy-requires-dual-control");
  await expectRejection("destroy refuses without reason",
    tenant.unregister("acme", {
      destroy: true, stepUpToken: "abc", dualControlApprover: "admin2",
      actor: { id: "admin" },
    }),
    "agent-tenant/destroy-requires-reason");
  // All preconditions met → destroy succeeds.
  var r = await tenant.unregister("acme", {
    destroy: true, stepUpToken: "abc", dualControlApprover: "admin2",
    reason: "GDPR Art. 17 request #2026-05-14",
    actor: { id: "admin", roles: ["root"] },
  });
  check("destroy with preconditions: mode = destroyed", r.mode === "destroyed");
  // Destroyed tenant is gone — not in archive either.
  var archived = await tenant.listArchived();
  check("destroy: not in archive", archived.length === 0);
}

async function testList() {
  var tenant = b.agent.tenant.create({});
  await tenant.register("a", {});
  await tenant.register("b", {});
  var rows = await tenant.list({});
  check("list returns 2", rows.length === 2);
}

async function testGuardRefusalAtBoundary() {
  var tenant = b.agent.tenant.create({});
  await expectRejection("register refuses bad tenant id",
    tenant.register("a/b", {}), "tenant-id/bad-char");
}

async function testSealFieldRoundTrip() {
  var tenant = b.agent.tenant.create({});
  b.cryptoField.registerTable("rx-patients-v0", { sealedFields: ["ssn"] });
  var ct = tenant.sealField("acme", "rx-patients-v0", "ssn", "123-45-6789");
  check("ciphertext carries tenant prefix", typeof ct === "string" && ct.indexOf("tnt-v1:") === 0);
  var pt = tenant.unsealField("acme", "rx-patients-v0", "ssn", ct);
  check("sealField round-trips plaintext", pt === "123-45-6789");
  // Idempotent — sealing already-sealed pass-through.
  var ct2 = tenant.sealField("acme", "rx-patients-v0", "ssn", ct);
  check("sealField idempotent on already-sealed", ct === ct2);
  // Null / undefined pass through.
  check("sealField null pass-through",  tenant.sealField("acme", "rx-patients-v0", "ssn", null) === null);
  check("sealField undef pass-through", tenant.sealField("acme", "rx-patients-v0", "ssn", undefined) === undefined);
}

async function testSealFieldCrossTenantRefused() {
  var tenant = b.agent.tenant.create({});
  b.cryptoField.registerTable("rx-patients-v1", { sealedFields: ["ssn"] });
  var ct = tenant.sealField("acme", "rx-patients-v1", "ssn", "secret-A");
  // Wrong tenantId must fail (Poly1305 tag mismatch from AAD difference).
  expectThrows("cross-tenant unseal refused",
    function () { tenant.unsealField("globex", "rx-patients-v1", "ssn", ct); }, /tag|invalid/i);
  // Wrong field also refused.
  expectThrows("wrong-field unseal refused",
    function () { tenant.unsealField("acme", "rx-patients-v1", "wrong-field", ct); }, /tag|invalid/i);
  // Wrong table also refused.
  expectThrows("wrong-table unseal refused",
    function () { tenant.unsealField("acme", "rx-other-table", "ssn", ct); }, /tag|invalid/i);
  // Missing tenant prefix on the ciphertext refused at boundary.
  expectThrows("bad-prefix ciphertext refused",
    function () { tenant.unsealField("acme", "rx-patients-v1", "ssn", "not-a-sealed-value"); },
    "bad-tenant-ciphertext");
}

async function testSealRowForTenant() {
  var tenant = b.agent.tenant.create({});
  b.cryptoField.registerTable("rx-patients-v2", { sealedFields: ["ssn", "dob"] });
  var row = { id: 1, name: "Alice", ssn: "123-45-6789", dob: "1990-01-01" };
  var sealed = tenant.sealRowForTenant("acme", "rx-patients-v2", row);
  check("sealRow id passthrough",       sealed.id === 1);
  check("sealRow name passthrough",     sealed.name === "Alice");
  check("sealRow ssn sealed",           typeof sealed.ssn === "string" && sealed.ssn.indexOf("tnt-v1:") === 0);
  check("sealRow dob sealed",           typeof sealed.dob === "string" && sealed.dob.indexOf("tnt-v1:") === 0);
  check("sealRow input not mutated",    row.ssn === "123-45-6789");
  var clear = tenant.unsealRowForTenant("acme", "rx-patients-v2", sealed);
  check("unsealRow ssn restored",       clear.ssn === "123-45-6789");
  check("unsealRow dob restored",       clear.dob === "1990-01-01");
}

async function testSealRowCrossTenantSafeFail() {
  var tenant = b.agent.tenant.create({});
  b.cryptoField.registerTable("rx-patients-v3", { sealedFields: ["ssn"] });
  var sealed = tenant.sealRowForTenant("acme", "rx-patients-v3", { id: 1, ssn: "secret" });
  var wrongTenant = tenant.unsealRowForTenant("globex", "rx-patients-v3", sealed);
  check("cross-tenant unsealRow null-fails on sealed field", wrongTenant.ssn === null);
  check("cross-tenant unsealRow keeps plain fields",         wrongTenant.id === 1);
}

async function testSealRowForUnknownTable() {
  var tenant = b.agent.tenant.create({});
  expectThrows("sealRowForTenant refuses unknown table",
    function () { tenant.sealRowForTenant("acme", "table-never-registered", { x: 1 }); },
    "agent-tenant/no-schema");
}

async function testDerivedKeyMasterBound() {
  // SUBSTRATE-5 — derivedKey must depend on the vault master, not
  // just public inputs. Reset the vault and confirm derivedKey
  // produces a DIFFERENT result for the same (tenantId, purpose).
  var tenant = b.agent.tenant.create({});
  var k1 = tenant.derivedKey("acme-clinic", "seal");
  // Rotate vault material: reset + re-init under a new dataDir
  // (writes a fresh keypair) produces a fresh master.
  var tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault2-"));
  helpers.teardownVaultOnly(global._testVaultDir);
  global._testVaultDir = tmpDir2;
  await helpers.setupVaultOnly(tmpDir2);
  var tenant2 = b.agent.tenant.create({});
  var k2 = tenant2.derivedKey("acme-clinic", "seal");
  check("derivedKey: vault rotation changes key bytes", k1 !== k2);
  check("derivedKey: deterministic within one vault",
    tenant2.derivedKey("acme-clinic", "seal") === k2);
  check("derivedKey: different tenant differs",
    tenant2.derivedKey("globex", "seal") !== k2);
  check("derivedKey: different purpose differs",
    tenant2.derivedKey("acme-clinic", "audit") !== k2);
}

async function testAadRotationDescriptorShape() {
  // SUBSTRATE — the module exports AAD_ROTATION descriptor(s) so the
  // vault-key rotation pipeline can eager-register the reseal hooks.
  var desc = b.agent.tenant.AAD_ROTATION;
  check("AAD_ROTATION is an array", Array.isArray(desc) && desc.length === 2);
  var byTable = {};
  desc.forEach(function (d) { byTable[d.table] = d; });
  var reg = byTable["agent_tenant_registry"];
  check("registry descriptor present", !!reg);
  check("registry rowIdField = tenantId", reg && reg.rowIdField === "tenantId");
  check("registry backend = external",    reg && reg.backend === "external");
  check("registry reseal is fn",          reg && typeof reg.reseal === "function");
  check("registry schemaVersion present", reg && typeof reg.schemaVersion === "string");
  var tnt = byTable["tnt-v1:"];
  check("tnt-v1 descriptor present",      !!tnt);
  check("tnt-v1 reseal is fn",            tnt && typeof tnt.reseal === "function");
  check("tnt-v1 backend = external",      tnt && tnt.backend === "external");
}

async function testTntCellResealAcrossRoots() {
  // The tnt-v1: family must re-seal old-root -> new-root via the
  // AAD_ROTATION reseal hook. Seal a cell under root1, rotate the live
  // vault to root2 (so a root1 cell no longer decrypts), reseal via the
  // hook, then confirm it decrypts under the live (root2) vault.
  var tenant = b.agent.tenant.create({});
  b.cryptoField.registerTable("rx-rotate-tnt", { sealedFields: ["ssn"] });
  var root1Json = b.vault.getKeysJson();
  var ct1 = tenant.sealField("acme", "rx-rotate-tnt", "ssn", "rotate-me-please");
  check("tnt reseal: cell sealed under root1", ct1.indexOf("tnt-v1:") === 0);

  // Rotate the live vault to root2.
  var tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-rot-"));
  helpers.teardownVaultOnly(global._testVaultDir);
  global._testVaultDir = tmpDir2;
  await helpers.setupVaultOnly(tmpDir2);
  var root2Json = b.vault.getKeysJson();
  check("tnt reseal: roots differ", root1Json !== root2Json);

  var tenant2 = b.agent.tenant.create({});
  // Pre-reseal: a root1 cell does not decrypt under the live root2.
  var failedPre = false;
  try { tenant2.unsealField("acme", "rx-rotate-tnt", "ssn", ct1); }
  catch (_e) { failedPre = true; }
  check("tnt reseal: root1 cell refused under root2 pre-reseal", failedPre);

  // Drive the reseal hook with an operator-shaped cell store.
  var stored = ct1;
  var store = {
    list: function () {
      return [{ tenantId: "acme", table: "rx-rotate-tnt", field: "ssn", value: stored }];
    },
    write: function (cell, next) { stored = next; },
  };
  var tnt = b.agent.tenant.AAD_ROTATION.filter(function (d) { return d.table === "tnt-v1:"; })[0];
  var result = await tnt.reseal({ store: store, oldRootJson: root1Json, newRootJson: root2Json });
  check("tnt reseal: count = 1", result.resealed === 1);
  check("tnt reseal: still carries prefix", stored.indexOf("tnt-v1:") === 0);
  check("tnt reseal: ciphertext changed", stored !== ct1);

  // Post-reseal: the cell decrypts under the live root2 vault.
  var pt = tenant2.unsealField("acme", "rx-rotate-tnt", "ssn", stored);
  check("tnt reseal: round-trips under new root", pt === "rotate-me-please");

  // Non-prefixed values pass through untouched (count not incremented).
  var plainStore = {
    list: function () {
      return [{ tenantId: "acme", table: "rx-rotate-tnt", field: "ssn", value: "not-sealed" }];
    },
    write: function () { check("tnt reseal: must not write plaintext", false); },
  };
  var r2 = await tnt.reseal({ store: plainStore, oldRootJson: root1Json, newRootJson: root2Json });
  check("tnt reseal: plaintext skipped", r2.resealed === 0);
}

async function testRegistryResealAcrossRoots() {
  // The registry metadata vault.aad: cells must re-seal old-root ->
  // new-root via the AAD_ROTATION reseal hook, rebuilding the AAD via
  // cryptoField._aadParts (single source of truth with the seal side).
  var SECRET = "billing-XQ-rotate-77";
  var rows = Object.create(null);
  var backend = {
    get:    function (k) { return Promise.resolve(rows[k] || null); },
    set:    function (k, row) { rows[k] = row; return Promise.resolve(); },
    delete: function (k) { delete rows[k]; return Promise.resolve(); },
    list:   function () { return Promise.resolve(Object.values(rows)); },
  };
  var tn = b.agent.tenant.create({ backend: backend });
  var root1Json = b.vault.getKeysJson();
  await tn.register("acme-reg", { posture: "hipaa", metadata: { billingId: SECRET } });
  check("registry reseal: metadata sealed under root1",
    typeof rows["acme-reg"].metadata === "string" &&
    /^vault(\.aad)?:/.test(rows["acme-reg"].metadata));

  // Rotate the live vault to root2.
  var tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-reg-"));
  helpers.teardownVaultOnly(global._testVaultDir);
  global._testVaultDir = tmpDir2;
  await helpers.setupVaultOnly(tmpDir2);
  var root2Json = b.vault.getKeysJson();

  var reg = b.agent.tenant.AAD_ROTATION.filter(function (d) {
    return d.table === "agent_tenant_registry";
  })[0];
  // Store adapter over the operator backend: list() yields the rows,
  // set(tenantId, row) writes back.
  var store = {
    list: function () { return backend.list(); },
    set:  function (k, row) { return backend.set(k, row); },
  };
  var before = rows["acme-reg"].metadata;
  var result = await reg.reseal({ store: store, oldRootJson: root1Json, newRootJson: root2Json });
  check("registry reseal: table name", result.table === "agent_tenant_registry");
  check("registry reseal: count = 1", result.resealed === 1);
  check("registry reseal: ciphertext changed", rows["acme-reg"].metadata !== before);

  // Post-reseal: lookup (live root2) round-trips the metadata back to an
  // object with the secret intact.
  var tn2 = b.agent.tenant.create({ backend: backend });
  var cfg = await tn2.lookup("acme-reg");
  check("registry reseal: metadata round-trips under new root",
    cfg && cfg.metadata && cfg.metadata.billingId === SECRET);
}

async function testTntDerivationExplicitRootVariant() {
  // _deriveTenantKeyBytes(tenantId, purpose, rootKeysJson?) must hash the
  // SUPPLIED root instead of the live singleton (default live). Surfaced
  // through the public derivedKey for the live path; the explicit-root
  // path is exercised through the reseal round-trips above (a cell sealed
  // under root1 decrypts under root2 only after reseal re-keys it via the
  // explicit-root derivation on both sides).
  var tenant = b.agent.tenant.create({});
  var live1 = tenant.derivedKey("acme", "seal");
  check("derivedKey live default deterministic",
    tenant.derivedKey("acme", "seal") === live1);
}

async function testUnsealRowAuditsOnDecryptRefusal() {
  // BUG-4 — cross-tenant decrypt nulls the field AND now emits a
  // cross_tenant_decrypt_refused audit so operator pipelines surface.
  var emits = [];
  var fakeAudit = { safeEmit: function (ev) { emits.push(ev); } };
  var tenant = b.agent.tenant.create({ audit: fakeAudit });
  b.cryptoField.registerTable("rx-patients-v4-audit", { sealedFields: ["ssn"] });
  var sealed = tenant.sealRowForTenant("acme", "rx-patients-v4-audit", { id: 1, ssn: "secret" });
  emits.length = 0;
  var unsealed = tenant.unsealRowForTenant("globex", "rx-patients-v4-audit", sealed);
  check("BUG-4: ssn nulled on cross-tenant",         unsealed.ssn === null);
  var saw = emits.some(function (ev) {
    return ev && ev.action === "agent.tenant.cross_tenant_decrypt_refused";
  });
  check("BUG-4: audit emitted on cross-tenant null", saw);
}

async function testRegistryMetadataSealedAtRest() {
  // The registry row's metadata is sealed at rest via b.cryptoField when
  // a vault is configured (it is, in this file's run()). Capture what
  // lands in the backend and assert the sensitive metadata is not stored
  // in the clear, then confirm lookup round-trips it back to an object.
  var SECRET = "tenant-billing-id-XQ42";
  var captured = null;
  var backend = {
    _m: Object.create(null),
    async get(k) { return this._m[k] || null; },
    async set(k, row) { this._m[k] = row; if (k === "acme-seal") captured = row; },
    async delete(k) { delete this._m[k]; },
    async list() { return Object.values(this._m); },
  };
  var tn = b.agent.tenant.create({ backend: backend });
  await tn.register("acme-seal", { posture: "hipaa", metadata: { billingId: SECRET } });
  check("tenant at-rest: metadata sealed (no plaintext leak)",
    typeof captured.metadata === "string" && captured.metadata.indexOf(SECRET) === -1);
  check("tenant at-rest: sealed metadata carries a vault prefix",
    /^vault(\.aad)?:/.test(String(captured.metadata)));
  var cfg = await tn.lookup("acme-seal");
  check("tenant at-rest: metadata round-trips to an object",
    cfg && cfg.metadata && cfg.metadata.billingId === SECRET);
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-"));
  global._testVaultDir = tmpDir;
  await helpers.setupVaultOnly(tmpDir);
  try {
    testSurface();
    await testRegistryMetadataSealedAtRest();
    await testRegisterLookupUnregister();
    await testCheckCrossTenant();
    await testCrossTenantAdminScope();
    await testDerivedKey();
    await testAuditFor();
    await testUnregisterArchiveDefault();
    await testDestroyRequiresPreconditions();
    await testList();
    await testGuardRefusalAtBoundary();
    await testSealFieldRoundTrip();
    await testSealFieldCrossTenantRefused();
    await testSealRowForTenant();
    await testSealRowCrossTenantSafeFail();
    await testSealRowForUnknownTable();
    await testUnsealRowAuditsOnDecryptRefusal();
    await testAadRotationDescriptorShape();
    await testTntDerivationExplicitRootVariant();
    await testTntCellResealAcrossRoots();
    await testRegistryResealAcrossRoots();
    await testDerivedKeyMasterBound();
  } finally {
    helpers.teardownVaultOnly(global._testVaultDir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
