// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.tenantQuota — per-tenant DB storage caps + query budget +
 * isolation breach detection.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;

// A b.db-shaped stub that satisfies create()'s duck-type check
// (from + prepare + getTableMetadata functions) without booting a real DB —
// used only by the config-validation cases, which throw before any query runs.
function _stubDb() {
  return {
    from:             function () { return { where: function () { return this; }, select: function () { return this; }, all: function () { return []; } }; },
    prepare:          function () { return { all: function () { return []; }, get: function () { return null; } }; },
    getTableMetadata: function () { return {}; },
  };
}

function _mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function _catch(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

function testSurface() {
  check("tenantQuota.create is fn",          typeof b.tenantQuota.create === "function");
  check("tenantQuota.budget is fn",          typeof b.tenantQuota.budget === "function");
  check("tenantQuota.instrumentQuery is fn", typeof b.tenantQuota.instrumentQuery === "function");
  check("TenantQuotaError is fn",            typeof b.tenantQuota.TenantQuotaError === "function");
  var e = new b.tenantQuota.TenantQuotaError("tenant-quota/test", "t");
  check("TenantQuotaError carries code",     e.code === "tenant-quota/test");
}

// ---------------------------------------------------------------------------
// budget() — sliding-window sentry (happy path + boundary)
// ---------------------------------------------------------------------------

function testBudgetSlidingWindow() {
  var budget = b.tenantQuota.budget({
    tenantField:            "tenantId",
    perTenantQpsCap:        2,
    perTenantTotalRowsRead: 100,
    window:                 b.constants.TIME.seconds(1),
    audit:                  false,
  });
  check("budget.observe is fn", typeof budget.observe === "function");

  var snap0 = budget.snapshot("tenant-acme");
  check("snapshot empty starts at zero", snap0.calls === 0 && snap0.rowsRead === 0);

  var ob1 = budget.observe("tenant-acme", { rowsRead: 5 });
  check("observe increments calls/rowsRead", ob1.calls === 1 && ob1.rowsRead === 5);

  // Force a budget breach by reading too many rows in one observe.
  var threwBudget = null;
  try { budget.observe("tenant-acme", { rowsRead: 200 }); }
  catch (e) { threwBudget = e; }
  check("observe throws when rowsRead exceeds cap",
    threwBudget && threwBudget.code === "tenant-quota/budget-exceeded");

  budget.reset("tenant-acme");
  var snapReset = budget.snapshot("tenant-acme");
  check("reset clears counters", snapReset.calls === 0);

  // TRUE sliding window (no fixed-window boundary doubling). maxCalls =
  // floor(qpsCap * window/1s) = 5. Fill 5 near the window's tail, then 1 more
  // just past the nominal reset: a fixed window admits it (~2x burst), a
  // sliding window refuses (trailing window still covers them).
  var sw = b.tenantQuota.budget({ tenantField: "tenantId", perTenantQpsCap: 5, window: 1000, audit: false });
  for (var i = 0; i < 5; i++) sw.observe("t-burst", { now: 900 });
  var threwBoundary = null;
  try { sw.observe("t-burst", { now: 1001 }); } catch (e) { threwBoundary = e; }
  check("sliding window refuses the boundary-straddling burst (not a fixed window)",
        threwBoundary && threwBoundary.code === "tenant-quota/budget-exceeded");
  // After a full window has elapsed, the old calls scroll out → admitted again
  // (advance >= BINS full-clear path in _slide).
  var allowedAfterGap = true;
  try { sw.observe("t-burst", { now: 2600 }); } catch (_e) { allowedAfterGap = false; }
  check("sliding window admits again once the prior calls age out", allowedAfterGap === true);
}

// ---------------------------------------------------------------------------
// budget() — observe defaults, calls-arm breach, in-counters snapshot,
// sub-window (small-advance) ring slide
// ---------------------------------------------------------------------------

function testBudgetObserveDefaults() {
  var budget = b.tenantQuota.budget({ tenantField: "tenantId", audit: false });

  // No info at all → rowsRead defaults to 0, now defaults to wall-clock.
  var d0 = budget.observe("t-default");
  check("observe with no info defaults rowsRead to 0", d0.rowsRead === 0 && d0.calls === 1);

  // Negative rowsRead is clamped to 0 (the `info.rowsRead >= 0` guard's false arm).
  var d1 = budget.observe("t-default", { rowsRead: -50 });
  check("observe clamps negative rowsRead to 0", d1.rowsRead === 0 && d1.calls === 2);

  // In-counters snapshot path (distinct from the empty-tenant zero return).
  var snapLive = budget.snapshot("t-default");
  check("snapshot of an observed tenant reports live calls", snapLive.calls === 2);

  // Calls-arm breach, isolated from the rows arm: maxCalls = floor(1 * 1) = 1,
  // rows cap huge, so the second call trips purely on the call count.
  var callBudget = b.tenantQuota.budget({
    tenantField:            "tenantId",
    perTenantQpsCap:        1,
    perTenantTotalRowsRead: 1000000,
    window:                 1000,
    audit:                  false,
  });
  callBudget.observe("t-calls", { now: 500, rowsRead: 0 });
  var threwCalls = null;
  try { callBudget.observe("t-calls", { now: 500, rowsRead: 0 }); }
  catch (e) { threwCalls = e; }
  check("observe throws on the calls arm of the budget (rowsRead well under cap)",
    threwCalls && threwCalls.code === "tenant-quota/budget-exceeded" &&
    /rowsRead=0\//.test(threwCalls.message));

  // Sub-window ring advance (0 < advance < BINS): observe at bin 0, then a
  // second observe a few bins later shifts the ring without a full clear.
  var slideBudget = b.tenantQuota.budget({ tenantField: "tenantId", window: 1200, audit: false });
  slideBudget.observe("t-slide", { now: 0 });
  var sSlide = slideBudget.observe("t-slide", { now: 300 });
  check("ring slides a few bins without dropping the earlier call",
    sSlide.calls === 2);
}

// ---------------------------------------------------------------------------
// budget() — config validation (every throw branch)
// ---------------------------------------------------------------------------

function testBudgetConfigValidation() {
  var nonObj = _catch(function () { return b.tenantQuota.budget(null); });
  check("budget rejects non-object opts",
    nonObj instanceof b.tenantQuota.TenantQuotaError);

  var unknownKey = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "tenantId", bogus: 1, audit: false });
  });
  check("budget rejects an unknown opt key",
    unknownKey && /unknown option/.test(unknownKey.message));

  var badField = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "", audit: false });
  });
  check("budget rejects empty tenantField",
    badField && badField.code === "tenant-quota/bad-field");

  var badQps = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "tenantId", perTenantQpsCap: 0, audit: false });
  });
  check("budget rejects non-positive perTenantQpsCap",
    badQps && badQps.code === "tenant-quota/bad-qps");

  var infQps = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "tenantId", perTenantQpsCap: Infinity, audit: false });
  });
  check("budget rejects Infinity perTenantQpsCap",
    infQps && infQps.code === "tenant-quota/bad-qps");

  var badRows = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "tenantId", perTenantTotalRowsRead: -1, audit: false });
  });
  check("budget rejects non-positive perTenantTotalRowsRead",
    badRows && badRows.code === "tenant-quota/bad-rows");

  var badWindow = _catch(function () {
    return b.tenantQuota.budget({ tenantField: "tenantId", window: 0, audit: false });
  });
  check("budget rejects non-positive window",
    badWindow && badWindow.code === "tenant-quota/bad-window");

  // observe() input validation — empty tenantId is refused.
  var okBudget = b.tenantQuota.budget({ tenantField: "tenantId", audit: false });
  var badObserve = _catch(function () { return okBudget.observe(""); });
  check("observe rejects empty tenantId",
    badObserve && badObserve.code === "tenant-quota/bad-tenant");

  // reset() with an explicit tenantId (the delete-one branch) and no-arg
  // (clear-all branch) both no-op cleanly.
  okBudget.observe("t-x");
  okBudget.reset("t-x");
  check("reset(tenantId) clears just that tenant", okBudget.snapshot("t-x").calls === 0);
  okBudget.observe("t-y");
  okBudget.reset();
  check("reset() with no arg clears every tenant", okBudget.snapshot("t-y").calls === 0);
}

// ---------------------------------------------------------------------------
// instrumentQuery() — isolation breach detection
// ---------------------------------------------------------------------------

function testInstrumentQueryBasic() {
  var goodCheck = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-a", value: 2 },
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    audit:       false,
  });
  check("instrumentQuery clean rows → ok",           goodCheck.ok === true);
  check("instrumentQuery clean rows → empty cross",  goodCheck.crossover.length === 0);

  var badCheck = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-b", value: 2 }, // crossover
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    audit:       false,
  });
  check("instrumentQuery crossover detected",         badCheck.ok === false);
  check("instrumentQuery crossover index recorded",   badCheck.crossover[0].index === 1);
  check("instrumentQuery crossover actual recorded",
    badCheck.crossover[0].actualTenantId === "tenant-b");
}

// ---------------------------------------------------------------------------
// instrumentQuery() — adversarial / defensive input
// ---------------------------------------------------------------------------

function testInstrumentQueryAdversarial() {
  var nullOpts = _catch(function () { return b.tenantQuota.instrumentQuery(null); });
  check("instrumentQuery rejects null opts",
    nullOpts && nullOpts.code === "tenant-quota/bad-instr");

  var scalarOpts = _catch(function () { return b.tenantQuota.instrumentQuery("nope"); });
  check("instrumentQuery rejects non-object opts",
    scalarOpts && scalarOpts.code === "tenant-quota/bad-instr");

  var unknownKey = _catch(function () {
    return b.tenantQuota.instrumentQuery({
      rows: [], tenantField: "tenantId", tenantId: "t", surprise: 1, audit: false,
    });
  });
  check("instrumentQuery rejects an unknown opt key",
    unknownKey && /unknown option/.test(unknownKey.message));

  var badRows = _catch(function () {
    return b.tenantQuota.instrumentQuery({
      rows: "not-an-array", tenantField: "tenantId", tenantId: "t", audit: false,
    });
  });
  check("instrumentQuery rejects non-array rows",
    badRows && badRows.code === "tenant-quota/bad-rows");

  var badField = _catch(function () {
    return b.tenantQuota.instrumentQuery({
      rows: [], tenantField: "", tenantId: "t", audit: false,
    });
  });
  check("instrumentQuery rejects empty tenantField",
    badField && badField.code === "tenant-quota/bad-field");

  var badTenant = _catch(function () {
    return b.tenantQuota.instrumentQuery({
      rows: [], tenantField: "tenantId", tenantId: "", audit: false,
    });
  });
  check("instrumentQuery rejects empty tenantId",
    badTenant && badTenant.code === "tenant-quota/bad-tenant");

  // Defensive row walk: non-object rows (null, scalar) are skipped, and rows
  // whose tenantField is null/undefined are NOT flagged as a crossover.
  var mixed = b.tenantQuota.instrumentQuery({
    rows: [
      null,                                  // skipped (not an object)
      42,                                    // skipped (not an object)
      { tenantId: null, value: 1 },          // null field → not a crossover
      { value: 2 },                          // missing field → not a crossover
      { tenantId: "tenant-a", value: 3 },    // matches claim → ok
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    audit:       false,
  });
  check("instrumentQuery skips non-object rows and null-field rows",
    mixed.ok === true && mixed.crossover.length === 0);

  // audit-on crossover: exercises the audit().safeEmit + observability branch
  // (default audit:true). The emission is best-effort so it never throws.
  var audited = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-b", value: 2 },
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    table:       "orders",
  });
  check("instrumentQuery audit-on path still returns the crossover result",
    audited.ok === false && audited.crossover.length === 1);

  // audit-on crossover WITHOUT a table → exercises the `opts.table || null`
  // fallback in the emitted audit metadata.
  var auditedNoTable = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-b", value: 2 },
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
  });
  check("instrumentQuery audit-on crossover without a table still reports the breach",
    auditedNoTable.ok === false && auditedNoTable.crossover.length === 1);
}

// ---------------------------------------------------------------------------
// create() — defensive: db.getTableMetadata() returning null
// ---------------------------------------------------------------------------

async function testEmptyMetadataResolvesNoTables() {
  // getTableMetadata() may legitimately return null (no tables declared yet);
  // the byte walk must fall back to an empty table set, not crash.
  var nullMetaDb = {
    from: function () {
      return { where: function () { return this; }, select: function () { return this; }, all: function () { return []; } };
    },
    prepare: function () { return { all: function () { return []; }, get: function () { return null; } }; },
    getTableMetadata: function () { return null; },
  };
  var quota = b.tenantQuota.create({ db: nullMetaDb, tenantField: "tenantId", audit: false });
  var snap = await quota.snapshot("t-none");
  check("snapshot on a db with null metadata yields zero bytes",
    snap.tenantId === "t-none" && snap.bytesUsed === 0);
  var listed = await quota.list();
  check("list on a db with null metadata is empty",
    Array.isArray(listed) && listed.length === 0);
}

// ---------------------------------------------------------------------------
// create() — config validation (every throw branch, no DB required)
// ---------------------------------------------------------------------------

function testCreateConfigValidation() {
  var stub = _stubDb();

  var nonObj = _catch(function () { return b.tenantQuota.create(null); });
  check("create rejects non-object opts",
    nonObj instanceof b.tenantQuota.TenantQuotaError);

  var unknownKey = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "tenantId", bogus: 1, audit: false });
  });
  check("create rejects an unknown opt key",
    unknownKey && /unknown option/.test(unknownKey.message));

  var missingDb = _catch(function () {
    return b.tenantQuota.create({ tenantField: "tenantId", audit: false });
  });
  check("create rejects a missing db handle",
    missingDb && missingDb.code === "tenant-quota/bad-db");

  var badDb = _catch(function () {
    return b.tenantQuota.create({ db: { foo: 1 }, tenantField: "tenantId", audit: false });
  });
  check("create rejects a non-b.db handle",
    badDb && badDb.code === "tenant-quota/bad-db");

  var badField = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "", audit: false });
  });
  check("create rejects empty tenantField",
    badField && badField.code === "tenant-quota/bad-field");

  var badCap = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "tenantId", defaultBytesCap: 0, audit: false });
  });
  check("create rejects non-positive defaultBytesCap",
    badCap && badCap.code === "tenant-quota/bad-cap");

  var nanCap = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "tenantId", defaultBytesCap: Number.NaN, audit: false });
  });
  check("create rejects NaN defaultBytesCap",
    nanCap && nanCap.code === "tenant-quota/bad-cap");

  var arrayPer = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "tenantId", perTenantBytesCap: [], audit: false });
  });
  check("create rejects an array perTenantBytesCap",
    arrayPer && arrayPer.code === "tenant-quota/bad-per-tenant");

  var badPerVal = _catch(function () {
    return b.tenantQuota.create({
      db: stub, tenantField: "tenantId",
      perTenantBytesCap: { "t-vip": -5 }, audit: false,
    });
  });
  check("create rejects a negative per-tenant override",
    badPerVal && badPerVal.code === "tenant-quota/bad-per-tenant");

  var badTtl = _catch(function () {
    return b.tenantQuota.create({ db: stub, tenantField: "tenantId", cacheTtlMs: -1, audit: false });
  });
  check("create rejects a negative cacheTtlMs",
    badTtl && badTtl.code === "tenant-quota/bad-ttl");

  // A fully-valid create with a stub db returns the enforcer object; the
  // default-cap / default-ttl / auditOn assignment branches all run here.
  var ok = b.tenantQuota.create({ db: stub, tenantField: "tenantId", audit: false });
  check("create with valid opts returns an enforcer object",
    ok && typeof ok.assert === "function" && typeof ok.snapshot === "function" &&
    typeof ok.list === "function" && typeof ok.invalidate === "function");
}

// ---------------------------------------------------------------------------
// create() — storage-cap lifecycle against a real encrypted DB
// ---------------------------------------------------------------------------

async function testStorageCapLifecycle() {
  var tmpDir = _mkTmp("tenant-quota-");
  try {
    await helpers.setupTestDb(tmpDir, [
      {
        name: "docs",
        columns: {
          _id:      "TEXT PRIMARY KEY",
          tenantId: "TEXT",
          body:     "TEXT",
          blob:     "BLOB",
        },
        indexes: ["tenantId"],
      },
      {
        // A table WITHOUT the tenantField — auto-detection must skip it.
        name: "sansTenant",
        columns: { _id: "TEXT PRIMARY KEY", label: "TEXT" },
      },
      {
        // A table with a SEALED column — its on-disk value is a vault
        // envelope far larger than the plaintext it unseals to. The byte
        // count must measure the stored envelope, not the auto-unsealed cell.
        name: "sealed_docs",
        columns: { _id: "TEXT PRIMARY KEY", tenantId: "TEXT", secret: "TEXT" },
        sealedFields: ["secret"],
        indexes: ["tenantId"],
      },
      {
        // A table whose NAME is a SQL reserved word ("from"). db.from()
        // supports it (quoting neutralizes the keyword), so the storage-byte
        // sum — which builds its own SQL — must quote it with allowReserved
        // too, or snapshot throws sql/reserved-word for a schema-valid table.
        name: "from",
        columns: { _id: "TEXT PRIMARY KEY", tenantId: "TEXT", note: "TEXT" },
        indexes: ["tenantId"],
      },
      {
        // A table whose tenantField ("tid") is itself a SEALED column with a
        // derived hash. On disk "tid" holds a vault envelope, so a plaintext
        // `WHERE tid = ?` matches nothing; the byte sum must filter by the
        // derived-hash blind index (as db.from().where() does) or the cap
        // silently counts zero for these tenants.
        name: "sealed_tenant",
        columns: { _id: "TEXT PRIMARY KEY", tid: "TEXT", tidHash: "TEXT", note: "TEXT" },
        sealedFields:  ["tid"],
        derivedHashes: { tidHash: { from: "tid" } },
        indexes: ["tidHash"],
      },
    ]);

    b.db.from("docs").insertOne({ _id: "d1", tenantId: "t-acme", body: "hello", blob: Buffer.from("ABCD") });
    b.db.from("docs").insertOne({ _id: "d2", tenantId: "t-acme", body: null }); // null col → skipped in the byte walk
    b.db.from("docs").insertOne({ _id: "d3", tenantId: "t-small", body: "x" });
    b.db.from("docs").insertOne({ _id: "d4", tenantId: null, body: "orphan" }); // null tenant → skipped by list()
    b.db.from("sansTenant").insertOne({ _id: "s1", label: "ignore-me" });

    // Auto-detected tables (walks getTableMetadata for the tenantField).
    var quota = b.tenantQuota.create({
      db:               b.db,
      tenantField:      "tenantId",
      defaultBytesCap:  b.constants.BYTES.gib(1),
      perTenantBytesCap: { "t-acme": b.constants.BYTES.gib(10) },
      audit:            false,
    });

    var snap = await quota.snapshot("t-acme");
    check("snapshot returns the standard shape",
      snap.tenantId === "t-acme" && typeof snap.bytesUsed === "number" &&
      typeof snap.bytesCap === "number" && typeof snap.percent === "number");
    check("snapshot counts textual + buffer bytes across the tenant's rows",
      snap.bytesUsed > 0);
    check("per-tenant override wins over the default cap",
      snap.bytesCap === b.constants.BYTES.gib(10));

    // Cache-aside: a second snapshot within the TTL returns the cached total
    // even after new rows land; invalidate() forces the recompute.
    var before = snap.bytesUsed;
    b.db.from("docs").insertOne({ _id: "d5", tenantId: "t-acme", body: "more-bytes-here" });
    var cached = await quota.snapshot("t-acme");
    check("snapshot serves the cached byte total inside the TTL",
      cached.bytesUsed === before);
    quota.invalidate("t-acme");
    var recomputed = await quota.snapshot("t-acme");
    check("invalidate(tenantId) forces a recompute that sees the new row",
      recomputed.bytesUsed > before);
    // No-arg invalidate clears the whole cache; the next snapshot recomputes.
    quota.invalidate();
    var afterClear = await quota.snapshot("t-small");
    check("invalidate() with no arg still yields a fresh snapshot",
      afterClear.tenantId === "t-small" && afterClear.bytesUsed > 0);

    // Default cap applies to a tenant with no override.
    check("tenant without an override uses the default cap",
      afterClear.bytesCap === b.constants.BYTES.gib(1));

    // assert() under the cap returns the snapshot.
    var okAssert = await quota.assert("t-small");
    check("assert under the cap returns the snapshot", okAssert.tenantId === "t-small");

    // list() enumerates distinct tenants (skipping the null-tenant orphan row).
    var listed = await quota.list();
    var ids = listed.map(function (s) { return s.tenantId; }).sort();
    check("list() returns a snapshot per distinct tenant",
      ids.length === 2 && ids[0] === "t-acme" && ids[1] === "t-small");

    // Over-cap refusal: a tiny cap forces assert() to refuse the insert.
    var tightQuota = b.tenantQuota.create({
      db:              b.db,
      tenantField:     "tenantId",
      defaultBytesCap: 1,        // 1 byte — any real row breaches
      cacheTtlMs:      0,        // always recompute (miss-branch every call)
      tables:          ["docs"], // explicit tables override (skips auto-detect)
      audit:           false,
    });
    var threwOver = null;
    try { await tightQuota.assert("t-small"); }
    catch (e) { threwOver = e; }
    check("assert refuses (throws) when the tenant is over its byte cap",
      threwOver && threwOver.code === "tenant-quota/exceeded");
    check("over-cap refusal is a TenantQuotaError",
      threwOver instanceof b.tenantQuota.TenantQuotaError);

    // snapshot() input validation: empty tenantId is refused.
    var badTenant = null;
    try { await quota.snapshot(""); }
    catch (e) { badTenant = e; }
    check("snapshot rejects empty tenantId",
      badTenant && badTenant.code === "tenant-quota/bad-tenant");

    // Blob byte-accounting: a BLOB column round-trips as a Uint8Array (not a
    // Node Buffer). Its contribution must be the true byte length, not the
    // decimal-joined String() form. Isolate a tenant whose only non-null cells
    // are _id + tenantId + an 8-byte blob so the total is exact.
    //   _id "bd1" (3) + tenantId "t-blob" (6) + blob.byteLength (8) = 17.
    b.db.from("docs").insertOne({ _id: "bd1", tenantId: "t-blob", body: null, blob: Buffer.from("ABCDEFGH") });
    var blobSnap = await quota.snapshot("t-blob");
    check("blob bytes counted by byteLength (not the stringified array)",
      blobSnap.bytesUsed === 3 + 6 + 8);

    // Sealed-column storage: a sealed cell is stored as a (much larger) vault
    // envelope. The byte count must read the raw stored value, not the ORM's
    // auto-unsealed facade — otherwise a tenant with sealed columns slips far
    // under a storage cap. Insert a tiny plaintext ("x"), then verify the
    // count reflects the full on-disk envelope for that isolated tenant.
    b.db.from("sealed_docs").insertOne({ _id: "sd1", tenantId: "t-sealed", secret: "x" });
    var rawSecret = b.db.prepare('SELECT secret FROM sealed_docs WHERE _id = ?').get("sd1").secret;
    check("sealed column is stored as a vault envelope, not plaintext (precondition)",
      typeof rawSecret === "string" && rawSecret !== "x" && Buffer.byteLength(rawSecret, "utf8") > 20);
    var sealedSnap = await quota.snapshot("t-sealed");
    // _id "sd1" (3) + tenantId "t-sealed" (8) + the raw envelope bytes. The
    // unsealed-plaintext path would count "x" as 1 byte → 12 total, far below.
    check("sealed column counted at its on-disk envelope size, not the unsealed plaintext",
      sealedSnap.bytesUsed === 3 + 8 + Buffer.byteLength(rawSecret, "utf8"));

    // A reserved-word table name ("from") is schema-valid and queryable via
    // db.from(); snapshot's own SQL must quote it with allowReserved so it
    // does not throw sql/reserved-word. _id "rw1" (3) + tenantId "t-rw" (4)
    // + note "hi" (2) = 9 bytes for this isolated tenant.
    b.db.from("from").insertOne({ _id: "rw1", tenantId: "t-rw", note: "hi" });
    var rwThrew = null, rwSnap = null;
    try { rwSnap = await quota.snapshot("t-rw"); } catch (e) { rwThrew = e; }
    check("snapshot does not throw on a reserved-word table name", rwThrew === null);
    check("reserved-word table rows counted correctly",
      rwSnap && rwSnap.bytesUsed === 3 + 4 + 2);

    // A schema-qualified table name ("archive.docs") must pass identifier
    // quoting the same way db.from() / b.sql do (they quote "schema"."table").
    // The previous hand-rolled quoteIdentifier treated the dot as part of one
    // name and rejected it with sql/bad-shape before the query ran. The
    // attached "archive" db is absent here, so the query fails with a
    // no-such-table error — the point is that it is NOT rejected at quoting.
    var qualQuota = b.tenantQuota.create({
      db:               b.db,
      tenantField:      "tenantId",
      tables:           ["archive.docs"],
      defaultBytesCap:  b.constants.BYTES.gib(1),
      audit:            false,
    });
    var qualErr = null;
    try { await qualQuota.snapshot("t-any"); } catch (e) { qualErr = e; }
    check("schema-qualified table name passes identifier quoting (not sql/bad-shape)",
      qualErr === null || qualErr.code !== "sql/bad-shape");

    // A sealed tenantField: "tid" is sealed on disk, so a plaintext WHERE
    // never matches. snapshot must filter by the derived-hash blind index
    // (as db.from().where() does) — otherwise the cap silently counts zero.
    b.db.from("sealed_tenant").insertOne({ _id: "st1", tid: "tenant-x", note: "data" });
    var sealedTenantQuota = b.tenantQuota.create({
      db:               b.db,
      tenantField:      "tid",
      tables:           ["sealed_tenant"],
      defaultBytesCap:  b.constants.BYTES.gib(1),
      audit:            false,
    });
    var stSnap = await sealedTenantQuota.snapshot("tenant-x");
    check("sealed tenantField resolves via derived hash (rows are found, not zero)",
      stSnap.bytesUsed > 0);
    // The row's raw cells: _id "st1" + the sealed "tid" envelope + the tidHash
    // digest + note "data" — comfortably over 40 bytes; the buggy plaintext
    // filter would match nothing and report 0.
    check("sealed-tenantField storage counted (envelope + hash + plaintext cells)",
      stSnap.bytesUsed > 40);

    // instrumentQuery audit-on path with a live audit chain (real safeEmit).
    var audited = b.tenantQuota.instrumentQuery({
      rows: [
        { tenantId: "t-acme", v: 1 },
        { tenantId: "t-evil", v: 2 },
      ],
      tenantField: "tenantId",
      tenantId:    "t-acme",
      table:       "docs",
    });
    check("instrumentQuery emits on a live audit chain and reports the breach",
      audited.ok === false && audited.crossover[0].actualTenantId === "t-evil");
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  testBudgetSlidingWindow();
  testBudgetObserveDefaults();
  testBudgetConfigValidation();
  testInstrumentQueryBasic();
  testInstrumentQueryAdversarial();
  testCreateConfigValidation();
  await testEmptyMetadataResolvesNoTables();
  await testStorageCapLifecycle();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[tenant-quota] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
