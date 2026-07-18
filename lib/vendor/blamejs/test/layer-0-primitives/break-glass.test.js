// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.breakGlass — column-policy / row-enforcement step-up auth (v0.5.0).
 *
 * Covers: surface, policy CRUD, TOTP factor verification, grant
 * lifecycle (expiry / exhaustion / revoke), error codes, IP/session
 * pinning data flow, audit emission per row, sweep.
 *
 * Run standalone: `node test/layer-0-primitives/break-glass.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var C = b.constants;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bg-")); }

// Build a test "patient" record table that mimics the operator-facing
// shape: a glass-locked column (ssn) sealed via cryptoField. We don't
// need a custom table schema — _blamejs_jobs has sealed columns we
// can repurpose for the unsealRow test (payload field is sealed). For
// the policy tests we use arbitrary table names since policy.set
// doesn't validate the table exists in the DB.

function _validTotp() {
  var secret = b.auth.totp.generateSecret();
  var code = b.auth.totp.generate(secret);
  return { secret: secret, code: code };
}

function _fakeReq(overrides) {
  var base = {
    user:    { id: "user-test-1" },
    session: { id: "sess-test-1" },
    socket:  { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" },
    method:  "POST",
    url:     "/admin/break-glass",
  };
  return Object.assign(base, overrides || {});
}

// ---- Surface ----

function testSurface() {
  check("b.breakGlass namespace present",          typeof b.breakGlass === "object");
  check("breakGlass.init is fn",                   typeof b.breakGlass.init === "function");
  check("breakGlass.policy.set is fn",             typeof b.breakGlass.policy.set === "function");
  check("breakGlass.policy.get is fn",             typeof b.breakGlass.policy.get === "function");
  check("breakGlass.policy.list is fn",            typeof b.breakGlass.policy.list === "function");
  check("breakGlass.policy.delete is fn",          typeof b.breakGlass.policy.delete === "function");
  check("breakGlass.grant is fn",                  typeof b.breakGlass.grant === "function");
  check("breakGlass.unsealRow is fn",              typeof b.breakGlass.unsealRow === "function");
  check("breakGlass.revoke is fn",                 typeof b.breakGlass.revoke === "function");
  check("breakGlass.listActive is fn",             typeof b.breakGlass.listActive === "function");
  check("breakGlass.BreakGlassError is class",     typeof b.breakGlass.BreakGlassError === "function");
}

// ---- init opts validation ----

function testInitOptsValidation() {
  // The `now` knob was documented as a Date.now override but nothing
  // consumed it (every time read is a direct Date.now()). It is removed
  // from the init allowlist, so passing it is now a config-time error.
  var threwNow = false;
  try { b.breakGlass.init({ now: 123 }); } catch (_e) { threwNow = true; }
  check("init: removed `now` opt throws", threwNow);

  // A bare trustProxy is refused — the grant IP pin would bind to a forgeable
  // X-Forwarded-For. Operators declare peer-gating instead.
  var threwTrustProxy = false;
  try { b.breakGlass.init({ trustProxy: true }); } catch (_e) { threwTrustProxy = true; }
  check("init: bare trustProxy refused (spoofable IP pin)", threwTrustProxy);

  var threwTrusted = false;
  try { b.breakGlass.init({ trustedProxies: ["10.0.0.0/8"] }); } catch (_e) { threwTrusted = true; }
  check("init: trustedProxies accepted", !threwTrusted);

  var threwResolver = false;
  try { b.breakGlass.init({ clientIpResolver: function (rq) { return rq && rq.headers && rq.headers["true-client-ip"]; } }); }
  catch (_e) { threwResolver = true; }
  check("init: clientIpResolver accepted", !threwResolver);

  var threwBadCidr = false;
  try { b.breakGlass.init({ trustedProxies: ["nope"] }); } catch (_e) { threwBadCidr = true; }
  check("init: malformed trustedProxies CIDR refused", threwBadCidr);

  // bare init() with no opts still works (resolves the socket address).
  var threwBare = false;
  try { b.breakGlass.init(); } catch (_e) { threwBare = true; }
  check("init: no-opts init still works", !threwBare);
}

// ---- Policy CRUD ----

async function testPolicyCRUD() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();

    // No policy → null
    var p0 = await b.breakGlass.policy.get("patients");
    check("policy.get unset returns null", p0 === null);

    // Set
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn", "diagnosis"],
      factors: ["totp"],
    });
    var p1 = await b.breakGlass.policy.get("patients");
    check("policy.get returns the saved policy",
          p1 && p1.table === "patients");
    check("policy.set defaults maxRowsPerGrant = 1",
          p1 && p1.maxRowsPerGrant === 1);
    check("policy.set defaults grantTtl = 15 min",
          p1 && p1.grantTtl === C.TIME.minutes(15));
    check("policy.set defaults reasonRequired = true",
          p1 && p1.reasonRequired === true);
    check("policy.set defaults pinIp = true",
          p1 && p1.pinIp === true);
    check("policy.set defaults sessionPin = true",
          p1 && p1.sessionPin === true);
    check("policy.set defaults onLockedAccess = throw",
          p1 && p1.onLockedAccess === "throw");
    check("policy.set defaults auditReasonStorage = cleartext",
          p1 && p1.auditReasonStorage === "cleartext");
    check("policy.set columns round-trip",
          p1 && Array.isArray(p1.columns) && p1.columns[0] === "ssn" && p1.columns[1] === "diagnosis");

    // List
    var all = await b.breakGlass.policy.list();
    check("policy.list returns 1 entry",  all.length === 1 && all[0].table === "patients");

    // Update (UPSERT)
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      grantTtl: C.TIME.minutes(5),
      maxRowsPerGrant: 10,
      reasonMinLength: 20,
    });
    var p2 = await b.breakGlass.policy.get("patients");
    check("policy.set is idempotent UPSERT (columns updated)",
          p2.columns.length === 1 && p2.columns[0] === "ssn");
    check("policy.set updates grantTtl",      p2.grantTtl === C.TIME.minutes(5));
    check("policy.set updates maxRowsPerGrant", p2.maxRowsPerGrant === 10);
    check("policy.set updates reasonMinLength", p2.reasonMinLength === 20);

    // Delete
    await b.breakGlass.policy.delete("patients");
    var p3 = await b.breakGlass.policy.get("patients");
    check("policy.delete removes the policy",  p3 === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Input validation (rejects bad opts at create time) ----

async function testPolicyValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, table, opts, codeRe) {
      return b.breakGlass.policy.set(table, opts).then(
        function () { check("policy.validate: " + label + " (should throw)", false); },
        function (e) { check("policy.validate: " + label, codeRe.test(e.code || "")); }
      );
    }
    await reject("rejects bad table",          "", { columns: ["x"], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing columns",    "t", { factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects empty columns",      "t", { columns: [], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing factors",    "t", { columns: ["x"] }, /breakglass\/bad-policy/);
    await reject("rejects unknown factor",     "t", { columns: ["x"], factors: ["sms"] }, /breakglass\/bad-policy/);
    await reject("rejects unknown factor 'sms'",   "t", { columns: ["x"], factors: ["sms"] }, /breakglass\/bad-policy/);
    await reject("rejects non-boolean cryptographic",
                                               "t", { columns: ["x"], factors: ["totp"], cryptographic: "yes" }, /breakglass\/bad-policy/);
    await reject("rejects bad onLockedAccess", "t", { columns: ["x"], factors: ["totp"], onLockedAccess: "panic" }, /breakglass\/bad-policy/);
    await reject("rejects bad maxRowsPerGrant","t", { columns: ["x"], factors: ["totp"], maxRowsPerGrant: 0 }, /breakglass\/bad-policy/);
    await reject("rejects negative grantTtl",  "t", { columns: ["x"], factors: ["totp"], grantTtl: -1 }, /breakglass\/bad-policy/);
    await reject("rejects bad auditReasonStorage",
                                               "t", { columns: ["x"], factors: ["totp"], auditReasonStorage: "raw" }, /breakglass\/bad-policy/);
    await reject("rejects serviceAccountBypass in 0.5.0",
                                               "t", { columns: ["x"], factors: ["totp"], serviceAccountBypass: { enabled: true } }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — happy path ----

async function testGrantHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:     _fakeReq(),
      table:   "patients",
      reason:  "investigating ticket #12345 for compliance review",
      factor:  { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: returns id",               typeof grant.id === "string" && grant.id.indexOf("bg-") === 0);
    check("grant: returns expiresAt",        typeof grant.expiresAt === "number" && grant.expiresAt > Date.now());
    check("grant: rowsRemaining = 1 (default)", grant.rowsRemaining === 1);
    check("grant: scopeTable echoed",        grant.scopeTable === "patients");
    check("grant: scopeColumns echoed",      grant.scopeColumns.length === 1 && grant.scopeColumns[0] === "ssn");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — requireScope wildcard is segment-aware ----

async function testGrantRequireScopeWildcardSegmentAware() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], requireScope: "phi:admin",
    });
    function grantWithScopes(actorId, scopes) {
      var totp = _validTotp();
      return b.breakGlass.grant({
        req:    _fakeReq({ user: { id: actorId, scopes: scopes } }),
        table:  "patients",
        reason: "investigating ticket #12345 for compliance review",
        factor: { type: "totp", code: totp.code, secret: totp.secret },
      });
    }
    // A partial-segment wildcard must NOT satisfy a different segment value:
    // "phi:a*" is not the segment wildcard "phi:*", so it must not glass-unseal
    // "phi:admin" (segment-aware match via b.permissions.match, not a raw
    // string prefix where "phi:admin".indexOf("phi:a") === 0).
    var denied = null;
    try { await grantWithScopes("user-deny", ["phi:a*"]); }
    catch (e) { denied = e; }
    check("break-glass: partial-segment wildcard 'phi:a*' does NOT satisfy requireScope 'phi:admin'",
          denied !== null && /breakglass\/missing-scope/.test(denied.code || ""));

    // A proper segment wildcard "phi:*" DOES satisfy it (legit wildcard preserved).
    var okWild = await grantWithScopes("user-wild", ["phi:*"]);
    check("break-glass: segment wildcard 'phi:*' satisfies requireScope 'phi:admin'",
          okWild && typeof okWild.id === "string");

    // The exact scope satisfies it.
    var okExact = await grantWithScopes("user-exact", ["phi:admin"]);
    check("break-glass: exact scope satisfies requireScope",
          okExact && typeof okExact.id === "string");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — refused paths ----

async function testGrantRefusalPaths() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      reasonMinLength: 12,
    });

    function reject(label, opts, codeRe) {
      return b.breakGlass.grant(opts).then(
        function () { check("grant.refusal: " + label + " (should throw)", false); },
        function (e) { check("grant.refusal: " + label, codeRe.test(e.code || "")); }
      );
    }
    var totp = _validTotp();

    await reject("policy-not-set",
      { req: _fakeReq(), table: "no-such-table", reason: "x".repeat(12),
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/policy-not-set/);

    await reject("missing-reason",
      { req: _fakeReq(), table: "patients", reason: "",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/missing-reason/);

    await reject("short-reason",
      { req: _fakeReq(), table: "patients", reason: "short",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/short-reason/);

    await reject("grant-column-mismatch",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        columns: ["nonexistent-column"],
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/grant-column-mismatch/);

    await reject("bad-factor (wrong code)",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: "000000", secret: totp.secret } },
      /breakglass\/bad-factor/);

    await reject("unauthorized (no actor on req)",
      { req: { socket: { remoteAddress: "127.0.0.1" }, headers: {} },
        table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/unauthorized/);

    await reject("bad factor type",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "magic-link" } },
      /breakglass\/bad-factor/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — concurrent TOTP replay (atomic step reservation) ----

async function testConcurrentTotpGrantReplay() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
    });
    var totp = _validTotp();
    var req  = _fakeReq();   // one req → one actor → one (actor, secret) replay key
    function grantOpts() {
      return {
        req:    req,
        table:  "patients",
        reason: "concurrent replay regression test",
        factor: { type: "totp", code: totp.code, secret: totp.secret },
      };
    }
    // Two grants in flight at once presenting the SAME in-window code. The
    // accepted TOTP step is reserved atomically as part of acceptance, so
    // exactly one grant succeeds and the other is refused as a replay — a
    // read-then-commit floor let both observe the old floor and both pass.
    var results = await Promise.allSettled([
      b.breakGlass.grant(grantOpts()),
      b.breakGlass.grant(grantOpts()),
    ]);
    var ok  = results.filter(function (r) { return r.status === "fulfilled"; });
    var bad = results.filter(function (r) { return r.status === "rejected"; });
    check("concurrent totp grant: exactly one grant succeeds", ok.length === 1);
    check("concurrent totp grant: the other is refused as a replay",
          bad.length === 1 &&
          /breakglass\/bad-factor/.test((bad[0].reason && bad[0].reason.code) || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant + unseal — full lifecycle on a real sealed table ----

async function testUnsealRowLifecycle() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    // Use _blamejs_jobs as the test target: payload is sealed by
    // cryptoField.sealRow per FRAMEWORK_SCHEMA.
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("test-q", { secret: "alice's diagnosis" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 3,   // raise from default-1 so we can test exhaustion + a normal read
    });

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "diagnostic spot-check on queue payloads",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: maxRowsPerGrant honored from policy", grant.rowsRemaining === 3);

    // Use grant once. Default policy pins IP + session, so redemption
    // threads the same request shape the grant was minted from.
    var unsealed = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() });
    check("unsealRow: returns the row",                 unsealed && unsealed._id === jid.jobId);
    check("unsealRow: payload column is decrypted",
          unsealed.payload && unsealed.payload.indexOf("alice") !== -1);

    // listActive shows 2 remaining
    var active = await b.breakGlass.listActive({ req: _fakeReq() });
    check("listActive: 1 grant",                        active.length === 1);
    check("listActive: rowsRemaining decremented",      active[0].rowsRemaining === 2);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Exhaustion ----

async function testGrantExhaustion() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("ex-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 1,    // strict default
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() });

    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() }); }
    catch (e) { threw = e; }
    check("exhaustion: second use of 1-row grant rejects",
          threw && /breakglass\/grant-exhausted/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Concurrent unsealRow — a 1-row grant must not double-claim ----

async function testConcurrentUnsealRowDoubleClaim() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // Two distinct rows in the glass-locked table.
    var j1 = await b.queue.enqueue("bg-dc-q", { secret: "row-one-secret" });
    var j2 = await b.queue.enqueue("bg-dc-q", { secret: "row-two-secret" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 1,   // row-by-row auth: ONE PHI read per grant
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "concurrent double-claim regression on a 1-row grant",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });

    // Two concurrent redemptions of the SAME 1-row grant against DIFFERENT
    // rows. The claim is an atomic compare-and-increment; exactly ONE caller
    // may win the single row slot. The loser must be refused as exhausted —
    // inferring the claim from a re-read of rowsConsumed (a concurrent
    // winner's increment is visible to the loser) let BOTH pass, unsealing two
    // rows under a maxRowsPerGrant:1 grant and defeating row-by-row auth.
    var results = await Promise.allSettled([
      b.breakGlass.unsealRow(grant, "_blamejs_jobs", j1.jobId, { req: _fakeReq() }),
      b.breakGlass.unsealRow(grant, "_blamejs_jobs", j2.jobId, { req: _fakeReq() }),
    ]);
    var ok  = results.filter(function (r) { return r.status === "fulfilled"; });
    var bad = results.filter(function (r) { return r.status === "rejected"; });
    check("concurrent unsealRow: exactly one row unsealed under a 1-row grant",
          ok.length === 1);
    check("concurrent unsealRow: the losing read is refused as exhausted",
          bad.length === 1 &&
          /breakglass\/grant-exhausted/.test((bad[0].reason && bad[0].reason.code) || ""));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Revoke ----

async function testGrantRevoke() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("rv-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.revoke(grant.id, { reason: "task complete" });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() }); }
    catch (e) { threw = e; }
    check("revoke: unseal after revoke rejects",
          threw && /breakglass\/grant-revoked/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Table mismatch ----

async function testTableMismatch() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["totp"] });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "investigating ticket #12345 for compliance review",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "doctors", "doc-1"); }
    catch (e) { threw = e; }
    check("table-mismatch: unseal on wrong table rejects",
          threw && /breakglass\/grant-table-mismatch/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Sweep ----

async function testSweepExpiredGrants() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"],
      grantTtl: 10,    // 10 ms — guaranteed expired by sweep time
    });
    var totp = _validTotp();
    await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "soak-test with 10ms ttl for sweep coverage",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    // 10ms-TTL grant must expire before the sweep can collect it.
    // Poll the sweep until it reports >= 1 expired grant.
    var swept = await helpers.waitUntil(async function () {
      var rv = await b.breakGlass._sweepExpiredForTest();
      return rv.expired >= 1 ? rv : false;
    }, { label: "break-glass.sweep: 10ms TTL grant expired + collected" });
    check("sweep: marks expired grants revoked", swept.expired >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant binding enforcement: IP pin / session pin / fail-closed ----

async function testIpPinEnforcement() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("ip-pin-q", { secret: "row-ip-pin" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
      pinIp: true, sessionPin: false,   // isolate the IP pin
    });
    var totp = _validTotp();
    // Mint from IP-A.
    var grant = await b.breakGlass.grant({
      req:    _fakeReq({ socket: { remoteAddress: "10.0.0.1" } }),
      table:  "_blamejs_jobs",
      reason: "ip-pin: minting from address A for redemption test",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });

    // Redeem from IP-B → refused on the operator unsealRow consumer.
    var threwUnseal = null;
    try {
      await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
        { req: _fakeReq({ socket: { remoteAddress: "10.0.0.2" } }) });
    } catch (e) { threwUnseal = e; }
    check("ip-pin: IP-B redeem refused (unsealRow)",
          threwUnseal && /breakglass\/grant-ip-mismatch/.test(threwUnseal.code));

    // The mismatch must NOT have consumed the grant — same-IP redeem still
    // succeeds afterward.
    var ok = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
      { req: _fakeReq({ socket: { remoteAddress: "10.0.0.1" } }) });
    check("ip-pin: same-IP redeem succeeds (mismatch did not consume)",
          ok && ok.payload && ok.payload.indexOf("row-ip-pin") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testIpPinPeerGated() {
  // With trustedProxies, the grant IP pins to the real client behind the
  // proxy — and a direct attacker forging X-Forwarded-For cannot satisfy it.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init({ trustedProxies: ["10.0.0.0/8"] });
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("ip-pin-pg-q", { secret: "row-ip-pin-pg" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
      pinIp: true, sessionPin: false,
    });
    var totp = _validTotp();
    // Mint behind the trusted proxy: peer 10.0.0.9 trusted → pin to the
    // forwarded client 203.0.113.7, NOT the proxy address.
    var grant = await b.breakGlass.grant({
      req:    _fakeReq({ socket: { remoteAddress: "10.0.0.9" }, headers: { "x-forwarded-for": "203.0.113.7" } }),
      table:  "_blamejs_jobs",
      reason: "ip-pin peer-gated: minting behind trusted proxy for the real client",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });

    // Direct attacker forging the client IP via XFF (untrusted peer) → refused.
    var threwSpoof = null;
    try {
      await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
        { req: _fakeReq({ socket: { remoteAddress: "198.51.100.66" }, headers: { "x-forwarded-for": "203.0.113.7" } }) });
    } catch (e) { threwSpoof = e; }
    check("ip-pin peer-gated: forged XFF redeem refused",
          threwSpoof && /breakglass\/grant-ip-mismatch/.test(threwSpoof.code));

    // Legitimate redeem through the proxy → succeeds (resolves to 203.0.113.7).
    var ok = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
      { req: _fakeReq({ socket: { remoteAddress: "10.0.0.9" }, headers: { "x-forwarded-for": "203.0.113.7" } }) });
    check("ip-pin peer-gated: proxied redeem of real client succeeds",
          ok && ok.payload && ok.payload.indexOf("row-ip-pin-pg") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionPinEnforcement() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("sess-pin-q", { secret: "row-sess-pin" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
      pinIp: false, sessionPin: true,   // isolate the session pin
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq({ session: { id: "sess-A" } }),
      table:  "_blamejs_jobs",
      reason: "session-pin: minting under session A for redemption test",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });

    var threw = null;
    try {
      await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
        { req: _fakeReq({ session: { id: "sess-B" } }) });
    } catch (e) { threw = e; }
    check("session-pin: different session redeem refused",
          threw && /breakglass\/grant-session-mismatch/.test(threw.code));

    var ok = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
      { req: _fakeReq({ session: { id: "sess-A" } }) });
    check("session-pin: same-session redeem succeeds",
          ok && ok.payload && ok.payload.indexOf("row-sess-pin") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testIpPinFailClosedOnNullBinding() {
  // An Express-shaped req exposes only `req.ip` (no socket.remoteAddress).
  // When pinIp is on and the binding could not be captured at mint, the
  // redemption must FAIL-CLOSED rather than silently skip enforcement.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("fc-q", { secret: "row-fc" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
      pinIp: true, sessionPin: false,
    });
    // Force a NULL ip binding at mint: a request with no socket AND no
    // req.ip, so clientIp resolves null even with the req.ip fallback.
    var noIpReq = {
      user:    { id: "user-test-1" },
      headers: { "user-agent": "test-agent" },
      method:  "POST",
      url:     "/admin/break-glass",
    };
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    noIpReq,
      table:  "_blamejs_jobs",
      reason: "fail-closed: minting with no resolvable client IP",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });

    var threw = null;
    try {
      await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
        { req: _fakeReq({ socket: { remoteAddress: "10.0.0.9" } }) });
    } catch (e) { threw = e; }
    check("ip-pin fail-closed: null binding refuses redemption",
          threw && /breakglass\/grant-ip-mismatch/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testTotpReplayDefense() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], maxRowsPerGrant: 5,
    });
    // Pin a deterministic clock so both grant attempts land on the same
    // TOTP step — the replay window.
    var fixedNow = 1_700_000_000_000;
    var secret = b.auth.totp.generateSecret();
    var code = b.auth.totp.generate(secret, { now: fixedNow });

    var g1 = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "totp-replay: first redemption of the code",
      factor: { type: "totp", secret: secret, code: code, now: fixedNow },
    });
    check("totp-replay: first grant succeeds", typeof g1.id === "string");

    // Same code + same clock = same step → must be rejected as a replay.
    var threw = null;
    try {
      await b.breakGlass.grant({
        req:    _fakeReq(),
        table:  "patients",
        reason: "totp-replay: second use of the SAME code must fail",
        factor: { type: "totp", secret: secret, code: code, now: fixedNow },
      });
    } catch (e) { threw = e; }
    check("totp-replay: re-using the same code in-window refused",
          threw && /breakglass\/bad-factor/.test(threw.code));

    // A DIFFERENT credential accepting a code at the same step still
    // succeeds — proves the replay floor is keyed by secret fingerprint,
    // not actorId alone.
    var secret2 = b.auth.totp.generateSecret();
    var code2 = b.auth.totp.generate(secret2, { now: fixedNow });
    var g2 = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "totp-replay: distinct credential same window still works",
      factor: { type: "totp", secret: secret2, code: code2, now: fixedNow },
    });
    check("totp-replay: distinct credential at same step still succeeds",
          typeof g2.id === "string" && g2.id !== g1.id);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- v0.5.1: Cryptographic mode (Model B) ----

async function testEncryptDecryptCellHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns:       ["ssn"],
      factors:       ["totp"],
      cryptographic: true,
      maxRowsPerGrant: 5,
    });
    var ct = await b.breakGlass.encryptCell("123-45-6789",
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("encryptCell: returns bgcell:1: prefix", typeof ct === "string" && ct.indexOf("bgcell:1:") === 0);
    var pt = await b.breakGlass.decryptCell(ct,
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("decryptCell: round-trip recovers plaintext", pt === "123-45-6789");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptionContextBinding() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });
    var ct = await b.breakGlass.encryptCell("123-45-6789",
      { table: "patients", rowId: "p-42", column: "ssn" });

    // Wrong rowId — decrypt must fail
    var threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "patients", rowId: "p-43", column: "ssn" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong rowId fails decrypt", threw !== null);

    // Wrong column — fails
    threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "patients", rowId: "p-42", column: "diagnosis" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong column fails decrypt", threw !== null);

    // Wrong table — fails
    threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "doctors", rowId: "p-42", column: "ssn" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong table fails decrypt", threw !== null);

    // Correct context — works
    var pt = await b.breakGlass.decryptCell(ct,
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("aad-binding: correct context decrypts", pt === "123-45-6789");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptCellRequiresCryptographicPolicy() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: false,
    });
    var threw = null;
    try {
      await b.breakGlass.encryptCell("x", { table: "patients", rowId: "1", column: "ssn" });
    } catch (e) { threw = e; }
    check("encryptCell: rejects Model A policy",
          threw && /breakglass\/policy-not-set/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptCellRejectsBadColumn() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });
    var threw = null;
    try {
      await b.breakGlass.encryptCell("x", { table: "patients", rowId: "1", column: "phone" });
    } catch (e) { threw = e; }
    check("encryptCell: rejects non-glass-locked column",
          threw && /breakglass\/grant-column-mismatch/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCryptographicUnsealRow() {
  // End-to-end Model B: write a Model-B-shaped row directly, issue
  // grant, unseal, verify cell decrypted via decryptCell with proper
  // context binding.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("crypto-q", { sentinel: "outer-payload" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      cryptographic:   true,
      maxRowsPerGrant: 3,
    });

    // Write a cryptographic-mode payload directly into the row.
    var bgPayload = await b.breakGlass.encryptCell("alice's diagnosis (Model B)",
      { table: "_blamejs_jobs", rowId: jid.jobId, column: "payload" });
    await b.clusterStorage.execute(
      "UPDATE _blamejs_jobs SET payload = ? WHERE _id = ?",
      [bgPayload, jid.jobId]
    );

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "Model B integration test for cryptographic unseal",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var row = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() });
    check("Model B unsealRow: decrypts cryptographic cell",
          row.payload === "alice's diagnosis (Model B)");

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMigrateModelAtoModelB() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // Enqueue 3 jobs in Model A (vault-sealed payload).
    var j1 = await b.queue.enqueue("mig-q", { secret: "row-1-secret" });
    var j2 = await b.queue.enqueue("mig-q", { secret: "row-2-secret" });
    var j3 = await b.queue.enqueue("mig-q", { secret: "row-3-secret" });

    // Set cryptographic policy + run migrate.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], cryptographic: true,
      maxRowsPerGrant: 5,
    });
    var result = await b.breakGlass.migrate("_blamejs_jobs", { batchSize: 10 });
    check("migrate: returns total + migrated counts",
          result.totalRows >= 3 && result.migratedRows >= 3);

    // Idempotent — second run skips already-migrated rows.
    var result2 = await b.breakGlass.migrate("_blamejs_jobs", { batchSize: 10 });
    check("migrate: second run is idempotent",
          result2.skippedRows >= result2.migratedRows);

    // Read via grant — confirms the migrated rows decrypt.
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "post-migration verification of payload decrypt path",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var row = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", j1.jobId, { req: _fakeReq() });
    check("migrate: row-1 reads as cryptographic-mode plaintext",
          row.payload && row.payload.indexOf("row-1-secret") !== -1);
    void j2; void j3;

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- v0.5.2: passkey factor + service-account bypass + admin tools ----

function testV052Surface() {
  check("breakGlass.unsealRowAsService is fn",  typeof b.breakGlass.unsealRowAsService === "function");
  check("breakGlass.listActiveAll is fn",       typeof b.breakGlass.listActiveAll === "function");
  check("breakGlass.revokeAll is fn",           typeof b.breakGlass.revokeAll === "function");
}

async function testPasskeyAcceptedInPolicy() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["passkey"],
    });
    var p = await b.breakGlass.policy.get("patients");
    check("passkey factor accepted in policy",   p && p.factors[0] === "passkey");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPasskeyFactorPath() {
  // We don't have a real WebAuthn fixture handy; verify the factor
  // dispatch + rejection of malformed assertions.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["passkey"],
    });
    var threw = null;
    try {
      await b.breakGlass.grant({
        req:    _fakeReq(),
        table:  "patients",
        reason: "investigating ticket #12345 for compliance review",
        factor: { type: "passkey" /* missing all the fields */ },
      });
    } catch (e) { threw = e; }
    check("passkey: malformed assertion rejected as bad-factor",
          threw && /breakglass\/bad-factor/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassPolicyValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, sab, codeRe) {
      return b.breakGlass.policy.set("t", {
        columns: ["x"], factors: ["totp"],
        serviceAccountBypass: sab,
      }).then(
        function () { check("sab.validate: " + label + " (should throw)", false); },
        function (e) { check("sab.validate: " + label, codeRe.test(e.code || "")); }
      );
    }
    await reject("rejects non-object",    "yes",                            /breakglass\/bad-policy/);
    await reject("rejects enabled false", { enabled: false, apiKeyIds: ["x"], requireRole: "y" }, /breakglass\/bad-policy/);
    await reject("rejects empty apiKeyIds", { enabled: true, apiKeyIds: [], requireRole: "y" }, /breakglass\/bad-policy/);
    await reject("rejects missing requireRole", { enabled: true, apiKeyIds: ["x"] }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("svc-q", { secret: "row-payload-svc" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
      serviceAccountBypass: {
        enabled:     true,
        apiKeyIds:   ["ak-svc-deidentify-job"],
        requireRole: "service:phi-reader",
      },
    });
    var serviceReq = {
      apiKey: {
        id:     "ak-svc-deidentify-job",
        scopes: ["service:phi-reader"],
      },
      socket:  { remoteAddress: "10.0.0.1" },
      headers: { "user-agent": "blamejs-svc" },
      method:  "GET",
      url:     "/cron/deid",
    };
    var row = await b.breakGlass.unsealRowAsService(serviceReq, "_blamejs_jobs", jid.jobId,
      { reason: "nightly de-identification run" });
    check("bypass: returns the row",
          row && typeof row.payload === "string" && row.payload.indexOf("row-payload-svc") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassRefusalPaths() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("svc-deny-q", { secret: "x" });

    // Policy WITHOUT serviceAccountBypass — bypass path must refuse.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
    });
    var threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-x", scopes: [] } }, "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses when not configured",
          threw && /breakglass\/bypass-not-configured/.test(threw.code));

    // Now with bypass configured but apiKey not in allowlist
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
      serviceAccountBypass: {
        enabled: true, apiKeyIds: ["ak-allowed"], requireRole: "service:reader",
      },
    });
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-other", scopes: ["service:reader"] } },
        "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses unknown apiKey id",
          threw && /breakglass\/bypass-unauthorized/.test(threw.code));

    // apiKey in allowlist but missing role
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-allowed", scopes: ["service:other"] } },
        "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses without required role",
          threw && /breakglass\/bypass-unauthorized/.test(threw.code));

    // No req.apiKey at all
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(_fakeReq(), "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses when req has no apiKey",
          threw && /breakglass\/bypass-no-apikey/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testListActiveAllAndRevokeAll() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("t1", { columns: ["c"], factors: ["totp"], maxRowsPerGrant: 3 });
    await b.breakGlass.policy.set("t2", { columns: ["c"], factors: ["totp"], maxRowsPerGrant: 3 });

    var totp = _validTotp();
    var g1 = await b.breakGlass.grant({
      req: _fakeReq(), table: "t1",
      reason: "compliance review per ticket #1",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var totp2 = _validTotp();
    var g2 = await b.breakGlass.grant({
      req: _fakeReq(), table: "t2",
      reason: "compliance review per ticket #2",
      factor: { type: "totp", code: totp2.code, secret: totp2.secret },
    });
    void g1; void g2;

    var all = await b.breakGlass.listActiveAll();
    check("listActiveAll: returns both grants",  all.length === 2);

    var t1Only = await b.breakGlass.listActiveAll({ table: "t1" });
    check("listActiveAll: filters by table",     t1Only.length === 1 && t1Only[0].scopeTable === "t1");

    // revokeAll requires actor or table scope
    var threw = null;
    try { await b.breakGlass.revokeAll({}); } catch (e) { threw = e; }
    check("revokeAll: refuses unbounded",
          threw && /breakglass\/bad-revoke-criteria/.test(threw.code));

    var result = await b.breakGlass.revokeAll({ table: "t1", reason: "ir-test" });
    check("revokeAll: reports revokedCount",     result && result.revokedCount === 1);

    var afterRevoke = await b.breakGlass.listActiveAll();
    check("revokeAll: t1 grant gone",             afterRevoke.length === 1 && afterRevoke[0].scopeTable === "t2");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Not-initialized guard — every primitive fails closed before init() ----

async function testRequireInitGuards() {
  // Every public entry point calls _requireInit() first. After a reset
  // (no init), each must throw breakglass/not-initialized — the fail-closed
  // guard that keeps an un-wired framework from minting grants or unsealing
  // PHI. No DB needed: the guard is the first statement in each function.
  b.breakGlass._resetForTest();
  var re = /breakglass\/not-initialized/;
  async function guard(label, fn) {
    var threw = null;
    try { await fn(); } catch (e) { threw = e; }
    check("require-init: " + label + " throws not-initialized",
          threw && re.test(threw.code || ""));
  }
  await guard("policy.get",     function () { return b.breakGlass.policy.get("t"); });
  await guard("policy.set",     function () { return b.breakGlass.policy.set("t", { columns: ["c"], factors: ["totp"] }); });
  await guard("policy.list",    function () { return b.breakGlass.policy.list(); });
  await guard("policy.delete",  function () { return b.breakGlass.policy.delete("t"); });
  await guard("grant",          function () { return b.breakGlass.grant({ req: _fakeReq(), table: "t", reason: "x", factor: {} }); });
  await guard("unsealRow",      function () { return b.breakGlass.unsealRow({ id: "bg-x" }, "t", "1"); });
  await guard("revoke",         function () { return b.breakGlass.revoke("bg-x"); });
  await guard("listActive",     function () { return b.breakGlass.listActive({ req: _fakeReq() }); });
  await guard("listActiveAll",  function () { return b.breakGlass.listActiveAll(); });
  await guard("revokeAll",      function () { return b.breakGlass.revokeAll({ table: "t" }); });
  await guard("encryptCell",    function () { return b.breakGlass.encryptCell("x", { table: "t", rowId: "1", column: "c" }); });
  await guard("decryptCell",    function () { return b.breakGlass.decryptCell("bgcell:1:AAAA", { table: "t", rowId: "1", column: "c" }); });
  await guard("migrate",        function () { return b.breakGlass.migrate("t"); });
  await guard("unsealRowAsService", function () { return b.breakGlass.unsealRowAsService(_fakeReq(), "t", "1"); });
}

// ---- Adversarial policy.set validation (identifier shape / opts shape) ----

async function testPolicyValidationAdversarial() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, table, opts, codeRe) {
      return b.breakGlass.policy.set(table, opts).then(
        function () { check("policy.validate.adv: " + label + " (should throw)", false); },
        function (e) { check("policy.validate.adv: " + label, codeRe.test(e.code || "")); }
      );
    }
    // opts entirely absent → "opts is required" (distinct from the missing-field
    // branches the happy-path validation test already covers).
    await reject("null opts rejected", "t", null, /breakglass\/bad-policy/);
    // Table name that is not a safe SQL identifier — it flows into migrate() /
    // unsealRowAsService() SQL, so a name with an embedded quote must be refused.
    await reject("table with embedded quote rejected", 'pa"tients',
      { columns: ["ssn"], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("table with space rejected", "pat ients",
      { columns: ["ssn"], factors: ["totp"] }, /breakglass\/bad-policy/);
    // Column entries: non-string / empty / bad-identifier shape.
    await reject("non-string column rejected", "t",
      { columns: [123], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("empty-string column rejected", "t",
      { columns: [""], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("column with embedded quote rejected", "t",
      { columns: ['ss"n'], factors: ["totp"] }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Adversarial encrypt/decrypt/migrate/revoke/policy-delete inputs ----

async function testCellAndAdminInputValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });

    async function rejects(label, fn, codeRe) {
      var threw = null;
      try { await fn(); } catch (e) { threw = e; }
      check("input.validate: " + label, threw && codeRe.test(threw.code || ""));
    }

    // encryptCell bad ctx (missing / wrong-typed fields)
    await rejects("encryptCell null ctx",
      function () { return b.breakGlass.encryptCell("x", null); }, /breakglass\/bad-cell-ctx/);
    await rejects("encryptCell ctx missing rowId",
      function () { return b.breakGlass.encryptCell("x", { table: "patients", column: "ssn" }); }, /breakglass\/bad-cell-ctx/);

    // decryptCell — bad ciphertext format, then bad ctx
    await rejects("decryptCell non-bgcell format",
      function () { return b.breakGlass.decryptCell("not-a-cell", { table: "patients", rowId: "1", column: "ssn" }); },
      /breakglass\/bad-ciphertext/);
    await rejects("decryptCell null ctx",
      function () { return b.breakGlass.decryptCell("bgcell:1:AAAA", null); }, /breakglass\/bad-cell-ctx/);

    // migrate — no policy, then non-cryptographic policy
    await rejects("migrate no policy",
      function () { return b.breakGlass.migrate("no-such-glass-table"); }, /breakglass\/policy-not-set/);
    await b.breakGlass.policy.set("plain", { columns: ["ssn"], factors: ["totp"] });   // Model A
    await rejects("migrate on Model-A policy refused",
      function () { return b.breakGlass.migrate("plain"); }, /breakglass\/bad-policy/);

    // revoke — empty grantId
    await rejects("revoke empty grantId",
      function () { return b.breakGlass.revoke(""); }, /breakglass\/bad-grant-opts/);

    // policy.delete — empty table
    await rejects("policy.delete empty table",
      function () { return b.breakGlass.policy.delete(""); }, /breakglass\/bad-policy/);

    // revokeAll — non-object criteria (distinct from the empty-criteria branch)
    await rejects("revokeAll null criteria",
      function () { return b.breakGlass.revokeAll(null); }, /breakglass\/bad-revoke-criteria/);

    // grant — no opts object
    await rejects("grant no opts",
      function () { return b.breakGlass.grant(); }, /breakglass\/bad-grant-opts/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Migrate on an empty policy'd table (paging break on first page) ----

async function testMigrateEmptyTable() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });   // creates _blamejs_jobs, no rows
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], cryptographic: true,
    });
    // No jobs enqueued → the first keyset page is empty → the loop breaks
    // immediately with zero rows and emits the completion audit.
    var summary = await b.breakGlass.migrate("_blamejs_jobs", { batchSize: 25 });
    check("migrate empty: totalRows 0",    summary.totalRows === 0);
    check("migrate empty: migratedRows 0", summary.migratedRows === 0);
    check("migrate empty: table echoed",   summary.table === "_blamejs_jobs");
    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- DEK survives an in-memory cache reset (re-unseal from the policy row) ----

async function testDekReUnsealFromPolicyRow() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });
    // First use generates + vault-seals the DEK into the policy row and
    // caches it in-process.
    var ct = await b.breakGlass.encryptCell("123-45-6789",
      { table: "patients", rowId: "p-1", column: "ssn" });
    // Reset drops the in-memory DEK cache but leaves the sealed DEK in the DB.
    // Re-init, then decrypt: _ensureDek must re-unseal the stored DEK (the
    // `sealed` branch) rather than mint a fresh one, or the round-trip breaks.
    b.breakGlass._resetForTest();
    b.breakGlass.init();
    var pt = await b.breakGlass.decryptCell(ct,
      { table: "patients", rowId: "p-1", column: "ssn" });
    check("dek-reuse: sealed DEK re-unseals after cache reset", pt === "123-45-6789");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- unsealRow argument-shape guards + not-found grant ----

async function testUnsealRowArgGuards() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    async function rejects(label, fn, codeRe) {
      var threw = null;
      try { await fn(); } catch (e) { threw = e; }
      check("unsealRow.guard: " + label, threw && codeRe.test(threw.code || ""));
    }
    await rejects("null grant handle",
      function () { return b.breakGlass.unsealRow(null, "t", "1"); }, /breakglass\/bad-grant-opts/);
    await rejects("handle without id",
      function () { return b.breakGlass.unsealRow({}, "t", "1"); }, /breakglass\/bad-grant-opts/);
    await rejects("empty table",
      function () { return b.breakGlass.unsealRow({ id: "bg-x" }, "", "1"); }, /breakglass\/bad-grant-opts/);
    await rejects("missing rowId",
      function () { return b.breakGlass.unsealRow({ id: "bg-x" }, "t", null); }, /breakglass\/bad-grant-opts/);
    await rejects("empty rowId",
      function () { return b.breakGlass.unsealRow({ id: "bg-x" }, "t", ""); }, /breakglass\/bad-grant-opts/);
    // A well-shaped handle whose id doesn't exist in the grants table reads
    // as revoked/never-issued (fail-closed).
    await rejects("unknown grant id reads as revoked",
      function () { return b.breakGlass.unsealRow({ id: "bg-does-not-exist" }, "t", "1"); },
      /breakglass\/grant-revoked/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- unsealRow: expired grant + row-not-found ----

async function testUnsealRowExpiredAndRowNotFound() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("bg-exp-q", { secret: "row-exp" });

    // Expired-grant path: a short-TTL grant whose expiry check trips before
    // any row read.
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], grantTtl: 20,
    });
    var totpA = _validTotp();
    var expiring = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "expired-grant coverage: short ttl grant",
      factor: { type: "totp", code: totpA.code, secret: totpA.secret },
    });
    await helpers.waitUntil(function () { return Date.now() > expiring.expiresAt; },
      { label: "break-glass.unsealRow: 20ms grant reaches expiry" });
    var threwExpired = null;
    try { await b.breakGlass.unsealRow(expiring, "patients", "any-row", { req: _fakeReq() }); }
    catch (e) { threwExpired = e; }
    check("unsealRow: expired grant refused",
          threwExpired && /breakglass\/grant-expired/.test(threwExpired.code));

    // Row-not-found path: a valid, live grant against a real table but a
    // rowId that isn't present. The grant is NOT consumed (SELECT-before-
    // increment ordering), so the error is row-not-found, not exhausted.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 3,
    });
    var totpB = _validTotp();
    var liveGrant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "row-not-found coverage: live grant on real table",
      factor: { type: "totp", code: totpB.code, secret: totpB.secret },
    });
    var threwMissing = null;
    try { await b.breakGlass.unsealRow(liveGrant, "_blamejs_jobs", "no-such-row-id", { req: _fakeReq() }); }
    catch (e) { threwMissing = e; }
    check("unsealRow: missing row refused with row-not-found",
          threwMissing && /breakglass\/row-not-found/.test(threwMissing.code));
    // The failed lookup did not consume the grant — a real row still reads.
    var ok = await b.breakGlass.unsealRow(liveGrant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() });
    check("unsealRow: row-not-found did not consume the grant",
          ok && ok.payload && ok.payload.indexOf("row-exp") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- unsealRow Model B: a corrupt / wrong-context cell fails closed ----

async function testUnsealRowCellDecryptFailed() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("bg-cd-q", { secret: "outer" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], cryptographic: true, maxRowsPerGrant: 3,
    });
    // Write a ciphertext encrypted for a DIFFERENT rowId into this row. The
    // AAD is bound to (table, rowId, column), so decrypting under the real
    // rowId fails the AEAD verify — unsealRow must surface cell-decrypt-failed
    // rather than return garbage or leak the wrong row's value.
    var wrongCtx = await b.breakGlass.encryptCell("someone-elses-ssn",
      { table: "_blamejs_jobs", rowId: "a-different-row", column: "payload" });
    await b.clusterStorage.execute(
      "UPDATE _blamejs_jobs SET payload = ? WHERE _id = ?", [wrongCtx, jid.jobId]);

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "cell-decrypt-failed coverage: swapped ciphertext",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId, { req: _fakeReq() }); }
    catch (e) { threw = e; }
    check("unsealRow Model B: wrong-context cell fails closed",
          threw && /breakglass\/cell-decrypt-failed/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- _enforceGrantPins: session pin with a null binding fails closed ----

async function testSessionPinFailClosedOnNullBinding() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("bg-sess-fc-q", { secret: "row-sess-fc" });
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
      pinIp: false, sessionPin: true,
    });
    // Mint from a request carrying NO session id → grantRow.sessionId is null.
    // With sessionPin on, redemption must refuse rather than skip the pin.
    var noSessReq = {
      user:    { id: "user-test-1" },
      socket:  { remoteAddress: "127.0.0.1" },
      headers: { "user-agent": "test-agent" },
      method:  "POST",
      url:     "/admin/break-glass",
    };
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    noSessReq,
      table:  "_blamejs_jobs",
      reason: "session-pin fail-closed: minting with no session id",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var threw = null;
    try {
      await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId,
        { req: _fakeReq({ session: { id: "sess-anything" } }) });
    } catch (e) { threw = e; }
    check("session-pin fail-closed: null binding refuses redemption",
          threw && /breakglass\/grant-session-mismatch/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- grant: factor lockout after repeated failures ----

async function testGrantFactorLockout() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["totp"] });
    var totp = _validTotp();
    var badCode = totp.code === "000000" ? "000001" : "000000";
    function attempt(reason) {
      return b.breakGlass.grant({
        req:    _fakeReq(),
        table:  "patients",
        reason: reason,
        factor: { type: "totp", secret: totp.secret, code: badCode },
      });
    }
    // Five failing factor verifications trip the lockout primitive
    // (maxAttempts 5). Each of the five is a plain bad-factor rejection.
    for (var i = 0; i < 5; i++) {
      var threw = null;
      try { await attempt("lockout coverage: failing attempt " + (i + 1)); }
      catch (e) { threw = e; }
      check("lockout: attempt " + (i + 1) + " rejected",
            threw && /breakglass\/(bad-factor|factor-rate-limited)/.test(threw.code || ""));
    }
    // The sixth attempt is refused at the lockout gate BEFORE factor
    // verification — a brute-forcer is shut out.
    var locked = null;
    try { await attempt("lockout coverage: should be rate-limited"); }
    catch (e) { locked = e; }
    check("lockout: sixth attempt refused as factor-rate-limited",
          locked && /breakglass\/factor-rate-limited/.test(locked.code || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- grant: requireScope satisfied via req.apiKey.scopes fallback ----

async function testGrantScopeViaApiKey() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], requireScope: "phi:admin",
    });
    // No req.user — the actor is an apiKey. Both the actorId resolution and
    // the requireScope check must fall back to req.apiKey (id + scopes).
    var totp = _validTotp();
    var apiKeyReq = {
      apiKey:  { id: "ak-phi-admin", scopes: ["phi:admin"] },
      session: { id: "sess-svc-1" },
      socket:  { remoteAddress: "127.0.0.1" },
      headers: { "user-agent": "svc-agent" },
      method:  "POST",
      url:     "/admin/break-glass",
    };
    var grant = await b.breakGlass.grant({
      req:    apiKeyReq,
      table:  "patients",
      reason: "apikey-scope coverage: service actor with phi:admin scope",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("apikey-scope: grant minted for apiKey actor carrying required scope",
          grant && typeof grant.id === "string");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- grant: TOTP factor missing secret / missing code ----

async function testGrantTotpFactorShapeRejections() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["totp"] });
    async function rejects(label, factor) {
      var threw = null;
      try {
        await b.breakGlass.grant({
          req:    _fakeReq(),
          table:  "patients",
          reason: "totp factor-shape coverage: " + label,
          factor: factor,
        });
      } catch (e) { threw = e; }
      check("totp-shape: " + label, threw && /breakglass\/bad-factor/.test(threw.code || ""));
    }
    // factor.type is "totp" (accepted), but the credential material is
    // incomplete — _verifyTotpFactor returns ok:false and grant refuses.
    await rejects("missing secret", { type: "totp", code: "123456" });
    await rejects("missing code",   { type: "totp", secret: "AAAAAAAAAAAAAAAA" });
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- grant: audit reason stored as HMAC (not cleartext) ----

async function testGrantAuditReasonHmac() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], auditReasonStorage: "hmac",
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "hmac-audit coverage: reason should hash, not store cleartext",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    // The grant still mints; the branch under test is the audit-reason
    // derivation (hmac mode → cleartext suppressed, hmac digest emitted).
    check("audit-reason hmac: grant minted with hmac reason storage",
          grant && typeof grant.id === "string");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- unsealRowAsService: input guards + Model B decrypt + roles fallback ----

async function testUnsealRowAsServiceGuardsAndModelB() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("bg-svc-b-q", { secret: "outer" });

    async function rejects(label, fn, codeRe) {
      var threw = null;
      try { await fn(); } catch (e) { threw = e; }
      check("svc.guard: " + label, threw && codeRe.test(threw.code || ""));
    }
    // Argument-shape + no-policy guards (before any bypass check).
    await rejects("null req",
      function () { return b.breakGlass.unsealRowAsService(null, "_blamejs_jobs", "1"); },
      /breakglass\/bad-grant-opts/);
    await rejects("empty table",
      function () { return b.breakGlass.unsealRowAsService({ apiKey: { id: "ak" } }, "", "1"); },
      /breakglass\/bad-grant-opts/);
    await rejects("no policy for table",
      function () { return b.breakGlass.unsealRowAsService({ apiKey: { id: "ak" } }, "no-policy-table", "1"); },
      /breakglass\/policy-not-set/);

    // Cryptographic-mode service bypass whose apiKey authorizes via `roles`
    // (not `scopes`) — the role-check fallback. The Model B cell decrypts
    // through the same encryption-context binding as the operator path.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], cryptographic: true,
      serviceAccountBypass: {
        enabled: true, apiKeyIds: ["ak-svc-b"], requireRole: "service:phi-reader",
      },
    });
    var cell = await b.breakGlass.encryptCell("alice's diagnosis (svc Model B)",
      { table: "_blamejs_jobs", rowId: jid.jobId, column: "payload" });
    await b.clusterStorage.execute(
      "UPDATE _blamejs_jobs SET payload = ? WHERE _id = ?", [cell, jid.jobId]);

    var serviceReq = {
      apiKey:  { id: "ak-svc-b", roles: ["service:phi-reader"] },   // roles, not scopes
      socket:  { remoteAddress: "10.0.0.5" },
      headers: { "user-agent": "blamejs-svc" },
      method:  "GET",
      url:     "/cron/deid",
    };
    var row = await b.breakGlass.unsealRowAsService(serviceReq, "_blamejs_jobs", jid.jobId,
      { reason: "svc Model B coverage: nightly de-identification" });
    check("svc Model B: roles-fallback authorized bypass decrypts the cell",
          row && row.payload === "alice's diagnosis (svc Model B)");

    // Authorized bypass but a rowId that doesn't exist → row-not-found.
    await rejects("authorized bypass, missing row",
      function () {
        return b.breakGlass.unsealRowAsService(serviceReq, "_blamejs_jobs", "no-such-svc-row",
          { reason: "svc row-not-found coverage" });
      }, /breakglass\/row-not-found/);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Passkey factor: full-field assertion drives the verify path ----

async function testPasskeyFullFieldFactorPath() {
  // The existing passkey test omits every field, so _verifyPasskeyFactor
  // short-circuits at the presence check. Supplying all five fields drives
  // the real WebAuthn verify call — a well-shaped but bogus assertion fails
  // verification (returns/raises), and grant refuses as bad-factor.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["passkey"] });
    var threw = null;
    try {
      await b.breakGlass.grant({
        req:    _fakeReq(),
        table:  "patients",
        reason: "passkey verify-path coverage: bogus but well-shaped assertion",
        factor: {
          type:              "passkey",
          response: {
            id:    "cred-id",
            rawId: "Y3JlZC1pZA",
            type:  "public-key",
            response: {
              clientDataJSON:    "e30",
              authenticatorData: "AAAA",
              signature:         "AAAA",
            },
          },
          expectedChallenge: "Y2hhbGxlbmdl",
          expectedOrigin:    "https://example.com",
          expectedRPID:      "example.com",
          credential: { id: "cred-id", publicKey: "AAAA", counter: 0 },
        },
      });
    } catch (e) { threw = e; }
    check("passkey full-field: bogus assertion refused as bad-factor",
          threw && /breakglass\/bad-factor/.test(threw.code || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- listActive / listActiveAll / revokeAll edge branches ----

async function testListAndRevokeEdgeBranches() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    // Unauthenticated listActive (no actor on req) → empty array, no leak.
    var none = await b.breakGlass.listActive({ req: { socket: { remoteAddress: "127.0.0.1" }, headers: {} } });
    check("listActive: unauthenticated caller gets []", Array.isArray(none) && none.length === 0);
    // No opts at all → still []
    var noneBare = await b.breakGlass.listActive();
    check("listActive: no-opts caller gets []", Array.isArray(noneBare) && noneBare.length === 0);

    await b.breakGlass.policy.set("t_edge", { columns: ["c"], factors: ["totp"], maxRowsPerGrant: 3 });
    var totp = _validTotp();
    var g = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "t_edge",
      reason: "list/revoke edge-branch coverage grant",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    void g;

    // listActiveAll `since` filter branch (existing tests only exercise the
    // table filter). A floor in the past keeps the grant; a floor in the
    // future filters it out.
    var sincePast = await b.breakGlass.listActiveAll({ since: Date.now() - C.TIME.minutes(5) });
    check("listActiveAll: since=past keeps the grant", sincePast.length === 1);
    var sinceFuture = await b.breakGlass.listActiveAll({ since: Date.now() + C.TIME.minutes(5) });
    check("listActiveAll: since=future filters it out", sinceFuture.length === 0);

    // revokeAll by actorId (the computeDerived predicate branch; existing
    // tests only revoke by table).
    var result = await b.breakGlass.revokeAll({ actorId: "user-test-1", reason: "ir-actor-scope" });
    check("revokeAll: by actorId revokes the actor's grant", result && result.revokedCount === 1);
    var after = await b.breakGlass.listActiveAll();
    check("revokeAll: actor's grant gone after revoke", after.length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  testInitOptsValidation();
  await testRequireInitGuards();
  await testPolicyCRUD();
  await testPolicyValidation();
  await testGrantHappyPath();
  await testGrantRequireScopeWildcardSegmentAware();
  await testGrantRefusalPaths();
  await testConcurrentTotpGrantReplay();
  await testUnsealRowLifecycle();
  await testGrantExhaustion();
  await testConcurrentUnsealRowDoubleClaim();
  await testGrantRevoke();
  await testTableMismatch();
  await testSweepExpiredGrants();
  // grant binding enforcement (IP / session pin + fail-closed) + TOTP replay
  await testIpPinEnforcement();
  await testIpPinPeerGated();
  await testSessionPinEnforcement();
  await testIpPinFailClosedOnNullBinding();
  await testTotpReplayDefense();
  // v0.5.1 Model B
  await testEncryptDecryptCellHappyPath();
  await testEncryptionContextBinding();
  await testEncryptCellRequiresCryptographicPolicy();
  await testEncryptCellRejectsBadColumn();
  await testCryptographicUnsealRow();
  await testMigrateModelAtoModelB();
  // v0.5.2 passkey + bypass + admin
  testV052Surface();
  await testPasskeyAcceptedInPolicy();
  await testPasskeyFactorPath();
  await testServiceAccountBypassPolicyValidation();
  await testServiceAccountBypassHappyPath();
  await testServiceAccountBypassRefusalPaths();
  await testListActiveAllAndRevokeAll();
  // Uncovered error / adversarial / defensive branch coverage
  await testPolicyValidationAdversarial();
  await testCellAndAdminInputValidation();
  await testMigrateEmptyTable();
  await testDekReUnsealFromPolicyRow();
  await testUnsealRowArgGuards();
  await testUnsealRowExpiredAndRowNotFound();
  await testUnsealRowCellDecryptFailed();
  await testSessionPinFailClosedOnNullBinding();
  await testGrantFactorLockout();
  await testGrantScopeViaApiKey();
  await testGrantTotpFactorShapeRejections();
  await testGrantAuditReasonHmac();
  await testUnsealRowAsServiceGuardsAndModelB();
  await testPasskeyFullFieldFactorPath();
  await testListAndRevokeEdgeBranches();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
