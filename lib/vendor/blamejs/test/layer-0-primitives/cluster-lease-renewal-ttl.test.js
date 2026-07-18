// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster-provider-db renewLease — lease-duration invariant across
 * repeated renewals.
 *
 * A renewable lease is a sliding window: every successful renewal must
 * push the expiry to `now + leaseTtl`, keeping the effective remaining
 * lifetime pinned at the configured TTL. The bounded-takeover guarantee
 * (a dead leader's row expires within leaseTtl so a follower can steal
 * it) depends entirely on this: if renewal inflates the expiry, the
 * dead leader's row stays "valid" far past leaseTtl and no follower can
 * take over — write availability is lost for a growing window.
 *
 * The lease span (expiresAt - acquiredAt) equals leaseTtl at acquire
 * time. This drives several renewals with real elapsed time between each
 * and asserts the span stays exactly leaseTtl — i.e. renewal slides BOTH
 * ends of the window forward rather than only stretching the far end.
 * Covers the SQLite dialect against a live in-process backend and the
 * MySQL dialect against the fake driver, since the two dialects renew
 * through different code paths (RETURNING vs. UPDATE-then-readback).
 *
 * Run standalone: `node test/layer-0-primitives/cluster-lease-renewal-ttl.test.js`
 */

var helpers = require("../helpers");
var b                    = helpers.b;
var fs                   = helpers.fs;
var os                   = helpers.os;
var path                 = helpers.path;
var check                = helpers.check;
var _makeSqliteDriver    = helpers._makeSqliteDriver;
var _makeFakeMysqlDriver = helpers._makeFakeMysqlDriver;
var C                    = b.constants;

var providerFactory = require(path.join(__dirname, "..", "..", "lib", "cluster-provider-db"));

// Renew `count` times with real elapsed time between each, asserting the
// lease span stays pinned at the configured TTL. `label` tags the dialect.
async function _assertRenewalKeepsTtl(label, provider, ttlMs) {
  var lease = await provider.acquireLease("node-A", ttlMs);
  check(label + ": acquire succeeds", lease !== null);
  check(label + ": span equals TTL at acquire",
        lease.expiresAt - lease.acquiredAt === ttlMs);

  for (var i = 1; i <= 5; i++) {
    // Real wall-clock elapse so Date.now() advances between renewals — the
    // drift only manifests when time passes between acquire and renewal.
    await helpers.passiveObserve(15, label + ": renewal-gap elapse #" + i);
    lease = await provider.renewLease(lease);

    var span      = lease.expiresAt - lease.acquiredAt;
    var remaining = lease.expiresAt - Date.now();

    // Core invariant: renewal slides the whole window, so the span stays
    // exactly the configured TTL. A renewal that only stretches expiresAt
    // (leaving acquiredAt frozen) grows the span past TTL every time.
    check(label + ": renewal #" + i + " keeps span == TTL (got " + span +
          ", TTL " + ttlMs + ")", span === ttlMs);
    // And the remaining lifetime never balloons past the TTL — a dead
    // leader would expire within leaseTtl and be steal-able on schedule.
    check(label + ": renewal #" + i + " remaining <= TTL (got " + remaining + ")",
          remaining <= ttlMs);
  }
}

async function testSqliteRenewalKeepsTtl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-renew-ttl-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { ops: { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    var p = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await p.ensureSchema();
    await _assertRenewalKeepsTtl("sqlite", p, C.TIME.seconds(30));
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
    try { driver._close(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function testMysqlRenewalKeepsTtl() {
  var driver = _makeFakeMysqlDriver();
  try {
    b.externalDb.init({
      backends: {
        ops: { connect: driver.connect, query: driver.query, close: driver.close, dialect: "mysql" },
      },
    });
    var p = providerFactory.create({ externalDbBackend: "ops", dialect: "mysql" });
    await p.ensureSchema();
    await _assertRenewalKeepsTtl("mysql", p, C.TIME.seconds(30));
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  await testSqliteRenewalKeepsTtl();
  await testMysqlRenewalKeepsTtl();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster-lease-renewal-ttl] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
