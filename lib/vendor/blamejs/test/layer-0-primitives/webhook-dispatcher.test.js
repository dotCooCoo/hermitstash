// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * webhook-dispatcher — durable signed-webhook delivery store
 * (b.webhook.dispatcher).
 *
 * Driven against a REAL node:sqlite backend (a faithful externalDb) + a real
 * vault (seal/unseal of the per-endpoint secret) + an injected transport, so
 * the persistence, fan-out, retry/backoff, dead-letter, and replay paths run
 * end-to-end without a network. SSRF refusal is exercised with IP-literal URLs
 * (ssrfGuard classifies an IP literal without DNS, so it runs offline).
 *
 * Covers: declareSchema; registerEndpoint with secret SEALED at rest (never
 * plaintext); SSRF refusal at registration; fan-out (one event → one delivery
 * row per subscribed endpoint); event-type + wildcard subscription matching;
 * a real signature the framework verifier accepts; first-attempt success;
 * transient-failure backoff scheduling; maxAttempts → dead-letter; permanent
 * (SSRF-rebind) → immediate dead-letter; deliveries.list/get/retry;
 * dlq.list/replay.
 *
 * Run standalone: node test/layer-0-primitives/webhook-dispatcher.test.js
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var { DatabaseSync } = require("node:sqlite");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// Minimal faithful externalDb over an in-memory node:sqlite db (mirrors the
// framework's sqlite provider: Date params → ISO strings, SELECT → { rows }).
function _sqliteExternalDb() {
  var db = new DatabaseSync(":memory:");
  function _bind(params) {
    return (params || []).map(function (v) {
      if (v instanceof Date) return v.toISOString();
      if (typeof v === "boolean") return v ? 1 : 0;
      return v;
    });
  }
  function _query(sqlText, params) {
    var stmt = db.prepare(sqlText);
    var args = _bind(params);
    if (/^\s*select/i.test(sqlText)) return { rows: stmt.all.apply(stmt, args) };
    var info = stmt.run.apply(stmt, args);
    return { rows: [], changes: info.changes };
  }
  var xdb = { dialect: "sqlite", query: async function (s, p) { return _query(s, p); } };
  return {
    dialect: "sqlite",
    query: async function (s, p) { return _query(s, p); },
    transaction: async function (fn) {
      db.exec("BEGIN");
      try { var r = await fn(xdb); db.exec("COMMIT"); return r; }
      catch (e) { try { db.exec("ROLLBACK"); } catch (_e) {} throw e; }
    },
    _raw: db,
  };
}

// A controllable transport: records every POST, returns a programmable status.
function _stubTransport() {
  var calls = [];
  var nextStatus = 200;
  var fn = function (url, body, headers) {
    calls.push({ url: url, body: body, headers: headers });
    return Promise.resolve({ status: nextStatus });
  };
  fn.calls = calls;
  fn.setStatus = function (s) { nextStatus = s; };
  return fn;
}

// A Postgres-dialect externalDb that reproduces the competing-consumer claim
// race that ONLY exists on a real row-locking backend (Postgres / MySQL at
// READ COMMITTED) — never on sqlite's single writer. Scenario: one delivery
// row is pending-and-due, but a CONCURRENT poller is mid-claim on it. A
// correct claim uses SELECT ... FOR UPDATE SKIP LOCKED, so this poller's SELECT
// skips the row the other poller locked and claims nothing. A claim that omits
// SKIP LOCKED still sees the row as pending under READ COMMITTED (the other
// txn is uncommitted at SELECT time), selects it, then its gated UPDATE matches
// zero rows (the other txn committed the flip first), and the reselect-by-id
// re-reads the now-in-flight row and hands it back — so BOTH pollers attempt
// the same delivery in one cycle.
function _contendedPgDb(dueId, dialect) {
  dialect = dialect || "postgres";
  function _run(sqlText) {
    var isClaimSelect = /select/i.test(sqlText)
      && /status\s*=\s*'pending'/i.test(sqlText)
      && /next_attempt_at/i.test(sqlText);
    if (isClaimSelect) {
      // SKIP LOCKED ⇒ the contended row is locked by the other poller ⇒ skipped.
      if (/for\s+update\s+skip\s+locked/i.test(sqlText)) return { rows: [] };
      return { rows: [{ delivery_id: dueId }] };          // no SKIP LOCKED: selected
    }
    // this poller's gated pending→in-flight UPDATE loses (the other poller
    // committed the claim first), so it matches zero rows.
    if (/^\s*update/i.test(sqlText) && /'in-flight'/i.test(sqlText)) return { rows: [], changes: 0 };
    // the buggy reselect re-reads the row the OTHER poller already flipped.
    if (/select/i.test(sqlText) && /status\s*=\s*'in-flight'/i.test(sqlText)) return { rows: [{ delivery_id: dueId }] };
    return { rows: [], changes: 0 };
  }
  // dialect carries the operator-supplied string (incl. the `postgresql` alias)
  // so the test exercises the dialect-normalization path the claim depends on.
  var xdb = { dialect: dialect, query: async function (s) { return _run(s); } };
  return {
    dialect: dialect,
    query: async function (s) { return _run(s); },
    transaction: async function (fn) { return await fn(xdb); },
  };
}

// Public IP literals — ssrfGuard classifies these without DNS, so the SSRF
// gate runs offline. The stub transport means no real POST is attempted.
var PUBLIC_URL  = "https://1.1.1.1/hooks";
var PUBLIC_URL2 = "https://8.8.8.8/hooks";

async function _readSealedSecret(xdb, endpointId) {
  var row = xdb._raw.prepare(
    "SELECT secret_sealed FROM " + tableName("webhook_endpoints") +
    " WHERE endpoint_id = ?").get(endpointId);
  return row && row.secret_sealed;
}

function tableName(local) { return b.frameworkSchema.tableName(local); }

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wd-"));
  await helpers.setupVaultOnly(tmpDir);
  try {
    await _runAll();
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function _runAll() {
  await testSurfaceAndSchema();
  await testRegisterSealsSecret();
  await testRegisterRefusesSsrf();
  await testDispatchFanOutAndSignature();
  await testEventTypeAndWildcardMatching();
  await testTransientFailureBacksOff();
  await testThrownTransportErrorBacksOff();
  await testTransientDnsRevalidationRetries();
  await testPermanentDnsRevalidationDeadLetters();
  await testDeliveryTimeSsrfRebindDeadLetters();
  await testMysqlSchemaNoPartialIndex();
  await testInlineDeliveryNotDoubleClaimed();
  await testPostgresClaimUsesSkipLockedDisjoint();
  await testMaxAttemptsDeadLetters();
  await testDlqReplay();
  await testDeliveriesRetry();
}

function _newDispatcher(xdb, transport, extra) {
  var opts = {
    externalDb:  xdb,
    httpRequest: transport,
    maxAttempts: 3,
    retryBackoff: { initialMs: 1000, maxMs: 60000, factor: 2 },
  };
  if (extra) Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; });
  return b.webhook.dispatcher(opts);
}

async function testSurfaceAndSchema() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  check("dispatcher returns object",            typeof wd === "object");
  ["declareSchema", "registerEndpoint", "removeEndpoint", "listEndpoints",
   "dispatch", "processRetries"].forEach(function (m) {
    check("dispatcher." + m + " is a function", typeof wd[m] === "function");
  });
  check("deliveries.list/get/retry present",
    wd.deliveries && typeof wd.deliveries.list === "function" &&
    typeof wd.deliveries.get === "function" && typeof wd.deliveries.retry === "function");
  check("dlq.list/replay present",
    wd.dlq && typeof wd.dlq.list === "function" && typeof wd.dlq.replay === "function");
  await wd.declareSchema();
  check("declareSchema is idempotent", true);
  await wd.declareSchema();   // second call must not throw (IF NOT EXISTS)
}

async function testRegisterSealsSecret() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  await wd.registerEndpoint({
    endpointId: "ep1", url: PUBLIC_URL,
    eventTypes: ["invoice.paid"], secret: "whsec_plaintext_secret",
  });
  var sealed = await _readSealedSecret(xdb, "ep1");
  check("secret is sealed at rest (vault: prefix)",
    typeof sealed === "string" && sealed.indexOf("vault:") === 0);
  check("secret plaintext NOT stored",
    sealed.indexOf("whsec_plaintext_secret") === -1);
  var eps = await wd.listEndpoints();
  check("listEndpoints returns the endpoint", eps.length === 1 && eps[0].endpointId === "ep1");
  check("listEndpoints does not leak the secret",
    JSON.stringify(eps).indexOf("whsec_plaintext_secret") === -1);
}

async function testRegisterRefusesSsrf() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  var privateThrew = false, metadataThrew = false, loopbackThrew = false, protoThrew = false;
  try { await wd.registerEndpoint({ endpointId: "p", url: "https://10.0.0.5/h", eventTypes: ["x"], secret: "s" }); }
  catch (e) { privateThrew = e.code === "webhook-dispatcher/ssrf-refused"; }
  try { await wd.registerEndpoint({ endpointId: "m", url: "https://169.254.169.254/", eventTypes: ["x"], secret: "s" }); }
  catch (e) { metadataThrew = e.code === "webhook-dispatcher/ssrf-refused"; }
  try { await wd.registerEndpoint({ endpointId: "l", url: "https://127.0.0.1/", eventTypes: ["x"], secret: "s" }); }
  catch (e) { loopbackThrew = e.code === "webhook-dispatcher/ssrf-refused"; }
  // Non-TLS refused by safeUrl (protocol), before the IP check.
  try { await wd.registerEndpoint({ endpointId: "h", url: "http://1.1.1.1/", eventTypes: ["x"], secret: "s" }); }
  catch (e) { protoThrew = (e.code === "safe-url/protocol-disallowed" || /protocol/.test(e.message)); }
  check("register refuses private IP (SSRF)",   privateThrew);
  check("register refuses metadata IP (SSRF)",  metadataThrew);
  check("register refuses loopback (SSRF)",     loopbackThrew);
  check("register refuses non-TLS",             protoThrew);
  // allowInternalDestinations opt-in lets an internal subscriber through.
  var wdInternal = _newDispatcher(xdb, _stubTransport(), { allowInternalDestinations: true });
  await wdInternal.declareSchema();
  var ok = false;
  try { await wdInternal.registerEndpoint({ endpointId: "int", url: "https://10.0.0.5/h", eventTypes: ["x"], secret: "s" }); ok = true; }
  catch (_e) { ok = false; }
  check("allowInternalDestinations opt-in permits private IP", ok);
}

async function testDispatchFanOutAndSignature() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  var secret = "whsec_fanout_secret";
  await wd.registerEndpoint({ endpointId: "a", url: PUBLIC_URL,  eventTypes: ["order.created"], secret: secret });
  await wd.registerEndpoint({ endpointId: "c", url: PUBLIC_URL2, eventTypes: ["order.created"], secret: secret });
  var res = await wd.dispatch("order.created", { id: "ord_1", total: 99 });
  check("fan-out delivered to both endpoints", res.delivered === 2 && res.failed === 0);
  check("transport POSTed twice",              transport.calls.length === 2);

  // The signed request the framework produces verifies with the framework's
  // own verifier under the same secret — proof the signature is real.
  var c0 = transport.calls[0];
  var sigHeader = c0.headers["Webhook-Signature"] || c0.headers["webhook-signature"];
  check("signature header present",            typeof sigHeader === "string" && sigHeader.length > 0);
  check("X-Webhook-Delivery-Id header present", typeof c0.headers["X-Webhook-Delivery-Id"] === "string");
  var verifier = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: secret } });
  // Pass the signed headers verbatim — they carry the Webhook-Signature the
  // verifier reads (plus the X-Webhook-* delivery headers it ignores).
  var info = await verifier.verify({ body: c0.body, headers: c0.headers });
  check("dispatcher signature verifies under endpoint secret", info && info.ok !== false);

  // Persisted rows reflect delivered status.
  var rows = await wd.deliveries.list({ status: "delivered" });
  check("both deliveries persisted as delivered", rows.length === 2);
  check("delivery carries responseStatus 200", rows[0].responseStatus === 200);
}

async function testEventTypeAndWildcardMatching() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "only-a", url: PUBLIC_URL,  eventTypes: ["a"],   secret: "s" });
  await wd.registerEndpoint({ endpointId: "star",   url: PUBLIC_URL2, eventTypes: ["*"],   secret: "s" });
  var resA = await wd.dispatch("a", { n: 1 });
  check("event 'a' reaches only-a + wildcard (2)", resA.delivered === 2);
  var resB = await wd.dispatch("b", { n: 2 });
  check("event 'b' reaches only the wildcard (1)", resB.delivered === 1);
}

async function testTransientFailureBacksOff() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(503);   // receiver down
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "down", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("transient failure not delivered",     res.delivered === 0 && res.failed === 1);
  var rows = await wd.deliveries.list({ endpointId: "down" });
  check("failed delivery stays pending for retry", rows.length === 1 && rows[0].status === "pending");
  check("attempts incremented to 1",           rows[0].attempts === 1);
  check("last_error recorded",                  /HTTP 503/.test(rows[0].lastError || ""));
}

async function testThrownTransportErrorBacksOff() {
  // A THROWN transport error (timeout / network / TLS) — httpClient throws it
  // as an alwaysPermanent WebhookDispatcherError (err.permanent === true). It
  // must still be treated as TRANSIENT (rescheduled), NOT dead-lettered on the
  // first attempt. (Regression: reading err.permanent dead-lettered it.)
  var xdb = _sqliteExternalDb();
  var transport = function () { var e = new Error("ETIMEDOUT connect"); e.permanent = true; throw e; };
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "to", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("thrown transport error not delivered",   res.delivered === 0 && res.failed === 1);
  var rows = await wd.deliveries.list({ endpointId: "to" });
  check("thrown transport error stays pending (transient, not dead)",
        rows.length === 1 && rows[0].status === "pending");
  check("thrown transport error not dead-lettered", res.deliveries[0].dead !== true);
}

async function testTransientDnsRevalidationRetries() {
  // The delivery-time SSRF re-validation resolves the destination host. A
  // TRANSIENT resolver fault (EAI_AGAIN) during that lookup must be treated as
  // transient — rescheduled — NOT dead-lettered. Regression: the re-validation
  // catch marked EVERY throw permanent, so a DNS blip dead-lettered a delivery.
  var xdb = _sqliteExternalDb();
  var HOST_URL = "https://hook.example.test/hooks";
  var calls = 0;
  var dnsLookup = function (host) {
    calls += 1;
    if (calls === 1) return Promise.resolve([{ address: "93.184.216.34", family: 4 }]); // register: public
    var e = new Error("getaddrinfo EAI_AGAIN " + host); e.code = "EAI_AGAIN";              // deliver: transient
    return Promise.reject(e);
  };
  var wd = _newDispatcher(xdb, _stubTransport(), { dnsLookup: dnsLookup });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "td", url: HOST_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("transient DNS in SSRF re-validation not delivered", res.delivered === 0 && res.failed === 1);
  check("transient DNS not dead-lettered", res.deliveries[0].dead !== true);
  var rows = await wd.deliveries.list({ endpointId: "td" });
  check("transient DNS delivery stays pending for retry", rows.length === 1 && rows[0].status === "pending");
  check("transient DNS resolver error recorded", /EAI_AGAIN/.test(rows[0].lastError || ""));
}

async function testPermanentDnsRevalidationDeadLetters() {
  // A PERMANENT resolver failure at the SSRF re-check — a host with no
  // addresses / a removed DNS record — carries the framework DnsError verdict
  // err.permanent === true. It must dead-letter immediately, NOT burn every
  // retry attempt on a name that will never resolve. (Distinct from a transient
  // DNS blip, which retries.)
  var xdb = _sqliteExternalDb();
  var HOST_URL = "https://gone.example.test/hooks";
  var calls = 0;
  var dnsLookup = function (host) {
    calls += 1;
    if (calls === 1) return Promise.resolve([{ address: "93.184.216.34", family: 4 }]); // register: public
    var e = new Error("dns lookup of '" + host + "' returned no addresses");             // deliver: permanent
    e.code = "dns/no-result"; e.permanent = true;
    return Promise.reject(e);
  };
  var wd = _newDispatcher(xdb, _stubTransport(), { dnsLookup: dnsLookup });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "gone", url: HOST_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("permanent DNS failure not delivered", res.delivered === 0 && res.failed === 1);
  check("permanent DNS failure is dead-lettered (not retried)", res.deliveries[0].dead === true);
  var rows = await wd.deliveries.list({ endpointId: "gone" });
  check("permanent DNS delivery status is dead", rows.length === 1 && rows[0].status === "dead");
}

async function testDeliveryTimeSsrfRebindDeadLetters() {
  // The control: a destination that was public at registration but REBINDS to a
  // loopback IP by delivery time is a genuine SSRF refusal — PERMANENT — and is
  // dead-lettered immediately (a WebhookDispatcherError, not a raw resolver fault).
  var xdb = _sqliteExternalDb();
  var HOST_URL = "https://hook.example.test/hooks";
  var calls = 0;
  var dnsLookup = function () {
    calls += 1;
    if (calls === 1) return Promise.resolve([{ address: "93.184.216.34", family: 4 }]); // register: public
    return Promise.resolve([{ address: "127.0.0.1", family: 4 }]);                        // deliver: rebound internal
  };
  var wd = _newDispatcher(xdb, _stubTransport(), { dnsLookup: dnsLookup });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "rb", url: HOST_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("SSRF-rebind at delivery not delivered", res.delivered === 0 && res.failed === 1);
  check("SSRF-rebind at delivery is dead-lettered (permanent)", res.deliveries[0].dead === true);
  var rows = await wd.deliveries.list({ endpointId: "rb" });
  check("SSRF-rebind delivery status is dead", rows.length === 1 && rows[0].status === "dead");
  check("SSRF-refused error recorded", /ssrf-refused|resolves to/.test(rows[0].lastError || ""));
}

async function testMysqlSchemaNoPartialIndex() {
  // MySQL has no partial indexes; sql.createIndex refuses `where` on mysql, so
  // declareSchema must emit a NON-partial index there or it throws on boot.
  var sqls = [];
  var mysqlXdb = {
    dialect: "mysql",
    query: async function (s) { sqls.push(s); return { rows: [] }; },
    transaction: async function (fn) { return fn(this); },
  };
  var wd = _newDispatcher(mysqlXdb, _stubTransport());
  var threw = null;
  try { await wd.declareSchema(); } catch (e) { threw = e; }
  check("declareSchema(mysql) does not throw on the pending index", threw === null);
  var idxSql = sqls.filter(function (s) { return /_pending_idx/i.test(s); }).join(" || ");
  check("mysql pending index is emitted",       idxSql.length > 0);
  check("mysql pending index is non-partial (no WHERE)", !/\bwhere\b/i.test(idxSql));
}

async function testInlineDeliveryNotDoubleClaimed() {
  // The inline first attempt must claim its row (status 'in-flight') BEFORE the
  // POST, so a retry poller firing during a slow inline POST can't grab the
  // same row and double-deliver. Simulate the poller from inside the transport.
  var xdb = _sqliteExternalDb();
  var calls = 0;
  var wd;
  var transport = function () {
    calls += 1;
    return wd.processRetries().then(function () { return { status: 200 }; });
  };
  wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "once", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });
  check("inline delivery not double-claimed by a concurrent poller", calls === 1);
}

async function testPostgresClaimUsesSkipLockedDisjoint() {
  // RED before the fix: on Postgres / MySQL the retry claim was a mark-then-
  // reselect with no FOR UPDATE SKIP LOCKED, so the reselect-by-id re-read any
  // in-flight row in the batch — including one a concurrent poller had just
  // claimed — and two pollers double-delivered the same row in one cycle. This
  // drives the postgres dialect because sqlite's single writer can't reproduce
  // it (the wrong-config gap that let it ship: testInlineDeliveryNotDoubleClaimed
  // runs on sqlite). The fix mirrors b.outbox's canonical competing-consumer
  // claim: FOR UPDATE SKIP LOCKED on Postgres / MySQL so concurrent pollers see
  // disjoint sets; the row another poller locked is skipped, so this poller
  // claims — and attempts — nothing.
  var pg = _contendedPgDb("d_contended");
  var wd = b.webhook.dispatcher({
    externalDb: pg, httpRequest: _stubTransport(), maxAttempts: 3,
    retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 },
    now: function () { return 1700000000000; },
  });
  var res = await wd.processRetries();
  check("processRetries claims nothing a concurrent poller already locked (Postgres SKIP LOCKED disjointness)",
        res.attempted === 0);

  // The `postgresql` alias normalizes to Postgres for SQL rendering, so the
  // SKIP LOCKED decision must follow the same normalization — otherwise the
  // dispatcher emits Postgres SQL but falls back to the mark-then-reselect race.
  var pgAlias = _contendedPgDb("d_contended_alias", "postgresql");
  var wdAlias = b.webhook.dispatcher({
    externalDb: pgAlias, httpRequest: _stubTransport(), maxAttempts: 3,
    retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 },
    now: function () { return 1700000000000; },
  });
  var resAlias = await wdAlias.processRetries();
  check("processRetries honors SKIP LOCKED under the 'postgresql' dialect alias",
        resAlias.attempted === 0);
}

async function testMaxAttemptsDeadLetters() {
  var now = 1700000000000;
  var clock = function () { return now; };
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(500);
  var wd = b.webhook.dispatcher({
    externalDb: xdb, httpRequest: transport, maxAttempts: 3,
    retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 }, now: clock,
  });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "dead", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });   // attempt 1 → pending
  // Advance the clock past each backoff so processRetries claims the row.
  now += 10000; await wd.processRetries();   // attempt 2 → pending
  now += 10000; var r3 = await wd.processRetries();   // attempt 3 → dead (maxAttempts)
  check("third attempt dead-letters",          r3.dead === 1);
  var dlq = await wd.dlq.list();
  check("DLQ holds the dead delivery",         dlq.length === 1 && dlq[0].status === "dead");
  check("dead delivery recorded 3 attempts",   dlq[0].attempts === 3);
}

async function testDlqReplay() {
  var now = 1700000000000;
  var clock = function () { return now; };
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(500);
  var wd = b.webhook.dispatcher({
    externalDb: xdb, httpRequest: transport, maxAttempts: 2,
    retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 }, now: clock,
  });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "rep", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });          // attempt 1 → pending
  now += 10000; await wd.processRetries();   // attempt 2 → dead
  var dlqBefore = await wd.dlq.list();
  check("delivery is in DLQ before replay",   dlqBefore.length === 1);
  // Receiver recovers; replay from the DLQ delivers.
  transport.setStatus(200);
  var replayRes = await wd.dlq.replay(dlqBefore[0].deliveryId);
  check("replay delivers",                    replayRes.ok === true);
  var dlqAfter = await wd.dlq.list();
  check("DLQ empty after successful replay",  dlqAfter.length === 0);
  var delivered = await wd.deliveries.list({ status: "delivered" });
  check("replayed delivery now delivered",    delivered.length === 1);
}

async function testDeliveriesRetry() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(500);
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "rt", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  var deliveryId = res.deliveries[0].deliveryId;
  var before = await wd.deliveries.get(deliveryId);
  check("delivery get returns the row",       before && before.deliveryId === deliveryId);
  transport.setStatus(200);
  var retryRes = await wd.deliveries.retry(deliveryId);
  check("manual retry delivers",              retryRes.ok === true);
  var after = await wd.deliveries.get(deliveryId);
  check("retried delivery now delivered",     after.status === "delivered");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[webhook-dispatcher] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
