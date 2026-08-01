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

// A Postgres-dialect externalDb whose claim SELECT returns a due-pending row
// and whose reads back a full delivery + endpoint row, so processRetries's
// FOR UPDATE SKIP LOCKED claim path takes its `return ids` branch and delivers
// the claimed id. Distinct from _contendedPgDb (which returns nothing to model
// the loser of a race) — this is the happy path where the claim succeeds.
function _pgHappyClaimDb(sealed) {
  var deliveryRow = {
    delivery_id: "d1", endpoint_id: "ep", url: PUBLIC_URL, event_type: "e",
    payload: '{"n":1}', idempotency_id: "idem", status: "in-flight", attempts: 0,
  };
  var epRow = { endpoint_id: "ep", url: PUBLIC_URL, secret_sealed: sealed, disabled: 0 };
  function _run(sqlText) {
    if (/^\s*update/i.test(sqlText)) return { rows: [], changes: 1 };
    // claim SELECT (status='pending' AND next_attempt_at) — one due row
    if (/select/i.test(sqlText) && /next_attempt_at/i.test(sqlText) && /status\s*=\s*'pending'/i.test(sqlText)) {
      return { rows: [{ delivery_id: "d1" }] };
    }
    if (/select/i.test(sqlText) && /idempotency_id/i.test(sqlText)) return { rows: [deliveryRow] }; // _loadDelivery
    if (/select/i.test(sqlText) && /secret_sealed/i.test(sqlText)) return { rows: [epRow] };        // _loadEndpointRow
    return { rows: [], changes: 0 };
  }
  var xdb = { dialect: "postgres", query: async function (s) { return _run(s); } };
  return {
    dialect: "postgres",
    query: async function (s) { return _run(s); },
    transaction: async function (fn) { return await fn(xdb); },
  };
}

// A sqlite-dialect externalDb whose claim SELECT returns a due row but whose
// in-flight RESELECT returns a rows-less result — exercising the
// `(afterRows && afterRows.rows) || []` fallback in the sqlite claim path (a
// driver variant that resolves a SELECT without a `rows` array).
function _sqliteReselectRowlessDb() {
  function _run(sqlText) {
    if (/^\s*update/i.test(sqlText)) return { rows: [], changes: 1 };
    if (/select/i.test(sqlText) && /next_attempt_at/i.test(sqlText)) return { rows: [{ delivery_id: "d1" }] }; // claim
    if (/select/i.test(sqlText) && /status\s*=\s*'in-flight'/i.test(sqlText)) return {};                        // reselect: no rows
    return { rows: [], changes: 0 };
  }
  var xdb = { dialect: "sqlite", query: async function (s) { return _run(s); } };
  return {
    dialect: "sqlite",
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
  // ---- error / edge / adversarial branch coverage ----
  await testDispatcherOptsValidation();
  await testBadTableNameRejected();
  await testPostgresFoldsMixedCaseTables();
  await testRegisterEventTypesValidation();
  await testDispatchInputValidation();
  await testDispatchNoSubscribers();
  await testDispatchStringAndBufferPayload();
  await testRemoveEndpoint();
  await testRetryUnknownDeliveryId();
  await testDeliveryEndpointRemovedDeadLetters();
  await testGetUnknownDeliveryReturnsNull();
  await testDefaultOptionsConstructAndDeliver();
  await testBackoffCappedAtMax();
  await testDisabledEndpointSkipped();
  await testCustomSignatureHeader();
  await testDeclareSchemaPostgresExplicitXdb();
  await testReapStaleInflight();
  await testListDeliveriesFilters();
  await testReservedWordTables();
  // ---- driver-variance / defensive-coercion branch coverage ----
  await testIntegerColumnCoercion();
  await testDefaultTransportGlue();
  await testTransportResponseShapeVariants();
  await testSsrfCatchMessagelessError();
  await testTransportThrowMessagelessError();
  await testCorruptedEventTypesTreatedAsNoSubscription();
  await testRowlessQueryResults();
  await testPostgresClaimHappyPathReturnsIds();
  await testSqliteReselectRowlessResult();
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

// ---- opts / construction validation (the validateOpts.shape + table-name gate) ----
async function testDispatcherOptsValidation() {
  var xdb = _sqliteExternalDb();
  var missingDb = false, badMax = false, infMax = false, unknownOpt = false;
  try { b.webhook.dispatcher({}); }
  catch (e) { missingDb = e.code === "webhook-dispatcher/bad-opts"; }
  try { b.webhook.dispatcher({ externalDb: xdb, httpRequest: _stubTransport(), maxAttempts: -5 }); }
  catch (e) { badMax = e.code === "webhook-dispatcher/bad-opts"; }
  try { b.webhook.dispatcher({ externalDb: xdb, httpRequest: _stubTransport(), maxAttempts: Infinity }); }
  catch (e) { infMax = e.code === "webhook-dispatcher/bad-opts"; }
  try { b.webhook.dispatcher({ externalDb: xdb, httpRequest: _stubTransport(), bogusOpt: 1 }); }
  catch (e) { unknownOpt = e.code === "webhook-dispatcher/bad-opts"; }
  check("dispatcher throws on missing externalDb",        missingDb);
  check("dispatcher throws on negative maxAttempts",      badMax);
  check("dispatcher throws on non-finite maxAttempts",    infMax);
  check("dispatcher throws on an unknown opt (exhaustive shape)", unknownOpt);
}

async function testBadTableNameRejected() {
  var xdb = _sqliteExternalDb();
  // An injection-bearing table name is refused at construction by
  // safeSql.quoteIdentifier (parity with b.db.from()).
  var endpointsThrew = false, deliveriesThrew = false;
  try { _newDispatcher(xdb, _stubTransport(), { endpointsTable: "bad name; DROP TABLE x" }); }
  catch (_e) { endpointsThrew = true; }
  try { _newDispatcher(xdb, _stubTransport(), { deliveriesTable: "evil\"; --" }); }
  catch (_e) { deliveriesThrew = true; }
  check("bad endpointsTable name rejected at construction",  endpointsThrew);
  check("bad deliveriesTable name rejected at construction", deliveriesThrew);
}

async function testRegisterEventTypesValidation() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  var emptyThrew = false, missingThrew = false;
  try { await wd.registerEndpoint({ endpointId: "e1", url: PUBLIC_URL, eventTypes: [], secret: "s" }); }
  catch (e) { emptyThrew = e.code === "webhook-dispatcher/bad-opts"; }
  try { await wd.registerEndpoint({ endpointId: "e2", url: PUBLIC_URL, secret: "s" }); }
  catch (e) { missingThrew = e.code === "webhook-dispatcher/bad-opts"; }
  check("registerEndpoint refuses empty eventTypes array", emptyThrew);
  check("registerEndpoint refuses missing eventTypes",     missingThrew);
  // Neither bad call should have written a row.
  var eps = await wd.listEndpoints();
  check("no endpoint persisted after eventTypes rejection", eps.length === 0);
}

async function testDispatchInputValidation() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  var emptyEventThrew = false, nullPayloadThrew = false, undefPayloadThrew = false;
  try { await wd.dispatch("", { n: 1 }); }
  catch (e) { emptyEventThrew = e.code === "webhook-dispatcher/bad-opts"; }
  try { await wd.dispatch("e", null); }
  catch (e) { nullPayloadThrew = e.code === "webhook-dispatcher/bad-opts"; }
  try { await wd.dispatch("e", undefined); }
  catch (e) { undefPayloadThrew = e.code === "webhook-dispatcher/bad-opts"; }
  check("dispatch refuses empty eventType",   emptyEventThrew);
  check("dispatch refuses null payload",       nullPayloadThrew);
  check("dispatch refuses undefined payload",  undefPayloadThrew);
}

async function testDispatchNoSubscribers() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "sub", url: PUBLIC_URL, eventTypes: ["subscribed.only"], secret: "s" });
  var res = await wd.dispatch("nobody.listening", { n: 1 });
  check("dispatch with no subscribers delivers nothing", res.delivered === 0 && res.failed === 0);
  check("dispatch with no subscribers has an empty deliveries list", res.deliveries.length === 0);
  check("no delivery row written for an unsubscribed event", transport.calls.length === 0);
}

async function testDispatchStringAndBufferPayload() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "raw", url: PUBLIC_URL, eventTypes: ["s", "b"], secret: "s" });
  await wd.dispatch("s", "already-a-string-body");
  check("string payload passed through verbatim (not re-serialized)",
    transport.calls.length === 1 && transport.calls[0].body === "already-a-string-body");
  await wd.dispatch("b", Buffer.from("buffer-bytes-body", "utf8"));
  check("Buffer payload coerced to its utf8 string",
    transport.calls.length === 2 && transport.calls[1].body === "buffer-bytes-body");
}

async function testRemoveEndpoint() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "keep",   url: PUBLIC_URL,  eventTypes: ["e"], secret: "s" });
  await wd.registerEndpoint({ endpointId: "remove", url: PUBLIC_URL2, eventTypes: ["e"], secret: "s" });
  var rm = await wd.removeEndpoint("remove");
  check("removeEndpoint reports removed", rm && rm.removed === true && rm.endpointId === "remove");
  var eps = await wd.listEndpoints();
  check("removed endpoint no longer listed",
    eps.length === 1 && eps[0].endpointId === "keep");
  var res = await wd.dispatch("e", { n: 1 });
  check("removed endpoint no longer receives dispatch", res.delivered === 1);
  // Validation: empty endpointId is refused.
  var idThrew = false;
  try { await wd.removeEndpoint(""); }
  catch (e) { idThrew = e.code === "webhook-dispatcher/bad-opts"; }
  check("removeEndpoint refuses empty endpointId", idThrew);
}

async function testRetryUnknownDeliveryId() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  var res = await wd.deliveries.retry("deadbeefdeadbeefdeadbeefdeadbeef");
  check("retry of an unknown delivery id fails softly (row not found)",
    res && res.ok === false && res.error === "delivery row not found");
  // Empty id is a hard validation throw.
  var threw = false;
  try { await wd.deliveries.retry(""); }
  catch (e) { threw = e.code === "webhook-dispatcher/bad-opts"; }
  check("retry refuses empty delivery id", threw);
}

async function testDeliveryEndpointRemovedDeadLetters() {
  // A delivery whose endpoint was removed between dispatch and re-attempt can
  // never sign (no secret) — it is dead-lettered as "endpoint no longer
  // registered", not retried forever.
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "gone2", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  var deliveryId = res.deliveries[0].deliveryId;
  await wd.removeEndpoint("gone2");
  var retryRes = await wd.deliveries.retry(deliveryId);
  check("delivery whose endpoint was removed is dead-lettered", retryRes.dead === true);
  var row = await wd.deliveries.get(deliveryId);
  check("removed-endpoint delivery status is dead", row && row.status === "dead");
  check("removed-endpoint delivery records the reason",
    /endpoint no longer registered/.test(row.lastError || ""));
}

async function testGetUnknownDeliveryReturnsNull() {
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  await wd.declareSchema();
  var got = await wd.deliveries.get("00000000000000000000000000000000");
  check("deliveries.get returns null for an unknown id", got === null);
}

async function testDefaultOptionsConstructAndDeliver() {
  // Construct with ONLY the required externalDb + an injected transport — every
  // other opt (maxAttempts / batchSize / claimReclaimMs / retryBackoff /
  // signatureHeader / allowedProtocols / now) falls to its default.
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = b.webhook.dispatcher({ externalDb: xdb, httpRequest: transport });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "def", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("dispatcher built with all-default opts delivers", res.delivered === 1);
  var sigHeader = transport.calls[0].headers["Webhook-Signature"];
  check("default signatureHeader is the framework default (Webhook-Signature)",
    typeof sigHeader === "string" && sigHeader.length > 0);
}

async function testBackoffCappedAtMax() {
  // initialMs (10s) exceeds maxMs (5s), so the very first reschedule must clamp
  // the backoff to maxMs — exercising the `ms > backoffMax` cap branch.
  var now = 1700000000000;
  var clock = function () { return now; };
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(503);
  var wd = b.webhook.dispatcher({
    externalDb: xdb, httpRequest: transport, maxAttempts: 5,
    retryBackoff: { initialMs: 10000, maxMs: 5000, factor: 2 }, now: clock,
  });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "cap", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });
  var rows = await wd.deliveries.list({ endpointId: "cap" });
  var expected = new Date(now + 5000).toISOString();
  check("backoff is clamped to maxMs, not initialMs*factor^n",
    rows.length === 1 && rows[0].nextAttemptAt === expected);
}

async function testDisabledEndpointSkipped() {
  // A disabled endpoint (disabled=1) is filtered out of the fan-out AND
  // surfaced as disabled:true by listEndpoints (_isTruthy on the integer flag).
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "dis", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  xdb._raw.prepare("UPDATE " + tableName("webhook_endpoints") +
    " SET disabled = 1 WHERE endpoint_id = ?").run("dis");
  var eps = await wd.listEndpoints();
  check("listEndpoints reports the endpoint as disabled",
    eps.length === 1 && eps[0].disabled === true);
  var res = await wd.dispatch("e", { n: 1 });
  check("a disabled endpoint receives no delivery",
    res.delivered === 0 && res.failed === 0 && transport.calls.length === 0);
}

async function testCustomSignatureHeader() {
  // A custom signatureHeader opt is forwarded to b.webhook.signer, so the POSTed
  // request carries the operator's header name instead of the default.
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport, { signatureHeader: "X-Partner-Signature" });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "csh", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });
  var h = transport.calls[0].headers;
  check("custom signatureHeader name is emitted", typeof h["X-Partner-Signature"] === "string");
  check("default Webhook-Signature header absent under a custom header",
    h["Webhook-Signature"] === undefined);
}

async function testDeclareSchemaPostgresExplicitXdb() {
  // declareSchema(xdb) with an explicit Postgres target: exercises the
  // `xdb || externalDb` xdb branch AND the postgres TIMESTAMPTZ + partial-index
  // (WHERE status='pending') branches — the complement of the mysql schema test.
  var xdb = _sqliteExternalDb();
  var wd = _newDispatcher(xdb, _stubTransport());
  var sqls = [];
  var pgTarget = {
    dialect: "postgres",
    query: async function (s) { sqls.push(s); return { rows: [] }; },
    transaction: async function (fn) { return fn(this); },
  };
  await wd.declareSchema(pgTarget);
  var joined = sqls.join(" || ");
  check("postgres schema uses TIMESTAMPTZ timestamps", /TIMESTAMPTZ/i.test(joined));
  var idxSql = sqls.filter(function (s) { return /_pending_idx/i.test(s); }).join(" || ");
  check("postgres pending index is partial (WHERE status = 'pending')",
    /where\s+status\s*=\s*'pending'/i.test(idxSql));
}

async function testReapStaleInflight() {
  // A worker that claimed a delivery (status 'in-flight') then crashed strands
  // the row. processRetries()'s reaper flips it back to 'pending' once the lease
  // (claimReclaimMs) expires; a FRESHLY-claimed in-flight row is NOT reaped.
  var now = 1700000000000;
  var clock = function () { return now; };
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  transport.setStatus(503);
  var wd = b.webhook.dispatcher({
    externalDb: xdb, httpRequest: transport, maxAttempts: 5,
    retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 }, now: clock,
  });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "reap", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var d1 = (await wd.dispatch("e", { n: 1 })).deliveries[0].deliveryId;   // → pending
  var d2 = (await wd.dispatch("e", { n: 2 })).deliveries[0].deliveryId;   // → pending
  var tenMinMs = 600000;   // well past the 5-min default claimReclaimMs lease
  var staleIso = new Date(now - tenMinMs).toISOString();
  var freshIso = new Date(now).toISOString();
  var dueIso   = new Date(now - tenMinMs).toISOString();
  var upd = "UPDATE " + tableName("webhook_deliveries") +
    " SET status = 'in-flight', claimed_at = ?, next_attempt_at = ? WHERE delivery_id = ?";
  xdb._raw.prepare(upd).run(staleIso, dueIso, d1);   // stranded past the lease
  xdb._raw.prepare(upd).run(freshIso, dueIso, d2);   // just claimed — still owned
  transport.setStatus(200);
  var res = await wd.processRetries();
  check("only the stale in-flight row is reaped + re-attempted", res.attempted === 1 && res.delivered === 1);
  var r1 = await wd.deliveries.get(d1);
  var r2 = await wd.deliveries.get(d2);
  check("reaped delivery is now delivered", r1 && r1.status === "delivered");
  check("freshly-claimed delivery is left in-flight (not reaped)", r2 && r2.status === "in-flight");
}

async function testListDeliveriesFilters() {
  // Drive the endpointId + status + explicit limit filter branches of
  // deliveries.list in one pass.
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "f1", url: PUBLIC_URL,  eventTypes: ["e"], secret: "s" });
  await wd.registerEndpoint({ endpointId: "f2", url: PUBLIC_URL2, eventTypes: ["e"], secret: "s" });
  await wd.dispatch("e", { n: 1 });   // both delivered (200)
  var f1 = await wd.deliveries.list({ endpointId: "f1", status: "delivered", limit: 10 });
  check("list filters by endpointId + status + explicit limit",
    f1.length === 1 && f1[0].endpointId === "f1" && f1[0].status === "delivered");
  var all = await wd.deliveries.list();
  check("list with no filter returns every delivery", all.length === 2);
}

// Reserved-word operator tables — endpoints/deliveries tables whose names are
// SQL keywords ("from" / "select") must declare, register, dispatch, and poll.
// The dispatcher builds every statement against a concrete externalDb handle
// (never b.clusterStorage), so the operator table names are quoted by
// construction; unquoted keyword names are a syntax error at declareSchema /
// registerEndpoint / dispatch. Parity with b.db.from()'s reserved-word support.
async function testReservedWordTables() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport, {
    endpointsTable:  "from",       // SQL reserved words — valid only when quoted
    deliveriesTable: "select",
  });
  // CREATE TABLE + partial index only parse when the identifiers are quoted.
  await wd.declareSchema();

  await wd.registerEndpoint({ endpointId: "kw", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var eps = await wd.listEndpoints();
  check("reserved-word tables: endpoint persisted + listed via quoted 'from' table",
    eps.length === 1 && eps[0].endpointId === "kw");

  // Read back through the quoted names to prove the rows landed in the keyword tables.
  var epRow = xdb._raw.prepare('SELECT endpoint_id FROM "from"').get();
  check("reserved-word tables: endpoint row under the quoted identifier", epRow && epRow.endpoint_id === "kw");

  var res = await wd.dispatch("e", { n: 1 });
  check("reserved-word tables: dispatch inserts + delivers via the quoted 'select' table",
    res.delivered === 1 && res.failed === 0);
  var delRow = xdb._raw.prepare('SELECT status FROM "select"').get();
  check("reserved-word tables: delivery row under the quoted identifier", delRow && delRow.status === "delivered");

  var rows = await wd.deliveries.list({ status: "delivered" });
  check("reserved-word tables: deliveries.list reads back the delivered row",
    rows.length === 1 && rows[0].status === "delivered");

  // processRetries drives the claim SELECT/UPDATE + reaper against the keyword table.
  var retryRes = await wd.processRetries();
  check("reserved-word tables: processRetries runs the claim path without a syntax error",
    retryRes && typeof retryRes.attempted === "number");
}

// A text-protocol backend returns INTEGER / int8 columns as STRINGS (the
// node-postgres reality the dispatcher's _intOf / _intOrNull coercion exists
// for). A corrupt / legacy read can even be non-numeric. Drive both through
// deliveries.get (the operator-console path) so the counter arithmetic stays a
// clean number and a garbage read coerces to 0 / null, never NaN.
async function testIntegerColumnCoercion() {
  var nextRow = null;
  var textProtoDb = {
    dialect: "sqlite",
    query: async function (s) {
      if (/^\s*select/i.test(s)) return { rows: nextRow ? [nextRow] : [] };
      return { rows: [], changes: 0 };
    },
    transaction: async function (fn) { return fn(this); },
  };
  var wd = _newDispatcher(textProtoDb, _stubTransport());

  // Numeric strings (the text protocol): coerce to numbers.
  nextRow = {
    delivery_id: "d1", endpoint_id: "ep", event_type: "e", status: "delivered",
    attempts: "3", next_attempt_at: "t0", delivered_at: "t1", response_status: "200", last_error: null,
  };
  var g1 = await wd.deliveries.get("d1");
  check("text-protocol numeric-string attempts coerces to a number", g1 && g1.attempts === 3);
  check("text-protocol numeric-string response_status coerces to a number", g1.responseStatus === 200);

  // A non-numeric (corrupt) read coerces to 0 / null, not NaN.
  nextRow = {
    delivery_id: "d2", endpoint_id: "ep", event_type: "e", status: "pending",
    attempts: "not-a-number", next_attempt_at: "t0", delivered_at: null, response_status: "garbage", last_error: null,
  };
  var g2 = await wd.deliveries.get("d2");
  check("non-numeric attempts coerces to 0 (not NaN)", g2 && g2.attempts === 0);
  check("non-numeric response_status coerces to null (not NaN)", g2.responseStatus === null);

  // An empty-string read (a driver that empties a NULL-ish integer) → 0 / null.
  nextRow = {
    delivery_id: "d3", endpoint_id: "ep", event_type: "e", status: "pending",
    attempts: "", next_attempt_at: "t0", delivered_at: null, response_status: "", last_error: null,
  };
  var g3 = await wd.deliveries.get("d3");
  check("empty-string integer read coerces to 0 / null", g3 && g3.attempts === 0 && g3.responseStatus === null);
}

// With NO httpRequest injected, the default transport POSTs through
// b.httpClient. Patch the http-client boundary (no network) to prove the
// default transport passes the signed POST through and maps the response
// status back — the glue the injected-transport tests never exercise.
async function testDefaultTransportGlue() {
  var httpClientMod = require("../../lib/http-client");
  var origRequest = httpClientMod.request;
  var captured = null;
  var nextResp = { statusCode: 200 };
  httpClientMod.request = function (reqOpts) {
    captured = reqOpts;
    return Promise.resolve(nextResp);
  };
  try {
    var xdb = _sqliteExternalDb();
    var wd = b.webhook.dispatcher({ externalDb: xdb });   // no httpRequest → default transport
    await wd.declareSchema();
    await wd.registerEndpoint({ endpointId: "dt",  url: PUBLIC_URL,  eventTypes: ["e"],  secret: "s" });
    await wd.registerEndpoint({ endpointId: "dt2", url: PUBLIC_URL2, eventTypes: ["e2"], secret: "s" });
    await wd.registerEndpoint({ endpointId: "dt3", url: PUBLIC_URL,  eventTypes: ["e3"], secret: "s" });

    // http-client returns { statusCode } — the mapper reads it as the status.
    nextResp = { statusCode: 200 };
    var res = await wd.dispatch("e", { n: 1 });
    check("default transport delivers via b.httpClient (statusCode)", res.delivered === 1);
    check("default transport issues a POST to the endpoint url",
      captured && captured.method === "POST" && captured.url === PUBLIC_URL);
    check("default transport forwards the signed request body + signature header",
      captured && captured.body === '{"n":1}' && typeof captured.headers["Webhook-Signature"] === "string");
    check("default transport passes the dispatcher's allowedProtocols + errorClass",
      captured && Array.isArray(captured.allowedProtocols) && typeof captured.errorClass === "function");

    // A response carrying { status } (no statusCode) is mapped via the fallback.
    nextResp = { status: 201 };
    var res2 = await wd.dispatch("e2", { n: 2 });
    check("default transport maps a { status } response", res2.delivered === 1);

    // A status-less response maps to 0 → a scheduled failure.
    nextResp = {};
    var res3 = await wd.dispatch("e3", { n: 3 });
    check("default transport maps a status-less response to HTTP 0 (failure)",
      res3.delivered === 0 && res3.failed === 1);
  } finally {
    httpClientMod.request = origRequest;
  }
}

// The _attemptDelivery status read is (result.status || result.statusCode) || 0.
// A transport returning { statusCode } (not { status }) still delivers; a
// status-less object maps to HTTP 0 → a scheduled failure.
async function testTransportResponseShapeVariants() {
  var xdb = _sqliteExternalDb();
  var shape = { statusCode: 200 };
  var transport = function () { return Promise.resolve(shape); };
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "sc", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res1 = await wd.dispatch("e", { n: 1 });
  check("transport returning { statusCode: 200 } is delivered", res1.delivered === 1);

  shape = {};   // status-less → (undefined || undefined) || 0 → 0
  await wd.registerEndpoint({ endpointId: "sc2", url: PUBLIC_URL2, eventTypes: ["e2"], secret: "s" });
  var res2 = await wd.dispatch("e2", { n: 2 });
  check("transport returning a status-less object maps to HTTP 0 (failure)",
    res2.delivered === 0 && res2.failed === 1);
  var rows = await wd.deliveries.list({ endpointId: "sc2" });
  check("HTTP 0 delivery stays pending and records the failure",
    rows.length === 1 && rows[0].status === "pending" && /HTTP 0/.test(rows[0].lastError || ""));
}

// A resolver rejection with NO .message at the delivery-time SSRF re-check is
// still stringified into last_error and treated as transient (rescheduled),
// never a NaN/undefined record and never a first-attempt dead-letter.
async function testSsrfCatchMessagelessError() {
  var xdb = _sqliteExternalDb();
  var HOST_URL = "https://hook.example.test/hooks";
  var calls = 0;
  var dnsLookup = function () {
    calls += 1;
    if (calls === 1) return Promise.resolve([{ address: "93.184.216.34", family: 4 }]); // register: public
    return Promise.reject(new Error(""));   // deliver: message-less resolver fault
  };
  var wd = _newDispatcher(xdb, _stubTransport(), { dnsLookup: dnsLookup });
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "ml", url: HOST_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("message-less resolver fault not delivered", res.delivered === 0 && res.failed === 1);
  check("message-less resolver fault is transient (not dead)", res.deliveries[0].dead !== true);
  var rows = await wd.deliveries.list({ endpointId: "ml" });
  check("message-less resolver fault stays pending with a stringified error",
    rows.length === 1 && rows[0].status === "pending" && (rows[0].lastError || "").length > 0);
}

// A transport that THROWS a message-less value is stringified into last_error
// and rescheduled (transient) — the (err && err.message) || String(err) glue.
async function testTransportThrowMessagelessError() {
  var xdb = _sqliteExternalDb();
  var transport = function () { throw new Error(""); };
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "tm", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  var res = await wd.dispatch("e", { n: 1 });
  check("message-less transport throw not delivered", res.delivered === 0 && res.failed === 1);
  var rows = await wd.deliveries.list({ endpointId: "tm" });
  check("message-less transport throw stays pending with a stringified error",
    rows.length === 1 && rows[0].status === "pending" && (rows[0].lastError || "").length > 0);
}

// An endpoint row whose event_types can't parse to an array (a corrupted /
// legacy row) is treated as subscribing to nothing (eventTypes || []) during
// fan-out — never throwing, never mis-delivering.
async function testCorruptedEventTypesTreatedAsNoSubscription() {
  var xdb = _sqliteExternalDb();
  var transport = _stubTransport();
  var wd = _newDispatcher(xdb, transport);
  await wd.declareSchema();
  await wd.registerEndpoint({ endpointId: "corrupt", url: PUBLIC_URL, eventTypes: ["e"], secret: "s" });
  xdb._raw.prepare("UPDATE " + tableName("webhook_endpoints") +
    " SET event_types = 'null' WHERE endpoint_id = ?").run("corrupt");
  var res = await wd.dispatch("e", { n: 1 });
  check("endpoint with unparseable event_types receives no delivery",
    res.delivered === 0 && res.failed === 0 && transport.calls.length === 0);
}

// A backend whose query() resolves WITHOUT a `rows` array (a driver variant, a
// non-SELECT result) is tolerated everywhere the read maps rows: the
// (res && res.rows) || [] guards yield empty lists instead of throwing.
async function testRowlessQueryResults() {
  var rowlessDb = {
    dialect: "sqlite",
    query: async function () { return {}; },
    transaction: async function (fn) { return fn(this); },
  };
  var wd = _newDispatcher(rowlessDb, _stubTransport());
  var eps = await wd.listEndpoints();
  check("listEndpoints tolerates a rows-less query result", Array.isArray(eps) && eps.length === 0);
  var list = await wd.deliveries.list();
  check("deliveries.list tolerates a rows-less query result", Array.isArray(list) && list.length === 0);
  var res = await wd.processRetries();
  check("processRetries tolerates a rows-less claim result", res.attempted === 0);
}

// On Postgres, the FOR UPDATE SKIP LOCKED claim SELECT is authoritative: the
// selected ids ARE the claim, so processRetries returns them directly (no
// reselect) and attempts each. Exercises the `if (supportsSkipLocked) return
// ids` branch with a NON-empty claim — the complement of _contendedPgDb.
async function testPostgresClaimHappyPathReturnsIds() {
  var sealed = b.vault.seal("s");
  var pg = _pgHappyClaimDb(sealed);
  var wd = b.webhook.dispatcher({
    externalDb: pg, httpRequest: _stubTransport(), maxAttempts: 3,
    now: function () { return 1700000000000; },
  });
  var res = await wd.processRetries();
  check("postgres claim returns the locked ids and delivers them",
    res.attempted === 1 && res.delivered === 1);
}

// The sqlite claim path re-reads which in-flight rows it flipped. A driver that
// resolves that reselect without a `rows` array falls back to [] (claims
// nothing this cycle) instead of throwing.
async function testSqliteReselectRowlessResult() {
  var db = _sqliteReselectRowlessDb();
  var wd = b.webhook.dispatcher({
    externalDb: db, httpRequest: _stubTransport(), maxAttempts: 3,
    now: function () { return 1700000000000; },
  });
  var res = await wd.processRetries();
  check("sqlite reselect tolerates a rows-less result (claims nothing)", res.attempted === 0);
}

// PostgreSQL folds UNQUOTED identifiers to lowercase, so a pre-0.18 deployment
// with a bare mixed-case custom endpoints/deliveries table already has folded
// tables. Now that names are always quoted, custom operator names must be folded
// to lowercase on postgres so they keep targeting the existing tables. sqlite is
// case-insensitive — no fold. RED before the fix: the postgres DDL quoted the
// mixed-case names verbatim, stranding the folded tables.
async function testPostgresFoldsMixedCaseTables() {
  function _capturingDb(dialect) {
    var sqls = [];
    var q = async function (s) { sqls.push(String(s)); return { rows: [] }; };
    return { _sqls: sqls, dialect: dialect, query: q,
      transaction: async function (fn) { return fn({ dialect: dialect, query: q }); } };
  }
  var pg = _capturingDb("postgres");
  var wdPg = b.webhook.dispatcher({
    externalDb: pg, httpRequest: _stubTransport(),
    endpointsTable: "MyEndpoints", deliveriesTable: "MyDeliveries",
  });
  await wdPg.declareSchema(pg);
  var pgDdl = pg._sqls.join("\n");
  check("postgres: mixed-case webhook tables fold to lowercase (legacy compat)",
    pgDdl.indexOf('"myendpoints"') !== -1 && pgDdl.indexOf('"mydeliveries"') !== -1 &&
    pgDdl.indexOf('"MyEndpoints"') === -1 && pgDdl.indexOf('"MyDeliveries"') === -1);

  var lite = _capturingDb("sqlite");
  var wdLite = b.webhook.dispatcher({
    externalDb: lite, httpRequest: _stubTransport(),
    endpointsTable: "MyEndpoints", deliveriesTable: "MyDeliveries",
  });
  await wdLite.declareSchema(lite);
  var liteDdl = lite._sqls.join("\n");
  check("sqlite: mixed-case webhook tables keep their casing (no fold)",
    liteDdl.indexOf('"MyEndpoints"') !== -1 && liteDdl.indexOf('"MyDeliveries"') !== -1);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[webhook-dispatcher] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
