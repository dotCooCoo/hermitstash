// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Durable signed-webhook delivery store — the middle the framework was
 * missing between b.webhook.signer (one inline POST, lost on exhaustion) and
 * b.outbox (durable at-least-once, but terminates at an in-process publisher
 * and never speaks HTTP). b.webhook.dispatcher composes the pieces already in
 * the framework: it registers endpoints, fans one business event out to every
 * subscribed endpoint as its own durable delivery row, signs each via
 * b.webhook.signer, attempts HTTP delivery, backs off across attempts on the
 * b.outbox retry curve, dead-letters after N attempts, and exposes a
 * list/retry/replay surface an operator console can drive.
 *
 * Storage is the operator's b.externalDb (the same way b.outbox takes it).
 * Per-endpoint secrets are sealed at rest with b.vault.seal — never stored
 * plaintext. Destination URLs are validated through b.safeUrl at registration
 * AND re-validated at every delivery attempt (DNS-rebinding / SSRF defense).
 *
 * Exposed as b.webhook.dispatcher; lives in its own module because a durable
 * delivery store is a distinct domain from the stateless sign/verify surface
 * in lib/webhook.js.
 */

var C = require("./constants");
var sql = require("./sql");
var safeSql = require("./safe-sql");
var safeUrl = require("./safe-url");
var safeJson = require("./safe-json");
var bCrypto = require("./crypto");
var frameworkSchema = require("./framework-schema");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { WebhookDispatcherError } = require("./framework-error");

// lib/webhook re-exports this module as b.webhook.dispatcher, so requiring it
// eagerly here is a cycle — and webhook.js reassigns module.exports at the
// bottom, which would hand us a stale empty object. Defer to call time.
var webhookSign = lazyRequire(function () { return require("./webhook"); });
var vault = lazyRequire(function () { return require("./vault"); });
// ssrfGuard.checkUrl resolves the host and refuses private / loopback /
// link-local / metadata destinations — safeUrl.parse only refuses by protocol
// + userinfo, so it alone does NOT stop SSRF to an internal IP. Composed at
// registration AND every delivery attempt (DNS-rebinding defense).
var ssrfGuard = lazyRequire(function () { return require("./ssrf-guard"); });
var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });
// Lazy — http-client pulls in node:http / node:https / node:http2; only the
// default delivery transport touches it. Keeping it lazy keeps b.webhook (which
// re-exports this module) free of the Node networking chain on its inbound
// verify path, so b.webhook.verify stays loadable in a Worker / edge runtime.
var httpClient = lazyRequire(function () { return require("./http-client"); });

var _err = WebhookDispatcherError.factory;

// ---- defaults ----
var DEFAULT_MAX_ATTEMPTS      = 8;
var DEFAULT_BACKOFF_INITIAL   = C.TIME.seconds(5);
var DEFAULT_BACKOFF_MAX       = C.TIME.minutes(60);
var DEFAULT_BACKOFF_FACTOR    = 2;
var DEFAULT_CLAIM_RECLAIM_MS  = C.TIME.minutes(5);
var DEFAULT_BATCH_SIZE        = 100;
var SIGNER_ALGO               = "hmac-sha3-512";   // framework symmetric webhook MAC
var DELIVERY_ID_BYTES         = C.BYTES.bytes(16);
var WILDCARD_EVENT            = "*";

// HTTP success band — a 2xx is delivered; everything else (incl. 3xx/4xx/5xx)
// is a delivery failure that backs off and eventually dead-letters.
var HTTP_OK_MIN = 200;
var HTTP_OK_MAX = 300;

function _validateTableName(name, label) {
  validateOpts.requireNonEmptyString(name, label, WebhookDispatcherError, "webhook-dispatcher/bad-opts");
  // safeSql.quoteIdentifier refuses an injection-bearing name at construction.
  safeSql.quoteIdentifier(name);
  return name;
}

function _sqlDialect(externalDb) {
  var d = externalDb && externalDb.dialect;
  if (d === "postgres" || d === "postgresql") return "postgres";
  if (d === "mysql") return "mysql";
  return "sqlite";
}

// Coerce an integer column read back from the backend to a JS number. Drivers
// differ: node:sqlite returns INTEGER as a number, but a text protocol (and a
// node-postgres BIGINT/int8) returns it as a STRING — `"1" + 1` would
// string-concat to "11", corrupting the attempt counter. Normalize on read so
// the dispatcher's arithmetic is driver-agnostic.
function _intOf(v) {
  if (typeof v === "number") return v;
  if (v === null || v === undefined || v === "") return 0;
  var n = Number(v);
  return isFinite(n) ? n : 0;
}
function _intOrNull(v) {
  if (v === null || v === undefined || v === "") return null;
  var n = Number(v);
  return isFinite(n) ? n : null;
}

function _coercePayloadString(payload) {
  if (typeof payload === "string") return payload;
  if (Buffer.isBuffer(payload)) return payload.toString("utf8");
  // Objects serialize via safeJson (proto-safe, stable) so the signed body is
  // deterministic and the receiver verifies the same bytes we signed.
  return safeJson.stringify(payload);
}

/**
 * @primitive b.webhook.dispatcher
 * @signature b.webhook.dispatcher(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.webhook.signer, b.webhook.verify, b.outbox.create, b.nonceStore.create
 *
 * Build a durable signed-webhook delivery store backed by the operator's
 * `b.externalDb`. The returned object exposes:
 *
 *   - `declareSchema(xdb?)` — idempotent `CREATE TABLE` for the endpoints +
 *     deliveries tables (run once at boot, like `b.outbox.declareSchema`).
 *   - `registerEndpoint({ endpointId, url, eventTypes, secret })` — persist a
 *     subscriber. The URL is validated through `b.safeUrl` (SSRF destinations
 *     refused); the secret is sealed at rest with `b.vault.seal`. `eventTypes`
 *     is an array of event names, or `["*"]` to receive every event.
 *   - `removeEndpoint(endpointId)` / `listEndpoints()`.
 *   - `dispatch(eventType, payload)` — fan the event out to every subscribed
 *     endpoint as its own durable delivery row, sign each via
 *     `b.webhook.signer`, and attempt delivery once inline. Returns
 *     `{ delivered, failed, deliveries: [...] }`.
 *   - `processRetries()` — poll/alarm entry point: claim every delivery whose
 *     `next_attempt_at` is due, re-attempt, back off on the `b.outbox` curve,
 *     and dead-letter after `maxAttempts`. Reaps deliveries stranded
 *     in-flight by a crashed worker. Returns `{ attempted, delivered, dead }`.
 *   - `deliveries.list({ endpointId?, status?, limit? })` / `deliveries.get(id)`
 *     / `deliveries.retry(id)` — operator-console surface.
 *   - `dlq.list({ limit? })` / `dlq.replay(id)` — dead-letter inspect + replay.
 *
 * Each delivery carries a stable `X-Webhook-Delivery-Id` (so a re-delivery is
 * deduped by the receiver, not rejected as a replay) plus the signer's fresh
 * per-attempt nonce in the signature (replay defense at the signature layer).
 *
 * @opts
 *   externalDb:      b.externalDb,        // required — storage backend
 *   endpointsTable:  string,              // default frameworkSchema.tableName("webhook_endpoints")
 *   deliveriesTable: string,              // default frameworkSchema.tableName("webhook_deliveries")
 *   maxAttempts:     number,              // default 8 → then dead-letter
 *   retryBackoff:    { initialMs, maxMs, factor },   // default 5s / 60min / 2x
 *   claimReclaimMs:  number,              // default 5 min stale-in-flight lease
 *   batchSize:       number,              // default 100 deliveries per processRetries
 *   signatureHeader: string,              // forwarded to b.webhook.signer
 *   allowedProtocols: object,             // b.safeUrl protocol set (default ALLOW_HTTP_TLS)
 *   allowInternalDestinations: boolean,   // default false — refuse SSRF (private/loopback/metadata)
 *   httpRequest:     function,            // (url, body, headers) → { status } — inject for tests
 *   now:             function,            // clock injection → ms epoch
 *   dnsLookup:       function,            // (host) → [{ address, family }] — override the SSRF destination resolver
 *
 * @example
 *   var wd = b.webhook.dispatcher({ externalDb: b.externalDb });
 *   await wd.declareSchema();
 *   await wd.registerEndpoint({
 *     endpointId: "acct_42",
 *     url:        "https://partner.example/hooks",
 *     eventTypes: ["invoice.paid", "invoice.refunded"],
 *     secret:     "whsec_partner_secret",
 *   });
 *   await wd.dispatch("invoice.paid", { id: "inv_1", amount: 4200 });
 *   // later, from a cron / alarm:
 *   await wd.processRetries();
 */
function dispatcher(opts) {
  validateOpts.shape(opts, {
    externalDb:      { methods: ["query", "transaction"] },
    endpointsTable:  "optional-string",
    deliveriesTable: "optional-string",
    maxAttempts:     "optional-positive-finite",
    batchSize:       "optional-positive-finite",
    claimReclaimMs:  "optional-positive-finite",
    retryBackoff:    { optional: true, shape: {
      initialMs: "optional-positive-finite",
      maxMs:     "optional-positive-finite",
      factor:    "optional-positive-finite",
    } },
    signatureHeader:           "optional-string",
    allowedProtocols:          "optional-plain-object",
    allowInternalDestinations: "optional-boolean",
    httpRequest:               "optional-function",
    now:                       "optional-function",
    dnsLookup:                 "optional-function",
  }, "webhook.dispatcher", WebhookDispatcherError, "webhook-dispatcher/bad-opts");
  var externalDb = opts.externalDb;
  var endpointsTable = _validateTableName(
    opts.endpointsTable || frameworkSchema.tableName("webhook_endpoints"),
    "dispatcher: endpointsTable");
  var deliveriesTable = _validateTableName(
    opts.deliveriesTable || frameworkSchema.tableName("webhook_deliveries"),
    "dispatcher: deliveriesTable");

  var maxAttempts    = opts.maxAttempts   || DEFAULT_MAX_ATTEMPTS;
  var batchSize      = opts.batchSize     || DEFAULT_BATCH_SIZE;
  var claimReclaimMs = opts.claimReclaimMs || DEFAULT_CLAIM_RECLAIM_MS;

  var backoff = opts.retryBackoff || {};
  var backoffInitial = backoff.initialMs || DEFAULT_BACKOFF_INITIAL;
  var backoffMax     = backoff.maxMs     || DEFAULT_BACKOFF_MAX;
  var backoffFactor  = backoff.factor    || DEFAULT_BACKOFF_FACTOR;

  var allowedProtocols = opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var signatureHeader = opts.signatureHeader || null;
  // Default-secure: refuse delivery to internal IP ranges. An operator whose
  // subscribers genuinely live on a private network opts in explicitly.
  var allowInternal = opts.allowInternalDestinations === true;
  var clock = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  // Refuse an SSRF / malformed destination: protocol + userinfo via safeUrl,
  // IP classification (private / loopback / metadata) via ssrfGuard. Async
  // because the IP check resolves the host. Throws a dispatcher-coded error.
  async function _assertSafeDestination(url, where) {
    safeUrl.parse(url, { allowedProtocols: allowedProtocols, errorClass: WebhookDispatcherError });
    var checkOpts = { allowInternal: allowInternal };
    if (typeof opts.dnsLookup === "function") checkOpts.dnsLookup = opts.dnsLookup;
    try {
      await ssrfGuard().checkUrl(url, checkOpts);
    } catch (e) {
      if (e && e.isSsrfError) {
        // A genuine SSRF refusal (destination resolved to a private / loopback /
        // metadata IP, or a rebind since registration) is PERMANENT — dead-letter.
        throw _err("webhook-dispatcher/ssrf-refused", where + ": " + e.message);
      }
      // A non-SsrfError from checkUrl is a raw resolver / network fault during
      // host resolution (EAI_AGAIN, ETIMEDOUT, SERVFAIL, ...). Re-throw it as-is
      // so the caller classifies it as TRANSIENT (retry), not permanent — a
      // transient DNS blip must not dead-letter a delivery.
      throw e;
    }
  }

  // Default transport: a real signed POST through the framework http client.
  // Injectable so a test (or a non-HTTP transport) substitutes its own.
  var httpRequest = opts.httpRequest || function (url, body, headers) {
    return httpClient().request({
      method:           "POST",
      url:              url,
      headers:          headers,
      body:             body,
      allowedProtocols: allowedProtocols,
      errorClass:       WebhookDispatcherError,
    }).then(function (res) {
      return { status: (res && (res.statusCode || res.status)) || 0 };
    });
  };

  // Per-secret signer cache — one b.webhook.signer bound to each endpoint
  // secret, keyed by the (unsealed) secret so re-deliveries reuse it.
  var _signerCache = Object.create(null);
  function _signerFor(secret) {
    if (_signerCache[secret]) return _signerCache[secret];
    var s = webhookSign().signer({
      algo:            SIGNER_ALGO,
      keys:            { v1: secret },
      signatureHeader: signatureHeader || undefined,
    });
    _signerCache[secret] = s;
    return s;
  }

  function _backoffMs(attempts) {
    var ms = backoffInitial * Math.pow(backoffFactor, Math.max(0, attempts - 1));
    if (ms > backoffMax) ms = backoffMax;
    return ms;
  }

  function _nowDate() { return new Date(clock()); }

  // ---- schema ----
  async function declareSchema(xdb) {
    var target = xdb || externalDb;
    var dialect = _sqlDialect(target);
    var tsType = dialect === "postgres" ? "TIMESTAMPTZ" : "TIMESTAMP";
    var endpointsDdl = sql.toExternalSql(sql.createTable(endpointsTable, [
      { name: "id",            serial: true },
      { name: "endpoint_id",   type: "VARCHAR(255)", notNull: true },
      { name: "url",           type: "TEXT",         notNull: true },
      { name: "event_types",   type: "TEXT",         notNull: true },
      { name: "secret_sealed", type: "TEXT",         notNull: true },
      { name: "disabled",      type: "INTEGER",      notNull: true, default: 0 },
      { name: "created_at",    type: tsType,         notNull: true },
    ], { dialect: dialect }), dialect);
    var endpointsIdx = sql.toExternalSql(sql.createIndex(endpointsTable + "_eid_idx",
      endpointsTable, ["endpoint_id"], { dialect: dialect }), dialect);

    var deliveriesDdl = sql.toExternalSql(sql.createTable(deliveriesTable, [
      { name: "id",              serial: true },
      { name: "delivery_id",     type: "VARCHAR(64)",  notNull: true },
      { name: "endpoint_id",     type: "VARCHAR(255)", notNull: true },
      { name: "url",             type: "TEXT",         notNull: true },
      { name: "event_type",      type: "VARCHAR(255)", notNull: true },
      { name: "payload",         type: "TEXT",         notNull: true },
      { name: "idempotency_id",  type: "VARCHAR(64)",  notNull: true },
      { name: "status",          type: "VARCHAR(16)",  notNull: true, default: "pending" },
      { name: "attempts",        type: "INTEGER",      notNull: true, default: 0 },
      { name: "next_attempt_at", type: tsType,         notNull: true },
      { name: "claimed_at",      type: tsType },
      { name: "delivered_at",    type: tsType },
      { name: "response_status", type: "INTEGER" },
      { name: "last_error",      type: "TEXT" },
      { name: "created_at",      type: tsType,         notNull: true },
    ], { dialect: dialect }), dialect);
    // Index on the due-pending pool the retry poller scans. Postgres/SQLite
    // get a PARTIAL index (status = 'pending'); MySQL has no partial indexes
    // (sql.createIndex refuses `where` for the mysql dialect), so it gets a
    // plain index on next_attempt_at — the processRetries query still filters
    // status = 'pending', so correctness is unchanged, only the index is a
    // touch less selective.
    var deliveriesIdxOpts = { dialect: dialect };
    if (dialect !== "mysql") deliveriesIdxOpts.where = "status = 'pending'";
    var deliveriesIdx = sql.toExternalSql(sql.createIndex(deliveriesTable + "_pending_idx",
      deliveriesTable, ["next_attempt_at"], deliveriesIdxOpts), dialect);

    await target.query(endpointsDdl.sql, endpointsDdl.params);
    await target.query(endpointsIdx.sql, endpointsIdx.params);
    await target.query(deliveriesDdl.sql, deliveriesDdl.params);
    await target.query(deliveriesIdx.sql, deliveriesIdx.params);
  }

  // ---- endpoint registration ----
  async function registerEndpoint(ep) {
    validateOpts.shape(ep, {
      endpointId: "required-string",
      url:        "required-string",
      secret:     "required-string",
      eventTypes: "optional-string-array",   // element validation; required-non-empty checked below
    }, "dispatcher.registerEndpoint", WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    if (!Array.isArray(ep.eventTypes) || ep.eventTypes.length === 0) {
      throw _err("webhook-dispatcher/bad-opts",
        "registerEndpoint: eventTypes must be a non-empty array of event names (or [\"*\"])");
    }
    // Refuse an SSRF / malformed destination at registration time — fail fast,
    // before a single delivery row is written.
    await _assertSafeDestination(ep.url, "registerEndpoint");

    var dialect = _sqlDialect(externalDb);
    var sealedSecret = vault().seal(ep.secret);
    var stmt = sql.insert(endpointsTable, { dialect: dialect })
      .values({
        endpoint_id:   ep.endpointId,
        url:           ep.url,
        event_types:   safeJson.stringify(ep.eventTypes),
        secret_sealed: sealedSecret,
        disabled:      0,
        created_at:    _nowDate(),
      })
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    _emitAudit("webhook.dispatcher.endpoint.register", "success",
      { endpointId: ep.endpointId, eventTypes: ep.eventTypes });
    return { endpointId: ep.endpointId };
  }

  async function removeEndpoint(endpointId) {
    validateOpts.requireNonEmptyString(endpointId, "removeEndpoint: endpointId",
      WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.delete(endpointsTable, { dialect: dialect })
      .where("endpoint_id", endpointId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    return { endpointId: endpointId, removed: true };
  }

  async function listEndpoints() {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(endpointsTable, { dialect: dialect })
      .columns(["endpoint_id", "url", "event_types", "disabled", "created_at"])
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return ((res && res.rows) || []).map(function (r) {
      return {
        endpointId: r.endpoint_id,
        url:        r.url,
        eventTypes: safeJson.parse(r.event_types),
        disabled:   _isTruthy(r.disabled),
        createdAt:  r.created_at,
      };
    });
  }

  // Load every enabled endpoint subscribed to eventType. event_types is a JSON
  // array stored as TEXT (portable across the three dialects); membership is
  // resolved in JS because a portable JSON-contains predicate doesn't exist
  // across sqlite / postgres / mysql. The endpoint count for a single tenant's
  // webhook fan-out is modest, so the full scan is acceptable.
  async function _subscribedEndpoints(eventType) {
    var all = await listEndpoints();
    return all.filter(function (e) {
      if (e.disabled) return false;
      var types = e.eventTypes || [];
      return types.indexOf(eventType) !== -1 || types.indexOf(WILDCARD_EVENT) !== -1;
    });
  }

  async function _loadEndpointRow(endpointId) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(endpointsTable, { dialect: dialect })
      .columns(["endpoint_id", "url", "secret_sealed", "disabled"])
      .where("endpoint_id", endpointId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return (res && res.rows && res.rows[0]) || null;
  }

  // ---- dispatch / delivery ----
  async function dispatch(eventType, payload) {
    validateOpts.requireNonEmptyString(eventType, "dispatch: eventType",
      WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    if (payload === undefined || payload === null) {
      throw _err("webhook-dispatcher/bad-opts", "dispatch: payload required");
    }
    var bodyStr = _coercePayloadString(payload);
    var endpoints = await _subscribedEndpoints(eventType);
    var dialect = _sqlDialect(externalDb);
    var results = [];
    for (var i = 0; i < endpoints.length; i += 1) {
      var ep = endpoints[i];
      var deliveryId = bCrypto.generateToken(DELIVERY_ID_BYTES);
      var idempotencyId = bCrypto.generateToken(DELIVERY_ID_BYTES);
      // Insert already CLAIMED for the inline attempt (status 'in-flight' +
      // claimed_at = now). processRetries() only claims status='pending' rows,
      // so a poller running during the slow inline POST cannot grab this row
      // and double-deliver it. The inline _attemptDelivery transitions it to
      // delivered / pending(+backoff) / dead; if this process dies mid-POST,
      // _reapStaleInflight reclaims it after claimReclaimMs.
      var insertStmt = sql.insert(deliveriesTable, { dialect: dialect })
        .values({
          delivery_id:     deliveryId,
          endpoint_id:     ep.endpointId,
          url:             ep.url,
          event_type:      eventType,
          payload:         bodyStr,
          idempotency_id:  idempotencyId,
          status:          "in-flight",
          attempts:        0,
          next_attempt_at: _nowDate(),
          claimed_at:      _nowDate(),
          created_at:      _nowDate(),
        })
        .toExternalSql(dialect);
      await externalDb.query(insertStmt.sql, insertStmt.params);
      // Best-effort first attempt inline; on failure it is scheduled for retry.
      var r = await _attemptDelivery(deliveryId);
      results.push(r);
    }
    return {
      delivered: results.filter(function (r) { return r.ok; }).length,
      failed:    results.filter(function (r) { return !r.ok; }).length,
      deliveries: results,
    };
  }

  async function _loadDelivery(deliveryId) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(deliveriesTable, { dialect: dialect })
      .columns(["delivery_id", "endpoint_id", "url", "event_type", "payload",
                "idempotency_id", "status", "attempts"])
      .where("delivery_id", deliveryId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return (res && res.rows && res.rows[0]) || null;
  }

  // Attempt one delivery by id: sign with the endpoint's sealed secret, POST,
  // and transition the row on the outcome (delivered / retry / dead).
  async function _attemptDelivery(deliveryId) {
    var row = await _loadDelivery(deliveryId);
    if (!row) return { deliveryId: deliveryId, ok: false, status: 0, error: "delivery row not found" };
    var epRow = await _loadEndpointRow(row.endpoint_id);
    if (!epRow) {
      await _markDead(deliveryId, _intOf(row.attempts) + 1, "endpoint no longer registered");
      return { deliveryId: deliveryId, ok: false, status: 0, dead: true, error: "endpoint missing" };
    }
    var attemptNo = _intOf(row.attempts) + 1;
    // Re-validate the destination at delivery time — a host that resolved
    // public at registration but rebound to an internal IP is refused here.
    // An SSRF refusal / malformed URL is PERMANENT (won't fix on retry) →
    // dead-letter immediately. Permanence is decided HERE by the failure
    // CLASS, not by err.permanent: the transport (httpClient) errors below
    // are thrown with WebhookDispatcherError, which is alwaysPermanent, so
    // reading err.permanent would mis-mark a timeout / network error / 5xx
    // as permanent and dead-letter it on the first attempt.
    try {
      await _assertSafeDestination(row.url, "deliver");
    } catch (err) {
      // Permanence by CLASS: a genuine SSRF refusal or malformed URL surfaces
      // as a WebhookDispatcherError (won't fix on retry) -> dead-letter. A
      // resolver fault from the host-resolution step carries the framework's
      // own terminal-vs-transient verdict on err.permanent — honor it so a
      // PERMANENT lookup failure (no addresses / a removed record: the
      // dns/no-result DnsError) dead-letters, while a transient one (a lookup
      // timeout, a system/resolve failure) is retried on the backoff curve
      // (capped at maxAttempts) like every other transport error below. A raw
      // resolver error without that verdict (EAI_AGAIN from the native
      // fallback, an injected resolver) is treated as transient — a DNS blip
      // must not dead-letter a delivery.
      var permanent = (err instanceof WebhookDispatcherError) || (err && err.permanent === true);
      return await _onFailure(deliveryId, attemptNo,
        (err && err.message) || String(err), permanent);
    }
    // Sign + POST. Transport errors (network, TLS, timeout, DNS) and any
    // non-2xx HTTP status are TRANSIENT — back off and retry (capped at
    // maxAttempts, after which _onFailure dead-letters).
    try {
      var secret = vault().unseal(epRow.secret_sealed);
      var signer = _signerFor(secret);
      var signed = signer.sign(row.payload);
      var headers = Object.assign({}, signed.headers, {
        "Content-Type":             "application/json",
        "X-Webhook-Delivery-Id":    row.delivery_id,
        "X-Webhook-Event-Type":     row.event_type,
        "X-Webhook-Idempotency-Id": row.idempotency_id,
      });
      var result = await httpRequest(row.url, row.payload, headers);
      var status = (result && (result.status || result.statusCode)) || 0;
      if (status >= HTTP_OK_MIN && status < HTTP_OK_MAX) {
        await _markDelivered(deliveryId, attemptNo, status);
        return { deliveryId: deliveryId, ok: true, status: status };
      }
      return await _onFailure(deliveryId, attemptNo, "delivery returned HTTP " + status, false);
    } catch (err) {
      return await _onFailure(deliveryId, attemptNo,
        (err && err.message) || String(err), false);
    }
  }

  async function _markDelivered(deliveryId, attemptNo, status) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(deliveriesTable, { dialect: dialect })
      .set({
        status:          "delivered",
        attempts:        attemptNo,
        delivered_at:    _nowDate(),
        response_status: status,
        claimed_at:      null,
      })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
  }

  // A failed attempt: dead-letter once attempts reach maxAttempts OR the error
  // is permanent (won't fix on retry), else reschedule on the backoff curve.
  async function _onFailure(deliveryId, attemptNo, errMsg, permanent) {
    if (permanent || attemptNo >= maxAttempts) {
      await _markDead(deliveryId, attemptNo, errMsg);
      return { deliveryId: deliveryId, ok: false, status: 0, dead: true, error: errMsg };
    }
    var dialect = _sqlDialect(externalDb);
    var nextAt = new Date(clock() + _backoffMs(attemptNo));
    var stmt = sql.update(deliveriesTable, { dialect: dialect })
      .set({
        status:          "pending",
        attempts:        attemptNo,
        next_attempt_at: nextAt,
        last_error:      errMsg,
        claimed_at:      null,
      })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    return { deliveryId: deliveryId, ok: false, status: 0, error: errMsg, nextAttemptAt: nextAt };
  }

  async function _markDead(deliveryId, attemptNo, errMsg) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(deliveriesTable, { dialect: dialect })
      .set({ status: "dead", attempts: attemptNo, last_error: errMsg, claimed_at: null })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    _emitAudit("webhook.dispatcher.dead-letter", "failure",
      { deliveryId: deliveryId, attempts: attemptNo, error: errMsg });
  }

  // ---- retry poller ----
  // Reset deliveries stranded 'in-flight' by a crashed worker (claimed but
  // never resolved) back to 'pending' once the lease expires — the
  // at-least-once guarantee b.outbox's reaper proved is the framework's job.
  async function _reapStaleInflight() {
    var dialect = _sqlDialect(externalDb);
    var cutoff = new Date(clock() - claimReclaimMs);
    var stmt = sql.update(deliveriesTable, { dialect: dialect })
      .set({ status: "pending", claimed_at: null })
      .whereRaw("status = 'in-flight'", [], { allowLiterals: true })
      .whereRaw("(claimed_at IS NULL OR claimed_at <= ?)", [cutoff])
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
  }

  // FOR UPDATE SKIP LOCKED is Postgres / MySQL-only; sqlite is a single writer
  // with no row lock. Decide on the NORMALIZED dialect — the same resolution the
  // SQL builders use (_sqlDialect maps the `postgresql` alias to `postgres`) — so
  // the lock decision can never disagree with the rendered SQL: a `postgresql`
  // caller emits Postgres SQL AND row-locks, never Postgres SQL with the sqlite
  // mark-then-reselect fallback (which would reopen the double-claim race).
  function _supportsForUpdateSkipLocked() {
    var d = _sqlDialect(externalDb);
    return d === "postgres" || d === "mysql";
  }

  // Claim due-pending deliveries by flipping them to 'in-flight' inside a
  // transaction, then attempt each claimed delivery. On Postgres / MySQL the
  // SELECT row-locks the due rows via FOR UPDATE SKIP LOCKED, so concurrent
  // retry pollers see DISJOINT sets — the rows this poller selected are exactly
  // the rows it owns. sqlite (single writer, no row lock) falls back to a
  // guarded mark-then-reselect: the UPDATE gated on status='pending' transitions
  // each row once, and we re-read the in-flight rows we flipped. Without the
  // SKIP LOCKED branch, two pollers under READ COMMITTED both reselect the same
  // in-flight row (the loser's UPDATE matches zero rows, but the reselect-by-id
  // re-reads the row the winner flipped) and double-deliver it in one cycle.
  async function processRetries() {
    await _reapStaleInflight();
    var dialect = _sqlDialect(externalDb);
    var supportsSkipLocked = _supportsForUpdateSkipLocked();
    var claimed = await externalDb.transaction(async function (xdb) {
      var nowDate = _nowDate();
      var selBuilder = sql.select(deliveriesTable, { dialect: dialect })
        .columns(["delivery_id"])
        .whereRaw("status = 'pending'", [], { allowLiterals: true })
        .whereRaw("next_attempt_at <= ?", [nowDate])
        .orderBy("next_attempt_at")
        .limit(batchSize);
      if (supportsSkipLocked) selBuilder.forUpdate({ skipLocked: true });
      var sel = selBuilder.toExternalSql(dialect);
      var rows = await xdb.query(sel.sql, sel.params);
      var ids = ((rows && rows.rows) || []).map(function (r) { return r.delivery_id; });
      if (ids.length === 0) return [];
      var mark = sql.update(deliveriesTable, { dialect: dialect })
        .set({ status: "in-flight", claimed_at: _nowDate() })
        .whereRaw("status = 'pending'", [], { allowLiterals: true })
        .whereInArray("delivery_id", ids)
        .toExternalSql(dialect);
      await xdb.query(mark.sql, mark.params);
      // Postgres / MySQL: the FOR UPDATE SKIP LOCKED SELECT already gave us an
      // exclusively-locked, disjoint set, so the selected ids ARE our claim.
      if (supportsSkipLocked) return ids;
      // sqlite / other: no row lock, so re-read which rows WE flipped. The
      // single writer serializes the gated UPDATE, so the in-flight rows in our
      // id set are ours.
      var after = sql.select(deliveriesTable, { dialect: dialect })
        .columns(["delivery_id"])
        .whereRaw("status = 'in-flight'", [], { allowLiterals: true })
        .whereInArray("delivery_id", ids)
        .toExternalSql(dialect);
      var afterRows = await xdb.query(after.sql, after.params);
      return ((afterRows && afterRows.rows) || []).map(function (r) { return r.delivery_id; });
    });

    var attempted = 0, delivered = 0, dead = 0;
    for (var i = 0; i < claimed.length; i += 1) {
      var r = await _attemptDelivery(claimed[i]);
      attempted += 1;
      if (r.ok) delivered += 1;
      if (r.dead) dead += 1;
    }
    return { attempted: attempted, delivered: delivered, dead: dead };
  }

  // ---- operator-console surface ----
  function _mapDelivery(r) {
    return {
      deliveryId:     r.delivery_id,
      endpointId:     r.endpoint_id,
      eventType:      r.event_type,
      status:         r.status,
      attempts:       _intOf(r.attempts),
      nextAttemptAt:  r.next_attempt_at,
      deliveredAt:    r.delivered_at,
      responseStatus: _intOrNull(r.response_status),
      lastError:      r.last_error,
    };
  }

  var DELIVERY_VIEW_COLS = ["delivery_id", "endpoint_id", "event_type", "status",
    "attempts", "next_attempt_at", "delivered_at", "response_status", "last_error"];

  async function _listDeliveries(filter) {
    filter = filter || {};
    var dialect = _sqlDialect(externalDb);
    var builder = sql.select(deliveriesTable, { dialect: dialect }).columns(DELIVERY_VIEW_COLS);
    if (filter.endpointId) builder.where("endpoint_id", filter.endpointId);
    if (filter.status) builder.where("status", filter.status);
    builder.orderBy("id").limit(filter.limit || DEFAULT_BATCH_SIZE);
    var stmt = builder.toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return ((res && res.rows) || []).map(_mapDelivery);
  }

  async function _getDelivery(deliveryId) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(deliveriesTable, { dialect: dialect })
      .columns(DELIVERY_VIEW_COLS)
      .where("delivery_id", deliveryId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    var row = res && res.rows && res.rows[0];
    return row ? _mapDelivery(row) : null;
  }

  // Reset a delivery to the pending pool for an immediate re-attempt. Used by
  // both deliveries.retry (any status) and dlq.replay (dead → pending).
  async function _requeue(deliveryId) {
    validateOpts.requireNonEmptyString(deliveryId, "retry: deliveryId",
      WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(deliveriesTable, { dialect: dialect })
      .set({ status: "pending", attempts: 0, next_attempt_at: _nowDate(), claimed_at: null, last_error: null })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    return await _attemptDelivery(deliveryId);
  }

  function _emitAudit(action, outcome, metadata) {
    try {
      audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} });
    } catch (_e) { /* audit is a drop-silent hot-path sink — never crash the delivery */ }
    try {
      observability().safeEvent(action, 1, metadata || {});
    } catch (_e) { /* drop-silent */ }
  }

  return {
    declareSchema:   declareSchema,
    registerEndpoint: registerEndpoint,
    removeEndpoint:  removeEndpoint,
    listEndpoints:   listEndpoints,
    dispatch:        dispatch,
    processRetries:  processRetries,
    deliveries: {
      list:  _listDeliveries,
      get:   _getDelivery,
      retry: _requeue,
    },
    dlq: {
      list:   function (filter) {
        filter = filter || {};
        return _listDeliveries({ status: "dead", limit: filter.limit, endpointId: filter.endpointId });
      },
      replay: _requeue,
    },
    close: function () { _signerCache = Object.create(null); },
  };
}

function _isTruthy(v) { return v === true || v === 1 || v === "1" || v === "true"; }

module.exports = { dispatcher: dispatcher };
