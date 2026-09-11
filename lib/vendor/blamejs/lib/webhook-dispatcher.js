// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

var DEFAULT_MAX_ATTEMPTS      = 8;
var DEFAULT_BACKOFF_INITIAL   = C.TIME.seconds(5);
var DEFAULT_BACKOFF_MAX       = C.TIME.minutes(60);
var DEFAULT_BACKOFF_FACTOR    = 2;
var DEFAULT_CLAIM_RECLAIM_MS  = C.TIME.minutes(5);
var DEFAULT_BATCH_SIZE        = 100;
var SIGNER_ALGO               = "hmac-sha3-512";
var DELIVERY_ID_BYTES         = C.BYTES.bytes(16);
var WILDCARD_EVENT            = "*";

var HTTP_OK_MIN = 200;
var HTTP_OK_MAX = 300;

function _validateTableName(name, label) {
  validateOpts.requireNonEmptyString(name, label, WebhookDispatcherError, "webhook-dispatcher/bad-opts");
  safeSql.quoteIdentifier(name, undefined, { allowReserved: true });
  return name;
}

function _tableOpts(dialect) { return { dialect: dialect, quoteName: true }; }

function _foldTableForDialect(name, dialect) {
  return dialect === "postgres" ? String(name).toLowerCase() : name;
}

function _sqlDialect(externalDb) {
  var d = externalDb && externalDb.dialect;
  if (d === "postgres" || d === "postgresql") return "postgres";
  if (d === "mysql") return "mysql";
  return "sqlite";
}

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
  var _createDialect = _sqlDialect(externalDb);
  var endpointsTable = _foldTableForDialect(_validateTableName(
    opts.endpointsTable || frameworkSchema.tableName("webhook_endpoints"),
    "dispatcher: endpointsTable"), _createDialect);
  var deliveriesTable = _foldTableForDialect(_validateTableName(
    opts.deliveriesTable || frameworkSchema.tableName("webhook_deliveries"),
    "dispatcher: deliveriesTable"), _createDialect);

  var maxAttempts    = opts.maxAttempts   || DEFAULT_MAX_ATTEMPTS;
  var batchSize      = opts.batchSize     || DEFAULT_BATCH_SIZE;
  var claimReclaimMs = opts.claimReclaimMs || DEFAULT_CLAIM_RECLAIM_MS;

  var backoff = opts.retryBackoff || {};
  var backoffInitial = backoff.initialMs || DEFAULT_BACKOFF_INITIAL;
  var backoffMax     = backoff.maxMs     || DEFAULT_BACKOFF_MAX;
  var backoffFactor  = backoff.factor    || DEFAULT_BACKOFF_FACTOR;

  var allowedProtocols = opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var signatureHeader = opts.signatureHeader || null;
  var allowInternal = opts.allowInternalDestinations === true;
  var clock = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  async function _assertSafeDestination(url, where) {
    safeUrl.parse(url, { allowedProtocols: allowedProtocols, errorClass: WebhookDispatcherError });
    var checkOpts = { allowInternal: allowInternal };
    if (typeof opts.dnsLookup === "function") checkOpts.dnsLookup = opts.dnsLookup;
    try {
      await ssrfGuard().checkUrl(url, checkOpts);
    } catch (e) {
      if (e && e.isSsrfError) {
        throw _err("webhook-dispatcher/ssrf-refused", where + ": " + e.message);
      }
      throw e;
    }
  }

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
    ], _tableOpts(dialect)), dialect);
    var endpointsIdx = sql.toExternalSql(sql.createIndex(endpointsTable + "_eid_idx",
      endpointsTable, ["endpoint_id"], _tableOpts(dialect)), dialect);

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
    ], _tableOpts(dialect)), dialect);
    var deliveriesIdxOpts = _tableOpts(dialect);
    if (dialect !== "mysql") deliveriesIdxOpts.where = "status = 'pending'";
    var deliveriesIdx = sql.toExternalSql(sql.createIndex(deliveriesTable + "_pending_idx",
      deliveriesTable, ["next_attempt_at"], deliveriesIdxOpts), dialect);

    await target.query(endpointsDdl.sql, endpointsDdl.params);
    await target.query(endpointsIdx.sql, endpointsIdx.params);
    await target.query(deliveriesDdl.sql, deliveriesDdl.params);
    await target.query(deliveriesIdx.sql, deliveriesIdx.params);
  }

  async function registerEndpoint(ep) {
    validateOpts.shape(ep, {
      endpointId: "required-string",
      url:        "required-string",
      secret:     "required-string",
      eventTypes: "optional-string-array",
    }, "dispatcher.registerEndpoint", WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    if (!Array.isArray(ep.eventTypes) || ep.eventTypes.length === 0) {
      throw _err("webhook-dispatcher/bad-opts",
        "registerEndpoint: eventTypes must be a non-empty array of event names (or [\"*\"])");
    }
    await _assertSafeDestination(ep.url, "registerEndpoint");

    var dialect = _sqlDialect(externalDb);
    var sealedSecret = vault().seal(ep.secret);
    var stmt = sql.insert(endpointsTable, _tableOpts(dialect))
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
    var stmt = sql.delete(endpointsTable, _tableOpts(dialect))
      .where("endpoint_id", endpointId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    return { endpointId: endpointId, removed: true };
  }

  async function listEndpoints() {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(endpointsTable, _tableOpts(dialect))
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
    var stmt = sql.select(endpointsTable, _tableOpts(dialect))
      .columns(["endpoint_id", "url", "secret_sealed", "disabled"])
      .where("endpoint_id", endpointId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return (res && res.rows && res.rows[0]) || null;
  }

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
      var insertStmt = sql.insert(deliveriesTable, _tableOpts(dialect))
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
    var stmt = sql.select(deliveriesTable, _tableOpts(dialect))
      .columns(["delivery_id", "endpoint_id", "url", "event_type", "payload",
                "idempotency_id", "status", "attempts"])
      .where("delivery_id", deliveryId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return (res && res.rows && res.rows[0]) || null;
  }

  async function _attemptDelivery(deliveryId) {
    var row = await _loadDelivery(deliveryId);
    if (!row) return { deliveryId: deliveryId, ok: false, status: 0, error: "delivery row not found" };
    var epRow = await _loadEndpointRow(row.endpoint_id);
    if (!epRow) {
      await _markDead(deliveryId, _intOf(row.attempts) + 1, "endpoint no longer registered");
      return { deliveryId: deliveryId, ok: false, status: 0, dead: true, error: "endpoint missing" };
    }
    var attemptNo = _intOf(row.attempts) + 1;
    try {
      await _assertSafeDestination(row.url, "deliver");
    } catch (err) {
      var permanent = (err instanceof WebhookDispatcherError) || (err && err.permanent === true);
      return await _onFailure(deliveryId, attemptNo,
        (err && err.message) || String(err), permanent);
    }
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
    var stmt = sql.update(deliveriesTable, _tableOpts(dialect))
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

  async function _onFailure(deliveryId, attemptNo, errMsg, permanent) {
    if (permanent || attemptNo >= maxAttempts) {
      await _markDead(deliveryId, attemptNo, errMsg);
      return { deliveryId: deliveryId, ok: false, status: 0, dead: true, error: errMsg };
    }
    var dialect = _sqlDialect(externalDb);
    var nextAt = new Date(clock() + _backoffMs(attemptNo));
    var stmt = sql.update(deliveriesTable, _tableOpts(dialect))
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
    var stmt = sql.update(deliveriesTable, _tableOpts(dialect))
      .set({ status: "dead", attempts: attemptNo, last_error: errMsg, claimed_at: null })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    _emitAudit("webhook.dispatcher.dead-letter", "failure",
      { deliveryId: deliveryId, attempts: attemptNo, error: errMsg });
  }

  async function _reapStaleInflight() {
    var dialect = _sqlDialect(externalDb);
    var cutoff = new Date(clock() - claimReclaimMs);
    var stmt = sql.update(deliveriesTable, _tableOpts(dialect))
      .set({ status: "pending", claimed_at: null })
      .whereRaw("status = 'in-flight'", [], { allowLiterals: true })
      .whereRaw("(claimed_at IS NULL OR claimed_at <= ?)", [cutoff])
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
  }

  function _supportsForUpdateSkipLocked() {
    var d = _sqlDialect(externalDb);
    return d === "postgres" || d === "mysql";
  }

  async function processRetries() {
    await _reapStaleInflight();
    var dialect = _sqlDialect(externalDb);
    var supportsSkipLocked = _supportsForUpdateSkipLocked();
    var claimed = await externalDb.transaction(async function (xdb) {
      var nowDate = _nowDate();
      var selBuilder = sql.select(deliveriesTable, _tableOpts(dialect))
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
      var mark = sql.update(deliveriesTable, _tableOpts(dialect))
        .set({ status: "in-flight", claimed_at: _nowDate() })
        .whereRaw("status = 'pending'", [], { allowLiterals: true })
        .whereInArray("delivery_id", ids)
        .toExternalSql(dialect);
      await xdb.query(mark.sql, mark.params);
      if (supportsSkipLocked) return ids;
      var after = sql.select(deliveriesTable, _tableOpts(dialect))
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
    var builder = sql.select(deliveriesTable, _tableOpts(dialect)).columns(DELIVERY_VIEW_COLS);
    if (filter.endpointId) builder.where("endpoint_id", filter.endpointId);
    if (filter.status) builder.where("status", filter.status);
    builder.orderBy("id").limit(filter.limit || DEFAULT_BATCH_SIZE);
    var stmt = builder.toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return ((res && res.rows) || []).map(_mapDelivery);
  }

  async function _getDelivery(deliveryId) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(deliveriesTable, _tableOpts(dialect))
      .columns(DELIVERY_VIEW_COLS)
      .where("delivery_id", deliveryId)
      .limit(1)
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    var row = res && res.rows && res.rows[0];
    return row ? _mapDelivery(row) : null;
  }

  async function _requeue(deliveryId) {
    validateOpts.requireNonEmptyString(deliveryId, "retry: deliveryId",
      WebhookDispatcherError, "webhook-dispatcher/bad-opts");
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(deliveriesTable, _tableOpts(dialect))
      .set({ status: "pending", attempts: 0, next_attempt_at: _nowDate(), claimed_at: null, last_error: null })
      .where("delivery_id", deliveryId)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    return await _attemptDelivery(deliveryId);
  }

  function _emitAudit(action, outcome, metadata) {
    // Drop-silent hot-path sinks: metadata is always an object at both call
    /* c8 ignore start */
    try {
      audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} });
    } catch (_e) { /* audit is a drop-silent hot-path sink — never crash the delivery */ }
    try {
      observability().safeEvent(action, 1, metadata || {});
    } catch (_e) { /* drop-silent */ }
    /* c8 ignore stop */
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
