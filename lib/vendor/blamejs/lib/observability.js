"use strict";
/**
 * @module b.observability
 * @nav    Observability
 * @title  Observability
 *
 * @intro
 *   Combined metrics + tracing tap surface — every framework hot
 *   path uses this one primitive to emit both a span and a counter
 *   bump in one call, with redact-aware metadata and breadcrumb
 *   integration into the audit chain.
 *
 *   `tap(name, attrs, fn)` wraps `fn` in a tracing span (via
 *   `b.tracing.tap`) and bumps a metrics counter named `name` (via
 *   `b.metrics.tap`) when the function settles, on both the success
 *   and failure branches. `event(name, value, labels)` is the
 *   fire-and-forget shape — fires the counter only, no span — and
 *   `safeEvent` wraps it in a try/catch so per-request hot paths
 *   can't crash the request that triggered them when the metrics
 *   registry has a misconfigured counter or label name.
 *
 *   `timed(name, fn, labels)` measures wall-clock duration of an
 *   operation and emits a counter event with `outcome: "ok"` /
 *   `"fail"` plus `duration_ms` in the labels — the standard pattern
 *   for per-call SLO tracking. `SEMCONV` carries the OTel
 *   semantic-convention attribute names (1.27+ stable namespace) so
 *   operators wiring the framework's tap into an OTel SDK don't
 *   maintain an aliasing table.
 *
 *   `traceContext.parse` / `traceContext.build` parse and emit the
 *   W3C `traceparent` header per RFC; `traceContext.parseTracestate`
 *   / `traceContext.buildTracestate` cover the `tracestate` companion
 *   header (32-entry / 512-char W3C cap). `baggage.parse` /
 *   `baggage.build` cover the W3C Baggage header for cross-service
 *   user context (tenant / region / experiment).
 *
 *   The drop-silent contract is intentional — observability runs in
 *   request hot paths where throwing on a misnamed metric would
 *   crash the request that triggered the emit. Bad input on
 *   `event` / `safeEvent` is dropped silently; bad input on `tap`
 *   throws at boot-time call sites where operators can fix typos
 *   before they corrupt the span tree AND the metrics route at the
 *   same time.
 *
 * @card
 *   Combined metrics + tracing tap surface — every framework hot path uses this one primitive to emit both a span and a counter bump in one call, with redact-aware metadata and breadcrumb integration into the audit chain.
 */
var C = require("./constants");
var lazyRequire = require("./lazy-require");

// safe-buffer can't be top-required: framework-error → observability →
// safe-buffer → framework-error forms a cycle. Lazy-loaded at first use.
var safeBuffer = lazyRequire(function () { return require("./safe-buffer"); });

var tracing = lazyRequire(function () { return require("./tracing"); });
var metrics = lazyRequire(function () { return require("./metrics"); });

// Operator-installed tap handler — wired via setTap(). When non-null,
// every observability event/tap dispatch routes here in addition to
// the framework's metrics module. Used by b.otelExport.create() so an
// OTLP/HTTP exporter receives the same hot-path counters the framework
// emits internally.
var _externalTap = null;

function _safeMetricsTap(name, value, labels) {
  try { metrics().tap(name, value, labels); }
  catch (_e) { /* boot-order tolerance — metrics may not be loaded */ }
  if (_externalTap !== null) {
    try { _externalTap(name, value, labels); }
    catch (_e) { /* operator-installed handler — drop-silent on its throws */ }
  }
}

// setTap — install an external tap handler. Operators wire this from
// `b.otelExport.create({...}).tapHandler` so every framework counter
// also lands in the operator's metrics pipeline.
//
// The handler signature mirrors metrics.tap: (name, value, labels).
// Pass null to remove the previously-installed handler.
/**
 * @primitive b.observability.setTap
 * @signature b.observability.setTap(handler)
 * @since     0.7.40
 * @related   b.observability.tap, b.observability.event
 *
 * Install an external tap handler that receives every
 * `(name, value, labels)` triple in addition to the framework's
 * metrics module. Wired by `b.otelExport.create()` so an OTLP/HTTP
 * exporter sees the same hot-path counters the framework emits
 * internally. Pass `null` to remove the previously-installed handler.
 *
 * @example
 *   b.observability.setTap(function (name, value, labels) {
 *     console.log("[obs]", name, value, labels);
 *   });
 *   b.observability.event("audit.record", 1,
 *     { action: "auth.login", outcome: "success" });
 *   // → "[obs] audit.record 1 { action: 'auth.login', outcome: 'success' }"
 *   b.observability.setTap(null);   // remove
 */
function setTap(handler) {
  if (handler !== null && typeof handler !== "function") {
    throw new TypeError("observability.setTap: handler must be a function or null, got " +
      typeof handler);
  }
  _externalTap = handler;
}

/**
 * @primitive b.observability.tap
 * @signature b.observability.tap(name, attrs, fn)
 * @since     0.7.0
 * @status    stable
 * @related   b.observability.event, b.tracing.tap, b.metrics.tap
 *
 * Wrap `fn` in a tracing span (via `b.tracing.tap`) and bump a
 * metrics counter named `name` (via `b.metrics.tap`) when the
 * function settles. The same `attrs` object becomes both span
 * attributes and metric labels. Counter fires on both the success
 * and failure paths so dashboards never miss a failure-rate
 * increment. The two-arg form `tap(name, fn)` skips attributes.
 * Throws on bad input — typos in `name` would silently corrupt both
 * the span tree and the metrics route, so this is a config-time
 * boundary.
 *
 * @example
 *   var rows = await b.observability.tap("db.query",
 *     { table: "users" },
 *     async function (span) {
 *       span.setAttribute("db.statement", "SELECT id FROM users");
 *       return await db.queryAll("SELECT id FROM users");
 *     });
 *   // span ended, framework_db_query_total bumped by 1
 */
function tap(name, attrs, fn) {
  if (typeof attrs === "function") { fn = attrs; attrs = null; }
  // Throw on bad input: tap is called from many call sites and a typo
  // in the name (e.g. variable holding undefined) silently corrupts
  // both the span tree AND the metrics counter route, with no obvious
  // symptom until somebody opens a dashboard. Throw at first call so
  // the operator catches it.
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("observability.tap: name must be a non-empty string, got " +
      (typeof name) + " " + JSON.stringify(name));
  }
  if (typeof fn !== "function") {
    throw new TypeError("observability.tap: fn must be a function, got " + (typeof fn));
  }
  return tracing().tap(name, attrs, function (span) {
    var ret;
    try {
      ret = fn(span);
    } catch (e) {
      _safeMetricsTap(name, 1, attrs);
      throw e;
    }
    if (ret && typeof ret.then === "function") {
      return ret.then(
        function (v) { _safeMetricsTap(name, 1, attrs); return v; },
        function (e) { _safeMetricsTap(name, 1, attrs); throw e; }
      );
    }
    _safeMetricsTap(name, 1, attrs);
    return ret;
  });
}

// Drop-silent on bad input by design: event is the fire-and-forget
// shape called from hot paths where throwing would crash the request
// that triggered it. Operators with a misnamed event see the missing
// counter, not a 500. metrics.tap performs its own label-name regex
// validation; an invalid call surfaces in the metrics module log, not
// via a thrown exception.
/**
 * @primitive b.observability.event
 * @signature b.observability.event(name, value, labels)
 * @since     0.7.0
 * @status    stable
 * @related   b.observability.tap, b.observability.safeEvent
 *
 * Fire-and-forget counter emit — same shape as `b.metrics.tap` but
 * routed through observability so the operator's external tap
 * (`setTap`) sees it too. Drop-silent on bad `name` by design: this
 * runs in hot paths where throwing on a typo would crash the request
 * that triggered the emit. Use `tap` instead when you also want a
 * span around the emitting code.
 *
 * @example
 *   b.observability.event("queue.enqueue", 1, { queueName: "email" });
 *   b.observability.event("error.construct", 1, { class: "DatabaseError" });
 */
function event(name, value, labels) {
  if (typeof name !== "string" || name.length === 0) return;
  _safeMetricsTap(name, value, labels);
}

// safeEvent — wraps `event` in a try/catch so callers on hot paths
// (per-request observability emits) can't crash the request that
// triggered them when the metrics registry has a misconfigured
// counter or label name. Replaces the per-file `_emitEvent` helper
// that 7+ modules previously duplicated.
/**
 * @primitive b.observability.safeEvent
 * @signature b.observability.safeEvent(name, value, labels)
 * @since     0.7.40
 * @related   b.observability.event, b.observability.tap
 *
 * Wraps `event` in a try/catch so per-request observability emits
 * cannot crash the request that triggered them when the metrics
 * registry has a misconfigured counter or label name. Replaces the
 * per-file `_emitEvent` helper that several modules previously
 * duplicated.
 *
 * @example
 *   // Inside a request handler — even with a typo in label name,
 *   // the request still completes.
 *   b.observability.safeEvent("auth.attempt", 1, { outcome: "success" });
 */
function safeEvent(name, value, labels) {
  try { event(name, value, labels); }
  catch (_e) { /* hot-path observability sink — drops silent on internal throws */ }
}

// timed — convenience wrapper that measures wall-clock duration of a
// sync or async operation and emits a counter event with
// duration_ms in the labels. Returns the wrapped function's return
// value verbatim; rethrows on error after emitting the failure event
// with outcome: "fail".
//
//   var rows = await b.observability.timed("db.query", async function () {
//     return await db.query("SELECT * FROM users");
//   }, { [SEMCONV.DB_OPERATION_NAME]: "select" });
//
// On success: emits `<name>` with { ...labels, outcome: "ok",
// duration_ms }. On throw: emits with outcome: "fail".
//
// The operation name MUST be a stable string (not derived from input)
// to keep the metric cardinality bounded; operators dynamically
// scope-naming via prefix should use the labels parameter instead.
/**
 * @primitive b.observability.timed
 * @signature b.observability.timed(name, fn, labels)
 * @since     0.7.40
 * @status    stable
 * @related   b.observability.event, b.observability.tap
 *
 * Measure wall-clock duration of a sync or async operation and emit
 * a counter event with `outcome: "ok"` / `"fail"` plus `duration_ms`
 * in the labels. Returns the wrapped function's return value
 * verbatim; on throw, emits the failure event with `error_type` set
 * to the error's `name` and re-throws. The `name` argument MUST be a
 * stable string (not derived from input) to keep the metric
 * cardinality bounded — operators dynamically scoping should put
 * variable parts into `labels`.
 *
 * @example
 *   var rows = await b.observability.timed("db.query",
 *     async function () {
 *       return await db.queryAll("SELECT id FROM users");
 *     },
 *     { [b.observability.SEMCONV.DB_OPERATION_NAME]: "select" });
 *   // → emits db.query with { outcome: "ok", duration_ms: 12,
 *   //   "db.operation.name": "select" }
 */
function timed(name, fn, labels) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("observability.timed: name must be a non-empty string");
  }
  if (typeof fn !== "function") {
    throw new TypeError("observability.timed: fn must be a function");
  }
  var start = Date.now();
  function _emit(outcome, extra) {
    var allLabels = Object.assign({}, labels || {}, {
      outcome:     outcome,
      duration_ms: Date.now() - start,
    }, extra || {});
    try { event(name, 1, allLabels); }
    catch (_e) { /* drop-silent — observability sink */ }
  }
  var ret;
  try { ret = fn(); }
  catch (e) {
    _emit("fail", { error_type: (e && e.name) || "Error" });
    throw e;
  }
  if (ret && typeof ret.then === "function") {
    return ret.then(
      function (v) { _emit("ok"); return v; },
      function (e) {
        _emit("fail", { error_type: (e && e.name) || "Error" });
        throw e;
      }
    );
  }
  _emit("ok");
  return ret;
}

// OpenTelemetry semantic-convention attribute names — the operator-
// facing canonical vocabulary the framework's b.observability /
// b.tracing / b.metrics emitters use when building span / metric
// attributes. Tracking the OTel semconv stable namespace (1.27+)
// directly here means operators wiring the framework's tap into an
// OTel SDK don't need to maintain an aliasing table — the names are
// already correct.
//
// When operators call b.observability.event() / safeEvent(), they
// pass attribute keys that should match the keys below. The map is
// frozen — adding a new attribute requires a release.
//
// Reference: https://opentelemetry.io/docs/specs/semconv/general/attributes/
var SEMCONV = Object.freeze({
  // HTTP server (stable per OTel semconv)
  HTTP_REQUEST_METHOD:        "http.request.method",
  HTTP_REQUEST_BODY_SIZE:     "http.request.body.size",
  HTTP_RESPONSE_STATUS_CODE:  "http.response.status_code",
  HTTP_RESPONSE_BODY_SIZE:    "http.response.body.size",
  HTTP_ROUTE:                 "http.route",
  // Server / network
  SERVER_ADDRESS:             "server.address",
  SERVER_PORT:                "server.port",
  CLIENT_ADDRESS:             "client.address",
  CLIENT_PORT:                "client.port",
  NETWORK_PEER_ADDRESS:       "network.peer.address",
  NETWORK_PROTOCOL_NAME:      "network.protocol.name",
  NETWORK_PROTOCOL_VERSION:   "network.protocol.version",
  // URL
  URL_FULL:                   "url.full",
  URL_PATH:                   "url.path",
  URL_QUERY:                  "url.query",
  URL_SCHEME:                 "url.scheme",
  // User agent
  USER_AGENT_ORIGINAL:        "user_agent.original",
  // Database
  DB_SYSTEM:                  "db.system",
  DB_NAMESPACE:               "db.namespace",
  DB_OPERATION_NAME:          "db.operation.name",
  DB_QUERY_TEXT:              "db.query.text",
  // Messaging
  MESSAGING_SYSTEM:           "messaging.system",
  MESSAGING_OPERATION:        "messaging.operation",
  MESSAGING_DESTINATION_NAME: "messaging.destination.name",
  // Auth / session
  USER_ID:                    "user.id",
  SESSION_ID:                 "session.id",
  // Errors
  ERROR_TYPE:                 "error.type",
  EXCEPTION_TYPE:             "exception.type",
  EXCEPTION_MESSAGE:          "exception.message",
  EXCEPTION_STACKTRACE:       "exception.stacktrace",
  // RPC
  RPC_SYSTEM:                 "rpc.system",
  RPC_SERVICE:                "rpc.service",
  RPC_METHOD:                 "rpc.method",
  RPC_GRPC_STATUS_CODE:       "rpc.grpc.status_code",
  // Messaging — additional client/server attrs
  MESSAGING_CLIENT_ID:                "messaging.client.id",
  MESSAGING_MESSAGE_ID:               "messaging.message.id",
  MESSAGING_DESTINATION_PARTITION_ID: "messaging.destination.partition.id",
  MESSAGING_BATCH_MESSAGE_COUNT:      "messaging.batch.message_count",
  // Network — transport / connection state
  NETWORK_TRANSPORT:          "network.transport",
  NETWORK_CONNECTION_TYPE:    "network.connection.type",
  // Process / runtime
  PROCESS_PID:                "process.pid",
  PROCESS_RUNTIME_NAME:       "process.runtime.name",
  PROCESS_RUNTIME_VERSION:    "process.runtime.version",
  // Service identification
  SERVICE_NAME:               "service.name",
  SERVICE_VERSION:             "service.version",
  SERVICE_INSTANCE_ID:        "service.instance.id",
  // Telemetry SDK self-identification
  TELEMETRY_SDK_NAME:         "telemetry.sdk.name",
  TELEMETRY_SDK_LANGUAGE:     "telemetry.sdk.language",
  TELEMETRY_SDK_VERSION:      "telemetry.sdk.version",
  // GenAI — OpenTelemetry semantic conventions for generative AI
  // workloads (LLM clients, vector DB queries, agent frameworks).
  // Tracking the otel-spec experimental namespace; covers the stable
  // attribute set as of 2026-Q2.
  GEN_AI_SYSTEM:                  "gen_ai.system",
  GEN_AI_REQUEST_MODEL:           "gen_ai.request.model",
  GEN_AI_REQUEST_TEMPERATURE:     "gen_ai.request.temperature",
  GEN_AI_REQUEST_TOP_P:           "gen_ai.request.top_p",
  GEN_AI_REQUEST_TOP_K:           "gen_ai.request.top_k",
  GEN_AI_REQUEST_MAX_TOKENS:      "gen_ai.request.max_tokens",
  GEN_AI_REQUEST_STOP_SEQUENCES:  "gen_ai.request.stop_sequences",
  GEN_AI_RESPONSE_MODEL:          "gen_ai.response.model",
  GEN_AI_RESPONSE_ID:             "gen_ai.response.id",
  GEN_AI_RESPONSE_FINISH_REASONS: "gen_ai.response.finish_reasons",
  GEN_AI_USAGE_INPUT_TOKENS:      "gen_ai.usage.input_tokens",
  GEN_AI_USAGE_OUTPUT_TOKENS:     "gen_ai.usage.output_tokens",
  GEN_AI_USAGE_TOTAL_TOKENS:      "gen_ai.usage.total_tokens",
  GEN_AI_OPERATION_NAME:          "gen_ai.operation.name",
  GEN_AI_TOOL_NAME:               "gen_ai.tool.name",
  GEN_AI_TOOL_CALL_ID:            "gen_ai.tool.call.id",
  GEN_AI_AGENT_ID:                "gen_ai.agent.id",
  GEN_AI_AGENT_NAME:              "gen_ai.agent.name",
  GEN_AI_AGENT_DESCRIPTION:       "gen_ai.agent.description",
  // Vector database / retrieval-augmented generation
  DB_VECTOR_QUERY_TOP_K:          "db.vector.query.top_k",
  DB_VECTOR_QUERY_DIMENSIONS:     "db.vector.query.dimensions",
  DB_VECTOR_QUERY_DISTANCE_METRIC: "db.vector.query.distance_metric",
  // Cloud / runtime context (frequently paired with GenAI)
  CLOUD_PROVIDER:                 "cloud.provider",
  CLOUD_REGION:                   "cloud.region",
  CLOUD_ACCOUNT_ID:               "cloud.account.id",
  CLOUD_RESOURCE_ID:              "cloud.resource_id",
  // Container / orchestration
  CONTAINER_ID:                   "container.id",
  CONTAINER_IMAGE_NAME:           "container.image.name",
  CONTAINER_IMAGE_TAG:            "container.image.tag",
  K8S_NAMESPACE_NAME:             "k8s.namespace.name",
  K8S_POD_NAME:                   "k8s.pod.name",
  K8S_DEPLOYMENT_NAME:            "k8s.deployment.name",
});

// W3C Trace Context — parse / build the `traceparent` HTTP header
// per https://www.w3.org/TR/trace-context-1/. Operators wiring
// distributed tracing across services use these to propagate the
// trace ID across an outbound HTTP call without a vendored OTel SDK.
//
// Format: `<version>-<trace-id>-<parent-id>-<trace-flags>`
//   version:     2 hex chars; "00" for v1
//   trace-id:    32 hex chars (128 bits); MUST be all-zero-rejected
//   parent-id:   16 hex chars (64 bits); MUST be all-zero-rejected
//   trace-flags: 2 hex chars; bit 0 = sampled
var _TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
var _ALL_ZERO_TRACE = "00000000000000000000000000000000";
var _ALL_ZERO_PARENT = "0000000000000000";

var _HEX_RADIX = 16;                                                               // allow:raw-byte-literal — Number.parseInt radix
var _TRACE_FLAG_SAMPLED = 0x01;                                                    // W3C Trace Context §3.2.2.5 sampled bit
var _TRACE_ID_BYTES = 16;                                                          // allow:raw-byte-literal — W3C Trace Context §3.2.2.3 (16 bytes)
var _PARENT_ID_BYTES = 8;                                                          // allow:raw-byte-literal — W3C Trace Context §3.2.2.4 (8 bytes)
var _FLAGS_HEX_LEN = 2;                                                            // allow:raw-byte-literal — W3C Trace Context flags are 1 byte = 2 hex chars

function _parseTraceparent(headerValue) {
  if (typeof headerValue !== "string" || headerValue.length === 0) return null;
  var s = headerValue.trim().toLowerCase();
  var m = s.match(_TRACEPARENT_RE);
  if (!m) return null;
  if (m[2] === _ALL_ZERO_TRACE) return null;     // §3.2.2.3 — trace-id MUST NOT be zero
  if (m[3] === _ALL_ZERO_PARENT) return null;    // §3.2.2.4 — parent-id MUST NOT be zero
  var flagsByte = parseInt(m[4], _HEX_RADIX);
  return {
    version:  m[1],
    traceId:  m[2],
    parentId: m[3],
    flags:    m[4],
    sampled:  (flagsByte & _TRACE_FLAG_SAMPLED) === _TRACE_FLAG_SAMPLED,
  };
}

function _buildTraceparent(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("traceContext.build: opts must be a plain object");
  }
  var traceId = opts.traceId;
  var parentId = opts.parentId;
  if (typeof traceId !== "string" || !safeBuffer().TRACE_ID_HEX_RE.test(traceId) || traceId === _ALL_ZERO_TRACE) {  // allow:regex-no-length-cap — fixed-length hex constant from safe-buffer
    throw new TypeError("traceContext.build: traceId must be 32 lowercase hex chars (non-zero)");
  }
  if (typeof parentId !== "string" || !safeBuffer().SPAN_ID_HEX_RE.test(parentId) || parentId === _ALL_ZERO_PARENT) {  // allow:regex-no-length-cap — fixed-length hex constant from safe-buffer
    throw new TypeError("traceContext.build: parentId must be 16 lowercase hex chars (non-zero)");
  }
  var flagsByte = (opts.sampled ? _TRACE_FLAG_SAMPLED : 0);
  var flags = flagsByte.toString(_HEX_RADIX).padStart(_FLAGS_HEX_LEN, "0");
  return "00-" + traceId + "-" + parentId + "-" + flags;
}

var _nodeCryptoForTrace = require("crypto");

function _newTraceId() {
  var hex = _nodeCryptoForTrace.randomBytes(_TRACE_ID_BYTES).toString("hex");
  // Zero-trace-id is forbidden per spec; in the astronomically unlikely
  // case rand returned all-zero, retry once.
  return hex === _ALL_ZERO_TRACE ? _nodeCryptoForTrace.randomBytes(_TRACE_ID_BYTES).toString("hex") : hex;
}

function _newParentId() {
  var hex = _nodeCryptoForTrace.randomBytes(_PARENT_ID_BYTES).toString("hex");
  return hex === _ALL_ZERO_PARENT ? _nodeCryptoForTrace.randomBytes(_PARENT_ID_BYTES).toString("hex") : hex;
}

// W3C Trace Context §3.3 — tracestate: comma-separated list of
// `vendor=value` pairs carrying vendor-specific trace data.
//
//   tracestate: rojo=00f067aa0ba902b7, congo=t61rcWkgMzE
//
// Spec rules (https://www.w3.org/TR/trace-context-1/#tracestate-header):
//   - vendor key: lowercase ASCII letters, digits, `_`, `-`, `*`, `/`,
//     length 1..256, optionally with `<tenant>@<system>` form
//   - value: printable ASCII (0x20..0x7E) excluding `,` and `=`,
//     length 1..256
//   - max 32 entries, max 512 chars total
//   - duplicate keys: keep first, drop rest
var _TRACESTATE_KEY_RE   = /^[a-z0-9][a-z0-9_\-*/]{0,255}(@[a-z0-9][a-z0-9_\-*/]{0,255})?$/;
var _TRACESTATE_VALUE_RE = /^[\x20-\x2B\x2D-\x3C\x3E-\x7E]{1,256}$/;     // printable, no "," or "="
var _TRACESTATE_MAX_ENTRIES = 32;                                                  // allow:raw-byte-literal — W3C spec hard cap (§3.3.1.3)
var _TRACESTATE_MAX_CHARS   = 512;                                                 // allow:raw-byte-literal — W3C spec hard cap (§3.3.1.3)

function _parseTracestate(headerValue) {
  if (typeof headerValue !== "string") return null;
  if (headerValue.length === 0 || headerValue.length > _TRACESTATE_MAX_CHARS) return null;
  var pairs = headerValue.split(",");
  if (pairs.length > _TRACESTATE_MAX_ENTRIES) return null;
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < pairs.length; i++) {
    var raw = pairs[i].trim();
    if (raw.length === 0) continue;
    var eqIdx = raw.indexOf("=");
    if (eqIdx === -1) return null;
    var key = raw.slice(0, eqIdx).trim();
    var val = raw.slice(eqIdx + 1).trim();
    if (!_TRACESTATE_KEY_RE.test(key)) return null;                              // allow:regex-no-length-cap — regex literal hard-caps key length per W3C §3.3.1.1
    if (!_TRACESTATE_VALUE_RE.test(val)) return null;                            // allow:regex-no-length-cap — regex literal hard-caps value length per W3C §3.3.1.2
    if (seen[key]) continue;     // dup-key: keep first
    seen[key] = true;
    out.push({ key: key, value: val });
  }
  return out;
}

function _buildTracestate(entries) {
  if (!Array.isArray(entries)) {
    throw new TypeError("traceContext.buildTracestate: entries must be an array");
  }
  if (entries.length > _TRACESTATE_MAX_ENTRIES) {
    throw new TypeError("traceContext.buildTracestate: too many entries (max " +
      _TRACESTATE_MAX_ENTRIES + ")");
  }
  var seen = Object.create(null);
  var parts = [];
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    if (!e || typeof e !== "object") {
      throw new TypeError("traceContext.buildTracestate: entries[" + i + "] must be an object");
    }
    if (typeof e.key !== "string" || !_TRACESTATE_KEY_RE.test(e.key)) {          // allow:regex-no-length-cap — regex literal hard-caps key length per W3C §3.3.1.1
      throw new TypeError("traceContext.buildTracestate: entries[" + i + "].key violates W3C key rules");
    }
    if (typeof e.value !== "string" || !_TRACESTATE_VALUE_RE.test(e.value)) {    // allow:regex-no-length-cap — regex literal hard-caps value length per W3C §3.3.1.2
      throw new TypeError("traceContext.buildTracestate: entries[" + i + "].value violates W3C value rules");
    }
    if (seen[e.key]) continue;
    seen[e.key] = true;
    parts.push(e.key + "=" + e.value);
  }
  var s = parts.join(",");
  if (s.length > _TRACESTATE_MAX_CHARS) {
    throw new TypeError("traceContext.buildTracestate: built string exceeds W3C 512-char cap");
  }
  return s;
}

var traceContext = {
  parse:           _parseTraceparent,
  build:           _buildTraceparent,
  newTraceId:      _newTraceId,
  newParentId:     _newParentId,
  parseTracestate: _parseTracestate,
  buildTracestate: _buildTracestate,
};

// ---- W3C Baggage (https://www.w3.org/TR/baggage/) ----
//
// `baggage` HTTP header carries a comma-separated list of
// `key=value;property=value;property=value` triplets. Used to
// propagate user-supplied context (tenantId, deploymentRegion,
// experimentId, etc.) across service boundaries WITHOUT mixing it
// into traceparent (which is reserved for trace identifiers).
//
// Spec rules:
//   - key: token per RFC 7230 (`tchar` set: `!#$%&'*+\-.^_\`|~` +
//     digits + ALPHA), length 1..255
//   - value: percent-encoded UTF-8, must NOT contain CTL chars,
//     `,`, `;`, `=` (those are structural delimiters)
//   - properties: optional, semicolon-separated `key=value` or bare
//     `key` after the main value
//   - max 64 entries per Baggage section recommendation
//   - max 8192 chars total (W3C recommended cap)
// Resolved at first call; lazyRequire returns a function.
function _baggageTokenRe() { return safeBuffer().RFC7230_TCHAR_RE; }
var _BAGGAGE_MAX_ENTRIES = 64;                                                     // allow:raw-byte-literal — W3C Baggage recommended cap
var _BAGGAGE_MAX_CHARS = C.BYTES.kib(8);                                           // W3C Baggage recommended 8192-char cap

function _parseBaggage(headerValue) {
  if (typeof headerValue !== "string") return null;
  if (headerValue.length === 0 || headerValue.length > _BAGGAGE_MAX_CHARS) return null;
  var entries = headerValue.split(",");
  if (entries.length > _BAGGAGE_MAX_ENTRIES) return null;
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < entries.length; i++) {
    var raw = entries[i].trim();
    if (raw.length === 0) continue;
    var parts = raw.split(";");
    var head = parts[0].trim();
    var eqIdx = head.indexOf("=");
    if (eqIdx === -1) return null;
    var key = head.slice(0, eqIdx).trim();
    var rawValue = head.slice(eqIdx + 1).trim();
    if (!_baggageTokenRe().test(key)) return null;                                 // allow:regex-no-length-cap — RFC 7230 tchar; bound by header-cap
    if (key.length > 255) return null;                                             // allow:raw-byte-literal — W3C key length cap
    var value;
    try { value = decodeURIComponent(rawValue); }
    catch (_e) { return null; }
    var props = [];
    for (var p = 1; p < parts.length; p++) {
      var prop = parts[p].trim();
      if (prop.length === 0) continue;
      var pEq = prop.indexOf("=");
      if (pEq === -1) {
        if (!_baggageTokenRe().test(prop)) return null;                            // allow:regex-no-length-cap — RFC 7230 tchar; bound by header-cap
        props.push({ key: prop, value: null });
      } else {
        var pKey = prop.slice(0, pEq).trim();
        var pVal = prop.slice(pEq + 1).trim();
        if (!_baggageTokenRe().test(pKey)) return null;                            // allow:regex-no-length-cap — RFC 7230 tchar; bound by header-cap
        var pValueDecoded;
        try { pValueDecoded = decodeURIComponent(pVal); }
        catch (_e) { return null; }
        props.push({ key: pKey, value: pValueDecoded });
      }
    }
    if (seen[key]) continue;
    seen[key] = true;
    out.push({ key: key, value: value, properties: props });
  }
  return out;
}

function _buildBaggage(entries) {
  if (!Array.isArray(entries)) {
    throw new TypeError("traceContext.buildBaggage: entries must be an array");
  }
  if (entries.length > _BAGGAGE_MAX_ENTRIES) {
    throw new TypeError("traceContext.buildBaggage: too many entries (max " +
      _BAGGAGE_MAX_ENTRIES + ")");
  }
  var seen = Object.create(null);
  var parts = [];
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    if (!e || typeof e !== "object") {
      throw new TypeError("traceContext.buildBaggage: entries[" + i + "] must be an object");
    }
    if (typeof e.key !== "string" || !_baggageTokenRe().test(e.key)) {             // allow:regex-no-length-cap — RFC 7230 tchar; bound by header-cap
      throw new TypeError("traceContext.buildBaggage: entries[" + i + "].key violates W3C key rules");
    }
    if (typeof e.value !== "string") {
      throw new TypeError("traceContext.buildBaggage: entries[" + i + "].value must be a string");
    }
    if (seen[e.key]) continue;
    seen[e.key] = true;
    var encodedValue = encodeURIComponent(e.value);
    var item = e.key + "=" + encodedValue;
    if (Array.isArray(e.properties)) {
      for (var p = 0; p < e.properties.length; p++) {
        var prop = e.properties[p];
        if (!prop || typeof prop !== "object") continue;
        if (typeof prop.key !== "string" || !_baggageTokenRe().test(prop.key)) {   // allow:regex-no-length-cap — RFC 7230 tchar; bound by header-cap
          throw new TypeError("traceContext.buildBaggage: entries[" + i +
            "].properties[" + p + "].key violates W3C property-key rules");
        }
        if (prop.value === null || prop.value === undefined) {
          item += ";" + prop.key;
        } else if (typeof prop.value === "string") {
          item += ";" + prop.key + "=" + encodeURIComponent(prop.value);
        } else {
          throw new TypeError("traceContext.buildBaggage: entries[" + i +
            "].properties[" + p + "].value must be a string or null");
        }
      }
    }
    parts.push(item);
  }
  var s = parts.join(",");
  if (s.length > _BAGGAGE_MAX_CHARS) {
    throw new TypeError("traceContext.buildBaggage: built string exceeds W3C 8192-char cap");
  }
  return s;
}

var baggage = {
  parse: _parseBaggage,
  build: _buildBaggage,
  MAX_ENTRIES: _BAGGAGE_MAX_ENTRIES,
};

// Lazy-required to avoid a require cycle (tracer / exporter both
// reach back into observability for safeEvent emissions).
var _tracerModule       = lazyRequire(function () { return require("./observability-tracer"); });
var _otlpExporterModule = lazyRequire(function () { return require("./observability-otlp-exporter"); });

var tracer = {
  create:            function (opts) { return _tracerModule().create(opts); },
  spanToTraceparent: function (span) { return _tracerModule().spanToTraceparent(span); },
  VALID_KINDS:       ["internal", "server", "client", "producer", "consumer"],
  VALID_STATUS_CODES: ["unset", "ok", "error"],
};

var otlpExporter = {
  create: function (opts) { return _otlpExporterModule().create(opts); },
};

module.exports = {
  tap:           tap,
  event:         event,
  safeEvent:     safeEvent,
  timed:         timed,
  setTap:        setTap,
  SEMCONV:       SEMCONV,
  traceContext:  traceContext,
  baggage:       baggage,
  tracer:        tracer,
  otlpExporter:  otlpExporter,
};
