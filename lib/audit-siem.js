"use strict";

/**
 * SIEM forwarding for the audit log.
 *
 * Streams every audit event to a configured SIEM via blamejs's log-stream
 * framework: RFC 5424 syslog (udp / tcp / tls) or an HTTP webhook (Splunk HEC,
 * Datadog, Grafana Loki, or any JSON-ingest endpoint, with bearer / basic /
 * header auth). Event metadata is redacted (secret / PII value-shapes stripped)
 * before it leaves the process. Off by default; opt in under Audit Log settings.
 *
 * HermitStash owns the b.logStream dispatcher exclusively (it uses its own
 * logger for everything else), so init/shutdown here don't contend with other
 * framework logging.
 */

var b = require("./vendor/blamejs");
var config = require("./config");
var C = require("./constants");
var logger = require("../app/shared/logger");

var _inited = false;
var _lastError = null; // surfaced by the connectivity test so a bad URL / sink config is visible

// Security-relevant failures forward at "warn" so a SIEM can alert on them; the
// rest are "info".
function _level(action) {
  var a = String(action || "").toLowerCase();
  return /fail|denied|deny|reject|block|error|invalid|unauthorized|locked|tamper|breach|suspend|revoke/.test(a) ? "warn" : "info";
}
function _outcome(action) {
  var a = String(action || "").toLowerCase();
  return /fail|denied|deny|reject|block|error|invalid|unauthorized|locked/.test(a) ? "failure" : "success";
}

// Build the single named sink config from the operator's settings.
function _sinkConfig() {
  var url = config.siemUrl;
  if (config.siemProtocol === "webhook") {
    // Audit events are low-volume and security-relevant, so favor latency over
    // throughput: a small batch flushed within ~2s instead of the 5s default.
    // The SIEM endpoint is admin-configured (not untrusted input) and is usually
    // an internal host reached over http — the same "cleartext is the operator's
    // choice" posture the udp/tcp syslog transports already take, so allow both.
    var cfg = { protocol: "webhook", url: url, batchSize: 25, maxBatchAgeMs: C.TIME.seconds(2),
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true };
    var scheme = config.siemWebhookAuth || "none";
    var cred = config.siemWebhookToken || "";
    if (scheme === "bearer") { cfg.auth = "bearer"; cfg.token = cred; }
    else if (scheme === "basic") { cfg.auth = "basic"; var p = cred.split(":"); cfg.username = p[0] || ""; cfg.password = p.slice(1).join(":"); }
    else if (scheme === "header") { cfg.auth = "header"; cfg.headers = cred ? { Authorization: cred } : {}; }
    else { cfg.auth = "none"; }
    return cfg;
  }
  // syslog (default). Facility 13 = "log audit" (RFC 5424 §6.2.1).
  return { protocol: "syslog", url: url, appName: "hermitstash", facility: 13 };
}

// (Re)configure the SIEM sink from current config. Idempotent — shuts the
// dispatcher down first so a settings change re-points cleanly. Returns whether
// forwarding is now active.
async function initSiem() {
  // shutdown() is async (it drains in-flight emits and closes sink fds). It must
  // be awaited before re-init, or init() no-ops while the old dispatcher is still
  // tearing down — leaving forwarding with no live sink.
  try { await b.logStream.shutdown(); } catch (_e) { /* not yet initialized */ }
  _inited = false;
  _lastError = null;
  if (!config.siemEnabled || !config.siemUrl) return false;
  try {
    b.logStream.init({ minLevel: config.siemMinLevel || "info", sinks: { siem: _sinkConfig() } });
    _inited = true;
    logger.info("[siem] audit forwarding enabled", { protocol: config.siemProtocol || "syslog" });
  } catch (e) {
    _lastError = (e && e.message) || String(e);
    logger.error("[siem] init failed", { err: _lastError });
    _inited = false;
  }
  return _inited;
}

// Forward one audit entry. No-op when forwarding is off. Never throws into the
// caller — audit.log() is fire-and-forget and an external SIEM outage must not
// affect request handling.
function forward(action, entry) {
  if (!_inited || !entry) return;
  try {
    b.logStream.emit(_level(action), "audit." + action, {
      action: action,
      outcome: _outcome(action),
      actor: entry.performedByEmail || entry.performedBy || null,
      actorId: entry.performedBy || null,
      targetEmail: entry.targetEmail || null,
      targetId: entry.targetId || null,
      ip: entry.ip || null,
      method: entry.method || null,
      path: entry.path || null,
      // The auth class (session / apikey / anonymous) is forensic context, not a
      // secret. The framework's redactor strips any field whose name contains
      // "auth", so this travels under a name the redactor leaves intact.
      actorKind: entry.authType || null,
      requestId: entry.requestId || null,
      userAgent: entry.userAgent || null,
      details: entry.details || null,
      at: entry.createdAt || null,
    });
  } catch (e) { logger.error("[siem] forward failed", { err: e && e.message }); }
}

// Re-init from current config and emit a connectivity test event. Delivery for
// UDP syslog cannot be acknowledged, so a clean result means "config valid +
// event dispatched" — the operator confirms receipt in their SIEM.
async function testConnection() {
  var ok = await initSiem();
  if (!ok) return { ok: false, error: _lastError || "SIEM forwarding is disabled or the endpoint URL is missing." };
  try {
    b.logStream.emit("info", "audit.siem_test", {
      action: "siem_test", outcome: "success",
      details: "HermitStash SIEM connectivity test", at: new Date().toISOString(),
    });
    // Give a batched webhook / TCP sink a moment to attempt delivery.
    await b.safeAsync.sleep(C.TIME.seconds(1));
    return { ok: true, protocol: config.siemProtocol || "syslog" };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}

module.exports = {
  initSiem: initSiem,
  forward: forward,
  testConnection: testConnection,
  isEnabled: function () { return _inited; },
};
