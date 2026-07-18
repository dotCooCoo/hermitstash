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

// Defense-in-depth value scrub for the free-form `details` field before it
// egresses to a SIEM. The framework's name-based redactor cannot scan into a
// string value; this classifier matches the framework's credential shapes
// (PEM/SSH private keys, PANs, and similar) and masks a hit, while leaving the
// high-entropy-but-not-secret content HS legitimately logs — SHA3 checksums,
// storage paths, key prefixes — untouched, so it adds coverage without stripping
// forensic context. Source discipline (no raw secret is placed in details)
// stays the primary control; this is the second layer.
var _detailsScrub = b.redact.classifyDefaults({ overrideAction: "redact" });
function _scrubDetails(details) {
  if (!details) return null;
  try { return _detailsScrub({ body: String(details) }).redactedBody; }
  catch (_e) { return null; } // never let a scrub fault leak the raw value or break forwarding
}

// Classify an audit action by WHOLE snake_case token, not substring. A substring
// match mislabels a negated action (user_unsuspended contains "suspend") and a
// naive keyword list misses the security actions that carry no failure word at
// all (rate_limit_hit, email_quota_exceeded). Action names are snake_case with
// the outcome as a trailing token, so a token-set match classifies both
// correctly.
//
// A refused/failed request. rate_limit_hit / email_quota_exceeded belong here:
// the request was blocked, which a SIEM should be able to correlate as a
// failure. Negations (unsuspended, reissued) are their own single token and do
// not match.
var _FAILURE_TOKENS = new Set([
  "fail", "failed", "denied", "deny", "rejected", "reject", "blocked", "block",
  "error", "errored", "invalid", "unauthorized", "locked", "lockout", "tamper",
  "tampered", "breach", "exceeded", "hit", "expired", "timeout", "timedout",
]);
// Notable security actions that SUCCEED (a deliberate revoke/suspend) — they
// raise the forwarded level so a SIEM can alert, without asserting a failed
// outcome. "unsuspended"/"reissued" are distinct tokens and do not match.
var _SECURITY_TOKENS = new Set(["revoke", "revoked", "suspend", "suspended"]);

function _tokens(action) {
  return String(action || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
function _hasFailureToken(tokens) {
  return tokens.some(function (t) { return _FAILURE_TOKENS.has(t); });
}
// Security-relevant events forward at "warn" so a SIEM can alert on them; the
// rest are "info".
function _level(action) {
  var t = _tokens(action);
  return (_hasFailureToken(t) || t.some(function (x) { return _SECURITY_TOKENS.has(x); })) ? "warn" : "info";
}
function _outcome(action) {
  return _hasFailureToken(_tokens(action)) ? "failure" : "success";
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
      // details is free-form forensic context; call sites log key prefixes, ids,
      // and reasons, never a raw secret. _scrubDetails is the second-layer guard
      // that masks a framework-recognized credential shape (a PEM/SSH key, a PAN)
      // if one ever reaches this field, without touching the checksums/paths HS
      // logs legitimately.
      details: _scrubDetails(entry.details),
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
  // Pure classifiers exposed for unit testing the token-based level/outcome map
  // and the details value-scrub.
  _level: _level,
  _outcome: _outcome,
  _scrubDetails: _scrubDetails,
};
