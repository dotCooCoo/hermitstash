"use strict";
/**
 * @module     b.pqcAgent
 * @nav        Production
 * @title      PQC Agent
 * @order      630
 *
 * @intro
 *   Outbound HTTPS agent locked to the framework's PQC group preference.
 *   The framework's posture is "all outbound TLS is PQC-only"; this
 *   primitive defines what that means at the agent level — TLSv1.3
 *   minimum, `ecdhCurve` set to the framework's PQC hybrid preference
 *   (`constants.TLS_GROUP_CURVE_STR`), keep-alive on.
 *
 *   `b.pqcAgent.agent` is a process-wide default agent, lazy-built on
 *   first access; `b.pqcAgent.create(opts)` builds a fresh agent with
 *   custom pool / timeout opts (ecdhCurve and minVersion cannot be
 *   weakened); `b.pqcAgent.reload()` tears down the default agent so
 *   the next access rebuilds against current TLS posture.
 *
 *   `lib/http-client.js`'s transport cache uses `pqcAgent.create()` under
 *   the hood, so the framework's bundled HTTP client and any operator-
 *   direct `https.request` calls converge on the same agent posture.
 *
 * @card
 *   Outbound HTTPS agent locked to TLSv1.3 + framework PQC hybrid group preference.
 */

var https = require("node:https");
var http  = require("node:http");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var networkTls = require("./network-tls");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var PqcAgentError = defineClass("PqcAgentError", { alwaysPermanent: true });

// audit imports crypto/handlers transitively — lazy to avoid load
// cycles when pqc-agent is required during framework bootstrap.
var audit = lazyRequire(function () { return require("./audit"); });

// IANA TLS Supported Groups Registry — every named-group identifier
// the framework knows by name. Operators with `allowOperatorGroups:
// true` may pass any entry from this registry; entries outside it
// still throw (catches typos / smuggled-separator attempts).
var KNOWN_TLS_GROUPS = Object.freeze([
  // PQC hybrids
  "SecP384r1MLKEM1024",   // draft-kwiatkowski-tls-ecdhe-mlkem 0x11ED
  "X25519MLKEM768",       // RFC 9794 0x11EC
  "SecP256r1MLKEM768",    // RFC 9794 0x11EB
  // Classical groups (operator opt-in only)
  "X25519",
  "secp256r1",            // allow:raw-byte-literal — IANA TLS group name (P-256), not bytes
  "secp384r1",            // allow:raw-byte-literal — IANA TLS group name (P-384), not bytes
  "secp521r1",            // allow:raw-byte-literal — IANA TLS group name (P-521), not bytes
  "X448",
]);

function _validateGroupName(name) {
  // Same shape as network-tls._validateKeyShare: alphanumeric +
  // underscore, bounded length. Refuses `:` so an operator can't
  // smuggle a second group through one slot.
  if (typeof name !== "string" || name.length === 0 || name.length > 64) { // allow:raw-byte-literal — string-length cap, not bytes
    throw new TypeError(
      "pqc-agent: ecdhCurve group entries must be non-empty strings up to 64 chars"
    );
  }
  if (!safeBuffer.BASE64URL_RE.test(name)) {
    throw new TypeError(
      "pqc-agent: ecdhCurve group '" + name + "' has illegal characters " +
      "(must match [A-Za-z0-9_-]+)"
    );
  }
}

// Defaults for connection pooling. These ARE overridable via opts —
// only the cryptographic posture (ecdhCurve / minVersion) is locked.
var DEFAULT_OPTS = {
  keepAlive:      true,
  keepAliveMsecs: C.TIME.seconds(30),
  maxSockets:     50,
  // Pool counts are protocol-side concurrency tunables, not byte
  // quantities — hex form keeps the byte-shape detector out of it.
  maxFreeSockets: 0x10,
  scheduling:     "lifo",
};

function _buildAgentOpts(opts) {
  opts = opts || {};
  // allowOperatorGroups gates operator-supplied groups outside the
  // framework PQC preference. Default false: caller may only narrow
  // (subset of) TLS_GROUP_PREFERENCE. Set true and any KNOWN_TLS_GROUPS
  // entry is permitted, including classical groups (operator's call
  // — security-defaults posture says default no, opt-in yes). Each
  // accepted operator group emits an audit event so the choice is
  // visible in the audit log.
  var allowOperatorGroups = opts.allowOperatorGroups === true;
  var merged = Object.assign({}, DEFAULT_OPTS, opts);
  delete merged.allowOperatorGroups;
  // Caller may narrow the framework's curve preference list (drop a
  // group, keep the remaining ones in framework-preferred order) but
  // cannot widen it unless allowOperatorGroups: true is set. A
  // caller-supplied `ecdhCurve` string is parsed into groups and each
  // group is validated; the empty narrowing is a misconfig — TLS
  // won't negotiate a key share — so reject too.
  if (typeof opts.ecdhCurve === "string" && opts.ecdhCurve.length > 0) {
    var requested = opts.ecdhCurve.split(":");
    if (requested.length === 0) {
      throw new TypeError(
        "pqc-agent: opts.ecdhCurve must contain at least one group"
      );
    }
    for (var rgi = 0; rgi < requested.length; rgi++) {
      var group = requested[rgi];
      _validateGroupName(group);
      if (C.TLS_GROUP_PREFERENCE.indexOf(group) !== -1) continue;
      if (!allowOperatorGroups) {
        throw new TypeError(
          "pqc-agent: opts.ecdhCurve='" + opts.ecdhCurve + "' includes '" +
          group + "' which is not in the framework PQC-hybrid " +
          "preference (" + C.TLS_GROUP_CURVE_STR + "); pass " +
          "{ allowOperatorGroups: true } to accept operator-supplied " +
          "groups, or construct an https.Agent directly."
        );
      }
      if (KNOWN_TLS_GROUPS.indexOf(group) === -1) {
        throw new TypeError(
          "pqc-agent: opts.ecdhCurve group '" + group + "' is not a " +
          "known IANA TLS Supported Group identifier"
        );
      }
      // Operator-supplied group accepted — audit-emit so the
      // framework-default deviation is visible to operators reading
      // the audit log. safeEmit is drop-silent on error (audit bus
      // failures must not break TLS agent construction).
      try {
        audit().safeEmit({
          action:   "pqcagent.operator_group.accepted",
          outcome:  "success",
          metadata: { group: group, ecdhCurve: opts.ecdhCurve },
        });
      } catch (_e) { /* drop-silent — audit is best-effort here */ }
    }
    merged.ecdhCurve = requested.join(":");
  } else {
    merged.ecdhCurve = C.TLS_GROUP_CURVE_STR;
  }
  merged.minVersion = "TLSv1.3";
  if (networkTls && typeof networkTls.applyToContext === "function") {
    merged = networkTls.applyToContext({ base: merged });
  }
  return merged;
}

/**
 * @primitive b.pqcAgent.create
 * @signature b.pqcAgent.create(opts?)
 * @since     0.5.0
 * @status    stable
 * @related   b.pqcAgent.reload
 *
 * Build a fresh https.Agent locked to the framework PQC hybrid group
 * preference (TLSv1.3 minimum, ecdhCurve set to
 * `C.TLS_GROUP_CURVE_STR`). Operator-supplied values for ecdhCurve
 * may NARROW the framework default (drop a group) but cannot widen it
 * unless `opts.allowOperatorGroups: true` is set; minVersion is fixed
 * at TLSv1.3 and cannot be weakened.
 *
 * @opts
 *   keepAlive?:           boolean,
 *   keepAliveMsecs?:      number,
 *   maxSockets?:          number,
 *   maxFreeSockets?:      number,
 *   scheduling?:          string,
 *   ecdhCurve?:           string,   // colon-separated group names; must subset C.TLS_GROUP_PREFERENCE
 *   allowOperatorGroups?: boolean,  // default false; opt in to operator-supplied groups outside the framework PQC preference
 *
 * @example
 *   var agent = b.pqcAgent.create({ maxSockets: 200 });
 *   var req = https.request("https://api.example.com/v1/x", { agent: agent });
 *   req.end();
 */
function create(opts) {
  var built = _buildAgentOpts(opts);
  var agent = new https.Agent(built);
  agent._builtOpts = built;
  // Per-instance cert rotation. The pre-v0.10.9 path required process
  // restart for cert rotation on agents built via explicit `create()`
  // (only the framework's lazy default had `b.pqcAgent.reload()`).
  // Attach `reloadCerts` so long-running daemons can pivot in place.
  agent.reloadCerts = function (newMaterial) {
    return _reloadCertsOnAgent(agent, opts, newMaterial);
  };
  return agent;
}

function _reloadCertsOnAgent(agent, originalOpts, newMaterial) {
  validateOpts.requireObject(newMaterial, "agent.reloadCerts",
    PqcAgentError, "pqcagent/reload-bad-opts");
  if (typeof newMaterial.cert !== "string" || newMaterial.cert.length === 0 ||
      typeof newMaterial.key  !== "string" || newMaterial.key.length === 0) {
    throw new PqcAgentError("pqcagent/reload-missing-material",
      "agent.reloadCerts: both cert and key are required (non-empty PEM strings)");
  }
  // Compound on the AGENT's last-known-good builtOpts (which start as
  // the create-time opts but are updated on each successful reload).
  // A sequence like "reload with new ca once, then reload only
  // cert/key" preserves the new ca because the previous successful
  // reload wrote it into agent._builtOpts.
  var nextOpts = Object.assign({}, agent._builtOpts, {
    cert: newMaterial.cert,
    key:  newMaterial.key,
  });
  if (newMaterial.ca !== undefined) nextOpts.ca = newMaterial.ca;
  var t0 = Date.now();
  try {
    // tls.createSecureContext throws on mismatched cert/key — surface
    // as a typed framework error with the underlying OpenSSL chain.
    require("node:tls").createSecureContext({                                                        // allow:inline-require — node:tls only needed during cert rotation (a non-hot path); a top-level require would pull TLS into the boot graph of every process that never reaches reloadCerts
      cert: nextOpts.cert,
      key:  nextOpts.key,
      ca:   nextOpts.ca,
    });
  } catch (e) {
    var errMsg = (e && e.message) ? e.message : String(e);
    if (/ca\b/i.test(errMsg)) {                                                                      // allow:regex-no-length-cap — error-message shape match; error text owned by Node, not adversarial input
      throw new PqcAgentError("pqcagent/reload-bad-ca",
        "agent.reloadCerts: ca bundle failed to parse: " + errMsg);
    }
    throw new PqcAgentError("pqcagent/reload-mismatch",
      "agent.reloadCerts: cert/key mismatch or malformed PEM (" + errMsg + ")");
  }
  agent.options = Object.assign({}, agent.options, {
    cert: nextOpts.cert,
    key:  nextOpts.key,
    ca:   nextOpts.ca,
  });
  agent._builtOpts = nextOpts;
  // Close idle keep-alive sockets so the next request uses the new
  // material. In-flight sockets complete naturally.
  try { agent.destroy(); } catch (_e) { /* best-effort */ }
  try {
    audit.safeEmit({
      action:   "pqcagent.reloadCerts",
      outcome:  "success",
      metadata: { durationMs: Date.now() - t0 },
    });
  } catch (_e2) { /* drop-silent */ }
  return { reloaded: true, durationMs: Date.now() - t0 };
}

/**
 * @primitive b.pqcAgent.createHttp
 * @signature b.pqcAgent.createHttp(opts?)
 * @since     0.5.0
 * @status    stable
 * @related   b.pqcAgent.create
 *
 * Build a cleartext `http.Agent` with the same pool defaults as
 * `b.pqcAgent.create` — no TLS posture to enforce. Exists so the
 * framework's HTTP client's h1 transport for cleartext origins (h2c
 * fixtures, internal services on a private network) shares the same
 * pool tuning as the encrypted path.
 *
 * @opts
 *   keepAlive?:      boolean,
 *   keepAliveMsecs?: number,
 *   maxSockets?:     number,
 *   maxFreeSockets?: number,
 *   scheduling?:     string,
 *
 * @example
 *   var agent = b.pqcAgent.createHttp({ maxSockets: 100 });
 *   var req = http.request("http://internal.svc/health", { agent: agent });
 *   req.end();
 */
function createHttp(opts) {
  return new http.Agent(Object.assign({}, DEFAULT_OPTS, opts || {}));
}

// Lazy-built default agent. Most callers use this; the lazy build
// avoids creating an https.Agent at require time for processes that
// never make an outbound HTTPS call.
var _defaultAgent = null;
function _getDefaultAgent() {
  if (!_defaultAgent) _defaultAgent = create();
  return _defaultAgent;
}

/**
 * @primitive b.pqcAgent.reload
 * @signature b.pqcAgent.reload()
 * @since     0.9.14
 * @status    stable
 * @related   b.pqcAgent.create
 *
 * Tear down the lazily-built default agent and reset to null so the
 * next `b.pqcAgent.agent` access rebuilds against current TLS posture
 * + network-tls applyToContext output.
 *
 * Long-running daemons that rotate the framework's TLS posture (via
 * `b.network.tls` config refresh, certificate-pinset reload, or a
 * `C.TLS_GROUP_PREFERENCE` update behind a feature flag) need a way
 * to re-source the outbound https.Agent without forking a new
 * process. `reload()` calls `.destroy()` on the existing default
 * agent — Node closes idle keep-alive sockets and lets in-flight
 * sockets complete naturally — then nulls the cache so the next
 * `agent` access builds fresh. Agents handed out via explicit
 * `b.pqcAgent.create()` are unaffected; only the framework's lazy
 * default is recycled.
 *
 * Returns `{ destroyed: boolean }` — `destroyed: true` when an agent
 * was actually torn down, `false` when no default had been built
 * (no callers yet asked for it).
 *
 * @example
 *   // operator's daemon picked up a refreshed TLS-pinset config:
 *   b.network.tls.reload();
 *   var res = b.pqcAgent.reload();
 *   logger.info("pqc-agent reloaded", res);
 */
function reload() {
  // CRYPTO-9 — null the cached agent BEFORE calling destroy. The
  // previous order let a concurrent _getDefaultAgent() see the
  // destroyed-not-null agent and hand it to a caller; the caller
  // then tries to issue a request through a torn-down keep-alive
  // pool and surfaces a "socket destroyed" error. Null-first means
  // every concurrent _getDefaultAgent() either sees the live agent
  // (request lands on the about-to-be-torn-down pool — natural
  // graceful drain) or the null sentinel (builds fresh).
  var prior = _defaultAgent;
  _defaultAgent = null;
  if (prior) {
    try { prior.destroy(); }
    catch (_e) { /* destroy is best-effort */ }
  }
  return { destroyed: prior !== null };
}

module.exports = {
  // Read property — getter so the agent is built on first access.
  get agent()  { return _getDefaultAgent(); },
  create:      create,
  createHttp:  createHttp,
  reload:      reload,
  DEFAULT_OPTS: DEFAULT_OPTS,
  KNOWN_TLS_GROUPS: KNOWN_TLS_GROUPS,
  enforced:    true,
};
