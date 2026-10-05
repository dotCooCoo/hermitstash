// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   minimum, `ecdhCurve` taken from the framework's live outbound
 *   posture (`b.network.tls.outboundPosture()`, which follows
 *   `b.network.tls.preferredGroups.set(...)`), keep-alive on.
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

// Best-effort + drop-silent: an audit failure must never break the request
function auditClassicalDowngrade(socket, meta) {
  try {
    if (!socket || typeof socket.getEphemeralKeyInfo !== "function") return;
    var info = socket.getEphemeralKeyInfo() || {};
    var group = info.name;
    var host  = (meta && (meta.host || meta.servername)) || null;
    var port  = (meta && meta.port) || null;

    if (info.type === "TLSGroup") return;
    if (typeof group === "string" &&
        Object.prototype.hasOwnProperty.call(C.PQC_GROUPS, group)) return;

    if (!group) {
      if (typeof socket.isSessionReused === "function" && socket.isSessionReused()) return;
      audit().safeEmit({
        action:   "tls.no_ephemeral_key_exchange",
        outcome:  "success",
        metadata: { host: host, port: port },
      });
      return;
    }

    audit().safeEmit({
      action:   "tls.classical_downgrade",
      outcome:  "success",
      metadata: { group: group, host: host, port: port },
    });
  } catch (_e) { /* drop-silent — audit is best-effort; never break TLS */ }
}

var KNOWN_TLS_GROUPS = Object.freeze([
  "SecP384r1MLKEM1024",
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
  "X25519",
  "secp256r1",
  "secp384r1",
  "secp521r1",
  "X448",
]);

function _validateGroupName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 64) {
    throw new TypeError(
      "pqc-agent: ecdhCurve group entries must be non-empty strings up to 64 chars"
    );
  }
  if (!safeBuffer.isBase64Url(name)) {
    throw new TypeError(
      "pqc-agent: ecdhCurve group '" + name + "' has illegal characters " +
      "(must match [A-Za-z0-9_-]+)"
    );
  }
}

var DEFAULT_OPTS = {
  keepAlive:      true,
  keepAliveMsecs: C.TIME.seconds(30),
  maxSockets:     50,
  maxFreeSockets: 0x10,
  scheduling:     "lifo",
};

function _buildAgentOpts(opts) {
  opts = opts || {};
  var allowOperatorGroups = opts.allowOperatorGroups === true;
  var merged = Object.assign({}, DEFAULT_OPTS, opts);
  delete merged.allowOperatorGroups;
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
      // safeEmit is drop-silent on error, so an audit bus failure does not break agent construction.
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
    merged.ecdhCurve = networkTls.outboundPosture().ecdhCurve;
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
 * preference (TLSv1.3 minimum, ecdhCurve taken from the live posture, so a
 * later `b.network.tls.preferredGroups.set(...)` is reflected by agents built
 * after it). Operator-supplied values for ecdhCurve
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
 *   ecdhCurve?:           string,   // colon-separated group names; must subset C.TLS_GROUP_PREFERENCE. The TLS `groups` list tracks this value exactly (mirrored from one resolved string), so a narrowed/reordered ecdhCurve is the negotiated key-share order.
 *   allowOperatorGroups?: boolean,  // default false; opt in to operator-supplied groups outside the framework PQC preference
 *
 * @example
 *   var agent = b.pqcAgent.create({ maxSockets: 200 });
 *   var req = https.request("https://api.example.com/v1/x", { agent: agent });
 *   req.end();
 */
function create(opts) {
  var built = _buildAgentOpts(opts);
  // allow:outbound-tls-posture — posture applied in _buildAgentOpts
  var agent = new https.Agent(built);
  agent._builtOpts = built;
  var _origCreateConnection = agent.createConnection.bind(agent);
  agent.createConnection = function (options, cb) {
    var socket = _origCreateConnection(options, cb);
    if (socket && typeof socket.once === "function") {
      socket.once("secureConnect", function () { auditClassicalDowngrade(socket, options); });
    }
    return socket;
  };
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
  var nextOpts = Object.assign({}, agent._builtOpts, {
    cert: newMaterial.cert,
    key:  newMaterial.key,
  });
  if (newMaterial.ca !== undefined) nextOpts.ca = newMaterial.ca;
  var t0 = Date.now();
  try {
    // allow:secure-context-cert-compression — validation only; this context is discarded and never serves a handshake
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

var _defaultAgent = null;
var _defaultAgentGeneration = null;
function _getDefaultAgent() {
  var generation = networkTls.postureGeneration();
  if (_defaultAgent && _defaultAgentGeneration !== generation) {
    var prior = _defaultAgent;
    _defaultAgent = null;
    try {
      prior.keepAlive = false;
      prior.maxFreeSockets = 0;
    } catch (_e) { /* best-effort — an exotic agent may freeze its options */ }
    var free = prior.freeSockets || {};
    Object.keys(free).forEach(function (name) {
      (free[name] || []).slice().forEach(function (sock) {
        try { sock.destroy(); } catch (_e) { /* best-effort idle-socket close */ }
      });
    });
  }
  if (!_defaultAgent) {
    _defaultAgent = create();
    _defaultAgentGeneration = generation;
  }
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
 *   // operator's daemon picked up a refreshed TLS posture and wants the
 *   // next outbound request built against it:
 *   var res = b.pqcAgent.reload();
 *   // → { destroyed: false } when no default agent had been built yet;
 *   //   the next b.pqcAgent.agent access builds against the new posture
 */
function reload() {
  var prior = _defaultAgent;
  _defaultAgent = null;
  if (prior) {
    try { prior.destroy(); }
    catch (_e) { /* destroy is best-effort */ }
  }
  return { destroyed: prior !== null };
}

module.exports = {
  get agent()  { return _getDefaultAgent(); },
  create:      create,
  createHttp:  createHttp,
  reload:      reload,
  _auditClassicalDowngrade: auditClassicalDowngrade,
  DEFAULT_OPTS: DEFAULT_OPTS,
  KNOWN_TLS_GROUPS: KNOWN_TLS_GROUPS,
  enforced:    true,
};
