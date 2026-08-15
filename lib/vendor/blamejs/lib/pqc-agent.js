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

// Observe an outbound socket's negotiated TLS key-exchange group and audit a
// classical (non-PQC) downgrade.
//
// node:tls names the negotiated group for BOTH kinds of key exchange: a
// classical group reports { type:"ECDH", name:"X25519" }, and an ML-KEM hybrid
// reports { type:"TLSGroup", name:"X25519MLKEM768" }. A post-quantum exchange
// is therefore identified POSITIVELY — by that type, or by the name appearing
// in C.PQC_GROUPS — and anything else that names a group is a classical
// fallback, emitted as a downgrade so operators can see which dependencies are
// not yet post-quantum ready.
//
// An ABSENT name is NOT evidence of a hybrid. It means the handshake reported
// no ephemeral group at all. On a RESUMED session that says nothing — the
// forward secrecy is inherited from the original handshake — so nothing is
// emitted. Otherwise it means the key exchange was not ephemeral at all, which
// gets its own action rather than silence. (Older Node did not model a hybrid
// as ECDH and returned {} for one, which made an absent name ambiguous; the
// framework's floor now reports the group by name, so the cases are
// distinguishable.)
//
// Best-effort + drop-silent: an audit failure must never break the request
// that triggered it.
function auditClassicalDowngrade(socket, meta) {
  try {
    if (!socket || typeof socket.getEphemeralKeyInfo !== "function") return;
    var info = socket.getEphemeralKeyInfo() || {};
    var group = info.name;
    var host  = (meta && (meta.host || meta.servername)) || null;
    var port  = (meta && meta.port) || null;

    // A post-quantum group identifies itself positively: node:tls reports a
    // named TLS group (`type: "TLSGroup"`) for a key exchange it does not
    // model as classical ECDH, and the framework's own hybrids are listed by
    // name in constants. Both signals are kept — the type covers a future
    // group the name table has not learned yet, the name table covers a
    // runtime that labels a known hybrid differently.
    if (info.type === "TLSGroup") return;
    if (typeof group === "string" &&
        Object.prototype.hasOwnProperty.call(C.PQC_GROUPS, group)) return;

    // Nothing reported. This is NOT "probably a hybrid" — per the tls docs
    // an empty key-info means the key exchange was not ephemeral, so the
    // connection has no forward secrecy at all. Audited under its own action
    // so it is neither silent nor mistaken for an observed classical group.
    if (!group) {
      // A RESUMED session performs no new key exchange, so an absent group
      // here says nothing about the connection's forward secrecy — it
      // inherits the original handshake's. Node's TLS-1.3 resumption uses
      // PSK with (EC)DHE and does still report a group, but psk_ke
      // resumption carries no key exchange at all, and connection-pool churn
      // makes resumption routine: recording those as findings would bury the
      // real ones. Nothing to judge, so judge nothing.
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
  "secp256r1",            // IANA TLS group name (P-256), not bytes
  "secp384r1",            // IANA TLS group name (P-384), not bytes
  "secp521r1",            // IANA TLS group name (P-521), not bytes
  "X448",
]);

function _validateGroupName(name) {
  // Same shape as network-tls._validateKeyShare: alphanumeric +
  // underscore, bounded length. Refuses `:` so an operator can't
  // smuggle a second group through one slot.
  if (typeof name !== "string" || name.length === 0 || name.length > 64) { // string-length cap, not bytes
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
    // No caller preference — take the LIVE group list, the same one every
    // other outbound client merges. Using the compiled-in default here meant
    // an operator who narrowed the groups still had the HTTP/1.1 agent
    // re-offering the ones they removed, while the h2 path (built per
    // session from the posture) honored the narrowing: one origin's
    // handshake obeyed the policy and the other did not, decided by ALPN.
    merged.ecdhCurve = networkTls.outboundPosture().ecdhCurve;
  }
  // `applyToContext` fills the group preference only when the base does not
  // already carry one, so the resolved ecdhCurve above stands as the caller's
  // narrowed or reordered selection rather than being re-derived from the
  // configured key shares in a different order.
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
  // _buildAgentOpts merged the live posture into `built` above, and narrowed
  // it when the caller named their own groups; re-applying it here would
  // overwrite that narrowing with the framework default.
  // allow:outbound-tls-posture — posture applied in _buildAgentOpts
  var agent = new https.Agent(built);
  agent._builtOpts = built;
  // Observe each NEW outbound socket's negotiated group (createConnection
  // runs per fresh connection, not per keep-alive reuse). A classical
  // negotiation means the peer offered no ML-KEM hybrid — audit the
  // downgrade. Hybrid stays preferred on every handshake; this only fires on
  // the classical fallback.
  var _origCreateConnection = agent.createConnection.bind(agent);
  agent.createConnection = function (options, cb) {
    var socket = _origCreateConnection(options, cb);
    if (socket && typeof socket.once === "function") {
      socket.once("secureConnect", function () { auditClassicalDowngrade(socket, options); });
    }
    return socket;
  };
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
    // allow:secure-context-cert-compression — validation only; this context is
    // discarded immediately and never serves a handshake
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
// The posture generation the cached agent was built under. An Agent copies its
// TLS options at construction, so the process-wide default would otherwise keep
// offering the groups an operator removed for the life of the process — the
// same staleness the HTTP client's transport pool stamps against. Rebuilding
// here means b.network.tls.preferredGroups.set(...) reaches the default agent
// without the operator also having to call reload().
var _defaultAgentGeneration = null;
function _getDefaultAgent() {
  var generation = networkTls.postureGeneration();
  if (_defaultAgent && _defaultAgentGeneration !== generation) {
    // Retire the old agent WITHOUT destroying it. reload() calls
    // Agent.destroy(), which resets sockets that are mid-response — so
    // refreshing the default because someone changed the posture would abort
    // an unrelated download or API call already running on it. Instead stop it
    // pooling and close only its IDLE sockets: work in flight finishes, and
    // each socket is destroyed as it is released rather than parked in a pool
    // nothing can reach again. Null first, so a concurrent caller either gets
    // the retiring agent (its request completes) or builds fresh.
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
  // Null the cached agent BEFORE calling destroy. The
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
  // Internal — shared with lib/http-client.js's h2 transport, which connects
  // via node:http2 (not this agent) and so needs the same downgrade
  // observation. Underscore-prefixed: not a public operator primitive.
  _auditClassicalDowngrade: auditClassicalDowngrade,
  DEFAULT_OPTS: DEFAULT_OPTS,
  KNOWN_TLS_GROUPS: KNOWN_TLS_GROUPS,
  enforced:    true,
};
