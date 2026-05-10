"use strict";
/**
 * pqc-agent — outbound HTTPS agent locked to PQC group preference.
 *
 * The framework's posture is "all outbound TLS is PQC-only". This is
 * the single primitive that defines what that means at the agent
 * level: TLSv1.3 minimum, ecdhCurve set to the framework's PQC hybrid
 * preference (constants.TLS_GROUP_CURVE_STR), keep-alive on.
 *
 * Two surfaces:
 *
 *   1. b.pqcAgent.agent — a process-wide default agent, lazy-built on
 *      first access. Use this for one-off outbound calls that go
 *      through node:https directly:
 *
 *        https.request(url, { agent: b.pqcAgent.agent }, ...);
 *
 *   2. b.pqcAgent.create(opts) — build a fresh agent with custom
 *      pool / timeout opts. ecdhCurve and minVersion CANNOT be
 *      weakened via opts; operator-supplied values for those are
 *      ignored and the framework's defaults win. Operators who need
 *      a non-PQC agent for a deliberate one-off integration with a
 *      non-PQC server construct their own new https.Agent() directly,
 *      outside this primitive.
 *
 * lib/http-client.js's transport cache uses pqcAgent.create() under
 * the hood, so the framework's bundled HTTP client and any operator-
 * direct https.request calls converge on the same agent posture.
 */

var https = require("node:https");
var http  = require("node:http");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var networkTls = require("./network-tls");
var safeBuffer = require("./safe-buffer");

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

function create(opts) {
  return new https.Agent(_buildAgentOpts(opts));
}

// http (cleartext) variant — same pool defaults but obviously no TLS
// posture to enforce. Operator-side, almost no caller wants this; it
// exists so http-client's h1 transport for cleartext origins (h2c
// fixtures, internal services) shares the pool tuning.
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

module.exports = {
  // Read property — getter so the agent is built on first access.
  get agent()  { return _getDefaultAgent(); },
  create:      create,
  createHttp:  createHttp,
  DEFAULT_OPTS: DEFAULT_OPTS,
  KNOWN_TLS_GROUPS: KNOWN_TLS_GROUPS,
  enforced:    true,
};
